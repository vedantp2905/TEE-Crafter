"""Unified deploy command: Dockerfile / OCI image → TEE (--batch | --persistent)."""

import os

import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.constants import KEEP_ON_FAILURE_ENV, PIPELINE_VERSION, console
from tee_crafter.cli.commands.deploy.deploy_helpers import (
    PLATFORM_LABELS,
    _DEFAULT_MAX_OUTPUT_SIZE,
    _TEE_PLATFORM_CHOICES,
    DEFAULT_BATCH_TIMEOUT,
    _resolve_ami_id,
    enforce_residency_gate,
    validate_flag_dependencies,
    validate_run_mode,
)
from tee_crafter.cli.commands.deploy.platform import PLATFORM_CONFIGS
from tee_crafter.cli.commands.deploy.byok_mode import BYOK_PROVIDERS
from tee_crafter.cli.commands.deploy.siem_mode import SIEM_PROVIDERS
from tee_crafter.cli.commands.deploy.flow_container import run_container_phases, resolve_docker_platform
from tee_crafter.cli.commands.deploy.flow_build import run_phases_5_to_6
from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.cli.deployment.common.terraform_step import cleanup_resources
from tee_crafter.cli.deployment.common.siem_sidecar import (
    siem_export_blocked_deploy,
)


#: Why there is no MAA region-tag mapping here.
#:
#: An earlier revision of this file mapped MAA hostnames to Azure service-tag
#: region suffixes (`sharedwus.wus.attest.azure.net` -> `WestUS`) and set
#: `TF_VAR_maa_service_tag_region`, by analogy with the Key Vault rule, which
#: does scope regionally. That analogy is false and it cost a partial deploy:
#:
#:   az network list-service-tags --location westus \
#:     --query "values[?starts_with(name,'AzureKeyVault')].name"
#:   -> AzureKeyVault, AzureKeyVault.AustraliaCentral, ... (many)
#:
#:   az network list-service-tags --location westus \
#:     --query "values[?contains(name,'Attestation')].name"
#:   -> AzureAttestation                        # and nothing else
#:
#: Azure publishes **no regional AzureAttestation tag**. Emitting
#: `AzureAttestation.WestUS` produces an NSG rule Azure rejects at apply time,
#: which is a failure *after* the VM exists. So MAA egress uses the flat tag,
#: and the only way to scope below it is `maa_endpoint_cidr` (a private
#: endpoint) — which the template's `check` block says out loud rather than
#: warning about a knob that cannot help.


def _renderer_accepts(render_fn, kwarg: str) -> bool:
    """Whether *render_fn* declares *kwarg* (or absorbs it via ``**kwargs``)."""
    import inspect
    try:
        params = inspect.signature(render_fn).parameters
    except (TypeError, ValueError):
        return False
    if kwarg in params:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _warn_if_image_predates_bake_inputs(console, tee_platform, image_id,
                                       registry) -> bool:
    """Warn when the baked image was produced from different bake-time inputs.

    ``stale_image_check`` compares the CLI image against the checkout. It cannot
    see this one: a VM image is baked once and reused for weeks, so a fix to
    something that is *baked in* -- a setup script, an AppArmor or seccomp
    profile, a systemd unit -- does not reach an existing image at all, and
    nothing about the deploy says so.

    That cost a run on 2026-08-24: an ``sgx-azure --batch`` deploy died with
    Gramine unable to mount its root filesystem, because AppArmor denied
    ``open("/")``. The fix was already in the repo and already covered by a
    test; the image had simply been baked before it landed. The symptom read
    like a fresh regression in the manifest.

    Warn rather than block: an older image is often exactly what you want (a
    pinned, vetted baseline), and re-baking on every unrelated edit would be
    worse. Records with no stored digest -- anything baked before this existed
    -- are silent, because "unknown" is not "stale".

    Returns True when a warning was printed (for tests).
    """
    rec = registry.lookup(tee_platform, image_id or "") or {}
    baked = (rec.get("bake_inputs_sha256") or "").strip().lower()
    if not baked:
        return False
    try:
        from tee_crafter.cli.loaders import bake_inputs_digest
        current = (bake_inputs_digest(tee_platform) or "").strip().lower()
    except Exception:
        return False
    if not current or current == baked:
        return False
    try:
        console.print(
            f"[yellow]⚠ This image was baked from different setup inputs than "
            f"the current tree.[/yellow]\n"
            f"[yellow]baked with [cyan]{baked[:16]}…[/cyan], tree is now "
            f"[cyan]{current[:16]}…[/cyan]. Anything that is *baked into* the "
            f"image — setup script, AppArmor/seccomp profile, systemd unit — has "
            f"changed since, and those changes are NOT in this image; only "
            f"deploy-time templates are refreshed on every deploy. If you are "
            f"testing such a fix, re-bake first:\n"
            f"  [bold]tee-crafter internal bake-ami --tee-platform "
            f"{tee_platform}[/bold]\n"
            f"[dim]Harmless if you meant to deploy a pinned older baseline.[/dim]")
    except Exception:
        pass
    return True


def _warn_if_host_gen_is_a_coin_flip(console, tee_platform, image_id, registry,
                                     gen_selectable: bool,
                                     expected_gens) -> bool:
    """Warn when the bake saw fewer host generations than the platform can give.

    The launch digest of an AMD SEV-SNP guest folds in host firmware and
    microcode, so each host CPU generation produces its own value. On a platform
    where the instance type does not decide the generation — Azure's
    ``DCas_v5``, which has been observed on two — a bake that only ever landed on
    one generation pins only that one. The deploy then works or does not
    depending on where the scheduler puts the VM.

    That outcome is safe: the client's measurement allowlist refuses the digest
    it was not given, so the failure is a refusal to attest, not a silent
    acceptance. It is also confusing, and it looks exactly like a broken image.
    Saying so up front is the whole point of this warning.

    Deliberately not a hard stop. Refusing here would block a deploy that has a
    real chance of landing on the captured generation and succeeding, in exchange
    for preventing a failure that already fails closed on its own.

    Returns True when a warning was printed (for tests).
    """
    if gen_selectable or len(expected_gens or []) < 2:
        return False
    captured = registry.captured_gens(tee_platform, image_id)
    if len(captured) >= len(expected_gens):
        return False
    missing = [g for g in expected_gens if g not in captured] or list(expected_gens)
    try:
        console.print(
            f"[yellow]⚠ This image was pinned on "
            f"{len(captured) or 'no'} of {len(expected_gens)} host CPU "
            f"generations.[/yellow]\n"
            f"[yellow]Captured: [cyan]{', '.join(captured) or '(none)'}[/cyan] · "
            f"not captured: [cyan]{', '.join(missing)}[/cyan]. On "
            f"[magenta]{tee_platform}[/magenta] the instance type does not decide "
            f"which generation you get, and each one produces a different launch "
            f"digest. If this VM lands on a generation that was not captured, "
            f"attestation will fail closed with a measurement mismatch — the "
            f"image is fine, it simply has no pinned digest for that host.\n"
            f"[yellow]To cover both, re-bake until capture reports both "
            f"generations. Do not hand-pin the second digest: a value nobody "
            f"measured is not evidence.[/yellow]")
    except Exception:
        pass
    return True


def _record_resume_manifest(build_dir, tee_platform, cpu, ram, measurements,
                            custom_ami) -> None:
    """Write the resume manifest, on both the deploy and no-deploy path.

    Placed before the ``if do_deploy:`` fork on purpose.  ``--no-deploy`` then
    ``deploy-from-build`` is a documented workflow, and a build directory whose
    apply died is the case that motivated the file — neither can afford this to
    happen only on the success path.
    """
    from tee_crafter.cli.commands.deploy.resume_manifest import write_manifest

    written = write_manifest(
        build_dir, tee_platform=tee_platform, cpu=cpu, ram=ram,
        measurements=measurements, custom_ami=custom_ami,
    )
    if not written:
        console.print(
            "[yellow]Could not write the resume manifest to this build "
            "directory; `tee-crafter deploy-from-build` will refuse it rather "
            "than guess the platform.[/yellow]")


def register_deploy(cli, *, command_name: str = "deploy", hidden: bool = False):
    @cli.command(command_name, hidden=hidden)
    @click.option(
        "--source", required=True,
        type=click.Path(exists=True, file_okay=False, dir_okay=True),
        help="Directory containing a Dockerfile and application code",
    )
    @click.option("--instance-type", "instance_type_opt", default=None, type=str,
                  envvar="TEE_CRAFTER_INSTANCE_TYPE",
                  help="Instance type to deploy (vCPU/RAM/GPU come from it). "
                       "Defaults to the platform's catalog default. List options "
                       "with `tee-crafter list-instances --tee-platform <p>`.")
    @click.option("--spot", "spot_opt", is_flag=True, default=False,
                  envvar="TEE_CRAFTER_SPOT",
                  help="Request a spot / low-priority / preemptible instance.")
    @click.option(
        "--container-port", default=None, type=int,
        help="Port the user's app listens on (default: auto-detect from EXPOSE, fallback 8080)",
    )
    # Retired: nothing ever read this value, so passing it silently left the
    # image's own CMD in place.  Kept (hidden) so existing scripts get an
    # explanation from ``validate_flag_dependencies`` instead of "no such
    # option".
    @click.option(
        "--container-cmd", default=None, type=str, hidden=True,
        help="Retired — rejected. Set CMD / ENTRYPOINT in your Dockerfile.",
    )
    @click.option("--deploy", is_flag=True, default=False,
                  help="Provision the cloud infrastructure and deploy. Without "
                       "it the pipeline builds and stages artifacts locally, "
                       "then stops.")
    @click.option("--auto-approve", is_flag=True, default=False,
                  help="Skip the interactive Terraform apply confirmation. "
                       "Requires --deploy.")
    @click.option("--teardown", is_flag=True, default=False,
                  help="Destroy the provisioned infrastructure after the client "
                       "run finishes. Requires --deploy.")
    @click.option(
        "--tee-platform", default="nitro-aws",
        type=click.Choice(_TEE_PLATFORM_CHOICES, case_sensitive=False),
        help="Target TEE + cloud (default: nitro-aws). --batch needs a CVM "
             "platform (Nitro Enclaves cannot run arbitrary images); "
             "--persistent is unavailable on sgx-azure.",
    )
    @click.option(
        "--ami-id", "ami_id", default=None, type=str,
        envvar="TEE_CRAFTER_AMI_ID",
        help="Pinned, hardened image ID. When omitted, reads TEE_CRAFTER_AMI_ID or "
             "the per-platform .env variable (AWS_SNP_AMI, AZURE_TDX_IMAGE, …; nitro-aws uses AWS_NITRO_AMI_X86_64 / AWS_NITRO_AMI_ARM64). "
             "Required when --deploy is set unless one of those is set. Bake with "
             "`tee-crafter internal bake-ami`.",
    )
    @click.option("--batch", "batch_mode", is_flag=True, default=False,
                  envvar="TEE_CRAFTER_BATCH",
                  help="One-shot batch (required unless --persistent): run the "
                       "container to completion and capture output via docker diff "
                       "+ docker cp (output.tar.gz).")
    @click.option("--persistent", "persistent_mode", is_flag=True, default=False,
                  envvar="TEE_CRAFTER_PERSISTENT",
                  help="Long-lived service behind the attested ingress proxy (RA-TLS). "
                       "Required unless --batch. Mutually exclusive with --batch. "
                       "Unavailable for sgx-azure.")
    @click.option("--batch-timeout", default=DEFAULT_BATCH_TIMEOUT, type=int,
                  envvar="TEE_CRAFTER_BATCH_TIMEOUT",
                  help="Hard timeout (seconds) for the batch job; default 3600. "
                       "Requires --batch.")
    @click.option("--input-dir", default=None,
                  envvar="TEE_CRAFTER_INPUT_DIR",
                  type=click.Path(exists=False, file_okay=False, dir_okay=True),
                  help="Requires --batch. Local directory uploaded to "
                       "/var/lib/tee_crafter/input (mounted "
                       "as /input:ro inside the container). NOT sealed: the "
                       "directory is uploaded as a plain tar.gz and extracted on "
                       "the host filesystem, so the cloud operator can read it. "
                       "Encrypt sensitive inputs yourself before passing them here.")
    # ---------- Workload network egress (databases, 3rd-party APIs) ----------
    @click.option("--egress-mode",
                  type=click.Choice(["deny", "vpc", "nat"], case_sensitive=False),
                  default="deny", envvar="TEE_CRAFTER_EGRESS_MODE",
                  help="Workload egress posture. 'deny' (default) = no outbound except "
                       "VPC-local 443 (KMS/attestation). 'vpc' = reach intra-VPC "
                       "destinations (private DB) on --egress-allow ports, no NAT. "
                       "'nat' = reach PUBLIC destinations (managed DB endpoint / SaaS) "
                       "via a NAT gateway, SG locked to the resolved CIDRs (never 0.0.0.0/0).")
    @click.option("--egress-allow", "egress_allow", multiple=True,
                  envvar="TEE_CRAFTER_EGRESS_ALLOW",
                  help="Allowlisted destination 'host:port' or 'cidr:port' the workload "
                       "may reach (e.g. db.example.com:5432). Repeatable. Requires "
                       "--egress-mode vpc or nat.")
    # ---------- Persistent service mode ----------
    @click.option("--service-profile",
                  type=click.Choice(["default", "long-lived", "short-lived", "streaming"],
                                    case_sensitive=False),
                  default="default",
                  envvar="TEE_CRAFTER_SERVICE_PROFILE",
                  help="Persistent RA-TLS service profile. 'default' = one-shot. "
                       "'long-lived' / 'short-lived' / 'streaming' enable service "
                       "mode with reviewed presets. Mutually exclusive with --batch.")
    # ---------- SIEM (JSON-only) ----------
    # Choices come from siem_mode.SIEM_PROVIDERS so the flag cannot drift from
    # the set the in-TEE sidecar can actually build an exporter for.
    @click.option("--siem", "siem_provider",
                  type=click.Choice(list(SIEM_PROVIDERS), case_sensitive=False),
                  default="none", envvar="TEE_CRAFTER_SIEM",
                  help="Stream signed continuous-attestation events to a SIEM. "
                       "Provider-specific fields go in --siem-config.")
    @click.option("--siem-config", "siem_config_path", default=None,
                  type=click.Path(exists=True, dir_okay=False),
                  envvar="TEE_CRAFTER_SIEM_CONFIG",
                  help="JSON file with the full SIEM exporter config. "
                       "Required when --siem != none, and rejected when --siem "
                       "is none (it would otherwise be read and ignored).")
    # ---------- BYOK (JSON-only) ----------
    # Choices come from BYOK_PROVIDERS rather than a second hand-written list.
    # They used to be two lists, and they drifted: `azure-skr` was added to
    # BYOK_PROVIDERS, wired through the config validator, the TF-var exporter,
    # the runtime bootstrap and the bake — and Click still rejected it at parse
    # time with "'azure-skr' is not one of 'none', 'aws-kms', …".  So the only
    # BYOK provider that works on an Azure CVM was unreachable from the CLI,
    # and 60 tests passed anyway because every one of them called the internal
    # functions directly.  Deriving the choices makes that particular drift
    # impossible.
    @click.option("--byok", "byok_provider",
                  type=click.Choice(list(BYOK_PROVIDERS), case_sensitive=False),
                  default="none", envvar="TEE_CRAFTER_BYOK",
                  help="Customer-managed keys with attestation-gated release. "
                       "Provider-specific fields go in --byok-config.")
    @click.option("--byok-config", "byok_policy_path", default=None,
                  type=click.Path(exists=True, dir_okay=False),
                  envvar="TEE_CRAFTER_BYOK_CONFIG",
                  help="JSON file with the full BYOK policy. "
                       "Required when --byok != none, and rejected when --byok "
                       "is none (it would otherwise be read and ignored).")
    @click.option("--secrets-env", "secrets_env_path", default=None,
                  type=click.Path(exists=True, dir_okay=False),
                  envvar="TEE_CRAFTER_SECRETS_ENV",
                  help="Plaintext dotenv file (DB passwords, API tokens, config) "
                       "delivered to the app at /run/tee_crafter/app.env. With "
                       "--byok aws-kms/gcp-kms it is envelope-sealed and released "
                       "only inside the attested TEE; without BYOK it is baked into "
                       "the measured image (fine for config — use --byok for secrets).")
    @click.option("--allow-vulnerable", is_flag=True, default=False,
                  envvar="TEE_CRAFTER_ALLOW_VULNERABLE",
                  help="Proceed even when the Trivy/Grype scan reports CRITICAL "
                       "or HIGH severity findings. Default is to abort the deploy. "
                       "NOT for production: every override is recorded in the "
                       "build provenance with gate_allowed=True.")
    @click.option("--keep-on-failure", "keep_on_failure", is_flag=True, default=False,
                  envvar=KEEP_ON_FAILURE_ENV,
                  help="Leave provisioned infrastructure running when the deploy "
                       "fails, for debugging. Default is to tear it down: a failed "
                       "run otherwise leaves the instance (and any NAT gateway) "
                       "billing until someone runs `tee-crafter destroy`.")
    def deploy_cmd(
        source, instance_type_opt, spot_opt, container_port, container_cmd,
        deploy, auto_approve, teardown,
        tee_platform, ami_id,
        batch_mode, persistent_mode, batch_timeout, input_dir,
        egress_mode, egress_allow,
        service_profile,
        siem_provider, siem_config_path,
        byok_provider, byok_policy_path,
        secrets_env_path,
        allow_vulnerable,
        keep_on_failure,
    ):
        """Deploy a Dockerfile / OCI image to a TEE.

        You must pass exactly one of --batch or --persistent (no default).
        """
        # ``--tee-platform`` is a case-insensitive Choice, so Click hands back
        # whatever the operator typed.  Every lookup below (PLATFORM_CONFIGS,
        # _CONTAINER_CFG, _PLATFORM_CLOUDS, …) is keyed on the lowercase slug.
        tee_platform = tee_platform.lower()
        if allow_vulnerable:
            os.environ["TEE_CRAFTER_ALLOW_VULNERABLE"] = "1"
        if keep_on_failure:
            os.environ[KEEP_ON_FAILURE_ENV] = "1"

        ok, service_profile = validate_run_mode(
            batch_mode=batch_mode,
            persistent_mode=persistent_mode,
            tee_platform=tee_platform,
            service_profile=service_profile,
        )
        if not ok:
            raise click.ClickException(
                "Invalid run mode — see the message above. Pass exactly one of "
                "--batch or --persistent (sgx-azure is --batch only).")

        # Options that only take effect under another flag: refuse them rather
        # than accept-and-ignore.  Runs before anything is built or provisioned.
        validate_flag_dependencies(
            batch_mode=batch_mode,
            persistent_mode=persistent_mode,
            container_cmd=container_cmd,
            batch_timeout=batch_timeout,
            input_dir=input_dir,
            siem_provider=siem_provider,
            siem_config_path=siem_config_path,
            byok_provider=byok_provider,
            byok_policy_path=byok_policy_path,
        )

        from tee_crafter.cli.commands.deploy.service_mode import (
            build_service_policy_from_profile, record_service_policy_audit,
        )
        from tee_crafter.cli.commands.deploy.siem_mode import (
            build_siem_config, record_siem_audit,
        )
        from tee_crafter.cli.commands.deploy.byok_mode import (
            build_byok_config, record_byok_audit,
        )
        from tee_crafter.cli.commands.deploy.compute import resolve_shape

        try:
            shape = resolve_shape(tee_platform, instance_type_opt, spot_opt)
        except ValueError as exc:
            raise click.ClickException(f"Invalid --instance-type: {exc}")
        enclave_cpu, enclave_ram = shape.cpu, shape.ram_mb
        instance_type = shape.instance_type
        spot = shape.spot

        if teardown and not deploy:
            raise click.ClickException("--teardown requires --deploy")
        if auto_approve and not deploy:
            raise click.ClickException("--auto-approve requires --deploy")
        try:
            service_mode, service_policy = build_service_policy_from_profile(service_profile)
        except ValueError as exc:
            raise click.ClickException(f"Invalid --service-profile: {exc}")
        if service_mode and batch_mode:
            raise click.ClickException(
                "--service-profile != 'default' is mutually exclusive with --batch")
        if service_mode:
            for k, v in service_policy.to_env().items():
                os.environ.setdefault(k, v)
            os.environ["TEE_CRAFTER_SERVICE_MODE"] = "1"

        try:
            siem_config = build_siem_config(
                provider=siem_provider, raw_config_path=siem_config_path,
            )
            siem_errs = siem_config.validate()
            if siem_errs:
                raise ValueError("; ".join(siem_errs))
        except click.ClickException:
            raise
        except Exception as exc:
            raise click.ClickException(f"Invalid --siem / --siem-config: {exc}")

        try:
            byok_config = build_byok_config(
                provider=byok_provider, raw_policy_path=byok_policy_path,
            )
            byok_errs = byok_config.validate()
            if byok_errs:
                raise ValueError("; ".join(byok_errs))
        except click.ClickException:
            raise
        except Exception as exc:
            raise click.ClickException(f"Invalid --byok / --byok-config: {exc}")

        # Offline pre-flight.  Everything here used to fire either after the
        # full container build (--egress-*, --secrets-env, --siem-config
        # egress) or after `terraform apply` (--batch on nitro-aws, an
        # instance shape forced through TF_VAR_*).  Nothing below touches a
        # cloud API, so it is safe — and cheap — to run first.
        from tee_crafter.cli.preflight import validate_deploy_combination
        validate_deploy_combination(
            tee_platform=tee_platform,
            batch_mode=batch_mode,
            instance_type=instance_type,
            egress_mode=egress_mode,
            egress_allow=list(egress_allow),
            secrets_env_path=secrets_env_path,
            siem_config=siem_config,
        )

        # Credential probe runs *after* the offline guards: it needs the
        # network, and a bad flag combination should not require live cloud
        # credentials to report.
        from tee_crafter.cli.cloud_auth import validate_required_creds
        validate_required_creds(tee_platform)

        platform_label = PLATFORM_LABELS.get(tee_platform, tee_platform)
        run_mode = "batch" if batch_mode else "persistent"
        audit = BuildAuditTrail()
        audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir="(pending)")
        audit.set_tee_platform(tee_platform)

        # Say so *before* anything is built, if this image predates the
        # checkout.  A deploy from a stale image succeeds and looks like
        # evidence; see stale_image_check for the two live runs that cost.
        from tee_crafter.cli.stale_image_check import stale_image_warning

        _stale = stale_image_warning()
        if _stale:
            console.print(Panel.fit(
                f"[bold yellow]Stale CLI image[/bold yellow]\n\n{_stale}",
                border_style="yellow"))
            audit.record("Pipeline Config", "CLI image matches checkout",
                         "warn", reason="image source digest != /workspace")
        else:
            audit.record_check(
                "Pipeline Config", "CLI image matches checkout", "PC-003",
                observed=True)
        console.print(Panel.fit(
            f"[bold blue]TEE-Crafter Deploy ({platform_label})[/bold blue]\n\n"
            f"Source: [green]{os.path.abspath(source)}[/green]\n"
            f"Resources: {enclave_cpu} vCPU, {enclave_ram} MB RAM\n"
            f"Run mode: [cyan]{run_mode}[/cyan]\n"
            f"TEE Platform: [magenta]{tee_platform.upper()}[/magenta]",
            border_style="blue",
        ))
        audit.record(
            "Pipeline Config", "Deploy pipeline initialized", "info",
            enclave_cpu=enclave_cpu, enclave_ram=enclave_ram,
            tee_platform=tee_platform, mode=run_mode,
            container_port=container_port,
            service_mode=bool(service_mode),
            siem=siem_provider, byok=byok_provider,
        )
        audit.record_check(
            "Pipeline Config", "tee_platform recognised", "PC-001",
            observed=bool(tee_platform in PLATFORM_LABELS),
        )
        audit.record_check(
            "Pipeline Config", "flow detected", "PC-002",
            observed=True,
            note=f"dockerfile/{run_mode}",
        )
        # Refuse an unworkable --byok azure-skr here, not in the TEE.  The
        # in-TEE adapter also refuses, correctly, but by then the VM exists and
        # is billing.  Deliberately outside the try/except below: this is a
        # configuration error, not a best-effort convenience.
        from tee_crafter.cli.commands.deploy.byok_mode import (
            azure_skr_prerequisite_error,
        )
        _skr_err = azure_skr_prerequisite_error(byok_provider, tee_platform)
        if _skr_err:
            console.print(Panel.fit(
                f"[bold red]--byok azure-skr cannot run here[/bold red]\n\n"
                f"{_skr_err}",
                border_style="red",
            ))
            audit.record("BYOK", "azure-skr prerequisites", "fail",
                         reason=_skr_err.splitlines()[0])
            return False
        try:
            from tee_crafter.cli.commands.deploy.byok_mode import export_byok_tf_vars
            _byok_tf_vars = export_byok_tf_vars(byok_config, tee_platform)
            if _byok_tf_vars:
                audit.record(
                    "BYOK", "Auto-exported terraform vars for instance-role decrypt",
                    "info", exported=sorted(_byok_tf_vars.keys()),
                )
        except Exception:
            pass
        from tee_crafter.cli.commands.deploy.flag_audit import audit_dev_hatch_flags
        audit_dev_hatch_flags(
            audit,
            tee_platform=tee_platform,
            byok_enabled=(byok_provider != "none"),
            byok_provider=byok_provider,
            siem_provider=siem_provider,
            allow_unbaked_ami=False,
        )
        try:
            from tee_crafter.cli.cloud_auth import emit_iam_verdicts
            emit_iam_verdicts(audit, tee_platform)
        except Exception:
            pass
        record_service_policy_audit(audit, service_policy, enabled=service_mode)
        record_siem_audit(audit, siem_config,
                           enabled=(siem_provider != "none"))
        _byok_cfg_sha = ""
        if byok_policy_path:
            try:
                from tee_crafter.core.audit import sha256_file
                _byok_cfg_sha = sha256_file(byok_policy_path)
            except Exception:
                _byok_cfg_sha = ""
        record_byok_audit(
            audit, byok_config,
            enabled=(byok_provider != "none"),
            tee_platform=tee_platform,
            byok_config_sha256=_byok_cfg_sha,
        )

        from tee_crafter.core.gpu import is_gpu_cc_platform
        if is_gpu_cc_platform(tee_platform):
            nras_key = os.environ.get("NVIDIA_NRAS_API_KEY", "")
            if not nras_key:
                console.print(Panel.fit(
                    "[bold red]NVIDIA_NRAS_API_KEY not set[/bold red]\n\n"
                    "GPU Confidential Computing requires an NVIDIA NRAS API key.\n"
                    "Add it to your [cyan].env[/cyan] file:\n\n"
                    "  NVIDIA_NRAS_API_KEY=your-key-here\n\n"
                    "Obtain a key from [link=https://ngc.nvidia.com]https://ngc.nvidia.com[/link]",
                    border_style="red",
                ))
                audit.record(
                    "Pipeline Config", "NVIDIA NRAS API key", "fail",
                    error="NVIDIA_NRAS_API_KEY not set in environment",
                )
                raise click.ClickException(
                    "NVIDIA_NRAS_API_KEY is not set; GPU Confidential Computing "
                    "cannot attest the GPU without it.")

        cpu, ram = enclave_cpu, enclave_ram
        if tee_platform == "gpu-cc-azure":
            from tee_crafter.core.gpu import GPU_CC_AZURE_LOCATION

            os.environ["TF_VAR_azure_location"] = GPU_CC_AZURE_LOCATION
        os.environ["TF_VAR_use_spot_instance"] = "true" if spot else "false"
        if instance_type and "TF_VAR_instance_type" not in os.environ:
            os.environ["TF_VAR_instance_type"] = instance_type

        # Fail-closed data-residency gate (no-op unless
        # TEE_CRAFTER_RESIDENCY_POLICY is set). Runs before any cloud resource
        # is created so a forbidden region never gets provisioned. No build dir
        # exists yet, so on a violation we abort like the other pre-build guards.
        if deploy and not enforce_residency_gate(console, audit, tee_platform):
            raise click.ClickException(
                "Residency policy violation — refusing to deploy. See the panel above.")

        # Ask the SIEM egress planner now what it will decide later.  It cannot
        # be *applied* until build_dir exists (it writes an audit doc there), but
        # the answer is pure data, and the deploy summary is printed long before
        # then — see will_open_public_egress().
        from tee_crafter.cli.commands.deploy.siem_egress_terraform import (
            will_open_public_egress,
        )
        siem_opens_egress = will_open_public_egress(
            siem_config, tee_platform=tee_platform)

        custom_ami = _resolve_ami_id(
            ami_id=ami_id, tee_platform=tee_platform, deploy=deploy,
            audit=audit, cpu=cpu, ram=ram, instance_type=instance_type,
            siem_opens_egress=siem_opens_egress,
        )
        # ``None`` is the hard failure (no pin, no dev hatch); ``""`` is the
        # deliberate TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI escape hatch, which
        # ``_resolve_ami_id`` has already warned about.  Testing truthiness
        # conflated the two and aborted the hatch as well.
        if deploy and custom_ami is None:
            # _resolve_ami_id already printed the failure panel.
            raise click.ClickException(
                "--deploy needs a pinned, hardened image. See the panel above.")

        # Auto-pin: resolve the baked image's launch measurement (captured at
        # bake time) and fail closed if sealed/BYOK is requested for a CVM
        # image that was never pinned.
        from tee_crafter.cli.commands.deploy import measurement_pin
        pinned_measurements = measurement_pin.resolve_all(tee_platform, custom_ami)
        _sealed_or_byok = bool(secrets_env_path) or (
            byok_config is not None
            and getattr(byok_config, "provider", "none") != "none")
        if deploy and not measurement_pin.enforce(
            console, tee_platform=tee_platform, image_id=custom_ami,
            pinned_measurements=pinned_measurements, sealed_or_byok=_sealed_or_byok,
        ):
            raise click.ClickException(
                "No bake-time launch measurement for this image; refusing to "
                "release sealed secrets to an unpinned TEE. See the panel above.")
        # Bind BYOK / sealed-env release to the vetted measurement(s) when the
        # operator did not pin one explicitly in --byok-config.
        if pinned_measurements and byok_config is not None and not getattr(
            byok_config, "allowed_measurement_sha256", None
        ):
            byok_config.allowed_measurement_sha256 = (
                measurement_pin.policy_sha256_list(pinned_measurements))

        # Read *and* predict: apply_siem_egress sets this variable after the
        # container build, so sampling the environment here alone would miss the
        # SIEM NAT path and skip the post-bake lockdown reminder on exactly the
        # runs that most need it.
        opened_setup_egress = siem_opens_egress or (
            os.environ.get("TF_VAR_allow_setup_egress", "false").lower() == "true"
        )

        # Run container pipeline
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console, transient=False,
        ) as progress:
            result = run_container_phases(
                progress, audit, source,
                container_port, tee_platform,
                instance_type=instance_type,
                enclave_cpu=cpu,
                enclave_ram=ram,
                batch=batch_mode,
                batch_timeout=batch_timeout,
            )
            if result is None:
                raise click.ClickException(
                    "Container build failed. See the phase output above.")
            build_dir, source_summary = result

        # Stage cross-cutting config files into the container build dir
        # (and mirror into ``app/``).  These are picked up by the in-TEE
        # runtime bootstrap.
        if service_mode and service_policy is not None:
            from tee_crafter.cli.commands.deploy.service_mode import write_service_policy
            write_service_policy(build_dir, service_policy, enabled=True)
        if siem_config is not None and getattr(siem_config, "provider", "none") != "none":
            from tee_crafter.cli.commands.deploy.siem_mode import write_siem_config
            write_siem_config(build_dir, siem_config, enabled=True)
            from tee_crafter.cli.commands.deploy.siem_egress_terraform import apply_siem_egress
            try:
                apply_siem_egress(build_dir, siem_config, tee_platform=tee_platform,
                                   audit=audit, console=console)
            except ValueError as exc:
                raise click.ClickException(
                    f"Invalid --siem-egress combination: {exc}")
        # Sealed/staged .env (BYOK optional). Runs BEFORE write_byok_config so a
        # sealed bundle rides the BYOK tmpfs env; without BYOK it bakes a
        # plaintext app.env into the measured image.
        if secrets_env_path:
            from tee_crafter.cli.commands.deploy.secret_env import (
                apply_secret_env, SecretEnvError,
            )
            try:
                apply_secret_env(
                    build_dir, secrets_env_path=secrets_env_path,
                    byok_config=byok_config, audit=audit, console=console,
                    tee_platform=tee_platform,
                )
            except SecretEnvError as exc:
                raise click.ClickException(f"Invalid --secrets-env: {exc}")
        if byok_config is not None and getattr(byok_config, "provider", "none") != "none":
            from tee_crafter.cli.commands.deploy.byok_mode import write_byok_config
            write_byok_config(build_dir, byok_config, enabled=True)
        # Workload egress allowlist (databases / 3rd-party APIs). Runs AFTER the
        # SIEM egress step so both unions into the same locked-down allowlist.
        from tee_crafter.cli.commands.deploy.workload_egress import (
            apply_workload_egress, EgressSpecError,
        )
        try:
            apply_workload_egress(
                build_dir, egress_mode=egress_mode, allow_specs=list(egress_allow),
                tee_platform=tee_platform, audit=audit, console=console,
            )
        except EgressSpecError as exc:
            raise click.ClickException(
                f"Invalid --egress-allow / --egress-mode: {exc}")
        from tee_crafter.cli.commands.deploy.platform import _stage_runtime_bootstrap
        _stage_runtime_bootstrap(build_dir)

        if batch_mode:
            from tee_crafter.cli.commands.deploy.batch_dispatch import (
                dispatch_batch_container,
            )
            container_tar = os.path.join(build_dir, "user_container.tar")
            if not os.path.isfile(container_tar):
                console.print(Panel.fit(
                    "[bold red]Batch container needs user_container.tar in build_dir[/bold red]\n\n"
                    "The container flow did not save a tarball.  Re-run the deploy from "
                    "scratch so [bold]flow_container[/bold] can stage the image; if this "
                    "keeps recurring, file a bug with the build dir attached.",
                    border_style="red"))
                save_audit_trail(audit, build_dir, console)
                raise click.ClickException(
                    "Batch container needs user_container.tar in the build dir.")
            console.print(Panel.fit(
                f"[bold blue]TEE-Crafter Batch Container Deploy[/bold blue]\n\n"
                f"TEE Platform: [magenta]{tee_platform.upper()}[/magenta]\n"
                f"Image: [cyan]{os.path.basename(container_tar)}[/cyan]\n"
                f"Mode: [cyan]Batch (image runs as-is, output captured via docker diff)[/cyan]",
                border_style="blue",
            ))
            batch_result = dispatch_batch_container(
                build_dir=build_dir, tee_platform=tee_platform,
                container_tar_path=container_tar,
                do_deploy=deploy, auto_approve=auto_approve, teardown=teardown,
                batch_timeout=batch_timeout,
                max_output_size=_DEFAULT_MAX_OUTPUT_SIZE,
                input_dir=input_dir, audit=audit, console=console,
                cpu=cpu, ram_mb=ram,
            )
            # ``BatchResult(success=False)`` was being dropped on the floor
            # here, so a batch that never ran the container still exited 0.
            # ``None`` is the legitimate "staged, --deploy not passed" case.
            if batch_result is not None and not batch_result.success:
                raise click.ClickException(
                    batch_result.message or "Batch run failed.")
            return

        # Platform-specific deployment phases (reuse existing)
        if tee_platform == "nitro-aws":
            deploy_ok = _deploy_nitro_container(
                build_dir, cpu, ram, instance_type, deploy, auto_approve,
                teardown, source_summary, audit, custom_ami,
            )
        elif tee_platform == "sgx-azure":
            deploy_ok = _deploy_sgx_container(
                build_dir, cpu, ram, instance_type, deploy, auto_approve,
                teardown, source_summary, audit, custom_ami,
            )
        elif tee_platform in PLATFORM_CONFIGS:
            deploy_ok = _deploy_cvm_container(
                build_dir, cpu, ram, instance_type, deploy, auto_approve,
                teardown, source_summary, audit, custom_ami,
                tee_platform, pinned_measurements=pinned_measurements,
            )
        else:
            save_audit_trail(audit, build_dir, console)
            console.print(
                f"\n[bold green]Container artifacts staged.[/bold green]\n"
                f"Build dir: [cyan]{os.path.abspath(build_dir)}[/cyan]\n"
            )
            deploy_ok = True

        # NET-1: remind operator to close setup egress after bake.
        if opened_setup_egress and deploy and not teardown:
            try:
                from tee_crafter.cli.deployment.common.wheel_manager import (
                    remind_post_bake_lockdown,
                )
                remind_post_bake_lockdown(console)
            except Exception:
                pass

        if not deploy_ok:
            raise click.ClickException(
                f"Deployment to {tee_platform} did not complete. "
                f"Build dir: {os.path.abspath(build_dir)}")

        # Checked last, on purpose.  The infrastructure and the attestation are
        # fine here — what is not fine is that the workload will refuse every
        # request, because its SIEM channel is dark and this platform arms the
        # in-TEE fail-closed gate.  Running the check here rather than aborting
        # at sidecar-install time keeps the attestation evidence and the signed
        # provenance (step 8g runs after the sidecar install), and one seam
        # means a newly added platform phase cannot forget it.
        _siem_blocked = siem_export_blocked_deploy(audit)
        if _siem_blocked and deploy:
            raise click.ClickException(
                f"Deployed, but {_siem_blocked} will not serve traffic: the "
                f"SIEM exporter never confirmed a delivery and the in-TEE "
                f"fail-closed gate refuses every request while the channel is "
                f"dark. Fix the collector path and redeploy, or set "
                f'"fail_open": true in the --siem-config to accept an '
                f"unaudited workload. Build dir: {os.path.abspath(build_dir)}")


def _deploy_nitro_container(
    build_dir, cpu, ram, instance_type, do_deploy, auto_approve,
    teardown, source_summary, audit, custom_ami,
) -> bool:
    """Nitro EIF build + deploy for container mode.  Returns success."""
    from tee_crafter.cli.deployment import run_nitro_deployment_phase

    docker_platform = resolve_docker_platform("nitro-aws", instance_type, cpu, ram)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console, transient=False,
    ) as progress:
        hashes = run_phases_5_to_6(progress, audit, build_dir, cpu, ram,
                                    instance_type=instance_type,
                                    docker_platform=docker_platform)
        if hashes is None:
            return False

    # Same early disk reclaim as CVM: EIF build no longer references the pipeline user image.
    from tee_crafter.cli.deployment.common.local_docker_prune import prune_pipeline_local_image

    prune_pipeline_local_image(build_dir)

    _record_resume_manifest(build_dir, "nitro-aws", cpu, ram, hashes, custom_ami)

    if do_deploy:
        try:
            return run_nitro_deployment_phase(
                console=console, build_dir=build_dir, cpu=cpu, ram=ram,
                hashes=hashes, auto_approve=auto_approve, teardown=teardown,
                source_code=source_summary,
                audit=audit, custom_ami=custom_ami,
            )
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Ctrl+C. Attempting cleanup...[/bold yellow]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console, transient=False,
            ) as progress:
                task = progress.add_task("[yellow]Running terraform destroy...[/yellow]", total=None)
                ok = cleanup_resources(console, build_dir, context="Destroy (Nitro Container)")
                progress.update(
                    task,
                    description="[green]✓ Destroyed.[/green]" if ok else "[bold red]✗ Destroy failed.[/bold red]",
                )
            raise click.Abort()
    else:
        save_audit_trail(audit, build_dir, console)
        console.print(
            f"\n[bold green]Container Nitro phases complete (no deployment).[/bold green]\n"
            f"Build dir: [cyan]{os.path.abspath(build_dir)}[/cyan]\n"
            f"Run with [bold]--deploy --auto-approve[/bold] to apply Terraform.\n"
        )
    return True


def _deploy_sgx_container(
    build_dir, cpu, ram, instance_type, do_deploy, auto_approve,
    teardown, source_summary, audit, custom_ami,
) -> bool:
    """SGX/Gramine deploy for container mode: RA-TLS enclave + Docker sidecar."""
    from tee_crafter.core.builder.platforms import (
        render_gramine_manifest, stage_sgx_artifacts,
        render_sgx_client_template,
    )
    from tee_crafter.core.enclave import sign_gramine_manifest
    from tee_crafter.core.iac import stage_sgx_terraform, verify_terraform_syntax
    from tee_crafter.core.audit import sha256_hex
    from tee_crafter.cli.deployment import run_sgx_deployment_phase
    from tee_crafter.cli.commands.deploy.platform import _extract_user_code

    def _load_template(name):
        tpl_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "templates",
        )
        with open(os.path.join(tpl_dir, name), "r", encoding="utf-8") as f:
            return f.read()

    effective_vm = instance_type or os.getenv("TF_VAR_vm_size") or "Standard_DC2s_v3"
    if not effective_vm.startswith("Standard_DC"):
        console.print(Panel.fit(
            "[bold red]SGX requires an Azure DCsv3/DCdsv3 VM[/bold red]\n\n"
            f"VM size [yellow]{effective_vm}[/yellow] does not expose /dev/sgx_enclave.",
            border_style="red",
        ))
        audit.record("Pipeline Config", "SGX VM size invalid", "fail", instance_type=effective_vm)
        return False

    app_vsock_path = os.path.join(build_dir, "app_vsock.py")
    if not os.path.isfile(app_vsock_path):
        console.print("[bold red]Error:[/bold red] Container flow did not produce app_vsock.py")
        return False
    with open(app_vsock_path, "r", encoding="utf-8") as f:
        vsock_code = f.read()

    user_imports, user_logic = _extract_user_code(vsock_code)
    gramine_code = _load_template(os.path.join("sgx", "app_gramine.template.py"))
    gramine_code = gramine_code.replace("{user_imports}", user_imports).replace("{user_logic}", user_logic)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console, transient=False,
    ) as progress:
        task = progress.add_task("[yellow]SGX Phase 2: Generating Gramine manifest...[/yellow]", total=None)
        sgx_enclave_mb = min(ram, 1024) if ram >= 256 else 256
        manifest_content = render_gramine_manifest(enclave_size=f"{sgx_enclave_mb}M", max_threads=max(8, cpu * 4))
        progress.update(task, description="[green]✓ SGX Phase 2: Gramine manifest generated.[/green]")

        task = progress.add_task("[yellow]SGX Phase 2: Staging SGX container artifacts...[/yellow]", total=None)
        sgx_build_dir = stage_sgx_artifacts(
            source_dir=os.path.abspath(os.path.join(build_dir, "app")),
            gramine_code=gramine_code,
            manifest_content=manifest_content,
            existing_build_dir=build_dir,
        )
        audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir=sgx_build_dir)
        progress.update(task, description="[green]✓ SGX Phase 2: Container + Gramine artifacts staged.[/green]")
        audit.record(
            "Phase 2: SGX Packaging", "Container Gramine app staged", "pass",
            gramine_app_sha256=sha256_hex(gramine_code),
            manifest_sha256=sha256_hex(manifest_content),
        )

        task = progress.add_task("[yellow]SGX Phase 2b: Signing Gramine manifest (local)...[/yellow]", total=None)
        sign_ok, measurements, sign_msg = sign_gramine_manifest(sgx_build_dir)
        if not sign_ok:
            # Fatal.  The old "skipped" branch left ``measurements`` empty,
            # which rendered the client with MRENCLAVE="unknown" and staged
            # Terraform with the same placeholder — i.e. an enclave nobody
            # can attest, shipped as a success.  The amd64 CLI image
            # (selected by ``main._resolve_cli_image`` for sgx-azure) bundles
            # gramine-sgx-sign, so reaching here means the toolchain is
            # genuinely missing rather than an expected arch fallback.
            progress.update(
                task,
                description="[bold red]✗ SGX Phase 2b: Gramine signing failed.[/bold red]")
            audit.record(
                "Phase 2: SGX Signing", "gramine-sgx-sign (local)", "fail",
                reason=sign_msg,
            )
            raise click.ClickException(
                f"Gramine manifest signing failed: {sign_msg}\n\n"
                "Without MRENCLAVE/MRSIGNER the client cannot verify the "
                "enclave and the Terraform binding would carry 'unknown'. "
                "Run this deploy from the amd64 CLI image (it ships "
                "gramine-sgx-sign), or install Gramine locally."
            )
        progress.update(task, description=f"[green]✓ SGX Phase 2b: {sign_msg}[/green]")
        audit.record("Phase 2: SGX Signing", "gramine-sgx-sign (local)", "pass", **measurements)

        task = progress.add_task("[yellow]SGX Phase 2c: Rendering client template...[/yellow]", total=None)
        client_code = render_sgx_client_template(
            mrenclave=measurements.get("MRENCLAVE", "unknown"),
            mrsigner=measurements.get("MRSIGNER", "unknown"),
        )
        with open(os.path.join(sgx_build_dir, "client_sgx.py"), "w", encoding="utf-8") as f:
            f.write(client_code)
        progress.update(task, description="[green]✓ SGX Phase 2c: Client template rendered.[/green]")

        task = progress.add_task("[yellow]SGX Phase 3: Generating SGX Terraform (Azure)...[/yellow]", total=None)
        sgx_tf = _load_template(os.path.join("sgx", "main.template.tf")).replace("__INSTANCE_TYPE__", effective_vm)
        stage_sgx_terraform(sgx_build_dir, sgx_tf, measurements)
        tf_ok, tf_msg = verify_terraform_syntax(sgx_build_dir)
        if not tf_ok:
            console.print(f"\n[bold yellow]Warning: Terraform syntax:[/bold yellow]\n{tf_msg}\n")
            progress.update(task, description="[yellow]! SGX Phase 3: Terraform generated but not fully validated.[/yellow]")
        else:
            progress.update(task, description="[green]✓ SGX Phase 3: Terraform generated and validated.[/green]")
        audit.record(
            "Phase 3: SGX IaC", "Terraform generated with MRENCLAVE binding", "pass",
            mrenclave=measurements.get("MRENCLAVE", "unknown"),
        )

    _record_resume_manifest(sgx_build_dir, "sgx-azure", cpu, ram, measurements,
                            custom_ami)

    if do_deploy:
        try:
            return run_sgx_deployment_phase(
                console=console, build_dir=sgx_build_dir, cpu=cpu, ram=ram,
                measurements=measurements, auto_approve=auto_approve,
                teardown=teardown, source_code=source_summary,
                audit=audit, custom_ami=custom_ami,
            )
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Ctrl+C. Attempting cleanup...[/bold yellow]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console, transient=False,
            ) as progress:
                task = progress.add_task("[yellow]Running terraform destroy...[/yellow]", total=None)
                ok = cleanup_resources(console, sgx_build_dir, context="Destroy (SGX Container)")
                progress.update(
                    task,
                    description="[green]✓ Destroyed.[/green]" if ok else "[bold red]✗ Destroy failed.[/bold red]",
                )
            raise click.Abort()
    else:
        save_audit_trail(audit, sgx_build_dir, console)
        console.print(
            f"\n[bold green]SGX container phases complete (no deployment).[/bold green]\n"
            f"Build dir: [cyan]{os.path.abspath(sgx_build_dir)}[/cyan]\n"
            f"MRENCLAVE: [magenta]{measurements.get('MRENCLAVE', 'pending-runtime')}[/magenta]\n"
            f"Run with [bold]--deploy --auto-approve[/bold] to apply Terraform.\n"
        )
    return True


def _deploy_cvm_container(
    build_dir, cpu, ram, instance_type, do_deploy, auto_approve,
    teardown, source_summary, audit, custom_ami,
    tee_platform, *, pinned_measurements=None,
) -> bool:
    """CVM deploy for container mode — reuses existing VM platform deploy.

    ``pinned_measurements`` (raw hex list from the bake-time registry) replaces
    the ``"unknown"`` TOFU placeholder in the rendered client so the
    post-deploy attestation check is bound to the vetted image.  SNP images may
    carry several entries (one per vCPU tier captured at bake time).
    """
    from tee_crafter.core.audit import sha256_hex
    from tee_crafter.core.iac import verify_terraform_syntax
    from tee_crafter.cli.commands.deploy.platform import (
        _load_template, _extract_user_code, _get_platform_fns,
        PLATFORM_CONFIGS, _INSTANCE_RULES,
    )
    from tee_crafter.core import catalog
    from tee_crafter.core.measurements import registry as _registry
    from tee_crafter.core.measurements.shapes import (
        SNP_VCPU_SENSITIVE_PLATFORMS, expected_host_gens,
        host_gen_is_selectable, instance_gen, instance_vcpu,
        variant_shape as _shape_of,
    )

    app_tpl, tf_tpl, client_file, default_inst, meas_init, meas_label, label = PLATFORM_CONFIGS[tee_platform]

    # Resolve the effective instance type: an explicit --instance-type / TF_VAR_*
    # env wins; otherwise fall back to the catalog default for the platform.
    env_override = None
    if tee_platform in _INSTANCE_RULES:
        env_override = os.getenv(_INSTANCE_RULES[tee_platform][0])
    effective_instance = (
        instance_type or env_override
        or catalog.default_instance_type(tee_platform) or default_inst
    )

    # Shape gate.  ``preflight._check_instance_shape`` already grades the same
    # effective value (including the TF_VAR_* override) before any spend; this
    # is the belt-and-braces copy for programmatic callers that bypass the CLI.
    if tee_platform in _INSTANCE_RULES:
        env_var, default, check_fn, err_msg = _INSTANCE_RULES[tee_platform]
        if not check_fn(effective_instance):
            console.print(Panel.fit(
                f"[bold red]{err_msg}[/bold red]\n\n[yellow]{effective_instance}[/yellow] is not valid.",
                border_style="red",
            ))
            return False

    # AMD SEV-SNP launch measurement can vary with CPU generation and vCPU
    # count.  When this image was pinned at bake time, the deploy may only use a
    # (generation, vCPU) shape whose digest was captured — otherwise the
    # post-deploy attestation / BYOK release would never match.  vCPU-independent
    # generations accept any size; unpinned images keep TOFU.
    if tee_platform in SNP_VCPU_SENSITIVE_PLATFORMS and pinned_measurements:
        want_vcpu = instance_vcpu(tee_platform, effective_instance)
        want_gen = instance_gen(tee_platform, effective_instance)
        if not _registry.accepts_shape(tee_platform, custom_ami, want_gen,
                                       want_vcpu,
                                       instance_type=effective_instance):
            caps = _registry.captured_variants(tee_platform, custom_ami)
            tiers = ", ".join(sorted({
                f"{_shape_of(v) or v.get('cpu_gen') or '?'}/{v.get('vcpu')} vCPU"
                for v in caps if v.get("vcpu") is not None
            })) or "(none)"
            console.print(Panel.fit(
                f"[bold red]No bake-time measurement for this shape[/bold red]\n\n"
                f"[yellow]{effective_instance}[/yellow] is {want_gen or '?'} / "
                f"{want_vcpu} vCPU, but the AMD SEV-SNP launch digest for "
                f"[magenta]{tee_platform}[/magenta] varies with CPU generation and "
                f"vCPU count; only these shapes were captured at bake:\n"
                f"  [cyan]{tiers}[/cyan]\n\n"
                f"Pick a captured shape, re-bake (set "
                f"[bold]TEE_CRAFTER_SNP_CAPTURE_VCPUS[/bold] to widen tiers), or pin "
                f"this shape with [bold]tee-crafter internal pin-measurement "
                f"--instance-type {effective_instance}[/bold].",
                border_style="red",
            ))
            return False
        _warn_if_host_gen_is_a_coin_flip(
            console, tee_platform, custom_ami, _registry,
            host_gen_is_selectable(tee_platform),
            expected_host_gens(tee_platform),
        )
    _warn_if_image_predates_bake_inputs(
        console, tee_platform, custom_ami, _registry)

    stage_fn, code_kwarg, render_client_fn, client_kwargs, stage_tf_fn, run_deploy_fn = _get_platform_fns(tee_platform)

    app_vsock_path = os.path.join(build_dir, "app_vsock.py")
    if not os.path.isfile(app_vsock_path):
        console.print("[bold red]Error:[/bold red] Container flow did not produce app_vsock.py")
        return False
    with open(app_vsock_path, "r", encoding="utf-8") as f:
        vsock_code = f.read()

    user_imports, user_logic = _extract_user_code(vsock_code)
    platform_code = _load_template(app_tpl).replace("{user_imports}", user_imports).replace("{user_logic}", user_logic)

    # The TDX evidence format is one decision shared by two programs: the app
    # produces that format and the client accepts only that format.  Both read
    # it from the same resolver so they cannot disagree — a guest producing
    # AzureGuest tokens for a client pinned to DCAP is exactly the mismatch that
    # aborted a live run, and it presents as "the server sent the wrong thing".
    if "{evidence_format}" in platform_code:
        from tee_crafter.core.builder.platforms import tdx_evidence_format

        _fmt = tdx_evidence_format()
        platform_code = platform_code.replace("{evidence_format}", _fmt)

        # The MAA endpoint decides who is allowed to vouch for this trust
        # domain, so it goes into the measured source rather than into the unit
        # environment: the host sets the environment and the host is outside the
        # TCB, so an env-supplied endpoint could be swung to an attacker's
        # MAA-shaped service. Baked, changing it changes the image.
        _maa = (os.environ.get("TEE_CRAFTER_MAA_ENDPOINT") or "").strip()
        if _fmt == "azure-guest" and not _maa:
            console.print(Panel.fit(
                "[bold red]TEE_CRAFTER_MAA_ENDPOINT is required for "
                "azure-guest evidence[/bold red]\n\n"
                "An Azure paravisor CVM cannot produce a DCAP quote, so its "
                "only verifiable evidence is an MAA token — and there is no "
                "safe default for which MAA instance gets to issue it.\n\n"
                "Set it to your provider, e.g. "
                "[cyan]https://sharedwus.wus.attest.azure.net[/cyan].",
                border_style="red",
            ))
            return False
        platform_code = platform_code.replace("{maa_endpoint}", _maa)

        # Open the NSG for MAA, or the TD cannot attest at all. The template's
        # egress is deny-all, so without this the AttestationClient call inside
        # the TD times out and the deploy fails at verify time — i.e. after the
        # VM has been paid for. Set here rather than left to the operator for
        # exactly that reason: it is not an independent choice, it is implied by
        # the evidence format.
        if _fmt == "azure-guest":
            os.environ.setdefault("TF_VAR_attest_maa_egress", "true")
            # Deliberately does NOT set TF_VAR_maa_service_tag_region: Azure
            # publishes no regional AzureAttestation tag, so any suffix we
            # invented would fail the apply. See the note above the imports.

    if tee_platform == "snp-azure" and client_kwargs is None:
        processor_family = "genoa" if "v6" in effective_instance else "milan"
        client_kwargs = {"measurement": "unknown", "processor_family": processor_family}

    cd_file = os.path.join(build_dir, "app", "container_digest.txt")
    if os.path.isfile(cd_file):
        with open(cd_file, "r", encoding="utf-8") as _cdf:
            _cd_val = _cdf.read().strip()
        if client_kwargs is None:
            client_kwargs = {}
        client_kwargs["container_digest"] = _cd_val

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console, transient=False,
    ) as progress:
        task = progress.add_task(f"[yellow]{label} Phase 2: Staging platform artifacts...[/yellow]", total=None)
        cvm_build_dir = stage_fn(
            source_dir=os.path.abspath(os.path.join(build_dir, "app")),
            **{code_kwarg: platform_code},
            existing_build_dir=build_dir,
        )

        audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir=cvm_build_dir)
        progress.update(task, description=f"[green]✓ {label} Phase 2: Platform artifacts staged.[/green]")
        audit.record(f"Phase 2: {label} Packaging", "Container app staged", "pass", app_sha256=sha256_hex(platform_code))

        measurements = dict(meas_init)
        # Auto-pin: replace the "unknown" TOFU placeholder with the vetted
        # launch measurement(s) captured for this image at bake time.
        if pinned_measurements:
            from tee_crafter.core.measurements import PLATFORM_MEASUREMENT_FIELD
            field = PLATFORM_MEASUREMENT_FIELD.get(tee_platform, "measurement")
            if client_kwargs is None:
                client_kwargs = {}
            client_kwargs[field] = pinned_measurements[0]
            # Only the SEV-SNP-family renderers take an allowlist: see
            # ``core/builder/platforms.py`` — render_snp_{aws,azure,gcp}_
            # client_template and render_gpu_cc_azure_client_template accept
            # ``measurements``; render_tdx_client_template,
            # render_tdx_gcp_client_template, render_gpu_cc_gcp_client_template
            # and render_gpu_cc_aws_client_template take
            # ``(mrtd|measurement, container_digest)`` only.  Passing the key
            # unconditionally raised TypeError on exactly those four platforms
            # the moment a pin existed, so `--ami-id` on a pinned TDX / GPU-CC
            # image could never render a client.
            if _renderer_accepts(render_client_fn, "measurements"):
                client_kwargs["measurements"] = pinned_measurements
                allowlisted = len(pinned_measurements)
            else:
                allowlisted = 1
            measurements[field] = pinned_measurements[0]
            audit.record(
                f"Phase 2: {label} Client",
                f"Client pinned to {allowlisted} bake-time measurement(s)",
                "pass", **{field: pinned_measurements[0]},
                allowlist_size=allowlisted,
                pins_available=len(pinned_measurements))
        # Measured-boot PCR references, for the platforms whose client compares
        # a PCR bundle rather than (only) a launch measurement.  Deliberately
        # outside the ``if pinned_measurements`` block above: gpu-cc-aws has no
        # launch measurement at all, so that block never runs for it and the
        # reference would never reach the client.
        #
        # ``expected_nitrotpm_pcrs`` (gpu-cc-aws) is compared against
        # hypervisor-signed values from a NitroTPM attestation document.
        # ``expected_vtpm_pcrs`` (gpu-cc-gcp) is compared against an *unsigned*
        # bundle the server publishes about itself -- a tripwire, not evidence,
        # which is why that client's real CPU anchor is its TDX quote.  Both
        # come from the same registry record, so one loop covers them.
        for _kwarg, _record_key, _what in (
            ("expected_nitrotpm_pcrs", "nitrotpm_pcrs", "NitroTPM measured boot"),
            ("expected_vtpm_pcrs", "vtpm_pcrs", "vTPM measured boot"),
        ):
            if not _renderer_accepts(render_client_fn, _kwarg):
                continue
            from tee_crafter.core.measurements import registry as _reg
            _rec = _reg.lookup(tee_platform, custom_ami) or {}
            _pcrs = _rec.get(_record_key) or {}
            if client_kwargs is None:
                client_kwargs = {}
            if _pcrs:
                client_kwargs[_kwarg] = ",".join(
                    f"{idx}:{_pcrs[idx]}" for idx in sorted(_pcrs, key=int))
                audit.record(
                    f"Phase 2: {label} Client",
                    f"Client pinned to bake-time {_what}",
                    "pass", pcrs=sorted(_pcrs, key=int))
            else:
                console.print(
                    f"[yellow]No {_what} PCRs recorded for this image. The "
                    "client cannot confirm the boot chain is the one this "
                    "image was baked with; re-bake to capture them.[/yellow]")
                audit.record(
                    f"Phase 2: {label} Client",
                    f"No {_what} reference available", "warn")
        task = progress.add_task(f"[yellow]{label} Phase 2b: Rendering client template...[/yellow]", total=None)
        client_code = render_client_fn(**client_kwargs)
        with open(os.path.join(cvm_build_dir, client_file), "w", encoding="utf-8") as f:
            f.write(client_code)
        progress.update(task, description=f"[green]✓ {label} Phase 2b: Client template rendered.[/green]")

        # Every platform with an Intel DCAP quote needs the collateral bundle,
        # not just the two TDX ones.  This gate used to be
        # ``("tdx-azure", "tdx-gcp")``, which is exactly the pair that already
        # had a QE-identity check -- so the two platforms that were *missing*
        # one (`sgx-azure`, `gpu-cc-gcp`) also got no collateral staged, and
        # widening the client-side check without widening this would have made
        # them fail closed with a bundle that was never going to arrive.
        if tee_platform in ("tdx-azure", "tdx-gcp", "sgx-azure", "gpu-cc-gcp"):
            from tee_crafter.core.attestation.tcb_collateral import (
                stage_tcb_collateral,
            )
            from tee_crafter.core.builder.runtime_modules import (
                copy_client_support_modules,
            )
            # The shared TCB evaluator must sit beside client.py: the client is
            # run with its own directory as cwd, so that directory is
            # sys.path[0].  Fatal if absent -- the client exits 1 without it,
            # which would turn a packaging mistake into "attestation always
            # fails" with the cause one directory away from the error.
            copy_client_support_modules(cvm_build_dir)
            qe_task = progress.add_task(
                f"[yellow]{label} Phase 2c: Fetching Intel PCS TCB collateral..."
                "[/yellow]",
                total=None,
            )
            ok, detail = stage_tcb_collateral(cvm_build_dir)
            if ok:
                progress.update(
                    qe_task,
                    description=(
                        f"[green]✓ {label} Phase 2c: TCB collateral bundled "
                        f"({detail}).[/green]"
                    ),
                )
                audit.record(
                    f"Phase 2: {label} Client",
                    "Intel PCS TCB collateral fetched and signature-verified",
                    "pass", summary=detail,
                )
            else:
                progress.update(
                    qe_task,
                    description=(
                        f"[yellow]! {label} Phase 2c: TCB collateral not staged "
                        f"({detail}). The client fails closed without it — "
                        "re-run with network access, or point "
                        "TEE_CRAFTER_PCS_BASE_URL at an internal PCS mirror."
                        "[/yellow]"
                    ),
                )
                audit.record(
                    f"Phase 2: {label} Client",
                    "Intel PCS TCB collateral fetched and signature-verified",
                    "fail", reason=detail,
                )

        task = progress.add_task(f"[yellow]{label} Phase 3: Generating Terraform...[/yellow]", total=None)
        tf_content = _load_template(tf_tpl).replace("__INSTANCE_TYPE__", effective_instance)
        stage_tf_fn(cvm_build_dir, tf_content, measurements)
        tf_ok, tf_msg = verify_terraform_syntax(cvm_build_dir)
        if not tf_ok:
            console.print(f"\n[bold yellow]Warning: Terraform syntax:[/bold yellow]\n{tf_msg}\n")
            progress.update(task, description=f"[yellow]! {label} Phase 3: Terraform generated but not fully validated.[/yellow]")
        else:
            progress.update(task, description=f"[green]✓ {label} Phase 3: Terraform generated and validated.[/green]")

    _record_resume_manifest(cvm_build_dir, tee_platform, cpu, ram, measurements,
                            custom_ami)

    if do_deploy:
        try:
            return run_deploy_fn(
                console=console, build_dir=cvm_build_dir, cpu=cpu, ram=ram,
                measurements=measurements, auto_approve=auto_approve,
                teardown=teardown, source_code=source_summary,
                audit=audit, custom_ami=custom_ami,
            )
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Ctrl+C. Attempting cleanup...[/bold yellow]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console, transient=False,
            ) as progress:
                task = progress.add_task("[yellow]Running terraform destroy...[/yellow]", total=None)
                ok = cleanup_resources(console, cvm_build_dir, context=f"Destroy ({label} Container)")
                progress.update(
                    task,
                    description="[green]✓ Destroyed.[/green]" if ok else "[bold red]✗ Destroy failed.[/bold red]",
                )
            raise click.Abort()
    else:
        save_audit_trail(audit, cvm_build_dir, console)
        meas_key = list(meas_init.keys())[0]
        console.print(
            f"\n[bold green]{label} container phases complete (no deployment).[/bold green]\n"
            f"Build dir: [cyan]{os.path.abspath(cvm_build_dir)}[/cyan]\n"
            f"{meas_label}: [magenta]{measurements.get(meas_key, 'pending-runtime')}[/magenta]\n"
            f"Run with [bold]--deploy --auto-approve[/bold] to apply Terraform.\n"
        )
    return True


def register(cli):
    """Register ``tee-crafter deploy-container``.

    This is a back-compat alias for ``tee-crafter deploy`` (identical command
    body). It is registered ``hidden=True`` so the canonical ``deploy`` is the
    only one surfaced in ``--help``; existing scripts/examples that still call
    ``deploy-container`` keep working.
    """
    register_deploy(cli, command_name="deploy-container", hidden=True)
