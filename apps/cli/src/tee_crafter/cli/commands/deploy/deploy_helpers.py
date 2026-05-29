"""Shared helpers for the unified ``tee-crafter deploy`` command."""

from __future__ import annotations

import os

from tee_crafter.cli.constants import Panel, console
from tee_crafter.cli.commands.deploy.validators import (
    ALLOW_NO_SECURE_BOOT_ENV,
    SecureBootUndetermined,
    validate_custom_ami_architecture,
    propagate_secure_boot_var_from_ami,
)
from tee_crafter.core import catalog
from tee_crafter.core.env_flags import env_hatch_open
from tee_crafter.core.pinned_image_env import (
    PLATFORM_PINNED_IMAGE_ENV,
    arch_pinned_image_env_key,
    effective_pinned_image_from_env,
)

PLATFORM_LABELS = {
    "nitro-aws": "Nitro Enclave (AWS)",
    "sgx-azure": "SGX/Gramine Enclave (Azure)",
    "tdx-azure": "TDX Confidential VM (Azure)",
    "snp-aws": "AMD SEV-SNP Confidential VM (AWS)",
    "snp-azure": "AMD SEV-SNP Confidential VM (Azure)",
    "snp-gcp": "AMD SEV-SNP Confidential VM (GCP)",
    "tdx-gcp": "Intel TDX Confidential VM (GCP)",
    "gpu-cc-gcp": "NVIDIA CC + Intel TDX Confidential GPU VM (GCP)",
    "gpu-cc-azure": "NVIDIA CC + AMD SEV-SNP Confidential GPU VM (Azure)",
    "gpu-cc-aws": "NVIDIA CC + NitroTPM GPU VM (AWS, weaker model)",
}

# Hard cap on the bundle the TEE is allowed to ship back.
_DEFAULT_MAX_OUTPUT_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB

# Env keys that carry the deploy region per cloud (first non-empty wins).
_REGION_ENV_BY_CLOUD = {
    "aws": ("TF_VAR_aws_region", "AWS_REGION", "AWS_DEFAULT_REGION"),
    "azure": ("TF_VAR_azure_location", "AZURE_LOCATION"),
    "gcp": ("TF_VAR_gcp_region", "TF_VAR_region", "GOOGLE_REGION",
            "CLOUDSDK_COMPUTE_REGION"),
}

_RESIDENCY_POLICY_ENV = "TEE_CRAFTER_RESIDENCY_POLICY"


def _cloud_of(tee_platform: str) -> str:
    for suffix, cloud in (("-aws", "aws"), ("-azure", "azure"), ("-gcp", "gcp")):
        if tee_platform.endswith(suffix):
            return cloud
    return ""


def _region_from_env(cloud: str) -> str:
    for key in _REGION_ENV_BY_CLOUD.get(cloud, ()):  # type: ignore[arg-type]
        val = os.environ.get(key, "").strip()
        if val:
            return val
    return ""


def enforce_residency_gate(console_, audit, tee_platform: str) -> bool:
    """Fail-closed data-residency gate, run before any cloud resources exist.

    Residency was previously *advisory* — the operator had to remember to run
    ``tee-crafter residency-check`` out of band, and nothing stopped ``deploy``
    from landing compute/buckets/KMS in a forbidden region. This wires the same
    :func:`validate_deployment` engine into the deploy path: when
    ``TEE_CRAFTER_RESIDENCY_POLICY`` points at a policy JSON, the chosen
    cloud/region is validated *before* Terraform apply and the deploy aborts on
    a violation (and records ``RES-001``). When the env var is unset the gate is
    a no-op, preserving the default behaviour.

    Returns ``True`` to proceed, ``False`` to abort the deploy.
    """
    policy_path = os.environ.get(_RESIDENCY_POLICY_ENV, "").strip()
    if not policy_path:
        return True  # residency not enforced for this deploy

    from tee_crafter.core.compliance.residency import (
        ResidencyPolicy, validate_deployment,
    )

    cloud = _cloud_of(tee_platform)
    region = _region_from_env(cloud)

    def _abort(reason: str) -> bool:
        console_.print(Panel.fit(
            f"[bold red]REFUSING TO DEPLOY: residency policy violation[/bold red]\n\n"
            f"{reason}\n\n"
            f"Policy: {policy_path}\n"
            f"Platform: {tee_platform}  Cloud: {cloud or '?'}  Region: {region or '(unset)'}\n\n"
            "Set the deploy region inside your residency boundary, or adjust the "
            f"policy. Unset {_RESIDENCY_POLICY_ENV} to disable residency enforcement.",
            border_style="red"))
        if audit:
            audit.record_check(
                "Phase 0", "Deployment region within residency policy", "RES-001",
                observed=False, note=reason[:200],
                tee_platform=tee_platform,
            )
        return False

    if not cloud:
        return _abort(f"could not infer cloud from tee_platform {tee_platform!r}")
    if not region:
        return _abort(
            "no deploy region is set; cannot prove residency. Export the "
            f"region env for {cloud} (one of {_REGION_ENV_BY_CLOUD.get(cloud)}).")

    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            import json as _json
            raw = _json.load(f)
        policy = ResidencyPolicy(
            allowed_regions=[tuple(p) for p in raw.get("allowed_regions", [])],
            allowed_countries=list(raw.get("allowed_countries", [])),
            allowed_jurisdictions=list(raw.get("allowed_jurisdictions", [])),
            allowed_regimes=list(raw.get("allowed_regimes", [])),
            forbid_cross_region_replication=bool(
                raw.get("forbid_cross_region_replication", True)),
            forbid_offshore_storage=bool(raw.get("forbid_offshore_storage", True)),
            require_signed_evidence=bool(raw.get("require_signed_evidence", True)),
            note=str(raw.get("note", "")),
        )
    except Exception as exc:
        return _abort(f"could not load residency policy {policy_path}: {exc}")

    try:
        validation = validate_deployment(
            cloud=cloud, primary_region=region, policy=policy)
    except KeyError:
        return _abort(f"region {region!r} is unknown for cloud {cloud!r} "
                      "(cannot classify jurisdiction — failing closed)")

    if not validation.primary_allowed:
        return _abort(validation.primary_reason or
                      f"region {region} is outside the residency policy")

    console_.print(
        f"[green]✓ Residency: {region} ({validation.primary.jurisdiction}) "
        f"within policy.[/green]")
    if audit:
        audit.record_check(
            "Phase 0", "Deployment region within residency policy", "RES-001",
            observed=True,
            note=f"{cloud}:{region} jurisdiction={validation.primary.jurisdiction}",
            tee_platform=tee_platform,
        )
    return True

_INTERNAL_UNBAKED_ENV = "TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI"

_TEE_PLATFORM_CHOICES = [
    "nitro-aws", "sgx-azure", "tdx-azure", "snp-aws", "snp-azure",
    "snp-gcp", "tdx-gcp", "gpu-cc-gcp", "gpu-cc-azure", "gpu-cc-aws",
]


def _resolve_ami_id(
    *, ami_id: str | None, tee_platform: str, deploy: bool,
    audit, cpu: int, ram: int, instance_type: str | None,
    siem_opens_egress: bool = False,
) -> str | None:
    """Resolve the AMI/image to deploy onto.

    *siem_opens_egress* is the caller's answer to "will a ``--siem`` export open
    the NAT path later in this run?"  It exists only so the pinned-image panel
    below can state the posture this deploy will actually have.  The SIEM module
    overrides ``TF_VAR_allow_setup_egress`` after the container build, which is
    well past this point, so without being told this function cannot know — and
    it used to print "Locked down" on runs that went on to get a NAT gateway and
    a default route.  Defaults to ``False`` for callers with no SIEM stage at all
    (e.g. ``deploy-from-build``).
    """
    # Pass the effective instance type so nitro-aws can pick the AMI that
    # matches the host architecture (AWS_NITRO_AMI_ARM64 vs
    # AWS_NITRO_AMI_X86_64).  TF_VAR_instance_type is included because Terraform
    # reads it directly, so it decides the architecture even when
    # --instance-type was never passed.
    pinned = effective_pinned_image_from_env(
        tee_platform,
        cli_or_explicit=ami_id,
        instance_type=(instance_type or os.getenv("TF_VAR_instance_type")
                       or catalog.default_instance_type(tee_platform)),
    )

    is_gcp = tee_platform in ("snp-gcp", "tdx-gcp", "gpu-cc-gcp")
    is_azure = tee_platform in ("sgx-azure", "tdx-azure", "snp-azure", "gpu-cc-azure")

    if pinned:
        if is_gcp:
            os.environ["TF_VAR_custom_image"] = pinned
        elif is_azure:
            os.environ["TF_VAR_custom_image_id"] = pinned
        else:
            os.environ["TF_VAR_custom_ami_id"] = pinned
            eff = instance_type or os.getenv("TF_VAR_instance_type")
            if not validate_custom_ami_architecture(pinned, eff):
                audit.record("Pipeline Config", "Pinned AMI architecture check", "fail")
                return None
            # Nitro AMIs are generic: the enclave allocator (memory_mib +
            # cpu_count) is rewritten to this deploy's enclave shape at launch
            # (see nitro/allocator.py), so a single AMI baked on the default
            # host runs on any instance size — no baked capacity cap to enforce.
            if tee_platform in ("nitro-aws", "snp-aws"):
                try:
                    sb_mode = propagate_secure_boot_var_from_ami(pinned)
                except SecureBootUndetermined as exc:
                    audit.record(
                        "Pipeline Config",
                        "UEFI Secure Boot posture from AMI tag", "fail",
                        secure_boot="undetermined", reason=str(exc)[:300],
                    )
                    console.print(Panel.fit(
                        f"[bold red]UEFI Secure Boot is not proven for this image"
                        f"[/bold red]\n\n{exc}\n\n"
                        "Re-bake with [cyan]tee-crafter internal bake-ami "
                        f"--tee-platform {tee_platform} --enable-secure-boot[/cyan], "
                        "or accept the weaker posture explicitly with\n"
                        f"  [cyan]{ALLOW_NO_SECURE_BOOT_ENV}=1[/cyan]\n"
                        "(the override is recorded in the build provenance).",
                        border_style="red"))
                    return None
                # The verdict grades whether Secure Boot is ON, not merely
                # whether a value could be determined.
                audit.record(
                    "Pipeline Config",
                    "UEFI Secure Boot posture from AMI tag",
                    "pass" if sb_mode == "true" else "warn",
                    secure_boot=sb_mode,
                    override=(sb_mode != "true"),
                    override_env=(ALLOW_NO_SECURE_BOOT_ENV
                                  if sb_mode != "true" else ""),
                )
        # The pinned image needs no first-boot package installs, so the baseline
        # is locked down.  A --siem export may still reopen it below; that is
        # reported rather than silently overwriting this line's claim.
        os.environ["TF_VAR_allow_setup_egress"] = "false"
        cloud = "GCP" if is_gcp else "Azure" if is_azure else "AWS"
        egress_line = (
            "[yellow]NAT gateway (opened for --siem export)[/yellow]"
            if siem_opens_egress else "[green]Locked down[/green]"
        )
        console.print(Panel.fit(
            f"[bold green]Pinned image ({cloud} — {tee_platform.upper()})[/bold green]\n\n"
            f"Image: [cyan]{pinned}[/cyan]\nCloud-init: [green]Skipped[/green]\n"
            f"Setup egress: {egress_line}",
            border_style="green",
        ))
        audit.record("Pipeline Config", "AMI pinned", "pass", ami_id=pinned,
                     setup_egress=("nat-for-siem" if siem_opens_egress
                                   else "locked-down"))
        return pinned

    if not deploy:
        return ""

    dev_unbaked = env_hatch_open(_INTERNAL_UNBAKED_ENV)
    if dev_unbaked:
        os.environ["TF_VAR_allow_setup_egress"] = "true"
        if tee_platform in ("nitro-aws", "snp-aws"):
            os.environ.setdefault("TF_VAR_enable_secure_boot", "false")
        from tee_crafter.cli.deployment.common.wheel_manager import warn_unbaked_deploy
        warn_unbaked_deploy(console)
        audit.record("Pipeline Config", "AMI pinning bypassed (internal dev only)", "warn")
        return ""

    # Name the exact variable this deploy needs.  ``nitro-aws`` has one pin per
    # CPU architecture, so "set the per-platform variable" is not actionable
    # advice there — an operator who set the x86_64 pin and then chose a
    # Graviton host needs to be told *which* of the two is missing, and that
    # the bake needs a matching --instance-type to produce it.
    eff_type = (instance_type or os.getenv("TF_VAR_instance_type")
                or catalog.default_instance_type(tee_platform))
    arch_key = arch_pinned_image_env_key(tee_platform, eff_type)
    if arch_key:
        arch = catalog.instance_architecture(eff_type)
        bake_type = "c7g.xlarge" if arch == "arm64" else "c6a.xlarge"
        sb_flag = " --no-enable-secure-boot" if arch == "arm64" else ""
        detail = (
            f"{tee_platform} pins one AMI per CPU architecture, and "
            f"[cyan]{eff_type}[/cyan] is [bold]{arch}[/bold].\n\n"
            f"Bake it with:\n\n"
            f"  [cyan]tee-crafter internal bake-ami --tee-platform "
            f"{tee_platform} \\\n     --instance-type {bake_type}{sb_flag}[/cyan]\n\n"
            f"then set [cyan]{arch_key}[/cyan] in your .env "
            f"(or pass [cyan]--ami-id <id>[/cyan] for this run)."
        )
    else:
        plat_key = PLATFORM_PINNED_IMAGE_ENV.get(tee_platform, "")
        detail = (
            "Bake one with:\n\n"
            "  [cyan]tee-crafter internal bake-ami --tee-platform "
            f"{tee_platform}[/cyan]\n\n"
            "then set "
            + (f"[cyan]{plat_key}[/cyan] in your .env"
               if plat_key else "the per-platform variable in your .env")
            + " (or pass [cyan]--ami-id <id>[/cyan] for this run)."
        )

    console.print(Panel.fit(
        "[bold red]AMI required[/bold red]\n\n"
        # NB: no square brackets around the flag name — Rich reads "[--deploy]"
        # as a markup tag and silently swallows it, so this line rendered as
        # " needs a pinned, hardened image." with the subject missing.
        "[cyan]--deploy[/cyan] needs a pinned, hardened image.\n\n"
        f"{detail}\n\n"
        "[dim]A global [cyan]TEE_CRAFTER_AMI_ID[/cyan] also works, but it "
        "ignores architecture — prefer the variable named above.[/dim]",
        border_style="red",
    ))
    audit.record("Pipeline Config", "AMI requirement not satisfied", "fail")
    return None


#: ``deploy --batch-timeout``'s Click default.  Used to tell "operator typed a
#: timeout" apart from "Click filled in the default" without threading a
#: ``click.Context`` down here.
DEFAULT_BATCH_TIMEOUT = 3600


def validate_flag_dependencies(
    *,
    batch_mode: bool,
    persistent_mode: bool,
    container_cmd: str | None,
    batch_timeout: int,
    input_dir: str | None,
    siem_provider: str,
    siem_config_path: str | None,
    byok_provider: str,
    byok_policy_path: str | None,
) -> None:
    """Reject options whose gating flag is absent, instead of ignoring them.

    Every option below was previously accepted, parsed, and then dropped on the
    floor because the code path that reads it never ran.  ``--siem-config``
    without ``--siem`` is the worst of them: the operator hands the CLI a file
    full of SIEM endpoints and tokens, the deploy succeeds, and no attestation
    events are ever exported — the failure only shows up as an empty SIEM index
    days later.  Nothing here needs the network or a build directory.

    ``build_siem_config`` / ``build_byok_config`` already cover the opposite
    direction (provider set, config file missing); this closes the other half.

    Raises :class:`click.ClickException` so the CLI exits non-zero.
    """
    import click as _click

    if container_cmd:
        raise _click.ClickException(
            "--container-cmd is not supported.\n\n"
            "TEE-Crafter runs your OCI image as-is so the measured image and "
            "the image you tested are the same artifact; there is no hook that "
            "rewrites its CMD. Set the command in your Dockerfile's CMD / "
            "ENTRYPOINT and rebuild.\n\n"
            "(This flag used to be accepted and then silently ignored.)"
        )

    if (siem_provider or "none").lower() == "none" and siem_config_path:
        raise _click.ClickException(
            f"--siem-config {siem_config_path} was given but --siem is 'none', "
            "so no SIEM exporter would be configured and the file would be "
            "ignored.\n\n"
            "Pass the provider too, e.g. --siem splunk-hec --siem-config "
            f"{siem_config_path}"
        )

    if (byok_provider or "none").lower() == "none" and byok_policy_path:
        raise _click.ClickException(
            f"--byok-config {byok_policy_path} was given but --byok is 'none', "
            "so no customer-managed key would be wired up and the file would be "
            "ignored.\n\n"
            "Pass the provider too, e.g. --byok aws-kms --byok-config "
            f"{byok_policy_path}"
        )

    # --batch-timeout / --input-dir are only read by the batch dispatcher.
    if persistent_mode and not batch_mode:
        if batch_timeout != DEFAULT_BATCH_TIMEOUT:
            raise _click.ClickException(
                f"--batch-timeout {batch_timeout} requires --batch; it has no "
                "effect on a --persistent service, which runs until you tear it "
                "down.\n\n"
                "For a persistent service, bound the run with --teardown or "
                "`tee-crafter destroy --build-dir <dir>`."
            )
        if input_dir:
            raise _click.ClickException(
                f"--input-dir {input_dir} requires --batch; the persistent "
                "service flow never uploads it.\n\n"
                "Bake the data into your image, or send it to the service over "
                "the attested RA-TLS ingress once it is up."
            )


def validate_run_mode(
    *,
    batch_mode: bool,
    persistent_mode: bool,
    tee_platform: str,
    service_profile: str,
) -> tuple[bool, str]:
    """Validate --batch / --persistent / platform constraints.

    Returns ``(ok, effective_service_profile)``.
    """
    if batch_mode and persistent_mode:
        console.print(Panel.fit(
            "[bold red]--batch and --persistent are mutually exclusive[/bold red]\n\n"
            "Pick one run mode. See docs/execution_model.md.",
            border_style="red",
        ))
        return False, service_profile

    if not batch_mode and not persistent_mode:
        console.print(Panel.fit(
            "[bold red]Run mode required[/bold red]\n\n"
            "Pass exactly one of [cyan]--batch[/cyan] (one-shot job, "
            "output.tar.gz) or [cyan]--persistent[/cyan] (long-lived service "
            "behind the attested proxy). There is no default.",
            border_style="red",
        ))
        return False, service_profile

    if tee_platform == "sgx-azure" and not batch_mode:
        console.print(Panel.fit(
            "[bold red]Intel SGX (sgx-azure) is batch-only for v1[/bold red]\n\n"
            "Pass [cyan]--batch[/cyan] to run your Dockerfile to completion "
            "via GSC + the batch collector, or pick a VM-class TEE for "
            "[cyan]--persistent[/cyan] services.",
            border_style="red",
        ))
        return False, service_profile

    profile = service_profile
    if persistent_mode and profile == "default":
        profile = "long-lived"

    return True, profile
