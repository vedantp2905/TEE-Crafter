"""Deploy-from-build: finish or redeploy an existing build directory.

Two jobs, and they used to be one:

* **Redeploy** a completed build directory onto fresh infrastructure.
* **Resume** a deploy whose ``terraform apply`` died partway. The build
  directory holds a valid ``terraform.tfstate``, so re-applying converges the
  resources that were already created instead of abandoning them.

The second job did not work, for a reason that only showed up after spending
money: this command hardcoded ``tee_platform="nitro-aws"`` and required an
``app.eif``, so pointing it at any confidential-VM build directory failed with
``app.eif not found`` — *after* an apply had already created the VM, the Bastion,
the VNet and the storage account. Destroy-and-redeploy was the only way forward.

It now dispatches on the platform recorded in the build directory by
:mod:`~tee_crafter.cli.commands.deploy.resume_manifest`, and restores the
``TF_VAR_*`` environment from the same file so the resumed apply plans what the
original apply planned.
"""

import os
import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.core.enclave import get_enclave_hashes
from tee_crafter.cli.deployment.common.terraform_step import cleanup_resources
from tee_crafter.core.audit import BuildAuditTrail, verify_ledger_signature
from tee_crafter.cli.constants import console, KEEP_ON_FAILURE_ENV, PIPELINE_VERSION
from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.cli.commands.deploy.deploy_helpers import _resolve_ami_id
from tee_crafter.cli.commands.deploy.platform import (
    RESUMABLE_PLATFORMS, deployment_phase_for,
)
from tee_crafter.cli.commands.deploy import resume_manifest
from tee_crafter.core.env_flags import env_hatch_open


def resolve_target_platform(build_dir: str) -> tuple[str, dict]:
    """Return ``(tee_platform, manifest)`` for *build_dir*, or raise.

    Fails closed on three separate things, because each one silently produced a
    wrong deploy before:

    1. **No platform recorded at all.** Refuse rather than assume. The previous
       assumption was ``nitro-aws``, which is why a TDX build directory reported
       a missing ``app.eif``.
    2. **A platform this command cannot drive.** Names it, and lists the ten it
       can.
    3. **A non-Nitro platform with no manifest** — only ``build_provenance.json``
       named the platform. That file has no launch measurements, and on
       ``sgx-azure``, ``snp-gcp`` and ``gpu-cc-azure`` the measurements are not
       decoration: SGX uploads them to the VM as ``measurements.json`` and the
       other two hand them to the client runner. Guessing ``{}`` would weaken
       the check instead of failing, so refuse. ``nitro-aws`` is exempt because
       its PCRs are recomputed from ``app.eif`` a few lines below.
    """
    platform, source = resume_manifest.resolve_platform(build_dir)
    if not platform:
        raise click.ClickException(
            f"Cannot tell which TEE platform {build_dir} was built for.\n\n"
            f"Neither {resume_manifest.MANIFEST_NAME} nor "
            f"provenance/build_provenance.json is present, and the directory "
            f"name is not authoritative (a Nitro build dir is named "
            f"'..._container_nitro_build_...' while the platform is "
            f"'nitro-aws').\n\n"
            f"Refusing to guess: guessing 'nitro-aws' is exactly the bug this "
            f"replaced. Re-run `tee-crafter deploy` for this source instead."
        )
    if platform not in RESUMABLE_PLATFORMS:
        raise click.ClickException(
            f"{build_dir} records tee_platform={platform!r}, which has no "
            f"deployment phase.\n\nSupported: {', '.join(RESUMABLE_PLATFORMS)}"
        )
    manifest = resume_manifest.read_manifest(build_dir) or {}
    if not manifest and platform != "nitro-aws":
        raise click.ClickException(
            f"{build_dir} was built for {platform} but has no "
            f"{resume_manifest.MANIFEST_NAME} (the platform came from "
            f"{source}).\n\n"
            f"That file carries the launch measurements and the TF_VAR_* "
            f"environment this deploy needs. Without the measurements "
            f"{platform} would deploy with an empty measurement set, which "
            f"weakens the attestation check rather than failing it; without the "
            f"TF_VAR_* values Terraform would fall back to variable defaults "
            f"and converge the existing state onto a different plan.\n\n"
            f"Re-run `tee-crafter deploy` instead. Build directories created "
            f"before {resume_manifest.MANIFEST_NAME} existed cannot be resumed."
        )
    console.print(
        f"[dim]Platform: [bold]{platform}[/bold] (from {source})[/dim]")
    return platform, manifest


def restore_terraform_env(manifest: dict) -> None:
    """Put the recorded ``TF_VAR_*`` environment back, and say what changed.

    Silence here would be the worst option: a resume that plans differently from
    the apply it is resuming looks identical to one that does not.
    """
    restored, overridden, cleared = resume_manifest.apply_tf_vars(manifest)
    if restored:
        console.print(
            f"[dim]Restored {len(restored)} TF_VAR_* value(s) from "
            f"{resume_manifest.MANIFEST_NAME}.[/dim]")
    for name, ambient, recorded in overridden:
        console.print(
            f"[yellow]{name}: using the recorded {recorded!r}, not the "
            f"{ambient!r} in this environment. A resume converges the existing "
            f"Terraform state; run `tee-crafter deploy` to change it."
            f"[/yellow]")
    if cleared:
        console.print(
            f"[yellow]Unset {', '.join(cleared)}: not set when this build's "
            f"Terraform was applied, so the half-applied plan never had "
            f"it.[/yellow]")


def _nitro_pcrs(build_dir: str, audit) -> dict:
    """Re-measure ``app.eif`` into PCR0/1/2 for a Nitro resume.

    Nitro is the one platform whose measurements do not need to come from the
    manifest: they are a pure function of the EIF sitting in the build
    directory, which is also the artefact ``verify_build_integrity`` has just
    authenticated.  Recomputing is strictly better than trusting a recorded
    copy — a swapped EIF changes the PCRs here and the deploy stops.
    """
    eif_path = os.path.join(build_dir, "app.eif")
    if not os.path.exists(eif_path):
        raise click.ClickException(
            f"app.eif not found in {build_dir}.\n\n"
            "This build directory records tee_platform=nitro-aws, whose enclave "
            "image is the thing being deployed. Re-run `tee-crafter deploy` to "
            "rebuild it."
        )
    audit.record_file_hash("Pre-Deploy Validation", "EIF artifact", eif_path)
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  console=console, transient=False) as progress:
        task_hash = progress.add_task(
            "[yellow]Extracting PCR hashes from EIF...[/yellow]", total=None)
        success, hashes, msg = get_enclave_hashes(eif_path)
        if not success:
            progress.update(
                task_hash,
                description="[bold red]✗ Failed to get hashes.[/bold red]")
            console.print(f"[red]Error:[/red]\n{msg}")
            audit.record("Pre-Deploy Validation", "PCR hash extraction", "fail")
            save_audit_trail(audit, build_dir, console)
            raise click.ClickException(
                f"Could not extract PCR hashes from {eif_path}")
        progress.update(task_hash,
                        description="[green]✓ PCR hashes extracted.[/green]")
        audit.record("Pre-Deploy Validation", "PCR hash extraction", "pass",
                     PCR0=hashes.get("PCR0", ""), PCR1=hashes.get("PCR1", ""),
                     PCR2=hashes.get("PCR2", ""))
    return hashes


def verify_build_integrity(build_dir: str, audit, *, skip: bool = False) -> None:
    """Verify the build directory's provenance before redeploying it.

    ``deploy-from-build`` deploys artefacts straight off local disk — an
    ``app.eif`` measured into a Nitro enclave, or a staged ``app/`` bundle
    uploaded to a confidential VM. The only thing binding those to the pipeline
    that produced them is ``build_provenance.json`` and its signature. Checking
    that the artefacts merely *exist* — which is all this command used to do —
    accepts a build dir whose payload was swapped after the fact.

    Delegates to the same helpers ``tee-crafter verify-provenance`` uses:
    :meth:`BuildAuditTrail.verify_chain` (hash chain),
    :meth:`BuildAuditTrail.verify_signature` (Ed25519 over the provenance
    document) and :func:`core.audit.ledger.verify_ledger_signature` (Ed25519
    over ``audit_evidence.json``, when the ledger sidecar is present).

    Raises :class:`click.ClickException` on any mismatch.
    """
    from tee_crafter.core.audit import build_layout as _layout

    prov_path = _layout.resolve_provenance_json(build_dir)
    if not os.path.isfile(prov_path):
        if skip:
            console.print(
                "[yellow]--skip-integrity-check: no build_provenance.json in "
                "this build dir; redeploying unverified artifacts.[/yellow]")
            audit.record("Pre-Deploy Validation", "Build provenance present",
                         "warn", reason="build_provenance.json missing (override)")
            return
        raise click.ClickException(
            f"No build_provenance.json in {build_dir}.\n\n"
            "This build directory cannot be authenticated, so the artifacts it "
            "would deploy cannot be trusted to be the ones the pipeline "
            "produced. Re-run `tee-crafter deploy` to build it, or pass "
            "--skip-integrity-check if you accept an unverified redeploy."
        )

    failures: list[str] = []
    chain_ok, chain_reason = BuildAuditTrail.verify_chain(prov_path)
    if not chain_ok:
        failures.append(f"hash chain: {chain_reason}")

    sig_ok, sig_reason = BuildAuditTrail.verify_signature(prov_path)
    if not sig_ok:
        failures.append(f"Ed25519 signature: {sig_reason}")

    ledger_path = _layout.resolve_audit_evidence_json(build_dir)
    if os.path.isfile(ledger_path):
        ledger_ok, ledger_reason = verify_ledger_signature(ledger_path)
        if not ledger_ok:
            failures.append(f"audit_evidence.json signature: {ledger_reason}")

    audit.record(
        "Pre-Deploy Validation", "Build directory provenance verified",
        "pass" if not failures else ("warn" if skip else "fail"),
        provenance=os.path.basename(prov_path),
        failures=failures or None,
    )
    if not failures:
        console.print(
            "[green]✓ Build provenance verified (hash chain + Ed25519).[/green]")
        return
    detail = "\n  - ".join(failures)
    if skip:
        console.print(
            f"[bold yellow]--skip-integrity-check: redeploying a build "
            f"directory that failed verification:[/bold yellow]\n  - {detail}")
        return
    raise click.ClickException(
        f"Build directory {build_dir} failed integrity verification:\n"
        f"  - {detail}\n\n"
        "Refusing to redeploy: the artifacts in this directory are not provably "
        "the ones the pipeline built and signed. Re-run `tee-crafter deploy`, "
        "or pass --skip-integrity-check if you accept an unverified redeploy."
    )


def register(cli):
    @cli.command()
    @click.option("--build-dir", required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True),
                  help="Path to the existing build directory")
    @click.option("--instance-type", "instance_type_opt", default=None, type=str,
                  envvar="TEE_CRAFTER_INSTANCE_TYPE",
                  help="Override the instance type / VM size. Defaults to the "
                       "shape this build directory was applied with. Changing it "
                       "makes this a redeploy rather than a resume, since "
                       "Terraform will replace the compute resource.")
    @click.option("--spot", "spot_opt", is_flag=True, default=None,
                  envvar="TEE_CRAFTER_SPOT",
                  help="Request a spot instance (AWS). Defaults to what this "
                       "build directory was applied with.")
    @click.option("--auto-approve", is_flag=True, default=False, help="Skip interactive approval for Terraform apply.")
    @click.option("--teardown", is_flag=True, default=False, help="Destroy resources after successful client run.")
    @click.option("--keep-on-failure", "keep_on_failure", is_flag=True, default=False,
                  envvar=KEEP_ON_FAILURE_ENV,
                  help="Leave provisioned infrastructure running when the deploy "
                       "fails, for debugging. Default is to tear it down.")
    @click.option("--skip-integrity-check", is_flag=True, default=False,
                  envvar="TEE_CRAFTER_SKIP_BUILD_INTEGRITY_CHECK",
                  help="Redeploy a build directory whose provenance hash chain or "
                       "Ed25519 signature does not verify. NOT for production: the "
                       "build dir is read straight off local disk, and what is in "
                       "it is what gets measured into the TEE.")
    @click.option(
        "--force-unlock", "force_unlock", is_flag=True, default=False,
        envvar="TEE_CRAFTER_FORCE_UNLOCK",
        help="Break a Terraform state lock left behind by an apply that was "
             "killed. Only pass this once you know no terraform process is "
             "still running against this build directory.",
    )
    @click.option(
        "--ami-id", "ami_id", default=None, type=str,
        envvar="TEE_CRAFTER_AMI_ID",
        help="Override the pinned, hardened AMI / image ID. Defaults to the image "
             "recorded in the build directory; falls back to the platform's "
             "*_IMAGE / AWS_NITRO_AMI_* variable from .env. Bake with "
             "`tee-crafter internal bake-*`.",
    )
    def deploy_from_build(
        build_dir,
        instance_type_opt,
        spot_opt,
        auto_approve,
        teardown,
        keep_on_failure,
        skip_integrity_check,
        force_unlock,
        ami_id,
    ):
        """Deploy from an existing build directory (skips container build).

        Works for all ten platforms.  Precedence for every input is the same:
        an explicit CLI flag wins, then what the build directory recorded, then
        the ambient environment.  The middle step is what makes a resume
        converge the Terraform state that is already there.
        """
        if keep_on_failure:
            os.environ[KEEP_ON_FAILURE_ENV] = "1"

        build_dir = os.path.abspath(build_dir)
        tee_platform, manifest = resolve_target_platform(build_dir)

        # A leftover state lock means the previous apply was killed rather than
        # interrupted (Terraform traps SIGINT and releases the lock on the way
        # out).  Terraform would refuse to plan, so the resume would stop with
        # a bare "Error acquiring the state lock" while the half-created
        # Bastion and NAT gateway keep billing.  Break it only on an explicit
        # instruction: this cannot distinguish a dead apply from a live one
        # running in another shell, and guessing wrong corrupts state.
        _lock = resume_manifest.read_state_lock(build_dir)
        if _lock is not None:
            _desc = resume_manifest.describe_state_lock(_lock)
            if not force_unlock:
                raise click.ClickException(
                    f"{build_dir} still holds a Terraform state lock "
                    f"({_desc}).\n\n"
                    f"Terraform will not plan against a locked state, so this "
                    f"resume would stop before touching anything.\n\n"
                    f"If no terraform process is running against this "
                    f"directory any more -- the usual case, since a lock only "
                    f"survives an apply that was killed -- re-run with "
                    f"--force-unlock.\n\n"
                    f"If one *is* still running, let it finish instead: "
                    f"breaking its lock can corrupt the state and orphan "
                    f"billing resources."
                )
            if resume_manifest.clear_state_lock(build_dir):
                console.print(
                    f"[yellow]Broke the Terraform state lock ({_desc}) "
                    f"because --force-unlock was given.[/yellow]")
            else:
                raise click.ClickException(
                    f"Could not remove "
                    f"{resume_manifest.STATE_LOCK_NAME} from {build_dir}. "
                    f"Delete it by hand and re-run.")

        # Before anything reads TF_VAR_*: _resolve_ami_id writes the image var,
        # and resolve_shape reads the instance var.  Both must see the recorded
        # environment, not this shell's.
        restore_terraform_env(manifest)

        from tee_crafter.cli.commands.deploy.compute import resolve_shape
        from tee_crafter.cli.commands.deploy.platform import INSTANCE_TYPE_TF_VAR

        instance_var = INSTANCE_TYPE_TF_VAR[tee_platform]
        if instance_type_opt:
            os.environ[instance_var] = instance_type_opt
        if spot_opt is not None:
            os.environ["TF_VAR_use_spot_instance"] = "true" if spot_opt else "false"

        try:
            shape = resolve_shape(
                tee_platform,
                instance_type_opt or os.environ.get(instance_var) or None,
                str(os.environ.get("TF_VAR_use_spot_instance", "")).lower() == "true",
            )
        except ValueError as exc:
            raise click.ClickException(f"Invalid --instance-type: {exc}")

        # Cred isolation is per-cloud, so it has to follow the platform rather
        # than assume AWS.  Runs after the offline argument checks so a typo
        # does not need live credentials to report.
        from tee_crafter.cli.cloud_auth import validate_required_creds
        validate_required_creds(tee_platform)

        # cpu/ram come from the manifest when it has them: they are the shape
        # the state was applied with, and on Nitro they are the *enclave*
        # carve-out rather than the host, so re-deriving them from the instance
        # type can legitimately differ.
        enclave_cpu = int(manifest.get("cpu") or shape.cpu)
        enclave_ram = int(manifest.get("ram") or shape.ram_mb)
        if instance_type_opt:
            enclave_cpu, enclave_ram = shape.cpu, shape.ram_mb
        instance_type = shape.instance_type

        console.print(Panel.fit(
            f"[bold blue]TEE-Crafter Deploy from Build[/bold blue]\n\n"
            f"Source: [green]{build_dir}[/green]\n"
            f"Platform: [green]{tee_platform}[/green]\n"
            f"Resources: {enclave_cpu} vCPU, {enclave_ram} MB RAM",
            border_style="blue",
        ))

        audit = BuildAuditTrail()
        audit.set_tee_platform(tee_platform)
        audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir=build_dir)
        audit.record("Pre-Deploy Validation", "Resumed from build directory",
                     "info", tee_platform=tee_platform,
                     manifest=bool(manifest),
                     tf_vars_restored=len(manifest.get("tf_vars") or {}))

        recorded_image = str(manifest.get("custom_ami") or "")
        if ami_id or not recorded_image:
            custom_ami = _resolve_ami_id(
                ami_id=ami_id, tee_platform=tee_platform, deploy=True,
                audit=audit, cpu=enclave_cpu, ram=enclave_ram,
                instance_type=instance_type,
            )
        else:
            # Same image, same state: deploying a *different* image onto an
            # existing state file is a redeploy, not a resume, and the client
            # in this build directory is pinned to the recorded image's
            # measurements.
            custom_ami = recorded_image
            console.print(f"[dim]Image: {custom_ami} (recorded)[/dim]")
        if not custom_ami and not env_hatch_open(
                "TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI"):
            # _resolve_ami_id already printed the failure panel.
            raise click.ClickException(
                "--deploy needs a pinned, hardened AMI. See the panel above.")
        opened_setup_egress = (
            os.environ.get("TF_VAR_allow_setup_egress", "false").lower() == "true"
        )
        main_tf_path = os.path.join(build_dir, "main.tf")
        if not os.path.exists(main_tf_path):
            raise click.ClickException(f"main.tf not found in {build_dir}")
        verify_build_integrity(build_dir, audit,
                               skip=skip_integrity_check)
        audit.record_file_hash("Pre-Deploy Validation", "Terraform config", main_tf_path)

        phase_fn, meas_kwarg = deployment_phase_for(tee_platform)
        if tee_platform == "nitro-aws":
            measurements = _nitro_pcrs(build_dir, audit)
        else:
            measurements = dict(manifest.get("measurements") or {})

        try:
            deploy_ok = phase_fn(
                console=console, build_dir=build_dir, cpu=enclave_cpu,
                ram=enclave_ram, auto_approve=auto_approve, teardown=teardown,
                audit=audit, custom_ami=custom_ami,
                **{meas_kwarg: measurements})
            # NET-1: nudge operator to bake + re-apply when setup egress
            # was opened.
            if opened_setup_egress and not teardown:
                try:
                    from tee_crafter.cli.deployment.common.wheel_manager import (
                        remind_post_bake_lockdown,
                    )
                    remind_post_bake_lockdown(console)
                except Exception:
                    pass
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Received Ctrl+C. Attempting Terraform destroy...[/bold yellow]")
            # Goes through cleanup_resources, not run_terraform_destroy: this
            # command drives all four Azure CVM platforms, and on Azure a
            # `terraform destroy` can exit 0 while the resource group survives
            # (the `traffic_analytics` flow log makes Azure create a
            # dataCollectionEndpoint and dataCollectionRule that Terraform does
            # not own).  cleanup_resources re-checks the group afterwards and
            # falls back to `az group delete`.  Interrupting a CVM apply is the
            # single most likely way to reach this handler, and a Bastion left
            # behind by it bills ~$0.19/hr.
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
                task_destroy = progress.add_task("[yellow]Running terraform destroy after interrupt...[/yellow]", total=None)
                d_success = cleanup_resources(
                    console, build_dir, context="Interrupt cleanup")
                if d_success:
                    progress.update(task_destroy, description="[green]✓ Resources destroyed after interrupt.[/green]")
                else:
                    progress.update(task_destroy, description="[bold red]✗ Destroy failed — resources may still be billing.[/bold red]")
            raise click.Abort()
        if not deploy_ok:
            raise click.ClickException(
                f"Deployment from {build_dir} did not complete.")
        # Same seam as `deploy`: infrastructure and attestation are fine, but a
        # dark SIEM channel on a preventive-gate platform means the workload
        # will answer siem_blackout to every caller.  See
        # siem_sidecar.siem_export_blocked_deploy.
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            siem_export_blocked_deploy,
        )
        _siem_blocked = siem_export_blocked_deploy(audit)
        if _siem_blocked:
            raise click.ClickException(
                f"Deployed, but {_siem_blocked} will not serve traffic: the "
                f"SIEM exporter never confirmed a delivery and the in-TEE "
                f"fail-closed gate refuses every request while the channel is "
                f"dark. Fix the collector path and redeploy, or set "
                f'"fail_open": true in the --siem-config.')
