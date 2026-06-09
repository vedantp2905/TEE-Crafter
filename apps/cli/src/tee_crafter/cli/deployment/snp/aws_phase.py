"""Orchestrate AMD SEV-SNP deployment phase on AWS: Terraform apply, SSM-based automation, teardown."""
import os
from tee_crafter.cli.constants import Console
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.core.iac import get_terraform_outputs, run_terraform_destroy
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.ssm import wait_for_ssm
from tee_crafter.cli.deployment.common.terraform_step import (
    cleanup_resources, run_terraform_apply_loop,
)
from tee_crafter.cli.deployment.common.phase_runner import destroy_on_failure
from tee_crafter.cli.deployment.common.vpc_endpoints import detect_and_skip_existing_vpc_endpoints
from tee_crafter.cli.deployment.snp.aws_setup import run_ssm_cloudinit_snp_aws_setup
from tee_crafter.cli.deployment.snp.aws_artifacts import upload_artifacts_via_s3
from tee_crafter.cli.deployment.snp.aws_service import start_snp_service, run_snp_client
from tee_crafter.cli.deployment.common.siem_sidecar import install_siem_sidecar
from tee_crafter.cli.deployment.common.byok_sidecar import install_byok_sidecar
from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.core.remote.ssm import run_ssm_command


def run_snp_aws_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, measurements: dict,
    auto_approve: bool, teardown: bool, source_code=None,
    data_sample_str=None, audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply, SSM-based post-deploy automation, optional teardown.

    Returns ``True`` only when the SNP client verified the attestation.
    """
    detect_and_skip_existing_vpc_endpoints(console, build_dir)
    max_retries = min(2, max(1, int(os.getenv("TEE_CRAFTER_PHASE4_MAX_RETRIES", "2"))))
    apply_success, last_error_msg = run_terraform_apply_loop(console, build_dir, auto_approve, audit)
    destroy_already_run = False
    automation_success = False
    # Teardown evidence must come from the teardown itself.  These were read
    # via ``locals().get(...)``, which resolves to whatever same-named local
    # happens to exist — and ``d_msg`` is also assigned by an earlier cleanup
    # path, so a run that tore nothing down could report that path's message as
    # its teardown result.  ``None`` means "not evaluated", which the ledger
    # treats as distinct from a pass.
    d_success: bool | None = None
    d_msg: str = ""
    outputs: dict = {}

    if not apply_success:
        console.print(f"\n[bold red]Deployment failed after {max_retries} Terraform apply attempts.[/bold red]")
        console.print(f"[red]Last Error:[/red] {last_error_msg}\n")
        if audit:
            audit.record("Phase 4: Deployment", "Terraform apply", "fail", attempts=max_retries)
        destroy_already_run = destroy_on_failure(
            console, build_dir, audit, destroy_fn=cleanup_resources,
            context="Post-failure cleanup",
            step="Terraform destroy (apply failed)") is not None
    else:
        console.print("\n[bold green]Step 7 complete.[/bold green] SNP infrastructure deployed via Terraform.\n")
        outputs = get_terraform_outputs(build_dir)
        instance_id = outputs.get("instance_id", "N/A")
        bucket_name = outputs.get("deployment_bucket", "N/A")
        private_ip = outputs.get("private_ip", "N/A")
        console.print(Panel(
            f"[cyan]Instance ID:[/cyan] {instance_id}\n"
            f"[cyan]Private IP:[/cyan] {private_ip}\n"
            f"[cyan]S3 Bucket:[/cyan] {bucket_name}",
            title="[bold green]SNP AWS Deployment Outputs[/bold green]", border_style="green"))
        if audit:
            audit.record("Phase 4: Deployment", "Infrastructure outputs", "info",
                         instance_id=instance_id, tee_platform="snp-aws")
            from tee_crafter.cli.deployment.common.deploy_verdicts import (
                record_deploy_outputs_verdicts,
            )
            record_deploy_outputs_verdicts(audit, outputs, tee_platform="snp-aws")
        # Pin the BYOK key to the role Terraform just created, before the
        # workload can ask for the DEK.  snp-aws has no attestation condition
        # key, so the principal is the whole gate; the role's name carries a
        # per-deploy suffix, so this is the first moment the exact ARN exists.
        # Fail closed -- continuing would run against whatever policy the key
        # happened to carry, which is the state this exists to prevent.
        from tee_crafter.cli.deployment.common.byok_key_policy import (
            pin_byok_key_to_instance_role,
        )
        _pin_region = (os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION")
                       or "us-east-2")
        # ami_id lets the pin look up the image's recorded NitroTPM PCRs, which
        # is what turns an identity-gated key policy into a measurement-gated
        # one. Read from the same env the deploy resolved the AMI from.
        _pin_ami = (os.getenv("TF_VAR_ami_id") or os.getenv("TEE_CRAFTER_AMI_ID")
                    or "")
        _pinned, _pin_detail = pin_byok_key_to_instance_role(
            console=console, build_dir=build_dir, tee_platform="snp-aws",
            outputs=outputs, region=_pin_region, audit=audit,
            ami_id=_pin_ami)
        if not _pinned:
            console.print(
                "[bold red]✗ BYOK key could not be pinned to this deploy's "
                f"instance role: {_pin_detail}[/bold red]\n"
                "[red]Refusing to continue. With no attestation condition on "
                "snp-aws the principal is the only control on the DEK, so an "
                "unpinned key is a key any matching role in the account can "
                "read.[/red]")
            if audit:
                audit.record("Phase 4: Deployment",
                             "BYOK key policy pinned to instance role", "fail",
                             tee_platform="snp-aws", reason=_pin_detail[:200])
            destroy_already_run = destroy_on_failure(
                console, build_dir, audit, destroy_fn=cleanup_resources,
                context="BYOK pinning failure cleanup",
                step="Terraform destroy (BYOK pin failed)") is not None
            return False

        if instance_id != "N/A" and bucket_name != "N/A":
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          console=console, transient=False) as progress:
                if custom_ami:
                    import boto3
                    aws_region = (os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION")
                                  or boto3.Session().region_name or "us-east-2")
                    t = progress.add_task("[yellow]Waiting for SSM on custom-AMI instance...[/yellow]", total=None)
                    ok = wait_for_ssm(instance_id, aws_region)
                    progress.update(t, description=(
                        "[green]✓ SSM online (custom AMI, setup skipped).[/green]" if ok
                        else "[bold red]✗ SSM timed out.[/bold red]"))
                    if not ok:
                        console.print(f"[red]SNP-AWS: SSM timed out for {instance_id} in {aws_region}.[/red]")
                    if audit and ok:
                        audit.record("Phase 5: Post-Deploy", "SSM online (custom AMI)", "pass")
                else:
                    ok, aws_region = run_ssm_cloudinit_snp_aws_setup(
                        progress, console, instance_id, bucket_name, build_dir, cpu, ram, audit)
                if ok:
                    if upload_artifacts_via_s3(
                        progress, console, build_dir, instance_id, bucket_name, aws_region, audit):
                        if start_snp_service(progress, console, instance_id, aws_region, audit):
                            _run = lambda c, _i=instance_id, _r=aws_region: run_ssm_command(_i, c, _r, timeout=60)
                            install_siem_sidecar(
                                console=console,
                                build_dir=build_dir,
                                tee_platform="snp-aws",
                                run_remote=_run,
                                audit=audit,
                            )
                            install_byok_sidecar(
                                console=console,
                                build_dir=build_dir,
                                tee_platform="snp-aws",
                                run_remote=_run,
                                audit=audit,
                            )
                            try:
                                from tee_crafter.cli.deployment.common.post_deploy_probes import (
                                    run_post_deploy_probes,
                                )
                                run_post_deploy_probes(
                                    audit, tee_platform="snp-aws",
                                    build_dir=build_dir, run_remote=_run,
                                )
                            except Exception as exc:
                                console.print(
                                    f"[yellow]Post-deploy probes skipped: "
                                    f"{type(exc).__name__}: {exc}[/yellow]"
                                )
                            automation_success = run_snp_client(
                                progress, console, build_dir, instance_id, aws_region, audit)
        if automation_success:
            console.print("\n[bold green]SNP AWS deployment pipeline complete.[/bold green]\n")
        else:
            console.print("\n[bold yellow]Infrastructure deployed, but post-deployment automation did not fully succeed.[/bold yellow]\n")
            destroy_already_run = destroy_on_failure(
                console, build_dir, audit, destroy_fn=cleanup_resources,
                context="Automation-failure cleanup",
                step="Terraform destroy (on failure)") is not None
    if teardown and not destroy_already_run:
        console.print("[yellow]Step 9: Executing Terraform destroy (teardown)...[/yellow]")
        d_success, d_msg = run_terraform_destroy(build_dir)
        console.print("[green]✓ Step 9: Resources destroyed successfully.[/green]" if d_success
                      else f"[bold red]✗ Step 9 Failed (destroy):[/bold red] {d_msg}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Terraform destroy (teardown)",
                         "pass" if d_success else "fail")
    elif not destroy_already_run:
        console.print(f"\n[dim]To tear down: [bold]tee-crafter destroy --build-dir {os.path.abspath(build_dir)}[/bold][/dim]")
    if audit:
        from tee_crafter.cli.audit_helpers import emit_teardown_and_cloud_audit
        emit_teardown_and_cloud_audit(
            audit, tee_platform="snp-aws",
            teardown_ok=d_success,
            teardown_msg=d_msg or "",
            outputs=outputs or {},
            build_dir=build_dir,
        )
        save_audit_trail(audit, build_dir, console)
    return bool(apply_success and automation_success)
