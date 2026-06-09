"""Orchestrate GPU CC deployment on AWS: Terraform apply, SSM-based automation, teardown."""
import os
from tee_crafter.cli.constants import Console
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.core.iac import get_terraform_outputs, run_terraform_destroy
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.ssm import wait_for_ssm, run_ssm_command
from tee_crafter.cli.deployment.common.terraform_step import (
    cleanup_resources, run_terraform_apply_loop,
)
from tee_crafter.cli.deployment.common.phase_runner import destroy_on_failure
from tee_crafter.cli.deployment.common.vpc_endpoints import detect_and_skip_existing_vpc_endpoints
from tee_crafter.cli.deployment.gpu_cc.aws_setup import run_ssm_cloudinit_gpu_cc_aws_setup
from tee_crafter.cli.deployment.snp.aws_artifacts import upload_artifacts_via_s3
from tee_crafter.cli.deployment.snp.aws_service import start_snp_service, run_snp_client
from tee_crafter.cli.deployment.common.nras_egress import apply_nras_egress_policy
from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.core.env_flags import env_hatch_open


def _inject_nras_env_via_ssm(instance_id, aws_region):
    """Write the NVIDIA_NRAS_API_KEY .env file to the GPU CC instance via SSM.

    F-17: the API key is base64-encoded before it enters the SSM command
    stream so it does not appear verbatim in CloudTrail / SSM command
    history or in ``aws ssm describe-*`` output.  On the target the
    decoded content is written to a mode-600 file owned by ``tee_enclave``
    inside ``/opt/tee-crafter-gpu-cc/.env``.  We do NOT log the key
    ourselves (no f-string include, no ``console.print`` of the value).
    """
    import base64 as _b64

    nvidia_api_key = os.environ.get("NVIDIA_NRAS_API_KEY", "")
    if not nvidia_api_key:
        raise RuntimeError(
            "NVIDIA_NRAS_API_KEY not set in environment. "
            "Add it to your .env file and re-run."
        )
    env_content = f"PYTHONUNBUFFERED=1\nNVIDIA_NRAS_API_KEY={nvidia_api_key}\n"
    env_b64 = _b64.b64encode(env_content.encode("utf-8")).decode("ascii")
    # Decode on the target, write to a tmpfs path (/dev/shm is in-RAM so
    # the key never lands on persistent disk unprotected), then `install`
    # into the final location with the right owner / mode.
    remote_cmd = (
        "set -eu; "
        "umask 077; "
        f"printf '%s' '{env_b64}' | base64 -d > /dev/shm/tee-crafter-gpu-cc.env && "
        "install -o tee_enclave -g tee_enclave -m 600 "
        "/dev/shm/tee-crafter-gpu-cc.env /opt/tee-crafter-gpu-cc/.env && "
        "shred -u /dev/shm/tee-crafter-gpu-cc.env 2>/dev/null || rm -f /dev/shm/tee-crafter-gpu-cc.env; "
        "test -s /opt/tee-crafter-gpu-cc/.env && "
        "grep -q '^NVIDIA_NRAS_API_KEY=' /opt/tee-crafter-gpu-cc/.env"
    )
    ok_env, out_env, err_env = run_ssm_command(
        instance_id, remote_cmd, aws_region, timeout=30,
    )
    if not ok_env:
        # Scrub any part of the error output that might echo the key back.
        safe_err = (err_env or out_env or "").replace(nvidia_api_key, "***").strip()[:200]
        raise RuntimeError(
            "Failed to install NRAS env file on instance: " + safe_err
        )


def run_gpu_cc_aws_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, measurements: dict,
    auto_approve: bool, teardown: bool, source_code=None,
    data_sample_str=None, audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply, SSM-based post-deploy automation, optional teardown.

    F-4: `gpu-cc-aws` is a PARTIAL-CONFIDENTIAL platform — there is no CPU-TEE
    and the CPU↔GPU PCIe link is NOT encrypted by the hardware TEE.  Operators
    must explicitly acknowledge this weaker model by setting
    ``TEE_CRAFTER_ACCEPT_PARTIAL_CC=1`` in the environment.  Without that
    acknowledgement we refuse to deploy to prevent accidental use of the
    partial model when ``gpu-cc-gcp`` / ``gpu-cc-azure`` would be appropriate.

    "Partial" is the accurate word, and what it partitions changed on
    2026-08-24.  The CPU side is no longer evidence-free: the host produces a
    NitroTPM attestation document that the client verifies against the pinned
    ``certs/nitro-root.pem``, comparing PCR4/PCR7 to bake-time values.  So the
    host's *boot chain* is attested.  What is still missing — and what keeps
    this gate in place — is memory encryption: host RAM is visible to the
    hypervisor, so measured boot proves what booted, not that it stays private.
    """
    # Teardown evidence must come from the teardown itself.  These were read
    # via ``locals().get(...)``, which resolves to whatever same-named local
    # happens to exist, so a run that tore nothing down could still record a
    # teardown verdict.  ``None`` means "not evaluated", which the ledger
    # treats as distinct from a pass.
    d_success: bool | None = None
    d_msg: str = ""
    outputs: dict = {}
    if not env_hatch_open("TEE_CRAFTER_ACCEPT_PARTIAL_CC"):
        console.print(Panel.fit(
            "[bold red]REFUSING TO DEPLOY: gpu-cc-aws is a PARTIAL-CONFIDENTIAL "
            "platform[/bold red]\n\n"
            "AWS GPU instances do NOT have a hardware CPU-TEE. The CPU↔GPU\n"
            "PCIe link is NOT encrypted by a hardware TEE, so any host\n"
            "compromise (hypervisor, kernel, firmware) can observe plaintext\n"
            "inputs/outputs between the CPU and the GPU.  NitroTPM only\n"
            "measures boot; it does not encrypt DMA.\n\n"
            "If this is an informed choice (e.g. regulatory equivalence to\n"
            "FIPS-validated GPU memory encryption is sufficient), re-run\n"
            "with:\n\n"
            "    TEE_CRAFTER_ACCEPT_PARTIAL_CC=1 tee-crafter deploy ...\n\n"
            "Otherwise, use [bold]gpu-cc-gcp[/bold] (Intel TDX + NVIDIA CC)\n"
            "or [bold]gpu-cc-azure[/bold] (AMD SEV-SNP + NVIDIA CC) for full\n"
            "dual attestation and encrypted PCIe.",
            border_style="red"))
        if audit:
            audit.record(
                "Phase 4: Deployment",
                "gpu-cc-aws partial-confidential acknowledgement",
                "fail",
                reason="TEE_CRAFTER_ACCEPT_PARTIAL_CC not set",
            )
            save_audit_trail(audit, build_dir, console)
        return False

    console.print(Panel.fit(
        "[bold yellow]WARNING: WEAKER SECURITY MODEL (explicitly accepted)[/bold yellow]\n\n"
        "gpu-cc-aws provides GPU-side confidential computing (NVIDIA CC mode)\n"
        "but does NOT have a hardware CPU-TEE. The CPU-GPU PCIe link is not\n"
        "encrypted by a TEE. This is a weaker model than gpu-cc-gcp or\n"
        "gpu-cc-azure.  Continuing because TEE_CRAFTER_ACCEPT_PARTIAL_CC is set.",
        border_style="yellow"))
    if audit:
        audit.record(
            "Phase 4: Deployment",
            "gpu-cc-aws partial-confidential acknowledgement",
            "pass",
            reason="TEE_CRAFTER_ACCEPT_PARTIAL_CC=1",
        )

    detect_and_skip_existing_vpc_endpoints(console, build_dir)
    apply_nras_egress_policy(console, "aws", audit)
    apply_success, last_error_msg = run_terraform_apply_loop(console, build_dir, auto_approve, audit)
    destroy_already_run = False
    automation_success = False

    if not apply_success:
        console.print("\n[bold red]Deployment failed.[/bold red]")
        console.print(f"[red]Last Error:[/red] {last_error_msg}\n")
        if audit:
            audit.record("Phase 4: Deployment", "Terraform apply", "fail")
        # A partially-applied p5.4xlarge + NAT gateway is the most expensive
        # leak in the product; destroy unless the operator asked to keep it.
        destroy_already_run = destroy_on_failure(
            console, build_dir, audit, destroy_fn=cleanup_resources,
            context="Post-failure cleanup",
            step="Terraform destroy (apply failed)") is not None
    else:
        console.print("\n[bold green]Step 7 complete.[/bold green] GPU CC AWS infrastructure deployed.\n")
        outputs = get_terraform_outputs(build_dir)
        instance_id = outputs.get("instance_id", "N/A")
        bucket_name = outputs.get("deployment_bucket", "N/A")
        private_ip = outputs.get("private_ip", "N/A")
        console.print(Panel(
            f"[cyan]Instance ID:[/cyan] {instance_id}\n"
            f"[cyan]Private IP:[/cyan] {private_ip}\n"
            f"[cyan]S3 Bucket:[/cyan] {bucket_name}\n"
            f"[cyan]Security Model:[/cyan] partial-confidential (NitroTPM + NVIDIA CC)",
            title="[bold green]GPU CC AWS Deployment Outputs[/bold green]", border_style="green"))
        if audit:
            audit.record("Phase 4: Deployment", "Infrastructure outputs", "info",
                         instance_id=instance_id, tee_platform="gpu-cc-aws",
                         security_model="partial-confidential")
            from tee_crafter.cli.deployment.common.deploy_verdicts import (
                record_deploy_outputs_verdicts,
            )
            record_deploy_outputs_verdicts(audit, outputs, tee_platform="gpu-cc-aws")
        if instance_id != "N/A" and bucket_name != "N/A":
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          console=console, transient=False) as progress:
                if custom_ami:
                    import boto3
                    aws_region = (os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION")
                                  or boto3.Session().region_name or "us-east-2")
                    t = progress.add_task("[yellow]Waiting for SSM on custom-AMI...[/yellow]", total=None)
                    ok = wait_for_ssm(instance_id, aws_region)
                    progress.update(t, description=(
                        "[green]✓ SSM online (custom AMI).[/green]" if ok
                        else "[bold red]✗ SSM timed out.[/bold red]"))
                    if ok:
                        _inject_nras_env_via_ssm(instance_id, aws_region)
                    if audit and ok:
                        audit.record("Phase 5: Post-Deploy", "SSM online (custom AMI)", "pass")
                else:
                    ok, aws_region = run_ssm_cloudinit_gpu_cc_aws_setup(
                        progress, console, instance_id, bucket_name, build_dir, cpu, ram, audit)
                if ok:
                    _gpu_cc_base = "/opt/tee-crafter-gpu-cc"
                    _gpu_cc_svc = "tee-crafter-gpu-cc.service"
                    if upload_artifacts_via_s3(
                        progress, console, build_dir, instance_id, bucket_name, aws_region, audit,
                        remote_base=_gpu_cc_base):
                        if start_snp_service(progress, console, instance_id, aws_region, audit,
                                             service_name=_gpu_cc_svc, remote_base=_gpu_cc_base):
                            from tee_crafter.cli.deployment.common.siem_sidecar import install_siem_sidecar
                            from tee_crafter.cli.deployment.common.byok_sidecar import install_byok_sidecar
                            _run = lambda c, _i=instance_id, _r=aws_region: run_ssm_command(_i, c, _r, timeout=60)
                            install_siem_sidecar(
                                console=console, build_dir=build_dir,
                                tee_platform="gpu-cc-aws",
                                run_remote=_run,
                                audit=audit,
                            )
                            install_byok_sidecar(
                                console=console, build_dir=build_dir,
                                tee_platform="gpu-cc-aws",
                                run_remote=_run,
                                audit=audit,
                            )
                            try:
                                from tee_crafter.cli.deployment.common.post_deploy_probes import (
                                    run_post_deploy_probes,
                                )
                                run_post_deploy_probes(
                                    audit, tee_platform="gpu-cc-aws",
                                    build_dir=build_dir, run_remote=_run,
                                )
                            except Exception as exc:
                                console.print(
                                    f"[yellow]Post-deploy probes skipped: "
                                    f"{type(exc).__name__}: {exc}[/yellow]"
                                )
                            automation_success = run_snp_client(
                                progress, console, build_dir, instance_id, aws_region, audit,
                                client_filename="client_gpu_cc_aws.py")
        if automation_success:
            console.print("\n[bold green]GPU CC AWS deployment pipeline complete.[/bold green]\n")
        else:
            console.print("\n[bold yellow]Infrastructure deployed, but post-deployment did not fully succeed.[/bold yellow]\n")
            destroy_already_run = destroy_on_failure(
                console, build_dir, audit, destroy_fn=cleanup_resources,
                context="Automation-failure cleanup",
                step="Terraform destroy (on failure)") is not None
    if teardown and not destroy_already_run:
        console.print("[yellow]Step 9: Executing Terraform destroy (teardown)...[/yellow]")
        d_success, d_msg = run_terraform_destroy(build_dir)
        console.print("[green]✓ Step 9: Resources destroyed.[/green]" if d_success
                      else f"[bold red]✗ Step 9 Failed:[/bold red] {d_msg}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Terraform destroy (teardown)",
                         "pass" if d_success else "fail")
    elif not destroy_already_run:
        console.print(f"\n[dim]To tear down: [bold]tee-crafter destroy --build-dir {os.path.abspath(build_dir)}[/bold][/dim]")
    if audit:
        from tee_crafter.cli.audit_helpers import emit_teardown_and_cloud_audit
        emit_teardown_and_cloud_audit(
            audit, tee_platform="gpu-cc-aws",
            teardown_ok=d_success,
            outputs=outputs or {},
            build_dir=build_dir,
        )
        save_audit_trail(audit, build_dir, console)
    return bool(apply_success and automation_success)
