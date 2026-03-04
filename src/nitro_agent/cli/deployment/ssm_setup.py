"""SSM wait, cloud-init, and Nitro Enclaves host setup."""

import os
import tempfile
import boto3
from rich.progress import Progress

from nitro_agent.core.ssm import wait_for_ssm, upload_file_via_s3, run_ssm_command
from nitro_agent.core.audit import BuildAuditTrail
from nitro_agent.cli.loaders import load_remote_setup_template


def run_ssm_cloudinit_nitro_setup(
    progress: Progress,
    console,
    instance_id: str,
    bucket_name: str,
    build_dir: str,
    cpu: int,
    ram: int,
    audit: BuildAuditTrail | None,
) -> tuple[bool, str]:
    """
    Wait for SSM, cloud-init, run remote setup script, verify nitro-cli.
    Returns (success, aws_region).
    """
    boto3_region = boto3.Session().region_name
    aws_region = os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION") or boto3_region or "us-east-2"

    task_ssm = progress.add_task("[yellow]Step 8a: Waiting for AWS Systems Manager (SSM) agent...[/yellow]", total=None)
    if not wait_for_ssm(instance_id, aws_region):
        progress.update(task_ssm, description="[bold red]✗ Step 8a Failed: SSM timed out.[/bold red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SSM agent online", "fail")
        return False, aws_region
    progress.update(task_ssm, description="[green]✓ Step 8a: SSM connected to host.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SSM agent online", "pass")

    task_cloud_init = progress.add_task("[yellow]Step 8b: Waiting for cloud-init...[/yellow]", total=None)
    ci_ok, ci_out, ci_err = run_ssm_command(instance_id, "cloud-init status --wait || true", aws_region)
    if ci_ok:
        progress.update(task_cloud_init, description="[green]✓ Step 8b: cloud-init completed.[/green]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Cloud-init completed", "pass")
    else:
        progress.update(task_cloud_init, description="[yellow]! Step 8b: cloud-init wait failed; continuing.[/yellow]")
        console.print(f"[dim yellow]cloud-init output:[/dim yellow]\n{ci_out}\n[dim yellow]error:[/dim yellow]\n{ci_err}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Cloud-init completed", "fail")

    task_nitro = progress.add_task("[yellow]Step 8c: Verifying Nitro Enclaves host setup...[/yellow]", total=None)
    enclave_memory = max(512, ram)
    allocator_mb = enclave_memory + 1024
    setup_template = load_remote_setup_template()
    setup_body = setup_template.format(allocator_mb=allocator_mb, cpu=cpu, aws_region=aws_region)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False, encoding="utf-8") as f:
        f.write(setup_body)
        setup_script_path = f.name
    try:
        s3_ok, s3_msg = upload_file_via_s3(
            setup_script_path, bucket_name, "remote_setup_script.sh",
            instance_id, "/home/ec2-user/remote_setup_script.sh", aws_region,
        )
    finally:
        try:
            os.unlink(setup_script_path)
        except OSError:
            pass
    if not s3_ok:
        progress.update(task_nitro, description=f"[bold red]✗ Step 8c Failed: {s3_msg}[/bold red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Upload setup script", "fail")
        return False, aws_region
    run_ssm_command(instance_id, "chmod +x /home/ec2-user/remote_setup_script.sh", aws_region)
    setup_ok, setup_out, setup_err = run_ssm_command(instance_id, "sudo /home/ec2-user/remote_setup_script.sh", aws_region)
    if not setup_ok:
        console.print(f"[bold red]Host setup script failed[/bold red]\nSTDOUT:\n{setup_out}\nSTDERR:\n{setup_err}")
    nitro_ok, nitro_out, nitro_err = run_ssm_command(
        instance_id, "if command -v nitro-cli >/dev/null 2>&1; then echo nitro_ok; else echo nitro_missing; fi", aws_region
    )
    if nitro_ok and "nitro_ok" in nitro_out:
        progress.update(task_nitro, description="[green]✓ Step 8c: Nitro Enclaves host environment ready.[/green]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Nitro Enclaves host setup", "pass")
    else:
        progress.update(task_nitro, description="[bold red]✗ Step 8c Failed: Nitro CLI not available.[/bold red]")
        console.print(f"[red]Nitro check STDOUT:[/red] {nitro_out}\n[red]STDERR:[/red] {nitro_err}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Nitro Enclaves host setup", "fail")
    return True, aws_region
