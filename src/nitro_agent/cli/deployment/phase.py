"""Orchestrate deployment phase: Terraform apply, post-deploy automation, teardown."""

import os
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from nitro_agent.core.iac import get_terraform_outputs, run_terraform_destroy
from nitro_agent.core.audit import BuildAuditTrail
from nitro_agent.cli.deployment.terraform_step import run_terraform_apply_loop
from nitro_agent.cli.deployment.ssm_setup import run_ssm_cloudinit_nitro_setup
from nitro_agent.cli.deployment.enclave_proxy import run_eif_upload_enclave_proxy
from nitro_agent.cli.deployment.client_step import run_client_step
from nitro_agent.cli.audit_helpers import save_audit_trail


def run_deployment_phase(
    console: Console,
    build_dir: str,
    cpu: int,
    ram: int,
    hashes: dict,
    prompt_iac,
    auto_approve: bool,
    teardown: bool,
    source_code=None,
    prompt_vsock=None,
    data_sample_str=None,
    audit: BuildAuditTrail | None = None,
) -> None:
    """Execute Terraform apply, post-deploy automation (SSM, enclave, client), optional teardown."""
    max_retries = int(os.getenv("NITRO_AGENT_PHASE4_MAX_RETRIES", "3"))
    apply_success, last_error_msg = run_terraform_apply_loop(console, build_dir, auto_approve, audit)

    if not apply_success:
        console.print(f"\n[bold red]Deployment failed after {max_retries} Terraform apply attempts.[/bold red]")
        console.print(f"[red]Last Error:[/red] {last_error_msg}\n")
        if audit:
            audit.record("Phase 4: Deployment", "Terraform apply", "fail", attempts=max_retries)
    else:
        console.print("\n[bold green]Step 7 complete.[/bold green] Infrastructure deployed via Terraform.\n")
        outputs = get_terraform_outputs(build_dir)
        public_ip = outputs.get("public_ip", "N/A")
        instance_id = outputs.get("instance_id", "N/A")
        bucket_name = outputs.get("deployment_bucket", "N/A")
        console.print(Panel(
            f"[cyan]Instance ID:[/cyan] {instance_id}\n"
            f"[cyan]Public IP:[/cyan] {public_ip}\n"
            f"[cyan]S3 Bucket:[/cyan] {bucket_name}",
            title="[bold green]Deployment Outputs[/bold green]",
            border_style="green",
        ))
        if audit:
            audit.record("Phase 4: Deployment", "Infrastructure outputs", "info",
                         instance_id=instance_id, kms_key_arn=outputs.get("kms_key_arn", "N/A"))
        automation_success = False
        if instance_id != "N/A" and bucket_name != "N/A":
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
                ok, aws_region = run_ssm_cloudinit_nitro_setup(
                    progress, console, instance_id, bucket_name, build_dir, cpu, ram, audit
                )
                if ok:
                    cid = run_eif_upload_enclave_proxy(
                        progress, console, build_dir, instance_id, bucket_name, cpu, ram, audit, aws_region
                    )
                    if cid:
                        automation_success = run_client_step(
                            progress, console, build_dir, instance_id, aws_region, public_ip, outputs, audit
                        )
                    else:
                        console.print("[yellow]Could not parse Enclave CID. Skipping client run.[/yellow]")
        if automation_success:
            console.print("\n[bold green]Deployment pipeline complete.[/bold green]\n")
        else:
            console.print("\n[bold yellow]Infrastructure deployed, but post-deployment automation did not fully succeed.[/bold yellow]\n")

    if teardown:
        console.print("[yellow]Step 9: Executing Terraform destroy (teardown)...[/yellow]")
        d_success, d_msg = run_terraform_destroy(build_dir)
        if d_success:
            console.print("[green]✓ Step 9: Resources destroyed successfully.[/green]")
            if audit:
                audit.record("Phase 5: Post-Deploy", "Terraform destroy (teardown)", "pass")
        else:
            console.print(f"[bold red]✗ Step 9 Failed (destroy):[/bold red] {d_msg}")
            if audit:
                audit.record("Phase 5: Post-Deploy", "Terraform destroy (teardown)", "fail")
    else:
        console.print(f"\n[dim]To tear down: [bold]nitro-agent destroy --build-dir {os.path.abspath(build_dir)}[/bold][/dim]")
    if audit:
        save_audit_trail(audit, build_dir, console)
