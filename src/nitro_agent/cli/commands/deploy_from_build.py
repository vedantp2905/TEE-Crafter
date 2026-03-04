"""Deploy-from-build command: deploy from an existing build directory."""

import os
import click
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from nitro_agent.core.enclave import get_enclave_hashes
from nitro_agent.core.iac import run_terraform_destroy
from nitro_agent.core.audit import BuildAuditTrail
from nitro_agent.cli.constants import console, PIPELINE_VERSION
from nitro_agent.cli.deployment import run_deployment_phase
from nitro_agent.cli.audit_helpers import save_audit_trail


def register(cli):
    @cli.command()
    @click.option("--build-dir", required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True),
                  help="Path to the existing build directory")
    @click.option("--enclave-cpu", required=True, type=int, help="Number of vCPUs for the enclave")
    @click.option("--enclave-ram", required=True, type=int, help="RAM in MB for the enclave")
    @click.option("--auto-approve", is_flag=True, default=False, help="Skip interactive approval for Terraform apply.")
    @click.option("--teardown", is_flag=True, default=False, help="Destroy resources after successful client run.")
    @click.option("--instance-type", default=None, type=str, help="Override EC2 instance type (e.g. c6g.xlarge).")
    @click.option("--no-spot", is_flag=True, default=False, help="Use On-Demand instead of Spot.")
    def deploy_from_build(build_dir, enclave_cpu, enclave_ram, auto_approve, teardown, instance_type, no_spot):
        """Deploy from an existing build directory (skips ingestion and build)."""
        build_dir = os.path.abspath(build_dir)
        console.print(Panel.fit(
            f"[bold blue]Nitro-Agent Deploy from Build[/bold blue]\n\nSource: [green]{build_dir}[/green]\n"
            f"Resources: {enclave_cpu} vCPU, {enclave_ram} MB RAM",
            border_style="blue",
        ))
        audit = BuildAuditTrail()
        audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir=build_dir)
        os.environ["TF_VAR_use_spot_instance"] = "false" if no_spot else "true"
        if instance_type and "TF_VAR_instance_type" not in os.environ:
            os.environ["TF_VAR_instance_type"] = instance_type
        eif_path = os.path.join(build_dir, "app.eif")
        main_tf_path = os.path.join(build_dir, "main.tf")
        if not os.path.exists(eif_path):
            console.print(f"[bold red]Error: app.eif not found in {build_dir}[/bold red]")
            return
        if not os.path.exists(main_tf_path):
            console.print(f"[bold red]Error: main.tf not found in {build_dir}[/bold red]")
            return
        audit.record_file_hash("Pre-Deploy Validation", "EIF artifact", eif_path)
        audit.record_file_hash("Pre-Deploy Validation", "Terraform config", main_tf_path)
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
            task_hash = progress.add_task("[yellow]Extracting PCR hashes from EIF...[/yellow]", total=None)
            success, hashes, msg = get_enclave_hashes(eif_path)
            if not success:
                progress.update(task_hash, description="[bold red]✗ Failed to get hashes.[/bold red]")
                console.print(f"[red]Error:[/red]\n{msg}")
                audit.record("Pre-Deploy Validation", "PCR hash extraction", "fail")
                save_audit_trail(audit, build_dir, console)
                return
            progress.update(task_hash, description="[green]✓ PCR hashes extracted.[/green]")
            audit.record("Pre-Deploy Validation", "PCR hash extraction", "pass",
                         PCR0=hashes.get("PCR0", ""), PCR1=hashes.get("PCR1", ""), PCR2=hashes.get("PCR2", ""))
        try:
            run_deployment_phase(console=console, build_dir=build_dir, cpu=enclave_cpu, ram=enclave_ram,
                                hashes=hashes, prompt_iac=None, auto_approve=auto_approve, teardown=teardown, audit=audit)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Received Ctrl+C. Attempting Terraform destroy...[/bold yellow]")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
                task_destroy = progress.add_task("[yellow]Running terraform destroy after interrupt...[/yellow]", total=None)
                d_success, d_msg = run_terraform_destroy(build_dir)
                if d_success:
                    progress.update(task_destroy, description="[green]✓ Resources destroyed after interrupt.[/green]")
                else:
                    progress.update(task_destroy, description=f"[bold red]✗ Destroy failed:[/bold red] {d_msg}")
            raise click.Abort()
