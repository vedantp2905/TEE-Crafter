"""Destroy command: tear down Terraform-managed resources."""

import os
import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from nitro_agent.core.iac import run_terraform_destroy
from nitro_agent.cli.constants import console


def register(cli):
    @cli.command()
    @click.option("--build-dir", required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True),
                  help="Path to the build directory containing Terraform files")
    def destroy(build_dir):
        """Destroy infrastructure created by a deployment."""
        build_dir = os.path.abspath(build_dir)
        console.print(f"[yellow]Destroying resources in: {build_dir}[/yellow]")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
            task = progress.add_task("[yellow]Running terraform destroy...[/yellow]", total=None)
            success, msg = run_terraform_destroy(build_dir)
            if success:
                progress.update(task, description="[green]✓ Resources destroyed successfully.[/green]")
            else:
                progress.update(task, description=f"[bold red]✗ Destroy failed:[/bold red] {msg}")
