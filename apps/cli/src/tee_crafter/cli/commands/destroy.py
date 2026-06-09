"""Destroy command: tear down Terraform-managed resources."""

import os
import click

from tee_crafter.cli.constants import console, Progress, SpinnerColumn, TextColumn
from tee_crafter.cli.deployment.common.terraform_step import cleanup_resources


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
            success = cleanup_resources(console, build_dir, context="Destroy")
            if success:
                progress.update(task, description="[green]✓ Resources destroyed successfully.[/green]")
            else:
                progress.update(task, description="[bold red]✗ Destroy failed.[/bold red]")
        # A failed destroy leaves cloud resources billing; exiting 0 hides that
        # from every wrapper script and CI job that checks the return code.
        if not success:
            raise click.ClickException(
                f"Destroy failed for {build_dir}. Resources may still exist — "
                f"re-run this command, or delete them from the cloud console."
            )
