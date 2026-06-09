"""``tee-crafter list-instances`` — show selectable shapes per TEE+cloud.

Prints the instance catalog (:mod:`tee_crafter.core.catalog`) so an operator can
pick an ``--instance-type`` for ``deploy`` and see its vCPU / RAM / GPU.  This is
the same catalog the web UI uses, so the CLI and UI always agree.
"""
from __future__ import annotations

import click

from tee_crafter.cli.constants import console
from tee_crafter.cli.commands.deploy.deploy_helpers import _TEE_PLATFORM_CHOICES
from tee_crafter.core import catalog

GIB = 1024


def register(cli):
    @cli.command("list-instances")
    @click.option(
        "--tee-platform", "platform", default=None,
        type=click.Choice(_TEE_PLATFORM_CHOICES, case_sensitive=False),
        help="Platform to list shapes for (default: all platforms).",
    )
    def list_instances(platform):
        """List selectable instance types with their vCPU / RAM / GPU."""
        from tee_crafter.cli.constants import Table

        platforms = [platform] if platform else list(_TEE_PLATFORM_CHOICES)
        for plat in platforms:
            specs = catalog.enumerate_instances(plat)
            default = catalog.default_instance_type(plat)
            if not specs:
                console.print(
                    f"[dim]{plat}: no enumerated catalog "
                    f"(default [cyan]{default}[/cyan]).[/dim]")
                continue
            table = Table(title=f"{plat}  (default: {default})", show_lines=False)
            table.add_column("instance type", style="cyan", no_wrap=True)
            table.add_column("vCPU", justify="right")
            table.add_column("RAM (GiB)", justify="right")
            table.add_column("GPU")
            table.add_column("CPU gen", style="dim")
            for s in specs:
                gpu = f"{s.gpu_count}\u00d7{(s.gpu_model or '').upper()}" if s.gpu_count else "-"
                name = s.instance_type + ("  (default)" if s.instance_type == default else "")
                table.add_row(name, str(s.vcpu), f"{s.ram_mb / GIB:g}", gpu, s.cpu_gen or "-")
            console.print(table)
