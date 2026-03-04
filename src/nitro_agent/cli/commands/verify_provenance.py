"""Verify-provenance command: check build provenance chain integrity."""

import json
import os
import click
from rich.panel import Panel

from nitro_agent.core.audit import BuildAuditTrail
from nitro_agent.cli.constants import console


def register(cli):
    @cli.command("verify-provenance")
    @click.option("--file", "provenance_file", required=True, type=click.Path(exists=True, dir_okay=False),
                  help="Path to build_provenance.json")
    def verify_provenance(provenance_file):
        """Verify the integrity of a build provenance audit trail."""
        provenance_file = os.path.abspath(provenance_file)
        console.print(f"[cyan]Verifying:[/cyan] {provenance_file}")
        ok, reason = BuildAuditTrail.verify_chain(provenance_file)
        if ok:
            with open(provenance_file, "r", encoding="utf-8") as f:
                doc = json.load(f)
            n = doc.get("total_entries", 0)
            head = doc.get("chain_head_hash", "")
            console.print(Panel(
                f"[green]Chain is intact.[/green]\n  Entries verified : {n}\n  Chain head hash  : {head}",
                title="[bold green]Provenance Verified[/bold green]",
                border_style="green",
            ))
        else:
            console.print(Panel(
                f"[bold red]Chain verification FAILED[/bold red]\n\n{reason}",
                title="[bold red]Provenance Tampered[/bold red]",
                border_style="red",
            ))
            raise SystemExit(1)
