"""CLI commands for compliance report generation.

Surfaced as a single ``tee-crafter compliance`` group with two
subcommands: ``report`` (audit a build_provenance.json against
frameworks) and ``list`` (enumerate the supported frameworks).  The
older flat ``compliance-report`` / ``compliance-list`` commands have
been removed from the public surface — call sites should use the new
subgroup form.
"""

import os
import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Table

from tee_crafter.cli.constants import console


def register(cli):
    @cli.group("compliance")
    def compliance():
        """Generate compliance reports + list supported frameworks."""

    @compliance.command("report")
    @click.option("--file", "provenance_file", required=True,
                  type=click.Path(exists=True, dir_okay=False),
                  help="Path to build_provenance.json")
    @click.option("--frameworks", "framework_list", default=None,
                  help="Comma-separated framework IDs (default: all)")
    @click.option("--format", "output_format", default="all",
                  type=click.Choice(["json", "md", "html", "all"]),
                  help="Output format(s)")
    @click.option("--output-dir", "output_dir", default=None,
                  type=click.Path(),
                  help="Output directory (default: directory of provenance file)")
    def compliance_report(provenance_file, framework_list, output_format, output_dir):
        """Generate compliance reports from a build provenance file."""
        from tee_crafter.core.compliance.engine import ComplianceEngine

        provenance_file = os.path.abspath(provenance_file)
        if output_dir is None:
            output_dir = os.path.dirname(provenance_file)

        framework_ids = None
        if framework_list:
            framework_ids = [f.strip() for f in framework_list.split(",")]

        formats = ["json", "md", "html"] if output_format == "all" else [output_format]

        console.print(f"[cyan]Provenance:[/cyan] {provenance_file}")
        console.print(f"[cyan]Frameworks:[/cyan] {framework_list or 'all (18)'}")

        engine = ComplianceEngine(
            provenance_path=provenance_file,
            framework_ids=framework_ids,
        )

        compliance_dir = engine.generate_report(output_dir, formats=formats)

        data = engine._build_report_data(engine.evaluate_all())
        s = data["summary"]

        console.print(Panel(
            f"[green]Frameworks:[/green]  {s['frameworks_evaluated']}\n"
            f"[green]Controls:[/green]    {s['total_controls']}\n"
            f"[green]Satisfied:[/green]   {s['by_status']['satisfied']}\n"
            f"[yellow]Partial:[/yellow]     {s['by_status']['partial']}\n"
            f"[red]Gap:[/red]         {s['by_status']['gap']}\n"
            f"[blue]Customer:[/blue]    {s['by_status']['customer_responsibility']}\n"
            f"[green]Product %:[/green]   {s['product_coverage_pct']}%\n\n"
            f"Output: {compliance_dir}/",
            title="[bold green]Compliance Report Generated[/bold green]",
            border_style="green",
        ))

    @compliance.command("list")
    def compliance_list():
        """List all available compliance frameworks."""
        from tee_crafter.core.compliance.registry import build_default_registry

        registry = build_default_registry()
        table = Table(title="TEE-Crafter Compliance Frameworks")
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Version", style="dim")
        table.add_column("Tier")
        table.add_column("Controls", justify="right")
        table.add_column("Product", justify="right", style="green")
        table.add_column("Shared", justify="right", style="yellow")
        table.add_column("Customer", justify="right", style="blue")

        for fw in registry.all():
            product = sum(1 for c in fw.controls
                          if c.responsibility.value == "product_evidence")
            shared = sum(1 for c in fw.controls
                         if c.responsibility.value == "shared")
            customer = sum(1 for c in fw.controls
                           if c.responsibility.value == "customer_responsibility")
            table.add_row(
                fw.framework_id, fw.name, fw.version, fw.tier,
                str(len(fw.controls)), str(product), str(shared), str(customer),
            )

        console.print(table)
