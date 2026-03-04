"""Audit trail persistence helpers."""

from rich.console import Console
from rich.panel import Panel

from nitro_agent.core.audit import BuildAuditTrail


def save_audit_trail(audit: BuildAuditTrail, build_dir: str, console: Console) -> None:
    """Persist the audit trail as JSON + human-readable summary."""
    json_path = audit.save(build_dir)
    txt_path = audit.save_summary(build_dir)
    console.print(Panel(
        f"[cyan]JSON:[/cyan]  {json_path}\n"
        f"[cyan]Text:[/cyan]  {txt_path}\n\n"
        "Verify chain integrity:\n"
        f"  [bold]nitro-agent verify-provenance --file {json_path}[/bold]",
        title="[bold green]Build Provenance Audit Trail[/bold green]",
        border_style="green",
    ))
