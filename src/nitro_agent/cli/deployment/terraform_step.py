"""Terraform apply step with retries."""

import os
import time

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from nitro_agent.core.iac import run_terraform_apply
from nitro_agent.core.audit import BuildAuditTrail


def run_terraform_apply_loop(
    console: Console,
    build_dir: str,
    auto_approve: bool,
    audit: BuildAuditTrail | None,
) -> tuple[bool, str]:
    """
    Run Terraform apply with retries. Returns (apply_success, last_error_msg).
    """
    max_retries = int(os.getenv("NITRO_AGENT_PHASE4_MAX_RETRIES", "3"))
    env_auto_approve = os.getenv("NITRO_AGENT_TF_AUTO_APPROVE", "").lower() in {"1", "true", "yes"}
    should_auto_approve = auto_approve or env_auto_approve

    if "TF_VAR_key_name" in os.environ:
        console.print(f"[dim]Using AWS Key Pair (for manual debug only): {os.environ['TF_VAR_key_name']}[/dim]")

    apply_success = False
    last_error_msg = ""

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task_apply = progress.add_task(
            "[yellow]Step 7: Executing Terraform apply (infrastructure)...[/yellow]", total=None
        )
        for attempt in range(max_retries):
            progress.update(
                task_apply,
                description=f"[yellow]Step 7: Terraform apply (Attempt {attempt+1}/{max_retries})...[/yellow]",
            )
            success, stdout, stderr = run_terraform_apply(build_dir, auto_approve=should_auto_approve)
            if success:
                apply_success = True
                progress.update(task_apply, description="[green]✓ Step 7: Deployment successful![/green]")
                if audit:
                    audit.record("Phase 4: Deployment", "Terraform apply", "pass", attempts=attempt + 1)
                break
            error_summary = (stderr.strip() or stdout.strip())[-1000:]
            last_error_msg = error_summary
            console.print(f"[bold red]Terraform Apply Failed (Attempt {attempt+1}):[/bold red]\n{error_summary}")
            if attempt < max_retries - 1:
                progress.update(task_apply, description="[red]! Apply failed. Retrying...[/red]")
                time.sleep(5)

    return apply_success, last_error_msg
