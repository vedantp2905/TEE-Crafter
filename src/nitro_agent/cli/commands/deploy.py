"""Deploy command: full pipeline from source to optional deployment."""

import os
import click
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from nitro_agent.core.iac import run_terraform_destroy
from nitro_agent.core.audit import BuildAuditTrail
from nitro_agent.cli.constants import console, PIPELINE_VERSION
from nitro_agent.cli.deployment import run_deployment_phase
from nitro_agent.cli.commands.deploy_flow import run_phases_1_to_4
from nitro_agent.cli.commands.deploy_flow_build import run_phases_5_to_6
from nitro_agent.cli.audit_helpers import save_audit_trail


def register(cli):
    @cli.command()
    @click.option("--source", required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True),
                  help="Path to the directory containing your Python app")
    @click.option("--enclave-cpu", required=True, type=int, help="Number of vCPUs for the enclave")
    @click.option("--enclave-ram", required=True, type=int, help="RAM in MB for the enclave")
    @click.option("--prompt-vsock", default=None, type=str, help="Optional description for AI vsock translation")
    @click.option("--prompt-iac", default=None, type=str, help="Optional infrastructure preferences")
    @click.option("--deploy", is_flag=True, default=False, help="Run Terraform apply and post-deploy")
    @click.option("--auto-approve", is_flag=True, default=False, help="Skip Terraform approval")
    @click.option("--data-file", default=None, type=click.Path(exists=True, dir_okay=False), help="Path to data.json")
    @click.option("--teardown", is_flag=True, default=False, help="Destroy resources after client run")
    @click.option("--instance-type", default=None, type=str, help="Override EC2 instance type")
    @click.option("--no-spot", is_flag=True, default=False, help="Use On-Demand instance")
    @click.option("--llm-provider", default="local", type=click.Choice(["local", "openai", "anthropic", "gemini"], case_sensitive=False),
                  help="LLM provider (default: local)")
    def deploy(source, enclave_cpu, enclave_ram, prompt_vsock, prompt_iac, deploy, auto_approve, data_file, teardown, instance_type, no_spot, llm_provider):
        """Deploy a Python application to an AWS Nitro Enclave."""
        from nitro_agent.llm.engine import set_provider, _PROVIDER_DISPLAY
        try:
            set_provider(llm_provider)
        except ValueError as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            return
        audit = BuildAuditTrail()
        audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir="(pending)")
        console.print(Panel.fit(
            f"[bold blue]Nitro-Agent Deploy[/bold blue]\n\nSource: [green]{os.path.abspath(source)}[/green]\n"
            f"Resources: {enclave_cpu} vCPU, {enclave_ram} MB RAM\n"
            f"LLM Provider: [cyan]{_PROVIDER_DISPLAY.get(llm_provider.lower(), llm_provider)}[/cyan]",
            border_style="blue",
        ))
        audit.record("Pipeline Config", "Pipeline initialized", "info",
                     enclave_cpu=enclave_cpu, enclave_ram=enclave_ram, llm_provider=llm_provider, deploy_flag=deploy)
        if llm_provider.lower() != "local":
            provider_name = _PROVIDER_DISPLAY.get(llm_provider.lower(), llm_provider)
            console.print(Panel.fit(
                f"[bold yellow]Third-party LLM[/bold yellow]\n\nYour source will be sent to [cyan]{provider_name}[/cyan]. "
                "Do not use for sensitive code unless you accept their policy.",
                border_style="yellow",
            ))
        cpu, ram = enclave_cpu, enclave_ram
        os.environ["TF_VAR_use_spot_instance"] = "false" if no_spot else "true"
        if instance_type and "TF_VAR_instance_type" not in os.environ:
            os.environ["TF_VAR_instance_type"] = instance_type
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
            result = run_phases_1_to_4(progress, audit, source, data_file, prompt_vsock, llm_provider)
            if result is None:
                return
            build_dir, source_code, _data_content, data_sample_str, _ = result
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
            hashes = run_phases_5_to_6(progress, audit, build_dir, cpu, ram, prompt_iac)
            if hashes is None:
                return
        if deploy:
            try:
                run_deployment_phase(console=console, build_dir=build_dir, cpu=cpu, ram=ram, hashes=hashes,
                                     prompt_iac=prompt_iac, auto_approve=auto_approve, teardown=teardown,
                                     source_code=source_code, prompt_vsock=prompt_vsock, data_sample_str=data_sample_str, audit=audit)
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Ctrl+C. Attempting Terraform destroy...[/bold yellow]")
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
                    task = progress.add_task("[yellow]Running terraform destroy...[/yellow]", total=None)
                    d_success, d_msg = run_terraform_destroy(build_dir)
                    progress.update(task, description="[green]✓ Destroyed.[/green]" if d_success else f"[bold red]✗ {d_msg}[/bold red]")
                raise click.Abort()
        else:
            save_audit_trail(audit, build_dir, console)
            console.print(
                f"\n[bold green]Phases 1–3 complete (no deployment).[/bold green]\n"
                f"Build dir: [cyan]{os.path.abspath(build_dir)}[/cyan]\n"
                f"Run with [bold]--deploy --auto-approve[/bold] to apply Terraform.\n"
            )
