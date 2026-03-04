"""Deploy flow Steps 1–4: ingestion → vsock → dockerfile → staging."""

import json
import os
from rich.progress import Progress

from nitro_agent.core.ingestion import ingest_directory
from nitro_agent.core.builder import stage_artifacts, render_dockerfile_template
from nitro_agent.core.verification import verify_app_is_not_server
from nitro_agent.llm.chains import generate_vsock_wrapper
from nitro_agent.core.audit import BuildAuditTrail, sha256_file, sha256_hex
from nitro_agent.cli.constants import console, PIPELINE_VERSION


def _template_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates")


def run_phases_1_to_4(progress, audit, source, data_file, prompt_vsock, llm_provider):
    """Steps 1–4: Ingest, vsock translation, Dockerfile, staging. Returns (build_dir, source_code, data_content, data_sample_str, data_file_path) or None."""
    source_path = os.path.abspath(source)
    task_ingest = progress.add_task("[yellow]Step 1: Ingesting code...[/yellow]", total=None)
    ingested_data = ingest_directory(source_path)
    if not ingested_data:
        console.print("[bold red]Error: No Python files found.[/bold red]")
        audit.record("Phase 1: Ingestion", "Source code scan", "fail", reason="No Python files found")
        return None
    ok, reason = verify_app_is_not_server(source_path)
    if not ok:
        console.print(f"[bold red]Error: Source app does not meet Phase 1 contract.[/bold red]\n{reason}")
        audit.record("Phase 1: Ingestion", "Server heuristic check", "fail", reason=reason)
        return None
    source_code = ingested_data["python_code"]
    dependencies = ingested_data["dependencies"]
    progress.update(task_ingest, description="[green]✓ Step 1: Code ingested.[/green]")
    audit.record("Phase 1: Ingestion", "Source code scanned", "pass",
                 source_sha256=sha256_hex(source_code), dependencies_sha256=sha256_hex(dependencies))
    audit.record("Phase 1: Ingestion", "Server heuristic check", "pass")
    data_file_path = data_file or os.path.join(source_path, "data.json")
    data_content, data_sample_str = "", ""
    if os.path.isfile(data_file_path):
        try:
            with open(data_file_path, "r", encoding="utf-8") as f:
                data_content = f.read()
            parsed_data = json.loads(data_content)
            sample_data = parsed_data[:2] if isinstance(parsed_data, list) and parsed_data else parsed_data
            data_sample_str = json.dumps(sample_data, indent=2)
            if len(data_sample_str) > 2000:
                data_sample_str = data_sample_str[:2000] + "\n... (truncated)"
        except Exception as e:
            console.print(f"[bold red]Warning:[/bold red] Data file not valid JSON: {e}")
    template_dir = _template_dir()
    vsock_template_path = os.path.join(template_dir, "app_vsock.template.py")
    template_sha = sha256_file(vsock_template_path)
    audit.record_file_hash("Phase 2: AI Translation", "app_vsock template (TCB)", vsock_template_path)
    audit.record_enclave_tcb_substeps(template_sha)
    task_vsock = progress.add_task("[yellow]Step 2: AI translating to vsock proxy...[/yellow]", total=None)
    try:
        vsock_wrapper = generate_vsock_wrapper(
            app_description=prompt_vsock or "", source_code=source_code, data_content=data_sample_str
        )
    except Exception as e:
        import traceback
        progress.update(task_vsock, description=f"[bold red]✗ Step 2 Failed: {str(e)}[/bold red]")
        console.print(f"[red]{traceback.format_exc()}[/red]")
        audit.record("Phase 2: AI Translation", "LLM code generation", "fail", error=str(e))
        return None
    progress.update(task_vsock, description="[green]✓ Step 2: vsock translation complete.[/green]")
    audit.record("Phase 2: AI Translation", "LLM code generation + pyflakes validation", "pass",
                 generated_app_vsock_sha256=sha256_hex(vsock_wrapper), llm_provider=llm_provider)
    task_docker = progress.add_task("[yellow]Step 3: Generating Dockerfile...[/yellow]", total=None)
    audit.record_file_hash("Phase 2: Packaging", "Dockerfile template (TCB)", os.path.join(template_dir, "Dockerfile.template"))
    try:
        dockerfile_content = render_dockerfile_template()
    except Exception as e:
        import traceback
        progress.update(task_docker, description=f"[bold red]✗ Step 3 Failed: {str(e)}[/bold red]")
        console.print(f"[red]{traceback.format_exc()}[/red]")
        audit.record("Phase 2: Packaging", "Dockerfile generation", "fail", error=str(e))
        return None
    progress.update(task_docker, description="[green]✓ Step 3: Dockerfile generated.[/green]")
    audit.record("Phase 2: Packaging", "Dockerfile generated", "pass", dockerfile_sha256=sha256_hex(dockerfile_content))
    task_stage = progress.add_task("[yellow]Step 4: Staging artifacts...[/yellow]", total=None)
    build_dir = stage_artifacts(source_dir=source_path, vsock_code=vsock_wrapper, dockerfile_content=dockerfile_content)
    audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir=build_dir)
    progress.update(task_stage, description=f"[green]✓ Step 4: Artifacts staged in [bold]{os.path.basename(build_dir)}[/bold].[/green]")
    audit.record_file_hash("Phase 2: Packaging", "Staged app_vsock.py", os.path.join(build_dir, "app_vsock.py"))
    audit.record_file_hash("Phase 2: Packaging", "Staged Dockerfile", os.path.join(build_dir, "Dockerfile"))
    audit.record_file_hash("Phase 2: Packaging", "host_proxy template (TCB)", os.path.join(template_dir, "host_proxy.template.py"))
    audit.record_file_hash("Phase 2: Packaging", "Staged host_proxy.py", os.path.join(build_dir, "host_proxy.py"))
    if not os.path.isfile(data_file_path):
        console.print("[bold red]Error:[/bold red] No data file. Use --data-file or place data.json in source.")
        return None
    with open(os.path.join(build_dir, "data.json"), "w", encoding="utf-8") as f:
        f.write(data_content)
    return (build_dir, source_code, data_content, data_sample_str, data_file_path)
