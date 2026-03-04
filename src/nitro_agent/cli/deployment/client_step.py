"""Run local client against enclave and capture output or fetch logs on failure."""

import json
import os
import sys
import time
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from nitro_agent.core.ssm import run_ssm_command
from nitro_agent.core.audit import BuildAuditTrail


def run_client_step(
    progress: Progress,
    console: Console,
    build_dir: str,
    instance_id: str,
    aws_region: str,
    public_ip: str,
    outputs: dict,
    audit: BuildAuditTrail | None,
) -> bool:
    """
    Run client.py locally, save output, record audit. On failure fetch proxy/enclave logs.
    Returns automation_success.
    """
    time.sleep(10)
    task_client_run = progress.add_task(
        f"[yellow]Step 8g: Running local client against proxy ({public_ip})...[/yellow]", total=None
    )
    try:
        c_res = subprocess.run(
            [sys.executable, os.path.join(build_dir, "client.py"), public_ip, outputs.get("kms_key_arn", "")],
            cwd=build_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
        success = c_res.returncode == 0
        c_out, c_err = c_res.stdout, c_res.stderr
    except Exception as e:
        success = False
        c_err = str(e)
        c_out = ""

    if success:
        progress.update(task_client_run, description="[green]✓ Step 8g: Client execution successful.[/green]")
        # Do not print client output to terminal (may be sensitive); it is still saved to file below.
        if audit:
            audit.record(
                "Phase 5: Post-Deploy", "End-to-end client verification", "pass",
                attestation_verified=True, pcr_values_matched=True, kms_encryption_used=True,
            )
            enc_cmd = "ENCLAVE_ID=$(nitro-cli describe-enclaves 2>/dev/null | python3 -c \"import sys,json;d=json.load(sys.stdin);print(d[0]['EnclaveID'] if d else '')\" 2>/dev/null); if [ -n \"$ENCLAVE_ID\" ]; then timeout 3 nitro-cli console --enclave-id $ENCLAVE_ID 2>/dev/null || true; else echo ''; fi"
            _enc_ok, enc_out, _ = run_ssm_command(instance_id, enc_cmd, aws_region)
            if _enc_ok and enc_out:
                startup_steps = BuildAuditTrail.parse_enclave_startup_report(enc_out)
                if startup_steps:
                    audit.record_enclave_runtime_startup(startup_steps)
        try:
            json_obj = json.loads(c_out)
            out_path = os.path.join(build_dir, "client_output.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(json_obj, f, indent=2)
            console.print(f"[dim]Client output saved to: {out_path}[/dim]")
        except json.JSONDecodeError:
            out_path = os.path.join(build_dir, "client_output.txt")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(c_out)
            console.print(f"[dim]Client output saved to: {out_path}[/dim]")
        except Exception as e:
            console.print(f"[red]Failed to save output: {e}[/red]")
        return True

    progress.update(task_client_run, description="[bold red]✗ Step 8g Failed: Client Execution Failed.[/bold red]")
    console.print(Panel(
        f"STDOUT:\n{c_out}\nSTDERR:\n{c_err}" if (c_out and c_err) else (c_err or c_out),
        title="[bold red]Client Error[/bold red]", border_style="red",
    ))
    if audit:
        audit.record("Phase 5: Post-Deploy", "End-to-end client verification", "fail")
    console.print("[yellow]Fetching host proxy logs...[/yellow]")
    log_ok, log_out, log_err = run_ssm_command(instance_id, "sudo journalctl -u host-proxy.service -n 100 --no-pager", aws_region)
    if log_ok:
        console.print(Panel(log_out, title="[bold yellow]host-proxy.service logs[/bold yellow]", border_style="yellow"))
    console.print("[yellow]Fetching vsock-proxy logs...[/yellow]")
    vsock_ok, vsock_out, _ = run_ssm_command(instance_id, "sudo journalctl -u nitro-enclaves-vsock-proxy.service -n 100 --no-pager", aws_region)
    if vsock_ok:
        console.print(Panel(vsock_out, title="[bold yellow]nitro-enclaves-vsock-proxy.service logs[/bold yellow]", border_style="yellow"))
    console.print("[yellow]Fetching enclave console logs...[/yellow]")
    enc_cmd = "ENCLAVE_ID=$(nitro-cli describe-enclaves | python3 -c \"import sys,json;d=json.load(sys.stdin);print(d[0]['EnclaveID'] if d else '')\" 2>/dev/null); if [ -n \"$ENCLAVE_ID\" ]; then timeout 3 nitro-cli console --enclave-id $ENCLAVE_ID 2>/dev/null || echo '(timeout)'; else echo '(no enclave)'; fi"
    enc_ok, enc_out, enc_err = run_ssm_command(instance_id, enc_cmd, aws_region)
    if enc_ok and enc_out.strip():
        console.print(Panel(enc_out, title="[bold yellow]Enclave Console[/bold yellow]", border_style="yellow"))
        if audit:
            startup_steps = BuildAuditTrail.parse_enclave_startup_report(enc_out)
            if startup_steps:
                audit.record_enclave_runtime_startup(startup_steps, status="pass")
    else:
        console.print(f"[dim]Enclave console not available: {enc_err or 'empty'}[/dim]")
    return False
