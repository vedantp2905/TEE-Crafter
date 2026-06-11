"""Run local client against enclave via SSM tunnel and capture output or fetch logs on failure."""

import os
import sys
import time
import subprocess
from tee_crafter.cli.constants import Console
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress

from tee_crafter.core.remote.ssm import run_ssm_command, SSMPortForward
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.deployment.common.attestation_report import (
    extract_attestation_report,
    emit_att_verdicts,
    detect_self_pinned_measurement,
)
from tee_crafter.cli.deployment.common.client_evidence import (
    record_client_evidence_paths,
    save_client_evidence,
)


def run_client_step(
    progress: Progress,
    console: Console,
    build_dir: str,
    instance_id: str,
    aws_region: str,
    outputs: dict,
    audit: BuildAuditTrail | None,
) -> bool:
    """
    Open an SSM port-forward tunnel, run client.py locally against localhost,
    save output, record audit. On failure fetch proxy/enclave logs.
    Returns automation_success.
    """
    remote_port = 443
    task_tunnel = progress.add_task(
        "[yellow]Step 8g: Opening SSM tunnel to enclave host...[/yellow]", total=None,
    )

    try:
        tunnel = SSMPortForward(instance_id, remote_port, aws_region)
        tunnel.start()
    except Exception as e:
        progress.update(task_tunnel, description=f"[bold red]✗ Step 8g Failed: SSM tunnel error: {e}[/bold red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SSM tunnel", "fail", reason=str(e))
        return False

    progress.update(task_tunnel, description=f"[green]✓ SSM tunnel open (localhost:{tunnel.local_port} -> {remote_port})[/green]")

    time.sleep(5)
    task_client_run = progress.add_task(
        f"[yellow]Step 8g: Running local client via SSM tunnel (localhost:{tunnel.local_port})...[/yellow]", total=None,
    )
    try:
        c_res = subprocess.run(
            [sys.executable, os.path.join(build_dir, "client.py"),
             f"localhost:{tunnel.local_port}", outputs.get("kms_key_arn", "")],
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
    finally:
        tunnel.stop()

    if success:
        progress.update(task_client_run, description="[green]✓ Step 8g: Client execution successful.[/green]")
        if audit:
            # AUD-7: harvest the real measurement / TCB fields the client just
            # verified, rather than only recording an opaque True.  The client
            # prints a JSON object on its last stdout line ('ATTESTATION_REPORT
            # ' prefix) with PCR / MRENCLAVE / MRTD / measurement / TCB SVNs.
            # That object is bound into the chain so verifiers can replay it.
            measurement_fields = extract_attestation_report(c_out, c_err)
            baseline_pinned = not detect_self_pinned_measurement(c_out, c_err)
            audit.record(
                "Phase 5: Post-Deploy", "End-to-end client verification", "pass",
                attestation_verified=True, pcr_values_matched=True, kms_encryption_used=True,
                measurement_baseline_pinned=baseline_pinned,
                **measurement_fields,
            )
            if not baseline_pinned:
                console.print(
                    "[yellow]⚠ Measurement was self-pinned (trust-on-first-use): "
                    "no baseline baked into the image. Production deploys should "
                    "ship a pinned measurements.json.[/yellow]"
                )
            emit_att_verdicts(
                audit, success=True, measurement_fields=measurement_fields,
                baseline_pinned=baseline_pinned,
            )
            enc_cmd = "ENCLAVE_ID=$(nitro-cli describe-enclaves 2>/dev/null | python3 -c \"import sys,json;d=json.load(sys.stdin);print(d[0]['EnclaveID'] if d else '')\" 2>/dev/null); if [ -n \"$ENCLAVE_ID\" ]; then timeout 3 nitro-cli console --enclave-id $ENCLAVE_ID 2>/dev/null || true; else echo ''; fi"
            _enc_ok, enc_out, _ = run_ssm_command(instance_id, enc_cmd, aws_region)
            if _enc_ok and enc_out:
                startup_steps = BuildAuditTrail.parse_enclave_startup_report(enc_out)
                if startup_steps:
                    audit.record_enclave_runtime_startup(startup_steps)
        _paths = save_client_evidence(build_dir, c_out, c_err, console=console)
        record_client_evidence_paths(audit, _paths)
        return True

    progress.update(task_client_run, description="[bold red]✗ Step 8g Failed: Client Execution Failed.[/bold red]")
    console.print(Panel(
        f"STDOUT:\n{c_out}\nSTDERR:\n{c_err}" if (c_out and c_err) else (c_err or c_out),
        title="[bold red]Client Error[/bold red]", border_style="red",
    ))
    # Save before fetching remote logs: this panel scrolls away behind three
    # journalctl dumps, and the client's own reasoning is the part that says why
    # verification failed rather than what the service was doing.
    save_client_evidence(build_dir, c_out, c_err, success=False, console=console)
    if audit:
        audit.record("Phase 5: Post-Deploy", "End-to-end client verification", "fail")
        emit_att_verdicts(audit, success=False, note=(c_err or "client did not complete")[:200])
    console.print("[yellow]Fetching host proxy logs...[/yellow]")
    log_ok, log_out, log_err = run_ssm_command(instance_id, "sudo journalctl -u host-proxy.service -b --no-pager -n 100", aws_region)
    if log_ok:
        console.print(Panel(log_out, title="[bold yellow]host-proxy.service logs[/bold yellow]", border_style="yellow"))
    console.print("[yellow]Fetching vsock-proxy logs...[/yellow]")
    vsock_ok, vsock_out, _ = run_ssm_command(instance_id, "sudo journalctl -u nitro-enclaves-vsock-proxy.service -b --no-pager -n 100", aws_region)
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
