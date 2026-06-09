"""SNP-AWS service management and client verification."""
import os
import sys
import subprocess
import time

from tee_crafter.cli.constants import Panel
from tee_crafter.core.remote.ssm import run_ssm_command

_PROXY_ERROR_MARKERS = ("Container not reachable", "connection_refused", "Internal proxy error", "proxy_error")


def _response_has_proxy_error(stdout: str) -> bool:
    text = stdout[:2000].lower()
    return any(m.lower() in text for m in _PROXY_ERROR_MARKERS)


def dump_service_journal(console, instance_id, aws_region,
                         *, service_name="tee-crafter-snp.service"):
    """Fetch and display a systemd service journal for debugging."""
    try:
        ok, journal, _ = run_ssm_command(
            instance_id,
            f"sudo journalctl -u {service_name} --since '10 min ago' -n 100 --no-pager 2>&1",
            aws_region, timeout=15)
        if journal and journal.strip():
            console.print(Panel(
                journal[-3000:],
                title=f"[bold yellow]{service_name} journal (last 100 lines)[/bold yellow]",
                border_style="yellow"))
    except Exception:
        console.print(f"[dim]SNP-AWS: could not retrieve {service_name} journal.[/dim]")


def start_snp_service(progress, console, instance_id, aws_region, audit,
                      *, service_name="tee-crafter-snp.service",
                      remote_base="/opt/tee-crafter-snp"):
    """Start a tee-crafter systemd service and wait for it to be ready."""
    t = progress.add_task(f"[yellow]Starting {service_name}...[/yellow]", total=None)
    console.print(f"[dim]SNP-AWS: resetting {service_name} on {instance_id}[/dim]")
    run_ssm_command(
        instance_id,
        f"sudo systemctl reset-failed {service_name} 2>/dev/null; "
        f"sudo systemctl stop {service_name} 2>/dev/null; true",
        aws_region, timeout=15)
    console.print("[dim]SNP-AWS: using baked systemd configuration (no deploy-time patching).[/dim]")
    run_ssm_command(instance_id, "sudo systemctl daemon-reload", aws_region, timeout=15)
    console.print("[dim]SNP-AWS: setting SEV device perms, starting service...[/dim]")
    start_ok, start_out, start_err = run_ssm_command(
        instance_id,
        "SEV_FOUND=0; for dev in /dev/sev-guest /dev/sev; do "
        "  if [ -c \"$dev\" ]; then sudo chmod 0660 \"$dev\"; sudo chgrp kvm \"$dev\" 2>/dev/null; "
        "    echo \"SEV device: $dev\"; ls -la \"$dev\"; SEV_FOUND=1; fi; done; "
        "if [ \"$SEV_FOUND\" = \"0\" ]; then echo 'No SEV device found'; fi; "
        f"sudo chown -R tee_enclave:tee_enclave {remote_base} && "
        f"sudo systemctl start {service_name}",
        aws_region, timeout=30)
    if start_out:
        console.print(f"[dim]SNP-AWS: start output: {(start_out or '').strip()[-300:]}[/dim]")
    if not start_ok:
        console.print("[yellow]SNP-AWS: systemctl start returned non-zero.[/yellow]")

    app_ready = False
    for attempt in range(24):
        time.sleep(5)
        ok, out, _ = run_ssm_command(
            instance_id, f"systemctl is-active {service_name} 2>/dev/null || true",
            aws_region, timeout=10)
        status = ((out or "").strip().split("\n")[0].strip()) if out else "unknown"
        console.print(f"[dim]SNP-AWS: service poll {attempt}, status={status!r}[/dim]")
        if status in ("failed", "inactive"):
            break
        ok, grep_out, _ = run_ssm_command(
            instance_id,
            f"sudo journalctl -u {service_name} --no-pager -o cat 2>/dev/null "
            "| grep -c 'listening on port' || echo 0",
            aws_region, timeout=10)
        if (grep_out or "").strip() not in ("", "0"):
            app_ready = True
            break
        if attempt % 3 == 0:
            ok2, crash_out, _ = run_ssm_command(
                instance_id,
                f"sudo journalctl -u {service_name} --no-pager -n 15 -o cat 2>&1 || true",
                aws_region, timeout=10)
            crash_text = (crash_out or "").strip()
            crash_sigs = ("ModuleNotFoundError", "ImportError", "SyntaxError",
                          "FileNotFoundError", "Traceback", "No module named")
            if any(sig in crash_text for sig in crash_sigs):
                console.print(f"[yellow]SNP-AWS: detected crash in service logs at poll {attempt}[/yellow]")
                console.print(f"[dim]{crash_text[-600:]}[/dim]")
                break

    if not app_ready:
        progress.update(t, description=f"[red]✗ {service_name} failed to start.[/red]")
        ok, journal, _ = run_ssm_command(
            instance_id,
            f"sudo journalctl -u {service_name} --since '5 min ago' -n 80 --no-pager",
            aws_region, timeout=15)
        if journal:
            console.print(Panel(journal, title=f"[bold yellow]{service_name} logs[/bold yellow]",
                                border_style="yellow"))
        ok2, status_out, _ = run_ssm_command(
            instance_id,
            f"sudo systemctl status {service_name} --no-pager -l 2>&1 || true",
            aws_region, timeout=10)
        if status_out:
            console.print(f"[dim]SNP-AWS: systemctl status:\n{(status_out or '')[-600:]}[/dim]")
        return False

    elapsed = (attempt + 1) * 5
    progress.update(t, description=f"[green]✓ SNP app service running (ready after ~{elapsed}s).[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SNP app service started", "pass")
    return True


def run_snp_client(progress, console, build_dir, instance_id, aws_region, audit,
                   *, client_filename="client_snp_aws.py"):
    """Run the SNP/GPU-CC client verification via SSM port-forward."""
    t = progress.add_task("[yellow]Running client verification...[/yellow]", total=None)
    client_path = os.path.join(build_dir, client_filename)
    if not os.path.isfile(client_path):
        console.print(f"[dim]SNP-AWS: client script not found at {client_path}[/dim]")
        progress.update(t, description=f"[yellow]⊘ {client_filename} not found — skipping.[/yellow]")
        return False

    from tee_crafter.core.remote.ssm import SSMPortForward
    console.print(f"[dim]SNP-AWS: opening SSM port-forward to {instance_id}:5005[/dim]")
    tunnel = SSMPortForward(instance_id, 5005, aws_region)
    try:
        local_port = tunnel.start(timeout=60)
    except Exception as e:
        progress.update(t, description=f"[red]✗ SSM port-forward failed: {e}[/red]")
        return False

    console.print(f"[dim]SNP-AWS: port-forward ready on localhost:{local_port}[/dim]")
    time.sleep(3)
    try:
        result = subprocess.run(
            [sys.executable, client_path, "127.0.0.1", str(local_port)],
            capture_output=True, text=True, timeout=300, cwd=build_dir)
        if result.returncode == 0:
            from tee_crafter.cli.deployment.common.client_evidence import (
                save_client_evidence,
            )
            save_client_evidence(build_dir, result.stdout, result.stderr,
                                 console=console)
            if _response_has_proxy_error(result.stdout):
                progress.update(t, description="[red]✗ SNP client got proxy error (container unreachable).[/red]")
                console.print(f"[dim]SNP-AWS: client output: {result.stdout[:500]}[/dim]")
                dump_service_journal(console, instance_id, aws_region)
                if audit:
                    audit.record("Phase 5: Post-Deploy", "SNP client verification", "fail",
                                 reason="proxy returned container error")
                return False
            progress.update(t, description="[green]✓ SNP client verification passed.[/green]")
            if audit:
                from tee_crafter.cli.deployment.common.attestation_report import (
                    extract_attestation_report, emit_att_verdicts,
                    detect_self_pinned_measurement,
                )
                measurement_fields = extract_attestation_report(result.stdout or "", result.stderr or "")
                baseline_pinned = not detect_self_pinned_measurement(
                    result.stdout or "", result.stderr or "")
                audit.record(
                    "Phase 5: Post-Deploy",
                    "SNP client verification",
                    "pass",
                    attestation_verified=True,
                    measurement_baseline_pinned=baseline_pinned,
                    **measurement_fields,
                )
                if not baseline_pinned:
                    console.print(
                        "[yellow]⚠ Measurement self-pinned (trust-on-first-use): "
                        "ship a pinned measurements.json for production.[/yellow]"
                    )
                emit_att_verdicts(
                    audit, success=True, measurement_fields=measurement_fields,
                    baseline_pinned=baseline_pinned,
                )
            return True
        progress.update(t, description="[red]✗ SNP client verification failed.[/red]")
        console.print(f"[red]SNP-AWS: client rc={result.returncode}[/red]")
        console.print(f"[dim]SNP-AWS: client stderr tail:\n{result.stderr[-1000:]}[/dim]")
        dump_service_journal(console, instance_id, aws_region)
        if audit:
            from tee_crafter.cli.deployment.common.attestation_report import emit_att_verdicts
            audit.record("Phase 5: Post-Deploy", "SNP client verification", "fail",
                         stderr=result.stderr[:200])
            emit_att_verdicts(audit, success=False, note=result.stderr[-200:])
        return False
    except subprocess.TimeoutExpired:
        progress.update(t, description="[red]✗ SNP client timed out (300s).[/red]")
        return False
    finally:
        tunnel.stop()
