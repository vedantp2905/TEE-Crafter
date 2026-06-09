"""Upload SGX artifacts, sign manifest on host, start Gramine enclave, run client via Bastion tunnel."""
import os
import subprocess
import sys
import time

from tee_crafter.cli.constants import Console
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress

from tee_crafter.core.remote.azure_ssh import run_ssh_command, SSHPortForward
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.deployment.sgx.enclave_steps import (
    upload_artifacts, install_user_requirements,
    install_tee_runtime_deps, sign_manifest_on_host,
    upload_container_tarball, start_container_service,
)
from tee_crafter.cli.deployment.sgx.enclave_start import start_enclave_service


def run_sgx_artifact_upload_and_sign(
    progress: Progress, console: Console, build_dir: str, ssh_key_path: str,
    cpu: int, ram: int, audit: BuildAuditTrail | None,
    admin_user: str = "azureuser", tunnel_port: int = 22,
) -> dict | None:
    """Upload SGX artifacts, install deps, sign manifest, start enclave.

    Returns measurements dict or None on failure.
    """
    remote_base = upload_artifacts(progress, console, build_dir, ssh_key_path,
                                   admin_user, tunnel_port, audit)
    if remote_base is None:
        return None
    install_user_requirements(progress, console, build_dir, remote_base,
                             ssh_key_path, admin_user, tunnel_port)
    install_tee_runtime_deps(progress, console, remote_base, ssh_key_path,
                            admin_user, tunnel_port)

    container_result = upload_container_tarball(
        progress, console, build_dir, remote_base,
        ssh_key_path, admin_user, tunnel_port, audit,
    )
    if container_result is None:
        return None
    is_container_mode = container_result is True

    measurements = sign_manifest_on_host(progress, console, remote_base, ssh_key_path,
                                         admin_user, tunnel_port, audit)
    if measurements is None:
        return None

    if is_container_mode:
        container_ok = start_container_service(
            progress, console, ssh_key_path, admin_user, tunnel_port, audit,
        )
        if not container_ok:
            console.print("[bold yellow]Container service failed to start; "
                          "enclave proxy will report 'Container not reachable'.[/bold yellow]")

    ok = start_enclave_service(progress, console, remote_base, ssh_key_path,
                               admin_user, tunnel_port, audit)
    if not ok:
        return None
    return measurements


def run_sgx_client_step(
    progress: Progress, console: Console, build_dir: str,
    bastion_name: str, resource_group: str, vm_resource_id: str,
    ssh_key_path: str, outputs: dict, measurements: dict,
    audit: BuildAuditTrail | None, admin_user: str = "azureuser",
    ssh_tunnel_port: int | None = None,
) -> bool:
    """Wait for enclave readiness, port-forward to 5005, and run the SGX client."""
    from tee_crafter.core.builder import render_sgx_client_template

    remote_port = 5005
    task_wait = progress.add_task(
        "[yellow]Step 8g: Waiting for enclave RA-TLS server to be ready "
        "(Gramine startup can take 2-3 min)...[/yellow]", total=None)
    enclave_ready = False
    ssh_port = ssh_tunnel_port or 22
    max_poll = 36
    for attempt in range(max_poll):
        time.sleep(5)
        _aok, _aout, _ = run_ssh_command("systemctl is-active sgx-enclave.service",
                                         ssh_key_path, user=admin_user, port=ssh_port, timeout=10)
        if _aok and ("inactive" in (_aout or "") or "failed" in (_aout or "")):
            break
        _jok, _jout, _ = run_ssh_command(
            "sudo journalctl -u sgx-enclave.service --no-pager -o cat 2>&1 | "
            "grep -c 'listening on port' || echo 0",
            ssh_key_path, user=admin_user, port=ssh_port, timeout=10)
        try:
            count = int((_jout or "0").strip())
        except ValueError:
            count = 0
        if count > 0:
            enclave_ready = True
            break
    if enclave_ready:
        elapsed = (attempt + 1) * 5
        progress.update(task_wait, description=f"[green]✓ Enclave RA-TLS server ready (after ~{elapsed}s).[/green]")
        time.sleep(3)
    else:
        elapsed = max_poll * 5
        progress.update(task_wait, description=f"[bold red]✗ Enclave not ready after {elapsed}s.[/bold red]")
        _, diag, _ = run_ssh_command(
            "sudo journalctl -u sgx-enclave.service --since '3 min ago' -n 60 --no-pager 2>&1",
            ssh_key_path, user=admin_user, port=ssh_port, timeout=15)
        if diag:
            console.print(Panel(diag, title="[bold red]sgx-enclave.service logs[/bold red]", border_style="red"))
        if audit:
            audit.record("Phase 5: Post-Deploy", "SGX enclave app ready", "fail")
        return False
    task_tunnel = progress.add_task(
        "[yellow]Step 8g: SSH port-forward to SGX enclave (port 5005)...[/yellow]", total=None)
    try:
        tunnel = SSHPortForward(ssh_key_path, admin_user, ssh_port, remote_port)
        tunnel.start()
    except Exception as e:
        progress.update(task_tunnel, description=f"[bold red]✗ Step 8g Failed: SSH port-forward error: {e}[/bold red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SSH port-forward (SGX enclave)", "fail", reason=str(e))
        return False
    progress.update(task_tunnel, description=f"[green]✓ App tunnel open (localhost:{tunnel.local_port} -> {remote_port})[/green]")
    client_code = render_sgx_client_template(
        mrenclave=measurements.get("MRENCLAVE", "unknown"),
        mrsigner=measurements.get("MRSIGNER", "unknown"))
    client_path = os.path.join(build_dir, "client_sgx.py")
    with open(client_path, "w", encoding="utf-8") as f:
        f.write(client_code)
    task_client = progress.add_task(
        f"[yellow]Step 8g: Running SGX client via Bastion tunnel (localhost:{tunnel.local_port})...[/yellow]",
        total=None)
    try:
        c_res = subprocess.run(
            [sys.executable, client_path, "localhost", str(tunnel.local_port)],
            cwd=build_dir, capture_output=True, text=True, timeout=120)
        success, c_out, c_err = c_res.returncode == 0, c_res.stdout, c_res.stderr
    except Exception as e:
        success, c_out, c_err = False, "", str(e)
    finally:
        tunnel.stop()
    if success:
        progress.update(task_client, description="[green]✓ Step 8g: SGX client execution successful.[/green]")
        if audit:
            from tee_crafter.cli.deployment.common.attestation_report import extract_attestation_report
            # AUD-7: capture the SGX-specific measurement / TCB fields the
            # verifier produced (MRENCLAVE, MRSIGNER, ISVPRODID, ISVSVN, …).
            measurement_fields = extract_attestation_report(c_out, c_err)
            # Pre-seed with anything the bake-time measurements dict already
            # knows so the audit entry is consistent even if the verifier
            # didn't echo every field on this run.
            for legacy_key, audit_key in (
                ("MRENCLAVE", "mrenclave"), ("MRSIGNER", "mrsigner"),
                ("ISV_PROD_ID", "isvprodid"), ("ISV_SVN", "isvsvn"),
            ):
                v = measurements.get(legacy_key)
                if v and audit_key not in measurement_fields:
                    measurement_fields[audit_key] = (
                        v.lower() if isinstance(v, str) and audit_key in ("mrenclave", "mrsigner") else v
                    )
            from tee_crafter.cli.deployment.common.attestation_report import (
                emit_att_verdicts, detect_self_pinned_measurement,
            )
            baseline_pinned = not detect_self_pinned_measurement(c_out, c_err)
            audit.record("Phase 5: Post-Deploy", "End-to-end SGX client verification", "pass",
                         attestation_verified=True, dcap_signature_verified=True,
                         mrenclave_matched=bool(measurements.get("MRENCLAVE")),
                         mrsigner_matched=bool(measurements.get("MRSIGNER")), data_encrypted=True,
                         measurement_baseline_pinned=baseline_pinned,
                         **measurement_fields)
            emit_att_verdicts(
                audit, success=True, measurement_fields=measurement_fields,
                baseline_pinned=baseline_pinned,
            )
        from tee_crafter.cli.deployment.common.client_evidence import (
            record_client_evidence_paths, save_client_evidence,
        )
        _paths = save_client_evidence(build_dir, c_out, c_err, console=console)
        record_client_evidence_paths(audit, _paths)
        return True
    progress.update(task_client, description="[bold red]✗ Step 8g Failed: SGX client execution failed.[/bold red]")
    console.print(Panel(
        f"STDOUT:\n{c_out}\nSTDERR:\n{c_err}" if (c_out and c_err) else (c_err or c_out),
        title="[bold red]SGX Client Error[/bold red]", border_style="red"))
    if audit:
        audit.record("Phase 5: Post-Deploy", "End-to-end SGX client verification", "fail")
        from tee_crafter.cli.deployment.common.attestation_report import emit_att_verdicts
        emit_att_verdicts(audit, success=False, note=(c_err or c_out)[-200:])
    console.print("[yellow]Note: Fetch sgx-enclave.service logs via Azure Portal or 'az network bastion ssh'.[/yellow]")
    return False
