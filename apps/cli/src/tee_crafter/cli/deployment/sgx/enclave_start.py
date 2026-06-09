"""SGX enclave service startup (step 8f)."""
import base64
import time

from tee_crafter.core.remote.azure_ssh import run_ssh_command
from tee_crafter.resources import load_unit
from tee_crafter.cli.constants import Panel


def start_enclave_service(progress, console, remote_base, ssh_key_path, admin_user,
                          tunnel_port, audit):
    """Step 8f: prepare the host and start the SGX enclave systemd service.

    Returns measurements dict on success (passed through), or None on failure.
    """
    mode_ok, mode_out, _ = run_ssh_command(
        f"if [ -f {remote_base}/.sgx_mode ]; then cat {remote_base}/.sgx_mode; "
        "elif [ -e /dev/sgx_enclave ] || [ -e /dev/sgx/enclave ]; then echo hw; "
        "else echo unknown; fi",
        ssh_key_path, user=admin_user, port=tunnel_port,
    )
    sgx_mode = mode_out.strip() if mode_ok else "unknown"
    task = progress.add_task("[yellow]Step 8f: Starting enclave via gramine-sgx (hardware)...[/yellow]", total=None)
    if sgx_mode != "hw":
        progress.update(task, description="[bold red]✗ SGX hardware required; cannot start enclave.[/bold red]")
        console.print("[red]SGX mode is not 'hw'. Use an Azure DCsv3/DCdsv3 instance.[/red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SGX enclave start", "fail", sgx_mode=sgx_mode)
        return False
    _, pre_ls, _ = run_ssh_command(
        f"ls -la {remote_base}/app_gramine.manifest.sgx {remote_base}/app_gramine.sig "
        f"{remote_base}/app_gramine.manifest.toml 2>&1",
        ssh_key_path, user=admin_user, port=tunnel_port)
    console.print(f"[dim]Pre-start file listing:[/dim]\n{pre_ls}")
    _, bake_marker, _ = run_ssh_command(
        "cat /etc/tee_crafter/baked_sgx 2>/dev/null || echo UNBAKED",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=5)
    is_baked = "UNBAKED" not in (bake_marker or "UNBAKED")
    if is_baked:
        console.print("[dim]Baked SGX image detected — skipping redundant setup[/dim]")
    if not is_baked:
        run_ssh_command(
            "id -u tee_enclave >/dev/null 2>&1 || "
            "sudo useradd --system --no-create-home --shell /usr/sbin/nologin tee_enclave; "
            "getent group sgx >/dev/null 2>&1 && sudo usermod -aG sgx tee_enclave 2>/dev/null || true",
            ssh_key_path, user=admin_user, port=tunnel_port)
    run_ssh_command(
        f"sudo chmod 0666 /dev/sgx_enclave 2>/dev/null || true; "
        f"sudo chmod 0666 /dev/sgx/enclave 2>/dev/null || true; "
        f"sudo chmod 0666 /dev/sgx_provision 2>/dev/null || true; "
        f"sudo chmod o+x /home/{admin_user}; "
        f"sudo chown -R tee_enclave:tee_enclave {remote_base}; "
        f"sudo chmod 755 {remote_base}",
        ssh_key_path, user=admin_user, port=tunnel_port)
    if not is_baked:
        _, unit_out, _ = run_ssh_command(
            "(systemctl cat sgx-enclave.service >/dev/null 2>&1 && echo ok) || echo missing",
            ssh_key_path, user=admin_user, port=tunnel_port)
        if "ok" not in (unit_out or ""):
            console.print("[dim]sgx-enclave.service not found — creating dynamically...[/dim]")
            unit_body = load_unit("sgx-azure", remote_base=remote_base)
            unit_b64 = base64.b64encode(unit_body.encode()).decode()
            run_ssh_command(
                f"echo '{unit_b64}' | base64 -d | sudo tee /etc/systemd/system/sgx-enclave.service > /dev/null && "
                "sudo systemctl daemon-reload && sudo systemctl enable sgx-enclave.service",
                ssh_key_path, user=admin_user, port=tunnel_port, timeout=15)
        run_ssh_command(
            "sudo dpkg -l libsgx-dcap-default-qpl 2>/dev/null | grep -q '^ii' && "
            "  sudo apt-get remove -y libsgx-dcap-default-qpl 2>/dev/null || true",
            ssh_key_path, user=admin_user, port=tunnel_port, timeout=30)
    run_ssh_command(
        "sudo systemctl restart aesmd 2>/dev/null; sleep 2; "
        "systemctl is-active aesmd && echo AESM_OK || echo AESM_FAIL",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=15)
    run_ssh_command(
        "sudo systemctl reset-failed sgx-enclave.service 2>/dev/null; "
        "sudo systemctl stop sgx-enclave.service 2>/dev/null; true",
        ssh_key_path, user=admin_user, port=tunnel_port)
    start_ok, start_out, start_err = run_ssh_command(
        "sudo systemctl start sgx-enclave.service",
        ssh_key_path, user=admin_user, port=tunnel_port)
    if not start_ok:
        progress.update(task, description="[bold red]✗ Step 8f Failed: Could not start enclave service.[/bold red]")
        console.print(f"[red]Start STDOUT:[/red]\n{start_out}\n[red]STDERR:[/red]\n{start_err}")
        _, journal, _ = run_ssh_command(
            "sudo journalctl -u sgx-enclave.service --since '30 seconds ago' -n 30 --no-pager",
            ssh_key_path, user=admin_user, port=tunnel_port)
        if journal:
            console.print(Panel(journal, title="[bold yellow]sgx-enclave.service logs[/bold yellow]", border_style="yellow"))
        if "SIGSEGV" in (journal or "") or "segmentation fault" in (journal or "").lower():
            console.print(
                "[dim]If the log shows SIGSEGV in Gramine PAL: use an SGX-baked custom image, "
                "ensure VM is DCsv3/DCdsv3, and try increasing enclave_size.[/dim]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SGX enclave started", "fail", sgx_mode=sgx_mode)
        return False
    time.sleep(10)
    health_ok, health_out, _ = run_ssh_command(
        "systemctl is-active sgx-enclave.service",
        ssh_key_path, user=admin_user, port=tunnel_port)
    _, svc_log, _ = run_ssh_command(
        "sudo journalctl -u sgx-enclave.service --since '15 seconds ago' -n 40 --no-pager 2>&1",
        ssh_key_path, user=admin_user, port=tunnel_port)
    if svc_log:
        console.print(Panel(svc_log, title="[bold green]sgx-enclave.service logs (post-start)[/bold green]",
                           border_style="green"))
    crash_looping = svc_log and svc_log.count("Started TEE-Crafter SGX") > 2
    if health_ok and "active" in health_out and not crash_looping:
        progress.update(task, description=f"[green]✓ Step 8f: Enclave running ({sgx_mode}).[/green]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SGX enclave started", "pass", sgx_mode=sgx_mode)
        return True
    reason = "crash-looping (rapid restarts)" if crash_looping else "service not active"
    progress.update(task, description=f"[bold red]✗ Step 8f Failed: Enclave {reason}.[/bold red]")
    _, exit_info, _ = run_ssh_command(
        "sudo journalctl -u sgx-enclave.service --since '30 seconds ago' -n 50 --no-pager 2>&1 | "
        "grep -E 'exited|signal|SEGV|fault|error|Error|Cannot|Permission' || true",
        ssh_key_path, user=admin_user, port=tunnel_port)
    if exit_info:
        console.print(Panel(exit_info, title="[bold red]Enclave exit diagnostics[/bold red]", border_style="red"))
    _, dev_info, _ = run_ssh_command(
        "ls -la /dev/sgx* /dev/sgx/enclave 2>&1; id tee_enclave 2>&1; groups tee_enclave 2>&1",
        ssh_key_path, user=admin_user, port=tunnel_port)
    if dev_info:
        console.print(f"[dim]SGX device info:\n{dev_info}[/dim]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SGX enclave started", "fail", sgx_mode=sgx_mode, note=reason)
    return False
