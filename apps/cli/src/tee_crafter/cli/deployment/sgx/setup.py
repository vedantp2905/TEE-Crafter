"""SSH wait, cloud-init, and SGX/Gramine host setup via Azure Bastion tunnel."""

import os
import tempfile
from tee_crafter.cli.constants import Progress
from tee_crafter.cli.constants import Panel

from tee_crafter.core.remote.azure_ssh import (
    wait_for_ssh, upload_file_via_scp, run_ssh_command,
)
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.builder import render_sgx_setup_script
from tee_crafter.core.env_flags import env_hatch_open

# SGX-specific debug flag (prefers platform flag, falls back to global)
DEBUG = (
    env_hatch_open("TEE_CRAFTER_DEBUG_SGX")
    or env_hatch_open("TEE_CRAFTER_DEBUG")
)


def run_ssh_cloudinit_sgx_setup(
    progress: Progress,
    console,
    ssh_key_path: str,
    build_dir: str,
    cpu: int,
    ram: int,
    audit: BuildAuditTrail | None,
    admin_user: str = "azureuser",
    tunnel_port: int = 22,
) -> bool:
    """
    Wait for SSH (through Bastion tunnel), cloud-init, then run the SGX
    host setup script (installs SGX PSW, DCAP, Gramine, generates signing
    key, creates systemd service).

    The caller must have started a BastionTunnel to port 22 and pass its
    local_port as ``tunnel_port``.

    Returns True on success.
    """

    # Step 8a: SSH connectivity through Bastion tunnel
    task_ssh = progress.add_task(
        "[yellow]Step 8a: Waiting for SSH via Bastion tunnel...[/yellow]", total=None,
    )
    if not wait_for_ssh(ssh_key_path, user=admin_user, port=tunnel_port):
        progress.update(task_ssh, description="[bold red]✗ Step 8a Failed: SSH timed out.[/bold red]")
        console.print("[dim]SSH debug: Bastion tunnel port={tunnel_port}. "
                      "Check Azure portal: VM running? Bastion healthy?[/dim]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SSH available (Bastion)", "fail")
        return False
    progress.update(task_ssh, description="[green]✓ Step 8a: SSH connected via Bastion tunnel.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SSH available (Bastion)", "pass")

    # Step 8b: cloud-init
    task_cloud_init = progress.add_task("[yellow]Step 8b: Waiting for cloud-init...[/yellow]", total=None)
    ci_ok, ci_out, ci_err = run_ssh_command(
        "cloud-init status --wait || true",
        ssh_key_path, user=admin_user, timeout=300, port=tunnel_port,
    )
    if ci_ok:
        progress.update(task_cloud_init, description="[green]✓ Step 8b: cloud-init completed.[/green]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Cloud-init completed", "pass")
    else:
        progress.update(task_cloud_init, description="[yellow]! Step 8b: cloud-init wait failed; continuing.[/yellow]")
        console.print(f"[dim yellow]cloud-init output:[/dim yellow]\n{ci_out}\n[dim yellow]error:[/dim yellow]\n{ci_err}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Cloud-init completed", "fail")

    # Step 8c: SGX/Gramine host setup
    task_sgx = progress.add_task("[yellow]Step 8c: Installing SGX PSW, DCAP, and Gramine...[/yellow]", total=None)

    if DEBUG:
        console.print(f"[dim]DEBUG Step 8c: tunnel_port={tunnel_port} build_dir={build_dir}[/dim]")

    # ``ram`` no longer reaches the script: setup_sgx.sh never substituted an
    # enclave size, it only mentioned one in a comment.  Enclave geometry for
    # the batch path comes from ``deployment/sgx/gsc.build_manifest`` instead.
    setup_body = render_sgx_setup_script()

    if DEBUG:
        console.print(f"[dim]DEBUG Step 8c: Rendered setup script len={len(setup_body)} bytes[/dim]")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False, encoding="utf-8") as f:
        f.write(setup_body)
        setup_script_path = f.name
    try:
        scp_ok, scp_msg = upload_file_via_scp(
            setup_script_path, f"/home/{admin_user}/setup_sgx.sh",
            ssh_key_path, user=admin_user, port=tunnel_port,
        )
    finally:
        try:
            os.unlink(setup_script_path)
        except OSError:
            pass

    if not scp_ok:
        progress.update(task_sgx, description=f"[bold red]✗ Step 8c Failed: {scp_msg}[/bold red]")
        console.print("[bold red]Step 8c SCP upload failed.[/bold red]")
        console.print(Panel(scp_msg, title="[yellow]SCP Error[/yellow]", border_style="yellow"))
        if audit:
            audit.record("Phase 5: Post-Deploy", "Upload SGX setup script", "fail")
        return False

    run_ssh_command(
        f"chmod +x /home/{admin_user}/setup_sgx.sh",
        ssh_key_path, user=admin_user, port=tunnel_port,
    )
    setup_ok, setup_out, setup_err = run_ssh_command(
        f"sudo /home/{admin_user}/setup_sgx.sh",
        ssh_key_path, user=admin_user, timeout=900, port=tunnel_port,
    )
    if not setup_ok:
        console.print(f"[bold red]SGX host setup script failed[/bold red]\nSTDOUT:\n{setup_out}\nSTDERR:\n{setup_err}")

    # Verify gramine-sgx is available
    gramine_ok, gramine_out, gramine_err = run_ssh_command(
        'if command -v gramine-sgx >/dev/null 2>&1; then echo gramine_ok; else echo gramine_missing; fi',
        ssh_key_path, user=admin_user, port=tunnel_port,
    )
    if not (gramine_ok and "gramine_ok" in gramine_out):
        progress.update(task_sgx, description="[bold red]✗ Step 8c Failed: gramine-sgx not available.[/bold red]")
        console.print(f"[red]Gramine check STDOUT:[/red] {gramine_out}\n[red]STDERR:[/red] {gramine_err}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SGX/Gramine host setup", "fail")
        return False

    # Detect SGX hardware — fall back to probing /dev/sgx_enclave if .sgx_mode
    # was wiped by deprovisioning (custom image path).
    mode_ok, mode_out, _ = run_ssh_command(
        f"if [ -f /home/{admin_user}/sgx-app/.sgx_mode ]; then cat /home/{admin_user}/sgx-app/.sgx_mode; "
        "elif [ -e /dev/sgx_enclave ] || [ -e /dev/sgx/enclave ]; then echo hw; "
        "else echo unknown; fi",
        ssh_key_path, user=admin_user, port=tunnel_port,
    )
    sgx_mode = mode_out.strip() if mode_ok else "unknown"

    if sgx_mode != "hw":
        progress.update(task_sgx, description="[bold red]✗ Step 8c Failed: SGX hardware required.[/bold red]")
        console.print(Panel(
            "[bold red]SGX requires an Azure DCsv3/DCdsv3 confidential VM.[/bold red]\n\n"
            "/dev/sgx_enclave not found on this instance.\n"
            "SGX deploys default to Standard_DC2s_v3; override via\n"
            "TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE=Standard_DCxs_v3.",
            title="[red]SGX Hardware Required[/red]",
            border_style="red",
        ))
        if audit:
            audit.record("Phase 5: Post-Deploy", "SGX/Gramine host setup", "fail",
                         sgx_mode=sgx_mode, note="SGX hardware required; no simulation mode")
        return False

    progress.update(task_sgx, description="[green]✓ Step 8c: SGX hardware enclave ready (gramine-sgx).[/green]")
    console.print("[dim]SGX mode: [bold green]hardware[/bold green] — full enclave memory protection.[/dim]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SGX/Gramine host setup", "pass", sgx_mode="hw")
    return True
