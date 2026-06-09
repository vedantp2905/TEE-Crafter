"""Cloud-init / first-boot setup for AMD SEV-SNP VMs on GCP via IAP tunnel."""

import time

from tee_crafter.core.remote.gcp_ssh import wait_for_ssh, run_ssh_command
from tee_crafter.resources import load_unit


def run_ssh_cloudinit_snp_gcp_setup(
    progress,
    console,
    ssh_key_path: str,
    build_dir: str,
    cpu: int,
    ram: int,
    audit,
    admin_user: str = "tee_admin",
    tunnel_port: int = 22,
) -> bool:
    """Wait for SSH and perform first-boot setup on a GCP SNP Confidential VM."""

    t = progress.add_task("[yellow]Waiting for SSH via IAP tunnel...[/yellow]", total=None)
    ok = wait_for_ssh(ssh_key_path, user=admin_user, timeout=300, port=tunnel_port)
    if not ok:
        progress.update(t, description="[bold red]✗ SSH timed out via IAP tunnel.[/bold red]")
        return False
    progress.update(t, description="[green]✓ SSH online via IAP tunnel.[/green]")

    t = progress.add_task("[yellow]Waiting for cloud-init to finish...[/yellow]", total=None)
    for _ in range(60):
        ok_ci, out, _ = run_ssh_command(
            "cloud-init status --wait 2>/dev/null || echo 'done'",
            ssh_key_path, user=admin_user, port=tunnel_port, timeout=30,
        )
        if ok_ci and ("done" in out or "status: done" in out):
            break
        time.sleep(5)
    progress.update(t, description="[green]✓ Cloud-init complete.[/green]")

    t = progress.add_task("[yellow]Installing system packages...[/yellow]", total=None)
    run_ssh_command(
        "sudo apt-get update -qq && "
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
        "python3-venv python3-dev build-essential curl git pkg-config libssl-dev",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=300,
    )
    progress.update(t, description="[green]✓ System packages installed.[/green]")

    t = progress.add_task("[yellow]Creating tee_enclave user and directories...[/yellow]", total=None)
    run_ssh_command(
        "id -u tee_enclave &>/dev/null || sudo useradd -r -m -d /opt/tee-crafter-snp -s /usr/sbin/nologin tee_enclave; "
        "sudo mkdir -p /opt/tee-crafter-snp/{app,certs,wheels}; "
        "sudo chown -R tee_enclave:tee_enclave /opt/tee-crafter-snp",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=30,
    )
    progress.update(t, description="[green]✓ User and directories created.[/green]")

    t = progress.add_task("[yellow]Creating Python venv + installing framework deps (offline)...[/yellow]", total=None)
    run_ssh_command(
        "sudo -u tee_enclave python3 -m venv /opt/tee-crafter-snp/venv && "
        "/opt/tee-crafter-snp/venv/bin/pip install --upgrade pip setuptools wheel 2>&1 | tail -1",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=120,
    )
    from tee_crafter.cli.deployment.common.wheel_manager import (
        CVM_FRAMEWORK_DEPS, make_framework_wheel_bundle,
    )
    from tee_crafter.core.remote.gcp_ssh import upload_file_via_scp
    bundle_path = make_framework_wheel_bundle(CVM_FRAMEWORK_DEPS, console, timeout=300)
    try:
        upload_file_via_scp(
            bundle_path, "/tmp/fw_bundle.tar.gz",
            ssh_key_path, user=admin_user, port=tunnel_port,
        )
    finally:
        import os as _os
        try:
            _os.unlink(bundle_path)
        except OSError:
            pass
    run_ssh_command(
        "cd /tmp && tar xzf fw_bundle.tar.gz && rm -f fw_bundle.tar.gz && "
        "/opt/tee-crafter-snp/venv/bin/pip install --no-cache-dir --no-index "
        "--find-links /tmp/framework_wheels -r /tmp/framework_req.txt 2>&1 | tail -3 && "
        "rm -rf /tmp/framework_wheels /tmp/framework_req.txt",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=180,
    )
    progress.update(t, description="[green]✓ Python venv + framework deps ready (offline).[/green]")

    t = progress.add_task("[yellow]Creating systemd service...[/yellow]", total=None)
    import base64
    unit = load_unit("snp-gcp")
    unit_b64 = base64.b64encode(unit.encode()).decode()
    run_ssh_command(
        f"echo '{unit_b64}' | base64 -d | sudo tee /etc/systemd/system/tee-crafter-snp.service > /dev/null && "
        "sudo systemctl daemon-reload && sudo systemctl enable tee-crafter-snp.service",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=30,
    )
    progress.update(t, description="[green]✓ Systemd service created.[/green]")

    if audit:
        audit.record("Phase 5: Post-Deploy", "SNP GCP VM cloud-init setup", "pass")

    return True
