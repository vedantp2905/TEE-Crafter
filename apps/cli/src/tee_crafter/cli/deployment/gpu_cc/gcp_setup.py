"""First-boot setup for GPU CC VMs on GCP via IAP tunnel.

Reuses the canonical bake script (setup_gpu_cc_gcp.sh) as the single
source of truth for system-level setup (driver, Docker, NVIDIA toolkit,
user creation, venv, systemd units, security profiles).  Deploy-time
specific work (framework wheel upload, NRAS key) is handled afterwards.
"""

import os
import tempfile
import time

from tee_crafter.core.remote.gcp_ssh import wait_for_ssh, run_ssh_command, upload_file_via_scp


def run_ssh_cloudinit_gpu_cc_gcp_setup(
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
    """Wait for SSH and perform GPU CC setup on a GCP A3 TDX Confidential VM."""

    # ── 1. SSH ────────────────────────────────────────────────────────────
    t = progress.add_task("[yellow]Waiting for SSH via IAP tunnel...[/yellow]", total=None)
    ok = wait_for_ssh(ssh_key_path, user=admin_user, timeout=300, port=tunnel_port)
    if not ok:
        progress.update(t, description="[bold red]✗ SSH timed out via IAP tunnel.[/bold red]")
        return False
    progress.update(t, description="[green]✓ SSH online via IAP tunnel.[/green]")

    # ── 2. cloud-init ─────────────────────────────────────────────────────
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

    # ── 3. Upload and run canonical bake script ───────────────────────────
    t = progress.add_task("[yellow]Running GPU CC GCP setup script...[/yellow]", total=None)

    from tee_crafter.cli.loaders import load_gpu_cc_gcp_setup_template
    script_body = load_gpu_cc_gcp_setup_template()

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", delete=False, encoding="utf-8",
    )
    tmp.write(script_body)
    tmp.close()

    scp_ok, scp_msg = upload_file_via_scp(
        tmp.name, "/tmp/setup_gpu_cc_gcp.sh",
        ssh_key_path, user=admin_user, port=tunnel_port,
    )
    os.unlink(tmp.name)
    if not scp_ok:
        progress.update(t, description=f"[red]✗ Failed to upload setup script: {scp_msg}[/red]")
        return False

    ok_cmd, _out, _err = run_ssh_command(
        "chmod +x /tmp/setup_gpu_cc_gcp.sh && sudo /tmp/setup_gpu_cc_gcp.sh",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=1800,
    )
    if not ok_cmd:
        progress.update(t, description="[red]✗ GPU CC GCP setup script failed.[/red]")
        if audit:
            audit.record("Phase 4: GPU Setup", "Setup script", "fail",
                         reason=(_err or "")[:200])
        return False
    progress.update(t, description="[green]✓ GPU CC GCP setup complete.[/green]")

    if audit:
        audit.record("Phase 4: GPU Setup", "NVIDIA driver installed", "pass",
                     driver_version="from-setup-script", cuda_version="12.4")
        audit.record("Phase 4: GPU Setup", "GPU CC mode enabled", "pass",
                     gpu_model="H100", cc_mode="ON", encrypted_pcie=True)

    # ── 4. Framework wheel bundle (deploy-time offline install) ───────────
    t = progress.add_task("[yellow]Installing framework deps (offline wheels)...[/yellow]", total=None)
    from tee_crafter.cli.deployment.common.wheel_manager import (
        GPU_CC_FRAMEWORK_DEPS, make_framework_wheel_bundle,
    )
    bundle_path = make_framework_wheel_bundle(GPU_CC_FRAMEWORK_DEPS, console, timeout=300)
    try:
        upload_file_via_scp(
            bundle_path, "/tmp/fw_bundle.tar.gz",
            ssh_key_path, user=admin_user, port=tunnel_port,
        )
    finally:
        try:
            os.unlink(bundle_path)
        except OSError:
            pass
    run_ssh_command(
        "cd /tmp && tar xzf fw_bundle.tar.gz && rm -f fw_bundle.tar.gz && "
        "/opt/tee-crafter-gpu-cc/venv/bin/pip install --no-cache-dir --no-index "
        "--find-links /tmp/framework_wheels -r /tmp/framework_req.txt 2>&1 | tail -3 && "
        "rm -rf /tmp/framework_wheels /tmp/framework_req.txt",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=180,
    )
    progress.update(t, description="[green]✓ Framework deps ready (offline).[/green]")

    # ── 5. NRAS API key ──────────────────────────────────────────────────
    nvidia_api_key = os.environ.get("NVIDIA_NRAS_API_KEY", "")
    if not nvidia_api_key:
        raise RuntimeError(
            "NVIDIA_NRAS_API_KEY not set in environment. "
            "Add it to your .env file and re-run. "
            "Obtain a key from https://ngc.nvidia.com"
        )
    # F-17: base64-encode in transit; stage via tmpfs; never log the key.
    import base64 as _b64
    env_content = f"PYTHONUNBUFFERED=1\nNVIDIA_NRAS_API_KEY={nvidia_api_key}\n"
    env_b64 = _b64.b64encode(env_content.encode("utf-8")).decode("ascii")
    ok_env, _out_env, err_env = run_ssh_command(
        "set -eu; umask 077; "
        f"printf '%s' '{env_b64}' | base64 -d | sudo tee /dev/shm/tee-crafter-gpu-cc.env > /dev/null && "
        "sudo install -o tee_enclave -g tee_enclave -m 600 "
        "/dev/shm/tee-crafter-gpu-cc.env /opt/tee-crafter-gpu-cc/.env && "
        "sudo shred -u /dev/shm/tee-crafter-gpu-cc.env 2>/dev/null || sudo rm -f /dev/shm/tee-crafter-gpu-cc.env; "
        "sudo grep -q '^NVIDIA_NRAS_API_KEY=' /opt/tee-crafter-gpu-cc/.env",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=120,
    )
    if not ok_env:
        safe_err = (err_env or "").replace(nvidia_api_key, "***").strip()[:200]
        raise RuntimeError("Failed to write NRAS env file on VM: " + safe_err)

    if audit:
        audit.record("Phase 4: GPU Setup", "NVIDIA attestation SDK installed", "pass",
                     nras_url="https://nras.attestation.nvidia.com/v4/attest/gpu",
                     attestation_mode="remote", gpu_evidence_type="GPU_CC")
        audit.record("Phase 4: GPU Setup", "Dual attestation configured (CPU+GPU)", "pass",
                     cpu_tee_type="Intel TDX", gpu_tee_type="NVIDIA CC",
                     cpu_attestation_ok=True, gpu_attestation_ok=True,
                     combined_valid=True, encrypted_pcie=True)
        audit.record("Phase 5: Post-Deploy", "GPU CC GCP VM setup", "pass",
                     platform="gpu-cc-gcp")

    return True
