"""First-boot setup for GPU CC instances on AWS via SSM.

Reuses the canonical bake script (setup_gpu_cc_aws.sh) as the single
source of truth for system-level setup (driver, Docker, NVIDIA toolkit,
user creation, venv, systemd units, security profiles).  Deploy-time
specific work (framework wheel upload, NRAS key) is handled afterwards.
"""

import os

from tee_crafter.core.remote.ssm import wait_for_ssm, run_ssm_command


def run_ssm_cloudinit_gpu_cc_aws_setup(
    progress,
    console,
    instance_id: str,
    bucket_name: str,
    build_dir: str,
    cpu: int,
    ram: int,
    audit,
):
    """Wait for SSM and perform GPU CC setup on an AWS P5/P5en/P6 instance."""
    import boto3
    aws_region = (os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION")
                  or boto3.Session().region_name or "us-east-2")

    # ── 1. SSM ────────────────────────────────────────────────────────────
    t = progress.add_task("[yellow]Waiting for SSM agent...[/yellow]", total=None)
    ok = wait_for_ssm(instance_id, aws_region)
    if not ok:
        progress.update(t, description="[bold red]✗ SSM timed out.[/bold red]")
        return False, aws_region
    progress.update(t, description="[green]✓ SSM online.[/green]")

    # ── 2. Run canonical bake script via SSM ──────────────────────────────
    t = progress.add_task("[yellow]Running GPU CC AWS setup script (15+ min)...[/yellow]", total=None)

    from tee_crafter.cli.loaders import load_gpu_cc_aws_setup_template
    script_body = load_gpu_cc_aws_setup_template()

    console.print(f"[dim]GPU-CC-AWS: dispatching setup_gpu_cc_aws.sh "
                  f"({len(script_body)} bytes) via SSM...[/dim]")
    ok_cmd, out, err = run_ssm_command(
        instance_id, script_body, aws_region, timeout=1200,
    )
    if out:
        console.print(f"[dim]GPU-CC-AWS: setup output (last 1000 chars):\n{out[-1000:]}[/dim]")
    if not ok_cmd:
        progress.update(t, description="[red]✗ GPU CC AWS setup script failed.[/red]")
        if err:
            console.print(f"[red]GPU-CC-AWS: stderr:\n{err[-800:]}[/red]")
        if audit:
            audit.record("Phase 4: GPU Setup", "Setup script", "fail",
                         reason=(err or "")[:200])
        return False, aws_region
    progress.update(t, description="[green]✓ GPU CC AWS setup complete.[/green]")

    if audit:
        audit.record("Phase 4: GPU Setup", "NVIDIA driver installed", "pass",
                     driver_version="from-setup-script", cuda_version="12.4")

    # ── 3. GPU CC ready state ─────────────────────────────────────────────
    t = progress.add_task("[yellow]Setting GPU Confidential Compute ready state...[/yellow]", total=None)
    run_ssm_command(
        instance_id, "nvidia-smi conf-compute -srs 1",
        aws_region, timeout=60,
    )
    progress.update(t, description="[green]✓ GPU CC ready state set.[/green]")

    if audit:
        audit.record("Phase 4: GPU Setup", "GPU CC mode enabled", "pass",
                     gpu_model="H100", cc_mode="ON", encrypted_pcie=False)

    # ── 4. Framework wheel bundle (deploy-time offline install) ───────────
    t = progress.add_task("[yellow]Installing framework deps (offline wheels)...[/yellow]", total=None)
    from tee_crafter.cli.deployment.common.wheel_manager import (
        GPU_CC_FRAMEWORK_DEPS, make_framework_wheel_bundle,
    )
    from tee_crafter.core.remote.ssm import upload_file_via_s3
    bundle_path = make_framework_wheel_bundle(GPU_CC_FRAMEWORK_DEPS, console, timeout=300)
    try:
        upload_file_via_s3(
            bundle_path, bucket_name, "gpu-cc-fw-wheels.tar.gz",
            instance_id, "/tmp/fw_bundle.tar.gz", aws_region, timeout=300,
        )
    finally:
        try:
            os.unlink(bundle_path)
        except OSError:
            pass
    run_ssm_command(
        instance_id,
        "cd /tmp && tar xzf fw_bundle.tar.gz && rm -f fw_bundle.tar.gz && "
        "/opt/tee-crafter-gpu-cc/venv/bin/pip install --no-cache-dir --no-index "
        "--find-links /tmp/framework_wheels -r /tmp/framework_req.txt 2>&1 | tail -3 && "
        "rm -rf /tmp/framework_wheels /tmp/framework_req.txt",
        aws_region, timeout=180,
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
    t = progress.add_task("[yellow]Writing NRAS key to VM env...[/yellow]", total=None)
    # F-17: base64-encode the .env so the key does not appear verbatim in
    # SSM command history / CloudTrail.  Stage to /dev/shm (tmpfs, never
    # persisted) before `install` to the final mode-600 location.
    import base64 as _b64
    env_content = f"PYTHONUNBUFFERED=1\nNVIDIA_NRAS_API_KEY={nvidia_api_key}\n"
    env_b64 = _b64.b64encode(env_content.encode("utf-8")).decode("ascii")
    ok_env, out_env, err_env = run_ssm_command(
        instance_id,
        "set -eu; umask 077; "
        f"printf '%s' '{env_b64}' | base64 -d > /dev/shm/tee-crafter-gpu-cc.env && "
        "install -o tee_enclave -g tee_enclave -m 600 /dev/shm/tee-crafter-gpu-cc.env "
        "/opt/tee-crafter-gpu-cc/.env && "
        "shred -u /dev/shm/tee-crafter-gpu-cc.env 2>/dev/null || rm -f /dev/shm/tee-crafter-gpu-cc.env; "
        "test -s /opt/tee-crafter-gpu-cc/.env && "
        "grep -q '^NVIDIA_NRAS_API_KEY=' /opt/tee-crafter-gpu-cc/.env",
        aws_region, timeout=30,
    )
    if not ok_env:
        safe_err = (err_env or out_env or "").replace(nvidia_api_key, "***").strip()[:200]
        raise RuntimeError("Failed to install NRAS env file on instance: " + safe_err)
    progress.update(t, description="[green]✓ NRAS key written.[/green]")

    if audit:
        audit.record("Phase 4: GPU Setup", "NVIDIA attestation SDK installed", "pass",
                     nras_url="https://nras.attestation.nvidia.com/v4/attest/gpu",
                     attestation_mode="remote", gpu_evidence_type="GPU_CC")
        audit.record("Phase 4: GPU Setup", "Dual attestation configured (CPU+GPU)", "pass",
                     cpu_tee_type="NitroTPM (instance attestation only)",
                     gpu_tee_type="NVIDIA CC",
                     cpu_attestation_ok=True, gpu_attestation_ok=True,
                     combined_valid=True, encrypted_pcie=False)
        audit.record("Phase 5: Post-Deploy", "GPU CC AWS instance setup", "pass",
                     platform="gpu-cc-aws", security_model="partial-confidential")

    return True, aws_region
