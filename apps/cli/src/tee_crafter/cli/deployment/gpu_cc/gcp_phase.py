"""NVIDIA GPU-CC deployment phase on GCP (Terraform apply + IAP automation).

Thin wrapper over :func:`run_tunneled_deployment_phase` with two GPU-CC
specifics: an NRAS egress policy applied before apply, and a baked-image hook
that patches the unit's app filename and injects the NRAS API key.
"""
import os

from tee_crafter.cli.constants import Console, Panel
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.gcp_ssh import IAPTunnel, wait_for_ssh, run_ssh_command
from tee_crafter.cli.deployment.gpu_cc.gcp_setup import run_ssh_cloudinit_gpu_cc_gcp_setup
from tee_crafter.cli.deployment.common.gcp_phase_client import run_gcp_client
from tee_crafter.cli.deployment.common.nras_egress import apply_nras_egress_policy
from tee_crafter.cli.deployment.common.phase_runner import (
    TunnelConn, TunneledPhaseConfig, run_tunneled_deployment_phase,
)


def _inject_nras_env_via_ssh(ssh_key_path, admin_user, tunnel_port):
    """Write the NVIDIA_NRAS_API_KEY .env file to the GPU CC VM.

    F-17: key is base64-encoded in-flight so it does not appear as a
    literal in IAP logs; staged to /dev/shm (tmpfs) and ``install``'d into
    a mode-600 tee_enclave-owned file.  Errors scrub the key before
    surfacing.
    """
    import base64 as _b64

    nvidia_api_key = os.environ.get("NVIDIA_NRAS_API_KEY", "")
    if not nvidia_api_key:
        raise RuntimeError(
            "NVIDIA_NRAS_API_KEY not set in environment. "
            "Add it to your .env file and re-run."
        )
    env_content = f"PYTHONUNBUFFERED=1\nNVIDIA_NRAS_API_KEY={nvidia_api_key}\n"
    env_b64 = _b64.b64encode(env_content.encode("utf-8")).decode("ascii")
    remote_cmd = (
        "set -eu; umask 077; "
        f"printf '%s' '{env_b64}' | base64 -d | sudo tee /dev/shm/tee-crafter-gpu-cc.env > /dev/null && "
        "sudo install -o tee_enclave -g tee_enclave -m 600 "
        "/dev/shm/tee-crafter-gpu-cc.env /opt/tee-crafter-gpu-cc/.env && "
        "sudo shred -u /dev/shm/tee-crafter-gpu-cc.env 2>/dev/null || sudo rm -f /dev/shm/tee-crafter-gpu-cc.env; "
        "sudo grep -q '^NVIDIA_NRAS_API_KEY=' /opt/tee-crafter-gpu-cc/.env"
    )
    ok, _out, err = run_ssh_command(
        remote_cmd, ssh_key_path, user=admin_user, port=tunnel_port, timeout=120)
    if not ok:
        safe_err = (err or "").replace(nvidia_api_key, "***").strip()[:200]
        raise RuntimeError("Failed to write NRAS env file on VM: " + safe_err)


_GPU_CC_GCP_CLIENT_CFG = dict(
    platform="GPU CC GCP", remote_base="/opt/tee-crafter-gpu-cc",
    service_name="tee-crafter-gpu-cc.service",
    device_chmod_cmd=(
        "for dev in /dev/tdx-guest /dev/tdx_guest; do "
        "  if [ -c \"$dev\" ]; then sudo chmod 0660 \"$dev\"; fi; "
        "done; true"
    ),
    client_filename="client_gpu_cc_gcp.py", audit_label="GPU CC GCP",
    tee_platform_slug="gpu-cc-gcp",
)


def _measurement(measurements: dict) -> str:
    return measurements.get("MRTD", measurements.get("measurement", "pending"))


def _render_panel(outputs: dict, measurements: dict):
    return Panel(
        f"[cyan]Instance:[/cyan] {outputs.get('instance_name', '')}\n"
        f"[cyan]Zone:[/cyan] {outputs.get('instance_zone', '')}\n"
        f"[cyan]Project:[/cyan] {outputs.get('project', '')}\n"
        f"[cyan]Bucket:[/cyan] {outputs.get('deployment_bucket', '')}\n"
        f"[cyan]Measurement:[/cyan] {_measurement(measurements)}",
        title="[bold green]GPU CC GCP Deployment Outputs[/bold green]", border_style="green")


def _build_conn(outputs: dict, build_dir: str):
    instance_name = outputs.get("instance_name", "")
    instance_zone = outputs.get("instance_zone", "")
    project = outputs.get("project", "")
    ssh_key_path = outputs.get("ssh_private_key_path", "")
    admin_user = outputs.get("admin_username", "tee_admin")
    if ssh_key_path and not os.path.isabs(ssh_key_path):
        ssh_key_path = os.path.join(os.path.abspath(build_dir), ssh_key_path)
    if not (instance_name and instance_zone and project and ssh_key_path):
        return None
    return TunnelConn(
        tunnel=IAPTunnel(instance_name, instance_zone, project, 22),
        ssh_key_path=ssh_key_path, admin_user=admin_user)


def _record_outputs(audit: BuildAuditTrail, outputs: dict) -> None:
    audit.record("Phase 4: Deployment", "Infrastructure outputs", "info",
                 instance=outputs.get("instance_name", ""),
                 zone=outputs.get("instance_zone", ""), tee_platform="gpu-cc-gcp")
    from tee_crafter.cli.deployment.common.deploy_verdicts import (
        record_deploy_outputs_verdicts,
    )
    gcp_outputs = dict(outputs)
    gcp_outputs["instance_name"] = outputs.get("instance_name", "")
    record_deploy_outputs_verdicts(audit, gcp_outputs, tee_platform="gpu-cc-gcp")


def _on_custom_ami(ssh_key_path, admin_user, port):
    run_ssh_command(
        "sudo sed -i 's|app_gpu_cc\\.py|app_gpu_cc_gcp.py|g' "
        "/etc/systemd/system/tee-crafter-gpu-cc.service && "
        "sudo systemctl daemon-reload",
        ssh_key_path, user=admin_user, port=port, timeout=15)
    _inject_nras_env_via_ssh(ssh_key_path, admin_user, port)


def _run_client(progress, console, build_dir, ssh_key_path, port, admin_user,
                audit, measurements, outputs):
    return run_gcp_client(
        progress, console, build_dir, ssh_key_path, port, admin_user, audit,
        instance_name=outputs.get("instance_name", ""),
        zone=outputs.get("instance_zone", ""), project=outputs.get("project", ""),
        **_GPU_CC_GCP_CLIENT_CFG, measurements=measurements)


def run_gpu_cc_gcp_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, measurements: dict,
    auto_approve: bool, teardown: bool, source_code=None,
    data_sample_str=None, audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply (GCP GPU CC), IAP-tunneled setup, optional teardown."""
    cfg = TunneledPhaseConfig(
        tee_platform="gpu-cc-gcp", cloud_label="GPU CC GCP", tunnel_label="IAP",
        render_panel=_render_panel, build_conn=_build_conn,
        setup_fn=run_ssh_cloudinit_gpu_cc_gcp_setup,
        wait_for_ssh=lambda k, u, p: wait_for_ssh(k, user=u, port=p),
        run_client=_run_client, run_remote=run_ssh_command,
        record_outputs=_record_outputs,
        pre_apply=lambda console, audit: apply_nras_egress_policy(console, "gcp", audit),
        on_custom_ami=_on_custom_ami,
    )
    return run_tunneled_deployment_phase(
        console, build_dir, cpu, ram, measurements, auto_approve, teardown,
        audit, custom_ami, cfg=cfg)
