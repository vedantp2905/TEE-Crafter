"""NVIDIA GPU-CC deployment phase on Azure (Terraform apply + Bastion automation).

Thin wrapper over :func:`run_tunneled_deployment_phase` with the GPU-CC NRAS
egress policy (pre-apply) and the baked-image NRAS-key injection hook.
"""
import os

from tee_crafter.cli.constants import Console, Panel
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.azure_ssh import BastionTunnel, wait_for_ssh, run_ssh_command
from tee_crafter.cli.deployment.common.terraform_step import (
    _az_force_delete_rg, _AZURE_RG_NAMES,
)
from tee_crafter.cli.deployment.gpu_cc.azure_setup import run_ssh_cloudinit_gpu_cc_azure_setup
from tee_crafter.cli.deployment.common.azure_bastion_client import run_azure_bastion_client
from tee_crafter.cli.deployment.common.nras_egress import apply_nras_egress_policy
from tee_crafter.cli.deployment.common.phase_runner import (
    TunnelConn, TunneledPhaseConfig, run_tunneled_deployment_phase,
)


def _inject_nras_env_via_ssh(ssh_key_path, admin_user, tunnel_port):
    """Write the NVIDIA_NRAS_API_KEY .env file to the GPU CC VM (base64 in-flight)."""
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


_GPU_CC_AZURE_CLIENT_CFG = dict(
    platform="GPU CC Azure", remote_base="/opt/tee-crafter-gpu-cc",
    service_name="tee-crafter-gpu-cc.service",
    device_chmod_cmd=(
        "for dev in /dev/sev-guest /dev/sev; do "
        "  if [ -c \"$dev\" ]; then sudo chmod 0660 \"$dev\"; sudo chgrp kvm \"$dev\" 2>/dev/null; fi; "
        "done; "
        "sudo chmod 0666 /dev/tpm0 /dev/tpmrm0 2>/dev/null; "
        "true"
    ),
    client_filename="client_gpu_cc_azure.py", audit_label="GPU CC Azure",
    tee_platform_slug="gpu-cc-azure",
)


def _pre_apply(console: Console, audit) -> None:
    rg_name = _AZURE_RG_NAMES.get("gpu-cc")
    if rg_name:
        _az_force_delete_rg(console, rg_name)
    from tee_crafter.cli.deployment.common import ensure_azure_network_watcher
    ensure_azure_network_watcher(
        console, os.environ.get("TF_VAR_azure_location", "eastus2"))
    apply_nras_egress_policy(console, "azure", audit)


def _render_panel(outputs: dict, measurements: dict):
    return Panel(
        f"[cyan]VM Name:[/cyan] {outputs.get('vm_name', 'N/A')}\n"
        f"[cyan]Private IP:[/cyan] {outputs.get('vm_private_ip', 'N/A')}\n"
        f"[cyan]Resource Group:[/cyan] {outputs.get('resource_group', 'N/A')}\n"
        f"[cyan]Bastion:[/cyan] {outputs.get('bastion_name', '')}\n"
        f"[cyan]Measurement:[/cyan] {measurements.get('measurement', 'pending')}",
        title="[bold green]GPU CC Azure Deployment Outputs[/bold green]", border_style="green")


def _build_conn(outputs: dict, build_dir: str):
    vm_id = outputs.get("vm_id", "")
    resource_group = outputs.get("resource_group", "N/A")
    bastion_name = outputs.get("bastion_name", "")
    ssh_key_path = outputs.get("ssh_private_key_path", "")
    admin_user = outputs.get("admin_username", "azureuser")
    if ssh_key_path and not os.path.isabs(ssh_key_path):
        ssh_key_path = os.path.join(os.path.abspath(build_dir), ssh_key_path)
    if not (bastion_name and vm_id and ssh_key_path):
        return None
    return TunnelConn(
        tunnel=BastionTunnel(bastion_name, resource_group, vm_id, 22),
        ssh_key_path=ssh_key_path, admin_user=admin_user)


def _record_outputs(audit: BuildAuditTrail, outputs: dict) -> None:
    audit.record("Phase 4: Deployment", "Infrastructure outputs", "info",
                 vm_name=outputs.get("vm_name", "N/A"),
                 bastion=outputs.get("bastion_name", ""), tee_platform="gpu-cc-azure")
    from tee_crafter.cli.deployment.common.deploy_verdicts import (
        record_deploy_outputs_verdicts,
    )
    azure_outputs = dict(outputs)
    azure_outputs["instance_name"] = outputs.get("vm_name", "N/A")
    record_deploy_outputs_verdicts(audit, azure_outputs, tee_platform="gpu-cc-azure")


def _on_custom_ami(ssh_key_path, admin_user, port):
    run_ssh_command(
        "sudo sed -i 's|app_gpu_cc\\.py|app_gpu_cc_azure.py|g' "
        "/etc/systemd/system/tee-crafter-gpu-cc.service && "
        "sudo systemctl daemon-reload",
        ssh_key_path, user=admin_user, port=port, timeout=15)
    _inject_nras_env_via_ssh(ssh_key_path, admin_user, port)


def _run_client(progress, console, build_dir, ssh_key_path, port, admin_user,
                audit, measurements, outputs):
    return run_azure_bastion_client(
        progress, console, build_dir, ssh_key_path, port, admin_user, audit,
        **_GPU_CC_AZURE_CLIENT_CFG)


def run_gpu_cc_azure_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, measurements: dict,
    auto_approve: bool, teardown: bool, source_code=None,
    data_sample_str=None, audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply (Azure GPU CC), Bastion-tunneled setup, optional teardown."""
    cfg = TunneledPhaseConfig(
        tee_platform="gpu-cc-azure", cloud_label="GPU CC Azure", tunnel_label="Bastion",
        render_panel=_render_panel, build_conn=_build_conn,
        setup_fn=run_ssh_cloudinit_gpu_cc_azure_setup,
        wait_for_ssh=lambda k, u, p: wait_for_ssh(k, user=u, port=p),
        run_client=_run_client, run_remote=run_ssh_command,
        record_outputs=_record_outputs, pre_apply=_pre_apply,
        on_custom_ami=_on_custom_ami,
    )
    return run_tunneled_deployment_phase(
        console, build_dir, cpu, ram, measurements, auto_approve, teardown,
        audit, custom_ami, cfg=cfg)
