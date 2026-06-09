"""Intel TDX deployment phase on Azure (Terraform apply + Bastion automation).

Thin wrapper over :func:`run_tunneled_deployment_phase`; keeps the TDX-specific
``_tdx_pre_start`` (kernel modules / configfs-tsm / systemd patching) which is
passed to the client runner.
"""
import os

from tee_crafter.cli.constants import Console, Panel
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.azure_ssh import BastionTunnel, wait_for_ssh, run_ssh_command
from tee_crafter.cli.deployment.common.terraform_step import (
    _az_force_delete_rg, _AZURE_RG_NAMES,
)
from tee_crafter.cli.deployment.tdx.setup import run_ssh_cloudinit_tdx_setup
from tee_crafter.cli.deployment.common.azure_bastion_client import run_azure_bastion_client
from tee_crafter.cli.deployment.common.phase_runner import (
    TunnelConn, TunneledPhaseConfig, run_tunneled_deployment_phase,
)

_TDX_CLIENT_CFG = dict(
    platform="TDX", remote_base="/opt/tee-crafter-tdx",
    service_name="tee-crafter-tdx.service",
    device_chmod_cmd=(
        "for dev in /dev/tdx-guest /dev/tdx_guest; do "
        "  if [ -c \"$dev\" ]; then sudo chmod 0660 \"$dev\"; sudo chgrp kvm \"$dev\" 2>/dev/null; fi; "
        "done; "
        "sudo chgrp kvm /sys/kernel/config/tsm/report/ 2>/dev/null; "
        "sudo chmod 0775 /sys/kernel/config/tsm/report/ 2>/dev/null; "
        "sudo chmod 0666 /dev/tpm0 /dev/tpmrm0 2>/dev/null; "
        "true"
    ),
    client_filename="client_tdx.py", audit_label="TDX",
    tee_platform_slug="tdx-azure",
)


def _tdx_pre_start(progress, console, ssh_key_path, admin_user, ssh_tunnel_port):
    """TDX-specific pre-service-start setup: kernel modules, diagnostics, systemd patching."""
    _, bake_marker, _ = run_ssh_command(
        "cat /etc/tee_crafter/baked_tdx 2>/dev/null || echo UNBAKED",
        ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=5)
    is_baked = "UNBAKED" not in (bake_marker or "UNBAKED")
    if is_baked:
        console.print("[dim]Baked TDX image detected — skipping package install + modprobe[/dim]")
    if not is_baked:
        run_ssh_command(
            "sudo apt-get install -y linux-modules-extra-$(uname -r) tpm2-tools 2>/dev/null || true; "
            "sudo modprobe tdx_guest 2>/dev/null || true; "
            "sudo modprobe configfs 2>/dev/null || true; "
            "sudo modprobe tsm_report 2>/dev/null || true",
            ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=60)
    _, diag_out, _ = run_ssh_command(
        "echo '--- TDX diagnostics ---'; "
        "echo 'kernel: '$(uname -r); "
        "echo 'tdx devices: '$(ls /dev/tdx* 2>/dev/null || echo 'none'); "
        "echo 'configfs-tsm: '$(ls -d /sys/kernel/config/tsm/report 2>/dev/null || echo 'absent'); "
        "echo 'tpm2_nvread: '$(command -v tpm2_nvread 2>/dev/null || echo 'not found'); "
        "echo 'tpm device: '$(ls /dev/tpm* 2>/dev/null || echo 'none')",
        ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=10)
    if diag_out:
        console.print(f"[dim]{diag_out.strip()}[/dim]")
    if not is_baked:
        run_ssh_command(
            "if ! grep -q 'tpm' /etc/systemd/system/tee-crafter-tdx.service 2>/dev/null; then "
            "  sudo sed -i 's|^ReadWritePaths=.*|& /dev/tpm0 /dev/tpmrm0|' "
            "    /etc/systemd/system/tee-crafter-tdx.service && "
            "  sudo systemctl daemon-reload; fi",
            ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=15)


def _pre_apply(console: Console, audit) -> None:
    _az_force_delete_rg(console, _AZURE_RG_NAMES["tdx"])
    from tee_crafter.cli.deployment.common import ensure_azure_network_watcher
    ensure_azure_network_watcher(
        console, os.environ.get("TF_VAR_azure_location",
                                os.environ.get("AZURE_LOCATION", "westus")))


def _render_panel(outputs: dict, measurements: dict):
    return Panel(
        f"[cyan]VM Name:[/cyan] {outputs.get('vm_name', 'N/A')}\n"
        f"[cyan]Private IP:[/cyan] {outputs.get('vm_private_ip', 'N/A')}\n"
        f"[cyan]Resource Group:[/cyan] {outputs.get('resource_group', 'N/A')}\n"
        f"[cyan]Bastion:[/cyan] {outputs.get('bastion_name', '')}\n"
        # Lowercase ``mrtd`` first: that is the canonical key for tdx-azure in
        # core/measurements/registry.py, and it is what the client actually pins
        # against.  Reading only ``MRTD`` printed "unknown" on runs where the
        # measurement *was* pinned -- an operator checking this panel would have
        # concluded attestation was unpinned when it was not.  The uppercase
        # fallback stays for the legacy shape that still carries it.
        f"[cyan]MRTD:[/cyan] "
        f"{measurements.get('mrtd') or measurements.get('MRTD') or 'pending'}",
        title="[bold green]TDX Deployment Outputs (Azure — Bastion)[/bold green]",
        border_style="green")


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
                 bastion=outputs.get("bastion_name", ""), tee_platform="tdx-azure")
    from tee_crafter.cli.deployment.common.deploy_verdicts import (
        record_deploy_outputs_verdicts,
    )
    azure_outputs = dict(outputs)
    azure_outputs["instance_name"] = outputs.get("vm_name", "N/A")
    record_deploy_outputs_verdicts(audit, azure_outputs, tee_platform="tdx-azure")


def _run_client(progress, console, build_dir, ssh_key_path, port, admin_user,
                audit, measurements, outputs):
    return run_azure_bastion_client(
        progress, console, build_dir, ssh_key_path, port, admin_user, audit,
        pre_start_fn=_tdx_pre_start, **_TDX_CLIENT_CFG)


def run_tdx_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, measurements: dict,
    auto_approve: bool, teardown: bool, source_code=None,
    data_sample_str=None, audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply (Azure TDX), Bastion-tunneled setup, optional teardown."""
    cfg = TunneledPhaseConfig(
        tee_platform="tdx-azure", cloud_label="TDX", tunnel_label="Bastion",
        render_panel=_render_panel, build_conn=_build_conn,
        setup_fn=run_ssh_cloudinit_tdx_setup,
        wait_for_ssh=lambda k, u, p: wait_for_ssh(k, user=u, port=p),
        run_client=_run_client, run_remote=run_ssh_command,
        record_outputs=_record_outputs, pre_apply=_pre_apply,
    )
    return run_tunneled_deployment_phase(
        console, build_dir, cpu, ram, measurements, auto_approve, teardown,
        audit, custom_ami, cfg=cfg)
