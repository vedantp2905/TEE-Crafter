"""Intel TDX deployment phase on GCP (Terraform apply + IAP automation).

Thin wrapper over :func:`run_tunneled_deployment_phase`.
"""
import os

from tee_crafter.cli.constants import Console, Panel
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.gcp_ssh import IAPTunnel, wait_for_ssh, run_ssh_command
from tee_crafter.cli.deployment.tdx.gcp_setup import run_ssh_cloudinit_tdx_gcp_setup
from tee_crafter.cli.deployment.common.gcp_phase_client import run_gcp_client
from tee_crafter.cli.deployment.common.phase_runner import (
    TunnelConn, TunneledPhaseConfig, run_tunneled_deployment_phase,
)

_TDX_GCP_CLIENT_CFG = dict(
    platform="TDX GCP", remote_base="/opt/tee-crafter-tdx",
    service_name="tee-crafter-tdx.service",
    device_chmod_cmd=(
        "for dev in /dev/tdx-guest /dev/tdx_guest; do "
        "  if [ -c \"$dev\" ]; then sudo chmod 0660 \"$dev\"; sudo chgrp kvm \"$dev\" 2>/dev/null; fi; "
        "done; "
        "sudo chgrp kvm /sys/kernel/config/tsm/report/ 2>/dev/null; "
        "sudo chmod 0775 /sys/kernel/config/tsm/report/ 2>/dev/null; "
        "true"
    ),
    client_filename="client_tdx_gcp.py", audit_label="TDX GCP",
    tee_platform_slug="tdx-gcp",
)


def _render_panel(outputs: dict, measurements: dict):
    return Panel(
        f"[cyan]Instance:[/cyan] {outputs.get('instance_name', '')}\n"
        f"[cyan]Zone:[/cyan] {outputs.get('instance_zone', '')}\n"
        f"[cyan]Project:[/cyan] {outputs.get('project', '')}\n"
        f"[cyan]Bucket:[/cyan] {outputs.get('deployment_bucket', '')}\n"
        f"[cyan]MRTD:[/cyan] {measurements.get('mrtd', 'pending')}",
        title="[bold green]TDX GCP Deployment Outputs[/bold green]", border_style="green")


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
                 zone=outputs.get("instance_zone", ""), tee_platform="tdx-gcp")
    from tee_crafter.cli.deployment.common.deploy_verdicts import (
        record_deploy_outputs_verdicts,
    )
    gcp_outputs = dict(outputs)
    gcp_outputs["instance_name"] = outputs.get("instance_name", "")
    record_deploy_outputs_verdicts(audit, gcp_outputs, tee_platform="tdx-gcp")


def _run_client(progress, console, build_dir, ssh_key_path, port, admin_user,
                audit, measurements, outputs):
    return run_gcp_client(
        progress, console, build_dir, ssh_key_path, port, admin_user, audit,
        instance_name=outputs.get("instance_name", ""),
        zone=outputs.get("instance_zone", ""), project=outputs.get("project", ""),
        **_TDX_GCP_CLIENT_CFG, measurements=measurements)


def run_tdx_gcp_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, measurements: dict,
    auto_approve: bool, teardown: bool, source_code=None,
    data_sample_str=None, audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply (GCP TDX), IAP-tunneled setup, optional teardown."""
    cfg = TunneledPhaseConfig(
        tee_platform="tdx-gcp", cloud_label="TDX GCP", tunnel_label="IAP",
        render_panel=_render_panel, build_conn=_build_conn,
        setup_fn=run_ssh_cloudinit_tdx_gcp_setup,
        wait_for_ssh=lambda k, u, p: wait_for_ssh(k, user=u, port=p),
        run_client=_run_client, run_remote=run_ssh_command,
        record_outputs=_record_outputs,
    )
    return run_tunneled_deployment_phase(
        console, build_dir, cpu, ram, measurements, auto_approve, teardown,
        audit, custom_ami, cfg=cfg)
