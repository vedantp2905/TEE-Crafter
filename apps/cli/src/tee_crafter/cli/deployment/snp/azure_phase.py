"""AMD SEV-SNP deployment phase on Azure (Terraform apply + Bastion automation).

Thin wrapper over :func:`run_tunneled_deployment_phase`.
"""
import os

from tee_crafter.cli.constants import Console, Panel
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.azure_ssh import BastionTunnel, wait_for_ssh, run_ssh_command
from tee_crafter.cli.deployment.common.terraform_step import (
    _az_force_delete_rg, _AZURE_RG_NAMES,
)
from tee_crafter.cli.deployment.snp.azure_setup import run_ssh_cloudinit_snp_azure_setup
from tee_crafter.cli.deployment.common.azure_bastion_client import run_azure_bastion_client
from tee_crafter.cli.deployment.common.phase_runner import (
    TunnelConn, TunneledPhaseConfig, run_tunneled_deployment_phase,
)

_SNP_AZURE_CLIENT_CFG = dict(
    platform="SNP Azure", remote_base="/opt/tee-crafter-snp",
    service_name="tee-crafter-snp.service",
    device_chmod_cmd=(
        "for dev in /dev/sev-guest /dev/sev; do "
        "  if [ -c \"$dev\" ]; then sudo chmod 0660 \"$dev\"; sudo chgrp kvm \"$dev\" 2>/dev/null; fi; "
        "done; "
        "sudo chmod 0666 /dev/tpm0 /dev/tpmrm0 2>/dev/null; "
        "true"
    ),
    client_filename="client_snp_azure.py", audit_label="SNP Azure",
    tee_platform_slug="snp-azure",
)


def _pre_apply(console: Console, audit) -> None:
    _az_force_delete_rg(console, _AZURE_RG_NAMES["snp"])
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
        f"[cyan]Measurement:[/cyan] {measurements.get('measurement', 'pending')}",
        title="[bold green]SNP Azure Deployment Outputs[/bold green]", border_style="green")


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
                 bastion=outputs.get("bastion_name", ""), tee_platform="snp-azure")
    from tee_crafter.cli.deployment.common.deploy_verdicts import (
        record_deploy_outputs_verdicts,
    )
    azure_outputs = dict(outputs)
    azure_outputs["instance_name"] = outputs.get("vm_name", "N/A")
    record_deploy_outputs_verdicts(audit, azure_outputs, tee_platform="snp-azure")


def _run_client(progress, console, build_dir, ssh_key_path, port, admin_user,
                audit, measurements, outputs):
    return run_azure_bastion_client(
        progress, console, build_dir, ssh_key_path, port, admin_user, audit,
        **_SNP_AZURE_CLIENT_CFG)


def run_snp_azure_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, measurements: dict,
    auto_approve: bool, teardown: bool, source_code=None,
    data_sample_str=None, audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply (Azure SEV-SNP), Bastion-tunneled setup, optional teardown."""
    cfg = TunneledPhaseConfig(
        tee_platform="snp-azure", cloud_label="SNP Azure", tunnel_label="Bastion",
        render_panel=_render_panel, build_conn=_build_conn,
        setup_fn=run_ssh_cloudinit_snp_azure_setup,
        wait_for_ssh=lambda k, u, p: wait_for_ssh(k, user=u, port=p),
        run_client=_run_client, run_remote=run_ssh_command,
        record_outputs=_record_outputs, pre_apply=_pre_apply,
    )
    return run_tunneled_deployment_phase(
        console, build_dir, cpu, ram, measurements, auto_approve, teardown,
        audit, custom_ami, cfg=cfg)
