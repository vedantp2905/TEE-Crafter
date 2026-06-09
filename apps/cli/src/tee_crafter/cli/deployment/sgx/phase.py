"""Orchestrate SGX deployment phase on Azure: Terraform apply, Bastion-based automation, teardown."""

import os
from tee_crafter.cli.constants import Console
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.core.iac import get_terraform_outputs
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.azure_ssh import BastionTunnel
from tee_crafter.cli.deployment.common.terraform_step import (
    run_terraform_apply_loop,
    cleanup_resources,
    _az_force_delete_rg,
    _AZURE_RG_NAMES,
)
from tee_crafter.cli.deployment.common.phase_runner import destroy_on_failure
from tee_crafter.cli.deployment.sgx.setup import run_ssh_cloudinit_sgx_setup
from tee_crafter.cli.deployment.sgx.enclave import (
    run_sgx_artifact_upload_and_sign,
    run_sgx_client_step,
)
from tee_crafter.cli.deployment.common.siem_sidecar import install_siem_sidecar
from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.core.env_flags import env_hatch_open


def _cleanup_orphaned_deploy_rg(console: Console) -> None:
    """Delete the SGX deploy RG if it exists from a previous failed run."""
    _az_force_delete_rg(console, _AZURE_RG_NAMES["sgx"])


def _stage_siem_on_sgx_host(console, build_dir, ssh_key_path,
                            admin_user, tunnel_port, measurements):
    """Copy siem.env + siem_export.py + a measurements file to the SGX VM
    so the sidecar can read them.  No-op when SIEM is disabled.
    """
    import base64 as _b64
    import json as _json
    from tee_crafter.core.remote.azure_ssh import run_ssh_command
    from tee_crafter.core.audit import build_layout as _layout
    siem_env = None
    for cand in (_layout.siem_env(build_dir),
                 os.path.join(build_dir, "siem.env"),
                 os.path.join(build_dir, "app", "siem.env")):
        if os.path.isfile(cand):
            siem_env = cand
            break
    if not siem_env:
        return
    siem_script = None
    for cand in (os.path.join(build_dir, "siem_export.py"),
                 os.path.join(build_dir, "app", "siem_export.py")):
        if os.path.isfile(cand):
            siem_script = cand
            break
    if not siem_script:
        return
    env_b64 = _b64.b64encode(open(siem_env, "rb").read()).decode("ascii")
    script_b64 = _b64.b64encode(open(siem_script, "rb").read()).decode("ascii")
    # SIEM-SEC-2: token-bearing env goes to tmpfs, non-secret half stays on disk.
    pub_env_path = None
    for cand in (_layout.siem_env_public(build_dir),
                 os.path.join(build_dir, "siem.env.public"),
                 os.path.join(build_dir, "app", "siem.env.public")):
        if os.path.isfile(cand):
            pub_env_path = cand
            break
    pub_b64 = ""
    if pub_env_path:
        pub_b64 = _b64.b64encode(open(pub_env_path, "rb").read()).decode("ascii")
    meas_doc = _json.dumps({
        "measurement": (measurements.get("MRENCLAVE") or "").lower(),
        "mrenclave":   (measurements.get("MRENCLAVE") or "").lower(),
        "mrsigner":    (measurements.get("MRSIGNER") or "").lower(),
        "pipeline_version": "sgx-azure-sidecar",
    })
    meas_b64 = _b64.b64encode(meas_doc.encode("utf-8")).decode("ascii")
    cmd = (
        "set -eu;"
        " sudo mkdir -p /opt/tee-crafter-sgx;"
        " sudo install -d -m 0700 -o tee_enclave -g tee_enclave /run/tee-crafter-sgx-azure;"
        # Secret half -> tmpfs.
        f" echo {env_b64} | base64 -d | sudo tee /run/tee-crafter-sgx-azure/siem.env >/dev/null;"
        " sudo chmod 0600 /run/tee-crafter-sgx-azure/siem.env;"
        " sudo chown tee_enclave:tee_enclave /run/tee-crafter-sgx-azure/siem.env;"
        # Public half -> persistent.
        + (f" echo {pub_b64} | base64 -d | sudo tee /opt/tee-crafter-sgx/siem.env.public >/dev/null;"
           " sudo chmod 0640 /opt/tee-crafter-sgx/siem.env.public;"
           " sudo chown tee_enclave:tee_enclave /opt/tee-crafter-sgx/siem.env.public;"
           if pub_b64 else "")
        + f" echo {script_b64} | base64 -d | sudo tee /opt/tee-crafter-sgx/siem_export.py >/dev/null;"
        f" echo {meas_b64} | base64 -d | sudo tee /opt/tee-crafter-sgx/measurements.json >/dev/null;"
        " sudo chmod 0755 /opt/tee-crafter-sgx/siem_export.py;"
        " sudo /usr/bin/python3 -c 'import cryptography' 2>/dev/null"
        " || sudo /usr/bin/python3 -m pip install --quiet cryptography 2>&1 | tail -3"
    )
    ok, _out, err = run_ssh_command(cmd, ssh_key_path, user=admin_user,
                                     port=tunnel_port, timeout=120)
    if not ok:
        console.print(f"[yellow]SIEM: failed to stage on SGX host: "
                      f"{(err or '')[-200:]}[/yellow]")


def run_sgx_deployment_phase(
    console: Console,
    build_dir: str,
    cpu: int,
    ram: int,
    measurements: dict,
    auto_approve: bool,
    teardown: bool,
    source_code=None,
    data_sample_str=None,
    audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply (Azure), Bastion-tunneled SGX automation, optional teardown.

    Returns ``True`` only when the SGX client verified the enclave quote.
    """
    _cleanup_orphaned_deploy_rg(console)
    from tee_crafter.cli.deployment.common import ensure_azure_network_watcher
    ensure_azure_network_watcher(console, os.environ.get("TF_VAR_azure_location", os.environ.get("AZURE_LOCATION", "westus")))
    max_retries = min(2, max(1, int(os.getenv("TEE_CRAFTER_PHASE4_MAX_RETRIES", "2"))))
    apply_success, last_error_msg = run_terraform_apply_loop(console, build_dir, auto_approve, audit)
    destroy_already_run = False
    automation_success = False
    teardown_ok: bool | None = None
    outputs: dict = {}

    if not apply_success:
        console.print(f"\n[bold red]Deployment failed after {max_retries} Terraform apply attempts.[/bold red]")
        console.print(f"[red]Last Error:[/red] {last_error_msg}\n")
        if audit:
            audit.record("Phase 4: Deployment", "Terraform apply", "fail", attempts=max_retries)
        teardown_ok = destroy_on_failure(
            console, build_dir, audit, destroy_fn=cleanup_resources,
            context="Post-failure cleanup",
            step="Terraform destroy (apply failed)")
        destroy_already_run = teardown_ok is not None
    else:
        console.print("\n[bold green]Step 7 complete.[/bold green] SGX infrastructure deployed via Terraform (Azure).\n")
        outputs = get_terraform_outputs(build_dir)
        vm_private_ip = outputs.get("vm_private_ip", "N/A")
        vm_name = outputs.get("vm_name", "N/A")
        vm_id = outputs.get("vm_id", "")
        resource_group = outputs.get("resource_group", "N/A")
        bastion_name = outputs.get("bastion_name", "")
        ssh_key_path = outputs.get("ssh_private_key_path", "")
        admin_user = outputs.get("admin_username", "azureuser")

        if ssh_key_path and not os.path.isabs(ssh_key_path):
            ssh_key_path = os.path.join(os.path.abspath(build_dir), ssh_key_path)

        console.print(Panel(
            f"[cyan]VM Name:[/cyan] {vm_name}\n"
            f"[cyan]Private IP:[/cyan] {vm_private_ip}\n"
            f"[cyan]Resource Group:[/cyan] {resource_group}\n"
            f"[cyan]Bastion:[/cyan] {bastion_name}\n"
            f"[cyan]MRENCLAVE:[/cyan] {measurements.get('MRENCLAVE', 'pending')}\n"
            f"[cyan]MRSIGNER:[/cyan] {measurements.get('MRSIGNER', 'pending')}",
            title="[bold green]SGX Deployment Outputs (Azure — Bastion)[/bold green]",
            border_style="green",
        ))
        if audit:
            audit.record("Phase 4: Deployment", "Infrastructure outputs", "info",
                         vm_name=vm_name, bastion=bastion_name, tee_platform="sgx-azure")
            from tee_crafter.cli.deployment.common.deploy_verdicts import (
                record_deploy_outputs_verdicts,
            )
            azure_outputs = dict(outputs)
            azure_outputs["instance_name"] = vm_name
            record_deploy_outputs_verdicts(audit, azure_outputs, tee_platform="sgx-azure")

        DEBUG = (
            env_hatch_open("TEE_CRAFTER_DEBUG_SGX")
            or env_hatch_open("TEE_CRAFTER_DEBUG")
        )
        if DEBUG:
            console.print("[dim]DEBUG SGX phase: Terraform outputs retrieved (vm_id, bastion, private_ip).[/dim]")

        if bastion_name and vm_id and ssh_key_path:
            if DEBUG:
                console.print(f"[dim]DEBUG SGX phase: Starting Step 8 (Bastion tunnel) bastion={bastion_name}[/dim]")

            # Open a persistent Bastion tunnel to SSH (port 22) for the entire setup phase
            console.print("[yellow]Opening Bastion tunnel to VM port 22 (may take a few minutes)...[/yellow]")
            ssh_tunnel = BastionTunnel(bastion_name, resource_group, vm_id, 22)
            try:
                ssh_tunnel.start(timeout=300)
                console.print(f"[green]✓ Bastion tunnel ready (localhost:{ssh_tunnel.local_port} -> VM:22)[/green]")

                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                              console=console, transient=False) as progress:
                    if custom_ami:
                        from tee_crafter.core.remote.azure_ssh import wait_for_ssh
                        t = progress.add_task("[yellow]Waiting for SSH on custom-image VM...[/yellow]", total=None)
                        ok = wait_for_ssh(ssh_key_path, user=admin_user, port=ssh_tunnel.local_port)
                        progress.update(t, description=(
                            "[green]✓ SSH online (custom image, setup skipped).[/green]" if ok
                            else "[bold red]✗ SSH timed out.[/bold red]"
                        ))
                        if audit and ok:
                            audit.record("Phase 5: Post-Deploy", "SSH available (custom image, Bastion)", "pass")
                    else:
                        ok = run_ssh_cloudinit_sgx_setup(
                            progress, console, ssh_key_path,
                            build_dir, cpu, ram, audit,
                            admin_user=admin_user,
                            tunnel_port=ssh_tunnel.local_port,
                        )
                    if ok:
                        host_measurements = run_sgx_artifact_upload_and_sign(
                            progress, console, build_dir, ssh_key_path,
                            cpu, ram, audit,
                            admin_user=admin_user,
                            tunnel_port=ssh_tunnel.local_port,
                        )
                        if host_measurements:
                            measurements.update(host_measurements)
                            _stage_siem_on_sgx_host(
                                console, build_dir, ssh_key_path,
                                admin_user, ssh_tunnel.local_port, measurements,
                            )
                            def _siem_remote(c, _k=ssh_key_path, _u=admin_user, _p=ssh_tunnel.local_port):
                                from tee_crafter.core.remote.azure_ssh import run_ssh_command as _rsc
                                return _rsc(c, _k, user=_u, port=_p, timeout=60)
                            install_siem_sidecar(
                                console=console, build_dir=build_dir,
                                tee_platform="sgx-azure",
                                run_remote=_siem_remote, audit=audit,
                            )
                            from tee_crafter.cli.deployment.common.byok_sidecar import install_byok_sidecar
                            install_byok_sidecar(
                                console=console, build_dir=build_dir,
                                tee_platform="sgx-azure",
                                run_remote=_siem_remote, audit=audit,
                            )
                            try:
                                from tee_crafter.cli.deployment.common.post_deploy_probes import (
                                    run_post_deploy_probes,
                                )
                                run_post_deploy_probes(
                                    audit, tee_platform="sgx-azure",
                                    build_dir=build_dir, run_remote=_siem_remote,
                                )
                            except Exception as exc:
                                console.print(
                                    f"[yellow]Post-deploy probes skipped: "
                                    f"{type(exc).__name__}: {exc}[/yellow]"
                                )
                            automation_success = run_sgx_client_step(
                                progress, console, build_dir,
                                bastion_name, resource_group, vm_id,
                                ssh_key_path, outputs, measurements, audit,
                                admin_user=admin_user,
                                ssh_tunnel_port=ssh_tunnel.local_port,
                            )
                        else:
                            console.print("[yellow]Could not sign manifest on host. Skipping client run.[/yellow]")

            except Exception as e:
                console.print("[bold red]Bastion tunnel failed:[/bold red]", end=" ")
                console.print(str(e), markup=False)
                if audit:
                    audit.record("Phase 5: Post-Deploy", "Bastion tunnel (SSH)", "fail", reason=str(e))
            finally:
                ssh_tunnel.stop()

        if automation_success:
            console.print("\n[bold green]SGX deployment pipeline complete.[/bold green]\n")
        else:
            console.print("\n[bold yellow]Infrastructure deployed, but post-deployment automation did not fully succeed.[/bold yellow]\n")
            teardown_ok = destroy_on_failure(
                console, build_dir, audit, destroy_fn=cleanup_resources,
                context="Automation-failure cleanup",
                step="Terraform destroy (on failure)")
            destroy_already_run = teardown_ok is not None

    if teardown and not destroy_already_run:
        console.print("[yellow]Step 9: Executing teardown...[/yellow]")
        teardown_ok = cleanup_resources(console, build_dir, context="Teardown")
        if teardown_ok:
            console.print("[green]✓ Step 9: Resources destroyed successfully.[/green]")
        else:
            console.print("[bold red]✗ Step 9 Failed (teardown).[/bold red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Terraform destroy (teardown)",
                         "pass" if teardown_ok else "fail")
    elif not destroy_already_run:
        console.print(f"\n[dim]To tear down: [bold]tee-crafter destroy --build-dir {os.path.abspath(build_dir)}[/bold][/dim]")

    if audit:
        from tee_crafter.cli.audit_helpers import emit_teardown_and_cloud_audit
        # ``teardown_ok`` is an explicit variable.  It used to be
        # ``locals().get("ok")``, which on the happy path picked up the
        # *SSH-setup* result from the block above — so a run that never tore
        # anything down could still record a passing teardown verdict.
        emit_teardown_and_cloud_audit(
            audit, tee_platform="sgx-azure",
            teardown_ok=teardown_ok,
            outputs=outputs,
            build_dir=build_dir,
        )
        save_audit_trail(audit, build_dir, console)
    return bool(apply_success and automation_success)
