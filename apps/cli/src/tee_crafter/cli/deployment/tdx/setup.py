"""TDX post-deploy setup: SSH wait, cloud-init, host installation via Bastion tunnel."""

import os
import time


from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.azure_ssh import wait_for_ssh, run_ssh_command, upload_file_via_scp
from tee_crafter.cli.constants import Console, Progress


def run_ssh_cloudinit_tdx_setup(
    progress: Progress,
    console: Console,
    ssh_key_path: str,
    build_dir: str,
    cpu: int,
    ram: int,
    audit: BuildAuditTrail | None = None,
    admin_user: str = "azureuser",
    tunnel_port: int = 0,
) -> bool:
    """
    Wait for SSH, wait for cloud-init, upload and run the TDX setup script.
    Returns True on success.
    """
    # 1. Wait for SSH
    t = progress.add_task("[yellow]Waiting for SSH (via Bastion)...[/yellow]", total=None)
    ok = wait_for_ssh(ssh_key_path, user=admin_user, port=tunnel_port, timeout=300)
    if not ok:
        progress.update(t, description="[bold red]✗ SSH timed out.[/bold red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SSH wait (Bastion)", "fail")
        return False
    progress.update(t, description="[green]✓ SSH online.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SSH available (Bastion)", "pass")

    # 2. Wait for cloud-init
    t = progress.add_task("[yellow]Waiting for cloud-init to finish...[/yellow]", total=None)
    for _attempt in range(30):
        ok_cmd, out, _ = run_ssh_command(
            "cloud-init status --wait 2>/dev/null || echo 'done'",
            ssh_key_path, user=admin_user, port=tunnel_port, timeout=120,
        )
        if ok_cmd and (out and ("done" in out.lower() or "status: done" in out.lower())):
            break
        time.sleep(10)
    progress.update(t, description="[green]✓ Cloud-init complete.[/green]")

    # 3. Upload and run setup script
    t = progress.add_task("[yellow]Running TDX host setup...[/yellow]", total=None)

    script_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts", "tdx_azure"
    )
    setup_script = os.path.join(script_dir, "setup_tdx.sh")

    if not os.path.isfile(setup_script):
        progress.update(t, description="[red]✗ setup_tdx.sh not found.[/red]")
        return False

    import tempfile
    # Use the same loader the bake path uses.  This used to call
    # ``_inject_security_profiles`` alone, which left ``__SYSTEMD_UNIT__``,
    # ``__CONTAINER_UNIT__`` and ``__SECRETS_UNIT__`` as literal text in the
    # uploaded script — so this path wrote a unit file containing the word
    # ``__SYSTEMD_UNIT__``.  Latent rather than live, because it only runs on the
    # unbaked-image path and production requires a pinned image, but it would
    # have swallowed the guest-attestation fragment too.
    from tee_crafter.cli.loaders import load_tdx_setup_template

    enriched = load_tdx_setup_template()
    tmp_script = tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", delete=False, encoding="utf-8",
    )
    tmp_script.write(enriched)
    tmp_script.close()

    scp_ok, scp_msg = upload_file_via_scp(
        tmp_script.name, "/tmp/setup_tdx.sh",
        ssh_key_path, user=admin_user, port=tunnel_port,
    )
    os.unlink(tmp_script.name)
    if not scp_ok:
        progress.update(t, description="[red]✗ Failed to upload setup script: {}[/red]".format(scp_msg))
        return False

    ok_cmd, _out, _err = run_ssh_command(
        "chmod +x /tmp/setup_tdx.sh && sudo /tmp/setup_tdx.sh",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=600,
    )
    if not ok_cmd:
        progress.update(t, description="[red]✗ TDX setup script failed.[/red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "TDX host setup", "fail", reason=_err[:200] if _err else "script failed")
        return False
    progress.update(t, description="[green]✓ TDX host setup complete.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "TDX host setup", "pass")

    return True
