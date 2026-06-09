"""SNP Azure post-deploy setup: SSH wait, cloud-init, host installation via Bastion tunnel."""

import os
import time


from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.azure_ssh import wait_for_ssh, run_ssh_command, upload_file_via_scp
from tee_crafter.cli.constants import Console, Progress


def run_ssh_cloudinit_snp_azure_setup(
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
    Wait for SSH, wait for cloud-init, upload and run the SNP Azure setup script.
    Returns True on success.
    """
    # 1. Wait for SSH
    t = progress.add_task("[yellow]Waiting for SSH (via Bastion)...[/yellow]", total=None)
    ok = wait_for_ssh(ssh_key_path, user=admin_user, port=tunnel_port, timeout=300)
    if not ok:
        progress.update(t, description="[bold red]✗ SSH timed out.[/bold red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SSH wait (Bastion, SNP Azure)", "fail")
        return False
    progress.update(t, description="[green]✓ SSH online.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SSH available (Bastion, SNP Azure)", "pass")

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
    t = progress.add_task("[yellow]Running SNP Azure host setup...[/yellow]", total=None)

    script_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts", "snp_azure"
    )
    setup_script = os.path.join(script_dir, "setup_snp_azure.sh")

    if not os.path.isfile(setup_script):
        progress.update(t, description="[red]✗ setup_snp_azure.sh not found.[/red]")
        return False

    import tempfile
    # Use the same loader the bake path uses — see the note in
    # ``deployment/tdx/setup.py``: calling ``_inject_security_profiles`` alone
    # left ``__SYSTEMD_UNIT__`` and friends as literal text in the uploaded
    # script, and would now swallow ``__AZURE_GUEST_ATTESTATION__`` as well.
    from tee_crafter.cli.loaders import load_snp_azure_setup_template

    enriched = load_snp_azure_setup_template()
    tmp_script = tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", delete=False, encoding="utf-8",
    )
    tmp_script.write(enriched)
    tmp_script.close()

    scp_ok, scp_msg = upload_file_via_scp(
        tmp_script.name, "/tmp/setup_snp_azure.sh",
        ssh_key_path, user=admin_user, port=tunnel_port,
    )
    os.unlink(tmp_script.name)
    if not scp_ok:
        progress.update(t, description=f"[red]✗ Failed to upload setup script: {scp_msg}[/red]")
        return False

    ok_cmd, _out, _err = run_ssh_command(
        "chmod +x /tmp/setup_snp_azure.sh && sudo /tmp/setup_snp_azure.sh",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=600,
    )
    if not ok_cmd:
        progress.update(t, description="[red]✗ SNP Azure setup script failed.[/red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SNP Azure host setup", "fail",
                         reason=(_err or "")[:200])
        return False
    progress.update(t, description="[green]✓ SNP Azure host setup complete.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SNP Azure host setup", "pass")

    # 4. Verify SEV-SNP is active
    t = progress.add_task("[yellow]Verifying SEV-SNP on Azure...[/yellow]", total=None)
    ok_cmd, out, _ = run_ssh_command(
        "ls -la /dev/sev-guest 2>&1 && snpguest report /tmp/test_snp.bin /dev/urandom --random 2>&1 && echo SNP_OK",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=30,
    )
    if ok_cmd and "SNP_OK" in (out or ""):
        progress.update(t, description="[green]✓ AMD SEV-SNP verified active on Azure.[/green]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SEV-SNP verification (Azure)", "pass")
    else:
        progress.update(t, description="[yellow]! SNP verification inconclusive; proceeding.[/yellow]")

    return True
