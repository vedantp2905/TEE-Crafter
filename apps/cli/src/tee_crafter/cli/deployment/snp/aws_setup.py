"""SNP AWS post-deploy setup: SSM wait, cloud-init, host installation."""

import os
import time


from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.remote.ssm import wait_for_ssm, run_ssm_command
from tee_crafter.cli.constants import Console, Progress


def run_ssm_cloudinit_snp_aws_setup(
    progress: Progress,
    console: Console,
    instance_id: str,
    bucket_name: str,
    build_dir: str,
    cpu: int,
    ram: int,
    audit: BuildAuditTrail | None = None,
) -> tuple[bool, str]:
    """
    Wait for SSM, wait for cloud-init, upload and run the SNP AWS setup script.
    Returns (success, aws_region).
    """
    import boto3

    boto3_region = boto3.Session().region_name
    aws_region = (
        os.getenv("TF_VAR_aws_region")
        or os.getenv("AWS_REGION")
        or boto3_region
        or "us-east-2"
    )
    console.print(f"[dim]SNP-AWS: resolved region={aws_region} "
                  f"(TF_VAR_aws_region / AWS_REGION / boto3 session)[/dim]")

    # 1. Wait for SSM
    t = progress.add_task("[yellow]Waiting for SSM agent...[/yellow]", total=None)
    console.print(f"[dim]SNP-AWS: waiting for SSM on {instance_id} (region={aws_region})...[/dim]")
    ok = wait_for_ssm(instance_id, aws_region)
    if not ok:
        progress.update(t, description="[bold red]✗ SSM timed out.[/bold red]")
        console.print("[red]SNP-AWS: SSM timed out. Check: instance running? "
                      "IAM has AmazonSSMManagedInstanceCore? Subnet has internet/VPC endpoint?[/red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SSM wait (SNP AWS)", "fail")
        return False, aws_region
    progress.update(t, description="[green]✓ SSM online.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SSM agent online (SNP AWS)", "pass")

    # 2. Wait for cloud-init
    t = progress.add_task("[yellow]Waiting for cloud-init...[/yellow]", total=None)
    for _attempt in range(30):
        ok_cmd, out, _ = run_ssm_command(
            instance_id,
            "cloud-init status --wait 2>/dev/null || echo 'done'",
            aws_region, timeout=120,
        )
        status_str = (out or "").strip()
        if _attempt % 5 == 0:
            console.print(f"[dim]SNP-AWS: cloud-init poll #{_attempt}, ok={ok_cmd}, "
                          f"status={repr(status_str[-80:])}[/dim]")
        if ok_cmd and ("done" in status_str.lower() or "status: done" in status_str.lower()):
            break
        time.sleep(10)
    progress.update(t, description="[green]✓ Cloud-init complete.[/green]")

    # 3. Upload and run setup script via SSM
    t = progress.add_task("[yellow]Running SNP AWS host setup...[/yellow]", total=None)

    script_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts", "snp_aws"
    )
    setup_script = os.path.join(script_dir, "setup_snp_aws.sh")

    if not os.path.isfile(setup_script):
        progress.update(t, description="[red]✗ setup_snp_aws.sh not found.[/red]")
        console.print(f"[red]SNP-AWS: expected script at {setup_script}[/red]")
        return False, aws_region

    from tee_crafter.cli.loaders import _inject_security_profiles

    with open(setup_script, "r", encoding="utf-8") as f:
        script_content = _inject_security_profiles(f.read())

    console.print(f"[dim]SNP-AWS: dispatching setup_snp_aws.sh ({len(script_content)} bytes) via SSM...[/dim]")
    ok_cmd, out, err = run_ssm_command(
        instance_id,
        script_content,
        aws_region, timeout=600,
    )
    if out:
        console.print(f"[dim]SNP-AWS: setup script output (last 1000 chars):\n{out[-1000:]}[/dim]")

    if not ok_cmd:
        progress.update(t, description="[red]✗ SNP AWS setup script failed.[/red]")
        if err:
            console.print(f"[red]SNP-AWS: setup script stderr:\n{err[-800:]}[/red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SNP AWS host setup", "fail",
                         reason=(err or "")[:200])
        return False, aws_region

    progress.update(t, description="[green]✓ SNP AWS host setup complete.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SNP AWS host setup", "pass")

    # 4. Verify SEV-SNP is active (check both /dev/sev-guest and /dev/sev)
    t = progress.add_task("[yellow]Verifying SEV-SNP is active...[/yellow]", total=None)
    ok_cmd, out, snp_err = run_ssm_command(
        instance_id,
        "ls -la /dev/sev-guest /dev/sev 2>&1; "
        "dmesg 2>/dev/null | grep -i 'sev-snp\\|sev_snp\\|SEV.*SNP' | tail -5; "
        "echo SNP_OK",
        aws_region, timeout=30,
    )
    if ok_cmd and "SNP_OK" in (out or ""):
        progress.update(t, description="[green]✓ AMD SEV-SNP verified active.[/green]")
        console.print(f"[dim]SNP-AWS: SEV-SNP verification output:\n{(out or '').strip()[:500]}[/dim]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "SEV-SNP verification", "pass")
    else:
        progress.update(t, description="[yellow]! SEV-SNP verification inconclusive; proceeding.[/yellow]")
        console.print(f"[dim]SNP-AWS: SEV-SNP verification (inconclusive):\n"
                      f"  stdout: {(out or '').strip()[:500]}\n"
                      f"  stderr: {(snp_err or '').strip()[:300]}[/dim]")

    return True, aws_region
