"""EIF upload, enclave run, and host proxy start."""

import json
import os
from rich.progress import Progress

from nitro_agent.core.ssm import upload_file_via_s3, run_ssm_command
from nitro_agent.core.enclave import parse_enclave_cid
from nitro_agent.core.audit import BuildAuditTrail, sha256_file


def run_eif_upload_enclave_proxy(
    progress: Progress,
    console,
    build_dir: str,
    instance_id: str,
    bucket_name: str,
    cpu: int,
    ram: int,
    audit: BuildAuditTrail | None,
    aws_region: str,
) -> str | None:
    """
    Upload EIF, run enclave, start host proxy. Returns EnclaveCID string or None.
    """
    enclave_memory = max(512, ram)
    eif_local = os.path.join(build_dir, "app.eif")
    task_upload = progress.add_task("[yellow]Step 8d: Uploading Enclave Image...[/yellow]", total=None)
    if not os.path.exists(eif_local):
        progress.update(task_upload, description=f"[bold red]✗ Step 8d Failed: EIF not found at {eif_local}[/bold red]")
        return None
    success, msg = upload_file_via_s3(eif_local, bucket_name, "app.eif", instance_id, "/home/ec2-user/app.eif", aws_region)
    if not success:
        progress.update(task_upload, description=f"[bold red]✗ Step 8d Failed (Upload):[/bold red] {msg}")
        return None
    progress.update(task_upload, description="[green]✓ Step 8d: EIF uploaded to host.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "EIF uploaded to host", "pass", eif_sha256=sha256_file(eif_local))

    task_run = progress.add_task("[yellow]Step 8e: Starting enclave...[/yellow]", total=None)
    run_cmd = f"sudo /usr/bin/nitro-cli run-enclave --cpu-count {cpu} --memory {enclave_memory} --eif-path /home/ec2-user/app.eif --enclave-cid 16"
    success, stdout, stderr = run_ssm_command(instance_id, run_cmd, aws_region)
    if not success:
        progress.update(task_run, description="[bold red]✗ Step 8e Failed: Failed to start enclave.[/bold red]")
        console.print(f"[red]Enclave Start STDOUT:[/red]\n{stdout}\n[red]STDERR:[/red]\n{stderr}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Enclave started", "fail")
        return None
    progress.update(task_run, description="[green]✓ Step 8e: Enclave started.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "Enclave started", "pass", cpu=cpu, memory_mb=enclave_memory)
    cid = parse_enclave_cid(stdout)
    if not cid:
        desc_success, desc_out, desc_err = run_ssm_command(instance_id, "nitro-cli describe-enclaves", aws_region)
        if desc_success:
            try:
                enclaves = json.loads(desc_out)
                if enclaves and isinstance(enclaves, list):
                    cid = str(enclaves[0].get("EnclaveCID", ""))
            except Exception:
                pass
    if not cid:
        return None

    task_proxy = progress.add_task("[yellow]Step 8f: Starting host proxy service...[/yellow]", total=None)
    host_proxy_local = os.path.join(build_dir, "host_proxy.py")
    upload_file_via_s3(host_proxy_local, bucket_name, "host_proxy.py", instance_id, "/home/ec2-user/host_proxy.py", aws_region)
    hp_success, hp_out, hp_err = run_ssm_command(instance_id, "sudo systemctl restart host-proxy.service", aws_region)
    if hp_success:
        progress.update(task_proxy, description="[green]✓ Step 8f: Host proxy service started.[/green]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Host proxy started", "pass")
    else:
        progress.update(task_proxy, description="[bold red]✗ Step 8f Failed: Failed to start host proxy.[/bold red]")
        console.print(f"[red]Host Proxy STDOUT:[/red]\n{hp_out}\n[red]STDERR:[/red]\n{hp_err}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Host proxy started", "fail")
    return cid
