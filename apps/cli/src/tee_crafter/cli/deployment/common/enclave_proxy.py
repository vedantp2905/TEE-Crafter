"""EIF upload, enclave run, and host proxy start."""

import json
import os
import time

from tee_crafter.core.remote.ssm import upload_file_via_s3, run_ssm_command
from tee_crafter.core.enclave import parse_enclave_cid
from tee_crafter.core.audit import BuildAuditTrail, sha256_file
from tee_crafter.cli.constants import Progress


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
    eif_size_mb = 0
    if os.path.exists(eif_local):
        eif_size_mb = os.path.getsize(eif_local) / (1024 * 1024)
    task_upload = progress.add_task(
        f"[yellow]Step 8d: Uploading Enclave Image ({eif_size_mb:.0f} MB, may take a few minutes)...[/yellow]",
        total=None,
    )
    #console.print(f"[dim]Nitro debug: EIF local path={eif_local}, size={eif_size_mb:.1f} MB[/dim]")
    if not os.path.exists(eif_local):
        progress.update(task_upload, description=f"[bold red]✗ Step 8d Failed: EIF not found at {eif_local}[/bold red]")
        return None

    #console.print(f"[dim]Nitro debug: starting S3+SSM upload (bucket={bucket_name}, key=app.eif, region={aws_region})[/dim]")
    success, msg = upload_file_via_s3(
        eif_local, bucket_name, "app.eif",
        instance_id, "/home/ec2-user/app.eif", aws_region,
        timeout=600, retries=3,
    )
    if not success:
        progress.update(task_upload, description=f"[bold red]✗ Step 8d Failed (Upload):[/bold red] {msg}")
        console.print(f"[red]Nitro debug: EIF upload failed. Details:[/red]\n{msg}")
        return None
    progress.update(task_upload, description="[green]✓ Step 8d: EIF uploaded to host.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "EIF uploaded to host", "pass", eif_sha256=sha256_file(eif_local))

    task_run = progress.add_task("[yellow]Step 8e: Starting enclave...[/yellow]", total=None)
    run_cmd = f"sudo /usr/bin/nitro-cli run-enclave --cpu-count {cpu} --memory {enclave_memory} --eif-path /home/ec2-user/app.eif --enclave-cid 16"
    console.print(f"[dim]Nitro debug: run-enclave cmd: {run_cmd}[/dim]")

    max_attempts = 3
    success = False
    stdout = stderr = ""
    for attempt in range(1, max_attempts + 1):
        progress.update(task_run, description=f"[yellow]Step 8e: Starting enclave (attempt {attempt}/{max_attempts})...[/yellow]")
        success, stdout, stderr = run_ssm_command(instance_id, run_cmd, aws_region, timeout=360)
        console.print(f"[dim]Nitro debug: run-enclave attempt {attempt} success={success}[/dim]")
        if not success:
            console.print(f"[dim]Nitro debug: run-enclave stdout (truncated):[/dim]\n{stdout[:800]}")
            console.print(f"[dim]Nitro debug: run-enclave stderr (truncated):[/dim]\n{stderr[:800]}")
        if success:
            break
        if attempt < max_attempts:
            time.sleep(15)

    if not success:
        progress.update(task_run, description="[bold red]✗ Step 8e Failed: Failed to start enclave.[/bold red]")
        console.print(f"[red]Enclave Start STDOUT:[/red]\n{stdout}\n[red]STDERR:[/red]\n{stderr}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Enclave started", "fail")
        return None
    progress.update(task_run, description="[green]✓ Step 8e: Enclave started.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "Enclave started", "pass", cpu=cpu, memory_mb=enclave_memory)
    console.print(f"[dim]Nitro debug: run-enclave raw output (truncated):[/dim]\n{stdout[:800]}")
    cid = parse_enclave_cid(stdout)
    if not cid:
        console.print("[dim]Nitro debug: parse_enclave_cid returned empty, falling back to 'nitro-cli describe-enclaves'[/dim]")
        desc_success, desc_out, desc_err = run_ssm_command(instance_id, "nitro-cli describe-enclaves", aws_region)
        if desc_success:
            try:
                enclaves = json.loads(desc_out)
                if enclaves and isinstance(enclaves, list):
                    cid = str(enclaves[0].get("EnclaveCID", ""))
            except Exception:
                pass
        else:
            console.print(f"[dim]Nitro debug: describe-enclaves failed. stdout:[/dim]\n{desc_out[:800]}")
            console.print(f"[dim]Nitro debug: describe-enclaves stderr:[/dim]\n{desc_err[:800]}")
    if not cid:
        console.print("[red]Nitro debug: could not determine Enclave CID after run-enclave and describe-enclaves.[/red]")
        return None

    # Restart vsock-proxy now that the enclave is running. On baked AMIs the
    # service auto-starts at boot before any enclave exists, hits
    # "Could not bind to cid: 3 port: 8000", and enters a failed state.
    console.print("[dim]Nitro debug: restarting nitro-enclaves-vsock-proxy.service[/dim]")
    run_ssm_command(
        instance_id,
        "sudo systemctl restart nitro-enclaves-vsock-proxy.service",
        aws_region,
    )

    task_proxy = progress.add_task("[yellow]Step 8f: Starting host proxy service...[/yellow]", total=None)

    # Stop any crash-looping proxy from boot and self-heal the five most
    # common reasons `systemctl start host-proxy.service` fails on a baked
    # Nitro AMI:
    #   1. `tee_enclave` user/group is missing (older bakes or a different
    #      setup script was used) → `User=tee_enclave` fails to resolve and
    #      systemd rejects the unit *before* ExecStart runs.
    #   2. `/opt/tee-crafter` was not chowned to tee_enclave (or was created
    #      later by the SSM-as-root upload) → WorkingDirectory fails.
    #   3. `/etc/tee_crafter/certs/host.{key,crt}` missing or not readable
    #      by the tee_enclave group → uvicorn can't load the TLS material
    #      and exits 1 before binding.
    #   4. Another process (e.g. a zombie proxy from a crash-loop during
    #      bake) is bound to 127.0.0.1:443 → bind EADDRINUSE.
    #   5. The baked unit's ExecStart has the literal `$PYTHON_BIN` token
    #      (systemd doesn't expand env refs inside ExecStart) → exec fails
    #      with ENOENT.
    # We repair all of these, then stamp a drop-in override that sets the
    # resolved python path + WorkingDirectory so we're independent of the
    # baked unit's state.
    run_ssm_command(
        instance_id,
        # --- 1 & 5 --- stop any old instance, clear crash-loop counter
        "sudo systemctl stop host-proxy.service 2>/dev/null; "
        "sudo systemctl reset-failed host-proxy.service 2>/dev/null; "
        # --- 1 --- ensure tee_enclave user/group exists
        "id -u tee_enclave >/dev/null 2>&1 || "
        "sudo useradd --system --create-home --home-dir /home/tee_enclave "
        "--shell /usr/sbin/nologin tee_enclave || true; "
        "sudo usermod -aG ne tee_enclave 2>/dev/null || true; "
        # --- 2 --- WorkingDirectory + host_proxy.py owner/perms
        "sudo mkdir -p /opt/tee-crafter; "
        "sudo chown -R tee_enclave:tee_enclave /opt/tee-crafter 2>/dev/null || true; "
        "sudo chmod 755 /opt/tee-crafter 2>/dev/null || true; "
        # --- 2b --- /var/log/tee_crafter must exist *before* systemd applies
        # ReadWritePaths (otherwise ExecStartPre fails with 226/NAMESPACE).
        # LogsDirectory= in the unit also creates this on modern systemd; mkdir
        # fixes older baked AMIs and races.
        "sudo mkdir -p /var/log/tee_crafter; "
        "sudo chown tee_enclave:tee_enclave /var/log/tee_crafter 2>/dev/null || "
        "sudo chown root:root /var/log/tee_crafter; "
        "sudo chmod 755 /var/log/tee_crafter 2>/dev/null || true; "
        # --- 3 --- cert dir + files readable by tee_enclave group; regenerate
        # if either the key or the cert is missing (a partial bake can leave
        # only one of them).
        "sudo mkdir -p /etc/tee_crafter/certs; "
        "if [ ! -s /etc/tee_crafter/certs/host.key ] || "
        "[ ! -s /etc/tee_crafter/certs/host.crt ]; then "
        "  sudo openssl req -x509 -nodes -days 365 -newkey ec "
        "    -pkeyopt ec_paramgen_curve:secp384r1 "
        "    -keyout /etc/tee_crafter/certs/host.key "
        "    -out /etc/tee_crafter/certs/host.crt "
        "    -subj '/C=US/ST=State/L=City/O=TEECrafter/CN=tee-enclave.local' "
        "    2>/dev/null || true; "
        "fi; "
        "sudo chown root:tee_enclave /etc/tee_crafter/certs/host.key /etc/tee_crafter/certs/host.crt 2>/dev/null || true; "
        "sudo chmod 640 /etc/tee_crafter/certs/host.key /etc/tee_crafter/certs/host.crt 2>/dev/null || true; "
        "sudo chmod 755 /etc/tee_crafter /etc/tee_crafter/certs 2>/dev/null || true; "
        # --- 4 --- free up 127.0.0.1:443 if a zombie uvicorn is clinging to it
        "(sudo ss -ltnp 'sport = :443' 2>/dev/null | awk 'NR>1 {print $NF}' | "
        "  grep -oE 'pid=[0-9]+' | cut -d= -f2 | xargs -r sudo kill -9) 2>/dev/null || true; "
        # --- 5 --- resolve python + write drop-in override
        "sudo mkdir -p /etc/systemd/system/host-proxy.service.d; "
        "PYBIN=$( [ -x /usr/bin/python3.12 ] && echo /usr/bin/python3.12 || echo /usr/bin/python3 ); "
        "printf \"[Service]\\nUser=tee_enclave\\nGroup=tee_enclave\\n"
        "LogsDirectory=tee_crafter\\n"
        "WorkingDirectory=/opt/tee-crafter\\n"
        "ExecStartPre=\\nExecStartPre=/bin/test -f /opt/tee-crafter/host_proxy.py\\n"
        "ExecStart=\\nExecStart=$PYBIN -m uvicorn host_proxy:app "
        "--host 127.0.0.1 --port 443 "
        "--ssl-keyfile=/etc/tee_crafter/certs/host.key "
        "--ssl-certfile=/etc/tee_crafter/certs/host.crt\\n"
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_VSOCK\\n"
        "TimeoutStartSec=90s\\n\" "
        "| sudo tee /etc/systemd/system/host-proxy.service.d/override.conf > /dev/null; "
        "sudo systemctl daemon-reload; true",
        aws_region,
    )

    # Verify host proxy Python deps are present (may be missing if bake
    # used a different Python version or pip install failed during bake).
    # If missing, download wheels locally and install offline — same
    # airgapped approach used by every other TEE platform.
    chk_ok, chk_out, _ = run_ssm_command(
        instance_id,
        "PYBIN=$( [ -x /usr/bin/python3.12 ] && echo /usr/bin/python3.12 || echo /usr/bin/python3 ); "
        "$PYBIN -c 'import uvicorn, fastapi, boto3, cryptography, requests' 2>&1 && echo DEPS_OK",
        aws_region, timeout=30,
    )
    if not chk_ok or "DEPS_OK" not in (chk_out or ""):
        console.print("[dim]Nitro: host proxy deps missing — installing via offline wheels[/dim]")
        if chk_out:
            console.print(f"[dim]Nitro debug: pre-install import error:\n{chk_out.strip()[:500]}[/dim]")
        from tee_crafter.cli.deployment.common.wheel_manager import make_nitro_proxy_wheel_bundle
        pyv_ok, pyv_out, _ = run_ssm_command(
            instance_id,
            "PYBIN=$( [ -x /usr/bin/python3.12 ] && echo /usr/bin/python3.12 || echo /usr/bin/python3 ); "
            "$PYBIN -V 2>&1 | cut -d' ' -f2 | cut -d. -f1,2",
            aws_region, timeout=15,
        )
        py_ver = pyv_out.strip() if pyv_ok and pyv_out.strip() else "3.10"
        bundle_path = make_nitro_proxy_wheel_bundle(console, py_ver)
        try:
            ok, msg = upload_file_via_s3(
                bundle_path, bucket_name, "host_proxy_wheels.tar.gz",
                instance_id, "/tmp/hp_bundle.tar.gz", aws_region,
                timeout=300,
            )
            if ok:
                inst_ok, inst_out, _ = run_ssm_command(
                    instance_id,
                    "cd /tmp && tar xzf hp_bundle.tar.gz && rm -f hp_bundle.tar.gz && "
                    "PYBIN=$( [ -x /usr/bin/python3.12 ] && echo /usr/bin/python3.12 || echo /usr/bin/python3 ); "
                    "sudo $PYBIN -m pip install --no-cache-dir --no-index "
                    "--find-links /tmp/host_proxy_wheels -r /tmp/host_proxy_req.txt 2>&1",
                    aws_region, timeout=240,
                )
                if not inst_ok:
                    console.print(f"[red]Nitro debug: offline wheel install failed:\n{(inst_out or '')[:600]}[/red]")
                # Re-verify imports so the post-install failure doesn't
                # silently cascade into a misleading systemctl error.
                rechk_ok, rechk_out, _ = run_ssm_command(
                    instance_id,
                    "PYBIN=$( [ -x /usr/bin/python3.12 ] && echo /usr/bin/python3.12 || echo /usr/bin/python3 ); "
                    "$PYBIN -c 'import uvicorn, fastapi, boto3, cryptography, requests' 2>&1 && echo DEPS_OK",
                    aws_region, timeout=30,
                )
                if not rechk_ok or "DEPS_OK" not in (rechk_out or ""):
                    console.print(f"[red]Nitro debug: deps still missing after wheel install:\n{(rechk_out or '')[:500]}[/red]")
                else:
                    console.print("[dim]Nitro debug: host proxy deps verified after offline install.[/dim]")
            else:
                console.print(f"[yellow]Nitro: wheel bundle upload failed: {msg}[/yellow]")
        finally:
            try:
                os.unlink(bundle_path)
            except OSError:
                pass

    host_proxy_local = os.path.join(build_dir, "host_proxy.py")
    console.print(f"[dim]Nitro debug: uploading host_proxy.py from {host_proxy_local}[/dim]")
    hp_up_ok, hp_up_msg = upload_file_via_s3(
        host_proxy_local, bucket_name, "host_proxy.py",
        instance_id, "/opt/tee-crafter/host_proxy.py", aws_region,
        timeout=300, retries=2,
    )
    if not hp_up_ok:
        progress.update(task_proxy, description="[bold red]✗ Step 8f Failed: Failed to upload host proxy script.[/bold red]")
        console.print(f"[red]Host proxy upload error:[/red]\n{hp_up_msg}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Host proxy uploaded", "fail", error=hp_up_msg)
        return None
    console.print("[dim]Nitro debug: host_proxy.py uploaded via S3+SSM.[/dim]")

    verify_ok, verify_out, _ = run_ssm_command(
        instance_id,
        "ls -la /opt/tee-crafter/host_proxy.py && echo FILE_EXISTS",
        aws_region,
    )
    if not verify_ok or "FILE_EXISTS" not in (verify_out or ""):
        progress.update(task_proxy, description="[bold red]✗ Step 8f Failed: host_proxy.py not found on instance after upload.[/bold red]")
        console.print(f"[red]Nitro debug: file verification failed. ls output:[/red]\n{verify_out}")
        return None
    console.print("[dim]Nitro debug: host_proxy.py verified on instance.[/dim]")

    # Make the uploaded script owned by the service user and world-readable.
    # SSM writes files as root/0644 which is already importable, but setting
    # the owner explicitly keeps auditors happy and lets tee_enclave write
    # its own __pycache__ (WorkingDirectory is already under /opt/tee-crafter).
    run_ssm_command(
        instance_id,
        "sudo chown tee_enclave:tee_enclave /opt/tee-crafter/host_proxy.py 2>/dev/null || true; "
        "sudo chmod 644 /opt/tee-crafter/host_proxy.py 2>/dev/null || true",
        aws_region,
    )

    # Start the proxy (reset-failed clears the boot crash-loop counter)
    hp_success, hp_out, hp_err = run_ssm_command(
        instance_id,
        "sudo systemctl reset-failed host-proxy.service 2>/dev/null; "
        "sudo systemctl start host-proxy.service",
        aws_region,
    )

    def _dump_host_proxy_diagnostics() -> None:
        """Fetch the real reason host-proxy.service failed.

        ``systemctl start`` only ever prints the generic "Job for X failed"
        line on STDERR; the actual crash trace lives in journald.  Without
        this the operator has to SSM in by hand and run `journalctl -xeu`
        themselves.  Best-effort: never raise.
        """
        try:
            _, diag_out, _ = run_ssm_command(
                instance_id,
                "echo '=== systemctl status host-proxy.service ==='; "
                "sudo systemctl status host-proxy.service --no-pager --full -n 40 || true; "
                "echo '=== journalctl -xeu host-proxy.service (last 120 lines) ==='; "
                "sudo journalctl -xeu host-proxy.service -b --no-pager -n 120 || true; "
                "echo '=== effective unit (base + drop-ins) ==='; "
                "sudo systemctl cat host-proxy.service --no-pager || true; "
                "echo '=== /opt/tee-crafter listing ==='; "
                "sudo ls -la /opt/tee-crafter 2>/dev/null || true; "
                "echo '=== /etc/tee_crafter/certs listing ==='; "
                "sudo ls -la /etc/tee_crafter/certs 2>/dev/null || true; "
                "echo '=== ss -ltnp on 127.0.0.1:443 ==='; "
                "sudo ss -ltnp 'sport = :443' 2>/dev/null || true; "
                "echo '=== tee_enclave id ==='; "
                "id tee_enclave 2>/dev/null || echo 'MISSING tee_enclave user'; "
                "echo '=== python import sanity ==='; "
                "PYBIN=$( [ -x /usr/bin/python3.12 ] && echo /usr/bin/python3.12 || echo /usr/bin/python3 ); "
                "$PYBIN -V 2>&1; "
                "$PYBIN -c 'import uvicorn, fastapi, boto3, cryptography, requests; print(\"imports OK\")' 2>&1 || true",
                aws_region, timeout=60,
            )
            console.print(f"[yellow]Host proxy diagnostics:[/yellow]\n{diag_out}")
        except Exception as exc:  # pragma: no cover — diagnostic only
            console.print(f"[yellow]Host proxy diagnostic fetch failed: {exc}[/yellow]")

    if not hp_success:
        progress.update(task_proxy, description="[bold red]✗ Step 8f Failed: Failed to start host proxy.[/bold red]")
        console.print(f"[red]Host Proxy STDOUT:[/red]\n{hp_out}\n[red]STDERR:[/red]\n{hp_err}")
        _dump_host_proxy_diagnostics()
        if audit:
            audit.record("Phase 5: Post-Deploy", "Host proxy started", "fail")
        return None

    # uvicorn + boto3 + fastapi + SSL cert load can take a few seconds on
    # slow instance types; give it a chance before declaring a crash-loop.
    # Poll up to ~20s for is-active.
    active = False
    last_chk_out = ""
    for _ in range(10):
        time.sleep(2)
        c_ok, c_out, _ = run_ssm_command(
            instance_id,
            "sudo systemctl is-active host-proxy.service",
            aws_region, timeout=20,
        )
        last_chk_out = (c_out or "").strip()
        if c_ok and last_chk_out == "active":
            active = True
            break
        # If it's already in a permanent failed state there's no point polling.
        if last_chk_out in ("failed", "inactive"):
            break

    if active:
        progress.update(task_proxy, description="[green]✓ Step 8f: Host proxy service started.[/green]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Host proxy started", "pass")
    else:
        progress.update(task_proxy, description="[bold red]✗ Step 8f Failed: Host proxy crashed after start.[/bold red]")
        console.print(f"[red]Host proxy final state:[/red] {last_chk_out or 'unknown'}")
        _dump_host_proxy_diagnostics()
        if audit:
            audit.record("Phase 5: Post-Deploy", "Host proxy started", "fail")
        return None

    return cid
