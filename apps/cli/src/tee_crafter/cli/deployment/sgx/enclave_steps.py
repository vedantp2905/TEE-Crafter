"""SGX enclave sub-steps: artifact upload, dependency install, manifest signing."""
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

from tee_crafter.core.remote.azure_ssh import (
    upload_file_via_scp, upload_directory_via_scp, run_ssh_command,
)
from tee_crafter.cli.constants import Panel


def _detect_remote_python(ssh_key_path, admin_user, port):
    ok, out, _ = run_ssh_command(
        "python3 -c 'import sys; print(\"{}.{}\".format(sys.version_info.major, sys.version_info.minor))'",
        ssh_key_path, user=admin_user, port=port, timeout=15,
    )
    return out.strip() if ok and out.strip() else "3.10"


def upload_artifacts(progress, console, build_dir, ssh_key_path, admin_user, tunnel_port, audit):
    """Step 8d: upload app/ and manifest to remote host."""
    task = progress.add_task("[yellow]Step 8d: Uploading SGX application artifacts...[/yellow]", total=None)
    app_dir = os.path.join(build_dir, "app")
    manifest_file = os.path.join(build_dir, "app_gramine.manifest.toml")
    if not os.path.isdir(app_dir):
        progress.update(task, description=f"[bold red]✗ Step 8d Failed: app/ not found in {build_dir}[/bold red]")
        return None
    remote_base = f"/home/{admin_user}/sgx-app"
    run_ssh_command(f"sudo mkdir -p {remote_base}/app && sudo chown -R {admin_user}:{admin_user} {remote_base}",
                    ssh_key_path, user=admin_user, port=tunnel_port)
    ok, msg = upload_directory_via_scp(app_dir, f"{remote_base}/", ssh_key_path, user=admin_user, port=tunnel_port)
    if not ok:
        progress.update(task, description=f"[bold red]✗ Step 8d Failed: {msg}[/bold red]")
        return None
    if os.path.isfile(manifest_file):
        up_ok, up_msg = upload_file_via_scp(manifest_file, f"{remote_base}/app_gramine.manifest.toml",
                                            ssh_key_path, user=admin_user, port=tunnel_port)
        if not up_ok:
            progress.update(task, description=f"[bold red]✗ Step 8d Failed (manifest): {up_msg}[/bold red]")
            return None
    progress.update(task, description="[green]✓ Step 8d: SGX artifacts uploaded to host.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "SGX artifacts uploaded", "pass")
    return remote_base


def _install_wheels_offline(progress, console, task, packages, remote_base, ssh_key_path,
                            admin_user, tunnel_port, py_ver, tar_prefix):
    """Download wheels locally, upload via SCP, extract into app/ on remote host."""
    wheel_dir = tempfile.mkdtemp(prefix=f"teecrafter_{tar_prefix}_")
    try:
        platforms = ["--platform", "manylinux2014_x86_64", "--platform", "linux_x86_64"]
        if tar_prefix == "tee_wheels":
            platforms.append("--platform"); platforms.append("manylinux_2_28_x86_64")
        dl = subprocess.run([sys.executable, "-m", "pip", "download", *packages, "-d", wheel_dir,
                            *platforms, "--python-version", py_ver, "--only-binary=:all:"],
                           capture_output=True, text=True, timeout=180)
        if dl.returncode != 0:
            subprocess.run([sys.executable, "-m", "pip", "download", *packages, "-d", wheel_dir,
                           "--platform", "manylinux2014_x86_64", "--platform", "linux_x86_64",
                           "--only-binary=:all:"], capture_output=True, text=True, timeout=180)
        whl_files = [f for f in os.listdir(wheel_dir) if f.endswith('.whl')]
        console.print(f"[dim]Downloaded {len(whl_files)} wheels ({tar_prefix})[/dim]")
        for wf in sorted(whl_files):
            console.print(f"[dim]  • {wf}[/dim]")
        if not whl_files:
            progress.update(task, description=f"[yellow]⊘ {tar_prefix}: No wheels found.[/yellow]")
            return
        tar_file = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
        tar_file.close()
        try:
            with tarfile.open(tar_file.name, "w:gz") as tar:
                tar.add(wheel_dir, arcname=tar_prefix)
            up_ok, up_msg = upload_file_via_scp(tar_file.name, f"{remote_base}/{tar_prefix}.tar.gz",
                                                ssh_key_path, user=admin_user, port=tunnel_port)
        finally:
            try: os.unlink(tar_file.name)
            except OSError: pass
        if up_ok:
            run_ssh_command(f"cd {remote_base} && tar xzf {tar_prefix}.tar.gz && rm -f {tar_prefix}.tar.gz",
                          ssh_key_path, user=admin_user, port=tunnel_port, timeout=30)
            inst_ok, inst_out, _ = run_ssh_command(
                f"cd {remote_base}/{tar_prefix} && for whl in *.whl; do "
                f"sudo unzip -o -q \"$whl\" -d {remote_base}/app/ 2>&1; done; echo 'UNZIP_OK'",
                ssh_key_path, user=admin_user, port=tunnel_port, timeout=180)
            if not inst_ok or "UNZIP_OK" not in (inst_out or ""):
                console.print(f"[dim yellow]Wheel extract output:[/dim yellow]\n{(inst_out or '')[-500:]}")
        else:
            progress.update(task, description=f"[bold red]✗ {tar_prefix}: wheel upload failed ({up_msg})[/bold red]")
            return
    except Exception as e:
        progress.update(task, description=f"[yellow]⊘ {tar_prefix} install failed: {e}[/yellow]")
        return
    finally:
        shutil.rmtree(wheel_dir, ignore_errors=True)


def install_user_requirements(progress, console, build_dir, remote_base, ssh_key_path,
                              admin_user, tunnel_port):
    """Step 8d-b: offline wheel install of user requirements.txt."""
    req_file = os.path.join(build_dir, "app", "requirements.txt")
    if not os.path.isfile(req_file):
        return
    task = progress.add_task("[yellow]Step 8d-b: Installing user requirements (offline)...[/yellow]", total=None)
    py_ver = _detect_remote_python(ssh_key_path, admin_user, tunnel_port)
    console.print(f"[dim]Remote Python version (Gramine runtime): {py_ver}[/dim]")
    _install_wheels_offline(progress, console, task, ["-r", req_file], remote_base,
                           ssh_key_path, admin_user, tunnel_port, py_ver, "wheels")
    progress.update(task, description="[green]✓ Step 8d-b: User requirements installed.[/green]")


def install_tee_runtime_deps(progress, console, remote_base, ssh_key_path, admin_user, tunnel_port):
    """Step 8d-c: offline install of cryptography, cffi, pycparser into app/."""
    task = progress.add_task("[yellow]Step 8d-c: Installing TEE runtime deps (cryptography, cffi)...[/yellow]", total=None)
    py_ver = _detect_remote_python(ssh_key_path, admin_user, tunnel_port)
    deps = ["cryptography>=42.0,<44", "cffi", "pycparser"]
    _install_wheels_offline(progress, console, task, deps, remote_base,
                           ssh_key_path, admin_user, tunnel_port, py_ver, "tee_wheels")
    progress.update(task, description="[green]✓ Step 8d-c: TEE runtime deps installed.[/green]")


def upload_container_tarball(progress, console, build_dir, remote_base, ssh_key_path,
                            admin_user, tunnel_port, audit):
    """Upload user_container.tar to the remote host and load the Docker image.

    Returns True if container mode artifacts were uploaded, False if no tarball
    found (not container mode), None on failure.
    """
    tar_path = os.path.join(build_dir, "user_container.tar")
    if not os.path.isfile(tar_path):
        return False

    task = progress.add_task(
        "[yellow]Step 8d-d: Uploading container image tarball...[/yellow]", total=None,
    )
    remote_tar = f"{remote_base}/user_container.tar"
    ok, msg = upload_file_via_scp(
        tar_path, remote_tar, ssh_key_path, user=admin_user, port=tunnel_port,
    )
    if not ok:
        progress.update(task, description=f"[bold red]✗ Step 8d-d Failed: {msg}[/bold red]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Container tarball upload", "fail")
        return None

    load_ok, load_out, load_err = run_ssh_command(
        f"sudo docker load -i {remote_tar} && sudo rm -f {remote_tar}",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=300,
    )
    if not load_ok:
        progress.update(task, description="[bold red]✗ Step 8d-d Failed: docker load failed.[/bold red]")
        console.print(f"[red]docker load output:[/red]\n{load_out}\n{load_err}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Container image load", "fail")
        return None

    progress.update(task, description="[green]✓ Step 8d-d: Container image uploaded and loaded.[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "Container image uploaded and loaded", "pass")
    return True


def start_container_service(progress, console, ssh_key_path, admin_user, tunnel_port, audit):
    """Start the tee-crafter-container.service (user Docker container)."""
    task = progress.add_task(
        "[yellow]Step 8d-e: Starting user container service...[/yellow]", total=None,
    )
    run_ssh_command(
        "sudo systemctl daemon-reload",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=15,
    )
    start_ok, start_out, start_err = run_ssh_command(
        "sudo systemctl start tee-crafter-container.service",
        ssh_key_path, user=admin_user, port=tunnel_port, timeout=60,
    )
    if not start_ok:
        progress.update(task, description="[bold red]✗ Step 8d-e Failed: Container service start failed.[/bold red]")
        console.print(f"[red]start output:[/red]\n{start_out}\n{start_err}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Container service start", "fail")
        return False

    time.sleep(5)
    health_ok, health_out, _ = run_ssh_command(
        "systemctl is-active tee-crafter-container.service",
        ssh_key_path, user=admin_user, port=tunnel_port,
    )
    _, svc_log, _ = run_ssh_command(
        "sudo journalctl -u tee-crafter-container.service --since '15 seconds ago' -n 20 --no-pager 2>&1",
        ssh_key_path, user=admin_user, port=tunnel_port,
    )

    if svc_log:
        console.print(Panel(svc_log, title="[bold green]tee-crafter-container.service logs[/bold green]",
                           border_style="green"))

    if health_ok and "active" in (health_out or ""):
        progress.update(task, description="[green]✓ Step 8d-e: User container running.[/green]")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Container service start", "pass")
        return True

    progress.update(task, description="[bold red]✗ Step 8d-e: Container service not active.[/bold red]")
    if audit:
        audit.record("Phase 5: Post-Deploy", "Container service start", "fail")
    return False


def sign_manifest_on_host(progress, console, remote_base, ssh_key_path, admin_user,
                          tunnel_port, audit):
    """Step 8e: preprocess + sign Gramine manifest on host. Returns measurements dict or None."""
    import re
    task = progress.add_task("[yellow]Step 8e: Signing Gramine manifest on host...[/yellow]", total=None)
    time.sleep(5)
    sign_cmd = (
        f"cd {remote_base} && "
        "sudo gramine-manifest --no-check app_gramine.manifest.toml "
        "app_gramine.manifest.processed.toml 2>&1 && "
        "sudo mv app_gramine.manifest.processed.toml app_gramine.manifest.toml && "
        "sudo gramine-sgx-sign --manifest app_gramine.manifest.toml "
        "--output app_gramine.manifest.sgx --sigfile app_gramine.sig 2>&1"
    )
    sign_ok, combined = False, ""
    for attempt in range(1, 4):
        progress.update(task, description=f"[yellow]Step 8e: Signing Gramine manifest (attempt {attempt}/3)...[/yellow]")
        ok, out, err = run_ssh_command(sign_cmd, ssh_key_path, user=admin_user, timeout=180, port=tunnel_port)
        combined = f"{out}\n{err}"
        if ok:
            sign_ok = True
            break
        transient = any(kw in combined.lower() for kw in ("banner exchange", "connection timed out",
                        "connection reset", "broken pipe", "no route to host"))
        if not transient or attempt == 3:
            break
        console.print(f"[dim yellow]Step 8e: SSH transient failure, retrying in {attempt * 10}s...[/dim yellow]")
        time.sleep(attempt * 10)
    if not sign_ok:
        progress.update(task, description="[bold red]✗ Step 8e Failed: gramine-sgx-sign failed.[/bold red]")
        console.print(f"[red]Sign output:[/red]\n{combined}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Gramine manifest signed on host", "fail")
        return None
    # Verify output files
    v_ok, v_out, _ = run_ssh_command(
        f"ls -la {remote_base}/app_gramine.manifest.sgx {remote_base}/app_gramine.sig 2>&1",
        ssh_key_path, user=admin_user, port=tunnel_port)
    if not v_ok or "No such file" in (v_out or ""):
        _, ls_out, _ = run_ssh_command(
            f"ls -la {remote_base}/app_gramine*.sig* {remote_base}/app_gramine.manifest.sig 2>&1",
            ssh_key_path, user=admin_user, port=tunnel_port)
        console.print(f"[dim yellow]Post-sign file check:[/dim yellow]\n{v_out}\n{ls_out}")
        run_ssh_command(f"cd {remote_base} && sudo test -f app_gramine.manifest.sig && "
                       "sudo mv app_gramine.manifest.sig app_gramine.sig; true",
                       ssh_key_path, user=admin_user, port=tunnel_port)
    measurements = {}
    m = (re.search(r"Measurement:\s*([0-9a-fA-F]{64})", combined) or
         re.search(r"Measurement:\s*\n\s*([0-9a-fA-F]{64})", combined) or
         re.search(r"mr_enclave\s*[:=]\s*([0-9a-fA-F]{64})", combined))
    s = re.search(r"mr_signer\s*[:=]\s*([0-9a-fA-F]{64})", combined)
    if m: measurements["MRENCLAVE"] = m.group(1).lower()
    if s: measurements["MRSIGNER"] = s.group(1).lower()
    if not measurements.get("MRENCLAVE") or not measurements.get("MRSIGNER"):
        view_ok, view_out, _ = run_ssh_command(
            f"cd {remote_base} && sudo gramine-sgx-sigstruct-view app_gramine.sig 2>&1",
            ssh_key_path, user=admin_user, port=tunnel_port)
        if view_ok:
            if not measurements.get("MRENCLAVE"):
                m2 = re.search(r"mr_enclave\s*[:=]\s*([0-9a-fA-F]{64})", view_out)
                if m2: measurements["MRENCLAVE"] = m2.group(1).lower()
            if not measurements.get("MRSIGNER"):
                s2 = re.search(r"mr_signer\s*[:=]\s*([0-9a-fA-F]{64})", view_out)
                if s2: measurements["MRSIGNER"] = s2.group(1).lower()
    progress.update(task, description=(
        f"[green]✓ Step 8e: Manifest signed. MRENCLAVE={measurements.get('MRENCLAVE', 'N/A')[:16]}...[/green]"))
    if audit:
        audit.record("Phase 5: Post-Deploy", "Gramine manifest signed on host", "pass", **measurements)
    return measurements
