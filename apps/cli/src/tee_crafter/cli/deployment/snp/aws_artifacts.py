"""SNP-AWS artifact upload and dependency installation via S3."""
import os
import shutil
import tempfile

from tee_crafter.core.remote.ssm import run_ssm_command


def upload_artifacts_via_s3(
    progress, console, build_dir, instance_id, bucket_name, aws_region, audit,
    *, remote_base="/opt/tee-crafter-snp",
):
    """Upload app artifacts + offline wheels to S3 and install on instance via SSM.

    Follows the same offline-wheel pattern as SGX / TDX / SNP-Azure:
    1. Download wheels LOCALLY (deployer machine has internet).
    2. Bundle app + wheels, upload to S3 (via deployer's AWS creds).
    3. Instance pulls from S3 via VPC endpoint (no internet needed).
    4. pip install --no-index --find-links (fully offline on instance).
    """
    import boto3
    app_dir = os.path.join(build_dir, "app")
    if not os.path.isdir(app_dir):
        console.print("[red]✗ No app/ directory found in build dir.[/red]")
        console.print(f"[dim]SNP-AWS: expected app dir at {app_dir}, "
                      f"contents of build_dir={os.listdir(build_dir)}[/dim]")
        return False

    app_files = os.listdir(app_dir)
    console.print(f"[dim]SNP-AWS: app dir contents ({len(app_files)} files): {app_files[:15]}[/dim]")

    container_tar = os.path.join(build_dir, "user_container.tar")
    is_container_mode = os.path.isfile(container_tar)

    req_file = os.path.join(app_dir, "requirements.txt")
    wheel_dir = None

    # Delta-only deploy: read the image's pip-freeze manifest over SSM and
    # skip downloading any wheel already on the baked AMI.  Falls through
    # to a full download if the manifest is missing (unbaked deploys),
    # so the optimization is strictly opportunistic.  See
    # docs/optimizations.md §1-2.
    from tee_crafter.cli.deployment.common.wheel_manager import (
        fetch_image_pip_manifest,
    )

    def _ssm_for_freeze(cmd, *, timeout):
        ok, out, err = run_ssm_command(instance_id, cmd, aws_region, timeout=timeout)
        return ok, out, err

    image_pins = fetch_image_pip_manifest(_ssm_for_freeze, timeout=30)
    if image_pins:
        console.print(f"[dim]SNP-AWS: image manifest has {len(image_pins)} pre-installed package(s)[/dim]")

    if is_container_mode:
        from tee_crafter.cli.deployment.common.wheel_manager import (
            download_wheels_delta,
            detect_python_version_cmd,
            write_cvm_container_host_requirements,
        )
        host_req = write_cvm_container_host_requirements(app_dir)
        t_whl = progress.add_task(
            "[yellow]Downloading host venv wheels (container mode)...[/yellow]", total=None,
        )
        console.print(
            "[dim]SNP-AWS: container mode — host venv gets proxy deps only "
            f"(see {os.path.basename(host_req)})[/dim]"
        )
        ver_ok, ver_out, _ = run_ssm_command(
            instance_id,
            detect_python_version_cmd(f"{remote_base}/venv"),
            aws_region, timeout=15)
        py_ver = ver_out.strip() if ver_ok and ver_out.strip() else "3.10"
        console.print(f"[dim]SNP-AWS: remote Python version: {py_ver}[/dim]")
        wheel_dir = tempfile.mkdtemp(prefix="teecrafter_snpaws_whl_")
        count = download_wheels_delta(
            host_req, py_ver, wheel_dir, console, "SNP-AWS-host",
            image_pins=image_pins,
        )
        for wf in sorted(os.listdir(wheel_dir))[:20]:
            console.print(f"[dim]  • {wf}[/dim]")
        progress.update(t_whl, description=f"[green]✓ {count} host-venv wheels downloaded.[/green]")
    elif os.path.isfile(req_file):
        with open(req_file, "r") as f:
            reqs = f.read().strip()
        if reqs:
            from tee_crafter.cli.deployment.common.wheel_manager import (
                download_wheels_delta, detect_python_version_cmd,
            )
            t_whl = progress.add_task("[yellow]Downloading Python wheels locally...[/yellow]", total=None)
            console.print(f"[dim]SNP-AWS: requirements.txt:\n{reqs}[/dim]")
            ver_ok, ver_out, _ = run_ssm_command(
                instance_id,
                detect_python_version_cmd(f"{remote_base}/venv"),
                aws_region, timeout=15)
            py_ver = ver_out.strip() if ver_ok and ver_out.strip() else "3.10"
            console.print(f"[dim]SNP-AWS: remote Python version: {py_ver}[/dim]")
            wheel_dir = tempfile.mkdtemp(prefix="teecrafter_snpaws_whl_")
            count = download_wheels_delta(
                req_file, py_ver, wheel_dir, console, "SNP-AWS",
                image_pins=image_pins,
            )
            for wf in sorted(os.listdir(wheel_dir))[:20]:
                console.print(f"[dim]  • {wf}[/dim]")
            progress.update(t_whl, description=f"[green]✓ {count} wheels downloaded locally.[/green]")

    t = progress.add_task("[yellow]Uploading SNP artifacts to S3...[/yellow]", total=None)
    tar_tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    tar_tmp.close()
    s3_key = "snp-artifacts/app_bundle.tar.gz"
    bundle_uploaded = False
    try:
        # Prefer parallel gzip (pigz) for ~3× compression speedup on
        # multi-core deployers.  See docs/optimizations.md §4.
        from tee_crafter.cli.deployment.common.wheel_manager import make_tarball_fast
        members = [(app_dir, "app")]
        if wheel_dir and os.path.isdir(wheel_dir):
            members.append((wheel_dir, "wheels"))
        make_tarball_fast(tar_tmp.name, members)
        bundle_size_mb = os.path.getsize(tar_tmp.name) / (1024 * 1024)
        console.print(f"[dim]SNP-AWS: uploading {bundle_size_mb:.1f} MB bundle "
                      f"(app + wheels) to s3://{bucket_name}/{s3_key} (region={aws_region})[/dim]")
        s3 = boto3.client("s3", region_name=aws_region)
        s3.upload_file(tar_tmp.name, bucket_name, s3_key)
        bundle_uploaded = True
    except Exception as exc:
        progress.update(t, description="[red]✗ S3 upload failed.[/red]")
        console.print(f"[red]SNP-AWS: S3 upload error: {exc}[/red]")
        return False
    finally:
        try: os.unlink(tar_tmp.name)
        except OSError: pass
        if wheel_dir:
            shutil.rmtree(wheel_dir, ignore_errors=True)
    progress.update(t, description="[green]✓ Artifacts uploaded to S3.[/green]")

    # ``app/`` carries byok.env and siem.env — the wrapped DEK, HSM bearer and
    # SIEM token.  The sibling ``download_file_via_s3`` already deletes its
    # round-trip object; this one did not, so every deploy left a copy of the
    # workload's secrets in the deployment bucket for the life of the bucket.
    try:
        if not _verify_and_pull_from_s3(progress, console, instance_id, bucket_name,
                                        s3_key, aws_region, remote_base):
            return False
    finally:
        if bundle_uploaded:
            try:
                boto3.client("s3", region_name=aws_region).delete_object(
                    Bucket=bucket_name, Key=s3_key)
            except Exception as exc:
                console.print(
                    f"[yellow]SNP-AWS: could not delete "
                    f"s3://{bucket_name}/{s3_key} (contains byok.env / "
                    f"siem.env): {exc}[/yellow]")

    if is_container_mode:
        from tee_crafter.cli.deployment.common.wheel_manager import (
            pip_upgrade_cmd,
            offline_install_cmd,
            verify_imports_cmd,
            remote_cvm_container_host_requirements,
        )
        venv = f"{remote_base}/venv"
        t_pip = progress.add_task(
            "[yellow]Installing host venv (container mode, offline)...[/yellow]", total=None,
        )
        run_ssm_command(
            instance_id, f"sudo {pip_upgrade_cmd(venv)}", aws_region, timeout=120)
        host_req_remote = remote_cvm_container_host_requirements(remote_base)
        console.print("[dim]SNP-AWS: offline pip install (host proxy deps only)[/dim]")
        pip_cmd = f"sudo {offline_install_cmd(venv, f'{remote_base}/wheels', host_req_remote)}"
        ok, out, err = run_ssm_command(instance_id, pip_cmd, aws_region, timeout=300)
        if not ok:
            progress.update(t_pip, description="[red]✗ Offline pip install failed.[/red]")
            console.print(f"[dim]pip output: {(out or err or '')[-600:]}[/dim]")
            return False
        v_ok, v_out, _ = run_ssm_command(
            instance_id,
            f"sudo -u tee_enclave {verify_imports_cmd(venv)}",
            aws_region, timeout=15)
        if not v_ok:
            progress.update(t_pip, description="[red]✗ Runtime import check failed.[/red]")
            console.print(f"[dim]{(v_out or '')[-400:]}[/dim]")
            return False
        progress.update(t_pip, description="[green]✓ Host venv ready (container mode).[/green]")
        console.print(f"[dim]SNP-AWS: pip install output (tail):\n{(out or '').strip()[-400:]}[/dim]")
    elif os.path.isfile(req_file):
        from tee_crafter.cli.deployment.common.wheel_manager import (
            pip_upgrade_cmd, offline_install_cmd, verify_imports_cmd,
        )
        venv = f"{remote_base}/venv"
        t_pip = progress.add_task("[yellow]Installing Python requirements (offline)...[/yellow]", total=None)
        run_ssm_command(
            instance_id, f"sudo {pip_upgrade_cmd(venv)}", aws_region, timeout=120)
        console.print("[dim]SNP-AWS: running offline pip install from pre-downloaded wheels[/dim]")
        pip_cmd = f"sudo {offline_install_cmd(venv, f'{remote_base}/wheels', f'{remote_base}/app/requirements.txt')}"
        ok, out, err = run_ssm_command(instance_id, pip_cmd, aws_region, timeout=300)
        if not ok:
            progress.update(t_pip, description="[red]✗ Offline pip install failed.[/red]")
            console.print(f"[dim]pip output: {(out or err or '')[-600:]}[/dim]")
            return False
        v_ok, v_out, _ = run_ssm_command(
            instance_id,
            f"sudo -u tee_enclave {verify_imports_cmd(venv)}",
            aws_region, timeout=15)
        if not v_ok:
            progress.update(t_pip, description="[red]✗ Runtime import check failed.[/red]")
            console.print(f"[dim]{(v_out or '')[-400:]}[/dim]")
            return False
        progress.update(t_pip, description="[green]✓ Python requirements installed (offline).[/green]")
        console.print(f"[dim]SNP-AWS: pip install output (tail):\n{(out or '').strip()[-400:]}[/dim]")
    if os.path.isfile(container_tar):
        if not _upload_and_load_container(
            progress, console, instance_id, bucket_name, container_tar,
            aws_region, remote_base,
        ):
            return False

    if audit:
        audit.record("Phase 5: Post-Deploy", "SNP artifacts + deps installed", "pass")
    return True


def _verify_and_pull_from_s3(progress, console, instance_id, bucket_name, s3_key,
                              aws_region, remote_base):
    """Verify AWS CLI, S3 connectivity, then pull bundle onto instance."""
    t_pf = progress.add_task("[yellow]Verifying AWS CLI on instance...[/yellow]", total=None)
    pf_cmd = 'set -e; export PATH="/usr/local/bin:/usr/bin:$PATH"; command -v aws && aws --version'
    pf_ok, pf_out, pf_err = run_ssm_command(instance_id, pf_cmd, aws_region, timeout=30)
    if pf_ok:
        console.print(f"[dim]SNP-AWS: AWS CLI on instance: {(pf_out or '').strip()}[/dim]")
        progress.update(t_pf, description="[green]✓ AWS CLI available on instance.[/green]")
    else:
        progress.update(t_pf, description="[red]✗ AWS CLI not found on instance.[/red]")
        console.print("[red]SNP-AWS: aws not found (expected to be baked into AMI). Re-bake AMI with awscli.[/red]")
        return False

    t_s3 = progress.add_task("[yellow]Verifying S3 connectivity...[/yellow]", total=None)
    s3_cmd = (f'set -e; export PATH="/usr/local/bin:/usr/bin:$PATH"; '
              f"aws s3 ls 's3://{bucket_name}/' --region {aws_region} --page-size 1 2>&1 | head -3")
    s3_ok, s3_out, _ = run_ssm_command(instance_id, s3_cmd, aws_region, timeout=60)
    if s3_ok:
        progress.update(t_s3, description="[green]✓ S3 reachable from instance.[/green]")
    else:
        progress.update(t_s3, description="[red]✗ S3 not reachable from instance.[/red]")
        console.print("[red]SNP-AWS: instance cannot reach S3. Check S3 Gateway/Interface endpoint.[/red]")
        return False

    t_dl = progress.add_task("[yellow]Installing artifacts on instance...[/yellow]", total=None)
    s3_uri = f"s3://{bucket_name}/{s3_key}"
    dl_cmd = (
        f'set -e; export PATH="/usr/local/bin:/usr/bin:$PATH"; '
        f"sudo mkdir -p {remote_base}/app {remote_base}/wheels; "
        f"aws s3 cp '{s3_uri}' /tmp/app_bundle.tar.gz --region {aws_region}; "
        f"cd {remote_base} && sudo tar xzf /tmp/app_bundle.tar.gz; rm -f /tmp/app_bundle.tar.gz; "
        f"sudo chown -R tee_enclave:tee_enclave {remote_base}; "
        f"ls -la {remote_base}/app/ && echo '---wheels---' && ls {remote_base}/wheels/ 2>/dev/null || true")
    console.print(f"[dim]SNP-AWS: pulling bundle from {s3_uri} to {instance_id}[/dim]")
    ok, out, err = run_ssm_command(instance_id, dl_cmd, aws_region, timeout=300)
    if not ok:
        progress.update(t_dl, description="[red]✗ Artifact installation failed.[/red]")
        console.print(f"[red]SNP-AWS: artifact install STDOUT:[/red]\n[dim]{(out or '')[-800:]}[/dim]")
        return False
    console.print(f"[dim]SNP-AWS: artifact install output:\n{(out or '').strip()[-600:]}[/dim]")
    progress.update(t_dl, description="[green]✓ Artifacts extracted on instance.[/green]")
    return True


def _upload_and_load_container(
    progress, console, instance_id, bucket_name, container_tar,
    aws_region, remote_base,
):
    """Upload user_container.tar to S3, pull onto instance, docker-load it, start service."""
    import boto3

    s3_key = "snp-artifacts/user_container.tar"
    tar_size_mb = os.path.getsize(container_tar) / (1024 * 1024)

    t = progress.add_task("[yellow]Uploading container image to S3...[/yellow]", total=None)
    console.print(f"[dim]SNP-AWS: uploading container tarball ({tar_size_mb:.0f} MB) "
                  f"to s3://{bucket_name}/{s3_key}[/dim]")
    try:
        s3 = boto3.client("s3", region_name=aws_region)
        s3.upload_file(container_tar, bucket_name, s3_key)
    except Exception as exc:
        progress.update(t, description="[red]✗ Container image S3 upload failed.[/red]")
        console.print(f"[red]SNP-AWS: S3 upload error: {exc}[/red]")
        return False
    progress.update(t, description="[green]✓ Container image uploaded to S3.[/green]")

    t = progress.add_task("[yellow]Loading container image on instance...[/yellow]", total=None)
    s3_uri = f"s3://{bucket_name}/{s3_key}"
    load_cmd = (
        f'set -e; export PATH="/usr/local/bin:/usr/bin:$PATH"; '
        f"aws s3 cp '{s3_uri}' /tmp/user_container.tar --region {aws_region}; "
        "out=$(sudo docker load -i /tmp/user_container.tar 2>&1); "
        "rm -f /tmp/user_container.tar; "
        'img=$(echo "$out" | sed -n "s/^Loaded image: //p" | tail -n 1); '
        '[ -z "$img" ] && img=$(echo "$out" | sed -n "s/^Loaded image ID: //p" | tail -n 1); '
        'test -n "$img" && sudo docker tag "$img" tee-crafter:latest; '
        f"echo '--- loaded images ---'; sudo docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}} {{{{.Size}}}}'"
    )
    ok, out, err = run_ssm_command(instance_id, load_cmd, aws_region, timeout=600)
    if not ok:
        progress.update(t, description="[red]✗ Container image load failed.[/red]")
        console.print(f"[red]SNP-AWS: docker load STDOUT:[/red]\n[dim]{(out or '')[-600:]}[/dim]")
        console.print(f"[red]SNP-AWS: docker load STDERR:[/red]\n[dim]{(err or '')[-400:]}[/dim]")
        return False
    console.print(f"[dim]SNP-AWS: docker load output:\n{(out or '').strip()[-400:]}[/dim]")
    progress.update(t, description="[green]✓ Container image loaded into Docker.[/green]")

    t = progress.add_task("[yellow]Starting user container service...[/yellow]", total=None)
    start_cmd = (
        "sudo systemctl daemon-reload; "
        "sudo systemctl stop tee-crafter-container.service 2>/dev/null; "
        "sudo docker rm -f tee-crafter 2>/dev/null; "
        "sudo systemctl start tee-crafter-container.service 2>&1; "
        "sleep 5; "
        "systemctl is-active tee-crafter-container.service 2>&1"
    )
    ok, out, err = run_ssm_command(instance_id, start_cmd, aws_region, timeout=60)
    status = (out or "").strip().split("\n")[-1].strip()
    if status == "active":
        ok3, port_out, _ = run_ssm_command(
            instance_id,
            "sudo docker logs tee-crafter 2>&1 | tail -10 || true; "
            "echo '---PORT_CHECK---'; "
            "ss -tlnp | grep -E ':(8080|5000|3000|80) ' || echo 'no_listen'",
            aws_region, timeout=10,
        )
        port_text = (port_out or "").strip()
        if port_text and "No such container" not in port_text:
            console.print(f"[dim]SNP-AWS: container logs + port check:\n{port_text[-500:]}[/dim]")
        if "exec format error" in (port_out or "").lower():
            progress.update(t, description="[red]✗ Container arch mismatch (exec format error).[/red]")
            console.print("[bold red]The Docker image was built for a different CPU architecture.[/bold red]")
            return False
        progress.update(t, description="[green]✓ User container running.[/green]")
        console.print("[dim]SNP-AWS: tee-crafter-container.service is active.[/dim]")
    else:
        ok2, journal, _ = run_ssm_command(
            instance_id,
            "sudo journalctl -u tee-crafter-container.service --no-pager -n 30 2>&1",
            aws_region, timeout=15,
        )
        console.print(f"[yellow]SNP-AWS: container service status={status!r}[/yellow]")
        console.print(f"[dim]SNP-AWS: container journal:\n{(journal or '')[-800:]}[/dim]")
        if "exec format error" in (journal or "").lower():
            progress.update(t, description="[red]✗ Container arch mismatch (exec format error).[/red]")
            console.print("[bold red]The Docker image was built for a different CPU architecture.[/bold red]")
            return False
        progress.update(t, description="[yellow]! User container not yet active — proxy may retry.[/yellow]")

    return True
