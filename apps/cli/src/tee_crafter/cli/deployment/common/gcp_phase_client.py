"""Shared GCP deployment client logic for SNP-GCP and TDX-GCP platforms."""
import os
import shutil
import subprocess
import sys
import tempfile
import time

from tee_crafter.cli.constants import Panel
from tee_crafter.core.remote.gcp_ssh import SSHPortForward
from tee_crafter.cli.deployment.common.attestation_report import extract_attestation_report

_PROXY_ERROR_MARKERS = ("Container not reachable", "connection_refused", "Internal proxy error", "proxy_error")


def _response_has_proxy_error(stdout: str) -> bool:
    """Return True if the client output contains a proxy-level error from the container sidecar."""
    text = stdout[:2000].lower()
    return any(m.lower() in text for m in _PROXY_ERROR_MARKERS)


def _extract_measurement_from_stderr(stderr: str, measurements: dict) -> None:
    """Best-effort parsing of attestation measurements from client stderr.

    AUD-7: previously this used double-escaped regex (``\\\\s*``) which never
    matched any real-world output, so SNP / TDX measurements were always
    blank in the audit trail.  Now delegated to the shared
    ``extract_attestation_report`` helper which handles both the legacy
    label format and the new ``ATTESTATION_REPORT {<json>}`` line.
    """
    if not stderr:
        return
    parsed = extract_attestation_report(stderr)
    if not parsed:
        return
    if "measurement" in measurements and parsed.get("measurement"):
        measurements["measurement"] = parsed["measurement"]
    if "mrtd" in measurements and parsed.get("mrtd"):
        measurements["mrtd"] = parsed["mrtd"]
    # surface any extra fields the caller did not pre-seed so callers can
    # forward them straight into ``audit.record(...)``.
    for k, v in parsed.items():
        measurements.setdefault(k, v)


def run_gcp_client(progress, console, build_dir, ssh_key_path, ssh_tunnel_port,
                   admin_user, audit, instance_name, zone, project, *,
                   platform, remote_base, service_name, device_chmod_cmd,
                   client_filename, audit_label, measurements=None,
                   tee_platform_slug=None):
    """Upload artifacts, install deps, start service, run client via IAP tunnel."""
    from tee_crafter.core.remote.gcp_ssh import run_ssh_command, upload_file_via_scp
    app_dir = os.path.join(build_dir, "app")
    container_tar = os.path.join(build_dir, "user_container.tar")
    is_container_mode = os.path.isfile(container_tar)

    venv = f"{remote_base}/venv"
    remote_app = f"{remote_base}/app"
    pip_req_remote = None
    wheel_dir = None

    if is_container_mode:
        from tee_crafter.cli.deployment.common.wheel_manager import (
            write_cvm_container_host_requirements,
            detect_python_version_cmd,
            remote_cvm_container_host_requirements,
            CVM_CONTAINER_HOST_REQ_FILENAME,
        )
        write_cvm_container_host_requirements(app_dir)
        pip_req_remote = remote_cvm_container_host_requirements(remote_base)
        local_req = os.path.join(app_dir, CVM_CONTAINER_HOST_REQ_FILENAME)
    else:
        req_file = os.path.join(app_dir, "requirements.txt")
        if os.path.isfile(req_file):
            from tee_crafter.cli.deployment.common.wheel_manager import (
                detect_python_version_cmd,
            )
            pip_req_remote = f"{remote_base}/app/requirements.txt"
            local_req = req_file

    run_ssh_command(
        f"sudo mkdir -p {remote_app} && sudo chown -R {admin_user}:{admin_user} {remote_base}",
        ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=30)

    if pip_req_remote:
        ver_ok, ver_out, _ = run_ssh_command(
            detect_python_version_cmd(venv),
            ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=15)
        py_ver = ver_out.strip() if ver_ok and ver_out.strip() else "3.10"
        wheel_dir = tempfile.mkdtemp(prefix="teecrafter_whl_")
        whl_label = f"{platform}-host" if is_container_mode else platform
        # Delta-only deploy: see docs/optimizations.md §1-2.
        from tee_crafter.cli.deployment.common.wheel_manager import (
            fetch_image_pip_manifest, download_wheels_delta,
        )

        def _remote_for_freeze(cmd, *, timeout):
            ok, out, err = run_ssh_command(
                cmd, ssh_key_path,
                user=admin_user, host="localhost", port=ssh_tunnel_port,
                timeout=timeout,
            )
            return ok, out, err

        image_pins = fetch_image_pip_manifest(_remote_for_freeze, timeout=20)
        download_wheels_delta(
            local_req, py_ver, wheel_dir, console, whl_label,
            image_pins=image_pins, timeout=300,
        )

    t = progress.add_task(f"[yellow]Uploading {platform} artifacts...[/yellow]", total=None)
    tar_tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    tar_tmp.close()
    try:
        # Prefer parallel gzip (pigz) for ~3× compression speedup on
        # multi-core deployers.  See docs/optimizations.md §4.
        from tee_crafter.cli.deployment.common.wheel_manager import make_tarball_fast
        members = [(app_dir, "app")]
        if wheel_dir:
            members.append((wheel_dir, "wheels"))
        make_tarball_fast(tar_tmp.name, members)
        for _attempt in range(3):
            ok, msg = upload_file_via_scp(tar_tmp.name, f"{remote_base}/app_bundle.tar.gz",
                                          ssh_key_path, user=admin_user, port=ssh_tunnel_port)
            if ok:
                break
            time.sleep(3)
        if not ok:
            progress.update(t, description=f"[red]✗ Upload failed: {msg}[/red]")
            return False
        run_ssh_command(f"cd {remote_base} && tar xzf app_bundle.tar.gz && rm -f app_bundle.tar.gz",
                        ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=60)
    finally:
        try: os.unlink(tar_tmp.name)
        except OSError: pass
        if wheel_dir:
            shutil.rmtree(wheel_dir, ignore_errors=True)
    progress.update(t, description=f"[green]✓ {platform} artifacts uploaded.[/green]")

    if pip_req_remote:
        from tee_crafter.cli.deployment.common.wheel_manager import (
            pip_upgrade_cmd, offline_install_cmd, verify_imports_cmd,
        )
        pip_label = "host venv (container mode)" if is_container_mode else "requirements"
        t = progress.add_task(f"[yellow]Installing {pip_label} (offline)...[/yellow]", total=None)
        run_ssh_command(pip_upgrade_cmd(venv),
                        ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=60)
        pip_ok, pip_out, pip_err = run_ssh_command(
            offline_install_cmd(venv, f"{remote_base}/wheels", pip_req_remote),
            ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=300)
        if not pip_ok:
            progress.update(t, description=f"[red]✗ {platform}: offline pip install failed.[/red]")
            console.print(f"[dim]pip output: {(pip_err or pip_out or '')[-600:]}[/dim]")
            return False
        v_ok, v_out, _ = run_ssh_command(
            verify_imports_cmd(venv),
            ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=15)
        if not v_ok:
            progress.update(t, description=f"[red]✗ {platform}: runtime import check failed.[/red]")
            console.print(f"[dim]{(v_out or '')[-400:]}[/dim]")
            return False
        ok_label = "Host venv ready (container mode)" if is_container_mode else "Requirements installed (offline)"
        progress.update(t, description=f"[green]✓ {ok_label}.[/green]")

    if os.path.isfile(container_tar):
        tar_mb = os.path.getsize(container_tar) / (1024 * 1024)
        scp_timeout = max(600, int(tar_mb * 3) + 120)
        t = progress.add_task(f"[yellow]Uploading {platform} container image ({tar_mb:.0f} MB)...[/yellow]", total=None)
        ok, msg = upload_file_via_scp(
            container_tar, f"{remote_base}/user_container.tar",
            ssh_key_path, user=admin_user, port=ssh_tunnel_port,
            timeout=scp_timeout)
        if not ok:
            progress.update(t, description=f"[red]✗ Container upload failed: {msg}[/red]")
            return False
        _load_tag = (
            f'out=$(sudo docker load -i {remote_base}/user_container.tar 2>&1) && '
            f'sudo rm -f {remote_base}/user_container.tar && '
            r'img=$(echo "$out" | sed -n "s/^Loaded image: //p" | tail -n 1); '
            r'[ -z "$img" ] && img=$(echo "$out" | sed -n "s/^Loaded image ID: //p" | tail -n 1); '
            r'test -n "$img" && sudo docker tag "$img" tee-crafter:latest'
        )
        run_ssh_command(_load_tag, ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=600)
        progress.update(t, description=f"[green]✓ {platform} container image loaded.[/green]")

        # BYOK secret material has to be in place *before* the container unit
        # is started.  That unit `Requires=` the secrets oneshot, and the
        # oneshot reads the wrapped DEK from
        # /run/tee-crafter-<platform>/byok.env — a path that only exists once
        # `install_byok_sidecar` has relocated it off disk.  Installing the
        # sidecars afterwards (as this did until 2026-08-21) meant the
        # container's one and only start attempt raced a secret that was not
        # there yet: the fail-closed bootstrap correctly refused, systemd
        # reported "Dependency failed for TEE-Crafter User Container", and
        # nothing ever retried — so `--byok gcp-kms --secrets-env` deployed a
        # verified, attested VM whose workload was never running.  Observed on
        # both snp-gcp and tdx-gcp.
        if tee_platform_slug:
            from tee_crafter.cli.deployment.common.byok_sidecar import (
                install_byok_sidecar,
            )
            from tee_crafter.cli.deployment.common.siem_sidecar import (
                install_siem_sidecar,
            )

            def _sidecar_remote(cmd, _k=ssh_key_path, _u=admin_user,
                                _p=ssh_tunnel_port):
                from tee_crafter.core.remote.gcp_ssh import (
                    run_ssh_command as _rsc,
                )
                return _rsc(cmd, _k, user=_u, port=_p, timeout=60)

            install_siem_sidecar(
                console=console, build_dir=build_dir,
                tee_platform=tee_platform_slug,
                run_remote=_sidecar_remote, audit=audit,
            )
            install_byok_sidecar(
                console=console, build_dir=build_dir,
                tee_platform=tee_platform_slug,
                run_remote=_sidecar_remote, audit=audit,
            )

        t = progress.add_task(f"[yellow]Starting {platform} user container...[/yellow]", total=None)
        svc = "tee-crafter-container.service"
        run_ssh_command(
            f"sudo systemctl daemon-reload && "
            f"sudo systemctl stop {svc} 2>/dev/null; "
            f"sudo docker rm -f tee-crafter 2>/dev/null; "
            f"sudo systemctl start {svc}",
            ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=30)
        time.sleep(5)
        _cok, _cout, _ = run_ssh_command(
            f"systemctl is-active {svc}",
            ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=10)
        cstatus = (_cout or "").strip()
        if cstatus == "active":
            _, cdiag, _ = run_ssh_command(
                "sudo docker logs tee-crafter 2>&1 | tail -10 || true",
                ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=10)
            cdiag_text = (cdiag or "").strip()
            if cdiag_text and "No such container" not in cdiag_text:
                console.print(f"[dim]{platform}: container logs:\n{cdiag_text[-400:]}[/dim]")
            if "exec format error" in cdiag_text.lower():
                progress.update(t, description="[red]✗ Container arch mismatch (exec format error).[/red]")
                return False
            progress.update(t, description=f"[green]✓ {platform} user container running.[/green]")
        else:
            _, cjournal, _ = run_ssh_command(
                f"sudo journalctl -u {svc} --no-pager -n 30 2>&1",
                ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=15)
            console.print(f"[yellow]{platform}: container service status={cstatus!r}[/yellow]")
            if cjournal:
                console.print(f"[dim]{cjournal[-800:]}[/dim]")
            if "exec format error" in (cjournal or "").lower():
                progress.update(t, description="[red]✗ Container arch mismatch (exec format error).[/red]")
                return False
            progress.update(t, description=f"[yellow]! {platform} container not yet active.[/yellow]")

    t = progress.add_task(f"[yellow]Starting {platform} app service...[/yellow]", total=None)
    # Batch the three pre-start SSH calls into one round-trip.  See
    # docs/optimizations.md §7.
    pre_start_cmd = (
        f"sudo systemctl reset-failed {service_name} 2>/dev/null; "
        f"sudo systemctl stop {service_name} 2>/dev/null; "
        f"{device_chmod_cmd}; "
        f"sudo chown -R tee_enclave:tee_enclave {remote_base} && "
        f"sudo chmod 755 {remote_base} {remote_app} && "
        f"sudo systemctl start {service_name}"
    )
    run_ssh_command(pre_start_cmd, ssh_key_path,
                    user=admin_user, port=ssh_tunnel_port, timeout=30)
    app_ready = False
    max_poll = 36
    # One SSH round-trip per poll cycle instead of two.  See
    # docs/optimizations.md §7.
    poll_cmd = (
        f"echo ACTIVE=$(systemctl is-active {service_name}); "
        f"echo LISTENING=$(sudo journalctl -u {service_name} --no-pager -o cat 2>&1 "
        f"| grep -c 'listening on port' || echo 0)"
    )
    for attempt in range(max_poll):
        time.sleep(5)
        _pok, _pout, _ = run_ssh_command(poll_cmd, ssh_key_path,
                                          user=admin_user, port=ssh_tunnel_port, timeout=15)
        active_state = "unknown"
        listening_count = 0
        for line in (_pout or "").splitlines():
            line = line.strip()
            if line.startswith("ACTIVE="):
                active_state = line.split("=", 1)[1].strip()
            elif line.startswith("LISTENING="):
                try:
                    listening_count = int(line.split("=", 1)[1].strip() or "0")
                except ValueError:
                    listening_count = 0
        if active_state in ("inactive", "failed"):
            break
        if listening_count > 0:
            app_ready = True
            break
    if not app_ready:
        progress.update(t, description=f"[red]✗ {platform} app service failed to start.[/red]")
        _, journal, _ = run_ssh_command(
            f"sudo journalctl -u {service_name} --since '3 min ago' -n 50 --no-pager",
            ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=15)
        if journal:
            console.print(Panel(journal, title=f"[bold yellow]{service_name} logs[/bold yellow]", border_style="yellow"))
        return False
    elapsed = (attempt + 1) * 5
    progress.update(t, description=f"[green]✓ {platform} app service running (ready after ~{elapsed}s).[/green]")
    if audit:
        audit.record("Phase 5: Post-Deploy", f"{audit_label} app service started", "pass")
    # The SIEM and BYOK sidecars are installed before the container starts —
    # see the comment at that call site for why the order matters.
    t = progress.add_task(f"[yellow]SSH port-forward to {platform} app (port 5005)...[/yellow]", total=None)
    app_tunnel = SSHPortForward(ssh_key_path, admin_user, ssh_tunnel_port, 5005)
    try:
        app_tunnel.start()
        progress.update(t, description=f"[green]✓ App tunnel ready (localhost:{app_tunnel.local_port} -> VM:5005)[/green]")
    except Exception as e:
        progress.update(t, description=f"[red]✗ SSH port-forward failed: {e}[/red]")
        return False
    t = progress.add_task(f"[yellow]Running {platform} client verification...[/yellow]", total=None)
    client_path = os.path.join(build_dir, client_filename)
    if not os.path.isfile(client_path):
        progress.update(t, description=f"[yellow]⊘ {client_filename} not found — skipping.[/yellow]")
        app_tunnel.stop()
        return False
    try:
        result = subprocess.run([sys.executable, client_path, "127.0.0.1", str(app_tunnel.local_port)],
                               capture_output=True, text=True, timeout=300, cwd=build_dir)
        if result.returncode == 0:
            from tee_crafter.cli.deployment.common.client_evidence import (
                save_client_evidence,
            )
            save_client_evidence(build_dir, result.stdout, result.stderr,
                                 console=console)
            if _response_has_proxy_error(result.stdout):
                progress.update(t, description=f"[red]✗ {platform} client got proxy error (container unreachable).[/red]")
                console.print(f"[dim]Client output: {result.stdout[:500]}[/dim]")
                if audit:
                    audit.record("Phase 5: Post-Deploy", f"{audit_label} client verification", "fail",
                                 reason="proxy returned container error")
                return False
            progress.update(t, description=f"[green]✓ {platform} client verification passed.[/green]")
            measurement_fields = extract_attestation_report(result.stdout or "", result.stderr or "")
            if isinstance(measurements, dict) and measurements:
                _extract_measurement_from_stderr(result.stderr or "", measurements)
                # ensure the caller's pre-seeded dict and the audit dict agree
                for k, v in measurements.items():
                    if v not in ("", None):
                        measurement_fields.setdefault(k, v)
            if audit:
                from tee_crafter.cli.deployment.common.attestation_report import (
                    emit_att_verdicts, detect_self_pinned_measurement,
                )
                baseline_pinned = not detect_self_pinned_measurement(
                    result.stdout or "", result.stderr or "")
                audit.record(
                    "Phase 5: Post-Deploy",
                    f"{audit_label} client verification",
                    "pass",
                    attestation_verified=True,
                    measurement_baseline_pinned=baseline_pinned,
                    **measurement_fields,
                )
                if not baseline_pinned:
                    console.print(
                        "[yellow]⚠ Measurement self-pinned (trust-on-first-use): "
                        "ship a pinned measurements.json for production.[/yellow]"
                    )
                emit_att_verdicts(
                    audit, success=True, measurement_fields=measurement_fields,
                    baseline_pinned=baseline_pinned,
                )
            return True
        progress.update(t, description=f"[red]✗ {platform} client verification failed.[/red]")
        # Persist full client output to disk so the tail can be inspected even if
        # the rendered console output is truncated.  The verifier prints a long
        # info-banner before any failure, so showing the *tail* (where errors
        # appear) is much more useful than the head.
        full_stderr = result.stderr or ""
        full_stdout = result.stdout or ""
        try:
            with open(os.path.join(build_dir, "client_stderr.log"), "w", encoding="utf-8") as _se:
                _se.write(full_stderr)
            with open(os.path.join(build_dir, "client_stdout.log"), "w", encoding="utf-8") as _so:
                _so.write(full_stdout)
        except Exception:
            pass
        console.print(f"[red]{platform}: client rc={result.returncode}[/red]")
        console.print(
            f"[dim]{platform}: client stderr tail "
            f"(full log at {os.path.basename(build_dir)}/client_stderr.log):\n"
            f"{full_stderr[-2500:]}[/dim]"
        )
        # Always pull the server-side journal on client failure — without it
        # we cannot distinguish a server crash from a transport issue.  The
        # service unit name is the same as ``service_name`` (which still
        # refers to the host-side tee-crafter app server, not the user
        # container).
        try:
            _jok, _journal, _ = run_ssh_command(
                f"sudo journalctl -u {service_name} --since '5 min ago' "
                f"-n 200 --no-pager 2>&1",
                ssh_key_path, user=admin_user, port=ssh_tunnel_port, timeout=20)
            if _journal:
                journal_path = os.path.join(build_dir, "server_journal.log")
                with open(journal_path, "w", encoding="utf-8") as _jf:
                    _jf.write(_journal)
                console.print(Panel(
                    _journal[-3000:],
                    title=f"[bold yellow]Server-side {service_name} journal (last 200 lines)[/bold yellow]",
                    border_style="yellow",
                ))
        except Exception as _je:
            console.print(f"[dim]Could not capture server journal: {_je}[/dim]")
        if audit:
            from tee_crafter.cli.deployment.common.attestation_report import emit_att_verdicts
            audit.record(
                "Phase 5: Post-Deploy", f"{audit_label} client verification", "fail",
                returncode=result.returncode,
                stderr_tail=full_stderr[-1500:],
                stderr_log="client_stderr.log",
            )
            emit_att_verdicts(audit, success=False, note=full_stderr[-200:])
        return False
    except subprocess.TimeoutExpired:
        progress.update(t, description=f"[red]✗ {platform} client timed out.[/red]")
        return False
    finally:
        app_tunnel.stop()
