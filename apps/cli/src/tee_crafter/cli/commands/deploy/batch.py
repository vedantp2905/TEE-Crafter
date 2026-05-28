"""Batch-mode orchestrator for ``deploy --batch`` and ``deploy-container --batch``.

Single entry point for the unified container batch surface:

* :func:`run_batch_container_deploy` — runs the user's Docker image as-is on the
  TEE host (``docs/batch_mode.md``) and captures every path the image wrote via
  ``docker diff`` + ``docker cp``.

The flow:

1. Stage a build directory (done by the caller / ``flow_container``).
2. Apply Terraform to provision the TEE.
3. Install the batch systemd unit + capture script + bundle.
4. Start the oneshot service, poll until it finishes, then download the
   ``output.tar.gz`` produced by the capture path.
5. Unpack the bundle into ``<build_dir>/output/`` and record provenance.

Steps 3-5 are platform-agnostic: they pick the right transport (SCP for
Azure/GCP, SSM/S3 for AWS, vsock collector for Nitro) via
:mod:`tee_crafter.cli.deployment.common.file_download`.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tarfile
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

from tee_crafter.cli.constants import Console
from tee_crafter.cli.constants import Panel

from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.cli.constants import console as _default_console
from tee_crafter.cli.deployment.common.file_download import (
    DownloadResult, download_batch_bundle, wait_for_oneshot_completion,
)
from tee_crafter.core.audit import BuildAuditTrail, sha256_file

logger = logging.getLogger(__name__)

BATCH_REMOTE_BASE = "/opt/tee-crafter-batch"
BATCH_REMOTE_INPUT = "/var/lib/tee_crafter/input"
BATCH_REMOTE_BUNDLE = "/var/lib/tee_crafter/output.tar.gz"
BATCH_REMOTE_SHA = BATCH_REMOTE_BUNDLE + ".sha256"
BATCH_CONTAINER_SERVICE = "tee-crafter-batch-container.service"


@dataclass
class BatchTransport:
    """Connection coordinates for the batch transport selector."""
    platform: str
    ssh_private_key_path: Optional[str] = None
    ssh_user: Optional[str] = None
    ssh_host: str = "localhost"
    ssh_port: int = 22
    aws_instance_id: Optional[str] = None
    aws_region: Optional[str] = None
    aws_bucket: Optional[str] = None
    aws_object_key: Optional[str] = None


@dataclass
class BatchResult:
    success: bool
    bundle_path: str = ""
    bundle_sha256: str = ""
    bundle_bytes: int = 0
    extracted_dir: str = ""
    exit_code: Optional[int] = None
    duration_sec: float = 0.0
    captured_file_count: int = 0
    captured_bytes: int = 0
    message: str = ""
    meta: dict = field(default_factory=dict)


def _ssh_runner(transport: BatchTransport):
    """Pick the correct ``run_ssh_command``/``run_ssm_command`` for *transport*."""
    p = transport.platform
    if p in ("tdx-azure", "snp-azure", "sgx-azure", "gpu-cc-azure"):
        from tee_crafter.core.remote.azure_ssh import run_ssh_command
        def _run(cmd: str, timeout: int = 60):
            return run_ssh_command(
                cmd, transport.ssh_private_key_path,
                user=transport.ssh_user or "azureuser",
                host=transport.ssh_host, port=transport.ssh_port,
                timeout=timeout)
        return _run
    if p in ("tdx-gcp", "snp-gcp", "gpu-cc-gcp"):
        from tee_crafter.core.remote.gcp_ssh import run_ssh_command
        def _run(cmd: str, timeout: int = 60):
            return run_ssh_command(
                cmd, transport.ssh_private_key_path,
                user=transport.ssh_user or "tee_admin",
                host=transport.ssh_host, port=transport.ssh_port,
                timeout=timeout)
        return _run
    if p in ("snp-aws", "gpu-cc-aws", "nitro-aws"):
        from tee_crafter.core.remote.ssm import run_ssm_command
        def _run(cmd: str, timeout: int = 60):
            return run_ssm_command(
                transport.aws_instance_id, cmd, transport.aws_region,
                timeout=timeout)
        return _run
    raise ValueError(f"Unsupported batch platform: {p}")


def _scp_uploader(transport: BatchTransport):
    """Pick the correct file upload function for *transport*."""
    p = transport.platform
    if p in ("tdx-azure", "snp-azure", "sgx-azure", "gpu-cc-azure"):
        from tee_crafter.core.remote.azure_ssh import upload_file_via_scp
        def _up(local: str, remote: str, timeout: int = 600):
            return upload_file_via_scp(
                local, remote, transport.ssh_private_key_path,
                user=transport.ssh_user or "azureuser",
                host=transport.ssh_host, port=transport.ssh_port,
                timeout=timeout)
        return _up
    if p in ("tdx-gcp", "snp-gcp", "gpu-cc-gcp"):
        from tee_crafter.core.remote.gcp_ssh import upload_file_via_scp
        def _up(local: str, remote: str, timeout: int = 600):
            return upload_file_via_scp(
                local, remote, transport.ssh_private_key_path,
                user=transport.ssh_user or "tee_admin",
                host=transport.ssh_host, port=transport.ssh_port,
                timeout=timeout)
        return _up
    if p in ("snp-aws", "gpu-cc-aws", "nitro-aws"):
        if not (transport.aws_bucket and transport.aws_region):
            raise ValueError("AWS batch upload needs aws_bucket and aws_region")
        from tee_crafter.core.remote.ssm_s3 import upload_file_via_s3
        def _up(local: str, remote: str, timeout: int = 600):
            key = f"batch/{os.path.basename(remote)}-{int(time.time())}"
            return upload_file_via_s3(
                local, transport.aws_bucket, key,
                transport.aws_instance_id, remote, transport.aws_region,
                timeout=timeout)
        return _up
    raise ValueError(f"Unsupported batch platform: {p}")


def _install_capture_script(transport: BatchTransport, run_remote, console: Console) -> bool:
    """Push ``tee_crafter_capture_container.sh`` onto the host and chmod +x it."""
    cur = os.path.dirname(os.path.abspath(__file__))
    src = os.path.normpath(os.path.join(
        cur, "..", "..", "..", "scripts", "common",
        "tee_crafter_capture_container.sh",
    ))
    if not os.path.isfile(src):
        console.print(f"[red]Capture script not found at {src}[/red]")
        return False
    upload = _scp_uploader(transport)
    tmp_remote = f"/tmp/tee_crafter_capture_container.sh.{int(time.time())}"
    ok, msg = upload(src, tmp_remote, timeout=120)
    if not ok:
        console.print(f"[red]Capture script upload failed: {msg}[/red]")
        return False
    ok, _, err = run_remote(
        f"sudo install -m 0755 -o root -g root {tmp_remote} "
        f"/usr/local/bin/tee_crafter_capture_container.sh && rm -f {tmp_remote}",
        timeout=30,
    )
    if not ok:
        console.print(f"[red]Capture script install failed: {err}[/red]")
        return False
    return True


def _install_unit(transport: BatchTransport, run_remote, console: Console,
                  *, unit_name: str, unit_text: str) -> bool:
    """Drop a systemd unit on the remote host via a base64-encoded inline pipe."""
    import base64
    encoded = base64.b64encode(unit_text.encode("utf-8")).decode("ascii")
    cmd = (
        f"echo {encoded} | base64 -d | "
        f"sudo tee /etc/systemd/system/{unit_name} >/dev/null && "
        f"sudo chmod 0644 /etc/systemd/system/{unit_name} && "
        f"sudo systemctl daemon-reload"
    )
    ok, _, err = run_remote(cmd, timeout=60)
    if not ok:
        console.print(f"[red]Unit install failed for {unit_name}: {err}[/red]")
        return False
    return True


#: Where the SGX bake leaves the enclave signing key (setup_sgx.sh step 6).
_VM_SIGNING_KEY = "/root/.config/gramine/enclave-key.pem"

#: Files the CVM secrets oneshot needs next to the app bundle.  ``app.env`` is
#: optional (only the plaintext ``--secrets-env`` path produces one).
_SECRET_BOOTSTRAP = "tee_crafter_secret_bootstrap.py"

#: The sidecar script ``tee-crafter-siem.service`` exec's on the VM host.
#: Staged from the build_dir root by ``core.builder.runtime_modules``.
_SIEM_EXPORTER = "siem_export.py"


def _upload_secret_bootstrap(transport: BatchTransport, run_remote, upload,
                             console: Console, *, build_dir: str,
                             ) -> Tuple[bool, str]:
    """Ship the secret-bootstrap script the CVM secrets oneshot executes.

    The batch container unit carries ``Requires=tee-crafter-secrets.service`` on
    every CVM platform (``resources._secrets_dep_block``), and that oneshot runs
    ``<remote_base>/app/tee_crafter_secret_bootstrap.py``.  The batch path
    uploaded only ``user_container.tar``, so the script was never there:

        can't open file '/opt/tee-crafter-snp/app/tee_crafter_secret_bootstrap.py'

    systemd then failed the dependency, the container **never started**, the
    capture hook found no container and exited 1, and the orchestrator reported
    the confusing downstream symptom
    ``scp: /var/lib/tee_crafter/output.tar.gz: No such file or directory``.
    Reproduced on both ``snp-azure`` and ``tdx-azure`` on 2026-08-22 and
    confirmed on the VM with ``systemctl status tee-crafter-secrets.service``.

    Uploading the script — rather than dropping the ``Requires=`` when no
    secrets were requested — keeps the fail-closed property: the oneshot still
    runs and still gates the workload, and it no-ops cleanly when there is
    nothing to unseal.  Deciding locally that "there are no secrets, so skip the
    gate" would put the gate behind a guess.

    SGX has no secrets oneshot (it is not in ``_REMOTE_BASE``), so this is a
    no-op there.
    """
    from tee_crafter.resources import _REMOTE_BASE

    remote_base = _REMOTE_BASE.get(transport.platform)
    if remote_base is None:
        return True, ""  # no secrets oneshot on this platform (SGX)

    local = os.path.join(build_dir, "app", _SECRET_BOOTSTRAP)
    if not os.path.isfile(local):
        local = os.path.join(build_dir, _SECRET_BOOTSTRAP)
    if not os.path.isfile(local):
        return False, (
            f"{_SECRET_BOOTSTRAP} is missing from {build_dir}; the CVM secrets "
            "oneshot cannot run and the container unit requires it")

    console.print("[yellow]Uploading secret bootstrap...[/yellow]")
    ok, _, err = run_remote(f"sudo mkdir -p {remote_base}/app", timeout=60)
    if not ok:
        return False, f"could not create {remote_base}/app: {(err or '')[:300]}"

    staged = f"/tmp/{_SECRET_BOOTSTRAP}"
    ok, msg = upload(local, staged, timeout=300)
    if not ok:
        return False, f"secret bootstrap upload failed: {msg[:300]}"
    ok, _, err = run_remote(
        f"sudo mv {staged} {remote_base}/app/{_SECRET_BOOTSTRAP} && "
        f"sudo chown root:root {remote_base}/app/{_SECRET_BOOTSTRAP} && "
        f"sudo chmod 0644 {remote_base}/app/{_SECRET_BOOTSTRAP}",
        timeout=60,
    )
    if not ok:
        return False, f"could not install the secret bootstrap: {(err or '')[:300]}"

    # The plaintext --secrets-env path also stages an app.env beside it.
    local_env = os.path.join(build_dir, "app", "app.env")
    if os.path.isfile(local_env):
        ok, msg = upload(local_env, "/tmp/tee_crafter_app.env", timeout=300)
        if not ok:
            return False, f"app.env upload failed: {msg[:300]}"
        ok, _, err = run_remote(
            f"sudo mv /tmp/tee_crafter_app.env {remote_base}/app/app.env && "
            f"sudo chmod 0600 {remote_base}/app/app.env",
            timeout=60,
        )
        if not ok:
            return False, f"could not install app.env: {(err or '')[:300]}"
    console.print("[green]✓ Secret bootstrap uploaded.[/green]")
    return True, ""


#: Sentinel the GSC runner echoes so the real exit status survives.
_RC_MARKER = "TEE_CRAFTER_RC="


#: The ephemeral NSG rule `templates/sgx/main.template.tf` adds for the GSC
#: build.  Deleted by :func:`close_graminize_egress` before the workload runs.
GRAMINIZE_EGRESS_RULE = "AllowGraminizeEgress"


def close_graminize_egress(build_dir: str, console: Console) -> Tuple[bool, str]:
    """Delete the build-only egress rule before the workload runs.

    Graminizing needs outbound 80/443 for one apt transaction (see
    :func:`_check_graminize_egress`); the workload does not, and this platform's
    whole posture is that it should not have it.  So the rule is opened by
    Terraform under its own name and closed here, by name, the moment the build
    is finished — leaving the batch container to run under ``DenyAllOutbound``
    like every other `sgx-azure` workload.

    A failure to close is treated as fatal by the caller.  Running a PHI
    workload with egress the operator did not ask for is worse than not running
    it, and "we opened it and could not close it" must never be a warning
    someone scrolls past.
    """
    import json as _json
    import subprocess as _sp

    tfstate = os.path.join(build_dir, "terraform.tfstate")
    if not os.path.isfile(tfstate):
        return False, f"no terraform.tfstate in {build_dir}"
    try:
        with open(tfstate, "r", encoding="utf-8") as fh:
            state = _json.load(fh)
    except (OSError, ValueError) as exc:
        return False, f"could not read terraform.tfstate: {exc}"

    nsg_name = rg_name = ""
    for res in state.get("resources", []):
        if res.get("type") != "azurerm_network_security_group":
            continue
        for inst in res.get("instances", []):
            attrs = inst.get("attributes", {}) or {}
            nsg_name = attrs.get("name", "") or nsg_name
            rg_name = attrs.get("resource_group_name", "") or rg_name
    if not nsg_name or not rg_name:
        return False, "could not find the NSG in terraform state"

    probe = _sp.run(
        ["az", "network", "nsg", "rule", "show", "-g", rg_name,
         "--nsg-name", nsg_name, "-n", GRAMINIZE_EGRESS_RULE, "-o", "none"],
        capture_output=True, text=True,
    )
    if probe.returncode != 0:
        # Never created (graminize_egress=false) or already gone — either way
        # the post-condition we care about already holds.
        console.print(
            f"[dim]Build egress rule {GRAMINIZE_EGRESS_RULE} not present; "
            f"nothing to close.[/dim]")
        return True, "absent"

    res = _sp.run(
        ["az", "network", "nsg", "rule", "delete", "-g", rg_name,
         "--nsg-name", nsg_name, "-n", GRAMINIZE_EGRESS_RULE],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        return False, (res.stderr or res.stdout or "az rule delete failed")[:400]

    verify = _sp.run(
        ["az", "network", "nsg", "rule", "show", "-g", rg_name,
         "--nsg-name", nsg_name, "-n", GRAMINIZE_EGRESS_RULE, "-o", "none"],
        capture_output=True, text=True,
    )
    if verify.returncode == 0:
        return False, "rule still present after delete"
    console.print(
        "[green]✓ Build egress closed — the workload runs under "
        "DenyAllOutbound.[/green]")
    return True, "closed"


def _check_graminize_egress(run_remote) -> Tuple[bool, str]:
    """Refuse to start a 30-minute build the VM's network cannot finish.

    Graminizing is a *source build*.  GSC's compile stage is ``FROM debian:13``
    and then installs build tooling from ``deb.debian.org``, adds Intel's SGX
    repository from ``download.01.org``, and clones Gramine from GitHub.  All of
    that is ordinary internet egress, and ``sgx-azure``'s NSG denies it: the only
    outbound rules the template writes are the Azure platform IP, IMDS, and
    HTTPS scoped to ``VirtualNetwork`` (``templates/sgx/main.template.tf``,
    ``AllowHTTPSEgress`` / ``DenyAllOutbound``).

    So the deploy failed at ``Step 1/30 : FROM debian:13`` with a Docker Hub
    ``i/o timeout``, roughly twenty-five minutes into the run, having already
    paid for Terraform, Bastion, and a 50 MB image upload.  Confirmed on the VM
    on 2026-08-22: ``curl https://registry-1.docker.io/v2/`` returned nothing at
    all, and adding a temporary Outbound rule for 80/443 made the same
    ``gsc build`` proceed straight past the Intel repository step.

    This is the actual reason MRENCLAVE had never been measured.  The Debian 13
    ``apt-key`` breakage was real and is fixed, but it sat downstream of a
    network that never let the build reach it.

    One probe, a few seconds, before any of that is spent.
    """
    ok, out, _ = run_remote(
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 "
        "https://registry-1.docker.io/v2/ || echo 000",
        timeout=60,
    )
    code = (out or "").strip().splitlines()[-1] if (out or "").strip() else "000"
    # 401 is the healthy answer here: the registry rejects an unauthenticated
    # v2 probe, which proves the TCP+TLS path works.  Only "no answer" is fatal.
    if ok and code not in ("000", ""):
        return True, ""
    return False, (
        "the SGX VM has no outbound internet, so GSC cannot graminize.\n"
        "  Graminizing builds Gramine from source on the VM: it needs Docker "
        "Hub (FROM debian:13), deb.debian.org, download.01.org and GitHub. "
        "This platform's NSG allows outbound HTTPS only to VirtualNetwork.\n"
        "  Re-run with [bold]TF_VAR_allow_setup_egress=true[/bold] to open "
        "outbound 80/443 for the build.\n"
        "  Note what that costs: the rule is written by Terraform and stays for "
        "the life of the VM, so the workload also runs with open egress rather "
        "than the deny-all posture this platform otherwise gives you. Decide "
        "that deliberately for anything handling PHI.")


def _run_gsc(run_remote, command: str, *, log: str, timeout: int):
    """Run a ``gsc`` command and actually notice when it fails.

    This wrapper exists because of a bug that hid every GSC failure this
    platform ever had.  The calls used to be::

        run_remote(f"sudo {command} 2>&1 | tail -40")

    and a shell pipeline exits with the status of its *last* command — ``tail``,
    which succeeds unconditionally.  So ``ok`` was ``True`` no matter what GSC
    did, both commands "passed", and the only thing that ever caught the problem
    was the ``docker image inspect`` afterwards, reporting the uninformative
    ``gsc reported success but gsc-<image> does not exist on the VM``.  The
    ``tail`` output that would have explained it was assigned to ``out`` and then
    only printed inside ``if not ok:`` — a branch that could not be reached.
    Measured on a real ``sgx-azure`` batch deploy, 2026-08-22: the deploy failed
    with that message and not one line of GSC's own output.

    GSC itself is well behaved here and that is worth stating, because the
    obvious suspicion is the other way round.  ``gsc build`` re-checks the image
    after the inner ``docker build`` and exits 1 with ``Failed to build unsigned
    graminized Docker image`` when it is absent (gsc.py:463-465 at the pinned
    commit 0b2ba93; reproduced locally the same day, ``RC=1``).  The status was
    real; this project threw it away.

    ``pipefail`` would fix the status but not the diagnosis, so instead the
    output goes to *log* on the VM (where it survives for an operator to read
    over SSH) and the exit code comes back in a sentinel line that no amount of
    piping can launder.
    """
    ok, out, err = run_remote(
        f"sudo {command} > {log} 2>&1; rc=$?; "
        f"echo '{_RC_MARKER}'$rc; tail -80 {log}",
        timeout=timeout,
    )
    text = (out or "") + (("\n" + err) if err else "")
    rc = None
    for line in text.splitlines():
        if line.startswith(_RC_MARKER):
            try:
                rc = int(line[len(_RC_MARKER):].strip())
            except ValueError:
                rc = None
            break
    if not ok:
        return False, text, f"could not run '{command}' on the VM"
    if rc is None:
        return False, text, (
            f"'{command}' produced no {_RC_MARKER} marker; its exit status is "
            f"unknown, so it cannot be treated as success")
    if rc != 0:
        return False, text, f"'{command}' exited {rc} (full log on the VM at {log})"
    return True, text, ""


def graminize_on_vm(run_remote, console: Console, *, image_ref: str,
                    ) -> Tuple[bool, str, str]:
    """Graminize *image_ref* with GSC **on the SGX VM**, in place.

    Returns ``(ok, message, mrenclave)``.

    This used to happen on the operator's workstation.  It cannot: GSC never
    passes a platform to ``docker build`` (there is no ``platform`` anywhere in
    ``gsc.py``), so it graminizes for the daemon's native architecture, and
    Gramine/SGX is x86-only.  On an arm64 host that silently produced an arm64
    Gramine — observed on 2026-08-22, where the build pulled
    ``libcurl4t64:arm64``.

    Doing it here is also strictly better than making it work locally:

    * the VM is amd64 and has real SGX, so the enclave is built where it runs;
    * the signing key is already on the VM, baked in by ``setup_sgx.sh``, so no
      private key crosses the wire.  MRSIGNER is therefore stable for every VM
      from a given image, which is what an attestation policy needs;
    * ``gramine-sgx-sign`` can report the real **MRENCLAVE** here, which the
      local path could only ever record as ``"pending-runtime"``.

    GSC names its own outputs — ``gsc-<image>-unsigned`` then ``gsc-<image>`` —
    so the signed image is re-tagged back onto *image_ref*, leaving the systemd
    unit (which runs ``tee-crafter:latest``) unchanged.
    """
    console.print("[yellow]Graminizing image on the SGX VM (GSC)...[/yellow]")
    ok, out, err = run_remote("command -v gsc || echo MISSING", timeout=30)
    if not ok or "MISSING" in (out or ""):
        return False, (
            "gsc is not installed on the SGX VM. The image was baked before GSC "
            "was added to scripts/sgx_azure/setup_sgx.sh — re-bake with "
            "`tee-crafter internal bake-ami --tee-platform sgx-azure`."
        ), ""

    ok_egress, egress_msg = _check_graminize_egress(run_remote)
    if not ok_egress:
        return False, egress_msg, ""

    # Reuse the one manifest definition rather than restating the fields here;
    # base64 so no shell quoting can mangle the TOML on the way over.
    import base64

    from tee_crafter.cli.deployment.sgx.gsc import build_manifest

    manifest = "/tmp/tee-crafter-gsc.manifest"
    encoded = base64.b64encode(build_manifest().encode("utf-8")).decode("ascii")
    ok, _, err = run_remote(f"echo {encoded} | base64 -d > {manifest}", timeout=30)
    if not ok:
        return False, f"could not write the GSC manifest: {(err or '')[:300]}", ""

    # `gsc build <image> <manifest>` -> gsc-<image>-unsigned
    ok, out, err = _run_gsc(
        run_remote, f"gsc build {image_ref} {manifest}",
        log="/tmp/tee-crafter-gsc-build.log", timeout=2400)
    if not ok:
        return False, f"gsc build failed: {((err or '') + (out or ''))[-2000:]}", ""

    # Declare the batch I/O paths in the finalized manifest, between build and
    # sign.  They cannot go in the fragment (GSC would demand they exist at
    # build time and then measure them) and they cannot go in after signing
    # (the signature would not cover them).  See
    # deployment/sgx/gsc.manifest_patch_command for the full argument.
    from tee_crafter.cli.deployment.sgx.gsc import (
        BATCH_ALLOWED_PATHS, gsc_unsigned_image_name,
        manifest_patch_dockerfile,
    )

    unsigned = gsc_unsigned_image_name(image_ref)
    _, app_user, _ = run_remote(
        f"sudo docker inspect -f '{{{{.Config.User}}}}' {unsigned}", timeout=60)
    patch_ctx = "/tmp/tee-crafter-gsc-patch"
    dockerfile = manifest_patch_dockerfile(unsigned, (app_user or "").strip())
    encoded = base64.b64encode(dockerfile.encode("utf-8")).decode("ascii")
    ok, out, err = run_remote(
        f"rm -rf {patch_ctx} && mkdir -p {patch_ctx} && "
        f"echo {encoded} | base64 -d > {patch_ctx}/Dockerfile && "
        f"sudo docker build -t {unsigned} {patch_ctx}",
        timeout=300)
    if not ok:
        return False, (
            "could not declare the batch I/O paths in the graminized "
            f"manifest: {((err or '') + (out or ''))[-800:]}"), ""
    console.print(
        "[dim]Declared " + " ".join(BATCH_ALLOWED_PATHS) +
        " in the enclave manifest (measured into MRENCLAVE at signing).[/dim]")
    # Say this out loud rather than leaving it in the container log.  Gramine
    # prints an "insecure configurations ... must not be used in production"
    # banner for any non-empty sgx.allowed_files, and it is telling the truth:
    # the enclave does not verify these paths.
    console.print(
        "[yellow]Note: the enclave does not verify /input or /output. Gramine "
        "will print an `insecure configurations` banner for sgx.allowed_files "
        "on every run. Input integrity rests on the input digest recorded in "
        "the signed audit trail, and /output is host-visible in the "
        "clear.[/yellow]")

    # `gsc sign-image <image> <key>` -> gsc-<image>
    ok, out, err = _run_gsc(
        run_remote, f"gsc sign-image {image_ref} {_VM_SIGNING_KEY}",
        log="/tmp/tee-crafter-gsc-sign.log", timeout=1200)
    if not ok:
        return False, f"gsc sign-image failed: {((err or '') + (out or ''))[-2000:]}", ""

    signed = f"gsc-{image_ref}"
    ok, out, _ = run_remote(
        f"sudo docker image inspect {signed} >/dev/null 2>&1 && echo PRESENT "
        f"|| echo ABSENT", timeout=60)
    if "PRESENT" not in (out or ""):
        # Both commands exited 0 but the artefact is missing; do not let the
        # unit fall back to running the un-graminized image.
        _, imgs, _ = run_remote(
            "sudo docker image ls --format '{{.Repository}}:{{.Tag}}' "
            "| grep -i gsc || echo '(no gsc-* images)'", timeout=60)
        return False, (
            f"gsc exited 0 for both build and sign-image but {signed} does not "
            f"exist on the VM.\n"
            f"  gsc-* images present: {(imgs or '').strip()[:300]}\n"
            f"  Full logs on the VM: /tmp/tee-crafter-gsc-build.log and "
            f"/tmp/tee-crafter-gsc-sign.log (re-run with "
            f"TEE_CRAFTER_KEEP_ON_FAILURE=1 to keep the VM and read them)"), ""

    mrenclave = read_mrenclave_on_vm(run_remote, signed)
    ok, _, err = run_remote(
        f"sudo docker tag {signed} {image_ref}", timeout=60)
    if not ok:
        return False, f"could not re-tag {signed}: {(err or '')[:300]}", ""
    console.print(
        f"[green]✓ Graminized on the VM ({signed})"
        + (f", MRENCLAVE {mrenclave[:16]}…" if mrenclave else "")
        + ".[/green]")
    return True, "", mrenclave


def read_mrenclave_on_vm(run_remote, signed_image: str) -> str:
    """Best-effort MRENCLAVE of the graminized image, read on the VM.

    GSC writes the signed SIGSTRUCT into the image, and
    ``gramine-sgx-sigstruct-view`` prints its measurement.  Returns ``""`` when
    it cannot be read — a missing measurement must not fail the deploy, but it
    must also never be invented, so the caller records "unreported" rather than
    a placeholder that looks like a value.
    """
    # PYTHONPATH is the whole trick, and without it this returned "" every time.
    # ``gramine-sgx-sigstruct-view`` is ``#!/usr/bin/python3`` and imports
    # ``graminelibos``, which GSC installs under its own meson prefix
    # (``/gramine/meson_build_output/lib/python3.N/site-packages``) rather than
    # onto the system path.  The graminized image's real entrypoint sets that up;
    # overriding it with ``/bin/sh`` — which this probe must do, since the normal
    # entrypoint launches the enclave — does not, so every invocation died with
    # ``ModuleNotFoundError: No module named 'graminelibos'``.  Both stderr and
    # the exit status were swallowed by ``2>/dev/null``, so the caller just saw
    # an empty string and recorded ``unreported``.
    #
    # The ``python3*`` glob is resolved on the VM rather than pinned: GSC's
    # Gramine build follows the base image's Python, which was 3.13 here and will
    # not stay 3.13.
    #
    # Measured working on real SGX hardware 2026-08-22:
    # mr_enclave 1fe84b9fb6190fc432b1fe8e0233c6fe51abf235a402f47944504aedcd82a21a
    probe = (
        f"sudo docker run --rm --entrypoint /bin/sh {signed_image} -c "
        "'export PYTHONPATH=$(ls -d /gramine/meson_build_output/lib/python3*/"
        "site-packages 2>/dev/null | head -1):$PYTHONPATH; "
        "for f in /gramine/app_files/*.sig; do "
        "  gramine-sgx-sigstruct-view \"$f\" 2>/dev/null; done' "
        "2>/dev/null | tr -d ' ' | sed -n 's/^mr_enclave:*//p' | head -1"
    )
    ok, out, _ = run_remote(probe, timeout=180)
    val = (out or "").strip().lower()
    if ok and len(val) == 64 and all(c in "0123456789abcdef" for c in val):
        return val
    return ""


#: The CVM dependency the batch unit ``Requires=``.  Started explicitly (and
#: blocking) before the batch unit so its failure is reported as its own, and so
#: the batch unit's own activation window is not spent queued behind it.
_SECRETS_UNIT = "tee-crafter-secrets.service"


def _start_secrets_dependency(transport: BatchTransport, run_remote,
                              console: Console) -> Tuple[bool, str]:
    """Start (blocking) the secrets oneshot the batch unit depends on.

    ``Requires=`` would start it anyway, but doing it here buys two things.

    First, the failure is attributable.  A dependency that fails takes the
    dependent job down with it, and what the orchestrator then sees on the
    *batch* unit is ``ActiveState=inactive Result=success`` — systemd's
    never-ran state, with no hint of which dependency died.  Starting it
    ourselves means a failure is reported against ``tee-crafter-secrets``
    with that unit's own journal attached.

    Second, it takes the wait off the batch unit's activation window.  The
    oneshot reads a hardware attestation report and may call out to a KMS, and
    it is allowed 120s (``secrets.service.template``: ``TimeoutStartSec``).
    While it runs, the batch unit's job sits queued, and a queued job is
    indistinguishable by ``systemctl show`` from one that never ran — see
    :func:`_start_oneshot_and_wait`.

    ``reset-failed`` first because the unit is ``WantedBy=multi-user.target``
    and therefore already ran once at boot, before the orchestrator had
    uploaded ``tee_crafter_secret_bootstrap.py``; that boot attempt failed, and
    a start-limit-hit unit refuses to start again until it is reset.

    No-op for SGX, which ships no secrets oneshot.
    """
    from tee_crafter.resources import _REMOTE_BASE

    if transport.platform not in _REMOTE_BASE:
        return True, ""
    console.print(f"[yellow]Starting {_SECRETS_UNIT} (fail-closed gate)...[/yellow]")
    ok, _, err = run_remote(
        f"sudo systemctl reset-failed {_SECRETS_UNIT} 2>/dev/null; "
        f"sudo systemctl start {_SECRETS_UNIT}",
        timeout=180,
    )
    if ok:
        console.print(f"[green]✓ {_SECRETS_UNIT} active.[/green]")
        return True, ""
    _, jout, jerr = run_remote(
        f"sudo systemctl status {_SECRETS_UNIT} --no-pager -l 2>&1 | head -20; "
        f"sudo journalctl -u {_SECRETS_UNIT} --no-pager -n 40 2>&1 | tail -30",
        timeout=60,
    )
    detail = ((jout or "") + (jerr or "")).strip()
    if detail:
        console.print(f"[dim]{detail[-2000:]}[/dim]")
    return False, (
        f"{_SECRETS_UNIT} failed to start: {(err or '').strip()[:300] or 'no stderr'}"
        " — the workload is gated on it, so the run is aborted (fail closed)")


def _start_oneshot_and_wait(transport: BatchTransport, run_remote,
                             console: Console, *, unit_name: str,
                             timeout: int) -> Tuple[bool, str]:
    ok, msg = _start_secrets_dependency(transport, run_remote, console)
    if not ok:
        return False, msg
    run_remote(
        f"sudo systemctl reset-failed {unit_name} 2>/dev/null; true",
        timeout=15,
    )
    # Start --no-block returns once the job is enqueued, so the orchestrator
    # has to work out from the outside what happened to it.  For a
    # ``Type=oneshot`` unit with ``RemainAfterExit=no`` that is harder than it
    # looks, because ``systemctl show`` reports **the same thing** in four
    # different situations.  Measured on systemd 257 (Debian 13) with a
    # purpose-built harness — see ``tests/cli/test_oneshot_activation_probe.py``
    # for the recorded transcript:
    #
    #   situation                | jobs | ActiveState | Result    | InvocationID
    #   -------------------------|------|-------------|-----------|-------------
    #   never started            |  0   | inactive    | success   | (empty)
    #   queued behind a slow dep |  1   | inactive    | success   | (empty)
    #   job cancelled (dep died) |  0   | inactive    | success   | (empty)
    #   running                  |  1   | activating  | success   | set
    #   finished successfully    |  0   | inactive    | success   | (empty)
    #   exited non-zero          |  0   | failed      | exit-code | set
    #
    # Two consequences drive the shape of this probe:
    #
    # * ``ExecMainStartTimestampMonotonic`` is **not** durable evidence that
    #   the unit ran.  systemd releases the runtime state of a successful
    #   oneshot the moment it goes back to inactive, so that field returns to
    #   0 and ``InvocationID`` empties — a completed run is byte-identical to
    #   one that never happened.  Only a *failed* unit keeps its state.
    # * ``systemctl list-jobs`` is the discriminator that does work.  A queued
    #   job is listed; a cancelled one is not.  Nothing in ``systemctl show``
    #   separates those two, which is exactly how a run that was merely slow
    #   to be scheduled got reported as "never ran" (snp-azure and tdx-azure,
    #   2026-08-22: the secrets oneshot took longer than the probe's window,
    #   and the batch unit started 30s later, just after we gave up on it).
    #
    # So: a pending job means keep waiting, a failed unit means fail now, and
    # in the ambiguous inactive-with-no-job case the journal — which does
    # persist — is asked whether the unit finished, was cancelled, or never
    # ran at all.  ``--since`` scopes that to this invocation so a previous
    # run's "Finished" cannot be mistaken for this one's.
    activation_probe = (
        "T0=$(date -u '+%Y-%m-%d %H:%M:%S'); echo \"T0=$T0\"; "
        f"sudo systemctl start --no-block {unit_name} && "
        "for i in $(seq 1 60); do "
        f"  vals=$(systemctl show {unit_name} "
        "    -p ActiveState -p Result -p ExecMainStatus "
        "    -p ExecMainStartTimestampMonotonic 2>/dev/null); "
        "  active=$(echo \"$vals\"  | sed -n 's/^ActiveState=//p'); "
        "  result=$(echo \"$vals\"  | sed -n 's/^Result=//p'); "
        "  exitst=$(echo \"$vals\"  | sed -n 's/^ExecMainStatus=//p'); "
        "  started=$(echo \"$vals\" | sed -n 's/^ExecMainStartTimestampMonotonic=//p'); "
        "  case \"$active\" in "
        "    activating|active|deactivating|reloading) "
        "      echo ACTIVATED:$active; exit 0;; "
        "    failed) "
        "      echo FAILED_EARLY:$active:result=$result:exit=$exitst; exit 0;; "
        "  esac; "
        # A job for this unit still exists: it is queued (typically behind
        # After=/Requires=) or running.  Either way it has not been cancelled,
        # so hand off to the completion waiter rather than declaring failure.
        f"  jobs=$(systemctl list-jobs --no-legend 2>/dev/null | grep -Fc '{unit_name}'); "
        "  if [ -n \"$jobs\" ] && [ \"$jobs\" != \"0\" ]; then "
        "    echo QUEUED:$active:jobs=$jobs; exit 0; "
        "  fi; "
        # Kept as a cheap short-circuit for the window between ExecStart
        # starting and ActiveState catching up; no longer load-bearing, since
        # the field is cleared again on success (see the table above).
        "  if [ -n \"$started\" ] && [ \"$started\" != \"0\" ]; then "
        "    echo ACTIVATED:ran:started=$started:result=$result; exit 0; "
        "  fi; "
        # Inactive, no job, never failed: ask the journal which of the three
        # identical-looking states this is.  Restricted to lines systemd
        # emitted — the unit's own stdout goes to the same journal, so an
        # unfiltered match on "Finished" would accept a user container that
        # merely printed "Finished processing" as a completed run.
        f"  jl=$(sudo journalctl -u {unit_name} --no-pager "
        "        --since \"$T0\" 2>/dev/null "
        "        | grep -oE 'systemd\\[[0-9]+\\]: (Dependency failed|Finished)'); "
        "  case \"$jl\" in "
        "    *'Dependency failed'*) "
        "      echo DEPENDENCY_FAILED:$active:result=$result; exit 0;; "
        "  esac; "
        "  case \"$jl\" in "
        "    *Finished*) "
        "      echo COMPLETED:$active:result=$result; exit 0;; "
        "  esac; "
        "  sleep 1; "
        "done; "
        "echo NEVER_RAN:$active:result=$result; exit 0"
    )
    ok, out, err = run_remote(activation_probe, timeout=120)
    if not ok:
        return False, f"start failed: {err}"
    activation_line = (out or "").strip().splitlines()[-1] if out else ""
    if activation_line.startswith(("NOT_ACTIVATED", "NEVER_RAN",
                                   "DEPENDENCY_FAILED")):
        # Print the journal rather than discarding it: `run_remote` returns the
        # output, and dropping it is what left the operator with only the
        # downstream SCP error to go on.
        _, jout, jerr = run_remote(
            f"sudo systemctl --no-pager --failed 2>&1 | head -20; "
            f"sudo systemctl list-jobs --no-pager 2>&1 | head -10; "
            f"sudo journalctl -u {unit_name} --no-pager -n 60 2>&1 | tail -40",
            timeout=60,
        )
        detail = ((jout or "") + (jerr or "")).strip()
        if detail:
            console.print(f"[dim]{detail[-2000:]}[/dim]")
        if activation_line.startswith("DEPENDENCY_FAILED"):
            return False, (
                f"systemd cancelled the job ({activation_line}) because a "
                f"Requires= dependency failed. Check "
                f"`systemctl status {_SECRETS_UNIT}` on the VM.")
        if activation_line.startswith("NEVER_RAN"):
            return False, (
                f"the unit never ran ({activation_line}): after 60s it had no "
                f"pending job, had never entered a running state, and its "
                f"journal recorded neither a start nor a cancellation.")
        return False, f"unit never activated: {activation_line}"
    if activation_line.startswith("COMPLETED"):
        # The whole job fit inside the probe window.  There is nothing left for
        # the completion waiter to observe — the unit's runtime state is
        # already released — so accept the journal's word for it.
        return True, "completed-during-activation"
    # The probe echoes the UTC timestamp it took just before starting the unit;
    # the waiter scopes its journal reads to it so a previous run of the same
    # unit on the same host cannot supply this run's "Finished" line.
    since = ""
    for line in (out or "").splitlines():
        if line.startswith("T0="):
            since = line.split("=", 1)[1].strip()
            break
    ok, state, last = wait_for_oneshot_completion(
        platform=transport.platform, service_name=unit_name,
        timeout=timeout,
        ssh_private_key_path=transport.ssh_private_key_path,
        ssh_user=transport.ssh_user,
        ssh_host=transport.ssh_host, ssh_port=transport.ssh_port,
        aws_instance_id=transport.aws_instance_id,
        aws_region=transport.aws_region,
        journal_since=since or None,
    )
    if not ok:
        return False, f"oneshot poll: {state} last={last[:200]}"
    return True, state


def _safe_member(m: "tarfile.TarInfo", dest_dir: str) -> Optional["tarfile.TarInfo"]:
    """Return ``m`` if safe to extract under *dest_dir*, else None.

    Hardened against four classes of malicious / merely-inconvenient archive
    entries that show up routinely in container batch output (``docker diff``
    on Debian-based images is full of them):

    1. Absolute member paths (``/etc/passwd``).
    2. ``..`` escapes that resolve outside *dest_dir*.
    3. Symlinks / hardlinks whose target is absolute (e.g.
       ``./files/usr/bin/nawk -> /usr/bin/gawk``) — Python 3.12's
       ``tarfile.data_filter`` aborts the whole extract on these; we skip
       them instead, which is correct for our use case (the link targets
       refer to files inside the *container*, not the host build dir).
    4. Symlinks / hardlinks whose resolved target escapes *dest_dir*.
    5. Special files (devices, fifos) — never present in legitimate
       batch output and refused outright.
    """
    name = m.name
    if not name or name.startswith("/") or ".." in name.split("/"):
        return None
    if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
        return None
    target_path = os.path.realpath(os.path.join(dest_dir, name))
    if not (target_path == dest_dir or target_path.startswith(dest_dir + os.sep)):
        return None
    if m.issym() or m.islnk():
        link = m.linkname or ""
        if not link or link.startswith("/"):
            return None
        if ".." in link.split("/"):
            return None
        link_resolved = os.path.realpath(
            os.path.join(os.path.dirname(target_path), link))
        if not (link_resolved == dest_dir
                or link_resolved.startswith(dest_dir + os.sep)):
            return None
    return m


def _extract_bundle(local_bundle: str, dest_dir: str) -> Tuple[int, int, dict]:
    """Unpack ``output.tar.gz`` and return (file_count, bytes, meta).

    Uses :func:`_safe_member` to filter the archive: unsafe entries are
    silently skipped (and counted in ``meta["captured_files"]["skipped"]``)
    rather than aborting the whole extract.  This is essential for the
    container batch path, where the captured tree often contains absolute
    symlinks created by ``docker cp`` against system paths inside the
    container image.
    """
    dest_dir = os.path.realpath(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)
    file_count = 0
    bytes_total = 0
    meta: dict = {}
    skipped = 0
    with tarfile.open(local_bundle, "r:gz") as tf:
        for m in tf.getmembers():
            safe = _safe_member(m, dest_dir)
            if safe is None:
                skipped += 1
                continue
            try:
                tf.extract(safe, dest_dir, set_attrs=False)
            except (OSError, tarfile.TarError) as e:
                logger.debug("skipping unextractable member %s: %s",
                             safe.name, e)
                skipped += 1
                continue
    for dirpath, _dirs, files in os.walk(dest_dir):
        for name in files:
            full = os.path.join(dirpath, name)
            try:
                bytes_total += os.path.getsize(full)
            except OSError:
                continue
            file_count += 1
    meta_path = os.path.join(dest_dir, "_meta.json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}
    if skipped:
        cf = meta.setdefault("captured_files", {})
        cf["skipped_unsafe_entries"] = skipped
    return file_count, bytes_total, meta


def _record_run(audit: Optional[BuildAuditTrail], *, mode: str, platform: str,
                input_sha: str, result: BatchResult,
                batch_entrypoint: str = "") -> None:
    if audit is None:
        return
    audit.record_batch_run(
        mode=mode, platform=platform,
        input_bundle_sha256=input_sha,
        output_bundle_sha256=result.bundle_sha256,
        exit_code=result.exit_code or 0,
        duration_sec=result.duration_sec,
        captured_file_count=result.captured_file_count,
        captured_bytes=result.captured_bytes,
        batch_entrypoint=batch_entrypoint,
        status="pass" if result.success else "fail",
        message=result.message[:200],
    )


def _install_siem_for_batch(run_remote, upload, console: Console, *,
                            build_dir: str, tee_platform: str, audit) -> None:
    """Start the SIEM sidecar before the workload, if SIEM is configured.

    The batch path never did this.  ``install_siem_sidecar`` is called from the
    per-platform *phase* modules (``deployment/<platform>/phase.py``), and
    ``--batch`` returns before any of them run — so ``--siem splunk-hec --batch``
    staged a ``siem.env``, opened egress for the collector, printed nothing to
    the contrary, and exported not one event.  On ``sgx-azure`` that was the
    whole story for the platform, because ``sgx-azure`` is batch-only.

    Ordering matters: the sidecar has to be streaming *before* the oneshot
    starts.  A batch container can exit in seconds, and an exporter started
    afterwards has nothing left to attest.

    A failure here is not fatal on its own — ``_withhold_output_if_unaudited``
    is what enforces the policy once the run is over, and it makes that call on
    delivered evidence rather than on whether an install script exited 0.
    """
    from tee_crafter.cli.deployment.common.siem_sidecar import (
        install_siem_sidecar, is_siem_enabled, sidecar_app_dir,
    )
    from tee_crafter.core.audit import build_layout as _layout

    if not is_siem_enabled(build_dir):
        return

    # Stage the script the unit exec's.  Exactly the `_upload_secret_bootstrap`
    # problem one unit over: the sidecar's ExecStart is
    # `<app_dir>/siem_export.py`, and on the persistent path that file arrives
    # because the phase modules ship the whole build_dir.  Batch uploads only
    # `user_container.tar` and the input directory, so the unit installed fine
    # and then crash-looped:
    #
    #     /usr/bin/python3: can't open file
    #     '/opt/tee-crafter-sgx/siem_export.py': [Errno 2] ...
    #
    # Observed on a live `sgx-azure --batch --siem datadog` run (2026-08-23,
    # restart counter 12).  The output gate did its job and withheld the
    # bundle, so the failure was safe -- but on `sgx-azure`, which is
    # batch-only, it meant SIEM had never once worked on this platform.
    # Everything the sidecar needs, in the order the install script expects it.
    #
    # `siem_export.py` is what the unit exec's.  `siem.env` is what tells it to
    # run at all: the install script relocates `<app_dir>/siem.env` onto tmpfs
    # (SIEM-SEC-2) and the unit reads it via `EnvironmentFile=-`, the `-`
    # meaning "optional".  Absent, the exporter starts, sees no
    # TEE_CRAFTER_SIEM_ENABLED, logs "SIEM disabled ... exiting" and stops --
    # observed on a live sgx-azure batch run on 2026-08-23, *after* the
    # exporter itself was being staged correctly.  Both files reach the VM for
    # free on the persistent path because the phase modules ship the whole
    # build_dir; batch uploads only the container tarball and the input dir.
    app_dir = sidecar_app_dir(tee_platform)
    _artifacts = (
        # (candidate local paths, remote name, mode)
        ((os.path.join(build_dir, _SIEM_EXPORTER),
          os.path.join(build_dir, "app", _SIEM_EXPORTER)),
         _SIEM_EXPORTER, "0644"),
        # 0600: this one carries the HEC token / API key until the install
        # script moves it to tmpfs and shreds the on-disk copy.
        ((_layout.siem_env(build_dir),
          os.path.join(build_dir, "siem", "siem.env"),
          os.path.join(build_dir, "siem.env"),
          os.path.join(build_dir, "app", "siem.env")),
         "siem.env", "0600"),
    )

    ok, _, err = run_remote(f"sudo mkdir -p {app_dir}", timeout=60)
    for candidates, name, mode in _artifacts:
        local = next((c for c in candidates if c and os.path.isfile(c)), None)
        if local is None:
            console.print(
                f"[yellow]⚠ {name} is not in {build_dir}; the SIEM sidecar "
                "will not export.[/yellow]")
            continue
        staged = f"/tmp/tee_crafter_stage_{name}"
        step_ok, step_err = ok, err
        if step_ok:
            step_ok, step_err = upload(local, staged, timeout=300)
        if step_ok:
            step_ok, _, step_err = run_remote(
                f"sudo mv {staged} {app_dir}/{name} && "
                f"sudo chown root:root {app_dir}/{name} && "
                f"sudo chmod {mode} {app_dir}/{name}",
                timeout=60,
            )
        if step_ok:
            console.print(f"[green]✓ SIEM {name} staged.[/green]")
        else:
            # Not fatal here: _withhold_output_if_unaudited decides the run's
            # fate on delivered evidence, not on whether an upload worked.
            console.print(
                f"[yellow]⚠ could not stage {name} to {app_dir}: "
                f"{str(step_err)[:200]}[/yellow]")

    try:
        install_siem_sidecar(
            console=console, build_dir=build_dir, tee_platform=tee_platform,
            run_remote=lambda cmd: run_remote(cmd, timeout=300),
            audit=audit, batch=True,
        )
    except Exception as exc:  # noqa: BLE001 — never let this abort the run
        console.print(
            f"[yellow]SIEM sidecar install raised {type(exc).__name__}; the "
            f"output gate will decide the outcome.[/yellow]")


def _withhold_output_if_unaudited(
    run_remote, console: Console, *, build_dir: str, tee_platform: str,
    local_bundle: str, extracted_dir: str, duration: float,
) -> Optional[BatchResult]:
    """No delivered audit trail, no output.  Returns a failure, or ``None``.

    This is the preventive control for batch runs, and it exists because the
    in-TEE one cannot apply: ``siem_health.fail_closed_wrap`` wraps
    ``process_request``, and a batch container has no requests — it runs to
    completion and exits.  So ``--batch --siem …`` was detective on *every*
    platform, not only on the two that run the exporter host-side.  What is
    available instead is the output: an unaudited run does not get to hand over
    PHI-derived results and report success.

    The bundle and its extraction are deleted rather than left on disk with a
    warning printed over them, because a warning is exactly what this control
    was before.  Operators who need the output of an unaudited run can say so —
    ``"fail_open": true`` in the ``--siem-config`` — which is the same escape
    hatch the eight CVM platforms already offer for the request gate.
    """
    from tee_crafter.cli.deployment.common.siem_sidecar import (
        batch_export_delivered, is_siem_enabled, siem_fail_open,
    )

    if not is_siem_enabled(build_dir):
        return None

    delivered, reason = batch_export_delivered(run_remote, tee_platform)
    if delivered:
        console.print(
            "[green]✓ Attestation events confirmed delivered for this batch "
            "run.[/green]")
        return None

    if siem_fail_open(build_dir):
        console.print(
            f"[yellow]! This batch run shipped no audit trail ({reason}).[/yellow]\n"
            f"[yellow]  Releasing the output anyway because fail_open is set. "
            f"The SOC has no record that this run happened.[/yellow]")
        return None

    for path in (local_bundle, f"{local_bundle}.sha256"):
        try:
            os.remove(path)
        except OSError:
            pass
    shutil.rmtree(extracted_dir, ignore_errors=True)

    console.print(
        f"[bold red]Output withheld: this batch run was not audited.[/bold red]\n"
        f"[red]  {reason}.\n"
        f"  The container ran and produced output, but its attestation events "
        f"never reached the collector, so there is no record of the run. The "
        f"bundle has been deleted rather than handed over.\n"
        f"  Fix the collector path and re-run, or set [cyan]\"fail_open\": true"
        f"[/cyan] in the --siem-config to accept an unaudited run.[/red]")
    return BatchResult(
        False, duration_sec=duration,
        message=f"output withheld — batch run not audited: {reason}",
    )


def collect_batch_output(
    *,
    transport: BatchTransport,
    build_dir: str,
    unit_name: str,
    unit_text: str,
    bundle_max_bytes: Optional[int] = None,
    timeout_sec: int = 3600,
    install_capture_script: bool = False,
    extra_pre_start: Optional[str] = None,
    audit: Optional[BuildAuditTrail] = None,
    console: Optional[Console] = None,
) -> BatchResult:
    """Install the batch unit, run it, download the bundle, and unpack it.

    This is the post-Terraform-apply half of both batch modes.  Every cloud
    detail (SCP vs. SSM, vsock vs. SSH host, etc.) is hidden inside the
    transport selectors, so callers only have to know which platform they
    are talking to.
    """
    console = console or _default_console
    run_remote = _ssh_runner(transport)

    if install_capture_script:
        if not _install_capture_script(transport, run_remote, console):
            return BatchResult(False, message="capture script install failed")

    if not _install_unit(transport, run_remote, console,
                         unit_name=unit_name, unit_text=unit_text):
        return BatchResult(False, message="systemd unit install failed")

    _install_siem_for_batch(run_remote, _scp_uploader(transport), console,
                            build_dir=build_dir,
                            tee_platform=transport.platform, audit=audit)

    if extra_pre_start:
        run_remote(extra_pre_start, timeout=60)

    # The unit name is the one thing an operator needs here — it is what
    # `journalctl -u <unit>` takes when a batch fails.  It used to vanish:
    # `strip_rich_markup` stripped every bracketed run, so "[{unit_name}]" was
    # treated as a style tag and deleted, printing "Running batch  on the VM".
    # Fixed in `cli.constants`, which now only strips real style tags.
    console.print(
        f"[yellow]Running batch [{unit_name}] on the VM "
        f"(quiet until done; max wait {timeout_sec}s)."
        "[/yellow]"
    )
    started = time.time()
    ok, state = _start_oneshot_and_wait(
        transport, run_remote, console,
        unit_name=unit_name, timeout=timeout_sec,
    )
    duration = time.time() - started
    if not ok:
        console.print(f"[red]Batch oneshot did not complete: {state}[/red]")
        # Print it.  This call used to fetch the journal and throw it away,
        # which is why the only thing an operator ever saw was the state string.
        _, jout, jerr = run_remote(
            f"sudo journalctl -u {unit_name} --no-pager -n 100 2>&1 | tail -100",
            timeout=30,
        )
        detail = ((jout or "") + (jerr or "")).strip()
        if detail:
            console.print(f"[dim]{detail[-4000:]}[/dim]")
        return BatchResult(False, duration_sec=duration, message=state)

    local_bundle = os.path.join(build_dir, "output.tar.gz")
    dl: DownloadResult = download_batch_bundle(
        platform=transport.platform,
        local_path=local_bundle,
        remote_bundle_path=BATCH_REMOTE_BUNDLE,
        remote_sha_path=BATCH_REMOTE_SHA,
        max_output_size=bundle_max_bytes,
        ssh_private_key_path=transport.ssh_private_key_path,
        ssh_user=transport.ssh_user,
        ssh_host=transport.ssh_host, ssh_port=transport.ssh_port,
        aws_instance_id=transport.aws_instance_id,
        aws_region=transport.aws_region,
        aws_bucket=transport.aws_bucket,
        aws_object_key=transport.aws_object_key
            or f"batch-output/{int(time.time())}.tar.gz",
        timeout=max(600, timeout_sec // 4),
    )
    if not dl.success:
        return BatchResult(
            False, duration_sec=duration, message=f"download failed: {dl.message}"
        )

    extracted_dir = os.path.join(build_dir, "output")
    file_count, bytes_total, meta = _extract_bundle(local_bundle, extracted_dir)

    exit_code = meta.get("exit_code")
    if exit_code is None:
        exit_code_path = os.path.join(extracted_dir, "_logs", "exit_code.txt")
        if os.path.isfile(exit_code_path):
            try:
                with open(exit_code_path, "r", encoding="utf-8") as f:
                    exit_code = int((f.read().strip() or "0").split()[0])
            except Exception:
                exit_code = None

    captured_files = meta.get("captured_files", {}) or {}
    captured_count = (
        captured_files.get("runtime_count", 0)
        + captured_files.get("tmp_count", 0)
    ) or file_count
    captured_bytes = (
        captured_files.get("runtime_bytes", 0)
        + captured_files.get("tmp_bytes", 0)
    ) or bytes_total

    withheld = _withhold_output_if_unaudited(
        run_remote, console,
        build_dir=build_dir, tee_platform=transport.platform,
        local_bundle=local_bundle, extracted_dir=extracted_dir,
        duration=duration,
    )
    if withheld is not None:
        return withheld

    return BatchResult(
        success=True,
        bundle_path=local_bundle,
        bundle_sha256=dl.sha256,
        bundle_bytes=dl.size_bytes,
        extracted_dir=extracted_dir,
        exit_code=exit_code,
        duration_sec=meta.get("duration_sec", duration),
        captured_file_count=captured_count,
        captured_bytes=captured_bytes,
        message="ok",
        meta=meta,
    )


def run_batch_container_deploy(
    *,
    build_dir: str,
    transport: BatchTransport,
    container_tar_local: str,
    bundle_max_bytes: Optional[int] = None,
    batch_timeout: int = 3600,
    input_dir_local: Optional[str] = None,
    audit: Optional[BuildAuditTrail] = None,
    console: Optional[Console] = None,
) -> BatchResult:
    """Mode A: run the user's Docker image on *transport* and capture its diff.

    The caller must have already:

    * provisioned the TEE (Terraform apply done),
    * resolved ``transport`` (host/instance, ssh key/region/bucket),
    * staged the user image as ``container_tar_local`` (the same tarball
      ``flow_container.py`` produces for non-batch deploys).
    """
    console = console or _default_console
    upload = _scp_uploader(transport)
    run_remote = _ssh_runner(transport)

    console.print(Panel.fit(
        "[bold blue]Batch container mode[/bold blue]\n\n"
        f"Platform: [cyan]{transport.platform}[/cyan]\n"
        f"Image tarball: [cyan]{os.path.basename(container_tar_local)}[/cyan]\n"
        f"Timeout: {batch_timeout}s",
        border_style="blue",
    ))

    result = BatchResult(False, message="batch did not run")
    input_sha = ""
    try:
        console.print("[yellow]Preparing remote directories...[/yellow]")
        ok_mkdir, _, err_mkdir = run_remote(
            f"sudo mkdir -p {BATCH_REMOTE_INPUT} /var/lib/tee_crafter && "
            f"sudo chown -R root:root {BATCH_REMOTE_INPUT}",
            timeout=60,
        )
        if not ok_mkdir:
            console.print(
                f"[red]Remote mkdir failed:[/red] {(err_mkdir or '').strip()[:400]}"
            )
            result = BatchResult(False, message=f"remote mkdir failed: {err_mkdir}")
            return result

        ok_secrets, secrets_msg = _upload_secret_bootstrap(
            transport, run_remote, upload, console, build_dir=build_dir,
        )
        if not ok_secrets:
            result = BatchResult(False, message=secrets_msg)
            return result

        if input_dir_local and os.path.isdir(input_dir_local):
            console.print(
                f"[yellow]Uploading input directory ({input_dir_local})...[/yellow]"
            )
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
                tmp_path = tmp.name
            try:
                with tarfile.open(tmp_path, "w:gz") as tf:
                    tf.add(input_dir_local, arcname=".")
                input_sha = sha256_file(tmp_path)
                ok, msg = upload(tmp_path, "/tmp/tee_crafter_input.tar.gz", timeout=600)
                if not ok:
                    console.print(f"[red]Input upload failed:[/red] {msg[:400]}")
                    result = BatchResult(False, message=f"input upload failed: {msg}")
                    return result
                ok_x, _, err_x = run_remote(
                    f"sudo tar xzf /tmp/tee_crafter_input.tar.gz -C {BATCH_REMOTE_INPUT} && "
                    f"rm -f /tmp/tee_crafter_input.tar.gz",
                    timeout=120,
                )
                if not ok_x:
                    console.print(
                        f"[red]Input extract failed:[/red] {(err_x or '').strip()[:400]}"
                    )
                    result = BatchResult(False, message=f"input extract failed: {err_x}")
                    return result
            finally:
                try: os.unlink(tmp_path)
                except OSError: pass

        if not os.path.isfile(container_tar_local):
            console.print(f"[red]Missing container tar:[/red] {container_tar_local}")
            result = BatchResult(
                False, message=f"missing container tar: {container_tar_local}"
            )
            return result
        tar_size_mb = os.path.getsize(container_tar_local) / (1024 * 1024)
        console.print(
            f"[yellow]Uploading container image ({tar_size_mb:.0f} MB)...[/yellow]"
        )
        # SCP (Azure/GCP) runs as the unprivileged SSH user, which has no
        # write access to root-owned ``/var/lib/tee_crafter`` even though we
        # created it above with ``sudo mkdir``. Stage the tarball through
        # ``/tmp`` (user-writable on every supported image) and ``sudo
        # install`` it into place with ``root:root 0644``. This keeps the
        # final file root-owned (same posture as before) and works
        # uniformly for SCP and SSM/S3 transports.
        tmp_tar_remote = f"/tmp/tee_crafter_user_container.{os.getpid()}.tar"
        ok, msg = upload(
            container_tar_local, tmp_tar_remote,
            timeout=max(600, int(os.path.getsize(container_tar_local) / 524288) + 120),
        )
        if not ok:
            console.print(f"[red]Image upload failed:[/red] {msg[:400]}")
            result = BatchResult(False, message=f"image upload failed: {msg}")
            return result
        ok_install, _, err_install = run_remote(
            f"sudo install -m 0644 -o root -g root "
            f"{tmp_tar_remote} /var/lib/tee_crafter/user_container.tar && "
            f"rm -f {tmp_tar_remote}",
            timeout=120,
        )
        if not ok_install:
            console.print(
                f"[red]Image install failed:[/red] {(err_install or '').strip()[:400]}"
            )
            run_remote(f"rm -f {tmp_tar_remote}", timeout=30)
            result = BatchResult(
                False, message=f"image install failed: {err_install}"
            )
            return result
        console.print("[green]✓ Container image uploaded.[/green]")

        console.print("[yellow]Loading container image into Docker on the VM...[/yellow]")
        ok_load, _, err_load = run_remote(
            "sudo docker load -i /var/lib/tee_crafter/user_container.tar 2>&1 | "
            "sed -n 's/^Loaded image: //p' | tail -1 | "
            "xargs -r -I{} sudo docker tag {} tee-crafter:latest",
            timeout=600,
        )
        if not ok_load:
            console.print(
                f"[red]Remote docker load failed:[/red] "
                f"{(err_load or '').strip()[:400]}"
            )
            result = BatchResult(
                False, message=f"remote docker load failed: {err_load}"
            )
            return result
        console.print("[green]✓ Container image loaded on VM.[/green]")
        # The server-image heuristic used to run here, against the image that
        # had just been loaded.  It now runs at build time, in
        # ``flow_container.warn_if_batch_image_looks_like_a_server``, because by
        # this point the operator has already paid for Terraform and Bastion —
        # which is the cost the warning exists to avoid.  Same image, same
        # check, roughly twenty minutes earlier.

        if transport.platform == "sgx-azure":
            from tee_crafter.cli.deployment.sgx.gsc import (
                ALLOW_NON_ENCLAVE_SGX_ENV, non_enclave_sgx_allowed,
            )
            ok_gsc, gsc_msg, mrenclave = graminize_on_vm(
                run_remote, console, image_ref="tee-crafter:latest",
            )
            if not ok_gsc:
                # Fail closed.  Running the un-graminized image means a plain
                # process on the SGX VM: no enclave, no MRENCLAVE, nothing to
                # attest — and this used to report success anyway.
                if not non_enclave_sgx_allowed():
                    result = BatchResult(
                        False,
                        message=(f"remote graminize failed: {gsc_msg}\n\n"
                                 f"Set {ALLOW_NON_ENCLAVE_SGX_ENV}=1 to accept a "
                                 f"NON-ENCLAVE run instead."))
                    return result
                console.print(
                    f"[bold yellow]! Running WITHOUT an enclave "
                    f"({ALLOW_NON_ENCLAVE_SGX_ENV} set): {gsc_msg}[/bold yellow]")
                if audit is not None:
                    audit.record("Phase 2: SGX Packaging", "GSC graminize (on VM)",
                                 "warn", reason=gsc_msg[:300],
                                 non_enclave_override=True)
            elif audit is not None:
                audit.record("Phase 2: SGX Packaging", "GSC graminize (on VM)",
                             "pass", mrenclave=mrenclave or "unreported")

            # The build is over; take its egress away before the workload runs.
            # Fatal on failure: an SGX workload silently keeping internet access
            # it was only lent for a `docker build` is precisely the posture
            # this platform exists to avoid.
            ok_closed, close_msg = close_graminize_egress(build_dir, console)
            if audit is not None:
                audit.record(
                    "Phase 2: SGX Packaging", "Close build egress",
                    "pass" if ok_closed else "fail", detail=close_msg[:300])
            if not ok_closed:
                return BatchResult(
                    False,
                    message=(
                        f"graminizing succeeded but the build-only egress rule "
                        f"({GRAMINIZE_EGRESS_RULE}) could not be closed: "
                        f"{close_msg}\n"
                        f"Refusing to run the workload with egress it should "
                        f"not have. Delete the rule by hand and re-run, or "
                        f"tear the deployment down."))

        from tee_crafter.resources import load_container_batch_unit
        unit_text = load_container_batch_unit(transport.platform,
                                              batch_timeout_sec=batch_timeout)

        result = collect_batch_output(
            transport=transport, build_dir=build_dir,
            unit_name=BATCH_CONTAINER_SERVICE, unit_text=unit_text,
            bundle_max_bytes=bundle_max_bytes,
            timeout_sec=batch_timeout,
            install_capture_script=True,
            audit=audit, console=console,
        )
        if result.success:
            console.print(Panel.fit(
                f"[bold green]Batch container run captured.[/bold green]\n"
                f"Exit code: {result.exit_code}\n"
                f"Files: {result.captured_file_count}   Bytes: {result.captured_bytes}\n"
                f"Bundle: [cyan]{result.bundle_path}[/cyan] (sha256={result.bundle_sha256[:16]}...)\n"
                f"Extracted: [cyan]{result.extracted_dir}[/cyan]",
                border_style="green",
            ))
        return result
    finally:
        # Always record the run + persist provenance, even on early returns
        # (mkdir/upload/load failures). Without this the build_dir would not
        # contain build_provenance.json, so a failed batch run would leave
        # nothing for `tee-crafter verify-provenance` to inspect.
        try:
            _record_run(audit, mode="container", platform=transport.platform,
                        input_sha=input_sha, result=result)
            if audit is not None:
                save_audit_trail(audit, build_dir, console)
        except Exception as exc:
            console.print(
                f"[dim]Audit trail save skipped: {exc}[/dim]"
            )


