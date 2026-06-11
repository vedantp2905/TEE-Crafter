"""Unified offline-wheel management for every TEE platform and cloud.

Security model
--------------
CVM / enclave instances have **no outbound internet access**.  Dependencies
are downloaded on the trusted deployer machine, transported via a secure
channel (S3-VPC-endpoint, SCP-over-Bastion, SCP-over-IAP), and installed
offline with ``pip install --no-index --find-links``.

Every non-SGX platform follows the same four steps:

  1. ``download_wheels()``     – pip download targeting x86_64 Linux
  2. caller uploads wheels     – platform-specific transport
  3. ``offline_install_cmd()`` – pip install --no-index (fully airgapped)
  4. ``verify_imports_cmd()``  – confirm critical runtime deps importable

No network-based ``pip install`` ever runs on a remote instance.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

# All TEE targets run x86_64 Linux.
_TARGET_PLATFORMS = (
    "manylinux2014_x86_64",
    "manylinux_2_17_x86_64",
    "manylinux_2_28_x86_64",
    "linux_x86_64",
)

TEE_RUNTIME_IMPORT_CHECK = "import requests, cryptography"

# Fixed deps for the Nitro host proxy (system Python, not user-specified).
NITRO_HOST_PROXY_DEPS = (
    "fastapi>=0.111,<1",
    "uvicorn>=0.29,<1",
    "boto3>=1.34,<2",
    "cryptography>=42.0,<44",
    "requests>=2.31,<3",
    # anyio (via starlette) needs this on Python < 3.11; the marker is
    # intentionally omitted so that pip-download on a 3.12 deployer still
    # fetches the wheel for 3.10 targets (pip evaluates markers against the
    # running interpreter, ignoring --python-version).
    "exceptiongroup>=1.0.2",
)

# Framework deps for CPU-TEE venvs (SNP/TDX) — baked into venv at setup.
CVM_FRAMEWORK_DEPS = (
    "cryptography>=42.0,<44",
)

# Container mode on CVMs: ``app_snp.py`` / ``app_tdx.py`` run in the guest venv on
# the host and only HTTP-forward to the user container. They need ``requests`` +
# ``cryptography`` (RA-TLS), not the user's full ``requirements.txt``.
CVM_CONTAINER_HOST_VENV_DEPS = (
    "requests>=2.31,<3",
    "cryptography>=42.0,<44",
    "exceptiongroup>=1.0.2",
)
CVM_CONTAINER_HOST_REQ_FILENAME = "host_venv_requirements.txt"

# BYOK provider -> extra host-venv pip deps the in-TEE secret bootstrap needs.
# The ``tee-crafter-secrets`` oneshot runs the attested key release through
# ``tee_crafter.core.keys.<provider>`` on the CVM host; container mode otherwise
# strips the venv to proxy deps, so the cloud SDK must be added back when BYOK
# is in play (mirrors what wheel-mode gets via the full install).
BYOK_PROVIDER_RUNTIME_DEPS = {
    "aws-kms": ("boto3>=1.34,<2",),
    "gcp-kms": ("google-cloud-kms>=2.21,<3",),
    "azure-kv": ("azure-identity>=1.16,<2", "azure-keyvault-keys>=4.9,<5"),
    "external-hsm": (),  # uses requests (already present)
    "none": (),
}

# tee_crafter subpackages the in-TEE secret bootstrap imports.  We stage just
# these (not the whole CLI) into the container-mode app bundle so the host venv
# can run the attested BYOK / sealed-.env release without a full package install.
_BYOK_RUNTIME_PKG_SUBDIRS = ("core/keys", "core/measurements")


def byok_provider_from_app_dir(app_dir: str) -> str:
    """Return the BYOK provider configured for this deploy (or ``"none"``).

    Reads ``byok.env.public`` (the non-secret BYOK config staged next to the
    app) for ``TEE_CRAFTER_BYOK=<provider>``.  Container-mode artifact staging
    uses this to decide whether the host venv needs the package + cloud SDK.
    """
    pub = os.path.join(app_dir, "byok.env.public")
    if not os.path.isfile(pub):
        return "none"
    try:
        with open(pub, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip()
                if line.startswith("TEE_CRAFTER_BYOK="):
                    val = line.split("=", 1)[1].strip()
                    return val or "none"
    except OSError:
        pass
    return "none"


def stage_byok_runtime_package(app_dir: str) -> str | None:
    """Copy the minimal ``tee_crafter`` runtime subpackage into *app_dir*.

    The secret bootstrap is launched as
    ``python3 <app_dir>/tee_crafter_secret_bootstrap.py`` so ``<app_dir>`` is on
    ``sys.path[0]``; staging ``<app_dir>/tee_crafter/`` therefore makes
    ``import tee_crafter.core.keys...`` resolve in the otherwise-stripped
    container-mode host venv.  Returns the staged package root, or ``None`` if
    the local package source could not be located.
    """
    try:
        import tee_crafter  # the deployer's installed package
    except Exception:  # noqa: BLE001
        return None
    pkg_file = getattr(tee_crafter, "__file__", None)
    if not pkg_file:
        return None
    src_root = os.path.dirname(os.path.abspath(pkg_file))
    dst_root = os.path.join(app_dir, "tee_crafter")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    os.makedirs(os.path.join(dst_root, "core"), exist_ok=True)
    # Package markers up the chain.
    for rel in ("__init__.py", os.path.join("core", "__init__.py")):
        s = os.path.join(src_root, rel)
        if os.path.isfile(s):
            shutil.copyfile(s, os.path.join(dst_root, rel))
    for sub in _BYOK_RUNTIME_PKG_SUBDIRS:
        s = os.path.join(src_root, sub)
        if os.path.isdir(s):
            shutil.copytree(
                s, os.path.join(dst_root, sub), dirs_exist_ok=True, ignore=ignore)
    return dst_root

# Framework deps for GPU-CC venvs.
# nv-attestation-sdk + cryptography + PyJWT are already installed by the
# bake script into the on-VM venv; only add packages here that are NOT
# baked but needed at deploy time (e.g. user framework requirements).
GPU_CC_FRAMEWORK_DEPS = (
    "cryptography>=42.0,<44",
)


# ---------------------------------------------------------------------------
#  requirements.txt helpers
# ---------------------------------------------------------------------------

def requirements_declares(text: str, package: str) -> bool:
    """True if *text* has a requirements-style line installing *package*."""
    want = package.strip().lower().replace("_", "-")
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "--")):
            continue
        name = re.split(r"[\[;><=!~]", line, maxsplit=1)[0]
        if name.strip().lower().replace("_", "-") == want:
            return True
    return False


# ---------------------------------------------------------------------------
#  Image pip-freeze manifest (delta-only deploy uploads)
# ---------------------------------------------------------------------------
#
# Every bake script writes ``/etc/tee_crafter/image_pip_frozen.txt`` after
# the venv is provisioned.  At deploy time we read it back over the same
# transport used to run the bake script, parse it into a {name: version}
# map, and ask the user's requirements.txt which entries the image already
# satisfies.  Those entries are dropped from the ``pip download`` call —
# meaning we never re-download or re-upload wheels that are already on
# the VM.  For GPU-CC this collapses a 2.9 GB upload to a few MB (just the
# app + any genuinely-new user deps).  See docs/optimizations.md §1-2.

IMAGE_PIP_FROZEN_PATH = "/etc/tee_crafter/image_pip_frozen.txt"


def parse_pip_freeze(text: str) -> dict[str, str]:
    """Parse ``pip freeze`` output into a ``{normalized_name: version}`` map.

    Lines that aren't simple ``name==version`` pins (editable installs,
    direct URLs, VCS refs, etc.) are skipped — we treat those as "uncertain"
    and let the deploy-time download fetch them again, which is the safe
    default.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "@", "/", "git+", "file:", "http")):
            continue
        if "==" not in line:
            continue
        name, _, ver = line.partition("==")
        name = name.strip().lower().replace("_", "-")
        ver = ver.strip()
        if not name or not ver or " " in ver:
            continue
        out[name] = ver
    return out


def _parse_req_entry(raw: str) -> tuple[str, str] | None:
    """Return ``(normalized_name, full_line)`` for a normal requirement line.

    Returns ``None`` for blank lines, comments, ``-r`` / ``-c`` includes,
    pip options, editable installs, direct URLs, and VCS refs — i.e.
    anything we should not try to interpret as a single-package pin.
    """
    line = raw.split("#", 1)[0].strip()
    if not line:
        return None
    if line.startswith(("-r", "-c", "-e", "--", "/", "@", "git+", "file:", "http")):
        return None
    name = re.split(r"[\[;><=!~ ]", line, maxsplit=1)[0]
    name = name.strip().lower().replace("_", "-")
    if not name:
        return None
    return name, raw


def _req_pins_exact_version(req_line: str, version: str) -> bool:
    """True if *req_line* pins exactly ``==version`` (no other constraints).

    Conservative: we only count ``foo==X.Y.Z`` as a match (optionally with
    an extras suffix and trailing whitespace / inline comment).  Anything
    fancier — ranges, multiple specifiers, environment markers — falls
    through to a normal download so we never silently drop a wheel the
    user explicitly constrained.
    """
    line = req_line.split("#", 1)[0].strip()
    if ";" in line:
        return False
    head, _, tail = line.partition("==")
    if not head or not tail:
        return False
    head = re.sub(r"\[.*?\]\s*$", "", head).strip()
    if any(op in head for op in (">", "<", "!", "~", "=")):
        return False
    tail_first = tail.split(",", 1)[0].strip()
    return tail_first == version


def filter_requirements_against_image(
    req_text: str, image_pins: dict[str, str],
) -> tuple[str, list[str]]:
    """Drop requirement lines that the image's pip-freeze already satisfies.

    Returns ``(filtered_requirements_text, skipped_package_names)``.

    The filtered text is what we hand to ``pip download``.  ``skipped``
    is logged so the operator can see exactly which heavy wheels were
    eliminated from the upload (e.g. ``torch``, ``nvidia-cudnn-cu12``).

    Only exact ``==`` pins are dropped — anything looser (range, marker,
    editable, VCS) is kept verbatim so we never violate the user's spec.
    """
    if not image_pins:
        return req_text, []
    kept: list[str] = []
    skipped: list[str] = []
    for raw in req_text.splitlines():
        parsed = _parse_req_entry(raw)
        if parsed is None:
            kept.append(raw)
            continue
        name, _ = parsed
        installed_ver = image_pins.get(name)
        if installed_ver and _req_pins_exact_version(raw, installed_ver):
            skipped.append(f"{name}=={installed_ver}")
            continue
        kept.append(raw)
    return "\n".join(kept) + ("\n" if req_text.endswith("\n") else ""), skipped


def write_cvm_container_host_requirements(app_dir: str) -> str:
    """Write ``host_venv_requirements.txt`` under *app_dir* for offline host venv install.

    When BYOK is enabled for this deploy (``byok.env.public`` present), the host
    venv additionally needs the provider's cloud SDK and the staged
    ``tee_crafter`` runtime subpackage so the in-TEE ``tee-crafter-secrets``
    oneshot can run the attested key / sealed-.env release.  Both are added here
    so every CVM container platform (snp/tdx/gpu) gets it from one place.
    """
    deps = list(CVM_CONTAINER_HOST_VENV_DEPS)
    provider = byok_provider_from_app_dir(app_dir)
    if provider not in ("none", ""):
        for dep in BYOK_PROVIDER_RUNTIME_DEPS.get(provider, ()):
            if dep not in deps:
                deps.append(dep)
        # Stage the runtime subpackage so `import tee_crafter.core.keys...`
        # resolves from the app dir in the stripped container-mode venv.
        stage_byok_runtime_package(app_dir)
    path = os.path.join(app_dir, CVM_CONTAINER_HOST_REQ_FILENAME)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(deps) + "\n")
    return path


def remote_cvm_container_host_requirements(remote_base: str) -> str:
    """Remote path to the file written by :func:`write_cvm_container_host_requirements`."""
    return f"{remote_base}/app/{CVM_CONTAINER_HOST_REQ_FILENAME}"


def ensure_tee_deps_in_requirements(req_path: str) -> None:
    """Append TEE runtime pins (``requests``, ``cryptography``, ``exceptiongroup``) if missing."""
    existing = ""
    if os.path.isfile(req_path):
        with open(req_path, "r", encoding="utf-8") as f:
            existing = f.read()
    to_add: list[str] = []
    if not requirements_declares(existing, "requests"):
        to_add.append("requests>=2.31,<3")
    if not requirements_declares(existing, "cryptography"):
        to_add.append("cryptography>=42.0,<44")
    if not requirements_declares(existing, "exceptiongroup"):
        to_add.append("exceptiongroup>=1.0.2")
    if to_add:
        with open(req_path, "a", encoding="utf-8") as f:
            f.write("\n" + "\n".join(to_add) + "\n")


# ---------------------------------------------------------------------------
#  Local wheel download
# ---------------------------------------------------------------------------

def download_wheels(
    req_file: str,
    py_version: str,
    dest_dir: str,
    console,
    label: str,
    timeout: int = 300,
) -> int:
    """Download wheels for x86_64 Linux into *dest_dir*.

    Both the strict (binary-only) and relaxed (source-allowed) attempts
    always pin the target platform to x86_64 Linux so that the result is
    correct even when the deployer runs on ARM macOS.

    Returns the number of files in *dest_dir* after download.
    """
    platform_args: list[str] = []
    for plat in _TARGET_PLATFORMS:
        platform_args.extend(["--platform", plat])

    dl = subprocess.run(
        [sys.executable, "-m", "pip", "download",
         "-r", req_file, "-d", dest_dir,
         *platform_args,
         "--python-version", py_version, "--only-binary=:all:"],
        capture_output=True, text=True, timeout=timeout,
    )
    if dl.returncode != 0:
        console.print(
            f"[dim]{label}: binary-only download failed, "
            "retrying with source allowed (still x86_64)…[/dim]"
        )
        subprocess.run(
            [sys.executable, "-m", "pip", "download",
             "-r", req_file, "-d", dest_dir,
             *platform_args,
             "--python-version", py_version],
            capture_output=True, text=True, timeout=timeout,
        )

    count = len(os.listdir(dest_dir))
    console.print(f"[dim]{label}: {count} wheel/sdist files downloaded[/dim]")
    return count


def download_wheels_delta(
    req_file: str,
    py_version: str,
    dest_dir: str,
    console,
    label: str,
    image_pins: dict[str, str] | None,
    timeout: int = 300,
) -> int:
    """Like :func:`download_wheels` but skip wheels already on the image.

    *image_pins* is the parsed ``/etc/tee_crafter/image_pip_frozen.txt``
    manifest from the bake VM, as returned by :func:`parse_pip_freeze`.
    If it is ``None`` or empty (e.g. the bake didn't write a manifest,
    or the deploy-time fetch failed), we fall back to the unfiltered
    download — same semantics as before, no regression.

    Returns the number of files in *dest_dir* after download (0 if the
    filtered requirements list was empty, i.e. every wheel was on the
    image — perfectly valid, the caller will simply not include
    ``wheels/`` in the upload bundle).
    """
    if not image_pins:
        return download_wheels(req_file, py_version, dest_dir, console, label, timeout)
    with open(req_file, "r", encoding="utf-8") as f:
        original = f.read()
    filtered, skipped = filter_requirements_against_image(original, image_pins)
    if skipped:
        console.print(
            f"[dim]{label}: skipping {len(skipped)} wheel(s) already on image: "
            f"{', '.join(skipped[:6])}"
            f"{', …' if len(skipped) > 6 else ''}[/dim]"
        )
    has_real_req = any(_parse_req_entry(line) is not None for line in filtered.splitlines())
    if not has_real_req:
        console.print(f"[dim]{label}: every wheel already on image — skipping download.[/dim]")
        os.makedirs(dest_dir, exist_ok=True)
        return 0
    filtered_path = req_file + ".filtered"
    with open(filtered_path, "w", encoding="utf-8") as f:
        f.write(filtered)
    try:
        return download_wheels(filtered_path, py_version, dest_dir, console, label, timeout)
    finally:
        try:
            os.unlink(filtered_path)
        except OSError:
            pass


def fetch_image_pip_manifest(run_remote_fn, *, timeout: int = 30) -> dict[str, str]:
    """Read ``/etc/tee_crafter/image_pip_frozen.txt`` from the remote VM.

    *run_remote_fn* must be a callable matching
    ``(cmd: str, timeout: int) -> tuple[bool, str, str]`` (the shape used
    by every transport wrapper in this codebase).  Empty or missing
    manifests are returned as ``{}`` so callers can blindly fall through
    to the unfiltered download — the optimization is strictly opportunistic.
    """
    cmd = f"cat {IMAGE_PIP_FROZEN_PATH} 2>/dev/null || true"
    try:
        ok, out, _ = run_remote_fn(cmd, timeout=timeout)
    except Exception:
        return {}
    if not ok or not out:
        return {}
    return parse_pip_freeze(out)


# ---------------------------------------------------------------------------
#  Fast tarball creation (parallel gzip when pigz is available)
# ---------------------------------------------------------------------------
#
# Python's built-in ``tarfile.open("w:gz")`` is single-threaded and
# compresses at ~30 MB/s on modern hardware — easily the bottleneck for
# a 100-300 MB app bundle on a multi-core deployer.  When the system
# has ``pigz`` (parallel gzip, ships in apt/brew) we shell out to
# ``tar -cf - <paths> | pigz -p N > <output>`` instead, which scales
# linearly with cores (typically 3-6× faster on a 6-core MacBook).
#
# Falls back to the pure-Python path when:
#   * ``pigz`` is not on $PATH,
#   * ``tar`` is not on $PATH (Windows deployers),
#   * the caller asked for ``force_python=True``,
#   * the shell pipeline returns a non-zero exit code.
#
# Both paths emit a gzip stream so the remote ``tar xzf`` decompresses
# identically — pigz output is just standard gzip with parallel CPU.

def _has_pigz() -> bool:
    return shutil.which("pigz") is not None and shutil.which("tar") is not None


def make_tarball_fast(
    out_path: str,
    members: list[tuple[str, str]],
    *,
    force_python: bool = False,
) -> bool:
    """Build a gzip tarball at *out_path* from ``[(src_path, arcname), …]``.

    Uses pigz when available, falls back to Python tarfile otherwise.
    Returns True on success.  Designed so callers can keep their old
    tarfile-based code path verbatim and simply call this helper first.

    Caller is responsible for *out_path* cleanup (this matches the
    existing pattern in ``azure_bastion_client.py`` /
    ``gcp_phase_client.py`` / ``aws_artifacts.py``).
    """
    if not force_python and _has_pigz():
        cpu = max(1, (os.cpu_count() or 4))
        # Use ``tar -C srcdir -cf -`` per member so we keep arcname
        # semantics (each member is added under its requested top-level
        # path inside the tarball, independent of the host filesystem
        # layout).  The pigz stage receives the uncompressed tar stream
        # and writes the final ``.tar.gz`` to disk.
        import tempfile as _t, subprocess as _sp

        with _t.NamedTemporaryFile(suffix=".tar", delete=False) as raw:
            raw_path = raw.name
        try:
            for src, arc in members:
                if os.path.isdir(src):
                    parent = os.path.dirname(src.rstrip("/")) or "."
                    base = os.path.basename(src.rstrip("/")) or "."
                    transform = f"--transform=s,^{re.escape(base)},{arc},"
                    rc = _sp.run(
                        ["tar", "-C", parent, "-rf", raw_path, transform, base],
                        capture_output=True, text=True, timeout=600,
                    )
                else:
                    parent = os.path.dirname(src) or "."
                    base = os.path.basename(src)
                    transform = f"--transform=s,^{re.escape(base)},{arc},"
                    rc = _sp.run(
                        ["tar", "-C", parent, "-rf", raw_path, transform, base],
                        capture_output=True, text=True, timeout=600,
                    )
                if rc.returncode != 0:
                    raise RuntimeError(f"tar -rf failed: {rc.stderr[:300]}")
            with open(out_path, "wb") as fout:
                rc = _sp.run(
                    ["pigz", "-c", "-p", str(cpu), raw_path],
                    stdout=fout, stderr=_sp.PIPE, timeout=600,
                )
            if rc.returncode != 0:
                raise RuntimeError(f"pigz failed: {rc.stderr.decode(errors='replace')[:300]}")
            return True
        except Exception:
            try:
                os.unlink(out_path)
            except OSError:
                pass
        finally:
            try:
                os.unlink(raw_path)
            except OSError:
                pass

    # Python fallback (also reached when pigz path raised).
    with tarfile.open(out_path, "w:gz") as tar:
        for src, arc in members:
            tar.add(src, arcname=arc)
    return True


def make_nitro_proxy_wheel_bundle(
    console,
    py_version: str = "3.10",
    timeout: int = 300,
) -> str:
    """Download fixed Nitro host-proxy deps and return a tarball path.

    The tarball contains ``host_proxy_wheels/`` and ``host_proxy_req.txt``.
    Caller must ``os.unlink()`` the returned path when done.
    """
    req_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="nitro_proxy_",
    )
    req_file.write("\n".join(NITRO_HOST_PROXY_DEPS) + "\n")
    req_file.close()
    wheel_dir = tempfile.mkdtemp(prefix="teecrafter_nitro_whl_")
    try:
        download_wheels(req_file.name, py_version, wheel_dir, console, "Nitro", timeout)
        bundle = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
        bundle.close()
        with tarfile.open(bundle.name, "w:gz") as tar:
            tar.add(wheel_dir, arcname="host_proxy_wheels")
            tar.add(req_file.name, arcname="host_proxy_req.txt")
        return bundle.name
    finally:
        shutil.rmtree(wheel_dir, ignore_errors=True)
        try:
            os.unlink(req_file.name)
        except OSError:
            pass


# ---------------------------------------------------------------------------
#  Remote command builders
# ---------------------------------------------------------------------------

def detect_python_version_cmd(venv_path: str) -> str:
    """Shell command that prints ``MAJOR.MINOR`` of the venv Python."""
    return f"{venv_path}/bin/python3 -V 2>&1 | cut -d' ' -f2 | cut -d. -f1,2"


def pip_upgrade_cmd(venv_path: str) -> str:
    """Shell command: upgrade pip inside a venv."""
    return f"{venv_path}/bin/pip install --upgrade pip 2>&1"


def offline_install_cmd(venv_path: str, wheels_dir: str, req_file: str) -> str:
    """Shell command: offline-only pip install from pre-downloaded wheels."""
    return (
        f"{venv_path}/bin/pip install --no-cache-dir --no-index "
        f"--find-links {wheels_dir} -r {req_file} 2>&1"
    )


def verify_imports_cmd(venv_path: str) -> str:
    """Shell command: verify TEE runtime deps can be imported from venv."""
    return f"{venv_path}/bin/python3 -c '{TEE_RUNTIME_IMPORT_CHECK}' 2>&1"


# ---------------------------------------------------------------------------
#  Framework wheel bundles (for first-boot setup — replaces network pip)
# ---------------------------------------------------------------------------

def make_framework_wheel_bundle(
    deps: tuple[str, ...],
    console,
    py_version: str = "3.10",
    timeout: int = 300,
) -> str:
    """Download TEE-framework wheels and return path to a tarball.

    The tarball contains ``framework_wheels/`` and ``framework_req.txt``.
    Caller must ``os.unlink()`` when done.
    """
    req_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="tee_fw_",
    )
    req_file.write("\n".join(deps) + "\n")
    req_file.close()
    wheel_dir = tempfile.mkdtemp(prefix="teecrafter_fw_whl_")
    try:
        download_wheels(req_file.name, py_version, wheel_dir, console,
                        "framework", timeout)
        bundle = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
        bundle.close()
        with tarfile.open(bundle.name, "w:gz") as tar:
            tar.add(wheel_dir, arcname="framework_wheels")
            tar.add(req_file.name, arcname="framework_req.txt")
        return bundle.name
    finally:
        shutil.rmtree(wheel_dir, ignore_errors=True)
        try:
            os.unlink(req_file.name)
        except OSError:
            pass


# ---------------------------------------------------------------------------
#  Security warnings
# ---------------------------------------------------------------------------

_UNBAKED_WARNING = (
    "[bold yellow]⚠  REDUCED SECURITY — deploying without a baked image[/bold yellow]\n\n"
    "[bold]Internal dev path only[/bold] (TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI=1).\n"
    "The VM will fetch packages from public mirrors (apt, pip, vendor repos)\n"
    "during first-boot setup. This exposes the VM to supply-chain and MITM\n"
    "risks before any attestation is performed.\n\n"
    "Terraform will open HTTP/HTTPS egress to the internet via a NAT gateway\n"
    "for this first boot only (TF_VAR_allow_setup_egress=true).\n\n"
    "[bold]For production:[/bold] always pass [cyan]--ami-id <baked-id>[/cyan] so\n"
    "egress stays locked down from the first boot. Bake the image with\n"
    "[cyan]tee-crafter internal bake-ami --tee-platform <platform>[/cyan]."
)

_POST_BAKE_LOCKDOWN_REMINDER = (
    "[bold yellow]NET-1: post-bake egress lockdown pending[/bold yellow]\n\n"
    "This deployment opened setup-phase internet egress "
    "([cyan]allow_setup_egress=true[/cyan]).\n"
    "After the VM has finished first-boot provisioning and passed attestation:\n\n"
    "  1. Run [cyan]tee-crafter internal bake-ami --tee-platform <platform>[/cyan]\n"
    "     to capture a golden AMI/image.\n"
    "  2. Re-run [cyan]tee-crafter deploy --ami-id <baked-id>[/cyan] (or set\n"
    "     [cyan]TEE_CRAFTER_AMI_ID[/cyan] in your .env). Terraform re-applies with\n"
    "     [cyan]allow_setup_egress=false[/cyan]; this tears down the NAT gateway / NSG\n"
    "     rule and leaves only narrowly-scoped, attestation-only egress."
)


def warn_unbaked_deploy(console) -> None:
    """Emit a prominent warning when deploying without a baked image."""
    from tee_crafter.cli.constants import Panel
    console.print(Panel.fit(_UNBAKED_WARNING, border_style="yellow"))


def remind_post_bake_lockdown(console) -> None:
    """NET-1 reminder after a first-boot deploy completes.

    The operator has just deployed a VM that opened public NAT-gateway
    egress for package installs.  We instruct them to bake the VM into a
    golden image and re-apply Terraform with ``allow_setup_egress=false``
    so the NAT path is removed from the blast surface.  Idempotent: safe
    to emit once per deploy; does nothing otherwise.
    """
    from tee_crafter.cli.constants import Panel
    console.print(Panel.fit(_POST_BAKE_LOCKDOWN_REMINDER, border_style="yellow"))
