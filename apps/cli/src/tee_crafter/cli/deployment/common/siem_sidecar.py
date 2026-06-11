"""Install + start the SIEM sidecar service on a deployed TEE.

This is the deploy-time counterpart to
``tee_crafter.templates.common.siem_export`` (the in-VM script) and
``tee_crafter.resources.systemd.tee-crafter-siem.service.template``
(the systemd unit template).

Flow:

1. The build phase has already staged ``siem.env`` into ``build_dir/``
   (and a mirror into ``build_dir/app/``).  It also staged
   ``siem_export.py`` into ``build_dir/app/`` via
   ``_copy_runtime_modules`` (see ``core/builder/platforms.py``).
2. The artifact upload step copies the entire ``app/`` directory to
   ``{remote_app_dir}`` on the VM (whatever the platform calls it —
   /opt/tee-crafter-snp/app, /opt/tee-crafter-tdx/app, …).
3. This module is invoked AFTER artifacts land and AFTER the main app
   service is running.  It:
   a. Skips entirely if SIEM is disabled.
   b. Renders the tee-crafter-siem.service template with the platform's
      remote paths.
   c. Drops the unit into /etc/systemd/system/ and starts it.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
from typing import Callable, Tuple

from tee_crafter.cli.constants import Panel
from tee_crafter.core.audit import Verdict as _Verdict
from tee_crafter.core.env_flags import interpret


SUPPORTED_PLATFORMS = (
    "snp-aws", "snp-azure", "snp-gcp",
    "tdx-azure", "tdx-gcp",
    "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
    "nitro-aws", "sgx-azure",
)

# Per-platform on-VM layout.
#
# Nitro: host runs `host_proxy.py` at /opt/tee-crafter/ (no app subdir).
#   Sidecar provider is "heartbeat" — emits boot-anchored measurement
#   events while the enclave is up.
# SGX:  gramine host runs `app_gramine` at /home/azureuser/sgx-app/
#   (no app subdir). Sidecar provider is "heartbeat".  Full per-tick
#   refresh from outside the enclave is a future enhancement, see
#   docs/siem.md.
_LAYOUT = {
    "snp-aws":      ("/opt/tee-crafter-snp",    "app"),
    "snp-azure":    ("/opt/tee-crafter-snp",    "app"),
    "snp-gcp":      ("/opt/tee-crafter-snp",    "app"),
    "tdx-azure":    ("/opt/tee-crafter-tdx",    "app"),
    "tdx-gcp":      ("/opt/tee-crafter-tdx",    "app"),
    "gpu-cc-aws":   ("/opt/tee-crafter-gpu-cc", "app"),
    "gpu-cc-azure": ("/opt/tee-crafter-gpu-cc", "app"),
    "gpu-cc-gcp":   ("/opt/tee-crafter-gpu-cc", "app"),
    "nitro-aws":    ("/opt/tee-crafter",     ""),
    "sgx-azure":    ("/opt/tee-crafter-sgx", ""),
}


#: Marker the install script prints after polling the unit and its health file.
_MARKER = "SIEM-SEC: tee-crafter-siem state="


def parse_sidecar_marker(text: str) -> tuple[str, str, str]:
    """Return ``(state, restarts, export_status)`` from the install output.

    Extracted so the decision can be tested without a live host: the two
    regressions here were both about *which token* the verdict reads.
    ``state`` alone said "active" for a crash-looping unit, and later for a
    unit whose every export timed out.  Later markers win, so a trailing
    journal line that happens to contain the prefix cannot shadow the real one.
    """
    state = restarts = export_status = ""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith(_MARKER):
            continue
        rest = line[len(_MARKER):].split()
        state = rest[0] if rest else ""
        for tok in rest[1:]:
            if tok.startswith("restarts="):
                restarts = tok.split("=", 1)[1]
            elif tok.startswith("export="):
                export_status = tok.split("=", 1)[1]
    return state, restarts, export_status


#: ``signing_key_sha256`` in the health file the install script ``cat``s.
_SIGNING_KEY_RE = re.compile(r'"signing_key_sha256"\s*:\s*"([0-9a-fA-F]{64})"')


def parse_signing_key_fingerprint(text: str) -> str:
    """SHA-256 of the SIEM exporter's Ed25519 public key, or ``""``.

    The exporter generates its signing key per process and keeps it in memory
    (``siem_export.AttestationLoop.__init__``), so before this was published the
    only copy travelled inside the events it signed.  That makes the key
    useless as a trust anchor: anyone who can inject into the SIEM can present
    a self-consistent chain signed by a key they generated, which is why
    ``verify-siem-chain`` refuses to verify signatures against the embedded key
    and why its authorship check had nothing correct to offer an operator.

    The install script already ``cat``s the whole SIEM-SEC-4 health file, so the
    fingerprint arrives in the captured output with no extra round trip; the
    deploy records it into the provenance ledger and the verifier discovers it
    from there.

    Scope of the guarantee, deliberately narrow: this pins the key **the deploy
    observed at install time, over the deploy's own channel**.  It is not
    hardware-attested — on ``nitro-aws`` and ``sgx-azure`` the exporter runs on
    the VM host, outside the TEE, so it cannot be.  What it does buy is that a
    stream signed by any *other* key is detectable, which is the injection case
    the anchor exists for.  Only 64-hex is accepted; anything else is treated as
    absent rather than recorded as a malformed anchor.
    """
    m = _SIGNING_KEY_RE.search(text or "")
    return m.group(1).lower() if m else ""


#: Platforms where the in-TEE SIEM fail-closed gate is genuinely armed.
#:
#: The exporter runs *inside* the VM and the app process loads
#: ``siem/siem.env.public`` through its systemd unit's ``EnvironmentFile=``, so
#: ``TEE_CRAFTER_SIEM_ENABLED=1`` is set in the same namespace that reads
#: ``/run/tee-crafter-<platform>/siem.health``.  On these,
#: ``last_export_status != "pass"`` means the workload refuses every request.
#:
#: ``nitro-aws`` gets there by a different route than the eight CVMs and the
#: difference matters when reading a failure.  There is no systemd unit inside a
#: Nitro enclave: the EIF carries ``siem_export.py`` and a measured
#: ``siem.env.public``, the enclave's entrypoint sources that file before
#: ``app_vsock.py`` execs, and the exporter runs as a thread in the enclave
#: writing its health file to the enclave's own tmpfs.
PREVENTIVE_GATE_PLATFORMS: frozenset = frozenset({
    "snp-aws", "snp-azure", "snp-gcp",
    "tdx-azure", "tdx-gcp",
    "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
    "nitro-aws",
})

#: Platforms where the gate is inert, so SIEM export is a **detective** control
#: (the SOC sees the stream stop) rather than a **preventive** one (the workload
#: stops serving).
#:
#: Both run the exporter as a host-side sidecar and neither passes the SIEM
#: environment across the TEE boundary — the nitro ``Dockerfile`` does not
#: ``COPY`` ``siem.env.public`` into the EIF and no SIEM keys reach the measured
#: ``app.env``; the Gramine manifest sets ``insecure__use_host_env = false`` and
#: lists no SIEM variables in ``[loader.env]``.  So
#: ``siem_health.is_fail_closed()`` returns False in-TEE and
#: ``fail_closed_wrap`` passes everything through.  The enclave could not read
#: the host's ``siem.health`` regardless.
#:
#: This split is encoded here rather than left in prose because per-platform
#: capability claims in this project's docs have been wrong six times.  Nothing
#: executes a sentence; something does execute this set.
#: ``nitro-aws`` left this set in 2026-08 when the exporter moved *inside* the
#: enclave (``templates/nitro/app_vsock.py::start_in_enclave_siem_export``).
#: The EIF now carries ``siem_export.py`` and the measured ``siem.env.public``,
#: the exporter writes its health file into the enclave's own tmpfs — the same
#: namespace ``siem_health`` reads — and it delivers over TLS it terminates
#: itself through a dedicated vsock tunnel.  So a blackout is now something the
#: enclave can detect and refuse on, which is what "preventive" means here.
#:
#: ``sgx-azure`` stays, and cannot leave by the same route: it is batch-only, so
#: there is no request path for a request gate to guard.  Its preventive control
#: is ``batch._withhold_output_if_unaudited`` instead, which is not what this
#: set is about.
DETECTIVE_ONLY_GATE_PLATFORMS: frozenset = frozenset({"sgx-azure"})


def gate_is_preventive(tee_platform: str, *, batch: bool = False) -> bool:
    """Whether a failed SIEM export will actually stop *tee_platform* serving.

    Unknown platforms are treated as preventive: assuming a control is armed and
    being wrong is a false alarm, while assuming it is inert and being wrong
    ships an unaudited PHI workload.

    ``batch`` exists because the in-TEE gate is ``fail_closed_wrap`` around
    ``process_request`` — a *request* path.  A batch run has no requests: the
    container runs to completion and exits.  So in batch mode the request gate
    cannot fire on **any** platform, including the eight otherwise-preventive
    ones, and telling the operator "the workload will refuse every request"
    would be nonsense.  What is preventive for a batch run is
    :func:`batch_export_delivered` — the output is withheld instead.
    """
    if batch:
        return False
    return (tee_platform or "") not in DETECTIVE_ONLY_GATE_PLATFORMS


#: Health-file keys the batch output gate reads.  Written by
#: ``templates/common/siem_export.py::_write_health_state``.
_HEALTH_FILE = "siem.health"

#: vsock port the Nitro enclave uses to reach the SIEM collector.  8000 is
#: already taken by the KMS tunnel that ``scripts/nitro_aws/setup_nitro.sh``
#: sets up at bake time.  Mirrored by ``_VSOCK_PORT_SIEM`` in
#: ``templates/nitro/app_vsock.template.py``; the two must agree.
NITRO_SIEM_VSOCK_PORT = 8001

#: The second ``vsock-proxy`` instance, added at deploy time.
NITRO_SIEM_PROXY_UNIT = "nitro-enclaves-vsock-proxy-siem.service"


def collector_endpoint(siem_env: dict) -> Tuple[str, int]:
    """``(host, port)`` the exporter will actually connect to, or ``("", 0)``.

    Derived from the staged SIEM env rather than from ``SiemConfig`` so that it
    reflects what was really written for this deploy.  The enclave needs this
    because its egress is a fixed allowlist: the host-side ``vsock-proxy`` is
    hard-wired to one destination per vsock port, so the destination has to be
    known at deploy time and cannot be chosen by the enclave afterwards.  That
    is the property that makes widening the allowlist acceptable — the enclave
    gains exactly one new reachable host, chosen by the operator.
    """
    # The provider key is ``TEE_CRAFTER_SIEM``, not ``..._PROVIDER`` — the same
    # name ``siem_export.py:524`` reads.
    provider = (siem_env.get("TEE_CRAFTER_SIEM") or "").strip().lower()
    if provider == "syslog-cef":
        host = (siem_env.get("TEE_CRAFTER_SIEM_HOST") or "").strip()
        try:
            port = int((siem_env.get("TEE_CRAFTER_SIEM_PORT") or "514").strip())
        except ValueError:
            return "", 0
        return (host, port) if host else ("", 0)
    if provider == "splunk-hec":
        from urllib.parse import urlparse
        parsed = urlparse((siem_env.get("TEE_CRAFTER_SIEM_ENDPOINT") or "").strip())
        if not parsed.hostname:
            return "", 0
        return parsed.hostname, parsed.port or (
            443 if parsed.scheme == "https" else 80)
    if provider == "datadog":
        site = (siem_env.get("TEE_CRAFTER_SIEM_SITE") or "datadoghq.com").strip()
        return f"http-intake.logs.{site}", 443
    return "", 0


def batch_export_delivered(
    run_remote, tee_platform: str, *, max_lag_seconds: int = 300,
) -> tuple[bool, str]:
    """Did this batch run's attestation events actually reach the SOC?

    Reads the sidecar's ``/run/tee-crafter-<platform>/siem.health`` on the host
    and applies the same test the in-TEE gate applies to it: the file exists,
    ``last_export_status`` is ``pass``, and its timestamp is recent enough to be
    describing *this* run rather than a stale success from earlier.

    Returns ``(delivered, reason)``; *reason* is empty when delivered.

    **Who is trusting whom.**  This check runs in the deployer, not in the TEE,
    so it is deliberately *not* the same guarantee as the in-TEE request gate on
    the eight CVM platforms.  It does not defend against a malicious host — a
    compromised host can write whatever it likes into that file.  What it does
    defend against is the case the SOC actually cares about and that nothing
    previously caught: a batch job that ran, produced PHI-derived output, and
    shipped no audit trail, with the deploy reporting success anyway.  The
    operator is the party being held to the policy here, and the operator is
    also the party running this code.
    """
    ok, out, _ = run_remote(
        f"sudo cat {runtime_dir_for(tee_platform)}/{_HEALTH_FILE} 2>/dev/null "
        "|| echo MISSING",
        timeout=60,
    )
    raw = (out or "").strip()
    if not ok or not raw or "MISSING" in raw:
        return False, (
            f"no {_HEALTH_FILE} on the host — the SIEM sidecar never ticked, so "
            f"nothing was exported for this run")
    try:
        state = json.loads(raw.splitlines()[-1])
    except (ValueError, IndexError):
        return False, f"{_HEALTH_FILE} is not readable JSON: {raw[:120]!r}"

    status = str(state.get("last_export_status", "")).strip()
    if status != "pass":
        err = str(state.get("last_export_error", ""))[:80]
        return False, (
            f"last_export_status={status or 'unknown'}"
            + (f" ({err})" if err else "")
            + " — the collector did not accept this run's events")

    try:
        age = int(time.time()) - int(state.get("ts", 0))
    except (TypeError, ValueError):
        return False, f"{_HEALTH_FILE} has no usable timestamp"
    if age > max_lag_seconds:
        return False, (
            f"last export was {age}s ago (> {max_lag_seconds}s) — that success "
            f"predates this batch run")
    return True, ""


def siem_fail_open(build_dir: str) -> bool:
    """Read the deploy's fail-open posture from the staged SIEM env.

    Mirrors ``siem_health.is_fail_closed`` deliberately: fail-open only on an
    explicit recognised truthy value, so a typo (``=2``) leaves the strict
    posture in force rather than silently disabling it.
    """
    from tee_crafter.core.audit import build_layout as _layout
    for candidate in (
        _layout.siem_env(build_dir),
        os.path.join(build_dir, "siem.env"),
        os.path.join(build_dir, "app", "siem.env"),
    ):
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("TEE_CRAFTER_SIEM_FAIL_OPEN="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        return interpret(val) is True
        except OSError:
            continue
    return False


def is_siem_enabled(build_dir: str) -> bool:
    """Return True iff ``siem.env`` in the build dir says SIEM is on."""
    from tee_crafter.core.audit import build_layout as _layout
    for candidate in (
        _layout.siem_env(build_dir),       # new layout
        os.path.join(build_dir, "siem.env"),  # legacy top-level
        os.path.join(build_dir, "app", "siem.env"),  # in-TEE staging
    ):
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("TEE_CRAFTER_SIEM_ENABLED="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        return interpret(val) is True
        except OSError:
            continue
    return False


def _resources_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    # cli/deployment/common/  ->  resources/
    return os.path.abspath(os.path.join(here, "..", "..", "..", "resources"))


def _load_template() -> str:
    path = os.path.join(_resources_dir(), "systemd",
                        "tee-crafter-siem.service.template")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def sidecar_app_dir(tee_platform: str) -> str:
    """Directory the sidecar unit's ``ExecStart`` runs ``siem_export.py`` from.

    Public because the caller that has to *put the file there* lives in a
    different module (``deploy/batch.py``) from the one that writes the unit.
    Deriving it twice is how the two drift, and the failure mode is silent
    until a deploy: the unit starts, python cannot find the script, systemd
    restarts it forever, and the run reports "no siem.health".
    """
    if tee_platform not in _LAYOUT:
        raise ValueError(
            f"unsupported tee_platform for SIEM sidecar: {tee_platform!r} "
            f"(supported: {sorted(_LAYOUT)})")
    remote_base, app_subdir = _LAYOUT[tee_platform]
    return (f"{remote_base}/{app_subdir}".rstrip("/")
            if app_subdir else remote_base)


def render_sidecar_unit(tee_platform: str) -> str:
    """Render the per-platform tee-crafter-siem.service systemd unit."""
    remote_app_dir = sidecar_app_dir(tee_platform)
    remote_base, app_subdir = _LAYOUT[tee_platform]
    # Nitro / SGX hosts may not carry a project venv next to the
    # remote base — fall back to system Python in that case.
    remote_venv = f"{remote_base}/venv" if app_subdir else "/usr"
    return (
        _load_template()
        .replace("{remote_app_dir}", remote_app_dir)
        .replace("{remote_venv}", remote_venv)
        .replace("{tee_platform}", tee_platform)
    )


# SIEM-SEC-2 (tmpfs token):
#
# The deploy artifact tarball lands ``siem.env`` (which contains the
# HEC token / API key / bearer credential) on the persistent disk at
# ``{remote_app_dir}/siem.env``.  If anyone snapshots that disk —
# AWS EBS snapshot, Azure managed-disk export, GCP PD restore — they
# read the bearer token in plaintext.  Confidential VMs encrypt
# *memory*, not the boot disk.
#
# The install script therefore relocates the token-bearing env file:
#
#   1. Creates ``/run/tee-crafter-{platform}/`` (tmpfs, 0700,
#      tee_enclave:tee_enclave).  ``/run`` is tmpfs by default on
#      all modern systemd distros, so its contents never touch
#      persistent storage.
#   2. Atomically moves ``{remote_app_dir}/siem.env`` to that tmpfs
#      directory with mode 0600.
#   3. ``shred -u`` overwrites the disk copy with zeros before
#      unlinking it.  On disk-encrypted filesystems shred is
#      cosmetic; on plain ext4 it makes block-level forensics
#      meaningfully harder.
#   4. The unit template references the tmpfs path via
#      ``EnvironmentFile=-/run/tee-crafter-{platform}/siem.env`` (the
#      leading ``-`` means "soft" — boot still succeeds after a
#      reboot when the tmpfs is empty, just with SIEM disabled until
#      the operator re-stages a fresh token via
#      ``tee-crafter siem-stage``).
#
# Users who explicitly accept the snapshot risk (e.g. development
# environments where redeploying is expensive) can override the
# behaviour with ``TEE_CRAFTER_SIEM_PERSIST=1`` in their deploy env;
# the install script honours that and skips the shred step.
_INSTALL_SCRIPT = (
    # Use ``set -u`` only — NOT ``-e``: an in-progress activation
    # leaves ``systemctl is-active`` returning 3, and we want to
    # finish the script (poll for ready, dump journal) instead of
    # aborting and losing diagnostics.  Each step explicitly handles
    # its own failure.
    "set -u;\n"
    "echo \"{unit_b64}\" | base64 -d | sudo tee /etc/systemd/system/tee-crafter-siem.service >/dev/null || "
    "{{ echo 'SIEM-SEC: failed to write unit file'; exit 10; }};\n"
    "sudo systemctl daemon-reload || "
    "{{ echo 'SIEM-SEC: daemon-reload failed'; exit 11; }};\n"
    # SIEM-SEC-2: relocate the token-bearing file to tmpfs.
    "sudo install -d -m 0700 -o tee_enclave -g tee_enclave {runtime_dir} || "
    "{{ echo 'SIEM-SEC-2: tmpfs mkdir failed'; exit 12; }};\n"
    "if [ -f {remote_app_dir}/siem.env ]; then\n"
    "  sudo install -m 0600 -o tee_enclave -g tee_enclave "
    "{remote_app_dir}/siem.env {runtime_dir}/siem.env || "
    "{{ echo 'SIEM-SEC-2: tmpfs install failed'; exit 13; }};\n"
    "  if [ \"${{TEE_CRAFTER_SIEM_PERSIST:-0}}\" = \"1\" ]; then\n"
    "    sudo chmod 0600 {remote_app_dir}/siem.env || true;\n"
    "    sudo chown tee_enclave:tee_enclave {remote_app_dir}/siem.env || true;\n"
    "    echo 'SIEM-SEC-2: TEE_CRAFTER_SIEM_PERSIST=1; leaving siem.env on disk (user-accepted snapshot risk).';\n"
    "  else\n"
    "    sudo shred -u {remote_app_dir}/siem.env 2>/dev/null || sudo rm -f {remote_app_dir}/siem.env;\n"
    "  fi;\n"
    "fi;\n"
    "sudo systemctl reset-failed tee-crafter-siem.service 2>/dev/null || true;\n"
    "sudo systemctl enable --now tee-crafter-siem.service 2>&1 || "
    "{{ echo 'SIEM-SEC: enable --now reported failure (will still poll)'; }};\n"
    # Poll up to ~25s for the unit to settle.  We accept ``active`` as
    # success; we treat ``activating`` after the timeout as a soft
    # warning so the deploy continues (events fail-open) while still
    # surfacing the last journal lines for diagnosis.
    "for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do\n"
    "  STATE=$(systemctl is-active tee-crafter-siem.service 2>/dev/null || true);\n"
    "  case \"$STATE\" in\n"
    "    active|inactive) break;;\n"
    "  esac;\n"
    "  sleep 2;\n"
    "done;\n"
    # A single `is-active` sample cannot tell "running" from "restarting
    # every RestartSec".  The unit is Restart=always, so a sidecar that
    # exits immediately is *momentarily* active on every restart cycle and
    # the loop above breaks on the first sample -- which is how a
    # crash-looping exporter came to report "events streaming" while
    # emitting nothing (an unimplemented provider raised on every start).
    # Re-sample after longer than RestartSec and compare NRestarts: a
    # stable unit holds its restart count, a crash-looping one does not.
    "R1=$(systemctl show -p NRestarts --value tee-crafter-siem.service 2>/dev/null || echo 0);\n"
    "sleep 7;\n"
    "STATE=$(systemctl is-active tee-crafter-siem.service 2>/dev/null || true);\n"
    "R2=$(systemctl show -p NRestarts --value tee-crafter-siem.service 2>/dev/null || echo 0);\n"
    "if [ \"$STATE\" = active ] && [ \"$R2\" != \"$R1\" ]; then STATE=crashlooping; fi;\n"
    # A live process is not a delivered event.  syslog-cef connects lazily, so a
    # sidecar whose collector is unreachable stays `active` forever while every
    # export times out -- which is exactly how "SIEM sidecar active - events
    # streaming" came to be printed against a collector that received zero
    # bytes.  The sidecar already publishes the answer: SIEM-SEC-4's health file
    # carries `last_export_status`, and the in-TEE fail-closed gate reads the
    # same field.  Poll it for one export cycle and report what it says.
    "HEALTH={runtime_dir}/siem.health;\n"
    "EXPORT=unknown;\n"
    "for _ in $(seq 1 12); do\n"
    "  if [ -s \"$HEALTH\" ]; then\n"
    "    EXPORT=$(sed -n 's/.*\"last_export_status\"[[:space:]]*:[[:space:]]*\"\\([a-z]*\\)\".*/\\1/p' \"$HEALTH\" | head -1);\n"
    "    [ -n \"$EXPORT\" ] && [ \"$EXPORT\" != unknown ] && break;\n"
    "  fi;\n"
    "  sleep 5;\n"
    "done;\n"
    "echo \"SIEM-SEC: tee-crafter-siem state=$STATE restarts=$R1->$R2 export=${{EXPORT:-unknown}}\";\n"
    "cat \"$HEALTH\" 2>/dev/null || echo \"SIEM-SEC: no health file at $HEALTH yet\";\n"
    "journalctl -u tee-crafter-siem.service --no-pager -n 40 2>&1 || true;\n"
    # Always exit 0 — the caller inspects the captured ``state=`` line
    # for active/inactive and treats SIEM failure as a soft warning
    # (events are designed to fail-open).  This stops a slow sidecar
    # boot from killing an otherwise-successful deploy.
    "exit 0;\n"
)


def runtime_dir_for(tee_platform: str) -> str:
    """Per-platform tmpfs path holding the token-bearing siem.env.

    Public so that other modules (``--siem-stage`` CLI, tests) can
    locate the same path the install script writes to.
    """
    return f"/run/tee-crafter-{tee_platform}"


def _install_script(unit_text: str, tee_platform: str) -> str:
    unit_b64 = base64.b64encode(unit_text.encode("utf-8")).decode("ascii")
    remote_base, app_subdir = _LAYOUT[tee_platform]
    remote_app_dir = (f"{remote_base}/{app_subdir}".rstrip("/")
                      if app_subdir else remote_base)
    return _INSTALL_SCRIPT.format(
        unit_b64=unit_b64,
        remote_app_dir=remote_app_dir,
        runtime_dir=runtime_dir_for(tee_platform),
    )


def read_siem_env(build_dir: str) -> dict:
    """Parse the staged SIEM env into a dict (``{}`` when SIEM is off)."""
    from tee_crafter.core.audit import build_layout as _layout
    out: dict = {}
    for candidate in (
        _layout.siem_env(build_dir),
        os.path.join(build_dir, "siem.env"),
        os.path.join(build_dir, "app", "siem.env"),
    ):
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    out.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except OSError:
            continue
        if out:
            break
    return out


#: Adds the collector to the enclave's egress allowlist and starts a second
#: ``vsock-proxy`` for it.  Written as one idempotent script because it runs
#: over ``run_remote`` and has to be safe to re-run on redeploy.
_ENCLAVE_EGRESS_SCRIPT = r"""
set -e
CFG=/etc/nitro_enclaves/vsock-proxy.yaml
HOST='{collector_host}'
PORT='{collector_port}'
VSOCK_PORT='{vsock_port}'

if [ ! -f "$CFG" ]; then
  echo "SIEM-EGRESS: $CFG missing (not a tee-crafter nitro AMI?)" >&2
  exit 1
fi

# Idempotent: only append if this exact destination is not already allowlisted.
if ! grep -q "address: $HOST, port: $PORT" "$CFG"; then
  printf '  - {{address: %s, port: %s}}\n' "$HOST" "$PORT" | sudo tee -a "$CFG" >/dev/null
fi

sudo tee /etc/systemd/system/{unit} >/dev/null <<UNIT
[Unit]
Description=vsock-proxy: enclave -> SIEM collector ($HOST:$PORT)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/vsock-proxy $VSOCK_PORT $HOST $PORT --config $CFG -w 4
Restart=always
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now {unit} >/dev/null 2>&1 || sudo systemctl restart {unit}
sleep 1
echo "SIEM-EGRESS: state=$(systemctl is-active {unit} 2>/dev/null) dest=$HOST:$PORT vsock=$VSOCK_PORT"
"""


def install_enclave_egress(
    *, console, build_dir: str, tee_platform: str,
    run_remote: Callable[[str], Tuple[bool, str, str]],
) -> Tuple[bool, str]:
    """Give the Nitro enclave a TLS path to the SIEM collector.

    Returns ``(ok, detail)``.  ``(True, "")`` when there is nothing to do.

    Why this is deploy-time rather than bake-time: ``setup_nitro.sh`` writes the
    allowlist while building the AMI, and at that point the collector is not
    known — it comes from ``--siem-config`` on the deploy command.  So the AMI
    ships with the single KMS entry it has always had, and this adds the second
    one against the running instance.

    Widening that allowlist is the one genuinely security-relevant part of the
    in-enclave export design, so state plainly what it does and does not cost.
    The enclave gains exactly one reachable host, fixed by the operator at
    deploy time and hard-wired into a ``vsock-proxy`` instance the enclave
    cannot reconfigure.  It does *not* gain general egress: ``vsock-proxy`` in
    simple mode forwards one vsock port to one destination, and the allowlist is
    checked against that destination.  What the enclave gets in return is the
    ability to terminate its own TLS to the collector, which is what makes
    ``last_export_status`` mean something inside the TEE — the parent instance
    can still drop the traffic, but it cannot read it and it cannot forge a
    delivery confirmation.
    """
    if tee_platform != "nitro-aws" or not is_siem_enabled(build_dir):
        return True, ""

    host, port = collector_endpoint(read_siem_env(build_dir))
    if not host:
        console.print(
            "[yellow]SIEM: could not derive a collector host from the staged "
            "config; the enclave gets no egress and the in-TEE gate will "
            "report a blackout.[/yellow]")
        return False, "collector endpoint not derivable"

    script = _ENCLAVE_EGRESS_SCRIPT.format(
        collector_host=host, collector_port=port,
        vsock_port=NITRO_SIEM_VSOCK_PORT, unit=NITRO_SIEM_PROXY_UNIT,
    )
    ok, out, err = run_remote(script)
    text = ((out or "") + ("\n" + err if err else "")).strip()
    if ok and "state=active" in text:
        console.print(
            f"[green]✓ Enclave egress armed: {host}:{port} via vsock "
            f"{NITRO_SIEM_VSOCK_PORT}.[/green]")
        return True, text
    console.print(
        f"[yellow]SIEM: enclave egress to {host}:{port} did not come up; the "
        f"in-enclave exporter will not reach the collector.[/yellow]\n"
        f"[dim]{text[-500:]}[/dim]")
    return False, text


def install_siem_sidecar(
    *,
    console,
    build_dir: str,
    tee_platform: str,
    run_remote: Callable[[str], Tuple[bool, str, str]],
    audit=None,
    batch: bool = False,
) -> bool:
    """Install + start the SIEM sidecar service on the remote VM.

    Args:
        console: CLI console for user-visible output.
        build_dir: path to the local build directory (used to gate on
            ``siem.env`` presence).
        tee_platform: one of ``SUPPORTED_PLATFORMS``.
        run_remote: callable ``(cmd) -> (ok, stdout, stderr)``.
            Adapts to SSM, IAP-tunneled SSH, Bastion SSH, etc.
        audit: optional ``BuildAuditTrail`` for provenance.
        batch: whether this is a ``--batch`` run.  Only affects what an
            unconfirmed export is *called* — in batch mode the consequence is
            withheld output rather than refused requests.

    Returns ``True`` if the sidecar is active (or SIEM was disabled —
    nothing to do).  Returns ``False`` on a real install failure.
    """
    if not is_siem_enabled(build_dir):
        # No SIEM configured -> nothing to wire.
        return True
    try:
        unit = render_sidecar_unit(tee_platform)
    except ValueError as e:
        console.print(f"[yellow]SIEM sidecar: {e}[/yellow]")
        if audit:
            audit.record_check(
                "Phase 5: Post-Deploy", "SIEM sidecar install", "SIEM-003",
                verdict=_Verdict.FAIL,
                observed=False,
                note=f"unit rendering failed: {e}",
                tee_platform=tee_platform,
            )
        return True
    script = _install_script(unit, tee_platform)
    console.print(f"[dim]SIEM: installing tee-crafter-siem.service "
                  f"({tee_platform})[/dim]")
    ok, out, err = run_remote(script)
    text = (out or "") + ("\n" + err if err else "")
    # New install script emits a stable ``SIEM-SEC: tee-crafter-siem
    # state=<state>`` marker after polling.  Parse that instead of the
    # last raw line so a trailing journalctl entry doesn't confuse us.
    state, restarts, export_status = parse_sidecar_marker(text)
    is_active = state == "active"
    # "active" only means the process is alive.  syslog-cef connects lazily, so
    # an unreachable collector leaves the sidecar happily running while every
    # export times out — observed on a real deploy where the collector received
    # zero bytes and the deploy still said "events streaming".  Require the
    # sidecar's own SIEM-SEC-4 health file to report a successful export before
    # making that claim.
    if ok and is_active and export_status == "pass":
        console.print("[green]✓ SIEM sidecar active — events streaming "
                      "(export confirmed).[/green]")
        signing_key = parse_signing_key_fingerprint(text)
        if signing_key:
            console.print(
                f"[dim]  SIEM chain signing key: {signing_key[:16]}… "
                "(recorded in the provenance ledger; pass it to "
                "verify-siem-chain --pinned-pubkey-sha256)[/dim]")
        if audit:
            audit.record_check(
                "Phase 5: Post-Deploy", "SIEM sidecar install", "SIEM-003",
                observed=True, tee_platform=tee_platform,
                last_export_status=export_status,
                # The out-of-band anchor for the exported event chain.  Empty
                # when the sidecar predates the health-file field, which
                # verify-siem-chain reports rather than silently ignoring.
                siem_signing_key_sha256=signing_key,
            )
        return True
    if ok and is_active:
        # Running but not (yet) exporting.  Do not call this streaming.
        console.print(
            f"[bold yellow]⚠ SIEM sidecar is running but has not confirmed an "
            f"export (last_export_status={export_status or 'unknown'}).[/bold yellow]\n"
            "[yellow]Events are NOT being delivered. Common cause: the "
            "workload's egress security group does not allow the collector's "
            "port, so the exporter times out while the process stays alive. "
            "The journal below shows the exporter's own verdict.[/yellow]")
        _flag_unverified_export(
            console, audit, build_dir, tee_platform, export_status, batch=batch)
    if state == "crashlooping":
        console.print(
            f"[bold yellow]⚠ SIEM sidecar is CRASH-LOOPING (restarts "
            f"{restarts}) — no events are being exported.[/bold yellow]\n"
            "[yellow]The unit reports 'active' between restarts, so this is "
            "not a slow boot. Check the journal below: an unsupported "
            "--siem provider raises on every start.[/yellow]")
    console.print(Panel(
        text[-2000:] or "(no output)",
        title="[bold yellow]SIEM sidecar install output[/bold yellow]",
        border_style="yellow",
    ))
    if audit:
        audit.record_check(
            "Phase 5: Post-Deploy", "SIEM sidecar install", "SIEM-003",
            verdict=_Verdict.WARN,
            observed=False,
            tee_platform=tee_platform,
            last_state=(state or "unknown")[:40],
            restarts=restarts[:20],
            last_export_status=(export_status or "unknown")[:20],
        )
    # The return value stays ``True`` because all six call sites discard it, and
    # threading a new failure path through six differently-shaped phase
    # functions — four of them on platforms that have never run on hardware —
    # is a worse bet than the single seam used instead.
    #
    # ``_flag_unverified_export`` marks the audit trail, and the deploy command
    # checks that mark once, at the end, via ``siem_export_blocked_deploy``.
    # Doing it there rather than raising here is deliberate: attestation
    # (step 8g) runs *after* the sidecar install, so aborting at this point
    # would throw away the attestation evidence and the signed provenance for a
    # problem that is about the workload's runtime posture, not its identity.
    # The deploy therefore completes, records everything, and *then* exits
    # non-zero.
    #
    # NOTE the previous justification here — "events fail-open by design" — was
    # simply wrong: ``SiemConfig.fail_open`` defaults to False.
    return True


#: Attribute set on the audit trail when the deploy must not be called a
#: success.  Carried on the audit object because that is the one thing every
#: call site already threads through.
_UNVERIFIED_EXPORT_ATTR = "siem_export_unverified"


def _flag_unverified_export(console, audit, build_dir, tee_platform,
                            export_status, *, batch: bool = False) -> None:
    """Escalate an unconfirmed export according to what it will actually cause.

    Three genuinely different situations, and conflating them is how the old
    blanket warning managed to be both alarmist and wrong:

    * **Preventive-gate platform, persistent, fail-closed** — the workload is
      deployed and will refuse every request.  That is a dead-on-arrival
      deployment, so the command must not exit 0.
    * **Batch, fail-closed** — there are no requests to refuse; what happens
      instead is that ``batch._withhold_output_if_unaudited`` deletes the bundle
      rather than handing over the results of an unaudited run.  Say *that*,
      because promising a request gate on a run that serves no requests is how
      an operator learns to ignore this warning.
    * **Detective-only platform, or fail-open** — the workload serves fine; what
      is lost is SOC visibility.  Loud warning, successful deploy.
    """
    fail_open = siem_fail_open(build_dir)
    if batch and not fail_open:
        console.print(
            "[bold red]This batch run will not hand over its output.[/bold red]\n"
            "[red]A batch container serves no requests, so the in-TEE gate is "
            "not what applies here — the collector does. Unless these events "
            "start landing before the run finishes, the output bundle is "
            "deleted instead of downloaded. Fix the collector path, or set "
            "[cyan]\"fail_open\": true[/cyan] in the --siem-config to accept an "
            "unaudited run.[/red]")
        if audit is not None:
            setattr(audit, _UNVERIFIED_EXPORT_ATTR, tee_platform)
        return
    preventive = gate_is_preventive(tee_platform, batch=batch)
    if preventive and not fail_open:
        console.print(
            "[bold red]This deployment will not serve traffic.[/bold red]\n"
            f"[red]{tee_platform} arms the in-TEE fail-closed gate, and it "
            f"refuses every request while last_export_status is not 'pass' — so "
            f"the workload is running but will answer "
            f"{{\"error\":\"siem_blackout\"}} to callers. Fix the collector "
            f"path and redeploy, or set [cyan]\"fail_open\": true[/cyan] in the "
            f"--siem-config to accept an unaudited workload.[/red]")
        if audit is not None:
            setattr(audit, _UNVERIFIED_EXPORT_ATTR, tee_platform)
        return
    reason = ("this platform runs the exporter host-side, so the in-TEE gate is "
              "inert and the workload keeps serving"
              if not preventive else
              "fail_open is set, so the gate is disabled")
    console.print(
        f"[yellow]Continuing: {reason}. SIEM export is a detective control on "
        f"this deploy — the SOC will see the stream stop, but nothing stops the "
        f"workload. Treat the warning above as a monitoring outage.[/yellow]")


def siem_export_blocked_deploy(audit) -> str:
    """The platform whose SIEM gate will refuse traffic, or ``""``.

    Checked once at the end of the deploy command rather than at each call site,
    so a new platform phase cannot forget it.
    """
    return getattr(audit, _UNVERIFIED_EXPORT_ATTR, "") or ""
