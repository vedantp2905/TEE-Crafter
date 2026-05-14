"""Self-contained SIEM exporter sidecar for TEE-Crafter workloads.

Reads ``siem.env`` and ships signed, hash-chained continuous-attestation
events to the configured SIEM (Splunk HEC today; the same dispatch
shape extends to Datadog / CloudWatch / Azure Monitor / syslog-CEF).

Why this exists
---------------
The full SIEM pipeline lives in ``tee_crafter.core.audit`` and is
designed to be imported by an in-enclave runtime bootstrap.  That works
for **Nitro** (where ``tee_crafter`` is bundled into the EIF) and
**SGX** (where the gramine manifest carries the audit module).  On
CVM platforms (SNP-AWS / SNP-Azure / SNP-GCP / TDX-Azure / TDX-GCP /
GPU-CC) the host venv is intentionally minimal, so we ship this
self-contained sidecar instead.

Design constraints
------------------
* stdlib + ``cryptography`` only — both already present on every CVM
  venv built by the bake scripts.
* No imports from ``tee_crafter.*`` — the build-side package is not
  installed on the VM.
* Platform-aware: auto-detects the right ``app_*.py`` to call into for
  real hardware attestation reports (SNP report, TDX quote, NVIDIA
  evidence, etc.), based on ``TEE_CRAFTER_TEE_PLATFORM`` (preferred)
  or by probing ``sys.path`` for ``app_snp.py`` / ``app_tdx.py`` /
  ``app_snp_gcp.py`` / ``app_tdx_gcp.py``.
* Fail-open: if the SIEM endpoint is unreachable the loop keeps
  running and reports the next tick, matching the
  ``ContinuousAttestor`` behaviour.

Event schema mirrors ``tee_crafter.core.audit.continuous.AttestationEvent``
byte-for-byte so SIEM dashboards built against the production exporter
also work against the sidecar output.

Canonicalisation is defined **here and only here**
(:data:`EVENT_SCHEMA_VERSION`, :data:`GENESIS_PREV_DIGEST`,
:func:`canonical_digest_payload`, :func:`compute_digest`).  This module
is the one copy that has to survive on a stripped CVM with no
``tee_crafter`` package installed, so the build-host producer
(:mod:`tee_crafter.core.audit.continuous`) and the verifier
(:mod:`tee_crafter.cli.commands.verify_siem_chain`) import these helpers
from here rather than re-deriving them.  Before schema 2 the producer
hashed a payload that still contained ``"digest": ""`` while both
verifiers excluded ``digest`` — different JSON, different SHA-256, so no
event a deployed TEE emitted could ever verify.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import importlib
import json
import logging
import os
import select
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger("tee_crafter.siem_export")


# ---------------------------------------------------------------------------
# env-file loader + helpers
# ---------------------------------------------------------------------------

def _load_env_file(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _iso_to_epoch(iso_ts: str) -> float:
    """Convert ISO-8601 UTC ``Z`` to a UNIX epoch float.  Splunk HEC
    rejects ISO strings in the ``time`` field (HTTP 400 / code 15).
    """
    if not iso_ts:
        return time.time()
    try:
        normalised = iso_ts[:-1] + "+00:00" if iso_ts.endswith("Z") else iso_ts
        return _dt.datetime.fromisoformat(normalised).timestamp()
    except (TypeError, ValueError):
        return time.time()


# ---------------------------------------------------------------------------
# Canonicalisation — the single source of truth for the event wire format
# ---------------------------------------------------------------------------

#: Wire-format version carried in every event and covered by the digest.
#:
#: * 1 (implicit, pre-fix) — producer hashed a payload containing
#:   ``"digest": ""``; both verifiers excluded ``digest``.  Nothing
#:   verified.  Genesis ``prev_digest`` was ``""`` in the sidecar and
#:   ``"0" * 64`` in ``core.audit.continuous``.
#: * 2 — digest excludes both ``digest`` and ``signature`` (a digest must
#:   not cover itself), genesis ``prev_digest`` is ``"0" * 64``
#:   everywhere, and ``schema_version`` is an explicit, digest-covered
#:   field so a verifier can reject a format it does not understand
#:   instead of mis-verifying it.
EVENT_SCHEMA_VERSION = 2

#: Versions this build's verifier knows how to check.  An event carrying
#: anything else must be rejected, not silently mis-verified.
SUPPORTED_SCHEMA_VERSIONS = frozenset({EVENT_SCHEMA_VERSION})

#: ``prev_digest`` of the first event in a chain.  64 hex zeros rather
#: than the empty string so a truncated-then-re-anchored window is
#: distinguishable from a genuine genesis event.
GENESIS_PREV_DIGEST = "0" * 64

#: Fields excluded from the canonical digest payload.  ``digest`` cannot
#: cover itself and ``signature`` is computed over ``digest``.
_DIGEST_EXCLUDED = ("digest", "signature")


def canonical_digest_payload(d: Dict[str, Any]) -> bytes:
    """Canonical JSON bytes an event's ``digest`` is computed over.

    Producer and verifier MUST both call this — the two hand-rolled
    copies that used to exist disagreed about ``digest``.
    """
    return json.dumps(
        {k: v for k, v in d.items() if k not in _DIGEST_EXCLUDED},
        separators=(",", ":"), sort_keys=True,
    ).encode()


def compute_digest(d: Dict[str, Any]) -> str:
    """SHA-256 hex of :func:`canonical_digest_payload` for event dict *d*."""
    return hashlib.sha256(canonical_digest_payload(d)).hexdigest()


# ---------------------------------------------------------------------------
# AttestationEvent — mirrors tee_crafter.core.audit.continuous
# ---------------------------------------------------------------------------

@dataclass
class AttestationEvent:
    event_id: str
    seq: int
    event_type: str
    timestamp: str
    pipeline_version: str
    instance_id: str
    tee_platform: str
    measurement_sha256: str
    attestation_sha256: str
    attestation_size_bytes: int
    status: str
    prev_digest: str
    schema_version: int = EVENT_SCHEMA_VERSION
    digest: str = ""
    signature: str = ""
    public_key_pem: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def canonical_digest_payload(self) -> bytes:
        return canonical_digest_payload(asdict(self))


# ---------------------------------------------------------------------------
# Exporters
# ---------------------------------------------------------------------------

class SiemExportError(RuntimeError):
    """An event could not be handed to the collector.

    Every exporter must raise this (or any exception) rather than logging and
    returning, because :meth:`AttestationLoop._tick` derives
    ``last_export_status`` *solely* from whether ``emit()`` raised.  An exporter
    that swallows its failures therefore reports ``pass`` forever, and that is
    not a cosmetic problem: ``last_export_status`` is what the in-TEE
    fail-closed gate reads (``siem_health.assert_siem_healthy``), and under the
    shipped default (``fail_open = False``) it is what decides whether the
    workload may serve at all.  Swallowing a failure silently converts "the SOC
    has lost sight of this enclave" into "everything is fine".

    That is exactly what happened.  Measured on a live ``nitro-aws`` deploy
    (2026-08-21) with the collector pointed at an RFC 2606 ``.invalid``
    hostname, so delivery was impossible by construction::

        WARNING HEC POST failed: URLError(gaierror(-2, 'Name or service not known'))
        INFO    emitted seq=0 status=pass size=0 platform=nitro-aws export=pass

    and the deploy printed "✓ SIEM sidecar active — events streaming (export
    confirmed)".  The readiness gate that requires ``export_status == "pass"``
    was already correct; it was being fed a lie by the exporters below.
    """


class SplunkHecExporter:
    """Minimal Splunk HEC exporter using stdlib urllib only."""

    def __init__(self, *, endpoint: str, token: str, index: str,
                 sourcetype: str, source: str, verify_ssl: bool = True):
        endpoint = endpoint.rstrip("/")
        if endpoint.endswith("/services/collector"):
            endpoint = endpoint[: -len("/services/collector")]
        self.url = endpoint + "/services/collector/event"
        self.headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }
        self.index = index
        self.sourcetype = sourcetype
        self.source = source
        self.verify_ssl = verify_ssl

    def emit(self, event: AttestationEvent) -> None:
        body = {
            "time": _iso_to_epoch(event.timestamp),
            "host": event.instance_id,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": asdict(event),
        }
        data = json.dumps(body, separators=(",", ":")).encode()
        req = urllib.request.Request(self.url, data=data, method="POST")
        for k, v in self.headers.items():
            req.add_header(k, v)
        ctx = ssl._create_unverified_context() if not self.verify_ssl else None
        try:
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                status = resp.status
                body = resp.read()[:200] if status >= 300 else b""
        except urllib.error.HTTPError as e:
            # 4xx/5xx: a bad token is a 403 here, and it is a hard failure —
            # the collector received nothing.
            raise SiemExportError(
                f"HEC HTTP {e.code}: {e.read()[:200]!r}") from e
        except Exception as e:
            raise SiemExportError(f"HEC POST failed: {e!r}") from e
        if status >= 300:
            raise SiemExportError(f"HEC HTTP {status}: {body!r}")


class DatadogLogsExporter:
    """Minimal Datadog Logs Intake exporter.  Same wire shape as Splunk
    HEC for our purposes — one HTTPS POST per event.
    """

    def __init__(self, *, api_key: str, site: str, service: str,
                 source: str, env: str, endpoint: Optional[str] = None,
                 verify_ssl: bool = True):
        self.url = (
            endpoint.rstrip("/") if endpoint
            else f"https://http-intake.logs.{site}/api/v2/logs"
        )
        self.headers = {
            "DD-API-KEY": api_key,
            "Content-Type": "application/json",
        }
        self.service = service
        self.source = source
        self.env = env
        self.verify_ssl = verify_ssl

    def emit(self, event: AttestationEvent) -> None:
        body = [{
            "ddsource": self.source,
            "service": self.service,
            "ddtags": f"env:{self.env},tee_platform:{event.tee_platform}",
            "hostname": event.instance_id,
            "message": json.dumps(asdict(event), separators=(",", ":")),
        }]
        data = json.dumps(body, separators=(",", ":")).encode()
        req = urllib.request.Request(self.url, data=data, method="POST")
        for k, v in self.headers.items():
            req.add_header(k, v)
        ctx = ssl._create_unverified_context() if not self.verify_ssl else None
        try:
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                status = resp.status
                body = resp.read()[:200] if status >= 300 else b""
        except urllib.error.HTTPError as e:
            raise SiemExportError(
                f"DD HTTP {e.code}: {e.read()[:200]!r}") from e
        except Exception as e:
            raise SiemExportError(f"DD POST failed: {e!r}") from e
        if status >= 300:
            raise SiemExportError(f"DD HTTP {status}: {body!r}")


class SyslogCefExporter:
    """RFC 5424 + CEF exporter for the in-VM sidecar.

    Wire format is **byte-for-byte identical** to
    :class:`tee_crafter.core.audit.exporters.syslog.SyslogCefExporter`
    so a SIEM dashboard or saved search written against the in-tree
    exporter also matches what the sidecar emits in production.

    The frame is RFC 5424:

        <PRI>1 ISO-TS HOSTNAME APP - - - CEF:0|Vendor|Product|...|

    Production collectors (rsyslog with ``parser RFC5424``, syslog-ng
    with ``flags(syslog-protocol)``, ArcSight SmartConnector, Sumo Cloud
    Syslog, …) reject anything that is not strictly RFC 5424 framed.
    The previous version of this class emitted just the CEF payload over
    UDP, which those collectors silently drop.

    TCP support is essential: any reliable forwarder (rsyslog →
    SaaS, syslog-ng cluster, ngrok TCP tunnel) speaks TCP, not UDP.
    Production TCP socket lifecycles must survive transient peer
    restarts (e.g. ngrok edge rotation, rsyslog graceful reload) — we
    catch socket errors, close the socket, and re-dial on the next
    ``emit()``.  ``connect_timeout`` and per-send timeout prevent a
    hung peer from wedging the entire attestation loop.

    UDP path remains available for legacy ``514/udp`` collectors; sockets are
    cheap so we re-create per-send to avoid the "stale source port"
    NAT-rebind hazard on long-lived UDP sockets.  **Default protocol is TCP**
    for reliable delivery when ``protocol`` is omitted from SIEM config.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        protocol: str = "tcp",
        facility: int = 13,    # log_audit
        severity: int = 5,      # notice
        hostname: str = "",
        device_vendor: str = "TEE-Crafter",
        device_product: str = "tee-crafter",
        device_version: str = "0.1.0",
        connect_timeout: float = 10.0,
        send_timeout: float = 5.0,
    ):
        if protocol not in ("udp", "tcp"):
            raise ValueError(
                f"SyslogCefExporter protocol must be 'udp' or 'tcp', got {protocol!r}")
        self.host = host
        self.port = int(port)
        self.protocol = protocol
        self.facility = int(facility)
        self.severity = int(severity)
        self.hostname = hostname or socket.gethostname()
        self.device_vendor = device_vendor
        self.device_product = device_product
        self.device_version = device_version
        self.connect_timeout = float(connect_timeout)
        self.send_timeout = float(send_timeout)
        self._tcp_sock: Optional[socket.socket] = None

    def _open_tcp(self) -> socket.socket:
        # Fresh DNS resolution on every connect — important when the
        # collector address rotates (ngrok free tier, multi-A-record
        # DNS, k8s service IP churn).
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.connect_timeout)
        s.connect((self.host, self.port))
        s.settimeout(self.send_timeout)
        # SO_KEEPALIVE with tight Linux knobs so the kernel discovers a
        # dead peer in seconds instead of the default ~2h.  Critical
        # when the collector lives behind ngrok / an ALB / a docker
        # bridge — these reset the underlying TCP without proxying a
        # clean FIN to the client.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
            if hasattr(socket, "TCP_KEEPINTVL"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            if hasattr(socket, "TCP_KEEPCNT"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except OSError:
            pass
        return s

    def _close_tcp(self) -> None:
        s = self._tcp_sock
        self._tcp_sock = None
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    def _peer_closed(self, sock) -> bool:
        """Pre-send liveness probe via ``select(timeout=0)``.

        Required because ``sendall`` on a peer that has FIN'd succeeds
        the first time (data lost to the kernel buffer) and only the
        *next* send observes the RST.  Single-send loss is
        unacceptable for an attestation event stream; we probe first.
        """
        try:
            readable, _, _ = select.select([sock], [], [], 0)
        except (OSError, ValueError):
            return True
        if not readable:
            return False
        try:
            data = sock.recv(1, socket.MSG_PEEK)
            return data == b"" or len(data) > 0
        except OSError:
            return True

    def emit(self, event: AttestationEvent) -> None:
        line = self._format(event).encode("utf-8")
        if self.protocol == "udp":
            # A successful UDP sendto proves only that the datagram reached the
            # local kernel — never that the collector received it.  That is a
            # protocol limit we cannot close here, and it is why syslog-cef over
            # UDP is the weakest of the three delivery signals.  What we *can*
            # do is not hide the failures that are locally detectable, such as
            # an unresolvable collector hostname (gaierror).
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(line, (self.host, self.port))
            except Exception as e:
                raise SiemExportError(
                    f"syslog UDP send to {self.host}:{self.port} "
                    f"failed: {e!r}") from e
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            return

        # TCP: probe-then-send with one retry on socket error.
        # ``sendall`` on a half-closed peer succeeds silently the first
        # time (data lost to the kernel buffer); MSG_PEEK probes the
        # FIN before the send.  The retry covers the race where the
        # peer dies *between* the probe and the send.
        payload = line + b"\n"
        for attempt in (1, 2):
            try:
                if self._tcp_sock is None:
                    self._tcp_sock = self._open_tcp()
                if self._peer_closed(self._tcp_sock):
                    self._close_tcp()
                    self._tcp_sock = self._open_tcp()
                self._tcp_sock.sendall(payload)
                return
            except (OSError, socket.timeout) as e:
                self._close_tcp()
                if attempt == 2:
                    logger.warning(
                        "syslog TCP send to %s:%d failed after reconnect: %r",
                        self.host, self.port, e)
                    raise
                logger.info(
                    "syslog TCP socket to %s:%d died (%r); reconnecting",
                    self.host, self.port, e)

    def close(self) -> None:
        self._close_tcp()

    # ------------------------------------------------------------------
    # Wire format — must match
    # tee_crafter.core.audit.exporters.syslog.SyslogCefExporter._format
    # byte-for-byte.  Regression-tested via siem-sandbox/scripts/smoke_syslog.py
    # ------------------------------------------------------------------

    def _format(self, ev: AttestationEvent) -> str:
        sev = self._sev_for_event(ev)
        cef_header = (
            f"CEF:0|{_cef_esc(self.device_vendor)}|"
            f"{_cef_esc(self.device_product)}|"
            f"{_cef_esc(self.device_version)}|"
            f"{_cef_esc(ev.event_type)}|"
            f"TEE attestation {ev.status}|{sev}|"
        )
        ext = (
            f"rt={ev.timestamp} "
            f"deviceExternalId={ev.instance_id} "
            f"cs1Label=teePlatform cs1={ev.tee_platform} "
            f"cs2Label=measurementSha256 cs2={ev.measurement_sha256} "
            f"cs3Label=attestationSha256 cs3={ev.attestation_sha256} "
            f"cs4Label=chainHead cs4={ev.digest} "
            f"cs5Label=signature cs5={ev.signature} "
            f"cn1Label=seq cn1={ev.seq} "
            f"cn2Label=attestationSizeBytes cn2={ev.attestation_size_bytes} "
            f"outcome={ev.status}"
        )
        pri = self.facility * 8 + self.severity
        return (
            f"<{pri}>1 {ev.timestamp} {self.hostname} "
            f"{self.device_product} - - - {cef_header}{ext}"
        )

    @staticmethod
    def _sev_for_event(ev: AttestationEvent) -> int:
        if ev.status == "fail":
            return 8
        if ev.status == "warn":
            return 5
        return 3


def _cef_esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("|", "\\|")


def _build_exporter():
    provider = os.environ.get("TEE_CRAFTER_SIEM", "none").lower()
    if provider == "splunk-hec":
        return SplunkHecExporter(
            endpoint=os.environ["TEE_CRAFTER_SIEM_ENDPOINT"],
            token=os.environ["TEE_CRAFTER_SIEM_TOKEN"],
            index=os.environ.get("TEE_CRAFTER_SIEM_INDEX", "main"),
            sourcetype=os.environ.get(
                "TEE_CRAFTER_SIEM_SOURCETYPE", "tee_crafter:attestation"),
            source=os.environ.get("TEE_CRAFTER_SIEM_SOURCE", "tee-crafter"),
            verify_ssl=os.environ.get(
                "TEE_CRAFTER_SIEM_X_VERIFY_SSL", "").strip().lower()
            not in ("0", "false", "no", "off"),
        )
    if provider == "datadog":
        return DatadogLogsExporter(
            api_key=os.environ["TEE_CRAFTER_SIEM_API_KEY"],
            site=os.environ.get("TEE_CRAFTER_SIEM_SITE", "datadoghq.com"),
            service=os.environ.get("TEE_CRAFTER_SIEM_SERVICE", "tee-crafter"),
            source=os.environ.get("TEE_CRAFTER_SIEM_DDSOURCE", "tee-crafter"),
            env=os.environ.get("TEE_CRAFTER_SIEM_ENV", "prod"),
            endpoint=os.environ.get("TEE_CRAFTER_SIEM_ENDPOINT") or None,
        )
    if provider == "syslog-cef":
        return SyslogCefExporter(
            host=os.environ["TEE_CRAFTER_SIEM_HOST"],
            port=int(os.environ.get("TEE_CRAFTER_SIEM_PORT", "514")),
            protocol=os.environ.get(
                "TEE_CRAFTER_SIEM_PROTOCOL", "tcp").lower(),
            facility=int(os.environ.get("TEE_CRAFTER_SIEM_FACILITY", "13")),
            severity=int(os.environ.get("TEE_CRAFTER_SIEM_SEVERITY", "5")),
            hostname=os.environ.get("TEE_CRAFTER_SIEM_HOSTNAME", ""),
            connect_timeout=float(os.environ.get(
                "TEE_CRAFTER_SIEM_CONNECT_TIMEOUT", "10")),
            send_timeout=float(os.environ.get(
                "TEE_CRAFTER_SIEM_SEND_TIMEOUT", "5")),
        )
    raise RuntimeError(f"unsupported SIEM provider for sidecar: {provider!r}")


# ---------------------------------------------------------------------------
# Platform-aware attestation provider
# ---------------------------------------------------------------------------

# Each provider returns ``(report_bytes, measurement_hex)``.  The
# measurement is best-effort: when the platform module can derive one
# we include it; otherwise empty string.
AttestProvider = Callable[[], Tuple[bytes, str]]


def _provider_snp_aws() -> AttestProvider:
    app = importlib.import_module("app_snp")
    fn_attest = app.generate_snp_attestation
    fn_meas = getattr(app, "_read_measurement_from_report", None)

    def _provider():
        nonce = (b"siem-tick-" + uuid.uuid4().bytes)[:64]
        report, _certs = fn_attest(nonce)
        meas = fn_meas(report) if (fn_meas and report) else ""
        return report, (meas or "")
    return _provider


def _provider_snp_azure() -> AttestProvider:
    app = importlib.import_module("app_snp")
    fn_attest = app.generate_snp_attestation
    fn_meas = getattr(app, "_read_measurement_from_report", None)

    def _provider():
        nonce = (b"siem-tick-" + uuid.uuid4().bytes)[:64]
        out = fn_attest(nonce)
        report = out[0] if isinstance(out, tuple) else out
        meas = fn_meas(report) if (fn_meas and report) else ""
        return report, (meas or "")
    return _provider


def _provider_snp_gcp() -> AttestProvider:
    app = importlib.import_module("app_snp_gcp")
    fn_attest = app.generate_snp_attestation
    fn_meas = getattr(app, "_read_measurement_from_report", None)

    def _provider():
        nonce = (b"siem-tick-" + uuid.uuid4().bytes)[:64]
        out = fn_attest(nonce)
        report = out[0] if isinstance(out, tuple) else out
        meas = fn_meas(report) if (fn_meas and report) else ""
        return report, (meas or "")
    return _provider


def _provider_tdx_azure() -> AttestProvider:
    app = importlib.import_module("app_tdx")
    fn_attest = getattr(app, "generate_tdx_quote", None) or app.generate_tdx_attestation
    fn_meas = getattr(app, "_read_mrtd_from_quote", None) or getattr(
        app, "_read_measurement_from_quote", None)

    def _provider():
        nonce = (b"siem-tick-" + uuid.uuid4().bytes)[:64]
        out = fn_attest(nonce)
        quote = out[0] if isinstance(out, tuple) else out
        meas = fn_meas(quote) if (fn_meas and quote) else ""
        return quote, (meas or "")
    return _provider


def _provider_tdx_gcp() -> AttestProvider:
    app = importlib.import_module("app_tdx_gcp")
    fn_attest = getattr(app, "generate_tdx_quote", None) or app.generate_tdx_attestation
    fn_meas = getattr(app, "_read_mrtd_from_quote", None) or getattr(
        app, "_read_measurement_from_quote", None)

    def _provider():
        nonce = (b"siem-tick-" + uuid.uuid4().bytes)[:64]
        out = fn_attest(nonce)
        quote = out[0] if isinstance(out, tuple) else out
        meas = fn_meas(quote) if (fn_meas and quote) else ""
        return quote, (meas or "")
    return _provider


def _provider_heartbeat(measurement_file_candidates) -> AttestProvider:
    """Boot-anchored heartbeat provider for platforms (Nitro / SGX) where
    the sidecar can't trivially trigger a fresh hardware attestation
    from outside the enclave.  Reads the boot-time measurement from
    one of the candidate JSON files and emits a heartbeat each tick.

    The measurement remains constant (boot-anchored), which is honest
    about what the sidecar is observing.  The freshness signal is the
    *event timestamp + signature chain*: a SIEM dashboard that stops
    receiving events from a given ``instance_id`` knows the enclave is
    no longer alive, even if individual reports are not re-issued.

    For per-tick fresh attestation in Nitro / SGX, future work will add
    a local vsock / RA-TLS attestation refresh path.
    """
    measurement_hex = ""
    pipeline_version = ""
    for cand in measurement_file_candidates:
        try:
            if os.path.isfile(cand):
                with open(cand, "r", encoding="utf-8") as f:
                    j = json.load(f)
                for k in ("measurement", "mrenclave", "mrtd", "pcr0", "pcr_0"):
                    if k in j and isinstance(j[k], str) and j[k]:
                        measurement_hex = j[k].lower()
                        break
                if not measurement_hex:
                    meas = j.get("measurements") or {}
                    for k in ("measurement", "mrenclave", "mrtd", "pcr0"):
                        v = meas.get(k)
                        if isinstance(v, str) and v:
                            measurement_hex = v.lower()
                            break
                pipeline_version = j.get("pipeline_version") or ""
                if measurement_hex:
                    break
        except Exception:
            continue

    def _provider():
        return b"", measurement_hex
    _provider.pipeline_version = pipeline_version  # type: ignore[attr-defined]
    return _provider


def _provider_nitro_aws() -> AttestProvider:
    return _provider_heartbeat([
        "/opt/tee-crafter/build_provenance.json",
        "/opt/tee-crafter/measurements.json",
    ])


def _provider_sgx_azure() -> AttestProvider:
    return _provider_heartbeat([
        "/opt/tee-crafter-sgx/build_provenance.json",
        "/opt/tee-crafter-sgx/measurements.json",
    ])


_PROVIDER_FACTORIES = {
    "snp-aws":   _provider_snp_aws,
    "snp-azure": _provider_snp_azure,
    "snp-gcp":   _provider_snp_gcp,
    "tdx-azure": _provider_tdx_azure,
    "tdx-gcp":   _provider_tdx_gcp,
    "gpu-cc-aws":   _provider_snp_aws,
    "gpu-cc-azure": _provider_snp_azure,
    "gpu-cc-gcp":   _provider_tdx_gcp,
    "nitro-aws":    _provider_nitro_aws,
    "sgx-azure":    _provider_sgx_azure,
}


def _autodetect_platform() -> str:
    """When TEE_CRAFTER_TEE_PLATFORM is unset, probe for an importable
    ``app_*.py`` module on sys.path."""
    candidates = [
        ("app_snp_gcp", "snp-gcp"),
        ("app_tdx_gcp", "tdx-gcp"),
        ("app_snp", "snp-aws"),
        ("app_tdx", "tdx-azure"),
    ]
    for mod_name, label in candidates:
        try:
            importlib.import_module(mod_name)
            return label
        except Exception:
            continue
    return ""


def _build_provider(platform: str) -> AttestProvider:
    factory = _PROVIDER_FACTORIES.get(platform)
    if factory is None:
        raise RuntimeError(
            f"no SIEM attestation provider for platform {platform!r}; "
            f"supported: {sorted(_PROVIDER_FACTORIES)}"
        )
    return factory()


# ---------------------------------------------------------------------------
# Instance-id helpers
# ---------------------------------------------------------------------------

def _read_aws_instance_id() -> str:
    try:
        token_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        )
        with urllib.request.urlopen(token_req, timeout=2) as r:
            tok = r.read().decode()
        iid_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": tok},
        )
        with urllib.request.urlopen(iid_req, timeout=2) as r:
            return r.read().decode()
    except Exception:
        return ""


def _read_azure_instance_id() -> str:
    try:
        req = urllib.request.Request(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "true"},
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            j = json.loads(r.read())
        return j.get("compute", {}).get("vmId") or ""
    except Exception:
        return ""


def _read_gcp_instance_id() -> str:
    try:
        req = urllib.request.Request(
            "http://metadata.google.internal/computeMetadata/v1/instance/id",
            headers={"Metadata-Flavor": "Google"},
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.read().decode()
    except Exception:
        return ""


def _read_instance_id(platform: str) -> str:
    if platform.endswith("-aws"):
        v = _read_aws_instance_id()
    elif platform.endswith("-azure"):
        v = _read_azure_instance_id()
    elif platform.endswith("-gcp"):
        v = _read_gcp_instance_id()
    else:
        v = ""
    return v or socket.gethostname()


# ---------------------------------------------------------------------------
# Main event loop
# ---------------------------------------------------------------------------

#: Where the workload process publishes its runtime-audit-log chain-key
#: commitment.  Must match
#: ``tee_crafter_audit_logger.CHAIN_COMMITMENT_PATH``; kept as a literal
#: here because the sidecar cannot import the app-side module.
CHAIN_COMMITMENT_PATH = "/run/tee_crafter/chain_key_commitment"


def read_chain_key_commitment() -> str:
    """Return the published chain-key commitment hex, or ``""`` if absent.

    Never raises: on host-side heartbeat sidecars (Nitro / SGX) the file
    simply does not exist because the workload runs in a different
    namespace.
    """
    path = os.environ.get(
        "TEE_CRAFTER_CHAIN_COMMITMENT_PATH", CHAIN_COMMITMENT_PATH)
    try:
        with open(path, "r", encoding="ascii") as f:
            value = f.read().strip().lower()
    except OSError:
        return ""
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        return ""
    return value


def _health_path(tee_platform: str) -> str:
    """Per-platform tmpfs path the sidecar writes / main app reads.

    The directory ``/run/tee-crafter-{platform}`` is created by the
    deploy-time install script (see
    ``tee_crafter.cli.deployment.common.siem_sidecar``) and is also where
    the token-bearing ``siem.env`` lives.  The health file is JSON, mode
    0640 (owner tee_enclave), so both the sidecar and the main app
    process — same UID — can write/read it without escalation.
    """
    return f"/run/tee-crafter-{tee_platform}/siem.health"


def _write_health_state(*, tee_platform: str, last_seq: int,
                        last_status: str, last_export_status: str,
                        last_export_error: str, last_digest: str,
                        signing_key_sha256: str = "") -> None:
    """SIEM-SEC-4: emit a tiny JSON snapshot the fail-closed gate can read.

    Atomically replaces the previous file so a partial write never
    confuses the reader.  We treat the *exporter* status as
    authoritative for "is SIEM observing us?" — a `pass` attestation
    that we couldn't ship is effectively a SIEM blackout.
    """
    path = _health_path(tee_platform)
    payload = {
        "ts": int(time.time()),
        "last_seq": int(last_seq),
        "last_status": last_status,
        "last_export_status": last_export_status,
        "last_export_error": last_export_error[:32],
        "last_digest": last_digest[:64],
        "tee_platform": tee_platform,
        # Fingerprint of the per-process Ed25519 key signing this stream.  The
        # deploy copies it into the provenance ledger so `verify-siem-chain`
        # has an anchor that did not arrive inside the events themselves.
        "signing_key_sha256": signing_key_sha256,
    }
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    except OSError:
        pass
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"), sort_keys=True)
    try:
        os.chmod(tmp, 0o640)
    except OSError:
        pass
    os.replace(tmp, path)


class AttestationLoop:
    """Generic TEE-attestation -> SIEM loop.

    Hash-chains every emitted event and signs the chain digest with a
    per-boot Ed25519 key — same wire format as
    ``tee_crafter.core.audit.continuous.ContinuousAttestor``.
    """

    def __init__(
        self, *,
        exporter,
        interval_seconds: int,
        instance_id: str,
        tee_platform: str,
        pipeline_version: str,
        attest_provider: AttestProvider,
    ):
        self.exporter = exporter
        self.interval = max(1, int(interval_seconds))
        self.instance_id = instance_id
        self.tee_platform = tee_platform
        self.pipeline_version = pipeline_version
        self.attest_provider = attest_provider
        self.seq = 0
        self.prev_digest = GENESIS_PREV_DIGEST
        self.signing_key = Ed25519PrivateKey.generate()
        self.public_pem = (
            self.signing_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        # SHA-256 over the DER SubjectPublicKeyInfo — the same normalisation
        # ``verify_siem_chain.pubkey_sha256`` applies, so an operator can pin
        # this value directly with ``--pinned-pubkey-sha256``.
        #
        # The key above is generated per process and lives only in memory, so
        # until this was published the *only* copy of it travelled inside the
        # events it signs.  That makes an anchor self-referential: anyone who
        # can inject into the SIEM can present a self-consistent chain signed
        # by a key they generated, and `verify-siem-chain` had nothing
        # out-of-band to compare against.  Surfacing the fingerprint here lets
        # the deploy record it into the build provenance ledger at install
        # time, before any event has been exported.
        self.public_key_sha256 = hashlib.sha256(
            self.signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()

    def _build_event(self, status: str, blob: bytes,
                     measurement_hex: str,
                     extra: Optional[Dict[str, Any]] = None) -> AttestationEvent:
        merged_extra = dict(extra or {})
        # AUD-3 genesis publication: the workload process publishes the
        # SHA-256 commitment to its in-memory runtime-audit-log HMAC key
        # (``tee_crafter_audit_logger.get_chain_key_commitment``) to a
        # tmpfs file; we echo it on every event so a SOC can pin it
        # against the value the enclave put in its attestation
        # ``report_data``.  Absent on host-side heartbeat sidecars
        # (Nitro / SGX), where no workload process shares our namespace.
        commitment = read_chain_key_commitment()
        if commitment:
            merged_extra.setdefault("chain_key_commitment", commitment)
        ev = AttestationEvent(
            event_id=uuid.uuid4().hex[:16],
            seq=self.seq,
            event_type="attestation_refresh" if self.seq else "attestation_boot",
            timestamp=_iso_now(),
            pipeline_version=self.pipeline_version,
            instance_id=self.instance_id,
            tee_platform=self.tee_platform,
            measurement_sha256=measurement_hex,
            attestation_sha256=hashlib.sha256(blob).hexdigest() if blob else "",
            attestation_size_bytes=len(blob),
            status=status,
            prev_digest=self.prev_digest,
            public_key_pem=self.public_pem,
            extra=merged_extra,
        )
        ev.digest = hashlib.sha256(ev.canonical_digest_payload()).hexdigest()
        ev.signature = self.signing_key.sign(ev.digest.encode()).hex()
        return ev

    def tick(self) -> None:
        report = b""
        measurement = ""
        extra: Dict[str, Any] = {}
        status = "pass"
        try:
            report, measurement = self.attest_provider()
        except Exception as e:
            logger.warning("attestation provider failed: %s", type(e).__name__)
            status = "fail"
            extra["error_type"] = type(e).__name__
            msg = str(e)[:160]
            extra["error_msg"] = msg.replace("/opt/tee-crafter-", "<base>/")
        ev = self._build_event(status, report, measurement, extra)
        export_status = "pass"
        export_err = ""
        try:
            self.exporter.emit(ev)
        except Exception as e:
            export_status = "fail"
            # Record *why*, not just the exception class.  Under the shipped
            # fail-closed default this string is the only clue an operator gets
            # for why the workload began refusing requests, and "SiemExportError"
            # alone does not distinguish a bad token from an unreachable host.
            # Quotes and backslashes are stripped because the sidecar readiness
            # check greedily seds `last_export_status` out of this same JSON
            # object, and this field is serialised ahead of it.
            detail = (str(e)[:160]
                      .replace("/opt/tee-crafter-", "<base>/")
                      .replace('"', "'")
                      .replace("\\", "/"))
            export_err = f"{type(e).__name__}: {detail}" if detail else type(e).__name__
            logger.warning("exporter.emit failed: %s", export_err)
        self.seq += 1
        self.prev_digest = ev.digest
        # SIEM-SEC-4: write the health-state file the main app's
        # fail-closed gate reads.  We write whether the export
        # succeeded or not — the fail-closed reader interprets the
        # ``last_export_status`` field.
        try:
            _write_health_state(
                tee_platform=self.tee_platform,
                last_seq=self.seq - 1,
                last_status=status,
                last_export_status=export_status,
                last_export_error=export_err,
                last_digest=ev.digest,
                signing_key_sha256=self.public_key_sha256,
            )
        except Exception as e:
            logger.warning("health-state write failed: %s", type(e).__name__)
        logger.info("emitted seq=%d status=%s size=%d platform=%s export=%s",
                    ev.seq - 1, ev.status, ev.attestation_size_bytes,
                    ev.tee_platform, export_status)

    def run(self) -> None:
        logger.info(
            "starting SIEM loop: platform=%s interval=%ds",
            self.tee_platform, self.interval,
        )
        while True:
            t0 = time.monotonic()
            self.tick()
            elapsed = time.monotonic() - t0
            sleep_for = max(0.5, self.interval - elapsed)
            time.sleep(sleep_for)


def main() -> int:
    # Configured here rather than at import time: the build host imports
    # this module purely for the canonicalisation helpers and must not
    # have its root logger reconfigured as a side effect.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [siem-export] %(levelname)s %(message)s",
    )
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    env_file = os.environ.get("TEE_CRAFTER_SIEM_ENV_FILE", "")
    if not env_file:
        for candidate in (
            "/opt/tee-crafter-snp/app/siem.env",
            "/opt/tee-crafter-tdx/app/siem.env",
            "/opt/tee-crafter-gpu-cc/app/siem.env",
            "/opt/tee-crafter-gpu-cc/.env",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "siem.env"),
        ):
            if os.path.isfile(candidate):
                env_file = candidate
                break
    if env_file:
        for k, v in _load_env_file(env_file).items():
            os.environ.setdefault(k, v)

    if os.environ.get("TEE_CRAFTER_SIEM_ENABLED", "0").lower() not in (
            "1", "true", "yes"):
        logger.info("SIEM disabled (TEE_CRAFTER_SIEM_ENABLED!=1); exiting.")
        return 0

    platform = (os.environ.get("TEE_CRAFTER_TEE_PLATFORM")
                or _autodetect_platform())
    if not platform:
        logger.error("Cannot determine TEE platform; set TEE_CRAFTER_TEE_PLATFORM.")
        return 2
    logger.info("resolved tee_platform=%s", platform)

    # SIEM-SEC-1: refuse to ship attestation events over an
    # unauthenticated TLS channel in production.  ``verify_ssl=0`` is
    # only legitimate for the local sandbox where Splunk is fronted
    # by a self-signed nginx cert.  If a user copy-pastes the sandbox
    # config into a production deploy we want a loud failure, not a
    # silent MITM-friendly export.
    verify_raw = os.environ.get(
        "TEE_CRAFTER_SIEM_X_VERIFY_SSL", "").strip().lower()
    if verify_raw in ("0", "false", "no", "off"):
        if os.environ.get(
                "TEE_CRAFTER_SIEM_X_ALLOW_INSECURE", "").lower() not in (
                "1", "true", "yes"):
            logger.error(
                "SIEM: TLS verification disabled but "
                "TEE_CRAFTER_SIEM_X_ALLOW_INSECURE is unset — refusing "
                "to export attestation events.  Either trust your SIEM's "
                "CA chain or set TEE_CRAFTER_SIEM_X_ALLOW_INSECURE=1 "
                "explicitly (sandbox only).")
            return 5
        logger.warning("SIEM: TLS verification DISABLED — sandbox mode.")

    try:
        provider = _build_provider(platform)
    except Exception as e:
        logger.error("provider factory failed for %s: %s",
                     platform, type(e).__name__)
        return 3
    try:
        exporter = _build_exporter()
    except Exception as e:
        logger.error("exporter factory failed: %s", type(e).__name__)
        return 4

    interval = int(os.environ.get("TEE_CRAFTER_SIEM_INTERVAL_SECONDS", "60"))
    pipeline_version = os.environ.get(
        "TEE_CRAFTER_PIPELINE_VERSION", f"tee-crafter-sidecar-{platform}")
    instance_id = _read_instance_id(platform)

    loop = AttestationLoop(
        exporter=exporter,
        interval_seconds=interval,
        instance_id=instance_id,
        tee_platform=platform,
        pipeline_version=pipeline_version,
        attest_provider=provider,
    )
    try:
        loop.run()
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        logger.exception("loop crashed: %r", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
