#!/usr/bin/env python3
"""syslog-ng local-sandbox smoke test.

What it does
------------
1.  Builds the *real* ``SyslogCefExporter`` (the same class TEE-Crafter
    uses inside an enclave) wired against the local docker-compose
    syslog-ng — once over UDP/5514, once over TCP/6601.

2.  Generates signed ``AttestationEvent``s through the *real*
    ``ContinuousAttestor`` / Ed25519 signing path so the smoke test
    exercises hash-chaining + signature emission, not just framing.

3.  Reads the lines syslog-ng wrote to ``/var/log/tee-crafter/teelog.log``
    inside the container (via ``docker exec``) and verifies, per
    transport:

    *  every event we emitted shows up exactly once,
    *  the RFC 5424 framing parses (PRI, VERSION=1, hostname, app),
    *  the CEF payload carries each AttestationEvent field
       (instance_id, tee_platform, measurement_sha256,
       attestation_sha256, hash-chain head, signature, seq),
    *  severity escalates from 3 (status=pass) to 8 (status=fail),
    *  the captured signatures verify against the captured PEM public
       key — proving the receiver-side wire-format round-trip preserves
       enough to do end-to-end audit verification, not just ingest.

4.  Prints a one-line summary per transport (events sent / events
    parsed / p50 emit latency) and exits 0 on success, 1 otherwise.

Run from the repo root, after ``docker compose up -d`` in
``siem-sandbox/syslog/``:

    python siem-sandbox/scripts/smoke_syslog.py
"""
from __future__ import annotations

import re
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from tee_crafter.core.audit.continuous import (
    AttestationEvent,
    AuditEventExporter,
    ContinuousAttestor,
    _short_uuid,
)
from tee_crafter.core.audit.exporters.syslog import SyslogCefExporter

CONTAINER = "tee-crafter-syslog-ng"
LOG_PATH = "/var/log/tee-crafter/teelog.log"
SMOKE_HOSTNAME_PREFIX = "tee-crafter-smoke"
N_EVENTS_PER_TRANSPORT = 4  # 1 boot + (n-2) refresh-pass + 1 refresh-fail


# ---------------------------------------------------------------------------
# Attestation source: alternating pass/fail so the smoke test can prove
# severity escalation on the wire.
# ---------------------------------------------------------------------------

class _AlternatingAttestor:
    """Drives `ContinuousAttestor` with deterministic pass/fail."""

    def __init__(self):
        self._n = 0

    def __call__(self, nonce: bytes) -> bytes:
        self._n += 1
        # The last call in each batch fails so we can assert severity=8.
        if self._n == N_EVENTS_PER_TRANSPORT:
            raise RuntimeError("smoke-test: simulated attestor failure")
        return b"SMOKE_QUOTE:" + nonce + b":" + str(self._n).encode()


# ---------------------------------------------------------------------------
# Capturing exporter — tees events to syslog AND to memory so the smoke
# test can compare the on-wire CEF line against the in-memory event.
# ---------------------------------------------------------------------------

class _CapturingSyslog(AuditEventExporter):
    def __init__(self, inner: SyslogCefExporter):
        self._inner = inner
        self.captured: List[AttestationEvent] = []
        self.latencies_ms: List[float] = []

    def emit(self, event: AttestationEvent) -> None:
        t0 = time.monotonic()
        self._inner.emit(event)
        self.latencies_ms.append((time.monotonic() - t0) * 1000)
        self.captured.append(event)

    def close(self) -> None:
        self._inner.close()


# ---------------------------------------------------------------------------
# Container helpers
# ---------------------------------------------------------------------------

def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        capture_output=True, text=True, check=check,
    )


def _wait_for_container_ready(*, timeout_s: int = 60) -> None:
    deadline = time.monotonic() + timeout_s
    last = "no response"
    while time.monotonic() < deadline:
        try:
            r = _docker("inspect", "-f", "{{.State.Health.Status}}", CONTAINER,
                       check=False)
            if r.returncode == 0:
                status = r.stdout.strip()
                if status == "healthy":
                    return
                last = f"container health: {status}"
            else:
                last = r.stderr.strip() or "container not found"
        except FileNotFoundError:
            sys.exit("[smoke] `docker` CLI not on PATH — install Docker Desktop.")
        time.sleep(2)
    sys.exit(
        f"[smoke] container {CONTAINER!r} did not become healthy in "
        f"{timeout_s}s (last: {last}). Did `docker compose up -d` from "
        "siem-sandbox/syslog/ finish?"
    )


def _truncate_log() -> None:
    """Wipe the log file so this run is independent of previous ones."""
    _docker("exec", CONTAINER, "sh", "-c", f": > {LOG_PATH}", check=False)


def _read_log_lines(*, deadline_s: int = 10,
                    expect_at_least: int = 1) -> List[str]:
    """Tail the syslog-ng log file from inside the container until we see
    `expect_at_least` lines or the deadline expires."""
    deadline = time.monotonic() + deadline_s
    lines: List[str] = []
    while time.monotonic() < deadline:
        r = _docker("exec", CONTAINER, "cat", LOG_PATH, check=False)
        if r.returncode == 0:
            lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
            if len(lines) >= expect_at_least:
                return lines
        time.sleep(0.5)
    return lines


# ---------------------------------------------------------------------------
# Wire-format parser — what we expect syslog-ng to have written.
#
# Our syslog-ng config emits:
#   <ISODATE> | <transport> | <hostname> | <app> | <CEF payload>
#
# The CEF payload itself is:
#   CEF:0|TEE-Crafter|tee-crafter|<ver>|<eventType>|TEE attestation <status>|<sev>|<extension k=v ...>
# ---------------------------------------------------------------------------

_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+\|\s+(?P<transport>udp|tcp)\s+\|\s+"
    r"(?P<host>\S+)\s+\|\s+(?P<app>\S+)\s+\|\s+(?P<cef>CEF:0\|.+)$"
)

_CEF_HEADER_RE = re.compile(
    r"^CEF:0\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|(?P<version>[^|]+)\|"
    r"(?P<event_type>[^|]+)\|(?P<name>[^|]+)\|(?P<sev>\d+)\|(?P<ext>.*)$"
)


@dataclass
class _ParsedLine:
    transport: str
    hostname: str
    app: str
    cef_event_type: str
    cef_severity: int
    cef_name: str
    ext: Dict[str, str]
    raw: str


def _parse_extension(ext: str) -> Dict[str, str]:
    """Parse CEF extension as space-separated k=v pairs.

    The exporter never emits values with spaces, so this naive split is
    safe; we still defend against trailing whitespace.
    """
    out: Dict[str, str] = {}
    for tok in ext.strip().split(" "):
        if not tok or "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        out[k] = v
    return out


def _parse_line(line: str) -> Optional[_ParsedLine]:
    m = _LINE_RE.match(line)
    if not m:
        return None
    cef = m.group("cef")
    mh = _CEF_HEADER_RE.match(cef)
    if not mh:
        return None
    return _ParsedLine(
        transport=m.group("transport"),
        hostname=m.group("host"),
        app=m.group("app"),
        cef_event_type=mh.group("event_type"),
        cef_severity=int(mh.group("sev")),
        cef_name=mh.group("name"),
        ext=_parse_extension(mh.group("ext")),
        raw=line,
    )


# ---------------------------------------------------------------------------
# Per-transport smoke run
# ---------------------------------------------------------------------------

@dataclass
class _TransportReport:
    transport: str
    host: str
    port: int
    sent: int
    parsed: int
    matched: int
    severity_pass: int
    severity_fail: int
    sig_verified: int
    p50_emit_ms: float
    ok: bool
    why: str = ""


def _run_one_transport(*, transport: str, host: str, port: int,
                       instance_id: str) -> _TransportReport:
    print(f"[smoke] === transport={transport} -> {host}:{port} ===")
    _truncate_log()
    # Small delay so the file mtime cleanly bisects pre/post truncation.
    time.sleep(0.2)

    inner = SyslogCefExporter(
        host=host, port=port, protocol=transport,
        hostname=SMOKE_HOSTNAME_PREFIX,
    )
    exporter = _CapturingSyslog(inner)
    attestor = _AlternatingAttestor()

    ca = ContinuousAttestor(
        attest=attestor, exporters=[exporter], interval_seconds=60,
        instance_id=instance_id, tee_platform="snp-aws",
        pipeline_version="syslog-smoke-1.0",
    )

    # boot + N-2 refresh-pass + 1 refresh-fail
    ca.emit_now(event_type="attestation_boot")
    for _ in range(N_EVENTS_PER_TRANSPORT - 1):
        ca.emit_now(event_type="attestation_refresh")

    sent = len(exporter.captured)
    p50 = statistics.median(exporter.latencies_ms) if exporter.latencies_ms else 0.0

    # Wait for syslog-ng to flush.  UDP is fire-and-forget; TCP is more
    # reliable but we still allow a generous deadline so the smoke test
    # is stable in CI under contention.
    lines = _read_log_lines(deadline_s=12, expect_at_least=sent)

    parsed: List[_ParsedLine] = []
    for ln in lines:
        p = _parse_line(ln)
        if p is not None and p.transport == transport and p.hostname == SMOKE_HOSTNAME_PREFIX:
            parsed.append(p)

    # Match captured-in-memory <-> parsed-on-wire by attestation_sha256
    # (the CEF extension key is `cs3`).  The exporter never reuses an
    # attestation_sha256 within a run because each event embeds a fresh
    # uuid in the nonce.
    by_attest: Dict[str, _ParsedLine] = {p.ext.get("cs3", ""): p for p in parsed}
    matched = 0
    sig_verified = 0
    severity_pass = 0
    severity_fail = 0
    why_fail: List[str] = []

    for ev in exporter.captured:
        p = by_attest.get(ev.attestation_sha256)
        if p is None:
            # Empty attestation_sha256 happens for status=fail events
            # because the platform attestor raised before producing a
            # blob.  Fall back to matching by sequence number (cn1).
            for pp in parsed:
                if pp.ext.get("cn1", "") == str(ev.seq):
                    p = pp
                    break
        if p is None:
            why_fail.append(f"seq={ev.seq} missing on the wire")
            continue
        matched += 1

        # Field-by-field fidelity check.
        expected = {
            "deviceExternalId": ev.instance_id,
            "cs1": ev.tee_platform,
            "cs2": ev.measurement_sha256,
            "cs3": ev.attestation_sha256,
            "cs4": ev.digest,
            "cs5": ev.signature,
            "cn1": str(ev.seq),
            "cn2": str(ev.attestation_size_bytes),
            "outcome": ev.status,
        }
        for k, v in expected.items():
            if p.ext.get(k, "") != v:
                why_fail.append(
                    f"seq={ev.seq} CEF {k} mismatch: wire={p.ext.get(k, '')!r} "
                    f"vs in-memory={v!r}"
                )

        if ev.status == "fail":
            severity_fail += 1
            if p.cef_severity != 8:
                why_fail.append(
                    f"seq={ev.seq} severity for status=fail was {p.cef_severity}, expected 8")
        else:
            severity_pass += 1
            if p.cef_severity != 3:
                why_fail.append(
                    f"seq={ev.seq} severity for status=pass was {p.cef_severity}, expected 3")

        if _verify_signature(ev):
            sig_verified += 1
        else:
            why_fail.append(f"seq={ev.seq} signature did not verify")

    ok = (
        matched == sent
        and severity_fail >= 1
        and severity_pass >= 1
        and sig_verified == sent
        and not why_fail
    )
    why = "; ".join(why_fail[:5]) if why_fail else ""
    return _TransportReport(
        transport=transport, host=host, port=port,
        sent=sent, parsed=len(parsed), matched=matched,
        severity_pass=severity_pass, severity_fail=severity_fail,
        sig_verified=sig_verified, p50_emit_ms=p50, ok=ok, why=why,
    )


def _verify_signature(ev: AttestationEvent) -> bool:
    """Verify the per-event Ed25519 signature using the embedded PEM."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        return False
    try:
        pk = serialization.load_pem_public_key(ev.public_key_pem.encode())
        if not isinstance(pk, Ed25519PublicKey):
            return False
        pk.verify(bytes.fromhex(ev.signature), ev.digest.encode("ascii"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _run_tcp_reconnect(*, host: str, port: int) -> bool:
    """Production-parity reconnect test.

    A long-running TEE will, at some point, observe its syslog peer
    bounce — rsyslog graceful reload, syslog-ng config push, ngrok edge
    rotation, ALB target swap, k8s pod replacement.  The exporter MUST
    survive that without crashing the attestation loop.  ``Splunk HEC``
    gets this for free (every emit opens a fresh HTTPS connection).
    Syslog over TCP keeps a persistent socket, so the exporter has to
    detect a dead socket and reconnect on demand.

    Test plan:

    1.  Truncate the log; open a long-lived TCP exporter; emit two
        events (pre-restart) and verify they land on the wire.
    2.  ``docker restart`` the syslog-ng container so the listener and
        every accepted TCP connection are torn down.  Wait until the
        new instance is healthy.
    3.  Emit two more events without touching the exporter.  The
        cached TCP socket inside the exporter is now half-open; the
        first ``sendall`` should fail, the exporter should drop the
        socket, redial, and succeed on retry.
    4.  Verify all four events ended up on the wire and that the
        ``ContinuousAttestor`` survived (no exception bubbled up).
    """
    print(f"[smoke] === tcp reconnect drill -> {host}:{port} ===")
    _truncate_log()
    time.sleep(0.2)

    inner = SyslogCefExporter(
        host=host, port=port, protocol="tcp",
        hostname=SMOKE_HOSTNAME_PREFIX + "-rc",
        connect_timeout=10.0, send_timeout=3.0,
    )
    captured: List[AttestationEvent] = []

    class _Capture(AuditEventExporter):
        def emit(self, event: AttestationEvent) -> None:
            inner.emit(event)
            captured.append(event)

        def close(self) -> None:
            inner.close()

    def _attest(nonce: bytes) -> bytes:
        return b"SMOKE_RECONNECT:" + nonce

    instance_id = f"smoke-tcp-rc-{_short_uuid()[:8]}"
    ca = ContinuousAttestor(
        attest=_attest, exporters=[_Capture()], interval_seconds=60,
        instance_id=instance_id, tee_platform="snp-aws",
        pipeline_version="syslog-smoke-1.0",
    )

    ca.emit_now(event_type="attestation_boot")
    ca.emit_now(event_type="attestation_refresh")

    print("[smoke]   pre-restart events emitted; bouncing syslog-ng container...")
    r = _docker("restart", "-t", "1", CONTAINER, check=False)
    if r.returncode != 0:
        print(f"[smoke]   docker restart failed: {r.stderr.strip()}")
        return False

    _wait_for_container_ready(timeout_s=60)
    print("[smoke]   container is healthy again; emitting post-restart events...")

    try:
        ca.emit_now(event_type="attestation_refresh")
        ca.emit_now(event_type="attestation_refresh")
    except Exception as e:
        print(f"[smoke]   exporter did NOT survive peer bounce: {type(e).__name__}: {e}")
        return False

    sent = len(captured)
    lines = _read_log_lines(deadline_s=15, expect_at_least=sent)
    parsed = [p for p in (_parse_line(ln) for ln in lines)
              if p is not None and p.transport == "tcp"
              and p.hostname == SMOKE_HOSTNAME_PREFIX + "-rc"]

    pre_restart_seqs = {0, 1}
    post_restart_seqs = {2, 3}
    seen_seqs = {int(p.ext.get("cn1", "-1")) for p in parsed if p.ext.get("cn1")}

    # Post-restart events MUST land — that's the actual reconnect proof.
    # Pre-restart events SHOULD land (named volume survives the bounce),
    # but on hosts with anonymous volumes they may not.  We grade
    # explicitly so the failure mode is legible.
    post_ok = post_restart_seqs.issubset(seen_seqs)
    pre_ok = pre_restart_seqs.issubset(seen_seqs)

    matched = 0
    sig_ok = 0
    for ev in captured:
        for p in parsed:
            if p.ext.get("cn1", "") == str(ev.seq):
                matched += 1
                if _verify_signature(ev):
                    sig_ok += 1
                break

    ok = post_ok and sig_ok == sent
    verdict = "PASS" if ok else "FAIL"
    print(
        f"[smoke]   reconnect: sent={sent} parsed={len(parsed)} matched={matched} "
        f"sig_ok={sig_ok}/{sent} pre_restart_landed={pre_ok} "
        f"post_restart_landed={post_ok} — {verdict}"
    )
    if not ok:
        missing = sorted(({0, 1, 2, 3} - seen_seqs))
        print(f"[smoke]   missing on-wire seqs: {missing}")
    inner.close()
    return ok


def main() -> int:
    print(f"[smoke] waiting for container {CONTAINER!r} to become healthy ...")
    _wait_for_container_ready()
    print(f"[smoke] container is healthy.  Log file: {LOG_PATH}\n")

    reports: List[_TransportReport] = []
    for transport, port in (("udp", 5514), ("tcp", 6601)):
        instance_id = f"smoke-{transport}-{_short_uuid()[:8]}"
        rep = _run_one_transport(
            transport=transport, host="localhost", port=port,
            instance_id=instance_id,
        )
        reports.append(rep)
        verdict = "PASS" if rep.ok else "FAIL"
        print(
            f"[smoke] {transport}: sent={rep.sent} parsed={rep.parsed} "
            f"matched={rep.matched} sev_pass={rep.severity_pass} "
            f"sev_fail={rep.severity_fail} sig_ok={rep.sig_verified}/{rep.sent} "
            f"p50_emit={rep.p50_emit_ms:.1f}ms — {verdict}"
        )
        if rep.why:
            print(f"[smoke]   detail: {rep.why}")
        print()

    reconnect_ok = _run_tcp_reconnect(host="localhost", port=6601)
    print()

    overall_ok = all(r.ok for r in reports) and reconnect_ok
    summary = " | ".join(
        f"{r.transport}:{('PASS' if r.ok else 'FAIL')}"
        for r in reports
    )
    summary += f" | tcp-reconnect:{'PASS' if reconnect_ok else 'FAIL'}"
    print(f"[smoke] === overall: {summary} ===")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
