"""Continuous attestation refresh with SIEM-ready signed events.

The single-shot ``build_provenance.json`` artifact captures everything
that happened during the build/deploy.  Once the workload is running,
auditors increasingly want a *streaming* trail: a tamper-evident
sequence of attestation events flowing into Splunk / Datadog / Sentinel
/ CloudWatch / generic syslog so a SOC can alert on attestation gaps.

This module provides:

* :class:`AttestationEvent` — canonical event schema.
* :class:`ContinuousAttestor` — periodically calls a platform attestation
  closure, hash-chains the resulting events with the previous event's
  digest, signs each event with a per-instance Ed25519 key, and fans the
  signed JSON out to one or more :class:`AuditEventExporter` sinks.
* :class:`InMemoryExporter` — handy for unit tests / health probes.

Concrete cloud exporters live in :mod:`tee_crafter.core.audit.exporters`.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger("tee_crafter.audit.continuous")

# The wire format is owned by the self-contained sidecar module, which is
# the copy that has to survive on a stripped CVM.  Importing it here (and
# in the verify-siem-chain command) keeps producer and verifier on one
# definition instead of three hand-rolled ones that disagreed.  The
# sibling fallback covers stripped TEEs where this file was copied next
# to ``siem_export.py`` without the ``tee_crafter`` package.
try:  # pragma: no cover - exercised only in stripped-TEE layouts
    from tee_crafter.templates.common.siem_export import (
        EVENT_SCHEMA_VERSION,
        GENESIS_PREV_DIGEST,
        SUPPORTED_SCHEMA_VERSIONS,
        canonical_digest_payload,
        compute_digest,
    )
except ImportError:  # pragma: no cover
    from siem_export import (  # type: ignore
        EVENT_SCHEMA_VERSION,
        GENESIS_PREV_DIGEST,
        SUPPORTED_SCHEMA_VERSIONS,
        canonical_digest_payload,
        compute_digest,
    )


@dataclass
class AttestationEvent:
    """One row in the continuous attestation feed."""
    event_id: str
    seq: int
    event_type: str
    timestamp: str
    """ISO-8601 UTC, suffix Z."""
    pipeline_version: str
    instance_id: str
    tee_platform: str
    measurement_sha256: str
    attestation_sha256: str
    attestation_size_bytes: int
    status: str
    """``pass`` / ``fail`` / ``warn``."""
    prev_digest: str
    schema_version: int = EVENT_SCHEMA_VERSION
    """Wire-format version; covered by ``digest`` so a verifier can
    reject a format it does not understand."""
    digest: str = ""
    """SHA-256 over canonical JSON of all fields except ``digest`` and
    ``signature`` — see
    :func:`tee_crafter.templates.common.siem_export.canonical_digest_payload`."""
    signature: str = ""
    """Hex-encoded Ed25519 signature over ``digest``."""
    public_key_pem: str = ""
    """PEM-encoded Ed25519 public key for the signing key.  Repeated on
    every event to make individual events self-verifying when shipped to
    SIEM tools that drop the rest of the stream."""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


class AuditEventExporter:
    """Base class for SIEM exporters.  Subclasses implement :meth:`emit`."""

    def emit(self, event: AttestationEvent) -> None:
        raise NotImplementedError

    def emit_many(self, events: Sequence[AttestationEvent]) -> None:
        for ev in events:
            try:
                self.emit(ev)
            except Exception:
                logger.exception("exporter %s failed to emit event %s",
                                  self.__class__.__name__, ev.event_id)

    def close(self) -> None:  # pragma: no cover - default no-op
        pass


class InMemoryExporter(AuditEventExporter):
    """Test/diagnostic exporter; keeps the last N events in memory."""

    def __init__(self, *, max_events: int = 1000):
        self.events: List[AttestationEvent] = []
        self._max = max_events

    def emit(self, event: AttestationEvent) -> None:
        self.events.append(event)
        if len(self.events) > self._max:
            self.events = self.events[-self._max:]


class ContinuousAttestor:
    """Periodically re-attests the running TEE and ships signed events.

    Threading model: a single background daemon thread drives the
    refresh loop.  The loop is best-effort — if the platform attestor
    or a sink fails, we log and keep going.  The hash chain remains
    intact because we always update ``prev_digest`` only on successful
    event construction (failures emit a ``status='fail'`` event with the
    error captured in ``extra``).
    """

    def __init__(
        self,
        *,
        attest: Callable[[bytes], bytes],
        exporters: Sequence[AuditEventExporter],
        interval_seconds: int = 300,
        instance_id: str = "",
        tee_platform: str = "",
        pipeline_version: str = "",
        signing_key=None,
        clock: Callable[[], float] = time.time,
        on_error: Optional[Callable[[BaseException], None]] = None,
    ):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        if not exporters:
            raise ValueError("at least one exporter required")
        self._attest = attest
        self._exporters = list(exporters)
        self.interval = interval_seconds
        self.instance_id = instance_id or _short_uuid()
        self.tee_platform = tee_platform or "unknown"
        self.pipeline_version = pipeline_version
        self._clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._next_seq = 0
        self._prev_digest = GENESIS_PREV_DIGEST
        self._on_error = on_error
        self._signer = signing_key if signing_key is not None else _Ed25519Signer()

    # ---- public API ----

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name="tee-crafter-continuous-attest",
                daemon=True)
            self._thread.start()

    def stop(self, *, timeout: float = 5.0) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout)
        self._thread = None
        for exp in self._exporters:
            try:
                exp.close()
            except Exception:
                pass

    def emit_now(self, *, event_type: str = "attestation_refresh",
                 extra: Optional[Dict[str, Any]] = None) -> AttestationEvent:
        """Synchronously run one attestation refresh + emit.  Useful for
        unit tests and for hand-fired events (e.g. on key rotation)."""
        nonce = _short_uuid().encode()
        try:
            blob = self._attest(nonce)
            status = "pass"
            err = ""
        except Exception as exc:
            blob = b""
            status = "fail"
            err = repr(exc)
        return self._build_and_emit(blob, event_type, status, extra, error=err)

    def hash_chain_head(self) -> str:
        with self._lock:
            return self._prev_digest

    # ---- internals ----

    def _run(self) -> None:
        # Fire one event immediately so SIEM has a heartbeat as soon as
        # the service starts.
        try:
            self.emit_now(event_type="attestation_boot")
        except Exception as exc:
            if self._on_error:
                try: self._on_error(exc)
                except Exception: pass
        while not self._stop.is_set():
            if self._stop.wait(self.interval):
                return
            try:
                self.emit_now(event_type="attestation_refresh")
            except Exception as exc:
                if self._on_error:
                    try: self._on_error(exc)
                    except Exception: pass

    def _build_and_emit(
        self, blob: bytes, event_type: str, status: str,
        extra: Optional[Dict[str, Any]], *, error: str = "",
    ) -> AttestationEvent:
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            prev = self._prev_digest

        merged_extra = dict(extra or {})
        if error:
            merged_extra["error"] = error

        ev = AttestationEvent(
            event_id=_short_uuid(),
            seq=seq,
            event_type=event_type,
            timestamp=_iso_now(self._clock()),
            pipeline_version=self.pipeline_version,
            instance_id=self.instance_id,
            tee_platform=self.tee_platform,
            measurement_sha256=hashlib.sha256(blob[:128]).hexdigest() if blob else "",
            attestation_sha256=hashlib.sha256(blob).hexdigest() if blob else "",
            attestation_size_bytes=len(blob),
            status=status,
            prev_digest=prev,
            public_key_pem=self._signer.public_key_pem(),
            extra=merged_extra,
        )
        ev.digest = self._compute_digest(ev)
        ev.signature = self._signer.sign(ev.digest.encode("ascii")).hex()

        with self._lock:
            self._prev_digest = ev.digest

        for exp in self._exporters:
            try:
                exp.emit(ev)
            except Exception as exc:
                logger.warning("exporter %s failed: %r",
                                exp.__class__.__name__, exc)
                if self._on_error:
                    try: self._on_error(exc)
                    except Exception: pass
        return ev

    @staticmethod
    def _compute_digest(ev: AttestationEvent) -> str:
        return compute_digest(asdict(ev))

    # Verification helpers (used by tests + the verify CLI):

    @staticmethod
    def verify_chain(events: Sequence[AttestationEvent]) -> List[str]:
        errs: List[str] = []
        prev = GENESIS_PREV_DIGEST
        for i, ev in enumerate(events):
            if ev.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
                errs.append(
                    f"event[{i}]: unsupported schema_version "
                    f"{ev.schema_version!r} (supported: "
                    f"{sorted(SUPPORTED_SCHEMA_VERSIONS)})")
                # Do not attempt a digest compare against a format we do
                # not understand — that is exactly how a mis-verify
                # becomes a silent pass.
                prev = ev.digest
                continue
            if ev.prev_digest != prev:
                errs.append(f"event[{i}]: prev_digest mismatch")
            if ContinuousAttestor._compute_digest(ev) != ev.digest:
                errs.append(f"event[{i}]: digest mismatch")
            prev = ev.digest
        return errs


# ---- helpers ----

def _short_uuid() -> str:
    return uuid.uuid4().hex


def _iso_now(t: float) -> str:
    return _dt.datetime.fromtimestamp(t, tz=_dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


class _Ed25519Signer:
    """Tiny Ed25519 wrapper used when caller doesn't pass their own key."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        self._sk = Ed25519PrivateKey.generate()
        self._pem = self._sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    def public_key_pem(self) -> str:
        return self._pem


__all__ = [
    "AttestationEvent",
    "AuditEventExporter",
    "ContinuousAttestor",
    "InMemoryExporter",
    # Re-exported from the sidecar module so callers of the core module do
    # not have to reach into ``tee_crafter.templates.common`` to hash an
    # event the same way the producer did.
    "EVENT_SCHEMA_VERSION",
    "GENESIS_PREV_DIGEST",
    "SUPPORTED_SCHEMA_VERSIONS",
    "canonical_digest_payload",
    "compute_digest",
]
