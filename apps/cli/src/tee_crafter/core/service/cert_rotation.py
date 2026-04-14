"""TTL-driven RA-TLS certificate rotation.

The single-shot RA-TLS template generates one cert at boot and never
re-issues.  Any persistent service must rotate on a regular cadence so a
freshly-attested SPKI is always being presented to new connections.

This module is platform-agnostic.  Per-platform templates inject a small
``attest_callable(spki_sha256: bytes) -> bytes`` closure that returns the
hardware quote / SNP report / Nitro doc with the supplied SPKI hash bound
into ``report_data`` (or the platform equivalent).  Everything else
— private key generation, X.509 wrapping, TTL enforcement, grace-period
overlap — is handled here so it can be unit tested on any laptop.
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple


AttestCallable = Callable[[bytes], bytes]


@dataclass
class CertRotationConfig:
    ttl_seconds: int = 3600
    grace_seconds: int = 300
    """How long the *previous* cert is still considered acceptable for
    in-flight connections after a rotation (so long-lived TLS sessions do
    not abort)."""

    pre_rotate_seconds: int = 60
    """How early before the TTL elapses the rotator should attempt to mint
    a new cert.  Avoids mass connection drops the moment a cert expires."""

    max_history: int = 4
    """Keep the N most recent rotated certs in memory for verifier audit
    trails and for the grace-period acceptance window."""

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.ttl_seconds <= 0:
            errors.append("ttl_seconds must be > 0")
        if self.grace_seconds < 0:
            errors.append("grace_seconds must be >= 0")
        if self.pre_rotate_seconds < 0:
            errors.append("pre_rotate_seconds must be >= 0")
        if self.pre_rotate_seconds >= self.ttl_seconds:
            errors.append("pre_rotate_seconds must be < ttl_seconds")
        if self.max_history < 1:
            errors.append("max_history must be >= 1")
        return errors


@dataclass(frozen=True)
class RotatedCert:
    """Snapshot of one rotation cycle's output."""
    seq: int
    issued_at: float
    expires_at: float
    spki_sha256: str
    cert_pem: bytes
    attestation_blob: bytes
    attestation_sha256: str = field(default="")

    def is_active(self, now: Optional[float] = None) -> bool:
        n = now if now is not None else time.time()
        return self.issued_at <= n < self.expires_at

    def is_in_grace(self, grace: int, now: Optional[float] = None) -> bool:
        n = now if now is not None else time.time()
        return self.expires_at <= n < (self.expires_at + grace)


class CertRotator:
    """Thread-safe RA-TLS cert rotator.

    The rotator does NOT manage TLS listeners; it only mints freshly
    attested certs and exposes the current and recently-retired bundles
    so the calling service can swap them into its TLS context.

    Typical use inside a TEE template::

        rotator = CertRotator(
            attest=_run_platform_attestation,
            issue_cert=_issue_x509_for_spki,
            cfg=CertRotationConfig(ttl_seconds=3600),
        )
        rotator.start()        # background timer thread
        ...
        ctx.set_cert(rotator.current().cert_pem)

    For unit tests, callers can drive the rotator manually with
    :meth:`rotate_now`.
    """

    def __init__(
        self,
        attest: AttestCallable,
        issue_cert: Callable[[bytes, bytes], Tuple[bytes, bytes]],
        cfg: Optional[CertRotationConfig] = None,
        *,
        clock: Callable[[], float] = time.time,
    ):
        """
        :param attest: closure that takes a 32-byte SHA-256 SPKI digest and
            returns the platform attestation blob.  The blob will be
            hashed and stored alongside the cert; verification of the
            ``report_data`` <-> SPKI binding is the platform template's
            responsibility (we don't reach into the blob format here).
        :param issue_cert: closure that takes (private_key_seed_bytes,
            spki_sha256) and returns ``(cert_pem, spki_pub_bytes)``.  The
            seed bytes are guaranteed to be cryptographically random and
            distinct per rotation.
        :param cfg: rotation timing configuration.
        :param clock: monotonic-ish clock (defaults to ``time.time`` so it
            matches certificate ``notBefore`` / ``notAfter``).
        """
        self.cfg = cfg or CertRotationConfig()
        errs = self.cfg.validate()
        if errs:
            raise ValueError("Invalid CertRotationConfig: " + "; ".join(errs))

        self._attest = attest
        self._issue_cert = issue_cert
        self._clock = clock
        self._lock = threading.RLock()
        self._history: List[RotatedCert] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._next_seq = 0
        self._on_rotate: Optional[Callable[[RotatedCert], None]] = None
        self._on_error: Optional[Callable[[BaseException], None]] = None

    # ---- public API ----

    def on_rotate(self, cb: Callable[[RotatedCert], None]) -> "CertRotator":
        self._on_rotate = cb
        return self

    def on_error(self, cb: Callable[[BaseException], None]) -> "CertRotator":
        self._on_error = cb
        return self

    def current(self) -> Optional[RotatedCert]:
        with self._lock:
            return self._history[-1] if self._history else None

    def history(self) -> List[RotatedCert]:
        with self._lock:
            return list(self._history)

    def is_acceptable(self, spki_sha256: str, *, now: Optional[float] = None) -> bool:
        """Return True if a TLS session presenting *spki_sha256* should be
        considered authentic right now (current cert OR a recently retired
        cert still inside its grace window)."""
        with self._lock:
            for rc in reversed(self._history):
                if rc.spki_sha256 != spki_sha256:
                    continue
                if rc.is_active(now):
                    return True
                if rc.is_in_grace(self.cfg.grace_seconds, now):
                    return True
                return False
            return False

    def rotate_now(self, *, seed: Optional[bytes] = None) -> RotatedCert:
        """Force an immediate rotation; returns the new cert.  Safe to
        call concurrently — only one rotation runs at a time per rotator.
        """
        with self._lock:
            now = self._clock()
            seed = seed if seed is not None else _rand_bytes(32)
            # Pre-compute SPKI by issuing the cert; the issuer returns the
            # raw SPKI bytes so we can hash them and feed the digest into
            # attestation, then re-issue with the binding.  In practice
            # platform templates do "issue once, attest once" since the
            # SPKI is determined by the seed.
            cert_pem, spki_bytes = self._issue_cert(seed, b"\x00" * 32)
            spki_digest = hashlib.sha256(spki_bytes).digest()
            attestation_blob = self._attest(spki_digest)
            attestation_sha = hashlib.sha256(attestation_blob).hexdigest()
            # Re-issue including the binding so the cert content references
            # the attestation-validated SPKI.  Implementations that already
            # accept the spki_digest as report_data can collapse this back
            # into a single call; the no-op default is fine for tests.
            cert_pem, spki_bytes2 = self._issue_cert(seed, spki_digest)
            # SPKI must remain stable across the two calls; if not, that's
            # a bug in the issuer closure.
            spki_digest2 = hashlib.sha256(spki_bytes2).digest()
            if spki_digest != spki_digest2:
                raise RuntimeError(
                    "issue_cert returned a different SPKI on re-issue; the "
                    "closure must be deterministic w.r.t. the seed."
                )
            rc = RotatedCert(
                seq=self._next_seq,
                issued_at=now,
                expires_at=now + self.cfg.ttl_seconds,
                spki_sha256=spki_digest.hex(),
                cert_pem=cert_pem,
                attestation_blob=attestation_blob,
                attestation_sha256=attestation_sha,
            )
            self._next_seq += 1
            self._history.append(rc)
            # Trim history but always keep at least the current + grace.
            if len(self._history) > self.cfg.max_history:
                self._history = self._history[-self.cfg.max_history:]
        # Fire callback outside the lock to avoid recursive deadlocks.
        if self._on_rotate is not None:
            try:
                self._on_rotate(rc)
            except Exception as exc:  # pragma: no cover - callback errors shouldn't crash rotator
                if self._on_error is not None:
                    try:
                        self._on_error(exc)
                    except Exception:
                        pass
        return rc

    def start(self) -> None:
        """Start the background rotation thread.  No-op if already running."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name="tee-crafter-cert-rotator", daemon=True)
            self._thread.start()

    def stop(self, *, timeout: Optional[float] = 5.0) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout)
        self._thread = None

    # ---- internals ----

    def _run(self) -> None:
        # First rotation immediately so the service has a cert before
        # accepting connections.
        try:
            self.rotate_now()
        except Exception as exc:  # pragma: no cover
            if self._on_error is not None:
                try:
                    self._on_error(exc)
                except Exception:
                    pass
        while not self._stop.is_set():
            cur = self.current()
            if cur is None:
                # Failed initial rotation; retry quickly.
                self._stop.wait(1.0)
                continue
            now = self._clock()
            sleep_for = max(
                1.0,
                cur.expires_at - now - float(self.cfg.pre_rotate_seconds),
            )
            if self._stop.wait(sleep_for):
                return
            try:
                self.rotate_now()
            except Exception as exc:
                if self._on_error is not None:
                    try:
                        self._on_error(exc)
                    except Exception:
                        pass
                # Back off briefly; do not crash the loop.
                self._stop.wait(min(30.0, max(1.0, self.cfg.pre_rotate_seconds / 2)))


def _rand_bytes(n: int) -> bytes:
    import os as _os
    return _os.urandom(n)
