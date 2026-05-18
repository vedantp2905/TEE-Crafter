"""In-TEE runtime glue for the persistent RA-TLS service mode.

This file is staged verbatim into per-platform template trees so the
running enclave/CVM imports the SAME ``ServicePolicy`` /
``CertRotator`` / ``ConnectionAttestor`` classes the build host validated
against.  The platform template provides three pluggable callables and
this module wires them into a steady-state runtime:

* ``run_attestation(spki_digest: bytes) -> bytes``
    returns the platform-native attestation blob (Nitro doc, SNP report,
    TDX quote, Azure ATR, GCP attestation token, ...) bound to the
    32-byte SPKI digest.

* ``issue_cert(seed: bytes, spki_digest: bytes) -> tuple[bytes, bytes]``
    returns ``(cert_pem, spki_pub_bytes)``.  The cert MUST embed the
    attestation blob in a custom OID extension that the client RA-TLS
    verifier understands.

* ``platform_attest_now() -> bool``
    cheap re-attestation probe used per-connection (often a thin wrapper
    around the same closure as ``run_attestation``).

Everything else — TTL bookkeeping, history, callbacks, env-driven config
— is the responsibility of :mod:`tee_crafter.core.service`, which is
shipped alongside this file inside the build artifact.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Callable, Optional, Tuple

logger = logging.getLogger("tee_crafter.service_runtime")

try:
    from tee_crafter.core.service import (
        CertRotator, CertRotationConfig,
        ConnectionAttestor, ReattestPolicy,
        ServicePolicy, OnAttestationFailure,
    )
except ImportError:  # pragma: no cover
    # When running inside a stripped TEE that does not have the full
    # tee_crafter package staged, fall back to the local copies that the
    # builder will have placed next to this file.
    sys.path.insert(0, os.path.dirname(__file__))
    from cert_rotation import CertRotator, CertRotationConfig  # type: ignore[no-redef]
    from reattest import ConnectionAttestor, ReattestPolicy  # type: ignore[no-redef]
    from policy import ServicePolicy, OnAttestationFailure  # type: ignore[no-redef]


# Kept in step with tee_crafter.core.env_flags by
# tests/core/test_env_flag_consistency.py.  This file is staged onto the
# instance and cannot import the package.
_TRUTHY = ("1", "true", "yes", "y", "on")
_FALSY = ("0", "false", "no", "n", "off")


def _bool_env(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").strip().lower()
    if v in _TRUTHY:
        return True
    if v in _FALSY:
        return False
    return default


def _on_failure_to_reattest_policy(of: OnAttestationFailure) -> ReattestPolicy:
    if of == OnAttestationFailure.HARD_STOP:
        return ReattestPolicy.HARD_STOP
    if of == OnAttestationFailure.WARN:
        return ReattestPolicy.WARN
    return ReattestPolicy.DRAIN


def build_runtime(
    *,
    run_attestation: Callable[[bytes], bytes],
    issue_cert: Callable[[bytes, bytes], Tuple[bytes, bytes]],
    platform_attest_now: Optional[Callable[[], bool]] = None,
    policy: Optional[ServicePolicy] = None,
):
    """Construct the rotator + attestor pair for a platform template.

    Returns a small dataclass-like object (a plain dict for zero-import
    overhead) that platform templates plug into their TLS server.
    """
    p = policy if policy is not None else ServicePolicy.from_env()
    errs = p.validate()
    if errs:
        raise ValueError("Invalid ServicePolicy: " + "; ".join(errs))

    rotator = CertRotator(
        attest=run_attestation,
        issue_cert=issue_cert,
        cfg=CertRotationConfig(
            ttl_seconds=p.cert_ttl_seconds,
            grace_seconds=p.cert_grace_seconds,
            pre_rotate_seconds=max(1, min(p.cert_ttl_seconds // 10, 300)),
        ),
    )

    if platform_attest_now is None:
        # If the platform did not provide a cheap probe, fall back to a
        # full attestation against a dummy SPKI; this is safe but slow.
        def platform_attest_now() -> bool:
            try:
                blob = run_attestation(b"\x00" * 32)
                return bool(blob)
            except Exception:
                return False

    attestor = ConnectionAttestor(
        attest_now=platform_attest_now,
        interval_seconds=p.reattest_interval_seconds,
        grace_seconds=p.reattest_grace_seconds,
        policy=_on_failure_to_reattest_policy(p.on_failure),
        max_tracked_connections=p.max_concurrent_connections * 2,
    )

    def _on_rotate(rc):
        logger.info("RA-TLS rotated seq=%d spki=%s exp=%d", rc.seq,
                    rc.spki_sha256[:12], int(rc.expires_at))
        for hook in p.extra_attestation_hooks:
            try:
                mod_name, func_name = hook.rsplit(".", 1)
                mod = __import__(mod_name, fromlist=[func_name])
                getattr(mod, func_name)(rc)
            except Exception as exc:
                logger.warning("rotation hook %s failed: %s", hook, exc)

    rotator.on_rotate(_on_rotate)
    rotator.on_error(lambda exc: logger.error("rotator error: %r", exc))

    return {
        "policy": p,
        "rotator": rotator,
        "attestor": attestor,
    }


def reattest_or_close(attestor, conn_id: str, *, on_close: Callable[[str], None]) -> bool:
    """Convenience wrapper for HTTP/2 / WebSocket request handlers.

    Returns True when the request may proceed.  When False, *on_close* is
    called with the failure reason and the caller should bail out
    (close stream / return 401 with a re-attestation hint).
    """
    res = attestor.check(conn_id)
    if not res.ok:
        try:
            on_close(res.reason or "re-attestation failed")
        except Exception:
            logger.exception("on_close handler raised")
        return False
    return True
