"""BYOK in-enclave fail-closed gate (mirrors :mod:`siem_health`).

When the operator opts into BYOK, the customer-managed DEK is released exactly
once at boot by the attestation-gated bootstrap (the CVM
``tee-crafter-secrets.service`` oneshot, or the in-process
``bootstrap_byok_release`` on direct-code platforms) and dropped at
``$TEE_CRAFTER_BYOK_DEK_PATH`` (tmpfs, 0600).

This module exposes :func:`assert_byok_healthy`, called immediately before
each request is dispatched to user code.  In the **production default**
(``TEE_CRAFTER_BYOK_FAIL_OPEN`` unset / ``0``) it refuses to serve when BYOK
was requested but the DEK is not present — so a workload can never silently run
without the customer key it was promised.

The gate only engages when ``TEE_CRAFTER_BYOK_ENABLED=1`` is visible in the
process environment.  In CVM **container** mode the user container does not
receive ``byok.env`` (only ``app.env``), so the in-app gate is dormant there —
fail-closed for that path is enforced upstream by the secrets oneshot, which
exits non-zero (and the container ``Requires=`` it) when the release fails.

Knobs (read at call time so they can be hot-changed):

* ``TEE_CRAFTER_BYOK_ENABLED``    — must be ``1`` for the gate to engage.
* ``TEE_CRAFTER_BYOK_FAIL_OPEN``  — DEV HATCH.  Default ``0`` (fail closed).
  Set ``1`` to keep serving even if the DEK is missing.
* ``TEE_CRAFTER_BYOK_DEK_PATH``   — where the released DEK is expected
  (default ``/run/tee_crafter/byok_dek.bin``).
* ``TEE_CRAFTER_BYOK_GRACE_SECONDS`` — initial window after process start
  during which a missing DEK is tolerated (release may still be in flight).
  Default 30s.
"""
from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger("tee_crafter.byok_health")

_PROCESS_START = time.monotonic()

_DEFAULT_DEK_PATH = "/run/tee_crafter/byok_dek.bin"


class ByokUnavailableError(RuntimeError):
    """Raised when fail-closed is engaged and the BYOK DEK is not present."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


#: Recognised truthy values.  Kept identical to :data:`siem_health._TRUE_SET`
#: so both gates answer the same env value the same way.
_TRUE_SET = ("1", "true", "yes", "on")


def _is_truthy(name: str, default: str = "0") -> bool:
    """Return ``True`` only for an explicitly recognised truthy value.

    See :func:`siem_health._is_truthy` — this is a true-set test, so an
    unrecognised value leaves the gate armed rather than disarming it.
    """
    return os.environ.get(name, default).strip().lower() in _TRUE_SET


def _dek_path() -> str:
    return os.environ.get("TEE_CRAFTER_BYOK_DEK_PATH", _DEFAULT_DEK_PATH) or _DEFAULT_DEK_PATH


def _grace_seconds() -> int:
    raw = os.environ.get("TEE_CRAFTER_BYOK_GRACE_SECONDS", "30").strip()
    return max(0, int(raw) if raw.isdigit() else 30)


def is_fail_closed() -> bool:
    """Return ``True`` iff the fail-closed gate is engaged.

    Production default: fail-closed when BYOK is enabled.  Dev hatch
    ``TEE_CRAFTER_BYOK_FAIL_OPEN=1`` disables it.

    The predicate tests the *truthy* set, not the falsy one.  Testing the
    falsy set meant any value outside ``0/false/no/off/""`` — including a
    typo such as ``TEE_CRAFTER_BYOK_FAIL_OPEN=2`` or ``=ture`` — silently
    disabled the gate and let the workload serve without the customer's
    key.  Anything we do not recognise now fails closed.
    """
    if not _is_truthy("TEE_CRAFTER_BYOK_ENABLED"):
        return False
    return not _is_truthy("TEE_CRAFTER_BYOK_FAIL_OPEN")


def _dek_present() -> bool:
    path = _dek_path()
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False


def status_snapshot() -> dict:
    """JSON-serialisable view of the BYOK gate state (for /healthz, tests)."""
    return {
        "fail_closed_enabled": is_fail_closed(),
        "byok_enabled": _is_truthy("TEE_CRAFTER_BYOK_ENABLED"),
        "dek_path": _dek_path(),
        "dek_present": _dek_present(),
        "grace_seconds": _grace_seconds(),
        "uptime_seconds": int(time.monotonic() - _PROCESS_START),
    }


def assert_byok_healthy() -> None:
    """Raise :class:`ByokUnavailableError` when BYOK is enabled but the DEK
    has not been released.  Returns silently when the gate is disabled.
    """
    if not is_fail_closed():
        return
    if _dek_present():
        return
    uptime = time.monotonic() - _PROCESS_START
    if uptime < _grace_seconds():
        return  # release may still be in flight at startup.
    raise ByokUnavailableError(
        f"BYOK enabled but released DEK absent at {_dek_path()} after "
        f"{int(uptime)}s; attestation-gated release appears to have failed")


def fail_closed_wrap(fn):
    """Decorator: wrap ``process_request`` so it refuses when the DEK is absent.

    The refusal payload mirrors ``siem_health.fail_closed_wrap`` so the
    templates hand it straight back to the client without user code running.
    """
    import functools

    @functools.wraps(fn)
    def _wrapper(data):
        try:
            assert_byok_healthy()
        except ByokUnavailableError as exc:
            logger.warning("BYOK unavailable, refusing request: %s", exc.reason)
            return {
                "error": "byok_unavailable",
                "reason": exc.reason,
                "policy": "fail_closed",
            }
        return fn(data)
    return _wrapper
