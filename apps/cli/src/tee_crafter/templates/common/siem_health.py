"""SIEM-SEC-4: in-enclave fail-closed gate.

The continuous-attestation sidecar
(:mod:`tee_crafter.templates.common.siem_export`) writes a small JSON
file to ``/run/tee-crafter-{platform}/siem.health`` every time it
finishes a tick.  The file looks like::

    {"ts": 1747000000, "last_seq": 42, "last_status": "pass",
     "last_export_status": "pass", "last_export_error": "",
     "last_digest": "abc...", "tee_platform": "snp-aws"}

This module exposes one function: :func:`assert_siem_healthy`.  In
the **production default** (``TEE_CRAFTER_SIEM_FAIL_OPEN`` unset or
``0``), every request handler calls this immediately before
dispatching to user code; if the SIEM channel is dark, the function
raises :class:`SiemBlackoutError` which the templates translate to a
structured ``503``-equivalent refusal.

Knobs (all read at call time so they can be hot-changed):

* ``TEE_CRAFTER_SIEM_ENABLED``  — must be ``1`` for the gate to engage.
* ``TEE_CRAFTER_SIEM_FAIL_OPEN`` — DEV HATCH.  Default ``0`` (fail
  closed).  Set ``1`` to revert to "log-and-keep-serving" — only use
  when you genuinely cannot accept the workload going dark while the
  SIEM endpoint is rotated/upgraded.
* ``TEE_CRAFTER_SIEM_INTERVAL_SECONDS`` — the export cadence; used to
  compute the staleness threshold (``max(120s, 3*interval)`` by
  default, overridable below).
* ``TEE_CRAFTER_SIEM_MAX_LAG_SECONDS`` — explicit override for the
  staleness threshold.
* ``TEE_CRAFTER_SIEM_GRACE_SECONDS`` — initial grace window after
  process start during which a missing health file is tolerated (the
  sidecar may not have ticked yet).  Default 60s.
"""
from __future__ import annotations

import json
import logging
import os
import time

logger = logging.getLogger("tee_crafter.siem_health")

_PROCESS_START = time.monotonic()


class SiemBlackoutError(RuntimeError):
    """Raised by :func:`assert_siem_healthy` when fail-closed is engaged
    and the SIEM channel cannot prove freshness.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


#: The *only* values that count as "yes".  Anything else — including a
#: typo such as ``2`` or ``ture`` — is not recognised.  Keep this in step
#: with :data:`byok_health._TRUE_SET`; the two gates are meant to answer
#: the same env value the same way, and an asymmetry here meant
#: ``TEE_CRAFTER_SIEM_ENABLED=on`` silently left the SIEM gate off while
#: ``TEE_CRAFTER_BYOK_ENABLED=on`` engaged the BYOK one.
_TRUE_SET = ("1", "true", "yes", "on")


def _is_truthy(name: str, default: str = "0") -> bool:
    """Return ``True`` only for an explicitly recognised truthy value.

    Deliberately a *true-set* test rather than a falsy-set test: the
    predicate is used both to arm the gate (``..._ENABLED``) and to
    disarm it (``..._FAIL_OPEN``), and testing the falsy set meant any
    unrecognised value disarmed the gate.  With a true-set test an
    unrecognised value leaves the gate armed.
    """
    return os.environ.get(name, default).strip().lower() in _TRUE_SET


def _health_path(platform: str) -> str:
    return f"/run/tee-crafter-{platform}/siem.health"


def _read_state(platform: str):
    path = _health_path(platform)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def is_fail_closed() -> bool:
    """Return ``True`` iff the fail-closed gate is engaged.

    Production default: fail-closed when SIEM is enabled.  Set the
    dev hatch ``TEE_CRAFTER_SIEM_FAIL_OPEN=1`` to disable the gate
    (workload continues serving even if the SIEM channel is dark).
    """
    if not _is_truthy("TEE_CRAFTER_SIEM_ENABLED"):
        return False
    # Fail open ONLY on an explicit recognised truthy value.  The
    # previous form tested the falsy set, so a typo
    # (``TEE_CRAFTER_SIEM_FAIL_OPEN=2``) disabled the gate.
    return not _is_truthy("TEE_CRAFTER_SIEM_FAIL_OPEN")


def _max_lag_seconds() -> int:
    explicit = os.environ.get("TEE_CRAFTER_SIEM_MAX_LAG_SECONDS", "").strip()
    if explicit.isdigit():
        return max(1, int(explicit))
    interval = int(os.environ.get("TEE_CRAFTER_SIEM_INTERVAL_SECONDS", "60"))
    return max(120, 3 * interval)


def _grace_seconds() -> int:
    raw = os.environ.get("TEE_CRAFTER_SIEM_GRACE_SECONDS", "60").strip()
    return max(0, int(raw) if raw.isdigit() else 60)


def status_snapshot(platform: str = "") -> dict:
    """Return a JSON-serialisable view of the current SIEM health
    state.  Useful for ``/healthz`` style endpoints, tests, and
    debugging.
    """
    platform = platform or os.environ.get("TEE_CRAFTER_TEE_PLATFORM", "")
    state = _read_state(platform) or {}
    return {
        "fail_closed_enabled": is_fail_closed(),
        "tee_platform": platform,
        "max_lag_seconds": _max_lag_seconds(),
        "grace_seconds": _grace_seconds(),
        "uptime_seconds": int(time.monotonic() - _PROCESS_START),
        **state,
    }


def assert_siem_healthy(platform: str = "") -> None:
    """Raise :class:`SiemBlackoutError` if SIEM cannot prove freshness.

    Cheap (one stat + one small file read) so it's safe to call on
    every request.  Returns silently when fail-closed is disabled.
    """
    if not is_fail_closed():
        return  # fail-open posture
    platform = platform or os.environ.get("TEE_CRAFTER_TEE_PLATFORM", "")
    if not platform:
        # If we don't know the platform we cannot find the health file;
        # bias toward refusal so operator can spot the mis-config.
        raise SiemBlackoutError(
            "SIEM fail-closed engaged but TEE_CRAFTER_TEE_PLATFORM unset")

    state = _read_state(platform)
    uptime = time.monotonic() - _PROCESS_START
    if state is None:
        if uptime < _grace_seconds():
            return  # sidecar has not ticked yet; allow.
        raise SiemBlackoutError(
            f"SIEM health file {_health_path(platform)} missing after "
            f"{int(uptime)}s; sidecar appears down")

    ts = int(state.get("ts", 0))
    age = time.time() - ts
    if age > _max_lag_seconds():
        raise SiemBlackoutError(
            f"SIEM last export was {int(age)}s ago > "
            f"{_max_lag_seconds()}s threshold; SOC observation lost")
    last_export = state.get("last_export_status", "fail")
    if last_export != "pass":
        # Sidecar is alive but the SIEM endpoint is rejecting events.
        raise SiemBlackoutError(
            f"SIEM last export status={last_export}; events not landing")


def fail_closed_wrap(fn):
    """Decorator: wrap ``process_request`` so it refuses when SIEM dark.

    The refusal payload is a JSON dict the templates pass straight back
    to the client without involving user code, so the user's handler
    has a uniform contract.
    """
    import functools

    @functools.wraps(fn)
    def _wrapper(data):
        try:
            assert_siem_healthy()
        except SiemBlackoutError as exc:
            logger.warning("SIEM blackout, refusing request: %s", exc.reason)
            return {
                "error": "siem_blackout",
                "reason": exc.reason,
                "policy": "fail_closed",
            }
        return fn(data)
    return _wrapper
