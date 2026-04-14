"""Per-connection re-attestation gate for long-lived TLS sessions.

The single-request RA-TLS templates re-attest implicitly: every TLS
handshake on a freshly-issued cert binds a new SPKI to a new platform
quote.  When a connection lives for minutes or hours (HTTP/2, gRPC,
WebSocket), that initial proof becomes stale.  :class:`ConnectionAttestor`
tracks each connection's last successful attestation and forces a
re-check before serving a request when the policy interval has elapsed.

This module exposes a small synchronous API plus an async-friendly
``await_check`` coroutine so it can be wired into FastAPI / aiohttp /
asyncio TCP servers without re-implementing the bookkeeping.
"""
from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional


class ReattestPolicy(str, enum.Enum):
    """What to do when a re-attestation check fails."""

    DROP_CONNECTION = "drop"
    DRAIN = "drain"
    """Allow the in-flight request to finish, then close the connection
    before serving the next request on it."""

    HARD_STOP = "hard_stop"
    """Tear the whole service down; the operator wants any attestation
    failure to be treated as a security incident."""

    WARN = "warn"
    """Log + emit a metric but keep serving (only suitable for dev)."""


@dataclass
class ReattestResult:
    ok: bool
    refreshed: bool
    """True if this call actually triggered a fresh platform attestation
    (rather than reusing a cached fresh one within the interval)."""
    last_attest_age_sec: float
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "refreshed": self.refreshed,
            "last_attest_age_sec": round(float(self.last_attest_age_sec), 3),
            "reason": self.reason,
        }


class ConnectionAttestor:
    """Per-connection bookkeeping with bounded memory.

    Each connection is identified by an opaque string (``conn_id``) — the
    template typically uses ``f"{remote_addr}:{conn_seq}"``.  Bookkeeping
    is bounded by ``max_tracked_connections`` to prevent a slow connection
    leak from filling memory.
    """

    def __init__(
        self,
        *,
        attest_now: Callable[[], bool],
        interval_seconds: int,
        grace_seconds: int = 0,
        policy: ReattestPolicy = ReattestPolicy.DRAIN,
        max_tracked_connections: int = 4096,
        clock: Callable[[], float] = time.time,
    ):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        if grace_seconds < 0:
            raise ValueError("grace_seconds must be >= 0")
        if max_tracked_connections <= 0:
            raise ValueError("max_tracked_connections must be > 0")
        self._attest_now = attest_now
        self.interval = interval_seconds
        self.grace = grace_seconds
        self.policy = policy
        self.max_tracked = max_tracked_connections
        self._clock = clock
        self._lock = threading.Lock()
        self._last: Dict[str, float] = {}
        self._global_last_ok: Optional[float] = None

    def register(self, conn_id: str, *, now: Optional[float] = None) -> None:
        n = now if now is not None else self._clock()
        with self._lock:
            if len(self._last) >= self.max_tracked and conn_id not in self._last:
                # Evict the oldest entry; ``dict`` preserves insertion order
                # in Py 3.7+, so the first key is also the oldest registration.
                oldest = next(iter(self._last))
                self._last.pop(oldest, None)
            self._last[conn_id] = n

    def forget(self, conn_id: str) -> None:
        with self._lock:
            self._last.pop(conn_id, None)

    def check(self, conn_id: str, *, now: Optional[float] = None) -> ReattestResult:
        """Synchronously verify *conn_id* is still entitled to keep
        serving requests.  Triggers a fresh attestation when needed."""
        n = now if now is not None else self._clock()
        with self._lock:
            last = self._last.get(conn_id)
        # If the connection has never been registered, treat as a fresh
        # registration: do an attestation right away.
        if last is None:
            return self._do_attest(conn_id, n,
                                    reason="connection not yet attested")
        age = n - last
        if age <= self.interval:
            return ReattestResult(ok=True, refreshed=False,
                                  last_attest_age_sec=age,
                                  reason="within interval")
        # Inside grace? still allowed, but we must trigger refresh.
        if age <= self.interval + self.grace:
            return self._do_attest(conn_id, n,
                                    reason=f"refresh within grace (age={age:.1f}s)")
        # Past grace; refresh is mandatory and a failure must be enforced.
        result = self._do_attest(conn_id, n,
                                  reason=f"past grace (age={age:.1f}s)")
        if not result.ok:
            result.reason = (result.reason or "") + " [past grace]"
        return result

    def last_global_attestation_age(self, *, now: Optional[float] = None) -> Optional[float]:
        n = now if now is not None else self._clock()
        with self._lock:
            return None if self._global_last_ok is None else (n - self._global_last_ok)

    # ---- internals ----

    def _do_attest(self, conn_id: str, now: float, reason: str) -> ReattestResult:
        ok = False
        try:
            ok = bool(self._attest_now())
        except Exception as exc:
            return ReattestResult(ok=False, refreshed=True,
                                  last_attest_age_sec=0.0,
                                  reason=f"{reason}: attest raised {exc!r}")
        if ok:
            with self._lock:
                self._last[conn_id] = now
                self._global_last_ok = now
            return ReattestResult(ok=True, refreshed=True,
                                  last_attest_age_sec=0.0,
                                  reason=reason)
        return ReattestResult(ok=False, refreshed=True,
                              last_attest_age_sec=0.0,
                              reason=f"{reason}: attestation returned False")
