"""Health-check state machine for fleet members.

The state machine is deliberately small and synchronous; the
production wiring runs ``HealthChecker.observe`` from whatever loop
already polls the fleet (Terraform's external data source, an SSM
script, or the persistent service-mode runtime).
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from tee_crafter.core.fleet.spec import HealthCheck


class HealthState(enum.Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthEvent:
    instance_id: str
    state: HealthState
    reason: str
    timestamp: float


@dataclass
class _NodeState:
    state: HealthState = HealthState.UNKNOWN
    consecutive_pass: int = 0
    consecutive_fail: int = 0
    last_attestation_ok: bool = True
    last_change_ts: float = field(default_factory=time.time)


class HealthChecker:
    """Tracks per-instance health rolled-up by interval/threshold."""

    def __init__(self, policy: HealthCheck,
                 clock: Optional[Callable[[], float]] = None):
        self._policy = policy
        self._clock = clock or time.time
        self._nodes: Dict[str, _NodeState] = {}
        self._events: List[HealthEvent] = []

    @property
    def policy(self) -> HealthCheck:
        return self._policy

    def observe(self, instance_id: str, *, probe_ok: bool,
                attestation_ok: bool = True, reason: str = "") -> HealthEvent:
        node = self._nodes.setdefault(instance_id, _NodeState())
        node.last_attestation_ok = attestation_ok

        passed = probe_ok and (attestation_ok or not self._policy.require_attestation)
        if passed:
            node.consecutive_pass += 1
            node.consecutive_fail = 0
        else:
            node.consecutive_fail += 1
            node.consecutive_pass = 0

        prev = node.state
        new = prev
        if not passed:
            if node.consecutive_fail >= self._policy.unhealthy_threshold:
                new = HealthState.UNHEALTHY
            elif prev != HealthState.UNHEALTHY:
                new = HealthState.DEGRADED
        else:
            if node.consecutive_pass >= self._policy.healthy_threshold:
                new = HealthState.HEALTHY
            elif prev == HealthState.UNKNOWN:
                new = HealthState.DEGRADED

        ts = self._clock()
        node.state = new
        if new != prev:
            node.last_change_ts = ts
        ev = HealthEvent(instance_id=instance_id, state=new,
                          reason=reason or ("ok" if passed else "fail"),
                          timestamp=ts)
        self._events.append(ev)
        return ev

    def state(self, instance_id: str) -> HealthState:
        node = self._nodes.get(instance_id)
        return node.state if node else HealthState.UNKNOWN

    def healthy_ids(self) -> List[str]:
        return [i for i, n in self._nodes.items() if n.state == HealthState.HEALTHY]

    def unhealthy_ids(self) -> List[str]:
        return [i for i, n in self._nodes.items() if n.state == HealthState.UNHEALTHY]

    def events(self) -> List[HealthEvent]:
        return list(self._events)

    def reset(self, instance_id: str) -> None:
        self._nodes.pop(instance_id, None)
