"""Declarative fleet description: candidate instance types, mix, schedule.

The fleet *spec* is intentionally cloud-agnostic.  Per-cloud Terraform
modules consume the resolved plan from
:class:`tee_crafter.core.fleet.scheduler.FleetScheduler`; the spec
itself only knows about TEE-capable instance types and their relative
capacity / weight.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple


class FleetSpecError(ValueError):
    """Raised when a fleet spec is internally inconsistent."""


@dataclass(frozen=True)
class InstanceCandidate:
    """One candidate ``(cloud, region, instance_type)`` row a fleet can
    pull from.  ``weight`` lets schedulers prefer one row over another
    when several are healthy and similarly priced (LP-style)."""
    cloud: str
    region: str
    instance_type: str
    capacity_units: float = 1.0
    weight: int = 1
    spot_eligible: bool = True

    def __post_init__(self):
        if self.capacity_units <= 0:
            raise FleetSpecError("capacity_units must be > 0")
        if self.weight <= 0:
            raise FleetSpecError("weight must be > 0")
        if self.cloud.lower() not in ("aws", "azure", "gcp"):
            raise FleetSpecError(f"unsupported cloud {self.cloud!r}")


@dataclass(frozen=True)
class FleetMix:
    """How much of the fleet is on-demand vs spot.

    ``on_demand_base`` is the floor of guaranteed on-demand capacity
    (units, not instances) — fleets fall back to it when spot
    interruption rates spike.

    ``spot_target_pct`` is the steady-state share of spot capacity
    above the floor (0–100).
    """
    on_demand_base: float = 0.0
    spot_target_pct: float = 80.0
    max_spot_interruption_rate: float = 0.10

    def __post_init__(self):
        if self.on_demand_base < 0:
            raise FleetSpecError("on_demand_base must be >= 0")
        if not 0.0 <= self.spot_target_pct <= 100.0:
            raise FleetSpecError("spot_target_pct must be in [0,100]")
        if not 0.0 <= self.max_spot_interruption_rate <= 1.0:
            raise FleetSpecError("max_spot_interruption_rate must be in [0,1]")


@dataclass(frozen=True)
class HealthCheck:
    """Health-check policy applied to every fleet member."""
    interval_seconds: int = 30
    timeout_seconds: int = 5
    unhealthy_threshold: int = 3
    healthy_threshold: int = 2
    require_attestation: bool = True
    """If True an unhealthy node is one that has *also* failed its
    most recent re-attestation; this avoids reaping nodes that simply
    have a slow HTTP probe."""

    def __post_init__(self):
        for k in ("interval_seconds", "timeout_seconds",
                  "unhealthy_threshold", "healthy_threshold"):
            v = getattr(self, k)
            if v <= 0:
                raise FleetSpecError(f"{k} must be > 0")
        if self.timeout_seconds >= self.interval_seconds:
            raise FleetSpecError("timeout_seconds must be < interval_seconds")


_CRON_HHMM = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


@dataclass(frozen=True)
class ScaleSchedule:
    """Minimal scale-to-zero schedule: business-hours window in a single
    timezone.  Outside the window, ``min_capacity_units`` shrinks to
    ``zero_capacity_units`` (default 0).

    ``business_days`` is a 7-bool list, Monday-first (matches Python
    ``datetime.weekday()``).
    """
    business_start_hhmm: Optional[str] = None
    business_end_hhmm: Optional[str] = None
    timezone: str = "UTC"
    business_days: Tuple[bool, ...] = (True,) * 5 + (False, False)
    zero_capacity_units: float = 0.0

    def __post_init__(self):
        if self.business_start_hhmm and not _CRON_HHMM.match(self.business_start_hhmm):
            raise FleetSpecError("business_start_hhmm must be HH:MM")
        if self.business_end_hhmm and not _CRON_HHMM.match(self.business_end_hhmm):
            raise FleetSpecError("business_end_hhmm must be HH:MM")
        if len(self.business_days) != 7:
            raise FleetSpecError("business_days must have 7 entries")
        if self.zero_capacity_units < 0:
            raise FleetSpecError("zero_capacity_units must be >= 0")

    @property
    def enabled(self) -> bool:
        return bool(self.business_start_hhmm and self.business_end_hhmm)

    def is_business_hours(self, now) -> bool:
        if not self.enabled:
            return True
        if not self.business_days[now.weekday()]:
            return False
        sh, sm = (int(x) for x in self.business_start_hhmm.split(":"))
        eh, em = (int(x) for x in self.business_end_hhmm.split(":"))
        cur = now.hour * 60 + now.minute
        start = sh * 60 + sm
        end = eh * 60 + em
        if start <= end:
            return start <= cur < end
        # Overnight window e.g. 22:00 - 06:00.
        return cur >= start or cur < end


@dataclass
class FleetSpec:
    """Top-level declarative description of a fleet."""
    name: str
    candidates: List[InstanceCandidate]
    target_capacity_units: float
    mix: FleetMix = field(default_factory=FleetMix)
    health: HealthCheck = field(default_factory=HealthCheck)
    schedule: ScaleSchedule = field(default_factory=ScaleSchedule)
    region_priority: Sequence[Tuple[str, str]] = field(default_factory=tuple)

    def __post_init__(self):
        if not self.name:
            raise FleetSpecError("fleet name is required")
        if not self.candidates:
            raise FleetSpecError("fleet must have at least one candidate")
        if self.target_capacity_units <= 0:
            raise FleetSpecError("target_capacity_units must be > 0")
        if self.mix.on_demand_base > self.target_capacity_units:
            raise FleetSpecError("on_demand_base exceeds target_capacity_units")
        seen = set()
        for c in self.candidates:
            key = (c.cloud, c.region, c.instance_type)
            if key in seen:
                raise FleetSpecError(f"duplicate candidate {key}")
            seen.add(key)

    def candidates_by_priority(self) -> List[InstanceCandidate]:
        """Return candidates ordered by ``region_priority`` (if any),
        then by descending ``weight``."""
        prio = {tuple(p): i for i, p in enumerate(self.region_priority)}
        def key(c: InstanceCandidate):
            return (prio.get((c.cloud, c.region), 1_000_000), -c.weight,
                    c.cloud, c.region, c.instance_type)
        return sorted(self.candidates, key=key)
