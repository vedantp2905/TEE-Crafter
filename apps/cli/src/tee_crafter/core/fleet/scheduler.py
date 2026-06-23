"""Cloud-agnostic fleet planner: turn a :class:`FleetSpec` plus current
health observations into a desired-state plan.

The planner is a pure function so it can be re-run on every health
observation without side-effects.  Per-cloud Terraform / SDK code calls
:meth:`FleetScheduler.plan` and applies the resulting
:class:`FleetPlan` (which lists how many on-demand / spot units each
``(cloud, region, instance_type)`` row should currently carry).
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from tee_crafter.core.fleet.cost import (
    PriceFeed, estimate_cost,
)
from tee_crafter.core.fleet.health import HealthChecker
from tee_crafter.core.fleet.spec import (
    FleetSpec, InstanceCandidate,
)


@dataclass
class FailoverDecision:
    """Result of "an unhealthy unit needs replacing" reasoning."""
    failed_instance_id: str
    replacement_candidate: Optional[InstanceCandidate]
    pool: str
    reason: str


@dataclass
class FleetPlan:
    """Desired state at a point in time."""
    fleet_name: str
    timestamp: str
    target_capacity_units: float
    on_demand_units: float
    spot_units: float
    rows: List[Dict[str, object]]
    in_business_hours: bool
    failovers: List[FailoverDecision] = field(default_factory=list)
    cost_preflight: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "fleet_name": self.fleet_name,
            "timestamp": self.timestamp,
            "target_capacity_units": self.target_capacity_units,
            "on_demand_units": self.on_demand_units,
            "spot_units": self.spot_units,
            "in_business_hours": self.in_business_hours,
            "rows": list(self.rows),
            "failovers": [
                {
                    "failed_instance_id": f.failed_instance_id,
                    "replacement": (
                        {"cloud": f.replacement_candidate.cloud,
                         "region": f.replacement_candidate.region,
                         "instance_type": f.replacement_candidate.instance_type}
                        if f.replacement_candidate else None),
                    "pool": f.pool, "reason": f.reason,
                } for f in self.failovers
            ],
            "cost_preflight": self.cost_preflight,
        }


class FleetScheduler:
    """Combines a :class:`FleetSpec`, a price feed and a
    :class:`HealthChecker` into desired-state plans + failover hints."""

    def __init__(self, spec: FleetSpec, price_feed: PriceFeed,
                 health: Optional[HealthChecker] = None,
                 clock: Optional[Callable[[], _dt.datetime]] = None):
        self._spec = spec
        self._price_feed = price_feed
        self._health = health or HealthChecker(spec.health)
        self._clock = clock or (lambda: _dt.datetime.utcnow())

    @property
    def health(self) -> HealthChecker:
        return self._health

    def plan(self) -> FleetPlan:
        now = self._clock()
        in_hours = self._spec.schedule.is_business_hours(now)
        target = (self._spec.target_capacity_units if in_hours
                  else self._spec.schedule.zero_capacity_units)

        # Build a tweaked spec at the (possibly zeroed) capacity for cost.
        from copy import copy
        spec_now = copy(self._spec)
        spec_now.target_capacity_units = max(target, 0.000001)
        if not in_hours:
            from tee_crafter.core.fleet.spec import FleetMix
            spec_now.mix = FleetMix(on_demand_base=min(self._spec.mix.on_demand_base,
                                                        spec_now.target_capacity_units),
                                      spot_target_pct=self._spec.mix.spot_target_pct,
                                      max_spot_interruption_rate=self._spec.mix.max_spot_interruption_rate)

        cost = estimate_cost(spec_now, self._price_feed)

        rows: List[Dict[str, object]] = []
        for r in cost.rows:
            rows.append({
                "cloud": r.candidate.cloud, "region": r.candidate.region,
                "instance_type": r.candidate.instance_type,
                "on_demand_count": r.on_demand_count,
                "spot_count": r.spot_count,
                "weight": r.candidate.weight,
            })

        failovers: List[FailoverDecision] = self._failover_decisions()

        ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        return FleetPlan(
            fleet_name=self._spec.name,
            timestamp=ts,
            target_capacity_units=target,
            on_demand_units=cost.on_demand_units if in_hours else 0.0,
            spot_units=cost.spot_units if in_hours else 0.0,
            rows=rows,
            in_business_hours=in_hours,
            failovers=failovers,
            cost_preflight=cost.to_dict(),
        )

    # ---- failover ------------------------------------------------------

    def _failover_decisions(self) -> List[FailoverDecision]:
        decisions: List[FailoverDecision] = []
        unhealthy = self._health.unhealthy_ids()
        if not unhealthy:
            return decisions
        ranked = self._spec.candidates_by_priority()
        if not ranked:
            return decisions
        # Cheapest spot vs on-demand candidate for replacement; fall back to first.
        spot_candidates = [c for c in ranked if c.spot_eligible]
        replacement_pool = "spot" if spot_candidates else "on-demand"
        replacement = (spot_candidates[0] if spot_candidates else ranked[0])
        for iid in unhealthy:
            decisions.append(FailoverDecision(
                failed_instance_id=iid,
                replacement_candidate=replacement,
                pool=replacement_pool,
                reason="unhealthy after threshold",
            ))
        return decisions
