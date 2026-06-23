"""Cost preflight: estimate hourly / monthly cost for a fleet spec.

A :class:`PriceFeed` is a small abstraction that returns
:class:`PriceQuote` rows for ``(cloud, region, instance_type)``.  The
production implementations live behind ``boto3.pricing`` /
``azure-mgmt-commerce`` / ``google-cloud-billing``; for tests + the
default offline path we ship :class:`StaticPriceFeed`, a JSON-backed
table the operator can keep in source control.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from tee_crafter.core.fleet.spec import (
    FleetSpec, InstanceCandidate, ScaleSchedule, FleetSpecError,
)


@dataclass(frozen=True)
class PriceQuote:
    """Hourly USD price for one ``(cloud, region, instance_type)`` row."""
    cloud: str
    region: str
    instance_type: str
    on_demand_usd_hr: float
    spot_usd_hr: Optional[float] = None
    currency: str = "USD"

    def __post_init__(self):
        if self.on_demand_usd_hr < 0:
            raise FleetSpecError("on_demand_usd_hr must be >= 0")
        if self.spot_usd_hr is not None and self.spot_usd_hr < 0:
            raise FleetSpecError("spot_usd_hr must be >= 0")


class PriceFeed:
    """Strategy interface."""
    def quote(self, cloud: str, region: str, instance_type: str) -> PriceQuote:
        raise NotImplementedError


class StaticPriceFeed(PriceFeed):
    """Reads quotes from a JSON file or in-memory dict.

    JSON shape::

        {"aws::us-east-1::m6a.xlarge": {"on_demand_usd_hr": 0.18,
                                          "spot_usd_hr": 0.07}}
    """
    def __init__(self, prices: Optional[Dict[str, Dict[str, float]]] = None):
        self._prices: Dict[str, Dict[str, float]] = dict(prices or {})

    @classmethod
    def from_file(cls, path: str) -> "StaticPriceFeed":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    def add(self, *, cloud: str, region: str, instance_type: str,
            on_demand_usd_hr: float, spot_usd_hr: Optional[float] = None) -> None:
        key = f"{cloud}::{region}::{instance_type}"
        self._prices[key] = {"on_demand_usd_hr": on_demand_usd_hr}
        if spot_usd_hr is not None:
            self._prices[key]["spot_usd_hr"] = spot_usd_hr

    def quote(self, cloud: str, region: str, instance_type: str) -> PriceQuote:
        key = f"{cloud}::{region}::{instance_type}"
        if key not in self._prices:
            raise KeyError(f"no price for {key}")
        row = self._prices[key]
        return PriceQuote(
            cloud=cloud, region=region, instance_type=instance_type,
            on_demand_usd_hr=float(row["on_demand_usd_hr"]),
            spot_usd_hr=(float(row["spot_usd_hr"]) if "spot_usd_hr" in row else None),
        )


@dataclass
class CostEstimate:
    """One row of the preflight breakdown."""
    candidate: InstanceCandidate
    quote: PriceQuote
    on_demand_units: float
    spot_units: float

    @property
    def on_demand_count(self) -> float:
        return self.on_demand_units / self.candidate.capacity_units

    @property
    def spot_count(self) -> float:
        return self.spot_units / self.candidate.capacity_units

    @property
    def hourly_usd(self) -> float:
        spot_price = (self.quote.spot_usd_hr if self.quote.spot_usd_hr is not None
                      else self.quote.on_demand_usd_hr)
        return (self.on_demand_count * self.quote.on_demand_usd_hr
                + self.spot_count * spot_price)


@dataclass
class CostPreflight:
    fleet_name: str
    rows: List[CostEstimate]
    on_demand_units: float
    spot_units: float
    target_capacity_units: float
    schedule_active_hours_per_week: float = 168.0
    warnings: List[str] = field(default_factory=list)

    @property
    def hourly_usd(self) -> float:
        return sum(r.hourly_usd for r in self.rows)

    @property
    def monthly_usd(self) -> float:
        # 30-day month, ``schedule_active_hours_per_week`` factors in
        # business-hours / scale-to-zero.
        if self.schedule_active_hours_per_week >= 168.0:
            return self.hourly_usd * 24 * 30
        weekly = self.hourly_usd * self.schedule_active_hours_per_week
        return weekly * (30 / 7)

    def to_dict(self) -> Dict[str, object]:
        return {
            "fleet_name": self.fleet_name,
            "target_capacity_units": self.target_capacity_units,
            "on_demand_units": self.on_demand_units,
            "spot_units": self.spot_units,
            "hourly_usd": round(self.hourly_usd, 6),
            "monthly_usd": round(self.monthly_usd, 4),
            "schedule_active_hours_per_week": self.schedule_active_hours_per_week,
            "rows": [
                {
                    "cloud": r.candidate.cloud, "region": r.candidate.region,
                    "instance_type": r.candidate.instance_type,
                    "on_demand_count": round(r.on_demand_count, 4),
                    "spot_count": round(r.spot_count, 4),
                    "on_demand_units": r.on_demand_units,
                    "spot_units": r.spot_units,
                    "on_demand_usd_hr": r.quote.on_demand_usd_hr,
                    "spot_usd_hr": r.quote.spot_usd_hr,
                    "hourly_usd": round(r.hourly_usd, 6),
                } for r in self.rows
            ],
            "warnings": list(self.warnings),
        }


def _schedule_active_hours_per_week(sched: ScaleSchedule) -> float:
    if not sched.enabled:
        return 168.0
    sh, sm = (int(x) for x in sched.business_start_hhmm.split(":"))
    eh, em = (int(x) for x in sched.business_end_hhmm.split(":"))
    start = sh + sm / 60.0
    end = eh + em / 60.0
    if start <= end:
        per_day = end - start
    else:
        per_day = (24 - start) + end
    days = sum(1 for d in sched.business_days if d)
    return max(0.0, per_day * days)


def estimate_cost(spec: FleetSpec, feed: PriceFeed) -> CostPreflight:
    candidates = spec.candidates_by_priority()
    if not candidates:
        raise FleetSpecError("fleet has no candidates")

    quotes: List[Tuple[InstanceCandidate, PriceQuote]] = []
    warnings: List[str] = []
    for c in candidates:
        try:
            q = feed.quote(c.cloud, c.region, c.instance_type)
        except KeyError as exc:
            warnings.append(f"missing price for {c.cloud}/{c.region}/"
                            f"{c.instance_type}: {exc}")
            continue
        quotes.append((c, q))

    if not quotes:
        raise FleetSpecError("no priced candidates available")

    # Spot-eligible quotes: prefer cheapest spot first.
    spot_q = [(c, q) for c, q in quotes if c.spot_eligible and q.spot_usd_hr is not None]
    spot_q.sort(key=lambda r: r[1].spot_usd_hr)
    od_q = list(quotes)
    od_q.sort(key=lambda r: r[1].on_demand_usd_hr)

    target = spec.target_capacity_units
    on_demand_floor = spec.mix.on_demand_base
    spot_target = (target - on_demand_floor) * (spec.mix.spot_target_pct / 100.0)
    od_extra = (target - on_demand_floor) - spot_target
    od_total = on_demand_floor + max(0.0, od_extra)

    if not spot_q and spot_target > 0:
        warnings.append("no spot-priced candidates; spot_target rolled into on-demand")
        od_total += spot_target
        spot_target = 0.0

    rows: Dict[Tuple[str, str, str], CostEstimate] = {}

    def _ensure_row(cand: InstanceCandidate, q: PriceQuote) -> CostEstimate:
        key = (cand.cloud, cand.region, cand.instance_type)
        if key not in rows:
            rows[key] = CostEstimate(candidate=cand, quote=q,
                                       on_demand_units=0.0, spot_units=0.0)
        return rows[key]

    remaining = od_total
    for c, q in od_q:
        if remaining <= 0:
            break
        take = min(remaining, target)
        _ensure_row(c, q).on_demand_units += take
        remaining -= take

    remaining = spot_target
    for c, q in spot_q:
        if remaining <= 0:
            break
        take = remaining
        _ensure_row(c, q).spot_units += take
        remaining = 0.0  # for now: pour into cheapest spot row entirely

    schedule_hrs = _schedule_active_hours_per_week(spec.schedule)
    return CostPreflight(
        fleet_name=spec.name, rows=list(rows.values()),
        on_demand_units=od_total, spot_units=spot_target,
        target_capacity_units=target,
        schedule_active_hours_per_week=schedule_hrs,
        warnings=warnings,
    )
