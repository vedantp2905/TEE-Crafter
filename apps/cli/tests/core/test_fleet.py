"""Unit tests for fleet spec, cost preflight, health, and scheduler."""
from __future__ import annotations

import datetime as _dt

import pytest

from tee_crafter.core.fleet import (
    FleetSpec, FleetMix, InstanceCandidate, HealthCheck, ScaleSchedule,
    FleetSpecError,
    StaticPriceFeed, estimate_cost, HealthChecker, HealthState,
    FleetScheduler,
)


def _spec(target=10.0, **kw):
    return FleetSpec(
        name="api-fleet",
        candidates=[
            InstanceCandidate(cloud="aws", region="eu-west-1",
                                 instance_type="m6a.xlarge",
                                 capacity_units=2.0, weight=2),
            InstanceCandidate(cloud="aws", region="eu-west-1",
                                 instance_type="m6a.large",
                                 capacity_units=1.0, weight=1),
        ],
        target_capacity_units=target,
        **kw,
    )


def _feed():
    return StaticPriceFeed({
        "aws::eu-west-1::m6a.xlarge": {"on_demand_usd_hr": 0.20,
                                          "spot_usd_hr": 0.08},
        "aws::eu-west-1::m6a.large":  {"on_demand_usd_hr": 0.10,
                                          "spot_usd_hr": 0.04},
    })


class TestSpec:
    def test_rejects_zero_capacity(self):
        with pytest.raises(FleetSpecError):
            InstanceCandidate(cloud="aws", region="x", instance_type="t",
                                 capacity_units=0)

    def test_rejects_unknown_cloud(self):
        with pytest.raises(FleetSpecError):
            InstanceCandidate(cloud="ibm", region="x", instance_type="t")

    def test_rejects_duplicate_candidates(self):
        c = InstanceCandidate(cloud="aws", region="eu-west-1",
                                 instance_type="m6a.xlarge")
        with pytest.raises(FleetSpecError, match="duplicate"):
            FleetSpec(name="x", candidates=[c, c], target_capacity_units=1.0)

    def test_rejects_floor_above_target(self):
        with pytest.raises(FleetSpecError, match="on_demand_base"):
            FleetSpec(name="x",
                      candidates=[InstanceCandidate(cloud="aws", region="eu-west-1",
                                                       instance_type="m6a.large")],
                      target_capacity_units=1.0,
                      mix=FleetMix(on_demand_base=5.0))

    def test_priority_ordering(self):
        s = _spec(region_priority=[("aws", "eu-west-1")])
        ordered = s.candidates_by_priority()
        # weight 2 should come before weight 1.
        assert ordered[0].instance_type == "m6a.xlarge"

    def test_mix_validates(self):
        with pytest.raises(FleetSpecError, match="spot_target_pct"):
            FleetMix(spot_target_pct=120)
        with pytest.raises(FleetSpecError, match="max_spot_interruption_rate"):
            FleetMix(max_spot_interruption_rate=5)

    def test_health_validates(self):
        with pytest.raises(FleetSpecError, match="timeout_seconds"):
            HealthCheck(interval_seconds=5, timeout_seconds=10)

    def test_schedule_business_hours_match(self):
        sched = ScaleSchedule(business_start_hhmm="09:00",
                                 business_end_hhmm="17:00")
        mon_morning = _dt.datetime(2026, 4, 20, 10, 0)  # Monday
        assert sched.is_business_hours(mon_morning)
        sat_morning = _dt.datetime(2026, 4, 18, 10, 0)  # Saturday
        assert not sched.is_business_hours(sat_morning)
        mon_evening = _dt.datetime(2026, 4, 20, 20, 0)
        assert not sched.is_business_hours(mon_evening)

    def test_schedule_overnight_window(self):
        sched = ScaleSchedule(business_start_hhmm="22:00",
                                 business_end_hhmm="06:00")
        late = _dt.datetime(2026, 4, 20, 23, 0)
        early = _dt.datetime(2026, 4, 21, 5, 0)
        midday = _dt.datetime(2026, 4, 20, 12, 0)
        assert sched.is_business_hours(late)
        assert sched.is_business_hours(early)
        assert not sched.is_business_hours(midday)

    def test_disabled_schedule_always_business_hours(self):
        sched = ScaleSchedule()
        assert sched.is_business_hours(_dt.datetime(2026, 1, 1, 3, 0))


class TestCost:
    def test_estimate_split(self):
        spec = _spec(target=10.0,
                      mix=FleetMix(on_demand_base=2.0, spot_target_pct=80.0))
        c = estimate_cost(spec, _feed())
        # on-demand floor 2 + 20% of remaining 8 = 1.6 → total 3.6 on demand,
        # 6.4 spot.
        assert pytest.approx(c.on_demand_units, abs=1e-6) == 3.6
        assert pytest.approx(c.spot_units, abs=1e-6) == 6.4
        # Cheapest spot is m6a.large @ $0.04/hr × 6.4 = 0.256
        # OD goes to cheapest: m6a.large @ $0.10/hr × 3.6 = 0.36
        assert pytest.approx(c.hourly_usd, abs=1e-6) == 0.36 + 0.256

    def test_estimate_no_spot_falls_back(self):
        feed = StaticPriceFeed({
            "aws::eu-west-1::m6a.xlarge": {"on_demand_usd_hr": 0.20},
            "aws::eu-west-1::m6a.large":  {"on_demand_usd_hr": 0.10},
        })
        spec = _spec(target=4.0, mix=FleetMix(on_demand_base=0.0,
                                                  spot_target_pct=100.0))
        c = estimate_cost(spec, feed)
        assert c.spot_units == 0.0
        assert c.on_demand_units == 4.0
        assert any("spot" in w for w in c.warnings)

    def test_estimate_missing_price_warns(self):
        feed = StaticPriceFeed({
            "aws::eu-west-1::m6a.xlarge": {"on_demand_usd_hr": 0.20,
                                              "spot_usd_hr": 0.08},
        })
        spec = _spec(target=2.0)
        c = estimate_cost(spec, feed)
        assert any("missing price" in w for w in c.warnings)

    def test_monthly_uses_schedule(self):
        spec = _spec(target=4.0,
                      mix=FleetMix(on_demand_base=0.0, spot_target_pct=0.0),
                      schedule=ScaleSchedule(business_start_hhmm="09:00",
                                                business_end_hhmm="17:00"))
        c = estimate_cost(spec, _feed())
        # 8 hrs/day × 5 days = 40 hrs/week
        assert c.schedule_active_hours_per_week == 40.0
        weekly = c.hourly_usd * 40.0
        assert pytest.approx(c.monthly_usd, rel=1e-6) == weekly * (30 / 7)

    def test_no_priced_candidates_raises(self):
        spec = _spec(target=4.0)
        with pytest.raises(FleetSpecError, match="no priced"):
            estimate_cost(spec, StaticPriceFeed({}))


class TestHealth:
    def test_unhealthy_after_threshold(self):
        h = HealthChecker(HealthCheck(interval_seconds=10, timeout_seconds=2,
                                          unhealthy_threshold=2,
                                          healthy_threshold=2,
                                          require_attestation=False))
        h.observe("i-1", probe_ok=False)
        assert h.state("i-1") == HealthState.DEGRADED
        h.observe("i-1", probe_ok=False)
        assert h.state("i-1") == HealthState.UNHEALTHY

    def test_recovers_after_threshold(self):
        h = HealthChecker(HealthCheck(interval_seconds=10, timeout_seconds=2,
                                          unhealthy_threshold=1,
                                          healthy_threshold=2,
                                          require_attestation=False))
        h.observe("i-1", probe_ok=False)
        assert h.state("i-1") == HealthState.UNHEALTHY
        h.observe("i-1", probe_ok=True)
        assert h.state("i-1") == HealthState.UNHEALTHY  # one good not enough
        h.observe("i-1", probe_ok=True)
        assert h.state("i-1") == HealthState.HEALTHY

    def test_attestation_failure_counts(self):
        h = HealthChecker(HealthCheck(interval_seconds=10, timeout_seconds=2,
                                          unhealthy_threshold=2,
                                          healthy_threshold=1,
                                          require_attestation=True))
        h.observe("i-1", probe_ok=True, attestation_ok=False)
        h.observe("i-1", probe_ok=True, attestation_ok=False)
        assert h.state("i-1") == HealthState.UNHEALTHY

    def test_listing(self):
        h = HealthChecker(HealthCheck(interval_seconds=10, timeout_seconds=2,
                                          unhealthy_threshold=1,
                                          healthy_threshold=1,
                                          require_attestation=False))
        h.observe("i-1", probe_ok=True)
        h.observe("i-2", probe_ok=False)
        assert h.healthy_ids() == ["i-1"]
        assert h.unhealthy_ids() == ["i-2"]

    def test_events_recorded(self):
        h = HealthChecker(HealthCheck(interval_seconds=10, timeout_seconds=2,
                                          unhealthy_threshold=1,
                                          healthy_threshold=1,
                                          require_attestation=False))
        h.observe("i-1", probe_ok=True)
        h.observe("i-1", probe_ok=False)
        ev = h.events()
        assert ev[-1].state == HealthState.UNHEALTHY
        assert ev[0].state == HealthState.HEALTHY


class TestScheduler:
    def test_plan_in_business_hours(self):
        spec = _spec(target=10.0,
                      mix=FleetMix(on_demand_base=2.0, spot_target_pct=80.0),
                      schedule=ScaleSchedule(business_start_hhmm="09:00",
                                                business_end_hhmm="17:00"))
        # Monday 10am
        sched = FleetScheduler(spec, _feed(),
                                 clock=lambda: _dt.datetime(2026, 4, 20, 10))
        plan = sched.plan()
        assert plan.in_business_hours
        assert plan.target_capacity_units == 10.0
        assert plan.on_demand_units > 0

    def test_plan_outside_business_hours(self):
        spec = _spec(target=10.0,
                      schedule=ScaleSchedule(business_start_hhmm="09:00",
                                                business_end_hhmm="17:00",
                                                zero_capacity_units=0.0))
        # Saturday — outside business days
        sched = FleetScheduler(spec, _feed(),
                                 clock=lambda: _dt.datetime(2026, 4, 18, 10))
        plan = sched.plan()
        assert not plan.in_business_hours
        assert plan.target_capacity_units == 0.0
        assert plan.on_demand_units == 0.0
        assert plan.spot_units == 0.0

    def test_plan_failover_when_unhealthy(self):
        spec = _spec(target=4.0)
        h = HealthChecker(spec.health)
        # Force i-1 unhealthy.
        for _ in range(spec.health.unhealthy_threshold):
            h.observe("i-1", probe_ok=False, attestation_ok=False)
        sched = FleetScheduler(spec, _feed(), health=h,
                                 clock=lambda: _dt.datetime(2026, 4, 20, 10))
        plan = sched.plan()
        assert len(plan.failovers) == 1
        assert plan.failovers[0].failed_instance_id == "i-1"
        assert plan.failovers[0].replacement_candidate is not None
        assert plan.failovers[0].pool == "spot"

    def test_plan_dict_round_trip(self):
        spec = _spec(target=4.0)
        sched = FleetScheduler(spec, _feed(),
                                 clock=lambda: _dt.datetime(2026, 4, 20, 10))
        plan = sched.plan()
        d = plan.to_dict()
        assert d["fleet_name"] == "api-fleet"
        assert "cost_preflight" in d and "rows" in d["cost_preflight"]
