"""``tee-crafter fleet-preflight`` — cost preview + plan for a fleet spec."""
from __future__ import annotations

import json
import os
import sys

import click

from tee_crafter.cli.constants import console, Panel, Table


def _load_spec(path: str):
    from tee_crafter.core.fleet.spec import (
        FleetSpec, FleetMix, HealthCheck, ScaleSchedule, InstanceCandidate,
    )
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    cands = [InstanceCandidate(
        cloud=c["cloud"], region=c["region"],
        instance_type=c["instance_type"],
        capacity_units=float(c.get("capacity_units", 1.0)),
        weight=int(c.get("weight", 1)),
        spot_eligible=bool(c.get("spot_eligible", True)),
    ) for c in raw["candidates"]]
    mix = raw.get("mix") or {}
    sched = raw.get("schedule") or {}
    health = raw.get("health") or {}
    return FleetSpec(
        name=raw["name"],
        candidates=cands,
        target_capacity_units=float(raw["target_capacity_units"]),
        mix=FleetMix(**{k: mix[k] for k in ("on_demand_base", "spot_target_pct",
                                              "max_spot_interruption_rate") if k in mix}),
        health=HealthCheck(**{k: health[k] for k in ("interval_seconds",
                                                        "timeout_seconds",
                                                        "unhealthy_threshold",
                                                        "healthy_threshold",
                                                        "require_attestation")
                                if k in health}),
        schedule=ScaleSchedule(**{k: sched[k] for k in ("business_start_hhmm",
                                                          "business_end_hhmm",
                                                          "timezone",
                                                          "zero_capacity_units")
                                    if k in sched} | (
            {"business_days": tuple(sched["business_days"])}
            if "business_days" in sched else {})),
        region_priority=tuple(tuple(p) for p in raw.get("region_priority", [])),
    )


def register(cli):
    @cli.command(name="fleet-preflight")
    @click.option("--spec", "spec_path", required=True,
                  type=click.Path(exists=True, dir_okay=False),
                  help="JSON file describing the fleet (see "
                       "tee_crafter.core.fleet.spec).")
    @click.option("--prices", "prices_path", required=True,
                  type=click.Path(exists=True, dir_okay=False),
                  help="JSON price table for StaticPriceFeed.")
    @click.option("--out", "out_path", default=None, type=click.Path(),
                  help="If given, write the JSON plan here.")
    @click.option("--format", "fmt", type=click.Choice(["table", "json"]),
                  default="table")
    def fleet_preflight(spec_path, prices_path, out_path, fmt):
        """Compute desired-state + cost preflight for a fleet."""
        from tee_crafter.core.fleet.cost import StaticPriceFeed
        from tee_crafter.core.fleet.scheduler import FleetScheduler

        try:
            spec = _load_spec(spec_path)
        except Exception as exc:
            console.print(Panel.fit(
                f"[bold red]Invalid fleet spec[/bold red]\n\n{exc}",
                border_style="red"))
            sys.exit(2)

        feed = StaticPriceFeed.from_file(prices_path)
        sched = FleetScheduler(spec, feed)
        plan = sched.plan()
        d = plan.to_dict()

        if out_path:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".",
                         exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(d, f, indent=2)

        if fmt == "json":
            console.print_json(json.dumps(d))
            return

        cost = d["cost_preflight"]
        tbl = Table(title=f"Fleet preflight — {spec.name}")
        tbl.add_column("Cloud"); tbl.add_column("Region")
        tbl.add_column("Type"); tbl.add_column("On-demand")
        tbl.add_column("Spot"); tbl.add_column("$/hr")
        for r in cost["rows"]:
            tbl.add_row(r["cloud"], r["region"], r["instance_type"],
                        f"{r['on_demand_count']:.2f}",
                        f"{r['spot_count']:.2f}",
                        f"{r['hourly_usd']:.4f}")
        console.print(tbl)
        console.print(f"[cyan]Target units :[/cyan] {d['target_capacity_units']}")
        console.print(f"[cyan]On-demand    :[/cyan] {d['on_demand_units']}")
        console.print(f"[cyan]Spot         :[/cyan] {d['spot_units']}")
        console.print(f"[cyan]Hourly USD   :[/cyan] {cost['hourly_usd']}")
        console.print(f"[cyan]Monthly USD  :[/cyan] {cost['monthly_usd']}")
        console.print(f"[cyan]Active hrs/wk:[/cyan] "
                        f"{cost['schedule_active_hours_per_week']}")
        if cost.get("warnings"):
            console.print("[yellow]Warnings:[/yellow]")
            for w in cost["warnings"]:
                console.print(f"  - {w}")
        if d["failovers"]:
            console.print("\n[red]Failovers needed:[/red]")
            for f in d["failovers"]:
                rep = f["replacement"]
                console.print(f"  - {f['failed_instance_id']} → "
                                f"{rep['cloud']}/{rep['region']}/"
                                f"{rep['instance_type']} ({f['pool']})")
