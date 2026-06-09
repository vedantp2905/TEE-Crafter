"""``tee-crafter residency-check`` — emit signed residency evidence."""
from __future__ import annotations

import json
import sys
from typing import Optional

import click

from tee_crafter.cli.constants import console, Panel, Table


def _load_policy(policy_path: Optional[str]):
    from tee_crafter.core.compliance.residency import ResidencyPolicy
    if not policy_path:
        return ResidencyPolicy()
    with open(policy_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    pol = ResidencyPolicy(
        allowed_regions=[tuple(p) for p in raw.get("allowed_regions", [])],
        allowed_countries=list(raw.get("allowed_countries", [])),
        allowed_jurisdictions=list(raw.get("allowed_jurisdictions", [])),
        allowed_regimes=list(raw.get("allowed_regimes", [])),
        forbid_cross_region_replication=bool(
            raw.get("forbid_cross_region_replication", True)),
        forbid_offshore_storage=bool(raw.get("forbid_offshore_storage", True)),
        require_signed_evidence=bool(raw.get("require_signed_evidence", True)),
        note=str(raw.get("note", "")),
    )
    errs = pol.validate()
    if errs:
        console.print(Panel.fit(
            "[bold red]Invalid residency policy[/bold red]\n\n" + "\n".join(errs),
            border_style="red"))
        sys.exit(2)
    return pol


def register(cli):
    @cli.command(name="residency-check")
    @click.option("--cloud", required=True,
                  type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False))
    @click.option("--region", required=True, type=str,
                  help="Primary deployment region (e.g. eu-west-1).")
    @click.option("--policy", "policy_path", default=None,
                  type=click.Path(exists=True, dir_okay=False),
                  help="JSON file with the residency policy. If omitted, an "
                       "empty (everything-allowed) policy is used.")
    @click.option("--terraform-plan", "tf_plan", default=None,
                  type=click.Path(exists=True, dir_okay=False),
                  help="Optional `terraform show -json` output to scan for "
                       "out-of-policy resources.")
    @click.option("--out", "out_path", required=True, type=click.Path(),
                  help="Path to write the signed residency_evidence.json.")
    @click.option("--strict/--no-strict", default=True,
                  help="Exit non-zero if validation fails (default).")
    def residency_check(cloud, region, policy_path, tf_plan, out_path, strict):
        """Validate region pinning and emit signed compliance evidence."""
        from tee_crafter.core.compliance.residency import (
            emit_residency_evidence, lookup_region,
        )
        try:
            lookup_region(cloud, region)
        except KeyError as exc:
            console.print(Panel.fit(
                f"[bold red]Unknown region[/bold red]\n\n{exc}", border_style="red"))
            sys.exit(2)

        policy = _load_policy(policy_path)

        plan = None
        if tf_plan:
            with open(tf_plan, "r", encoding="utf-8") as f:
                plan = json.load(f)

        evidence = emit_residency_evidence(
            cloud=cloud, primary_region=region, policy=policy,
            terraform_plan=plan,
        )
        evidence.write(out_path)

        v = evidence.document["validation"]
        passed = v["passed"]
        primary = v["primary"]

        tbl = Table(title="Residency check")
        tbl.add_column("Field"); tbl.add_column("Value")
        tbl.add_row("Cloud", primary["cloud"])
        tbl.add_row("Region", primary["region"])
        tbl.add_row("Country", primary["country_iso2"])
        tbl.add_row("Jurisdiction", primary["jurisdiction"])
        tbl.add_row("Regime", primary["regime"])
        tbl.add_row("Primary allowed", str(v["primary_allowed"]))
        if v["primary_reason"]:
            tbl.add_row("Reason", v["primary_reason"])
        tbl.add_row("Cross-region findings",
                    str(len(v["cross_region_findings"])))
        tbl.add_row("Out-of-policy resources",
                    str(len(v["out_of_policy_resources"])))
        tbl.add_row("PASSED", "[green]yes[/green]" if passed else "[red]no[/red]")
        tbl.add_row("Evidence", out_path)
        tbl.add_row("Signature", out_path + ".sig")
        tbl.add_row("Public key", out_path + ".pub")
        tbl.add_row("Doc SHA-256", evidence.document_sha256[:16] + "…")
        console.print(tbl)

        if v["out_of_policy_resources"]:
            console.print("\n[red]Out-of-policy resources:[/red]")
            for r in v["out_of_policy_resources"][:25]:
                console.print(f"  - {r['address']} [{r['type']}] "
                                f"region={r['region']} ({r['reason']})")

        if not passed and strict:
            sys.exit(1)
