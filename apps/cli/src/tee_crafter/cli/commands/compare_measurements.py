"""``internal compare-measurements`` — is a launch digest disk-independent here?

On ``snp-azure`` two bakes of the same platform, built from materially different
disks, produce the same launch measurement. That is correct AMD SEV-SNP
behaviour — the launch digest covers initial guest memory, not the OS disk — and
the workload is bound separately by the container digest inside ``report_data``.

The important word is *here*. ``snp-aws`` and ``snp-gcp`` boot through different
firmware, so the result must be re-established per platform rather than assumed.
This command is the compare step of that experiment:

1. Bake the platform.
2. Change something in the image that would land on disk.
3. Bake it again.
4. Run this command.

It reads only what the bake already wrote to the measurement registry, so it
costs nothing and can be run at any time. What it cannot verify is step 2 — the
registry does not record what went into an image — so the output states that
precondition rather than implying it was met.
"""
from __future__ import annotations

import json as _json

import click

from tee_crafter.cli.constants import console
from tee_crafter.core.measurements import compare as _compare
from tee_crafter.core.measurements import registry as _registry

_VERDICT_STYLE = {
    _compare.VERDICT_DISK_INDEPENDENT: ("green", "DISK-INDEPENDENT"),
    _compare.VERDICT_DISK_DEPENDENT: ("yellow", "DISK-DEPENDENT"),
    _compare.VERDICT_CONTRADICTORY: ("red", "CONTRADICTORY"),
    _compare.VERDICT_INSUFFICIENT: ("dim", "NOT YET ANSWERABLE"),
}


def register(cli):
    @cli.command("compare-measurements")
    @click.option(
        "--tee-platform", "platform", required=True,
        type=click.Choice(sorted(_registry.PLATFORM_MEASUREMENT_FIELD),
                          case_sensitive=False),
        help="Platform whose bakes should be compared.",
    )
    @click.option(
        "--json", "as_json", is_flag=True,
        help="Emit the raw comparison as JSON instead of a table.",
    )
    def compare_measurements(platform, as_json):
        """Compare every recorded bake of a platform, shape for shape."""
        platform = platform.lower()
        result = _compare.compare_bakes(platform)

        if as_json:
            click.echo(_json.dumps(result, indent=2, sort_keys=True))
            return

        images = result["images"]
        console.print(
            f"[bold]{platform}[/bold] — {len(images)} bake(s) in the registry "
            f"[dim]({_registry.registry_dir()})[/dim]")
        for img in images:
            gens = ", ".join(img["observed_gens"]) or "-"
            inferred = ", ".join(img["inferred_gens"])
            gen_note = f" [dim](inferred, not compared: {inferred})[/dim]" if inferred else ""
            console.print(
                f"  [cyan]{img['image_id']}[/cyan]\n"
                f"    captured {img['captured_at'] or '?'} · source "
                f"{img['source'] or '?'} · {len(img['measurements'])} digest(s) · "
                f"observed gen(s): {gens}{gen_note}")

        if result["comparisons"]:
            console.print("\n[bold]Shapes present in more than one bake[/bold]")
            for cmp_ in result["comparisons"]:
                shape = f"{cmp_['cpu_gen'] or '?'} / {cmp_['vcpu'] or '?'} vCPU"
                if cmp_["same"]:
                    console.print(
                        f"  [green]same[/green]  {shape}: "
                        f"{cmp_['digests'][0][:16]}…")
                else:
                    console.print(
                        f"  [yellow]differs[/yellow]  {shape}: "
                        + ", ".join(d[:16] + "…" for d in cmp_["digests"]))

        style, label = _VERDICT_STYLE.get(result["verdict"], ("dim", result["verdict"]))
        console.print(f"\n[{style}]Verdict: {label}[/{style}] — {result['reason']}")

        if result["verdict"] == _compare.VERDICT_DISK_INDEPENDENT:
            console.print(
                "[dim]This only supports the claim if the two bakes really did "
                "differ in software. The registry does not record that; confirm "
                "it before extending the disk-independence claim to this "
                "platform in docs/measurements.md.[/dim]")
        elif result["verdict"] == _compare.VERDICT_INSUFFICIENT:
            console.print(
                "[dim]Nothing is wrong — the experiment has not been run yet. "
                "Bake twice with a deliberate change between the bakes, on the "
                "same shape, then run this again.[/dim]")
