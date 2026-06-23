"""What ships in the measurement registry must be evidence, not a claim.

The registry is shipped inside the package, and `deploy` treats every entry in
it as the vetted baseline for the client verifier, the BYOK release policy and
the sealed-`.env` gate. So an entry that is wrong is worse than an entry that is
absent: absent fails closed with a clear message, wrong fails closed with a
measurement mismatch that looks like a broken image.

Two properties are enforced here, both learned the hard way.

**No `manual` pins.** `internal pin-measurement` validates nothing beyond
hex-ness — the value arrives on a command line, so nothing checks that it was
read on this platform, from this image, or from a TEE at all. It is the right
tool for an air-gapped read or a platform with no auto-capture, but a `manual`
entry must not be what a user's key release is gated on by default.

**No untrustworthy CPU-generation labels.** A variant's `cpu_gen` may be
inferred from the instance type only where the instance type actually fixes the
generation. On Azure SEV-SNP it does not: a live `Standard_DC2as_v5` and
`Standard_DC4as_v5` — both catalogued `milan` — were observed running on
`AMD EPYC 9V74`, which is Genoa (bake of 2026-08-24). An inferred label there is
not a cosmetic mislabel; it silently reclassifies a host-generation difference
as a vCPU-tier difference, which is how three bakes of one image family ended up
disagreeing with each other.

A failure here is not "delete the file" by reflex. It means either re-bake the
platform so capture records the generation off the booted CPU, or the entry is
for an image nobody deploys and should go.
"""
from __future__ import annotations

import json
import os

import pytest

from tee_crafter.core.measurements.shapes import (
    SNP_VCPU_SENSITIVE_PLATFORMS,
    host_gen_is_selectable,
)

_REGISTRY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "measurements")


def _entries():
    """(platform, filename, record) for every shipped registry entry."""
    out = []
    for platform in sorted(os.listdir(_REGISTRY)):
        pdir = os.path.join(_REGISTRY, platform)
        if not os.path.isdir(pdir):
            continue
        for name in sorted(os.listdir(pdir)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(pdir, name), encoding="utf-8") as fh:
                out.append((platform, name, json.load(fh)))
    return out


ENTRIES = _entries()

#: Platforms whose measurement is not captured from a booted instance and may
#: legitimately arrive by another route. Nitro `PCR0` and SGX `MRENCLAVE` are
#: build-time deterministic (the builder derives and pins them), and
#: `gpu-cc-aws` self-pins its measured-boot digest at runtime.
SELF_PIN_OK = {"nitro-aws", "sgx-azure", "gpu-cc-aws"}


def test_the_registry_is_not_empty():
    """Guards every test below: an empty registry would pass them all while
    leaving every CVM platform unpinned."""
    assert ENTRIES, "no measurement registry entries found"


@pytest.mark.parametrize("platform,name,rec",
                         ENTRIES, ids=[f"{p}/{n[:28]}" for p, n, _ in ENTRIES])
def test_no_shipped_entry_is_a_manual_claim(platform, name, rec):
    if platform in SELF_PIN_OK:
        pytest.skip(f"{platform} does not auto-capture from a booted instance")
    assert rec.get("source") == "bake-ami", (
        f"{platform}/{name} has source={rec.get('source')!r}. A manual pin "
        "records a claim, not a measurement — re-bake the platform so capture "
        "reads the digest off a booted instance, or drop the entry."
    )


@pytest.mark.parametrize("platform,name,rec",
                         ENTRIES, ids=[f"{p}/{n[:28]}" for p, n, _ in ENTRIES])
def test_cpu_generation_labels_are_trustworthy(platform, name, rec):
    """An inferred generation is only acceptable where the SKU fixes it."""
    if host_gen_is_selectable(platform):
        return
    bad = [
        v for v in (rec.get("variants") or [])
        if v.get("cpu_gen") and v.get("cpu_gen_source") != "observed"
    ]
    assert not bad, (
        f"{platform}/{name} labels {len(bad)} variant(s) with a CPU generation "
        f"inferred from the instance type, on a platform where the instance "
        f"type does not fix it. Observed counter-example: Standard_DC2as_v5 is "
        f"catalogued 'milan' and ran on AMD EPYC 9V74 (Genoa). Re-bake so "
        f"capture records cpu_gen_source=observed."
    )


@pytest.mark.parametrize("platform,name,rec",
                         ENTRIES, ids=[f"{p}/{n[:28]}" for p, n, _ in ENTRIES])
def test_an_independence_claim_rests_on_observed_generations(platform, name, rec):
    """`vcpu_independent_gens` lets one digest cover every size of a generation,
    so it widens what a deploy accepts. Two equal digests under two *guessed*
    labels are equally consistent with both probes having landed on the same
    host, which establishes nothing — so the claim needs observed labels."""
    claimed = rec.get("vcpu_independent_gens") or []
    if not claimed or host_gen_is_selectable(platform):
        return
    observed = {
        v.get("cpu_gen") for v in (rec.get("variants") or [])
        if v.get("cpu_gen_source") == "observed"
    }
    for gen in claimed:
        assert gen in observed, (
            f"{platform}/{name} claims vCPU-independence for {gen!r} without an "
            f"observed generation to support it"
        )


@pytest.mark.parametrize("platform,name,rec",
                         ENTRIES, ids=[f"{p}/{n[:28]}" for p, n, _ in ENTRIES])
def test_every_entry_carries_at_least_one_measurement(platform, name, rec):
    values = rec.get("measurements") or []
    if not values:
        field = rec.get("field") or "measurement"
        values = [v for v in (rec.get(field), rec.get("measurement")) if v]
    assert values, f"{platform}/{name} has no measurement value at all"
    for val in values:
        assert isinstance(val, str) and val.strip(), f"{platform}/{name}: {val!r}"
        assert len(val) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in val), (
            f"{platform}/{name} has a non-hex measurement: {val[:32]!r}"
        )


def test_one_entry_per_snp_platform_at_most():
    """A second entry for an SNP platform means a superseded image is still
    pinned. Harmless to a deploy that names the current image, but it is dead
    weight in a shipped package and it made the `snp-azure` disagreement hard to
    see. TDX/Nitro/SGX are exempt: nothing here supersedes them per-image."""
    counts = {}
    for platform, _name, _rec in ENTRIES:
        if platform in SNP_VCPU_SENSITIVE_PLATFORMS:
            counts[platform] = counts.get(platform, 0) + 1
    extra = {p: n for p, n in counts.items() if n > 1}
    assert not extra, f"more than one pinned image per SNP platform: {extra}"
