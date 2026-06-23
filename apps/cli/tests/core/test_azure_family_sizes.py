"""Azure confidential VM sizes are per-family, and the ratios are not flat.

The catalog used to model every confidential family as one shared vCPU tier list
(2…96) plus a single GiB/vCPU ratio per prefix (DC = 4, EC = 8).  Three things
were wrong with that, all three measured against ``az vm list-skus`` in six
regions (westus, westus3, eastus, eastus2, westeurope, northeurope) on
2026-08-22, which agreed on vCPU and MemoryGB for every size with no conflicts:

1. ``DCes_v6`` / ``DCeds_v6`` publish a **128**-vCPU size the tier list stopped
   short of, while ``ECes_v6`` / ``ECeds_v6`` stop at **64** — so the list was
   simultaneously too short and too long depending on the family.
2. ``ECas_v5`` / ``ECads_v5`` span **6, 7 and 8** GiB/vCPU and ``ECas_v6`` /
   ``ECads_v6`` span **7 and 8**; only ``ECes_v6`` / ``ECeds_v6`` are flat 8.
   ``InstanceSpec.ram_mb`` feeds sizing and cost output, so over-reporting
   memory by 128 GiB on ``Standard_EC96as_v5`` is a user-visible wrong number.
3. ``ECas_v5`` / ``ECads_v5`` have a **20**-vCPU size no other family has.

The important negative case is ``Standard_DC128as_v6``: 128 is a real tier for
the Intel ``es`` families but **not** for the AMD ``as`` ones, so the naive fix
of appending 128 to a shared list would make ``lookup`` advertise a size Azure
does not sell.  That is the same failure shape as the ``snp-aws`` Genoa split —
a catalog enumerating more than the cloud offers — and it is what
``TestOffTierSizesAreRefused`` exists to keep out.

The expected values below are transcribed from that live SKU data rather than
re-derived from the catalog's own constants; a test that recomputes the ratio it
is checking would pass against any ratio.
"""
from __future__ import annotations

import pytest

from tee_crafter.core import catalog

GIB = 1024

#: vCPU → GiB, straight from ``az vm list-skus``.  Only the sizes that deviate
#: from the family ratio, plus the boundary tiers, are listed.
LIVE_EC_RAM_GIB = {
    "Standard_EC2as_v5": (2, 16),
    "Standard_EC16as_v5": (16, 128),
    "Standard_EC20as_v5": (20, 160),
    "Standard_EC32as_v5": (32, 192),     # 6.0 GiB/vCPU, not 8
    "Standard_EC48as_v5": (48, 384),
    "Standard_EC96as_v5": (96, 672),     # 7.0 GiB/vCPU, not 8
    "Standard_EC32ads_v5": (32, 192),
    "Standard_EC96ads_v5": (96, 672),
    "Standard_EC32as_v6": (32, 256),     # v6 *is* 8 at 32
    "Standard_EC96as_v6": (96, 672),     # but 7 at 96
    "Standard_EC96ads_v6": (96, 672),
}

#: DC families are genuinely flat 4 GiB/vCPU.
LIVE_DC_RAM_GIB = {
    "Standard_DC2as_v5": (2, 8),
    "Standard_DC96as_v5": (96, 384),
    "Standard_DC96ads_v6": (96, 384),
    "Standard_DC128es_v6": (128, 512),
    "Standard_DC128eds_v6": (128, 512),
}

SNP = "snp-azure"
TDX = "tdx-azure"


def _platform_for(size: str) -> str:
    """AMD ``as``/``ads`` sizes are SNP; Intel ``es``/``eds`` are TDX."""
    return TDX if ("es_v" in size or "eds_v" in size) else SNP


class TestRamMatchesLiveSkuData:
    @pytest.mark.parametrize("size,expected", sorted(LIVE_EC_RAM_GIB.items()))
    def test_ec_ram(self, size, expected):
        vcpu, ram_gib = expected
        spec = catalog.lookup(_platform_for(size), size)
        assert spec is not None, f"{size} is a real Azure SKU"
        assert spec.vcpu == vcpu
        assert spec.ram_mb == ram_gib * GIB, (
            f"{size}: catalog says {spec.ram_mb // GIB} GiB, Azure says {ram_gib}")

    @pytest.mark.parametrize("size,expected", sorted(LIVE_DC_RAM_GIB.items()))
    def test_dc_ram(self, size, expected):
        vcpu, ram_gib = expected
        spec = catalog.lookup(_platform_for(size), size)
        assert spec is not None, f"{size} is a real Azure SKU"
        assert (spec.vcpu, spec.ram_mb) == (vcpu, ram_gib * GIB)

    def test_the_deviating_sizes_are_not_the_flat_ratio(self):
        """Guard the premise: if these ever equal 8 GiB/vCPU the test is moot."""
        spec = catalog.lookup(SNP, "Standard_EC32as_v5")
        assert spec.ram_mb != 32 * 8 * GIB, (
            "EC32as_v5 at 8 GiB/vCPU means the override table stopped being applied")
        spec = catalog.lookup(SNP, "Standard_EC96as_v6")
        assert spec.ram_mb != 96 * 8 * GIB


class TestPerFamilyTiers:
    def test_intel_dc_reaches_128(self):
        for size in ("Standard_DC128es_v6", "Standard_DC128eds_v6"):
            assert catalog.lookup(TDX, size) is not None, size

    def test_intel_ec_stops_at_64(self):
        assert catalog.lookup(TDX, "Standard_EC64es_v6") is not None
        for size in ("Standard_EC96es_v6", "Standard_EC128es_v6",
                     "Standard_EC96eds_v6"):
            assert catalog.lookup(TDX, size) is None, (
                f"{size} does not exist; ECesv6/ECedsv6 cap at 64 vCPU")

    def test_amd_ec_v5_has_a_20_vcpu_size(self):
        for size in ("Standard_EC20as_v5", "Standard_EC20ads_v5"):
            spec = catalog.lookup(SNP, size)
            assert spec is not None and spec.vcpu == 20, size

    def test_20_vcpu_is_v5_only(self):
        for size in ("Standard_EC20as_v6", "Standard_DC20as_v5",
                     "Standard_DC20es_v6"):
            assert catalog.lookup(_platform_for(size), size) is None, size


class TestOffTierSizesAreRefused:
    """The regression this whole change exists to prevent."""

    @pytest.mark.parametrize("size", [
        "Standard_DC128as_v5", "Standard_DC128as_v6",
        "Standard_DC128ads_v5", "Standard_DC128ads_v6",
        "Standard_EC128as_v5", "Standard_EC128as_v6",
    ])
    def test_amd_families_do_not_reach_128(self, size):
        assert catalog.lookup(SNP, size) is None, (
            f"{size} parses but Azure does not sell it — 128 vCPU is an Intel "
            "DCes_v6/DCeds_v6 tier only")

    @pytest.mark.parametrize("size", [
        "Standard_DC1as_v5", "Standard_DC3as_v5", "Standard_DC6as_v5",
        "Standard_DC12as_v5", "Standard_DC256as_v6", "Standard_DC0as_v5",
    ])
    def test_arbitrary_vcpu_counts_are_refused(self, size):
        assert catalog.lookup(SNP, size) is None, f"{size} is not a real tier"

    def test_a_parseable_name_is_not_sufficient(self):
        """``lookup`` must gate on the tier list, not just the regex."""
        import re
        pat = re.compile(r"^Standard_([DE])C(\d+)(a|e)(d?)s_(v[56])$")
        assert pat.match("Standard_DC12as_v5"), "premise: the name does parse"
        assert catalog.lookup(SNP, "Standard_DC12as_v5") is None


class TestEnumerationAgreesWithLookup:
    @pytest.mark.parametrize("platform", [SNP, TDX])
    def test_every_enumerated_shape_looks_up_identically(self, platform):
        for spec in catalog.enumerate_instances(platform):
            again = catalog.lookup(platform, spec.instance_type)
            assert again is not None, f"{spec.instance_type} enumerated but not found"
            assert (again.vcpu, again.ram_mb, again.cpu_gen) == (
                spec.vcpu, spec.ram_mb, spec.cpu_gen)

    def test_enumeration_includes_the_128_vcpu_tdx_sizes(self):
        names = {s.instance_type for s in catalog.enumerate_instances(TDX)}
        assert "Standard_DC128es_v6" in names
        assert "Standard_DC128eds_v6" in names

    def test_enumeration_excludes_sizes_azure_does_not_sell(self):
        names = {s.instance_type for s in catalog.enumerate_instances(TDX)}
        assert "Standard_EC96es_v6" not in names
        assert "Standard_EC128es_v6" not in names
        snp_names = {s.instance_type for s in catalog.enumerate_instances(SNP)}
        assert not any(n.startswith("Standard_DC128") for n in snp_names)

    @pytest.mark.parametrize("platform", [SNP, TDX])
    def test_no_duplicate_shapes(self, platform):
        names = [s.instance_type for s in catalog.enumerate_instances(platform)]
        assert len(names) == len(set(names))


class TestFamilyTableShape:
    @pytest.mark.parametrize("table", [
        catalog._AZURE_SNP_FAMILIES, catalog._AZURE_TDX_FAMILIES])
    def test_every_row_is_a_four_tuple(self, table):
        for key, val in table.items():
            assert len(val) == 4, key
            gen, ram_per, tiers, overrides = val
            assert isinstance(gen, str) and gen
            assert ram_per > 0
            assert isinstance(tiers, tuple) and tiers == tuple(sorted(set(tiers)))
            assert isinstance(overrides, dict)

    @pytest.mark.parametrize("table", [
        catalog._AZURE_SNP_FAMILIES, catalog._AZURE_TDX_FAMILIES])
    def test_overrides_only_name_real_tiers(self, table):
        """An override for a vCPU count the family lacks is dead data."""
        for key, (_gen, _ram, tiers, overrides) in table.items():
            for v in overrides:
                assert v in tiers, f"{key}: override for absent tier {v}"

    @pytest.mark.parametrize("table", [
        catalog._AZURE_SNP_FAMILIES, catalog._AZURE_TDX_FAMILIES])
    def test_overrides_actually_differ_from_the_ratio(self, table):
        """An override equal to the ratio is noise and hides real drift."""
        for key, (_gen, ram_per, _tiers, overrides) in table.items():
            for v, ram in overrides.items():
                assert ram != v * ram_per, (
                    f"{key}: override for {v} vCPU equals the family ratio")

    def test_the_local_disk_twins_share_tiers_and_ram(self):
        """``d`` variants are the same silicon; they must not drift apart."""
        for table in (catalog._AZURE_SNP_FAMILIES, catalog._AZURE_TDX_FAMILIES):
            for (de, suffix, ver), val in table.items():
                if "d" in suffix:
                    continue
                twin_suffix = suffix.replace("s", "ds", 1) if suffix.endswith("s") else None
                twin = table.get((de, twin_suffix, ver))
                assert twin is not None, f"{de}{suffix}_{ver} has no d-variant row"
                assert twin == val, f"{de}{suffix}_{ver} and its d-twin disagree"
