"""Azure's ``d`` (local-temp-disk) confidential SKUs must be in the catalog.

``Standard_DC2es_v6`` and ``Standard_DC2eds_v6`` are two distinct SKUs, not one
SKU with an option — Azure appends ``d`` when the size ships a local temp disk.
The catalog's name regex was ``(a|e)s_`` with no room for that ``d``, so
``lookup`` returned ``None`` for half of Azure's confidential line-up: Intel TDX
went GA in February 2026 across **DCesv6, DCedsv6, ECesv6 and ECedsv6**, and the
AMD side has had ``DCadsv5``/``ECadsv5``/``DCadsv6``/``ECadsv6`` all along.

Why it mattered rather than being cosmetic: the deploy gate in
``cli/commands/deploy/platform.py`` only prefix-matches ``Standard_DC`` /
``Standard_EC``, so it *already* accepted ``Standard_DC2eds_v6``. The catalog
was the stricter of the two, which is the mirror image of the ``snp-aws`` Genoa
bug recorded in ``catalog.py`` — there the catalog advertised shapes the gate
refused; here the gate accepted shapes the catalog could not size. Either way
the two disagreed, so ``TestCatalogAgreesWithTheDeployGate`` below pins that
they do not.

The metadata is reused unchanged because it was measured, not assumed: against
``az vm list-skus --location westus`` on 2026-08-22 every ``d`` variant carries
the same vCPU tiers and the same GiB/vCPU as its non-``d`` twin.
"""
from __future__ import annotations

import pytest

from tee_crafter.core import catalog
from tee_crafter.cli.commands.deploy.platform import _INSTANCE_RULES

#: (platform, non-d name, d name) — the pairs that must behave identically.
TWINS = [
    ("tdx-azure", "Standard_DC2es_v6", "Standard_DC2eds_v6"),
    ("tdx-azure", "Standard_DC48es_v6", "Standard_DC48eds_v6"),
    ("tdx-azure", "Standard_EC8es_v6", "Standard_EC8eds_v6"),
    ("snp-azure", "Standard_DC2as_v5", "Standard_DC2ads_v5"),
    ("snp-azure", "Standard_EC16as_v5", "Standard_EC16ads_v5"),
    ("snp-azure", "Standard_DC8as_v6", "Standard_DC8ads_v6"),
    ("snp-azure", "Standard_EC8as_v6", "Standard_EC8ads_v6"),
]


class TestLocalDiskVariantsResolve:
    @pytest.mark.parametrize("platform,plain,withd", TWINS)
    def test_d_variant_resolves(self, platform, plain, withd):
        assert catalog.lookup(platform, withd) is not None, (
            f"{withd} is a real Azure SKU but the catalog cannot size it")

    @pytest.mark.parametrize("platform,plain,withd", TWINS)
    def test_d_variant_matches_its_twin_except_the_name(self, platform, plain, withd):
        """Measured invariant: the local disk changes nothing we model."""
        a = catalog.lookup(platform, plain)
        b = catalog.lookup(platform, withd)
        assert a is not None and b is not None
        assert (b.vcpu, b.ram_mb, b.cpu_gen) == (a.vcpu, a.ram_mb, a.cpu_gen)
        assert b.instance_type == withd

    def test_tdx_128_vcpu_size_resolves(self):
        """DCesv6/DCedsv6 reach 128 vCPU / 512 GiB per the GA announcement."""
        spec = catalog.lookup("tdx-azure", "Standard_DC128eds_v6")
        assert spec is not None
        assert (spec.vcpu, spec.ram_mb) == (128, 128 * 4 * 1024)


class TestTechnologiesStaySeparate:
    """A ``d`` variant must not leak across the AMD/Intel boundary."""

    @pytest.mark.parametrize("name", ["Standard_DC2eds_v6", "Standard_EC8eds_v6"])
    def test_snp_rejects_intel_d_variants(self, name):
        assert catalog.lookup("snp-azure", name) is None

    @pytest.mark.parametrize("name", ["Standard_DC2ads_v5", "Standard_EC8ads_v6"])
    def test_tdx_rejects_amd_d_variants(self, name):
        assert catalog.lookup("tdx-azure", name) is None

    def test_the_two_family_tables_are_disjoint(self):
        """What actually enforces the AMD/Intel split, pinned explicitly.

        ``lookup`` has an ``ae != expect_ae`` guard *and* looks the suffix up in
        a per-technology table.  Deleting the guard breaks nothing — a mutation
        run confirmed it — because the tables share no suffix, so the ``.get``
        already returns ``None`` across the boundary.  That makes the guard
        redundant depth rather than the control, and this test pins the property
        the guard is redundant *against*: the moment someone adds an ``as`` row
        to the TDX table (or an ``es`` row to the SNP table) the separation
        would start depending on that guard alone, and this fails to say so.
        """
        snp = {suffix for _de, suffix, _ver in catalog._AZURE_SNP_FAMILIES}
        tdx = {suffix for _de, suffix, _ver in catalog._AZURE_TDX_FAMILIES}
        assert snp & tdx == set(), f"family tables now overlap on {snp & tdx}"
        assert all(s.startswith("a") for s in snp), snp
        assert all(s.startswith("e") for s in tdx), tdx


class TestMalformedNamesStillRejected:
    """Widening the regex must not turn it into a rubber stamp."""

    @pytest.mark.parametrize("name", [
        "Standard_DC2ds_v6",      # 'd' but no a/e technology letter
        "Standard_DC2eds_v4",     # unsupported version
        "Standard_DC2edss_v6",    # doubled s
        "Standard_DC2eds",        # no version
        "DC2eds_v6",              # missing Standard_ prefix
        "Standard_DCeds_v6",      # no vCPU count
        "Standard_XC2eds_v6",     # bad prefix letter
        "Standard_DC2eds_v6x",    # trailing junk
    ])
    def test_rejected(self, name):
        assert catalog.lookup("tdx-azure", name) is None
        assert catalog.lookup("snp-azure", name) is None


class TestEnumerationIncludesThem:
    @pytest.mark.parametrize("platform,prefix", [
        ("tdx-azure", "eds"), ("snp-azure", "ads"),
    ])
    def test_list_instances_offers_d_variants(self, platform, prefix):
        names = [s.instance_type for s in catalog.enumerate_instances(platform)]
        assert any(prefix in n for n in names), (
            f"list-instances for {platform} shows no {prefix} shapes: {names[:5]}")

    @pytest.mark.parametrize("platform", ["tdx-azure", "snp-azure"])
    def test_enumeration_has_no_duplicates(self, platform):
        names = [s.instance_type for s in catalog.enumerate_instances(platform)]
        assert len(names) == len(set(names))

    @pytest.mark.parametrize("platform", ["tdx-azure", "snp-azure"])
    def test_every_enumerated_shape_resolves(self, platform):
        for spec in catalog.enumerate_instances(platform):
            assert catalog.lookup(platform, spec.instance_type) is not None


class TestCatalogAgreesWithTheDeployGate:
    """Nothing the catalog advertises may be refused by preflight.

    This is the check that would have caught the ``snp-aws`` Genoa split, where
    ``list-instances`` printed shapes the very next command rejected.
    """

    @pytest.mark.parametrize("platform", ["tdx-azure", "snp-azure", "snp-aws"])
    def test_gate_accepts_everything_enumerated(self, platform):
        _var, _default, validator, message = _INSTANCE_RULES[platform]
        bad = [s.instance_type for s in catalog.enumerate_instances(platform)
               if not validator(s.instance_type)]
        assert not bad, f"{platform}: catalog offers shapes the gate rejects " \
                        f"({message}): {bad}"

    @pytest.mark.parametrize("platform", ["tdx-azure", "snp-azure"])
    def test_the_gate_default_is_itself_catalogued(self, platform):
        _var, default, _validator, _message = _INSTANCE_RULES[platform]
        assert catalog.lookup(platform, default) is not None, (
            f"{platform} default {default} is not in the catalog")
