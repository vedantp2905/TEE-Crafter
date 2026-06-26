"""Canned-provenance sweep: every TEE platform we ship.

Real cloud deploys for all ten platforms aren't feasible inside the
test runner, so this sweep is a static check that the audit catalogue
returns a coherent `required_checks_for(plat)` list for every platform
and that the filter set agrees with the per-platform applicability
rules baked into ``CheckSpec.platform_filter``.

Catches regressions like "BYOK-008 was meant for AWS only but the
catalogue says it applies to GCP" without needing live infrastructure.
"""
from __future__ import annotations

import pytest

from tee_crafter.core.audit.checks import (
    CHECKS,
    required_checks_for,
    DEFAULT_REQUIRED_CHECKS,
)


_ALL_PLATFORMS = [
    "nitro-aws",
    "snp-aws",
    "gpu-cc-aws",
    "snp-azure",
    "tdx-azure",
    "sgx",
    "gpu-cc-azure",
    "snp-gcp",
    "tdx-gcp",
    "gpu-cc-gcp",
]


@pytest.mark.parametrize("plat", _ALL_PLATFORMS)
def test_required_checks_for_platform_is_non_empty(plat):
    required = required_checks_for(plat)
    assert required, f"required-check list empty for {plat}"


@pytest.mark.parametrize("plat", _ALL_PLATFORMS)
def test_required_checks_only_include_applicable_specs(plat):
    """Every cid returned for *plat* must actually apply to *plat*."""
    for cid in required_checks_for(plat):
        spec = CHECKS[cid]
        assert spec.applies_to(plat), (
            f"required_checks_for({plat}) contains {cid} but its "
            f"platform_filter is {spec.platform_filter!r}"
        )


def test_every_default_required_check_known():
    """The DEFAULT_REQUIRED_CHECKS list must reference real check_ids."""
    for cid in DEFAULT_REQUIRED_CHECKS:
        assert cid in CHECKS, f"unknown check_id in defaults: {cid}"


def test_byok_unwrap_specifics_apply_broadly():
    """BYOK-002 should apply to every TEE platform in the catalogue."""
    spec = CHECKS["BYOK-002"]
    for plat in _ALL_PLATFORMS:
        assert spec.applies_to(plat), plat


def test_dep_aws_only_check_does_not_apply_to_gcp():
    """DEP-005 (IMDSv2 required) must NOT apply to GCP."""
    spec = CHECKS["DEP-005"]
    assert not spec.applies_to("snp-gcp")
    assert spec.applies_to("snp-aws")


def test_ct_azure_check_does_not_apply_to_aws():
    """CT-005 (Azure Activity Log) must NOT apply to AWS or GCP."""
    spec = CHECKS["CT-005"]
    assert not spec.applies_to("snp-aws")
    assert not spec.applies_to("snp-gcp")
    assert spec.applies_to("snp-azure")
