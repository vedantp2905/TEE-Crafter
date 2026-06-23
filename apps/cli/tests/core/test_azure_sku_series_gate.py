"""What the Azure SKU version suffix does and does not determine.

``snp-azure`` is on the ``_HOST_GEN_NOT_SELECTABLE`` list for a good reason:
choosing ``Standard_DC2as_v5`` does not decide whether Azure schedules you on
Milan or Genoa, so comparing the catalogued generation against the observed one
rejects images that work.

These tests once required the *opposite* of what they now assert. The theory was
that ``_v5`` and ``_v6`` are different SKU families on different firmware, so a
``_v6`` deploy against ``_v5``-only pins should be refused up front rather than
billing a VM that then fails attestation. A single snp-azure bake on 2026-08-24
settled it: ``Standard_DC2as_v5``, ``DC4as_v5`` and ``DC4as_v6`` all produced the
same digest, with ``cpu_gen`` observed as ``genoa`` for each. The determinant is
the host CPU generation -- precisely the thing an instance type cannot select
here -- and not the version suffix.

So the refusal is gone and ``shape_series`` survives only for reporting. vCPU
count, which *is* an input to the launch digest (one VMSA per vCPU), still
refuses.
"""
from __future__ import annotations

import json

import pytest

from tee_crafter.core.measurements import registry
from tee_crafter.core.measurements.shapes import shape_series, variant_shape

PLATFORM = "snp-azure"
IMAGE = "/subscriptions/x/images/tee_crafter_snp_ubuntu/versions/2026.0824.005408"
DIGEST_V5 = "b2" * 48


@pytest.fixture
def registry_dir(tmp_path, monkeypatch):
    # Assign the override seam rather than the env var: it outranks the
    # environment, so this stays hermetic on a machine that exports
    # ``TEE_CRAFTER_MEASUREMENTS_DIR``.
    monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
    return tmp_path


def _write(registry_dir, variants, indep=None):
    path = registry_dir / PLATFORM
    path.mkdir(parents=True, exist_ok=True)
    record = {
        "platform": PLATFORM,
        "image_id": IMAGE,
        "field": "measurement",
        "measurements": sorted({v["measurement"] for v in variants}),
        "variants": variants,
        "source": "bake-ami",
        "captured_at": "2026-08-24T00:54:08Z",
    }
    if indep is not None:
        record["vcpu_independent_gens"] = indep
    (path / (registry._sanitize(IMAGE) + ".json")).write_text(json.dumps(record))


V5_ONLY = [
    {"vm_size": "Standard_DC2as_v5", "vcpu": 2, "measurement": DIGEST_V5,
     "cpu_gen": "genoa", "cpu_gen_source": "observed"},
    {"vm_size": "Standard_DC4as_v5", "vcpu": 4, "measurement": DIGEST_V5,
     "cpu_gen": "genoa", "cpu_gen_source": "observed"},
]


# --------------------------------------------------------------------------
# shape_series
# --------------------------------------------------------------------------

@pytest.mark.parametrize("shape,expected", [
    ("Standard_DC2as_v5", "v5"),
    ("Standard_DC96ads_v5", "v5"),
    ("Standard_DC2as_v6", "v6"),
    ("Standard_EC8as_v6", "v6"),
])
def test_series_is_the_version_suffix(shape, expected):
    assert shape_series(PLATFORM, shape) == expected


def test_series_ignores_the_dc_ec_distinction():
    """DC and EC differ in RAM per vCPU, which is not an input to the launch
    measurement. Discriminating on it would refuse shapes for no reason."""
    assert shape_series(PLATFORM, "Standard_DC2as_v5") == \
        shape_series(PLATFORM, "Standard_EC2as_v5")


@pytest.mark.parametrize("platform", ["snp-aws", "snp-gcp", "tdx-gcp"])
def test_platforms_with_selectable_generations_have_no_series(platform):
    """Those already compare cpu_gen properly; adding a second axis would be
    redundant."""
    assert shape_series(platform, "m6a.large") is None


def test_unparseable_shape_has_no_series():
    assert shape_series(PLATFORM, "something-odd") is None


def test_variant_shape_reads_whichever_key_was_used():
    assert variant_shape({"vm_size": "Standard_DC2as_v5"}) == "Standard_DC2as_v5"
    assert variant_shape({"instance_type": "m6a.large"}) == "m6a.large"
    assert variant_shape({"machine_type": "n2d-standard-2"}) == "n2d-standard-2"
    assert variant_shape({"vcpu": 2}) is None


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

def test_v6_is_accepted_against_v5_only_pins(registry_dir):
    """This assertion is inverted from its original form, on evidence.

    It used to require a refusal, on the theory that v5 and v6 are different SKU
    families on different firmware and so could produce different launch
    digests. A single snp-azure bake on 2026-08-24 measured
    Standard_DC2as_v5, DC4as_v5 and DC4as_v6 and got the *same* digest from all
    three, with cpu_gen observed as `genoa` each time. The determinant is the
    host CPU generation -- the thing an Azure instance type does not select --
    not the version suffix. Refusing here rejected deploys that would have
    worked, which is the opposite of what a cost gate is for.
    """
    _write(registry_dir, V5_ONLY)
    assert registry.accepts_shape(
        PLATFORM, IMAGE, "genoa", 2,
        instance_type="Standard_DC2as_v6") is True


def test_v5_still_accepted(registry_dir):
    _write(registry_dir, V5_ONLY)
    assert registry.accepts_shape(
        PLATFORM, IMAGE, "genoa", 2, instance_type="Standard_DC2as_v5") is True


def test_vcpu_independence_covers_every_size_of_the_generation(registry_dir):
    """With `genoa` recorded vCPU-independent, any size of it is covered --
    including a version suffix that was never booted, since the digest does not
    depend on it (measured 2026-08-24)."""
    _write(registry_dir, V5_ONLY, indep=["genoa"])
    assert registry.accepts_shape(
        PLATFORM, IMAGE, "genoa", 2,
        instance_type="Standard_DC2as_v6") is True
    assert registry.accepts_shape(
        PLATFORM, IMAGE, "genoa", 64,
        instance_type="Standard_DC64as_v5") is True


def test_v6_still_accepted_once_v6_is_captured(registry_dir):
    _write(registry_dir, V5_ONLY + [
        {"vm_size": "Standard_DC2as_v6", "vcpu": 2, "measurement": "cc" * 48,
         "cpu_gen": "genoa", "cpu_gen_source": "observed"},
    ])
    assert registry.accepts_shape(
        PLATFORM, IMAGE, "genoa", 2,
        instance_type="Standard_DC2as_v6") is True


def test_omitting_instance_type_keeps_the_older_looser_behaviour(registry_dir):
    """Callers that never pass a shape must not start failing."""
    _write(registry_dir, V5_ONLY)
    assert registry.accepts_shape(PLATFORM, IMAGE, "genoa", 2) is True


def test_variants_without_a_recorded_shape_do_not_block(registry_dir):
    """A legacy record with no vm_size cannot be series-checked, and guessing
    would retroactively refuse images that were fine."""
    _write(registry_dir, [{"vcpu": 2, "measurement": DIGEST_V5}])
    assert registry.accepts_shape(
        PLATFORM, IMAGE, "genoa", 2,
        instance_type="Standard_DC2as_v6") is True


def test_an_unmeasured_vcpu_tier_still_refuses(registry_dir):
    """vCPU count *is* an input to the SEV-SNP launch digest (one VMSA per
    vCPU), so this refusal stays -- unlike the version-suffix one."""
    _write(registry_dir, V5_ONLY)
    assert registry.accepts_shape(
        PLATFORM, IMAGE, "genoa", 96,
        instance_type="Standard_DC96as_v5") is False
