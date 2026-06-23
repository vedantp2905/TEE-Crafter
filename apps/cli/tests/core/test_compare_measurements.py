"""Comparing bakes must not repeat the mistake it exists to prevent.

The claim being tested for is that two bakes of the same platform, built from
materially different disks, produce the same launch measurement — correct AMD
SEV-SNP behaviour, since the launch digest covers initial guest memory rather
than the OS disk. It was established on ``snp-azure`` and must be re-established
per platform, because ``snp-aws`` and ``snp-gcp`` boot through different
firmware.

Doing that comparison by hand is what put three ``snp-azure`` bakes in the
registry disagreeing with each other: two digests for one image, recorded as a
vCPU-tier difference when it was a host-generation difference. So the comparison
is narrow on purpose, and these tests pin the narrowness:

* only the same shape is compared — same generation, same vCPU count;
* only a generation that was **observed** on the booted VM counts, never one
  inferred from the instance type;
* platforms whose digest is shape-independent (TDX ``MRTD``, Nitro ``PCR0``, SGX
  ``MRENCLAVE``) are compared on their single digest, and the SEV-SNP platforms
  are explicitly excluded from that shortcut.

The verdict describes the data, not a guarantee. In particular nothing here can
check the precondition — whether the two bakes really did differ in software —
because the registry does not record it.
"""
from __future__ import annotations

import json

import pytest

from tee_crafter.core.measurements import compare as _compare
from tee_crafter.core.measurements import registry as _registry


@pytest.fixture
def registry_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(_registry, "_REGISTRY_DIR", str(tmp_path))
    return tmp_path


def _write(registry_dir, platform, image_id, record):
    directory = registry_dir / platform
    directory.mkdir(parents=True, exist_ok=True)
    (directory / (_registry._sanitize(image_id) + ".json")).write_text(
        json.dumps(record), encoding="utf-8")


def _snp(image_id, variants, captured_at="2026-01-01T00:00:00Z",
         platform="snp-aws"):
    measurements = []
    for v in variants:
        if v["measurement"] not in measurements:
            measurements.append(v["measurement"])
    return {
        "platform": platform, "image_id": image_id, "field": "measurement",
        "measurement": measurements[0], "measurements": measurements,
        "variants": variants, "captured_at": captured_at, "source": "bake-ami",
    }


def _observed(vcpu, measurement, gen="milan"):
    return {"instance_type": f"m6a.{vcpu}", "vcpu": vcpu,
            "measurement": measurement, "cpu_gen": gen,
            "cpu_gen_source": "observed"}


A = "aa" * 48
B = "bb" * 48


def _internal_group():
    """The ``internal`` group with its subcommands attached.

    Importing the group is not enough: subcommands are added by ``register()``,
    so a bare import gives an empty group and every invocation exits 2. Building
    it through ``register`` is also the thing worth testing — a command that
    exists but was never wired up is indistinguishable from one that does not.
    """
    import click

    from tee_crafter.cli.commands import internal as _internal_mod

    @click.group()
    def root():
        pass

    _internal_mod.register(root)
    return root.commands["internal"]


class TestNotEnoughDataIsSaidPlainly:

    def test_no_bakes_at_all(self, registry_dir):
        result = _compare.compare_bakes("snp-aws")
        assert result["verdict"] == _compare.VERDICT_INSUFFICIENT
        assert result["images"] == []

    def test_one_bake_is_not_a_comparison(self, registry_dir):
        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [_observed(2, A)]))
        result = _compare.compare_bakes("snp-aws")
        assert result["verdict"] == _compare.VERDICT_INSUFFICIENT
        assert "only 1 bake" in result["reason"]

    def test_two_bakes_with_no_overlapping_shape(self, registry_dir):
        """Different shapes are *expected* to differ, so they say nothing about
        the disk. Reporting a verdict from them would be the original error."""
        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [_observed(2, A)]))
        _write(registry_dir, "snp-aws", "ami-2", _snp("ami-2", [_observed(32, B)]))
        result = _compare.compare_bakes("snp-aws")
        assert result["verdict"] == _compare.VERDICT_INSUFFICIENT
        assert result["comparisons"] == []


class TestWhenAnInferredGenerationIsTrustedAndWhenItIsNot:
    """Whether an inferred CPU generation may be compared depends on the
    platform, and both directions are load-bearing.

    On Azure SEV-SNP one size is scheduled on more than one host generation, so
    a label derived from the SKU can be wrong — and a wrong label reclassifies a
    host-generation difference as something else, which is how the disagreeing
    `snp-azure` entries were produced. On `snp-aws` and `snp-gcp` the instance
    type does fix the generation, so refusing an inferred label there would make
    the comparison permanently unanswerable for no gain in soundness.
    """

    @staticmethod
    def _inferred(gen="milan"):
        return {"instance_type": "size", "vcpu": 2, "measurement": A,
                "cpu_gen": gen, "cpu_gen_source": "instance_type"}

    def test_azure_refuses_an_inferred_generation(self, registry_dir):
        """The guard that matters: two variants labelled from the SKU may have
        run on different hosts, so an identical digest proves nothing."""
        for image_id in ("img-1", "img-2"):
            _write(registry_dir, "snp-azure", image_id,
                   _snp(image_id, [self._inferred()], platform="snp-azure"))
        result = _compare.compare_bakes("snp-azure")
        assert result["verdict"] == _compare.VERDICT_INSUFFICIENT
        assert result["comparisons"] == []

    def test_azure_accepts_an_observed_generation(self, registry_dir):
        """Positive control for the test above: the refusal must be about the
        label's provenance, not about Azure being excluded outright."""
        obs = dict(self._inferred(), cpu_gen_source="observed")
        for image_id in ("img-1", "img-2"):
            _write(registry_dir, "snp-azure", image_id,
                   _snp(image_id, [obs], platform="snp-azure"))
        result = _compare.compare_bakes("snp-azure")
        assert result["verdict"] == _compare.VERDICT_DISK_INDEPENDENT

    @pytest.mark.parametrize("platform", ["snp-aws", "snp-gcp"])
    def test_aws_and_gcp_accept_an_inferred_generation(self, registry_dir,
                                                      platform):
        """There the instance type fixes the generation, so the label is correct
        by construction and the comparison is sound."""
        for image_id in ("img-1", "img-2"):
            _write(registry_dir, platform, image_id,
                   _snp(image_id, [self._inferred()], platform=platform))
        result = _compare.compare_bakes(platform)
        assert result["verdict"] == _compare.VERDICT_DISK_INDEPENDENT

    def test_an_inferred_generation_is_still_reported_to_the_operator(self,
                                                                     registry_dir):
        """Reported separately from an observed one either way, so a reader can
        see which kind of label a verdict rests on."""
        _write(registry_dir, "snp-aws", "ami-1",
               _snp("ami-1", [self._inferred()]))
        result = _compare.compare_bakes("snp-aws")
        assert result["images"][0]["inferred_gens"] == ["milan"]
        assert result["images"][0]["observed_gens"] == []

    def test_a_variant_with_no_generation_is_compared_on_vcpu(self, registry_dir):
        """No label is not a wrong label. A record predating generation capture
        still has a usable vCPU count."""
        bare = {"instance_type": "m6a.large", "vcpu": 2, "measurement": A}
        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [bare]))
        _write(registry_dir, "snp-aws", "ami-2", _snp("ami-2", [dict(bare)]))
        result = _compare.compare_bakes("snp-aws")
        assert result["verdict"] == _compare.VERDICT_DISK_INDEPENDENT


class TestTheThreeRealVerdicts:

    def test_same_digest_on_the_same_shape_is_disk_independent(self, registry_dir):
        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [_observed(2, A)]))
        _write(registry_dir, "snp-aws", "ami-2", _snp("ami-2", [_observed(2, A)]))
        result = _compare.compare_bakes("snp-aws")
        assert result["verdict"] == _compare.VERDICT_DISK_INDEPENDENT
        assert result["comparisons"][0]["same"] is True

    def test_different_digests_on_the_same_shape_is_disk_dependent(self,
                                                                  registry_dir):
        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [_observed(2, A)]))
        _write(registry_dir, "snp-aws", "ami-2", _snp("ami-2", [_observed(2, B)]))
        result = _compare.compare_bakes("snp-aws")
        assert result["verdict"] == _compare.VERDICT_DISK_DEPENDENT
        assert result["comparisons"][0]["same"] is False

    def test_both_at_once_is_reported_as_contradictory(self, registry_dir):
        """Not collapsed to whichever came first. One shape agreeing and another
        disagreeing is a real signal about the platform and needs looking at,
        not a tie to be broken."""
        _write(registry_dir, "snp-aws", "ami-1",
               _snp("ami-1", [_observed(2, A), _observed(32, A)]))
        _write(registry_dir, "snp-aws", "ami-2",
               _snp("ami-2", [_observed(2, A), _observed(32, B)]))
        result = _compare.compare_bakes("snp-aws")
        assert result["verdict"] == _compare.VERDICT_CONTRADICTORY
        assert sorted(c["same"] for c in result["comparisons"]) == [False, True]

    def test_the_same_vcpu_on_two_generations_is_not_one_comparison(self,
                                                                   registry_dir):
        """Genoa and Milan at 2 vCPU are two shapes. Merging them is exactly how
        a host-generation difference became a vCPU-tier claim."""
        _write(registry_dir, "snp-aws", "ami-1",
               _snp("ami-1", [_observed(2, A, "milan")]))
        _write(registry_dir, "snp-aws", "ami-2",
               _snp("ami-2", [_observed(2, B, "genoa")]))
        result = _compare.compare_bakes("snp-aws")
        assert result["verdict"] == _compare.VERDICT_INSUFFICIENT


class TestShapeIndependentPlatformsUseTheirSingleDigest:
    """TDX `MRTD`, Nitro `PCR0` and SGX `MRENCLAVE` do not vary by shape and the
    bake stores no variants for them, so without a fallback they would be
    permanently 'insufficient data'."""

    @pytest.mark.parametrize("platform,field", [
        ("tdx-azure", "mrtd"), ("tdx-gcp", "mrtd"),
        ("nitro-aws", "pcr0"), ("sgx-azure", "mrenclave"),
    ])
    def test_two_variant_less_records_are_comparable(self, registry_dir,
                                                     platform, field):
        for image_id in ("img-1", "img-2"):
            _write(registry_dir, platform, image_id, {
                "platform": platform, "image_id": image_id, "field": field,
                field: A, "measurements": [A], "captured_at": "2026-01-01T00:00:00Z",
            })
        result = _compare.compare_bakes(platform)
        assert result["verdict"] == _compare.VERDICT_DISK_INDEPENDENT
        assert result["comparisons"][0]["cpu_gen"] is None

    @pytest.mark.parametrize("platform", ["snp-aws", "snp-azure", "snp-gcp",
                                          "gpu-cc-azure"])
    def test_snp_platforms_do_not_get_the_shortcut(self, registry_dir, platform):
        """The whole point: an SEV-SNP digest does vary by shape, so comparing
        two of them without knowing the shape is the unsound comparison."""
        for image_id in ("img-1", "img-2"):
            _write(registry_dir, platform, image_id, {
                "platform": platform, "image_id": image_id,
                "field": "measurement", "measurement": A, "measurements": [A],
                "captured_at": "2026-01-01T00:00:00Z",
            })
        result = _compare.compare_bakes(platform)
        assert result["verdict"] == _compare.VERDICT_INSUFFICIENT


class TestTheRegistryReaderIsRobust:

    def test_a_corrupt_file_does_not_break_the_comparison(self, registry_dir):
        """One bad file must not make the tool unavailable — it is data the bake
        writes, and the other records are still worth reading."""
        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [_observed(2, A)]))
        (registry_dir / "snp-aws" / "broken.json").write_text("{not json",
                                                             encoding="utf-8")
        result = _compare.compare_bakes("snp-aws")
        assert [i["image_id"] for i in result["images"]] == ["ami-1"]

    def test_non_json_files_are_ignored(self, registry_dir):
        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [_observed(2, A)]))
        (registry_dir / "snp-aws" / "notes.txt").write_text("x", encoding="utf-8")
        assert len(_compare.compare_bakes("snp-aws")["images"]) == 1

    def test_records_come_back_oldest_first(self, registry_dir):
        _write(registry_dir, "snp-aws", "ami-late",
               _snp("ami-late", [_observed(2, A)], captured_at="2026-06-01T00:00:00Z"))
        _write(registry_dir, "snp-aws", "ami-early",
               _snp("ami-early", [_observed(2, A)], captured_at="2026-01-01T00:00:00Z"))
        ids = [i["image_id"] for i in _compare.compare_bakes("snp-aws")["images"]]
        assert ids == ["ami-early", "ami-late"]

    def test_a_missing_platform_directory_is_empty_not_an_error(self, registry_dir):
        assert _registry.records_for_platform("snp-gcp") == []

    def test_an_empty_platform_name_is_empty(self):
        assert _registry.records_for_platform("") == []


class TestTheCliCommand:

    def test_it_is_registered_under_internal(self):
        from click.testing import CliRunner

        result = CliRunner().invoke(_internal_group(),
                                    ["compare-measurements", "--help"])
        assert result.exit_code == 0

    def test_json_output_is_machine_readable(self, registry_dir):
        from click.testing import CliRunner

        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [_observed(2, A)]))
        _write(registry_dir, "snp-aws", "ami-2", _snp("ami-2", [_observed(2, A)]))
        result = CliRunner().invoke(
            _internal_group(), ["compare-measurements", "--tee-platform",
                                "snp-aws", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["verdict"] == _compare.VERDICT_DISK_INDEPENDENT

    def test_an_unknown_platform_is_rejected(self):
        from click.testing import CliRunner

        result = CliRunner().invoke(
            _internal_group(), ["compare-measurements", "--tee-platform",
                                "not-a-tee"])
        assert result.exit_code != 0

    def test_it_states_the_precondition_it_cannot_check(self, registry_dir):
        """A green verdict only supports the claim if the two bakes really did
        differ in software, and the registry does not record that."""
        from click.testing import CliRunner

        _write(registry_dir, "snp-aws", "ami-1", _snp("ami-1", [_observed(2, A)]))
        _write(registry_dir, "snp-aws", "ami-2", _snp("ami-2", [_observed(2, A)]))
        result = CliRunner().invoke(
            _internal_group(), ["compare-measurements", "--tee-platform",
                                "snp-aws"])
        assert result.exit_code == 0
        assert "differ in software" in result.output
