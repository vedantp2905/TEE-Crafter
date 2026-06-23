"""The deploy must not compare an observed CPU generation against a guessed one.

Bake and deploy learn the host CPU generation two different ways. Capture reads
the model line off the booted VM, so a stored variant records what the CPU *was*
(``cpu_gen_source: "observed"``). The deploy has no VM yet, so it can only ask
the catalog what the instance type *implies*.

On Azure those disagree. ``Standard_DC2as_v5`` is catalogued as Milan, and live
probes on that exact size produced two different launch digests — a
host-generation difference, because Azure schedules ``DCas_v5`` on Milan or
Genoa. So after capture started recording observed generations, a bake that
landed on Genoa stored ``cpu_gen: "genoa"`` for a shape the deploy calls
``milan``, and the pre-deploy shape gate refused a perfectly good image with "no
bake-time measurement for this shape".

That is the regression these tests pin. Two separate behaviours:

* the gate ignores the generation where the generation is not selectable, and
  matches on vCPU instead;
* the deploy *says* when the bake covered fewer generations than the platform can
  schedule, because that deploy is a coin flip and the eventual failure —
  correctly fail-closed at attestation — looks exactly like a broken image.

Where instance type really does determine the generation, keep comparing: on
``snp-aws`` ``m6a`` is Milan and ``m7a`` is Genoa (different hardware families),
and on ``snp-gcp`` the bake and the deploy both pin ``min_cpu_platform``.
"""
from __future__ import annotations

import json
import os

import pytest

from tee_crafter.core.measurements import registry as _registry
from tee_crafter.core.measurements.shapes import (
    expected_host_gens,
    host_gen_is_selectable,
)


@pytest.fixture
def registry_dir(tmp_path, monkeypatch):
    """Point the registry at a scratch directory for the duration of a test."""
    monkeypatch.setattr(_registry, "_REGISTRY_DIR", str(tmp_path))
    return tmp_path


def _write(registry_dir, platform, image_id, record):
    directory = registry_dir / platform
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (_registry._sanitize(image_id) + ".json")
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _record(image_id, variants, measurements=None, **extra):
    rec = {
        "platform": "snp-azure",
        "image_id": image_id,
        "field": "measurement",
        "measurements": measurements or ["aa" * 48],
        "variants": variants,
    }
    rec.update(extra)
    return rec


class TestWhichPlatformsCanChooseTheirHostGeneration:

    @pytest.mark.parametrize("platform", ["snp-azure", "gpu-cc-azure"])
    def test_azure_snp_cannot(self, platform):
        assert host_gen_is_selectable(platform) is False

    @pytest.mark.parametrize("platform", ["snp-aws", "snp-gcp"])
    def test_the_others_can(self, platform):
        """Guards the negative tests above: a predicate that returned False for
        everything would pass them while disabling a real gate."""
        assert host_gen_is_selectable(platform) is True

    def test_an_unknown_platform_defaults_to_selectable(self):
        """The permissive answer here is the strict one for the gate: a
        selectable platform keeps comparing generations."""
        assert host_gen_is_selectable("no-such-platform") is True

    def test_azure_snp_is_expected_to_present_two_generations(self):
        assert sorted(expected_host_gens("snp-azure")) == ["genoa", "milan"]

    def test_gpu_cc_azure_expects_one(self):
        """One SKU, one expected generation — so the coin-flip warning must not
        fire there and make every deploy noisy."""
        assert expected_host_gens("gpu-cc-azure") == ["genoa"]


class TestTheShapeGateIgnoresAGuessedGeneration:

    def test_an_observed_genoa_bake_accepts_a_milan_labelled_shape(self,
                                                                  registry_dir):
        """The exact regression: the bake landed on Genoa, the catalog calls
        Standard_DC2as_v5 Milan, and the deploy must not refuse."""
        _write(registry_dir, "snp-azure", "img-a", _record("img-a", [
            {"vm_size": "Standard_DC2as_v5", "vcpu": 2, "measurement": "aa" * 48,
             "cpu_gen": "genoa", "cpu_gen_source": "observed"},
        ]))
        assert _registry.accepts_shape("snp-azure", "img-a", "milan", 2) is True

    def test_an_uncaptured_vcpu_tier_is_still_refused(self, registry_dir):
        """Ignoring the generation must not turn the gate off. The vCPU count
        genuinely does change the digest — one VMSA per vCPU — so a tier nobody
        measured has no digest to attest against."""
        _write(registry_dir, "snp-azure", "img-b", _record("img-b", [
            {"vm_size": "Standard_DC2as_v5", "vcpu": 2, "measurement": "aa" * 48,
             "cpu_gen": "genoa", "cpu_gen_source": "observed"},
        ]))
        assert _registry.accepts_shape("snp-azure", "img-b", "milan", 32) is False

    def test_a_vcpu_independent_generation_accepts_any_size(self, registry_dir):
        _write(registry_dir, "snp-azure", "img-c", _record(
            "img-c",
            [{"vm_size": "Standard_DC2as_v5", "vcpu": 2, "measurement": "aa" * 48,
              "cpu_gen": "genoa", "cpu_gen_source": "observed"}],
            vcpu_independent_gens=["genoa"]))
        assert _registry.accepts_shape("snp-azure", "img-c", "milan", 96) is True

    def test_a_selectable_platform_still_rejects_a_foreign_generation(self,
                                                                     registry_dir):
        """snp-aws must keep the generation check: m6a and m7a are different
        hardware, so a Genoa-only pin really cannot cover a Milan shape."""
        _write(registry_dir, "snp-aws", "ami-1", {
            "platform": "snp-aws", "image_id": "ami-1", "field": "measurement",
            "measurements": ["bb" * 48],
            "variants": [{"instance_type": "m7a.large", "vcpu": 2,
                          "measurement": "bb" * 48, "cpu_gen": "genoa"}],
        })
        assert _registry.accepts_shape("snp-aws", "ami-1", "milan", 2) is False
        assert _registry.accepts_shape("snp-aws", "ami-1", "genoa", 2) is True

    def test_a_record_with_no_variants_is_unaffected(self, registry_dir):
        """A bare manual pin carries no per-shape data; it must not be
        retroactively blocked."""
        _write(registry_dir, "snp-azure", "img-d", {
            "platform": "snp-azure", "image_id": "img-d",
            "field": "measurement", "measurements": ["cc" * 48],
        })
        assert _registry.accepts_shape("snp-azure", "img-d", "milan", 8) is True

    def test_an_unknown_vcpu_count_is_not_refused(self, registry_dir):
        """`instance_vcpu` returns None for a shape outside the catalog. That is
        ignorance, not evidence of a mismatch, and the client still fails closed
        on the digest."""
        _write(registry_dir, "snp-azure", "img-e", _record("img-e", [
            {"vm_size": "Standard_DC2as_v5", "vcpu": 2, "measurement": "aa" * 48,
             "cpu_gen": "genoa", "cpu_gen_source": "observed"},
        ]))
        assert _registry.accepts_shape("snp-azure", "img-e", None, None) is True


class TestTheCoinFlipWarning:

    @staticmethod
    def _warn(platform, captured_gens, registry_dir):
        from tee_crafter.cli.commands.deploy.deploy_container import (
            _warn_if_host_gen_is_a_coin_flip,
        )

        class _Console:
            def __init__(self):
                self.lines = []

            def print(self, text):
                self.lines.append(text)

        variants = [
            {"vm_size": "Standard_DC2as_v5", "vcpu": 2, "measurement": "aa" * 48,
             "cpu_gen": gen, "cpu_gen_source": "observed"}
            for gen in captured_gens
        ]
        _write(registry_dir, platform, "img-x", _record("img-x", variants))
        console = _Console()
        fired = _warn_if_host_gen_is_a_coin_flip(
            console, platform, "img-x", _registry,
            host_gen_is_selectable(platform), expected_host_gens(platform))
        return fired, "\n".join(console.lines)

    def test_it_fires_when_only_one_of_two_generations_was_captured(self,
                                                                   registry_dir):
        fired, text = self._warn("snp-azure", ["genoa"], registry_dir)
        assert fired is True
        assert "genoa" in text and "milan" in text

    def test_it_is_quiet_when_both_were_captured(self, registry_dir):
        fired, _ = self._warn("snp-azure", ["genoa", "milan"], registry_dir)
        assert fired is False

    def test_it_is_quiet_on_a_single_generation_platform(self, registry_dir):
        """gpu-cc-azure has one SKU and one expected generation, so there is
        nothing to warn about and warning anyway would train operators to
        ignore it."""
        fired, _ = self._warn("gpu-cc-azure", ["genoa"], registry_dir)
        assert fired is False

    def test_it_is_quiet_where_the_generation_is_selectable(self, registry_dir):
        fired, _ = self._warn("snp-aws", ["milan"], registry_dir)
        assert fired is False

    def test_it_tells_the_operator_not_to_hand_pin_the_missing_digest(self,
                                                                     registry_dir):
        """The fix is a re-bake. Hand-pinning the second digest would record a
        value nobody measured, which is the unverifiable `manual` pin this whole
        area is about."""
        _, text = self._warn("snp-azure", ["genoa"], registry_dir)
        assert "re-bake" in text.lower()
        assert "hand-pin" in text.lower()

    def test_it_says_the_failure_mode_is_fail_closed(self, registry_dir):
        """An operator reading this needs to know the risk is a refusal to
        attest, not a silent acceptance."""
        _, text = self._warn("snp-azure", ["genoa"], registry_dir)
        assert "fail closed" in text.lower()


class TestManualPinsLabelTheirGuessedGeneration:
    """`internal pin-measurement` has no VM to ask, so any generation it records
    is inferred. Leaving it unlabelled made a guess indistinguishable from an
    observation — and the comparison tooling relies on telling them apart."""

    def test_the_command_marks_the_source_as_inferred(self):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "src", "tee_crafter", "cli", "commands",
            "pin_measurement.py")
        with open(path, "r", encoding="utf-8") as fh:
            src = fh.read()
        assert 'variant["cpu_gen_source"] = "instance_type"' in src
