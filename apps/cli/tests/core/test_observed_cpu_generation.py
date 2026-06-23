"""The CPU generation must be observed, not inferred from the instance type.

Azure schedules ``Standard_DCxas_v5`` on Milan **or** Genoa hosts, and the
SEV-SNP launch measurement depends on the host firmware. Inferring the
generation from the ``v5``/``v6`` suffix therefore produces a label that can be
wrong, and — worse — makes a host-generation difference look like a vCPU-tier
difference.

Both halves of that were observed on real hardware:

* A live ``Standard_DC2as_v5`` validated its VCEK against the **Genoa** chain
  and had its firmware SVN checked as Genoa-class, while
  ``instance_gen('snp-azure', 'Standard_DC2as_v5')`` says ``milan``.
* Three ``snp-azure`` bakes of the same image family disagreed: two recorded
  ``DC2as_v5`` and ``DC4as_v5`` as having the same digest and concluded the
  digest was vCPU-independent; one recorded them as different. Equal digests
  under two guessed labels are equally consistent with both probes having
  landed on the same host generation, which is the likelier reading given AWS
  and GCP show a distinct digest for *every* vCPU tier.

So the fix is not a better guess. It is to have the measuring VM report its own
CPU model, to mark whether a generation was observed or inferred, and to refuse
to record the independence claim unless it was observed.
"""
from __future__ import annotations

import pytest

from tee_crafter.core.measurements import capture as cap


class TestTheVmReportsItsOwnCpu:

    @pytest.mark.parametrize("platform", ["snp-azure", "tdx-azure", "snp-aws",
                                          "tdx-gcp", "snp-gcp"])
    def test_the_probe_is_in_every_capture_command(self, platform):
        assert "TEE_CRAFTER_CPU_MODEL=" in cap.capture_command(platform)

    @pytest.mark.parametrize("platform", ["snp-azure", "tdx-azure"])
    def test_the_probe_runs_before_the_readers(self, platform):
        """The readers exit as soon as one succeeds.

        Appended rather than prepended, the probe would never run on the common
        path — which is the failure mode where a diagnostic is present in the
        source and absent from every log.
        """
        cmd = cap.capture_command(platform)
        assert cmd.index("TEE_CRAFTER_CPU_MODEL=") < cmd.index("PYEOF")

    def test_it_reads_the_model_name_field(self):
        assert "/proc/cpuinfo" in cap.capture_command("snp-azure")

    def test_the_model_line_parses(self):
        text = ("TEE_CRAFTER_CPU_MODEL=AMD EPYC 7V13 64-Core Processor\n"
                "TEE_CRAFTER_MEASUREMENT=" + "ab" * 48 + "\n")
        assert cap.parse_cpu_model_line(text) == "AMD EPYC 7V13 64-Core Processor"

    def test_the_measurement_still_parses_alongside_it(self):
        text = ("TEE_CRAFTER_CPU_MODEL=AMD EPYC 7V13\n"
                "TEE_CRAFTER_MEASUREMENT=" + "ab" * 48 + "\n")
        assert cap.parse_measurement_line(text) == "ab" * 48

    @pytest.mark.parametrize("text", ["", "no model here", None])
    def test_a_missing_model_is_none_not_a_guess(self, text):
        assert cap.parse_cpu_model_line(text) is None


class TestGenerationFromTheReportedModel:

    @pytest.mark.parametrize("model,gen", [
        # The cloud parts carry a letter, so a four-digit match would miss them.
        ("AMD EPYC 7V13 64-Core Processor", "milan"),
        ("AMD EPYC 9V84 96-Core Processor", "genoa"),
        ("AMD EPYC 7763 64-Core Processor", "milan"),
        ("AMD EPYC 9004", "genoa"),
        ("AMD EPYC 7002", "rome"),
    ])
    def test_known_parts(self, model, gen):
        assert cap.gen_from_cpu_model(model) == gen

    @pytest.mark.parametrize("model", [
        "Intel(R) Xeon(R) Platinum 8480C CPU @ 2.00GHz",
        "AMD Ryzen 9 5950X",
        "unknown",
        "",
        None,
    ])
    def test_anything_unrecognised_is_none(self, model):
        """None, never a default.

        A guessed label that looks observed is the defect being removed; a
        caller receiving None must record no generation at all.
        """
        assert cap.gen_from_cpu_model(model) is None


class TestTheInferredLabelIsStillWrongAndThatIsThePoint:
    """Guards the premise. If Azure ever exposes the generation in the SKU,
    this test fails and the observed-generation machinery can be revisited."""

    def test_the_instance_type_says_milan_for_dc2as_v5(self):
        from tee_crafter.core.measurements.shapes import instance_gen
        assert instance_gen("snp-azure", "Standard_DC2as_v5") == "milan"

    def test_but_that_size_ran_on_genoa(self):
        """Documented, not executable: the evidence is a hardware run.

        ``AMD certificate chain: PASSED against Genoa`` and
        ``SNP SVN bits 55:48 = 0x1C >= 0x16 for Genoa-class`` came off a live
        ``Standard_DC2as_v5``. Kept as a named test so the contradiction is
        discoverable from the suite rather than only from a log.
        """
        from tee_crafter.core.measurements.shapes import instance_gen
        inferred = instance_gen("snp-azure", "Standard_DC2as_v5")
        observed = cap.gen_from_cpu_model("AMD EPYC 9V84 96-Core Processor")
        assert inferred != observed


class TestTheIndependenceClaimRequiresObservation:
    """``vcpu_independent_gens`` is a claim about the platform, so it needs
    evidence; the early stop is only cost control, so it does not."""

    def test_the_claim_is_gated_on_observation(self):
        src = open(_capture_src(), encoding="utf-8").read()
        block = src[src.index("# Early stop, and the independence *claim*"):]
        head = block[:block.index("if not variants:")]
        assert "all_observed" in head
        assert "cpu_gen_source" in head

    def test_the_early_stop_is_not_gated_on_observation(self):
        """Requiring observation to stop probing would boot every vCPU tier on
        clouds where the model is not reported — real VMs, real money."""
        src = open(_capture_src(), encoding="utf-8").read()
        block = src[src.index("# Early stop, and the independence *claim*"):]
        head = block[:block.index("if not variants:")]
        stop = head[head.index("skip_gens.add("):]
        assert stop.startswith("skip_gens.add(gen)")

    def test_variants_record_which_kind_of_label_they_carry(self):
        src = open(_capture_src(), encoding="utf-8").read()
        assert '"cpu_gen_source"] = "observed" if obs_gen else "instance_type"' \
            in src.replace("variant[", "")


def _capture_src() -> str:
    import tee_crafter.cli.commands.baking.common.measurement_capture as mc
    return mc.__file__
