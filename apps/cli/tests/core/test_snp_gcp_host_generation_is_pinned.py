"""The snp-gcp deploy must ask for the CPU generation the bake measured on.

An AMD SEV-SNP launch measurement folds in host firmware and microcode, so it is
specific to the host CPU generation. The bake pins the generation it measures on
— ``--min-cpu-platform "AMD Milan"`` in ``baking/gcp.py`` — and the deploy
template did not pin anything, so the digest being attested against and the host
producing it were held together only by N2D happening to offer nothing newer
that SEV-SNP runs on. True today; not a thing to depend on silently, and exactly
the class of assumption that turned into a false measurement mismatch on Azure.

Verified against Terraform: ``terraform validate`` accepts ``min_cpu_platform``
on ``google_compute_instance`` in this configuration (2026-08-23), so the
argument is real rather than assumed.
"""
from __future__ import annotations

import os
import re

import pytest

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "src", "tee_crafter")
_TEMPLATE = os.path.join(_SRC, "templates", "snp", "gcp", "main.template.tf")
_BAKE = os.path.join(_SRC, "cli", "commands", "baking", "gcp.py")


def _template() -> str:
    with open(_TEMPLATE, "r", encoding="utf-8") as fh:
        return fh.read()


class TestTheDeployPinsTheGeneration:

    def test_the_instance_sets_min_cpu_platform(self):
        assert re.search(r"^\s*min_cpu_platform\s*=", _template(), re.MULTILINE)

    def test_it_is_a_variable_so_an_operator_can_change_it(self):
        assert 'variable "min_cpu_platform"' in _template()

    def test_an_empty_value_falls_back_to_google_choosing(self):
        """Opting out has to be possible without editing the template — a
        capacity problem in one generation should not need a code change."""
        src = _template()
        assert re.search(r'var\.min_cpu_platform\s*!=\s*""', src)
        assert re.search(r'var\.min_cpu_platform\s*!=\s*""[^\n]*:\s*null', src)


class TestTheBakeAndTheDeployAgree:
    """The point of pinning is that the two values are the same one. Two
    independently-correct settings that disagree would pin a digest captured on
    one generation and then attest against a VM on another."""

    def test_the_bake_pins_a_generation_for_snp_gcp(self):
        with open(_BAKE, "r", encoding="utf-8") as fh:
            bake = fh.read()
        match = re.search(
            r'platform="SNP-GCP".*?min_cpu_platform="([^"]+)"', bake, re.S)
        assert match, "the snp-gcp bake no longer pins min_cpu_platform"
        assert match.group(1) == "AMD Milan"

    def test_the_template_default_is_the_same_value(self):
        src = _template()
        block = src[src.index('variable "min_cpu_platform"'):]
        block = block[:block.index("}")]
        assert 'default     = "AMD Milan"' in block or \
               'default = "AMD Milan"' in block, block


class TestTheMachineTypeDescriptionMatchesTheCatalog:
    """The description used to say "Must be N2D, C2D, or C3D for AMD SEV-SNP".
    C2D and C3D are plain AMD SEV — no integrity protection and no attestation
    report — and the catalog rejects them for this platform. A template
    documenting a family the code refuses is an invitation to "fix" the code."""

    @staticmethod
    def _description() -> str:
        """The ``description =`` string only.

        Deliberately not the whole variable block: the comment above it names
        C2D and C3D in order to explain why they are excluded, and asserting
        over the block would match that explanation and fail. Pinning the wrong
        text is how a passing test ends up guarding nothing.
        """
        src = _template()
        block = src[src.index('variable "machine_type"'):]
        block = block[:block.index("\n}")]
        match = re.search(r'description\s*=\s*"([^"]*)"', block)
        assert match, "machine_type has no description"
        return match.group(1)

    @pytest.mark.parametrize("family", ["C2D", "C3D", "C4D"])
    def test_sev_only_families_are_not_advertised(self, family):
        assert family not in self._description()

    def test_n2d_is_still_named(self):
        assert "N2D" in self._description()

    def test_the_catalog_agrees(self):
        from tee_crafter.core import catalog
        assert catalog.lookup("snp-gcp", "c2d-standard-4") is None
        assert catalog.lookup("snp-gcp", "n2d-standard-2") is not None
