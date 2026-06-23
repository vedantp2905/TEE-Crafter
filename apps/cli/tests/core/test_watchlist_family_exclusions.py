"""The machine families `docs/watchlist.md` warns about must stay rejected.

That file exists to stop a specific mistake: adding a Google Cloud machine
family to a platform because its generation number looks newer, when the family
offers a materially weaker guarantee. The warnings were prose only, so nothing
stopped the change they warn against. These tests pin them.

Each case is a distinct trap:

* **C4D / C2D / C3D on `snp-gcp`** — these are plain AMD **SEV**, not SEV-SNP.
  SEV without SNP lacks the integrity protection and the attestation report this
  project's evidence chain is built on. C4D being the newest AMD silicon in
  Compute Engine is exactly what makes it tempting.
* **C4 on `tdx-gcp`** — Intel TDX on C4 was in Preview when last checked.
  Accepting it would also need a fresh `MRTD`, because the launch measurement is
  specific to the platform firmware and does not carry over from C3.
* **The local-SSD C3 variants** — a separate Preview from C3 itself, and local
  SSD is ephemeral, so anything written there is neither measured nor persisted.
* **G4 on `gpu-cc-gcp`** — pairs AMD SEV (not SNP) with NVIDIA confidential
  computing. Close enough to be tempting, and strictly weaker on the CPU side
  than the Intel TDX this platform uses today.

A failure here is not necessarily a bug: if a family genuinely gains SEV-SNP or
TDX general availability, that is a real platform addition. It needs its own
measurement capture and, for G4, its own trust-model write-up — not a catalog
row and a green test. Update `docs/watchlist.md` in the same change.
"""
from __future__ import annotations

import pytest

from tee_crafter.core import catalog


class TestSnpGcpRequiresSevSnpNotPlainSev:

    @pytest.mark.parametrize("machine_type", [
        "c4d-standard-4", "c4d-standard-8", "c4d-highmem-8",
        "c2d-standard-4", "c3d-standard-4", "c3d-highmem-8",
    ])
    def test_sev_only_families_are_rejected(self, machine_type):
        assert catalog.lookup("snp-gcp", machine_type) is None

    def test_n2d_is_still_accepted(self):
        """Guards the negative tests: a gate that rejects everything would
        pass them all while breaking the platform."""
        assert catalog.lookup("snp-gcp", "n2d-standard-2") is not None

    def test_the_default_is_an_n2d_shape(self):
        assert catalog.default_instance_type("snp-gcp").startswith("n2d-")


class TestTdxGcpAcceptsC3Only:

    @pytest.mark.parametrize("machine_type", [
        "c4-standard-4", "c4-standard-8", "c4-highmem-8",
    ])
    def test_c4_is_rejected_while_tdx_there_is_preview(self, machine_type):
        assert catalog.lookup("tdx-gcp", machine_type) is None

    @pytest.mark.parametrize("machine_type", [
        "c3-standard-4-lssd", "c3-standard-8-lssd",
    ])
    def test_the_local_ssd_variants_are_rejected(self, machine_type):
        """Ephemeral scratch inside a TDX guest is neither measured nor
        persisted, so it must not hold state a verifier reasons about."""
        assert catalog.lookup("tdx-gcp", machine_type) is None

    def test_plain_c3_is_still_accepted(self):
        assert catalog.lookup("tdx-gcp", "c3-standard-4") is not None

    def test_the_default_is_a_c3_shape(self):
        assert catalog.default_instance_type("tdx-gcp").startswith("c3-")


class TestGpuCcGcpKeepsItsTdxCpuSide:

    @pytest.mark.parametrize("machine_type", [
        "g4-standard-4", "g4-highgpu-1g",
    ])
    def test_g4_is_rejected(self, machine_type):
        """G4's CPU side is SEV without SNP — a different trust model, not a
        new instance type on this one."""
        assert catalog.lookup("gpu-cc-gcp", machine_type) is None

    def test_the_default_is_an_a3_shape(self):
        assert catalog.default_instance_type("gpu-cc-gcp").startswith("a3-")

    def test_the_template_pins_tdx_explicitly(self):
        """The CPU-side evidence here is an Intel TDX MRTD, and the template
        says so rather than letting the provider infer a type."""
        import os
        import tee_crafter
        tf = os.path.join(os.path.dirname(tee_crafter.__file__),
                          "templates", "gpu_cc", "gcp", "main.template.tf")
        assert 'confidential_instance_type = "TDX"' in open(tf).read()


class TestNoneOfThemAreInTheCatalogAtAll:
    """Belt and braces: `lookup` returning None could also come from a
    platform gate while the row exists and is reachable another way."""

    @pytest.mark.parametrize("prefix", ["c4-", "c4d-", "c2d-", "c3d-", "g4-"])
    def test_no_row_uses_the_prefix(self, prefix):
        import os
        src = open(os.path.join(os.path.dirname(catalog.__file__),
                                "catalog.py"), encoding="utf-8").read()
        assert f'"{prefix}' not in src
