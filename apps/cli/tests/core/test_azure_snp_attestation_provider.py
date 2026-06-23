"""Azure SEV-SNP CVMs have no ``/dev/sev-guest``; the report comes from the vTPM.

Verified on hardware on 2026-08-23: a live ``Standard_DC2as_v5`` confidential VM
exposes ``/dev/tpm0`` and ``/dev/tpmrm0`` and has neither ``/dev/sev-guest`` nor
``/dev/sev``.  Before this, ``snp-azure`` and ``gpu-cc-azure`` were mapped to the
``/dev/sev-guest`` reader, so every BYOK release on those platforms died with
``attestation provider failed: FileNotFoundError`` and fail-closed kept the
workload stopped -- i.e. ``--byok`` could not work at all there.
"""
from __future__ import annotations

import struct

import pytest

from tee_crafter.core.keys import attestation_providers as ap


def _hcl_blob(measurement: bytes = b"\xb2" * 48, *, magic=b"HCLA",
              version: int = 2, report_size: int = 1184,
              header: int = 32) -> bytes:
    """Build an Azure HCL blob framing a synthetic AMD SNP report."""
    report = bytearray(report_size)
    struct.pack_into("<I", report, 0, version)
    report[0x90:0x90 + 48] = measurement
    return magic + b"\x00" * (header - len(magic)) + bytes(report)


class _Run:
    """Stand-in for subprocess.run over tpm2_nvread."""

    def __init__(self, stdout=b"", returncode=0, stderr=b""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr
        self.argv = None

    def __call__(self, argv, **kw):
        self.argv = argv
        return self


@pytest.fixture
def patch_run(monkeypatch):
    def _apply(runner):
        import subprocess
        monkeypatch.setattr(subprocess, "run", runner)
        return runner
    return _apply


class TestPlatformMapping:

    def test_azure_snp_platforms_use_the_vtpm_provider(self):
        for platform in ("snp-azure", "gpu-cc-azure"):
            p = ap.build_for_platform(platform)
            assert isinstance(p, ap.AzureSnpAttestationProvider), platform

    @pytest.mark.parametrize("platform", ["snp-aws", "snp-gcp", "gpu-cc-aws"])
    def test_non_azure_snp_platforms_keep_the_sev_guest_reader(self, platform):
        """AWS and GCP do expose /dev/sev-guest; do not regress them."""
        p = ap.build_for_platform(platform)
        assert isinstance(p, ap.SnpAttestationProvider)
        assert not isinstance(p, ap.AzureSnpAttestationProvider)

    def test_azure_provider_is_a_specialisation_not_a_fork(self):
        """It must reuse the SNP measurement parsing, only swapping the source."""
        assert issubclass(ap.AzureSnpAttestationProvider,
                          ap.SnpAttestationProvider)


class TestVtpmReader:

    def test_returns_the_amd_report_body(self, patch_run):
        patch_run(_Run(stdout=_hcl_blob()))
        report = ap._read_snp_report_vtpm(b"")
        assert len(report) == 1184
        assert report[0x90:0x90 + 48] == b"\xb2" * 48

    def test_reads_the_documented_nv_index(self, patch_run):
        r = patch_run(_Run(stdout=_hcl_blob()))
        ap._read_snp_report_vtpm(b"")
        assert "tpm2_nvread" in r.argv[0]
        assert "0x01400001" in r.argv

    def test_rejects_a_bad_magic(self, patch_run):
        patch_run(_Run(stdout=_hcl_blob(magic=b"XXXX")))
        with pytest.raises(RuntimeError, match="bad HCL magic"):
            ap._read_snp_report_vtpm(b"")

    def test_rejects_a_short_blob(self, patch_run):
        patch_run(_Run(stdout=b"HCLA" + b"\x00" * 100))
        with pytest.raises(RuntimeError, match="too small"):
            ap._read_snp_report_vtpm(b"")

    def test_rejects_an_old_report_version(self, patch_run):
        patch_run(_Run(stdout=_hcl_blob(version=1)))
        with pytest.raises(RuntimeError, match="version"):
            ap._read_snp_report_vtpm(b"")

    def test_surfaces_tpm2_nvread_failure(self, patch_run):
        patch_run(_Run(returncode=1, stderr=b"NV index not found"))
        with pytest.raises(RuntimeError, match="NV index not found"):
            ap._read_snp_report_vtpm(b"")


class TestProviderOutput:

    def test_fresh_returns_the_measurement_sha(self, patch_run):
        import hashlib
        meas = b"\xb2" * 48
        patch_run(_Run(stdout=_hcl_blob(measurement=meas)))
        provider = ap.build_for_platform("snp-azure")
        report, issued_at, meas_sha = provider.fresh(purpose="byok")
        assert len(report) == 1184
        assert issued_at > 0
        assert meas_sha == hashlib.sha256(meas).hexdigest()

    def test_nonce_is_accepted_but_cannot_be_bound(self, patch_run):
        """The HCL report is host-minted, so REPORT_DATA is fixed.

        Documented rather than silently ignored: freshness for the actual
        release comes from the MAA token AzureAttestSKR mints, not from here.
        """
        blob = _hcl_blob()
        patch_run(_Run(stdout=blob))
        provider = ap.build_for_platform("snp-azure")
        a, _, _ = provider.fresh(purpose="byok", nonce=b"\x01" * 32)
        b, _, _ = provider.fresh(purpose="byok", nonce=b"\x02" * 32)
        assert a == b
