"""Tests for concrete attestation providers (with injected report readers).

The TDX fixtures below are built from the **published container layouts**, not
from the constants the code reads.  The previous fixture was
``_tdx_report(mrtd_hex, off=0x130)`` -- the same 0x130 the provider used -- so
it validated the code against itself and could never fail, which is how a
wrong offset shipped.  Here each field is placed at its spec offset and the
MRTD position falls out of the surrounding structure.
"""
from __future__ import annotations

import hashlib
import struct

import pytest

from tee_crafter.core.keys.attestation_providers import (
    TDX_AZURE_HCLA_MRTD_OFFSET,
    TDX_QUOTE_MRTD_OFFSET,
    TDX_TDREPORT_MRTD_OFFSET,
    SnpAttestationProvider,
    TdxAttestationProvider,
    build_for_platform,
    detect_tdx_mrtd_offset,
)


def _snp_report(meas_hex: str) -> bytes:
    return bytes(0x90) + bytes.fromhex(meas_hex) + bytes(1184 - 0x90 - 48)


# --- TDX fixtures assembled field-by-field from the spec layouts ------------

def _tdx_quote(mrtd_hex: str, *, version: int = 4,
               tee_type: int = 0x00000081) -> bytes:
    """A TD Quote v4 built from the DCAP quote layout.

    Header (48 B): version u16 | att_key_type u16 | tee_type u32 |
                   qe_svn u16 | pce_svn u16 | qe_vendor_id 16 B | user_data 20 B
    TD Quote Body (584 B): TEE_TCB_SVN 16 | MRSEAM 48 | MRSIGNERSEAM 48 |
                   SEAMATTRIBUTES 8 | TDATTRIBUTES 8 | XFAM 8 | MRTD 48 |
                   MRCONFIGID 48 | MROWNER 48 | MROWNERCONFIG 48 |
                   RTMR[0..3] 4x48 | REPORTDATA 64
    """
    header = (
        struct.pack("<HHIHH", version, 2, tee_type, 0, 0)
        + b"\x93\x9a\x72\x33\xf7\x9c\x4c\xa9\x94\x0a\x0d\xb3\x95\x7f\x06\x07"  # QE vendor
        + bytes(20)                                                            # user_data
    )
    assert len(header) == 48, len(header)
    body = (
        bytes(16)                    # TEE_TCB_SVN
        + bytes(48)                  # MRSEAM
        + bytes(48)                  # MRSIGNERSEAM
        + bytes(8)                   # SEAMATTRIBUTES
        + bytes(8)                   # TDATTRIBUTES
        + bytes(8)                   # XFAM
        + bytes.fromhex(mrtd_hex)    # MRTD
        + bytes(48)                  # MRCONFIGID
        + bytes(48)                  # MROWNER
        + bytes(48)                  # MROWNERCONFIG
        + bytes(48 * 4)              # RTMR[0..3]
        + bytes(64)                  # REPORTDATA
    )
    assert len(body) == 584, len(body)
    return header + body + bytes(64)  # + a stub signature-data tail


def _tdx_tdreport(mrtd_hex: str) -> bytes:
    """A bare 1024-byte TDREPORT_STRUCT per the Intel TDX Module ABI.

    REPORTMACSTRUCT 256 | TEE_TCB_INFO 256 | TDINFO_STRUCT 512, and inside
    TDINFO_STRUCT: ATTRIBUTES 8 | XFAM 8 | MRTD 48 | ...
    """
    reportmac = bytes(256)
    tee_tcb_info = bytes(256)
    tdinfo = (
        bytes(8)                    # ATTRIBUTES
        + bytes(8)                  # XFAM
        + bytes.fromhex(mrtd_hex)   # MRTD
        + bytes(512 - 8 - 8 - 48)   # MRCONFIGID / MROWNER / ... / reserved
    )
    assert len(tdinfo) == 512, len(tdinfo)
    report = reportmac + tee_tcb_info + tdinfo
    assert len(report) == 1024, len(report)
    return report


def _tdx_azure_hcla(mrtd_hex: str) -> bytes:
    """Azure HCLA blob: 32-byte header ('HCLA', version, size) + TDREPORT."""
    header = b"HCLA" + struct.pack("<II", 2, 1024) + bytes(20)
    assert len(header) == 32, len(header)
    return header + _tdx_tdreport(mrtd_hex) + b'{"runtime":"data"}'


class TestTdxContainerOffsets:
    """The offsets the code uses must match the independently-built fixtures."""

    def test_quote_offset(self):
        mrtd = "cd" * 48
        quote = _tdx_quote(mrtd)
        assert quote.index(bytes.fromhex(mrtd)) == TDX_QUOTE_MRTD_OFFSET
        assert TDX_QUOTE_MRTD_OFFSET == 184

    def test_tdreport_offset(self):
        mrtd = "ef" * 48
        report = _tdx_tdreport(mrtd)
        assert report.index(bytes.fromhex(mrtd)) == TDX_TDREPORT_MRTD_OFFSET
        assert TDX_TDREPORT_MRTD_OFFSET == 528

    def test_azure_hcla_offset(self):
        mrtd = "1a" * 48
        blob = _tdx_azure_hcla(mrtd)
        assert blob.index(bytes.fromhex(mrtd)) == TDX_AZURE_HCLA_MRTD_OFFSET
        assert TDX_AZURE_HCLA_MRTD_OFFSET == 560

    def test_0x130_is_not_any_of_them(self):
        """Regression guard: 304 was the shipped default and matches nothing."""
        assert 0x130 not in (TDX_QUOTE_MRTD_OFFSET, TDX_TDREPORT_MRTD_OFFSET,
                             TDX_AZURE_HCLA_MRTD_OFFSET)

    @pytest.mark.parametrize("build,expected", [
        (_tdx_quote, TDX_QUOTE_MRTD_OFFSET),
        (_tdx_tdreport, TDX_TDREPORT_MRTD_OFFSET),
        (_tdx_azure_hcla, TDX_AZURE_HCLA_MRTD_OFFSET),
    ])
    def test_detection(self, build, expected):
        assert detect_tdx_mrtd_offset(build("77" * 48)) == expected

    def test_detection_refuses_to_guess(self):
        with pytest.raises(ValueError, match="unrecognised TDX"):
            detect_tdx_mrtd_offset(b"\x00" * 400)


class TestSnpProvider:
    def test_fresh_returns_measurement_sha256(self):
        meas = "ab" * 48
        captured = {}

        def reader(nonce):
            captured["nonce"] = nonce
            return _snp_report(meas)

        p = SnpAttestationProvider(report_reader=reader)
        blob, ts, sha = p.fresh(purpose="data_decrypt", nonce=b"nonce123")
        assert captured["nonce"] == b"nonce123"
        assert sha == hashlib.sha256(bytes.fromhex(meas)).hexdigest()
        assert len(sha) == 64
        assert ts > 0
        assert blob  # non-empty (orchestrator preflight requires it)

    def test_measurement_sha_matches_deploy_policy(self):
        """The in-guest sha must equal what the deploy auto-pin computes."""
        from tee_crafter.cli.commands.deploy.measurement_pin import policy_sha256
        meas = "3f" * 48
        p = SnpAttestationProvider(report_reader=lambda n: _snp_report(meas))
        _, _, sha = p.fresh(purpose="x")
        assert sha == policy_sha256(meas)


class TestTdxProvider:
    @pytest.mark.parametrize("build", [_tdx_quote, _tdx_tdreport, _tdx_azure_hcla])
    def test_fresh_returns_mrtd_sha256(self, build):
        mrtd = "cd" * 48
        p = TdxAttestationProvider(report_reader=lambda n: build(mrtd))
        _, _, sha = p.fresh(purpose="x", nonce=b"n")
        assert sha == hashlib.sha256(bytes.fromhex(mrtd)).hexdigest()

    def test_measurement_sha_matches_deploy_policy(self):
        """The in-guest sha must equal what the deploy auto-pin computes."""
        from tee_crafter.cli.commands.deploy.measurement_pin import policy_sha256
        mrtd = "3f" * 48
        p = TdxAttestationProvider(report_reader=lambda n: _tdx_quote(mrtd))
        _, _, sha = p.fresh(purpose="x")
        assert sha == policy_sha256(mrtd)

    def test_explicit_offset_overrides_detection(self):
        mrtd = "9a" * 48
        p = TdxAttestationProvider(
            report_reader=lambda n: _tdx_azure_hcla(mrtd),
            mrtd_offset=TDX_AZURE_HCLA_MRTD_OFFSET)
        _, _, sha = p.fresh(purpose="x")
        assert sha == hashlib.sha256(bytes.fromhex(mrtd)).hexdigest()

    def test_unrecognised_container_fails_loudly(self):
        """Better a hard error than a plausible hash of the wrong 48 bytes."""
        p = TdxAttestationProvider(report_reader=lambda n: b"\x00" * 300)
        with pytest.raises(ValueError, match="unrecognised TDX"):
            p.fresh(purpose="x")


class TestFactory:
    @pytest.mark.parametrize("platform,cls", [
        ("snp-aws", SnpAttestationProvider),
        ("gpu-cc-aws", SnpAttestationProvider),
        ("tdx-azure", TdxAttestationProvider),
        ("gpu-cc-gcp", TdxAttestationProvider),
    ])
    def test_build_for_platform(self, platform, cls):
        prov = build_for_platform(platform, report_reader=lambda n: _snp_report("ab" * 48))
        assert isinstance(prov, cls)

    def test_unknown_platform_raises(self):
        with pytest.raises(ValueError):
            build_for_platform("nitro-aws")
