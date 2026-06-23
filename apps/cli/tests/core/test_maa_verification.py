"""C1: verify MAA tokens for tdx-azure instead of refusing outright.

The Azure vTPM path used to `sys.exit(1)`, and the reasoning was sound: an HCLA
blob is a raw TDREPORT plus runtime-claims JSON out of vTPM NV 0x01400001, and
nothing in it is checkable client-side — no AK chain in the blob, and the
REPORTMACSTRUCT is MAC'd with a key only the TDX module and the QE hold. The
only party who can make it verifiable is MAA.

So the token is what gets verified, and that is fully testable offline: these
tests mint RS256 tokens with a throwaway RSA key and a matching JWKS, using the
exact claim shape from Microsoft's published TDX example
(https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples).

The negative cases matter more than the positive one. A verifier that accepts
`{"alg":"none"}`, follows the token's own `jku`, or picks "the first RSA key in
the JWKS" is worse than the honest refusal it replaced, because it looks like
verification.
"""
from __future__ import annotations

import json
import time

import pytest

jwt = pytest.importorskip("jwt")

from cryptography.hazmat.primitives.asymmetric import rsa

from tests.core._maa_loader import (
    COMPLIANT_CVM, MaaVerificationError, TDX_ATTESTATION_TYPE,
    attest_tdx_dcap_quote, expected_issuer_for, jwks_url_for,
    verify_maa_tdx_token,
)

ISSUER = "https://maasand001.eus.attest.azure.net"
KID = "test-signing-key-1"
MRTD = "5be56d418d33661a6c21da77c9503a07e430b35eb92a0bd042a6b3c4e79b3c82bb1c594e770d0d129a0724669f1e953f"
REPORT_DATA = "93c6db49f2318387bcebdad0275e206725d948f9000d900344aa44abaef14596" + "0" * 64


@pytest.fixture(scope="module")
def signing():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(signing):
    from jwt.algorithms import RSAAlgorithm
    entry = json.loads(RSAAlgorithm.to_jwk(signing.public_key()))
    entry.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"keys": [entry]}


def _claims(**over):
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 3600,
        "jti": "abc123",
        "eat_profile": "https://aka.ms/maa-eat-profile-tdxvm",
        "attester_tcb_status": "UpToDate",
        "dbgstat": "disabled",
        "x-ms-attestation-type": TDX_ATTESTATION_TYPE,
        "x-ms-compliance-status": COMPLIANT_CVM,
        "x-ms-ver": "1.0",
        "tdx_mrtd": MRTD,
        "tdx_rtmr0": "00" * 48,
        "tdx_rtmr1": "11" * 48,
        "tdx_rtmr2": "22" * 48,
        "tdx_rtmr3": "33" * 48,
        "tdx_report_data": REPORT_DATA,
        "tdx_td_attributes_debug": False,
        "x-ms-runtime": {"keys": [{"kid": "HCLTransferKey", "kty": "RSA"}]},
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not _OMIT}


_OMIT = object()


def _token(signing, *, headers=None, **over):
    hdr = {"kid": KID, "jku": f"{ISSUER}/certs"}
    hdr.update(headers or {})
    return jwt.encode(_claims(**over), signing, algorithm="RS256", headers=hdr)


def _verify(tok, jwks, **kw):
    kw.setdefault("expected_issuer", ISSUER)
    return verify_maa_tdx_token(tok, jwks=jwks, **kw)


class TestAValidTokenIsAccepted:
    def test_it_verifies_and_reports_the_measurements(self, signing, jwks):
        v = _verify(_token(signing), jwks)
        assert v.mrtd == MRTD
        assert v.rtmrs == ("00" * 48, "11" * 48, "22" * 48, "33" * 48)
        assert v.issuer == ISSUER
        assert v.tcb_status == "UpToDate"
        assert v.debug is False

    def test_it_surfaces_the_skr_transfer_key(self, signing, jwks):
        """`x-ms-runtime.keys` carries HCLTransferKey — the key Managed HSM
        wraps the released DEK to.  This is the C1 -> C2 handoff."""
        v = _verify(_token(signing), jwks)
        assert v.runtime_keys
        assert v.runtime_keys[0]["kid"] == "HCLTransferKey"

    def test_pinning_matching_measurements_passes(self, signing, jwks):
        v = _verify(_token(signing), jwks, expected_mrtd=MRTD,
                    expected_rtmrs=["00" * 48, "", "", ""],
                    expected_report_data=REPORT_DATA)
        assert v.mrtd == MRTD

    def test_pinning_is_case_insensitive(self, signing, jwks):
        assert _verify(_token(signing), jwks, expected_mrtd=MRTD.upper()).mrtd == MRTD


class TestSignatureAndKeyResolution:
    def test_an_unsigned_token_is_refused(self, signing, jwks):
        """`{"alg":"none"}` must never reach claim parsing."""
        tok = jwt.encode(_claims(), key="", algorithm="none",
                         headers={"kid": KID})
        with pytest.raises(MaaVerificationError, match="alg is 'none'"):
            _verify(tok, jwks)

    def test_hmac_alg_confusion_is_refused(self, signing, jwks):
        tok = jwt.encode(_claims(), key="secret", algorithm="HS256",
                         headers={"kid": KID})
        with pytest.raises(MaaVerificationError, match="only RS256"):
            _verify(tok, jwks)

    def test_a_token_signed_by_another_key_is_refused(self, jwks):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(MaaVerificationError, match="signature"):
            _verify(_token(other), jwks)

    def test_an_unknown_kid_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="no JWKS entry"):
            _verify(_token(signing, headers={"kid": "not-published"}), jwks)

    def test_a_missing_kid_is_not_guessed(self, signing, jwks):
        """MAA publishes several keys; 'first RSA key' verifies against a key
        that did not sign the token, sometimes."""
        tok = jwt.encode(_claims(), signing, algorithm="RS256",
                         headers={"jku": f"{ISSUER}/certs"})
        with pytest.raises(MaaVerificationError, match="no `kid`"):
            _verify(tok, jwks)

    def test_an_empty_jwks_is_refused(self, signing):
        with pytest.raises(MaaVerificationError, match="no `keys`"):
            _verify(_token(signing), {"keys": []})


class TestIssuerAndJku:
    def test_a_foreign_issuer_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError):
            _verify(_token(signing, iss="https://evil.attest.azure.net"), jwks)

    def test_a_jku_pointing_elsewhere_is_refused(self, signing, jwks):
        """The header is attacker-influenced; jku is checked, never followed."""
        tok = _token(signing, headers={"jku": "https://evil.example.com/certs"})
        with pytest.raises(MaaVerificationError, match="jku"):
            _verify(tok, jwks)

    def test_a_non_https_expected_issuer_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="must be https"):
            _verify(_token(signing), jwks,
                    expected_issuer="http://maasand001.eus.attest.azure.net")

    def test_trailing_slashes_do_not_change_the_issuer(self):
        assert expected_issuer_for(ISSUER + "/") == ISSUER
        assert jwks_url_for(ISSUER + "/") == ISSUER + "/certs"


class TestExpiry:
    def test_an_expired_token_is_refused(self, signing, jwks):
        now = int(time.time())
        with pytest.raises(MaaVerificationError, match="expired"):
            _verify(_token(signing, exp=now - 3600, nbf=now - 7200,
                           iat=now - 7200), jwks)

    def test_a_not_yet_valid_token_is_refused(self, signing, jwks):
        now = int(time.time())
        with pytest.raises(MaaVerificationError):
            _verify(_token(signing, nbf=now + 7200, iat=now + 7200,
                           exp=now + 10800), jwks)


class TestTheClaimsThatDecideTrust:
    def test_a_non_tdx_token_is_refused(self, signing, jwks):
        """An SEV-SNP token is a valid MAA token for a different platform."""
        with pytest.raises(MaaVerificationError, match="not for a TDX VM"):
            _verify(_token(signing, **{"x-ms-attestation-type": "sevsnpvm"}), jwks)

    def test_a_noncompliant_cvm_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="did not consider this VM compliant"):
            _verify(_token(signing, **{"x-ms-compliance-status": "non-compliant"}), jwks)

    def test_a_debug_trust_domain_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="DEBUG trust domain"):
            _verify(_token(signing, tdx_td_attributes_debug=True), jwks)

    def test_dbgstat_enabled_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="dbgstat"):
            _verify(_token(signing, dbgstat="enabled"), jwks)

    def test_a_token_with_no_mrtd_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="no tdx_mrtd"):
            _verify(_token(signing, tdx_mrtd=""), jwks)

    def test_an_mrtd_mismatch_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="MRTD mismatch"):
            _verify(_token(signing), jwks, expected_mrtd="ab" * 48)

    def test_an_rtmr_mismatch_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="RTMR2 mismatch"):
            _verify(_token(signing), jwks,
                    expected_rtmrs=["", "", "ff" * 48, ""])

    def test_a_report_data_mismatch_is_refused(self, signing, jwks):
        """This is the channel binding — a mismatch means another session."""
        with pytest.raises(MaaVerificationError, match="channel binding"):
            _verify(_token(signing), jwks, expected_report_data="ab" * 64)


class TestTheAttestCall:
    """Thin by design; the security lives in the verifier above."""

    def test_it_posts_to_the_tdxvm_endpoint_and_returns_the_token(self):
        seen = {}

        def _post(url, body):
            seen["url"], seen["body"] = url, body
            return {"token": "the.jwt.here"}

        tok = attest_tdx_dcap_quote(endpoint=ISSUER, tdx_quote=b"\x04\x00" + b"\x00" * 64,
                                    runtime_data=b'{"k":1}', http_post=_post)
        assert tok == "the.jwt.here"
        assert seen["url"].startswith(f"{ISSUER}/attest/TdxVm?api-version=")
        assert "quote" in seen["body"]
        assert seen["body"]["runtimeData"]["dataType"] == "JSON"

    def test_a_response_without_a_token_is_an_error(self):
        with pytest.raises(MaaVerificationError, match="no `token`"):
            attest_tdx_dcap_quote(endpoint=ISSUER, tdx_quote=b"x",
                            http_post=lambda u, b: {"error": "nope"})

    def test_a_transport_failure_is_an_error(self):
        def _boom(u, b):
            raise OSError("connection refused")
        with pytest.raises(MaaVerificationError, match="attest call failed"):
            attest_tdx_dcap_quote(endpoint=ISSUER, tdx_quote=b"x", http_post=_boom)


class TestTheAttestUrlIsPinnedToAVersionThatExists:
    """`/attest/TdxVm` is not served by every api-version.

    Measured against the live shared provider (2026-08-23):
    `2022-08-01` and `2020-10-01` return a bodiless 404, `2023-04-01-preview`
    returns `400 "Quote is empty"` for an empty body. A real `tdx-azure` deploy
    failed on exactly that 404. `/attest/SevSnpVm` answers on all three, which
    is why the wrong pin looked correct until TDX ran.
    """

    def test_default_api_version_is_the_one_that_serves_tdxvm(self):
        seen = {}

        def _post(url, body):
            seen["url"] = url
            return {"token": "t"}

        attest_tdx_dcap_quote(endpoint=ISSUER, tdx_quote=b"x", http_post=_post)
        assert "api-version=2023-04-01-preview" in seen["url"]
        assert "/attest/TdxVm?" in seen["url"]

    def test_the_version_is_still_overridable(self):
        seen = {}

        def _post(url, body):
            seen["url"] = url
            return {"token": "t"}

        attest_tdx_dcap_quote(endpoint=ISSUER, tdx_quote=b"x", http_post=_post,
                        api_version="2099-01-01")
        assert "api-version=2099-01-01" in seen["url"]
