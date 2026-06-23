"""``/attest/AzureGuest`` token verification — the only path an Azure CVM has.

Why this file exists at all, in the words of what it cost: ``tdx-azure`` burned
three live runs on the assumption that an Azure TDX CVM could produce evidence
for ``/attest/TdxVm``.  It cannot.  Per Microsoft's attestation report format
table, vTPM NV ``0x01400001`` is ``[32-byte HCLA header][hardware report at
offset 32, 1024 bytes for TDX][runtime data at 1216]``, and the hardware report
is a *raw* ``TDREPORT`` whose ``REPORTMACSTRUCT`` only the TDX module and the
Quoting Enclave can check.  ``/attest/TdxVm`` verifies Intel DCAP quotes, so it
answered 404 (wrong api-version) and then 400 — and the 400 was never a
body-shaping problem.
https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design

The AzureGuest token differs from the TdxVm token in two ways that both decide
security, and both are asserted below:

1. **The hardware verdict is nested** under ``x-ms-isolation-tee``.  The
   top-level ``x-ms-attestation-type`` is ``azurevm``, which an ordinary Trusted
   Launch VM — no memory encryption, no CVM — also earns.  Checking only the
   outer claim accepts a non-confidential VM.
2. **The session binding is the client-payload nonce**, because ``report_data``
   on a paravisor CVM is spent by the paravisor on the hash of its own runtime
   claims.  A token with no binding is replayable: any Azure tenant can obtain a
   valid ``azure-compliant-cvm`` token for a VM they control.  The previous code
   verified a token and never checked this, which is the defect that matters
   most here.

Token shape is copied from Microsoft's published example rather than invented:
https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from tests.core._maa_loader import (
    AZURE_GUEST_ATTESTATION_TYPE, ISOLATION_TEE_CLAIM, MaaVerificationError,
    expected_client_payload_nonces, verify_maa_azure_guest_token,
)

ISSUER = "https://sharedwus.wus.attest.azure.net"
KID = "test-signing-key"
BINDING = hashlib.sha256(b"a session").digest()
MRTD = "5b" * 48


@pytest.fixture(scope="module")
def signing():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(signing):
    from jwt.algorithms import RSAAlgorithm
    import json as _json

    jwk = _json.loads(RSAAlgorithm.to_jwk(signing.public_key()))
    jwk["kid"] = KID
    return {"keys": [jwk]}


def _isolation_tee(**over):
    """The nested hardware verdict, TDX flavour."""
    tee = {
        "x-ms-attestation-type": "tdxvm",
        "x-ms-compliance-status": "azure-compliant-cvm",
        "attester_tcb_status": "UpToDate",
        "dbgstat": "disabled",
        "tdx_mrtd": MRTD,
        "tdx_rtmr0": "00" * 48,
        "tdx_rtmr1": "11" * 48,
        "tdx_rtmr2": "22" * 48,
        "tdx_rtmr3": "33" * 48,
        "tdx_td_attributes_debug": False,
        "tdx_report_data": "ab" * 64,
        # Present so the tests prove the verifier does NOT take its
        # key-encryption key from here.  Microsoft: "there may be a key under
        # $.x-ms-isolation-tee.x-ms-runtime.keys, this is *not* the key that Key
        # Vault will be using".
        "x-ms-runtime": {"keys": [{"kid": "HCLAkPub", "kty": "RSA",
                                   "key_ops": ["encrypt"],
                                   "n": "aaa", "e": "AQAB"}]},
    }
    tee.update(over)
    return tee


def _claims(*, nonce=None, tee=None, **over):
    if nonce is None:
        nonce = BINDING.hex()
    claims = {
        "iss": ISSUER,
        "iat": 1000,
        "nbf": 1000,
        "exp": 2_000_000_000,
        "x-ms-attestation-type": AZURE_GUEST_ATTESTATION_TYPE,
        "x-ms-azurevm-attestation-protocol-ver": "2.0",
        "secureboot": True,
        ISOLATION_TEE_CLAIM: _isolation_tee() if tee is None else tee,
        "x-ms-runtime": {
            "client-payload": {"nonce": nonce},
            "keys": [{"kid": "TpmEphemeralEncryptionKey", "kty": "RSA",
                      "key_ops": ["encrypt"], "n": "bbb", "e": "AQAB"}],
        },
        "x-ms-ver": "1.0",
    }
    claims.update(over)
    return claims


def _token(signing, *, headers=None, **claim_over):
    import jwt as _jwt

    hdr = {"kid": KID, "jku": f"{ISSUER}/certs"}
    if headers:
        hdr.update(headers)
    # PyJWT refuses to *encode* a null `kid`, but MAA tokens arriving over the
    # wire can simply omit it — which is the case the verifier must refuse
    # rather than guess. Dropping the key is how that token gets built.
    hdr = {k: v for k, v in hdr.items() if v is not None}
    return _jwt.encode(_claims(**claim_over), signing, algorithm="RS256",
                       headers=hdr)


def _verify(tok, jwks, **kw):
    kw.setdefault("expected_binding", BINDING)
    return verify_maa_azure_guest_token(
        tok, expected_issuer=ISSUER, jwks=jwks, **kw)


class TestAValidTokenIsAccepted:
    def test_it_verifies_and_reports_the_nested_verdict(self, signing, jwks):
        v = _verify(_token(signing), jwks)
        assert v.issuer == ISSUER
        assert v.mrtd == MRTD
        assert v.compliance_status == "azure-compliant-cvm"
        assert v.tcb_status == "UpToDate"
        assert v.rtmrs[1] == "11" * 48
        assert v.debug is False

    def test_pinning_a_matching_mrtd_passes(self, signing, jwks):
        assert _verify(_token(signing), jwks, expected_mrtd=MRTD.upper()).mrtd == MRTD

    def test_an_mrtd_mismatch_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="MRTD mismatch"):
            _verify(_token(signing), jwks, expected_mrtd="cd" * 48)

    def test_an_rtmr_mismatch_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="RTMR2 mismatch"):
            _verify(_token(signing), jwks,
                    expected_rtmrs=["", "", "ff" * 48, ""])


class TestTheKeyEncryptionKeyComesFromTheOuterRuntime:
    """SKR wraps to the *top-level* ``x-ms-runtime.keys`` key.

    Both levels carry a key in a real token and they are different keys; taking
    the wrong one produces a release that cannot be unwrapped, and nothing
    detects it until a live Managed HSM call.
    """

    def test_it_returns_the_tpm_ephemeral_key_not_the_ak(self, signing, jwks):
        v = _verify(_token(signing), jwks)
        kids = [k.get("kid") for k in v.runtime_keys]
        assert kids == ["TpmEphemeralEncryptionKey"]
        assert "HCLAkPub" not in kids


class TestATrustedLaunchVmIsNotAConfidentialVm:
    """The failure mode of checking only the outer attestation type."""

    def test_a_token_with_no_isolation_tee_is_refused(self, signing, jwks):
        tok = _token(signing, **{ISOLATION_TEE_CLAIM: None})
        with pytest.raises(MaaVerificationError, match="no 'x-ms-isolation-tee'"):
            _verify(tok, jwks)

    def test_an_empty_isolation_tee_is_refused(self, signing, jwks):
        tok = _token(signing, **{ISOLATION_TEE_CLAIM: {}})
        with pytest.raises(MaaVerificationError, match="no 'x-ms-isolation-tee'"):
            _verify(tok, jwks)

    def test_the_outer_type_must_still_be_azurevm(self, signing, jwks):
        """A flat /attest/TdxVm token must not be accepted here: it has no
        isolation-tee object and no client-payload nonce, so none of the checks
        below it would run."""
        tok = _token(signing, **{"x-ms-attestation-type": "tdxvm"})
        with pytest.raises(MaaVerificationError, match="not an AzureGuest token"):
            _verify(tok, jwks)

    def test_a_snp_verdict_is_refused_when_tdx_was_expected(self, signing, jwks):
        tee = _isolation_tee(**{"x-ms-attestation-type": "sevsnpvm"})
        with pytest.raises(MaaVerificationError, match="x-ms-attestation-type"):
            _verify(_token(signing, tee=tee), jwks)

    def test_a_noncompliant_cvm_is_refused(self, signing, jwks):
        tee = _isolation_tee(**{"x-ms-compliance-status": "unknown"})
        with pytest.raises(MaaVerificationError, match="compliance-status"):
            _verify(_token(signing, tee=tee), jwks)


class TestDebugTrustDomainsAreRefused:
    def test_tdx_debug_attribute(self, signing, jwks):
        tee = _isolation_tee(tdx_td_attributes_debug=True)
        with pytest.raises(MaaVerificationError, match="DEBUG trust domain"):
            _verify(_token(signing, tee=tee), jwks)

    def test_dbgstat_enabled(self, signing, jwks):
        tee = _isolation_tee(dbgstat="enabled")
        with pytest.raises(MaaVerificationError, match="dbgstat"):
            _verify(_token(signing, tee=tee), jwks)

    def test_snp_debuggable_flag(self, signing, jwks):
        """Checked even on the TDX path: the claim only appears on an SNP CVM,
        and if one ever reaches here it must not slip through on a name this
        verifier does not read."""
        tee = _isolation_tee(**{"x-ms-attestation-type": "sevsnpvm",
                                "x-ms-sevsnpvm-is-debuggable": True})
        with pytest.raises(MaaVerificationError, match="debuggable"):
            _verify(_token(signing, tee=tee), jwks,
                    expected_isolation_type="sevsnpvm")


class TestTheSessionBinding:
    """The check whose absence made the old path meaningless.

    Without it a token proves "an Azure confidential VM exists". Any tenant can
    get one of those for a VM they own and replay it into someone else's
    connection.
    """

    def test_a_matching_hex_nonce_passes(self, signing, jwks):
        _verify(_token(signing, nonce=BINDING.hex()), jwks)

    def test_a_base64_of_the_hex_nonce_also_passes(self, signing, jwks):
        """AttestationClient's documented sample shows `-n 1234` arriving as
        `"nonce": "MTIzNA=="`, i.e. base64 of the argument. Accepting both
        encodings avoids a hard failure on a detail owned by Microsoft's binary,
        and both candidates still derive from the same secret digest."""
        enc = base64.b64encode(BINDING.hex().encode()).decode()
        _verify(_token(signing, nonce=enc), jwks)

    def test_a_foreign_nonce_is_refused(self, signing, jwks):
        other = hashlib.sha256(b"someone else's session").digest()
        with pytest.raises(MaaVerificationError, match="does not match"):
            _verify(_token(signing, nonce=other.hex()), jwks)

    def test_an_absent_nonce_is_refused(self, signing, jwks):
        tok = _token(signing, **{"x-ms-runtime": {"keys": []}})
        with pytest.raises(MaaVerificationError, match="no x-ms-runtime"):
            _verify(tok, jwks)

    def test_an_empty_nonce_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="no x-ms-runtime"):
            _verify(_token(signing, nonce=""), jwks)

    def test_no_expected_binding_means_no_check(self, signing, jwks):
        """Deliberate and narrow: the *client* refuses to call without a
        binding. This library-level escape exists only for callers with no
        session to bind, and is pinned so the distinction stays explicit."""
        other = hashlib.sha256(b"unrelated").digest()
        v = verify_maa_azure_guest_token(
            _token(signing, nonce=other.hex()),
            expected_issuer=ISSUER, jwks=jwks)
        assert v.compliance_status == "azure-compliant-cvm"


class TestTheCandidateNonceEncodings:
    def test_hex_is_first_and_present(self):
        cands = expected_client_payload_nonces(BINDING)
        assert BINDING.hex() in cands

    def test_base64_of_hex_is_offered(self):
        cands = expected_client_payload_nonces(BINDING)
        assert base64.b64encode(BINDING.hex().encode()).decode() in cands

    def test_it_does_not_accept_an_arbitrary_value(self):
        cands = expected_client_payload_nonces(BINDING)
        assert "" not in cands
        assert "deadbeef" not in cands

    def test_distinct_bindings_share_no_candidate(self):
        a = expected_client_payload_nonces(hashlib.sha256(b"a").digest())
        b = expected_client_payload_nonces(hashlib.sha256(b"b").digest())
        assert not (set(a) & set(b))


class TestTheJwtLayerIsStillHardened:
    """Same guarantees as the TdxVm verifier, because it is the same code.

    Asserted here rather than assumed: the two verifiers sharing
    ``_decode_verified_claims`` is the whole reason a bypass cannot land in one
    of them alone, and a refactor that duplicates it would pass every test in
    the other file.
    """

    def test_an_unsigned_token_is_refused(self, signing, jwks):
        import jwt as _jwt
        tok = _jwt.encode(_claims(), key="", algorithm="none",
                          headers={"kid": KID})
        with pytest.raises(MaaVerificationError, match="alg is"):
            _verify(tok, jwks)

    def test_hmac_alg_confusion_is_refused(self, signing, jwks):
        import jwt as _jwt
        tok = _jwt.encode(_claims(), key="secret", algorithm="HS256",
                          headers={"kid": KID})
        with pytest.raises(MaaVerificationError, match="alg is"):
            _verify(tok, jwks)

    def test_a_token_signed_by_another_key_is_refused(self, jwks):
        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(MaaVerificationError, match="signature"):
            _verify(_token(rogue), jwks)

    def test_a_missing_kid_is_not_guessed(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="no `kid`"):
            _verify(_token(signing, headers={"kid": None}), jwks)

    def test_a_jku_pointing_elsewhere_is_refused(self, signing, jwks):
        tok = _token(signing, headers={"jku": "https://evil.example/certs"})
        with pytest.raises(MaaVerificationError, match="jku"):
            _verify(tok, jwks)

    def test_a_foreign_issuer_is_refused(self, signing, jwks):
        tok = _token(signing, iss="https://someone-else.attest.azure.net")
        with pytest.raises(MaaVerificationError):
            _verify(tok, jwks)

    def test_an_expired_token_is_refused(self, signing, jwks):
        with pytest.raises(MaaVerificationError, match="expired"):
            _verify(_token(signing), jwks, now=3_000_000_000)
