"""The `azure-guest` path end to end through the rendered `tdx-azure` client.

This file exists because of a specific, expensive failure mode. The MAA verifier
had 27 green unit tests while the *whole model* was wrong — they called the
verifier directly with tokens from an endpoint that could never have issued one
for our hardware. Before that, the same suite was green while the client's
build-time format gate made the MAA path unreachable at all. Both times, testing
the component proved nothing about the path.

So these tests drive the **rendered client**, from `verify_ratls_connection`
through the format gate, the token verification, and the session-binding check,
with a real RSA-signed token and a real recomputation of the v2 preimage. The
only things stubbed are the socket layer and the JWKS fetch.

The property that matters most here is the last one: a token can be perfectly
valid — correctly signed by the real MAA, `azure-compliant-cvm`, matching MRTD —
and still be *someone else's*. On this platform `report_data` belongs to the
paravisor, so the nonce is the only thing tying a token to this session, and an
earlier version of this code checked nothing at all.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from tests.core.test_dcap_verify import _patch_transport, _tdx_client

ISSUER = "https://sharedwus.wus.attest.azure.net"
KID = "e2e-key"
MRTD = "ef" * 48
CONTAINER_DIGEST = ""


@pytest.fixture(scope="module")
def signing():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks_doc(signing):
    from jwt.algorithms import RSAAlgorithm

    jwk = json.loads(RSAAlgorithm.to_jwk(signing.public_key()))
    jwk["kid"] = KID
    return {"keys": [jwk]}


@pytest.fixture(scope="module")
def ag_client(tmp_path_factory):
    return _tdx_client("azure", tmp_path_factory.mktemp("tdx_ag_e2e"),
                       mrtd=MRTD, evidence_format="azure-guest")


def _token(signing, *, nonce: str, mrtd: str = MRTD, **tee_over) -> str:
    import jwt as _jwt

    tee = {
        "x-ms-attestation-type": "tdxvm",
        "x-ms-compliance-status": "azure-compliant-cvm",
        "attester_tcb_status": "UpToDate",
        "dbgstat": "disabled",
        "tdx_mrtd": mrtd,
        "tdx_rtmr0": "00" * 48, "tdx_rtmr1": "00" * 48,
        "tdx_rtmr2": "00" * 48, "tdx_rtmr3": "00" * 48,
        "tdx_td_attributes_debug": False,
        "tdx_report_data": "cc" * 64,
    }
    tee.update(tee_over)
    claims = {
        "iss": ISSUER, "iat": 1000, "nbf": 1000, "exp": 2_000_000_000,
        "x-ms-attestation-type": "azurevm",
        "x-ms-isolation-tee": tee,
        "x-ms-runtime": {
            "client-payload": {"nonce": nonce},
            "keys": [{"kid": "TpmEphemeralEncryptionKey", "kty": "RSA",
                      "key_ops": ["encrypt"], "n": "bbb", "e": "AQAB"}],
        },
    }
    return _jwt.encode(claims, signing, algorithm="RS256",
                       headers={"kid": KID, "jku": f"{ISSUER}/certs"})


def _wire(monkeypatch, client, jwks_doc, token: str):
    """Point the client at our MAA and canned JWKS, and hand it *token*.

    ``urllib.request.urlopen`` is patched on the real module, because the client
    does ``import urllib.request as _urlreq`` *inside* the function and that
    resolves the genuine module every call. An earlier version of this helper
    tried to shim ``__import__`` in the client's namespace; it silently did
    nothing and the tests fetched the **live** JWKS from
    ``sharedwus.wus.attest.azure.net``. They failed rather than passing, which
    is the only reason it was caught — a unit test that reaches the network is
    not a unit test, and one that reaches a real attestation service would have
    started passing the moment the token happened to line up.
    """
    import urllib.request as _real_urlreq

    monkeypatch.setattr(client, "_MAA_ENDPOINT", ISSUER)

    class _Resp:
        @staticmethod
        def read():
            return json.dumps(jwks_doc).encode()

    def _no_network(url, *a, **k):
        assert "/certs" in str(url), f"unexpected fetch: {url}"
        return _Resp()

    monkeypatch.setattr(_real_urlreq, "urlopen", _no_network)
    return _patch_transport(monkeypatch, client, token.encode())


def _session(client, *, ecdh_pub=b"ecdh-public-key-bytes",
             commitment="ab" * 32):
    """The v2 preimage digest the server would have bound, and the matching
    attestation response."""
    digest = client._attest_binding_digest(
        client._CERT_BINDING_PURPOSE, ecdh_pub,
        CONTAINER_DIGEST.encode(), commitment.encode("ascii"))
    att_resp = {
        "cert_report_data_binding": client._EXPECTED_CERT_REPORT_DATA_BINDING,
        "chain_key_commitment": commitment,
    }
    return digest, att_resp, ecdh_pub


class TestTheHappyPathCrossesEveryGate:
    def test_a_bound_token_verifies_and_the_binding_check_passes(
            self, ag_client, signing, jwks_doc, monkeypatch):
        digest, att_resp, ecdh_pub = _session(ag_client)
        _wire(monkeypatch, ag_client, jwks_doc, _token(signing, nonce=digest.hex()))

        conn, quote_info = ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert quote_info["evidence_format"] == "azure-guest"
        assert quote_info["mrtd"] == MRTD
        assert quote_info["client_payload_nonce"] == digest.hex()

        ok, reason = ag_client.verify_report_data_binding(
            quote_info["report_data"], att_resp, ecdh_pub,
            CONTAINER_DIGEST, quote_info)
        assert ok, reason

    def test_the_recorded_issuer_is_maa_not_intel(
            self, ag_client, signing, jwks_doc, monkeypatch, capsys):
        """The provenance ledger must not claim an Intel trust root for a
        Microsoft-rooted attestation."""
        digest, _, _ = _session(ag_client)
        _wire(monkeypatch, ag_client, jwks_doc, _token(signing, nonce=digest.hex()))
        ag_client.verify_ratls_connection("10.0.0.1", 5005)

        line = next(ln for ln in capsys.readouterr().out.splitlines()
                    if ln.startswith("ATTESTATION_REPORT "))
        report = json.loads(line.split(" ", 1)[1])
        assert report["issuer"] == ISSUER
        assert report["quote_signature_alg"] == "RS256"
        assert report["report_kind"] == "azure_guest_maa"


class TestAValidTokenForAnotherSessionIsRefused:
    """The defect that made the old path meaningless.

    Everything about this token is genuine — MAA signed it, the CVM is
    compliant, the MRTD matches. It was just issued for a different session, and
    any Azure tenant can obtain one for a VM they control.
    """

    def test_a_foreign_nonce_fails_the_binding_check(
            self, ag_client, signing, jwks_doc, monkeypatch):
        _, att_resp, ecdh_pub = _session(ag_client)
        foreign = hashlib.sha256(b"a VM the attacker owns").digest()
        _wire(monkeypatch, ag_client, jwks_doc, _token(signing, nonce=foreign.hex()))

        _conn, quote_info = ag_client.verify_ratls_connection("10.0.0.1", 5005)
        ok, reason = ag_client.verify_report_data_binding(
            quote_info["report_data"], att_resp, ecdh_pub,
            CONTAINER_DIGEST, quote_info)
        assert not ok
        assert "different session" in reason

    def test_a_token_with_no_nonce_fails_the_binding_check(
            self, ag_client, signing, jwks_doc, monkeypatch):
        _, att_resp, ecdh_pub = _session(ag_client)
        _wire(monkeypatch, ag_client, jwks_doc, _token(signing, nonce=""))

        _conn, quote_info = ag_client.verify_ratls_connection("10.0.0.1", 5005)
        ok, reason = ag_client.verify_report_data_binding(
            quote_info["report_data"], att_resp, ecdh_pub,
            CONTAINER_DIGEST, quote_info)
        assert not ok
        assert "replay" in reason or "nothing ties it" in reason

    def test_a_different_ecdh_key_fails_even_with_a_valid_token(
            self, ag_client, signing, jwks_doc, monkeypatch):
        """The nonce binds the ECDH key, so a substituted key must not verify --
        otherwise the attested channel and the encrypted channel come apart."""
        digest, att_resp, _ = _session(ag_client)
        _wire(monkeypatch, ag_client, jwks_doc, _token(signing, nonce=digest.hex()))
        _conn, quote_info = ag_client.verify_ratls_connection("10.0.0.1", 5005)

        ok, reason = ag_client.verify_report_data_binding(
            quote_info["report_data"], att_resp, b"a-different-ecdh-key",
            CONTAINER_DIGEST, quote_info)
        assert not ok

    def test_a_different_audit_commitment_fails(
            self, ag_client, signing, jwks_doc, monkeypatch):
        digest, _, ecdh_pub = _session(ag_client)
        _wire(monkeypatch, ag_client, jwks_doc, _token(signing, nonce=digest.hex()))
        _conn, quote_info = ag_client.verify_ratls_connection("10.0.0.1", 5005)

        swapped = {
            "cert_report_data_binding":
                ag_client._EXPECTED_CERT_REPORT_DATA_BINDING,
            "chain_key_commitment": "cd" * 32,
        }
        ok, _reason = ag_client.verify_report_data_binding(
            quote_info["report_data"], swapped, ecdh_pub,
            CONTAINER_DIGEST, quote_info)
        assert not ok


class TestTheTokenItselfMustStillHoldUp:
    def test_a_noncompliant_cvm_aborts_the_connection(
            self, ag_client, signing, jwks_doc, monkeypatch):
        digest, _, _ = _session(ag_client)
        tok = _token(signing, nonce=digest.hex(),
                     **{"x-ms-compliance-status": "unknown"})
        conns = _wire(monkeypatch, ag_client, jwks_doc, tok)
        with pytest.raises(SystemExit) as exc:
            ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert exc.value.code == 1
        assert conns and conns[0].closed

    def test_an_mrtd_mismatch_aborts_the_connection(
            self, ag_client, signing, jwks_doc, monkeypatch):
        digest, _, _ = _session(ag_client)
        tok = _token(signing, nonce=digest.hex(), mrtd="11" * 48)
        conns = _wire(monkeypatch, ag_client, jwks_doc, tok)
        with pytest.raises(SystemExit) as exc:
            ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert exc.value.code == 1
        assert conns and conns[0].closed

    def test_a_token_from_another_signer_aborts_the_connection(
            self, ag_client, jwks_doc, monkeypatch):
        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        digest, _, _ = _session(ag_client)
        conns = _wire(monkeypatch, ag_client, jwks_doc,
                      _token(rogue, nonce=digest.hex()))
        with pytest.raises(SystemExit) as exc:
            ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert exc.value.code == 1
        assert conns and conns[0].closed

    def test_a_debug_trust_domain_aborts_the_connection(
            self, ag_client, signing, jwks_doc, monkeypatch):
        digest, _, _ = _session(ag_client)
        tok = _token(signing, nonce=digest.hex(), tdx_td_attributes_debug=True)
        conns = _wire(monkeypatch, ag_client, jwks_doc, tok)
        with pytest.raises(SystemExit) as exc:
            ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert exc.value.code == 1
        assert conns and conns[0].closed

    def test_no_configured_maa_endpoint_aborts(
            self, ag_client, signing, jwks_doc, monkeypatch):
        """Fail closed rather than fall back to something unverifiable."""
        digest, _, _ = _session(ag_client)
        conns = _wire(monkeypatch, ag_client, jwks_doc,
                      _token(signing, nonce=digest.hex()))
        monkeypatch.setattr(ag_client, "_MAA_ENDPOINT", "")
        with pytest.raises(SystemExit) as exc:
            ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert exc.value.code == 1
        assert conns and conns[0].closed


class TestTheDcapPathStillEnforcesItsOwnBinding:
    """The shared binding function must not have loosened the DCAP branch."""

    def test_a_dcap_report_data_mismatch_still_fails(self, ag_client):
        digest, att_resp, ecdh_pub = _session(ag_client)
        ok, _ = ag_client.verify_report_data_binding(
            b"\x00" * 64, att_resp, ecdh_pub, CONTAINER_DIGEST,
            {"evidence_format": "dcap"})
        assert not ok

    def test_a_dcap_report_data_match_still_passes(self, ag_client):
        digest, att_resp, ecdh_pub = _session(ag_client)
        ok, reason = ag_client.verify_report_data_binding(
            digest + b"\x00" * 32, att_resp, ecdh_pub, CONTAINER_DIGEST,
            {"evidence_format": "dcap"})
        assert ok, reason

    def test_an_absent_quote_info_defaults_to_the_dcap_check(self, ag_client):
        """Callers that predate the parameter must keep getting the hardware
        check, never the weaker nonce one."""
        digest, att_resp, ecdh_pub = _session(ag_client)
        ok, _ = ag_client.verify_report_data_binding(
            b"\x00" * 64, att_resp, ecdh_pub, CONTAINER_DIGEST)
        assert not ok
