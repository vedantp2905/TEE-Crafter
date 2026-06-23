"""C2: the released key actually comes back as plaintext.

``AzureKeyVaultAdapter.release`` had every piece except the last one. It found
``key.key_hsm`` in the envelope and handed the bytes back as
``wrapped_for_recipient`` with ``plaintext=None``, and
``unwrap_ckm_rsa_aes_key_wrap`` sat in ``core/keys/rsa_aes_key_wrap.py`` with
nobody calling it. The runtime bootstrap then refused, correctly, rather than
staging an empty DEK — so BYOK on Azure was fail-closed rather than working.

The join is the *key-encryption key*: Key Vault wraps the released key to the
RSA public key in the token's top-level ``x-ms-runtime.keys``, which Microsoft
identifies as ``TpmEphemeralEncryptionKey``. That is what makes SKR a release to
*this* TEE and not to anyone who can reach the endpoint. So the round trip below
wraps exactly the way the HSM does — RSA-OAEP an ephemeral AES key to the
recipient, AES-KWP the target under it — and asserts the adapter gets the
original bytes back.

Response shapes here are copied from Microsoft's samples rather than invented,
because inventing them is how this file got the blob format wrong twice:
``key_hsm`` is *not* the ciphertext, it is base64 of a JSON envelope whose
``ciphertext`` field holds it, and the walkthrough's real response nests the JWK
two levels deeper than the REST reference's does. A test that makes up the
response cannot catch either mistake.
https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp

The binding check earns its own class. Wrapping to a key we do not hold and
being handed a token that bound a key we do not hold produce the same
``InvalidUnwrap`` at the crypto layer, but they mean different things: the
first is a broken release, the second is somebody else's token. Reporting the
second as the first is how a misdirected release becomes "transient decrypt
error" in an incident review.
"""
from __future__ import annotations

import base64
import json
import os

import pytest

from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tee_crafter.core.keys.azure_kv import (
    ISOLATION_TEE_AK_KID, KEY_ENCRYPTION_KEY_KID, AzureKeyVaultAdapter,
    find_key_encryption_key, transfer_key_jwk, transfer_key_matches,
)
from tee_crafter.core.keys.spec import (
    AttestedKeyRef, KeyProvider, KeyReleaseError, KeyReleasePolicy,
    UnwrapAlgorithm,
)

KEY_URL = "https://mhsm-test.managedhsm.azure.net/keys/dek/abcd1234"
DEK = b"\xa5" * 32


@pytest.fixture(scope="module")
def recipient():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _wrap_like_managed_hsm(target: bytes, public_key, *, oaep_hash=None) -> bytes:
    """CKM_RSA_AES_KEY_WRAP, the way Managed HSM produces it."""
    aes = os.urandom(32)
    algo = oaep_hash or hashes.SHA256()
    wrapped_aes = public_key.encrypt(
        aes,
        padding.OAEP(mgf=padding.MGF1(algorithm=algo), algorithm=algo, label=None),
    )
    return wrapped_aes + keywrap.aes_key_wrap_with_padding(aes, target)


def _key_hsm(wrapped: bytes, *, enc: str = "CKM_RSA_AES_KEY_WRAP") -> str:
    """``key_hsm`` as Managed HSM really emits it.

    Not the raw ciphertext: base64 of a JSON envelope whose ``ciphertext``
    field holds the CKM_RSA_AES_KEY_WRAP blob. Shape copied verbatim from
    Microsoft's "Key Release Response" sample.
    """
    inner = {
        "schema_version": "1.0",
        "header": {"kid": KEY_ENCRYPTION_KEY_KID, "alg": "dir", "enc": enc},
        "ciphertext": _b64u(wrapped),
    }
    return _b64u(json.dumps(inner).encode())


def _release_response(wrapped: bytes, *, kid: str = KEY_URL,
                      enc: str = "CKM_RSA_AES_KEY_WRAP",
                      nested: bool = False) -> dict:
    key_obj = {"kid": kid, "kty": "RSA-HSM", "key_hsm": _key_hsm(wrapped, enc=enc)}
    if nested:
        # The shape the confidential-computing walkthrough shows.
        envelope = {"request": {"enc": enc},
                    "response": {"key": {"key": key_obj,
                                         "attributes": {"enabled": True}}}}
    else:
        # The shape the REST reference shows.
        envelope = {
            "attributes": {"enabled": True},
            "key": key_obj,
            "release_policy": {"contentType": "application/json; charset=utf-8"},
        }
    return {"value": _b64u(json.dumps(envelope).encode())}


def _ref() -> AttestedKeyRef:
    return AttestedKeyRef(provider=KeyProvider.AZURE_KEY_VAULT, key_id=KEY_URL)


def _release(adapter, resp):
    return adapter.release(
        key_ref=_ref(), attestation=b"a.b.c", policy=KeyReleasePolicy())


def _http_returning(resp):
    def _http(method, url, headers, body):
        return resp
    return _http


class TestTheRoundTrip:
    def test_the_dek_comes_back_as_plaintext(self, recipient):
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)),
            recipient_private_key=recipient)
        material = _release(adapter, None)
        assert material.plaintext == DEK
        assert material.unwrap_algorithm is UnwrapAlgorithm.CKM_RSA_AES_KEY_WRAP

    def test_it_records_how_the_unwrap_went(self, recipient):
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)),
            recipient_private_key=recipient)
        meta = _release(adapter, None).provider_response_metadata
        assert meta["unwrapped"] is True
        assert meta["oaep_hash"] == "sha256"
        assert meta["wrapped_aes_key_bytes"] == 256

    def test_sha1_oaep_also_round_trips(self, recipient):
        """Azure does not document which OAEP digest it uses, so both are
        tried. A release that only works on one of them is not a working
        release."""
        wrapped = _wrap_like_managed_hsm(
            DEK, recipient.public_key(), oaep_hash=hashes.SHA1())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)),
            recipient_private_key=recipient)
        material = _release(adapter, None)
        assert material.plaintext == DEK
        assert material.provider_response_metadata["oaep_hash"] == "sha1"

    def test_the_wrapped_bytes_are_still_returned(self, recipient):
        """Callers that audit the ciphertext keep working."""
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)),
            recipient_private_key=recipient)
        assert _release(adapter, None).wrapped_for_recipient == wrapped


class TestWithoutAPrivateKeyNothingChanges:
    def test_plaintext_stays_none(self, recipient):
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)))
        material = _release(adapter, None)
        assert material.plaintext is None
        assert material.wrapped_for_recipient == wrapped
        assert "unwrapped" not in material.provider_response_metadata


class TestTheTransferKeyBinding:
    def test_a_token_binding_another_key_is_refused_before_unwrapping(
            self, recipient):
        """The distinction that matters: not "decrypt failed", but "this
        release was not wrapped for us"."""
        stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)),
            recipient_private_key=recipient,
            expected_transfer_key=transfer_key_jwk(stranger))
        with pytest.raises(KeyReleaseError, match="not wrapped for this TEE"):
            _release(adapter, None)

    def test_a_matching_token_passes_through(self, recipient):
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)),
            recipient_private_key=recipient,
            expected_transfer_key=transfer_key_jwk(recipient))
        assert _release(adapter, None).plaintext == DEK

    def test_wrapping_to_the_wrong_key_is_a_release_error_not_a_crash(
            self, recipient):
        stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrapped = _wrap_like_managed_hsm(DEK, stranger.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)),
            recipient_private_key=recipient)
        with pytest.raises(KeyReleaseError, match="could not be unwrapped"):
            _release(adapter, None)

    def test_the_error_does_not_leak_key_material(self, recipient):
        stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrapped = _wrap_like_managed_hsm(DEK, stranger.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped)),
            recipient_private_key=recipient)
        with pytest.raises(KeyReleaseError) as exc:
            _release(adapter, None)
        text = str(exc.value)
        assert DEK.hex() not in text
        assert wrapped.hex()[:32] not in text


class TestTheJwkHelpers:
    def test_jwk_round_trips_against_its_own_private_key(self, recipient):
        assert transfer_key_matches(transfer_key_jwk(recipient), recipient)

    def test_jwk_carries_the_kid_azure_uses(self, recipient):
        assert transfer_key_jwk(recipient)["kid"] == KEY_ENCRYPTION_KEY_KID
        assert transfer_key_jwk(recipient)["kty"] == "RSA"

    def test_a_foreign_jwk_does_not_match(self, recipient):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert not transfer_key_matches(transfer_key_jwk(other), recipient)

    def test_comparison_survives_base64_padding_differences(self, recipient):
        """JWK base64url is only canonical if everyone strips the same way;
        comparing integers rather than strings is what makes that safe."""
        jwk = dict(transfer_key_jwk(recipient))
        jwk["n"] = jwk["n"] + "=="          # legal padding
        jwk["e"] = _b64u(b"\x00\x01\x00\x01")  # leading zero byte
        assert transfer_key_matches(jwk, recipient)

    @pytest.mark.parametrize("bad", [
        None, {}, {"kty": "EC", "n": "aa", "e": "AQAB"},
        {"kty": "RSA"}, {"kty": "RSA", "n": "!!!", "e": "AQAB"},
    ])
    def test_malformed_jwks_are_false_not_exceptions(self, bad, recipient):
        assert transfer_key_matches(bad, recipient) is False

    def test_find_key_encryption_key_matches_on_kid(self):
        keys = [{"kid": "other", "kty": "RSA"},
                {"kid": KEY_ENCRYPTION_KEY_KID, "kty": "RSA", "n": "a", "e": "b"}]
        assert find_key_encryption_key(keys)["kid"] == KEY_ENCRYPTION_KEY_KID

    def test_find_key_encryption_key_does_not_take_the_first_rsa_key(self):
        """Same discipline the MAA verifier applies to JWKS lookup."""
        assert find_key_encryption_key([{"kid": "other", "kty": "RSA"}]) is None

    @pytest.mark.parametrize("bad", [None, "nope", 5, []])
    def test_find_key_encryption_key_tolerates_junk(self, bad):
        assert find_key_encryption_key(bad) is None


class TestTheDocumentedResponseShapes:
    """Both Microsoft samples, and the envelope layer that was missed."""

    def test_the_walkthrough_nesting_is_understood(self, recipient):
        """`$.response.key.key.key_hsm`, not `$.key.key_hsm`."""
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped, nested=True)),
            recipient_private_key=recipient)
        assert _release(adapter, None).plaintext == DEK

    def test_raw_ciphertext_in_key_hsm_is_rejected_not_misread(self, recipient):
        """The old bug: treating base64(key_hsm) as the blob itself. It must
        fail loudly rather than being fed to the unwrapper as garbage."""
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        envelope = {"key": {"kid": KEY_URL, "kty": "RSA-HSM",
                            "key_hsm": _b64u(wrapped)}}
        resp = {"value": _b64u(json.dumps(envelope).encode())}
        adapter = AzureKeyVaultAdapter(http=_http_returning(resp),
                                       recipient_private_key=recipient)
        with pytest.raises(KeyReleaseError, match="documented JSON envelope"):
            _release(adapter, None)

    def test_an_unexpected_wrapping_algorithm_is_refused(self, recipient):
        wrapped = _wrap_like_managed_hsm(DEK, recipient.public_key())
        adapter = AzureKeyVaultAdapter(
            http=_http_returning(_release_response(wrapped, enc="RSA-OAEP-256")),
            recipient_private_key=recipient)
        with pytest.raises(KeyReleaseError, match="not CKM_RSA_AES_KEY_WRAP"):
            _release(adapter, None)

    def test_a_missing_ciphertext_field_is_an_error(self, recipient):
        inner = {"schema_version": "1.0", "header": {"enc": "CKM_RSA_AES_KEY_WRAP"}}
        envelope = {"key": {"kid": KEY_URL,
                            "key_hsm": _b64u(json.dumps(inner).encode())}}
        resp = {"value": _b64u(json.dumps(envelope).encode())}
        adapter = AzureKeyVaultAdapter(http=_http_returning(resp),
                                       recipient_private_key=recipient)
        with pytest.raises(KeyReleaseError, match="no `ciphertext`"):
            _release(adapter, None)


class TestTheIsolationTeeKeyIsNotTheOne:
    """Microsoft: the key under `$.x-ms-isolation-tee.x-ms-runtime.keys` "is
    **not** the key that Key Vault will be using". Two RSA keys in one token,
    and picking the wrong one fails only on a live release."""

    def test_the_attestation_key_is_refused_loudly(self):
        keys = [{"kid": ISOLATION_TEE_AK_KID, "kty": "RSA", "n": "a", "e": "b"}]
        with pytest.raises(KeyReleaseError, match="isolation-tee attestation key"):
            find_key_encryption_key(keys)

    def test_the_right_kid_is_selected_from_a_mixed_set(self):
        keys = [{"kid": "somethingelse", "kty": "RSA"},
                {"kid": KEY_ENCRYPTION_KEY_KID, "kty": "RSA", "n": "a", "e": "b"}]
        assert find_key_encryption_key(keys)["kid"] == KEY_ENCRYPTION_KEY_KID

    def test_the_kid_is_the_one_microsoft_documents(self):
        assert KEY_ENCRYPTION_KEY_KID == "TpmEphemeralEncryptionKey"
        assert ISOLATION_TEE_AK_KID == "HCLAkPub"
