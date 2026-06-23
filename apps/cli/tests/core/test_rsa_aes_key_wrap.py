"""C2: the unwrap half of Azure Secure Key Release, which never existed.

``AzureKeyVaultAdapter.release`` returned genuinely unwrappable bytes and
nothing unwrapped them, so ``plaintext`` stayed ``None``.  The mechanism is
PKCS#11 ``CKM_RSA_AES_KEY_WRAP``:

    blob = RSA-OAEP(ephemeral AES key) || AES-KWP(target key)

Two steps.  The value used to be labelled ``RSA_OAEP_SHA256``, and a consumer
that believed the label and did a single RSA-OAEP decrypt would fail on the
AES-KWP half — so these tests wrap keys *the way Azure does* and assert the
round trip, rather than asserting against a hand-written expected blob that
would only prove the implementation agrees with itself.
"""
from __future__ import annotations

import os

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding

from tee_crafter.core.keys.rsa_aes_key_wrap import (
    KeyUnwrapError, unwrap_ckm_rsa_aes_key_wrap,
)

_HASHES = {"sha256": hashes.SHA256, "sha1": hashes.SHA1}


@pytest.fixture(scope="module")
def rsa2048():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa3072():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _wrap(target: bytes, private_key, *, oaep="sha256", aes_bits=256) -> bytes:
    """Produce a CKM_RSA_AES_KEY_WRAP blob the way the HSM would."""
    aes_key = os.urandom(aes_bits // 8)
    algo = _HASHES[oaep]()
    rsa_part = private_key.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=algo), algorithm=algo, label=None),
    )
    return rsa_part + aes_key_wrap_with_padding(aes_key, target)


class TestTheRoundTrip:
    def test_a_32_byte_dek_survives(self, rsa2048):
        target = os.urandom(32)
        out = unwrap_ckm_rsa_aes_key_wrap(_wrap(target, rsa2048), rsa2048)
        assert out.plaintext == target

    @pytest.mark.parametrize("oaep", ["sha256", "sha1"])
    def test_both_oaep_digests_work_and_are_reported(self, rsa2048, oaep):
        """Azure does not document which digest it uses, so both are tried."""
        target = os.urandom(32)
        out = unwrap_ckm_rsa_aes_key_wrap(_wrap(target, rsa2048, oaep=oaep), rsa2048)
        assert out.plaintext == target
        assert out.oaep_hash == oaep

    @pytest.mark.parametrize("aes_bits", [128, 192, 256])
    def test_every_ephemeral_aes_size_works(self, rsa2048, aes_bits):
        target = os.urandom(32)
        blob = _wrap(target, rsa2048, aes_bits=aes_bits)
        assert unwrap_ckm_rsa_aes_key_wrap(blob, rsa2048).plaintext == target

    @pytest.mark.parametrize("size", [1, 7, 8, 16, 31, 32, 64, 190])
    def test_target_lengths_including_non_multiples_of_eight(self, rsa2048, size):
        """AES-KWP (RFC 5649) not AES-KW (RFC 3394) — arbitrary lengths."""
        target = os.urandom(size)
        assert unwrap_ckm_rsa_aes_key_wrap(_wrap(target, rsa2048), rsa2048).plaintext == target

    def test_a_3072_bit_recipient_splits_at_384_bytes(self, rsa3072):
        target = os.urandom(32)
        out = unwrap_ckm_rsa_aes_key_wrap(_wrap(target, rsa3072), rsa3072)
        assert out.plaintext == target
        assert out.wrapped_aes_key_bytes == 384

    def test_the_split_follows_the_recipient_key_not_the_blob(self, rsa2048):
        """2048-bit modulus -> the RSA segment is exactly 256 bytes."""
        out = unwrap_ckm_rsa_aes_key_wrap(_wrap(os.urandom(32), rsa2048), rsa2048)
        assert out.wrapped_aes_key_bytes == 256


class TestItRefusesRatherThanGuesses:
    def test_empty_blob(self, rsa2048):
        with pytest.raises(KeyUnwrapError, match="empty"):
            unwrap_ckm_rsa_aes_key_wrap(b"", rsa2048)

    def test_a_blob_too_short_to_be_this_mechanism(self, rsa2048):
        with pytest.raises(KeyUnwrapError, match="at least"):
            unwrap_ckm_rsa_aes_key_wrap(os.urandom(200), rsa2048)

    def test_the_rsa_only_blob_that_the_old_label_implied(self, rsa2048):
        """A bare RSA-OAEP blob — what ``RSA_OAEP_SHA256`` suggested — is
        rejected as too short rather than half-decrypted."""
        bare = rsa2048.public_key().encrypt(
            os.urandom(32),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        assert len(bare) == 256
        with pytest.raises(KeyUnwrapError, match="at least"):
            unwrap_ckm_rsa_aes_key_wrap(bare, rsa2048)

    def test_wrapped_to_a_different_key(self, rsa2048, rsa3072):
        """Same modulus size would be needed to even reach OAEP; use a blob
        built for another 2048-bit key."""
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        blob = _wrap(os.urandom(32), other)
        with pytest.raises(KeyUnwrapError, match="not wrapped to this private key"):
            unwrap_ckm_rsa_aes_key_wrap(blob, rsa2048)

    def test_a_corrupt_kwp_body_is_named_as_such(self, rsa2048):
        """The RSA half succeeding narrows the diagnosis to truncation."""
        blob = bytearray(_wrap(os.urandom(32), rsa2048))
        blob[-1] ^= 0xFF
        with pytest.raises(KeyUnwrapError, match="AES-KWP unwrap"):
            unwrap_ckm_rsa_aes_key_wrap(bytes(blob), rsa2048)

    def test_an_ephemeral_key_of_the_wrong_size_is_rejected(self, rsa2048):
        """RSA-OAEP succeeding does not prove the blob is this mechanism."""
        not_an_aes_key = os.urandom(20)
        rsa_part = rsa2048.public_key().encrypt(
            not_an_aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        with pytest.raises(KeyUnwrapError, match="20-byte ephemeral key"):
            unwrap_ckm_rsa_aes_key_wrap(rsa_part + os.urandom(24), rsa2048)

    def test_errors_never_leak_plaintext(self, rsa2048):
        target = b"SUPER-SECRET-DEK-MATERIAL-000000"
        blob = bytearray(_wrap(target, rsa2048))
        blob[-1] ^= 0xFF
        with pytest.raises(KeyUnwrapError) as exc:
            unwrap_ckm_rsa_aes_key_wrap(bytes(blob), rsa2048)
        assert b"SUPER-SECRET" not in str(exc.value).encode()
