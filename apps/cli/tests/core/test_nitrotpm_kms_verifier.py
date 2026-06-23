"""CPU-side attestation for ``gpu-cc-aws``, using KMS as the verifier.

``gpu-cc-aws`` refuses CPU-side attestation, for an honest reason: a NitroTPM
attestation document is signed by the Nitro Hypervisor and this project pins no
AWS NitroTPM root to check it against (``certs/nitro-root.pem`` is the Nitro
*Enclaves* root, a different key hierarchy).

``kms:GenerateRandom`` closes that without a root certificate. It accepts a
``Recipient`` carrying a NitroTPM document, takes no ``KeyId`` at all, and AWS
documents ``CiphertextForRecipient`` as present "only when the Recipient
parameter in the request includes a valid attestation document".

The single most important test here is
``test_plaintext_response_is_not_read_as_success``. KMS answers a *non*-attested
``GenerateRandom`` happily, just with ``Plaintext`` instead -- so an
implementation that merely wrapped the call in try/except would report a passed
attestation for a document KMS never validated.
"""
from __future__ import annotations

import pytest

from tee_crafter.core.keys.nitrotpm import (
    NitroTpmError, decrypt_ciphertext_for_recipient, verify_document_via_kms,
)

DOC = b"\xd2\x84attestation-document"


class _Kms:
    def __init__(self, response=None, raises=None):
        self.response, self.raises = response or {}, raises
        self.request = None

    def generate_random(self, **kwargs):
        self.request = kwargs
        if self.raises:
            raise self.raises
        return self.response


class _AccessDeniedException(Exception):
    pass


def test_ciphertext_for_recipient_means_verified():
    kms = _Kms({"CiphertextForRecipient": b"cms-blob"})
    result = verify_document_via_kms(kms, DOC)
    assert result["verified"] is True
    assert result["verifier"] == "aws-kms"


def test_plaintext_response_is_not_read_as_success():
    """The whole point. A non-attested GenerateRandom succeeds and returns
    Plaintext; treating a 200 as a pass would verify nothing at all."""
    kms = _Kms({"Plaintext": b"\x00" * 32})
    result = verify_document_via_kms(kms, DOC)
    assert result["verified"] is False
    assert "Plaintext" in result["detail"]


def test_empty_response_is_not_verified():
    assert verify_document_via_kms(_Kms({}), DOC)["verified"] is False


def test_the_document_is_sent_as_the_recipient():
    kms = _Kms({"CiphertextForRecipient": b"x"})
    verify_document_via_kms(kms, DOC)
    assert kms.request["Recipient"] == {
        "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
        "AttestationDocument": DOC,
    }


def test_no_key_id_is_sent():
    """GenerateRandom uses "no account-specific resources, such as KMS keys",
    which is what makes it a pure attestation check rather than a key operation.
    """
    kms = _Kms({"CiphertextForRecipient": b"x"})
    verify_document_via_kms(kms, DOC)
    assert "KeyId" not in kms.request


def test_access_denied_is_a_verdict_not_an_error():
    """With PCR conditions attached to the IAM permission, a measurement
    mismatch surfaces as AccessDenied. Raising here would invite a retry loop
    against a machine that will never pass."""
    kms = _Kms(raises=_AccessDeniedException("not authorized"))
    result = verify_document_via_kms(kms, DOC)
    assert result["verified"] is False
    assert "mismatch" in result["detail"]


def test_other_errors_still_raise():
    """A throttle or a network fault is not evidence about the instance."""
    kms = _Kms(raises=RuntimeError("connection reset"))
    with pytest.raises(NitroTpmError, match="GenerateRandom failed"):
        verify_document_via_kms(kms, DOC)


def test_empty_document_is_refused():
    with pytest.raises(NitroTpmError, match="no attestation document"):
        verify_document_via_kms(_Kms(), b"")


def test_detail_names_the_trust_root():
    """This is a delegation, not a locally rooted check. It should say so, the
    same way tdx-azure is explicit about trusting MAA rather than Intel DCAP."""
    result = verify_document_via_kms(_Kms({"CiphertextForRecipient": b"x"}), DOC)
    assert "AWS KMS" in result["detail"]
    assert "not a locally pinned" in result["detail"]


def test_number_of_bytes_is_forwarded():
    kms = _Kms({"CiphertextForRecipient": b"x"})
    verify_document_via_kms(kms, DOC, number_of_bytes=16)
    assert kms.request["NumberOfBytes"] == 16


# --------------------------------------------------------------------------
# Liveness: the round-trip is what defeats replay
# --------------------------------------------------------------------------

def test_round_trip_binds_to_a_key_the_caller_holds():
    """A replayed document cannot be paired with a private key the attacker
    lacks, so being able to decrypt the response proves the document belongs to
    this holder -- an end-to-end check over real CMS, not a stub.
    """
    import os

    from asn1crypto import cms as asn1_cms
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    secret, cek, iv = os.urandom(32), os.urandom(32), os.urandom(16)

    # AES-CBC with PKCS#7 padding, so this also exercises the unpadding checks.
    pad = 16 - (len(secret) % 16)
    encryptor = Cipher(algorithms.AES(cek), modes.CBC(iv)).encryptor()
    body = encryptor.update(secret + bytes([pad]) * pad) + encryptor.finalize()

    wrapped = private_key.public_key().encrypt(
        cek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))

    envelope = asn1_cms.ContentInfo({
        "content_type": "enveloped_data",
        "content": asn1_cms.EnvelopedData({
            "version": "v0",
            "recipient_infos": [
                asn1_cms.RecipientInfo({
                    "ktri": asn1_cms.KeyTransRecipientInfo({
                        "version": "v0",
                        "rid": asn1_cms.RecipientIdentifier({
                            "subject_key_identifier": b"\x01" * 20}),
                        "key_encryption_algorithm": {"algorithm": "rsaes_oaep"},
                        "encrypted_key": wrapped,
                    }),
                }),
            ],
            "encrypted_content_info": {
                "content_type": "data",
                "content_encryption_algorithm": {
                    "algorithm": "aes256_cbc",
                    "parameters": iv,
                },
                "encrypted_content": body,
            },
        }),
    }).dump()

    result = verify_document_via_kms(
        _Kms({"CiphertextForRecipient": envelope}), DOC)
    assert result["verified"] is True
    assert decrypt_ciphertext_for_recipient(
        result["ciphertext_for_recipient"], private_key) == secret
