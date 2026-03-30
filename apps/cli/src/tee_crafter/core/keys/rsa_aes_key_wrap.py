"""Unwrap PKCS#11 ``CKM_RSA_AES_KEY_WRAP`` blobs.

This is the half of Azure Secure Key Release that was missing.
``AzureKeyVaultAdapter.release`` returns genuinely unwrappable bytes, but
nothing unwrapped them, so ``plaintext`` stayed ``None`` and the runtime
bootstrap refused rather than staging an empty DEK.

The mechanism, from the PKCS#11 v2.40 mechanism spec §2.1.22 and Azure's
``KeyEncryptionAlgorithm`` documentation:

    blob = RSA-OAEP(ephemeral AES key, recipient RSA pubkey)
         || AES-KWP(target key, ephemeral AES key)

Two steps, not one.  A consumer that believed the older ``RSA_OAEP_SHA256``
label and did a single RSA-OAEP decrypt would fail on the AES-KWP half — which
is exactly the trap :class:`~tee_crafter.core.keys.spec.UnwrapAlgorithm`
documents.

**Where the split is.** The RSA-OAEP ciphertext is always exactly the modulus
size, so the boundary is ``private_key.key_size // 8`` — a property of the
recipient key we already hold, not something parsed out of the blob.  A blob
shorter than that (plus a minimum AES-KWP body) cannot be valid and is rejected
rather than sliced into nonsense.

**OAEP digest.** PKCS#11 leaves it to the ``CK_RSA_PKCS_OAEP_PARAMS`` the
wrapping side used, and Azure does not document which it picks. SHA-256 is
tried first and SHA-1 second, because a wrong digest fails cleanly (the OAEP
padding check fails) rather than silently producing wrong plaintext. Both are
tried before giving up so an Azure-side change of default does not become a
mystery outage; the digest that worked is reported for the audit trail.

RFC 5649 (AES-KWP) rather than RFC 3394 (AES-KW): the target key need not be a
multiple of 8 bytes, and ``aes_key_unwrap_with_padding`` is the ``cryptography``
primitive for it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

#: Smallest sane AES-KWP body: RFC 5649 emits at least two 8-byte blocks.
_MIN_KWP_BYTES = 16


class KeyUnwrapError(ValueError):
    """The blob could not be unwrapped with the supplied private key."""


@dataclass(frozen=True)
class UnwrappedKey:
    """Plaintext key plus how it was recovered, for the audit trail."""

    plaintext: bytes
    oaep_hash: str
    """``"sha256"`` or ``"sha1"`` — which OAEP digest actually worked."""
    wrapped_aes_key_bytes: int
    """Size of the RSA-OAEP segment; equals the recipient modulus size."""


def unwrap_ckm_rsa_aes_key_wrap(
    blob: bytes, private_key: "RSAPrivateKey",
) -> UnwrappedKey:
    """Recover the target key from *blob* using the recipient's RSA key.

    Raises :class:`KeyUnwrapError` with a specific reason on any failure —
    never returns partial or guessed plaintext.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.keywrap import (
        InvalidUnwrap, aes_key_unwrap_with_padding,
    )

    if not blob:
        raise KeyUnwrapError("empty wrapped-key blob")

    rsa_len = private_key.key_size // 8
    if len(blob) < rsa_len + _MIN_KWP_BYTES:
        raise KeyUnwrapError(
            f"blob is {len(blob)} bytes; a CKM_RSA_AES_KEY_WRAP blob for a "
            f"{private_key.key_size}-bit key needs at least "
            f"{rsa_len + _MIN_KWP_BYTES} ({rsa_len} of RSA-OAEP plus an "
            f"AES-KWP body). Wrong recipient key, or not this mechanism.")

    rsa_segment, kwp_segment = blob[:rsa_len], blob[rsa_len:]

    aes_key: Optional[bytes] = None
    used_hash = ""
    oaep_errors = []
    for label, algo in (("sha256", hashes.SHA256()), ("sha1", hashes.SHA1())):
        try:
            aes_key = private_key.decrypt(
                rsa_segment,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=algo),
                    algorithm=algo,
                    label=None,
                ),
            )
            used_hash = label
            break
        except Exception as exc:  # cryptography raises a bare ValueError here
            oaep_errors.append(f"{label}: {type(exc).__name__}")

    if aes_key is None:
        raise KeyUnwrapError(
            "RSA-OAEP decrypt of the ephemeral AES key failed under both "
            f"SHA-256 and SHA-1 ({'; '.join(oaep_errors)}). The blob was not "
            "wrapped to this private key.")

    if len(aes_key) not in (16, 24, 32):
        raise KeyUnwrapError(
            f"RSA-OAEP yielded a {len(aes_key)}-byte ephemeral key; expected "
            "an AES-128/192/256 key. The blob is not CKM_RSA_AES_KEY_WRAP.")

    try:
        plaintext = aes_key_unwrap_with_padding(aes_key, kwp_segment)
    except InvalidUnwrap as exc:
        raise KeyUnwrapError(
            f"AES-KWP unwrap of the target key failed: {exc}. The RSA half "
            "succeeded, so the blob is truncated or corrupt rather than "
            "wrapped to the wrong key.") from exc

    if not plaintext:
        raise KeyUnwrapError("AES-KWP unwrap produced zero bytes")

    return UnwrappedKey(
        plaintext=plaintext,
        oaep_hash=used_hash,
        wrapped_aes_key_bytes=rsa_len,
    )
