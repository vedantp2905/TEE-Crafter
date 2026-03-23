"""GCP KMS / Confidential Space adapter.

GCP's attested-decrypt path piggy-backs on Cloud KMS' standard ``Decrypt``
API plus a *workload identity* federation token issued by the Confidential
Space attestation verifier.  The gate lives in the **IAM binding** on the KMS
key: ``roles/cloudkms.cryptoKeyDecrypter`` granted to a ``principalSet://``
workload-identity pool with an attribute condition on the attestation token's
claims.  See :mod:`tee_crafter.core.keys.gating` -- without that condition this
provider is ``iam-scoped``, not attestation-gated.

Additional authenticated data
-----------------------------
Cloud KMS' ``additional_authenticated_data`` is a plain AEAD input: the bytes
handed to ``Decrypt`` must be **byte-identical** to the bytes handed to
``Encrypt``, or decryption fails.  It carries no authorisation semantics
whatsoever -- Cloud KMS never inspects it, and there is no IAM condition key
that can reference it.

This adapter used to pass the raw attestation report as the AAD.  That can
never work: the report is regenerated on every boot, so it is not equal to
anything the wrap side could have known.  Every ``--byok gcp-kms`` decrypt was
guaranteed to fail.

The AAD is therefore defined as the **canonical encryption context** (see
:func:`canonical_aad`), for three reasons:

1. It is deterministic and known to *both* sides offline, which an attestation
   report can never be.
2. It gives GCP the same "this ciphertext belongs to this workload/tenant"
   binding that AWS KMS gives natively via ``EncryptionContext``, so the two
   providers behave alike.
3. An **empty** encryption context canonicalises to ``b""``, which is exactly
   what Cloud KMS uses when the ``Encrypt`` call omits the field.  Existing
   ciphertexts wrapped without an AAD therefore keep decrypting.

Wrap-side callers must use :func:`canonical_aad` on the *same* encryption
context dict.  ``byok-sandbox/gcp/wrap_dek.py`` does.

This adapter is intentionally generic: any callable that posts a JSON
attested-decrypt request and returns the decoded plaintext or wrapped
DEK can be plugged in.  The default implementation uses
``google-cloud-kms`` if it is importable; otherwise ``decrypt=`` must be
supplied.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Callable, Dict, Mapping, Optional

from tee_crafter.core.keys.gating import gating_from_extra
from tee_crafter.core.keys.spec import (
    AttestedKeyMaterial, AttestedKeyRef, KeyProvider, KeyReleaseError,
    KeyReleasePolicy, KmsAdapter, UnwrapAlgorithm,
)


GcpDecrypt = Callable[[Dict[str, Any]], Dict[str, Any]]


def canonical_aad(encryption_context: Optional[Mapping[str, str]]) -> bytes:
    """Canonical Cloud KMS AAD bytes for an encryption context.

    **Both** the wrap side and the unwrap side must call this; Cloud KMS
    compares the bytes for equality, so any difference in key order, spacing,
    or encoding breaks decryption.

    Canonical form is ``json.dumps(ctx, sort_keys=True, separators=(",", ":"))``
    encoded as UTF-8 -- the same canonicalisation
    :mod:`tee_crafter.core.sealing.seal` uses for its GCM AAD.  An empty or
    missing context maps to ``b""`` so it matches a Cloud KMS ``Encrypt`` call
    that omitted ``additional_authenticated_data`` entirely.

    >>> canonical_aad(None)
    b''
    >>> canonical_aad({"b": "2", "a": "1"})
    b'{"a":"1","b":"2"}'
    """
    if not encryption_context:
        return b""
    return json.dumps(
        dict(encryption_context), sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


class GcpKmsAdapter(KmsAdapter):
    provider = KeyProvider.GCP_KMS

    def __init__(
        self,
        *,
        decrypt: Optional[GcpDecrypt] = None,
    ):
        self._decrypt = decrypt

    def _default_decrypt(self) -> GcpDecrypt:
        try:
            from google.cloud import kms_v1  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise KeyReleaseError(
                "google-cloud-kms is required for GcpKmsAdapter; pass decrypt=...") from exc
        client = kms_v1.KeyManagementServiceClient()

        def _decrypt(req):
            resp = client.decrypt(request=req)
            return {
                "plaintext": resp.plaintext,
                "name": getattr(resp, "name", ""),
                "verified_plaintext_crc32c": bool(
                    getattr(resp, "verified_plaintext_crc32c", False)),
            }
        return _decrypt

    def release(
        self,
        *,
        key_ref: AttestedKeyRef,
        attestation: bytes,
        policy: KeyReleasePolicy,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> AttestedKeyMaterial:
        if key_ref.provider != KeyProvider.GCP_KMS:
            raise KeyReleaseError(
                f"GcpKmsAdapter cannot release {key_ref.provider.value} keys")

        ciphertext_b64 = key_ref.extra.get("ciphertext_b64")
        if not ciphertext_b64:
            raise KeyReleaseError(
                "GCP KMS release expects key_ref.extra['ciphertext_b64']")
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
        except Exception as exc:
            raise KeyReleaseError(f"ciphertext_b64 is not valid base64: {exc}")

        # AAD == canonical encryption context, byte-identical to what the wrap
        # side computed.  NOT the attestation blob: Cloud KMS compares AAD for
        # equality and never inspects it, and a fresh per-boot report can never
        # equal anything the wrap side knew.  See the module docstring.
        req: Dict[str, Any] = {
            "name": key_ref.key_id,
            "ciphertext": ciphertext,
            "additional_authenticated_data": canonical_aad(encryption_context),
        }
        decrypt = self._decrypt or self._default_decrypt()
        try:
            resp = decrypt(req)
        except Exception as exc:
            raise KeyReleaseError(f"GCP KMS Decrypt failed: {exc}") from exc
        plaintext = resp.get("plaintext")
        if not plaintext:
            raise KeyReleaseError("GCP KMS Decrypt returned no plaintext")

        # Whether this release was really attestation-gated depends on the key's
        # IAM binding, which we cannot read from inside the TEE; the deploy side
        # records it as extra['attribute_condition_bound'].
        gating = gating_from_extra(KeyProvider.GCP_KMS, key_ref.extra)

        return AttestedKeyMaterial(
            key_ref=key_ref,
            plaintext=plaintext,
            wrapped_for_recipient=None,
            unwrap_algorithm=UnwrapAlgorithm.DIRECT_BYTES,
            released_at=0.0,
            attestation_sha256="",
            attestation_age_seconds=0.0,
            audit_id="",
            provider_response_metadata={
                "name": resp.get("name", key_ref.key_id),
                "verified_plaintext_crc32c": resp.get("verified_plaintext_crc32c"),
                **gating.as_dict(),
            },
            gating=gating.gating,
            measurement_gate=gating.measurement_gate,
            gating_note=gating.note,
        )
