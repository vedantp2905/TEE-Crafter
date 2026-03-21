"""AWS KMS adapter with optional Nitro Enclave Recipient flow.

Nitro Enclaves
--------------
When ``unwrap=AttestedKeyRef.unwrap=AWS_NITRO_RECIPIENT``, the adapter
attaches the running enclave's attestation document (PKCS#7 envelope
containing the enclave PCRs and a public key) to the ``Recipient``
parameter of ``kms:Decrypt``.  KMS evaluates the attached attestation
against the customer-managed key policy (which references condition keys
like ``kms:RecipientAttestation:PCR0``) and re-encrypts the plaintext key
to the enclave-supplied public key.  The plaintext therefore never leaves
the customer's KMS in the clear.

For non-Nitro CVMs (SNP / GPU CC), AWS exposes **no** ``Recipient``
parameter and **no** condition key for an AMD SEV-SNP measurement, so the
adapter falls back to a plain ``kms:Decrypt``.  That call is gated on the
caller's IAM principal and nothing else.  It is honest to call that path
``iam-scoped`` -- see :mod:`tee_crafter.core.keys.gating` -- and the returned
:class:`~tee_crafter.core.keys.spec.AttestedKeyMaterial` says so.  Both paths
require BYOK; neither lets the build host see plaintext key material outside
the TEE.
"""
from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from tee_crafter.core.env_flags import interpret
from tee_crafter.core.keys.gating import (
    FACT_NITROTPM_PCRS_PINNED, FACT_PCRS_PINNED, gating_from_extra,
)
from tee_crafter.core.keys.spec import (
    AttestedKeyMaterial, AttestedKeyRef, KeyProvider, KeyReleaseError,
    KeyReleasePolicy, KmsAdapter, UnwrapAlgorithm,
)


#: Unwrap algorithms that ride the ``Recipient`` parameter.  Both return a CMS
#: envelope rather than plaintext; they differ only in who signed the attached
#: attestation document and therefore which condition keys the policy uses.
_RECIPIENT_UNWRAPS = frozenset({
    UnwrapAlgorithm.AWS_NITRO_RECIPIENT,
    UnwrapAlgorithm.AWS_NITROTPM_RECIPIENT,
})


class AwsKmsAdapter(KmsAdapter):
    provider = KeyProvider.AWS_KMS

    def __init__(self, *, kms_client=None, region: str = ""):
        """
        :param kms_client: optional pre-built ``boto3.client('kms')``.
            When ``None``, a client is created lazily on first call so
            unit tests can instantiate the adapter without AWS creds.
        :param region: region for lazy client creation.  Empty means "let boto3
            resolve it" -- from ``AWS_REGION`` / ``AWS_DEFAULT_REGION``, or from
            instance metadata when running on EC2.  This used to default to
            ``us-east-2``, which silently sent a key release at one specific
            region regardless of where the key or the instance actually was; a
            wrong region fails the release rather than reaching the wrong key,
            but it reports "key not found" instead of "no region configured".
        """
        self._kms_client = kms_client
        self._region = (region or "").strip()

    def _client(self):
        if self._kms_client is not None:
            return self._kms_client
        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise KeyReleaseError(
                "boto3 is required for AwsKmsAdapter; install tee_crafter with "
                "the [aws] extra or pass an explicit kms_client.") from exc
        self._kms_client = (
            boto3.client("kms", region_name=self._region) if self._region
            else boto3.client("kms"))
        return self._kms_client

    def release(
        self,
        *,
        key_ref: AttestedKeyRef,
        attestation: bytes,
        policy: KeyReleasePolicy,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> AttestedKeyMaterial:
        if key_ref.provider != KeyProvider.AWS_KMS:
            raise KeyReleaseError(
                f"AwsKmsAdapter cannot release {key_ref.provider.value} keys")

        ciphertext_b64 = key_ref.extra.get("ciphertext_b64")
        if not ciphertext_b64:
            raise KeyReleaseError(
                "AWS KMS release expects key_ref.extra['ciphertext_b64'] "
                "(the customer's wrapped DEK)")
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
        except Exception as exc:
            raise KeyReleaseError(f"ciphertext_b64 is not valid base64: {exc}")

        request: Dict[str, Any] = {
            "CiphertextBlob": ciphertext,
            "KeyId": key_ref.key_id,
        }
        if encryption_context:
            request["EncryptionContext"] = dict(encryption_context)

        attested = key_ref.unwrap in _RECIPIENT_UNWRAPS
        if attested:
            # Attach the attestation as the Recipient envelope so KMS evaluates
            # it against the key policy and re-encrypts the plaintext to the
            # public key carried inside the document.  Identical request shape
            # for both document flavours; what differs is which condition keys
            # the policy is written against (PCR<n> for enclaves,
            # NitroTPMPCR<n> for instances).
            if not attestation:
                raise KeyReleaseError(
                    f"{key_ref.unwrap.value} requires an attestation document; "
                    "without one KMS denies the request outright when the key "
                    "policy carries a RecipientAttestation condition, and "
                    "returns plaintext when it does not -- neither is an "
                    "attested release")
            request["Recipient"] = {
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "AttestationDocument": attestation,
            }

        client = self._client()
        try:
            response = client.decrypt(**request)
        except Exception as exc:
            raise KeyReleaseError(f"kms:Decrypt failed: {exc}") from exc

        plaintext: Optional[bytes] = None
        wrapped_for_recipient: Optional[bytes] = None

        if attested:
            wrapped_for_recipient = response.get("CiphertextForRecipient")
            if not wrapped_for_recipient:
                raise KeyReleaseError(
                    f"{key_ref.unwrap.value} release succeeded but the response "
                    "had no CiphertextForRecipient field. KMS omits it when it "
                    "did not treat the request as attested, so treat this as a "
                    "failed attested release rather than reading Plaintext.")
        else:
            plaintext = response.get("Plaintext")
            if not plaintext:
                raise KeyReleaseError("kms:Decrypt returned no Plaintext field")

        # Only a Recipient flow can ever be KMS-enforced, and only when the key
        # policy actually pins PCRs (recorded by the deploy side).  A
        # non-Recipient decrypt is identity-gated no matter what the key policy
        # says, so never let either fact upgrade it.
        pinned = interpret(str(key_ref.extra.get(FACT_PCRS_PINNED, ""))) is True
        tpm_pinned = interpret(
            str(key_ref.extra.get(FACT_NITROTPM_PCRS_PINNED, ""))) is True
        gating = gating_from_extra(
            KeyProvider.AWS_KMS, key_ref.extra,
            **{
                FACT_PCRS_PINNED: (
                    key_ref.unwrap == UnwrapAlgorithm.AWS_NITRO_RECIPIENT
                    and pinned),
                FACT_NITROTPM_PCRS_PINNED: (
                    key_ref.unwrap == UnwrapAlgorithm.AWS_NITROTPM_RECIPIENT
                    and tpm_pinned),
            },
        )

        meta = {
            "key_id": response.get("KeyId", key_ref.key_id),
            "encryption_algorithm": response.get("EncryptionAlgorithm", ""),
            "request_id": response.get("ResponseMetadata", {}).get("RequestId", ""),
            **gating.as_dict(),
        }
        return AttestedKeyMaterial(
            key_ref=key_ref,
            plaintext=plaintext,
            wrapped_for_recipient=wrapped_for_recipient,
            unwrap_algorithm=key_ref.unwrap,
            released_at=0.0,
            attestation_sha256="",
            attestation_age_seconds=0.0,
            audit_id="",
            provider_response_metadata=meta,
            gating=gating.gating,
            measurement_gate=gating.measurement_gate,
            gating_note=gating.note,
        )
