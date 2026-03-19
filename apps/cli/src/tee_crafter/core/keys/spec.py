"""Core types for BYOK key release."""
from __future__ import annotations

import enum
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from tee_crafter.core.env_flags import env_hatch_open


class KeyGating(str, enum.Enum):
    """How strongly a *key custodian* gates a release.

    This is deliberately about the custodian (KMS / Key Vault / HSM), not
    about anything TEE-Crafter does locally.  The question each value answers
    is: *if an attacker ignored our Python entirely and called the provider
    API directly with whatever credentials the instance already has, would
    the provider still refuse?*

    ``KMS_ENFORCED``
        The provider evaluates a hardware-attestation claim that identifies
        *this* workload before releasing.  Example: AWS KMS
        ``kms:RecipientAttestation:PCR0`` equality on a Nitro ``Recipient``
        decrypt; Azure Managed HSM Secure Key Release pinned to
        ``x-ms-sevsnpvm-launchmeasurement``.

    ``IAM_SCOPED``
        The provider only checks *identity* (an IAM principal, a role ARN, a
        workload-identity principal).  Attestation, if collected at all, is
        checked by us in-process and is therefore advisory.  Anyone who can
        assume the identity — including code running as root on the CVM host
        that reads instance credentials from IMDS — can decrypt.

    ``NONE``
        TEE-Crafter cannot assert any custodian-side gate, either because the
        policy lives entirely with the customer (external HSM) or because the
        path is dev-only (local file).
    """

    KMS_ENFORCED = "kms-enforced"
    IAM_SCOPED = "iam-scoped"
    NONE = "none"


class KeyProvider(str, enum.Enum):
    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_kv"
    GCP_KMS = "gcp_kms"
    EXTERNAL_HSM = "external_hsm"
    LOCAL_FILE = "local_file"  # dev-only: customer ships a sealed file alongside the build


class UnwrapAlgorithm(str, enum.Enum):
    """How the adapter is expected to deliver the plaintext key."""
    DIRECT_BYTES = "direct_bytes"
    """Adapter returns plaintext bytes (use only for symmetric DEKs that
    the calling code will re-seal in TEE memory)."""

    AWS_NITRO_RECIPIENT = "aws_nitro_recipient"
    """AWS Nitro Enclave attested-decrypt: response is a CMS envelope
    encrypted to the enclave's attested public key.  Must be unwrapped
    inside the enclave with the matching private key."""

    AWS_NITROTPM_RECIPIENT = "aws_nitrotpm_recipient"
    """AWS NitroTPM attested-decrypt on an *ordinary* EC2 instance.

    Same ``Recipient`` mechanics as :attr:`AWS_NITRO_RECIPIENT` -- KMS returns a
    CMS envelope in ``CiphertextForRecipient`` -- but the attestation document is
    produced by the NitroTPM and signed by the Nitro Hypervisor rather than by
    the Nitro Security Module, and the condition keys are
    ``kms:RecipientAttestation:NitroTPMPCR<n>`` rather than
    ``...:PCR<n>``.  This is what makes measurement-gated key release reachable
    on ``snp-aws``, which is a Nitro instance but not an enclave.  See
    :mod:`tee_crafter.core.keys.nitrotpm`."""

    RSA_OAEP_SHA256 = "rsa_oaep_sha256"
    """Symmetric DEK wrapped under the enclave's RSA-OAEP-SHA-256
    public key (works with most cloud KMS WrappingKey APIs)."""

    CKM_RSA_AES_KEY_WRAP = "ckm_rsa_aes_key_wrap"
    """PKCS#11 ``CKM_RSA_AES_KEY_WRAP``: an ephemeral AES key wrapped
    under the recipient's RSA public key with OAEP, concatenated with the
    target key wrapped under that AES key with AES-KWP (RFC 5649).

    Two steps, not one.  This is what Azure Key Vault Managed HSM returns
    from ``POST /keys/{name}/{version}/release``; the value used to be
    labelled :attr:`RSA_OAEP_SHA256`, and a consumer that believed the
    label and did a single RSA-OAEP decrypt would fail on the AES-KWP
    half.  See ``KeyEncryptionAlgorithm`` in
    https://learn.microsoft.com/en-us/rest/api/keyvault/keys/release/release
    """


@dataclass(frozen=True)
class AttestedKeyRef:
    """Opaque, plaintext-free reference to a customer-managed key."""
    provider: KeyProvider
    key_id: str
    """Provider-specific identifier (KMS key ARN, Key Vault key URL,
    GCP fully-qualified name, external endpoint URL, ...)."""

    region: str = ""
    unwrap: UnwrapAlgorithm = UnwrapAlgorithm.DIRECT_BYTES
    label: str = ""
    """Free-form label for audit log readability."""
    extra: Dict[str, str] = field(default_factory=dict)
    """Provider-specific extras (e.g. AWS encryption context, Key Vault
    release-policy version, external HSM tenant id)."""

    def short(self) -> str:
        return f"{self.provider.value}:{self.key_id[-32:]}"


#: Environment escape hatch for :attr:`KeyReleasePolicy.allow_any_measurement`.
#: Exists so the in-TEE bootstrap (which builds the policy from ``byok.env``)
#: can be opted out without a code change.
ALLOW_ANY_MEASUREMENT_ENV = "TEE_CRAFTER_BYOK_ALLOW_ANY_MEASUREMENT"


@dataclass
class KeyReleasePolicy:
    """Gate that all key releases must pass."""

    required_provider: Optional[KeyProvider] = None
    """If set, refuses releases whose AttestedKeyRef does not match."""

    max_attestation_age_seconds: int = 300
    """The attestation blob accompanying the release request must have
    been generated no more than this many seconds ago."""

    allowed_measurement_sha256: List[str] = field(default_factory=list)
    """Allowlist of SHA-256(measurement) values.

    An **empty list is rejected** by :meth:`validate` unless
    :attr:`allow_any_measurement` (or the ``TEE_CRAFTER_BYOK_ALLOW_ANY_MEASUREMENT``
    environment escape hatch) is set.  An empty allowlist silently disables the
    measurement check entirely, which is exactly the failure mode we do not
    want to ship as a default.
    """

    allow_any_measurement: bool = False
    """Explicit opt-out of the non-empty-allowlist requirement.

    Set this (or export ``TEE_CRAFTER_BYOK_ALLOW_ANY_MEASUREMENT=1``) only when
    you knowingly accept that *any* measurement will be released to — e.g. the
    very first bake of a new image, before a measurement has been pinned.  Note
    that even a populated allowlist is only **advisory** on providers whose
    gating is :attr:`KeyGating.IAM_SCOPED`; see :mod:`tee_crafter.core.keys.gating`.
    """

    require_signed_audit: bool = True
    """If True, every release attempt must be appended to the audit chain.

    Enforced by :class:`~tee_crafter.core.keys.release.KeyReleaseOrchestrator`
    in two places: it refuses to be constructed without an ``audit=`` sink, and
    a failed audit write aborts the release instead of being swallowed.  Set
    False (or export ``TEE_CRAFTER_BYOK_REQUIRE_SIGNED_AUDIT=0``) only when you
    accept releases that leave no record.
    """

    require_encryption_context_keys: List[str] = field(default_factory=list)
    """For AWS-style providers: the request's encryption context must
    contain at least these keys.  Useful for tying a key to a specific
    workload identity."""

    def allows_any_measurement(self) -> bool:
        """True when the operator has explicitly opted out of the allowlist."""
        if self.allow_any_measurement:
            return True
        return env_hatch_open(ALLOW_ANY_MEASUREMENT_ENV)

    def validate(self) -> List[str]:
        errs: List[str] = []
        if self.max_attestation_age_seconds <= 0:
            errs.append("max_attestation_age_seconds must be > 0")
        for m in self.allowed_measurement_sha256:
            if len(m) != 64:
                errs.append(f"measurement {m!r} is not a 64-hex SHA-256")
        if not self.allowed_measurement_sha256 and not self.allows_any_measurement():
            errs.append(
                "allowed_measurement_sha256 is empty, which disables the "
                "measurement gate entirely.  Pin the bake-time measurement, or "
                "opt out deliberately with allow_any_measurement=True / "
                f"{ALLOW_ANY_MEASUREMENT_ENV}=1")
        return errs


@dataclass
class AttestedKeyMaterial:
    """Result of a successful release.

    The caller is responsible for placing ``plaintext`` (when present)
    into a memlocked buffer and for zeroing it after use.
    """
    key_ref: AttestedKeyRef
    plaintext: Optional[bytes]
    wrapped_for_recipient: Optional[bytes]
    unwrap_algorithm: UnwrapAlgorithm
    released_at: float
    attestation_sha256: str
    attestation_age_seconds: float
    audit_id: str = ""
    provider_response_metadata: Dict[str, Any] = field(default_factory=dict)

    gating: KeyGating = KeyGating.NONE
    """What the *key custodian* actually enforced for this release.

    Machine-readable so the evidence layer and the docs can state the truth per
    provider×platform combination instead of a blanket "attestation-gated"
    claim.  Populated by :class:`~tee_crafter.core.keys.release.KeyReleaseOrchestrator`
    from :func:`tee_crafter.core.keys.gating.gating_for`.
    """

    measurement_gate: str = "advisory"
    """``"policy-enforced"`` or ``"advisory"``.

    ``"advisory"`` means the ``allowed_measurement_sha256`` check ran as a
    local ``if`` in this process, on the CVM host, over a report we did not
    verify a signature for — i.e. it raises the bar for accidents, not for
    adversaries.  It is ``"policy-enforced"`` only when :attr:`gating` is
    :attr:`KeyGating.KMS_ENFORCED`, where the custodian evaluated the
    measurement itself.
    """

    gating_note: str = ""
    """Human-readable one-liner explaining :attr:`gating` for this combination."""


class KeyReleaseError(Exception):
    """Raised when a release request is denied by either the local
    policy or the remote provider."""


class KmsAdapter(ABC):
    """Synchronous KMS adapter contract.

    All concrete adapters must be safe to construct without performing
    network IO so unit tests can instantiate them with mocks.  Network IO
    happens only inside :meth:`release`.
    """

    provider: KeyProvider = KeyProvider.LOCAL_FILE

    @abstractmethod
    def release(
        self,
        *,
        key_ref: AttestedKeyRef,
        attestation: bytes,
        policy: KeyReleasePolicy,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> AttestedKeyMaterial:
        """Request that the provider release the key referenced by
        *key_ref*, conditioned on the supplied attestation.

        Raises :class:`KeyReleaseError` on policy or provider failure.
        """

    # Convenience: every adapter exposes a fast pre-flight check that
    # validates *only* the local policy.  Raising here lets the caller
    # avoid making a network call when the request is doomed.
    def preflight(
        self,
        *,
        key_ref: AttestedKeyRef,
        attestation: bytes,
        policy: KeyReleasePolicy,
        attestation_issued_at: Optional[float] = None,
    ) -> None:
        errs = policy.validate()
        if errs:
            raise KeyReleaseError("Invalid policy: " + "; ".join(errs))
        if policy.required_provider is not None and key_ref.provider != policy.required_provider:
            raise KeyReleaseError(
                f"Policy requires provider {policy.required_provider.value!r}, "
                f"but key_ref is {key_ref.provider.value!r}"
            )
        if not attestation:
            raise KeyReleaseError("Empty attestation blob")
        if attestation_issued_at is not None:
            age = time.time() - float(attestation_issued_at)
            if age > policy.max_attestation_age_seconds:
                raise KeyReleaseError(
                    f"Attestation is {age:.0f}s old; policy max is "
                    f"{policy.max_attestation_age_seconds}s"
                )
            if age < -5:
                raise KeyReleaseError(
                    f"Attestation timestamp is {age:.0f}s in the future; clock skew?")
