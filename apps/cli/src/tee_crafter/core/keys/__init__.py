"""Customer-managed key (BYOK) support with attestation-gated release.

Most regulated buyers do not want TEE-Crafter to mint and own the data
encryption keys for their workload.  They want to keep keys in *their*
KMS / Key Vault / HSM, audit every release, and condition each release on
a fresh hardware attestation.

This package gives the build host and the in-TEE runtime a unified API
for that:

* :class:`AttestedKeyRef` — opaque key handle (provider, key id, region,
  unwrap algorithm).  Build hosts pass this around without ever holding
  plaintext key material.
* :class:`KeyReleasePolicy` — declarative gate for a release request
  (required PCRs, allowed measurements, freshness window, audit hook).
* :class:`KmsAdapter` — abstract async-friendly base class.  The adapter
  takes an attestation blob and returns either plaintext key bytes (for
  symmetric DEK release) or an enclave-wrapped ciphertext (for
  recipient-info flows like AWS Nitro Enclaves).
* :class:`KeyReleaseOrchestrator` — composes a policy + adapter +
  attestation source so callers say
  ``orch.release(key_ref) -> AttestedKeyMaterial`` once and get a typed
  result with provenance metadata for the audit trail.

Concrete adapters live in submodules so optional cloud SDKs are not
forced on every install:

* :mod:`tee_crafter.core.keys.aws_kms` — AWS KMS (with optional Nitro
  Enclave ``Recipient`` parameter for true attested unwrap).
* :mod:`tee_crafter.core.keys.azure_kv` — Azure Key Vault Managed HSM
  (uses ``release_key`` with a JSON-encoded attestation token).
* :mod:`tee_crafter.core.keys.gcp_kms` — GCP KMS / external HSM via the
  Cloud KMS attested-decrypt pattern.
* :mod:`tee_crafter.core.keys.external_hsm` — POSTs the attestation to a
  customer-controlled HTTPS endpoint that returns a wrapped DEK.
* :mod:`tee_crafter.core.keys.gating` — machine-readable truth table stating,
  per provider x platform, whether the key custodian itself enforces
  attestation (``kms-enforced``), only checks identity (``iam-scoped``), or
  gives us nothing to assert (``none``).  Read this before describing any BYOK
  path as "attestation-gated".
"""
from tee_crafter.core.keys.spec import (
    AttestedKeyRef,
    AttestedKeyMaterial,
    KeyGating,
    KeyProvider,
    KeyReleasePolicy,
    KeyReleaseError,
    KmsAdapter,
)
from tee_crafter.core.keys.gating import (
    ProviderGating,
    gating_for,
    gating_table,
)
from tee_crafter.core.keys.release import (
    KeyReleaseOrchestrator,
    AttestationProvider,
)

__all__ = [
    "AttestedKeyRef",
    "AttestedKeyMaterial",
    "KeyGating",
    "KeyProvider",
    "KeyReleasePolicy",
    "KeyReleaseError",
    "KmsAdapter",
    "KeyReleaseOrchestrator",
    "AttestationProvider",
    "ProviderGating",
    "gating_for",
    "gating_table",
]
