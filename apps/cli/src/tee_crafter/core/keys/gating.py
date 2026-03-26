"""Machine-readable truth table: what each BYOK provider actually enforces.

Background
----------
Every BYOK path in TEE-Crafter used to be described as "attestation-gated".
That is true for exactly one provider x platform combination.  For the rest,
the only thing standing between an attacker and the key is either an IAM
identity (which the CVM already holds, and which anyone with root on the CVM
can read out of IMDS) or the customer's own HSM policy, which we cannot see.

Rather than argue about wording in prose, this module states the answer as
data, keyed by ``(provider, tee_platform)``, so the release path, the audit /
evidence layer, and the docs can all read the *same* value.  Every entry
answers one question:

    If an attacker skipped our Python entirely and called the provider API
    directly with the credentials the instance already has, would the
    provider still refuse?

* :attr:`~tee_crafter.core.keys.spec.KeyGating.KMS_ENFORCED` -- yes, because
  the provider evaluates a hardware-attestation claim naming *this* workload.
* :attr:`~tee_crafter.core.keys.spec.KeyGating.IAM_SCOPED` -- no; the provider
  only checks identity.  Our measurement allowlist still runs, but it runs
  in-process on the untrusted host, so it is **advisory**.
* :attr:`~tee_crafter.core.keys.spec.KeyGating.NONE` -- we cannot assert
  anything (customer-owned HSM policy, or a dev-only local file).

Some combinations are conditional: ``aws_kms`` on ``nitro-aws`` is only
KMS-enforced once PCRs are actually pinned into the key policy, and
``azure_kv`` is only KMS-enforced once the Secure Key Release policy binds
``x-ms-sevsnpvm-launchmeasurement`` / ``x-ms-sevsnpvm-hostdata``.  Those are
expressed as the ``upgrade_when`` fact name; :func:`gating_for` takes the fact
as a keyword and returns the upgraded verdict only when it is True.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from tee_crafter.core.keys.spec import KeyGating, KeyProvider
from tee_crafter.core.env_flags import interpret

#: Fact names understood by :func:`gating_for` (keyword arguments).
FACT_PCRS_PINNED = "pcrs_pinned"
"""AWS/Nitro: the KMS key policy carries ``kms:RecipientAttestation:PCR{0,1,2}``
equality conditions (i.e. the operator supplied ``--pcrs-json``)."""

FACT_NITROTPM_PCRS_PINNED = "nitrotpm_pcrs_pinned"
"""AWS/CVM: the KMS key policy carries ``kms:RecipientAttestation:NitroTPMPCR<n>``
equality conditions and the release path attaches a NitroTPM attestation
document.  Distinct from :data:`FACT_PCRS_PINNED`, which is the Nitro *Enclaves*
condition key -- a different key hierarchy and a different set of PCRs."""

FACT_WORKLOAD_CLAIMS_BOUND = "workload_claims_bound"
"""Azure: the Secure Key Release policy pins ``x-ms-sevsnpvm-launchmeasurement``
(and ideally ``x-ms-sevsnpvm-hostdata``) rather than only the attestation type."""

FACT_ATTRIBUTE_CONDITION_BOUND = "attribute_condition_bound"
"""GCP: the key's IAM binding carries a Confidential Space workload-identity
attribute condition on the attestation token (e.g.
``assertion.submods.container.image_digest``) rather than an unconditional
grant to a principal."""


@dataclass(frozen=True)
class ProviderGating:
    """One row of the truth table."""

    gating: KeyGating
    enforced_by: str
    """Short label for *who* refuses: ``"aws-kms-key-policy"``,
    ``"azure-mhsm-skr-policy"``, ``"iam"``, ``"customer-hsm"``, ``"nobody"``."""
    note: str
    upgrade_when: Optional[str] = None
    """Name of the fact that, when True, promotes this row to :attr:`upgraded`."""
    upgraded: Optional["ProviderGating"] = None

    @property
    def measurement_gate(self) -> str:
        """``"policy-enforced"`` when the custodian checks the measurement."""
        return ("policy-enforced" if self.gating is KeyGating.KMS_ENFORCED
                else "advisory")

    def as_dict(self) -> Dict[str, str]:
        return {
            "gating": self.gating.value,
            "enforced_by": self.enforced_by,
            "measurement_gate": self.measurement_gate,
            "note": self.note,
        }


_NITRO_KMS_ENFORCED = ProviderGating(
    gating=KeyGating.KMS_ENFORCED,
    enforced_by="aws-kms-key-policy",
    note=("AWS KMS evaluates the Nitro attestation document attached to the "
          "Decrypt Recipient parameter against kms:RecipientAttestation:PCR{0,1,2} "
          "equality conditions and re-encrypts to the enclave's attested public "
          "key.  This is the reference implementation."),
)

_NITRO_UNPINNED = ProviderGating(
    gating=KeyGating.IAM_SCOPED,
    enforced_by="iam",
    note=("No --pcrs-json supplied, so the key policy degrades to "
          "Null:{kms:RecipientAttestation:ImageSha384: false} -- 'the caller is "
          "*some* enclave in this account'.  Any enclave in the account "
          "decrypts; the specific workload is not identified."),
    upgrade_when=FACT_PCRS_PINNED,
    upgraded=_NITRO_KMS_ENFORCED,
)

#: Why ``_AWS_CVM`` below is a *TEE-Crafter* gap rather than an AWS one.
#:
#: This entry used to say "AWS KMS exposes no condition key for AMD SEV-SNP (or
#: NitroTPM) measurements".  The SEV-SNP half is still true -- KMS has no
#: condition key for an SNP launch measurement, and `kms:Decrypt`'s `Recipient`
#: parameter does not accept an SNP attestation report.  The NitroTPM half is
#: no longer true, and it is the half that matters, because it means an
#: attestation-gated key on `snp-aws` is buildable rather than blocked:
#:
#:   * KMS ships ``kms:RecipientAttestation:NitroTPMPCR4`` / ``NitroTPMPCR7`` /
#:     ``NitroTPMPCR12`` for Decrypt, GenerateDataKey, GenerateDataKeyPair,
#:     DeriveSharedSecret and GenerateRandom, effective when `Recipient` carries
#:     a signed NitroTPM attestation document
#:     (docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-tpm.html).
#:   * It applies to **ordinary EC2 instances**, not only Nitro Enclaves: the
#:     instance must be launched from an "Attestable AMI", and AWS's own example
#:     policy binds PCR4 + PCR12 for standard boot, or PCR7 for Secure Boot
#:     (docs.aws.amazon.com/AWSEC2/latest/UserGuide/prepare-attestation-service.html).
#:
#: `snp-aws` runs M6a/C6a/R6a -- Nitro instances -- and the bake already enrols
#: UEFI Secure Boot by default (`bake_ami._SECURE_BOOT_AWS_PLATFORMS`), so PCR7
#: is the natural binding.  What this buys is a measured-boot binding, not an
#: SEV-SNP memory-encryption binding: it proves the instance booted the AMI we
#: baked, which is strictly more than "some principal holding this role".
#:
#: Verified against the AWS docs on 2026-08-23.  Tracked as C6.
NITROTPM_UPGRADE_NOTE = (
    "Attestation-gated BYOK on snp-aws runs on AWS's NitroTPM PCR condition "
    "keys -- kms:RecipientAttestation:NitroTPMPCR4/7/12 -- with PCR4 (boot "
    "manager code) for image identity and PCR7 (Secure Boot policy), which the "
    "bake already enrols.  It is all-or-nothing by construction: KMS states the "
    "condition 'is effective only when the Recipient parameter in the request "
    "specifies a signed attestation document from NitroTPM' and that 'if the "
    "request does not include an attestation document, permission is denied', "
    "so pinning PCRs without attaching a document denies every decrypt.  Both "
    "halves therefore ship together -- see core/keys/nitrotpm.py for the "
    "document and the CMS unwrap, and cli/deployment/common/byok_key_policy.py "
    "for the conditions.  An Attestable AMI is NOT a prerequisite: that is how "
    "AWS makes PCRs predictable ahead of time from a KIWI NG image description "
    "on Amazon Linux 2023, whereas this project records what the baked image "
    "actually measures, the same way every other platform's measurement "
    "reaches the registry.  Verified against the AWS docs 2026-08-23: "
    "docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-tpm.html, "
    "docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation.html and "
    ".../nitrotpm-attestation-document-content.html"
)

_AWS_NITROTPM_ENFORCED = ProviderGating(
    gating=KeyGating.KMS_ENFORCED,
    enforced_by="aws-kms-key-policy",
    note=("AWS KMS evaluates a NitroTPM attestation document -- generated by the "
          "NitroTPM and signed by the Nitro Hypervisor -- attached to the "
          "Decrypt Recipient parameter against "
          "kms:RecipientAttestation:NitroTPMPCR4 and NitroTPMPCR7 equality "
          "conditions, and re-encrypts the plaintext to the RSA public key "
          "carried inside that document.  PCR4 is the boot manager code, so the "
          "gate names this baked image; PCR7 is the Secure Boot policy the bake "
          "enrols into the AMI's UefiData.  This is a measured-boot binding, "
          "not an SEV-SNP memory-encryption binding: KMS still has no condition "
          "key for an SNP launch measurement.  It proves the instance booted the "
          "AMI we baked, which is strictly more than 'some principal holding "
          "this role'."),
)

_AWS_CVM = ProviderGating(
    gating=KeyGating.IAM_SCOPED,
    enforced_by="iam",
    upgrade_when=FACT_NITROTPM_PCRS_PINNED,
    upgraded=_AWS_NITROTPM_ENFORCED,
    note=("AWS KMS exposes no condition key for an AMD SEV-SNP measurement, so "
          "kms:Decrypt here is identity-gated, not attestation-gated: the check "
          "is that the caller's principal ARN matches the instance role.  Two "
          "things narrow that, both on by default since 2026-08-23.  (1) The "
          "deploy pins the key policy to the *exact* per-deploy role ARN with "
          "ArnEquals once Terraform has created it "
          "(cli/deployment/common/byok_key_policy.py); keys are created with no "
          "decrypt grant at all (--pin-at-deploy), so there is no window in "
          "which a role-name pattern is accepted.  (2) IMDSv2 is required with "
          "http_put_response_hop_limit = 1, so the workload *container* -- one "
          "network hop away -- cannot reach IMDS to read those credentials at "
          "all.  Residual risk, stated precisely: an attacker with root on the "
          "VM host (outside the container) can still obtain the role "
          "credentials and decrypt outside the TEE.  SEV-SNP memory encryption "
          "already excludes the cloud operator, so this is a guest-compromise "
          "threat rather than an infrastructure one.  The measurement allowlist "
          "is advisory.  This row is the *unpinned* state: supply NitroTPM PCR "
          "conditions and the release upgrades to measured-boot binding -- see "
          "NITROTPM_UPGRADE_NOTE."),
)

_AZURE_CLAIMS_BOUND = ProviderGating(
    gating=KeyGating.KMS_ENFORCED,
    enforced_by="azure-mhsm-skr-policy",
    note=("Managed HSM Secure Key Release evaluates the MAA token against a "
          "policy that pins x-ms-sevsnpvm-launchmeasurement (and hostdata), so "
          "the release names this specific workload image."),
)

_AZURE_TYPE_ONLY = ProviderGating(
    gating=KeyGating.IAM_SCOPED,
    enforced_by="iam",
    note=("Secure Key Release is real, but the shipped policy pins only "
          "x-ms-attestation-type against the *shared public* MAA authorities, "
          "which any SEV-SNP/TDX CVM in any Azure tenant satisfies.  The "
          "effective gate is therefore the vault's data-plane RBAC.  Pass a "
          "launch measurement (and ideally host data) to bind the workload."),
    upgrade_when=FACT_WORKLOAD_CLAIMS_BOUND,
    upgraded=_AZURE_CLAIMS_BOUND,
)

_AZURE_SGX = ProviderGating(
    gating=KeyGating.IAM_SCOPED,
    enforced_by="iam",
    note=("sgx-azure is served the combined SNP+TDX release policy, whose "
          "x-ms-attestation-type claims an SGX workload does not present.  "
          "Treat this combination as identity-gated and expect SKR itself to "
          "fail; it is not wired end to end."),
)

_GCP_CONDITIONED = ProviderGating(
    gating=KeyGating.KMS_ENFORCED,
    enforced_by="gcp-iam-attribute-condition",
    note=("The key's IAM binding carries a Confidential Space workload-identity "
          "attribute condition on the attestation token, so Cloud KMS refuses "
          "callers whose attestation claims do not match."),
)

_GCP_UNCONDITIONED = ProviderGating(
    gating=KeyGating.IAM_SCOPED,
    enforced_by="iam",
    note=("Cloud KMS AAD carries no policy semantics -- it is a plain AEAD "
          "binding, not an authorisation input.  Without a Confidential Space / "
          "workload-identity-pool attribute condition on the key's IAM binding, "
          "the real gate is an unconditional IAM grant.  The measurement "
          "allowlist is advisory."),
    upgrade_when=FACT_ATTRIBUTE_CONDITION_BOUND,
    upgraded=_GCP_CONDITIONED,
)

_EXTERNAL_HSM = ProviderGating(
    gating=KeyGating.NONE,
    enforced_by="customer-hsm",
    note=("The release decision is delegated to the customer's HSM gateway; "
          "TEE-Crafter forwards the raw attestation blob and cannot assert what "
          "the gateway does with it.  The unwrap algorithm is pinned "
          "client-side so a hostile gateway cannot downgrade it."),
)

_LOCAL_FILE = ProviderGating(
    gating=KeyGating.NONE,
    enforced_by="nobody",
    note="Dev-only path: the key material ships alongside the build.",
)

_UNKNOWN = ProviderGating(
    gating=KeyGating.NONE,
    enforced_by="nobody",
    note=("No gating fact recorded for this provider/platform combination; "
          "treat as ungated until someone establishes otherwise."),
)


#: ``(provider, tee_platform)`` -> row.  ``tee_platform=""`` is the
#: provider-wide default used when the caller does not know the platform.
_TABLE: Dict[Tuple[KeyProvider, str], ProviderGating] = {
    (KeyProvider.AWS_KMS, "nitro-aws"): _NITRO_UNPINNED,
    (KeyProvider.AWS_KMS, "snp-aws"): _AWS_CVM,
    (KeyProvider.AWS_KMS, "gpu-cc-aws"): _AWS_CVM,
    (KeyProvider.AWS_KMS, ""): _AWS_CVM,

    (KeyProvider.AZURE_KEY_VAULT, "snp-azure"): _AZURE_TYPE_ONLY,
    (KeyProvider.AZURE_KEY_VAULT, "tdx-azure"): _AZURE_TYPE_ONLY,
    (KeyProvider.AZURE_KEY_VAULT, "gpu-cc-azure"): _AZURE_TYPE_ONLY,
    (KeyProvider.AZURE_KEY_VAULT, "sgx-azure"): _AZURE_SGX,
    (KeyProvider.AZURE_KEY_VAULT, ""): _AZURE_TYPE_ONLY,

    (KeyProvider.GCP_KMS, "snp-gcp"): _GCP_UNCONDITIONED,
    (KeyProvider.GCP_KMS, "tdx-gcp"): _GCP_UNCONDITIONED,
    (KeyProvider.GCP_KMS, "gpu-cc-gcp"): _GCP_UNCONDITIONED,
    (KeyProvider.GCP_KMS, ""): _GCP_UNCONDITIONED,

    (KeyProvider.EXTERNAL_HSM, ""): _EXTERNAL_HSM,
    (KeyProvider.LOCAL_FILE, ""): _LOCAL_FILE,
}


def gating_for(
    provider: KeyProvider,
    tee_platform: str = "",
    **facts: bool,
) -> ProviderGating:
    """Return the gating row for *provider* on *tee_platform*.

    *facts* are the conditional upgrades documented at module level
    (:data:`FACT_PCRS_PINNED`, :data:`FACT_WORKLOAD_CLAIMS_BOUND`,
    :data:`FACT_ATTRIBUTE_CONDITION_BOUND`).  Unknown fact names are ignored so
    a caller can pass whatever it happens to know.

    >>> gating_for(KeyProvider.AWS_KMS, "nitro-aws").gating
    <KeyGating.IAM_SCOPED: 'iam-scoped'>
    >>> gating_for(KeyProvider.AWS_KMS, "nitro-aws", pcrs_pinned=True).gating
    <KeyGating.KMS_ENFORCED: 'kms-enforced'>
    """
    platform = (tee_platform or "").strip().lower()
    row = _TABLE.get((provider, platform)) or _TABLE.get((provider, "")) or _UNKNOWN
    if row.upgrade_when and facts.get(row.upgrade_when) and row.upgraded is not None:
        return row.upgraded
    return row


def _truthy(value: object) -> bool:
    """Recognised-truthy only.  Anything else -- unset, or a spelling we do not
    know -- is False, which is the weaker verdict this table wants."""
    return interpret(str(value or "")) is True


def gating_from_extra(
    provider: KeyProvider,
    extra: Optional[Dict[str, str]],
    **override_facts: bool,
) -> ProviderGating:
    """Resolve gating from an :class:`~tee_crafter.core.keys.spec.AttestedKeyRef`'s ``extra``.

    Adapters run inside the TEE and cannot read the key's own policy, so the
    deploy side records what it configured as ``extra`` entries (which reach the
    runtime as ``TEE_CRAFTER_BYOK_X_*`` environment variables):

    * ``tee_platform``               -- e.g. ``snp-gcp``
    * ``pcrs_pinned``                -- Nitro: PCR equality conditions present
    * ``workload_claims_bound``      -- Azure: SKR policy pins launchmeasurement
    * ``attribute_condition_bound``  -- GCP: IAM attribute condition present

    Absent entries are read as False, i.e. the **weaker** verdict.  That is the
    intended direction: an unrecorded fact must never upgrade the claim.
    """
    extra = extra or {}
    facts = {
        FACT_PCRS_PINNED: _truthy(extra.get(FACT_PCRS_PINNED)),
        FACT_NITROTPM_PCRS_PINNED: _truthy(
            extra.get(FACT_NITROTPM_PCRS_PINNED)),
        FACT_WORKLOAD_CLAIMS_BOUND: _truthy(extra.get(FACT_WORKLOAD_CLAIMS_BOUND)),
        FACT_ATTRIBUTE_CONDITION_BOUND: _truthy(
            extra.get(FACT_ATTRIBUTE_CONDITION_BOUND)),
    }
    facts.update(override_facts)
    return gating_for(provider, extra.get("tee_platform", ""), **facts)


def gating_table() -> Dict[str, Dict[str, str]]:
    """Flatten the table to ``{"<provider>/<platform>": {...}}`` for evidence.

    Conditional rows are emitted twice, with the upgraded variant suffixed by
    the fact that unlocks it, so a reader sees both the shipped default and
    what it takes to do better.
    """
    out: Dict[str, Dict[str, str]] = {}
    for (provider, platform), row in _TABLE.items():
        key = f"{provider.value}/{platform or 'any'}"
        out[key] = row.as_dict()
        if row.upgrade_when and row.upgraded is not None:
            out[f"{key}+{row.upgrade_when}"] = row.upgraded.as_dict()
    return out


__all__ = [
    "ProviderGating",
    "gating_for",
    "gating_from_extra",
    "gating_table",
    "FACT_PCRS_PINNED",
    "FACT_NITROTPM_PCRS_PINNED",
    "NITROTPM_UPGRADE_NOTE",
    "FACT_WORKLOAD_CLAIMS_BOUND",
    "FACT_ATTRIBUTE_CONDITION_BOUND",
]
