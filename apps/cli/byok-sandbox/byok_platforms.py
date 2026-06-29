"""Shared TEE platform constants for BYOK sandbox helpers.

Maps ``tee-crafter deploy-container --tee-platform …`` names to key-policy
and JSON skeleton hints so operators generate the right KMS / KV material."""
from __future__ import annotations

import copy
import warnings
from typing import Any, Dict, List, Optional

# Mirrors tee-crafter deploy-container AWS/GCP/Azure BYOK targets.
AWS_TEE_PLATFORMS: tuple[str, ...] = ("nitro-aws", "snp-aws", "gpu-cc-aws")
GCP_TEE_PLATFORMS: tuple[str, ...] = ("tdx-gcp", "snp-gcp", "gpu-cc-gcp")
AZURE_TEE_PLATFORMS: tuple[str, ...] = ("sgx-azure", "tdx-azure", "snp-azure", "gpu-cc-azure")

#: Platforms whose KMS key policy has *no* attestation condition available, so
#: the caller's IAM principal is the whole access-control decision.
AWS_IAM_ONLY_TEE_PLATFORMS: tuple[str, ...] = ("snp-aws", "gpu-cc-aws")

#: CLI spelling of the wildcard opt-in, quoted in the refusal message so the
#: operator is told exactly how to override.
WILDCARD_ROLE_OPT_IN_FLAG = "--allow-wildcard-role"

# Terraform IAM role name_prefix patterns (see main.template.tf files).
_AWS_ROLE_PATTERN: Dict[str, str] = {
    "nitro-aws": "tee-crafter-role-*",
    "snp-aws": "tee-crafter-snp-role-*",
    "gpu-cc-aws": "tee-crafter-gpu-cc-role-*",
}

# Terraform resource address of the EC2 instance role, for `terraform state show`.
# Verified against src/tee_crafter/templates/{nitro/main,snp/aws/main,
# gpu_cc/aws/main}.template.tf -- each role is declared with `count`, hence [0].
_AWS_ROLE_TF_ADDRESS: Dict[str, str] = {
    "nitro-aws": "aws_iam_role.enclave_role[0]",
    "snp-aws": "aws_iam_role.snp_role[0]",
    "gpu-cc-aws": "aws_iam_role.gpu_cc_role[0]",
}


class AwsKeyPolicyError(ValueError):
    """Base class for refusals raised while building an AWS KMS key policy."""


class InstanceRoleArnRequiredError(AwsKeyPolicyError):
    """No exact instance-role ARN was supplied for an IAM-only AWS platform.

    Raised instead of quietly emitting a wildcard principal condition.  See
    :func:`validate_aws_instance_role_arns` for the message the operator gets.
    """


class InvalidInstanceRoleArnError(AwsKeyPolicyError):
    """A supplied instance-role ARN is not an exact ARN (empty, or contains ``*``)."""


class WildcardRolePolicyWarning(UserWarning):
    """Emitted when a caller explicitly opts in to the wildcard role pattern."""


def aws_instance_role_arn_pattern(account_id: str, tee_platform: str) -> str:
    """ArnLike **wildcard** pattern for the instance role Terraform creates.

    This is a name *pattern*, not an identity.  On ``snp-aws`` / ``gpu-cc-aws``
    it is the entire access-control decision (AWS KMS has no SEV-SNP / NitroTPM
    condition key), so using it in a key policy grants ``kms:Decrypt`` to anyone
    who can create a role whose name matches.  It is never used by default:
    :func:`build_aws_kms_key_policy` only reaches it when the caller passes
    ``allow_wildcard_role=True``.
    """
    if tee_platform not in _AWS_ROLE_PATTERN:
        raise ValueError(f"unknown AWS tee platform: {tee_platform!r}")
    suffix = _AWS_ROLE_PATTERN[tee_platform]
    return f"arn:aws:iam::{account_id}:role/{suffix}"


def _how_to_find_the_role_arn(tee_platform: str) -> str:
    """Concrete commands that yield the exact instance-role ARN."""
    address = _AWS_ROLE_TF_ADDRESS.get(tee_platform, "aws_iam_role.<role>[0]")
    prefix = _AWS_ROLE_PATTERN.get(tee_platform, "tee-crafter-role-*").rstrip("*")
    return (
        "Find the exact ARN one of these ways: "
        f"(1) in the deploy directory, `terraform state show '{address}'` and read "
        "its `arn` (there is no `terraform output` for it); "
        f"(2) `aws iam list-roles --query \"Roles[?starts_with(RoleName, '{prefix}')]"
        ".Arn\" --output text`; "
        "(3) if you brought your own role, it is the value you passed as "
        "`existing_enclave_role_arn` / TF_VAR_existing_enclave_role_arn."
    )


def _wildcard_exposure_warning(account_id: str, tee_platform: str) -> str:
    return (
        f"AWS KMS key policy for {tee_platform} is being built with the WILDCARD "
        f"principal condition ArnLike aws:PrincipalArn = "
        f"{aws_instance_role_arn_pattern(account_id, tee_platform)}.  AWS KMS has no "
        "condition key for an AMD SEV-SNP launch measurement, so this pattern is the "
        "ONLY gate on kms:Decrypt for the customer's DEK: every principal in account "
        f"{account_id} whose role name matches it can decrypt, and anyone holding "
        "iam:CreateRole in that account can mint such a role and read the data key.  "
        "Throwaway sandbox accounts only -- pass exact role ARNs instead."
    )


def validate_aws_instance_role_arns(
    tee_platform: str,
    role_arns: Optional[List[str]],
    *,
    allow_wildcard_role: bool = False,
) -> List[str]:
    """Normalise *role_arns* for *tee_platform*, refusing an implicit wildcard.

    Returns the cleaned list of exact ARNs, which is empty only when
    *allow_wildcard_role* is True (the caller has opted in to the wildcard) or
    when *tee_platform* does not gate on the principal at all (``nitro-aws``,
    where the gate is the Nitro ``Recipient`` attestation).

    Raises :class:`InvalidInstanceRoleArnError` if an entry is not an exact ARN,
    and :class:`InstanceRoleArnRequiredError` if an IAM-only platform was given
    neither exact ARNs nor the explicit opt-in.  Emits no warning -- callers that
    actually build the wildcard policy do that (see
    :func:`build_aws_kms_key_policy`), so a pre-flight check does not double-warn.
    """
    exact = [a.strip() for a in (role_arns or []) if a and a.strip()]
    bad = [a for a in exact if not a.startswith("arn:") or "*" in a]
    if bad:
        raise InvalidInstanceRoleArnError(
            f"instance-role ARNs must be exact ARNs with no wildcards; got {bad}")
    if tee_platform not in AWS_IAM_ONLY_TEE_PLATFORMS or exact:
        return exact
    if allow_wildcard_role:
        return []
    raise InstanceRoleArnRequiredError(
        f"{tee_platform}: AWS KMS exposes no condition key for an AMD SEV-SNP (or "
        "NitroTPM) launch measurement, so the caller's IAM principal is the entire "
        "access control on this key.  Refusing to emit the "
        f"{aws_instance_role_arn_pattern('<account-id>', tee_platform)} wildcard by "
        "default: it would grant kms:Decrypt on the customer's DEK to anyone who can "
        "create a role matching that name in the account.  Supply the exact "
        "instance-role ARN(s) instead (--instance-role-arn <arn>, repeatable; "
        f"role_arns=[...] in Python).  {_how_to_find_the_role_arn(tee_platform)}  "
        f"If you really want the wildcard, opt in explicitly with "
        f"{WILDCARD_ROLE_OPT_IN_FLAG} (allow_wildcard_role=True)."
    )


def aws_unwrap_algorithm(tee_platform: str) -> str:
    """Return ``unwrap`` field for byok-config.json."""
    if tee_platform == "nitro-aws":
        return "aws_nitro_recipient"
    if tee_platform in ("snp-aws", "gpu-cc-aws"):
        return "direct_bytes"
    raise ValueError(f"unknown AWS tee platform: {tee_platform!r}")


def default_aws_byok_out_path(tee_platform: str) -> str:
    """Default skeleton path: ``configs/byok-<tee-platform>.json``."""
    return f"byok-sandbox/configs/byok-{tee_platform}.json"


def default_gcp_byok_out_path(tee_platform: str) -> str:
    """Default skeleton path.

    When *tee_platform* is ``snp-gcp`` the committed quick-start file is
    ``byok-gcp.json`` (one GCP config for the repo).  Other GCP platforms
    use ``byok-<tee-platform>.json``.
    """
    if tee_platform == "snp-gcp":
        return "byok-sandbox/configs/byok-gcp.json"
    return f"byok-sandbox/configs/byok-{tee_platform}.json"


def default_azure_byok_out_path(tee_platform: str) -> str:
    return f"byok-sandbox/configs/byok-azure-{tee_platform}.json"


def build_aws_kms_key_policy(
    account_id: str,
    tee_platform: str,
    *,
    pcr0: Optional[str] = None,
    pcr1: Optional[str] = None,
    pcr2: Optional[str] = None,
    role_arns: Optional[List[str]] = None,
    allow_wildcard_role: bool = False,
    pin_at_deploy: bool = False,
) -> Dict[str, Any]:
    """Full KMS key policy document for the selected AWS TEE platform.

    ``role_arns`` applies to ``snp-aws`` / ``gpu-cc-aws`` only: supply the exact
    instance-role ARN(s) Terraform created and the policy pins them with
    ``ArnEquals``.  On those platforms it is **required** -- omitting it raises
    :class:`InstanceRoleArnRequiredError` rather than silently emitting the
    ``role/tee-crafter-<plat>-role-*`` wildcard, because with no attestation
    condition available the principal is the whole access control.

    ``allow_wildcard_role=True`` restores the wildcard for throwaway sandbox
    accounts.  It emits a :class:`WildcardRolePolicyWarning` describing what the
    key becomes reachable by; it is never the default on any code path.

    ``pin_at_deploy=True`` emits **no decrypt statement at all**, and is the
    recommended option.  The role's name carries a per-deploy suffix, so its
    exact ARN does not exist when the key does; the deploy reads it from the
    ``instance_role_arn`` Terraform output and adds the grant itself
    (``cli/deployment/common/byok_key_policy.py``).  A key that grants nothing
    until pinned has no window in which it is broadly readable, which neither
    of the other two options can say.
    """
    if not pin_at_deploy:
        role_arns = validate_aws_instance_role_arns(
            tee_platform, role_arns, allow_wildcard_role=allow_wildcard_role)
    root_arn = f"arn:aws:iam::{account_id}:root"
    admin_stmt: Dict[str, Any] = {
        "Sid": "AllowKeyManagementByAccount",
        "Effect": "Allow",
        "Principal": {"AWS": root_arn},
        "Action": [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion",
            "kms:Encrypt",
            "kms:GenerateDataKey",
        ],
        "Resource": "*",
    }

    if pin_at_deploy:
        if role_arns or allow_wildcard_role:
            raise ValueError(
                "pin_at_deploy is mutually exclusive with --instance-role-arn "
                "and --allow-wildcard-role: it exists to avoid granting decrypt "
                "to anything until the deploy names the exact role.")
        return {
            "Version": "2012-10-17",
            "Id": "tee-crafter-byok-test",
            "Statement": [admin_stmt],
        }

    if tee_platform == "nitro-aws":
        enclave_condition: Dict[str, Dict[str, str]] = {
            "Null": {"kms:RecipientAttestation:ImageSha384": "false"},
        }
        if pcr0 or pcr1 or pcr2:
            eq: Dict[str, str] = {}
            if pcr0:
                eq["kms:RecipientAttestation:PCR0"] = pcr0
            if pcr1:
                eq["kms:RecipientAttestation:PCR1"] = pcr1
            if pcr2:
                eq["kms:RecipientAttestation:PCR2"] = pcr2
            enclave_condition["StringEqualsIgnoreCase"] = eq
        decrypt_stmt = {
            "Sid": "AllowNitroDecryptViaRecipient",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["kms:Decrypt"],
            "Resource": "*",
            "Condition": {
                **enclave_condition,
                "StringEquals": {"kms:CallerAccount": account_id},
            },
        }
        return {
            "Version": "2012-10-17",
            "Id": "tee-crafter-byok-test",
            "Statement": [admin_stmt, decrypt_stmt],
        }

    if tee_platform in AWS_IAM_ONLY_TEE_PLATFORMS:
        # There is no AWS KMS condition key for an AMD SEV-SNP (or NitroTPM)
        # measurement, so this statement is identity-gated and nothing more.
        # See core/keys/gating.py -- it is reported as `iam-scoped`, not
        # attestation-gated.
        #
        # Given that, the principal condition is the *entire* control, so exact
        # ARNs pinned with ArnEquals are the only default: no wildcard appears in
        # the policy at all.  `validate_aws_instance_role_arns` above has already
        # refused the empty case unless the caller opted in explicitly, so
        # reaching the `else` branch means `allow_wildcard_role=True`.
        if role_arns:
            condition_arn: Dict[str, Any] = {
                "ArnEquals": {"aws:PrincipalArn": list(role_arns)},
            }
        else:
            warnings.warn(
                _wildcard_exposure_warning(account_id, tee_platform),
                WildcardRolePolicyWarning,
                stacklevel=2,
            )
            condition_arn = {
                "ArnLike": {
                    "aws:PrincipalArn": aws_instance_role_arn_pattern(
                        account_id, tee_platform),
                },
            }
        decrypt_stmt = {
            "Sid": "AllowTeeInstanceRoleDecrypt",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["kms:Decrypt", "kms:DescribeKey"],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"kms:CallerAccount": account_id},
                **condition_arn,
            },
        }
        return {
            "Version": "2012-10-17",
            "Id": "tee-crafter-byok-test",
            "Statement": [admin_stmt, decrypt_stmt],
        }

    raise ValueError(f"unknown AWS tee platform: {tee_platform!r}")


_DEFAULT_AZURE_RELEASE_POLICY: Dict[str, Any] = {
    "version": "1.0.0",
    "anyOf": [
        {
            "authority": "https://sharedeus.eus.attest.azure.net",
            "allOf": [{"claim": "x-ms-attestation-type", "equals": "sevsnpvm"}],
        },
        {
            "authority": "https://sharedeus2.eus2.attest.azure.net",
            "allOf": [{"claim": "x-ms-attestation-type", "equals": "sevsnpvm"}],
        },
        {
            "authority": "https://sharedeus.eus.attest.azure.net",
            "allOf": [{"claim": "x-ms-attestation-type", "equals": "tdxvm"}],
        },
        {
            "authority": "https://sharedeus2.eus2.attest.azure.net",
            "allOf": [{"claim": "x-ms-attestation-type", "equals": "tdxvm"}],
        },
    ],
}


#: Claims that actually bind a release to *one* workload image.
#:   ``x-ms-sevsnpvm-launchmeasurement`` — SHA-384 of the guest launch digest.
#:   ``x-ms-sevsnpvm-hostdata``          — the 32-byte HOST_DATA the CVM was
#:                                         launched with (image/config binding).
AZURE_LAUNCH_MEASUREMENT_CLAIM = "x-ms-sevsnpvm-launchmeasurement"
AZURE_HOST_DATA_CLAIM = "x-ms-sevsnpvm-hostdata"


def azure_release_policy_for_tee_platform(
    tee_platform: str,
    *,
    launch_measurement: Optional[str] = None,
    host_data: Optional[str] = None,
    authorities: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Return a release-policy document tuned for ``--tee-platform``.

    Without ``launch_measurement`` the generated policy pins only
    ``x-ms-attestation-type`` against the **shared, public** MAA authorities
    (``sharedeus``/``sharedeus2``).  Every SEV-SNP or TDX CVM on Azure — in any
    tenant, belonging to anyone — satisfies that.  It proves "a confidential VM
    asked", not "*your* confidential VM asked".

    Passing ``launch_measurement`` (and ideally ``host_data``) appends equality
    claims that name the specific workload, which is what makes Secure Key
    Release genuinely ``kms-enforced`` rather than ``iam-scoped``
    (:mod:`tee_crafter.core.keys.gating`).  ``authorities`` replaces the shared
    MAA endpoints with a customer-owned MAA instance; the shared ones are
    multi-tenant and cannot distinguish your tenant from anyone else's.

    The attestation-type claim stays at ``allOf[0]`` so existing readers that
    index it keep working; added claims are appended.
    """
    doc = copy.deepcopy(_DEFAULT_AZURE_RELEASE_POLICY)
    any_of: List[Dict[str, Any]] = doc["anyOf"]

    def _keep(predicate) -> None:
        nonlocal any_of
        any_of = [e for e in any_of if predicate(e)]
        doc["anyOf"] = any_of

    if tee_platform in ("snp-azure", "gpu-cc-azure"):
        # Confidential GPU VMs on Azure ride the SEV-SNP CVM attestation path.
        _keep(lambda e: e["allOf"][0]["equals"] == "sevsnpvm")
    elif tee_platform == "tdx-azure":
        _keep(lambda e: e["allOf"][0]["equals"] == "tdxvm")
    elif tee_platform == "sgx-azure":
        # Premium KV keys still use MAA-shaped policies; Gramine paths vary.
        # Keep the permissive combined SNP+TDX policy but tag metadata so
        # operators know this is not SNP/TDX-exclusive.  Note the SNP/TDX claim
        # types are ones an SGX enclave does not present at all, so treat this
        # combination as unwired rather than gated.
        pass
    else:
        raise ValueError(f"unknown Azure tee platform: {tee_platform!r}")

    extra_claims: List[Dict[str, str]] = []
    if launch_measurement:
        extra_claims.append({
            "claim": AZURE_LAUNCH_MEASUREMENT_CLAIM,
            "equals": launch_measurement.lower(),
        })
    if host_data:
        extra_claims.append({
            "claim": AZURE_HOST_DATA_CLAIM,
            "equals": host_data.lower(),
        })
    if extra_claims:
        for entry in doc["anyOf"]:
            entry["allOf"] = list(entry["allOf"]) + copy.deepcopy(extra_claims)

    if authorities:
        base = copy.deepcopy(doc["anyOf"])
        doc["anyOf"] = [
            {**copy.deepcopy(entry), "authority": authority}
            for authority in authorities
            for entry in base
        ]

    return doc


def azure_release_policy_is_workload_bound(policy: Dict[str, Any]) -> bool:
    """True when *every* branch of *policy* pins the launch measurement.

    Any single unbound branch makes the whole ``anyOf`` satisfiable without it,
    so this is an ``all``, not an ``any``.  Callers record the result as the
    ``workload_claims_bound`` BYOK extra, which is what promotes ``azure-kv``
    to ``kms-enforced`` in the gating table.
    """
    branches = policy.get("anyOf") or []
    if not branches:
        return False
    return all(
        any(c.get("claim") == AZURE_LAUNCH_MEASUREMENT_CLAIM
            for c in (branch.get("allOf") or []))
        for branch in branches
    )


def azure_combined_release_policy() -> Dict[str, Any]:
    """Legacy default: allow either SNP or TDX MAA authorities (two regions each)."""
    return copy.deepcopy(_DEFAULT_AZURE_RELEASE_POLICY)
