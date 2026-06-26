"""Unit tests for BYOK sandbox platform helpers (no cloud credentials)."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BYOK_SANDBOX = ROOT / "byok-sandbox"
sys.path.insert(0, str(BYOK_SANDBOX))

from byok_platforms import (  # noqa: E402
    AWS_IAM_ONLY_TEE_PLATFORMS,
    InstanceRoleArnRequiredError,
    InvalidInstanceRoleArnError,
    WildcardRolePolicyWarning,
    aws_instance_role_arn_pattern,
    aws_unwrap_algorithm,
    azure_combined_release_policy,
    azure_release_policy_for_tee_platform,
    build_aws_kms_key_policy,
    default_aws_byok_out_path,
    default_gcp_byok_out_path,
    validate_aws_instance_role_arns,
)


def test_default_byok_out_paths() -> None:
    assert default_aws_byok_out_path("nitro-aws").endswith("byok-nitro-aws.json")
    assert default_gcp_byok_out_path("snp-gcp").endswith("byok-gcp.json")
    assert "snp-aws" in default_aws_byok_out_path("snp-aws")


def test_aws_unwrap_algorithm() -> None:
    assert aws_unwrap_algorithm("nitro-aws") == "aws_nitro_recipient"
    assert aws_unwrap_algorithm("snp-aws") == "direct_bytes"
    assert aws_unwrap_algorithm("gpu-cc-aws") == "direct_bytes"


def test_snp_role_arn_pattern() -> None:
    p = aws_instance_role_arn_pattern("123456789012", "snp-aws")
    assert p == "arn:aws:iam::123456789012:role/tee-crafter-snp-role-*"


def test_nitro_policy_requires_recipient() -> None:
    pol = build_aws_kms_key_policy("123456789012", "nitro-aws")
    decrypt = [
        s for s in pol["Statement"]
        if s.get("Sid") == "AllowNitroDecryptViaRecipient"
    ]
    assert len(decrypt) == 1
    assert (decrypt[0]["Condition"]["Null"]["kms:RecipientAttestation:ImageSha384"]
            == "false")


# NOTE: the former `test_snp_policy_uses_principal_arn` asserted that the
# *default* snp-aws policy carried `ArnLike ... tee-crafter-snp-role-*`.  That
# default was the finding: with no AWS KMS condition
# key for a SEV-SNP launch measurement, the principal condition is the whole
# access control, so a role-name wildcard hands the customer's DEK to anyone
# holding iam:CreateRole in the account.  The default now refuses; the wildcard
# is asserted below only on the explicit opt-in path.
def test_snp_policy_pins_exact_role_arns_with_arn_equals() -> None:
    arns = [
        "arn:aws:iam::123456789012:role/tee-crafter-snp-role-20260819abcd",
        "arn:aws:iam::123456789012:role/tee-crafter-snp-role-20260819efgh",
    ]
    pol = build_aws_kms_key_policy("123456789012", "snp-aws", role_arns=arns)
    decrypt = [
        s for s in pol["Statement"]
        if s.get("Sid") == "AllowTeeInstanceRoleDecrypt"
    ]
    assert len(decrypt) == 1
    cond = decrypt[0]["Condition"]
    # Expected condition document written out independently of the code
    # under test -- do not rebuild it by calling build_aws_kms_key_policy.
    assert cond == {
        "StringEquals": {"kms:CallerAccount": "123456789012"},
        "ArnEquals": {
            "aws:PrincipalArn": [
                "arn:aws:iam::123456789012:role/tee-crafter-snp-role-20260819abcd",
                "arn:aws:iam::123456789012:role/tee-crafter-snp-role-20260819efgh",
            ],
        },
    }
    assert "ArnLike" not in cond
    assert "kms:Decrypt" in decrypt[0]["Action"]
    assert "kms:DescribeKey" in decrypt[0]["Action"]
    # No wildcard anywhere in the principal condition of any statement.
    for stmt in pol["Statement"]:
        for operator, kv in (stmt.get("Condition") or {}).items():
            for key, value in kv.items():
                if key != "aws:PrincipalArn":
                    continue
                assert operator == "ArnEquals", operator
                assert all("*" not in v for v in value), value


@pytest.mark.parametrize("platform", AWS_IAM_ONLY_TEE_PLATFORMS)
def test_iam_only_platform_policy_refuses_without_exact_arns(platform: str) -> None:
    with pytest.raises(InstanceRoleArnRequiredError) as excinfo:
        build_aws_kms_key_policy("123456789012", platform)
    msg = str(excinfo.value)
    assert "--allow-wildcard-role" in msg
    assert "terraform state show" in msg
    assert platform in msg


@pytest.mark.parametrize("platform", AWS_IAM_ONLY_TEE_PLATFORMS)
def test_iam_only_platform_policy_refuses_empty_arn_list(platform: str) -> None:
    # An empty / whitespace-only list must not be treated as "operator opted in".
    with pytest.raises(InstanceRoleArnRequiredError):
        build_aws_kms_key_policy("123456789012", platform, role_arns=[])
    with pytest.raises(InstanceRoleArnRequiredError):
        build_aws_kms_key_policy("123456789012", platform, role_arns=["  "])


def test_wildcard_role_arn_rejected_as_exact_arn() -> None:
    with pytest.raises(InvalidInstanceRoleArnError):
        build_aws_kms_key_policy(
            "123456789012", "snp-aws",
            role_arns=["arn:aws:iam::123456789012:role/tee-crafter-snp-role-*"])
    with pytest.raises(InvalidInstanceRoleArnError):
        build_aws_kms_key_policy(
            "123456789012", "snp-aws", role_arns=["tee-crafter-snp-role-abc"])


def test_wildcard_role_requires_opt_in_and_warns() -> None:
    with pytest.warns(WildcardRolePolicyWarning) as record:
        pol = build_aws_kms_key_policy(
            "123456789012", "gpu-cc-aws", allow_wildcard_role=True)
    decrypt = [
        s for s in pol["Statement"]
        if s.get("Sid") == "AllowTeeInstanceRoleDecrypt"
    ][0]
    assert decrypt["Condition"]["ArnLike"] == {
        "aws:PrincipalArn":
            "arn:aws:iam::123456789012:role/tee-crafter-gpu-cc-role-*",
    }
    assert "ArnEquals" not in decrypt["Condition"]
    warning_text = " ".join(str(w.message) for w in record)
    assert "tee-crafter-gpu-cc-role-*" in warning_text
    assert "iam:CreateRole" in warning_text
    assert "kms:Decrypt" in warning_text


def test_validate_role_arns_strips_and_passes_through() -> None:
    assert validate_aws_instance_role_arns(
        "snp-aws", ["  arn:aws:iam::1:role/r  ", "", None],  # type: ignore[list-item]
    ) == ["arn:aws:iam::1:role/r"]
    # nitro-aws is gated on the Recipient attestation, not the principal, so no
    # ARN is required there and none is invented.
    assert validate_aws_instance_role_arns("nitro-aws", None) == []


def test_nitro_policy_never_carries_a_principal_arn_condition() -> None:
    pol = build_aws_kms_key_policy("123456789012", "nitro-aws", pcr0="aa")
    rendered = json.dumps(pol)
    assert "aws:PrincipalArn" not in rendered
    assert "tee-crafter-role-*" not in rendered


def test_nitro_policy_pcr_merge() -> None:
    pol = build_aws_kms_key_policy(
        "123456789012", "nitro-aws",
        pcr0="aa", pcr1="bb")
    decrypt = [
        s for s in pol["Statement"]
        if s.get("Sid") == "AllowNitroDecryptViaRecipient"
    ][0]
    eq = decrypt["Condition"]["StringEqualsIgnoreCase"]
    assert eq["kms:RecipientAttestation:PCR0"] == "aa"
    assert eq["kms:RecipientAttestation:PCR1"] == "bb"


def test_azure_release_policies_are_json_serializable() -> None:
    combined = azure_combined_release_policy()
    json.dumps(combined)
    snp = azure_release_policy_for_tee_platform("snp-azure")
    assert all(x["allOf"][0]["equals"] == "sevsnpvm" for x in snp["anyOf"])
    tdx = azure_release_policy_for_tee_platform("tdx-azure")
    assert all(x["allOf"][0]["equals"] == "tdxvm" for x in tdx["anyOf"])


def test_generate_byok_config_dispatcher_exists() -> None:
    gen = BYOK_SANDBOX / "generate_byok_config.py"
    assert gen.is_file()


# --- entry points: the wildcard must not be reachable by default ------------
# These run the real scripts.  Both refuse before importing boto3, so no AWS
# call is attempted and no credentials are needed.

def _run(script: Path, *argv: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        [sys.executable, str(script), *argv],
        capture_output=True, text=True, timeout=120,
    )


@pytest.mark.parametrize("platform", AWS_IAM_ONLY_TEE_PLATFORMS)
def test_create_kms_key_cli_refuses_wildcard_by_default(platform: str) -> None:
    proc = _run(BYOK_SANDBOX / "aws" / "create_kms_key.py",
                "--tee-platform", platform, "--region", "us-east-2")
    assert proc.returncode == 2, proc.stderr
    assert "--allow-wildcard-role" in proc.stderr
    assert "--instance-role-arn" in proc.stderr
    # It must not have got as far as talking to AWS or writing a skeleton.
    assert "AWS account:" not in proc.stderr
    assert proc.stdout == ""


def test_create_kms_key_cli_rejects_wildcard_in_instance_role_arn() -> None:
    proc = _run(BYOK_SANDBOX / "aws" / "create_kms_key.py",
                "--tee-platform", "snp-aws",
                "--instance-role-arn",
                "arn:aws:iam::123456789012:role/tee-crafter-snp-role-*")
    assert proc.returncode == 2, proc.stderr
    assert "exact ARNs" in proc.stderr


def test_generate_byok_config_dispatcher_inherits_the_refusal() -> None:
    # The dispatcher forwards argv verbatim, so it must not open a softer path.
    proc = _run(BYOK_SANDBOX / "generate_byok_config.py",
                "aws", "--tee-platform", "snp-aws")
    assert proc.returncode == 2, proc.stderr
    assert "--allow-wildcard-role" in proc.stderr


def test_create_kms_key_forwards_the_opt_in_to_every_policy_build() -> None:
    """Every build_aws_kms_key_policy call site passes allow_wildcard_role.

    Guards against a future call site that omits it and so can never produce
    the wildcard even when the operator asked for it (and, symmetrically,
    against one that hardcodes True).
    """
    tree = ast.parse((BYOK_SANDBOX / "aws" / "create_kms_key.py")
                     .read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "build_aws_kms_key_policy"
    ]
    assert calls, "no build_aws_kms_key_policy call sites found"
    for call in calls:
        kwargs = {kw.arg: kw.value for kw in call.keywords}
        assert "allow_wildcard_role" in kwargs
        assert isinstance(kwargs["allow_wildcard_role"], ast.Attribute)
        assert kwargs["allow_wildcard_role"].attr == "allow_wildcard_role"


def test_no_other_sandbox_script_builds_an_aws_key_policy() -> None:
    """create_kms_key.py is the only producer of the AWS KMS key policy.

    If a new caller appears it needs its own review of the wildcard default,
    so make that show up as a test failure rather than a silent regression.
    """
    producers = sorted(
        p.relative_to(BYOK_SANDBOX).as_posix()
        for p in BYOK_SANDBOX.rglob("*.py")
        if "build_aws_kms_key_policy" in p.read_text(encoding="utf-8")
    )
    assert producers == ["aws/create_kms_key.py", "byok_platforms.py"]


def test_wrap_dek_flags_present() -> None:
    aws_wrap = BYOK_SANDBOX / "aws" / "wrap_dek.py"
    src = aws_wrap.read_text(encoding="utf-8")
    assert "--tee-platform" in src
    assert "aws_unwrap_algorithm" in src
