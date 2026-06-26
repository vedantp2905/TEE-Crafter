"""Tests for tee_crafter.cli.commands.deploy.flag_audit."""
from __future__ import annotations


from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.commands.deploy.flag_audit import audit_dev_hatch_flags


def test_default_env_emits_only_pass_rows(monkeypatch):
    """With every dev hatch left at its production-correct default the
    matrix should not contain a single FAIL row."""
    for env in (
        "TEE_CRAFTER_PROXY_STRICT_IMDS",
        "TEE_CRAFTER_PROXY_NO_CREDS",
        "TEE_CRAFTER_NRAS_STRICT",
        "TEE_CRAFTER_STRICT_TSM",
        "TEE_CRAFTER_SIEM_FAIL_OPEN",
        "TEE_CRAFTER_ALLOW_VULNERABLE",
        "TEE_CRAFTER_ACCEPT_PARTIAL_CC",
        "TEE_CRAFTER_STRICT_SNP_AK_BINDING",
        "TEE_CRAFTER_TDX_ALLOW_MISSING_QE_IDENTITY",
        "TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL",
        "TEE_CRAFTER_SKIP_POST_DESTROY_SHRED",
        "TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE",
        "TF_VAR_allow_nras_broad_internet",
        "TF_VAR_allow_setup_egress",
        "TF_VAR_enable_secure_boot",
        "TF_VAR_byok_aws_kms_arn",
        "TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI",
    ):
        monkeypatch.delenv(env, raising=False)

    audit = BuildAuditTrail()
    audit_dev_hatch_flags(
        audit, tee_platform="snp-aws",
        byok_enabled=False,
    )
    failed = [
        r for r in audit.ledger.rows
        if r.verdict == "fail" and r.check_id.startswith("DH-")
    ]
    assert not failed, [r.check_id for r in failed]


def test_dev_hatch_flip_is_reported_as_fail(monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_SIEM_FAIL_OPEN", "1")
    audit = BuildAuditTrail()
    audit_dev_hatch_flags(
        audit, tee_platform="snp-aws",
        byok_enabled=False,
    )
    row = audit.ledger.get("DH-005")
    assert row is not None
    assert row.verdict in ("fail", "warn")


def test_byok_kms_arn_required_when_byok_enabled(monkeypatch):
    monkeypatch.delenv("TF_VAR_byok_aws_kms_arn", raising=False)
    audit = BuildAuditTrail()
    audit_dev_hatch_flags(
        audit, tee_platform="snp-aws",
        byok_enabled=True,
    )
    row = audit.ledger.get("DH-016")
    assert row is not None
    assert row.verdict == "fail"


def test_unbaked_ami_flag_is_caught(monkeypatch):
    audit = BuildAuditTrail()
    audit_dev_hatch_flags(
        audit, tee_platform="snp-aws",
        byok_enabled=False,
        allow_unbaked_ami=True,
    )
    row = audit.ledger.get("DH-017")
    assert row is not None
    assert row.verdict == "fail"
