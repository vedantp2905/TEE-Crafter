"""Tests for tee_crafter.cli.deployment.common.cloud_audit."""
from __future__ import annotations


from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.deployment.common import cloud_audit


def test_aws_cloudtrail_lookup_missing_boto3(monkeypatch):
    """When boto3 cannot be imported the helper returns the standard
    warn-tuple instead of raising — callers can then emit a warn row."""
    import builtins

    real_import = builtins.__import__

    def _raise(name, *a, **kw):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", _raise)
    import datetime
    ok, events, err = cloud_audit.aws_cloudtrail_lookup(
        {"ResourceName": "i-1234"},
        since=datetime.datetime.utcnow(),
    )
    assert ok is False
    assert events == []
    assert "boto3" in err


def test_record_cloud_audit_verdicts_no_op_without_audit():
    """A None audit must not crash the helper (defensive guard)."""
    cloud_audit.record_cloud_audit_verdicts(
        None,  # type: ignore[arg-type]
        tee_platform="snp-aws",
    )


def test_record_cloud_audit_verdicts_aws_no_instance_id(tmp_path):
    """No instance_id → no CT-001; BYOK off → CT-002 is not_applicable."""
    audit = BuildAuditTrail()
    cloud_audit.record_cloud_audit_verdicts(
        audit, tee_platform="snp-aws",
        build_dir=str(tmp_path),
        terraform_outputs={"kms_key_arn": "arn:aws:kms:us-east-1:1:key/deployment-only"},
    )
    assert audit.ledger.get("CT-001") is None
    row = audit.ledger.get("CT-002")
    assert row is not None
    assert row.verdict == "not_applicable"


def test_record_cloud_audit_verdicts_ignores_deployment_kms_when_byok_off(
    tmp_path, monkeypatch,
):
    """Terraform ``kms_key_arn`` must not drive CT-002 when BYOK is disabled.

    CT-001 (RunInstances) is still expected to fire when an instance id
    is supplied — it is independent of BYOK.  What we *do* assert is
    that the lookup is never invoked with the deployment-only kms key
    arn (which would cause a false-negative CT-002 FAIL).
    """
    seen_resource_names: list = []
    def _lookup(filters=None, **kw):
        if filters and "ResourceName" in filters:
            seen_resource_names.append(filters["ResourceName"])
        return (True, [], "")
    monkeypatch.setattr(cloud_audit, "aws_cloudtrail_lookup", _lookup)
    audit = BuildAuditTrail()
    cloud_audit.record_cloud_audit_verdicts(
        audit,
        tee_platform="nitro-aws",
        aws_instance_id="i-abc",
        build_dir=str(tmp_path),
        terraform_outputs={
            "kms_key_arn": "arn:aws:kms:us-east-1:1:key/terraform-deployment-key",
        },
    )
    assert audit.ledger.get("CT-002").verdict == "not_applicable"
    assert audit.ledger.get("CT-003").verdict == "not_applicable"
    assert seen_resource_names == ["i-abc"], (
        "CT-001 should look up the instance, but no BYOK-key lookup must "
        "leak the deployment KMS arn"
    )


def test_record_cloud_audit_verdicts_nitro_ct003_na_without_byok(tmp_path):
    audit = BuildAuditTrail()
    cloud_audit.record_aws_cloudtrail_verdicts(
        audit, tee_platform="nitro-aws", instance_id="i-1", byok_key_arn="",
    )
    assert audit.ledger.get("CT-003").verdict == "not_applicable"


def test_resolve_customer_byok_key_reads_staged_env(tmp_path):
    byok_dir = tmp_path / "byok"
    byok_dir.mkdir()
    (byok_dir / "byok.env.public").write_text(
        "TEE_CRAFTER_BYOK_ENABLED=1\n"
        "TEE_CRAFTER_BYOK=aws-kms\n"
        "TEE_CRAFTER_BYOK_KEY_ID=arn:aws:kms:us-east-1:999:key/customer-byok\n",
        encoding="utf-8",
    )
    on, aws, az, gcp = cloud_audit.resolve_customer_byok_key(
        "snp-aws", str(tmp_path),
    )
    assert on is True
    assert aws == "arn:aws:kms:us-east-1:999:key/customer-byok"
    assert az == ""
    assert gcp == ""


def test_ct002_empty_cloudtrail_page_is_warn_not_fail(monkeypatch):
    """Zero events in the lookback window is inconclusive (lag), not proof
    BYOK was skipped — must not hard-fail CT-002."""
    monkeypatch.setattr(
        cloud_audit, "aws_cloudtrail_lookup",
        lambda *a, **kw: (True, [], ""),
    )
    audit = BuildAuditTrail()
    cloud_audit.record_aws_cloudtrail_verdicts(
        audit,
        tee_platform="snp-aws",
        instance_id="i-abc",
        byok_key_arn="arn:aws:kms:us-east-1:1:key/customer",
        byok_enabled=True,
    )
    row = audit.ledger.get("CT-002")
    assert row is not None
    assert row.verdict == "warn"
    assert "lookback" in (row.note or "").lower()


def test_record_aws_cloudtrail_verdicts_emits_warn_on_permission_denied(
    monkeypatch,
):
    """A boto3 lookup raising AccessDenied must become a warn row, never
    a hard fail."""

    def _broken_lookup(*a, **kw):
        return False, [], "AccessDeniedException: caller lacks LookupEvents"

    monkeypatch.setattr(cloud_audit, "aws_cloudtrail_lookup", _broken_lookup)

    audit = BuildAuditTrail()
    cloud_audit.record_aws_cloudtrail_verdicts(
        audit,
        tee_platform="snp-aws",
        instance_id="i-0123abcd",
        byok_key_arn="arn:aws:kms:us-east-1:1:key/abc",
    )
    row = audit.ledger.get("CT-001")
    assert row is not None
    assert row.verdict == "warn"


def test_resolve_aws_region_rejects_shell_parameter_expansion(monkeypatch):
    """A literal ``${TF_VAR_aws_region:-us-east-2}`` (from a dotenv loader
    that does not perform shell expansion) must not be propagated to
    boto3 — regression for the ``InvalidRegionError`` warn in
    docker_flask_api_container_*_20260516_030754_17c6e1af.
    """
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("TF_VAR_aws_region", raising=False)
    assert cloud_audit._sanitize_aws_region("${TF_VAR_aws_region:-us-east-2}") is None
    assert cloud_audit._sanitize_aws_region("us-east-2") == "us-east-2"
    assert cloud_audit._sanitize_aws_region("eu-west-3") == "eu-west-3"
    assert cloud_audit._sanitize_aws_region("") is None
    assert cloud_audit._sanitize_aws_region(None) is None
    assert cloud_audit._sanitize_aws_region("garbage") is None


def test_resolve_aws_region_prefers_explicit_then_env(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "${BROKEN}")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-2")
    monkeypatch.delenv("TF_VAR_aws_region", raising=False)
    assert cloud_audit._resolve_aws_region(None) == "us-east-2"
    assert cloud_audit._resolve_aws_region("eu-north-1") == "eu-north-1"
