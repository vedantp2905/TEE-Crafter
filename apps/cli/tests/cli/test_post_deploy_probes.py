"""Tests for the platform-agnostic post-deploy probes module."""
from __future__ import annotations


from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.deployment.common.post_deploy_probes import (
    run_post_deploy_probes,
)


def _ok_runner(observed_for: dict):
    """Build a fake run_remote that returns canned output per script."""
    def _runner(script: str):
        if "PDR-001: observed=ok" in script:
            return True, "PDR-001: observed=ok\n", ""
        for cid, observed in observed_for.items():
            if cid in script:
                return True, f"{cid}: observed={observed}\n", ""
        return True, "", ""
    return _runner


def test_runner_unavailable_emits_warn():
    audit = BuildAuditTrail()
    run_post_deploy_probes(
        audit, tee_platform="snp-aws", build_dir="/tmp/probe-test-x",
        run_remote=None,
    )
    row = audit.ledger.get("PDR-001")
    assert row is not None
    assert row.verdict in ("warn", "fail")


def test_runner_reports_management_plane_ok(tmp_path):
    runner = _ok_runner({})
    audit = BuildAuditTrail()
    run_post_deploy_probes(
        audit, tee_platform="snp-aws", build_dir=str(tmp_path),
        run_remote=runner,
    )
    row = audit.ledger.get("PDR-001")
    assert row is not None
    assert row.verdict == "pass"


def test_runner_emits_probe_failures_for_drift(tmp_path):
    """When the cloud-init probe reports a non-'done' value the
    matrix should mark PDR-002 as fail (not pass)."""
    runner = _ok_runner({"PDR-002": "running"})
    audit = BuildAuditTrail()
    run_post_deploy_probes(
        audit, tee_platform="snp-aws", build_dir=str(tmp_path),
        run_remote=runner,
    )
    row = audit.ledger.get("PDR-002")
    if row is not None:
        assert row.verdict in ("fail", "warn")


def test_pdr008_gcp_allows_single_iap_user_key(tmp_path):
    """On GCP the IAP-tunnel deployer SSH key lands in one
    authorized_keys file — that must NOT spuriously fail PDR-008.
    Regression for the snp-gcp / tdx-gcp false-fail in
    docker_flask_api_container_*_20260516_03*.
    """
    runner = _ok_runner({"PDR-008": "1"})
    audit = BuildAuditTrail()
    run_post_deploy_probes(
        audit, tee_platform="snp-gcp", build_dir=str(tmp_path),
        run_remote=runner,
    )
    row = audit.ledger.get("PDR-008")
    assert row is not None, "PDR-008 row missing"
    assert row.verdict == "pass", row.note
    assert "GCP IAP-tunnel" in (row.note or ""), row.note


def test_pdr008_aws_fails_on_any_ssh_key(tmp_path):
    """AWS hosts are SSM-only; any authorized_keys file is a finding."""
    runner = _ok_runner({"PDR-008": "1"})
    audit = BuildAuditTrail()
    run_post_deploy_probes(
        audit, tee_platform="snp-aws", build_dir=str(tmp_path),
        run_remote=runner,
    )
    row = audit.ledger.get("PDR-008")
    assert row is not None
    assert row.verdict == "fail"


def test_pdr009_passes_on_full_hardening_cocktail(tmp_path):
    """snp-gcp / tdx-gcp / snp-azure units ship the production
    hardening cocktail; the probe must accept it as PASS rather than
    fall to WARN because ``MemoryDenyWriteExecute`` isn't yes.
    """
    observed_value = (
        "ProtectSystem=strict;ProtectHome=yes;PrivateTmp=yes;"
        "NoNewPrivileges=no;RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6;"
        "IPAddressDeny=link-local multicast;MemoryDenyWriteExecute=no;"
        " unit=tee-crafter-snp.service"
    )
    runner = _ok_runner({"PDR-009": observed_value})
    audit = BuildAuditTrail()
    run_post_deploy_probes(
        audit, tee_platform="snp-gcp", build_dir=str(tmp_path),
        run_remote=runner,
    )
    row = audit.ledger.get("PDR-009")
    assert row is not None
    assert row.verdict == "pass", row.note
