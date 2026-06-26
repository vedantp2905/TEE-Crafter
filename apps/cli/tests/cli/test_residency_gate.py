"""Tests for the fail-closed deploy-time residency gate (RES-001).

Residency used to be advisory (a separate ``residency-check`` command); the
gate wires the same validation engine into ``deploy`` so a forbidden region is
refused before any cloud resource is created.
"""
from __future__ import annotations

import json

from unittest.mock import MagicMock


from tee_crafter.cli.commands.deploy.deploy_helpers import (
    _RESIDENCY_POLICY_ENV,
    enforce_residency_gate,
)


class _FakeAudit:
    def __init__(self):
        self.checks = []

    def record_check(self, *args, **kwargs):
        self.checks.append((args, kwargs))


def _res001(audit):
    for args, kwargs in audit.checks:
        if "RES-001" in args:
            return kwargs
    return None


def _write_policy(tmp_path, doc):
    p = tmp_path / "residency.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def test_noop_when_policy_unset(monkeypatch):
    monkeypatch.delenv(_RESIDENCY_POLICY_ENV, raising=False)
    audit = _FakeAudit()
    assert enforce_residency_gate(MagicMock(), audit, "snp-aws") is True
    assert _res001(audit) is None  # nothing recorded when not enforced


def test_blocks_region_outside_policy(tmp_path, monkeypatch):
    monkeypatch.setenv(_RESIDENCY_POLICY_ENV,
                       _write_policy(tmp_path, {"allowed_countries": ["US"]}))
    monkeypatch.setenv("TF_VAR_aws_region", "eu-west-1")
    audit = _FakeAudit()
    assert enforce_residency_gate(MagicMock(), audit, "snp-aws") is False
    k = _res001(audit)
    assert k is not None and k["observed"] is False


def test_allows_region_within_policy(tmp_path, monkeypatch):
    monkeypatch.setenv(_RESIDENCY_POLICY_ENV,
                       _write_policy(tmp_path, {"allowed_countries": ["US"]}))
    monkeypatch.setenv("TF_VAR_aws_region", "us-east-2")
    audit = _FakeAudit()
    assert enforce_residency_gate(MagicMock(), audit, "snp-aws") is True
    k = _res001(audit)
    assert k is not None and k["observed"] is True


def test_fail_closed_when_region_missing(tmp_path, monkeypatch):
    monkeypatch.setenv(_RESIDENCY_POLICY_ENV,
                       _write_policy(tmp_path, {"allowed_countries": ["US"]}))
    for k in ("TF_VAR_aws_region", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(k, raising=False)
    audit = _FakeAudit()
    assert enforce_residency_gate(MagicMock(), audit, "snp-aws") is False


def test_fail_closed_on_unknown_region(tmp_path, monkeypatch):
    monkeypatch.setenv(_RESIDENCY_POLICY_ENV,
                       _write_policy(tmp_path, {"allowed_countries": ["US"]}))
    monkeypatch.setenv("TF_VAR_aws_region", "moon-base-1")
    audit = _FakeAudit()
    assert enforce_residency_gate(MagicMock(), audit, "snp-aws") is False
