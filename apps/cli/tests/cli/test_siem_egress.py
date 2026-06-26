"""Tests for the SIEM egress translation module.

These tests are pure-data: they exercise ``decide_egress`` /
``EgressDecision.to_tfvars_env`` and ``apply_siem_egress`` without
touching real cloud APIs or Terraform.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import List

import pytest

from tee_crafter.cli.commands.deploy.siem_egress_terraform import (
    apply_siem_egress,
    decide_egress,
    write_siem_egress_audit,
)


@dataclass
class _FakeSiemConfig:
    provider: str = "none"
    egress_mode: str = "auto"
    egress_allowlist_cidrs: List[str] = field(default_factory=list)
    egress_ports: List[int] = field(default_factory=lambda: [443])
    log_group: str = ""


class _FakeAudit:
    def __init__(self):
        self.records = []

    def record(self, *args, **kwargs):
        self.records.append((args, kwargs))


# ---------------------------------------------------------------------------
# decide_egress
# ---------------------------------------------------------------------------

class TestDecideEgress:
    def test_none_provider_is_noop(self):
        d = decide_egress(provider="none", egress_mode="auto", tee_platform="snp-aws")
        assert not d.needs_public_egress
        assert not d.provision_logs_endpoint
        assert d.cloud == "aws"

    def test_no_offered_provider_provisions_a_logs_endpoint(self):
        """The interface-endpoint branch is unreachable and must stay so.

        It existed for `cloudwatch`, which was removed from SIEM_PROVIDERS
        because the sidecar has no exporter for it. Provisioning a CloudWatch
        Logs interface endpoint (and a logs:PutLogEvents grant) for a stream
        nothing ever wrote to was the worst part of that defect, so assert no
        remaining provider turns it on.
        """
        from tee_crafter.cli.commands.deploy.siem_mode import SIEM_PROVIDERS
        for provider in SIEM_PROVIDERS:
            if provider == "none":
                continue
            for mode in ("auto", "private", "public"):
                try:
                    d = decide_egress(
                        provider=provider,
                        egress_mode=mode,
                        tee_platform="snp-aws",
                    )
                except ValueError:
                    # e.g. `private` with a public-internet-only intake.
                    continue
                assert d.provision_logs_endpoint is False, (
                    f"{provider}/{mode} still requests a logs endpoint")
                assert "TF_VAR_siem_provision_logs_endpoint" not in \
                    d.to_tfvars_env()

    def test_syslog_cef_private_stays_intra_vpc(self):
        d = decide_egress(
            provider="syslog-cef",
            egress_mode="private",
            tee_platform="snp-aws",
        )
        assert d.needs_public_egress is False
        assert d.provision_logs_endpoint is False
        assert "intra-VPC" in d.note

    def test_splunk_hec_auto_needs_nat(self):
        d = decide_egress(
            provider="splunk-hec",
            egress_mode="auto",
            tee_platform="snp-aws",
            egress_allowlist_cidrs=["52.51.0.0/16"],
        )
        assert d.needs_public_egress is True
        assert d.egress_cidrs == ["52.51.0.0/16"]
        env = d.to_tfvars_env()
        assert env["TF_VAR_allow_setup_egress"] == "true"
        assert json.loads(env["TF_VAR_siem_egress_cidrs"]) == ["52.51.0.0/16"]

    def test_datadog_auto_on_azure_needs_nat(self):
        d = decide_egress(
            provider="datadog", egress_mode="auto", tee_platform="tdx-azure",
        )
        assert d.cloud == "azure"
        assert d.needs_public_egress is True
        env = d.to_tfvars_env()
        assert env["TF_VAR_allow_setup_egress"] == "true"

    def test_syslog_cef_auto_no_nat(self):
        d = decide_egress(
            provider="syslog-cef", egress_mode="auto", tee_platform="snp-gcp",
        )
        assert d.needs_public_egress is False
        assert d.provision_logs_endpoint is False

    def test_private_mode_rejects_internet_only_provider(self):
        with pytest.raises(ValueError):
            decide_egress(
                provider="datadog",
                egress_mode="private",
                tee_platform="snp-aws",
            )

    def test_public_mode_always_provisions_nat(self):
        d = decide_egress(
            provider="cloudwatch",  # private-capable, but forced public
            egress_mode="public",
            tee_platform="snp-aws",
        )
        assert d.needs_public_egress is True

    def test_egress_none_is_noop(self):
        d = decide_egress(
            provider="splunk-hec",
            egress_mode="none",
            tee_platform="snp-aws",
        )
        assert d.needs_public_egress is False
        assert d.to_tfvars_env() == {}

    def test_custom_ports_serialised_only_when_non_default(self):
        d_default = decide_egress(
            provider="splunk-hec",
            egress_mode="public",
            tee_platform="snp-aws",
            egress_allowlist_cidrs=["1.2.3.4/32"],
        )
        assert "TF_VAR_siem_egress_ports" not in d_default.to_tfvars_env()

        d_custom = decide_egress(
            provider="splunk-hec",
            egress_mode="public",
            tee_platform="snp-aws",
            egress_allowlist_cidrs=["1.2.3.4/32"],
            egress_ports=[8088, 443],
        )
        env = d_custom.to_tfvars_env()
        assert json.loads(env["TF_VAR_siem_egress_ports"]) == [8088, 443]


# ---------------------------------------------------------------------------
# write_siem_egress_audit
# ---------------------------------------------------------------------------

class TestAuditFile:
    def test_writes_json_with_decision_payload(self):
        with tempfile.TemporaryDirectory() as build_dir:
            d = decide_egress(
                provider="syslog-cef",
                egress_mode="auto",
                tee_platform="snp-aws",
            )
            path = write_siem_egress_audit(build_dir, d)
            assert os.path.basename(path) == "siem_egress.json"
            payload = json.loads(open(path).read())
            assert payload["cloud"] == "aws"
            assert payload["provision_logs_endpoint"] is False
            assert payload["note"]
            assert "tfvars_env" in payload
            assert "TF_VAR_siem_provision_logs_endpoint" not in payload["tfvars_env"]


# ---------------------------------------------------------------------------
# apply_siem_egress
# ---------------------------------------------------------------------------

class TestApplySiemEgress:
    def setup_method(self):
        # Snapshot any TF_VAR_* in os.environ so we can clean up.
        self._snapshot = {
            k: v for k, v in os.environ.items() if k.startswith("TF_VAR_")
        }
        for k in list(os.environ):
            if k.startswith("TF_VAR_"):
                del os.environ[k]

    def teardown_method(self):
        for k in list(os.environ):
            if k.startswith("TF_VAR_"):
                del os.environ[k]
        os.environ.update(self._snapshot)

    def test_sets_env_vars_and_writes_audit(self):
        cfg = _FakeSiemConfig(
            provider="syslog-cef",
            egress_mode="auto",
        )
        audit = _FakeAudit()
        with tempfile.TemporaryDirectory() as build_dir:
            decision, env = apply_siem_egress(
                build_dir,
                cfg,
                tee_platform="snp-aws",
                audit=audit,
            )
            assert decision.provision_logs_endpoint is False
            assert "TF_VAR_siem_provision_logs_endpoint" not in os.environ
            from tee_crafter.core.audit import build_layout as _layout
            assert os.path.exists(_layout.siem_egress_json(build_dir))
            assert audit.records, "audit.record should have been called"

    def test_propagates_validation_error(self):
        cfg = _FakeSiemConfig(
            provider="datadog",
            egress_mode="private",
        )
        with tempfile.TemporaryDirectory() as build_dir:
            with pytest.raises(ValueError):
                apply_siem_egress(build_dir, cfg, tee_platform="snp-aws")
