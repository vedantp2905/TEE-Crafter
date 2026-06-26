"""Tests for the general workload egress allowlist (DB / 3rd-party APIs)."""
from __future__ import annotations

import json
import os

import pytest

from tee_crafter.cli.commands.deploy.workload_egress import (
    EgressSpecError,
    apply_workload_egress,
    decide_workload_egress,
    merge_into_egress_tfvars,
    parse_egress_specs,
    write_workload_egress_audit,
)


def _fake_resolver(host: str):
    return {"db.example.com": ["203.0.113.10/32"]}.get(host, ["198.51.100.5/32"])


class TestParseSpecs:
    def test_host_port(self):
        assert parse_egress_specs(["db.example.com:5432"]) == [("db.example.com", 5432)]

    def test_cidr_keeps_mask(self):
        assert parse_egress_specs(["10.0.5.0/24:5432"]) == [("10.0.5.0/24", 5432)]

    def test_missing_port_rejected(self):
        with pytest.raises(EgressSpecError):
            parse_egress_specs(["db.example.com"])

    def test_bad_port_rejected(self):
        with pytest.raises(EgressSpecError):
            parse_egress_specs(["db.example.com:notaport"])

    def test_out_of_range_port_rejected(self):
        with pytest.raises(EgressSpecError):
            parse_egress_specs(["db.example.com:70000"])


class TestDecide:
    def test_default_deny_opens_nothing(self):
        d = decide_workload_egress(egress_mode="deny", allow_specs=[])
        assert d.mode == "deny"
        assert d.egress_cidrs == []
        assert d.needs_nat is False

    def test_deny_with_allow_is_error(self):
        with pytest.raises(EgressSpecError):
            decide_workload_egress(egress_mode="deny", allow_specs=["db:5432"])

    def test_vpc_no_nat(self):
        d = decide_workload_egress(
            egress_mode="vpc", allow_specs=["10.0.5.0/24:5432"], resolver=_fake_resolver)
        assert d.needs_nat is False
        assert d.egress_cidrs == ["10.0.5.0/24"]
        assert d.egress_ports == [5432]

    def test_nat_for_public(self):
        d = decide_workload_egress(
            egress_mode="nat", allow_specs=["db.example.com:5432"], resolver=_fake_resolver)
        assert d.needs_nat is True
        assert d.egress_cidrs == ["203.0.113.10/32"]
        assert d.egress_ports == [5432]

    def test_literal_ip_to_slash32(self):
        d = decide_workload_egress(
            egress_mode="nat", allow_specs=["203.0.113.9:443"], resolver=_fake_resolver)
        assert d.egress_cidrs == ["203.0.113.9/32"]

    def test_bad_mode(self):
        with pytest.raises(EgressSpecError):
            decide_workload_egress(egress_mode="bogus", allow_specs=[])


class TestMergeTfvars:
    def test_unions_with_existing_siem_allowlist(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_siem_egress_cidrs", json.dumps(["8.8.8.8/32"]))
        monkeypatch.setenv("TF_VAR_siem_egress_ports", json.dumps([443]))
        monkeypatch.delenv("TF_VAR_allow_setup_egress", raising=False)
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_SETUP_EGRESS_NAT", raising=False)
        d = decide_workload_egress(
            egress_mode="nat", allow_specs=["db.example.com:5432"], resolver=_fake_resolver)
        env = merge_into_egress_tfvars(d, "snp-gcp")
        assert set(json.loads(env["TF_VAR_siem_egress_cidrs"])) == {"8.8.8.8/32", "203.0.113.10/32"}
        assert set(json.loads(env["TF_VAR_siem_egress_ports"])) == {443, 5432}
        # The narrow per-CIDR rules are the whole plan: `allow_setup_egress`
        # would additionally open 0.0.0.0/0 on 80/443 at higher precedence,
        # so `--egress-mode nat` must not turn it on.
        assert "TF_VAR_allow_setup_egress" not in env
        assert "TF_VAR_allow_setup_egress" not in os.environ

    def test_blanket_nat_only_under_explicit_opt_in(self, monkeypatch):
        monkeypatch.delenv("TF_VAR_siem_egress_cidrs", raising=False)
        monkeypatch.delenv("TF_VAR_allow_setup_egress", raising=False)
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_SETUP_EGRESS_NAT", "1")
        d = decide_workload_egress(
            egress_mode="nat", allow_specs=["db.example.com:5432"], resolver=_fake_resolver)
        env = merge_into_egress_tfvars(d, "snp-aws")
        assert env["TF_VAR_allow_setup_egress"] == "true"

    def test_vpc_does_not_set_nat(self, monkeypatch):
        monkeypatch.delenv("TF_VAR_siem_egress_cidrs", raising=False)
        monkeypatch.delenv("TF_VAR_allow_setup_egress", raising=False)
        d = decide_workload_egress(
            egress_mode="vpc", allow_specs=["10.0.5.0/24:5432"], resolver=_fake_resolver)
        env = merge_into_egress_tfvars(d)
        assert "TF_VAR_allow_setup_egress" not in env
        assert "TF_VAR_allow_setup_egress" not in os.environ

    def test_deny_sets_nothing(self, monkeypatch):
        d = decide_workload_egress(egress_mode="deny", allow_specs=[])
        assert merge_into_egress_tfvars(d) == {}


class TestAuditDoc:
    def test_writes_json(self, tmp_path):
        d = decide_workload_egress(
            egress_mode="nat", allow_specs=["db.example.com:5432"], resolver=_fake_resolver)
        out = write_workload_egress_audit(str(tmp_path), d)
        doc = json.loads(open(out).read())
        assert doc["mode"] == "nat"
        assert doc["needs_nat"] is True
        assert doc["egress_cidrs"] == ["203.0.113.10/32"]


class _CaptureAudit:
    def __init__(self):
        self.checks = []

    def record(self, *a, **k):
        pass

    def record_check(self, phase, step, check_id, **k):
        self.checks.append((check_id, k))


class TestApply:
    def test_emits_egr_checks(self, tmp_path, monkeypatch):
        monkeypatch.delenv("TF_VAR_siem_egress_cidrs", raising=False)
        audit = _CaptureAudit()
        apply_workload_egress(
            str(tmp_path), egress_mode="deny", allow_specs=[],
            tee_platform="snp-aws", audit=audit, console=None)
        ids = {c[0] for c in audit.checks}
        assert "EGR-005" in ids
        assert "EGR-006" in ids

    def test_flags_wide_cidr(self, tmp_path, monkeypatch):
        monkeypatch.delenv("TF_VAR_siem_egress_cidrs", raising=False)
        monkeypatch.delenv("TF_VAR_allow_setup_egress", raising=False)
        audit = _CaptureAudit()
        # 0.0.0.0/0 as a literal CIDR spec — EGR-006 must observe False.
        # snp-gcp derives its Cloud NAT from the allowlist, so the nat-route
        # gate below is not what fires here.
        apply_workload_egress(
            str(tmp_path), egress_mode="nat", allow_specs=["0.0.0.0/0:5432"],
            tee_platform="snp-gcp", audit=audit, console=None)
        egr006 = [c for c in audit.checks if c[0] == "EGR-006"][0]
        assert egr006[1]["observed"] is False

    def test_egr006_fails_when_blanket_flag_is_on(self, tmp_path, monkeypatch):
        """EGR-006 grades the effective rule set, not just the allowlist.

        Regression: with a narrow allowlist *and*
        ``TF_VAR_allow_setup_egress=true`` the row used to read observed=True
        while the NSG/SG actually permitted 0.0.0.0/0 on 80/443.
        """
        monkeypatch.delenv("TF_VAR_siem_egress_cidrs", raising=False)
        monkeypatch.setenv("TF_VAR_allow_setup_egress", "true")
        audit = _CaptureAudit()
        apply_workload_egress(
            str(tmp_path), egress_mode="vpc", allow_specs=["10.0.5.0/24:5432"],
            tee_platform="snp-gcp", audit=audit, console=None)
        egr006 = [c for c in audit.checks if c[0] == "EGR-006"][0]
        assert egr006[1]["observed"] is False
        assert "allow_setup_egress" in egr006[1]["note"]

    def test_nat_refused_on_aws_without_opt_in(self, tmp_path, monkeypatch):
        """AWS templates only create the NAT via the blanket flag — refuse."""
        monkeypatch.delenv("TF_VAR_siem_egress_cidrs", raising=False)
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_SETUP_EGRESS_NAT", raising=False)
        with pytest.raises(EgressSpecError, match="not wired"):
            apply_workload_egress(
                str(tmp_path), egress_mode="nat",
                allow_specs=["203.0.113.9:5432"],
                tee_platform="snp-aws", audit=None, console=None)
