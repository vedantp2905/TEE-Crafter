"""Unit tests for the SIEM + BYOK CLI plumbing.

The user-facing CLI surface has been collapsed.  All provider-specific
fields (host/port/endpoint/token/api_key/dce_url/log_group/key_id/region/…)
must now be supplied via JSON config files referenced by ``--siem-config``
or ``--byok-config``.

These tests therefore drive ``build_siem_config`` / ``build_byok_config``
through JSON files rather than kwargs.  Validation, env-file emission,
and ``app/`` mirroring are still exercised end-to-end.
"""
from __future__ import annotations

import json
import os

import pytest

from tee_crafter.cli.commands.deploy.siem_mode import (
    SIEM_PROVIDERS, build_siem_config, write_siem_config, record_siem_audit,
)
from tee_crafter.cli.commands.deploy.byok_mode import (
    build_byok_config, write_byok_config, record_byok_audit,
)


class _FakeAudit:
    def __init__(self):
        self.records = []
        self.checks = []
    def record(self, *args, **kwargs):
        self.records.append((args, kwargs))
    def record_check(self, *args, **kwargs):
        self.checks.append((args, kwargs))


def _write_siem_json(tmp_path, doc: dict, name: str = "siem.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return str(p)


def _write_byok_json(tmp_path, doc: dict, name: str = "byok.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return str(p)


# ---------------------------------------------------------------------------
# SIEM
# ---------------------------------------------------------------------------

class TestSiemBuild:
    def test_none_provider_validates(self):
        cfg = build_siem_config(provider="none")
        assert cfg.provider == "none"
        assert cfg.validate() == []

    def test_provider_without_config_path_rejected(self):
        with pytest.raises(ValueError, match="requires --siem-config"):
            build_siem_config(provider="splunk-hec")

    def test_syslog_defaults_port_to_514(self, tmp_path):
        path = _write_siem_json(tmp_path, {"host": "siem.example.com"})
        cfg = build_siem_config(provider="syslog-cef", raw_config_path=path)
        assert cfg.port == 514
        assert cfg.protocol == "tcp"
        assert cfg.validate() == []

    def test_syslog_requires_host(self, tmp_path):
        path = _write_siem_json(tmp_path, {})
        cfg = build_siem_config(provider="syslog-cef", raw_config_path=path)
        errs = cfg.validate()
        assert any("host" in e for e in errs)

    def test_splunk_requires_endpoint_and_token(self, tmp_path):
        path = _write_siem_json(tmp_path, {})
        cfg = build_siem_config(provider="splunk-hec", raw_config_path=path)
        errs = cfg.validate()
        assert any("endpoint" in e for e in errs)
        assert any("token" in e for e in errs)

    def test_splunk_validates_https(self, tmp_path):
        path = _write_siem_json(tmp_path, {
            "endpoint": "https://hec.example/8088",
            "token": "abc",
        })
        cfg = build_siem_config(provider="splunk-hec", raw_config_path=path)
        assert cfg.validate() == []

    def test_env_var_overrides_fail_open_to_closed(self, tmp_path, monkeypatch):
        """``TEE_CRAFTER_SIEM_FAIL_OPEN=0`` must flip a sandbox config's
        ``fail_open: true`` to ``False`` at load time so SIEM-002 passes
        without editing the JSON.
        """
        path = _write_siem_json(tmp_path, {
            "host": "siem.example.com", "fail_open": True,
        })
        monkeypatch.setenv("TEE_CRAFTER_SIEM_FAIL_OPEN", "0")
        cfg = build_siem_config(provider="syslog-cef", raw_config_path=path)
        assert cfg.fail_open is False

    def test_env_var_can_force_fail_open(self, tmp_path, monkeypatch):
        path = _write_siem_json(tmp_path, {
            "host": "siem.example.com", "fail_open": False,
        })
        monkeypatch.setenv("TEE_CRAFTER_SIEM_FAIL_OPEN", "1")
        cfg = build_siem_config(provider="syslog-cef", raw_config_path=path)
        assert cfg.fail_open is True

    def test_env_var_unset_preserves_config(self, tmp_path, monkeypatch):
        path = _write_siem_json(tmp_path, {
            "host": "siem.example.com", "fail_open": True,
        })
        monkeypatch.delenv("TEE_CRAFTER_SIEM_FAIL_OPEN", raising=False)
        cfg = build_siem_config(provider="syslog-cef", raw_config_path=path)
        assert cfg.fail_open is True

    def test_datadog_requires_api_key(self, tmp_path):
        path = _write_siem_json(tmp_path, {})
        cfg = build_siem_config(provider="datadog", raw_config_path=path)
        errs = cfg.validate()
        assert any("api_key" in e or "api-key" in e for e in errs)

    @pytest.mark.parametrize("provider", ["cloudwatch", "azure-monitor"])
    def test_providers_without_a_sidecar_exporter_are_rejected(
            self, tmp_path, provider):
        """`--siem cloudwatch|azure-monitor` must not be selectable.

        Both used to validate cleanly and deploy: Terraform provisioned a
        CloudWatch Logs interface endpoint and a logs:PutLogEvents grant, the
        deploy printed "SIEM sidecar active - events streaming", and the
        sidecar then crash-looped 28 times because
        `siem_export._build_exporter` raises for any provider it has no
        exporter class for. Observed on a live nitro-aws deploy: zero events,
        no log group created.

        Accepting a provider the sidecar cannot build is worse than refusing
        it, so the membership check now rejects these outright.
        """
        path = _write_siem_json(tmp_path, {
            "log_group": "lg", "log_stream": "ls", "region": "us-east-2",
            "dce_url": "https://dce.example", "dcr_immutable_id": "dcr-abc",
            "stream_name": "Custom-X",
        })
        cfg = build_siem_config(provider=provider, raw_config_path=path)
        errs = cfg.validate()
        # A complete, previously-valid config must still be refused, purely
        # because the provider has no exporter.
        assert errs, f"{provider} validated cleanly despite having no exporter"
        assert any("--siem must be one of" in e for e in errs), errs

    def test_offered_providers_match_the_sidecar_factory(self):
        """SIEM_PROVIDERS must not drift from what the sidecar can build.

        `siem_export._build_exporter` is the factory that actually runs inside
        the deployment; anything absent from it raises on every start. Parse the
        providers it handles straight out of the shipped module rather than
        restating a list here, so adding an exporter without offering it (or
        the reverse) fails this test.
        """
        import pathlib as _pl
        import re as _re
        sidecar = (_pl.Path(__file__).resolve().parents[2] / "src" / "tee_crafter"
                   / "templates" / "common" / "siem_export.py").read_text()
        factory = sidecar[sidecar.index("def _build_exporter("):]
        factory = factory[:factory.index("raise RuntimeError")]
        built = set(_re.findall(r'provider == "([a-z-]+)"', factory))
        assert built, "could not parse providers out of _build_exporter"
        assert set(SIEM_PROVIDERS) - {"none"} == built, (
            f"--siem offers {sorted(set(SIEM_PROVIDERS) - {'none'})} but the "
            f"sidecar can only build {sorted(built)}"
        )

    def test_provider_mismatch_in_json_rejected(self, tmp_path):
        path = _write_siem_json(tmp_path, {
            "provider": "splunk-hec",
            "endpoint": "https://hec.example",
            "token": "tok",
        })
        with pytest.raises(ValueError, match="does not match"):
            build_siem_config(provider="datadog", raw_config_path=path)

    def test_to_env_only_emits_relevant_keys(self, tmp_path):
        path = _write_siem_json(tmp_path, {
            "endpoint": "https://hec.example",
            "token": "secret-tok",
        })
        cfg = build_siem_config(provider="splunk-hec", raw_config_path=path)
        env = cfg.to_env()
        assert env["TEE_CRAFTER_SIEM"] == "splunk-hec"
        assert env["TEE_CRAFTER_SIEM_TOKEN"] == "secret-tok"
        # syslog-only keys must not appear
        assert "TEE_CRAFTER_SIEM_HOST" not in env
        assert "TEE_CRAFTER_SIEM_PROTOCOL" not in env

    def test_describe_human_readable(self, tmp_path):
        path = _write_siem_json(tmp_path, {
            "host": "siem.example", "port": 601, "protocol": "tcp",
        })
        cfg = build_siem_config(provider="syslog-cef", raw_config_path=path)
        assert "siem.example:601/tcp" in cfg.describe()


class TestSiemWrite:
    def test_write_creates_files_and_mirrors_app(self, tmp_path):
        from tee_crafter.core.audit import build_layout as _layout
        path = _write_siem_json(tmp_path, {
            "endpoint": "https://hec.example", "token": "tok",
        })
        cfg = build_siem_config(provider="splunk-hec", raw_config_path=path)
        app = tmp_path / "app"
        app.mkdir()
        out = write_siem_config(str(tmp_path), cfg, enabled=True)
        assert os.path.isfile(out)
        assert os.path.isfile(_layout.siem_env(str(tmp_path)))
        assert os.path.isfile(app / "siem.json")
        assert os.path.isfile(app / "siem.env")

    def test_write_disabled_marks_env(self, tmp_path):
        from tee_crafter.core.audit import build_layout as _layout
        cfg = build_siem_config(provider="none")
        write_siem_config(str(tmp_path), cfg, enabled=False)
        env = open(_layout.siem_env(str(tmp_path))).read()
        assert "TEE_CRAFTER_SIEM_ENABLED=0" in env

    def test_audit_records_provider(self, tmp_path):
        path = _write_siem_json(tmp_path, {
            "endpoint": "https://hec.example", "token": "tok",
        })
        cfg = build_siem_config(provider="splunk-hec", raw_config_path=path)
        audit = _FakeAudit()
        record_siem_audit(audit, cfg, enabled=True)
        assert audit.records
        kwargs = audit.records[0][1]
        assert kwargs["provider"] == "splunk-hec"


# ---------------------------------------------------------------------------
# BYOK
# ---------------------------------------------------------------------------

class TestByokBuild:
    def test_none_validates(self):
        cfg = build_byok_config(provider="none")
        assert cfg.validate() == []

    def test_provider_without_policy_path_rejected(self):
        with pytest.raises(ValueError, match="requires --byok-config"):
            build_byok_config(provider="aws-kms")

    def test_aws_kms_requires_key_id_and_region(self, tmp_path):
        path = _write_byok_json(tmp_path, {})
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        errs = cfg.validate()
        assert any("key" in e or "key-id" in e for e in errs)
        assert any("region" in e for e in errs)

    def test_aws_kms_complete(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "key_id": "arn:aws:kms:us-east-2:123:key/abc",
            "region": "us-east-2",
            "unwrap": "aws_nitro_recipient",
        })
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        assert cfg.validate() == []

    def test_azure_kv_requires_key_url(self, tmp_path):
        path = _write_byok_json(tmp_path, {"key_id": "not-a-url"})
        cfg = build_byok_config(provider="azure-kv", raw_policy_path=path)
        errs = cfg.validate()
        assert any("Key Vault" in e or "https://" in e for e in errs)

    def test_external_hsm_requires_https_endpoint(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "key_id": "k",
            "hsm_endpoint": "http://insecure",
        })
        cfg = build_byok_config(provider="external-hsm", raw_policy_path=path)
        errs = cfg.validate()
        assert any("https://" in e for e in errs)

    def test_unwrap_choice_validated(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "key_id": "k", "region": "us-east-2", "unwrap": "bogus",
        })
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        errs = cfg.validate()
        assert any("unwrap" in e for e in errs)

    def test_allowed_measurement_must_be_64_hex(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "key_id": "k", "region": "us-east-2",
            "policy": {"allowed_measurement_sha256": ["short"]},
        })
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        errs = cfg.validate()
        assert any("SHA-256" in e for e in errs)

    def test_encryption_context_kv_parsing(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "key_id": "k", "region": "us-east-2",
            "encryption_context": ["tenant=acme", "env=prod"],
        })
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        assert cfg.encryption_context == {"tenant": "acme", "env": "prod"}

    def test_provider_mismatch_in_json_rejected(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "provider": "aws-kms", "key_id": "arn:k", "region": "us-east-2",
        })
        with pytest.raises(ValueError, match="does not match"):
            build_byok_config(provider="azure-kv", raw_policy_path=path)

    def test_full_policy_round_trip(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "provider": "aws-kms", "key_id": "arn:k", "region": "us-east-2",
            "unwrap": "aws_nitro_recipient",
            "encryption_context": {"tenant": "acme"},
            "policy": {
                "max_attestation_age_seconds": 60,
                "allowed_measurement_sha256": ["a" * 64],
                "require_encryption_context_keys": ["tenant"],
            },
        })
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        assert cfg.allowed_measurement_sha256 == ["a" * 64]
        assert cfg.require_encryption_context_keys == ["tenant"]
        assert cfg.max_attestation_age_seconds == 60

    def test_to_env_only_emits_set_keys(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "key_id": "arn", "region": "us-east-2",
            "encryption_context": ["t=a"],
        })
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        env = cfg.to_env()
        assert env["TEE_CRAFTER_BYOK"] == "aws-kms"
        assert env["TEE_CRAFTER_BYOK_KEY_ID"] == "arn"
        assert env["TEE_CRAFTER_BYOK_REGION"] == "us-east-2"
        assert env["TEE_CRAFTER_BYOK_ENCRYPTION_CONTEXT"] == "t=a"


class TestByokWrite:
    def test_write_creates_and_mirrors(self, tmp_path):
        import pathlib as _pl
        from tee_crafter.core.audit import build_layout as _layout
        path = _write_byok_json(tmp_path, {
            "key_id": "arn", "region": "us-east-2",
        })
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        (tmp_path / "app").mkdir()
        write_byok_config(str(tmp_path), cfg, enabled=True)
        # New layout: build-dir copy under byok/; in-TEE staging copy
        # mirrored under app/.
        for base in (
            _pl.Path(_layout.byok_dir(str(tmp_path))),
            tmp_path / "app",
        ):
            assert (base / "byok.json").is_file()
            assert (base / "byok.env").is_file()

    def test_audit_records_key_tail(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "key_id": "arn:aws:kms:us-east-2:123:key/abcdefghijklmnopqrstuv",
            "region": "us-east-2",
        })
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        audit = _FakeAudit()
        record_byok_audit(audit, cfg, enabled=True)
        assert audit.records
        kwargs = audit.records[0][1]
        assert kwargs["provider"] == "aws-kms"
        assert kwargs["region"] == "us-east-2"
        assert "key_id_tail" in kwargs

    def _byok011(self, audit):
        for args, kwargs in audit.checks:
            if "BYOK-011" in args:
                return kwargs
        return None

    def test_byok011_warns_on_empty_allowlist_cvm(self, tmp_path, monkeypatch):
        from tee_crafter.core.audit import Verdict
        monkeypatch.delenv("TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", raising=False)
        path = _write_byok_json(tmp_path, {
            "key_id": "arn:aws:kms:us-east-2:123:key/abc", "region": "us-east-2"})
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        audit = _FakeAudit()
        record_byok_audit(audit, cfg, enabled=True, tee_platform="snp-aws")
        k = self._byok011(audit)
        assert k is not None and k["observed"] is False
        assert k["verdict"] == Verdict.WARN

    def test_byok011_fails_strict_on_empty_allowlist(self, tmp_path, monkeypatch):
        from tee_crafter.core.audit import Verdict
        monkeypatch.setenv("TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", "1")
        path = _write_byok_json(tmp_path, {
            "key_id": "arn:aws:kms:us-east-2:123:key/abc", "region": "us-east-2"})
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        audit = _FakeAudit()
        record_byok_audit(audit, cfg, enabled=True, tee_platform="tdx-gcp")
        k = self._byok011(audit)
        assert k is not None and k["verdict"] == Verdict.FAIL

    def test_byok011_passes_with_allowlist(self, tmp_path, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", raising=False)
        path = _write_byok_json(tmp_path, {
            "key_id": "arn:aws:kms:us-east-2:123:key/abc", "region": "us-east-2",
            "policy": {"allowed_measurement_sha256": ["a" * 64]}})
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        audit = _FakeAudit()
        record_byok_audit(audit, cfg, enabled=True, tee_platform="snp-aws")
        k = self._byok011(audit)
        assert k is not None and k["observed"] is True

    def test_byok011_nitro_recipient_is_backstopped(self, tmp_path, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", raising=False)
        path = _write_byok_json(tmp_path, {
            "key_id": "arn:aws:kms:us-east-2:123:key/abc", "region": "us-east-2",
            "unwrap": "aws_nitro_recipient"})
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        audit = _FakeAudit()
        record_byok_audit(audit, cfg, enabled=True, tee_platform="nitro-aws")
        k = self._byok011(audit)
        # Empty in-guest allowlist, but Nitro Recipient binds PCRs server-side.
        assert k is not None and k["observed"] is True

    def _skr_cfg(self, tmp_path):
        path = _write_byok_json(tmp_path, {
            "key_id": "https://v.vault.azure.net/keys/dek/1",
            "unwrap": "direct_bytes"})
        return build_byok_config(provider="azure-skr", raw_policy_path=path)

    def test_byok011_azure_skr_still_warns_on_empty_allowlist(
            self, tmp_path, monkeypatch):
        """azure-skr is not upgraded to a pass by the server-side policy.

        Key Vault's ``release_policy`` is a real server-side gate, but it is
        only *measurement*-bound if it asserts the launchmeasurement claim, and
        this check cannot read the policy.  Fail closed on what we cannot prove.
        """
        from tee_crafter.core.audit import Verdict
        monkeypatch.delenv("TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", raising=False)
        audit = _FakeAudit()
        record_byok_audit(audit, self._skr_cfg(tmp_path), enabled=True,
                          tee_platform="snp-azure")
        k = self._byok011(audit)
        assert k is not None and k["observed"] is False
        assert k["verdict"] == Verdict.WARN

    def test_byok011_azure_skr_does_not_claim_absent_server_side_condition(
            self, tmp_path, monkeypatch):
        """The note must not repeat the old, false "no server-side" claim.

        Key Vault refuses to release an exportable key without a
        ``release_policy`` and evaluates it against the MAA token, so telling
        the operator there is no server-side condition points at the wrong fix.
        """
        monkeypatch.delenv("TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", raising=False)
        audit = _FakeAudit()
        record_byok_audit(audit, self._skr_cfg(tmp_path), enabled=True,
                          tee_platform="snp-azure")
        note = self._byok011(audit)["note"]
        assert "no server-side" not in note
        assert "release_policy" in note
        assert "launchmeasurement" in note

    def test_byok011_azure_skr_hard_fails_under_strict(
            self, tmp_path, monkeypatch):
        from tee_crafter.core.audit import Verdict
        monkeypatch.setenv("TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", "1")
        audit = _FakeAudit()
        record_byok_audit(audit, self._skr_cfg(tmp_path), enabled=True,
                          tee_platform="snp-azure")
        assert self._byok011(audit)["verdict"] == Verdict.FAIL

    def test_byok011_non_skr_cvm_keeps_the_no_server_side_note(
            self, tmp_path, monkeypatch):
        """The original branch must survive for platforms it is true of."""
        monkeypatch.delenv("TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", raising=False)
        path = _write_byok_json(tmp_path, {
            "key_id": "arn:aws:kms:us-east-2:123:key/abc", "region": "us-east-2"})
        cfg = build_byok_config(provider="aws-kms", raw_policy_path=path)
        audit = _FakeAudit()
        record_byok_audit(audit, cfg, enabled=True, tee_platform="snp-gcp")
        assert "no server-side PCR condition" in self._byok011(audit)["note"]
