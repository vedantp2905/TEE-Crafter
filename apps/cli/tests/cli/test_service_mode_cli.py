"""CLI plumbing tests for persistent RA-TLS service mode.

The user-facing CLI surface has been collapsed to a single
``--service-profile`` flag.  The 8 individual knobs (cert-ttl, reattest-*,
keepalive, streaming, max-conns, on-attestation-failure) are still tested
here against the *internal* ``build_service_policy`` builder, which the
``build_service_policy_from_profile`` dispatcher delegates to.
"""
from __future__ import annotations

import json
import os

import pytest

from tee_crafter.cli.commands.deploy.service_mode import (
    SERVICE_PROFILES, build_service_policy, build_service_policy_from_profile,
    write_service_policy, record_service_policy_audit,
)
from tee_crafter.core.service import OnAttestationFailure, ServicePolicy


class TestBuildServicePolicy:
    def test_defaults_validate(self):
        p = build_service_policy(
            enabled=True, cert_ttl=3600, cert_grace=300,
            reattest_interval=600, reattest_grace=60,
            keepalive=True, streaming=False,
            max_conns=1024, on_failure="drain",
        )
        assert p.is_valid()
        assert p.on_failure == OnAttestationFailure.DRAIN

    def test_invalid_failure_mode(self):
        # --on-attestation-failure is gone from the public CLI; the
        # internal builder still validates the underlying enum.
        with pytest.raises(ValueError, match="on_failure"):
            build_service_policy(
                enabled=True, cert_ttl=3600, cert_grace=300,
                reattest_interval=600, reattest_grace=60,
                keepalive=True, streaming=False,
                max_conns=1024, on_failure="boom",
            )

    def test_invalid_policy_when_enabled(self):
        # cert_ttl < reattest_interval is invalid
        with pytest.raises(ValueError, match="reattest_interval_seconds"):
            build_service_policy(
                enabled=True, cert_ttl=300, cert_grace=10,
                reattest_interval=600, reattest_grace=10,
                keepalive=True, streaming=False,
                max_conns=4, on_failure="drain",
            )

    def test_disabled_skips_validation(self):
        # When --service-mode is not set, we should not crash on bad values
        p = build_service_policy(
            enabled=False, cert_ttl=300, cert_grace=10,
            reattest_interval=600, reattest_grace=10,
            keepalive=True, streaming=False,
            max_conns=4, on_failure="drain",
        )
        assert isinstance(p, ServicePolicy)
        # But the underlying ServicePolicy still flags issues if asked.
        assert not p.is_valid()


class TestWriteServicePolicy:
    def test_writes_json_and_env(self, tmp_path):
        p = build_service_policy(
            enabled=True, cert_ttl=600, cert_grace=60,
            reattest_interval=300, reattest_grace=30,
            keepalive=False, streaming=True,
            max_conns=8, on_failure="hard_stop",
        )
        json_path = write_service_policy(str(tmp_path), p, enabled=True)
        env_path = os.path.join(tmp_path, "service_policy.env")
        assert os.path.isfile(json_path)
        assert os.path.isfile(env_path)
        doc = json.loads(open(json_path).read())
        assert doc["enabled"] is True
        assert doc["policy"]["on_failure"] == "hard_stop"
        env = open(env_path).read()
        assert "TEE_CRAFTER_SERVICE_MODE=1" in env
        assert "TEE_CRAFTER_KEEPALIVE=0" in env
        assert "TEE_CRAFTER_STREAMING=1" in env
        assert "TEE_CRAFTER_ON_ATTEST_FAIL=hard_stop" in env

    def test_disabled_writes_zero_marker(self, tmp_path):
        p = build_service_policy(
            enabled=False, cert_ttl=3600, cert_grace=300,
            reattest_interval=600, reattest_grace=60,
            keepalive=True, streaming=False,
            max_conns=1024, on_failure="drain",
        )
        write_service_policy(str(tmp_path), p, enabled=False)
        env = open(tmp_path / "service_policy.env").read()
        assert "TEE_CRAFTER_SERVICE_MODE=0" in env

    def test_mirrors_into_app_when_present(self, tmp_path):
        (tmp_path / "app").mkdir()
        p = build_service_policy(
            enabled=True, cert_ttl=3600, cert_grace=300,
            reattest_interval=600, reattest_grace=60,
            keepalive=True, streaming=False,
            max_conns=1024, on_failure="drain",
        )
        write_service_policy(str(tmp_path), p, enabled=True)
        assert os.path.isfile(tmp_path / "app" / "service_policy.json")
        assert os.path.isfile(tmp_path / "app" / "service_policy.env")


class TestRecordAudit:
    def test_records_entry(self):
        events = []

        class FakeAudit:
            def record(self, phase, step, status, **kwargs):
                events.append((phase, step, status, kwargs))

        p = build_service_policy(
            enabled=True, cert_ttl=3600, cert_grace=300,
            reattest_interval=600, reattest_grace=60,
            keepalive=True, streaming=True,
            max_conns=2048, on_failure="warn",
        )
        record_service_policy_audit(FakeAudit(), p, enabled=True)
        assert len(events) == 1
        phase, step, status, kw = events[0]
        assert phase == "Service Mode"
        assert kw["streaming_enabled"] is True
        assert kw["on_failure"] == "warn"

    def test_none_audit_is_safe(self):
        # Passing None must never raise.
        p = build_service_policy(
            enabled=True, cert_ttl=3600, cert_grace=300,
            reattest_interval=600, reattest_grace=60,
            keepalive=True, streaming=False,
            max_conns=1024, on_failure="drain",
        )
        record_service_policy_audit(None, p, enabled=True)


class TestProfileDispatcher:
    """Cover the public ``--service-profile`` entry point."""

    def test_default_disabled(self):
        enabled, p = build_service_policy_from_profile("default")
        assert enabled is False
        assert isinstance(p, ServicePolicy)

    @pytest.mark.parametrize("name", ["long-lived", "short-lived", "streaming"])
    def test_known_profiles_enable_service(self, name):
        enabled, p = build_service_policy_from_profile(name)
        assert enabled is True
        assert p.is_valid(), f"{name} preset must be valid"

    def test_streaming_profile_sets_streaming_flag(self):
        _, p = build_service_policy_from_profile("streaming")
        assert p.streaming_enabled is True

    def test_unknown_profile_rejected(self):
        with pytest.raises(ValueError, match="--service-profile"):
            build_service_policy_from_profile("nope")

    def test_none_falls_back_to_default(self):
        enabled, _ = build_service_policy_from_profile(None)  # type: ignore[arg-type]
        assert enabled is False

    def test_known_profiles_match_registered_set(self):
        assert set(SERVICE_PROFILES) == {
            "default", "long-lived", "short-lived", "streaming"
        }
