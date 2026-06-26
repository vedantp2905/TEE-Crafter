"""BYOK-SEC-1 deploy-time sidecar: byok.env relocation to tmpfs.

Mirrors ``tests/cli/test_siem_sidecar*.py`` (where they exist) and
``tests/cli/test_byok_secret_split.py``.  These tests do NOT contact a
real instance — they check the install-script generator, the
``is_byok_enabled`` predicate, and the ``run_remote`` happy-path
glue.
"""
from __future__ import annotations


import pytest

from tee_crafter.cli.deployment.common.byok_sidecar import (
    SUPPORTED_PLATFORMS,
    _LAYOUT,
    _install_script,
    install_byok_sidecar,
    is_byok_enabled,
    runtime_dir_for,
)


class _FakeConsole:
    def __init__(self):
        self.lines = []

    def print(self, *args, **kwargs):
        self.lines.append(" ".join(str(a) for a in args))


class _FakeAudit:
    def __init__(self):
        self.records = []
        self.checks = []

    def record(self, *args, **kwargs):
        self.records.append((args, kwargs))

    def record_check(self, *args, **kwargs):
        self.checks.append((args, kwargs))


# ---------------------------------------------------------------------------
# is_byok_enabled
# ---------------------------------------------------------------------------

class TestIsByokEnabled:
    def test_no_files_returns_false(self, tmp_path):
        assert is_byok_enabled(str(tmp_path)) is False

    def test_byok_env_with_enabled_marker(self, tmp_path):
        (tmp_path / "byok.env").write_text(
            "TEE_CRAFTER_BYOK=aws-kms\nTEE_CRAFTER_BYOK_ENABLED=1\n",
            encoding="utf-8")
        assert is_byok_enabled(str(tmp_path)) is True

    def test_byok_env_public_with_enabled_marker(self, tmp_path):
        (tmp_path / "byok.env.public").write_text(
            "TEE_CRAFTER_BYOK_ENABLED=true\n", encoding="utf-8")
        assert is_byok_enabled(str(tmp_path)) is True

    def test_enabled_zero_returns_false(self, tmp_path):
        (tmp_path / "byok.env").write_text(
            "TEE_CRAFTER_BYOK_ENABLED=0\n", encoding="utf-8")
        assert is_byok_enabled(str(tmp_path)) is False

    def test_checks_app_subdir_too(self, tmp_path):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "byok.env.public").write_text(
            "TEE_CRAFTER_BYOK_ENABLED=yes\n", encoding="utf-8")
        assert is_byok_enabled(str(tmp_path)) is True


# ---------------------------------------------------------------------------
# runtime_dir_for / _install_script
# ---------------------------------------------------------------------------

class TestInstallScript:
    @pytest.mark.parametrize("platform", list(_LAYOUT.keys()))
    def test_script_uses_per_platform_tmpfs_dir(self, platform):
        script = _install_script(platform)
        expected_dir = runtime_dir_for(platform)
        assert expected_dir in script, (
            f"install script for {platform} does not reference its "
            f"tmpfs dir {expected_dir}")
        # Confirm the disk copy gets shredded (or rm'd as fallback)
        # rather than left behind.
        assert "shred -u" in script
        # The disk-copy override switch must be honoured.
        assert "TEE_CRAFTER_BYOK_PERSIST" in script
        # Final marker so the parent's run_remote callback can grep.
        assert "BYOK-SEC-1: byok.env relocated to tmpfs" in script

    @pytest.mark.parametrize("platform", ["nitro-aws", "sgx-azure",
                                            "made-up-platform"])
    def test_script_is_noop_for_unsupported(self, platform):
        # Nitro / SGX don't ship byok.env on disk; the install script
        # is intentionally a no-op so the deploy phase can call us
        # unconditionally.
        script = _install_script(platform)
        assert "shred" not in script
        assert "no-op" in script


# ---------------------------------------------------------------------------
# install_byok_sidecar — happy path + early-out
# ---------------------------------------------------------------------------

class TestInstallByokSidecar:
    def test_disabled_is_noop(self, tmp_path):
        console = _FakeConsole()
        audit = _FakeAudit()
        calls = []

        def fake_run(_cmd):
            calls.append(_cmd)
            return True, "", ""

        ok = install_byok_sidecar(
            console=console, build_dir=str(tmp_path),
            tee_platform="snp-aws", run_remote=fake_run, audit=audit,
        )
        assert ok is True
        assert calls == [], "must not run anything when BYOK is off"
        assert audit.records == []

    def test_nitro_noop_when_byok_enabled(self, tmp_path):
        # BYOK is on but the platform is Nitro: byok.env is consumed
        # via EIF, not disk, so the sidecar records a not_applicable
        # ledger row and returns ok.
        (tmp_path / "byok.env").write_text(
            "TEE_CRAFTER_BYOK_ENABLED=1\n", encoding="utf-8")
        console = _FakeConsole()
        audit = _FakeAudit()
        calls = []

        def fake_run(_cmd):
            calls.append(_cmd)
            return True, "", ""

        ok = install_byok_sidecar(
            console=console, build_dir=str(tmp_path),
            tee_platform="nitro-aws", run_remote=fake_run, audit=audit,
        )
        assert ok is True
        assert calls == [], "Nitro path must skip the remote install"
        assert audit.checks, "must emit a not_applicable BYOK-007 row"
        _, kwargs = audit.checks[0]
        assert "no-op for nitro-aws" in kwargs.get("note", "")

    def test_happy_path_records_pass(self, tmp_path):
        (tmp_path / "byok.env").write_text(
            "TEE_CRAFTER_BYOK_ENABLED=1\n", encoding="utf-8")
        console = _FakeConsole()
        audit = _FakeAudit()

        def fake_run(_cmd):
            return True, "BYOK-SEC-1: byok.env relocated to tmpfs (or absent).", ""

        ok = install_byok_sidecar(
            console=console, build_dir=str(tmp_path),
            tee_platform="snp-aws", run_remote=fake_run, audit=audit,
        )
        assert ok is True
        assert audit.checks, "must emit BYOK-007 row"
        _, kwargs = audit.checks[0]
        assert kwargs.get("tee_platform") == "snp-aws"

    def test_failure_does_not_break_deploy(self, tmp_path):
        # Fail-open: sidecar failure logs a warning + audit entry but
        # the caller proceeds.  We just confirm the return value
        # reflects the failure without raising.
        (tmp_path / "byok.env").write_text(
            "TEE_CRAFTER_BYOK_ENABLED=1\n", encoding="utf-8")
        console = _FakeConsole()
        audit = _FakeAudit()

        def fake_run(_cmd):
            return False, "", "remote command exploded"

        ok = install_byok_sidecar(
            console=console, build_dir=str(tmp_path),
            tee_platform="snp-aws", run_remote=fake_run, audit=audit,
        )
        # Returns False on failure so the caller can log richer detail
        # if it wants, but the deploy doesn't abort.
        assert ok is False
        # The audit captured the warning state on the structured ledger.
        from tee_crafter.core.audit import Verdict
        verdicts = [kw.get("verdict") for _, kw in audit.checks]
        assert Verdict.WARN in verdicts


# ---------------------------------------------------------------------------
# SUPPORTED_PLATFORMS covers everything that loads byok.env at runtime
# ---------------------------------------------------------------------------

class TestPlatformCoverage:
    def test_layout_keys_match_supported_minus_noops(self):
        # Nitro + SGX are listed as supported (so callers can pass
        # them without ValueError) but have no layout entry because
        # they're no-ops.
        layout_set = set(_LAYOUT)
        supported = set(SUPPORTED_PLATFORMS)
        no_ops = {"nitro-aws", "sgx-azure"}
        assert layout_set == supported - no_ops
