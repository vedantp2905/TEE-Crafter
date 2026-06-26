"""Tests for the BYOK in-enclave fail-closed gate (byok_health)."""
from __future__ import annotations

import importlib.util
import os

import pytest

_BH_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "tee_crafter",
    "templates", "common", "byok_health.py",
)


@pytest.fixture()
def bh():
    spec = importlib.util.spec_from_file_location("byok_health_under_test", _BH_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_disabled_when_byok_off(bh, monkeypatch):
    monkeypatch.delenv("TEE_CRAFTER_BYOK_ENABLED", raising=False)
    assert bh.is_fail_closed() is False
    # No-op even though no DEK exists.
    bh.assert_byok_healthy()


def test_fail_closed_by_default_when_enabled(bh, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_BYOK_ENABLED", "1")
    monkeypatch.delenv("TEE_CRAFTER_BYOK_FAIL_OPEN", raising=False)
    assert bh.is_fail_closed() is True


def test_dev_hatch_disables(bh, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_BYOK_ENABLED", "1")
    monkeypatch.setenv("TEE_CRAFTER_BYOK_FAIL_OPEN", "1")
    assert bh.is_fail_closed() is False


def test_refuses_when_dek_missing_after_grace(bh, tmp_path, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_BYOK_ENABLED", "1")
    monkeypatch.delenv("TEE_CRAFTER_BYOK_FAIL_OPEN", raising=False)
    monkeypatch.setenv("TEE_CRAFTER_BYOK_DEK_PATH", str(tmp_path / "absent.bin"))
    monkeypatch.setenv("TEE_CRAFTER_BYOK_GRACE_SECONDS", "0")
    with pytest.raises(bh.ByokUnavailableError):
        bh.assert_byok_healthy()


def test_allows_when_dek_present(bh, tmp_path, monkeypatch):
    dek = tmp_path / "dek.bin"
    dek.write_bytes(b"\x01" * 32)
    monkeypatch.setenv("TEE_CRAFTER_BYOK_ENABLED", "1")
    monkeypatch.delenv("TEE_CRAFTER_BYOK_FAIL_OPEN", raising=False)
    monkeypatch.setenv("TEE_CRAFTER_BYOK_DEK_PATH", str(dek))
    monkeypatch.setenv("TEE_CRAFTER_BYOK_GRACE_SECONDS", "0")
    bh.assert_byok_healthy()  # no raise


def test_grace_window_tolerates_missing(bh, tmp_path, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_BYOK_ENABLED", "1")
    monkeypatch.delenv("TEE_CRAFTER_BYOK_FAIL_OPEN", raising=False)
    monkeypatch.setenv("TEE_CRAFTER_BYOK_DEK_PATH", str(tmp_path / "absent.bin"))
    monkeypatch.setenv("TEE_CRAFTER_BYOK_GRACE_SECONDS", "9999")
    bh.assert_byok_healthy()  # within grace -> allowed


def test_fail_closed_wrap_refuses(bh, tmp_path, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_BYOK_ENABLED", "1")
    monkeypatch.delenv("TEE_CRAFTER_BYOK_FAIL_OPEN", raising=False)
    monkeypatch.setenv("TEE_CRAFTER_BYOK_DEK_PATH", str(tmp_path / "absent.bin"))
    monkeypatch.setenv("TEE_CRAFTER_BYOK_GRACE_SECONDS", "0")

    @bh.fail_closed_wrap
    def handler(data):
        return {"ok": True}

    out = handler({"x": 1})
    assert out["error"] == "byok_unavailable"
    assert out["policy"] == "fail_closed"
