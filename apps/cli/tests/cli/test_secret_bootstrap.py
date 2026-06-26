"""Tests for the CVM host secret-bootstrap oneshot entry."""
from __future__ import annotations

import importlib.util
import os

import pytest

_SB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "tee_crafter",
    "templates", "common", "tee_crafter_secret_bootstrap.py",
)


@pytest.fixture()
def sb(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("secret_bootstrap_under_test", _SB_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Redirect the tmpfs target into the test sandbox.
    monkeypatch.setattr(mod, "APP_ENV_PATH", str(tmp_path / "run" / "app.env"))
    return mod


def _clear_byok(monkeypatch):
    for k in ("TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64", "TEE_CRAFTER_BYOK_ENABLED",
              "TEE_CRAFTER_SECRETS_FAIL_OPEN"):
        monkeypatch.delenv(k, raising=False)


def test_noop_ensures_app_env(sb, monkeypatch):
    _clear_byok(monkeypatch)
    monkeypatch.setattr(sb, "_staged_app_env", lambda: "/does/not/exist")
    assert sb.main() == 0
    assert os.path.isfile(sb.APP_ENV_PATH)


def test_baked_env_copied(sb, tmp_path, monkeypatch):
    _clear_byok(monkeypatch)
    staged = tmp_path / "app.env"
    staged.write_text("ENVIRONMENT=production\nPORT=8080\n")
    monkeypatch.setattr(sb, "_staged_app_env", lambda: str(staged))
    assert sb.main() == 0
    delivered = open(sb.APP_ENV_PATH).read()
    assert "ENVIRONMENT=production" in delivered


def test_empty_baked_env_not_copied(sb, tmp_path, monkeypatch):
    _clear_byok(monkeypatch)
    staged = tmp_path / "app.env"
    staged.write_text("# only a comment\n")
    monkeypatch.setattr(sb, "_staged_app_env", lambda: str(staged))
    assert sb.main() == 0
    # File exists (ensured) but carries no real vars.
    assert not sb._has_content(sb.APP_ENV_PATH)


def test_byok_enabled_unknown_platform_fail_closed(sb, monkeypatch):
    _clear_byok(monkeypatch)
    monkeypatch.setenv("TEE_CRAFTER_BYOK_ENABLED", "1")
    monkeypatch.setattr(sb, "_platform", lambda: "nitro-aws")  # no host provider
    monkeypatch.setattr(sb, "_staged_app_env", lambda: "/does/not/exist")
    assert sb.main() == 1  # fail-closed


def test_byok_enabled_fail_open_hatch(sb, monkeypatch):
    _clear_byok(monkeypatch)
    monkeypatch.setenv("TEE_CRAFTER_BYOK_ENABLED", "1")
    monkeypatch.setenv("TEE_CRAFTER_SECRETS_FAIL_OPEN", "1")
    monkeypatch.setattr(sb, "_platform", lambda: "nitro-aws")
    monkeypatch.setattr(sb, "_staged_app_env", lambda: "/does/not/exist")
    assert sb.main() == 0  # hatch downgrades to warning
