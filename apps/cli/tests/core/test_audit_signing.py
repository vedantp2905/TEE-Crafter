"""Tests for the long-lived provenance signing flow (G-1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.audit.signing import (
    ProvenanceSigningError,
    generate_keypair_pem,
    load_signing_key,
    public_key_fingerprint,
)


_ENV_KEYS = (
    "TEE_CRAFTER_PROVENANCE_SIGNING_KEY",
    "TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE",
    "TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL",
)


@pytest.fixture(autouse=True)
def _clear_signing_env(monkeypatch, tmp_path):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(
        "tee_crafter.core.audit.signing._DEFAULT_KEY_PATH",
        tmp_path / "no-such.pem",
    )
    yield


class TestLoadSigningKey:
    def test_refuses_without_key_or_ephemeral_opt_in(self):
        with pytest.raises(ProvenanceSigningError):
            load_signing_key()

    def test_ephemeral_when_opt_in(self, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", "1")
        loaded = load_signing_key()
        assert loaded.kind == "ephemeral"
        assert loaded.source.startswith("ephemeral:")

    def test_env_pem_takes_precedence(self, monkeypatch):
        priv_pem, _pub_pem, _fpr = generate_keypair_pem()
        monkeypatch.setenv(
            "TEE_CRAFTER_PROVENANCE_SIGNING_KEY", priv_pem.decode("ascii"),
        )
        loaded = load_signing_key()
        assert loaded.kind == "longlived"
        assert "TEE_CRAFTER_PROVENANCE_SIGNING_KEY" in loaded.source

    def test_env_path(self, monkeypatch, tmp_path):
        priv_pem, _pub_pem, _fpr = generate_keypair_pem()
        key_path = tmp_path / "audit.pem"
        key_path.write_bytes(priv_pem)
        monkeypatch.setenv(
            "TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE", str(key_path),
        )
        loaded = load_signing_key()
        assert loaded.kind == "longlived"
        assert str(key_path) in loaded.source

    def test_default_path_pickup(self, monkeypatch, tmp_path):
        priv_pem, _pub_pem, _fpr = generate_keypair_pem()
        key_path = tmp_path / "default.pem"
        key_path.write_bytes(priv_pem)
        monkeypatch.setattr(
            "tee_crafter.core.audit.signing._DEFAULT_KEY_PATH", key_path,
        )
        loaded = load_signing_key()
        assert loaded.kind == "longlived"
        assert str(key_path) in loaded.source

    def test_corrupt_env_pem_falls_through_to_error(self, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_SIGNING_KEY", "not a pem")
        with pytest.raises(ProvenanceSigningError):
            load_signing_key()


class TestFingerprint:
    def test_fingerprint_stable_across_calls(self):
        priv_pem, _pub_pem, fpr = generate_keypair_pem()
        from cryptography.hazmat.primitives import serialization

        priv = serialization.load_pem_private_key(priv_pem, password=None)
        again = public_key_fingerprint(priv.public_key())
        assert again == fpr
        assert len(fpr) == 64


class TestSaveAndVerify:
    def _write_audit(self, tmp_path: Path) -> Path:
        trail = BuildAuditTrail()
        trail.record("Build", "step1", "pass")
        trail.record("Build", "step2", "pass")
        return Path(trail.save(str(tmp_path)))

    def test_save_emits_longlived_sidecars(self, tmp_path, monkeypatch):
        priv_pem, _pub_pem, expected_fpr = generate_keypair_pem()
        monkeypatch.setenv(
            "TEE_CRAFTER_PROVENANCE_SIGNING_KEY", priv_pem.decode("ascii"),
        )
        path = self._write_audit(tmp_path)
        sig = path.parent / "build_provenance.sig"
        pub = path.parent / "build_provenance.pub"
        fpr = path.parent / "build_provenance.pub.sha256"
        kind = path.parent / "build_provenance.key_kind.txt"
        assert sig.is_file() and pub.is_file()
        assert fpr.is_file() and kind.is_file()
        assert fpr.read_text().strip() == expected_fpr
        assert kind.read_text().splitlines()[0] == "longlived"

    def test_save_emits_ephemeral_sidecars(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", "1")
        path = self._write_audit(tmp_path)
        kind = path.parent / "build_provenance.key_kind.txt"
        assert kind.read_text().splitlines()[0] == "ephemeral"

    def test_verify_signature_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", "1")
        path = self._write_audit(tmp_path)
        ok, reason = BuildAuditTrail.verify_signature(str(path))
        assert ok, reason

    def test_verify_with_pinned_fingerprint(self, tmp_path, monkeypatch):
        priv_pem, _pub_pem, expected_fpr = generate_keypair_pem()
        monkeypatch.setenv(
            "TEE_CRAFTER_PROVENANCE_SIGNING_KEY", priv_pem.decode("ascii"),
        )
        path = self._write_audit(tmp_path)
        ok, reason = BuildAuditTrail.verify_signature(
            str(path),
            pinned_pubkey_sha256=expected_fpr,
            require_longlived=True,
        )
        assert ok, reason

    def test_pinned_fingerprint_mismatch_fails(self, tmp_path, monkeypatch):
        priv_pem, _pub_pem, _fpr = generate_keypair_pem()
        monkeypatch.setenv(
            "TEE_CRAFTER_PROVENANCE_SIGNING_KEY", priv_pem.decode("ascii"),
        )
        path = self._write_audit(tmp_path)
        ok, reason = BuildAuditTrail.verify_signature(
            str(path), pinned_pubkey_sha256="0" * 64,
        )
        assert not ok
        assert "fingerprint mismatch" in reason

    def test_require_longlived_blocks_ephemeral(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", "1")
        path = self._write_audit(tmp_path)
        ok, reason = BuildAuditTrail.verify_signature(
            str(path), require_longlived=True,
        )
        assert not ok
        assert "ephemeral" in reason or "longlived" in reason
