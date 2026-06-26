"""BYOK-SEC-1: ensure wrapped DEK + HSM bearer never persist to disk.

The contract:

* ``byok.env``         — full env on disk *only* until deploy-time
                          installer relocates it to tmpfs.  Contains
                          the wrapped DEK + HSM bearer.
* ``byok.env.public``  — public env that survives on disk
                          indefinitely.  Must NOT contain any wrapped
                          key material or bearer tokens.
* ``byok.json``        — manifest on disk; the wrapped DEK + HSM
                          bearer values must be replaced with the
                          ``<redacted>`` sentinel.
* All three files must end up at mode 0600 / 0640 (best-effort —
  POSIX permission bits can't be relied on inside containers, so we
  only assert when the umask cooperated).
"""
from __future__ import annotations

import json
import os
import pathlib
import stat

import pytest

from tee_crafter.cli.commands.deploy.byok_mode import (
    ByokConfig,
    SECRET_ENV_KEYS,
    is_byok_secret_key,
    split_byok_env_secrets,
    write_byok_config,
)


def _sample_config() -> ByokConfig:
    """A representative aws-kms config carrying both kinds of secrets."""
    cfg = ByokConfig(
        provider="aws-kms",
        key_id="arn:aws:kms:us-east-2:111111111111:key/abc",
        region="us-east-2",
        unwrap="aws_nitro_recipient",
    )
    cfg.encryption_context = {"tenant": "acme"}
    cfg.allowed_measurement_sha256 = ["a" * 64]
    cfg.hsm_bearer_token = "hsm-deadbeef-bearer"
    cfg.extra = {
        "ciphertext_b64": "AAAAAAAA=" * 16,  # wrapped DEK
        "dek_sha256": "deadbeef" * 8,       # NOT a secret (just a checksum)
    }
    return cfg


# ---------------------------------------------------------------------------
# is_byok_secret_key / split_byok_env_secrets
# ---------------------------------------------------------------------------

class TestSecretKeyClassification:
    def test_explicit_secret_keys_are_secret(self):
        for key in SECRET_ENV_KEYS:
            assert is_byok_secret_key(key), key

    @pytest.mark.parametrize("public_key", [
        "TEE_CRAFTER_BYOK",
        "TEE_CRAFTER_BYOK_KEY_ID",
        "TEE_CRAFTER_BYOK_REGION",
        "TEE_CRAFTER_BYOK_UNWRAP",
        "TEE_CRAFTER_BYOK_DEK_PATH",
        "TEE_CRAFTER_BYOK_MAX_AGE",
        "TEE_CRAFTER_BYOK_ENABLED",
        "TEE_CRAFTER_BYOK_ALLOWED_MEASUREMENTS",
        "TEE_CRAFTER_BYOK_REQUIRED_CONTEXT_KEYS",
        "TEE_CRAFTER_BYOK_ENCRYPTION_CONTEXT",
        "TEE_CRAFTER_BYOK_REQUIRE_SIGNED_AUDIT",
        # an X_* extra whose name doesn't suggest a secret stays public
        "TEE_CRAFTER_BYOK_X_DEK_SHA256",
        "TEE_CRAFTER_BYOK_X_TENANT_ID",
    ])
    def test_non_secret_keys_are_public(self, public_key):
        assert not is_byok_secret_key(public_key), public_key

    @pytest.mark.parametrize("secret_key", [
        # Pattern-matched extras that look like secret material
        "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64",
        "TEE_CRAFTER_BYOK_X_HSM_BEARER",
        "TEE_CRAFTER_BYOK_X_AUTH_TOKEN",
        "TEE_CRAFTER_BYOK_X_DB_PASSWORD",
        "TEE_CRAFTER_BYOK_X_API_KEY",
        "TEE_CRAFTER_BYOK_X_CLIENT_SECRET",
        "TEE_CRAFTER_BYOK_X_PRIVATE_KEY",
        "TEE_CRAFTER_BYOK_X_VAULT_PASSPHRASE",
    ])
    def test_pattern_matched_extras_are_secret(self, secret_key):
        assert is_byok_secret_key(secret_key), secret_key

    def test_split_partitions_secrets(self):
        env = {
            "TEE_CRAFTER_BYOK": "aws-kms",
            "TEE_CRAFTER_BYOK_KEY_ID": "arn:...",
            "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64": "BBBB=",
            "TEE_CRAFTER_BYOK_X_DEK_SHA256": "deadbeef",
            "TEE_CRAFTER_BYOK_HSM_BEARER": "hsm-token",
        }
        secrets, public = split_byok_env_secrets(env)
        assert "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64" in secrets
        assert "TEE_CRAFTER_BYOK_HSM_BEARER" in secrets
        assert "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64" not in public
        assert "TEE_CRAFTER_BYOK_HSM_BEARER" not in public
        # non-secret keys stay on the public side
        assert public["TEE_CRAFTER_BYOK"] == "aws-kms"
        assert public["TEE_CRAFTER_BYOK_X_DEK_SHA256"] == "deadbeef"


# ---------------------------------------------------------------------------
# write_byok_config — round-trip with secrets
# ---------------------------------------------------------------------------

class TestWriteByokConfigSecretSplit:
    def test_secrets_only_in_byok_env_not_public(self, tmp_path):
        from tee_crafter.core.audit import build_layout as _layout
        cfg = _sample_config()
        out = write_byok_config(str(tmp_path), cfg, enabled=True)
        assert os.path.basename(out) == "byok.json"

        env_path = pathlib.Path(_layout.byok_env(str(tmp_path)))
        env_pub_path = pathlib.Path(_layout.byok_env_public(str(tmp_path)))

        env_text = env_path.read_text(encoding="utf-8")
        env_pub_text = env_pub_path.read_text(encoding="utf-8")

        # BYOK-SEC-1: the wrapped DEK ciphertext must live ONLY in
        # byok.env (which is destined for tmpfs).  byok.env.public is
        # what survives on disk after deploy and must be clean.
        assert "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64=" in env_text
        assert "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64=" not in env_pub_text
        # The HSM bearer (used by external-hsm provider) follows the
        # same rule.
        assert "TEE_CRAFTER_BYOK_HSM_BEARER=" in env_text
        assert "TEE_CRAFTER_BYOK_HSM_BEARER=" not in env_pub_text
        # The non-secret DEK fingerprint stays in BOTH so monitoring
        # can confirm the DEK identity without needing tmpfs.
        assert "TEE_CRAFTER_BYOK_X_DEK_SHA256=" in env_text
        assert "TEE_CRAFTER_BYOK_X_DEK_SHA256=" in env_pub_text
        # The key-ID / region / unwrap mode are public.
        for must in ("TEE_CRAFTER_BYOK_KEY_ID=",
                     "TEE_CRAFTER_BYOK_REGION=",
                     "TEE_CRAFTER_BYOK_UNWRAP="):
            assert must in env_pub_text, must

    def test_manifest_redacts_wrapped_dek_and_hsm_bearer(self, tmp_path):
        from tee_crafter.core.audit import build_layout as _layout
        cfg = _sample_config()
        write_byok_config(str(tmp_path), cfg, enabled=True)
        doc = json.loads(
            pathlib.Path(_layout.byok_json(str(tmp_path))).read_text(
                encoding="utf-8"))

        # The raw wrapped DEK ciphertext must NOT appear in the
        # manifest (which is mode 0600 but still disk-resident).
        raw_ct = cfg.extra["ciphertext_b64"]
        assert raw_ct not in json.dumps(doc), \
            "wrapped DEK ciphertext leaked into byok.json"
        # HSM bearer similarly.
        assert "hsm-deadbeef-bearer" not in json.dumps(doc), \
            "HSM bearer token leaked into byok.json"
        # The redaction sentinel is the on-disk fingerprint.
        assert doc["config"]["hsm_bearer_token"] == "<redacted>"
        red = doc["config"]["extra"]["ciphertext_b64"]
        assert red.startswith("<redacted:") and red.endswith("b>"), red
        # Non-secret extras still echo verbatim — they're useful for
        # operators triaging "did the right DEK ship?" without granting
        # access to the key material itself.
        assert doc["config"]["extra"]["dek_sha256"] == cfg.extra["dek_sha256"]

    def test_file_modes_are_locked_down(self, tmp_path):
        # On most CI environments umask is 022 so the explicit chmods
        # take effect; on others (containers with quirky umasks) the
        # call is best-effort.  Test only when the chmod stuck.
        from tee_crafter.core.audit import build_layout as _layout
        cfg = _sample_config()
        write_byok_config(str(tmp_path), cfg, enabled=True)
        byok_root = pathlib.Path(_layout.byok_dir(str(tmp_path)))
        for name, expected in (("byok.env", 0o600),
                                ("byok.env.public", 0o640),
                                ("byok.json", 0o600)):
            p = byok_root / name
            mode = stat.S_IMODE(p.stat().st_mode)
            assert mode == expected, (
                f"{name}: expected mode {oct(expected)}, got {oct(mode)}")

    def test_mirrors_into_app_dir(self, tmp_path):
        (tmp_path / "app").mkdir()
        cfg = _sample_config()
        write_byok_config(str(tmp_path), cfg, enabled=True)
        for name in ("byok.env", "byok.env.public", "byok.json"):
            assert (tmp_path / "app" / name).is_file(), name
