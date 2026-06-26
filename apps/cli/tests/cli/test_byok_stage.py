"""Tests for ``tee-crafter byok-stage`` (sister of ``siem-stage``).

We exercise the rendered remote script without actually shelling out:

  * Mode bits and ownership match BYOK-SEC-1 (0600 tmpfs, 0640 disk).
  * Secret material (wrapped DEK base64) lands ONLY in the
    ``runtime_dir/byok.env`` slice, never in the on-disk public path.
  * Nitro / SGX are refused (their BYOK ships inside the build artifact).
  * The "no secrets in config" guard fires before we render anything.
  * ``--no-restart`` flips off the systemctl try-restart block.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from tee_crafter.cli.commands.byok_stage import (
    _build_remote_command,
    register,
)


def _decode_b64(script: str, *, kind: str) -> str:
    """Pull either the secret or public base64 blob out of the rendered
    remote script and decode it.  ``kind`` is "byok.env" or
    "byok.env.public"."""
    needle = "byok.env" if kind == "byok.env" else "byok.env.public"
    for line in script.splitlines():
        if needle in line and "base64 -d" in line and "echo " in line:
            payload = line.split("echo ", 1)[1].split(" |", 1)[0].strip()
            return base64.b64decode(payload).decode("utf-8")
    raise AssertionError(f"No base64 blob for {kind!r} in script")


def test_build_remote_command_mode_bits_and_ownership():
    """BYOK-SEC-1: tmpfs slice is 0600, disk slice is 0640, both owned
    by ``tee_enclave``."""
    secret = {"TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64": "AAAA"}
    public = {"TEE_CRAFTER_BYOK_KEY_ID": "arn:aws:kms:us-east-2:1:key/x"}
    script = _build_remote_command(
        tee_platform="snp-aws", secret_env=secret, public_env=public,
        restart_workload=False,
    )
    # tmpfs dir: 0700 owned by tee_enclave (defensive — siem may pre-create)
    assert "install -d -m 0700 -o tee_enclave -g tee_enclave /run/tee-crafter-snp-aws" in script
    # secret file: 0600 owned by tee_enclave
    assert "chmod 0600 /run/tee-crafter-snp-aws/byok.env" in script
    assert "chown tee_enclave:tee_enclave /run/tee-crafter-snp-aws/byok.env" in script
    # public file: 0640 owned by tee_enclave (readable by group)
    assert "chmod 0640 /opt/tee-crafter-snp/app/byok.env.public" in script
    assert "chown tee_enclave:tee_enclave /opt/tee-crafter-snp/app/byok.env.public" in script


def test_secret_blob_never_lands_in_public_half():
    """The wrapped-DEK ciphertext (TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64)
    is a SECRET_ENV_KEY — it must only appear in the byok.env (tmpfs)
    payload, never in byok.env.public (disk)."""
    secret_value = "WRAPPED-DEK-MATERIAL-DO-NOT-LEAK"
    secret = {"TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64": secret_value,
              "TEE_CRAFTER_BYOK_HSM_BEARER": "bearer-token-also-secret"}
    public = {"TEE_CRAFTER_BYOK_KEY_ID": "arn:aws:kms:us-east-2:1:key/x",
              "TEE_CRAFTER_BYOK": "aws-kms",
              "TEE_CRAFTER_BYOK_ENABLED": "1"}
    script = _build_remote_command(
        tee_platform="tdx-gcp", secret_env=secret, public_env=public,
        restart_workload=False,
    )

    secret_blob = _decode_b64(script, kind="byok.env")
    public_blob = _decode_b64(script, kind="byok.env.public")

    assert secret_value in secret_blob
    assert "bearer-token-also-secret" in secret_blob
    # The public blob must not contain ANY of the secret values.
    assert secret_value not in public_blob
    assert "bearer-token-also-secret" not in public_blob
    # And it must contain the non-secret keys.
    assert "TEE_CRAFTER_BYOK_KEY_ID=" in public_blob
    assert "TEE_CRAFTER_BYOK_ENABLED=1" in public_blob


def test_stale_on_disk_secret_is_shredded():
    """If a previous full-deploy left a byok.env on disk (pre-tmpfs
    install), the remote script shreds it so the secret half never
    persists across rotations."""
    script = _build_remote_command(
        tee_platform="snp-azure",
        secret_env={"TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64": "x"},
        public_env={"TEE_CRAFTER_BYOK_ENABLED": "1"},
        restart_workload=False,
    )
    assert "shred -u /opt/tee-crafter-snp/app/byok.env" in script


def test_restart_flag_toggles_systemctl_block():
    """``--no-restart`` (i.e. restart_workload=False) omits the
    try-restart loop entirely."""
    secret = {"TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64": "x"}
    public = {"TEE_CRAFTER_BYOK_ENABLED": "1"}
    on = _build_remote_command(tee_platform="gpu-cc-aws",
                                secret_env=secret, public_env=public,
                                restart_workload=True)
    off = _build_remote_command(tee_platform="gpu-cc-aws",
                                 secret_env=secret, public_env=public,
                                 restart_workload=False)
    assert "systemctl try-restart" in on
    assert "systemctl try-restart" not in off


def test_nitro_refused():
    """BYOK on Nitro ships inside the EIF; re-staging from outside is
    conceptually wrong and the command must refuse."""
    with pytest.raises(click.ClickException) as exc:
        _build_remote_command(
            tee_platform="nitro-aws",
            secret_env={"TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64": "x"},
            public_env={"TEE_CRAFTER_BYOK_ENABLED": "1"},
            restart_workload=False,
        )
    assert "ships inside the build artifact" in exc.value.message


def test_sgx_refused():
    """Same for SGX (Gramine manifest carries BYOK config)."""
    with pytest.raises(click.ClickException) as exc:
        _build_remote_command(
            tee_platform="sgx-azure",
            secret_env={"TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64": "x"},
            public_env={"TEE_CRAFTER_BYOK_ENABLED": "1"},
            restart_workload=False,
        )
    assert "ships inside the build artifact" in exc.value.message


def test_cli_refuses_empty_secret_config(tmp_path: Path):
    """A byok-config that produces zero secret keys is almost
    certainly an operator mistake — refuse with a useful error.

    We hand it a config with provider=aws-kms but NO extra.ciphertext_b64
    and NO hsm_bearer_token, which yields an empty secret_env."""
    cfg = {
        "provider": "aws-kms",
        "key_id": "arn:aws:kms:us-east-2:123456789012:key/abc",
        "region": "us-east-2",
        "label": "test",
        "unwrap": "direct_bytes",
        "encryption_context": {"tenant": "t", "env": "e"},
        "policy": {
            "max_attestation_age_seconds": 300,
            "allowed_measurement_sha256": [],
            "require_encryption_context_keys": ["tenant", "env"],
            "require_signed_audit": True,
        },
        "extra": {},  # <- no ciphertext_b64, the secret-producing field
    }
    cfg_path = tmp_path / "byok.json"
    cfg_path.write_text(json.dumps(cfg))

    @click.group()
    def cli():
        pass
    register(cli)

    runner = CliRunner()
    result = runner.invoke(cli, [
        "byok-stage",
        "--platform", "snp-aws",
        "--byok-config", str(cfg_path),
        "--instance-id", "i-doesnotmatter",
        "--dry-run",
    ])
    assert result.exit_code != 0, result.output
    assert "no secret keys" in result.output.lower() \
        or "no wrapped DEK" in result.output


def test_cli_dry_run_emits_script_with_secrets_marker(tmp_path: Path):
    """A well-formed config with a wrapped DEK should render a script
    that mentions the BYOK-SEC-1 marker and includes the wrapped
    payload in base64.  --dry-run prints it; in normal mode the
    script is sent over SSM/SSH instead."""
    cfg = {
        "provider": "aws-kms",
        "key_id": "arn:aws:kms:us-east-2:123456789012:key/abc",
        "region": "us-east-2",
        "label": "test",
        "unwrap": "aws_nitro_recipient",
        "encryption_context": {"tenant": "t", "env": "e"},
        "policy": {
            "max_attestation_age_seconds": 300,
            "allowed_measurement_sha256": [],
            "require_encryption_context_keys": ["tenant", "env"],
            "require_signed_audit": True,
        },
        "extra": {
            "ciphertext_b64": "AAECAwQFBgcICQ==",
        },
    }
    cfg_path = tmp_path / "byok.json"
    cfg_path.write_text(json.dumps(cfg))

    @click.group()
    def cli():
        pass
    register(cli)

    runner = CliRunner()
    result = runner.invoke(cli, [
        "byok-stage",
        "--platform", "snp-aws",
        "--byok-config", str(cfg_path),
        "--instance-id", "i-test",
        "--dry-run",
    ])
    assert result.exit_code == 0, result.output
    # The script should contain the BYOK-SEC-1 stable marker.
    assert "BYOK-SEC-1: byok.env re-staged" in result.output
    # And the secret-half mode bit.
    assert "chmod 0600" in result.output
