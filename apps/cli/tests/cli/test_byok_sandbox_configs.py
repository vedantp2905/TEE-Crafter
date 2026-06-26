"""Lock-in test for generated ``byok-sandbox/configs/byok-*.json``.

The sandbox configs are the entry-point for BYOK deploys — if they go
out of sync with :class:`ByokConfig` they break the documented
quick-start.  This test proves each loads cleanly, validates, and
round-trips through ``write_byok_config`` into a build directory.

The files themselves are *not* in git: ``extra.ciphertext_b64`` is a DEK
wrapped by the operator's own KMS/Key Vault key, so the configs only exist
after ``byok-sandbox/<cloud>/create_*_key.py`` and ``wrap_dek.py`` have run
against real cloud resources.  Those cases carry ``@pytest.mark.integration``;
the rest of this module runs offline.
"""
from __future__ import annotations

import json
import os
import pathlib

import pytest

from tee_crafter.cli.commands.deploy.byok_mode import (
    build_byok_config, write_byok_config,
)


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SANDBOX = _REPO_ROOT / "byok-sandbox" / "configs"


@pytest.mark.integration
@pytest.mark.parametrize("name,provider,unwrap", [
    ("byok-nitro-aws.json", "aws-kms", "aws_nitro_recipient"),
    ("byok-snp-aws.json", "aws-kms", "direct_bytes"),
    ("byok-gcp.json", "gcp-kms", "direct_bytes"),
])
def test_committed_config_loads_and_round_trips(tmp_path, name, provider, unwrap):
    path = _SANDBOX / name
    assert path.is_file(), f"missing config: {path}"
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw.get("provider") == provider
    assert raw.get("unwrap") == unwrap
    assert (raw.get("extra") or {}).get("ciphertext_b64"), (
        f"{name}: run wrap_dek.py — extra.ciphertext_b64 is empty"
    )

    cfg = build_byok_config(provider=provider, raw_policy_path=str(path))
    errs = cfg.validate()
    assert errs == [], f"{name} did not validate: {errs}"

    build_dir = tmp_path / "build"
    build_dir.mkdir()
    out_path = write_byok_config(str(build_dir), cfg, enabled=True)
    assert os.path.isfile(out_path)
    from tee_crafter.core.audit import build_layout as _layout
    env_path = _layout.byok_env(str(build_dir))
    env_pub_path = _layout.byok_env_public(str(build_dir))
    assert os.path.isfile(env_path)
    assert os.path.isfile(env_pub_path), "BYOK-SEC-1: byok.env.public must exist"
    env_text = pathlib.Path(env_path).read_text(encoding="utf-8")
    env_pub_text = pathlib.Path(env_pub_path).read_text(encoding="utf-8")
    assert "TEE_CRAFTER_BYOK_ENABLED=1" in env_text
    assert f"TEE_CRAFTER_BYOK={provider}" in env_text
    assert "TEE_CRAFTER_BYOK_ENABLED=1" in env_pub_text
    assert "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64=" in env_text
    assert "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64=" not in env_pub_text, (
        "wrapped DEK must never appear in byok.env.public (BYOK-SEC-1)"
    )


@pytest.mark.integration
def test_snp_aws_metadata_records_platform():
    raw = json.loads((_SANDBOX / "byok-snp-aws.json").read_text(encoding="utf-8"))
    assert raw["_metadata"]["tee_platform"] == "snp-aws"
    assert raw["unwrap"] == "direct_bytes"


def test_export_byok_tf_vars_snp_aws_sets_kms_arn(monkeypatch):
    """``--byok-config`` on snp-aws must auto-export
    ``TF_VAR_byok_aws_kms_arn`` so the terraform IAM block attaches a
    kms:Decrypt grant.  Without it DH-016 FAILs and the in-TEE bootstrap
    cannot unwrap the wrapped DEK (the regression we hit on the
    ``20260520_003611_cf8478fd`` build).
    """
    from tee_crafter.cli.commands.deploy.byok_mode import (
        ByokConfig, export_byok_tf_vars,
    )
    monkeypatch.delenv("TF_VAR_byok_aws_kms_arn", raising=False)
    cfg = ByokConfig(provider="aws-kms",
                     key_id="arn:aws:kms:us-east-2:123:key/abc",
                     region="us-east-2", unwrap="direct_bytes")
    exported = export_byok_tf_vars(cfg, "snp-aws")
    assert exported == {"TF_VAR_byok_aws_kms_arn":
                        "arn:aws:kms:us-east-2:123:key/abc"}
    assert (os.environ["TF_VAR_byok_aws_kms_arn"]
            == "arn:aws:kms:us-east-2:123:key/abc")


def test_export_byok_tf_vars_nitro_does_not_export(monkeypatch):
    """Nitro decrypts inside the enclave via kmstool-enclave with the
    Recipient attestation document — the *instance role* does not need
    kms:Decrypt, so the helper must leave ``TF_VAR_byok_aws_kms_arn``
    unset.  Setting it on Nitro would mistakenly broaden the host's IAM
    surface.
    """
    from tee_crafter.cli.commands.deploy.byok_mode import (
        ByokConfig, export_byok_tf_vars,
    )
    monkeypatch.delenv("TF_VAR_byok_aws_kms_arn", raising=False)
    cfg = ByokConfig(provider="aws-kms",
                     key_id="arn:aws:kms:us-east-2:123:key/abc",
                     region="us-east-2", unwrap="aws_nitro_recipient")
    exported = export_byok_tf_vars(cfg, "nitro-aws")
    assert exported == {}
    assert "TF_VAR_byok_aws_kms_arn" not in os.environ


def test_export_byok_tf_vars_respects_operator_value(monkeypatch):
    """Operator-supplied env value must never be silently overwritten."""
    from tee_crafter.cli.commands.deploy.byok_mode import (
        ByokConfig, export_byok_tf_vars,
    )
    monkeypatch.setenv("TF_VAR_byok_aws_kms_arn",
                       "arn:aws:kms:us-east-2:999:key/operator")
    cfg = ByokConfig(provider="aws-kms",
                     key_id="arn:aws:kms:us-east-2:111:key/different",
                     region="us-east-2", unwrap="direct_bytes")
    exported = export_byok_tf_vars(cfg, "gpu-cc-aws")
    assert exported == {}
    assert (os.environ["TF_VAR_byok_aws_kms_arn"]
            == "arn:aws:kms:us-east-2:999:key/operator")


def test_export_byok_tf_vars_no_op_when_disabled(monkeypatch):
    from tee_crafter.cli.commands.deploy.byok_mode import (
        ByokConfig, export_byok_tf_vars,
    )
    monkeypatch.delenv("TF_VAR_byok_aws_kms_arn", raising=False)
    assert export_byok_tf_vars(ByokConfig(provider="none"), "snp-aws") == {}
    assert "TF_VAR_byok_aws_kms_arn" not in os.environ
