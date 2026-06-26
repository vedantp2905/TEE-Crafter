"""Options whose gating flag is absent must be rejected, not ignored.

``--siem-config`` without ``--siem``, ``--byok-config`` without ``--byok``,
``--input-dir`` / ``--batch-timeout`` without ``--batch``, and ``--container-cmd``
(which nothing has ever read) were all accepted, parsed, and then dropped.  The
worst of them is ``--siem-config``: the deploy succeeds, no attestation events
are ever exported, and the operator finds out days later from an empty SIEM
index.

These assert on ``exit_code`` — same contract as ``test_deploy_exit_codes.py``.
"""
from __future__ import annotations

import json
from pathlib import Path

import click
from click.testing import CliRunner


def _cli():
    """A Click group with only ``deploy`` registered (no Docker re-exec)."""
    from tee_crafter.cli.commands.deploy.deploy import register
    group = click.Group()
    register(group)
    return group


def _source(tmp_path: Path) -> str:
    src = tmp_path / "app"
    src.mkdir()
    (src / "Dockerfile").write_text("FROM alpine\nCMD true\n")
    return str(src)


def _invoke(tmp_path: Path, *args: str):
    return CliRunner().invoke(_cli(), ["deploy", "--source", _source(tmp_path), *args])


def _json_file(tmp_path: Path, name: str, doc: dict) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return str(path)


class TestUngatedOptionsAreRejected:
    def test_siem_config_without_siem_provider(self, tmp_path):
        cfg = _json_file(tmp_path, "siem.json",
                         {"provider": "splunk-hec", "endpoint": "https://x",
                          "token": "t"})
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--siem-config", cfg)
        assert r.exit_code != 0, r.output
        assert "--siem is 'none'" in r.output

    def test_byok_config_without_byok_provider(self, tmp_path):
        cfg = _json_file(tmp_path, "byok.json",
                         {"provider": "aws-kms", "key_id": "arn:aws:kms:x"})
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--byok-config", cfg)
        assert r.exit_code != 0, r.output
        assert "--byok is 'none'" in r.output

    def test_container_cmd_is_rejected(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--container-cmd", "python -m app")
        assert r.exit_code != 0, r.output
        assert "--container-cmd is not supported" in r.output

    def test_container_cmd_is_hidden_from_help(self):
        result = CliRunner().invoke(_cli(), ["deploy", "--help"])
        assert result.exit_code == 0, result.output
        assert "--container-cmd" not in result.output

    def test_batch_timeout_with_persistent(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--persistent",
                    "--batch-timeout", "60")
        assert r.exit_code != 0, r.output
        assert "--batch-timeout 60 requires --batch" in r.output

    def test_input_dir_with_persistent(self, tmp_path):
        indir = tmp_path / "inputs"
        indir.mkdir()
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--persistent",
                    "--input-dir", str(indir))
        assert r.exit_code != 0, r.output
        assert "requires --batch" in r.output


class TestGatedOptionsStillAccepted:
    """The gate must not fire on the combinations that are actually valid."""

    def test_default_batch_timeout_with_persistent_is_fine(self, tmp_path):
        from tee_crafter.cli.commands.deploy.deploy_helpers import (
            DEFAULT_BATCH_TIMEOUT, validate_flag_dependencies,
        )
        # No exception.
        validate_flag_dependencies(
            batch_mode=False, persistent_mode=True, container_cmd=None,
            batch_timeout=DEFAULT_BATCH_TIMEOUT, input_dir=None,
            siem_provider="none", siem_config_path=None,
            byok_provider="none", byok_policy_path=None,
        )

    def test_batch_timeout_and_input_dir_with_batch(self, tmp_path):
        from tee_crafter.cli.commands.deploy.deploy_helpers import (
            validate_flag_dependencies,
        )
        validate_flag_dependencies(
            batch_mode=True, persistent_mode=False, container_cmd=None,
            batch_timeout=60, input_dir="/tmp/in",
            siem_provider="none", siem_config_path=None,
            byok_provider="none", byok_policy_path=None,
        )

    def test_provider_plus_config_pairs_pass(self):
        from tee_crafter.cli.commands.deploy.deploy_helpers import (
            validate_flag_dependencies,
        )
        validate_flag_dependencies(
            batch_mode=True, persistent_mode=False, container_cmd=None,
            batch_timeout=3600, input_dir=None,
            siem_provider="splunk-hec", siem_config_path="/tmp/siem.json",
            byok_provider="aws-kms", byok_policy_path="/tmp/byok.json",
        )


class TestEgressAllowStillGated:
    """Pre-existing gate (``decide_workload_egress``) — must keep firing."""

    def test_egress_allow_with_default_deny(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--egress-allow", "db.example.com:5432")
        assert r.exit_code != 0, r.output
        assert "--egress-allow requires --egress-mode" in r.output
