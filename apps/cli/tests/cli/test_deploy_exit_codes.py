"""Every deploy-surface failure path must exit non-zero.

Before this file, the only non-zero exit anywhere in the deploy surface was
the ``click.Abort()`` after Ctrl+C.  Validation failures printed a red panel
and then ``return``-ed from the Click callback, which Click treats as success
— so a run that never provisioned anything, or provisioned an instance and
then failed, both reported rc=0.  CI could not tell a good deploy from a bad
one, which is what let the rest of the findings in this batch survive.

The pre-existing guard tests assert on ``result.output`` only (see
``test_batch_mode.TestCliGuards``); these assert on ``result.exit_code``.
"""
from __future__ import annotations

import json
from pathlib import Path

import click
import pytest
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


class TestRunModeExitCodes:
    def test_batch_and_persistent_together(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch", "--persistent")
        assert r.exit_code != 0, r.output

    def test_neither_batch_nor_persistent(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure")
        assert r.exit_code != 0, r.output

    def test_sgx_persistent(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "sgx-azure", "--persistent")
        assert r.exit_code != 0, r.output


class TestFlagCombinationExitCodes:
    def test_teardown_without_deploy(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch", "--teardown")
        assert r.exit_code != 0, r.output
        assert "--teardown requires --deploy" in r.output

    def test_auto_approve_without_deploy(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch", "--auto-approve")
        assert r.exit_code != 0, r.output
        assert "--auto-approve requires --deploy" in r.output

    def test_unknown_instance_type(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--instance-type", "Standard_NOT_A_REAL_SIZE")
        assert r.exit_code != 0, r.output
        assert "instance-type" in r.output.lower()

    def test_service_profile_with_batch(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--service-profile", "long-lived")
        assert r.exit_code != 0, r.output
        assert "mutually exclusive" in r.output


class TestConfigValidationExitCodes:
    def test_siem_provider_without_config(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--siem", "splunk-hec")
        assert r.exit_code != 0, r.output
        assert "--siem" in r.output

    def test_malformed_siem_config(self, tmp_path):
        cfg = tmp_path / "siem.json"
        # splunk-hec with no endpoint / token -> SiemConfig.validate() errors.
        cfg.write_text(json.dumps({"provider": "splunk-hec"}))
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--siem", "splunk-hec", "--siem-config", str(cfg))
        assert r.exit_code != 0, r.output

    def test_byok_provider_without_config(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--byok", "aws-kms")
        assert r.exit_code != 0, r.output

    def test_malformed_secrets_env(self, tmp_path):
        env = tmp_path / "bad.env"
        env.write_text("this line has no equals sign\n")
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--secrets-env", str(env))
        assert r.exit_code != 0, r.output
        assert "--secrets-env" in r.output


class TestEgressExitCodes:
    def test_egress_allow_without_mode(self, tmp_path):
        """``--egress-allow`` with the default ``deny`` mode is contradictory."""
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--egress-allow", "10.0.0.5:5432")
        assert r.exit_code != 0, r.output
        assert "--egress-allow" in r.output

    def test_malformed_egress_spec(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--egress-mode", "vpc", "--egress-allow", "no-port-here")
        assert r.exit_code != 0, r.output

    def test_egress_port_out_of_range(self, tmp_path):
        r = _invoke(tmp_path, "--tee-platform", "tdx-azure", "--batch",
                    "--egress-mode", "vpc", "--egress-allow", "10.0.0.5:99999")
        assert r.exit_code != 0, r.output


class TestBatchResultIsHonoured:
    """``BatchResult(success=False)`` must reach the process exit code.

    Both callers discarded the return value even though the in-code comment
    claimed it "makes the CLI exit non-zero" — so a batch whose container
    never ran reported success.
    """

    def _run_to_dispatch(self, tmp_path, monkeypatch, batch_result):
        import tee_crafter.cli.commands.deploy.deploy_container as dc

        build_dir = tmp_path / "build"
        (build_dir / "app").mkdir(parents=True)
        (build_dir / "user_container.tar").write_bytes(b"FAKE")

        monkeypatch.setattr(
            dc, "run_container_phases",
            lambda *a, **kw: (str(build_dir), "[container mode: test]"))
        monkeypatch.setattr(
            "tee_crafter.cli.cloud_auth.validate_required_creds",
            lambda *a, **kw: None)
        monkeypatch.setattr(
            "tee_crafter.cli.commands.deploy.batch_dispatch.dispatch_batch_container",
            lambda **kw: batch_result)
        return CliRunner().invoke(_cli(), [
            "deploy", "--source", _source(tmp_path),
            "--tee-platform", "tdx-azure", "--batch",
        ])

    def test_failed_batch_exits_non_zero(self, tmp_path, monkeypatch):
        from tee_crafter.cli.commands.deploy.batch import BatchResult
        r = self._run_to_dispatch(
            tmp_path, monkeypatch,
            BatchResult(False, message="batch dispatch failed: boom"))
        assert r.exit_code != 0, r.output
        assert "boom" in r.output

    def test_successful_batch_exits_zero(self, tmp_path, monkeypatch):
        from tee_crafter.cli.commands.deploy.batch import BatchResult
        r = self._run_to_dispatch(
            tmp_path, monkeypatch, BatchResult(True, message="ok"))
        assert r.exit_code == 0, r.output

    def test_staged_only_exits_zero(self, tmp_path, monkeypatch):
        """``None`` is the legitimate "staged, --deploy not passed" result."""
        r = self._run_to_dispatch(tmp_path, monkeypatch, None)
        assert r.exit_code == 0, r.output


class TestDestroyExitCode:
    def _destroy_cli(self):
        from tee_crafter.cli.commands.destroy import register
        group = click.Group()
        register(group)
        return group

    def test_failed_destroy_exits_non_zero(self, tmp_path, monkeypatch):
        """``tee-crafter destroy`` printed "✗ Destroy failed" and exited 0."""
        monkeypatch.setattr(
            "tee_crafter.cli.commands.destroy.cleanup_resources",
            lambda *a, **kw: False)
        r = CliRunner().invoke(
            self._destroy_cli(), ["destroy", "--build-dir", str(tmp_path)])
        assert r.exit_code != 0, r.output
        assert "destroy failed" in r.output.lower()

    def test_successful_destroy_exits_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "tee_crafter.cli.commands.destroy.cleanup_resources",
            lambda *a, **kw: True)
        r = CliRunner().invoke(
            self._destroy_cli(), ["destroy", "--build-dir", str(tmp_path)])
        assert r.exit_code == 0, r.output


class TestDeployFromBuildIntegrityExitCode:
    """``deploy-from-build`` checked only that app.eif and main.tf exist."""

    def _cli(self):
        from tee_crafter.cli.commands.deploy.from_build import register
        group = click.Group()
        register(group)
        return group

    def _build_dir(self, tmp_path: Path) -> Path:
        d = tmp_path / "build_x"
        d.mkdir()
        (d / "app.eif").write_bytes(b"NOT-A-REAL-EIF")
        (d / "main.tf").write_text("# tf\n")
        # The resume manifest names the platform.  Without it the command stops
        # at the "which platform is this?" gate instead of reaching the
        # integrity check these tests are about.
        (d / "deploy_manifest.json").write_text(json.dumps({
            "manifest_version": 1, "tee_platform": "nitro-aws",
            "cpu": 2, "ram": 2048, "measurements": {}, "custom_ami": "",
            "tf_vars": {},
        }))
        return d

    def test_missing_provenance_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "tee_crafter.cli.cloud_auth.validate_required_creds",
            lambda *a, **kw: None)
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI", "1")
        r = CliRunner().invoke(self._cli(), [
            "deploy-from-build", "--build-dir", str(self._build_dir(tmp_path)),
        ])
        assert r.exit_code != 0, r.output
        assert "build_provenance.json" in r.output

    def test_tampered_provenance_is_refused(self, tmp_path, monkeypatch):
        from tee_crafter.cli.commands.deploy.from_build import verify_build_integrity
        from tee_crafter.core.audit import BuildAuditTrail, build_layout as layout

        # A per-build keypair is enough to exercise the verifier; production
        # runs use the long-lived key from ~/.tee-crafter.
        monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", "1")
        build_dir = self._build_dir(tmp_path)
        trail = BuildAuditTrail()
        trail.set_metadata(pipeline_version="test", build_dir=str(build_dir))
        trail.record("Phase 1", "step", "pass")
        trail.save(str(build_dir))

        prov = Path(layout.resolve_provenance_json(str(build_dir)))
        doc = json.loads(prov.read_text())
        doc["entries"][0]["step"] = "tampered"
        prov.write_text(json.dumps(doc))

        with pytest.raises(click.ClickException) as exc:
            verify_build_integrity(str(build_dir), BuildAuditTrail())
        assert "failed integrity verification" in str(exc.value.message)

    def test_intact_provenance_passes(self, tmp_path, monkeypatch):
        from tee_crafter.cli.commands.deploy.from_build import verify_build_integrity
        from tee_crafter.core.audit import BuildAuditTrail

        monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", "1")
        build_dir = self._build_dir(tmp_path)
        trail = BuildAuditTrail()
        trail.set_metadata(pipeline_version="test", build_dir=str(build_dir))
        trail.record("Phase 1", "step", "pass")
        trail.save(str(build_dir))

        # No exception == verified.
        verify_build_integrity(str(build_dir), BuildAuditTrail())
