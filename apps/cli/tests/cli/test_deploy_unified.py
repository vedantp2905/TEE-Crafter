"""Tests for the unified deploy command (plan 00)."""


import click

from tee_crafter.cli.commands.deploy.deploy_helpers import validate_run_mode
from tee_crafter.cli.commands.deploy.deploy import register


class TestValidateRunMode:
    def test_neither_batch_nor_persistent_rejected(self):
        ok, _ = validate_run_mode(
            batch_mode=False,
            persistent_mode=False,
            tee_platform="tdx-azure",
            service_profile="default",
        )
        assert ok is False

    def test_sgx_requires_batch(self):
        ok, _ = validate_run_mode(
            batch_mode=False,
            persistent_mode=True,
            tee_platform="sgx-azure",
            service_profile="default",
        )
        assert ok is False

    def test_sgx_batch_ok(self):
        ok, profile = validate_run_mode(
            batch_mode=True,
            persistent_mode=False,
            tee_platform="sgx-azure",
            service_profile="default",
        )
        assert ok is True
        assert profile == "default"

    def test_persistent_bumps_profile(self):
        ok, profile = validate_run_mode(
            batch_mode=False,
            persistent_mode=True,
            tee_platform="tdx-azure",
            service_profile="default",
        )
        assert ok is True
        assert profile == "long-lived"


class TestDeployCommandSurface:
    def test_deploy_has_batch_and_persistent_flags(self):
        cmd = click.Group()
        register(cmd)
        deploy = cmd.commands["deploy"]
        param_names = {p.name for p in deploy.params}
        assert "batch_mode" in param_names
        assert "persistent_mode" in param_names
        assert "source" in param_names

    def test_no_handler_flags(self):
        cmd = click.Group()
        register(cmd)
        deploy = cmd.commands["deploy"]
        param_names = {p.name for p in deploy.params}
        assert "handler_path" not in param_names
        assert "no_llm" not in param_names

    def test_deploy_container_alias_registered(self):
        from tee_crafter.cli.commands import register_commands
        root = click.Group()
        register_commands(root)
        assert "deploy-container" in root.commands
