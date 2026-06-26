"""Tests for cli/main.py: CLI group registration, Docker helpers."""

from pathlib import Path

import pytest


from tee_crafter.cli.main import (
    _docker_image,
    _package_root,
    _should_exec_in_docker,
    _workspace_root,
    cli,
)


class TestPackageRoot:
    def test_returns_path(self):
        root = _package_root()
        assert isinstance(root, Path)

    def test_is_directory(self):
        root = _package_root()
        assert root.is_dir()

    def test_points_at_cli_package(self):
        # _package_root() must contain the CLI Dockerfiles + src/ so it can
        # serve as the Docker build context.
        root = _package_root()
        assert (root / "Dockerfile").is_file()
        assert (root / "src" / "tee_crafter").is_dir()


class TestWorkspaceRoot:
    def test_is_cwd(self):
        assert _workspace_root() == Path.cwd()


class TestDockerImage:
    def test_default_image(self, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_DOCKER_IMAGE", raising=False)
        assert _docker_image() == "tee-crafter"

    def test_custom_image(self, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_DOCKER_IMAGE", "custom-image:v2")
        assert _docker_image() == "custom-image:v2"


class TestShouldExecInDocker:
    def test_not_in_docker(self, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_IN_DOCKER", raising=False)
        assert _should_exec_in_docker(["tee-crafter", "deploy"]) is True

    def test_already_in_docker(self, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_IN_DOCKER", "1")
        assert _should_exec_in_docker(["tee-crafter", "deploy"]) is False

    @pytest.mark.parametrize("argv", [
        ["tee-crafter"],
        ["tee-crafter", "--help"],
        ["tee-crafter", "-h"],
        ["tee-crafter", "--version"],
        ["tee-crafter", "deploy", "--help"],
        ["tee-crafter", "verify-provenance", "--help"],
    ])
    def test_informational_invocations_stay_on_host(self, monkeypatch, argv):
        """Printing help must not build a Docker image.

        Every command is registered on the host, so Click renders all help
        locally.  Re-execing these built a multi-hundred-megabyte image to
        print a usage string, and ``tee-crafter --help`` is the README's
        first command.
        """
        monkeypatch.delenv("TEE_CRAFTER_IN_DOCKER", raising=False)
        assert _should_exec_in_docker(argv) is False

    @pytest.mark.parametrize("argv", [
        ["tee-crafter", "deploy", "--tee-platform", "nitro-aws"],
        ["tee-crafter", "destroy"],
        ["tee-crafter", "bake-ami", "--tee-platform", "snp-aws"],
    ])
    def test_real_work_still_reexecs(self, monkeypatch, argv):
        monkeypatch.delenv("TEE_CRAFTER_IN_DOCKER", raising=False)
        assert _should_exec_in_docker(argv) is True


class TestCLIGroup:
    def test_cli_is_click_group(self):
        import click
        assert isinstance(cli, click.Group)

    def test_cli_has_commands(self):
        assert len(cli.commands) > 0

    def test_deploy_command_registered(self):
        assert "deploy" in cli.commands

    def test_destroy_command_registered(self):
        assert "destroy" in cli.commands

    def test_verify_provenance_registered(self):
        assert "verify-provenance" in cli.commands
