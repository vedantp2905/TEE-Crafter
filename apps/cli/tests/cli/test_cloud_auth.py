"""Tests for cloud credential isolation.

The user-facing guarantee is: when ``--tee-platform`` selects an
AWS-only flow, the CLI only requires AWS credentials.  No Azure/GCP
bootstrap fires and no Azure/GCP env vars are demanded.  Conversely,
when AWS creds are missing for an AWS deploy, the CLI fails fast with
a clear error pointing at ``docs/aws_setup.md``.
"""
from __future__ import annotations

from unittest import mock

import click
import pytest

from tee_crafter.cli import cloud_auth


# ---------------------------------------------------------------------------
# cloud_for_platform
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("platform,cloud", [
    ("nitro-aws", "aws"),
    ("snp-aws", "aws"),
    ("gpu-cc-aws", "aws"),
    ("sgx-azure", "azure"),
    ("tdx-azure", "azure"),
    ("snp-azure", "azure"),
    ("gpu-cc-azure", "azure"),
    ("snp-gcp", "gcp"),
    ("tdx-gcp", "gcp"),
    ("gpu-cc-gcp", "gcp"),
])
def test_cloud_for_platform_known(platform, cloud):
    assert cloud_auth.cloud_for_platform(platform) == cloud


@pytest.mark.parametrize("platform", ["", None, "made-up", "container"])
def test_cloud_for_platform_unknown(platform):
    assert cloud_auth.cloud_for_platform(platform) is None


# ---------------------------------------------------------------------------
# bootstrap_cloud_auth — cloud scoping
# ---------------------------------------------------------------------------

class TestBootstrapScoping:
    """Make sure picking AWS does NOT touch Azure/GCP bootstrap (and vice versa)."""

    def _patches(self):
        return (
            mock.patch.object(cloud_auth, "_bootstrap_azure"),
            mock.patch.object(cloud_auth, "_bootstrap_gcp"),
        )

    def test_aws_platform_skips_azure_and_gcp(self, monkeypatch):
        monkeypatch.setenv(cloud_auth._IN_DOCKER_ENV, "1")
        with mock.patch.object(cloud_auth, "_bootstrap_azure") as az, \
             mock.patch.object(cloud_auth, "_bootstrap_gcp") as gcp:
            cloud_auth.bootstrap_cloud_auth(tee_platform="nitro-aws")
            az.assert_not_called()
            gcp.assert_not_called()

    def test_azure_platform_calls_only_azure(self, monkeypatch):
        monkeypatch.setenv(cloud_auth._IN_DOCKER_ENV, "1")
        with mock.patch.object(cloud_auth, "_bootstrap_azure") as az, \
             mock.patch.object(cloud_auth, "_bootstrap_gcp") as gcp:
            cloud_auth.bootstrap_cloud_auth(tee_platform="sgx-azure")
            az.assert_called_once()
            gcp.assert_not_called()

    def test_gcp_platform_calls_only_gcp(self, monkeypatch):
        monkeypatch.setenv(cloud_auth._IN_DOCKER_ENV, "1")
        with mock.patch.object(cloud_auth, "_bootstrap_azure") as az, \
             mock.patch.object(cloud_auth, "_bootstrap_gcp") as gcp:
            cloud_auth.bootstrap_cloud_auth(tee_platform="snp-gcp")
            az.assert_not_called()
            gcp.assert_called_once()

    def test_unknown_platform_falls_through_to_multi_cloud(self, monkeypatch):
        """Non-deploy subcommands (``--help``) preserve the historical
        behaviour of bootstrapping every cloud the user has env vars for."""
        monkeypatch.setenv(cloud_auth._IN_DOCKER_ENV, "1")
        with mock.patch.object(cloud_auth, "_bootstrap_azure") as az, \
             mock.patch.object(cloud_auth, "_bootstrap_gcp") as gcp:
            cloud_auth.bootstrap_cloud_auth(tee_platform=None)
            az.assert_called_once()
            gcp.assert_called_once()

    def test_outside_docker_is_noop(self, monkeypatch):
        monkeypatch.delenv(cloud_auth._IN_DOCKER_ENV, raising=False)
        with mock.patch.object(cloud_auth, "_bootstrap_azure") as az, \
             mock.patch.object(cloud_auth, "_bootstrap_gcp") as gcp:
            cloud_auth.bootstrap_cloud_auth(tee_platform="nitro-aws")
            cloud_auth.bootstrap_cloud_auth(tee_platform="sgx-azure")
            cloud_auth.bootstrap_cloud_auth(tee_platform="snp-gcp")
            az.assert_not_called()
            gcp.assert_not_called()


# ---------------------------------------------------------------------------
# validate_required_creds — only the selected cloud is required
# ---------------------------------------------------------------------------

class TestValidateRequiredCreds:
    def test_unknown_platform_skips_check(self):
        # Probe should NOT be invoked when the platform is unknown.
        with mock.patch.object(cloud_auth, "_aws_creds_work") as p:
            cloud_auth.validate_required_creds("unknown-platform")
            p.assert_not_called()

    def test_skip_flag(self):
        with mock.patch.object(cloud_auth, "_aws_creds_work") as p:
            cloud_auth.validate_required_creds("nitro-aws", skip=True)
            p.assert_not_called()

    def test_aws_platform_calls_only_aws_probe(self):
        with mock.patch.object(cloud_auth, "_aws_creds_work", return_value=None) as aws, \
             mock.patch.object(cloud_auth, "_azure_creds_work") as az, \
             mock.patch.object(cloud_auth, "_gcp_creds_work") as gcp:
            cloud_auth.validate_required_creds("nitro-aws")
            aws.assert_called_once()
            az.assert_not_called()
            gcp.assert_not_called()

    def test_azure_platform_calls_only_azure_probe(self):
        with mock.patch.object(cloud_auth, "_aws_creds_work") as aws, \
             mock.patch.object(cloud_auth, "_azure_creds_work", return_value=None) as az, \
             mock.patch.object(cloud_auth, "_gcp_creds_work") as gcp:
            cloud_auth.validate_required_creds("sgx-azure")
            aws.assert_not_called()
            az.assert_called_once()
            gcp.assert_not_called()

    def test_gcp_platform_calls_only_gcp_probe(self):
        with mock.patch.object(cloud_auth, "_aws_creds_work") as aws, \
             mock.patch.object(cloud_auth, "_azure_creds_work") as az, \
             mock.patch.object(cloud_auth, "_gcp_creds_work", return_value=None) as gcp:
            cloud_auth.validate_required_creds("snp-gcp")
            aws.assert_not_called()
            az.assert_not_called()
            gcp.assert_called_once()

    def test_aws_failure_raises_click_exception_pointing_to_aws_doc(self):
        with mock.patch.object(cloud_auth, "_aws_creds_work",
                                return_value="creds missing"):
            with pytest.raises(click.ClickException) as exc:
                cloud_auth.validate_required_creds("nitro-aws")
        msg = exc.value.message
        assert "AWS" in msg
        assert "nitro-aws" in msg
        assert "docs/aws_setup.md" in msg
        # Crucially: error does NOT demand the other clouds' creds.
        assert "AZURE" not in msg.upper() or "do NOT need credentials" in msg
        assert "GCP" not in msg.upper() or "do NOT need credentials" in msg

    def test_azure_failure_points_to_azure_doc(self):
        with mock.patch.object(cloud_auth, "_azure_creds_work",
                                return_value="az login required"):
            with pytest.raises(click.ClickException) as exc:
                cloud_auth.validate_required_creds("tdx-azure")
        assert "docs/azure_setup.md" in exc.value.message

    def test_gcp_failure_points_to_gcp_doc(self):
        with mock.patch.object(cloud_auth, "_gcp_creds_work",
                                return_value="adc missing"):
            with pytest.raises(click.ClickException) as exc:
                cloud_auth.validate_required_creds("snp-gcp")
        assert "docs/gcp_setup.md" in exc.value.message

    def test_success_does_not_raise(self):
        with mock.patch.object(cloud_auth, "_aws_creds_work", return_value=None):
            cloud_auth.validate_required_creds("nitro-aws")  # no raise
