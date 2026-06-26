"""Tests for pinned image resolution from environment variables."""

from __future__ import annotations

import pytest

from tee_crafter.core.pinned_image_env import (
    LEGACY_GLOBAL,
    PLATFORM_PINNED_IMAGE_ENV,
    effective_pinned_image_from_env,
)


@pytest.fixture(autouse=True)
def _clear_pinned_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from tee_crafter.core.pinned_image_env import ALL_PINNED_IMAGE_ENV_KEYS
    for key in ALL_PINNED_IMAGE_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_explicit_cli_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_SNP_AMI", "ami-from-env")
    monkeypatch.setenv(LEGACY_GLOBAL, "ami-legacy")
    assert effective_pinned_image_from_env("snp-aws", cli_or_explicit=" ami-cli ") == "ami-cli"


def test_legacy_global_before_per_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LEGACY_GLOBAL, "ami-legacy")
    monkeypatch.setenv("AWS_SNP_AMI", "ami-snp")
    assert effective_pinned_image_from_env("snp-aws", cli_or_explicit=None) == "ami-legacy"


def test_nitro_has_no_platform_wide_variable() -> None:
    """nitro-aws spans two architectures, so a single pin cannot serve it.

    These tests used AWS_NITRO_AMI as the generic example. That variable is
    gone: the platform pins one AMI per architecture instead, and the
    architecture-aware behaviour lives in test_nitro_dual_arch_ami_pins.py.
    """
    assert "nitro-aws" not in PLATFORM_PINNED_IMAGE_ENV


def test_per_platform_when_no_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCP_TDX_IMAGE", "projects/p/global/images/tdx-baked")
    assert effective_pinned_image_from_env("tdx-gcp", cli_or_explicit=None) == "projects/p/global/images/tdx-baked"


def test_gpu_cc_aws_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_GPU_CC_AMI", "ami-gpu")
    assert effective_pinned_image_from_env("gpu-cc-aws", cli_or_explicit=None) == "ami-gpu"
