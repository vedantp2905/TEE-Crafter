"""A pinned-image variable may carry a trailing ``# ...`` comment.

Docker's ``--env-file`` parser does not treat ``#`` as a comment once a value
has started; a shell that sources the same file does.  Since the documented way
to run this CLI is ``docker run --env-file .env``, the same line means two
different things on the two paths — and the container gets the one with the
comment glued on.  That cost a ``snp-aws`` deploy attempt on 2026-08-23:

    InvalidAMIID.Malformed: Invalid id: "ami-0dc3a149b36b33fff   # snp-aws-..."

No resources were created, so it was cheap, but the same trap applies to every
platform and every user who annotates their AMI list.
"""
from __future__ import annotations

import pytest

from tee_crafter.core.pinned_image_env import (
    PLATFORM_PINNED_IMAGE_ENV, effective_pinned_image_from_env,
)

AMI = "ami-0dc3a149b36b33fff"
AZURE_ID = ("/subscriptions/s/resourceGroups/g/providers/Microsoft.Compute/"
            "galleries/gal/images/img/versions/2026.0823.065615")


@pytest.mark.parametrize("suffix", [
    "   # snp-aws-20260822-072446 (Milan, x86_64)",
    "\t# baked 2026-08-22",
    "#no-space",
    "  ",
    "",
], ids=["spaced-comment", "tab-comment", "tight-comment", "trailing-ws", "clean"])
def test_a_trailing_comment_is_stripped_from_an_ami(monkeypatch, suffix):
    monkeypatch.delenv("TEE_CRAFTER_AMI_ID", raising=False)
    monkeypatch.setenv("AWS_SNP_AMI", AMI + suffix)
    assert effective_pinned_image_from_env("snp-aws") == AMI


def test_azure_resource_ids_survive_intact(monkeypatch):
    """The value has slashes and dots; only ``#`` is special."""
    monkeypatch.delenv("TEE_CRAFTER_AMI_ID", raising=False)
    monkeypatch.setenv("AZURE_TDX_IMAGE", AZURE_ID + "  # tdx bake")
    assert effective_pinned_image_from_env("tdx-azure") == AZURE_ID


@pytest.mark.parametrize("platform", sorted(PLATFORM_PINNED_IMAGE_ENV))
def test_every_platform_gets_the_same_treatment(monkeypatch, platform):
    """One code path, so no platform is left with the old behaviour."""
    monkeypatch.delenv("TEE_CRAFTER_AMI_ID", raising=False)
    monkeypatch.setenv(PLATFORM_PINNED_IMAGE_ENV[platform], "img-1 # note")
    assert effective_pinned_image_from_env(platform) == "img-1"


def test_the_legacy_global_pin_is_stripped_too(monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_AMI_ID", AMI + " # global pin")
    assert effective_pinned_image_from_env("snp-aws") == AMI


def test_a_comment_only_value_reads_as_unset(monkeypatch):
    """Not an empty-string image id, which would fail much later and worse."""
    monkeypatch.delenv("TEE_CRAFTER_AMI_ID", raising=False)
    monkeypatch.setenv("AWS_SNP_AMI", "  # nothing baked yet")
    assert effective_pinned_image_from_env("snp-aws") is None


def test_an_explicit_flag_is_not_second_guessed(monkeypatch):
    """``--ami-id`` comes from a shell, not an env file: leave it alone."""
    monkeypatch.delenv("TEE_CRAFTER_AMI_ID", raising=False)
    assert effective_pinned_image_from_env(
        "snp-aws", cli_or_explicit="ami-explicit") == "ami-explicit"


def test_the_repos_own_env_no_longer_relies_on_the_strip(monkeypatch):
    """Belt and braces: fix the file as well as tolerate the pattern.

    The strip makes the trap survivable; keeping ``.env`` clean means the
    Docker and shell paths agree byte-for-byte in the first place.
    """
    import os
    import re

    root = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "..", "..")
    path = os.path.join(root, ".env")
    if not os.path.isfile(path):
        pytest.skip("no local .env")
    offenders = [
        ln.split("=", 1)[0]
        for ln in open(path, encoding="utf-8").read().splitlines()
        if re.match(r"^(AWS_NITRO_AMI|AWS_SNP_AMI|AZURE_\w*IMAGE|GCP_\w*IMAGE)"
                    r"\w*=\S.*\s#", ln)
    ]
    assert offenders == [], f"inline comments still present: {offenders}"
