"""The ``snp-aws`` bake has to produce a NitroTPM-capable AMI.

Measurement-gated key release on this platform depends on two things the bake
owns and nothing downstream can add later:

* the AMI must declare ``TpmSupport=v2.0``, which only ``RegisterImage`` can set
  -- ``CreateImage`` has no such parameter, so an AMI captured from a running
  instance always reports ``TpmSupport: null``;
* ``nitro-tpm-attest`` must be in the image, because AWS packages it for Amazon
  Linux 2023 only and this image is Ubuntu.

Both are cheap to get wrong in a way that only shows up an hour into a paid bake,
or worse, at key-release time on a running deploy. These tests read the shipped
sources rather than mocking EC2, because what is being checked is wiring and
ordering, not API behaviour.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from tee_crafter.cli.commands.baking import snp as snp_bake

SETUP = (Path(snp_bake.__file__).parents[3]
         / "scripts" / "snp_aws" / "setup_snp_aws.sh")


@pytest.fixture(scope="module")
def bake_source():
    return inspect.getsource(snp_bake)


@pytest.fixture(scope="module")
def setup_script():
    """The *rendered* setup script, not the raw file on disk.

    The nitro-tpm-attest installer moved into
    ``scripts/common/nitro_tpm_attest_install.sh`` so that ``gpu-cc-aws`` could
    share one copy instead of growing a second that drifts; the raw file now
    carries only the ``__NITRO_TPM_ATTEST_INSTALL__`` placeholder.  Rendering is
    the better assertion regardless: this is the text that actually runs on the
    bake instance, so a substitution that silently stopped working would fail
    these tests rather than pass them against a file nobody executes.
    """
    from tee_crafter.cli import loaders
    return loaders.load_snp_aws_setup_template()


# --------------------------------------------------------------------------
# Bake wiring
# --------------------------------------------------------------------------

def test_bake_registers_the_ami_with_nitro_tpm(bake_source):
    assert "register_nitro_tpm_ami" in bake_source


def test_registration_happens_before_the_snapshot_ledger(bake_source):
    """Ordering is a money bug, not a style question.

    ``register_nitro_tpm_ami`` deregisters the source AMI once the replacement is
    available. Recording backing snapshots first files them under an AMI id that
    is about to disappear, and this identity cannot list snapshots afterwards --
    so the snapshots keep billing with nothing pointing at them.
    """
    register_at = bake_source.index("register_nitro_tpm_ami(")
    ledger_at = bake_source.index("record_backing_snapshots(")
    assert register_at < ledger_at, (
        "the NitroTPM re-registration must run before record_backing_snapshots, "
        "otherwise the ledger points at the AMI that gets deregistered")


def test_registration_failure_does_not_abort_the_bake(bake_source):
    """A bake costs an hour of instance time; losing it over an optional
    capability would be the wrong trade. The gating table already reports an
    unattestable image honestly as iam-scoped."""
    assert "except NitroTpmAmiError" in bake_source


def test_nitro_tpm_is_gated_on_secure_boot(bake_source):
    """PCR7 is the Secure Boot policy digest. With Secure Boot off it measures
    an absent policy, so enabling the TPM would imply a gate that is not there."""
    idx = bake_source.index("register_nitro_tpm_ami(")
    preceding = bake_source[:idx]
    assert "if enable_secure_boot:" in preceding


def test_the_tpm_ami_is_the_one_returned(bake_source):
    """Returning the pre-registration id would hand the operator an AMI that
    cannot attest, while the console said NitroTPM was enabled."""
    assert "ami_id = tpm_ami_id" in bake_source


# --------------------------------------------------------------------------
# Image contents
# --------------------------------------------------------------------------

def test_setup_installs_nitro_tpm_attest(setup_script):
    assert "nitro-tpm-attest" in setup_script


def test_nitro_tpm_attest_lands_where_the_release_path_looks(setup_script):
    """``core/keys/nitrotpm.NITRO_TPM_ATTEST_BIN`` defaults to /usr/bin."""
    from tee_crafter.core.keys.nitrotpm import NITRO_TPM_ATTEST_BIN

    assert NITRO_TPM_ATTEST_BIN == "/usr/bin/nitro-tpm-attest"
    assert "/usr/bin/nitro-tpm-attest" in setup_script


def test_nitro_tpm_tools_revision_is_pinned(setup_script):
    """Same supply-chain rule the snpguest build already follows: build a named
    commit or build nothing."""
    assert "NITROTPM_TOOLS_COMMIT=" in setup_script
    line = next(l for l in setup_script.splitlines()
                if l.startswith("NITROTPM_TOOLS_COMMIT="))
    sha = line.split("=", 1)[1].strip().strip('"')
    assert len(sha) == 40 and all(c in "0123456789abcdef" for c in sha)


def test_commit_mismatch_refuses_to_build(setup_script):
    assert "NitroTPM-Tools commit mismatch" in setup_script


def test_the_build_does_not_rely_on_jammy_libtss2(setup_script):
    """Verified in Docker before the first bake: Ubuntu 22.04 ships TSS 3.2.0
    and nitro-tpm-attest's build.rs requires ^4.0.0, so a native build against
    libtss2-dev aborts. Because the step is non-fatal that miss would have been
    silent, producing an AMI without the binary.

    Asserted against the install lines rather than the file, because the script
    *explains* why libtss2-dev is not used and a whole-file check would match
    the explanation.
    """
    installs = [ln for ln in setup_script.splitlines()
                if "libtss2-dev" in ln and not ln.lstrip().startswith("#")]
    assert not installs, f"libtss2-dev still installed: {installs}"


def test_the_build_uses_the_upstream_static_builder(setup_script):
    """Alpine + musl + tpm2-tss 4.1.3, --disable-shared, so the result has no
    libtss2 runtime dependency and runs on Jammy."""
    assert "docker/builder.Dockerfile" in setup_script
    assert "cargo build --bin nitro-tpm-attest --release" in setup_script


def test_the_build_runs_after_docker_is_available(setup_script):
    """It needs a working daemon, and the Docker Engine block is late in the
    script."""
    docker_at = setup_script.index("--- Docker Engine for container-mode")
    build_at = setup_script.index("--- Build and install nitro-tpm-attest")
    assert docker_at < build_at
    assert "docker info" in setup_script


def test_tpm2_tools_is_installed(setup_script):
    """tpm2_pcrread is how the bake reads PCR4/PCR7 into the registry."""
    assert "tpm2-tools" in setup_script


def test_build_failure_is_non_fatal_but_says_what_was_lost(setup_script):
    assert "identity-gated" in setup_script


# --------------------------------------------------------------------------
# Secure Boot must survive the re-registration
# --------------------------------------------------------------------------

class _FakeEc2:
    """Minimal EC2 stand-in for register_nitro_tpm_ami."""

    def __init__(self, uefi_data="QU1aTlVFRkk=", tpm=None):
        self._uefi = uefi_data
        self._tpm = tpm
        self.register_kwargs = None
        self.deregistered = []

    def describe_images(self, ImageIds):
        return {"Images": [{
            "ImageId": ImageIds[0], "BootMode": "uefi-preferred",
            "TpmSupport": self._tpm, "Architecture": "x86_64",
            "RootDeviceName": "/dev/sda1", "VirtualizationType": "hvm",
            "EnaSupport": True,
            "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {
                "SnapshotId": "snap-1", "VolumeSize": 30, "VolumeType": "gp3",
                "DeleteOnTermination": True, "Encrypted": True}}],
        }]}

    def describe_image_attribute(self, ImageId, Attribute):
        assert Attribute == "uefiData"
        if not self._uefi:
            return {"UefiData": {}}
        return {"UefiData": {"Value": self._uefi}}

    def register_image(self, **kwargs):
        self.register_kwargs = kwargs
        return {"ImageId": "ami-new"}

    def get_waiter(self, _name):
        class _W:
            def wait(self, **_kw):
                return None
        return _W()

    def deregister_image(self, ImageId):
        self.deregistered.append(ImageId)


def test_secure_boot_nvram_is_carried_into_the_tpm_ami():
    """Caught on hardware 2026-08-24, not by review.

    RegisterImage silently produces an empty UEFI variable store when UefiData
    is omitted, so the re-registered AMI booted with Secure Boot *disabled*
    while the bake still believed it had enrolled a policy. Pinning PCR7 in that
    state measures an unprotected boot and looks entirely healthy.
    """
    from tee_crafter.cli.commands.baking.common.nitro_tpm_ami import (
        register_nitro_tpm_ami,
    )

    ec2 = _FakeEc2(uefi_data="QU1aTlVFRkktYmxvYg==")
    new_id, boot = register_nitro_tpm_ami(
        ec2, source_ami_id="ami-src", name="x", wait=False)

    assert new_id == "ami-new" and boot == "uefi"
    assert ec2.register_kwargs["UefiData"] == "QU1aTlVFRkktYmxvYg=="
    assert ec2.register_kwargs["TpmSupport"] == "v2.0"
    assert ec2.register_kwargs["BootMode"] == "uefi"


def test_absent_uefi_data_is_not_fatal():
    """An image that never enrolled Secure Boot is a legitimate input."""
    from tee_crafter.cli.commands.baking.common.nitro_tpm_ami import (
        register_nitro_tpm_ami,
    )

    ec2 = _FakeEc2(uefi_data="")
    register_nitro_tpm_ami(ec2, source_ami_id="ami-src", name="x", wait=False)
    assert "UefiData" not in ec2.register_kwargs


def test_already_tpm_enabled_ami_is_left_alone():
    """A resumed bake must not register a third AMI, nor re-read attributes."""
    from tee_crafter.cli.commands.baking.common.nitro_tpm_ami import (
        register_nitro_tpm_ami,
    )

    ec2 = _FakeEc2(tpm="v2.0")
    new_id, _boot = register_nitro_tpm_ami(
        ec2, source_ami_id="ami-src", name="x", wait=False)
    assert new_id == "ami-src"
    assert ec2.register_kwargs is None
    assert ec2.deregistered == []
