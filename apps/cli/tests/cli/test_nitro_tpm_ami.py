"""``gpu-cc-aws`` needs an AMI that NitroTPM will attest, and CreateImage can't make one.

The EC2 API is asymmetric here: ``RegisterImage`` accepts ``TpmSupport``,
``CreateImage`` does not. An AMI produced from a running instance therefore
always reports ``TpmSupport: null``, and no stock Canonical AMI declares
``tpm-support`` either — so the only route to a NitroTPM-capable image is a
registration this project performs over the snapshots ``CreateImage`` made.

These tests cover the shape of that call, because the failure modes are all
silent-until-deploy: a missing ``TpmSupport`` gives an image the Terraform
postcondition refuses, a wrong ``BootMode`` gives an image that does not boot,
and a stray read-only field from ``DescribeImages`` makes ``RegisterImage``
reject the whole call.

None of this makes CPU-side attestation *verifiable* — that needs an AWS
NitroTPM root to anchor the attestation key, which this project does not have.
It removes one prerequisite. See ``docs/pending.md``.
"""
from __future__ import annotations

import pytest

from tee_crafter.cli.commands.baking.common.nitro_tpm_ami import (
    NitroTpmAmiError,
    register_nitro_tpm_ami,
)


SRC = "ami-source0000000001"
NEW = "ami-newtpm0000000002"
SNAP = "snap-0abc0000000000001"


def _image(**over):
    img = {
        "ImageId": SRC,
        "Architecture": "x86_64",
        "RootDeviceName": "/dev/sda1",
        "VirtualizationType": "hvm",
        "BootMode": "uefi-preferred",
        "EnaSupport": True,
        "SriovNetSupport": "simple",
        "TpmSupport": None,
        "BlockDeviceMappings": [{
            "DeviceName": "/dev/sda1",
            "Ebs": {
                "SnapshotId": SNAP,
                "VolumeSize": 100,
                "VolumeType": "gp3",
                "DeleteOnTermination": True,
                "Iops": 3000,
                "Throughput": 125,
                # DescribeImages returns this; RegisterImage rejects it
                # alongside a SnapshotId.
                "Encrypted": False,
            },
        }],
    }
    img.update(over)
    return img


class _Waiter:
    def __init__(self, log): self.log = log
    def wait(self, **kw): self.log.append(("wait", kw))


_ABSENT = object()  # distinct from None, which _image() would mask


class _Ec2:
    def __init__(self, image=_ABSENT, register_id=NEW):
        self.image = _image() if image is _ABSENT else image
        self.register_id = register_id
        self.calls = []

    def describe_images(self, **kw):
        self.calls.append(("describe_images", kw))
        return {"Images": [self.image] if self.image else []}

    def register_image(self, **kw):
        self.calls.append(("register_image", kw))
        return {"ImageId": self.register_id}

    def deregister_image(self, **kw):
        self.calls.append(("deregister_image", kw))

    def get_waiter(self, name):
        self.calls.append(("get_waiter", name))
        return _Waiter(self.calls)

    def kwargs_for(self, op):
        return next(kw for name, kw in self.calls if name == op)

    def names(self):
        return [c[0] for c in self.calls]


class TestTheRegistrationTurnsOnTheTpm:

    def test_it_requests_tpm_v2(self):
        ec2 = _Ec2()
        new_id, _ = register_nitro_tpm_ami(
            ec2, source_ami_id=SRC, name="img-tpm")
        assert new_id == NEW
        assert ec2.kwargs_for("register_image")["TpmSupport"] == "v2.0"

    def test_it_pins_boot_mode_to_uefi_not_uefi_preferred(self):
        """``uefi-preferred`` permits a legacy-BIOS fallback.

        An instance that fell back would come up with no TPM at all, which is
        the silent downgrade this whole path exists to avoid — so the new AMI
        is registered as strictly ``uefi`` even though the source says
        ``uefi-preferred``.
        """
        ec2 = _Ec2()
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        assert ec2.kwargs_for("register_image")["BootMode"] == "uefi"

    def test_it_reuses_the_snapshot_rather_than_copying(self):
        ec2 = _Ec2()
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        bdm = ec2.kwargs_for("register_image")["BlockDeviceMappings"]
        assert bdm[0]["Ebs"]["SnapshotId"] == SNAP

    def test_it_carries_over_the_hardware_attributes(self):
        ec2 = _Ec2()
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        kw = ec2.kwargs_for("register_image")
        assert kw["Architecture"] == "x86_64"
        assert kw["RootDeviceName"] == "/dev/sda1"
        assert kw["VirtualizationType"] == "hvm"
        assert kw["EnaSupport"] is True
        assert kw["SriovNetSupport"] == "simple"


class TestTheBlockDeviceProjection:
    """``DescribeImages`` output is not a valid ``RegisterImage`` input."""

    def test_read_only_fields_are_dropped(self):
        ec2 = _Ec2()
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        ebs = ec2.kwargs_for("register_image")["BlockDeviceMappings"][0]["Ebs"]
        assert "Encrypted" not in ebs, ebs

    def test_iops_and_throughput_survive_on_gp3(self):
        ec2 = _Ec2()
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        ebs = ec2.kwargs_for("register_image")["BlockDeviceMappings"][0]["Ebs"]
        assert ebs["Iops"] == 3000 and ebs["Throughput"] == 125

    @pytest.mark.parametrize("vol_type", ["gp2", "standard", "sc1", "st1"])
    def test_iops_and_throughput_are_dropped_where_they_are_rejected(self, vol_type):
        img = _image()
        img["BlockDeviceMappings"][0]["Ebs"]["VolumeType"] = vol_type
        ec2 = _Ec2(image=img)
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        ebs = ec2.kwargs_for("register_image")["BlockDeviceMappings"][0]["Ebs"]
        assert "Iops" not in ebs and "Throughput" not in ebs

    def test_instance_store_entries_keep_their_device_layout(self):
        img = _image()
        img["BlockDeviceMappings"].append(
            {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"})
        ec2 = _Ec2(image=img)
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        bdm = ec2.kwargs_for("register_image")["BlockDeviceMappings"]
        assert {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"} in bdm


class TestItRefusesRatherThanProducingABrokenImage:

    @pytest.mark.parametrize("boot_mode", ["legacy-bios", "", None])
    def test_a_non_uefi_source_is_refused(self, boot_mode):
        """NitroTPM requires UEFI; re-registering legacy BIOS as UEFI would
        trade a missing TPM for an unbootable image."""
        ec2 = _Ec2(image=_image(BootMode=boot_mode))
        with pytest.raises(NitroTpmAmiError, match="UEFI"):
            register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        assert "register_image" not in ec2.names()

    def test_a_missing_source_is_refused(self):
        ec2 = _Ec2(image=None)  # DescribeImages returns no Images
        with pytest.raises(NitroTpmAmiError, match="not found"):
            register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")

    def test_no_snapshot_is_refused(self):
        ec2 = _Ec2(image=_image(BlockDeviceMappings=[]))
        with pytest.raises(NitroTpmAmiError, match="block device"):
            register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")

    def test_the_source_survives_a_refusal(self):
        """A failed TPM enable must leave a usable AMI behind."""
        ec2 = _Ec2(image=_image(BootMode="legacy-bios"))
        with pytest.raises(NitroTpmAmiError):
            register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        assert "deregister_image" not in ec2.names()


class TestOrderingAndIdempotence:

    def test_the_source_is_deregistered_only_after_the_new_ami_is_available(self):
        """An interrupted run must never leave zero usable AMIs."""
        ec2 = _Ec2()
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        names = ec2.names()
        assert names.index("wait") < names.index("deregister_image")
        assert names.index("register_image") < names.index("wait")

    def test_the_snapshot_is_not_deleted(self):
        """Deregistering the intermediate leaves the snapshot, which the new
        AMI now references — that is why this is a re-registration and not a
        copy."""
        ec2 = _Ec2()
        register_nitro_tpm_ami(ec2, source_ami_id=SRC, name="img-tpm")
        assert "delete_snapshot" not in ec2.names()

    def test_an_already_nitro_tpm_ami_is_left_alone(self):
        """A resumed bake must not register a third AMI."""
        ec2 = _Ec2(image=_image(TpmSupport="v2.0"))
        got, boot = register_nitro_tpm_ami(
            ec2, source_ami_id=SRC, name="img-tpm")
        assert got == SRC
        assert "register_image" not in ec2.names()
        assert "deregister_image" not in ec2.names()

    def test_waiting_can_be_disabled_for_callers_that_poll_themselves(self):
        ec2 = _Ec2()
        register_nitro_tpm_ami(
            ec2, source_ami_id=SRC, name="img-tpm", wait=False)
        assert "wait" not in ec2.names()
        assert "deregister_image" in ec2.names()


class TestTheBakeUsesIt:

    def test_the_gpu_cc_bake_calls_it(self):
        import tee_crafter.cli.commands.baking.gpu_cc as g
        src = open(g.__file__, encoding="utf-8").read()
        assert "register_nitro_tpm_ami(" in src

    def test_a_failure_does_not_abort_the_bake(self):
        """The image is still usable with require_nitro_tpm=false, so the bake
        reports the loss of attestability instead of throwing the AMI away."""
        import tee_crafter.cli.commands.baking.gpu_cc as g
        src = open(g.__file__, encoding="utf-8").read()
        assert "except NitroTpmAmiError" in src
        assert "require_nitro_tpm=false" in src
