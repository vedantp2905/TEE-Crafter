"""The snapshot id behind a baked AMI must be recorded while it is knowable.

``create_image`` makes an EBS snapshot per block device; ``DeregisterImage``
does not delete it.  In this project's AWS account the identity that bakes
(``user/test-1``) can deregister an image and can describe images, but is denied
both ``ec2:DeleteSnapshot`` and ``ec2:DescribeSnapshots``.  So the snapshot id
exists in exactly one reachable place — the AMI's own block device mapping —
and deregistering the AMI removes that too.  One snapshot
(``snap-05f937c10555a08ea``) was already stranded that way.

Recording at bake time is the only point where the information is available
without new IAM.  These tests pin the two properties that matter: the id is
captured, and capturing it can never break a bake that has otherwise succeeded.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from tee_crafter.cli.commands.baking.common import ebs_ledger as L


@pytest.fixture()
def registry(tmp_path, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_MEASUREMENTS_DIR", str(tmp_path))
    import tee_crafter.core.measurements.registry as reg
    monkeypatch.setattr(reg, "_REGISTRY_DIR", str(tmp_path))
    return tmp_path


def _ec2(snapshot_ids=("snap-aaa",), *, raises=False):
    ec2 = MagicMock()
    if raises:
        ec2.describe_images.side_effect = RuntimeError("AccessDenied")
        return ec2
    ec2.describe_images.return_value = {
        "Images": [{
            "ImageId": "ami-test",
            "BlockDeviceMappings": (
                [{"DeviceName": "/dev/sda1",
                  "Ebs": {"SnapshotId": s}} for s in snapshot_ids]
                + [{"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"}]
            ),
        }]
    }
    return ec2


class TestSnapshotIdsAreRead:
    def test_single_device(self):
        assert L.backing_snapshot_ids(_ec2(), "ami-test") == ["snap-aaa"]

    def test_multiple_devices(self):
        ids = L.backing_snapshot_ids(_ec2(("snap-a", "snap-b")), "ami-test")
        assert ids == ["snap-a", "snap-b"]

    def test_instance_store_mappings_are_skipped(self):
        """A mapping with no Ebs block has no snapshot to record."""
        assert L.backing_snapshot_ids(_ec2(), "ami-test") == ["snap-aaa"]

    def test_duplicates_are_collapsed(self):
        ids = L.backing_snapshot_ids(_ec2(("snap-a", "snap-a")), "ami-test")
        assert ids == ["snap-a"]

    def test_a_denied_describe_returns_empty_rather_than_raising(self):
        assert L.backing_snapshot_ids(_ec2(raises=True), "ami-test") == []


class TestTheLedgerIsWritten:
    def test_an_entry_is_appended(self, registry):
        ids = L.record_backing_snapshots(
            _ec2(), "ami-test", platform="snp-aws", region="us-east-2",
            ami_name="tee-crafter-snp-aws-x")
        assert ids == ["snap-aaa"]
        entries = json.loads((registry / L.LEDGER_NAME).read_text())
        mine = [e for e in entries if e["ami_id"] == "ami-test"]
        assert len(mine) == 1
        assert mine[0]["snapshot_ids"] == ["snap-aaa"]
        assert mine[0]["platform"] == "snp-aws"
        assert mine[0]["region"] == "us-east-2"

    def test_it_lands_beside_the_measurement_registry(self, registry):
        L.record_backing_snapshots(_ec2(), "ami-test", platform="snp-aws",
                                   region="us-east-2")
        assert (registry / L.LEDGER_NAME).is_file()

    def test_it_is_not_inside_a_platform_directory(self, registry):
        """The registry looks up ``<platform>/<image>.json`` by exact path and
        never enumerates, so a file at the root cannot be mistaken for a pin."""
        L.record_backing_snapshots(_ec2(), "ami-test", platform="snp-aws",
                                   region="us-east-2")
        assert not (registry / "snp-aws").exists()

    def test_re_recording_the_same_ami_replaces_rather_than_duplicates(self, registry):
        for _ in range(3):
            L.record_backing_snapshots(_ec2(), "ami-test", platform="snp-aws",
                                       region="us-east-2")
        entries = json.loads((registry / L.LEDGER_NAME).read_text())
        assert len([e for e in entries if e["ami_id"] == "ami-test"]) == 1

    def test_earlier_entries_survive(self, registry):
        L.record_backing_snapshots(_ec2(("snap-1",)), "ami-one",
                                   platform="snp-aws", region="us-east-2")
        L.record_backing_snapshots(_ec2(("snap-2",)), "ami-two",
                                   platform="nitro-aws", region="us-east-2")
        ids = {e["ami_id"] for e in json.loads((registry / L.LEDGER_NAME).read_text())}
        assert {"ami-one", "ami-two"} <= ids

    def test_nothing_is_written_when_there_is_nothing_to_record(self, registry):
        assert L.record_backing_snapshots(
            _ec2(raises=True), "ami-test", platform="snp-aws",
            region="us-east-2") == []
        assert not (registry / L.LEDGER_NAME).exists()


class TestTheKnownOrphanIsCarried:
    def test_the_stranded_snapshot_is_seeded(self, registry):
        entries = L.load_ledger()
        orphan = [e for e in entries
                  if "snap-05f937c10555a08ea" in e.get("snapshot_ids", [])]
        assert orphan, "the snapshot already lost this way must stay on record"
        assert orphan[0]["ami_id"] == "ami-070603b2133e92fef"

    def test_it_survives_a_write(self, registry):
        L.record_backing_snapshots(_ec2(), "ami-test", platform="snp-aws",
                                   region="us-east-2")
        entries = json.loads((registry / L.LEDGER_NAME).read_text())
        assert any("snap-05f937c10555a08ea" in e.get("snapshot_ids", [])
                   for e in entries)

    def test_it_is_not_duplicated_on_reload(self, registry):
        L.record_backing_snapshots(_ec2(), "ami-a", platform="snp-aws",
                                   region="us-east-2")
        L.record_backing_snapshots(_ec2(), "ami-b", platform="snp-aws",
                                   region="us-east-2")
        entries = json.loads((registry / L.LEDGER_NAME).read_text())
        assert len([e for e in entries
                    if e["ami_id"] == "ami-070603b2133e92fef"]) == 1


class TestACorruptLedgerDoesNotBreakABake:
    @pytest.mark.parametrize("junk", ["not json", "{}", "[1, 2, 3]", ""])
    def test_unreadable_content_is_replaced_not_raised(self, registry, junk):
        (registry / L.LEDGER_NAME).write_text(junk)
        ids = L.record_backing_snapshots(_ec2(), "ami-test", platform="snp-aws",
                                         region="us-east-2")
        assert ids == ["snap-aaa"]
        entries = json.loads((registry / L.LEDGER_NAME).read_text())
        assert any(e["ami_id"] == "ami-test" for e in entries)


class TestTheOperatorIsTold:
    def test_the_hint_names_both_calls(self):
        hint = L.retirement_hint("ami-x", ["snap-y"], "us-east-2")
        assert "deregister-image" in hint and "delete-snapshot" in hint
        assert "snap-y" in hint and "ami-x" in hint

    def test_no_hint_when_nothing_was_recorded(self):
        assert L.retirement_hint("ami-x", [], "us-east-2") is None

    @pytest.mark.parametrize("module,platform", [
        ("snp", "snp-aws"), ("nitro", "nitro-aws"), ("gpu_cc", "gpu-cc-aws"),
    ])
    def test_every_aws_bake_path_records(self, module, platform):
        import importlib
        import inspect
        mod = importlib.import_module(
            f"tee_crafter.cli.commands.baking.{module}")
        src = inspect.getsource(mod)
        assert "record_backing_snapshots" in src, (
            f"{module} bakes an AMI without recording its snapshot")
        assert f'platform="{platform}"' in src
        assert "retirement_hint" in src
