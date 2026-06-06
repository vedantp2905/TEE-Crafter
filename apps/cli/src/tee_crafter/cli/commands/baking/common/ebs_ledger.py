"""Record the EBS snapshot that backs each baked AMI, at bake time.

``aws ec2 create-image`` creates a snapshot for every block device and attaches
it to the new AMI.  ``ec2:DeregisterImage`` does **not** delete that snapshot —
retiring an AMI leaves a 30 GiB snapshot billing at roughly $1.50/month
indefinitely.

The reason this has to be recorded here, rather than looked up when someone
finally cleans up, is a permission gap in the account this project uses.  For
``iam::950771918023:user/test-1``:

* ``ec2:DeregisterImage`` is allowed — the AMI can be retired;
* ``ec2:DeleteSnapshot`` is denied — the snapshot cannot be removed;
* ``ec2:DescribeSnapshots`` is denied — the snapshots cannot even be *listed*.

So the snapshot id is only knowable while the AMI still exists (via
``ec2:DescribeImages``, which *is* allowed).  Deregister first and the id is
gone for good: there is no API call this identity can make that will ever name
it again.  ``snap-05f937c10555a08ea`` was already lost that way, orphaned from
``ami-070603b2133e92fef``, and is seeded below so it stays actionable.

The ledger lives beside the measurement registry because that directory is
already bind-mounted into the re-exec container (``TEE_CRAFTER_MEASUREMENTS_DIR``)
and therefore already survives the ``--rm``.  It is a flat file at the registry
*root*; the registry itself only ever reads ``<platform>/<image>.json`` by exact
path and never enumerates, so nothing else looks at it.

Deleting the snapshots still needs one IAM statement — see ``docs/aws_setup.md``.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

#: File name under the measurement-registry root.
LEDGER_NAME = "aws_ebs_snapshots.json"

#: Snapshots known to be orphaned before the ledger existed.  Kept in code
#: rather than only in the ledger file so a fresh checkout still carries them.
SEEDED_ORPHANS: List[Dict[str, Any]] = [
    {
        "ami_id": "ami-070603b2133e92fef",
        "ami_name": "(deregistered before the ledger existed)",
        "platform": "snp-aws",
        "region": "us-east-2",
        "snapshot_ids": ["snap-05f937c10555a08ea"],
        "recorded_at": "2026-08-22T00:00:00Z",
        "note": "AMI already deregistered; snapshot orphaned and unlistable.",
    },
]


def ledger_path() -> str:
    from tee_crafter.core.measurements.registry import registry_dir
    return os.path.join(registry_dir(), LEDGER_NAME)


def load_ledger() -> List[Dict[str, Any]]:
    """Existing entries plus any seeded orphan not already present."""
    entries: List[Dict[str, Any]] = []
    path = ledger_path()
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, list):
                entries = [e for e in loaded if isinstance(e, dict)]
        except (OSError, ValueError):
            # A corrupt ledger must not break a bake.  It is a record, not a
            # gate: losing it costs $1.50/month, losing the AMI costs an hour.
            entries = []
    known = {e.get("ami_id") for e in entries}
    for seed in SEEDED_ORPHANS:
        if seed["ami_id"] not in known:
            entries.append(dict(seed))
    return entries


def backing_snapshot_ids(ec2, ami_id: str) -> List[str]:
    """Snapshot ids behind *ami_id*, via ``DescribeImages``.

    Returns ``[]`` on any failure — an unrecorded snapshot is a small recurring
    cost, while an exception here would abort a bake that has already succeeded.
    """
    try:
        resp = ec2.describe_images(ImageIds=[ami_id])
    except Exception:
        return []
    ids: List[str] = []
    for image in resp.get("Images", []):
        for mapping in image.get("BlockDeviceMappings", []):
            snap = (mapping.get("Ebs") or {}).get("SnapshotId")
            if snap and snap not in ids:
                ids.append(snap)
    return ids


def record_backing_snapshots(ec2, ami_id: str, *, platform: str, region: str,
                             ami_name: str = "") -> List[str]:
    """Append *ami_id*'s backing snapshot ids to the ledger. Returns the ids."""
    snapshot_ids = backing_snapshot_ids(ec2, ami_id)
    if not snapshot_ids:
        return []
    entries = [e for e in load_ledger() if e.get("ami_id") != ami_id]
    entries.append({
        "ami_id": ami_id,
        "ami_name": ami_name,
        "platform": platform,
        "region": region,
        "snapshot_ids": snapshot_ids,
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "Deregistering the AMI will NOT delete these snapshots.",
    })
    path = ledger_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, sort_keys=True)
            fh.write("\n")
    except OSError:
        return snapshot_ids
    return snapshot_ids


def retirement_hint(ami_id: str, snapshot_ids: List[str],
                    region: str) -> Optional[str]:
    """Operator-facing note naming what a later ``deregister-image`` leaves."""
    if not snapshot_ids:
        return None
    joined = " ".join(snapshot_ids)
    return (
        f"Backing EBS snapshot(s): {joined}\n"
        f"Recorded in {LEDGER_NAME}. Deregistering {ami_id} does not delete "
        f"them; they keep billing (~$1.50/month per 30 GiB). To retire it "
        f"fully:\n"
        f"  aws ec2 deregister-image --region {region} --image-id {ami_id}\n"
        f"  aws ec2 delete-snapshot --region {region} --snapshot-id "
        f"{snapshot_ids[0]}"
    )
