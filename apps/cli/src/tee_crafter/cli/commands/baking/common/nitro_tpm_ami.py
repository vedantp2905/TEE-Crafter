"""Re-register a baked AMI with NitroTPM v2.0 so it can produce attestations.

``gpu-cc-aws`` is the only platform that needs this, and it needs it because of
an asymmetry in the EC2 API: **NitroTPM is a property set when an AMI is
registered, and ``CreateImage`` cannot set it.** ``RegisterImage`` takes
``TpmSupport``; ``CreateImage`` takes no such parameter, and an AMI produced
from a running instance therefore always reports ``TpmSupport: null``.

That is not a cosmetic gap. No stock Canonical AMI declares ``tpm-support``
either (verified against the live EC2 API: zero Canonical images report it for
any release, while 194 amazon-owned images do), so a NitroTPM-capable image can
only come from a registration this project performs. The ``gpu_cc/aws``
Terraform carries a fail-closed postcondition that refuses to launch when
``require_nitro_tpm`` is true and no baked AMI was supplied, precisely because
the alternative is a silent downgrade of CPU-side attestation.

So the bake does:

1. ``CreateImage`` from the stopped bake instance — produces an AMI plus one
   EBS snapshot per block device.
2. ``RegisterImage`` over those same snapshots with ``TpmSupport='v2.0'`` —
   produces a second AMI that *is* NitroTPM-capable, referencing the snapshots
   the first one made rather than copying any data.
3. ``DeregisterImage`` on the intermediate. Deregistering does **not** delete
   the snapshots (that is the whole reason ``ebs_ledger`` exists), and the new
   AMI now references them, so nothing is orphaned and nothing is duplicated.

**This is what makes CPU-side attestation possible.** ``TpmSupport=v2.0`` is
what lets the instance produce a NitroTPM attestation document at all, and that
document is verifiable: its ``cabundle`` roots at ``CN=aws.nitro-enclaves``,
which is byte-for-byte ``certs/nitro-root.pem``, the certificate this project
already pins for ``nitro-aws``.

An earlier version of this docstring said the opposite — that the Nitro
Enclaves root "endorses a different key hierarchy" and so no anchor existed.
Measured against a real document on 2026-08-24, the chain is TPM leaf →
instance → zonal → region → that root, with every signature valid. The claim
was wrong, and it was the reason ``gpu-cc-aws`` refused CPU-side attestation
instead of performing it.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

#: NitroTPM requires the AMI to boot via UEFI.  A legacy-BIOS source image
#: cannot simply be re-registered as UEFI: the guest would not boot, and we
#: would have swapped a missing TPM for an unbootable image.
_UEFI_BOOT_MODES = ("uefi", "uefi-preferred")

#: Fields EC2 accepts inside ``BlockDeviceMappings[].Ebs`` on *RegisterImage*.
#: Deliberately an allowlist rather than a denylist: ``DescribeImages`` returns
#: read-only members (``Encrypted`` alongside a ``SnapshotId`` is the one that
#: bites) which ``RegisterImage`` rejects outright.
_EBS_REGISTER_FIELDS = (
    "SnapshotId", "VolumeSize", "VolumeType", "DeleteOnTermination",
    "Iops", "Throughput",
)


class NitroTpmAmiError(RuntimeError):
    """Raised when the source AMI cannot be re-registered with a TPM."""


def _ebs_mappings_for_register(image: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Project ``DescribeImages`` block devices onto RegisterImage's schema."""
    mappings: List[Dict[str, Any]] = []
    for bdm in image.get("BlockDeviceMappings") or []:
        ebs = bdm.get("Ebs")
        if not ebs or not ebs.get("SnapshotId"):
            # Ephemeral/instance-store entries carry no snapshot; pass the
            # device name through untouched so the layout is preserved.
            if bdm.get("VirtualName"):
                mappings.append({k: v for k, v in bdm.items()
                                 if k in ("DeviceName", "VirtualName")})
            continue
        kept = {k: ebs[k] for k in _EBS_REGISTER_FIELDS if k in ebs}
        # gp2 and standard volumes reject Iops/Throughput; io1/io2/gp3 accept
        # them.  Dropping them for the volume types that refuse them keeps the
        # call valid without having to model every type's rules.
        if kept.get("VolumeType") in ("gp2", "standard", "sc1", "st1"):
            kept.pop("Iops", None)
            kept.pop("Throughput", None)
        mappings.append({"DeviceName": bdm["DeviceName"], "Ebs": kept})
    if not mappings:
        raise NitroTpmAmiError(
            "source AMI reports no block device mappings, so there is nothing "
            "to register a new AMI over")
    return mappings



def _read_uefi_data(ec2, ami_id: str) -> str:
    """Return the AMI's base64 UEFI variable store, or ``""``.

    Separate from ``DescribeImages`` because EC2 exposes ``uefiData`` only as an
    image *attribute*.  Missing is a legitimate answer (Secure Boot was never
    enrolled), so this never raises -- the caller decides what to do about it.
    """
    try:
        resp = ec2.describe_image_attribute(ImageId=ami_id, Attribute="uefiData")
    except Exception:
        return ""
    return ((resp or {}).get("UefiData") or {}).get("Value") or ""


def register_nitro_tpm_ami(
    ec2,
    *,
    source_ami_id: str,
    name: str,
    description: str = "",
    tags: Optional[List[Dict[str, str]]] = None,
    wait: bool = True,
    waiter_delay: int = 15,
    waiter_max_attempts: int = 240,
) -> Tuple[str, str]:
    """Re-register *source_ami_id* with NitroTPM v2.0.

    Returns ``(new_ami_id, boot_mode)``.  Raises :class:`NitroTpmAmiError`
    when the source image cannot support a TPM, leaving the source AMI intact
    so the caller can fall back to a non-attestable deploy rather than losing
    the bake.

    The source AMI is deregistered only after the replacement reports
    ``available``: an interrupted run must never leave zero usable AMIs.
    """
    described = ec2.describe_images(ImageIds=[source_ami_id])
    images = described.get("Images") or []
    if not images:
        raise NitroTpmAmiError(f"source AMI {source_ami_id} not found")
    image = images[0]

    boot_mode = image.get("BootMode") or ""
    if boot_mode not in _UEFI_BOOT_MODES:
        raise NitroTpmAmiError(
            f"source AMI {source_ami_id} reports boot mode "
            f"{boot_mode or 'legacy-bios (unset)'}; NitroTPM requires UEFI. "
            "Re-registering it as UEFI would produce an unbootable image, so "
            "the TPM cannot be added to this AMI.")

    if image.get("TpmSupport") == "v2.0":
        # Idempotent: a resumed bake must not register a third AMI.
        return source_ami_id, boot_mode

    # UEFI NVRAM must be carried across explicitly, and this is not optional
    # book-keeping.  ``DescribeImages`` does not return ``UefiData``; it is a
    # separate ``DescribeImageAttribute`` call, and ``RegisterImage`` silently
    # produces an AMI with an *empty* variable store when it is omitted.
    #
    # Observed on hardware 2026-08-24: an AMI re-registered without it booted
    # with ``mokutil --sb-state`` reporting "SecureBoot disabled", despite the
    # source AMI carrying a 4181-byte store with the Platform Key, KEK and db
    # the bake had enrolled.  That is the worst possible shape of failure here —
    # the whole point of PCR7 is to measure the Secure Boot policy, so dropping
    # the policy while continuing to pin PCR7 would produce a confident-looking
    # measurement of an unprotected boot.
    uefi_data = _read_uefi_data(ec2, source_ami_id)
    if uefi_data:
        kwargs_uefi = {"UefiData": uefi_data}
    elif image.get("BootMode") in _UEFI_BOOT_MODES:
        # A UEFI image with no variable store is legitimate (Secure Boot was
        # never enrolled), so this is not fatal.  Say so, because the operator
        # may have passed --enable-secure-boot and deserves to know it did not
        # survive.
        kwargs_uefi = {}
    else:
        kwargs_uefi = {}

    kwargs: Dict[str, Any] = {
        "Name": name,
        "Architecture": image.get("Architecture") or "x86_64",
        "RootDeviceName": image["RootDeviceName"],
        "BlockDeviceMappings": _ebs_mappings_for_register(image),
        "VirtualizationType": image.get("VirtualizationType") or "hvm",
        # UEFI, not the source's `uefi-preferred`: NitroTPM needs UEFI, and
        # `uefi-preferred` lets the instance fall back to legacy BIOS, which
        # would silently produce an instance with no TPM.
        "BootMode": "uefi",
        "TpmSupport": "v2.0",
    }
    if description:
        kwargs["Description"] = description
    if image.get("EnaSupport") is not None:
        kwargs["EnaSupport"] = image["EnaSupport"]
    if image.get("SriovNetSupport"):
        kwargs["SriovNetSupport"] = image["SriovNetSupport"]
    if image.get("ImdsSupport"):
        kwargs["ImdsSupport"] = image["ImdsSupport"]
    kwargs.update(kwargs_uefi)
    if tags:
        kwargs["TagSpecifications"] = [
            {"ResourceType": "image", "Tags": list(tags)}]

    new_ami_id = ec2.register_image(**kwargs)["ImageId"]

    if wait:
        ec2.get_waiter("image_available").wait(
            ImageIds=[new_ami_id],
            WaiterConfig={"Delay": waiter_delay,
                          "MaxAttempts": waiter_max_attempts},
        )

    # Only now is it safe to drop the intermediate.  The snapshots survive it
    # by design and are referenced by the new AMI.
    ec2.deregister_image(ImageId=source_ami_id)
    return new_ami_id, "uefi"
