"""Pre-flight AMI/image validators for the deploy command."""

import os

import boto3
from botocore.exceptions import ClientError
from tee_crafter.cli.constants import Panel

from tee_crafter.cli.constants import console


def get_effective_region() -> str:
    session_region = boto3.Session().region_name
    return (
        os.getenv("TF_VAR_aws_region")
        or os.getenv("AWS_REGION")
        or session_region
        or "us-east-2"
    )


def get_instance_architecture(instance_type: str | None) -> str | None:
    """Delegates to :func:`tee_crafter.core.catalog.instance_architecture`."""
    from tee_crafter.core.catalog import instance_architecture
    return instance_architecture(instance_type)


class SecureBootUndetermined(RuntimeError):
    """The pinned AMI does not prove that UEFI Secure Boot is enrolled."""


#: Explicit, audited opt-in to deploy an AMI whose Secure-Boot posture is
#: unknown or off.  Named separately from ``TF_VAR_enable_secure_boot`` so an
#: operator cannot disable the gate by accident while setting the Terraform
#: variable for an unrelated reason.
from tee_crafter.core.env_flags import env_hatch_open
ALLOW_NO_SECURE_BOOT_ENV = "TEE_CRAFTER_ALLOW_NO_SECURE_BOOT"


def secure_boot_override_enabled() -> bool:
    return env_hatch_open(ALLOW_NO_SECURE_BOOT_ENV)


def propagate_secure_boot_var_from_ami(custom_ami: str) -> str:
    """Set ``TF_VAR_enable_secure_boot`` from the pinned AMI's tags.

    Reads the ``tee-crafter-secure-boot`` tag written by ``bake-ami``.
    Matrix:

    +--------------------------+-----------------------------------------+
    | AMI tag                  | Action                                  |
    +==========================+=========================================+
    | ``enabled``              | export ``TF_VAR_enable_secure_boot=true``
    |                          | and return ``"true"``.                  |
    +--------------------------+-----------------------------------------+
    | ``disabled`` / missing / | raise :class:`SecureBootUndetermined`,  |
    | tag fetch failed         | unless :data:`ALLOW_NO_SECURE_BOOT_ENV` |
    |                          | is set — then export ``false`` and      |
    |                          | return ``"false"`` / ``"unknown"``.     |
    +--------------------------+-----------------------------------------+

    An EC2 tag is mutable metadata, not evidence: anyone with
    ``ec2:CreateTags`` can flip it, and it is absent on any AMI not baked by
    this tool.  It used to be silently coerced to ``false`` here, and the
    audit row graded ``sb_mode in ("true", "false")`` — i.e. it passed
    whenever a *value was determined*, not when Secure Boot was actually on.
    Both halves of that are now fail-closed: no ``enabled`` tag means no
    deploy without an explicit, recorded override.

    If the operator pre-set ``TF_VAR_enable_secure_boot`` we honour it
    verbatim (``false`` still requires the override).
    """
    explicit = os.environ.get("TF_VAR_enable_secure_boot")
    if explicit is not None and explicit.strip().lower() in ("true", "false"):
        value = explicit.strip().lower()
        if value == "false" and not secure_boot_override_enabled():
            raise SecureBootUndetermined(
                "TF_VAR_enable_secure_boot=false was set in the environment, "
                "which launches the instance without UEFI Secure Boot."
            )
        return value

    region = get_effective_region()
    ec2 = boto3.client("ec2", region_name=region)
    sb_tag = ""
    detail = ""
    try:
        resp = ec2.describe_images(ImageIds=[custom_ami])
        images = resp.get("Images", [])
        if not images:
            detail = f"no AMI found with ID {custom_ami} in {region}"
        else:
            tags = {t.get("Key"): t.get("Value")
                    for t in images[0].get("Tags", []) or []}
            sb_tag = (tags.get("tee-crafter-secure-boot") or "").strip().lower()
            if not sb_tag:
                detail = (f"{custom_ami} carries no tee-crafter-secure-boot tag "
                          f"(was it baked by `tee-crafter internal bake-ami`?)")
            elif sb_tag != "enabled":
                detail = f"{custom_ami} is tagged tee-crafter-secure-boot={sb_tag!r}"
    except ClientError as exc:
        detail = f"could not read the AMI's tags in {region}: {exc}"

    if sb_tag == "enabled":
        os.environ["TF_VAR_enable_secure_boot"] = "true"
        return "true"

    if not secure_boot_override_enabled():
        raise SecureBootUndetermined(detail or "Secure Boot posture is unknown")
    # Recorded override: Terraform defaults ``enable_secure_boot`` to true, so
    # the launch precondition would reject an un-enrolled AMI without this.
    os.environ["TF_VAR_enable_secure_boot"] = "false"
    return "false" if sb_tag == "disabled" else "unknown"


def validate_custom_ami_architecture(custom_ami: str, instance_type: str | None) -> bool:
    """Ensure AMI architecture matches the effective instance type family."""
    expected_arch = get_instance_architecture(instance_type)
    if expected_arch is None:
        console.print(
            Panel.fit(
                "[yellow]Warning: Could not infer instance architecture from type; "
                "skipping AMI architecture pre-flight check.[/yellow]",
                border_style="yellow",
            )
        )
        return True

    region = get_effective_region()
    ec2 = boto3.client("ec2", region_name=region)
    try:
        resp = ec2.describe_images(ImageIds=[custom_ami])
    except ClientError as e:
        console.print(
            Panel.fit(
                "[yellow]Warning: Could not inspect custom AMI architecture; "
                "skipping AMI architecture check.[/yellow]\n\n"
                f"[dim]{e}[/dim]",
                border_style="yellow",
            )
        )
        return True

    images = resp.get("Images", [])
    if not images:
        console.print(
            Panel.fit(
                f"[yellow]Warning: No AMI found with ID {custom_ami}; "
                "skipping AMI architecture check.[/yellow]",
                border_style="yellow",
            )
        )
        return True

    img = images[0]
    arch_list = img.get("Architectures") or []
    ami_arch = arch_list[0] if arch_list else img.get("Architecture")

    if not ami_arch or ami_arch == expected_arch:
        return True

    console.print(
        Panel.fit(
            "[bold red]Custom AMI architecture mismatch[/bold red]\n\n"
            "The chosen AMI cannot be used with the requested instance type.\n\n"
            f"- AMI ID: {custom_ami}\n"
            f"- AMI architecture: {ami_arch}\n"
            f"- Instance type: {instance_type}\n"
            f"- Expected instance architecture: {expected_arch}\n\n"
            "Re-bake a new AMI on a matching instance family (e.g. Graviton for arm64) "
            "or choose an instance type whose architecture matches this AMI.",
            border_style="red",
        )
    )
    return False
