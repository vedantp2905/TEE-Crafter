"""Shared helpers for all bake-ami platform modules."""
import hashlib
import json
import os
import re
import subprocess
import time
import uuid

import click

from tee_crafter.cli.loaders import (
    load_nitro_setup_template,
    render_sgx_setup_script,
    load_snp_aws_setup_template,
    load_snp_azure_setup_template,
    load_tdx_setup_template,
    load_gpu_cc_aws_setup_template,
    load_gpu_cc_gcp_setup_template,
    load_gpu_cc_azure_setup_template,
    _inject_security_profiles,
    _inject_systemd_units,
    inject_secure_boot_block,
)

from tee_crafter.cli.commands.baking.common.azure_cvm import (  # noqa: F401 – re-export
    create_azure_cvm,
)


#: Set this to make the per-run bake suffix deterministic (CI reruns that want
#: to re-attach to a half-finished bake, or a test that asserts on names).
BAKE_SUFFIX_ENV = "TEE_CRAFTER_BAKE_SUFFIX"


def bake_run_suffix() -> str:
    """A short, lowercase-alphanumeric token unique to this bake invocation.

    Every Azure bake used to name its throwaway resource group and VM after the
    platform alone (``tee-crafter-bake-tdx-rg`` / ``tee-crafter-bake-tdx-vm``),
    and every bake ends by deleting that resource group.  Two ``bake-ami`` runs
    for the same platform therefore shared one resource group: the first to
    finish deleted the second's live VM mid-bake, and the loser's
    ``ResourceGroupBeingDeleted`` retry loop (see the per-platform bake modules)
    could only sit there until it gave up.  Suffixing the *ephemeral* names
    makes concurrent bakes independent.

    The persistent names — the images resource group, the Compute Gallery and
    the gallery image definition — are deliberately *not* suffixed: they are the
    shared destination every bake publishes into.

    Override with :data:`BAKE_SUFFIX_ENV` when you need a stable value.
    """
    override = os.environ.get(BAKE_SUFFIX_ENV, "").strip().lower()
    if override:
        cleaned = re.sub(r"[^a-z0-9]", "", override)[:12]
        if cleaned:
            return cleaned
    return uuid.uuid4().hex[:8]


def azure_subscription_fingerprint() -> str:
    """8 lowercase hex chars derived from the current Azure subscription id.

    Azure **storage account names share one global namespace across every
    Azure tenant**, so the old hard-coded names (``teecraftertdxvhd``,
    ``teecraftersgxvhd``, ``teecraftersnpvhd``, ``teecraftergpuccvhd``) are
    first-come-first-served: once any Azure customer anywhere owns the name,
    ``az storage account create`` fails for everyone else and the bake dies at
    the following ``az storage account keys list``.

    Hashing the subscription id gives a name that is unique per subscription but
    *stable across bakes within it*, so repeat bakes reuse one staging account
    instead of leaking a fresh one per run.

    Returns ``""`` when the subscription cannot be read (not logged in, ``az``
    missing); callers then fall back to the legacy fixed name.
    """
    try:
        res = subprocess.run(
            ["az", "account", "show", "--output", "json"],
            capture_output=True, text=True, timeout=30,
        )
        if res.returncode != 0:
            return ""
        sub_id = (json.loads(res.stdout) or {}).get("id", "")
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, TypeError):
        return ""
    if not sub_id:
        return ""
    return hashlib.sha256(sub_id.encode("utf-8")).hexdigest()[:8]


def azure_vhd_storage_account(base_name: str, env_var: str) -> str:
    """Resolve the VHD staging storage account name for an Azure bake.

    Precedence: explicit ``env_var`` > ``base_name`` + subscription fingerprint
    > ``base_name`` unchanged (only when the subscription cannot be read).

    Azure storage account names must be 3-24 lowercase alphanumeric characters,
    so the base is clipped to 16 before the 8-character fingerprint is appended
    (``teecraftergpuccvhd`` is already 18 characters on its own).
    """
    explicit = os.environ.get(env_var, "").strip()
    if explicit:
        return explicit
    fingerprint = azure_subscription_fingerprint()
    if not fingerprint:
        return base_name
    return f"{base_name[:16]}{fingerprint}"


def load_setup_script(platform: str, *, enable_secure_boot: bool = False, **kwargs) -> str:
    """Load and parameterize the host setup script for the given platform.

    ``enable_secure_boot`` (default ``False``) controls whether the
    ``__SECURE_BOOT_ENROLL__`` placeholder in the AWS setup scripts
    (``setup_nitro.sh``, ``setup_snp_aws.sh``) is replaced with the real
    UEFI key-enrollment block from ``scripts/common/secure_boot_enroll_aws.sh``.
    All other platforms ignore this flag (their AMIs / images use the
    cloud-provider's Trusted Launch / Shielded VM toggles directly via
    Terraform — see ``snp/azure``, ``snp/gcp``, ``tdx/*``, ``sgx``).
    """
    if platform == "nitro-aws":
        template = load_nitro_setup_template()
        rendered = template.format(**kwargs)
        return inject_secure_boot_block(rendered, enable_secure_boot)
    elif platform == "tdx-azure":
        return load_tdx_setup_template()
    elif platform == "snp-aws":
        return inject_secure_boot_block(
            load_snp_aws_setup_template(), enable_secure_boot,
        )
    elif platform == "snp-azure":
        return load_snp_azure_setup_template()
    elif platform == "snp-gcp":
        script_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "..", "..", "scripts", "snp_gcp")
        with open(os.path.join(script_dir, "setup_snp_gcp.sh"), "r", encoding="utf-8") as f:
            content = _inject_security_profiles(f.read())
        return _inject_systemd_units(content, "snp-gcp")
    elif platform == "tdx-gcp":
        script_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "..", "..", "scripts", "tdx_gcp")
        with open(os.path.join(script_dir, "setup_tdx_gcp.sh"), "r", encoding="utf-8") as f:
            content = _inject_security_profiles(f.read())
        return _inject_systemd_units(content, "tdx-gcp")
    elif platform == "sgx-azure":
        return render_sgx_setup_script()
    elif platform == "gpu-cc-aws":
        return load_gpu_cc_aws_setup_template()
    elif platform == "gpu-cc-gcp":
        return load_gpu_cc_gcp_setup_template()
    elif platform == "gpu-cc-azure":
        return load_gpu_cc_azure_setup_template()
    else:
        raise ValueError(f"Unknown platform: {platform}")


def resolve_base_ami(ec2, platform: str, region: str, architecture: str = "x86_64") -> str:
    """Find the latest base AMI for a given platform."""
    if platform == "nitro-aws":
        arch = architecture or "x86_64"
        name_suffix = "arm64" if arch == "arm64" else "x86_64"
        resp = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": [f"al2023-ami-2023.*-kernel-*-{name_suffix}"]},
                {"Name": "architecture", "Values": [arch]},
                {"Name": "state", "Values": ["available"]},
            ],
        )
    else:
        resp = ec2.describe_images(
            Owners=["099720109477"],
            Filters=[
                {"Name": "name", "Values": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )
    images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:
        raise click.ClickException(f"No base AMI found for platform={platform} in {region}")
    return images[0]["ImageId"]


def get_default_subnet(ec2) -> str:
    resp = ec2.describe_subnets(Filters=[{"Name": "default-for-az", "Values": ["true"]}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise click.ClickException("No default subnet found. Specify --subnet-id.")
    return subnets[0]["SubnetId"]


def get_default_subnet_in_az(ec2, availability_zone: str) -> str:
    """Return the default-for-az subnet located in the requested AZ.

    This is used to keep GPU deployments pinned to a specific AZ
    (e.g., us-east-2a) to avoid capacity/availability-zone drift.
    """
    resp = ec2.describe_subnets(Filters=[
        {"Name": "default-for-az", "Values": ["true"]},
        {"Name": "availability-zone", "Values": [availability_zone]},
    ])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise click.ClickException(
            f"No default subnet found in AZ={availability_zone}. Specify --subnet-id.")
    return subnets[0]["SubnetId"]


def get_ssm_instance_profile(iam) -> str:
    import json
    from botocore.exceptions import ClientError

    role_name = "tee-crafter-bake-ami-role"
    profile_name = "tee-crafter-bake-ami-profile"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    try:
        iam.get_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Temporary role for TEE-Crafter AMI baking (SSM access only)",
        )
    for arn in [
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ]:
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        except ClientError:
            pass
    try:
        iam.get_instance_profile(InstanceProfileName=profile_name)
    except iam.exceptions.NoSuchEntityException:
        iam.create_instance_profile(InstanceProfileName=profile_name)
        iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        time.sleep(10)
    return profile_name


def az_cli(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run an ``az`` CLI command and return the result."""
    filtered = [a for a in args if a != "--output"]
    has_output = any(a == "--output" for a in args)
    cmd = ["az", *filtered]
    if not has_output:
        cmd += ["--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise click.ClickException(f"az {' '.join(args[:3])}... failed:\n{result.stderr[:8000]}")
    return result
