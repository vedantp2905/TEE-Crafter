"""bake-ami command: build a custom image with all TEE dependencies pre-installed.

Internal-only command. Registered under the hidden ``tee-crafter internal``
subgroup — invoked as ``tee-crafter internal bake-ami …``.

Eliminates runtime internet access, removing supply-chain risk from package
fetching at boot.  The resulting image ID is passed to ``deploy --ami-id`` /
``deploy-container --ami-id`` / ``deploy-from-build --ami-id``.

Platform-specific logic lives in:
  bake_nitro.py  — AWS Nitro Enclaves
  bake_sgx.py    — Azure SGX / Gramine
  bake_tdx.py    — Azure Intel TDX
  bake_snp.py    — AMD SEV-SNP (AWS + Azure)
  bake_gcp.py    — GCP Confidential VMs (AMD SEV-SNP + Intel TDX)
  gpu_cc.py      — NVIDIA Confidential GPU (AWS + GCP + Azure)
"""

import click

from tee_crafter.cli.commands.baking.nitro import bake_nitro_ami
from tee_crafter.cli.commands.baking.sgx import bake_sgx_azure_image
from tee_crafter.cli.commands.baking.tdx import bake_tdx_azure_image
from tee_crafter.cli.commands.baking.snp import bake_snp_aws_ami, bake_snp_azure_image
from tee_crafter.cli.commands.baking.gcp import bake_snp_gcp_image, bake_tdx_gcp_image
from tee_crafter.cli.commands.baking.gpu_cc import (
    bake_gpu_cc_aws_ami, bake_gpu_cc_gcp_image, bake_gpu_cc_azure_image,
)

_PLATFORM_DEFAULT_REGIONS = {
    "nitro-aws": "us-east-2",
    "sgx-azure": "westus",
    "tdx-azure": "westus",
    "snp-aws": "us-east-2",
    "snp-azure": "westus",
    "snp-gcp": "us-central1-a",
    "tdx-gcp": "us-central1-a",
    "gpu-cc-aws": "us-east-2",
    "gpu-cc-gcp": "us-central1-a",
    "gpu-cc-azure": "eastus2",
}

_ALL_PLATFORMS = list(_PLATFORM_DEFAULT_REGIONS.keys())


_SECURE_BOOT_AWS_PLATFORMS = {"nitro-aws", "snp-aws"}


def bake_ami_internal(
    tee_platform: str,
    region: str,
    instance_type: str | None = None,
    subnet_id: str | None = None,
    enclave_ram: int = 4096,
    enclave_cpu: int = 2,
    spot: bool = False,
    enable_secure_boot: bool = True,
) -> str:
    """Programmatic entry point to bake a TEE-Crafter image.

    Returns the image ID (AMI ID on AWS, Azure Image/Gallery resource ID on Azure).

    ``enable_secure_boot`` (default ``True`` since 2026 — see
    ``docs/security.md`` §15.1A) is honoured for ``nitro-aws`` and
    ``snp-aws`` (the only platforms where SB is a bake-time decision
    baked into the AMI's UEFI NVRAM).  On Azure SGX/TDX/SNP and GCP
    TDX/SNP, Secure Boot / Trusted Launch is already hard-enabled in
    the Terraform templates, so callers must pass ``False`` to suppress
    a redundant request (the CLI callback in this module normalises
    that for the operator).  The three GPU CC platforms keep SB OFF
    (their Terraform templates default ``var.enable_secure_boot=false``)
    because the proprietary NVIDIA DKMS driver is not signed by any
    standard UEFI vendor key; see ``docs/gpu_flow.md`` for the
    rationale.  Passing ``enable_secure_boot=True`` for any non-AWS
    platform raises ``click.ClickException`` so the caller can't
    silently ship an AMI/image whose SB posture doesn't match its
    stated intent.
    """
    if tee_platform == "gpu-cc-azure":
        from tee_crafter.core.gpu import GPU_CC_AZURE_LOCATION

        region = GPU_CC_AZURE_LOCATION
    use_spot = spot
    if enable_secure_boot and tee_platform not in _SECURE_BOOT_AWS_PLATFORMS:
        raise click.ClickException(
            f"--enable-secure-boot only applies to {sorted(_SECURE_BOOT_AWS_PLATFORMS)}; "
            f"platform '{tee_platform}' already enables Secure Boot via Terraform "
            "(snp-azure / snp-gcp / tdx-azure / tdx-gcp / sgx-azure) or keeps it "
            "intentionally off (gpu-cc-* — see docs/gpu_flow.md)."
        )
    if tee_platform == "nitro-aws":
        return bake_nitro_ami(region, instance_type, subnet_id, enclave_ram, enclave_cpu,
                              use_spot=use_spot, enable_secure_boot=enable_secure_boot)
    elif tee_platform == "sgx-azure":
        return bake_sgx_azure_image(region, instance_type, enclave_ram, enclave_cpu, use_spot=use_spot)
    elif tee_platform == "tdx-azure":
        return bake_tdx_azure_image(region, instance_type, enclave_ram, enclave_cpu, use_spot=use_spot)
    elif tee_platform == "snp-aws":
        return bake_snp_aws_ami(region, instance_type, subnet_id, enclave_ram, enclave_cpu,
                                use_spot=use_spot, enable_secure_boot=enable_secure_boot)
    elif tee_platform == "snp-azure":
        return bake_snp_azure_image(region, instance_type, enclave_ram, enclave_cpu, use_spot=use_spot)
    elif tee_platform == "snp-gcp":
        return bake_snp_gcp_image(region, instance_type, enclave_ram, enclave_cpu, use_spot=use_spot)
    elif tee_platform == "tdx-gcp":
        return bake_tdx_gcp_image(region, instance_type, enclave_ram, enclave_cpu, use_spot=use_spot)
    elif tee_platform == "gpu-cc-aws":
        return bake_gpu_cc_aws_ami(region, instance_type, subnet_id, enclave_ram, enclave_cpu, use_spot=use_spot)
    elif tee_platform == "gpu-cc-gcp":
        return bake_gpu_cc_gcp_image(region, instance_type, enclave_ram, enclave_cpu, use_spot=use_spot)
    elif tee_platform == "gpu-cc-azure":
        return bake_gpu_cc_azure_image(region, instance_type, enclave_ram, enclave_cpu, use_spot=use_spot)
    else:
        raise click.ClickException(f"Unknown TEE platform: {tee_platform}")


def register(cli):
    @cli.command("bake-ami")
    @click.option(
        "--tee-platform", default="nitro-aws",
        type=click.Choice(_ALL_PLATFORMS, case_sensitive=False),
        help="TEE platform to bake (default: nitro-aws)",
    )
    @click.option(
        "--region", default=None,
        help="AWS region (Nitro/SNP-AWS) or Azure location (SGX/TDX/SNP-Azure). "
             "Defaults per platform.",
    )
    @click.option(
        "--instance-type", default=None,
        help="Override instance type (AWS) or VM size (Azure) for the bake instance",
    )
    @click.option("--subnet-id", default=None, help="Subnet for the bake instance (AWS only)")
    @click.option("--spot", is_flag=True, default=False, help="Use Spot / preemptible / low-priority for baking (needs spot quota)")
    @click.option(
        "--enclave-ram", default=4096, type=int,
        help="Nitro: baked allocator baseline RAM (MiB). The deploy rewrites "
             "this to the instance's enclave shape at launch, so the AMI is "
             "generic — leave the default unless you have a specific reason. "
             "Default: 4096 (4 GB).",
    )
    @click.option(
        "--enclave-cpu", default=2, type=int,
        help="Nitro: baked allocator baseline vCPUs (reconfigured at deploy). "
             "Default: 2.",
    )
    @click.option(
        "--enable-secure-boot/--no-enable-secure-boot", "enable_secure_boot",
        default=True, show_default=True,
        help=(
            "AWS only (nitro-aws, snp-aws): enroll UEFI Secure Boot PK/KEK/db "
            "on the bake instance via efi-updatevar; aws ec2 create-image then "
            "captures the resulting UEFI NVRAM into the AMI so instances launched "
            "from it boot with Secure Boot enforcing.  Defaults to ON — pass "
            "--no-enable-secure-boot to bake an unhardened dev AMI.  Silently "
            "ignored on snp-azure/snp-gcp/tdx-azure/tdx-gcp/sgx-azure (already "
            "SB-on in Terraform) and on gpu-cc-* (intentionally SB-off due to "
            "unsigned NVIDIA DKMS driver — explicit --enable-secure-boot on "
            "those platforms is rejected so the operator can't quietly assume "
            "a posture the AMI cannot deliver)."
        ),
    )
    def bake_ami(tee_platform, region, instance_type, subnet_id, spot, enclave_ram, enclave_cpu, enable_secure_boot):
        """Build a custom image with all TEE dependencies pre-installed.

        Supported platforms:
          nitro-aws    — AWS Nitro Enclaves
          sgx-azure    — Azure SGX / Gramine (DCsv3)
          tdx-azure    — Azure Intel TDX (DCesv6)
          snp-aws      — AWS AMD SEV-SNP (M6a/C6a/R6a)
          snp-azure    — Azure AMD SEV-SNP (DCasv5/ECasv5)
          snp-gcp      — GCP AMD SEV-SNP (N2D)
          tdx-gcp      — GCP Intel TDX (C3)
          gpu-cc-aws   — NVIDIA CC + NitroTPM (P5/P5en/P6)
          gpu-cc-gcp   — NVIDIA CC + TDX (A3 High-GPU)
          gpu-cc-azure — NVIDIA CC + SEV-SNP (NCC H100 v5)
        """
        tee_platform = tee_platform.lower()
        if region is None:
            region = _PLATFORM_DEFAULT_REGIONS.get(tee_platform, "us-east-2")

        # Secure Boot is meaningful at bake-time only for nitro-aws / snp-aws.
        # Default is now True (SB on for everything except gpu-cc-*), so on
        # every other platform we silently downgrade to False — UNLESS the
        # operator explicitly passed `--enable-secure-boot`, in which case we
        # raise to make the unsupported request visible.  This keeps `bake-ami
        # --tee-platform sgx-azure` working with stock defaults while still
        # rejecting `bake-ami --tee-platform gpu-cc-azure --enable-secure-boot`.
        ctx = click.get_current_context()
        try:
            sb_explicit = (
                ctx.get_parameter_source("enable_secure_boot")
                is click.core.ParameterSource.COMMANDLINE
            )
        except Exception:
            sb_explicit = False
        if enable_secure_boot and tee_platform not in _SECURE_BOOT_AWS_PLATFORMS:
            if sb_explicit:
                raise click.ClickException(
                    f"--enable-secure-boot only applies to {sorted(_SECURE_BOOT_AWS_PLATFORMS)}; "
                    f"platform '{tee_platform}' either already hard-enables Secure Boot "
                    "via Terraform (sgx-azure / snp-azure / tdx-azure / snp-gcp / tdx-gcp) "
                    "or intentionally keeps it off (gpu-cc-* — unsigned NVIDIA DKMS; "
                    "see docs/gpu_flow.md). Re-run without --enable-secure-boot."
                )
            enable_secure_boot = False

        # Cloud calls start here.  The credential probe and the quota preflight
        # both need the network, so they run *after* every offline flag guard —
        # otherwise `bake-ami --tee-platform gpu-cc-azure --enable-secure-boot`
        # reported "AWS credentials are not usable" instead of the actual
        # problem, and the guards above were untestable without live creds.
        from tee_crafter.cli.cloud_auth import validate_required_creds
        validate_required_creds(tee_platform)

        try:
            from tee_crafter.cli.preflight import run_preflight
            run_preflight(tee_platform, instance_type, region, use_spot=spot)
        except click.ClickException:
            raise
        except Exception:
            pass  # non-fatal

        bake_ami_internal(
            tee_platform=tee_platform,
            region=region,
            instance_type=instance_type,
            subnet_id=subnet_id,
            enclave_ram=enclave_ram,
            enclave_cpu=enclave_cpu,
            spot=spot,
            enable_secure_boot=enable_secure_boot,
        )
