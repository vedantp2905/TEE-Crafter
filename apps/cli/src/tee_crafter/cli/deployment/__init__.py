"""Deployment phase: Terraform apply and post-deploy automation."""

from tee_crafter.cli.deployment.nitro.phase import run_nitro_deployment_phase
from tee_crafter.cli.deployment.sgx.phase import run_sgx_deployment_phase
from tee_crafter.cli.deployment.tdx.phase import run_tdx_deployment_phase
from tee_crafter.cli.deployment.snp.aws_phase import run_snp_aws_deployment_phase
from tee_crafter.cli.deployment.snp.azure_phase import run_snp_azure_deployment_phase

__all__ = [
    "run_nitro_deployment_phase",
    "run_sgx_deployment_phase",
    "run_tdx_deployment_phase",
    "run_snp_aws_deployment_phase",
    "run_snp_azure_deployment_phase",
]
