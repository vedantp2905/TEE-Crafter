"""Deploy command — unified Dockerfile execution model (plan 00)."""

from tee_crafter.cli.commands.deploy.deploy_container import register_deploy


def register(cli):
    """Register ``tee-crafter deploy`` (Dockerfile / OCI image → TEE)."""
    register_deploy(cli, command_name="deploy")
