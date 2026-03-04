"""CLI command implementations."""

from nitro_agent.cli.commands.destroy import register as register_destroy
from nitro_agent.cli.commands.verify_provenance import register as register_verify_provenance
from nitro_agent.cli.commands.deploy_from_build import register as register_deploy_from_build
from nitro_agent.cli.commands.deploy import register as register_deploy


def register_commands(cli):
    """Register all CLI commands on the given Click group."""
    register_destroy(cli)
    register_verify_provenance(cli)
    register_deploy_from_build(cli)
    register_deploy(cli)
