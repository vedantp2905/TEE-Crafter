"""CLI command implementations."""

from tee_crafter.cli.commands.destroy import register as register_destroy
from tee_crafter.cli.commands.verify_provenance import register as register_verify_provenance
from tee_crafter.cli.commands.verify_siem_chain import register as register_verify_siem_chain
from tee_crafter.cli.commands.siem_stage import register as register_siem_stage
from tee_crafter.cli.commands.byok_stage import register as register_byok_stage
from tee_crafter.cli.commands.audit_keys import register as register_audit_keys
from tee_crafter.cli.commands.deploy.from_build import register as register_deploy_from_build
from tee_crafter.cli.commands.deploy.deploy import register as register_deploy
from tee_crafter.cli.commands.deploy.deploy_container import register as register_deploy_container
from tee_crafter.cli.commands.compliance import register as register_compliance
from tee_crafter.cli.commands.seal_input import register as register_seal_input
from tee_crafter.cli.commands.residency import register as register_residency
from tee_crafter.cli.commands.fleet import register as register_fleet
from tee_crafter.cli.commands.list_instances import register as register_list_instances
from tee_crafter.cli.commands.internal import register as register_internal


def register_commands(cli):
    """Register all CLI commands on the given Click group."""
    register_destroy(cli)
    register_verify_provenance(cli)
    register_verify_siem_chain(cli)
    register_siem_stage(cli)
    register_byok_stage(cli)
    register_audit_keys(cli)
    register_deploy_from_build(cli)
    register_deploy(cli)
    register_deploy_container(cli)
    register_compliance(cli)
    register_seal_input(cli)
    register_residency(cli)
    register_fleet(cli)
    register_list_instances(cli)
    register_internal(cli)
