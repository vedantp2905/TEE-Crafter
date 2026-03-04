"""
Nitro-Agent CLI entrypoint.

Commands and deployment logic are split across:
- cli/constants.py      – PIPELINE_VERSION, console
- cli/loaders.py        – load_remote_setup_template, load_root_ca
- cli/audit_helpers.py  – save_audit_trail
- cli/deployment/       – Terraform apply, SSM setup, enclave/proxy, client run, phase orchestration
- cli/commands/         – destroy, verify-provenance, deploy-from-build, deploy
"""

import click
from dotenv import load_dotenv

from nitro_agent.cli.constants import console
from nitro_agent.cli.commands import register_commands

load_dotenv()


@click.group()
def cli():
    """Nitro-Agent: AI-powered AWS Nitro Enclave deployer."""
    pass


register_commands(cli)


def main():
    cli()


if __name__ == "__main__":
    main()
