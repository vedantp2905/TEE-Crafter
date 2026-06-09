"""Internal subcommands for power users / SaaS orchestrator only.

Anything registered on this group is hidden from the public ``--help`` of
``tee-crafter`` and intended to be invoked by the platform itself
(automated AMI baker, catalog management, etc.) rather than by end
users.  We keep them as CLI commands so the SaaS worker can shell out
without a separate Python entry point, but they should never appear in
public docs.

End users on the local CLI can still invoke them with
``tee-crafter internal <cmd>`` when explicitly needed for development.
"""

from __future__ import annotations

import click

from tee_crafter.cli.commands.bake_ami import register as register_bake_ami
from tee_crafter.cli.commands.compare_measurements import (
    register as register_compare_measurements,
)
from tee_crafter.cli.commands.pin_measurement import register as register_pin_measurement


@click.group("internal", hidden=True)
def internal():
    """(internal) Platform-only commands. Not part of the public CLI surface."""


def register(cli):
    register_bake_ami(internal)
    register_pin_measurement(internal)
    register_compare_measurements(internal)
    cli.add_command(internal)
