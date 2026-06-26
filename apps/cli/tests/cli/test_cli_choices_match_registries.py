"""Every provider the code supports must be accepted by the CLI that selects it.

``--byok azure-skr`` was rejected at Click parse time — ``'azure-skr' is not one
of 'none', 'aws-kms', 'azure-kv', 'gcp-kms', 'external-hsm'`` — for as long as it
existed. It had been added to ``BYOK_PROVIDERS``, threaded through the config
validator, the ``TF_VAR_*`` exporter, the runtime bootstrap, the Terraform
templates and three bake scripts. The one thing not updated was a second,
hand-written choice list in the ``@click.option`` decorator.

The consequence is worth stating plainly: **the only BYOK provider that can work
on an Azure confidential VM was unreachable from the CLI**, and 60 unit tests
were green because every one of them called the internal functions directly. The
failure surfaced on the first attempt to actually run it.

So these tests do not check the option list against a literal — that would just
be a third copy. They drive the real Click command and assert that a value the
code claims to support gets past parsing.
"""
from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

from tee_crafter.cli.commands.deploy.byok_mode import BYOK_PROVIDERS
from tee_crafter.cli.commands.deploy.siem_mode import SIEM_PROVIDERS


def _deploy_cli():
    from tee_crafter.cli.commands.deploy.deploy import register

    group = click.Group()
    register(group)
    return group


def _parse_error_for(*args: str) -> str:
    """Run ``deploy`` with *args* and return output if Click rejected the value.

    Uses ``--no-deploy`` and a nonexistent source so the command fails fast on
    something *other* than the flag under test; a Click ``UsageError`` for an
    invalid choice is exit code 2 and mentions "is not one of".
    """
    r = CliRunner().invoke(_deploy_cli(), ["deploy", *args])
    return r.output if "is not one of" in r.output else ""


@pytest.mark.parametrize("provider", sorted(BYOK_PROVIDERS))
def test_every_byok_provider_is_accepted_by_the_cli(provider):
    err = _parse_error_for("--byok", provider, "--source", "/nonexistent")
    assert not err, (
        f"--byok {provider} is in BYOK_PROVIDERS but the CLI rejects it:\n{err}")


@pytest.mark.parametrize("provider", sorted(SIEM_PROVIDERS))
def test_every_siem_provider_is_accepted_by_the_cli(provider):
    """Same shape of bug, checked on the neighbouring flag before it bites."""
    err = _parse_error_for("--siem", provider, "--source", "/nonexistent")
    assert not err, (
        f"--siem {provider} is in SIEM_PROVIDERS but the CLI rejects it:\n{err}")


def test_a_provider_that_does_not_exist_is_still_rejected():
    """The fix must not have widened the option to accept anything."""
    assert _parse_error_for("--byok", "not-a-provider",
                            "--source", "/nonexistent")


def test_azure_skr_specifically(monkeypatch):
    """Named on its own, because this is the one that was broken.

    It is also the only BYOK provider that works on an Azure CVM, so a
    regression here silently removes Azure BYOK entirely.
    """
    assert "azure-skr" in BYOK_PROVIDERS
    assert not _parse_error_for("--byok", "azure-skr", "--source",
                                "/nonexistent")


def test_the_option_choices_are_derived_not_copied():
    """Guard the mechanism, not just today's outcome.

    Asserting the two lists are equal today would pass again the moment someone
    re-hardcodes them with matching contents. This asserts the decorator
    actually references the registry.
    """
    import inspect

    from tee_crafter.cli.commands.deploy import deploy_container

    src = inspect.getsource(deploy_container)
    byok_opt = src.split('"--byok", "byok_provider"', 1)[1][:400]
    assert "BYOK_PROVIDERS" in byok_opt, (
        "--byok choices should come from BYOK_PROVIDERS, not a literal list")
