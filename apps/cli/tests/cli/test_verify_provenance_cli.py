"""End-to-end Click tests for ``tee-crafter verify-provenance``."""
from __future__ import annotations


import click
from click.testing import CliRunner

import pytest

from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.audit import build_layout as _layout
from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.cli.constants import console as cli_console
from tee_crafter.cli.commands.verify_provenance import register


@pytest.fixture
def cli_app():
    @click.group()
    def cli():
        pass

    register(cli)
    return cli


def _emit_minimal_provenance(tmp_path):
    audit = BuildAuditTrail()
    audit.set_metadata("0.1.0", str(tmp_path))
    audit.set_tee_platform("snp-aws")
    audit.record("Build", "test build", "pass")
    audit.record_check(
        "Phase 0", "BYOK provider resolved", "BYOK-001",
        observed="aws-kms",
    )
    audit.record_check(
        "Phase 0", "SIEM signing on", "SIEM-006",
        observed=True,
    )
    # Saving produces both build_provenance.json + audit_evidence.json
    # in the same directory.
    save_audit_trail(audit, str(tmp_path), cli_console)
    return _layout.provenance_json(str(tmp_path))


def test_verify_provenance_with_ledger_passes(cli_app, tmp_path):
    prov = _emit_minimal_provenance(tmp_path)
    runner = CliRunner()
    res = runner.invoke(
        cli_app,
        ["verify-provenance", "--file", prov, "--skip-signature"],
        catch_exceptions=False,
    )
    assert res.exit_code == 0, res.output


def test_verify_provenance_required_check_gate_passes(cli_app, tmp_path):
    prov = _emit_minimal_provenance(tmp_path)
    runner = CliRunner()
    res = runner.invoke(
        cli_app,
        ["verify-provenance", "--file", prov,
         "--skip-signature",
         "--required-checks", "BYOK-001,SIEM-006"],
        catch_exceptions=False,
    )
    assert res.exit_code == 0, res.output


def test_verify_provenance_required_check_gate_fails_on_missing(
    cli_app, tmp_path,
):
    prov = _emit_minimal_provenance(tmp_path)
    runner = CliRunner()
    res = runner.invoke(
        cli_app,
        ["verify-provenance", "--file", prov,
         "--skip-signature",
         "--required-checks", "BYOK-001,DEFINITELY-MISSING-CHECK"],
        catch_exceptions=False,
    )
    assert res.exit_code == 4, res.output
