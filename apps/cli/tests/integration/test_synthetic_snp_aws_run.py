"""Synthetic ``snp-aws`` deploy → verify-provenance round-trip.

The plan calls for a real `tee-crafter deploy snp-aws --byok-config
... --siem syslog-cef` run capped off with
``tee-crafter verify-provenance --required-checks``. Until that real
cloud run lands in CI we emulate the artefacts a successful deploy
*would* produce — the ledger fields are real, the cloud calls are not
— and exercise the gate end-to-end. Regressions in the catalogue,
ledger schema, or required-check resolver will surface here.
"""
from __future__ import annotations

import json
import os

import click
from click.testing import CliRunner

from tee_crafter.cli.audit_helpers import (
    emit_teardown_and_cloud_audit,
    save_audit_trail,
)
from tee_crafter.cli.commands.deploy.flag_audit import audit_dev_hatch_flags
from tee_crafter.cli.commands.verify_provenance import register
from tee_crafter.cli.constants import console as cli_console
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.audit import build_layout as _layout


def _emit_artifacts(build_dir, *, tee_platform: str):
    # Pretend the post-destroy shred + docker prune both ran cleanly.
    (build_dir / "post_destroy_shred_manifest.txt").write_text(
        "shred manifest", encoding="utf-8")
    (build_dir / "docker_prune_summary.txt").write_text(
        "docker prune ok", encoding="utf-8")
    audit = BuildAuditTrail()
    audit.set_metadata("0.1.0", str(build_dir))
    audit.set_tee_platform(tee_platform)

    audit.record_check(
        "Phase 0", "tee_platform recognised", "PC-001",
        observed=tee_platform,
    )
    audit.record_check(
        "Phase 0", "flow detected", "PC-002",
        observed="container",
    )
    audit_dev_hatch_flags(
        audit, tee_platform=tee_platform,
        byok_enabled=True,
        byok_provider="aws-kms",
        siem_provider="syslog-cef",
    )
    audit.record_check(
        "Phase 1", "Critical CVEs == 0", "VLN-002",
        observed=True,
    )
    audit.record_check(
        "Phase 1", "terraform validate", "IAC-001", observed=True,
    )
    audit.record_check(
        "Phase 1", "no SSH ingress", "IAC-002", observed=True,
    )
    audit.record_check(
        "Phase 1", "no 0.0.0.0/0 ingress", "IAC-003", observed=True,
    )
    audit.record_check(
        "Phase 2", "terraform apply success", "DEP-001", observed=True,
    )
    audit.record_check(
        "Phase 2", "Instance running", "DEP-002", observed=True,
    )
    audit.record_check(
        "Phase 2", "BYOK provider resolved", "BYOK-001",
        expected=True, observed=True,
        note="provider=aws-kms",
    )
    audit.record_check(
        "Phase 2", "SIEM provider resolved", "SIEM-001",
        expected=True, observed=True,
        note="provider=syslog-cef",
    )
    audit.record_check(
        "Phase 5", "Client received attestation report", "ATT-001",
        observed=True,
    )
    audit.record_check(
        "Phase 5", "Client verified attestation signature", "ATT-002",
        observed=True,
    )
    emit_teardown_and_cloud_audit(
        audit, tee_platform=tee_platform,
        teardown_ok=True, teardown_msg="ok",
        outputs={},
        build_dir=str(build_dir),
    )
    save_audit_trail(audit, str(build_dir), cli_console)
    return audit


def test_synthetic_snp_aws_deploy_then_verify(tmp_path):
    _emit_artifacts(tmp_path, tee_platform="snp-aws")
    prov_path = _layout.provenance_json(str(tmp_path))
    ledger_path = _layout.audit_evidence_json(str(tmp_path))
    assert os.path.isfile(prov_path)
    assert os.path.isfile(ledger_path)

    @click.group()
    def cli():
        pass

    register(cli)
    runner = CliRunner()
    res = runner.invoke(
        cli,
        ["verify-provenance", "--file", prov_path,
         "--skip-signature",
         "--required-checks", "BYOK-001,SIEM-001,ATT-002,DEP-001,IAC-002"],
        catch_exceptions=False,
    )
    assert res.exit_code == 0, res.output

    with open(ledger_path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    cids = {r["check_id"] for r in doc["rows"]}
    for required in ("PC-001", "PC-002", "DH-005", "VLN-002",
                     "IAC-002", "BYOK-001", "SIEM-001",
                     "ATT-001", "TEAR-001"):
        assert required in cids, required


def test_synthetic_nitro_aws_deploy_then_verify(tmp_path):
    """Same artefact emission contract as snp-aws; primarily catches
    Nitro-specific catalogue regressions (CT-003, IAC-004, BYOK-007 N/A)."""
    _emit_artifacts(tmp_path, tee_platform="nitro-aws")
    prov_path = _layout.provenance_json(str(tmp_path))
    ledger_path = _layout.audit_evidence_json(str(tmp_path))
    assert os.path.isfile(prov_path)
    assert os.path.isfile(ledger_path)

    @click.group()
    def cli():
        pass

    register(cli)
    runner = CliRunner()
    res = runner.invoke(
        cli,
        ["verify-provenance", "--file", prov_path,
         "--skip-signature",
         "--required-checks", "BYOK-001,SIEM-001,ATT-002,DEP-001,IAC-002"],
        catch_exceptions=False,
    )
    assert res.exit_code == 0, res.output


def test_emit_att_verdicts_records_full_runtime_family():
    """``emit_att_verdicts`` must record every catalogued ATT row.

    The full runtime gate (ATT-001..ATT-008) is what
    ``--required-checks auto`` relies on.  Regression test for the
    historical gap where ATT-004 ("Issuer in pinned allowlist") was
    in DEFAULT_REQUIRED_CHECKS but never emitted by the per-platform
    client wrappers.
    """
    from tee_crafter.cli.deployment.common.attestation_report import (
        emit_att_verdicts,
    )

    audit = BuildAuditTrail()
    audit.set_tee_platform("snp-aws")
    emit_att_verdicts(
        audit, success=True,
        measurement_fields={
            "issuer": "AMD-SEV",
            "spki_sha256": "deadbeef" * 8,
            "nonce": "ab" * 16,
            "mrtd": "ff" * 24,
        },
    )
    cids = {r.check_id for r in audit.ledger.rows}
    for required in ("ATT-001", "ATT-002", "ATT-003", "ATT-004",
                     "ATT-005", "ATT-006", "ATT-007", "ATT-008"):
        assert required in cids, required
    # ATT-009 / ATT-010 are GPU-only; they must NOT fire on snp-aws.
    assert "ATT-009" not in cids
    assert "ATT-010" not in cids


def test_emit_att_verdicts_gpu_cc_emits_nvattest_and_dual_bind():
    """GPU-CC platforms must additionally record ATT-009 + ATT-010."""
    from tee_crafter.cli.deployment.common.attestation_report import (
        emit_att_verdicts,
    )

    audit = BuildAuditTrail()
    audit.set_tee_platform("gpu-cc-aws")
    emit_att_verdicts(
        audit, success=True,
        measurement_fields={
            "issuer": "NVIDIA-NRAS",
            "spki_sha256": "feed" * 16,
            "nonce": "ab" * 16,
            "mrtd": "ff" * 24,
            "nras_token_kid": "kid-12345",
            "nras_eat_digest": "ee" * 32,
            "nras_token_valid": True,
        },
    )
    cids = {r.check_id: r.verdict for r in audit.ledger.rows}
    assert cids.get("ATT-009") == "pass"
    assert cids.get("ATT-010") == "pass"
