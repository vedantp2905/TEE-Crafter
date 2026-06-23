"""Tests for tee_crafter.core.audit.ledger."""
from __future__ import annotations

import json
import os


from tee_crafter.core.audit.ledger import (
    AuditEvidenceLedger,
)
from tee_crafter.core.audit.checks import (
    Verdict,
    Severity,
    derive_verdict,
)


def test_record_check_known_id_populates_metadata():
    ledger = AuditEvidenceLedger()
    ledger.record_check(
        "BYOK-002",
        expected="dek_then_kek",
        observed="dek_then_kek",
        evidence_pointer="byok-config.json",
        note="aws-kms dek_then_kek",
    )
    rows = ledger.rows
    assert len(rows) == 1
    row = rows[0]
    assert row.check_id == "BYOK-002"
    assert row.category == "BYOK"
    assert row.severity == Severity.CRITICAL.value
    assert row.verdict == Verdict.PASS.value
    assert row.expected == "dek_then_kek"
    assert row.observed == "dek_then_kek"
    assert row.evidence_pointer == "byok-config.json"


def test_record_check_unknown_id_still_accepted():
    ledger = AuditEvidenceLedger()
    ledger.record_check(
        "CUSTOM-999",
        observed=True,
        expected=True,
    )
    rows = ledger.rows
    assert rows[0].check_id == "CUSTOM-999"
    assert rows[0].verdict == Verdict.PASS.value
    assert "_warning" in rows[0].extra


def test_record_check_observed_mismatch_yields_fail():
    ledger = AuditEvidenceLedger()
    ledger.record_check("SIEM-002", observed=True)
    row = ledger.rows[0]
    assert row.verdict == Verdict.FAIL.value


def test_totals_and_categories():
    ledger = AuditEvidenceLedger()
    ledger.record_check("SIEM-002", observed=True)  # fail (expected False)
    ledger.record_check("SIEM-005", observed=True)  # pass
    ledger.record_check("IAM-001", observed="arn:aws:iam::1:user/x")  # pass
    totals = ledger.totals()
    assert totals.get(Verdict.PASS.value, 0) >= 1
    assert totals.get(Verdict.FAIL.value, 0) >= 1
    by_cat = ledger.totals_by_category()
    assert "SIEM" in by_cat
    assert by_cat["SIEM"][Verdict.FAIL.value] >= 1


def test_save_produces_all_formats(tmp_path):
    ledger = AuditEvidenceLedger()
    ledger.record_check("BYOK-002", observed="dek_then_kek")
    paths = ledger.save(str(tmp_path))
    for ext in ("json", "txt", "md", "html"):
        assert os.path.isfile(paths[ext]), ext
    with open(paths["json"], "r", encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["rows"][0]["check_id"] == "BYOK-002"
    assert doc["totals"][Verdict.PASS.value] == 1


def test_derive_verdict_explicit_pass():
    v = derive_verdict("dek_then_kek", "dek_then_kek")
    assert v == Verdict.PASS


def test_derive_verdict_observed_none_is_warn():
    v = derive_verdict(True, None)
    assert v == Verdict.WARN


def test_derive_verdict_expected_none_is_info():
    """expected=None means the row is informational (caller recorded a
    value but did not assert a production expectation).  Previously this
    case spuriously derived FAIL because ``bool(None) == bool('arn:...')``
    was False — see false-fail on IAM-001 / BYOK-003 / BYOK-004 in
    docker_flask_api_container_nitro_build_20260516_030754_17c6e1af.
    """
    assert derive_verdict(None, "arn:aws:iam::1:user/x") == Verdict.INFO
    assert derive_verdict(None, True) == Verdict.INFO
    assert derive_verdict(None, 7) == Verdict.INFO


def test_record_check_with_explicit_not_applicable_is_honored():
    """``verdict=Verdict.NOT_APPLICABLE`` must round-trip into the ledger
    even when an ``expected``/``observed`` pair is also supplied — this
    is the BYOK-007 ``no-op for nitro-aws`` regression that originally
    flipped the explicit N/A back to a derived FAIL.
    """
    from tee_crafter.core.audit import BuildAuditTrail

    audit = BuildAuditTrail()
    audit.record_check(
        "Phase 5: Post-Deploy", "BYOK env relocation", "BYOK-007",
        verdict=Verdict.NOT_APPLICABLE,
        observed=False,
        note="no-op for nitro-aws (EIF/manifest-delivered)",
    )
    rows = audit.ledger.rows
    assert len(rows) == 1
    assert rows[0].check_id == "BYOK-007"
    assert rows[0].verdict == Verdict.NOT_APPLICABLE.value


def test_provenance_document_persists_tee_platform(tmp_path):
    """build_provenance.json must carry the tee_platform tag so
    ``verify-provenance --required-checks auto`` can resolve the
    per-platform required-check list without also loading the
    sibling audit_evidence.json.
    """
    import json
    from tee_crafter.core.audit import BuildAuditTrail
    from tee_crafter.core.audit import build_layout as _layout

    a = BuildAuditTrail()
    a.set_metadata("0.0.1", str(tmp_path))
    a.set_tee_platform("snp-aws")
    a.record("Pipeline Config", "init", "info")
    a.save(str(tmp_path))
    with open(_layout.resolve_provenance_json(str(tmp_path)), "r") as f:
        doc = json.load(f)
    assert doc.get("tee_platform") == "snp-aws"


def test_ledger_sweep_fills_missing_required_checks_as_warn(tmp_path):
    """Required checks that the build did not produce should show
    up as ``warn`` rows after the audit-helpers sweep, never silently
    vanish.  This is the regression that broke ATT-004 historically.
    """
    from tee_crafter.core.audit import BuildAuditTrail
    from tee_crafter.cli.audit_helpers import _sweep_missing_required_checks
    from tee_crafter.core.audit.checks import required_checks_for

    a = BuildAuditTrail()
    a.set_metadata("0.0.1", str(tmp_path))
    a.set_tee_platform("snp-aws")
    # Emit just one row, then run the sweep.
    a.record_check(
        "Pipeline Config", "tee_platform recognised", "PC-001",
        observed=True,
    )
    _sweep_missing_required_checks(a)

    required = required_checks_for("snp-aws")
    for cid in required:
        row = a.ledger.get(cid)
        assert row is not None, cid
    # The sweep must have used ``warn`` for everything except the
    # one row the test emitted.
    assert a.ledger.get("PC-001").verdict == Verdict.PASS.value
    assert a.ledger.get("ATT-004").verdict == Verdict.WARN.value
    assert a.ledger.get("DEP-001").verdict == Verdict.WARN.value


# ---------------------------------------------------------------------------
# not_evaluated sweep
# ---------------------------------------------------------------------------

def test_sweep_marks_unrecorded_applicable_checks_not_evaluated(tmp_path):
    """A check nobody ran must say so, not be absent.

    Absence reads as "this check does not exist"; ``not_evaluated``
    reads as "we never gathered evidence", which is the truth.
    """
    ledger = AuditEvidenceLedger(tee_platform="snp-aws")
    ledger.record_check("PC-001", observed=True)
    added = ledger.sweep_not_evaluated()

    assert "PC-001" not in added, "an observed row must not be overwritten"
    assert ledger.get("PC-001").verdict == Verdict.PASS.value
    assert ledger.get("PKG-007") is None, (
        "PKG-007 is Nitro-only; it must not be swept into an snp-aws ledger"
    )
    assert ledger.get("BYOK-008").verdict == Verdict.NOT_EVALUATED.value
    assert "no evidence" in ledger.get("BYOK-008").note


def test_sweep_is_idempotent():
    ledger = AuditEvidenceLedger(tee_platform="tdx-gcp")
    first = ledger.sweep_not_evaluated()
    second = ledger.sweep_not_evaluated()
    assert first and not second


def test_save_sweeps_by_default_and_can_be_disabled(tmp_path):
    swept = AuditEvidenceLedger(tee_platform="snp-aws")
    swept.record_check("PC-001", observed=True)
    swept.save(str(tmp_path / "swept"))

    bare = AuditEvidenceLedger(tee_platform="snp-aws")
    bare.record_check("PC-001", observed=True)
    bare.save(str(tmp_path / "bare"), sweep=False)

    assert len(swept.rows) > 1
    assert len(bare.rows) == 1


def test_not_evaluated_appears_in_totals_and_renderers(tmp_path):
    ledger = AuditEvidenceLedger(tee_platform="snp-aws")
    ledger.record_check("PC-001", observed=True)
    paths = ledger.save(str(tmp_path))
    with open(paths["json"], encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["totals"][Verdict.NOT_EVALUATED.value] > 0
    # The txt renderer upper-cases verdict names in its totals line.
    for fmt in ("txt", "md", "html"):
        with open(paths[fmt], encoding="utf-8") as f:
            assert "not_evaluated" in f.read().lower(), fmt


# ---------------------------------------------------------------------------
# Ed25519 signature round-trip
# ---------------------------------------------------------------------------

def _signed_build(tmp_path, monkeypatch):
    """Produce a signed provenance + ledger pair in *tmp_path*."""
    from tee_crafter.core.audit import BuildAuditTrail
    from tee_crafter.core.audit import build_layout as _layout
    from tee_crafter.core.audit import signing

    monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", "1")
    monkeypatch.setattr(signing, "_EPHEMERAL_KEY", None, raising=False)

    trail = BuildAuditTrail()
    trail.set_metadata("0.1.0-test", str(tmp_path))
    trail.set_tee_platform("snp-aws")
    trail.record("Build", "test build", "pass")
    trail.record_check("Pipeline", "tee_platform recognised", "PC-001",
                       observed=True)
    trail.save(str(tmp_path))
    trail.ledger.save(str(tmp_path))
    trail.ledger.sign(str(tmp_path))
    return _layout.resolve_audit_evidence_json(str(tmp_path))


def test_ledger_signature_round_trips(tmp_path, monkeypatch):
    """``sign`` writes hex over canonical JSON; the verifier must agree.

    ``verify_ledger_signature`` had zero callers, and the ad-hoc block in
    ``verify-provenance`` read the hex signature as raw bytes and
    verified it over the raw file — two independent mismatches, so the
    result could only ever be INVALID.
    """
    from tee_crafter.core.audit.ledger import verify_ledger_signature

    ledger_path = _signed_build(tmp_path, monkeypatch)
    ok, reason = verify_ledger_signature(ledger_path)
    assert ok, reason


def test_ledger_signature_detects_tampering(tmp_path, monkeypatch):
    from tee_crafter.core.audit.ledger import verify_ledger_signature

    ledger_path = _signed_build(tmp_path, monkeypatch)
    with open(ledger_path, encoding="utf-8") as f:
        doc = json.load(f)
    doc["rows"][0]["verdict"] = "pass"
    doc["rows"][0]["check_id"] = "PC-999"
    with open(ledger_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    ok, reason = verify_ledger_signature(ledger_path)
    assert not ok
    assert reason


def test_ephemeral_signing_key_is_stable_within_a_process(monkeypatch):
    """One keypair per process, not per call.

    The trail, the SLSA envelope and the ledger each call
    ``load_signing_key()``.  A fresh key per call meant only one of the
    three signatures could ever match the single published public key.
    """
    from tee_crafter.core.audit import signing

    monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", "1")
    for var in ("TEE_CRAFTER_PROVENANCE_SIGNING_KEY",
                "TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(signing, "_EPHEMERAL_KEY", None, raising=False)
    monkeypatch.setattr(signing, "_from_keyring", lambda: None)
    monkeypatch.setattr(signing, "_from_default_path", lambda: None)

    first = signing.load_signing_key()
    second = signing.load_signing_key()
    assert first.kind == "ephemeral"
    assert (signing.public_key_fingerprint(first.key.public_key())
            == signing.public_key_fingerprint(second.key.public_key()))


def _verify_provenance_cli():
    import click
    from tee_crafter.cli.commands.verify_provenance import register

    @click.group()
    def cli():
        pass

    register(cli)
    return cli


def test_verify_provenance_exits_nonzero_on_bad_ledger_signature(
    tmp_path, monkeypatch,
):
    """An INVALID ledger signature must break the build, not print red text.

    ``docs/audit_matrix.md`` tells auditors to check this signature, so
    a verifier that reports INVALID and still exits 0 gives them a green
    CI badge over an unverifiable artefact.
    """
    from click.testing import CliRunner
    from tee_crafter.core.audit import build_layout as _layout

    _signed_build(tmp_path, monkeypatch)
    prov = _layout.resolve_provenance_json(str(tmp_path))

    runner = CliRunner()
    res = runner.invoke(_verify_provenance_cli(),
                        ["verify-provenance", "--file", prov],
                        catch_exceptions=False)
    assert res.exit_code == 0, res.output
    assert "VALID" in res.output

    # Corrupt the signature: same length, wrong bytes.
    sig_path = _layout.resolve_audit_evidence_sig(str(tmp_path))
    with open(sig_path, encoding="utf-8") as f:
        sig = f.read().strip()
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(("00" if sig[:2] != "00" else "11") + sig[2:])

    res = runner.invoke(_verify_provenance_cli(),
                        ["verify-provenance", "--file", prov],
                        catch_exceptions=False)
    assert res.exit_code == 5, res.output
    assert "Ledger Signature Invalid" in res.output


def test_verify_provenance_skip_signature_also_skips_the_ledger(
    tmp_path, monkeypatch,
):
    from click.testing import CliRunner
    from tee_crafter.core.audit import build_layout as _layout

    _signed_build(tmp_path, monkeypatch)
    prov = _layout.resolve_provenance_json(str(tmp_path))
    os.remove(_layout.resolve_audit_evidence_sig(str(tmp_path)))

    res = CliRunner().invoke(
        _verify_provenance_cli(),
        ["verify-provenance", "--file", prov, "--skip-signature"],
        catch_exceptions=False,
    )
    assert res.exit_code == 0, res.output


def test_not_evaluated_row_does_not_satisfy_a_required_check(
    tmp_path, monkeypatch,
):
    """The swept row must fail the gate exactly like a missing one."""
    from click.testing import CliRunner
    from tee_crafter.core.audit import build_layout as _layout

    _signed_build(tmp_path, monkeypatch)
    prov = _layout.resolve_provenance_json(str(tmp_path))

    res = CliRunner().invoke(
        _verify_provenance_cli(),
        ["verify-provenance", "--file", prov,
         "--required-checks", "PC-001"],
        catch_exceptions=False,
    )
    assert res.exit_code == 0, res.output

    res = CliRunner().invoke(
        _verify_provenance_cli(),
        ["verify-provenance", "--file", prov,
         "--required-checks", "PC-001,ATT-002"],
        catch_exceptions=False,
    )
    assert res.exit_code == 4, res.output
    assert "not_evaluated" in res.output
