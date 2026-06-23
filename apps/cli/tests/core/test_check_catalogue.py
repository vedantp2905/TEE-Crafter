"""Sanity tests for the audit check catalogue."""
from __future__ import annotations

import pathlib
import re

import pytest

from tee_crafter.core.audit.checks import (
    ALL_PLATFORMS,
    CHECKS,
    DEFAULT_REQUIRED_CHECKS,
    Severity,
    SourceKind,
    required_checks_for,
)


def applies_to(cid: str, tee_platform: str) -> bool:
    return CHECKS[cid].applies_to(tee_platform)


def test_required_checks_known():
    for cid in DEFAULT_REQUIRED_CHECKS:
        assert cid in CHECKS, cid


def test_catalogue_minimum_categories_present():
    seen = {spec.category for spec in CHECKS.values()}
    for required in (
        "PC", "DH", "PKG", "VLN", "IAC", "IAM", "DEP", "PDR",
        "ATT", "SIEM", "BYOK", "EGR", "CT", "TEAR", "PROV", "RES",
    ):
        assert required in seen, required


def test_severity_values_sane():
    for cid, spec in CHECKS.items():
        assert isinstance(spec.severity, Severity), cid
        assert isinstance(spec.source_kind, SourceKind), cid


def test_required_checks_for_aws_filters_correctly():
    aws_required = required_checks_for("snp-aws")
    # IAC-008 only applies to AWS Nitro; ensure required set still
    # accepts it as a string.
    assert isinstance(aws_required, list)
    for cid in aws_required:
        assert applies_to(cid, "snp-aws"), cid


def test_applies_to_handles_unknown_platform_gracefully():
    assert applies_to("BYOK-002", "snp-aws")
    # Unknown platform never crashes — it just returns True for the
    # 'no platform filter' default, or False with a filter.
    assert applies_to("BYOK-002", "")


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src" / "tee_crafter"
_DOCS = _REPO_ROOT.parents[1] / "docs"
_CATALOGUE_FILE = _SRC / "core" / "audit" / "checks.py"
_ID_RE = re.compile(
    r'["\']('
    r'(?:PC|DH|PKG|VLN|IAC|IAM|DEP|PDR|ATT|SIEM|BYOK|EGR|CT|TEAR|PROV|RES)'
    r'-\d+)["\']'
)


def _collect_emitted_ids() -> set[str]:
    """Return every catalogue ``check_id`` referenced by pipeline code.

    The catalogue file itself is excluded.  Scanning it meant every
    ``check_id`` matched its own definition, so the completeness guard
    below compared ``checks.py`` against ``checks.py`` and could never
    fail — which is exactly why 15 orphaned ids (3 of them ``critical``)
    sat in the catalogue undetected.

    Templates are excluded too: they mention ids in docstrings, not as
    ``record_check`` sites.
    """
    out: set[str] = set()
    for path in _SRC.rglob("*.py"):
        if "/templates/" in str(path) or path == _CATALOGUE_FILE:
            continue
        text = path.read_text(errors="ignore")
        for m in _ID_RE.finditer(text):
            out.add(m.group(1))
    return out


#: Catalogued rows that no pipeline call site emits today.  Each one is
#: real audit debt: the row appears in the catalogue (and therefore in
#: the rendered matrix as ``not_evaluated``) but nothing in the deploy
#: path ever gathers evidence for it.  The list is frozen so a 16th
#: orphan fails CI; shrinking it is the goal.
#:
#: Owners, from the audit:
#:   PKG-006/007  — Nitro EIF build phase (cli/deployment/nitro/phase.py)
#:   PKG-004/008  — container packaging + AMI bake phases
#:   BYOK-006     — byok-stage command
#:   BYOK-008     — in-TEE decrypt probe (post-deploy probe phase)
#:   BYOK-009     — KMS key-policy reader (cli/deployment/common/cloud_audit.py)
#:   CT-004/007   — cloud-audit readers
#:   DEP-003      — deploy phase (AMI id vs pinned)
#:   EGR-003      — post-deploy probe (setup-egress closed)
#:   PC-005       — pipeline init (SLSA emitter loaded)
#:   SIEM-004     — post-deploy probe (first boot event delivered)
#:   VLN-005/006  — vulnerability gate
_KNOWN_UNEMITTED = frozenset({
    "BYOK-006", "BYOK-008", "BYOK-009",
    "CT-004", "CT-007",
    "DEP-003",
    "EGR-003",
    "PC-005",
    "PKG-004", "PKG-006", "PKG-007", "PKG-008",
    "SIEM-004",
    "VLN-005", "VLN-006",
})


def test_no_new_orphan_check_ids():
    """The set of catalogued-but-never-emitted ids must not grow.

    A row in the catalogue that no call site emits is a claim the
    pipeline does not back.  ``_KNOWN_UNEMITTED`` freezes the existing
    debt so it is visible and countable; anything new fails here.
    """
    emitted = _collect_emitted_ids()
    orphans = {cid for cid in CHECKS if cid not in emitted}
    new = sorted(orphans - _KNOWN_UNEMITTED)
    assert not new, (
        f"New catalogued check_ids with no emitter: {new}.  Add a "
        f"record_check call site, or (if the check is genuinely gone) "
        f"remove the spec from src/tee_crafter/core/audit/checks.py."
    )
    fixed = sorted(_KNOWN_UNEMITTED - orphans)
    assert not fixed, (
        f"These ids now have emitters: {fixed}.  Remove them from "
        f"_KNOWN_UNEMITTED so the guard keeps ratcheting."
    )


def test_critical_orphans_are_the_known_three():
    """No *new* critical row may go unemitted.

    ``PKG-007`` (EIF build + PCR capture), ``BYOK-008`` (first in-TEE
    decrypt) and ``BYOK-009`` (KMS key policy) are the three critical
    rows with no emitter.  A build that renders them as ``pass`` would
    be asserting evidence it never collected.
    """
    emitted = _collect_emitted_ids()
    critical_orphans = sorted(
        cid for cid, spec in CHECKS.items()
        if cid not in emitted and spec.severity is Severity.CRITICAL
    )
    assert critical_orphans == ["BYOK-008", "BYOK-009", "PKG-007"], (
        f"Critical rows without an emitter changed: {critical_orphans}"
    )


def test_default_required_checks_emitted_for_every_platform():
    """Every platform's required-check list is fully emitter-backed.

    Regression test for the gap where ATT-004 was in
    DEFAULT_REQUIRED_CHECKS but never recorded by
    ``emit_att_verdicts`` — every ``--required-checks auto`` CI gate
    would have failed-closed on a missing row.
    """
    emitted = _collect_emitted_ids()
    gaps: dict[str, list[str]] = {}
    for plat in sorted(ALL_PLATFORMS):
        missing = [cid for cid in required_checks_for(plat)
                   if cid not in emitted]
        if missing:
            gaps[plat] = missing
    assert not gaps, (
        f"Required-check gates without an emitter: {gaps}.  "
        f"Add the matching record_check call or relax the catalogue."
    )


# ---------------------------------------------------------------------------
# Documented rows vs rows a build actually produces
# ---------------------------------------------------------------------------

def _documented_required_checks() -> set[str]:
    """Parse the required-check ids out of ``docs/audit_matrix.md``.

    That document is what auditors are handed, so it — not the source
    file that defines the catalogue — is the "documented row list" the
    runtime artefact has to match.
    """
    text = (_DOCS / "audit_matrix.md").read_text(encoding="utf-8")
    # The "catalogue-defined default required gate" bullet list.
    start = text.index("The catalogue-defined default required gate is:")
    end = text.index("After per-platform filtering", start)
    section = text[start:end]
    ids = set(_ID_RE.findall(section.replace("`", '"')))
    # `ATT-001`..`ATT-006` is written as a bulleted enumeration; the
    # regex above already picks each one up individually.
    return ids


def test_documented_required_gate_matches_catalogue():
    """``docs/audit_matrix.md`` and ``DEFAULT_REQUIRED_CHECKS`` agree."""
    documented = _documented_required_checks()
    catalogued = set(DEFAULT_REQUIRED_CHECKS)
    assert documented == catalogued, (
        f"docs/audit_matrix.md and DEFAULT_REQUIRED_CHECKS disagree.\n"
        f"  only in docs:      {sorted(documented - catalogued)}\n"
        f"  only in catalogue: {sorted(catalogued - documented)}"
    )


@pytest.mark.parametrize("platform", sorted(ALL_PLATFORMS))
def test_saved_ledger_accounts_for_every_applicable_row(platform, tmp_path):
    """A saved ledger must contain a row for every applicable check.

    This is the runtime half of the guard: it inspects the artefact an
    auditor reads (``audit_evidence.json``), not the source that
    produced it.  Rows nothing evaluated appear as ``not_evaluated`` —
    absent is not an option, because absence reads as "this check does
    not exist" rather than "we never ran it".
    """
    import json

    from tee_crafter.core.audit.ledger import AuditEvidenceLedger

    ledger = AuditEvidenceLedger(tee_platform=platform)
    # One genuinely-observed row, so the ledger is not purely swept.
    ledger.record_check("PC-001", observed=True)
    paths = ledger.save(str(tmp_path))
    with open(paths["json"], encoding="utf-8") as f:
        doc = json.load(f)
    present = {row["check_id"] for row in doc["rows"]}
    expected = {cid for cid, spec in CHECKS.items() if spec.applies_to(platform)}
    assert expected - present == set(), (
        f"{platform}: applicable catalogue rows missing from the saved "
        f"ledger: {sorted(expected - present)}"
    )
    # And rows that do NOT apply to this platform must stay out.
    inapplicable = {cid for cid, spec in CHECKS.items()
                    if not spec.applies_to(platform)}
    assert present & inapplicable == set(), (
        f"{platform}: ledger carries rows for other platforms: "
        f"{sorted(present & inapplicable)}"
    )
    # The one row we actually observed must not be swept over.
    by_id = {row["check_id"]: row for row in doc["rows"]}
    assert by_id["PC-001"]["verdict"] == "pass"
    assert by_id["PROV-003"]["verdict"] == "not_evaluated"
