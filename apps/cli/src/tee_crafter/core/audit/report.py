"""Audit trail reporting and verification (offline, client-side)."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from tee_crafter.core.audit.helpers import AuditEntry


_ICONS = {"pass": "✓", "fail": "✗", "warn": "!", "skip": "○", "info": "ℹ"}


def write_summary(
    entries: list[AuditEntry],
    doc: Dict[str, Any],
    build_dir: str,
    ledger_doc: Optional[Dict[str, Any]] = None,
) -> str:
    """Write a human-readable summary alongside the JSON trail. Returns path."""
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("  tee-crafter BUILD PROVENANCE REPORT")
    lines.append("=" * 72)
    lines.append(f"  Pipeline version : {doc['pipeline_version'] or 'dev'}")
    lines.append(f"  Build directory  : {doc['build_dir']}")
    lines.append(f"  Started at       : {doc['started_at']}")
    lines.append(f"  Finished at      : {doc['finished_at']}")
    lines.append(f"  Host platform    : {doc['host_platform']}")
    lines.append(f"  Total steps      : {doc['total_entries']}")
    lines.append(f"  Chain head hash  : {doc['chain_head_hash']}")
    lines.append("=" * 72)
    lines.append("")
    current_phase = ""
    pass_count = fail_count = 0
    for entry in entries:
        if entry.phase != current_phase:
            current_phase = entry.phase
            lines.append(f"── {current_phase} {'─' * max(1, 58 - len(current_phase))}")
        icon = _ICONS.get(entry.status, "?")
        if entry.status == "pass":
            pass_count += 1
        elif entry.status == "fail":
            fail_count += 1
        lines.append(f"  [{icon}] {entry.step}")
        for k, v in entry.details.items():
            val_str = str(v)
            if len(val_str) > 80:
                val_str = val_str[:77] + "..."
            lines.append(f"      {k}: {val_str}")
    lines.append("")
    lines.append("-" * 72)
    lines.append(f"  SUMMARY: {pass_count} passed, {fail_count} failed, "
                 f"{doc['total_entries'] - pass_count - fail_count} other")
    lines.append("-" * 72)
    lines.append("")

    if ledger_doc is not None:
        lines.extend(_render_audit_matrix_block(ledger_doc))
        lines.append("")

    lines.append("Verify chain integrity: each entry's prev_hash must equal")
    lines.append("the SHA-256 digest of the preceding entry's canonical JSON.")
    lines.append("Full machine-readable trail: provenance/build_provenance.json")
    if ledger_doc is not None:
        lines.append("Structured pass/fail evidence: audit/audit_evidence.json")
    lines.append("")
    from tee_crafter.core.audit import build_layout as _layout
    _layout.ensure_dirs(build_dir)
    path = _layout.provenance_txt(build_dir)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return os.path.abspath(path)


def _render_audit_matrix_block(ledger_doc: Dict[str, Any]) -> List[str]:
    """Return the AUDIT MATRIX section to splice into the provenance txt."""
    rows: List[Dict[str, Any]] = ledger_doc.get("rows", []) or []
    totals: Dict[str, int] = ledger_doc.get("totals", {}) or {}
    by_cat: Dict[str, Dict[str, int]] = ledger_doc.get("totals_by_category", {}) or {}
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("  AUDIT EVIDENCE MATRIX")
    lines.append("=" * 72)
    order = ["fail", "warn", "pass", "not_applicable", "info"]
    parts = "  ".join(
        f"{k.upper()}={totals.get(k, 0)}" for k in order
    )
    lines.append(f"  Totals: {parts}")
    if by_cat:
        lines.append("  Per-category:")
        for cat in sorted(by_cat.keys()):
            bucket = by_cat[cat]
            counts = "  ".join(
                f"{k}={bucket.get(k, 0)}" for k in order if bucket.get(k, 0)
            )
            lines.append(f"    {cat:<6}  {counts or 'no rows'}")
    failed = [r for r in rows if r.get("verdict") == "fail"]
    if failed:
        lines.append("")
        lines.append(f"  {len(failed)} FAILED CHECK(S):")
        for row in failed:
            lines.append(
                f"   - {row.get('check_id', '?')}  {row.get('title', '?')}"
            )
            if row.get("expected") is not None or row.get("observed") is not None:
                lines.append(
                    f"       expected={row.get('expected')!r}  "
                    f"observed={row.get('observed')!r}"
                )
            if row.get("remediation"):
                lines.append(f"       fix={row['remediation']}")
    warned = [r for r in rows if r.get("verdict") == "warn"]
    if warned:
        lines.append("")
        lines.append(f"  {len(warned)} WARNED CHECK(S):")
        for row in warned:
            lines.append(
                f"   - {row.get('check_id', '?')}  {row.get('title', '?')}"
            )
    lines.append("=" * 72)
    return lines


def parse_enclave_startup_report(console_output: str) -> Optional[List[str]]:
    """Parse enclave stdout for startup report JSON line.

    Returns the list of step IDs if found, else None.
    """
    if not console_output or not isinstance(console_output, str):
        return None
    for line in console_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if obj.get("audit") == "enclave_startup" and "steps" in obj:
                steps = obj["steps"]
                if isinstance(steps, list) and all(isinstance(s, str) for s in steps):
                    return steps
        except (json.JSONDecodeError, TypeError):
            continue
    return None


def verify_chain(provenance_path: str) -> tuple[bool, str]:
    """Re-compute every hash in a saved ``build_provenance.json`` and confirm chain integrity.

    Returns ``(True, "")`` on success or ``(False, reason)`` on failure.
    """
    with open(provenance_path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    entries = doc.get("entries", [])
    if not entries:
        return False, "Audit trail is empty."
    prev_hash = "0" * 64
    for entry_dict in entries:
        if entry_dict.get("prev_hash") != prev_hash:
            return (False,
                    f"Chain broken at seq {entry_dict.get('seq')}: "
                    f"expected prev_hash {prev_hash}, got {entry_dict.get('prev_hash')}")
        e = AuditEntry(**entry_dict)
        prev_hash = e.digest()
    if prev_hash != doc.get("chain_head_hash"):
        return (False,
                f"chain_head_hash mismatch: computed {prev_hash}, "
                f"recorded {doc.get('chain_head_hash')}")
    return True, ""
