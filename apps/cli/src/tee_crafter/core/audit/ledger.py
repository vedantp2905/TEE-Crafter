"""Audit evidence ledger — structured pass/fail matrix for every build.

The :class:`AuditEvidenceLedger` is a sibling artefact of the
hash-chained :class:`BuildAuditTrail`.  While the trail is a temporal
log of every step (info / pass / fail / skip), the ledger is a flat
list of *verdicts* keyed by stable ``check_id``s defined in
:mod:`tee_crafter.core.audit.checks`.

Each :class:`LedgerRow` carries enough metadata for an out-of-band
auditor to confirm the claim independently:

* ``expected`` / ``observed`` — exactly what was compared
* ``source_seq`` — the trail entry that produced this verdict
* ``source_kind`` — pipeline / probe / cloud_audit
* ``evidence_pointer`` — a relative path under ``builds/<id>/`` or a
  cloud resource ARN where the underlying proof lives
* ``severity`` / ``responsibility`` — copied from :data:`CHECKS`

Persistence: ``save(build_dir)`` writes four artefacts:

* ``audit_evidence.json`` — the canonical machine-readable record
* ``audit_evidence.txt`` — grouped, human-readable summary
* ``audit_evidence.md``  — Markdown table for inclusion in reports
* ``audit_evidence.html`` — colour-coded, sortable matrix for review

The JSON file is signed by the operator's Ed25519 audit key (the same
key used for ``build_provenance.json``) so a single fingerprint pin
covers both the temporal trail and the structured matrix.
"""
from __future__ import annotations

import datetime
import html
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from tee_crafter.core.audit.checks import (
    CATEGORIES,
    CATEGORY_TITLES,
    CHECKS,
    Responsibility,
    Severity,
    SourceKind,
    Verdict,
    derive_verdict,
)
from tee_crafter.core.audit.helpers import _sanitize_details

logger = logging.getLogger("tee_crafter.audit.ledger")


@dataclass
class LedgerRow:
    """One row in the audit evidence ledger."""

    check_id: str
    title: str
    category: str
    severity: str
    source_kind: str
    responsibility: str
    verdict: str
    expected: Any = None
    observed: Any = None
    source_seq: Optional[int] = None
    evidence_pointer: str = ""
    tee_platform: str = ""
    timestamp: str = ""
    note: str = ""
    remediation: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


class AuditEvidenceLedger:
    """Accumulates :class:`LedgerRow` entries keyed by ``check_id``."""

    LEDGER_VERSION = "1.0"

    def __init__(self, tee_platform: str = "") -> None:
        self._rows: Dict[str, LedgerRow] = {}
        self._tee_platform = tee_platform or ""
        self._created_at = datetime.datetime.utcnow().isoformat() + "Z"

    @property
    def tee_platform(self) -> str:
        return self._tee_platform

    def set_tee_platform(self, tee_platform: str) -> None:
        self._tee_platform = tee_platform or ""

    @property
    def rows(self) -> List[LedgerRow]:
        return list(self._rows.values())

    # ------------------------------------------------------------------
    def record_check(
        self,
        check_id: str,
        *,
        verdict: Optional[Verdict] = None,
        expected: Any = None,
        observed: Any = None,
        source_seq: Optional[int] = None,
        evidence_pointer: str = "",
        note: str = "",
        **extra: Any,
    ) -> LedgerRow:
        """Record a single verdict in the ledger.

        If *verdict* is omitted, it is derived from ``expected`` /
        ``observed`` via :func:`derive_verdict`.  When *check_id* is not
        in :data:`CHECKS` the row is still accepted (so unknown IDs are
        visible during development) but flagged in ``extra``.
        """
        spec = CHECKS.get(check_id)
        if spec is not None and expected is None:
            expected = spec.default_expected

        if verdict is None:
            v = derive_verdict(expected, observed)
        elif isinstance(verdict, Verdict):
            v = verdict
        else:
            v = Verdict.from_status(str(verdict))

        title = spec.title if spec else check_id
        category = spec.category if spec else "MISC"
        severity = (spec.severity.value if spec else Severity.MODERATE.value)
        source_kind = (spec.source_kind.value if spec
                       else SourceKind.PIPELINE.value)
        responsibility = (spec.responsibility.value if spec
                          else Responsibility.PRODUCT.value)
        remediation = spec.remediation if spec else ""

        sanitised_extra = _sanitize_details(dict(extra))

        row = LedgerRow(
            check_id=check_id,
            title=title,
            category=category,
            severity=severity,
            source_kind=source_kind,
            responsibility=responsibility,
            verdict=v.value,
            expected=_sanitise_scalar(expected),
            observed=_sanitise_scalar(observed),
            source_seq=source_seq,
            evidence_pointer=evidence_pointer or "",
            tee_platform=self._tee_platform,
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            note=note,
            remediation=remediation,
            extra=sanitised_extra,
        )
        if spec is None:
            row.extra.setdefault(
                "_warning",
                f"check_id {check_id!r} not in master catalogue",
            )
        self._rows[check_id] = row
        return row

    # ------------------------------------------------------------------
    def has(self, check_id: str) -> bool:
        return check_id in self._rows

    def get(self, check_id: str) -> Optional[LedgerRow]:
        return self._rows.get(check_id)

    def verdict(self, check_id: str) -> Optional[Verdict]:
        row = self._rows.get(check_id)
        return Verdict(row.verdict) if row else None

    def totals(self) -> Dict[str, int]:
        """Total rows per verdict value."""
        out = {v.value: 0 for v in Verdict}
        for row in self._rows.values():
            out[row.verdict] = out.get(row.verdict, 0) + 1
        return out

    def totals_by_category(self) -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for row in self._rows.values():
            bucket = out.setdefault(
                row.category,
                {v.value: 0 for v in Verdict},
            )
            bucket[row.verdict] = bucket.get(row.verdict, 0) + 1
        return out

    def failed(self) -> List[LedgerRow]:
        return [r for r in self._rows.values() if r.verdict == Verdict.FAIL.value]

    def warned(self) -> List[LedgerRow]:
        return [r for r in self._rows.values() if r.verdict == Verdict.WARN.value]

    def missing(self, required_checks: List[str]) -> List[str]:
        """Return required check_ids that are not present in the ledger."""
        return [cid for cid in required_checks if cid not in self._rows]

    # ------------------------------------------------------------------
    def sweep_not_evaluated(self) -> List[str]:
        """Add a ``not_evaluated`` row for every applicable catalogue check
        the build never recorded, and return the ids that were added.

        Absence is not evidence.  Before this sweep, a check the pipeline
        simply never ran was indistinguishable from one that does not
        exist: 15 of the 128 catalogued ids had no emitter at all, and
        nothing in the artefact said so.  Emitting them explicitly means
        every row an auditor reads in ``docs/audit_matrix.md`` has a
        matching row in ``audit_evidence.json``, and a ``not_evaluated``
        row fails a ``--required-checks`` gate exactly like a missing one
        would — it just says *why*.

        Platform-filtered checks that do not apply to this build's
        ``tee_platform`` are skipped: their absence is correct, not a gap.
        """
        added: List[str] = []
        for cid, spec in CHECKS.items():
            if cid in self._rows:
                continue
            if self._tee_platform and not spec.applies_to(self._tee_platform):
                continue
            self.record_check(
                cid,
                verdict=Verdict.NOT_EVALUATED,
                observed=None,
                note=(
                    "no evidence was collected for this check during this "
                    f"build (source={spec.source_kind.value}); "
                    f"remediation={spec.remediation or 'see docs/audit_matrix.md'}"
                ),
            )
            added.append(cid)
        return added

    # ------------------------------------------------------------------
    def build_document(self) -> Dict[str, Any]:
        totals = self.totals()
        return {
            "ledger_version": self.LEDGER_VERSION,
            "tee_platform": self._tee_platform,
            "created_at": self._created_at,
            "finished_at": datetime.datetime.utcnow().isoformat() + "Z",
            "totals": totals,
            "totals_by_category": self.totals_by_category(),
            "rows": [r.to_dict() for r in self._rows.values()],
        }

    def save(self, build_dir: str, *, sweep: bool = True) -> Dict[str, str]:
        """Write the ledger to disk in JSON / TXT / MD / HTML format.

        Unless *sweep* is False, :meth:`sweep_not_evaluated` runs first so
        the persisted artefact accounts for every catalogue row that
        applies to this platform rather than silently omitting the ones no
        phase happened to record.

        Returns a dict mapping format → absolute path.
        """
        from tee_crafter.core.audit import build_layout as _layout
        if sweep:
            self.sweep_not_evaluated()
        os.makedirs(build_dir, exist_ok=True)
        _layout.ensure_dirs(build_dir)
        doc = self.build_document()
        paths: Dict[str, str] = {}

        json_path = _layout.audit_evidence_json(build_dir)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
        paths["json"] = os.path.abspath(json_path)

        txt_path = _layout.audit_evidence_txt(build_dir)
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(_render_text(doc))
        paths["txt"] = os.path.abspath(txt_path)

        md_path = _layout.audit_evidence_md(build_dir)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(_render_markdown(doc))
        paths["md"] = os.path.abspath(md_path)

        html_path = _layout.audit_evidence_html(build_dir)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(_render_html(doc))
        paths["html"] = os.path.abspath(html_path)

        return paths

    def sign(self, build_dir: str) -> Optional[str]:
        """Sign ``audit_evidence.json`` with the Ed25519 audit key.

        Returns the absolute path to the ``.sig`` file, or ``None`` if
        signing was skipped (cryptography backend missing, etc.).  The
        signing failure is logged but never raised — we always want the
        ledger artefact to land even if the signature does not.
        """
        from tee_crafter.core.audit import build_layout as _layout
        json_path = _layout.resolve_audit_evidence_json(build_dir)
        if not os.path.isfile(json_path):
            return None
        try:
            from tee_crafter.core.audit.signing import load_signing_key
            with open(json_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            canonical = json.dumps(
                doc, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            loaded = load_signing_key()
            signature = loaded.key.sign(canonical)
            sig_path = _layout.audit_evidence_sig(build_dir)
            with open(sig_path, "w", encoding="utf-8") as f:
                f.write(signature.hex())
            kind_path = _layout.audit_evidence_key_kind(build_dir)
            with open(kind_path, "w", encoding="utf-8") as f:
                f.write(f"{loaded.kind}\nsource={loaded.source}\n")
            return os.path.abspath(sig_path)
        except Exception as exc:
            logger.warning(
                "Audit ledger signing failed: %s: %s",
                type(exc).__name__, exc,
            )
            try:
                err_path = _layout.audit_evidence_signing_error(build_dir)
                with open(err_path, "w", encoding="utf-8") as f:
                    f.write(
                        "Audit-evidence signing FAILED.\n\n"
                        f"Reason: {type(exc).__name__}: {exc}\n\n"
                        "The same Ed25519 audit key as the provenance "
                        "trail is used; see "
                        "provenance/build_provenance.signing_error.txt for the "
                        "primary remediation steps.\n"
                    )
            except OSError:
                pass
            return None


# ----------------------------- Verification -----------------------------

def verify_ledger_signature(
    ledger_path: str,
    *,
    pinned_pubkey_sha256: Optional[str] = None,
    require_longlived: bool = False,
) -> tuple[bool, str]:
    """Verify ``audit_evidence.sig`` for a saved ledger file.

    The signature is verified against the canonical JSON serialisation
    of the file (sorted keys, no whitespace).  When *pinned_pubkey_sha256*
    is provided the signing key's SPKI-SHA256 fingerprint must match.
    """
    from tee_crafter.core.audit import build_layout as _layout
    # *ledger_path* may live in either ``audit/audit_evidence.json`` (new)
    # or the legacy top-level location.  Walk back to the build dir so
    # both layouts resolve identically.
    ledger_dir = os.path.dirname(ledger_path)
    build_dir = (os.path.dirname(ledger_dir)
                 if os.path.basename(ledger_dir) == _layout.AUDIT_DIR
                 else ledger_dir)
    sig_path = _layout.resolve_audit_evidence_sig(build_dir)
    pub_path = _layout.resolve_provenance_pub(build_dir)
    if not os.path.isfile(sig_path) or not os.path.isfile(pub_path):
        return False, "audit_evidence.sig or build_provenance.pub not found"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
        from tee_crafter.core.audit.signing import public_key_fingerprint

        with open(ledger_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        canonical = json.dumps(
            doc, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        with open(sig_path, "r", encoding="utf-8") as f:
            signature = bytes.fromhex(f.read().strip())
        with open(pub_path, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())
        if not isinstance(pub_key, Ed25519PublicKey):
            return False, "Public key is not Ed25519"
        pub_key.verify(signature, canonical)
        if pinned_pubkey_sha256:
            actual = public_key_fingerprint(pub_key)
            if actual.lower() != pinned_pubkey_sha256.strip().lower():
                return False, (
                    f"Public-key fingerprint mismatch: "
                    f"build={actual}, pinned={pinned_pubkey_sha256}"
                )
        if require_longlived:
            kind_path = _layout.resolve_audit_evidence_key_kind(build_dir)
            kind = ""
            if os.path.isfile(kind_path):
                try:
                    with open(kind_path, "r", encoding="utf-8") as f:
                        kind = f.readline().strip().lower()
                except OSError:
                    kind = ""
            if kind != "longlived":
                return False, (
                    f"Ledger key kind is '{kind or 'unknown'}'; "
                    f"production requires 'longlived'."
                )
        return True, ""
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# ---------------------------- Renderers ---------------------------------

def _sanitise_scalar(value: Any) -> Any:
    """Make sure expected/observed are JSON-serialisable scalars."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_sanitise_scalar(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _sanitise_scalar(v) for k, v in value.items()}
    return str(value)


_ICONS = {
    "pass": "✓",
    "fail": "✗",
    "warn": "!",
    "not_applicable": "○",
    "not_evaluated": "?",
    "info": "ℹ",
}

_VERDICT_ORDER = [
    "fail", "warn", "not_evaluated", "pass", "not_applicable", "info",
]


def _render_text(doc: Dict[str, Any]) -> str:
    rows: List[Dict[str, Any]] = doc.get("rows", [])
    totals: Dict[str, int] = doc.get("totals", {})
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("  tee-crafter AUDIT EVIDENCE MATRIX")
    lines.append("=" * 72)
    lines.append(f"  Platform   : {doc.get('tee_platform') or 'unknown'}")
    lines.append(f"  Created    : {doc.get('created_at')}")
    lines.append(f"  Finished   : {doc.get('finished_at')}")
    summary = "  ".join(
        f"{v.upper()}={totals.get(v, 0)}" for v in _VERDICT_ORDER
    )
    lines.append(f"  Totals     : {summary}")
    lines.append("=" * 72)
    lines.append("")

    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        by_category.setdefault(row["category"], []).append(row)

    for cat in CATEGORIES:
        bucket = by_category.get(cat, [])
        if not bucket:
            continue
        title = CATEGORY_TITLES.get(cat, cat)
        lines.append(f"-- {cat} — {title} {'-' * max(1, 50 - len(cat) - len(title))}")
        for row in sorted(bucket, key=lambda r: r["check_id"]):
            icon = _ICONS.get(row["verdict"], "?")
            lines.append(
                f"  [{icon}] {row['check_id']}  {row['title']}  "
                f"(severity={row['severity']})"
            )
            if row.get("expected") is not None or row.get("observed") is not None:
                lines.append(
                    f"      expected={row.get('expected')!r}  "
                    f"observed={row.get('observed')!r}"
                )
            if row.get("evidence_pointer"):
                lines.append(f"      evidence={row['evidence_pointer']}")
            if row.get("note"):
                lines.append(f"      note={row['note']}")
            if row["verdict"] == "fail" and row.get("remediation"):
                lines.append(f"      fix={row['remediation']}")

    lines.append("")
    failed = [r for r in rows if r["verdict"] == "fail"]
    if failed:
        lines.append("-" * 72)
        lines.append(f"  {len(failed)} FAILED CHECK(S):")
        for row in failed:
            lines.append(f"   - {row['check_id']}  {row['title']}")
        lines.append("-" * 72)
    lines.append("")
    return "\n".join(lines)


def _render_markdown(doc: Dict[str, Any]) -> str:
    rows: List[Dict[str, Any]] = doc.get("rows", [])
    totals = doc.get("totals", {})
    out: List[str] = []
    out.append("# TEE-Crafter Audit Evidence Matrix")
    out.append("")
    out.append(f"- Platform: `{doc.get('tee_platform') or 'unknown'}`")
    out.append(f"- Created: `{doc.get('created_at')}`")
    out.append(f"- Finished: `{doc.get('finished_at')}`")
    totals_str = ", ".join(
        f"{v}={totals.get(v, 0)}" for v in _VERDICT_ORDER
    )
    out.append(f"- Totals: {totals_str}")
    out.append("")
    out.append("| check_id | category | severity | verdict | title | expected | observed | evidence |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for row in sorted(rows, key=lambda r: (r["category"], r["check_id"])):
        out.append(
            "| `{cid}` | {cat} | {sev} | **{v}** | {title} | `{e}` | `{o}` | {ev} |".format(
                cid=row["check_id"],
                cat=row["category"],
                sev=row["severity"],
                v=row["verdict"],
                title=row["title"].replace("|", "\\|"),
                e=_short(row.get("expected")),
                o=_short(row.get("observed")),
                ev=row.get("evidence_pointer") or "",
            )
        )
    out.append("")
    return "\n".join(out)


def _render_html(doc: Dict[str, Any]) -> str:
    rows: List[Dict[str, Any]] = doc.get("rows", [])
    totals = doc.get("totals", {})
    colour = {
        "pass": "#1b7a3a",
        "fail": "#b3261e",
        "warn": "#a05a00",
        "not_applicable": "#6b6b6b",
        "not_evaluated": "#7a5c00",
        "info": "#1a4ed8",
    }
    parts: List[str] = []
    parts.append("<!doctype html><html><head>")
    parts.append('<meta charset="utf-8">')
    parts.append("<title>TEE-Crafter Audit Evidence Matrix</title>")
    parts.append("""<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
       Roboto, "Helvetica Neue", Arial, sans-serif; margin: 24px; }
h1 { font-size: 20px; margin: 0 0 8px; }
.meta { color: #444; margin-bottom: 16px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { border: 1px solid #d0d0d0; padding: 6px 8px; vertical-align: top; }
th { background: #f5f5f5; text-align: left; cursor: pointer; }
tr.cat { background: #fafafa; font-weight: 600; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 10px;
        color: #fff; font-size: 11px; font-weight: 600; letter-spacing: .04em;
        text-transform: uppercase; }
code { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
       background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }
</style>""")
    parts.append("</head><body>")
    parts.append("<h1>TEE-Crafter Audit Evidence Matrix</h1>")
    parts.append('<div class="meta">')
    parts.append(f"Platform: <code>{html.escape(str(doc.get('tee_platform') or 'unknown'))}</code> · ")
    parts.append(f"Created: <code>{html.escape(str(doc.get('created_at')))}</code> · ")
    parts.append(f"Finished: <code>{html.escape(str(doc.get('finished_at')))}</code><br>")
    parts.append("Totals: ")
    for v in _VERDICT_ORDER:
        parts.append(
            f'<span class="pill" style="background:{colour.get(v, "#333")}">'
            f"{html.escape(v)}: {totals.get(v, 0)}</span> "
        )
    parts.append("</div>")

    parts.append("<table><thead><tr>")
    for h in ("check_id", "category", "severity", "verdict", "title",
              "expected", "observed", "evidence", "remediation"):
        parts.append(f"<th>{h}</th>")
    parts.append("</tr></thead><tbody>")

    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        by_cat.setdefault(row["category"], []).append(row)
    for cat in CATEGORIES:
        bucket = by_cat.get(cat, [])
        if not bucket:
            continue
        parts.append(
            f'<tr class="cat"><td colspan="9">{cat} — '
            f"{html.escape(CATEGORY_TITLES.get(cat, cat))}</td></tr>"
        )
        for row in sorted(bucket, key=lambda r: r["check_id"]):
            v = row["verdict"]
            parts.append("<tr>")
            parts.append(f"<td><code>{html.escape(row['check_id'])}</code></td>")
            parts.append(f"<td>{html.escape(row['category'])}</td>")
            parts.append(f"<td>{html.escape(row['severity'])}</td>")
            parts.append(
                f'<td><span class="pill" style="background:{colour.get(v, "#333")}">'
                f"{html.escape(v)}</span></td>"
            )
            parts.append(f"<td>{html.escape(row['title'])}</td>")
            parts.append(f"<td><code>{html.escape(_short(row.get('expected')))}</code></td>")
            parts.append(f"<td><code>{html.escape(_short(row.get('observed')))}</code></td>")
            parts.append(f"<td>{html.escape(row.get('evidence_pointer') or '')}</td>")
            parts.append(f"<td>{html.escape(row.get('remediation') or '')}</td>")
            parts.append("</tr>")
    parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "".join(parts)


def _short(value: Any, max_len: int = 80) -> str:
    s = "" if value is None else str(value)
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


__all__ = [
    "AuditEvidenceLedger",
    "LedgerRow",
    "verify_ledger_signature",
]
