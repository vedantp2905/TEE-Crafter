"""HTML compliance report renderer (branded single-page report)."""
from __future__ import annotations

import html
import os
from typing import Any, Dict, List


_STATUS_BADGE = {
    "satisfied": ('<span style="background:#16a34a;color:#fff;padding:2px 8px;'
                  'border-radius:4px;font-size:12px;">PASS</span>'),
    "partial": ('<span style="background:#ca8a04;color:#fff;padding:2px 8px;'
                'border-radius:4px;font-size:12px;">PARTIAL</span>'),
    "gap": ('<span style="background:#dc2626;color:#fff;padding:2px 8px;'
            'border-radius:4px;font-size:12px;">GAP</span>'),
    "not_applicable": ('<span style="background:#6b7280;color:#fff;padding:2px 8px;'
                       'border-radius:4px;font-size:12px;">N/A</span>'),
    "customer_responsibility": ('<span style="background:#2563eb;color:#fff;padding:2px 8px;'
                                'border-radius:4px;font-size:12px;">CUSTOMER</span>'),
}


def render_html(report_data: Dict[str, Any], compliance_dir: str) -> str:
    """Write compliance_report.html. Returns file path."""
    parts: List[str] = []
    parts.append(_html_head(report_data))
    parts.append(_html_summary(report_data))
    parts.append(_html_evidence(report_data))

    for fw_id, fw_data in report_data.get("frameworks", {}).items():
        parts.append(_html_framework(fw_id, fw_data))

    parts.append(_html_footer(report_data))

    path = os.path.join(compliance_dir, "compliance_report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    return path


def _e(text: str) -> str:
    return html.escape(str(text))


def _html_head(data: Dict[str, Any]) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TEE-Crafter Compliance Report</title>
<style>
  :root {{ --bg: #f8fafc; --card: #fff; --border: #e2e8f0; --text: #1e293b;
           --muted: #64748b; --accent: #0f172a; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: var(--bg); color: var(--text); line-height: 1.6;
          max-width: 1100px; margin: 0 auto; padding: 24px 16px; }}
  h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 4px; }}
  h2 {{ font-size: 20px; font-weight: 600; margin: 32px 0 12px; border-bottom: 2px solid var(--accent);
        padding-bottom: 4px; }}
  h3 {{ font-size: 16px; font-weight: 600; margin: 16px 0 8px; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-bottom: 24px; }}
  .meta code {{ background: #f1f5f9; padding: 1px 5px; border-radius: 3px; font-size: 12px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
           padding: 16px; margin-bottom: 16px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; }}
  .stat {{ text-align: center; }}
  .stat .num {{ font-size: 28px; font-weight: 700; }}
  .stat .label {{ font-size: 12px; color: var(--muted); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 6px; background: #f1f5f9; font-weight: 600;
       border-bottom: 2px solid var(--border); }}
  td {{ padding: 8px 6px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: #f8fafc; }}
  .fw-meta {{ color: var(--muted); font-size: 12px; margin-bottom: 8px; }}
  footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
            color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>
<h1>TEE-Crafter Compliance Report</h1>
<div class="meta">
  Report ID: <code>{_e(data['report_id'])}</code> &middot;
  Generated: {_e(data['generated_at'])} &middot;
  Platform: <strong>{_e(data['deployment']['tee_platform'])}</strong> &middot;
  Flow: {_e(data['deployment']['flow'])} &middot;
  Cloud: {_e(data['deployment']['cloud'])}
</div>"""


def _html_summary(data: Dict[str, Any]) -> str:
    s = data["summary"]
    bs = s["by_status"]
    return f"""
<h2>Summary</h2>
<div class="card">
  <div class="grid">
    <div class="stat"><div class="num">{s['frameworks_evaluated']}</div><div class="label">Frameworks</div></div>
    <div class="stat"><div class="num">{s['total_controls']}</div><div class="label">Controls</div></div>
    <div class="stat"><div class="num" style="color:#16a34a">{bs['satisfied']}</div><div class="label">Satisfied</div></div>
    <div class="stat"><div class="num" style="color:#ca8a04">{bs['partial']}</div><div class="label">Partial</div></div>
    <div class="stat"><div class="num" style="color:#dc2626">{bs['gap']}</div><div class="label">Gap</div></div>
    <div class="stat"><div class="num" style="color:#2563eb">{bs['customer_responsibility']}</div><div class="label">Customer</div></div>
    <div class="stat"><div class="num">{s['product_coverage_pct']}%</div><div class="label">Product Coverage</div></div>
  </div>
</div>"""


def _html_evidence(data: Dict[str, Any]) -> str:
    inv = data.get("evidence_inventory", [])
    if not inv:
        return ""
    rows = ""
    for e in inv:
        rows += f"<tr><td>{_e(e['key'])}</td><td>{_e(e['strength'])}</td></tr>\n"
    return f"""
<h2>Evidence Inventory</h2>
<div class="card">
<table><thead><tr><th>Evidence</th><th>Strength</th></tr></thead>
<tbody>{rows}</tbody></table>
</div>"""


def _html_framework(fw_id: str, fw_data: Dict[str, Any]) -> str:
    rows = ""
    for c in fw_data.get("controls", []):
        badge = _STATUS_BADGE.get(c["status"], _e(c["status"]))
        notes = _e(c.get("notes", ""))
        if len(notes) > 120:
            notes = notes[:117] + "..."
        ca = c.get("customer_action", "")
        if ca:
            notes += f" <em>{_e(ca[:80])}</em>"
        rows += (f"<tr><td><strong>{_e(c['control_id'])}</strong></td>"
                 f"<td>{_e(c['title'])}</td><td>{badge}</td>"
                 f"<td>{_e(c.get('responsibility', ''))}</td>"
                 f"<td>{notes}</td></tr>\n")

    return f"""
<h2>{_e(fw_data['name'])}</h2>
<div class="fw-meta">{_e(fw_data['version'])} &middot; Tier: {_e(fw_data['tier'])} &middot;
  {fw_data['controls_evaluated']} controls &middot;
  {fw_data['satisfied']} satisfied &middot; {fw_data['partial']} partial &middot;
  {fw_data['gap']} gap</div>
<div class="card">
<table>
<thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Responsibility</th><th>Notes</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>"""


def _html_footer(data: Dict[str, Any]) -> str:
    prov = data["provenance"]
    ch = prov.get("chain_head_hash", "") or ""
    return f"""
<footer>
  <p>Report ID: <code>{_e(data.get('report_id', ''))}</code></p>
  <p>Chain head (SHA-256): <code>{_e(ch)}</code></p>
  <p>Provenance: <code>{_e(prov['file'])}</code> &middot;
     Chain valid: {prov['chain_valid']} &middot;
     Signature valid: {prov['signature_valid']} &middot;
     Entries: {prov['total_entries']}</p>
  <p>Generated by TEE-Crafter Compliance Engine v{_e(data['generator_version'])}.
     This report reflects product-level evidence only.
     See <code>docs/compliance.md</code> for full coverage roadmap.</p>
</footer>
</body>
</html>"""
