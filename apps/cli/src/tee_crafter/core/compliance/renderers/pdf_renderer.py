"""Shared Responsibility Matrix renderer (HTML + lightweight PDF).

Generates a print-ready ``shared_responsibility_matrix.html`` and, when possible,
a minimal ``shared_responsibility_matrix.pdf`` using only the Python standard library.
"""
from __future__ import annotations

import html as _html
import os
import zlib
from typing import Any, Dict, List


def render_srm(report_data: Dict[str, Any], compliance_dir: str) -> str:
    """Generate the Shared Responsibility Matrix in HTML (always) and PDF (best-effort).

    Returns the path to the compliance directory.
    """
    rows = _build_rows(report_data)
    html_path = _render_html(report_data, rows, compliance_dir)
    _render_pdf(report_data, rows, compliance_dir)
    return html_path


def _build_rows(data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Flatten all framework controls into SRM rows."""
    rows: List[Dict[str, str]] = []
    for fw_id, fw_data in data.get("frameworks", {}).items():
        fw_name = fw_data.get("name", fw_id)
        for ctrl in fw_data.get("controls", []):
            resp = ctrl.get("responsibility", "")
            label = {
                "product_evidence": "TEE-Crafter",
                "shared": "Shared",
                "customer_responsibility": "Customer",
            }.get(resp, resp)

            product_scope = ""
            customer_scope = ""
            if resp == "product_evidence":
                product_scope = ctrl.get("notes", "Full product evidence.")
                customer_scope = "None required."
            elif resp == "customer_responsibility":
                product_scope = "Not applicable."
                customer_scope = ctrl.get("customer_action", "") or ctrl.get("notes", "")
            else:
                ev_list = ctrl.get("evidence", [])
                if ev_list:
                    product_scope = "Evidence: " + ", ".join(e["key"] for e in ev_list)
                else:
                    product_scope = ctrl.get("notes", "")
                customer_scope = ctrl.get("customer_action", "Organizational controls needed.")

            rows.append({
                "framework": fw_name,
                "control_id": ctrl["control_id"],
                "title": ctrl["title"],
                "responsibility": label,
                "status": ctrl.get("status", ""),
                "product_scope": product_scope[:200],
                "customer_scope": customer_scope[:200],
            })
    return rows


def _e(text: str) -> str:
    return _html.escape(str(text))


def _render_html(data: Dict[str, Any], rows: List[Dict[str, str]],
                 compliance_dir: str) -> str:
    deployment = data.get("deployment", {})
    summary = data.get("summary", {})

    table_rows = []
    for r in rows:
        resp_class = {
            "TEE-Crafter": "resp-product",
            "Shared": "resp-shared",
            "Customer": "resp-customer",
        }.get(r["responsibility"], "")
        table_rows.append(
            f"<tr>"
            f"<td>{_e(r['framework'])}</td>"
            f"<td><strong>{_e(r['control_id'])}</strong></td>"
            f"<td>{_e(r['title'])}</td>"
            f"<td class=\"{resp_class}\">{_e(r['responsibility'])}</td>"
            f"<td class=\"scope\">{_e(r['product_scope'])}</td>"
            f"<td class=\"scope\">{_e(r['customer_scope'])}</td>"
            f"</tr>"
        )

    by_status = summary.get("by_status", {})

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TEE-Crafter Shared Responsibility Matrix</title>
<style>
  @page {{ size: landscape; margin: 12mm; }}
  @media print {{
    body {{ font-size: 9px; }}
    .no-print {{ display: none; }}
    table {{ page-break-inside: auto; }}
    tr {{ page-break-inside: avoid; }}
  }}
  :root {{ --bg: #fafbfc; --card: #fff; --border: #d1d5db; --text: #111827;
           --muted: #6b7280; --product: #065f46; --shared: #92400e; --customer: #1e40af; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Helvetica Neue', Arial, sans-serif; background: var(--bg);
          color: var(--text); line-height: 1.5; padding: 24px; }}
  h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 2px; }}
  .subtitle {{ color: var(--muted); font-size: 13px; margin-bottom: 16px; }}
  .meta-grid {{ display: flex; gap: 24px; margin-bottom: 20px; flex-wrap: wrap; }}
  .meta-item {{ font-size: 12px; }}
  .meta-item strong {{ display: block; font-size: 11px; color: var(--muted);
                       text-transform: uppercase; letter-spacing: 0.5px; }}
  .legend {{ display: flex; gap: 16px; margin-bottom: 16px; font-size: 12px; }}
  .legend span {{ padding: 2px 10px; border-radius: 4px; font-weight: 600; }}
  .leg-product {{ background: #d1fae5; color: var(--product); }}
  .leg-shared {{ background: #fef3c7; color: var(--shared); }}
  .leg-customer {{ background: #dbeafe; color: var(--customer); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 11px; }}
  th {{ text-align: left; padding: 8px 6px; background: #f3f4f6; font-weight: 700;
       border-bottom: 2px solid var(--border); font-size: 10px;
       text-transform: uppercase; letter-spacing: 0.3px; }}
  td {{ padding: 6px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  tr:hover td {{ background: #f9fafb; }}
  .resp-product {{ color: var(--product); font-weight: 600; }}
  .resp-shared {{ color: var(--shared); font-weight: 600; }}
  .resp-customer {{ color: var(--customer); font-weight: 600; }}
  .scope {{ font-size: 10px; color: var(--muted); max-width: 280px; }}
  footer {{ margin-top: 24px; padding-top: 12px; border-top: 1px solid var(--border);
            color: var(--muted); font-size: 11px; }}
</style>
</head>
<body>
<h1>Shared Responsibility Matrix</h1>
<div class="subtitle">TEE-Crafter Compliance — generated for auditor review</div>

<div class="meta-grid">
  <div class="meta-item"><strong>Platform</strong>{_e(deployment.get('tee_platform', ''))}</div>
  <div class="meta-item"><strong>Flow</strong>{_e(deployment.get('flow', ''))}</div>
  <div class="meta-item"><strong>Cloud</strong>{_e(deployment.get('cloud', ''))}</div>
  <div class="meta-item"><strong>Frameworks</strong>{summary.get('frameworks_evaluated', 0)}</div>
  <div class="meta-item"><strong>Controls</strong>{summary.get('total_controls', 0)}</div>
  <div class="meta-item"><strong>Product-Satisfied</strong>{by_status.get('satisfied', 0)}</div>
  <div class="meta-item"><strong>Shared</strong>{by_status.get('partial', 0)}</div>
  <div class="meta-item"><strong>Customer</strong>{by_status.get('customer_responsibility', 0)}</div>
</div>

<div class="legend">
  <span class="leg-product">TEE-Crafter</span>
  <span class="leg-shared">Shared</span>
  <span class="leg-customer">Customer</span>
</div>

<table>
<thead>
<tr>
  <th>Framework</th><th>Control</th><th>Title</th>
  <th>Responsibility</th><th>TEE-Crafter Scope</th><th>Customer Scope</th>
</tr>
</thead>
<tbody>
{"".join(table_rows)}
</tbody>
</table>

<footer>
  <p>Generated by TEE-Crafter Compliance Engine &middot;
     Report ID: {_e(data.get('report_id', ''))}</p>
  <p>Chain head (SHA-256): {_e(data.get('provenance', {}).get('chain_head_hash', ''))}
     &middot; {_e(data.get('generated_at', ''))}</p>
  <p>This matrix is produced from automated build evidence. Controls marked
     &ldquo;Customer&rdquo; require organizational policies and documentation.
     Controls marked &ldquo;Shared&rdquo; require both product evidence
     and customer processes.</p>
</footer>
</body>
</html>"""

    path = os.path.join(compliance_dir, "shared_responsibility_matrix.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# Minimal PDF generation using only stdlib
# ---------------------------------------------------------------------------

class _MiniPDF:
    """Tiny PDF writer — supports text and basic tables, no external deps."""

    def __init__(self) -> None:
        self._objects: List[bytes] = []
        self._pages: List[int] = []
        self._font_obj = 0
        self._page_width = 842  # A4 landscape points
        self._page_height = 595

    def _add_obj(self, content: bytes) -> int:
        self._objects.append(content)
        return len(self._objects)

    def build(self, title: str, rows: List[Dict[str, str]],
              meta: Dict[str, str]) -> bytes:
        font_id = self._add_obj(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        )
        font_bold_id = self._add_obj(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        )
        self._font_obj = font_id
        self._font_bold = font_bold_id

        pages_placeholder = self._add_obj(b"PAGES_PLACEHOLDER")
        pages_obj_id = pages_placeholder

        # Called for its side effect: it appends to ``self._pages``.
        self._build_pages(title, rows, meta, pages_obj_id)

        pages_kids = " ".join(f"{p} 0 R" for p in self._pages)
        pages_content = (
            f"<< /Type /Pages /Kids [{pages_kids}] "
            f"/Count {len(self._pages)} >>".encode()
        )
        self._objects[pages_obj_id - 1] = pages_content

        catalog_id = self._add_obj(
            f"<< /Type /Catalog /Pages {pages_obj_id} 0 R >>".encode()
        )

        return self._serialize(catalog_id)

    def _build_pages(self, title: str, rows: List[Dict[str, str]],
                     meta: Dict[str, str], pages_obj: int) -> None:
        lm, tm = 40, self._page_height - 40
        col_widths = [90, 60, 140, 80, 220, 220]
        row_height = 14
        header_labels = ["Framework", "Control", "Title", "Responsibility",
                         "TEE-Crafter Scope", "Customer Scope"]

        y = tm
        streams: List[List[str]] = [[]]

        def new_page():
            nonlocal y
            streams.append([])
            y = tm

        def cur():
            return streams[-1]

        def text(x, yp, txt, bold=False, size=8):
            safe = txt.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            font = "/F2" if bold else "/F1"
            cur().append(f"BT {font} {size} Tf {x} {yp} Td ({safe}) Tj ET")

        def hline(x1, x2, yp):
            cur().append(f"{x1} {yp} m {x2} {yp} l S")

        text(lm, y, title, bold=True, size=14)
        y -= 18
        for k, v in meta.items():
            text(lm, y, f"{k}: {v}", size=8)
            y -= 12
        y -= 8
        hline(lm, self._page_width - 40, y)
        y -= 16

        x = lm
        for i, label in enumerate(header_labels):
            text(x, y, label, bold=True, size=7)
            x += col_widths[i]
        y -= row_height
        hline(lm, self._page_width - 40, y + 4)
        y -= 4

        for row in rows:
            if y < 50:
                new_page()
                x = lm
                for i, label in enumerate(header_labels):
                    text(x, y, label, bold=True, size=7)
                    x += col_widths[i]
                y -= row_height
                hline(lm, self._page_width - 40, y + 4)
                y -= 4

            vals = [
                row["framework"][:20],
                row["control_id"],
                row["title"][:30],
                row["responsibility"],
                row["product_scope"][:50],
                row["customer_scope"][:50],
            ]
            x = lm
            for i, val in enumerate(vals):
                text(x, y, val, size=7)
                x += col_widths[i]
            y -= row_height

        for page_cmds in streams:
            stream_content = "\n".join(page_cmds).encode()
            compressed = zlib.compress(stream_content)
            stream_obj = self._add_obj(
                f"<< /Length {len(compressed)} /Filter /FlateDecode >>\n"
                f"stream\n".encode() + compressed + b"\nendstream"
            )
            resources = (
                f"<< /Font << /F1 {self._font_obj} 0 R "
                f"/F2 {self._font_bold} 0 R >> >>"
            )
            page_id = self._add_obj(
                f"<< /Type /Page /Parent {pages_obj} 0 R "
                f"/MediaBox [0 0 {self._page_width} {self._page_height}] "
                f"/Contents {stream_obj} 0 R "
                f"/Resources {resources} >>".encode()
            )
            self._pages.append(page_id)

    def _serialize(self, catalog_id: int) -> bytes:
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: List[int] = []
        for i, obj in enumerate(self._objects):
            offsets.append(len(out))
            obj_num = i + 1
            out += f"{obj_num} 0 obj\n".encode()
            out += obj + b"\n"
            out += b"endobj\n"

        xref_offset = len(out)
        out += b"xref\n"
        out += f"0 {len(self._objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()

        out += b"trailer\n"
        out += f"<< /Size {len(self._objects) + 1} /Root {catalog_id} 0 R >>\n".encode()
        out += b"startxref\n"
        out += f"{xref_offset}\n".encode()
        out += b"%%EOF\n"
        return bytes(out)


def _render_pdf(data: Dict[str, Any], rows: List[Dict[str, str]],
                compliance_dir: str) -> str | None:
    """Best-effort PDF generation."""
    try:
        pdf = _MiniPDF()
        deployment = data.get("deployment", {})
        meta = {
            "Report ID": data.get("report_id", ""),
            "Chain head": data.get("provenance", {}).get("chain_head_hash", ""),
            "Platform": deployment.get("tee_platform", ""),
            "Flow": deployment.get("flow", ""),
            "Cloud": deployment.get("cloud", ""),
            "Generated": data.get("generated_at", ""),
        }
        content = pdf.build("TEE-Crafter Shared Responsibility Matrix", rows, meta)
        path = os.path.join(compliance_dir, "shared_responsibility_matrix.pdf")
        with open(path, "wb") as f:
            f.write(content)
        return path
    except Exception:
        return None
