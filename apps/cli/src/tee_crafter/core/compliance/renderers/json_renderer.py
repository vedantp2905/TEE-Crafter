"""JSON compliance report renderer (dashboard-ready)."""
from __future__ import annotations

import json
import os
from typing import Any, Dict


def render_json(report_data: Dict[str, Any], compliance_dir: str,
                frameworks_dir: str) -> str:
    """Write compliance_report.json and per-framework JSON files.

    Returns the path to the aggregate report.
    """
    aggregate_path = os.path.join(compliance_dir, "compliance_report.json")
    with open(aggregate_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, sort_keys=False)

    for fw_id, fw_data in report_data.get("frameworks", {}).items():
        fw_path = os.path.join(frameworks_dir, f"{fw_id}.json")
        fw_report = {
            "schema_version": report_data["schema_version"],
            "report_id": report_data["report_id"],
            "generated_at": report_data["generated_at"],
            "framework": fw_data,
        }
        with open(fw_path, "w", encoding="utf-8") as f:
            json.dump(fw_report, f, indent=2, sort_keys=False)

    return aggregate_path
