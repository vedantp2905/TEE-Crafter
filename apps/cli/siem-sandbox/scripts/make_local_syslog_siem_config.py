#!/usr/bin/env python3
"""Write a laptop-local ``--siem-config`` for syslog-cef (no ngrok).

Use when the TEE runs on the same host as the syslog receiver (rare) or
when you tunnel manually.  For cloud TEE → laptop via ngrok TCP, prefer
``make_remote_syslog_siem_config.py``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from siem_platforms import TEE_PLATFORMS  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "siem-sandbox" / "configs" / "syslog-local-generated.json"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6601)
    ap.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    ap.add_argument("--interval-seconds", type=int, default=30)
    ap.add_argument(
        "--tee-platform",
        default=None,
        choices=TEE_PLATFORMS,
        help="Annotates hostname hint + printed deploy snippet.",
    )
    ap.add_argument(
        "--fail-open",
        action="store_true",
        help="Dev hatch: fail_open=true (default false).",
    )
    args = ap.parse_args()

    doc = {
        "provider": "syslog-cef",
        "interval_seconds": args.interval_seconds,
        "sign_events": True,
        "fail_open": bool(args.fail_open),
        "host": args.host,
        "port": args.port,
        "protocol": args.protocol,
        "facility": 13,
        "hostname": (
            f"tee-crafter-{args.tee_platform}"
            if args.tee_platform
            else "tee-crafter-local"
        ),
        "egress_mode": "none",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"[make-local-syslog] wrote {args.out.relative_to(REPO_ROOT)}")
    if args.tee_platform:
        print(f"[make-local-syslog] deploy example uses --tee-platform {args.tee_platform}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
