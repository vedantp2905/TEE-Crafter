#!/usr/bin/env python3
"""Generate SIEM JSON configs for tee-crafter ``--siem-config``.

Subcommands forward to the existing helpers:

  syslog-ngrok   → make_remote_syslog_siem_config.py (ngrok TCP + egress lock)
  splunk-ngrok   → make_remote_splunk_siem_config.py (ngrok HTTPS → HEC)
  syslog-local   → make_local_syslog_siem_config.py (static host/port JSON)

Examples
--------

    python3 siem-sandbox/scripts/generate_siem_config.py syslog-ngrok \\
      --tee-platform snp-aws

    python3 siem-sandbox/scripts/generate_siem_config.py splunk-ngrok \\
      --tee-platform nitro-aws --interval-seconds 60
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TARGETS = {
    "syslog-ngrok": _HERE / "make_remote_syslog_siem_config.py",
    "splunk-ngrok": _HERE / "make_remote_splunk_siem_config.py",
    "syslog-local": _HERE / "make_local_syslog_siem_config.py",
}


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "flavor",
        choices=sorted(_TARGETS.keys()),
        help="Which SIEM config generator to run.",
    )
    ap.add_argument(
        "forwarded",
        nargs=argparse.REMAINDER,
        help="Extra flags for the underlying script.",
    )
    args = ap.parse_args()
    script = _TARGETS[args.flavor]
    if not script.is_file():
        print(f"[generate-siem-config] missing script: {script}", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(script), *args.forwarded]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
