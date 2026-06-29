#!/usr/bin/env python3
"""Dispatch to cloud-specific BYOK skeleton generators (single entrypoint).

Examples
--------

    python3 byok-sandbox/generate_byok_config.py aws \\
      --tee-platform snp-aws --region us-east-2 --alias tee-byok-snp

    python3 byok-sandbox/generate_byok_config.py gcp \\
      --tee-platform tdx-gcp --project my-proj

    python3 byok-sandbox/generate_byok_config.py azure \\
      --tee-platform snp-azure --vault tc-byok-$RANDOM

Anything after the cloud name is forwarded verbatim to the underlying script.
Use ``<cloud> --help`` by running the target script directly, e.g.::

    python3 byok-sandbox/aws/create_kms_key.py --help
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TARGETS = {
    "aws": _HERE / "aws" / "create_kms_key.py",
    "gcp": _HERE / "gcp" / "create_kms_key.py",
    "azure": _HERE / "azure" / "create_kv_key.py",
}


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "cloud",
        choices=sorted(_TARGETS.keys()),
        help="Which cloud helper to invoke.",
    )
    ap.add_argument(
        "forwarded",
        nargs=argparse.REMAINDER,
        help="Arguments passed through to the cloud script.",
    )
    args = ap.parse_args()
    script = _TARGETS[args.cloud]
    if not script.is_file():
        print(f"[generate-byok-config] missing script: {script}", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(script), *args.forwarded]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
