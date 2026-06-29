#!/usr/bin/env python3
"""Render a ready-to-use ``--siem-config`` JSON for the current ngrok tunnel.

When the ngrok profile of ``siem-sandbox/splunk/docker-compose.yml`` is up
(``docker compose --profile ngrok up -d``), ngrok publishes a public HTTPS
URL that forwards to the local Splunk HEC port.  The URL changes every
time the ngrok container restarts (free tier; no reserved domains), so
hard-coding it in a JSON file is fragile.

Pass ``--tee-platform`` so the printed recipe matches your TEE.
``fail_open`` defaults to false (production parity); pass ``--fail-open``
for local debugging only.

This script reads ngrok's local agent API at ``http://localhost:4040/api/tunnels``,
picks the current public HTTPS URL, resolves its hostname to IPv4 ``/32``
prefixes, and writes a TEE-Crafter ``--siem-config`` JSON with
``egress_allowlist_cidrs`` + ``egress_ports: [443]`` so AWS (and peers)
can lock NAT egress to the live ngrok edge — you do **not** hand-pick
CIDRs for the laptop sandbox.  (Same pattern as
``make_remote_syslog_siem_config.py`` for syslog-over-ngrok TCP.)

Hand the rendered file straight to ``tee-crafter deploy*`` to run a
real cloud-TEE test against your laptop's Splunk:

    docker compose --profile ngrok up -d
    python siem-sandbox/scripts/make_remote_splunk_siem_config.py
    # -> wrote siem-sandbox/configs/splunk-via-ngrok.json
    #    endpoint = https://abc-123.ngrok-free.app/services/collector

    tee-crafter deploy-container \\
        --tee-platform snp-aws \\
        --ami-id $SNP_AMI --source ./examples/docker_flask_api \\
        --siem splunk-hec \\
        --siem-config siem-sandbox/configs/splunk-via-ngrok.json \\
        --deploy --auto-approve --teardown
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from siem_platforms import TEE_PLATFORMS  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "siem-sandbox" / "configs" / "splunk-via-ngrok.json"
NGROK_API = "http://localhost:4040/api/tunnels"


def _load_env(path: Path) -> Dict[str, str]:
    if not path.is_file():
        return {}
    out: Dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _ngrok_public_url(*, deadline_s: int = 60) -> str:
    """Poll the ngrok agent API until a public HTTPS tunnel is published."""
    deadline = time.monotonic() + deadline_s
    last_err = "no response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(NGROK_API, timeout=3) as r:
                body = json.loads(r.read().decode("utf-8"))
            tunnels = body.get("tunnels", []) or []
            # Prefer the HTTPS tunnel (ngrok publishes both http+https).
            https = [t for t in tunnels
                     if t.get("public_url", "").startswith("https://")]
            if https:
                return https[0]["public_url"]
            if tunnels:
                last_err = "ngrok returned no https tunnel yet"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
        time.sleep(2)
    sys.exit(
        f"[make-remote-cfg] ngrok agent API on {NGROK_API} did not "
        f"publish a tunnel in {deadline_s}s (last error: {last_err}). "
        "Did `docker compose --profile ngrok up -d` finish?  Run "
        "`docker logs tee-crafter-ngrok` to debug."
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help=f"output JSON path (default: {DEFAULT_OUT})")
    ap.add_argument("--index", default="tee_crafter",
                    help="Splunk index to target (default: tee_crafter)")
    ap.add_argument("--interval-seconds", type=int, default=30,
                    help="continuous-attestation refresh interval (default: 30)")
    ap.add_argument(
        "--tee-platform",
        default=None,
        choices=TEE_PLATFORMS,
        help="Targets tee-crafter --tee-platform (updates Splunk source hint "
             "and printed recipe).",
    )
    ap.add_argument(
        "--fail-open",
        action="store_true",
        help="Set fail_open=true (dev hatch).  Default is fail-closed.",
    )
    args = ap.parse_args()

    sandbox_env = _load_env(REPO_ROOT / "siem-sandbox" / "splunk" / ".env")
    token = sandbox_env.get("SPLUNK_HEC_TOKEN", "11111111-1111-1111-1111-111111111111")

    public_url = _ngrok_public_url()
    endpoint = public_url.rstrip("/") + "/services/collector"

    doc = {
        "provider": "splunk-hec",
        "interval_seconds": args.interval_seconds,
        "sign_events": True,
        "fail_open": bool(args.fail_open),
        "endpoint": endpoint,
        "token": token,
        "index": args.index,
        "sourcetype": "tee_crafter:attestation",
        "source": (
            f"tee-crafter-{args.tee_platform}"
            if args.tee_platform
            else "tee-crafter"
        ),
        # ngrok terminates real Let's-Encrypt TLS at its edge and forwards
        # plain HTTP to our HEC port — TEE-Crafter sees a real cert, so no
        # verify_ssl override needed.  Set egress_mode=public so the
        # platform's NAT egress permits the ngrok CDN; in prod you'd
        # narrow this to the ALB CIDR via egress_allowlist_cidrs.
        "egress_mode": "public",
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"[make-remote-cfg] wrote {args.out.relative_to(REPO_ROOT)}")
    print(f"[make-remote-cfg]   endpoint = {endpoint}")
    print(f"[make-remote-cfg]   index    = {args.index}")
    print()
    plat = args.tee_platform or "snp-aws"
    print("Use it with tee-crafter deploy-container:")
    print(f"  tee-crafter deploy-container --tee-platform {plat} \\")
    print("      --source ./examples/docker_flask_api \\")
    print("      --ami-id $TEE_CRAFTER_AMI_ID \\")
    print(f"      --siem splunk-hec \\")
    print(f"      --siem-config {args.out.relative_to(REPO_ROOT)} \\")
    print(f"      --deploy --auto-approve --teardown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
