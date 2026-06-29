#!/usr/bin/env python3
"""Render a ready-to-use ``--siem-config`` JSON for syslog-cef via ngrok TCP.

When the ngrok profile of ``siem-sandbox/syslog/docker-compose.yml`` is up
(``docker compose --profile ngrok up -d``), ngrok publishes a public
``tcp://host:port`` that forwards raw bytes into syslog-ng's RFC-5424 TCP
listener (:601 inside the docker network).

Pass ``--tee-platform`` so the generated JSON's hostname and copy-paste
deploy snippet match your target TEE.  ``fail_open`` defaults to false
(production parity); pass ``--fail-open`` for local debugging only.

Splunk HEC uses ``ngrok http`` (HTTPS → HTTP).  Syslog is not HTTP, so we
use ``ngrok tcp`` instead.  The TEE's ``SyslogCefExporter`` connects with
``protocol: tcp`` to the public endpoint — same CEF framing as prod.

The ngrok agent's local API defaults to :4040; Splunk's stack already uses
that, so the syslog stack binds its agent API to **:4041** (see
``docker-compose.yml``).  This script reads:

    http://localhost:4041/api/tunnels

Example:

    cd siem-sandbox/syslog
    echo NGROK_AUTHTOKEN=<paste> >> .env
    docker compose --profile ngrok up -d

    cd ../..
    python siem-sandbox/scripts/make_remote_syslog_siem_config.py
    # -> wrote siem-sandbox/configs/syslog-via-ngrok.json
    #    host = 0.tcp.ngrok.io, port = 12345, egress_ports = [12345]

    tee-crafter deploy-container \\
        --tee-platform snp-aws \\
        --ami-id $SNP_AMI --source ./examples/docker_flask_api \\
        --siem syslog-cef \\
        --siem-config siem-sandbox/configs/syslog-via-ngrok.json \\
        --deploy --auto-approve --teardown

``egress_mode`` is ``public`` (not ``auto``) so the cloud VM gets NAT
egress — ``auto`` for syslog-cef is intra-VPC only and would block
internet-reachable ngrok.  ``egress_ports`` includes the ngrok TCP port
so AWS ``siem_egress_ports`` can open that outbound port when you pair
this with ``egress_allowlist_cidrs``.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.request
from pathlib import Path
from typing import List, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from siem_platforms import TEE_PLATFORMS  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "siem-sandbox" / "configs" / "syslog-via-ngrok.json"
DEFAULT_NGROK_API = "http://localhost:4041/api/tunnels"


def _ngrok_tcp_endpoint(*, ngrok_api: str, deadline_s: int = 90) -> Tuple[str, int]:
    """Poll the ngrok agent API until a public TCP tunnel is published."""
    deadline = time.monotonic() + deadline_s
    last_err = "no response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(ngrok_api, timeout=3) as r:
                body = json.loads(r.read().decode("utf-8"))
            tunnels = body.get("tunnels", []) or []
            for t in tunnels:
                url = (t.get("public_url") or "").strip()
                if url.startswith("tcp://"):
                    rest = url[len("tcp://") :]
                    if ":" not in rest:
                        last_err = f"bad tcp url {url!r}"
                        continue
                    host, _, port_s = rest.rpartition(":")
                    try:
                        port = int(port_s)
                    except ValueError:
                        last_err = f"bad tcp port in {url!r}"
                        continue
                    if host and port > 0:
                        return host, port
            if tunnels:
                last_err = "ngrok returned no tcp:// tunnel yet"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
        time.sleep(2)
    sys.exit(
        f"[make-remote-syslog] ngrok agent API on {ngrok_api} did not "
        f"publish a tcp tunnel in {deadline_s}s (last error: {last_err}). "
        "Did `docker compose --profile ngrok up -d` from "
        "siem-sandbox/syslog/ finish?  Is NGROK_AUTHTOKEN set in "
        "siem-sandbox/syslog/.env?  Run `docker logs tee-crafter-ngrok-syslog` "
        "to debug."
    )


def _resolve_cidrs(host: str) -> List[str]:
    """Resolve ``host`` to one ``/32`` CIDR per published A record.

    ngrok's TCP edge for a single region resolves to a small (~3) A-record
    set; locking the cloud TEE's NAT egress to that exact set is the
    production-parity behaviour — the SG/NSG allows attestation traffic to
    *only* the ngrok edge IPs, not the entire internet.

    On rare ngrok edge rotations (we observed ~24h stability on the free
    tier) the deploy must be rebuilt; this is documented as a trade-off.
    Use ``--egress-allow open`` to escape-hatch to ``0.0.0.0/0`` if you
    have a long-running deploy and accept the wider blast radius.
    """
    try:
        addrs = sorted({ai[4][0]
                        for ai in socket.getaddrinfo(host, None,
                                                      socket.AF_INET,
                                                      socket.SOCK_STREAM)})
    except socket.gaierror as e:
        sys.exit(f"[make-remote-syslog] DNS resolution for {host!r} failed: {e}")
    if not addrs:
        sys.exit(f"[make-remote-syslog] no A records for {host!r}")
    return [f"{ip}/32" for ip in addrs]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help=f"output JSON path (default: {DEFAULT_OUT})")
    ap.add_argument("--ngrok-api", default=DEFAULT_NGROK_API,
                    help=f"ngrok local agent API (default: {DEFAULT_NGROK_API})")
    ap.add_argument("--interval-seconds", type=int, default=30,
                    help="continuous-attestation refresh interval (default: 30)")
    ap.add_argument(
        "--tee-platform",
        default=None,
        choices=TEE_PLATFORMS,
        help="Targets tee-crafter --tee-platform (sets hostname hint + printed "
             "deploy recipe).",
    )
    ap.add_argument(
        "--fail-open",
        action="store_true",
        help="Set fail_open=true (dev hatch).  Default is fail-closed "
             "(production parity).",
    )
    ap.add_argument("--egress-allow", choices=("locked", "open"),
                    default="locked",
                    help=("'locked' (default, prod-parity): SG/NSG egress "
                          "is constrained to the resolved /32 of the ngrok "
                          "TCP edge.  'open' allows 0.0.0.0/0 on the ngrok "
                          "port — escape hatch when ngrok rotates edge IPs "
                          "during a long deploy."))
    args = ap.parse_args()

    host, port = _ngrok_tcp_endpoint(ngrok_api=args.ngrok_api)

    if args.egress_allow == "locked":
        allow_cidrs = _resolve_cidrs(host)
    else:
        allow_cidrs = ["0.0.0.0/0"]

    doc = {
        "provider": "syslog-cef",
        "interval_seconds": args.interval_seconds,
        "sign_events": True,
        "fail_open": bool(args.fail_open),
        "host": host,
        "port": port,
        "protocol": "tcp",
        "facility": 13,
        "hostname": (
            f"tee-crafter-{args.tee_platform}"
            if args.tee_platform
            else "tee-crafter"
        ),
        # Cloud TEE -> public ngrok needs NAT, not syslog's default
        # auto=intra-VPC-only path.
        "egress_mode": "public",
        # AWS's siem_egress_ports rule fires only when
        # egress_allowlist_cidrs is non-empty.  Without this allowlist
        # the SG would open 443/tcp only and silently drop the syslog
        # TCP connection.  Resolving ngrok host->/32 keeps prod parity:
        # the host can talk to the ngrok edge on the ngrok port, and
        # nothing else.
        "egress_allowlist_cidrs": allow_cidrs,
        "egress_ports": [port],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"[make-remote-syslog] wrote {args.out.relative_to(REPO_ROOT)}")
    print(f"[make-remote-syslog]   host         = {host}")
    print(f"[make-remote-syslog]   port         = {port}")
    print(f"[make-remote-syslog]   protocol     = tcp")
    print(f"[make-remote-syslog]   egress_mode  = public")
    print(f"[make-remote-syslog]   egress_cidrs = {allow_cidrs}")
    print(f"[make-remote-syslog]   egress_ports = [{port}]")
    print()
    plat = args.tee_platform or "snp-aws"
    print("Use it with tee-crafter deploy-container:")
    print(f"  tee-crafter deploy-container --tee-platform {plat} \\")
    print("      --source ./examples/docker_flask_api \\")
    print("      --ami-id $TEE_CRAFTER_AMI_ID \\")
    print("      --siem syslog-cef \\")
    print(f"      --siem-config {args.out.relative_to(REPO_ROOT)} \\")
    print("      --deploy --auto-approve --teardown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
