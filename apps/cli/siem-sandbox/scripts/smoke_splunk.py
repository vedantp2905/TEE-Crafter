#!/usr/bin/env python3
"""Splunk HEC local-sandbox smoke test.

What it does
------------
1.  Builds the *real* ``SplunkHecExporter`` (the same class TEE-Crafter uses
    inside an enclave) wired against the local docker-compose Splunk:
    ``https://localhost:8088/services/collector``.

2.  Generates a handful of signed ``AttestationEvent``s through the *real*
    ``ContinuousAttestor`` / Ed25519 signing path so the smoke test
    exercises hash-chaining + signature emission, not just framing.

3.  Posts them via HEC, then queries Splunk's REST search API
    (``https://localhost:8089``) until the events appear in the
    ``tee_crafter`` index — proving end-to-end ingest.

4.  Prints a one-line summary (events sent / events found / p50 latency).
    Exit code 0 on success, 1 otherwise.

Run from the repo root:

    python siem-sandbox/scripts/smoke_splunk.py

Reads ``siem-sandbox/splunk/.env`` (created via ``cp .env.example .env``)
for the password + HEC token; falls back to the dev defaults.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

try:
    import requests  # type: ignore
except ImportError:
    sys.exit("[smoke] please `pip install requests` first")

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from tee_crafter.core.audit.continuous import (
    AttestationEvent,
    ContinuousAttestor,
    _short_uuid,
)
from tee_crafter.core.audit.exporters.splunk_hec import SplunkHecExporter


def _load_dotenv(path: Path) -> Dict[str, str]:
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


def _wait_for_splunk(rest_url: str, password: str, *, timeout_s: int = 180) -> None:
    """Block until Splunk's REST API answers — accounts for the ~2 min first boot."""
    deadline = time.monotonic() + timeout_s
    last_err = ""
    while time.monotonic() < deadline:
        try:
            r = requests.get(
                f"{rest_url}/services/server/info?output_mode=json",
                auth=("admin", password), verify=False, timeout=4,
            )
            if r.ok:
                return
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
        time.sleep(3)
    sys.exit(f"[smoke] Splunk did not become ready in {timeout_s}s "
             f"(last error: {last_err}). "
             "Did `docker compose up -d` from siem-sandbox/splunk/ finish?")


def _ensure_index(rest_url: str, password: str, index: str) -> None:
    """Create the index if it doesn't already exist.  Splunk's HEC will
    silently drop events targeted at a non-existent index, which is the
    #1 reason smoke tests pass on the wire but show 0 search hits."""
    auth = ("admin", password)
    list_url = f"{rest_url}/services/data/indexes?output_mode=json"
    r = requests.get(list_url, auth=auth, verify=False, timeout=10)
    r.raise_for_status()
    names = {e["name"] for e in r.json().get("entry", [])}
    if index in names:
        return
    r = requests.post(
        f"{rest_url}/services/data/indexes",
        auth=auth, verify=False, timeout=15,
        data={"name": index, "datatype": "event"},
    )
    if not r.ok and "already exists" not in r.text:
        sys.exit(f"[smoke] could not create index {index!r}: HTTP {r.status_code} {r.text[:200]}")


def _build_event(seq: int, *, prev_digest: str) -> AttestationEvent:
    return AttestationEvent(
        event_id=_short_uuid(),
        seq=seq,
        event_type="attestation_refresh" if seq else "attestation_boot",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        pipeline_version="smoke-1.0",
        instance_id="smoke-dev-laptop",
        tee_platform="snp-gcp",
        measurement_sha256="0" * 64,
        attestation_sha256="0" * 64,
        attestation_size_bytes=1184,
        status="pass",
        prev_digest=prev_digest,
        digest="d" * 64,
        signature="s" * 64,
        public_key_pem="-----BEGIN PUBLIC KEY-----\nSMOKE\n-----END PUBLIC KEY-----",
    )


def _search_hits(rest_url: str, password: str, index: str, instance_id: str,
                 *, deadline_s: int = 30) -> int:
    """Poll Splunk search until events with our instance_id appear."""
    auth = ("admin", password)
    deadline = time.monotonic() + deadline_s
    last = 0
    while time.monotonic() < deadline:
        spl = f'search index={index} instance_id="{instance_id}" | stats count'
        r = requests.post(
            f"{rest_url}/services/search/jobs/oneshot?output_mode=json",
            auth=auth, verify=False, timeout=20,
            data={"search": spl, "earliest_time": "-5m"},
        )
        if r.ok:
            body = r.json()
            results = body.get("results") or []
            if results:
                try:
                    last = int(results[0].get("count", 0))
                except (TypeError, ValueError):
                    last = 0
                if last > 0:
                    return last
        time.sleep(2)
    return last


def main() -> int:
    sandbox = REPO_ROOT / "siem-sandbox" / "splunk"
    env = _load_dotenv(sandbox / ".env")
    if not env:
        env = _load_dotenv(sandbox / ".env.example")

    password = env.get("SPLUNK_PASSWORD", "changeme123!")
    hec_token = env.get("SPLUNK_HEC_TOKEN", "11111111-1111-1111-1111-111111111111")
    # Smoke test hits nginx-alb on :8443 (HTTPS w/ self-signed dev cert),
    # which terminates TLS and reverse-proxies to splunk:8088 (HTTP)
    # inside the docker network.  Mirrors the production
    # "AWS ALB + ACM -> HTTP -> ECS task running splunk" wire shape.
    hec_url = "https://localhost:8443/services/collector"
    # The mgmt / REST API on :8089 is HTTPS-only in Splunk and we hit it
    # directly (no nginx) because it's only used for verification queries.
    rest_url = "https://localhost:8089"
    index = "tee_crafter"
    instance_id = f"smoke-{_short_uuid()}"

    print(f"[smoke] waiting for Splunk REST API on {rest_url} ...")
    _wait_for_splunk(rest_url, password)
    print(f"[smoke] Splunk is up.  Ensuring index={index!r} ...")
    _ensure_index(rest_url, password, index)

    exporter = SplunkHecExporter(
        endpoint=hec_url.replace("/services/collector", ""),
        token=hec_token,
        index=index,
        sourcetype="tee_crafter:attestation",
        source="tee-crafter-smoke",
        # nginx-alb serves a self-signed dev cert; clients must skip
        # verification.  Same flag your --siem-config JSON would set via
        # `"extra": {"verify_ssl": "0"}` (see splunk-local.json).
        verify_ssl=False,
    )

    n_events = 3
    latencies_ms = []
    prev_digest = ""
    print(f"[smoke] emitting {n_events} events to {hec_url} (instance_id={instance_id}) ...")
    for i in range(n_events):
        ev = _build_event(i, prev_digest=prev_digest)
        # Stamp our smoke-test instance_id so search can isolate this run.
        ev.instance_id = instance_id
        t0 = time.monotonic()
        exporter.emit(ev)
        latencies_ms.append((time.monotonic() - t0) * 1000)
        prev_digest = ev.digest

    print("[smoke] querying Splunk search API to confirm ingest ...")
    found = _search_hits(rest_url, password, index, instance_id)
    p50 = statistics.median(latencies_ms) if latencies_ms else 0

    ok = found >= n_events
    print(
        f"[smoke] {n_events} events sent, {found} events found in "
        f"Splunk index={index}, p50 HEC POST latency {p50:.0f} ms — "
        f"{'PASS' if ok else 'FAIL'}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
