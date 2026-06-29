#!/usr/bin/env python3
"""Report on every trust anchor this repo pins, and warn before one expires.

Why this exists
---------------
``apps/cli/src/tee_crafter/certs/`` holds the anchors every generated verifier
client is built around.  Six of them are vendor roots that run to 2045-2049.
One is not: ``nvidia-nras-intermediate.pem`` is an *intermediate*, it expires
**2029-12-08**, and ``gpu_cc/*/client.template.py`` pins it by exact DER
equality against ``x5c[1]`` of the NRAS JWKS key — no name matching, no walk to
a root, no fallback.  When NVIDIA rotates that intermediate, every already
deployed GPU-CC client stops verifying GPU attestation, at once, with
``x5c chain: FAIL (intermediate does not match pinned NVIDIA CA)``.

Pinning the intermediate is deliberate (it is what NVIDIA's JWKS actually
carries), but it means rotation is a scheduled outage unless someone notices
first.  This script is how you notice first.  Run it on a schedule; it exits
non-zero when an anchor is close to expiry or when the live NRAS chain no
longer matches the pin.

Usage::

    python3 .github/scripts/check_pinned_anchors.py            # offline only
    python3 .github/scripts/check_pinned_anchors.py --live     # also poll NRAS
    python3 .github/scripts/check_pinned_anchors.py --warn-days 365

Offline mode needs no network and no credentials, so it is safe in CI.
``--live`` fetches the public NVIDIA NRAS JWKS (no API key required for the
JWKS endpoint itself).
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

REPO_ROOT = Path(__file__).resolve().parents[2]
CERTS_DIR = REPO_ROOT / "apps/cli/src/tee_crafter/certs"

NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"

#: The anchor whose rotation is a fleet-wide fail-closed event.  Named so the
#: report can single it out rather than burying it in an alphabetical list.
CRITICAL_PIN = "nvidia-nras-intermediate.pem"

#: Default warning horizon.  A year is not excessive for something that
#: requires rebuilding and redeploying every GPU-CC client: the work is a
#: coordinated fleet rollout, not a one-line patch.
DEFAULT_WARN_DAYS = 365


def _der_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _load_all(path: Path) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(path.read_bytes())


def check_local(warn_days: int, now: datetime.datetime) -> tuple[int, list[str]]:
    """Report expiry for every pinned anchor.  Returns (problems, lines)."""
    problems = 0
    lines: list[str] = []
    for path in sorted(CERTS_DIR.glob("*.pem")):
        try:
            certs = _load_all(path)
        except Exception as exc:  # noqa: BLE001 - report, never crash the check
            lines.append(f"  {path.name}: UNPARSEABLE ({exc})")
            problems += 1
            continue
        for cert in certs:
            days = (cert.not_valid_after_utc - now).days
            cn = ""
            try:
                cn = cert.subject.rfc4514_string()
            except Exception:  # noqa: BLE001
                cn = "<unprintable subject>"
            flag = ""
            if days < 0:
                flag = "  *** EXPIRED ***"
                problems += 1
            elif days <= warn_days:
                flag = f"  *** EXPIRES IN {days}d ***"
                problems += 1
            lines.append(
                f"  {path.name:32} {cert.not_valid_after_utc.date()}  "
                f"({days:>6}d)  {cn[:58]}{flag}")
    return problems, lines


def check_live_nras(now: datetime.datetime) -> tuple[int, list[str]]:
    """Compare the live NRAS JWKS intermediate against the pinned DER."""
    lines: list[str] = []
    pinned_path = CERTS_DIR / CRITICAL_PIN
    if not pinned_path.is_file():
        return 1, [f"  {CRITICAL_PIN} is missing from {CERTS_DIR}"]
    pinned = _load_all(pinned_path)[0]
    pinned_digest = _der_sha256(pinned)

    try:
        request = urllib.request.Request(
            NRAS_JWKS_URL,
            headers={"Accept": "application/json",
                     "User-Agent": "tee-crafter-anchor-check"})
        with urllib.request.urlopen(request, timeout=30) as response:
            doc = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, OSError,
            json.JSONDecodeError) as exc:
        # Unreachable is not the same as rotated.  Say so instead of raising
        # an alarm that would train the operator to ignore this check.
        message = (f"  NRAS JWKS unreachable ({type(exc).__name__}: {exc})"
                   " — pin NOT checked against live service")
        return 0, [message]

    keys = doc.get("keys") if isinstance(doc, dict) else doc
    if not isinstance(keys, list) or not keys:
        return 1, ["  NRAS JWKS carried no keys — cannot check the pin"]

    seen: dict[str, int] = {}
    unparseable: list[str] = []
    leaf_soonest: datetime.datetime | None = None
    for key in keys:
        x5c = key.get("x5c") or []
        if len(x5c) < 2:
            continue
        try:
            intermediate = x509.load_der_x509_certificate(
                base64.b64decode(x5c[1]))
            leaf = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
        except Exception as exc:  # noqa: BLE001
            # Report rather than swallow: a JWKS entry this script cannot read
            # is an entry it cannot check the pin against, and silently
            # skipping enough of them would let "live match: YES" be based on
            # one lucky key.
            unparseable.append(f"{key.get('kid', '<no kid>')}: "
                               f"{type(exc).__name__}")
            continue
        digest = _der_sha256(intermediate)
        seen[digest] = seen.get(digest, 0) + 1
        if leaf_soonest is None or leaf.not_valid_after_utc < leaf_soonest:
            leaf_soonest = leaf.not_valid_after_utc

    if not seen:
        return 1, ["  no usable x5c chain in the NRAS JWKS"]

    lines.append(f"  keys served              : {len(keys)}")
    if unparseable:
        lines.append(f"  unreadable entries       : {len(unparseable)} "
                     f"({', '.join(unparseable[:3])}"
                     f"{', …' if len(unparseable) > 3 else ''})")
    if leaf_soonest is not None:
        lines.append(
            f"  soonest leaf expiry      : {leaf_soonest.date()} "
            f"({(leaf_soonest - now).days}d) — leaves are short-lived by "
            "design; this is NOT the pin")
    lines.append(f"  pinned intermediate      : {pinned_digest[:32]}…")

    if pinned_digest in seen:
        others = len(seen) - 1
        lines.append(
            f"  live match               : YES ({seen[pinned_digest]} of "
            f"{len(keys)} keys chain to the pinned intermediate)")
        if others:
            lines.append(
                f"  NOTE: {others} other intermediate(s) also served — NVIDIA "
                "may be mid-rotation. Plan a re-pin now, before the pinned "
                "one stops being served.")
            return 1, lines
        return 0, lines

    lines.append("  live match               : *** NO ***")
    lines.append("  The NRAS JWKS no longer serves the pinned intermediate. "
                 "Every deployed GPU-CC client is failing GPU attestation "
                 "closed RIGHT NOW. Served intermediate digest(s): "
                 + ", ".join(f"{d[:32]}…" for d in sorted(seen)))
    return 1, lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--live", action="store_true",
                    help="also poll the public NVIDIA NRAS JWKS and compare "
                         "its intermediate against the pinned DER")
    ap.add_argument("--warn-days", type=int, default=DEFAULT_WARN_DAYS,
                    help=f"warn when an anchor expires within N days "
                         f"(default {DEFAULT_WARN_DAYS})")
    args = ap.parse_args()

    now = datetime.datetime.now(datetime.timezone.utc)
    problems = 0

    print(f"Pinned trust anchors in {CERTS_DIR.relative_to(REPO_ROOT)}")
    print(f"(as of {now.date()}, warning horizon {args.warn_days}d)\n")
    local_problems, lines = check_local(args.warn_days, now)
    problems += local_problems
    print("\n".join(lines))

    if args.live:
        print("\nLive NVIDIA NRAS JWKS check")
        live_problems, live_lines = check_live_nras(now)
        problems += live_problems
        print("\n".join(live_lines))
    else:
        print("\n(skipping the live NRAS check — pass --live to enable)")

    print()
    if problems:
        print(f"{problems} anchor issue(s) need attention. See "
              "docs/trust_anchor_rotation.md for the rotation runbook.")
        return 1
    print("all pinned anchors are current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
