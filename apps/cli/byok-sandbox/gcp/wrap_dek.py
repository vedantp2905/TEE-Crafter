#!/usr/bin/env python3
"""Wrap a Data Encryption Key (DEK) with a BYOK GCP KMS key.

Same flow as ``byok-sandbox/aws/wrap_dek.py`` but speaks GCP KMS.  The
``ciphertext`` returned by Cloud KMS is base64-encoded and written into
``extra.ciphertext_b64`` of the byok-config JSON so it can be plugged
into ``tee-crafter deploy-container --byok gcp-kms --byok-config <path>``.

Usage
-----

    python3 byok-sandbox/gcp/wrap_dek.py \
      --config byok-sandbox/configs/byok-gcp.json \
      --out-plaintext byok-sandbox/configs/byok-gcp.dek.b64
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from byok_platforms import GCP_TEE_PLATFORMS  # noqa: E402


def _canonical_aad(encryption_context: Dict[str, str]) -> bytes:
    """Canonical Cloud KMS AAD bytes — mirrors ``core.keys.gcp_kms.canonical_aad``.

    Duplicated (rather than imported) because ``byok-sandbox/`` is a standalone
    operator toolkit that runs from a checkout without the ``tee_crafter``
    package installed.  The canonical form is deliberately trivial so the two
    copies cannot drift silently:
    ``json.dumps(ctx, sort_keys=True, separators=(",", ":"))`` UTF-8 encoded,
    with an empty context mapping to ``b""``.
    ``tests/core/test_keys.py::TestGcpKmsAadInterop`` asserts they agree.
    """
    if not encryption_context:
        return b""
    return json.dumps(
        dict(encryption_context), sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="byok-sandbox/configs/byok-gcp.json")
    ap.add_argument("--dek-bytes", type=int, default=32)
    ap.add_argument("--dek-stdin", action="store_true")
    ap.add_argument("--dek-file", default="")
    ap.add_argument("--out-plaintext", default="")
    ap.add_argument(
        "--tee-platform",
        default=None,
        choices=list(GCP_TEE_PLATFORMS),
        help="Must match create_kms_key.py _metadata.tee_platform when set.",
    )
    args = ap.parse_args()

    try:
        from google.cloud import kms_v1
    except ImportError:
        raise SystemExit(
            "ERROR: google-cloud-kms is required.  "
            "Install with `pip install google-cloud-kms`.")

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if (cfg.get("provider") or "").lower() != "gcp-kms":
        raise SystemExit(f"{args.config}: provider != gcp-kms")
    meta_plat = (cfg.get("_metadata") or {}).get("tee_platform") or ""
    if args.tee_platform:
        if meta_plat and meta_plat != args.tee_platform:
            raise SystemExit(
                f"{args.config}: _metadata.tee_platform is {meta_plat!r} but "
                f"--tee-platform is {args.tee_platform!r}")
    key_id = cfg.get("key_id") or ""
    if not key_id:
        raise SystemExit(f"{args.config}: key_id is empty")

    if args.dek_stdin:
        plaintext = sys.stdin.buffer.read()
    elif args.dek_file:
        with open(args.dek_file, "rb") as f:
            plaintext = f.read()
    else:
        plaintext = os.urandom(args.dek_bytes)
    if args.dek_stdin or args.dek_file:
        if len(plaintext) != args.dek_bytes:
            raise SystemExit(f"DEK length {len(plaintext)} != --dek-bytes {args.dek_bytes}")

    # AAD must be byte-identical to what GcpKmsAdapter.release() passes to
    # Decrypt, or Cloud KMS refuses.  Both sides derive it from the same
    # encryption context via the one shared canonicaliser; an empty context
    # canonicalises to b"", matching a request that omits the field entirely.
    enc_ctx: Dict[str, str] = dict(cfg.get("encryption_context") or {})
    aad = _canonical_aad(enc_ctx)

    client = kms_v1.KeyManagementServiceClient()
    print(f"[byok-gcp] wrapping {len(plaintext)}-byte DEK with {key_id} "
          f"(aad={len(aad)}B from {len(enc_ctx)} encryption-context entries)",
          file=sys.stderr)
    req: Dict[str, object] = {"name": key_id, "plaintext": plaintext}
    if aad:
        req["additional_authenticated_data"] = aad
    resp = client.encrypt(request=req)
    ct = resp.ciphertext
    ct_b64 = base64.b64encode(ct).decode("ascii")
    sha = hashlib.sha256(plaintext).hexdigest()
    print(f"[byok-gcp] wrapped: ct={len(ct)}B sha256(dek)={sha[:16]}...",
          file=sys.stderr)

    cfg.setdefault("extra", {})
    cfg["extra"]["ciphertext_b64"] = ct_b64
    cfg["extra"]["dek_sha256"] = sha
    cfg["extra"]["dek_bytes"] = str(args.dek_bytes)
    with open(args.config, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"[byok-gcp] wrote ciphertext into {args.config}",
          file=sys.stderr)

    if args.out_plaintext:
        out_dir = os.path.dirname(os.path.abspath(args.out_plaintext))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.out_plaintext, "w", encoding="ascii") as f:
            f.write(base64.b64encode(plaintext).decode("ascii"))
        try:
            os.chmod(args.out_plaintext, 0o600)
        except Exception:
            pass

    print(json.dumps({
        "key_id": key_id, "dek_sha256": sha,
        "ciphertext_b64_len": len(ct_b64),
        "byok_config": os.path.abspath(args.config),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
