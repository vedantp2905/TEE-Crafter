#!/usr/bin/env python3
"""Wrap a Data Encryption Key (DEK) with an Azure Key Vault BYOK key.

Same flow as ``byok-sandbox/{aws,gcp}/wrap_dek.py`` but speaks Azure
Key Vault.  RSA-OAEP-SHA256 is used to wrap the DEK and the resulting
ciphertext (base64url -> base64) is written into
``extra.ciphertext_b64`` of the byok-config JSON.

Requires ``azure-keyvault-keys`` + ``azure-identity``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from byok_platforms import AZURE_TEE_PLATFORMS  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="byok-sandbox/configs/byok-azure.json")
    ap.add_argument("--dek-bytes", type=int, default=32)
    ap.add_argument("--dek-stdin", action="store_true")
    ap.add_argument("--dek-file", default="")
    ap.add_argument("--out-plaintext", default="")
    ap.add_argument(
        "--tee-platform",
        default=None,
        choices=list(AZURE_TEE_PLATFORMS),
        help="Must match create_kv_key.py _metadata.tee_platform when set.",
    )
    args = ap.parse_args()

    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys.crypto import (
            CryptographyClient, KeyWrapAlgorithm,
        )
    except ImportError:
        raise SystemExit(
            "ERROR: azure-keyvault-keys + azure-identity are required.  "
            "Install with `pip install azure-keyvault-keys azure-identity`.")

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if (cfg.get("provider") or "").lower() != "azure-kv":
        raise SystemExit(f"{args.config}: provider != azure-kv")
    meta_plat = (cfg.get("_metadata") or {}).get("tee_platform") or ""
    if args.tee_platform:
        if meta_plat and meta_plat != args.tee_platform:
            raise SystemExit(
                f"{args.config}: _metadata.tee_platform is {meta_plat!r} but "
                f"--tee-platform is {args.tee_platform!r}")
    key_url = cfg.get("key_id") or ""
    if not key_url.startswith("https://"):
        raise SystemExit(f"{args.config}: key_id must be a Key Vault key URL")

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

    cred = DefaultAzureCredential()
    crypto = CryptographyClient(key_url, credential=cred)
    print(f"[byok-az] wrapping {len(plaintext)}-byte DEK with {key_url}",
          file=sys.stderr)
    result = crypto.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, plaintext)
    ct = result.encrypted_key
    ct_b64 = base64.b64encode(ct).decode("ascii")
    sha = hashlib.sha256(plaintext).hexdigest()
    print(f"[byok-az] wrapped: ct={len(ct)}B sha256(dek)={sha[:16]}...",
          file=sys.stderr)

    cfg.setdefault("extra", {})
    cfg["extra"]["ciphertext_b64"] = ct_b64
    cfg["extra"]["dek_sha256"] = sha
    cfg["extra"]["dek_bytes"] = str(args.dek_bytes)
    with open(args.config, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

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
        "key_url": key_url, "dek_sha256": sha,
        "ciphertext_b64_len": len(ct_b64),
        "byok_config": os.path.abspath(args.config),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
