#!/usr/bin/env python3
"""Wrap a Data Encryption Key (DEK) with a BYOK AWS KMS key.

Reads an existing ``byok-config.json`` (skeleton produced by
``create_kms_key.py``), generates a random 32-byte DEK (or accepts one
on stdin / via ``--dek-file``), encrypts it via ``kms:Encrypt`` with the
configured ``encryption_context``, and writes the base64-encoded
ciphertext back into the same JSON file under ``extra.ciphertext_b64``
so the document is ready to feed into
``tee-crafter deploy-container --byok aws-kms --byok-config <path>``.

For the per-request smoke test (see ``smoke_byok_aws.py``), this script
also prints the **plaintext DEK** on stdout (base64) so the smoke
driver can verify the enclave returned the same bytes.  Treat that
output as a secret.

Usage
-----

    # Random DEK + write ciphertext back into byok-nitro-aws.json:
    python3 byok-sandbox/aws/wrap_dek.py \
      --config byok-sandbox/configs/byok-nitro-aws.json \
      --tee-platform nitro-aws
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

from byok_platforms import AWS_TEE_PLATFORMS, aws_unwrap_algorithm  # noqa: E402


def _load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_config(path: str, doc: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, default=str)


def _load_dek(args) -> bytes:
    if args.dek_stdin:
        data = sys.stdin.buffer.read()
        if not data:
            raise SystemExit("--dek-stdin set but stdin was empty")
        if len(data) != args.dek_bytes:
            raise SystemExit(
                f"--dek-stdin gave {len(data)} bytes, expected {args.dek_bytes}; "
                "either pipe exactly --dek-bytes bytes or drop --dek-bytes")
        return data
    if args.dek_file:
        with open(args.dek_file, "rb") as f:
            data = f.read()
        if len(data) != args.dek_bytes:
            raise SystemExit(
                f"--dek-file gave {len(data)} bytes, expected {args.dek_bytes}")
        return data
    return os.urandom(args.dek_bytes)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--config", default="byok-sandbox/configs/byok-nitro-aws.json",
        help="byok-config.json produced by create_kms_key.py.  The wrapped "
             "DEK is written back into extra.ciphertext_b64.",
    )
    ap.add_argument(
        "--dek-bytes", type=int, default=32,
        help="DEK length in bytes (default: 32 = AES-256).",
    )
    ap.add_argument("--dek-stdin", action="store_true",
                    help="Read the plaintext DEK from stdin (exactly --dek-bytes).")
    ap.add_argument("--dek-file", default="",
                    help="Read the plaintext DEK from a file.")
    ap.add_argument(
        "--out-plaintext", default="",
        help="If set, write the plaintext DEK (base64) to this path so smoke "
             "tests can verify the enclave returns the same bytes.  Treat as "
             "secret.",
    )
    ap.add_argument(
        "--strip-metadata", action="store_true",
        help="Drop the `_metadata` block before saving so the file is identical "
             "to what production would ship.",
    )
    ap.add_argument(
        "--tee-platform",
        default=None,
        choices=list(AWS_TEE_PLATFORMS),
        help="Cross-check against create_kms_key.py output "
             "(_metadata.tee_platform + unwrap).",
    )
    args = ap.parse_args()

    try:
        import boto3
    except ImportError:
        print("ERROR: boto3 is required.", file=sys.stderr)
        return 2

    cfg = _load_config(args.config)
    provider = (cfg.get("provider") or "").lower()
    if provider != "aws-kms":
        raise SystemExit(f"{args.config}: provider is {provider!r}, expected aws-kms")

    meta_plat = (cfg.get("_metadata") or {}).get("tee_platform") or ""
    expect_unwrap = aws_unwrap_algorithm(args.tee_platform) if args.tee_platform else None
    cfg_unwrap = str(cfg.get("unwrap") or "").strip()
    if args.tee_platform:
        if meta_plat and meta_plat != args.tee_platform:
            raise SystemExit(
                f"{args.config}: _metadata.tee_platform is {meta_plat!r} but "
                f"--tee-platform {args.tee_platform!r}; regenerate with "
                "create_kms_key.py or drop --tee-platform.")
        if cfg_unwrap and cfg_unwrap != expect_unwrap:
            raise SystemExit(
                f"{args.config}: unwrap is {cfg_unwrap!r}; expected "
                f"{expect_unwrap!r} for --tee-platform {args.tee_platform!r}.")
    elif meta_plat:
        implied = aws_unwrap_algorithm(meta_plat)
        if cfg_unwrap and cfg_unwrap != implied:
            raise SystemExit(
                f"{args.config}: unwrap {cfg_unwrap!r} disagrees with "
                f"_metadata.tee_platform {meta_plat!r} (expects {implied!r}).")
    key_id = cfg.get("key_id") or ""
    region = cfg.get("region") or "us-east-2"
    enc_ctx: Dict[str, str] = dict(cfg.get("encryption_context") or {})
    if not key_id:
        raise SystemExit(f"{args.config}: key_id is empty (run create_kms_key.py first)")

    plaintext = _load_dek(args)

    kms = boto3.client("kms", region_name=region)
    print(f"[byok] wrapping {len(plaintext)}-byte DEK with {key_id}",
          file=sys.stderr)
    resp = kms.encrypt(
        KeyId=key_id, Plaintext=plaintext,
        EncryptionContext=enc_ctx or {},
    )
    ciphertext = resp["CiphertextBlob"]
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    sha = hashlib.sha256(plaintext).hexdigest()
    print(f"[byok] wrapped: ct={len(ciphertext)}B sha256(dek)={sha[:16]}...",
          file=sys.stderr)

    cfg.setdefault("extra", {})
    cfg["extra"]["ciphertext_b64"] = ciphertext_b64
    cfg["extra"]["dek_sha256"] = sha
    cfg["extra"]["dek_bytes"] = str(args.dek_bytes)
    if args.strip_metadata:
        cfg.pop("_metadata", None)
    _write_config(args.config, cfg)
    print(f"[byok] wrote ciphertext into {args.config} -> extra.ciphertext_b64",
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
        print(f"[byok] plaintext DEK base64 -> {args.out_plaintext} "
              "(chmod 0600).  TREAT AS SECRET.", file=sys.stderr)

    print(json.dumps({
        "key_id": key_id, "region": region,
        "dek_sha256": sha, "ciphertext_b64_len": len(ciphertext_b64),
        "encryption_context": enc_ctx,
        "byok_config": os.path.abspath(args.config),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
