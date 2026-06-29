#!/usr/bin/env python3
"""Create (or re-use) a customer-managed AWS KMS key for TEE-Crafter BYOK.

End state
---------
* ``--tee-platform nitro-aws``: ``kms:Decrypt`` requires a Nitro
  ``Recipient`` attestation (unwrap ``aws_nitro_recipient``).  Optional
  ``--pcrs-json`` pins PCR0/1/2.
* ``--tee-platform snp-aws`` / ``gpu-cc-aws``: AWS KMS has no SEV-SNP (or
  NitroTPM) attestation condition key, so ``kms:Decrypt`` is gated on the
  caller's IAM principal and nothing else.  ``--instance-role-arn <exact
  ARN>`` is therefore **required** (repeatable); the policy pins it with
  ``ArnEquals``.  Unwrap is ``direct_bytes``.  Export
  ``TF_VAR_byok_aws_kms_arn`` to the key ARN before ``deploy-container``.
* Writes a ``byok-config.json`` skeleton (then run ``wrap_dek.py``).

Idempotent on ``--alias``.

Usage
-----

    # Nitro (default): Recipient-gated decrypt
    python3 byok-sandbox/aws/create_kms_key.py \\
      --tee-platform nitro-aws --region us-east-2 \\
      --alias tee-crafter-byok-smoke

    # SNP-AWS: decrypt pinned to one exact instance role + direct_bytes unwrap.
    # Get the ARN from the deploy dir with:
    #   terraform state show 'aws_iam_role.snp_role[0]'
    python3 byok-sandbox/aws/create_kms_key.py \\
      --tee-platform snp-aws --region us-east-2 \\
      --alias tee-crafter-byok-snp \\
      --instance-role-arn arn:aws:iam::123456789012:role/tee-crafter-snp-role-abc123

    # PCR-pinned Nitro key:
    python3 byok-sandbox/aws/create_kms_key.py \\
      --tee-platform nitro-aws --region us-east-2 \\
      --alias tee-crafter-byok-prod \\
      --pcrs-json builds/.../pcrs.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from byok_platforms import (  # noqa: E402
    AWS_IAM_ONLY_TEE_PLATFORMS,
    AWS_TEE_PLATFORMS,
    AwsKeyPolicyError,
    aws_instance_role_arn_pattern,
    aws_unwrap_algorithm,
    build_aws_kms_key_policy,
    default_aws_byok_out_path,
    validate_aws_instance_role_arns,
)


def _load_pcrs(path: str) -> Dict[str, str]:
    """Return ``{"PCR0": "<hex>", "PCR1": "<hex>", ...}`` from a Nitro pcrs.json."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    # Accept both `Measurements: {PCR0: ...}` (nitro-cli describe-eif format)
    # and a flat `{PCR0: ...}` dictionary.
    if isinstance(raw, dict) and isinstance(raw.get("Measurements"), dict):
        raw = raw["Measurements"]
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected dict, got {type(raw).__name__}")
    pcrs: Dict[str, str] = {}
    for key, value in raw.items():
        if not key.upper().startswith("PCR"):
            continue
        if not isinstance(value, str):
            continue
        pcrs[key.upper()] = value
    if "PCR0" not in pcrs:
        raise ValueError(f"{path}: no PCR0 entry found")
    return pcrs


def _resolve_alias(kms, alias: str) -> Optional[str]:
    """Return the key id behind ``alias/<alias>`` or None."""
    if not alias.startswith("alias/"):
        alias = "alias/" + alias
    try:
        resp = kms.describe_key(KeyId=alias)
        return resp["KeyMetadata"]["KeyId"]
    except kms.exceptions.NotFoundException:
        return None
    except Exception as exc:
        print(f"WARN: could not resolve {alias}: {exc}", file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--tee-platform",
        default="nitro-aws",
        choices=AWS_TEE_PLATFORMS,
        help="Target tee-crafter --tee-platform value.  nitro-aws uses "
             "Recipient-gated kms:Decrypt (unwrap aws_nitro_recipient); "
             "snp-aws and gpu-cc-aws use instance-role-gated Decrypt "
             "(unwrap direct_bytes).  After deploy, set "
             "TF_VAR_byok_aws_kms_arn to this key ARN for SNP/GPU-CC.",
    )
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-2"))
    ap.add_argument("--alias", default="tee-crafter-byok-smoke")
    ap.add_argument(
        "--pcrs-json",
        default="",
        help="Optional path to a Nitro pcrs.json so the key policy can be "
             "pinned to PCR0/1/2.  Without this, the key allows decrypt "
             "from any caller in the same AWS account that attaches a Nitro "
             "attestation document.",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Where to write the byok-config skeleton "
             "(default: byok-sandbox/configs/byok-<tee-platform>.json).",
    )
    ap.add_argument(
        "--encryption-context",
        action="append",
        default=[],
        metavar="k=v",
        help="Encryption-context pairs to require at decrypt time (repeatable). "
             "Stored in byok-config.json and forwarded by the in-TEE adapter.",
    )
    ap.add_argument(
        "--instance-role-arn",
        action="append",
        default=[],
        metavar="ARN",
        help="Exact IAM role ARN allowed to kms:Decrypt on snp-aws / "
             "gpu-cc-aws (repeatable).  REQUIRED for those platforms unless "
             "--allow-wildcard-role is passed.  There is no `terraform output` "
             "for it; from the deploy directory run "
             "`terraform state show 'aws_iam_role.snp_role[0]'` "
             "(gpu_cc_role for gpu-cc-aws) and read its `arn`, or "
             "`aws iam list-roles --query \"Roles[?starts_with(RoleName, "
             "'tee-crafter-snp-role-')].Arn\" --output text`.",
    )
    ap.add_argument(
        "--pin-at-deploy", action="store_true",
        help="RECOMMENDED for snp-aws / gpu-cc-aws. Create the key with NO "
             "kms:Decrypt grant at all; the deploy reads the exact instance "
             "role ARN from the `instance_role_arn` Terraform output and adds "
             "the grant itself, pinned with ArnEquals. Solves the ordering "
             "problem -- the role's name carries a per-deploy suffix, so its "
             "ARN cannot be known when the key is created -- without ever "
             "opening the key to a role-name pattern. Mutually exclusive with "
             "--instance-role-arn and --allow-wildcard-role.")

    ap.add_argument(
        "--allow-wildcard-role",
        action="store_true",
        help="DANGEROUS opt-in: use the legacy "
             "role/tee-crafter-<plat>-role-* wildcard instead of exact ARNs.  "
             "Throwaway sandbox accounts only -- since AWS KMS has no SEV-SNP "
             "attestation condition, that pattern is the only gate on the "
             "customer's DEK, so anyone who can create a role matching the "
             "name can decrypt it.",
    )
    ap.add_argument(
        "--reuse-only",
        action="store_true",
        help="Do not create a new key; fail if the alias does not exist.",
    )
    ap.add_argument(
        "--force-new",
        action="store_true",
        help="Always create a new key even if the alias already exists (will "
             "overwrite the alias to point at the new key).",
    )
    args = ap.parse_args()
    out_path = args.out if args.out is not None else default_aws_byok_out_path(
        args.tee_platform)

    if args.pcrs_json and args.tee_platform != "nitro-aws":
        print("ERROR: --pcrs-json only applies to --tee-platform nitro-aws "
              "(Nitro PCR pinning).  Omit --pcrs-json for SNP / GPU-CC.",
              file=sys.stderr)
        return 2

    role_arns: List[str] = [a.strip() for a in (args.instance_role_arn or []) if a.strip()]
    if args.tee_platform in AWS_IAM_ONLY_TEE_PLATFORMS:
        # AWS KMS has no SEV-SNP attestation condition key, so the principal
        # condition is the entire control on this path.  A wildcard role name is
        # therefore not an acceptable default.  Validate before any AWS call so
        # we never create or re-policy a key we are going to refuse to write.
        try:
            # --pin-at-deploy grants nothing now, so there is no ARN to
            # pre-flight; the deploy supplies the exact one later.
            if args.pin_at_deploy:
                role_arns = []
            else:
                role_arns = validate_aws_instance_role_arns(
                    args.tee_platform, role_arns,
                    allow_wildcard_role=args.allow_wildcard_role)
        except AwsKeyPolicyError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        if not role_arns:
            pattern = aws_instance_role_arn_pattern(
                "<this-account>", args.tee_platform)
            print("[byok] *** --allow-wildcard-role: the key policy will allow "
                  f"kms:Decrypt from EVERY principal matching {pattern}.  There "
                  "is no attestation condition behind it, so anyone with "
                  "iam:CreateRole in this account can mint a matching role and "
                  "read the customer's DEK.  Sandbox accounts only. ***",
                  file=sys.stderr)
    elif role_arns:
        print("WARN: --instance-role-arn is ignored for nitro-aws (the gate is "
              "the Recipient attestation, not the principal).", file=sys.stderr)
        role_arns = []

    try:
        import boto3
    except ImportError:
        print("ERROR: boto3 is required.  Install with `pip install boto3`.",
              file=sys.stderr)
        return 2

    sts = boto3.client("sts", region_name=args.region)
    kms = boto3.client("kms", region_name=args.region)

    account_id = sts.get_caller_identity()["Account"]
    print(f"[byok] AWS account: {account_id}, region: {args.region}",
          file=sys.stderr)

    pcr0 = pcr1 = pcr2 = None
    if args.pcrs_json:
        pcrs = _load_pcrs(args.pcrs_json)
        pcr0 = pcrs.get("PCR0")
        pcr1 = pcrs.get("PCR1")
        pcr2 = pcrs.get("PCR2")
        print(f"[byok] PCR-pinned: PCR0={pcr0[:16]}... PCR1={pcr1[:16] if pcr1 else '-'}",
              file=sys.stderr)
    elif args.tee_platform == "nitro-aws":
        print("[byok] WARNING: key policy is NOT pinned to specific PCRs.  "
              "Any Nitro enclave running in this AWS account that attaches a "
              "valid attestation document will be able to decrypt.  Re-run "
              "with --pcrs-json <path> before treating this key as "
              "production-grade.", file=sys.stderr)
    elif role_arns:
        print(f"[byok] tee-platform={args.tee_platform}: KMS Decrypt pinned with "
              f"ArnEquals to {len(role_arns)} exact instance-role ARN(s): "
              f"{', '.join(role_arns)}.  This is identity gating, not attestation "
              "gating -- root on the CVM can read those role credentials from "
              "IMDS and decrypt directly (core/keys/gating.py reports "
              "iam-scoped).", file=sys.stderr)
    else:
        print(f"[byok] tee-platform={args.tee_platform}: KMS Decrypt gated only "
              "by the wildcard instance-role name pattern (--allow-wildcard-role).",
              file=sys.stderr)

    existing = _resolve_alias(kms, args.alias)
    if existing and not args.force_new:
        if args.reuse_only:
            print(f"[byok] reuse-only: using existing alias/{args.alias} -> {existing}",
                  file=sys.stderr)
        else:
            print(f"[byok] alias/{args.alias} already exists -> {existing}; "
                  "updating key policy and re-using.  Pass --force-new to make "
                  "a fresh key instead.", file=sys.stderr)
        key_id = existing
        policy = build_aws_kms_key_policy(
            account_id, args.tee_platform, pcr0=pcr0, pcr1=pcr1, pcr2=pcr2,
            role_arns=role_arns or None,
            allow_wildcard_role=args.allow_wildcard_role,
            pin_at_deploy=args.pin_at_deploy)
        kms.put_key_policy(KeyId=key_id, PolicyName="default",
                           Policy=json.dumps(policy))
    else:
        if args.reuse_only:
            print(f"ERROR: --reuse-only set but alias/{args.alias} does not exist",
                  file=sys.stderr)
            return 1
        policy = build_aws_kms_key_policy(
            account_id, args.tee_platform, pcr0=pcr0, pcr1=pcr1, pcr2=pcr2,
            role_arns=role_arns or None,
            allow_wildcard_role=args.allow_wildcard_role,
            pin_at_deploy=args.pin_at_deploy)
        resp = kms.create_key(
            Description=(
                f"TEE-Crafter BYOK ({args.tee_platform}) {args.alias}"
            ),
            KeyUsage="ENCRYPT_DECRYPT",
            CustomerMasterKeySpec="SYMMETRIC_DEFAULT",
            Origin="AWS_KMS",
            Policy=json.dumps(policy),
            Tags=[
                {"TagKey": "Project", "TagValue": "tee-crafter"},
                {"TagKey": "Purpose", "TagValue": "byok"},
                {"TagKey": "Alias", "TagValue": args.alias},
            ],
        )
        key_id = resp["KeyMetadata"]["KeyId"]
        alias_name = args.alias if args.alias.startswith("alias/") \
            else f"alias/{args.alias}"
        try:
            kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
        except kms.exceptions.AlreadyExistsException:
            kms.update_alias(AliasName=alias_name, TargetKeyId=key_id)
        print(f"[byok] created key: {key_id} (alias {alias_name})",
              file=sys.stderr)

    key_meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    key_arn = key_meta["Arn"]
    print(f"[byok] key ARN: {key_arn}", file=sys.stderr)

    # Build the byok-config skeleton.  Allowed measurement hash is filled
    # in by wrap_dek.py (or by the operator) once the build is done.
    enc_ctx: Dict[str, str] = {}
    for kv in args.encryption_context or []:
        if "=" not in kv:
            print(f"WARN: --encryption-context {kv!r} ignored (need k=v)",
                  file=sys.stderr)
            continue
        k, v = kv.split("=", 1)
        enc_ctx[k.strip()] = v.strip()

    unwrap_alg = aws_unwrap_algorithm(args.tee_platform)
    skeleton = {
        "provider": "aws-kms",
        "key_id": key_arn,
        "region": args.region,
        "label": args.alias,
        "unwrap": unwrap_alg,
        "encryption_context": enc_ctx,
        "policy": {
            "max_attestation_age_seconds": 300,
            "allowed_measurement_sha256": [],
            "require_encryption_context_keys": list(enc_ctx.keys()),
            "require_signed_audit": True,
        },
        "dek_path": "/run/tee_crafter/byok_dek.bin",
        "extra": {
            # Placeholder — wrap_dek.py will fill this in (or the operator
            # can paste their own wrapped DEK).
            "ciphertext_b64": "",
            # Gating facts.  These ride to the TEE as TEE_CRAFTER_BYOK_X_*
            # and drive core/keys/gating.py, so the evidence bundle reports
            # what the key policy really enforces instead of a blanket
            # "attestation-gated" claim.  Only a PCR-pinned Nitro Recipient
            # decrypt is kms-enforced; everything else here is iam-scoped.
            "tee_platform": args.tee_platform,
            "pcrs_pinned": "1" if (args.tee_platform == "nitro-aws"
                                   and (pcr0 or pcr1 or pcr2)) else "0",
        },
        "_metadata": {
            "tee_platform": args.tee_platform,
            "account_id": account_id,
            "pcr_pinned": bool(pcr0 or pcr1 or pcr2),
            "principal_pinning": ("arn-equals" if role_arns
                                  else "arn-like-wildcard"),
            "instance_role_arns": role_arns,
            "pcr0": pcr0 or "",
            "pcr1": pcr1 or "",
            "pcr2": pcr2 or "",
            "created_at": key_meta["CreationDate"].isoformat()
                if key_meta.get("CreationDate") else "",
        },
    }
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(skeleton, f, indent=2, default=str)
    print(f"[byok] wrote skeleton -> {out_path}", file=sys.stderr)
    if args.tee_platform in ("snp-aws", "gpu-cc-aws"):
        print("[byok] Next: wrap DEK — python3 byok-sandbox/aws/wrap_dek.py "
              f"--tee-platform {args.tee_platform} "
              f"--config {out_path}",
              file=sys.stderr)
        print("[byok] Next: export TF_VAR_byok_aws_kms_arn="
              f"\"{key_arn}\"  before terraform apply / deploy.",
              file=sys.stderr)
    else:
        print("[byok] Next: wrap DEK — python3 byok-sandbox/aws/wrap_dek.py "
              f"--config {out_path}",
              file=sys.stderr)
    print(json.dumps({"key_arn": key_arn, "key_id": key_id,
                       "region": args.region, "alias": args.alias,
                       "tee_platform": args.tee_platform,
                       "unwrap": unwrap_alg,
                       "byok_config": os.path.abspath(out_path)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
