#!/usr/bin/env python3
"""Create (or re-use) an Azure Key Vault key for TEE-Crafter BYOK testing.

Two modes
---------
* ``--mode premium`` (default) — Premium-tier Key Vault + software-backed
  key with a key release policy.  The ``release`` operation is gated by
  the Microsoft Azure Attestation (MAA) token presented by an SNP/TDX
  CVM, which is exactly what
  ``tee_crafter.core.keys.azure_kv.AzureKeyVaultAdapter`` consumes.
  Costs ~~$1/month for a Premium vault + per-operation pricing.

* ``--mode mhsm`` — Managed HSM with an HSM-backed key.  Required for
  FIPS-validated production deployments but costs ~$3/hr base.  This
  mode prints the ``az`` commands and exits without running them; the
  operator runs them manually after confirming they want to pay for the
  Managed HSM cluster.

Both modes emit a ``byok-config.json`` skeleton (same schema as the
AWS/GCP helpers) so ``tee-crafter deploy-container --byok azure-kv
--byok-config <path>`` is one CLI flag away.

Usage
-----

    # 1. Premium-vault smoke test (cheap):
    python3 byok-sandbox/azure/create_kv_key.py \
      --subscription <sub-id> \
      --resource-group tee-crafter-byok-rg \
      --location eastus \
      --vault tee-crafter-byok-kv-$RANDOM \
      --key tee-crafter-byok-smoke \
      --out byok-sandbox/configs/byok-azure.json

    # 2. Print the Managed HSM commands without running them:
    python3 byok-sandbox/azure/create_kv_key.py --mode mhsm --print-only \
      --resource-group tee-crafter-byok-rg --location eastus \
      --mhsm tee-crafter-mhsm --key tee-crafter-byok-key
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from byok_platforms import (  # noqa: E402
    AZURE_TEE_PLATFORMS,
    azure_combined_release_policy,
    azure_release_policy_for_tee_platform,
    azure_release_policy_is_workload_bound,
    default_azure_byok_out_path,
)


def _run(cmd: List[str], *, check: bool = True,
         capture: bool = True, env: Optional[dict] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=capture,
                           text=True, env=env)


def _az_account() -> dict:
    out = _run(["az", "account", "show", "-o", "json"]).stdout
    return json.loads(out)


def _vault_exists(rg: str, vault: str) -> bool:
    res = _run(["az", "keyvault", "show", "--name", vault,
                "--resource-group", rg, "-o", "none"], check=False)
    return res.returncode == 0


def _key_exists(vault: str, key: str) -> bool:
    res = _run(["az", "keyvault", "key", "show",
                "--vault-name", vault, "--name", key, "-o", "none"],
               check=False)
    return res.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="premium", choices=("premium", "mhsm"))
    ap.add_argument("--subscription", default="")
    ap.add_argument("--resource-group", default="tee-crafter-byok-rg")
    ap.add_argument("--location", default="eastus")
    ap.add_argument("--vault", default="",
                    help="Premium Key Vault name (--mode premium).")
    ap.add_argument("--mhsm", default="",
                    help="Managed HSM name (--mode mhsm).")
    ap.add_argument("--key", default="tee-crafter-byok-smoke")
    ap.add_argument(
        "--tee-platform",
        default=None,
        choices=list(AZURE_TEE_PLATFORMS),
        help="Tune Key Vault release policy for the intended tee-crafter "
             "Azure platform (omit for combined SNP+TDX policy).  Ignored "
             "when --release-policy-file is set.",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Output skeleton (default byok-azure.json or "
             "byok-azure-<tee-platform>.json).",
    )
    ap.add_argument("--print-only", action="store_true",
                    help="Print az commands without executing.")
    ap.add_argument(
        "--release-policy-file", default="",
        help="Path to a JSON release policy.  When unset, uses "
             "--tee-platform-specific policy or a combined SNP+TDX default.",
    )
    ap.add_argument(
        "--launch-measurement", default="",
        help="Hex x-ms-sevsnpvm-launchmeasurement to pin in the release "
             "policy.  Without it the policy pins only x-ms-attestation-type "
             "against the SHARED PUBLIC MAA authorities, which every SEV-SNP / "
             "TDX CVM in every Azure tenant satisfies.  Take this from the "
             "bake-time measurement registry.",
    )
    ap.add_argument(
        "--host-data", default="",
        help="Hex x-ms-sevsnpvm-hostdata to pin alongside the launch "
             "measurement (binds the image/config the CVM was launched with).",
    )
    ap.add_argument(
        "--maa-authority", action="append", default=[], metavar="URL",
        help="Customer-owned MAA instance URL to use instead of the shared "
             "multi-tenant sharedeus/sharedeus2 endpoints (repeatable).",
    )
    args = ap.parse_args()
    out_path = (
        args.out
        if args.out is not None
        else (
            default_azure_byok_out_path(args.tee_platform)
            if args.tee_platform
            else "byok-sandbox/configs/byok-azure.json"
        )
    )

    if not args.subscription:
        try:
            args.subscription = _az_account()["id"]
        except Exception as exc:
            raise SystemExit(f"could not read az subscription: {exc}")

    # ----- Managed HSM (print-only) -----------------------------------------
    if args.mode == "mhsm":
        if not args.mhsm:
            args.mhsm = "tee-crafter-mhsm"
        cmds = [
            ["az", "keyvault", "create",
             "--hsm-name", args.mhsm,
             "--resource-group", args.resource_group,
             "--location", args.location,
             "--administrators", _az_account().get("user", {}).get("name", "")],
            ["az", "keyvault", "key", "create",
             "--hsm-name", args.mhsm,
             "--name", args.key,
             "--ops", "encrypt", "decrypt", "wrapKey", "unwrapKey", "sign", "verify",
             "--kty", "RSA-HSM",
             "--size", "3072",
             "--exportable", "true",
             "--policy", "@release-policy.json"],
        ]
        if args.print_only or True:  # Managed HSM is always print-only.
            print("# Managed HSM is a paid resource (~$3/hr base).  Run the\n"
                  "# following only if you understand the cost.  See:\n"
                  "#   https://learn.microsoft.com/azure/key-vault/managed-hsm/\n",
                  file=sys.stderr)
            for c in cmds:
                print("  " + " ".join(shlex.quote(x) for x in c))
            return 0

    # ----- Premium Key Vault ------------------------------------------------
    if not args.vault:
        raise SystemExit("--mode premium requires --vault <name>")

    # Resource group.
    _run(["az", "group", "create", "--name", args.resource_group,
          "--location", args.location, "-o", "none"], check=False)

    # Vault.
    if not _vault_exists(args.resource_group, args.vault):
        print(f"[byok-az] creating Premium Key Vault {args.vault}...",
              file=sys.stderr)
        _run(["az", "keyvault", "create",
              "--name", args.vault, "--resource-group", args.resource_group,
              "--location", args.location, "--sku", "premium",
              "--enable-rbac-authorization", "true",
              "--enabled-for-deployment", "true",
              "-o", "none"])
    else:
        print(f"[byok-az] vault {args.vault} already exists", file=sys.stderr)

    # Make sure the running identity has Key Vault Crypto Officer + Releaser.
    me = _az_account()
    upn = me.get("user", {}).get("name", "")
    sub_id = me["id"]
    scope = (f"/subscriptions/{sub_id}/resourceGroups/{args.resource_group}"
             f"/providers/Microsoft.KeyVault/vaults/{args.vault}")
    for role in ("Key Vault Crypto Officer", "Key Vault Crypto User"):
        try:
            _run(["az", "role", "assignment", "create",
                  "--assignee", upn, "--role", role,
                  "--scope", scope, "-o", "none"], check=False)
        except Exception:
            pass

    # Release policy JSON for az keyvault key create / skeleton metadata.
    if args.release_policy_file:
        with open(args.release_policy_file, "r", encoding="utf-8") as f:
            policy_text = f.read()
    elif args.tee_platform:
        policy_text = json.dumps(azure_release_policy_for_tee_platform(
            args.tee_platform,
            launch_measurement=args.launch_measurement or None,
            host_data=args.host_data or None,
            authorities=args.maa_authority or None))
    else:
        policy_text = json.dumps(azure_combined_release_policy())

    # Secure Key Release is only workload-bound when EVERY anyOf branch pins
    # the launch measurement; one unbound branch makes the whole policy
    # satisfiable without it.  This drives the gating claim in the evidence
    # bundle (core/keys/gating.py), so compute it from the policy we are
    # actually about to install, not from the flags.
    workload_bound = azure_release_policy_is_workload_bound(
        json.loads(policy_text))
    if not workload_bound:
        print("[byok-az] WARNING: release policy does not pin "
              "x-ms-sevsnpvm-launchmeasurement, so it is satisfied by ANY "
              "SEV-SNP/TDX confidential VM in ANY Azure tenant.  The effective "
              "gate is the vault's data-plane RBAC, not attestation.  Re-run "
              "with --launch-measurement <hex> (and --host-data) before "
              "treating this key as production-grade.", file=sys.stderr)

    if not _key_exists(args.vault, args.key):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                          encoding="utf-8") as tf:
            tf.write(policy_text)
            policy_path = tf.name
        print(f"[byok-az] creating releasable key {args.key}...",
              file=sys.stderr)
        try:
            # NOTE: releasability is conferred by --exportable + the release
            # --policy, NOT by a key op. Newer az CLI rejects "release" in
            # --ops (allowed: encrypt/decrypt/sign/verify/wrapKey/unwrapKey/
            # import/export).
            # Secure Key Release requires an HSM-backed key: a Premium vault
            # rejects exportable software ("RSA") keys (AKV.SKR.1006), so use
            # RSA-HSM. (Managed HSM mode above already uses RSA-HSM.)
            _run(["az", "keyvault", "key", "create",
                  "--vault-name", args.vault, "--name", args.key,
                  "--ops", "encrypt", "decrypt", "wrapKey", "unwrapKey",
                  "--kty", "RSA-HSM",
                  "--size", "3072",
                  "--exportable", "true",
                  "--policy", "@" + policy_path,
                  "-o", "none"])
        finally:
            try:
                os.unlink(policy_path)
            except Exception:
                pass
    else:
        print(f"[byok-az] key {args.key} already exists, re-using",
              file=sys.stderr)

    # Resolve full Key Vault key URL.
    key_info = json.loads(_run(["az", "keyvault", "key", "show",
                                 "--vault-name", args.vault,
                                 "--name", args.key, "-o", "json"]).stdout)
    key_url = key_info["key"]["kid"]

    skeleton = {
        "provider": "azure-kv",
        "key_id": key_url,
        "region": args.location,
        "label": args.key,
        "unwrap": "rsa_oaep_sha256",
        "encryption_context": {},
        "policy": {
            "max_attestation_age_seconds": 300,
            "allowed_measurement_sha256": [],
            "require_encryption_context_keys": [],
            "require_signed_audit": True,
        },
        "dek_path": "/run/tee_crafter/byok_dek.bin",
        "extra": {
            "ciphertext_b64": "",
            # Gating facts — see core/keys/gating.py.  azure-kv is only
            # kms-enforced when the SKR policy names this specific workload.
            "tee_platform": args.tee_platform or "",
            "workload_claims_bound": "1" if workload_bound else "0",
        },
        "_metadata": {
            "tee_platform": args.tee_platform or "",
            "workload_claims_bound": workload_bound,
            "subscription": args.subscription, "resource_group": args.resource_group,
            "vault": args.vault, "key": args.key, "location": args.location,
            "release_policy": json.loads(policy_text),
        },
    }
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(skeleton, f, indent=2)

    print(json.dumps({
        "key_url": key_url,
        "vault": args.vault, "key": args.key,
        "resource_group": args.resource_group, "location": args.location,
        "tee_platform": args.tee_platform or None,
        "byok_config": os.path.abspath(out_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
