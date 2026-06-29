#!/usr/bin/env python3
"""Create (or re-use) a GCP KMS symmetric key for TEE-Crafter BYOK testing.

End state
---------
* A KeyRing in ``--location`` (default ``us-central1``) named
  ``--keyring`` (default ``tee-crafter-byok``).
* A symmetric encrypt/decrypt CryptoKey called ``--key`` (default
  ``tee-crafter-byok-smoke``) inside that KeyRing.
* An IAM policy on the key that grants ``roles/cloudkms.cryptoKeyDecrypter``
  to the caller's identity *and* the workload-identity principal
  (configurable via ``--decrypter``) so a Confidential Space VM can
  perform attestation-gated decrypts.  For a first smoke test the
  default just adds the current ``gcloud`` user.
* Writes a ``byok-config.json`` skeleton (same schema as the AWS
  helper, only ``provider`` flips to ``gcp-kms``).

Usage
-----

    python3 byok-sandbox/gcp/create_kms_key.py \
      --project $(gcloud config get-value project) \
      --location us-central1 \
      --keyring tee-crafter-byok \
      --key tee-crafter-byok-smoke \
      --out byok-sandbox/configs/byok-gcp.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from byok_platforms import (  # noqa: E402
    GCP_TEE_PLATFORMS,
    default_gcp_byok_out_path,
)


def _run(cmd: list, *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check,
                           capture_output=capture, text=True)


def _gcloud_account() -> str:
    out = _run(["gcloud", "config", "get-value", "account"]).stdout.strip()
    if not out:
        raise SystemExit("gcloud account is unset (`gcloud auth login`)")
    return out


def _keyring_exists(project: str, location: str, keyring: str) -> bool:
    res = _run(
        ["gcloud", "kms", "keyrings", "describe", keyring,
         "--project", project, "--location", location],
        check=False)
    return res.returncode == 0


def _key_exists(project: str, location: str, keyring: str, key: str) -> bool:
    res = _run(
        ["gcloud", "kms", "keys", "describe", key,
         "--project", project, "--location", location,
         "--keyring", keyring],
        check=False)
    return res.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--project",
        default=_run(["gcloud", "config", "get-value", "project"],
                     check=False).stdout.strip() or "",
        help="GCP project id (default: gcloud config project).",
    )
    ap.add_argument("--location", default="us-central1")
    ap.add_argument("--keyring", default="tee-crafter-byok")
    ap.add_argument("--key", default="tee-crafter-byok-smoke")
    ap.add_argument(
        "--decrypter",
        action="append",
        default=[],
        help="Additional principal to grant cloudkms.cryptoKeyDecrypter on "
             "the new key.  Repeatable.  Example: "
             "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool-x/attribute.image_digest/sha256:...",
    )
    ap.add_argument(
        "--tee-platform",
        default=None,
        choices=list(GCP_TEE_PLATFORMS),
        help="Records intended tee-crafter --tee-platform in _metadata and "
             "picks a default --out path.  Omit for legacy "
             "byok-gcp.json naming.",
    )
    ap.add_argument(
        "--attribute-condition",
        default="",
        help="CEL attribute condition applied to the decrypter IAM binding, "
             "e.g. "
             "'assertion.submods.container.image_digest == \"sha256:...\"'.  "
             "Without one, the binding is unconditional and the key is only "
             "IAM-gated -- Cloud KMS AAD carries no policy semantics, so "
             "nothing else in this path checks the attestation.  Recorded as "
             "the attribute_condition_bound BYOK fact.",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Output skeleton path "
             "(default: byok-gcp.json or byok-gcp-<tee-platform>.json).",
    )
    args = ap.parse_args()
    out_path = (
        args.out
        if args.out is not None
        else (
            default_gcp_byok_out_path(args.tee_platform)
            if args.tee_platform
            else "byok-sandbox/configs/byok-gcp.json"
        )
    )
    if not args.project:
        raise SystemExit("--project is required")

    print(f"[byok-gcp] project={args.project} location={args.location} "
          f"keyring={args.keyring} key={args.key}", file=sys.stderr)

    if not _keyring_exists(args.project, args.location, args.keyring):
        print(f"[byok-gcp] creating keyring {args.keyring}...", file=sys.stderr)
        _run(["gcloud", "kms", "keyrings", "create", args.keyring,
              "--project", args.project, "--location", args.location])
    else:
        print(f"[byok-gcp] keyring {args.keyring} already exists",
              file=sys.stderr)

    if not _key_exists(args.project, args.location, args.keyring, args.key):
        print(f"[byok-gcp] creating key {args.key}...", file=sys.stderr)
        _run([
            "gcloud", "kms", "keys", "create", args.key,
            "--project", args.project, "--location", args.location,
            "--keyring", args.keyring,
            "--purpose", "encryption",
            "--default-algorithm", "google-symmetric-encryption",
        ])
    else:
        print(f"[byok-gcp] key {args.key} already exists, re-using",
              file=sys.stderr)

    # Always (re-)grant decrypter to the current account + the
    # `application-default` principal (which is what the Python google-cloud-kms
    # client uses) + any extras.  When ADC is set up as service-account
    # impersonation (e.g. `gcloud auth application-default login` after
    # `gcloud iam service-accounts add-iam-policy-binding ... --role roles/iam.serviceAccountTokenCreator`),
    # the impersonated principal also needs the binding.
    principals = [f"user:{_gcloud_account()}"] + list(args.decrypter or [])
    adc_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
    if os.path.isfile(adc_path):
        try:
            with open(adc_path, "r", encoding="utf-8") as f:
                adc = json.load(f)
            url = adc.get("service_account_impersonation_url") or ""
            if "serviceAccounts/" in url:
                sa = url.split("serviceAccounts/", 1)[1].split(":", 1)[0]
                if sa and f"serviceAccount:{sa}" not in principals:
                    principals.append(f"serviceAccount:{sa}")
        except Exception:
            pass
    key_resource = (
        f"projects/{args.project}/locations/{args.location}"
        f"/keyRings/{args.keyring}/cryptoKeys/{args.key}"
    )
    for member in principals:
        cmd = [
            "gcloud", "kms", "keys", "add-iam-policy-binding", args.key,
            "--project", args.project, "--location", args.location,
            "--keyring", args.keyring,
            "--member", member,
            "--role", "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        ]
        # The attribute condition is the ONLY thing that makes this path
        # attestation-gated; Cloud KMS' AAD is a plain AEAD input with no
        # authorisation semantics.  Applied to the workload-identity
        # (principalSet://) members only -- a human user principal has no
        # attestation claims to condition on.
        if args.attribute_condition and member.startswith("principalSet://"):
            cmd += ["--condition",
                    f"expression={args.attribute_condition},"
                    f"title=tee-crafter-confidential-space"]
        try:
            _run(cmd)
            print(f"[byok-gcp]   granted decrypter on {member}"
                  + (" (attribute-conditioned)"
                     if "--condition" in cmd else ""),
                  file=sys.stderr)
        except subprocess.CalledProcessError as exc:
            print(f"[byok-gcp]   WARN: could not grant on {member}: "
                  f"{(exc.stderr or '')[:200]}", file=sys.stderr)

    condition_bound = bool(
        args.attribute_condition
        and any(m.startswith("principalSet://") for m in principals))
    if not condition_bound:
        print("[byok-gcp] WARNING: no Confidential Space attribute condition "
              "on the decrypter binding, so this key is IAM-gated only.  Any "
              "principal holding the binding decrypts, attested or not.  Pass "
              "--decrypter principalSet://... --attribute-condition '<CEL>' to "
              "make it attestation-gated.", file=sys.stderr)

    skeleton = {
        "provider": "gcp-kms",
        "key_id": key_resource,
        "region": args.location,
        "label": args.key,
        "unwrap": "direct_bytes",
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
            # Gating facts — see core/keys/gating.py.  gcp-kms is iam-scoped
            # unless the decrypter binding carries a Confidential Space
            # attribute condition on the attestation token.
            "tee_platform": args.tee_platform or "",
            "attribute_condition_bound": "1" if condition_bound else "0",
        },
        "_metadata": {
            "tee_platform": args.tee_platform or "",
            "project": args.project, "location": args.location,
            "keyring": args.keyring,
            "attribute_condition": args.attribute_condition or "",
        },
    }
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(skeleton, f, indent=2)

    print(json.dumps({
        "key_id": key_resource,
        "project": args.project, "location": args.location,
        "keyring": args.keyring, "key": args.key,
        "tee_platform": args.tee_platform or None,
        "byok_config": os.path.abspath(out_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
