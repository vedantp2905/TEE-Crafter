#!/usr/bin/env python3
"""End-to-end BYOK smoke test against a running Nitro enclave.

Flow
----
1.  Read a ``byok-config.json`` produced by ``create_kms_key.py`` +
    ``wrap_dek.py`` (so it carries ``key_id``, ``region``,
    ``encryption_context``, ``extra.ciphertext_b64`` and
    ``extra.dek_sha256``).
2.  Open an SSM ``AWS-StartPortForwardingSession`` to the deployed
    Nitro instance on ``localhost:<free port> -> instance:443``.
3.  **Mint short-lived STS session credentials** via
    ``sts:GetSessionToken`` (default 15-minute TTL) so the laptop's
    long-lived ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` never
    leave the laptop.  Only the ephemeral session token is forwarded
    over the SSM tunnel.  Build the payload the in-enclave
    ``app_vsock`` template's KMS branch expects::

        {"ciphertext_b64": "<wrapped DEK or DEK-prepended JSON>",
         "__aws_credentials": {"access_key": "<STS_AK>",
                                "secret_key": "<STS_SK>",
                                "token":      "<STS_SESSION_TOKEN>",
                                "region":     "us-east-2",
                                "expiration": "<ISO-8601 UTC>"}}

4.  POST it to ``https://localhost:<port>/enclave`` (the host_proxy on
    the instance forwards over vsock to the enclave).
5.  Expect the enclave to call ``kms:Decrypt`` with the attached Nitro
    attestation document attached in ``Recipient``, unwrap the
    ``CiphertextForRecipient`` CMS envelope, hand the plaintext to
    ``process_request``, and ship its return value back over the proxy.
6.  Verify the response is **not** an enclave error.  When the
    plaintext DEK happens to be a JSON object (because the operator
    wrapped a JSON payload via ``wrap_dek.py``), pretty-print the
    decoded result.

Threat model
------------

The smoke script intentionally **does not** forward the developer's
long-lived IAM-user keys.  Three reasons:

* The keys live on the laptop indefinitely; if they ever leak, the
  blast radius is everything the user can do, not just this test.
* The host instance, the host_proxy, and the SSM tunnel are all in the
  trust path for the JSON body.  Limiting that body to a 15-minute
  session token caps the worst-case exposure window.
* The customer KMS key policy is the *real* gate; even with the STS
  token an attacker still cannot release the wrapped DEK without a
  matching Nitro attestation document (PCRs, image SHA, ...).

Set ``--cred-duration 3600`` to extend the token TTL (max 36h for
IAM-user creds, 12h for assumed-role base) or ``--use-ambient-creds``
to fall back to the historical "ship whatever boto3 finds" behaviour
(useful when running from an EC2 instance with an instance-role; the
ambient creds are already short-lived in that case).

Usage
-----

    python3 byok-sandbox/aws/smoke_byok_aws.py \
      --config byok-sandbox/configs/byok-aws.json \
      --instance-id i-0123456789abcdef0 \
      --region us-east-2 \
      --json-payload '{"task":"ping"}'
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from typing import Optional


# ---------------------------------------------------------------------------
# SSM port-forward (vendored from src/tee_crafter/core/remote/ssm.py so the
# sandbox script does not require importing the package).  See that file for
# the production implementation.
# ---------------------------------------------------------------------------

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SsmPortForward:
    def __init__(self, instance_id: str, remote_port: int, region: str):
        self.instance_id = instance_id
        self.remote_port = remote_port
        self.region = region
        self.local_port = 0
        self._proc: Optional[subprocess.Popen] = None

    def start(self, timeout: int = 60) -> int:
        self.local_port = _find_free_port()
        params = json.dumps({
            "portNumber": [str(self.remote_port)],
            "localPortNumber": [str(self.local_port)],
        })
        cmd = [
            "aws", "ssm", "start-session", "--target", self.instance_id,
            "--document-name", "AWS-StartPortForwardingSession",
            "--parameters", params, "--region", self.region,
        ]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.local_port),
                                                timeout=1):
                    return self.local_port
            except OSError:
                if self._proc.poll() is not None:
                    _, err = self._proc.communicate()
                    raise RuntimeError(
                        f"SSM port-forward exited early "
                        f"(rc={self._proc.returncode}): "
                        f"{err.decode(errors='replace')[:500]}")
                time.sleep(0.5)
        raise TimeoutError(
            f"SSM port-forward did not become reachable on "
            f"127.0.0.1:{self.local_port} within {timeout}s")

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()


# ---------------------------------------------------------------------------

def _short_lived_session_credentials(
    region: str,
    *,
    duration_seconds: int,
    mfa_serial: Optional[str] = None,
    mfa_token: Optional[str] = None,
) -> dict:
    """Mint short-lived STS session credentials so we never forward the
    laptop's long-lived ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY``
    over the SSM tunnel.

    Tries, in order:

    1. **Already-temporary creds** (the boto3 session resolves a
       ``token`` field — true for instance-role / assume-role / SSO).
       Those are already short-lived; re-pack them verbatim.

    2. **`sts:GetSessionToken`** for plain IAM-user creds.  The
       resulting `(AK, SK, token)` triplet expires in
       ``duration_seconds`` (900-129600s for IAM users).  MFA is
       supported via ``--mfa-serial`` / ``--mfa-token``.

    The plaintext IAM-user secret key is never sent over the wire.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise SystemExit("ERROR: boto3 is required for the smoke test.")
    session = boto3.Session(region_name=region)
    ambient = session.get_credentials()
    if ambient is None:
        raise SystemExit(
            "No AWS credentials in the local environment.  Configure with "
            "`aws configure` or AWS_PROFILE before running the smoke test.")
    frozen = ambient.get_frozen_credentials()
    if frozen.token:
        return {
            "access_key": frozen.access_key,
            "secret_key": frozen.secret_key,
            "token": frozen.token,
            "region": region,
            "expiration": "ambient-short-lived",
            "_minted_by": "ambient",
        }
    sts = session.client("sts")
    kwargs = {"DurationSeconds": int(duration_seconds)}
    if mfa_serial:
        kwargs["SerialNumber"] = mfa_serial
        if not mfa_token:
            raise SystemExit("--mfa-serial requires --mfa-token <6-digit code>.")
        kwargs["TokenCode"] = mfa_token
    try:
        resp = sts.get_session_token(**kwargs)
    except ClientError as exc:
        raise SystemExit(
            f"sts:GetSessionToken failed: "
            f"{exc.response.get('Error', {}).get('Code', '')} — "
            f"{exc.response.get('Error', {}).get('Message', exc)}"
        )
    c = resp["Credentials"]
    return {
        "access_key": c["AccessKeyId"],
        "secret_key": c["SecretAccessKey"],
        "token": c["SessionToken"],
        "region": region,
        "expiration": c["Expiration"].isoformat(),
        "_minted_by": "sts:GetSessionToken",
    }


def _ambient_credentials_for_payload(region: str) -> dict:
    """Legacy fallback: forward the raw ambient credentials.

    Only safe when those creds are *already* short-lived (EC2
    instance role, SSO, assume-role).  Enabled by ``--use-ambient-creds``.
    """
    try:
        import boto3
    except ImportError:
        raise SystemExit("ERROR: boto3 is required for the smoke test.")
    session = boto3.Session(region_name=region)
    creds = session.get_credentials()
    if creds is None:
        raise SystemExit(
            "No AWS credentials in the local environment.  Configure with "
            "`aws configure` or AWS_PROFILE before running the smoke test.")
    frozen = creds.get_frozen_credentials()
    return {
        "access_key": frozen.access_key,
        "secret_key": frozen.secret_key,
        "token": frozen.token or "",
        "region": region,
        "expiration": "ambient",
        "_minted_by": "ambient",
    }


def _build_wrapped_payload(plaintext_obj: dict, key_id: str, region: str,
                            encryption_context: dict) -> str:
    """Encrypt a JSON object with the BYOK KMS key and return base64
    ciphertext suitable for the enclave's ``ciphertext_b64`` branch."""
    import boto3
    kms = boto3.client("kms", region_name=region)
    pt = json.dumps(plaintext_obj).encode("utf-8")
    resp = kms.encrypt(
        KeyId=key_id, Plaintext=pt,
        EncryptionContext=encryption_context or {},
    )
    return base64.b64encode(resp["CiphertextBlob"]).decode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--config", required=True,
        help="byok-config.json (produced by create_kms_key.py + wrap_dek.py)",
    )
    ap.add_argument("--instance-id", required=True,
                    help="EC2 instance id of the deployed Nitro host.")
    ap.add_argument("--region", default="",
                    help="AWS region (default: from --config).")
    ap.add_argument(
        "--json-payload", default="",
        help="Inline JSON payload to wrap fresh with kms:Encrypt and send to "
             "the enclave.  When omitted, the smoke driver uses the "
             "existing extra.ciphertext_b64 from the config (which must "
             "already wrap a valid JSON object that the user's "
             "process_request can ingest).",
    )
    ap.add_argument("--payload-file", default="",
                    help="JSON file to wrap fresh; alternative to --json-payload.")
    ap.add_argument("--remote-port", type=int, default=443,
                    help="Host-side port of host_proxy.service.")
    ap.add_argument("--timeout", type=float, default=180.0,
                    help="HTTP timeout for the wrapped request, seconds.")
    ap.add_argument("--no-tunnel", action="store_true",
                    help="Skip SSM tunnel and POST directly to "
                         "https://<instance>:443/enclave (requires reachable IP).")
    ap.add_argument("--direct-host", default="",
                    help="With --no-tunnel, the host[:port] to POST to.")

    # Credential-handling controls.  The default mints short-lived STS
    # session creds so the laptop's long-lived IAM-user key never enters
    # the SSM tunnel.  See "Threat model" in the module docstring.
    ap.add_argument(
        "--cred-duration", type=int, default=900,
        help="STS session-credential TTL in seconds (900..129600 for "
             "IAM-user base; default 900 = 15 minutes).",
    )
    ap.add_argument(
        "--mfa-serial", default="",
        help="If your IAM user requires MFA for sts:GetSessionToken, the "
             "ARN/serial of the MFA device.",
    )
    ap.add_argument(
        "--mfa-token", default="",
        help="6-digit MFA code; required when --mfa-serial is set.",
    )
    ap.add_argument(
        "--use-ambient-creds", action="store_true",
        help="Forward whatever boto3 finds (env / profile / instance role) "
             "WITHOUT minting a fresh STS token.  Only safe when those "
             "creds are already short-lived (SSO / assume-role / EC2 "
             "instance role).  NOT recommended from a developer laptop "
             "holding long-lived IAM-user keys.",
    )
    ap.add_argument(
        "--skip-creds", action="store_true",
        help="Do not attach __aws_credentials to the payload.  Use this "
             "to exercise paths that do not need KMS (e.g. ECIES or "
             "attestation-only) and to prove the enclave handles "
             "creds-free requests correctly.",
    )
    args = ap.parse_args()

    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        raise SystemExit("ERROR: requests is required (pip install requests).")

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    region = args.region or cfg.get("region") or os.environ.get("AWS_REGION", "us-east-2")
    key_id = cfg.get("key_id") or ""
    enc_ctx = dict(cfg.get("encryption_context") or {})
    extra = dict(cfg.get("extra") or {})
    existing_ct = extra.get("ciphertext_b64") or ""

    payload_json: Optional[dict] = None
    if args.payload_file:
        with open(args.payload_file, "r", encoding="utf-8") as f:
            payload_json = json.load(f)
    elif args.json_payload:
        payload_json = json.loads(args.json_payload)

    if payload_json is not None:
        if not key_id:
            raise SystemExit(f"{args.config}: key_id missing, cannot wrap a "
                             "fresh JSON payload")
        print(f"[byok] wrapping fresh JSON payload via {key_id}",
              file=sys.stderr)
        ciphertext_b64 = _build_wrapped_payload(
            payload_json, key_id, region, enc_ctx)
    else:
        if not existing_ct:
            raise SystemExit(
                f"{args.config}: extra.ciphertext_b64 is empty and no "
                "--json-payload/--payload-file given; nothing to send")
        print(f"[byok] re-using extra.ciphertext_b64 from {args.config}",
              file=sys.stderr)
        ciphertext_b64 = existing_ct

    body: dict = {"ciphertext_b64": ciphertext_b64}
    if args.skip_creds:
        print("[byok] --skip-creds: not attaching __aws_credentials "
              "(the enclave will rely on the host-proxy instance role).",
              file=sys.stderr)
    elif args.use_ambient_creds:
        body["__aws_credentials"] = _ambient_credentials_for_payload(region)
        print("[byok] --use-ambient-creds: forwarding ambient creds verbatim "
              "(assumed short-lived).", file=sys.stderr)
    else:
        creds = _short_lived_session_credentials(
            region,
            duration_seconds=args.cred_duration,
            mfa_serial=args.mfa_serial or None,
            mfa_token=args.mfa_token or None,
        )
        body["__aws_credentials"] = creds
        # Don't print the actual token; just the metadata.
        print(f"[byok] minted short-lived session creds via "
              f"{creds['_minted_by']} (expires={creds['expiration']}, "
              f"AK=...{creds['access_key'][-4:]})", file=sys.stderr)
    print(f"[byok] payload built: ct_len={len(ciphertext_b64)} "
          f"region={region}", file=sys.stderr)

    if args.no_tunnel:
        host = args.direct_host or args.instance_id
        url = f"https://{host}/enclave"
        tunnel = None
    else:
        tunnel = SsmPortForward(args.instance_id, args.remote_port, region)
        local = tunnel.start()
        url = f"https://localhost:{local}/enclave"
        print(f"[byok] SSM tunnel up: localhost:{local} -> "
              f"{args.instance_id}:{args.remote_port}", file=sys.stderr)

    try:
        print(f"[byok] POST {url}", file=sys.stderr)
        t0 = time.time()
        resp = requests.post(url, json=body, timeout=args.timeout, verify=False)
        dt = time.time() - t0
        print(f"[byok] HTTP {resp.status_code} in {dt:.2f}s, "
              f"response={len(resp.content)} bytes", file=sys.stderr)
        try:
            body_out = resp.json()
        except Exception:
            body_out = {"raw_text": resp.text[:4000]}
        ok = (resp.status_code == 200 and isinstance(body_out, dict)
              and "error" not in body_out)
        if extra.get("dek_sha256"):
            try:
                if isinstance(body_out, dict) and body_out.get("dek_echo_b64"):
                    raw = base64.b64decode(body_out["dek_echo_b64"])
                    if hashlib.sha256(raw).hexdigest() != extra["dek_sha256"]:
                        ok = False
                        body_out["_smoke_error"] = "dek_echo mismatch"
            except Exception:
                pass
        print(json.dumps({
            "ok": ok, "elapsed_seconds": round(dt, 3),
            "http_status": resp.status_code,
            "endpoint": url, "key_id": key_id, "region": region,
            "encryption_context": enc_ctx,
            "response": body_out,
        }, indent=2, default=str))
        return 0 if ok else 1
    finally:
        if tunnel is not None:
            tunnel.stop()


if __name__ == "__main__":
    sys.exit(main())
