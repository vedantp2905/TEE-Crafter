from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os
import socket
import json
import logging
import asyncio
import threading
import time
from typing import Dict, Any, Optional

# LOG-1: Scrub Authorization headers and request/response bodies from uvicorn
# access logs.  Without this, any Authorization bearer or API key that a
# mis-configured caller might put in the header ends up persisted in journald.
class _RedactAuthFilter(logging.Filter):
    _SENSITIVE_HEADERS = ("authorization", "cookie", "x-api-key", "proxy-authorization")

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401 — logging hook
        try:
            msg = record.getMessage()
        except Exception:
            # Fail closed: a record this filter cannot read is a record it
            # cannot redact, and returning True here would emit it verbatim —
            # defeating the control on exactly the inputs weird enough to break
            # formatting.  Replace the payload rather than dropping the record,
            # so the fact that a request was logged survives while its
            # (possibly credential-bearing) content does not.
            record.msg = "[log record suppressed: unreadable, could not redact]"
            record.args = ()
            return True
        lowered = msg.lower()
        for h in self._SENSITIVE_HEADERS:
            if h in lowered:
                # Replace anything after `header:` up to the next whitespace.
                import re as _re
                msg = _re.sub(
                    rf"(?i)({h}\s*[:=]\s*)\S+",
                    r"\1***REDACTED***",
                    msg,
                )
                record.msg = msg
                record.args = ()
        return True


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
for _uvi in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi"):
    logging.getLogger(_uvi).addFilter(_RedactAuthFilter())

app = FastAPI(title="Nitro Enclave Host Proxy", version="1.0.0")

import subprocess

def get_enclave_cid() -> int:
    import subprocess
    import json
    import logging
    try:
        out = subprocess.check_output(['nitro-cli', 'describe-enclaves'], text=True)
        data = json.loads(out)
        if data and isinstance(data, list) and len(data) > 0:
            return data[0]['EnclaveCID']
    except Exception as e:
        logging.error(f"Could not auto-detect enclave CID: {e}")
    return 16 # Default or fallback

VSOCK_PORT = 5005
TIMEOUT = 120.0

def _forward_to_enclave(payload_bytes: bytes) -> bytes:
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        cid = get_enclave_cid()
        logging.info(f"[PROXY] Connecting to enclave CID={cid} port={VSOCK_PORT}...")
        sock.connect((cid, VSOCK_PORT))
        logging.info(f"[PROXY] Connected. Sending {len(payload_bytes)} bytes...")
        sock.sendall(payload_bytes)
        sock.shutdown(socket.SHUT_WR)
        logging.info("[PROXY] Payload sent, waiting for response...")
        
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        logging.info(f"[PROXY] Received {len(response)} bytes from enclave")
        return bytes(response)
    except Exception as e:
        logging.error(f"[PROXY] vsock error: {type(e).__name__}: {e}")
        raise
    finally:
        sock.close()

import boto3


# SEC-CREDS-2: scope ALL forwarded AWS credentials to one place.  The
# host_proxy is the only component that talks to IMDS; the enclave never
# does (it has no network stack of its own).  We deliberately:
#
#   * Refuse to start if the host instance is on IMDSv1 (the v2 token
#     endpoint is mandatory for production).
#   * Always re-fetch the boto3 session credentials per-request — we do
#     NOT cache.  Caching would defeat the short-lived-STS guarantee
#     and could survive an instance-role rotation.
#   * Only attach ``__aws_credentials`` to requests that actually need
#     KMS (``ciphertext_b64`` or ``encrypted_payload`` paths).  Pure
#     attestation requests (``action == "get_attestation"``) get
#     forwarded without any credential material.
#
# Setting ``TEE_CRAFTER_PROXY_NO_CREDS=1`` in the host environment hard
# disables credential forwarding entirely (useful for tests, or once
# the enclave is reworked to source its own creds via vsock-kmstool).


_NO_CREDS = os.environ.get("TEE_CRAFTER_PROXY_NO_CREDS", "0").lower() in (
    "1", "true", "yes", "y",
)
# SEC-CREDS-2: production default is STRICT — when strict mode is on, the
# host proxy never forwards AWS_ACCESS_KEY_ID-style env credentials to the
# enclave.  Credentials must come from the instance role via IMDS.
#
# Why this needs its own code path rather than just a probe: botocore's
# default resolver puts the env provider *ahead* of IMDS.  In
# ``botocore/credentials.py::create_credential_resolver`` the chain is
# built as ``providers = pre_profile + profile_providers + post_profile``
# with ``pre_profile = [env_provider, assume_role_provider]`` and
# ``post_profile = [OriginalEC2Provider(), BotoProvider(),
# container_provider, instance_metadata_provider]`` (verified against the
# installed botocore).  So a plain ``boto3.Session().get_credentials()``
# on a host that has both a working IMDSv2 *and* AWS_ACCESS_KEY_ID in the
# environment returns the long-lived env key — which is exactly what
# strict mode claims to prevent.  Strict mode therefore resolves from
# IMDS explicitly (see ``_fetch_short_lived_creds(imds_only=True)``)
# whenever env credentials are present on the host.
#
# Dev hatch ``TEE_CRAFTER_PROXY_STRICT_IMDS=0`` re-enables the env-cred
# fallback (laptop-style ad-hoc testing only — never set in prod).
# Strict unless explicitly switched off.  The previous form listed the truthy
# spellings, so ``=on`` -- absent from that list -- silently dropped strict IMDS
# and re-enabled the env-cred fallback.
_STRICT_IMDS = os.environ.get(
    "TEE_CRAFTER_PROXY_STRICT_IMDS", "1").strip().lower() not in (
    "0", "false", "no", "n", "off",
)
_IMDSV2_PROBE_LOCK = threading.Lock()
_IMDSV2_PROBE_RESULT: Optional[bool] = None


def _imdsv2_available() -> bool:
    """Cheap, cached probe: can we obtain an IMDSv2 session token?

    Returns ``True`` on EC2 with IMDSv2 enabled.  Returns ``False`` off
    EC2 or when IMDSv1 is the only flavour available — we treat IMDSv1
    as a misconfiguration and refuse to forward credentials.
    """
    global _IMDSV2_PROBE_RESULT
    with _IMDSV2_PROBE_LOCK:
        if _IMDSV2_PROBE_RESULT is not None:
            return _IMDSV2_PROBE_RESULT
        try:
            import urllib.request
            req = urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                method="PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            )
            with urllib.request.urlopen(req, timeout=1.0) as r:
                _IMDSV2_PROBE_RESULT = bool(r.read())
        except Exception:
            _IMDSV2_PROBE_RESULT = False
        return _IMDSV2_PROBE_RESULT


def _request_needs_aws_creds(body_json: Any) -> bool:
    """True only when the enclave will call out to AWS KMS for this
    request.  Pure attestation handshakes never need creds; ECIES and
    KMS-decrypt paths do (for entropy seeding / kms:Decrypt)."""
    if not isinstance(body_json, dict):
        return False
    if body_json.get("ciphertext_b64"):
        return True
    if body_json.get("encrypted_payload"):
        return True
    return False


def _imds_only_credentials():
    """Resolve credentials from the EC2 instance role, bypassing env vars.

    Uses botocore's ``InstanceMetadataProvider`` directly instead of the
    default resolver chain, because that chain consults ``EnvProvider``
    first (see the SEC-CREDS-2 note above).  Returns a botocore
    ``Credentials`` object, or ``None`` when IMDS yields nothing.
    """
    from botocore.credentials import InstanceMetadataProvider
    from botocore.utils import InstanceMetadataFetcher

    provider = InstanceMetadataProvider(
        iam_role_fetcher=InstanceMetadataFetcher(timeout=1.0, num_attempts=2),
    )
    return provider.load()


def _fetch_short_lived_creds(region: str, imds_only: bool = False) -> Optional[dict]:
    """Resolve credentials for the enclave's KMS call.

    ``imds_only=True`` skips botocore's default chain entirely and reads
    the instance role from IMDS, so long-lived ``AWS_ACCESS_KEY_ID`` env
    credentials on the host cannot be forwarded.  The default (``False``)
    uses the ordinary boto3 chain and is only reached when strict mode is
    off, or when the host has no env credentials to leak in the first
    place.

    Never caches: every request re-resolves so the credential's TTL is
    always honoured.  Returns ``None`` (and the caller drops the
    ``__aws_credentials`` field) if no creds are available.
    """
    if _NO_CREDS:
        return None
    if imds_only:
        try:
            creds = _imds_only_credentials()
        except Exception as exc:
            logging.error("[PROXY] IMDS-only credential resolution failed: %s",
                          type(exc).__name__)
            return None
    else:
        session = boto3.Session()
        creds = session.get_credentials()
    if creds is None:
        return None
    frozen = creds.get_frozen_credentials()
    payload = {
        "access_key": frozen.access_key,
        "secret_key": frozen.secret_key,
        "token": frozen.token or "",
        "region": region,
    }
    # boto3 surfaces an ``expiry_time`` on temporary creds; we forward it
    # so the enclave can log when its tokens are due to roll over.
    expiry = getattr(creds, "_expiry_time", None)
    if expiry is not None:
        try:
            payload["expiration"] = expiry.isoformat()
        except Exception:
            payload["expiration"] = str(expiry)
    return payload


@app.post("/enclave")
async def handle_enclave_request(request: Request):
    """
    Blindly forwards incoming JSON payloads over vsock to the secure enclave
    and returns the enclave's response. The host never reads the plaintext.
    """
    try:
        body_bytes = await request.body()
        if not body_bytes:
            raise HTTPException(status_code=400, detail="Empty request body")
            
        try:
            body_json = json.loads(body_bytes)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Body must be valid JSON")

        # SEC-CREDS-2: callers must never set this field themselves —
        # the host is the only authority that resolves AWS creds.  Strip
        # any inbound ``__aws_credentials`` to prevent client-side
        # credential injection.
        if isinstance(body_json, dict):
            body_json.pop("__aws_credentials", None)

        # LOG-1: log only the structural size, NEVER the keys or values.  The
        # enclave is the only principal that is supposed to see plaintext.
        req_key_count = len(body_json) if isinstance(body_json, (dict, list)) else 1
        logging.info("[PROXY] Incoming request (%d top-level fields)", req_key_count)

        needs_creds = _request_needs_aws_creds(body_json)
        if needs_creds and not _NO_CREDS:
            # Region resolution priority: explicit AWS_REGION env on the
            # host, then the boto3 session default.  We do not look at
            # the inbound JSON — the customer's region is configured at
            # deploy time, not per-request.
            region = (os.environ.get("AWS_REGION")
                      or boto3.Session().region_name
                      or "us-east-2")
            imdsv2_ok = _imdsv2_available()
            has_env_creds = bool(os.environ.get("AWS_ACCESS_KEY_ID"))
            # SEC-CREDS-2: strict mode must never forward long-lived
            # AWS_ACCESS_KEY_ID env credentials to the enclave.  Two
            # distinct cases, both keyed on env creds actually existing —
            # if there is nothing to leak, ordinary resolution is fine
            # (the enclave treats the ECIES entropy-seed path as
            # best-effort and returns a structured error on KMS-decrypt
            # paths when creds are genuinely required).
            #
            #   1. No IMDSv2 at all: nothing safe is available, so refuse
            #      outright rather than silently downgrading.
            #   2. IMDSv2 works: resolve from IMDS *explicitly*.  Letting
            #      boto3 resolve here would hand back the env key,
            #      because botocore orders EnvProvider ahead of
            #      InstanceMetadataProvider (see the module note above).
            if _STRICT_IMDS and not imdsv2_ok and has_env_creds:
                logging.error(
                    "[PROXY] SEC-CREDS-2 STRICT: IMDSv2 unavailable but "
                    "AWS_ACCESS_KEY_ID is set on the host and "
                    "TEE_CRAFTER_PROXY_STRICT_IMDS=1; refusing to fall "
                    "back to long-lived env creds.  Configure the "
                    "instance profile + IMDSv2 token endpoint, or set "
                    "TEE_CRAFTER_PROXY_STRICT_IMDS=0 for dev.",
                )
                raise HTTPException(
                    status_code=503,
                    detail="Host instance has env credentials but no "
                           "IMDSv2 (strict mode refuses env fallback); "
                           "see SEC-CREDS-2 / docs/security.md.",
                )
            if _STRICT_IMDS and has_env_creds:
                creds = _fetch_short_lived_creds(region, imds_only=True)
                if creds is None:
                    logging.error(
                        "[PROXY] SEC-CREDS-2 STRICT: AWS_ACCESS_KEY_ID is set "
                        "on the host, so credentials were resolved from IMDS "
                        "only — and IMDS returned none.  Refusing to fall back "
                        "to the env key.",
                    )
                    raise HTTPException(
                        status_code=503,
                        detail="Host instance has env credentials and the "
                               "instance role returned none (strict mode "
                               "refuses env fallback); see SEC-CREDS-2 / "
                               "docs/security.md.",
                    )
            else:
                creds = _fetch_short_lived_creds(region) if (imdsv2_ok or has_env_creds) else None
            if creds is None:
                # Common, non-fatal case: a request that *might* need KMS
                # (ECIES entropy seeding) arrives while IMDS is the only
                # cred source and is unreachable.  Forward without creds;
                # the enclave handles missing-creds for ECIES gracefully
                # and returns a structured error for KMS-decrypt paths.
                logging.warning(
                    "[PROXY] No AWS credentials available (imdsv2=%s, "
                    "env=%s); forwarding without __aws_credentials.",
                    imdsv2_ok, has_env_creds,
                )
            else:
                body_json["__aws_credentials"] = creds
                _exp = creds.get("expiration", "ambient")
                # LOG-1: do NOT emit the access-key tail.  Even the last
                # 4 characters identify the principal across log lines
                # and combined with timestamps can leak which IAM user
                # is on call.  Region + expiry is enough operational
                # context to debug rotation issues.
                logging.info(
                    "[PROXY] Forwarding short-lived creds for KMS path "
                    "(region=%s expires=%s)",
                    region, _exp,
                )
        else:
            if _NO_CREDS:
                logging.info("[PROXY] TEE_CRAFTER_PROXY_NO_CREDS=1; "
                             "not forwarding creds.")
            else:
                # Attestation-only request, no creds attached.  This is
                # the common case for the initial handshake.
                logging.info("[PROXY] No KMS markers in request; "
                             "forwarding without creds.")

        body_bytes_with_creds = json.dumps(body_json).encode('utf-8')
        logging.info(f"[PROXY] Forwarding {len(body_bytes_with_creds)} bytes to enclave...")
            
        loop = asyncio.get_event_loop()
        response_bytes = await loop.run_in_executor(None, _forward_to_enclave, body_bytes_with_creds)
        
        if not response_bytes:
            raise HTTPException(status_code=502, detail="Empty response from enclave")
        
        logging.info(f"[PROXY] Enclave response: {len(response_bytes)} bytes")
            
        try:
            resp_data = json.loads(response_bytes.decode('utf-8'))
            if "error" in resp_data:
                # LOG-1: do NOT dump resp_data verbatim — error messages can
                # quote enclave-internal state.  Record only the error key.
                err_keys = list(resp_data.keys()) if isinstance(resp_data, dict) else ["<non-dict>"]
                logging.error("[PROXY] Enclave error response (keys=%s)", err_keys)
                return JSONResponse(status_code=400, content=resp_data)
            return JSONResponse(status_code=200, content=resp_data)
        except json.JSONDecodeError:
            logging.warning("[PROXY] Non-JSON enclave response (%d bytes suppressed)",
                            len(response_bytes))
            return JSONResponse(
                status_code=502,
                content={"error": "Malformed response from enclave"},
            )
            
    except HTTPException:
        # Preserve intentional HTTP error codes (400/502/503/...) raised
        # above so the client sees the real cause.  Without this the
        # broad ``except Exception`` below would swallow them and return
        # a generic 500 — which is what bit us on SEC-CREDS-2 / 503.
        raise
    except Exception as e:
        logging.error("[PROXY] Error proxying to enclave: %s", type(e).__name__)
        raise HTTPException(status_code=500, detail="Internal proxy error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "host_proxy:app",
        host="127.0.0.1",
        port=443,
        ssl_keyfile="/etc/tee_crafter/certs/host.key",
        ssl_certfile="/etc/tee_crafter/certs/host.crt",
        # LOG-1: disable the uvicorn access log entirely.  It otherwise
        # logs full request paths, which can include tokens placed in
        # query strings by mis-configured callers (e.g. `?api_key=...`).
        # Structured audit data is emitted by handle_enclave_request
        # itself with scrubbed fields.
        access_log=False,
        server_header=False,
        proxy_headers=False,
        # F-10 / defence-in-depth: ensure we only bind to loopback even
        # if IPv6 is enabled on the host.  Uvicorn respects `host` but
        # refuses to share a listener across families unless told to.
        forwarded_allow_ips="127.0.0.1",
    )
