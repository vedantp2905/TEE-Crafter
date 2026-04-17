"""NVIDIA Confidential Computing attestation integration.

Shared module deployed into GPU CC builds (copied alongside the attestation
monitor).  Provides GPU CC mode initialization, NVIDIA Remote Attestation
Service (NRAS) integration, and combined CPU+GPU attestation helpers.

At runtime this module is available inside the confidential VM.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger("tee_crafter.gpu_attestation")

NRAS_URL = "https://nras.attestation.nvidia.com/v4/attest/gpu"

_HOPPER_MIN_DRIVER = "535"
_BLACKWELL_MIN_DRIVER = "590"

# Driver versions with known vulnerabilities that affect the CC trust chain
# (GPU firmware RIM, attestation signing, or memory encryption bypass).  Populate
# from NVIDIA PSIRT advisories; entries match on the exact `major.minor.patch`
# prefix reported by `nvidia-smi`.
#
# References:
#   - https://nvidia.custhelp.com/app/answers/detail/a_id/5531 (Oct 2024 CC)
#   - https://nvidia.custhelp.com/app/answers/detail/a_id/5614 (Feb 2025 CC)
#   - https://nvidia.custhelp.com/app/answers/detail/a_id/5630 (Apr 2025 CC)
_CVE_BLOCKED_DRIVERS: Tuple[str, ...] = (
    # Hopper H100/H200 CC pre-release builds with signing key issues.
    "535.54",
    "535.86",
    "535.104",
    # Pre-GA Hopper CC builds affected by NVIDIA-SA-2024-0014 / 0015.
    "535.129.03",
    # Blackwell early driver with firmware RIM bypass (rolled back by NVIDIA).
    "560.28",
    "565.57",
)

# Strict regex to parse `nvidia-smi conf-compute -f` output.  NVIDIA's CLI has
# shipped several phrasings; we anchor on the terminal state keyword rather
# than substring-matching "ON" (which would false-positive on lines such as
# "CC Mode: OFF (was ON)").  The three legal terminal states are:
#   ON        — production CC mode, memory encrypted
#   OFF       — CC disabled, no protection
#   DEVTOOLS  — CC enabled but memory encryption off (debug only)
_CC_MODE_RE = re.compile(
    r"(?:CC|Confidential\s+Compute).*?"
    r"(?:Feature|Mode|State|Status)\s*[:=]\s*"
    r"(ON|OFF|DEVTOOLS)\b",
    re.IGNORECASE,
)


def _parse_cc_feature_status(output: str) -> str:
    """Return one of ``"on" | "off" | "devtools" | "unknown"`` from CLI output.

    Refuses to guess.  Unknown output is treated as a hard fail by callers.
    """
    if not output:
        return "unknown"
    match = _CC_MODE_RE.search(output)
    if match is None:
        # Last-ditch fallback for unknown phrasings: walk each line, split on
        # `:` or `=`, and if the right-hand side is exactly ON/OFF/DEVTOOLS we
        # accept it.  Also accept a bare token on its own line.  This keeps us
        # forward-compatible with nvidia-smi output drift (observed on driver
        # 550.x: `CC status: ON` — no Feature/Mode/State keyword).
        for line in reversed(output.strip().splitlines()):
            stripped = line.strip()
            upper = stripped.upper()
            if upper in ("ON", "OFF", "DEVTOOLS"):
                return upper.lower()
            for sep in (":", "="):
                if sep in stripped:
                    rhs = stripped.rsplit(sep, 1)[-1].strip().upper()
                    if rhs in ("ON", "OFF", "DEVTOOLS"):
                        return rhs.lower()
                    break
        return "unknown"
    return match.group(1).lower()


def _driver_is_blocked(driver_version: str) -> Tuple[bool, str]:
    """Return ``(blocked, reason)`` if *driver_version* matches a CVE entry."""
    dv = (driver_version or "").strip()
    if not dv:
        return True, "driver version not reported"
    for bad in _CVE_BLOCKED_DRIVERS:
        if dv == bad or dv.startswith(bad + "."):
            return True, f"driver {dv} matches CVE block-list entry {bad}"
    return False, ""


def initialize_gpu_cc_mode(mode: Optional[str] = None) -> Dict[str, Any]:
    """Verify CC is active and set GPUs Ready State.

    On Azure NCC H100 v5 (and similar), CC mode is enabled at the hypervisor
    level.  This function:
      1. Queries GPU info via ``nvidia-smi``.
      2. Checks CC feature status (``conf-compute -f``).
      3. Sets GPUs Ready State (``conf-compute -srs 1``).

    Returns a summary dict with gpu_count, driver_version, cc_status etc.
    """
    if mode is None:
        mode = os.environ.get("TEE_CRAFTER_GPU_CC_MODE", "PROTECT")
    result: Dict[str, Any] = {"cc_mode": mode, "success": False}

    try:
        # Per-GPU UUIDs give us a precise, strict count.
        uuid_smi = subprocess.run(
            ["nvidia-smi", "--query-gpu=gpu_name,driver_version,uuid",
             "--format=csv,noheader"],
            capture_output=True, text=True, timeout=30,
        )
        if uuid_smi.returncode != 0:
            result["error"] = uuid_smi.stderr.strip()
            return result

        lines = [l.strip() for l in uuid_smi.stdout.strip().splitlines() if l.strip()]
        if not lines:
            result["error"] = "No GPUs detected"
            return result

        uuids: List[str] = []
        for line in lines:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 3 and parts[2].startswith("GPU-"):
                uuids.append(parts[2])
        if not uuids:
            result["error"] = "nvidia-smi did not report per-GPU UUIDs"
            return result

        first_parts = [p.strip() for p in lines[0].split(",")]
        result["gpu_name"] = first_parts[0] if len(first_parts) > 0 else "unknown"
        result["driver_version"] = first_parts[1] if len(first_parts) > 1 else "unknown"
        result["gpu_uuids"] = uuids
        result["gpu_count"] = len(uuids)
    except FileNotFoundError:
        result["error"] = "nvidia-smi not found"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result

    # Reject driver versions on the CVE block-list before trusting CC status.
    blocked, reason = _driver_is_blocked(result["driver_version"])
    if blocked:
        result["error"] = f"CVE-blocked NVIDIA driver: {reason}"
        return result

    try:
        cc_feat = subprocess.run(
            ["nvidia-smi", "conf-compute", "-f"],
            capture_output=True, text=True, timeout=30,
        )
        cc_status = cc_feat.stdout.strip() if cc_feat.returncode == 0 else ""
        result["cc_feature_status"] = cc_status
        parsed = _parse_cc_feature_status(cc_status)
        result["cc_feature_parsed"] = parsed
        if parsed != "on":
            result["error"] = (
                f"CC feature not ON (parsed={parsed!r}, raw={cc_status!r})"
            )
            return result
    except Exception as exc:
        result["error"] = f"conf-compute -f exception: {exc}"
        return result

    try:
        grs = subprocess.run(
            ["nvidia-smi", "conf-compute", "-grs"],
            capture_output=True, text=True, timeout=15,
        )
        ready_out = grs.stdout.strip() if grs.returncode == 0 else ""
        if "ready" in ready_out.lower() and "not-ready" not in ready_out.lower():
            result["gpu_ready_state"] = ready_out
            result["success"] = True
            return result

        srs = subprocess.run(
            ["nvidia-smi", "conf-compute", "-srs", "1"],
            capture_output=True, text=True, timeout=60,
        )
        if srs.returncode != 0:
            err_detail = srs.stderr.strip() or srs.stdout.strip()
            if "Insufficient Permissions" in err_detail or "Insufficient Permissions" in (srs.stderr + srs.stdout):
                _logger.warning("conf-compute -srs needs root; add ExecStartPre to systemd unit")
            result["error"] = f"conf-compute -srs failed: {err_detail}"
            return result

        grs2 = subprocess.run(
            ["nvidia-smi", "conf-compute", "-grs"],
            capture_output=True, text=True, timeout=15,
        )
        result["gpu_ready_state"] = grs2.stdout.strip() if grs2.returncode == 0 else "unknown"
        result["success"] = True
    except Exception as exc:
        result["error"] = f"conf-compute -srs exception: {exc}"

    return result


def compute_nras_nonce(
    binding: Optional[bytes] = None,
    salt: Optional[bytes] = None,
) -> Tuple[str, bytes, bytes]:
    """Derive an NRAS nonce bound to local key material.

    F-7: the NRAS EAT nonce must prove that the attestation belongs to the
    TLS key the server will present, otherwise an attacker that relays a
    valid attestation from a different host can pair it with their own
    TLS identity.  We compute ``SHA256(binding || salt)`` where *binding*
    is the uncompressed ECDH public key bytes (caller supplies) and *salt*
    is 32 random bytes generated here if not supplied.

    Returns ``(nonce_hex, binding, salt)``.  When *binding* is ``None`` we
    fall back to a pure random nonce (and return empty binding) — callers
    that need the binding guarantee must supply one.
    """
    import hashlib

    if salt is None:
        salt = os.urandom(32)

    if binding is None:
        # No ECDH key bound: random nonce, flagged via empty binding.
        return os.urandom(32).hex(), b"", salt

    digest = hashlib.sha256(binding + salt).digest()
    return digest.hex(), binding, salt


def get_gpu_attestation(
    api_key: str = "",
    mode: str = "remote",
    nras_url: str = NRAS_URL,
    tls_binding: Optional[bytes] = None,
    nonce_salt: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Collect GPU evidence and submit to NVIDIA NRAS for attestation.

    Returns a dict with ``token`` (signed EAT JWT), ``verified``,
    ``gpu_evidence_hash``, and the nonce binding material so callers can
    include them in the RA-TLS certificate extensions.

    F-7 binding: pass *tls_binding* = uncompressed ECDH public key bytes
    and (optionally) a fixed *nonce_salt*.  The nonce submitted to NRAS
    will equal ``SHA256(tls_binding || nonce_salt)``; a client that also
    knows the ECDH pubkey can recompute and compare against the
    NRAS-signed ``eat_nonce`` claim to detect evidence-relay attacks.

    Falls back to local verification when *mode* is ``"local"``.

    Compatible with ``nv-attestation-sdk`` v2.7+.  :data:`NRAS_URL` pins **v4**
    while the SDK's own default is v3 (``NV_NRAS_GPU_URL`` in
    ``nv_attestation_sdk/utils/config.py``), so the endpoint is passed
    explicitly rather than inherited.  v4 is publicly accessible and needs no
    service key; the ``NVIDIA_ATTESTATION_SERVICE_KEY`` the SDK reads stays
    unset.  Verified against SDK 2.7.0 and confirmed on real Azure NCC H100 v5
    hardware (``nras_token_valid: true``).

    *mode* ``"local"`` runs the SDK's local verifier instead, which does **not**
    remove the network dependency: ``verifier/cc_admin.py`` fetches driver and
    VBIOS RIMs from ``rim.attestation.nvidia.com`` unless local RIM paths are
    supplied, and calls ``ocsp_certificate_chain_validation`` unconditionally
    against ``ocsp.ndis.nvidia.com`` with no flag to skip it.  Local mode
    therefore widens the egress allowlist from one host to two.
    """
    result: Dict[str, Any] = {"mode": mode, "verified": False}

    nonce_hex, binding_used, salt_used = compute_nras_nonce(tls_binding, nonce_salt)
    result["nras_nonce"] = nonce_hex
    result["nras_nonce_salt_hex"] = salt_used.hex()
    result["nras_nonce_binding_sha256"] = (
        __import__("hashlib").sha256(binding_used).hexdigest() if binding_used else ""
    )

    try:
        from nv_attestation_sdk import attestation  # type: ignore[import-untyped]

        att = attestation.Attestation()
        att.set_name("tee-crafter-gpu-cc")
        att.set_nonce(nonce_hex)

        if mode == "remote":
            att.add_verifier(
                attestation.Devices.GPU,
                attestation.Environment.REMOTE,
                nras_url,
                "",
            )
        else:
            att.add_verifier(
                attestation.Devices.GPU,
                attestation.Environment.LOCAL,
                "",
                "",
            )

        evidence_list = att.get_evidence()
        if not evidence_list:
            result["error"] = "No GPU evidence collected"
            return result

        att_result = att.attest(evidence_list)
        raw_token = att.get_token()
        if isinstance(raw_token, (list, dict)):
            result["token"] = json.dumps(raw_token)
        else:
            result["token"] = str(raw_token)
        result["verified"] = bool(att_result)

        import hashlib
        evidence_bytes = json.dumps(evidence_list, sort_keys=True, default=str).encode()
        result["gpu_evidence_hash"] = hashlib.sha256(evidence_bytes).hexdigest()

    except ImportError:
        result["error"] = (
            "nv-attestation-sdk not installed. "
            "Install with: pip install 'nv-attestation-sdk>=2.7.0'"
        )
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _extract_nras_jwt(token: str) -> tuple:
    """Extract the real NRAS overall JWT from a Detached EAT Bundle.

    The Python SDK ``get_token()`` returns a nested list (RFC 9711):
        [
            ["JWT", "<sdk-wrapper>"],
            {"REMOTE_GPU_CLAIMS": [["JWT", "<nras-jwt>"], {"GPU-0": "...", ...}]}
        ]

    Returns (nras_overall_jwt_str, per_gpu_jwt_dict).
    """
    try:
        bundle = json.loads(token)
    except (ValueError, TypeError):
        return token, {}

    if isinstance(bundle, list) and len(bundle) >= 2:
        section = bundle[1] if isinstance(bundle[1], dict) else {}
        for key in ("REMOTE_GPU_CLAIMS", "LOCAL_GPU_CLAIMS"):
            nested = section.get(key)
            if isinstance(nested, list) and len(nested) >= 2:
                overall = (nested[0][1]
                           if isinstance(nested[0], list) and len(nested[0]) >= 2
                           else None)
                gpu_map = {}
                detached = nested[1] if isinstance(nested[1], dict) else {}
                for k, v in detached.items():
                    if isinstance(v, str):
                        gpu_map[k] = v
                    elif isinstance(v, list) and len(v) >= 2 and isinstance(v[1], str):
                        gpu_map[k] = v[1]
                if overall:
                    return overall, gpu_map

        first = bundle[0]
        if isinstance(first, list) and len(first) >= 2:
            return first[1], {}

    if isinstance(bundle, dict):
        eat = bundle.get("detached_eat")
        if isinstance(eat, list):
            return _extract_nras_jwt(json.dumps(eat))

    return token, {}


def get_gpu_health() -> Dict[str, Any]:
    """Quick health check: CC mode status, driver version, GPU count.

    Returns a dict whose ``cc_mode`` is strictly one of
    ``"on" | "off" | "devtools" | "unknown"`` (lowercase) so callers don't
    need to re-parse.  The raw CLI output is preserved in ``cc_mode_raw``.
    """
    try:
        smi = subprocess.run(
            ["nvidia-smi", "--query-gpu=gpu_name,driver_version,memory.total,uuid",
             "--format=csv,noheader"],
            capture_output=True, text=True, timeout=15,
        )
        if smi.returncode != 0:
            return {"healthy": False, "error": smi.stderr.strip()}

        lines = [l.strip() for l in smi.stdout.strip().splitlines() if l.strip()]
        uuids = [
            parts[3].strip()
            for line in lines
            for parts in [[p.strip() for p in line.split(",")]]
            if len(parts) >= 4 and parts[3].startswith("GPU-")
        ]
        driver_version = ""
        if lines:
            first = [p.strip() for p in lines[0].split(",")]
            if len(first) >= 2:
                driver_version = first[1]

        cc_status = subprocess.run(
            ["nvidia-smi", "conf-compute", "-f"],
            capture_output=True, text=True, timeout=15,
        )
        cc_raw = cc_status.stdout.strip() if cc_status.returncode == 0 else ""
        cc_mode = _parse_cc_feature_status(cc_raw)

        blocked, reason = _driver_is_blocked(driver_version)
        healthy = bool(lines) and bool(uuids) and not blocked

        return {
            "healthy": healthy,
            "gpu_count": len(uuids),
            "cc_mode": cc_mode,
            "cc_mode_raw": cc_raw,
            "driver_version": driver_version,
            "driver_blocked": blocked,
            "driver_block_reason": reason,
            "gpus": lines,
        }
    except Exception as exc:
        return {"healthy": False, "error": str(exc)}


