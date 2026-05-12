"""Attestation-bound key rotation manager for TEE workloads.

Manages cryptographic key lifecycle inside the TEE: tracks key generation,
enforces time-based and event-triggered rotation, binds rotations to hardware
attestation, and maintains a hash-chained, tamper-evident rotation log.

Every rotation event records:
  - old/new key fingerprints (SHA-256 of public key bytes)
  - rotation reason (time_based | event_triggered | attestation_drift | startup)
  - optional attestation measurement at time of rotation
  - requests served on the retiring key
  - rotation latency

Known limitation — tamper evidence and where this log lives
-----------------------------------------------------------
``TEE_AUDIT_LOG_DIR`` defaults to ``/var/log/tee_crafter``, which on the
CVM platforms is the guest's persistent OS disk: outside the launch
measurement, outside TEE memory encryption, and reachable by anyone with
root on the guest or with volume/cloud-plane access.

The chain in this file is an **unkeyed SHA-256** chain (see
:func:`_write_entry` / :func:`verify_chain`), not the keyed HMAC chain
``tee_crafter_audit_logger`` uses.  An unkeyed chain detects *accidental*
corruption and naive single-entry edits, but anyone who can write the
file can recompute every following ``entry_hash`` and produce a chain
that verifies.  So: "hash-chained" above means integrity-checked, and
does **not** mean forgery-resistant.  Do not present this log as tamper
*proof* to an auditor.

Treat the SIEM export as the authoritative rotation record; this file is
the local diagnostic copy.

This file is copied into the TEE image at build time and imported by the
platform template app (Nitro vsock, SNP, TDX, SGX).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

_logger = logging.getLogger("tee_crafter.key_rotation")

_LOG_DIR = os.environ.get("TEE_AUDIT_LOG_DIR", "/var/log/tee_crafter")
_LOG_FILE = os.path.join(_LOG_DIR, "key_rotation.jsonl")

_DEFAULT_ROTATION_SECS = int(os.environ.get("TEE_KEY_ROTATION_SECS", "3600"))
_DEFAULT_GRACE_SECS = int(os.environ.get("TEE_KEY_GRACE_SECS", "30"))
_MAX_REQUESTS_PER_KEY = int(os.environ.get("TEE_KEY_MAX_REQUESTS", "0"))

_lock = threading.Lock()
_prev_hash = "0" * 64
_entry_seq = 0

_rotation_interval = _DEFAULT_ROTATION_SECS
_grace_window = _DEFAULT_GRACE_SECS
_max_requests_per_key = _MAX_REQUESTS_PER_KEY
_attest_fn: Optional[Callable[[], Dict[str, Any]]] = None
_rotate_callback: Optional[Callable[[], Dict[str, str]]] = None

_current_key_id: str = ""
_current_key_fingerprint: str = ""
_current_key_type: str = ""
_key_created_at: float = 0.0
_key_request_count: int = 0
_total_rotations: int = 0
_rotation_history: List[Dict[str, Any]] = []


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(pub_bytes: bytes) -> str:
    return _sha256(pub_bytes)


def _ensure_log_dir() -> None:
    try:
        os.makedirs(_LOG_DIR, mode=0o700, exist_ok=True)
    except OSError:
        pass


def _write_entry(entry: Dict[str, Any]) -> None:
    """Append a hash-chained JSON entry to the rotation log."""
    global _prev_hash, _entry_seq

    with _lock:
        entry["seq"] = _entry_seq
        entry["prev_hash"] = _prev_hash
        entry_json = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        entry["entry_hash"] = _sha256(entry_json.encode())
        _prev_hash = entry["entry_hash"]
        _entry_seq += 1

    _ensure_log_dir()
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")
    except OSError as exc:
        _logger.warning("Key rotation log write failed: %s", exc)


def configure(
    rotation_interval_secs: int = _DEFAULT_ROTATION_SECS,
    grace_window_secs: int = _DEFAULT_GRACE_SECS,
    max_requests_per_key: int = 0,
    attest_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    rotate_callback: Optional[Callable[[], Dict[str, str]]] = None,
) -> None:
    """Configure the key rotation manager.

    Parameters
    ----------
    rotation_interval_secs:
        Time-based rotation interval (default 3600s / 1 hour).
    grace_window_secs:
        Overlap window after rotation where old key is still logged as valid
        (for in-flight requests finishing on the old key).
    max_requests_per_key:
        Rotate after this many requests (0 = disabled).
    attest_fn:
        Platform-specific attestation callback. If provided, every rotation
        will include a fresh attestation measurement.
    rotate_callback:
        Called to perform the actual key rotation. Must return a dict with
        at minimum ``{"key_id": ..., "fingerprint": ..., "key_type": ...}``.
        If not set, the template handles rotation and calls ``record_rotation``
        manually.
    """
    global _rotation_interval, _grace_window, _max_requests_per_key
    global _attest_fn, _rotate_callback
    _rotation_interval = rotation_interval_secs
    _grace_window = grace_window_secs
    _max_requests_per_key = max_requests_per_key
    _attest_fn = attest_fn
    _rotate_callback = rotate_callback


def record_key_birth(
    key_id: str,
    pub_bytes: bytes,
    key_type: str = "ECDH",
) -> None:
    """Record the initial key generation at TEE boot."""
    global _current_key_id, _current_key_fingerprint, _current_key_type
    global _key_created_at, _key_request_count

    fp = _fingerprint(pub_bytes)
    _current_key_id = key_id
    _current_key_fingerprint = fp
    _current_key_type = key_type
    _key_created_at = time.monotonic()
    _key_request_count = 0

    _write_entry({
        "event": "key_birth",
        "ts": time.time(),
        "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "key_id": key_id,
        "key_fingerprint": fp,
        "key_type": key_type,
        "rotation_interval_secs": _rotation_interval,
        "max_requests_per_key": _max_requests_per_key,
    })
    _logger.info("Key birth recorded: id=%s fp=%s..%s type=%s",
                 key_id, fp[:8], fp[-8:], key_type)


def record_rotation(
    new_key_id: str,
    new_pub_bytes: bytes,
    new_key_type: str = "ECDH",
    reason: str = "time_based",
    rotation_latency_ms: float = 0.0,
) -> Dict[str, Any]:
    """Record a completed key rotation.

    Call this *after* the template has swapped in the new key.
    Returns the rotation record.
    """
    global _current_key_id, _current_key_fingerprint, _current_key_type
    global _key_created_at, _key_request_count, _total_rotations

    now_mono = time.monotonic()
    old_id = _current_key_id
    old_fp = _current_key_fingerprint
    old_type = _current_key_type
    old_lifetime = now_mono - _key_created_at if _key_created_at else 0
    old_requests = _key_request_count

    new_fp = _fingerprint(new_pub_bytes)

    attestation_data: Dict[str, Any] = {}
    if _attest_fn is not None:
        try:
            attestation_data = _attest_fn()
        except Exception as exc:
            attestation_data = {"error": str(exc)[:200]}
            _logger.warning("Attestation during rotation failed: %s", exc)

    _current_key_id = new_key_id
    _current_key_fingerprint = new_fp
    _current_key_type = new_key_type
    _key_created_at = now_mono
    _key_request_count = 0
    _total_rotations += 1

    record = {
        "event": "key_rotation",
        "ts": time.time(),
        "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reason": reason,
        "rotation_number": _total_rotations,
        "retired_key": {
            "key_id": old_id,
            "fingerprint": old_fp,
            "key_type": old_type,
            "lifetime_secs": round(old_lifetime, 2),
            "requests_served": old_requests,
        },
        "new_key": {
            "key_id": new_key_id,
            "fingerprint": new_fp,
            "key_type": new_key_type,
        },
        "rotation_latency_ms": round(rotation_latency_ms, 2),
        "grace_window_secs": _grace_window,
    }
    if attestation_data:
        record["attestation_at_rotation"] = {
            k: v for k, v in attestation_data.items()
            if k in ("measurement", "report_hash", "error")
        }

    _write_entry(record)

    with _lock:
        _rotation_history.append(record)
        if len(_rotation_history) > 500:
            _rotation_history[:] = _rotation_history[-250:]

    _logger.info(
        "Key rotated (#%d): %s..->%s.. reason=%s served=%d lifetime=%.0fs latency=%.1fms",
        _total_rotations, old_fp[:8], new_fp[:8], reason,
        old_requests, old_lifetime, rotation_latency_ms,
    )
    return record


def tick_request() -> None:
    """Increment the request counter for the current key epoch."""
    global _key_request_count
    _key_request_count += 1


def should_rotate() -> tuple[bool, str]:
    """Check whether rotation is needed.

    Returns ``(should_rotate, reason)``.
    """
    if not _key_created_at:
        return False, ""

    elapsed = time.monotonic() - _key_created_at
    if elapsed >= _rotation_interval:
        return True, "time_based"

    if _max_requests_per_key > 0 and _key_request_count >= _max_requests_per_key:
        return True, "max_requests"

    return False, ""


def trigger_rotation(reason: str = "event_triggered") -> Optional[Dict[str, Any]]:
    """Force an immediate rotation via the configured callback.

    Returns the rotation record, or None if no callback is configured.
    """
    if _rotate_callback is None:
        _logger.warning("trigger_rotation called but no rotate_callback configured")
        return None

    t0 = time.monotonic()
    result = _rotate_callback()
    latency = (time.monotonic() - t0) * 1000

    return record_rotation(
        new_key_id=result.get("key_id", f"key-{_total_rotations + 1}"),
        new_pub_bytes=result.get("pub_bytes", b""),
        new_key_type=result.get("key_type", "ECDH"),
        reason=reason,
        rotation_latency_ms=latency,
    )


def get_status() -> Dict[str, Any]:
    """Return rotation manager status for observability."""
    elapsed = time.monotonic() - _key_created_at if _key_created_at else 0
    next_rotation_in = max(0, _rotation_interval - elapsed)

    with _lock:
        recent = _rotation_history[-5:] if _rotation_history else []

    avg_lifetime = 0.0
    avg_requests = 0.0
    if _rotation_history:
        lifetimes = [r["retired_key"]["lifetime_secs"] for r in _rotation_history]
        requests = [r["retired_key"]["requests_served"] for r in _rotation_history]
        avg_lifetime = sum(lifetimes) / len(lifetimes)
        avg_requests = sum(requests) / len(requests)

    return {
        "configured": bool(_key_created_at),
        "rotation_interval_secs": _rotation_interval,
        "grace_window_secs": _grace_window,
        "max_requests_per_key": _max_requests_per_key,
        "current_key": {
            "key_id": _current_key_id,
            "fingerprint": _current_key_fingerprint,
            "key_type": _current_key_type,
            "age_secs": round(elapsed, 1),
            "requests_served": _key_request_count,
            "next_rotation_in_secs": round(next_rotation_in, 1),
        },
        "total_rotations": _total_rotations,
        "avg_key_lifetime_secs": round(avg_lifetime, 1),
        "avg_requests_per_key": round(avg_requests, 1),
        "attestation_bound": _attest_fn is not None,
        "recent_rotations": [
            {
                "rotation_number": r["rotation_number"],
                "reason": r["reason"],
                "ts_iso": r["ts_iso"],
                "retired_fingerprint": r["retired_key"]["fingerprint"][:16] + "...",
                "new_fingerprint": r["new_key"]["fingerprint"][:16] + "...",
                "latency_ms": r["rotation_latency_ms"],
            }
            for r in recent
        ],
    }


def verify_chain(path: Optional[str] = None) -> tuple[bool, str]:
    """Verify the hash chain of the rotation log.

    Returns ``(ok, message)``.
    """
    path = path or _LOG_FILE
    if not os.path.exists(path):
        return False, f"Rotation log not found: {path}"

    prev = "0" * 64
    line_no = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line_no += 1
                entry = json.loads(line)
                if entry.get("prev_hash") != prev:
                    return False, f"Chain break at line {line_no}: expected prev_hash={prev}"
                stored_hash = entry.pop("entry_hash", "")
                check_json = json.dumps(entry, separators=(",", ":"), sort_keys=True)
                computed = _sha256(check_json.encode())
                if computed != stored_hash:
                    return False, f"Hash mismatch at line {line_no}"
                prev = stored_hash
    except (json.JSONDecodeError, KeyError) as exc:
        return False, f"Parse error at line {line_no}: {exc}"
    return True, f"Rotation log verified: {line_no} entries, {_total_rotations} rotations"
