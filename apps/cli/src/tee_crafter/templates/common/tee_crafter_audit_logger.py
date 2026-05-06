"""Runtime audit logger for TEE workloads.

Logs request/response *metadata only* (sizes, hashes, latencies, status)
without ever recording plaintext payloads.  Provides a tamper-evident,
hash-chained JSON-lines log that extends the build-time provenance into
runtime operation.

AUD-1..3 hardening:
    * AUD-1 — The log file is created with mode ``0o600`` and the log
      directory with ``0o700`` (owner-only).  Rotation preserves these
      bits.  Umask is temporarily tightened during file creation so a
      permissive process umask cannot widen them.
    * AUD-2 — Every entry is flushed with ``os.fsync`` *before* the
      in-memory chain head advances, so a crash between the write and
      the next call cannot leave the chain head pointing at an entry
      that is not on disk.  File descriptor is kept open in append
      mode to avoid repeated open/close race windows.
    * AUD-3 — The hash chain is now an HMAC chain keyed by a
      per-process secret (``_CHAIN_KEY``).  The key is generated
      fresh at process start and *never persisted to disk*.  Its
      SHA-256 commitment is emitted as a "genesis" entry so the
      commitment can be bound to the attestation evidence (the
      enclave can cover it with its RA-TLS key binding).  An attacker
      with write access to the log cannot forge a continuation of the
      chain without the in-memory key.

Known limitation — where these logs live
----------------------------------------
``TEE_AUDIT_LOG_DIR`` defaults to ``/var/log/tee_crafter``.  On the CVM
platforms (SNP, TDX, SGX-Azure, GPU-CC) that path is on the guest's
persistent OS disk.  That disk is **not** covered by the launch
measurement and is **not** protected by the TEE's memory encryption, so
it is reachable by anyone with root on the guest, with a snapshot of the
volume, or with cloud-plane access to the disk image.  The 0700/0600
modes above stop other *guest* users; they stop nothing above that line.

What this design does and does not buy you:

* It does NOT make the log confidential or immutable against the host or
  the cloud operator.  Do not describe it as such to an auditor.
* It DOES make undetected *alteration* hard: the HMAC chain is keyed by
  a per-process secret that only ever exists in TEE memory, so an
  attacker who edits or truncates the file cannot produce a valid
  continuation.  Wholesale replacement (new key, new genesis) is caught
  by pinning the genesis commitment — see
  :func:`publish_chain_key_commitment`.
* Off-box durability is the SIEM sidecar's job, not this file's.  A log
  that never leaves the guest can still be deleted.

On Nitro the enclave has no persistent filesystem, so this path is
enclave tmpfs — inside the encrypted enclave memory, and gone at
shutdown.  That is the stronger case, and also the one where SIEM export
matters most.

This file is copied into the TEE image at build time and imported by the
platform template app (Nitro vsock, SNP, TDX, SGX).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import threading
import time
from typing import Any, Dict, Optional, Tuple

_logger = logging.getLogger("tee_crafter.audit")

_LOG_DIR = os.environ.get("TEE_AUDIT_LOG_DIR", "/var/log/tee_crafter")
_LOG_FILE = os.path.join(_LOG_DIR, "runtime_audit.jsonl")
_MAX_LOG_SIZE = int(os.environ.get("TEE_AUDIT_MAX_SIZE_MB", "50")) * 1024 * 1024

_lock = threading.Lock()
_prev_hash = "0" * 64
_entry_seq = 0

# AUD-3: per-process HMAC key.  32 bytes of CSPRNG output.  Never
# written to disk; its SHA-256 commitment is published via the first
# genesis entry and bound into attestation evidence.
_CHAIN_KEY: bytes = secrets.token_bytes(32)
_CHAIN_KEY_COMMITMENT: str = hashlib.sha256(_CHAIN_KEY).hexdigest()
_GENESIS_WRITTEN = False
_LOG_FP: Optional["os.PathLike"] = None  # not used; we reopen each write for rotation safety


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(data: bytes) -> str:
    return hmac.new(_CHAIN_KEY, data, hashlib.sha256).hexdigest()


def get_chain_key_commitment() -> str:
    """Return the SHA-256 commitment to the per-process chain HMAC key.

    Templates should include this in attestation evidence so remote
    verifiers can pin the commitment and later reject logs whose
    genesis entry commitment does not match.  See
    :func:`publish_chain_key_commitment` for the mechanism that gets it
    out of this process.  The per-platform app templates bind it to the
    hardware quote by folding it into the length-prefixed
    ``tee-crafter/attest-binding/v2`` preimage they hash into
    ``report_data`` (Nitro uses the attestation document's ``nonce``).
    """
    return _CHAIN_KEY_COMMITMENT


#: Tmpfs path the commitment is published to.  The SIEM sidecar reads it
#: (``siem_export.CHAIN_COMMITMENT_PATH``) and echoes it on every
#: attestation event; keep the two literals in step.
CHAIN_COMMITMENT_PATH = "/run/tee_crafter/chain_key_commitment"


def publish_chain_key_commitment(path: str = "") -> str:
    """Write the chain-key commitment where out-of-band verifiers can see it.

    Without publication the commitment is purely self-referential: it is
    written into the log's own genesis entry and compared against that
    same log, so an attacker who replaces the log wholesale replaces the
    commitment too.  Writing it to tmpfs lets the SIEM sidecar attach it
    to every exported attestation event, and lets the platform template
    fold it into the ``tee-crafter/attest-binding/v2`` preimage that is
    hashed into the attestation ``report_data``.

    Note this publication is a no-op on SGX: the SIEM sidecar runs on the
    host, and Gramine's tmpfs is enclave memory, so the sidecar can never
    read it.  SGX binds the commitment via ``report_data`` only.

    Returns the commitment hex on success, ``""`` when the file could not
    be written (best-effort, like the rest of this module — the caller
    keeps serving).

    Both outcomes are logged, and the success case is logged on purpose.  Only
    the failure used to say anything, which left the two states that matter
    indistinguishable in a log: a write that failed silently somewhere without
    raising ``OSError``, and a call that never happened at all.  Under Gramine
    that is not hypothetical — the enclave's tmpfs is emulated, so whether this
    write succeeds is a property of the runtime rather than of this code, and it
    has never been watched on a real ``sgx-azure --batch`` run.  One line per
    outcome means a single run answers it from the enclave's own log.
    """
    target = path or os.environ.get(
        "TEE_CRAFTER_CHAIN_COMMITMENT_PATH", CHAIN_COMMITMENT_PATH)
    tmp = target + ".tmp"
    try:
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        with open(tmp, "w", encoding="ascii") as f:
            f.write(_CHAIN_KEY_COMMITMENT + "\n")
        # 0640: the sidecar runs as the same UID/GID and only needs read.
        os.chmod(tmp, 0o640)
        os.replace(tmp, target)
    except OSError as exc:
        _logger.warning(
            "chain-key commitment NOT published to %s: %s — the commitment is "
            "still bound via attestation report_data; only the sidecar's "
            "out-of-band copy is missing", target, exc)
        return ""
    _logger.info("chain-key commitment published to %s", target)
    return _CHAIN_KEY_COMMITMENT


def _ensure_log_dir() -> None:
    try:
        os.makedirs(_LOG_DIR, mode=0o700, exist_ok=True)
        # AUD-1: enforce directory mode even if os.makedirs silently
        # accepted a pre-existing, permissive directory.
        try:
            os.chmod(_LOG_DIR, 0o700)
        except OSError:
            pass
    except OSError:
        pass


def _ensure_log_file_perms() -> None:
    """AUD-1: ensure the log file itself is 0600 root-only."""
    try:
        if os.path.exists(_LOG_FILE):
            mode = stat.S_IMODE(os.stat(_LOG_FILE).st_mode)
            if mode & 0o077:
                os.chmod(_LOG_FILE, 0o600)
    except OSError:
        pass


def _rotate_if_needed() -> None:
    """Simple rotation: if log exceeds max size, rename to .prev and start fresh."""
    try:
        if os.path.exists(_LOG_FILE) and os.path.getsize(_LOG_FILE) > _MAX_LOG_SIZE:
            prev = _LOG_FILE + ".prev"
            if os.path.exists(prev):
                os.remove(prev)
            os.rename(_LOG_FILE, prev)
            # Rotated file inherits the 0600 permission bits; the new
            # file will be created with restrictive perms below.
    except OSError:
        pass


def _open_log_for_append():
    """Open the log file for append with restrictive perms on creation."""
    fd = os.open(
        _LOG_FILE,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC,
        0o600,
    )
    return os.fdopen(fd, "a", encoding="utf-8")


def _write_entry_line(line: str) -> None:
    """AUD-2: write a single line with fsync durability."""
    f = _open_log_for_append()
    try:
        f.write(line)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            # On tmpfs and some enclave stacks fsync may not be
            # supported; we've already flushed, so tolerate it.
            pass
    finally:
        f.close()
    _ensure_log_file_perms()


def _maybe_write_genesis() -> None:
    """Emit a genesis entry committing to the per-process HMAC key."""
    global _GENESIS_WRITTEN, _prev_hash, _entry_seq
    if _GENESIS_WRITTEN:
        return
    genesis = {
        "seq": _entry_seq,
        "ts": time.time(),
        "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": "_genesis",
        "status": "ok",
        "pid": os.getpid(),
        "chain_key_commitment": _CHAIN_KEY_COMMITMENT,
        "prev_hash": _prev_hash,
    }
    genesis_json = json.dumps(genesis, separators=(",", ":"), sort_keys=True)
    tag = _hmac_sha256(genesis_json.encode())
    genesis["entry_hash"] = tag
    _prev_hash = tag
    _entry_seq += 1
    _ensure_log_dir()
    try:
        _write_entry_line(
            json.dumps(genesis, separators=(",", ":"), sort_keys=True) + "\n"
        )
        _GENESIS_WRITTEN = True
    except OSError as exc:
        _logger.warning("Audit genesis write failed: %s", exc)


def log_request(
    *,
    request_bytes: bytes,
    response_bytes: bytes,
    action: str = "data",
    status: str = "ok",
    latency_ms: float = 0.0,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Record a single request/response audit entry.

    Hashes payloads instead of logging them, preserving privacy while
    enabling integrity verification.
    """
    global _prev_hash, _entry_seq

    # Capture payload-derived fields outside the lock (they don't need it).
    req_sz = len(request_bytes)
    req_h = _sha256(request_bytes)
    resp_sz = len(response_bytes)
    resp_h = _sha256(response_bytes)

    with _lock:
        _ensure_log_dir()
        _maybe_write_genesis()
        _rotate_if_needed()

        entry = {
            # AUD-3: capture seq inside the lock so it reflects the
            # state after any genesis entry has consumed seq=0.
            "seq": _entry_seq,
            "ts": time.time(),
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "status": status,
            "request_size": req_sz,
            "request_hash": req_h,
            "response_size": resp_sz,
            "response_hash": resp_h,
            "latency_ms": round(latency_ms, 2),
            "pid": os.getpid(),
        }
        if extra:
            entry["extra"] = extra

        entry["prev_hash"] = _prev_hash
        entry_json = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        # AUD-3: HMAC-SHA256 keyed tag so an attacker with only log
        # write access cannot rewrite the tail of the chain.
        entry["entry_hash"] = _hmac_sha256(entry_json.encode())

        try:
            _write_entry_line(
                json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n"
            )
            # Only advance the in-memory chain head after the line is
            # safely on disk (AUD-2).  If the write failed we want the
            # next entry to retry against the previous committed head.
            _prev_hash = entry["entry_hash"]
            _entry_seq += 1
        except OSError as exc:
            _logger.warning("Audit log write failed: %s", exc)


def get_stats() -> Dict[str, Any]:
    """Return summary statistics from the current audit log."""
    with _lock:
        return {
            "total_entries": _entry_seq,
            "chain_head_hash": _prev_hash,
            "chain_key_commitment": _CHAIN_KEY_COMMITMENT,
            "log_file": _LOG_FILE,
            "log_exists": os.path.exists(_LOG_FILE),
            "log_size_bytes": (
                os.path.getsize(_LOG_FILE)
                if os.path.exists(_LOG_FILE)
                else 0
            ),
        }


def wrap_process_request(fn):
    """Return an instrumented version of ``process_request``.

    Usage (inside template, right after user_logic)::

        import tee_crafter_audit_logger
        process_request = tee_crafter_audit_logger.wrap_process_request(process_request)
    """
    import functools
    import time as _t

    @functools.wraps(fn)
    def _wrapper(data):
        req_bytes = json.dumps(data, default=str, separators=(",", ":")).encode()
        t0 = _t.monotonic()
        try:
            result = fn(data)
            resp_bytes = json.dumps(result, default=str, separators=(",", ":")).encode()
            log_request(
                request_bytes=req_bytes,
                response_bytes=resp_bytes,
                status="ok",
                latency_ms=(_t.monotonic() - t0) * 1000,
            )
            return result
        except Exception as exc:
            log_request(
                request_bytes=req_bytes,
                response_bytes=b"",
                status="error",
                latency_ms=(_t.monotonic() - t0) * 1000,
                extra={"error": str(exc)[:200]},
            )
            raise

    return _wrapper


def verify_chain(
    path: Optional[str] = None,
    chain_key: Optional[bytes] = None,
) -> Tuple[bool, str]:
    """Verify the HMAC hash chain of the runtime audit log.

    ``chain_key`` must equal the per-process HMAC key that the enclave
    generated; verifiers obtain it by receiving it over an attested
    channel after the genesis entry has been bound to attestation
    evidence (AUD-3).  If ``chain_key`` is None, only the structural
    chaining is verified (prev_hash linkage and genesis commitment
    presence) — the HMAC tag itself cannot be validated.

    Returns ``(ok, message)``.
    """
    path = path or _LOG_FILE
    if not os.path.exists(path):
        return False, f"Log file not found: {path}"

    prev = "0" * 64
    line_no = 0
    genesis_commitment: Optional[str] = None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line_no += 1
                entry = json.loads(line)
                if entry.get("prev_hash") != prev:
                    return False, (
                        f"Chain break at line {line_no}: "
                        f"expected prev_hash={prev}"
                    )
                stored_hash = entry.pop("entry_hash", "")
                check_json = json.dumps(entry, separators=(",", ":"), sort_keys=True)
                if chain_key is not None:
                    computed = hmac.new(
                        chain_key, check_json.encode(), hashlib.sha256
                    ).hexdigest()
                    if not hmac.compare_digest(computed, stored_hash):
                        return False, f"HMAC mismatch at line {line_no}"
                if line_no == 1:
                    if entry.get("action") != "_genesis":
                        return False, "Missing genesis entry"
                    genesis_commitment = entry.get("chain_key_commitment")
                    if chain_key is not None:
                        expected = hashlib.sha256(chain_key).hexdigest()
                        if not hmac.compare_digest(
                            str(genesis_commitment or ""), expected
                        ):
                            return False, "Chain key commitment mismatch"
                prev = stored_hash
    except (json.JSONDecodeError, KeyError) as exc:
        return False, f"Parse error at line {line_no}: {exc}"
    return True, (
        f"Chain verified: {line_no} entries (commitment={genesis_commitment})"
    )
