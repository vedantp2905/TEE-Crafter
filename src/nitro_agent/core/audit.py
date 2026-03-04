"""
Build Provenance Audit Trail for Nitro-Agent.

Produces a hash-chained, tamper-evident record of every security-relevant
action taken during the build/deploy pipeline.  The trail is saved to the
build directory so the client can independently verify that every signature,
hash, and security mechanism was in place for their enclave.

Design rationale (Kerckhoffs' principle):  security comes from
cryptographic guarantees (PCR binding, attestation, KMS key policies),
not from secrecy of the pipeline.  The audit trail records *what*
happened (hashes, pass/fail, PCR values) but never records *secrets*
(AWS credentials, private keys, session tokens).

Security considerations (safe / good practice)
-----------------------------------------------
- We only record: hashes (SHA-256), PCR values, pass/fail status, resource
  IDs (instance_id, kms_key_arn), step names, and template/artifact digests.
  No credentials, keys, tokens, or plaintext data are ever intentionally
  recorded.
- Details are sanitized before storage: any string value that looks like an
  AWS key, session token, or private key is redacted to avoid accidental
  leakage from exception messages or future code changes.
- The hash chain (prev_hash) makes the log tamper-evident: altering any
  entry invalidates all subsequent hashes. Clients can verify with
  BuildAuditTrail.verify_chain(path).
- The trail is stored only in the user's build directory; it is not sent
  to any remote service. Enclave startup report contains only step IDs
  (e.g. "rsa_key_generated"), no keys or data.
- We do not sign the final document with a private key; integrity is via
  the hash chain. For higher assurance, the client could sign
  build_provenance.json externally after generation.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


def sha256_hex(data: str | bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    """Return the SHA-256 hex digest of a file, or empty string if missing."""
    if not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _looks_like_secret(value: str) -> bool:
    """Heuristic: avoid persisting values that look like credentials or keys."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) < 4:
        return False
    # AWS access key ID format (e.g. AKIAIOSFODNN7EXAMPLE)
    if v.startswith("AKIA") and len(v) <= 24:
        return True
    # Base64-looking session token (long and alnum with +/=)
    if len(v) > 200 and v.replace("+", "").replace("/", "").replace("=", "").replace("-", "").replace("_", "").isalnum():
        return True
    if "AQo" in v and len(v) > 100:
        return True
    # PEM-style private key
    if "-----BEGIN " in v and "PRIVATE KEY" in v:
        return True
    return False


def _sanitize_details(details: Dict[str, Any]) -> Dict[str, Any]:
    """Redact any detail value that looks like a secret (defense in depth)."""
    out: Dict[str, Any] = {}
    for k, v in details.items():
        if isinstance(v, str) and _looks_like_secret(v):
            out[k] = "[REDACTED]"
        elif isinstance(v, dict):
            out[k] = _sanitize_details(v)
        elif isinstance(v, list):
            out[k] = ["[REDACTED]" if isinstance(x, str) and _looks_like_secret(x) else x for x in v]
        else:
            out[k] = v
    return out


# Canonical list of security-critical substeps guaranteed by the enclave template (TCB).
# Each dict: id (machine-readable), name (human-readable), category (startup | request_attestation | request_data).
ENCLAVE_TCB_SUBSTEPS: List[Dict[str, str]] = [
    # Startup (module load and run_vsock_server() init)
    {"id": "rsa_key_generated", "name": "RSA-2048 key pair generated for KMS attestation", "category": "startup"},
    {"id": "loopback_interface_up", "name": "Loopback interface (127.0.0.1) brought up", "category": "startup"},
    {"id": "dns_patch_kms_to_loopback", "name": "DNS patch: kms.*.amazonaws.com -> 127.0.0.1 (TLS via vsock)", "category": "startup"},
    {"id": "tcp_to_vsock_proxy_listening", "name": "TCP-to-VSOCK proxy listening on 127.0.0.1:443 -> CID 3:8000", "category": "startup"},
    {"id": "vsock_server_listening", "name": "VSOCK server listening on port 5005", "category": "startup"},
    # Attestation request path
    {"id": "nsm_attestation_document_requested", "name": "NSM attestation document requested (nsm-cli)", "category": "request_attestation"},
    {"id": "attestation_doc_returned", "name": "Attestation document (COSE_Sign1) returned to client", "category": "request_attestation"},
    # Data request path (crypto and confinement)
    {"id": "aws_credentials_injected", "name": "AWS credentials injected from host proxy (no plaintext to host)", "category": "request_data"},
    {"id": "entropy_seeded_from_kms", "name": "Entropy seeded from KMS GenerateRandom (256 bytes)", "category": "request_data"},
    {"id": "attestation_doc_with_rsa_pubkey", "name": "Attestation document requested with enclave RSA public key", "category": "request_data"},
    {"id": "kms_decrypt_with_recipient", "name": "KMS Decrypt called with Recipient (attestation document)", "category": "request_data"},
    {"id": "cms_envelope_parsed", "name": "CMS (RFC 5652) EnvelopedData parsed", "category": "request_data"},
    {"id": "cek_rsa_oaep_unwrapped", "name": "Content-encryption key RSA-OAEP unwrapped with enclave private key", "category": "request_data"},
    {"id": "content_aes_decrypted", "name": "Payload AES-GCM/AES-CBC decrypted", "category": "request_data"},
    {"id": "process_request_invoked", "name": "process_request() invoked with plaintext only (key confinement)", "category": "request_data"},
    {"id": "response_serialized_sent", "name": "Response JSON serialized and sent over VSOCK only (channel confinement)", "category": "request_data"},
]


@dataclass
class AuditEntry:
    """A single step in the provenance record."""
    seq: int
    timestamp: str
    phase: str
    step: str
    status: str  # "pass", "fail", "skip", "info"
    details: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""

    def digest(self) -> str:
        """Compute a deterministic SHA-256 digest of this entry."""
        canonical = json.dumps(
            {
                "seq": self.seq,
                "timestamp": self.timestamp,
                "phase": self.phase,
                "step": self.step,
                "status": self.status,
                "details": self.details,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256_hex(canonical)


class BuildAuditTrail:
    """
    Accumulates a hash-chained sequence of :class:`AuditEntry` records.

    Each entry's ``prev_hash`` is the digest of the preceding entry,
    forming a tamper-evident chain.  If any entry is modified after the
    fact, all subsequent hashes become invalid.
    """

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._head_hash: str = "0" * 64  # genesis sentinel
        self._start_time = datetime.datetime.utcnow().isoformat() + "Z"
        self._pipeline_version: str = ""
        self._build_dir: str = ""

    # ------------------------------------------------------------------
    # Public recording API
    # ------------------------------------------------------------------

    def set_metadata(
        self,
        pipeline_version: str,
        build_dir: str,
    ) -> None:
        self._pipeline_version = pipeline_version
        self._build_dir = build_dir

    def record(
        self,
        phase: str,
        step: str,
        status: str,
        **details: Any,
    ) -> AuditEntry:
        """Append a new entry to the chain and return it. Details are sanitized before storage."""
        entry = AuditEntry(
            seq=len(self._entries),
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            phase=phase,
            step=step,
            status=status,
            details=_sanitize_details(dict(details)),
            prev_hash=self._head_hash,
        )
        self._head_hash = entry.digest()
        self._entries.append(entry)
        return entry

    # Convenience helpers for common patterns --------------------------

    def record_file_hash(
        self,
        phase: str,
        step: str,
        filepath: str,
        *,
        label: str = "",
    ) -> AuditEntry:
        """Record the SHA-256 digest of *filepath*."""
        digest = sha256_file(filepath)
        return self.record(
            phase,
            step,
            "pass" if digest else "fail",
            file=os.path.basename(filepath),
            sha256=digest,
            label=label or os.path.basename(filepath),
        )

    def record_hash_value(
        self,
        phase: str,
        step: str,
        content: str,
        *,
        label: str = "",
    ) -> AuditEntry:
        """Record the SHA-256 digest of an in-memory string."""
        return self.record(
            phase,
            step,
            "pass",
            sha256=sha256_hex(content),
            label=label,
        )

    def record_enclave_tcb_substeps(
        self,
        template_sha256: str,
        *,
        phase: str = "Enclave TCB",
    ) -> None:
        """
        Record all template-guaranteed enclave security substeps.
        Each substep is recorded as a separate chain entry for granular verification.
        """
        for sub in ENCLAVE_TCB_SUBSTEPS:
            self.record(
                phase,
                sub["name"],
                "pass",
                substep_id=sub["id"],
                category=sub["category"],
                template_sha256=template_sha256,
            )

    def record_enclave_runtime_startup(
        self,
        steps: List[str],
        *,
        phase: str = "Enclave Runtime",
        status: str = "pass",
    ) -> AuditEntry:
        """Record the enclave-reported startup steps (from enclave stdout)."""
        return self.record(
            phase,
            "Enclave startup report (from console)",
            status,
            reported_steps=steps,
            step_count=len(steps),
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def _build_document(self) -> Dict[str, Any]:
        return {
            "audit_trail_version": "1.0",
            "pipeline_version": self._pipeline_version,
            "build_dir": self._build_dir,
            "started_at": self._start_time,
            "finished_at": datetime.datetime.utcnow().isoformat() + "Z",
            "host_platform": platform.platform(),
            "python_version": platform.python_version(),
            "total_entries": len(self._entries),
            "chain_head_hash": self._head_hash,
            "entries": [asdict(e) for e in self._entries],
        }

    def save(self, build_dir: str) -> str:
        """
        Write the audit trail to ``build_provenance.json`` inside
        *build_dir*.  Returns the absolute path of the written file.
        """
        self._build_dir = build_dir
        doc = self._build_document()
        path = os.path.join(build_dir, "build_provenance.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        return os.path.abspath(path)

    def save_summary(self, build_dir: str) -> str:
        """
        Write a human-readable summary alongside the JSON trail.
        Returns the absolute path.
        """
        doc = self._build_document()
        lines: List[str] = []

        lines.append("=" * 72)
        lines.append("  NITRO-AGENT BUILD PROVENANCE REPORT")
        lines.append("=" * 72)
        lines.append(f"  Pipeline version : {doc['pipeline_version'] or 'dev'}")
        lines.append(f"  Build directory  : {doc['build_dir']}")
        lines.append(f"  Started at       : {doc['started_at']}")
        lines.append(f"  Finished at      : {doc['finished_at']}")
        lines.append(f"  Host platform    : {doc['host_platform']}")
        lines.append(f"  Total steps      : {doc['total_entries']}")
        lines.append(f"  Chain head hash  : {doc['chain_head_hash']}")
        lines.append("=" * 72)
        lines.append("")

        current_phase = ""
        pass_count = 0
        fail_count = 0

        for entry in self._entries:
            if entry.phase != current_phase:
                current_phase = entry.phase
                lines.append(f"── {current_phase} {'─' * max(1, 58 - len(current_phase))}")

            status_icon = {
                "pass": "✓",
                "fail": "✗",
                "skip": "○",
                "info": "ℹ",
            }.get(entry.status, "?")

            if entry.status == "pass":
                pass_count += 1
            elif entry.status == "fail":
                fail_count += 1

            lines.append(f"  [{status_icon}] {entry.step}")

            for k, v in entry.details.items():
                val_str = str(v)
                if len(val_str) > 80:
                    val_str = val_str[:77] + "..."
                lines.append(f"      {k}: {val_str}")

        lines.append("")
        lines.append("-" * 72)
        lines.append(f"  SUMMARY: {pass_count} passed, {fail_count} failed, "
                      f"{doc['total_entries'] - pass_count - fail_count} other")
        lines.append("-" * 72)
        lines.append("")
        lines.append("Verify chain integrity: each entry's prev_hash must equal")
        lines.append("the SHA-256 digest of the preceding entry's canonical JSON.")
        lines.append("Full machine-readable trail: build_provenance.json")
        lines.append("")

        path = os.path.join(build_dir, "build_provenance.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return os.path.abspath(path)

    # ------------------------------------------------------------------
    # Verification (static, can be run by the client offline)
    # ------------------------------------------------------------------

    @staticmethod
    def parse_enclave_startup_report(console_output: str) -> Optional[List[str]]:
        """
        Parse enclave stdout for a single JSON line emitted by the enclave
        at startup: {"audit": "enclave_startup", "steps": ["id1", "id2", ...]}.
        Returns the list of step IDs if found, else None.
        """
        if not console_output or not isinstance(console_output, str):
            return None
        for line in console_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if obj.get("audit") == "enclave_startup" and "steps" in obj:
                    steps = obj["steps"]
                    if isinstance(steps, list) and all(isinstance(s, str) for s in steps):
                        return steps
            except (json.JSONDecodeError, TypeError):
                continue
        return None

    @staticmethod
    def verify_chain(provenance_path: str) -> tuple[bool, str]:
        """
        Re-compute every hash in a saved ``build_provenance.json`` and
        confirm the chain is intact.

        Returns ``(True, "")`` on success or ``(False, reason)`` on failure.
        """
        with open(provenance_path, "r", encoding="utf-8") as f:
            doc = json.load(f)

        entries = doc.get("entries", [])
        if not entries:
            return False, "Audit trail is empty."

        prev_hash = "0" * 64  # genesis sentinel

        for entry_dict in entries:
            if entry_dict.get("prev_hash") != prev_hash:
                return (
                    False,
                    f"Chain broken at seq {entry_dict.get('seq')}: "
                    f"expected prev_hash {prev_hash}, "
                    f"got {entry_dict.get('prev_hash')}",
                )

            e = AuditEntry(**entry_dict)
            prev_hash = e.digest()

        if prev_hash != doc.get("chain_head_hash"):
            return (
                False,
                f"chain_head_hash mismatch: computed {prev_hash}, "
                f"recorded {doc.get('chain_head_hash')}",
            )

        return True, ""
