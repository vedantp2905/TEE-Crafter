"""Audit trail utility functions: hashing, secret detection, and TCB substeps."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List


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
    if v.startswith("AKIA") and len(v) <= 24:
        return True
    if len(v) > 200 and v.replace("+", "").replace("/", "").replace("=", "").replace("-", "").replace("_", "").isalnum():
        return True
    if "AQo" in v and len(v) > 100:
        return True
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


ENCLAVE_TCB_SUBSTEPS: List[Dict[str, str]] = [
    {"id": "rsa_key_generated", "name": "RSA-2048 key pair generated for KMS attestation", "category": "startup"},
    {"id": "loopback_interface_up", "name": "Loopback interface (127.0.0.1) brought up", "category": "startup"},
    {"id": "dns_patch_kms_to_loopback", "name": "DNS patch: kms.*.amazonaws.com -> 127.0.0.1 (TLS via vsock)", "category": "startup"},
    {"id": "tcp_to_vsock_proxy_listening", "name": "TCP-to-VSOCK proxy listening on 127.0.0.1:443 -> CID 3:8000", "category": "startup"},
    {"id": "vsock_server_listening", "name": "VSOCK server listening on port 5005", "category": "startup"},
    {"id": "nsm_attestation_document_requested", "name": "NSM attestation document requested (nsm-cli)", "category": "request_attestation"},
    {"id": "attestation_doc_returned", "name": "Attestation document (COSE_Sign1) returned to client", "category": "request_attestation"},
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
    status: str
    details: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""

    def digest(self) -> str:
        """Compute a deterministic SHA-256 digest of this entry."""
        canonical = json.dumps(
            {"seq": self.seq, "timestamp": self.timestamp, "phase": self.phase,
             "step": self.step, "status": self.status, "details": self.details,
             "prev_hash": self.prev_hash},
            sort_keys=True, separators=(",", ":"),
        )
        return sha256_hex(canonical)
