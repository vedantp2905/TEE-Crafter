"""Build-host side: package an input directory and wrap it to the enclave."""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import io
import json
import os
import tarfile
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


SEAL_VERSION = 1
ALG = "RSA-OAEP-SHA256+AES-256-GCM"


@dataclass
class SealedBundle:
    sealed_path: str
    manifest_path: str
    plaintext_sha256: str
    size_bytes: int
    target_spki_sha256: str
    build_id: str
    timestamp: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sealed_path": self.sealed_path,
            "manifest_path": self.manifest_path,
            "plaintext_sha256": self.plaintext_sha256,
            "size_bytes": self.size_bytes,
            "target_spki_sha256": self.target_spki_sha256,
            "build_id": self.build_id,
            "timestamp": self.timestamp,
            "alg": ALG,
            "v": SEAL_VERSION,
            **self.extra,
        }


def _tar_directory(input_dir: str) -> bytes:
    """Deterministically tar+gzip *input_dir* into a single in-memory blob.

    Determinism matters: the plaintext SHA-256 is part of the public
    manifest and is verified inside the enclave after unseal.  We:

    * sort directory entries lexicographically,
    * strip mtimes / uid / gid / group / owner names,
    * use gzip without an embedded filename or timestamp.
    """
    if not os.path.isdir(input_dir):
        raise FileNotFoundError(f"input_dir not found or not a directory: {input_dir}")

    buf = io.BytesIO()
    # gzip: mtime=0, name="" -> deterministic header.
    import gzip
    gz = gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0)
    with tarfile.open(fileobj=gz, mode="w") as tar:
        for root, dirs, files in os.walk(input_dir, topdown=True):
            dirs.sort()
            files.sort()
            for name in dirs + files:
                full = os.path.join(root, name)
                arc = os.path.relpath(full, input_dir)
                if arc == ".":
                    continue
                ti = tar.gettarinfo(full, arcname=arc)
                ti.mtime = 0
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                if ti.isfile():
                    with open(full, "rb") as f:
                        tar.addfile(ti, f)
                else:
                    tar.addfile(ti)
    gz.close()
    return buf.getvalue()


def _load_target_spki(target_pub_pem: bytes):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(target_pub_pem)


def _spki_sha256(target_pub) -> str:
    from cryptography.hazmat.primitives import serialization
    spki = target_pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def seal_input_directory(
    *,
    input_dir: str,
    target_pub_pem: bytes,
    out_path: str,
    build_id: str = "",
    additional_aad: Optional[Dict[str, str]] = None,
) -> SealedBundle:
    """Wrap *input_dir* to *target_pub_pem* and write to *out_path*.

    Writes ``<out_path>`` (the sealed JSON envelope) and
    ``<out_path>.manifest.json`` (the plaintext metadata).  The manifest
    is safe to publish; the ``out_path`` cannot be opened without the
    enclave's private key.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    target_pub = _load_target_spki(target_pub_pem)
    if not isinstance(target_pub, rsa.RSAPublicKey):
        raise TypeError("target public key must be RSA (RSA-OAEP-SHA256 KEM)")

    spki_hex = _spki_sha256(target_pub)

    plaintext = _tar_directory(input_dir)
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()

    dek = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    aad_obj = {
        "v": SEAL_VERSION,
        "alg": ALG,
        "target_spki_sha256": spki_hex,
        "build_id": build_id,
        "plaintext_sha256": plaintext_sha256,
        **(additional_aad or {}),
    }
    aad = json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    aes = AESGCM(dek)
    ciphertext = aes.encrypt(iv, plaintext, aad)
    # AESGCM concatenates ciphertext||tag (16 bytes); split for the manifest.
    if len(ciphertext) < 16:
        raise RuntimeError("AESGCM ciphertext shorter than tag length")
    body, tag = ciphertext[:-16], ciphertext[-16:]

    wrapped_dek = target_pub.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None),
    )

    timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    envelope = {
        "v": SEAL_VERSION,
        "alg": ALG,
        "target_spki_sha256": spki_hex,
        "build_id": build_id,
        "wrapped_dek_b64": base64.b64encode(wrapped_dek).decode("ascii"),
        "iv_b64": base64.b64encode(iv).decode("ascii"),
        "aad_b64": base64.b64encode(aad).decode("ascii"),
        "ciphertext_b64": base64.b64encode(body).decode("ascii"),
        "tag_b64": base64.b64encode(tag).decode("ascii"),
        "plaintext_sha256": plaintext_sha256,
        "size_bytes": len(plaintext),
        "timestamp": timestamp,
    }

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)
        f.write("\n")

    manifest_path = out_path + ".manifest.json"
    manifest = {k: v for k, v in envelope.items()
                 if k not in ("ciphertext_b64", "wrapped_dek_b64",
                              "iv_b64", "aad_b64", "tag_b64")}
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    return SealedBundle(
        sealed_path=out_path, manifest_path=manifest_path,
        plaintext_sha256=plaintext_sha256, size_bytes=len(plaintext),
        target_spki_sha256=spki_hex, build_id=build_id,
        timestamp=timestamp,
    )
