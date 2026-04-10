"""In-TEE side: unwrap a sealed input bundle and stage it on disk."""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import tarfile
from typing import Any, Dict, Optional


class UnsealError(Exception):
    """Raised when a sealed bundle cannot be opened, decrypted, or trusted."""


def _load_envelope(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise UnsealError(f"sealed bundle not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            env = json.load(f)
    except json.JSONDecodeError as exc:
        raise UnsealError(f"sealed bundle is not valid JSON: {exc}")
    if env.get("v") != 1:
        raise UnsealError(f"unsupported sealed-bundle version: {env.get('v')!r}")
    if env.get("alg") != "RSA-OAEP-SHA256+AES-256-GCM":
        raise UnsealError(f"unsupported sealed-bundle alg: {env.get('alg')!r}")
    return env


def _b64(env: Dict[str, Any], key: str) -> bytes:
    raw = env.get(key)
    if not isinstance(raw, str):
        raise UnsealError(f"missing or non-string field: {key}")
    try:
        return base64.b64decode(raw)
    except Exception as exc:
        raise UnsealError(f"{key} is not valid base64: {exc}")


#: Envelope fields that ``seal.py`` also copies into the GCM AAD.  After
#: decryption succeeds these must agree, or the envelope was relabelled.
_AAD_MIRRORED_FIELDS = (
    "v", "alg", "target_spki_sha256", "build_id", "plaintext_sha256",
)


def _authenticated_aad(aad: bytes, env: Dict[str, Any]) -> Dict[str, Any]:
    """Parse the (now GCM-authenticated) AAD and cross-check the envelope.

    ``seal.py`` writes ``target_spki_sha256`` / ``build_id`` in two places: the
    top-level envelope JSON, and inside the AAD blob that AES-GCM actually
    authenticates.  Only the second is tamper-evident.  Gating on the first --
    which is what this module used to do -- means an attacker can relabel a
    bundle by editing one unauthenticated JSON string, with no key material,
    and both the SPKI and build-id gates fall open.

    Called only *after* ``AESGCM.decrypt`` has succeeded, so the bytes here are
    known-good.  Any disagreement with the top-level copy is a relabelling
    attempt and is fatal.
    """
    try:
        aad_obj = json.loads(aad.decode("utf-8"))
    except Exception as exc:
        raise UnsealError(f"aad_b64 is not valid UTF-8 JSON: {exc}")
    if not isinstance(aad_obj, dict):
        raise UnsealError("aad_b64 must decode to a JSON object")
    for key in _AAD_MIRRORED_FIELDS:
        if key not in aad_obj:
            raise UnsealError(f"authenticated AAD is missing field: {key}")
        if aad_obj[key] != env.get(key):
            raise UnsealError(
                f"envelope field {key!r} was relabelled: authenticated AAD says "
                f"{aad_obj[key]!r}, envelope says {env.get(key)!r}")
    return aad_obj


def _safe_extract_tar(tarball: bytes, dest_dir: str) -> int:
    """Extract a tar.gz blob to *dest_dir* with traversal protection."""
    os.makedirs(dest_dir, exist_ok=True)
    bio = io.BytesIO(tarball)
    extracted = 0
    with gzip.GzipFile(fileobj=bio, mode="rb") as gz, \
            tarfile.open(fileobj=gz, mode="r:") as tar:
        members = []
        dest_abs = os.path.realpath(dest_dir)
        for m in tar.getmembers():
            target = os.path.realpath(os.path.join(dest_dir, m.name))
            if not target.startswith(dest_abs + os.sep) and target != dest_abs:
                raise UnsealError(
                    f"sealed bundle contains traversal path: {m.name!r}")
            if m.issym() or m.islnk():
                # Reject every link rather than try to validate the target;
                # input bundles never legitimately need symlinks.
                continue
            if m.isdev() or m.isfifo():
                continue
            members.append(m)
        # filter argument added in 3.12; keep compat with 3.11 by rolling
        # our own enforcement above.
        try:
            tar.extractall(dest_dir, members=members,
                            filter=tarfile.data_filter)  # type: ignore[arg-type]
        except TypeError:
            tar.extractall(dest_dir, members=members)
        extracted = sum(1 for m in members if m.isfile())
    return extracted


def unseal_to_directory(
    *,
    sealed_path: str,
    private_key_pem: bytes,
    dest_dir: str,
    expected_target_spki_sha256: Optional[str] = None,
    expected_build_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Decrypt *sealed_path* and extract it into *dest_dir*.

    :raises UnsealError: on any policy or cryptographic failure.

    Returns a dict with ``plaintext_sha256``, ``files_extracted``,
    ``size_bytes``, suitable for the caller to write into the audit
    trail / batch ``_meta.json``.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    env = _load_envelope(sealed_path)

    # Cheap pre-flight against the *unauthenticated* top-level fields: it saves
    # an RSA decrypt on an obviously-wrong bundle.  It is NOT the gate -- these
    # same two values are re-checked below against the GCM-authenticated AAD,
    # and the envelope must agree with it.
    if expected_target_spki_sha256 is not None:
        if env.get("target_spki_sha256") != expected_target_spki_sha256:
            raise UnsealError(
                f"target_spki_sha256 mismatch: bundle binds to "
                f"{env.get('target_spki_sha256')!r}, expected "
                f"{expected_target_spki_sha256!r}")

    if expected_build_id is not None:
        if env.get("build_id") != expected_build_id:
            raise UnsealError(
                f"build_id mismatch: bundle is for {env.get('build_id')!r}, "
                f"this enclave's build is {expected_build_id!r}")

    sk = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(sk, rsa.RSAPrivateKey):
        raise UnsealError("private key must be RSA (matches RSA-OAEP-SHA256 KEM)")

    wrapped_dek = _b64(env, "wrapped_dek_b64")
    iv = _b64(env, "iv_b64")
    aad = _b64(env, "aad_b64")
    body = _b64(env, "ciphertext_b64")
    tag = _b64(env, "tag_b64")

    try:
        dek = sk.decrypt(
            wrapped_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None),
        )
    except Exception as exc:
        raise UnsealError(f"could not unwrap DEK: {exc}")
    if len(dek) != 32:
        raise UnsealError(f"unwrapped DEK has wrong length: {len(dek)}")

    aes = AESGCM(dek)
    try:
        plaintext = aes.decrypt(iv, body + tag, aad)
    except Exception as exc:
        raise UnsealError(f"AES-GCM authentication failed: {exc}")

    # `aad` is now known-good.  Everything the caller gates on must come from
    # it, not from the top-level JSON.
    aad_obj = _authenticated_aad(aad, env)

    if expected_target_spki_sha256 is not None:
        if aad_obj["target_spki_sha256"] != expected_target_spki_sha256:
            raise UnsealError(
                f"target_spki_sha256 mismatch: bundle binds to "
                f"{aad_obj['target_spki_sha256']!r}, expected "
                f"{expected_target_spki_sha256!r}")

    if expected_build_id is not None:
        if aad_obj["build_id"] != expected_build_id:
            raise UnsealError(
                f"build_id mismatch: bundle is for {aad_obj['build_id']!r}, "
                f"this enclave's build is {expected_build_id!r}")

    expected_sha = aad_obj["plaintext_sha256"]
    actual_sha = hashlib.sha256(plaintext).hexdigest()
    if expected_sha and expected_sha != actual_sha:
        raise UnsealError(
            f"plaintext_sha256 mismatch (expected {expected_sha}, got {actual_sha})")

    extracted = _safe_extract_tar(plaintext, dest_dir)

    return {
        "plaintext_sha256": actual_sha,
        "files_extracted": extracted,
        "size_bytes": len(plaintext),
        "target_spki_sha256": aad_obj["target_spki_sha256"],
        "build_id": aad_obj["build_id"],
    }
