"""Provenance signing key management.

The build provenance is signed with Ed25519 in two modes:

* **Long-lived key (production)** — the operator sets one of
  ``TEE_CRAFTER_PROVENANCE_SIGNING_KEY`` (PEM text), or
  ``TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE`` (PEM path), or pre-populates
  the OS keyring entry ``tee-crafter`` / ``provenance-signing-key``, or
  drops a PEM at ``~/.tee-crafter/provenance-signing-key.pem`` (0600).
  Every build then ships the *same* public key, so an out-of-band
  verifier can pin it by SHA-256 fingerprint via
  ``tee-crafter verify-provenance --pinned-pubkey-sha256 <hex>``.

* **Ephemeral key (development)** — when no long-lived key is configured
  *and* ``TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL`` is unset (default) the
  signer aborts.  When the env var is set (``=1``) the signer generates a
  per-build keypair and emits ``build_provenance.key_kind.txt = ephemeral``
  so the verifier can fail-closed in production.

The key file always carries the public-key SHA-256 fingerprint at
``build_provenance.pub.sha256`` so operators can compare it to the
fingerprint they pinned in their CI / audit policy.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_ENV_PEM = "TEE_CRAFTER_PROVENANCE_SIGNING_KEY"
_ENV_PATH = "TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE"
_ENV_ALLOW_EPHEMERAL = "TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL"

_KEYRING_SERVICE = "tee-crafter"
_KEYRING_USER = "provenance-signing-key"

_DEFAULT_KEY_PATH = Path.home() / ".tee-crafter" / "provenance-signing-key.pem"


class ProvenanceSigningError(RuntimeError):
    """Raised when no long-lived key is available and ephemeral mode is off."""


@dataclass(frozen=True)
class LoadedSigningKey:
    """The signing key plus a label describing where it came from."""

    key: Ed25519PrivateKey
    kind: str  # "longlived" | "ephemeral"
    source: str  # human-readable provenance string


def _parse_pem(pem_text: str) -> Optional[Ed25519PrivateKey]:
    """Load an Ed25519 private key from PEM text or return None on failure."""
    try:
        loaded = serialization.load_pem_private_key(
            pem_text.encode("utf-8"), password=None,
        )
    except Exception:
        return None
    if isinstance(loaded, Ed25519PrivateKey):
        return loaded
    return None


def _from_env_pem() -> Optional[Tuple[Ed25519PrivateKey, str]]:
    raw = os.environ.get(_ENV_PEM, "").strip()
    if not raw:
        return None
    key = _parse_pem(raw)
    if key is None:
        return None
    return key, f"env:{_ENV_PEM}"


def _from_env_path() -> Optional[Tuple[Ed25519PrivateKey, str]]:
    p = os.environ.get(_ENV_PATH, "").strip()
    if not p:
        return None
    path = Path(p).expanduser()
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    key = _parse_pem(text)
    if key is None:
        return None
    return key, f"env-file:{path}"


def _from_keyring() -> Optional[Tuple[Ed25519PrivateKey, str]]:
    try:
        import keyring  # type: ignore
    except Exception:
        return None
    try:
        stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USER)
    except Exception:
        return None
    if not stored:
        return None
    key = _parse_pem(stored)
    if key is None:
        return None
    return key, f"keyring:{_KEYRING_SERVICE}/{_KEYRING_USER}"


def _from_default_path() -> Optional[Tuple[Ed25519PrivateKey, str]]:
    if not _DEFAULT_KEY_PATH.is_file():
        return None
    try:
        text = _DEFAULT_KEY_PATH.read_text(encoding="utf-8")
    except OSError:
        return None
    key = _parse_pem(text)
    if key is None:
        return None
    return key, f"file:{_DEFAULT_KEY_PATH}"


#: Process-wide cache for the dev-mode ephemeral keypair.  Without this every
#: ``load_signing_key()`` call minted a *fresh* key, so the provenance trail,
#: the SLSA envelope and the audit ledger each ended up signed by a different
#: key while only one ``build_provenance.pub`` was written — making every
#: verification fail in ephemeral mode.  One keypair per process keeps the
#: "per-build keypair" contract in the module docstring truthful.
_EPHEMERAL_KEY: Optional[Ed25519PrivateKey] = None


def _ephemeral() -> Tuple[Ed25519PrivateKey, str]:
    global _EPHEMERAL_KEY
    if _EPHEMERAL_KEY is None:
        _EPHEMERAL_KEY = Ed25519PrivateKey.generate()
    return _EPHEMERAL_KEY, "ephemeral:generated"


def load_signing_key() -> LoadedSigningKey:
    """Resolve the signing key with provenance, honouring the policy in
    the module docstring.  Never returns None; raises
    :class:`ProvenanceSigningError` when ephemeral fallback is disabled
    and no long-lived key is configured.
    """
    for resolver in (_from_env_pem, _from_env_path, _from_keyring, _from_default_path):
        loaded = resolver()
        if loaded is not None:
            key, src = loaded
            return LoadedSigningKey(key=key, kind="longlived", source=src)

    if os.environ.get(_ENV_ALLOW_EPHEMERAL, "").strip().lower() not in (
        "1", "true", "yes", "y", "on",
    ):
        raise ProvenanceSigningError(
            "No long-lived provenance signing key is configured. Set one of "
            f"{_ENV_PEM}, {_ENV_PATH}, the OS keyring entry "
            f"'{_KEYRING_SERVICE}/{_KEYRING_USER}', or drop a PEM at "
            f"{_DEFAULT_KEY_PATH} (mode 0600). To allow an ephemeral "
            f"per-build keypair in dev, export "
            f"{_ENV_ALLOW_EPHEMERAL}=1 (NOT for production)."
        )

    key, src = _ephemeral()
    return LoadedSigningKey(key=key, kind="ephemeral", source=src)


def public_key_fingerprint(pub_key: Ed25519PublicKey) -> str:
    """SHA-256 of the SubjectPublicKeyInfo DER encoding (matches how
    operators are expected to pin a key in CI policy)."""
    der = pub_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def public_key_pem(pub_key: Ed25519PublicKey) -> bytes:
    return pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def generate_keypair_pem() -> Tuple[bytes, bytes, str]:
    """Generate a fresh Ed25519 keypair and return (priv_pem, pub_pem, fpr).

    Used by ``tee-crafter audit gen-signing-key`` to bootstrap a
    production signing key on a new operator machine.
    """
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = public_key_pem(pub)
    return priv_pem, pub_pem, public_key_fingerprint(pub)


def install_default_key(priv_pem: bytes) -> Path:
    """Write *priv_pem* to ``~/.tee-crafter/provenance-signing-key.pem``
    at mode 0600 and return the path.  Refuses to overwrite an existing
    file (the operator must remove it explicitly to avoid clobbering a
    production key)."""
    target = _DEFAULT_KEY_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(
            f"{target} already exists; remove it explicitly before regenerating."
        )
    target.write_bytes(priv_pem)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


__all__ = [
    "LoadedSigningKey",
    "ProvenanceSigningError",
    "generate_keypair_pem",
    "install_default_key",
    "load_signing_key",
    "public_key_fingerprint",
    "public_key_pem",
]
