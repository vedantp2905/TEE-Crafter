"""Attested sealed-``.env`` injection (operator hands plaintext; only the
attested enclave can decrypt).

Motivation
----------
In the container-orchestrated model the user's app frequently needs secrets —
a database password, an API token — that must NOT sit in plaintext on the
build host, in the image, or in a Terraform variable. This module lets the
operator hand a plaintext ``.env`` to ``--secrets-env`` at deploy time; the CLI
**envelope-seals** it so the cleartext is only recoverable *inside* the TEE,
gated by the **same attestation policy as BYOK**:

1. Generate a random 256-bit data key (DEK).
2. AES-256-GCM encrypt the ``.env`` bytes with the DEK (any size — no KMS 4 KiB
   plaintext limit).
3. KMS-encrypt the 32-byte DEK with the customer's BYOK key, with the BYOK
   encryption context. The wrapped DEK is only decryptable by a workload whose
   attestation document satisfies the key policy (e.g.
   ``kms:RecipientAttestation:ImageSha384`` on Nitro).

The resulting bundle ships as a BYOK *secret* extra
(``TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64``) so it only ever lands in the
tmpfs ``byok.env`` (never on the host disk or in ``byok.json``). In-TEE,
:func:`tee_crafter_runtime_bootstrap.bootstrap_secret_env_release` reuses the
BYOK orchestrator to attested-decrypt the DEK, AES-GCM-decrypts the ``.env``,
and writes it to ``/run/tee_crafter/app.env`` (tmpfs, 0600).

This module is import-light and KMS-client-injectable so it can be unit-tested
without cloud access.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, Optional

# Providers whose key can directly wrap the 32-byte DEK with kms:Encrypt.
SEALABLE_PROVIDERS = ("aws-kms", "gcp-kms")

SECRET_ENV_BUNDLE_EXTRA_KEY = "SECRET_ENV_BUNDLE_B64"
SECRET_ENV_FLAG_EXTRA_KEY = "SECRET_ENV"
BUNDLE_ALG = "AES-256-GCM"


class SecretEnvError(ValueError):
    """Raised on a malformed --secrets-env file or unsupported provider."""


def load_dotenv_plaintext(path: str) -> bytes:
    """Read + lightly validate a dotenv file, returning its raw bytes.

    We do not parse/normalise the file (the app may rely on exact
    formatting); we only sanity-check that it is non-empty text with at
    least one ``KEY=VALUE`` line so an obvious mistake (binary blob, JSON,
    empty file) fails fast at deploy rather than silently in the TEE.
    """
    if not os.path.isfile(path):
        raise SecretEnvError(f"--secrets-env file not found: {path}")
    with open(path, "rb") as f:
        raw = f.read()
    if not raw.strip():
        raise SecretEnvError(f"--secrets-env file is empty: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretEnvError(f"--secrets-env must be UTF-8 dotenv text: {exc}")
    has_assignment = any(
        ("=" in ln and not ln.lstrip().startswith("#"))
        for ln in text.splitlines()
    )
    if not has_assignment:
        raise SecretEnvError(
            "--secrets-env has no KEY=VALUE lines; expected a dotenv file")
    return raw


def _kms_wrap_dek(
    dek: bytes,
    *,
    provider: str,
    key_id: str,
    region: str,
    encryption_context: Dict[str, str],
    kms_client: Any = None,
) -> str:
    """KMS-encrypt the 32-byte DEK; returns base64 ciphertext.

    ``kms_client`` is injectable for tests. When omitted, a boto3 (aws-kms)
    or google-cloud-kms (gcp-kms) client is constructed lazily.
    """
    if provider == "aws-kms":
        client = kms_client
        if client is None:
            import boto3  # lazy: only needed for a real seal
            client = boto3.client("kms", region_name=region or None)
        resp = client.encrypt(
            KeyId=key_id,
            Plaintext=dek,
            EncryptionContext=encryption_context or {},
        )
        blob = resp["CiphertextBlob"]
        return base64.b64encode(blob).decode("ascii")
    if provider == "gcp-kms":
        client = kms_client
        if client is None:
            # A bare lazy import here surfaced as an unhandled
            # `ModuleNotFoundError: No module named 'google'` traceback partway
            # through a real deploy, after the image build and vulnerability
            # scan had already run.  `core.keys.gcp_kms` guards the same import;
            # this one did not.
            try:
                from google.cloud import kms as gcp_kms  # lazy
            except ImportError as exc:
                raise SecretEnvError(
                    "--byok gcp-kms needs the google-cloud-kms client to wrap "
                    "the DEK, and it is not importable here. It is a declared "
                    "dependency, so this usually means an editable install "
                    "predating it or a stale CLI image: reinstall with "
                    "`pip install -e apps/cli`, or rebuild the container with "
                    "`make docker-build-cli`."
                ) from exc
            client = gcp_kms.KeyManagementServiceClient()
        resp = client.encrypt(request={"name": key_id, "plaintext": dek})
        return base64.b64encode(resp.ciphertext).decode("ascii")
    raise SecretEnvError(
        f"--secrets-env requires a sealable BYOK provider {SEALABLE_PROVIDERS}; "
        f"got {provider!r}")


def seal_secret_env(
    plaintext: bytes,
    *,
    provider: str,
    key_id: str,
    region: str = "",
    encryption_context: Optional[Dict[str, str]] = None,
    kms_client: Any = None,
    dek: Optional[bytes] = None,
) -> str:
    """Envelope-seal ``plaintext`` -> base64 bundle string.

    The bundle is ``{alg, env_nonce_b64, env_ct_b64, wrapped_dek_b64,
    enc_ctx}`` JSON, base64-encoded. ``dek`` is injectable for deterministic
    tests; otherwise a fresh 32-byte key is generated.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if provider not in SEALABLE_PROVIDERS:
        raise SecretEnvError(
            f"--secrets-env requires --byok one of {SEALABLE_PROVIDERS} "
            f"(attestation-gated wrap); got {provider!r}")
    if not key_id:
        raise SecretEnvError("--secrets-env requires a BYOK key_id to wrap the data key")

    enc_ctx = dict(encryption_context or {})
    dek = dek or os.urandom(32)
    nonce = os.urandom(12)
    # Bind the ciphertext to the encryption context (defence in depth).
    aad = json.dumps(enc_ctx, sort_keys=True).encode("utf-8") if enc_ctx else b""
    env_ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    wrapped_dek_b64 = _kms_wrap_dek(
        dek, provider=provider, key_id=key_id, region=region,
        encryption_context=enc_ctx, kms_client=kms_client,
    )
    bundle = {
        "alg": BUNDLE_ALG,
        "env_nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "env_ct_b64": base64.b64encode(env_ct).decode("ascii"),
        "wrapped_dek_b64": wrapped_dek_b64,
        "enc_ctx": enc_ctx,
    }
    return base64.b64encode(json.dumps(bundle).encode("utf-8")).decode("ascii")


# Path the baked plaintext .env (no-BYOK mode) is written to in the build dir.
# The in-TEE entrypoint sources this alongside the runtime-decrypted tmpfs copy.
BUILD_APP_ENV_FILE = "app.env"


def ensure_build_app_env(build_dir: str) -> str:
    """Guarantee ``<build_dir>/app.env`` exists (possibly empty).

    The container overlay always ``COPY``s this file, so it must exist even
    when no ``--secrets-env`` was given. Returns the path.
    """
    os.makedirs(build_dir, exist_ok=True)
    path = os.path.join(build_dir, BUILD_APP_ENV_FILE)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("# tee-crafter app env (empty: no --secrets-env supplied)\n")
        os.chmod(path, 0o600)
    return path


# Platforms where runtime delivery to the workload is wired.
#   * CVM (snp/tdx/gpu): the ``tee-crafter-secrets.service`` oneshot copies the
#     baked ``app.env`` (or attested-unseals the sealed bundle) to
#     ``/run/tee_crafter/app.env`` before the container starts (--env-file).
#   * Nitro: the EIF entrypoint sources ``/tee-crafter-runtime/app.env``
#     (baked).  Sealed Nitro needs NSM recipient-unwrap (not yet supported).
_CVM_DELIVERS = frozenset({
    "snp-aws", "snp-azure", "snp-gcp",
    "tdx-azure", "tdx-gcp",
    "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
})


def _is_delivered(tee_platform: str, mode: str) -> bool:
    platform = (tee_platform or "").lower()
    if platform in _CVM_DELIVERS:
        return True  # secrets oneshot handles both baked + sealed
    if platform.startswith("nitro"):
        return mode == "plaintext"  # baked sources app.env; sealed unsupported
    return False  # SGX: no secrets oneshot


def _record_delivery(audit: Any, *, tee_platform: str, mode: str) -> None:
    """Record BYOK-014: does this platform/mode deliver the .env at runtime?"""
    if audit is None:
        return
    delivered = _is_delivered(tee_platform, mode)
    try:
        audit.record_check(
            "BYOK", "Sealed/baked .env delivered to workload at runtime",
            "BYOK-014", expected=True, observed=delivered,
            note=(f"{mode} mode on {tee_platform or 'unknown'}: "
                  + ("delivered via secrets oneshot / EIF entrypoint"
                     if delivered else
                     "NOT delivered (carry config in Dockerfile ENV)")))
    except Exception:
        pass


def _warn_undelivered(console: Any, *, tee_platform: str, mode: str) -> None:
    """Warn only when the chosen secret-env path will NOT reach the workload.

    Delivery is wired for all CVM platforms (via the secrets oneshot) and for
    Nitro baked mode (entrypoint sources the baked file).  The remaining gaps
    are Nitro **sealed** (needs NSM recipient-unwrap) and SGX (no oneshot).
    """
    if _is_delivered(tee_platform, mode) or console is None:
        return
    platform = (tee_platform or "").lower()
    if platform.startswith("nitro") and mode == "sealed":
        reason = ("sealed (BYOK) .env on Nitro requires NSM recipient-unwrap, "
                  "which is not yet supported")
    else:
        reason = (f"runtime delivery to the workload is not wired on "
                  f"{platform or 'this platform'}")
    try:
        console.print(
            f"[yellow]⚠ --secrets-env: the .env was {mode} successfully, but "
            f"{reason}. The workload will NOT see these variables at runtime. "
            f"Carry runtime config the container needs in your Dockerfile "
            f"(ENV) for now; sealed mode still guarantees build-time "
            f"confidentiality. See docs/cli_reference.md (--secrets-env).[/yellow]")
    except Exception:
        pass


def apply_secret_env(
    build_dir: str,
    *,
    secrets_env_path: str,
    byok_config: Any = None,
    audit: Any = None,
    console: Any = None,
    kms_client: Any = None,
    tee_platform: str = "",
) -> str:
    """Deliver ``--secrets-env`` into the TEE. BYOK optional.

    Two modes, both surfaced to the app at ``/run/tee_crafter/app.env``:

    * **Sealed (BYOK aws-kms / gcp-kms):** envelope-seal the ``.env`` to the
      BYOK key; the bundle rides the tmpfs ``byok.env`` and the in-TEE
      bootstrap attested-decrypts it at runtime. Cleartext never on disk /
      image. Recorded as ``BYOK-012``.
    * **Plaintext (no BYOK, or a non-sealable provider):** the ``.env`` is
      written to ``<build_dir>/app.env`` and baked into the **measured** TEE
      image (part of the attested boundary, never exposed to clients, but it
      does live in the image artifact). Suitable for non-secret config; for
      true secrets use ``--byok aws-kms``/``gcp-kms``.

    Returns the mode string (``"sealed"`` / ``"plaintext"``). Raises
    :class:`SecretEnvError` on a malformed file.
    """
    plaintext = load_dotenv_plaintext(secrets_env_path)
    provider = getattr(byok_config, "provider", "none") or "none"
    app_env_path = ensure_build_app_env(build_dir)

    if provider in SEALABLE_PROVIDERS:
        bundle_b64 = seal_secret_env(
            plaintext,
            provider=provider,
            key_id=getattr(byok_config, "key_id", ""),
            region=getattr(byok_config, "region", ""),
            encryption_context=getattr(byok_config, "encryption_context", {}) or {},
            kms_client=kms_client,
        )
        extra = getattr(byok_config, "extra", None)
        if extra is None:
            extra = {}
            byok_config.extra = extra
        extra[SECRET_ENV_BUNDLE_EXTRA_KEY] = bundle_b64
        extra[SECRET_ENV_FLAG_EXTRA_KEY] = "1"
        # Sealed mode: keep the baked file empty (no plaintext on disk/image).
        if audit is not None:
            try:
                audit.record(
                    "BYOK", "Sealed application .env to BYOK key (attestation-gated)",
                    "info", provider=provider, bytes_sealed=len(plaintext),
                    bundle_bytes=len(bundle_b64))
                audit.record_check(
                    "BYOK", "Application .env envelope-sealed to BYOK key",
                    "BYOK-012", expected=True, observed=True,
                    note=f"{provider}: envelope AES-256-GCM + KMS-wrapped DEK; "
                         "attested unseal to /run/tee_crafter/app.env by the "
                         "tee-crafter-secrets oneshot on CVM (fail-closed)")
            except Exception:
                pass
        if console is not None:
            try:
                console.print(
                    f"[dim]Sealed {len(plaintext)} B .env to {provider} "
                    f"(attestation-gated; tmpfs-only in TEE)[/dim]")
            except Exception:
                pass
        _record_delivery(audit, tee_platform=tee_platform, mode="sealed")
        _warn_undelivered(console, tee_platform=tee_platform, mode="sealed")
        return "sealed"

    # Plaintext mode (no BYOK / non-sealable provider): bake into measured image.
    with open(app_env_path, "wb") as f:
        f.write(plaintext if plaintext.endswith(b"\n") else plaintext + b"\n")
    os.chmod(app_env_path, 0o600)
    if audit is not None:
        try:
            audit.record(
                "BYOK", "Staged plaintext .env into measured TEE image "
                "(not attestation-sealed)", "info",
                provider=provider, bytes_staged=len(plaintext),
                advice="use --byok aws-kms/gcp-kms to attestation-seal secrets")
        except Exception:
            pass
    if console is not None:
        try:
            console.print(
                f"[dim]Staged {len(plaintext)} B .env into the measured image "
                f"(plaintext — use --byok aws-kms/gcp-kms to seal secrets)[/dim]")
        except Exception:
            pass
    _record_delivery(audit, tee_platform=tee_platform, mode="plaintext")
    _warn_undelivered(console, tee_platform=tee_platform, mode="plaintext")
    return "plaintext"
