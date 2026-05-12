"""In-TEE runtime bootstrap for SIEM exporters and BYOK key release.

This module is staged verbatim into every build so the running enclave /
CVM imports the SAME continuous-attestation and key-release machinery
the build host validated against.  Application templates call:

* :func:`bootstrap_continuous_attestation` -- starts the background
  signed-event exporter described by ``siem.env`` (written by
  :mod:`tee_crafter.cli.commands.deploy.siem_mode`).
* :func:`bootstrap_chain_commitment` -- publishes the runtime audit
  log's genesis commitment to tmpfs so the SIEM sidecar can attach it to
  every attestation event.  Binding that same value into the hardware
  quote is done by the per-platform app templates, which fold it into the
  length-prefixed ``tee-crafter/attest-binding/v2`` preimage they hash
  into ``report_data`` (Nitro carries it in the document ``nonce``).
  There used to be an ``attestation_report_data()`` helper here proposing
  a different scheme -- 32 bytes of key binding followed by 32 raw bytes
  of commitment.  It had no callers, it did not match what any template
  does, and the split layout could not defend against a field-splicing
  attack the way the length-prefixed preimage does, so it was removed
  rather than left for the next reader to implement.
* :func:`bootstrap_byok_release` -- if ``byok.env`` is present, runs an
  attestation-gated key release against the configured KMS adapter and
  drops the released DEK at ``$TEE_CRAFTER_BYOK_DEK_PATH`` (tmpfs, 0600)
  so the user app can ``open()`` it without speaking to the cloud KMS
  itself.

Both functions are best-effort and never raise into the caller: they
fall open with a logged warning when the configuration is malformed or
absent so the workload still starts (the operator's audit trail will
record the failure).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("tee_crafter.runtime_bootstrap")

# We import lazily so that platforms that strip the full tee_crafter
# package (Gramine SGX, minimal CVM rootfs) only fail when the operator
# actually opted into SIEM/BYOK.

def _try_import_audit():
    try:
        from tee_crafter.core.audit.continuous import ContinuousAttestor  # type: ignore
        return ContinuousAttestor
    except Exception:
        # Fall back to the local copy that the builder will have placed
        # next to this file in stripped TEEs.
        sys.path.insert(0, os.path.dirname(__file__))
        try:
            from continuous import ContinuousAttestor  # type: ignore
            return ContinuousAttestor
        except Exception:
            return None


def _try_import_keys():
    try:
        from tee_crafter.core.keys.spec import (  # type: ignore
            AttestedKeyRef, KeyProvider, KeyReleasePolicy, UnwrapAlgorithm,
        )
        from tee_crafter.core.keys.release import KeyReleaseOrchestrator, AttestationProvider
        from tee_crafter.core.keys.aws_kms import AwsKmsAdapter
        from tee_crafter.core.keys.azure_kv import AzureKeyVaultAdapter
        from tee_crafter.core.keys.azure_skr_tool import AzureSkrToolAdapter
        from tee_crafter.core.keys.gcp_kms import GcpKmsAdapter
        from tee_crafter.core.keys.external_hsm import ExternalHsmAdapter
        return {
            "AttestedKeyRef": AttestedKeyRef, "KeyProvider": KeyProvider,
            "KeyReleasePolicy": KeyReleasePolicy, "UnwrapAlgorithm": UnwrapAlgorithm,
            "Orchestrator": KeyReleaseOrchestrator,
            "AttestationProvider": AttestationProvider,
            "AwsKmsAdapter": AwsKmsAdapter,
            "AzureKeyVaultAdapter": AzureKeyVaultAdapter,
            "AzureSkrToolAdapter": AzureSkrToolAdapter,
            "GcpKmsAdapter": GcpKmsAdapter,
            "ExternalHsmAdapter": ExternalHsmAdapter,
        }
    except Exception as exc:
        logger.info("BYOK modules not available in TEE: %r", exc)
        return None


# ---------------------------------------------------------------------------
# SIEM bootstrap
# ---------------------------------------------------------------------------

def _build_exporter_from_env(provider: str):
    """Construct the right :class:`AuditEventExporter` from env vars."""
    if provider == "syslog-cef":
        from tee_crafter.core.audit.exporters.syslog import SyslogCefExporter
        return SyslogCefExporter(
            host=os.environ.get("TEE_CRAFTER_SIEM_HOST", "localhost"),
            port=int(os.environ.get("TEE_CRAFTER_SIEM_PORT", "514")),
            protocol=os.environ.get("TEE_CRAFTER_SIEM_PROTOCOL", "tcp"),
            facility=int(os.environ.get("TEE_CRAFTER_SIEM_FACILITY", "13")),
            hostname=os.environ.get("TEE_CRAFTER_SIEM_HOSTNAME", ""),
        )
    if provider == "splunk-hec":
        from tee_crafter.core.audit.exporters.splunk_hec import SplunkHecExporter
        # extra.verify_ssl=0 disables TLS verification for the HEC POST.
        # Required when Splunk presents the default self-signed dev cert
        # (the local siem-sandbox/splunk/ docker-compose, or any Fargate
        # deployment that hasn't yet wired ACM in front of the HEC port).
        verify_raw = os.environ.get("TEE_CRAFTER_SIEM_X_VERIFY_SSL", "").strip().lower()
        verify_ssl = verify_raw not in ("0", "false", "no", "off")
        return SplunkHecExporter(
            endpoint=os.environ["TEE_CRAFTER_SIEM_ENDPOINT"],
            token=os.environ["TEE_CRAFTER_SIEM_TOKEN"],
            index=os.environ.get("TEE_CRAFTER_SIEM_INDEX", "main"),
            sourcetype=os.environ.get(
                "TEE_CRAFTER_SIEM_SOURCETYPE", "tee_crafter:attestation"),
            source=os.environ.get("TEE_CRAFTER_SIEM_SOURCE", "tee-crafter"),
            verify_ssl=verify_ssl,
        )
    if provider == "datadog":
        from tee_crafter.core.audit.exporters.datadog import DatadogLogsExporter
        return DatadogLogsExporter(
            api_key=os.environ["TEE_CRAFTER_SIEM_API_KEY"],
            site=os.environ.get("TEE_CRAFTER_SIEM_SITE", "datadoghq.com"),
            service=os.environ.get("TEE_CRAFTER_SIEM_SERVICE", "tee-crafter"),
            ddsource=os.environ.get("TEE_CRAFTER_SIEM_DDSOURCE", "tee-crafter"),
            env=os.environ.get("TEE_CRAFTER_SIEM_ENV", "prod"),
        )
    if provider == "azure-monitor":
        from tee_crafter.core.audit.exporters.azure_monitor import AzureMonitorExporter
        bearer = os.environ.get("TEE_CRAFTER_SIEM_BEARER", "")
        # The bearer token is normally fetched via IMDS at runtime; we
        # accept either a static token for tests or an IMDS fetcher.
        if bearer:
            def _provider(): return bearer
        else:
            def _provider():
                import urllib.request
                req = urllib.request.Request(
                    "http://169.254.169.254/metadata/identity/oauth2/token"
                    "?api-version=2018-02-01&resource=https://monitor.azure.com/",
                    headers={"Metadata": "true"},
                )
                with urllib.request.urlopen(req, timeout=3) as r:
                    return json.loads(r.read())["access_token"]
        return AzureMonitorExporter(
            dce_url=os.environ["TEE_CRAFTER_SIEM_DCE_URL"],
            dcr_immutable_id=os.environ["TEE_CRAFTER_SIEM_DCR_IMMUTABLE_ID"],
            stream_name=os.environ["TEE_CRAFTER_SIEM_STREAM_NAME"],
            bearer_token_provider=_provider,
        )
    if provider == "cloudwatch":
        from tee_crafter.core.audit.exporters.cloudwatch import CloudWatchLogsExporter
        return CloudWatchLogsExporter(
            log_group=os.environ["TEE_CRAFTER_SIEM_LOG_GROUP"],
            log_stream=os.environ["TEE_CRAFTER_SIEM_LOG_STREAM"],
            region=os.environ.get("TEE_CRAFTER_SIEM_REGION", "").strip() or None,
        )
    raise ValueError(f"unsupported SIEM provider {provider!r}")


def bootstrap_continuous_attestation(
    *,
    attest: Callable[[bytes], bytes],
    instance_id: str = "",
    tee_platform: str = "",
    pipeline_version: str = "",
):
    """Start a :class:`ContinuousAttestor` driven by ``siem.env``.

    Returns the running attestor (so the caller can ``stop()`` it on
    shutdown) or ``None`` when SIEM export is disabled.

    ``attest`` is a platform-specific closure: ``attest(nonce_bytes) ->
    attestation_blob_bytes``.  The bootstrap module never builds this
    itself because the platform owns the actual TEE-Specific paths
    (Nitro NSM, SNP /dev/sev-guest, TDX /dev/tdx-guest, Azure ATR,
    GCP TPM).
    """
    enabled = os.environ.get("TEE_CRAFTER_SIEM_ENABLED", "0").strip().lower(
    ) in ("1", "true", "yes", "y", "on")
    provider = (os.environ.get("TEE_CRAFTER_SIEM", "none") or "none").lower()
    if not enabled or provider == "none":
        return None

    Cont = _try_import_audit()
    if Cont is None:
        logger.warning("SIEM enabled but tee_crafter.core.audit not importable; skipping")
        return None
    try:
        exp = _build_exporter_from_env(provider)
    except Exception as exc:
        logger.warning("SIEM exporter %s failed to construct: %r", provider, exc)
        return None

    interval = int(os.environ.get("TEE_CRAFTER_SIEM_INTERVAL_SECONDS", "60"))
    attestor = Cont(
        attest=attest, exporters=[exp], interval_seconds=interval,
        instance_id=instance_id, tee_platform=tee_platform,
        pipeline_version=pipeline_version,
    )
    attestor.start()
    logger.info("Continuous attestation -> %s every %ds", provider, interval)
    return attestor


# ---------------------------------------------------------------------------
# BYOK bootstrap
# ---------------------------------------------------------------------------

def _parse_csv(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    return [x for x in (s.strip() for s in raw.split(",")) if x]


def _parse_kv_csv(name: str) -> Dict[str, str]:
    raw = os.environ.get(name, "")
    out: Dict[str, str] = {}
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece or "=" not in piece:
            continue
        k, v = piece.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _build_orchestrator(mods: Dict[str, Any], attestation_provider, audit):
    KeyProvider = mods["KeyProvider"]
    KeyReleasePolicy = mods["KeyReleasePolicy"]
    Orchestrator = mods["Orchestrator"]
    provider_name = (os.environ.get("TEE_CRAFTER_BYOK", "none") or "none").lower()
    if provider_name == "aws-kms":
        # No region fallback here: build_byok_config().validate() already
        # refuses aws-kms without one, so an empty value means something is
        # wrong upstream and boto3's own resolution is a better answer than a
        # hardcoded region that happens to be where this was first tested.
        adapter = mods["AwsKmsAdapter"](
            region=os.environ.get("TEE_CRAFTER_BYOK_REGION", "").strip(),
        )
        provider = KeyProvider.AWS_KMS
    elif provider_name == "azure-kv":
        # Kept for flows where we genuinely hold the recipient private key (an
        # external HSM, or tests).  On an Azure CVM this returns
        # ``plaintext=None`` and the caller refuses -- correctly: the key Key
        # Vault wraps to is sealed to the vTPM, so no Python process can unwrap
        # it.  ``azure-skr`` is the setting that works there.
        adapter = mods["AzureKeyVaultAdapter"]()
        provider = KeyProvider.AZURE_KEY_VAULT
    elif provider_name == "azure-skr":
        adapter = mods["AzureSkrToolAdapter"]()
        provider = KeyProvider.AZURE_KEY_VAULT
    elif provider_name == "gcp-kms":
        adapter = mods["GcpKmsAdapter"]()
        provider = KeyProvider.GCP_KMS
    elif provider_name == "external-hsm":
        adapter = mods["ExternalHsmAdapter"](
            endpoint=os.environ["TEE_CRAFTER_BYOK_HSM_ENDPOINT"],
            bearer_token=os.environ.get("TEE_CRAFTER_BYOK_HSM_BEARER", ""),
        )
        provider = KeyProvider.EXTERNAL_HSM
    else:
        return None

    policy = KeyReleasePolicy(
        max_attestation_age_seconds=int(
            os.environ.get("TEE_CRAFTER_BYOK_MAX_AGE", "300")),
        allowed_measurement_sha256=_parse_csv(
            "TEE_CRAFTER_BYOK_ALLOWED_MEASUREMENTS"),
        # On unless explicitly switched off: an unrecognised spelling must not
        # be what drops the signed-audit requirement before a key release.
        require_signed_audit=os.environ.get(
            "TEE_CRAFTER_BYOK_REQUIRE_SIGNED_AUDIT", "1").strip().lower()
        not in ("0", "false", "no", "n", "off"),
        require_encryption_context_keys=_parse_csv(
            "TEE_CRAFTER_BYOK_REQUIRED_CONTEXT_KEYS"),
    )
    return Orchestrator(
        attestation_provider=attestation_provider,
        adapters={provider: adapter},
        policy=policy,
        audit=audit,
    ), provider


class _InTeeAuditSink:
    """Adapt the in-TEE HMAC-chained audit log to the ``.record()`` interface
    ``KeyReleaseOrchestrator`` expects.

    ``core.keys.release`` is written against the operator-side
    ``BuildAuditTrail``.  Inside the enclave that class does not exist, but the
    guarantee it provides — an append-only, tamper-evident record of every key
    release — does, via ``tee_crafter_audit_logger``.  This maps one onto the
    other.

    Failures propagate deliberately.  ``_record_audit`` treats a sink error as
    fatal under ``require_signed_audit``, which is the whole point of the
    policy: swallowing it here would silently reopen the gap.
    """

    def record(self, phase: str, name: str, status: str, **details) -> None:
        from tee_crafter_audit_logger import log_request  # local: staged beside us
        # Key material never reaches the log — ``release._record_audit`` passes
        # only non-secret identifiers (provider, region, label, key-id tail).
        payload = json.dumps(
            {"phase": phase, "name": name, **details},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        log_request(
            request_bytes=payload,
            response_bytes=b"",
            action="key_release",
            status=status,
            extra={"phase": phase, "name": name, **details},
        )


def bootstrap_byok_release(
    *,
    attestation_provider,
    audit=None,
    write_dek: bool = True,
) -> Optional[Tuple[Any, Any]]:
    """Run an attestation-gated key release described by ``byok.env``.

    Returns ``(material, key_ref)`` on success; ``None`` when BYOK is
    disabled or the release fails (the failure is recorded in the audit
    trail).  If *write_dek* is True and the released material contains
    plaintext bytes, they are atomically written to
    ``$TEE_CRAFTER_BYOK_DEK_PATH`` (tmpfs-backed, 0600) and the path is
    set in the environment for the user app to consume.
    """
    enabled = os.environ.get("TEE_CRAFTER_BYOK_ENABLED", "0").strip().lower(
    ) in ("1", "true", "yes", "y", "on")
    provider_name = (os.environ.get("TEE_CRAFTER_BYOK", "none") or "none").lower()
    if not enabled or provider_name == "none":
        return None

    mods = _try_import_keys()
    if mods is None:
        logger.warning("BYOK enabled but tee_crafter.core.keys not importable; skipping")
        return None

    if audit is None:
        # ``KeyReleasePolicy.require_signed_audit`` defaults to True and
        # ``KeyReleaseOrchestrator`` refuses to construct without a sink — an
        # audit entry that never landed is indistinguishable from a release
        # that never happened.  The in-TEE boot path has no BuildAuditTrail
        # (that lives on the operator's workstation), so without this adapter
        # every ``--byok`` deployment would fail closed at boot.
        #
        # The in-TEE HMAC-chained request log is the right sink here: it is
        # the same append-only chain the attestation monitor and SIEM exporter
        # read, so a key release becomes a first-class, verifiable event rather
        # than a line in stderr.
        audit = _InTeeAuditSink()

    AttestedKeyRef = mods["AttestedKeyRef"]
    UnwrapAlgorithm = mods["UnwrapAlgorithm"]

    try:
        orchestrator, provider = _build_orchestrator(mods, attestation_provider, audit)
    except Exception as exc:
        logger.warning("BYOK orchestrator construction failed: %r", exc)
        return None

    try:
        unwrap = UnwrapAlgorithm(
            os.environ.get("TEE_CRAFTER_BYOK_UNWRAP", "direct_bytes"))
    except Exception:
        unwrap = UnwrapAlgorithm.DIRECT_BYTES

    key_ref = AttestedKeyRef(
        provider=provider,
        key_id=os.environ.get("TEE_CRAFTER_BYOK_KEY_ID", ""),
        region=os.environ.get("TEE_CRAFTER_BYOK_REGION", ""),
        unwrap=unwrap,
        label=os.environ.get("TEE_CRAFTER_BYOK_LABEL", ""),
        extra={k[len("TEE_CRAFTER_BYOK_X_"):].lower(): v
               for k, v in os.environ.items()
               if k.startswith("TEE_CRAFTER_BYOK_X_")},
    )

    enc_ctx = _parse_kv_csv("TEE_CRAFTER_BYOK_ENCRYPTION_CONTEXT")

    try:
        material = orchestrator.release(
            key_ref, encryption_context=enc_ctx or None)
    except Exception as exc:
        logger.warning("BYOK release failed: %r", exc)
        return None

    # NitroTPM release returns a CMS envelope encrypted to the public key the
    # attestation provider put inside the document, so the unwrap has to happen
    # here, holding that provider's private half. Without this the release
    # succeeds and then reports "wrapped key with no plaintext" below -- the
    # measurement gate would work and the DEK still would not arrive.
    if (material.plaintext is None
            and getattr(material, "wrapped_for_recipient", None)
            and unwrap == UnwrapAlgorithm.AWS_NITROTPM_RECIPIENT):
        private_key = getattr(attestation_provider, "recipient_private_key", None)
        if private_key is None:
            logger.error(
                "BYOK unwrap=aws_nitrotpm_recipient but the attestation "
                "provider exposes no recipient_private_key, so the CMS envelope "
                "KMS returned cannot be opened. Expected "
                "NitroTpmAttestationProvider.")
            return None
        try:
            from tee_crafter.core.keys.nitrotpm import (
                decrypt_ciphertext_for_recipient,
            )
            material.plaintext = decrypt_ciphertext_for_recipient(
                material.wrapped_for_recipient, private_key)
            logger.info(
                "BYOK NitroTPM release unwrapped: KMS accepted the attestation "
                "document and the DEK was decrypted in-TEE with the key inside "
                "it (gating=%s)", material.measurement_gate)
        except Exception as exc:
            logger.error("BYOK NitroTPM CMS unwrap failed: %r", exc)
            return None

    if write_dek and material.plaintext is None:
        # Do not fall through to the "BYOK released ... for user app" log below.
        # The adapter returned only `wrapped_for_recipient`, so there is no DEK
        # to stage and the app would start against a path that does not exist.
        # `azure-kv` always lands here: Key Vault SKR returns the key wrapped
        # under CKM_RSA_AES_KEY_WRAP and nothing in-TEE unwraps it yet.
        logger.error(
            "BYOK %s returned a wrapped key with no plaintext; %s cannot be "
            "staged. Sealed-env/DEK delivery is unavailable on this provider.",
            key_ref.provider.value, "TEE_CRAFTER_BYOK_DEK_PATH")
        return None

    if write_dek:
        path = os.environ.get(
            "TEE_CRAFTER_BYOK_DEK_PATH", "/run/tee_crafter/byok_dek.bin")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True, mode=0o700)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(material.plaintext)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            os.environ["TEE_CRAFTER_BYOK_DEK_PATH"] = path
        except Exception as exc:
            logger.warning("BYOK could not stage DEK at %s: %r", path, exc)

    logger.info("BYOK released %s (age=%.1fs, sha=%s) for user app",
                key_ref.short(), material.attestation_age_seconds,
                material.attestation_sha256[:12])
    return material, key_ref


def bootstrap_secret_env_release(
    *,
    attestation_provider,
    audit=None,
    env_path: str = "/run/tee_crafter/app.env",
    inject_environ: bool = True,
) -> Optional[Dict[str, str]]:
    """Decrypt the operator's sealed ``.env`` through the BYOK attestation gate.

    Reads ``TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64`` (an envelope bundle
    written by :mod:`secret_env`): the wrapped DEK is released by the same
    attestation-gated orchestrator BYOK uses, the AES-256-GCM ``.env`` payload
    is decrypted, and the cleartext is written to *env_path* (tmpfs, 0600) and
    optionally injected into ``os.environ``. Returns the parsed dict on success
    or ``None`` (disabled / failed; failures are logged + audited, never raised).
    """
    import base64 as _b64

    bundle_b64 = os.environ.get("TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64", "")
    if not bundle_b64:
        return None

    mods = _try_import_keys()
    if mods is None:
        logger.warning("sealed .env present but tee_crafter.core.keys missing; skipping")
        return None

    if audit is None:
        # Same reasoning as ``bootstrap_byok_release`` above, and the same sink.
        # This path did not default it, so with the shipped policy
        # (``require_signed_audit`` defaults to True) the orchestrator refused
        # to construct and every ``--secrets-env`` + ``--byok`` deploy failed
        # closed at boot with
        #
        #   sealed .env orchestrator construction failed: ValueError(
        #     'KeyReleasePolicy.require_signed_audit is set but no audit sink
        #      was passed to KeyReleaseOrchestrator(audit=...)')
        #
        # while the BYOK DEK release beside it succeeded — two call sites onto
        # one orchestrator, only one of them wired.  Observed on real GCP
        # hardware (snp-gcp and tdx-gcp) 2026-08-21: attestation verified, DEK
        # released, and the workload container still never started because its
        # secrets oneshot exited non-zero.
        audit = _InTeeAuditSink()

    try:
        built = _build_orchestrator(mods, attestation_provider, audit)
        if built is None:
            return None
        orchestrator, provider = built
    except Exception as exc:
        logger.warning("sealed .env orchestrator construction failed: %r", exc)
        return None

    try:
        bundle = json.loads(_b64.b64decode(bundle_b64).decode("utf-8"))
        wrapped_dek = bundle["wrapped_dek_b64"]
        nonce = _b64.b64decode(bundle["env_nonce_b64"])
        env_ct = _b64.b64decode(bundle["env_ct_b64"])
        enc_ctx = bundle.get("enc_ctx") or {}
    except Exception as exc:
        logger.warning("sealed .env bundle malformed: %r", exc)
        return None

    AttestedKeyRef = mods["AttestedKeyRef"]
    UnwrapAlgorithm = mods["UnwrapAlgorithm"]
    # The DEK is opaque bytes -> request DIRECT_BYTES so the orchestrator returns
    # plaintext (CVM/TLS path). Nitro Recipient mode returns wrapped-to-enclave
    # material that must be NSM-unwrapped (handled by the BYOK DEK path).
    key_ref = AttestedKeyRef(
        provider=provider,
        key_id=os.environ.get("TEE_CRAFTER_BYOK_KEY_ID", ""),
        region=os.environ.get("TEE_CRAFTER_BYOK_REGION", ""),
        unwrap=UnwrapAlgorithm.DIRECT_BYTES,
        label="sealed-env-dek",
        extra={"ciphertext_b64": wrapped_dek},
    )
    try:
        material = orchestrator.release(key_ref, encryption_context=enc_ctx or None)
    except Exception as exc:
        logger.warning("sealed .env DEK release failed: %r", exc)
        return None

    dek = getattr(material, "plaintext", None)
    if not dek:
        logger.warning("sealed .env: attested release returned no plaintext DEK "
                       "(recipient-unwrap path not supported for sealed .env yet)")
        return None

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aad = json.dumps(enc_ctx, sort_keys=True).encode("utf-8") if enc_ctx else b""
        plaintext = AESGCM(dek).decrypt(nonce, env_ct, aad)
    except Exception as exc:
        logger.warning("sealed .env payload decrypt failed: %r", exc)
        return None

    # Persist to tmpfs (0600) so the container launch can --env-file it, and
    # parse for in-process consumers.
    parsed: Dict[str, str] = {}
    for line in plaintext.decode("utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        parsed[k.strip()] = v.strip().strip('"').strip("'")

    try:
        os.makedirs(os.path.dirname(env_path), exist_ok=True, mode=0o700)
        tmp = env_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(plaintext if plaintext.endswith(b"\n") else plaintext + b"\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, env_path)
    except Exception as exc:
        logger.warning("sealed .env could not be staged at %s: %r", env_path, exc)

    if inject_environ:
        for k, v in parsed.items():
            os.environ.setdefault(k, v)

    logger.info("sealed .env released via attested gate: %d var(s) -> %s",
                len(parsed), env_path)
    if audit is not None:
        try:
            audit.record("BYOK", "Sealed .env released inside TEE", "info",
                         var_count=len(parsed), env_path=env_path)
        except Exception:
            pass
    return parsed


# ---------------------------------------------------------------------------
# AUD-3 genesis-commitment publication
# ---------------------------------------------------------------------------

def _try_import_audit_logger():
    try:
        import tee_crafter_audit_logger  # type: ignore
        return tee_crafter_audit_logger
    except Exception:
        sys.path.insert(0, os.path.dirname(__file__))
        try:
            import tee_crafter_audit_logger  # type: ignore
            return tee_crafter_audit_logger
        except Exception:
            return None


def bootstrap_chain_commitment() -> str:
    """Publish the runtime-audit-log chain-key commitment to tmpfs.

    ``tee_crafter_audit_logger`` keys its hash chain with a per-process
    secret that never touches disk, and writes a SHA-256 commitment to
    that key into the log's genesis entry.  Until this call existed the
    commitment had no reader outside the log itself, so replacing the log
    wholesale (new key, new genesis, new chain) was undetectable.
    Publishing it lets the SIEM sidecar attach it to every attestation
    event and lets the platform template bind it into ``report_data``.

    Returns the commitment hex, or ``""`` when the audit logger is not
    staged in this image.
    """
    mod = _try_import_audit_logger()
    if mod is None:
        logger.info("runtime audit logger not staged; no chain commitment")
        return ""
    try:
        return mod.publish_chain_key_commitment()
    except Exception as exc:
        logger.warning("chain-commitment publication failed: %r", exc)
        return ""


def bootstrap_all(
    *,
    attest_callable: Callable[[bytes], bytes],
    attestation_provider=None,
    instance_id: str = "",
    tee_platform: str = "",
    pipeline_version: str = "",
    audit=None,
):
    """One-call setup: starts continuous attestation export AND runs BYOK.

    Returns ``{"attestor": <ContinuousAttestor or None>,
    "byok": (material, key_ref) or None,
    "chain_key_commitment": <hex or "">}``.

    The user-facing app templates call this near the top of ``main()``.
    Both halves are best-effort; failures are logged and skipped so a
    misconfigured exporter cannot wedge a production workload.
    """
    out: Dict[str, Any] = {"attestor": None, "byok": None}
    # Publish the audit-log genesis commitment BEFORE the SIEM loop
    # starts so the very first exported event already carries it.
    out["chain_key_commitment"] = bootstrap_chain_commitment()
    try:
        out["attestor"] = bootstrap_continuous_attestation(
            attest=attest_callable, instance_id=instance_id,
            tee_platform=tee_platform, pipeline_version=pipeline_version,
        )
    except Exception as exc:
        logger.warning("continuous attestation bootstrap failed: %r", exc)
    if attestation_provider is not None:
        try:
            out["byok"] = bootstrap_byok_release(
                attestation_provider=attestation_provider, audit=audit)
        except Exception as exc:
            logger.warning("BYOK bootstrap failed: %r", exc)
        try:
            out["secret_env"] = bootstrap_secret_env_release(
                attestation_provider=attestation_provider, audit=audit)
        except Exception as exc:
            logger.warning("sealed .env bootstrap failed: %r", exc)
    return out
