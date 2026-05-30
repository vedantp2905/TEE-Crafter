"""CLI plumbing for BYOK / customer-managed keys with attestation-gated release.

Public CLI surface is just ``--byok <provider>`` + ``--byok-config
<path/to/policy.json>``.  This module loads the JSON document into a
:class:`ByokConfig`, validates it, writes ``byok.json`` + ``byok.env``
into the staged build directory (mirrored into ``build_dir/app/`` when
present), and records an audit entry.

In-TEE, ``tee_crafter.templates.common.tee_crafter_runtime_bootstrap``
reads the same env at startup and constructs the appropriate
:class:`KmsAdapter`, runs an attestation-gated ``release`` to materialize
the customer-managed DEK, and exposes it to the user app under
``TEE_CRAFTER_BYOK_DEK_PATH`` (a tmpfs-backed file).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


BYOK_PROVIDERS = (
    "none",
    "aws-kms",
    "azure-kv",
    # Azure Secure Key Release delegated to Microsoft's AzureAttestSKR.  A
    # separate provider rather than a mode of `azure-kv` because the two cannot
    # both work on the same platform: Key Vault wraps the released key to
    # `TpmEphemeralEncryptionKey`, whose private half is sealed to the vTPM, so
    # `azure-kv` returns no plaintext on a CVM.  See core/keys/azure_skr_tool.py.
    "azure-skr",
    "gcp-kms",
    "external-hsm",
)

#: Providers that release an Azure Key Vault / Managed HSM key and therefore
#: need the Key Vault network path opened.
_AZURE_KV_PROVIDERS = ("azure-kv", "azure-skr")

#: Platforms whose bake installs ``AzureAttestSKR``, i.e. the ones where
#: ``--byok azure-skr`` can actually run.
#:
#: All three Azure confidential-VM platforms.  This list used to be shorter:
#: the guest-attestation block lived only in
#: ``scripts/tdx_azure/setup_tdx.sh``, so ``snp-azure`` and ``gpu-cc-azure``
#: accepted ``--byok azure-skr`` at the CLI and then found no binary to call
#: inside the TEE — a fail-closed refusal, but at the worst possible moment.
#: It now comes from ``scripts/common/azure_guest_attestation.sh``, shared by
#: all three bakes.
AZURE_SKR_PLATFORMS = ("tdx-azure", "snp-azure", "gpu-cc-azure")


def azure_skr_prerequisite_error(provider: str, tee_platform: str) -> str:
    """Why ``--byok azure-skr`` cannot work here, or ``""`` if it can.

    Checked at build time rather than left to the in-TEE adapter, which also
    refuses but does so on a VM that has already been paid for.
    """
    if provider != "azure-skr":
        return ""
    if tee_platform and tee_platform not in AZURE_SKR_PLATFORMS:
        return (
            f"--byok azure-skr is an Azure confidential-VM mechanism and "
            f"{tee_platform} is not one.\n\n"
            f"It delegates key release to Microsoft's AzureAttestSKR, which "
            f"reads the vTPM-sealed TpmEphemeralEncryptionKey — a paravisor "
            f"key that only exists on {', '.join(AZURE_SKR_PLATFORMS)}.\n\n"
            f"For AWS use --byok aws-kms; for GCP use --byok gcp-kms."
        )
    endpoint = (os.environ.get("TEE_CRAFTER_MAA_ENDPOINT") or "").strip()
    if not endpoint:
        return (
            "TEE_CRAFTER_MAA_ENDPOINT is required for --byok azure-skr.\n\n"
            "AzureAttestSKR attests the VM to Microsoft Azure Attestation "
            "before Key Vault will release, and the Key Vault release policy "
            "names the MAA instance it trusts. There is no safe default for "
            "which authority gets to vouch for this VM.\n\n"
            "Set it to your provider, e.g. "
            "https://sharedwus.wus.attest.azure.net"
        )
    if not endpoint.startswith("https://"):
        return (
            f"TEE_CRAFTER_MAA_ENDPOINT must be an https:// URL, got "
            f"{endpoint!r}.\n\n"
            f"The attestation token authorises a key release; fetching it over "
            f"a channel an on-path attacker can rewrite defeats the point."
        )
    return ""

#: AWS platforms that are Nitro instances but not Nitro Enclaves, so they can
#: produce a NitroTPM attestation document once their AMI is registered with
#: TpmSupport=v2.0. nitro-aws is excluded: it uses the *Enclaves* condition
#: keys (kms:RecipientAttestation:PCR<n>), a different key hierarchy.
_NITROTPM_CAPABLE_PLATFORMS = frozenset({"snp-aws", "gpu-cc-aws"})

UNWRAP_MODES = (
    "direct_bytes",
    "aws_nitro_recipient",
    # Measurement-gated release on an ordinary (non-enclave) AWS CVM, via
    # kms:RecipientAttestation:NitroTPMPCR{4,7}. Opt-in rather than the default
    # for snp-aws, and deliberately so: the PCR conditions and the runtime
    # attaching an attestation document have to arrive together. KMS denies any
    # request whose Recipient lacks a document once those conditions are on the
    # key, so pinning one half alone takes BYOK from weakly-gated to broken.
    "aws_nitrotpm_recipient",
    "rsa_oaep_sha256",
)


# BYOK-SEC-1: env vars whose values are treated as bearer secrets or
# wrapped key material.  These are stripped from the public env file
# that survives on disk after deploy, and ONLY live in the tmpfs copy
# (``/run/tee-crafter-<platform>/byok.env``) — exact mirror of how
# ``siem_mode.SECRET_ENV_KEYS`` handles HEC tokens, API keys, etc.
#
#   * ``TEE_CRAFTER_BYOK_HSM_BEARER`` — bearer credential the external
#     HSM gateway uses to authenticate the in-TEE release request.
#     Equivalent to an API key.
#   * ``TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64`` — wrapped DEK ciphertext.
#     Not plaintext key material (it's encrypted to the customer's
#     KMS key), but a snapshot copy plus a leaked KMS key would let an
#     attacker reproduce the DEK off-box.  Treated as a secret on the
#     defence-in-depth principle that wrapped-key blobs should never
#     persist alongside the long-lived host disk.
#   * ``TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK`` — the DEK wrapped to the Azure
#     Key Vault key's public half, which ``AzureAttestSKR`` unwraps in-guest
#     after Secure Key Release.  Same reasoning as the ciphertext blob above:
#     encrypted, but it must not persist next to the host disk.
SECRET_ENV_KEYS = frozenset({
    "TEE_CRAFTER_BYOK_HSM_BEARER",
    "TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64",
    "TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK",
})


def is_byok_secret_key(key: str) -> bool:
    """Helper: is this env-var name a BYOK-bearer secret?

    Public so the deploy-time sidecar (mirrors SIEM-SEC-2) can find
    secrets without re-importing the dataclass.  Matches:

      * Anything in :data:`SECRET_ENV_KEYS` verbatim.
      * Any ``TEE_CRAFTER_BYOK_X_*`` extra whose name *suggests*
        sensitive material (``*CIPHERTEXT*``, ``*BEARER*``, ``*TOKEN*``,
        ``*PASSWORD*``, ``*KEY*``, ``*SECRET*``).  This is conservative
        on purpose — operators add provider-specific extras via the
        ``extra`` block, and we'd rather false-positive into tmpfs
        than false-negative onto disk.
    """
    if key in SECRET_ENV_KEYS:
        return True
    if not key.startswith("TEE_CRAFTER_BYOK_X_"):
        return False
    suffix = key[len("TEE_CRAFTER_BYOK_X_"):].upper()
    return any(marker in suffix for marker in (
        "CIPHERTEXT", "BEARER", "TOKEN", "PASSWORD", "SECRET", "API_KEY",
        "PRIVATE_KEY", "PASSPHRASE",
    ))


def split_byok_env_secrets(
    env_data: Dict[str, str],
) -> tuple[Dict[str, str], Dict[str, str]]:
    """Partition ``env_data`` into (secret, public) halves for BYOK-SEC-1.

    Public-half keys carry config that is innocuous if it leaks via a
    disk snapshot (provider name, KMS ARN, region, encryption-context
    keys, policy thresholds).  Secret-half keys hold bearer tokens or
    wrapped key material and only ever land in
    ``/run/tee-crafter-<platform>/byok.env`` (tmpfs).
    """
    secrets_env: Dict[str, str] = {}
    public_env: Dict[str, str] = {}
    for k, v in env_data.items():
        if is_byok_secret_key(k):
            secrets_env[k] = v
        else:
            public_env[k] = v
    return secrets_env, public_env


@dataclass
class ByokConfig:
    provider: str = "none"
    key_id: str = ""
    region: str = ""
    label: str = ""
    unwrap: str = "direct_bytes"

    # AWS-specific encryption context: comma-separated key=value pairs.
    encryption_context: Dict[str, str] = field(default_factory=dict)

    # Optional gateway URL for external-hsm provider.
    hsm_endpoint: str = ""
    hsm_bearer_token: str = ""

    # Policy fields used to build a KeyReleasePolicy.
    max_attestation_age_seconds: int = 300
    allowed_measurement_sha256: List[str] = field(default_factory=list)
    require_signed_audit: bool = True
    require_encryption_context_keys: List[str] = field(default_factory=list)

    # Where the bootstrap module should drop the released DEK
    # (tmpfs-backed, 0600).
    dek_path: str = "/run/tee_crafter/byok_dek.bin"

    # Provider-specific extras (AAD strings, project ids, ...).
    extra: Dict[str, str] = field(default_factory=dict)

    def validate(self) -> List[str]:
        """Validate the loaded ``--byok-config`` JSON.

        Error messages name the JSON keys that the policy file should
        contain (the per-field CLI flags ``--byok-key-id`` / ``--byok-region``
        / ``--byok-unwrap`` / ... are no longer part of the public CLI).
        """
        errs: List[str] = []
        if self.provider == "none":
            return errs
        if self.provider not in BYOK_PROVIDERS:
            errs.append(f"--byok must be one of {BYOK_PROVIDERS}")
            return errs
        if not self.key_id:
            errs.append("byok-config: 'key_id' is required for all real BYOK providers")
        if self.unwrap not in UNWRAP_MODES:
            errs.append(f"byok-config: 'unwrap' must be one of {UNWRAP_MODES}")
        if self.max_attestation_age_seconds <= 0:
            errs.append("byok-config: 'policy.max_attestation_age_seconds' must be > 0")
        for m in self.allowed_measurement_sha256:
            if len(m) != 64:
                errs.append(
                    f"byok-config: 'policy.allowed_measurement_sha256' entry "
                    f"{m!r} is not a 64-hex SHA-256"
                )
        if self.provider == "aws-kms" and not self.region:
            errs.append("byok-config: 'region' is required for aws-kms")
        if self.provider == "external-hsm":
            if not self.hsm_endpoint.startswith("https://"):
                errs.append("byok-config: 'hsm_endpoint' must be https://")
        if self.provider in _AZURE_KV_PROVIDERS and not (self.key_id.startswith("https://")):
            errs.append(f"byok-config: 'key_id' for {self.provider} must be a Key Vault key URL "
                        "(https://<vault>.managedhsm.azure.net/keys/<name>)")
        return errs

    def to_env(self) -> Dict[str, str]:
        e: Dict[str, str] = {
            "TEE_CRAFTER_BYOK": self.provider,
            "TEE_CRAFTER_BYOK_KEY_ID": self.key_id,
            "TEE_CRAFTER_BYOK_UNWRAP": self.unwrap,
            "TEE_CRAFTER_BYOK_DEK_PATH": self.dek_path,
            "TEE_CRAFTER_BYOK_MAX_AGE": str(self.max_attestation_age_seconds),
            "TEE_CRAFTER_BYOK_REQUIRE_SIGNED_AUDIT":
                "1" if self.require_signed_audit else "0",
        }
        if self.region:
            e["TEE_CRAFTER_BYOK_REGION"] = self.region
        if self.label:
            e["TEE_CRAFTER_BYOK_LABEL"] = self.label
        if self.hsm_endpoint:
            e["TEE_CRAFTER_BYOK_HSM_ENDPOINT"] = self.hsm_endpoint
        if self.hsm_bearer_token:
            e["TEE_CRAFTER_BYOK_HSM_BEARER"] = self.hsm_bearer_token
        if self.encryption_context:
            e["TEE_CRAFTER_BYOK_ENCRYPTION_CONTEXT"] = ",".join(
                f"{k}={v}" for k, v in sorted(self.encryption_context.items())
            )
        if self.allowed_measurement_sha256:
            e["TEE_CRAFTER_BYOK_ALLOWED_MEASUREMENTS"] = ",".join(
                self.allowed_measurement_sha256)
        if self.require_encryption_context_keys:
            e["TEE_CRAFTER_BYOK_REQUIRED_CONTEXT_KEYS"] = ",".join(
                self.require_encryption_context_keys)
        # azure-skr reads two more names at run time, and neither was being
        # emitted -- so the guest received a byok.env with the key id and the
        # unwrap mode but nothing to unwrap and no attestation authority.
        # Verified on hardware 2026-08-23: the tmpfs byok.env on a live
        # snp-azure CVM had TEE_CRAFTER_BYOK_KEY_ID and _UNWRAP but no wrapped
        # DEK, so `AzureAttestSKR` could not have run even once the attestation
        # provider was fixed.  Both are taken from this process's environment
        # because that is where the operator supplies them (they are not
        # --byok-config fields: the DEK ciphertext is per-deploy material and
        # the MAA endpoint is shared with the attestation path).
        #
        # Only for azure-skr: on every other provider these names are unused,
        # and emitting an empty value would make `byok_health` report a
        # configured-but-blank secret.
        if self.provider == "azure-skr":
            import os as _os
            _wrapped = (_os.environ.get(
                "TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK") or "").strip()
            if _wrapped:
                e["TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK"] = _wrapped
            _maa = (_os.environ.get("TEE_CRAFTER_MAA_ENDPOINT") or "").strip()
            if _maa:
                e["TEE_CRAFTER_MAA_ENDPOINT"] = _maa
        for k, v in (self.extra or {}).items():
            e[f"TEE_CRAFTER_BYOK_X_{k.upper()}"] = str(v)
        return e

    def describe(self) -> str:
        if self.provider == "none":
            return "BYOK disabled (TEE-Crafter ephemeral keys only)."
        return (f"{self.provider} key={self.key_id[-32:]} "
                f"region={self.region or '-'} unwrap={self.unwrap} "
                f"max_age={self.max_attestation_age_seconds}s "
                f"allowlist={len(self.allowed_measurement_sha256)} "
                f"context_keys={','.join(self.require_encryption_context_keys) or '-'}")


def _parse_kv_list(values: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for v in values or []:
        if "=" not in v:
            raise ValueError(f"expected key=value, got {v!r}")
        k, val = v.split("=", 1)
        out[k.strip()] = val.strip()
    return out


def export_byok_tf_vars(cfg: ByokConfig, tee_platform: str) -> Dict[str, str]:
    """Auto-export the ``TF_VAR_*`` variables that the IaC templates rely on
    when BYOK is active.

    The instance role attached to ``snp-aws`` / ``gpu-cc-aws`` only gains
    ``kms:Decrypt`` on the customer key when terraform sees
    ``TF_VAR_byok_aws_kms_arn``.  Without it, the IAM policy is omitted and
    the in-TEE bootstrap KMS-decrypt call returns AccessDenied even though
    BYOK is configured.  DH-016 catches the gap as a FAIL; this helper
    closes the gap automatically so the operator does not have to remember
    to ``export TF_VAR_byok_aws_kms_arn=$key_id``.

    Returns the dict of env vars set so the caller can record an audit
    note.  Existing operator-supplied values are never overwritten.
    """
    out: Dict[str, str] = {}
    if cfg is None or cfg.provider == "none" or not cfg.key_id:
        return out
    if cfg.provider == "aws-kms" and tee_platform in ("snp-aws", "gpu-cc-aws"):
        if not os.environ.get("TF_VAR_byok_aws_kms_arn"):
            os.environ["TF_VAR_byok_aws_kms_arn"] = cfg.key_id
            out["TF_VAR_byok_aws_kms_arn"] = cfg.key_id
    # GCP / Azure: the in-TEE release must reach Cloud KMS / Key Vault on a
    # deny-all-egress VPC.  These flags make the IaC publish the private
    # reachability path (GCP: googleapis DNS -> restricted VIP; Azure:
    # Microsoft.KeyVault service endpoint + NSG allow).  Without them the
    # release hangs and the workload never starts (fail-closed).
    if cfg.provider == "gcp-kms" and tee_platform in (
            "snp-gcp", "tdx-gcp", "gpu-cc-gcp"):
        if not os.environ.get("TF_VAR_byok_gcp_kms"):
            os.environ["TF_VAR_byok_gcp_kms"] = "true"
            out["TF_VAR_byok_gcp_kms"] = "true"
        # Reachability is not authorization.  The flag above only publishes the
        # private googleapis route so Cloud KMS is *reachable* under deny-all
        # egress; it grants nothing.  The CVM's service account is created by
        # Terraform with a ``random_id`` suffix, so the operator cannot
        # pre-grant it, and no other resource gives it a Cloud KMS role — so
        # without the key id here the in-TEE unwrap fails PERMISSION_DENIED
        # with BYOK fully configured, which is exactly the failure
        # ``TF_VAR_byok_aws_kms_arn`` exists to prevent on AWS.
        if not os.environ.get("TF_VAR_byok_gcp_kms_key_id"):
            os.environ["TF_VAR_byok_gcp_kms_key_id"] = cfg.key_id
            out["TF_VAR_byok_gcp_kms_key_id"] = cfg.key_id
    if cfg.provider in _AZURE_KV_PROVIDERS and tee_platform in (
            "snp-azure", "tdx-azure", "gpu-cc-azure"):
        if not os.environ.get("TF_VAR_byok_azure_kv"):
            os.environ["TF_VAR_byok_azure_kv"] = "true"
            out["TF_VAR_byok_azure_kv"] = "true"
    return out


def build_byok_config(*, provider: str,
                      raw_policy_path: Optional[str] = None) -> ByokConfig:
    """Construct a :class:`ByokConfig` from the slim public CLI surface.

    The public CLI only exposes ``--byok <provider>`` + ``--byok-config
    <path>``.  When ``provider`` != ``"none"`` and ``raw_policy_path``
    is given, every field is loaded from that JSON file.  Schema:

    .. code-block:: json

      {
        "provider": "aws-kms",
        "key_id": "arn:aws:kms:...",
        "region": "us-east-2",
        "unwrap": "aws_nitro_recipient",
        "encryption_context": {"tenant": "acme"},
        "policy": {
          "max_attestation_age_seconds": 120,
          "allowed_measurement_sha256": ["aaaa..."],
          "require_encryption_context_keys": ["tenant"]
        },
        "dek_path": "/run/tee_crafter/byok_dek.bin"
      }
    """
    p = (provider or "none").lower()
    if p == "none":
        return ByokConfig(provider="none")

    if not raw_policy_path:
        raise ValueError(
            f"--byok={p} requires --byok-config <path/to/policy.json> "
            "(key_id, region, encryption_context, allowed_measurement, ...)"
        )

    with open(raw_policy_path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError(f"--byok-config {raw_policy_path}: must be a JSON object")
    # CLI provider wins.
    doc.setdefault("provider", p)
    if str(doc.get("provider", "none")).lower() != p:
        raise ValueError(
            f"--byok-config provider {doc['provider']!r} does not match "
            f"--byok {p!r}"
        )
    cfg = ByokConfig(
        provider=str(doc.get("provider", "none")).lower(),
        key_id=str(doc.get("key_id", "")),
        region=str(doc.get("region", "")),
        label=str(doc.get("label", "")),
        unwrap=str(doc.get("unwrap", "direct_bytes")),
        hsm_endpoint=str(doc.get("hsm_endpoint", "")),
        hsm_bearer_token=str(doc.get("hsm_bearer_token", "")),
        dek_path=str(doc.get("dek_path", "/run/tee_crafter/byok_dek.bin")),
    )
    ec = doc.get("encryption_context") or {}
    if isinstance(ec, dict):
        cfg.encryption_context = {str(k): str(v) for k, v in ec.items()}
    elif isinstance(ec, list):
        cfg.encryption_context = _parse_kv_list([str(x) for x in ec])
    pol = doc.get("policy") or {}
    if isinstance(pol, dict):
        cfg.max_attestation_age_seconds = int(pol.get(
            "max_attestation_age_seconds", 300))
        cfg.allowed_measurement_sha256 = [
            str(m) for m in (pol.get("allowed_measurement_sha256") or [])
        ]
        cfg.require_encryption_context_keys = [
            str(k) for k in (pol.get("require_encryption_context_keys") or [])
        ]
        cfg.require_signed_audit = bool(pol.get("require_signed_audit", True))
    ex = doc.get("extra") or {}
    if isinstance(ex, dict):
        cfg.extra = {str(k): str(v) for k, v in ex.items()}
    return cfg


def write_byok_config(build_dir: str, cfg: ByokConfig, *, enabled: bool) -> str:
    """Persist the BYOK config to *build_dir* and mirror into ``app/``.

    Emits THREE files per location (mirrors :func:`siem_mode.write_siem_config`):

    * ``byok.json``        — human-readable manifest, **secret values
                              redacted** (wrapped DEK ciphertext, HSM
                              bearer token).  Mode 0600.  Survives on
                              disk.
    * ``byok.env``         — full env, **contains the wrapped DEK
                              ciphertext and the HSM bearer token**.
                              Deploy-time installer relocates this to
                              ``/run/tee-crafter-<platform>/byok.env``
                              (tmpfs) and shreds the disk copy.  Mode
                              0600.
    * ``byok.env.public``  — same env *minus* the keys named in
                              :data:`SECRET_ENV_KEYS` (and the
                              conservative pattern-matched extras).
                              Stays on disk; survives reboot; pointing
                              the systemd unit at this file means
                              non-secret BYOK config remains available
                              after a reboot wipes /run.  Mode 0640.
    """
    os.makedirs(build_dir, exist_ok=True)

    # BYOK-SEC-1: build a redacted view of the dataclass for byok.json
    # so a disk-snapshot leak does not yield wrapped DEK material.  We
    # keep the *fact* that a secret exists (truthiness) plus the
    # provider/key/region for traceability — but the secret value
    # itself is replaced with a sentinel.
    redacted_cfg = dict(cfg.__dict__)
    if redacted_cfg.get("hsm_bearer_token"):
        redacted_cfg["hsm_bearer_token"] = "<redacted>"
    redacted_extra: Dict[str, str] = {}
    for k, v in (cfg.extra or {}).items():
        full_key = f"TEE_CRAFTER_BYOK_X_{k.upper()}"
        if is_byok_secret_key(full_key):
            redacted_extra[k] = f"<redacted:{len(str(v))}b>"
        else:
            redacted_extra[k] = v
    redacted_cfg["extra"] = redacted_extra

    doc: Dict[str, Any] = {
        "enabled": bool(enabled and cfg.provider != "none"),
        "provider": cfg.provider,
        "describe": cfg.describe(),
        "config": redacted_cfg,
    }
    env_data = cfg.to_env()
    env_data["TEE_CRAFTER_BYOK_ENABLED"] = "1" if doc["enabled"] else "0"

    secrets_env, public_env = split_byok_env_secrets(env_data)

    def _write_triple(base: str) -> None:
        os.makedirs(base, exist_ok=True)
        jp = os.path.join(base, "byok.json")
        ep = os.path.join(base, "byok.env")
        ep_pub = os.path.join(base, "byok.env.public")
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, default=str)
        with open(ep, "w", encoding="utf-8") as f:
            f.write(
                "# BYOK-SEC-1: this file contains the wrapped DEK and/or\n"
                "# HSM bearer token.  Deploy-time installer relocates it\n"
                "# to /run/tee-crafter-<platform>/byok.env (tmpfs) and\n"
                "# `shred -u`s the disk copy.  Never check this into git.\n"
            )
            for k, v in sorted(env_data.items()):
                f.write(f"{k}={v}\n")
        with open(ep_pub, "w", encoding="utf-8") as f:
            f.write(
                "# BYOK-SEC-1: non-secret BYOK config (provider, key_id,\n"
                "# region, policy thresholds, encryption-context keys).\n"
                "# The wrapped-DEK / HSM-bearer half lives on tmpfs at\n"
                "# /run/tee-crafter-<platform>/byok.env and is never\n"
                "# written to persistent disk after deploy.\n"
            )
            for k, v in sorted(public_env.items()):
                f.write(f"{k}={v}\n")
        try:
            os.chmod(ep, 0o600)
            os.chmod(jp, 0o600)
            os.chmod(ep_pub, 0o640)
        except Exception:
            pass

    # Build-dir copy lives in the new ``byok/`` subdir; the in-TEE
    # bundle staging copy under ``app/`` keeps its flat layout because
    # the uploader rsyncs that directory verbatim into the TEE image.
    from tee_crafter.core.audit import build_layout as _layout
    _write_triple(_layout.byok_dir(build_dir))
    app_dir = os.path.join(build_dir, "app")
    if os.path.isdir(app_dir):
        _write_triple(app_dir)
    return _layout.byok_json(build_dir)


def _expected_unwrap_for_platform(tee_platform: str, provider: str) -> str:
    """Return the expected ``unwrap`` mode for *provider* + *tee_platform*."""
    if provider == "aws-kms":
        if tee_platform == "nitro-aws":
            return "aws_nitro_recipient"
        # snp-aws / gpu-cc-aws can do better than direct_bytes -- see
        # ``aws_nitrotpm_recipient`` in UNWRAP_MODES -- but the stronger mode
        # requires an image whose AMI carries TpmSupport=v2.0 and whose bake
        # recorded PCRs. This function has neither the image nor the registry, so
        # it names the mode that always works and the audit row treats the
        # stronger one as acceptable rather than unexpected (see BYOK-002).
        return "direct_bytes"
    if provider in _AZURE_KV_PROVIDERS:
        # CKM_RSA_AES_KEY_WRAP either way; the difference is *who* unwraps it.
        # `azure-skr` hands back an already-unwrapped DEK, so the staged bytes
        # are plaintext from this layer's point of view.
        return "direct_bytes"
    if provider == "gcp-kms":
        return "direct_bytes"
    if provider == "external-hsm":
        return "rsa_oaep_sha256"
    return ""


def record_byok_audit(
    audit,
    cfg: ByokConfig,
    *,
    enabled: bool,
    tee_platform: str = "",
    byok_config_sha256: str = "",
) -> None:
    """Record BYOK-* verdict rows for the resolved policy.

    Emits BYOK-001/002/003/004/005/010 as structured pass/fail rows
    so an out-of-band auditor can confirm the provider, unwrap mode,
    key tail, allowlist size, attestation freshness window, and the
    config file digest from the build provenance alone.
    """
    if audit is None:
        return
    active = bool(enabled and cfg.provider != "none")
    if not active:
        try:
            audit.record(
                "BYOK", "Customer-managed key release policy resolved",
                "skip", enabled=False, provider=cfg.provider,
            )
        except Exception:
            pass
        return
    try:
        audit.record(
            "BYOK", "Customer-managed key release policy resolved",
            "info",
            enabled=active,
            provider=cfg.provider, key_id_tail=cfg.key_id[-32:] if cfg.key_id else "",
            region=cfg.region, unwrap=cfg.unwrap,
            max_attestation_age_seconds=cfg.max_attestation_age_seconds,
            allowlist_size=len(cfg.allowed_measurement_sha256),
            describe=cfg.describe(),
        )
    except Exception:
        return

    # BYOK-001 — provider resolved.
    try:
        audit.record_check(
            "BYOK", "Provider resolved", "BYOK-001",
            observed=cfg.provider in BYOK_PROVIDERS and cfg.provider != "none",
            note=f"provider={cfg.provider}",
        )
    except Exception:
        pass

    # BYOK-002 — unwrap mode correct for tee_platform.
    if tee_platform:
        expected = _expected_unwrap_for_platform(tee_platform, cfg.provider)
        if expected:
            # A *stronger* mode than the baseline must not read as a failure.
            # aws_nitrotpm_recipient is measurement-gated where direct_bytes is
            # identity-gated, so flagging it would tell an auditor the safer
            # configuration was the wrong one.
            acceptable = {expected}
            if (cfg.provider == "aws-kms"
                    and tee_platform in _NITROTPM_CAPABLE_PLATFORMS):
                acceptable.add("aws_nitrotpm_recipient")
            audit.record_check(
                "BYOK", "Unwrap mode correct for tee_platform", "BYOK-002",
                expected=True,
                observed=(cfg.unwrap in acceptable),
                note=(f"expected unwrap in {sorted(acceptable)}, "
                      f"got {cfg.unwrap}"),
            )

    # BYOK-003 — key_id_tail recorded.
    audit.record_check(
        "BYOK", "key_id_tail recorded", "BYOK-003",
        observed=bool(cfg.key_id),
        note=cfg.key_id[-32:] if cfg.key_id else "",
    )

    # BYOK-004 — allowlist size known (informational — always true; we
    # record it so an empty allowlist shows up explicitly).
    audit.record_check(
        "BYOK", "Allowlist size known", "BYOK-004",
        observed=True,
        note=f"size={len(cfg.allowed_measurement_sha256)}",
    )

    # BYOK-005 — max attestation age within policy.
    audit.record_check(
        "BYOK", "max_attestation_age_seconds <= 600", "BYOK-005",
        expected=True,
        observed=(0 < cfg.max_attestation_age_seconds <= 600),
        note=f"{cfg.max_attestation_age_seconds}s",
    )

    # BYOK-010 — config sha256 (when supplied by caller).
    if byok_config_sha256:
        audit.record_check(
            "BYOK", "byok_config sha256 recorded", "BYOK-010",
            observed=True,
            note=byok_config_sha256,
        )

    # BYOK-013 — runtime fail-closed gate engaged.  The gate ships in every
    # app template (byok_health.fail_closed_wrap) and, on CVM container mode,
    # the secrets oneshot Requires= keeps the workload stopped if release
    # fails.  Production default is fail-closed; the dev hatch downgrades it.
    _byok_fail_open = os.environ.get(
        "TEE_CRAFTER_BYOK_FAIL_OPEN", "").strip().lower() in (
        "1", "true", "yes", "on")
    audit.record_check(
        "BYOK", "BYOK runtime fail-closed gate engaged", "BYOK-013",
        expected=True, observed=not _byok_fail_open,
        note=("fail-closed (default)" if not _byok_fail_open
              else "TEE_CRAFTER_BYOK_FAIL_OPEN=1 — dev hatch, NOT for prod"),
    )

    # BYOK-011 — key release bound to a vetted measurement.
    #
    # The in-TEE KeyReleaseOrchestrator only compares the live measurement
    # against ``allowed_measurement_sha256`` when that allowlist is NON-empty
    # (core/keys/release.py). An empty allowlist therefore disables in-guest
    # measurement binding: release falls back to "any fresh attestation of any
    # measurement". Nitro is backstopped server-side (the customer KMS key
    # policy enforces ``kms:RecipientAttestation:PCRn`` conditions), so an empty
    # in-guest allowlist is still measurement-bound there. Every other platform
    # uses the ``direct_bytes`` CVM path with no server-side PCR condition, so an
    # empty allowlist means release is NOT bound to the operator-vetted image.
    #
    # Surface this honestly (mirrors the ATT-003 TOFU treatment): WARN by
    # default, hard FAIL when TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT=1 so CI can
    # refuse an unbound BYOK deploy.
    _has_allowlist = bool(cfg.allowed_measurement_sha256)
    _nitro_backstop = (tee_platform == "nitro-aws"
                       and cfg.unwrap == "aws_nitro_recipient")
    # ``azure-skr`` is the third case, and it is neither of the two above.
    # Azure Key Vault will not release an exportable key at all without a
    # `release_policy`, and it evaluates that policy server-side against the
    # MAA token before the key leaves the vault -- so unlike the other
    # ``direct_bytes`` CVM platforms there *is* a server-side condition here.
    # But it is not automatically a *measurement* condition: a valid policy can
    # assert only `x-ms-attestation-type` / `x-ms-compliance-status` and omit
    # `x-ms-isolation-tee.x-ms-sevsnpvm-launchmeasurement`, which would admit
    # any compliant CVM.  We cannot tell which without reading the policy from
    # the vault, so this stays a WARN rather than becoming a pass -- fail
    # closed on what we cannot prove.  What changes is the reason given: the
    # old note claimed "this platform has no server-side PCR condition", which
    # is simply false for azure-skr and points the operator at the wrong fix.
    _akv_server_side = cfg.provider == "azure-skr"
    _strict = os.environ.get(
        "TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT", "").strip().lower() in (
        "1", "true", "yes", "on")
    if _has_allowlist or _nitro_backstop:
        audit.record_check(
            "BYOK", "Key release bound to a vetted measurement", "BYOK-011",
            observed=True,
            note=("server-side KMS PCR conditions (Nitro Recipient)"
                  if _nitro_backstop and not _has_allowlist
                  else f"in-guest allowlist ({len(cfg.allowed_measurement_sha256)} entries)"),
        )
    elif _akv_server_side:
        from tee_crafter.core.audit import Verdict as _V
        audit.record_check(
            "BYOK", "Key release bound to a vetted measurement", "BYOK-011",
            verdict=_V.FAIL if _strict else _V.WARN,
            observed=False,
            note=("empty allowed_measurement_sha256 on azure-skr: in-guest "
                  "release is not measurement-bound. Key Vault does enforce "
                  "the key's release_policy server-side against the MAA token, "
                  "so release is not unconditional -- but only if that policy "
                  "asserts x-ms-isolation-tee.x-ms-sevsnpvm-launchmeasurement "
                  "(or the TDX equivalent), which this check cannot see. "
                  "Verify it with `az keyvault key show`, and/or pin "
                  "policy.allowed_measurement_sha256 in --byok-config "
                  "(set TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT=1 to hard-fail)."),
        )
    else:
        from tee_crafter.core.audit import Verdict as _V
        audit.record_check(
            "BYOK", "Key release bound to a vetted measurement", "BYOK-011",
            verdict=_V.FAIL if _strict else _V.WARN,
            observed=False,
            note=(f"empty allowed_measurement_sha256 on {tee_platform or 'CVM'}: "
                  "in-guest release is NOT bound to a vetted measurement and "
                  "this platform has no server-side PCR condition. Pin "
                  "policy.allowed_measurement_sha256 in --byok-config "
                  "(set TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT=1 to hard-fail)."),
        )
