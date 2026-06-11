"""Post-deploy cloud-audit-log readers — CT-001 .. CT-007.

Each function queries the corresponding cloud's audit log
(``cloudtrail:LookupEvents`` / Azure Monitor / GCP Logging) for the
events that prove the deployment happened, the BYOK key was used, etc.
Failures fall back to a ``warn`` row (so a missing IAM permission
doesn't blow the matrix up) with an explicit remediation hint.

Operators grant read-only access via:

* AWS — attach ``cloudtrail:LookupEvents`` (already in the
  ``TeeCrafterDataOps`` policy).
* Azure — assign ``Monitoring Reader`` on the subscription.
* GCP — assign ``roles/logging.viewer`` on the project.
"""
from __future__ import annotations

import datetime
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from tee_crafter.core.audit import BuildAuditTrail, Verdict


logger = logging.getLogger("tee_crafter.cloud_audit")

DEFAULT_LOOKBACK_MINUTES = 30

_AWS_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")

# Terraform ``kms_key_arn`` on AWS templates is the *deployment* CMK
# (state bucket / artifact encryption), not the customer's BYOK key.
# Never feed it into CT-002 — only the key from ``byok.env`` when
# ``TEE_CRAFTER_BYOK_ENABLED=1``.
_BYOK_ENV_KEYS = (
    "TEE_CRAFTER_BYOK_KEY_ID",
    "TEE_CRAFTER_BYOK_REGION",
    "TEE_CRAFTER_BYOK",
)


def _read_byok_env_map(build_dir: str) -> Dict[str, str]:
    """Parse BYOK env files under *build_dir* into a flat dict."""
    from tee_crafter.core.audit import build_layout as _layout

    out: Dict[str, str] = {}
    for candidate in (
        _layout.byok_env(build_dir),
        _layout.byok_env_public(build_dir),
        os.path.join(build_dir, "byok.env"),
        os.path.join(build_dir, "byok.env.public"),
        os.path.join(build_dir, "app", "byok.env"),
        os.path.join(build_dir, "app", "byok.env.public"),
    ):
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
        except OSError:
            continue
        if out:
            break
    return out


def resolve_customer_byok_key(
    tee_platform: str,
    build_dir: str = "",
    *,
    terraform_outputs: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str, str, str]:
    """Return ``(enabled, aws_key_arn, azure_vault_key, gcp_key_name)``.

    *enabled* comes from ``TEE_CRAFTER_BYOK_ENABLED`` in the staged
    ``byok.env``.  Per-cloud resource identifiers are read from the
    same file — **not** from Terraform outputs (which may carry an
    unrelated deployment KMS key on AWS).
    """
    _ = terraform_outputs  # reserved for future cross-checks
    if not build_dir:
        return False, "", "", ""
    from tee_crafter.cli.deployment.common.byok_sidecar import is_byok_enabled

    if not is_byok_enabled(build_dir):
        return False, "", "", ""
    env = _read_byok_env_map(build_dir)
    provider = (env.get("TEE_CRAFTER_BYOK") or "").strip().lower()
    key_id = (env.get("TEE_CRAFTER_BYOK_KEY_ID") or "").strip()
    if not key_id or provider in {"", "none"}:
        return True, "", "", ""

    aws_key = ""
    azure_key = ""
    gcp_key = ""
    if provider == "aws-kms":
        aws_key = key_id
    elif provider == "azure-kv":
        # Activity log filter uses vault name; key URL is
        # https://<vault>.vault.azure.net/keys/<name> or managedhsm.
        azure_key = key_id
    elif provider == "gcp-kms":
        gcp_key = key_id
    return True, aws_key, azure_key, gcp_key


def _emit_byok_cloud_check_na(
    audit: BuildAuditTrail,
    *,
    check_id: str,
    title: str,
    note: str,
) -> None:
    audit.record_check(
        "Phase 6: Cloud audit",
        title,
        check_id,
        verdict=Verdict.NOT_APPLICABLE,
        observed=False,
        note=note,
    )


def _sanitize_aws_region(value: Optional[str]) -> Optional[str]:
    """Return *value* if it looks like a real AWS region, else ``None``.

    ``.env`` files frequently contain literal ``${TF_VAR_aws_region:-...}``
    expressions because dotenv loaders do not perform shell-style
    parameter expansion.  Passing that string into boto3 yields an
    ``InvalidRegionError``; we'd rather fall back to the SDK default
    region resolution chain and surface a clean ``warn``.
    """
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    if v.startswith("$"):
        return None
    if not _AWS_REGION_RE.match(v):
        return None
    return v


def _resolve_aws_region(region: Optional[str]) -> Optional[str]:
    for cand in (region, os.environ.get("AWS_REGION"),
                 os.environ.get("AWS_DEFAULT_REGION"),
                 os.environ.get("TF_VAR_aws_region")):
        v = _sanitize_aws_region(cand)
        if v:
            return v
    return None


# ----------------------------- AWS --------------------------------------

def aws_cloudtrail_lookup(
    events_filter: Dict[str, str],
    *,
    since: datetime.datetime,
    until: Optional[datetime.datetime] = None,
    region: Optional[str] = None,
    max_results: int = 50,
) -> Tuple[bool, List[Dict[str, Any]], str]:
    """Wrap ``cloudtrail:LookupEvents`` with sensible defaults.

    Returns ``(ok, events, error_or_empty)``.  ``ok=False`` does NOT
    mean "the event was absent" — it means the call itself failed
    (network / permission / SDK missing).  Callers should treat the
    empty-events case as a separate verdict.
    """
    try:
        import boto3  # type: ignore
    except ImportError:
        return False, [], "boto3 not installed"
    try:
        kw = {}
        sane_region = _resolve_aws_region(region)
        if sane_region:
            kw["region_name"] = sane_region
        client = boto3.client("cloudtrail", **kw)
        attrs = [
            {"AttributeKey": k, "AttributeValue": v}
            for k, v in events_filter.items()
        ]
        end_t = until or datetime.datetime.utcnow()
        resp = client.lookup_events(
            LookupAttributes=attrs,
            StartTime=since,
            EndTime=end_t,
            MaxResults=min(50, max_results),
        )
        return True, resp.get("Events", []), ""
    except Exception as exc:
        return False, [], f"{type(exc).__name__}: {exc}"


def record_aws_cloudtrail_verdicts(
    audit: BuildAuditTrail,
    *,
    tee_platform: str,
    instance_id: str = "",
    byok_key_arn: str = "",
    byok_enabled: bool = False,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    region: Optional[str] = None,
) -> None:
    """Emit CT-001 / CT-002 / CT-003 / CT-007 for an AWS deploy.

    Pulls a single time-windowed page from CloudTrail per check and
    records the verdict.  Permission errors land as ``warn`` rows with
    a remediation pointer.
    """
    if audit is None:
        return
    since = datetime.datetime.utcnow() - datetime.timedelta(
        minutes=lookback_minutes)

    if instance_id:
        ok, events, err = aws_cloudtrail_lookup(
            {"ResourceName": instance_id},
            since=since, region=region,
        )
        run_inst = any(
            e.get("EventName") == "RunInstances" for e in events
        )
        if not ok:
            audit.record_check(
                "Phase 6: Cloud audit",
                "CloudTrail RunInstances for instance_id", "CT-001",
                verdict=Verdict.WARN, observed=False, note=err[:200],
            )
        else:
            audit.record_check(
                "Phase 6: Cloud audit",
                "CloudTrail RunInstances for instance_id", "CT-001",
                observed=run_inst,
                note=f"events={len(events)}",
            )
    if not byok_key_arn:
        if byok_enabled:
            audit.record_check(
                "Phase 6: Cloud audit",
                "CloudTrail kms:Decrypt by instance role", "CT-002",
                verdict=Verdict.WARN,
                observed=False,
                note="BYOK enabled but TEE_CRAFTER_BYOK_KEY_ID missing in byok.env",
            )
            if tee_platform == "nitro-aws":
                audit.record_check(
                    "Phase 6: Cloud audit",
                    "CloudTrail NitroEnclave attestation event", "CT-003",
                    verdict=Verdict.WARN,
                    observed=False,
                    note="BYOK enabled but customer KMS key id missing",
                )
        else:
            _emit_byok_cloud_check_na(
                audit,
                check_id="CT-002",
                title="CloudTrail kms:Decrypt by instance role",
                note="BYOK not enabled — no customer KMS envelope-encryption expected",
            )
            if tee_platform == "nitro-aws":
                _emit_byok_cloud_check_na(
                    audit,
                    check_id="CT-003",
                    title="CloudTrail NitroEnclave attestation event",
                    note="BYOK not enabled — no enclave KMS Recipient calls expected",
                )
    elif byok_key_arn:
        ok, events, err = aws_cloudtrail_lookup(
            {"ResourceName": byok_key_arn},
            since=since, region=region,
        )
        # CT-002 is "envelope encryption was actually exercised on
        # the BYOK key".  Accept ANY of the data-plane KMS calls
        # because real deployments interleave them:
        #
        # * ``GenerateDataKey`` / ``GenerateDataKeyWithoutPlaintext``
        #   — sidecar wraps a fresh DEK at boot,
        # * ``Decrypt``  — sidecar (or enclave) unwraps the DEK to
        #   read back BYOK-encrypted state,
        # * ``Encrypt`` — sidecar re-wraps a rotated DEK,
        # * ``ReEncrypt`` — KMS-side re-wrap during key rotation.
        #
        # ``DescribeKey`` / ``GetKeyPolicy`` are control-plane and
        # do NOT evidence data-plane use, so they're excluded.
        _DATA_PLANE = {
            "Decrypt", "GenerateDataKey",
            "GenerateDataKeyWithoutPlaintext",
            "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext",
            "Encrypt", "ReEncrypt",
        }
        data_plane = [e for e in events if e.get("EventName") in _DATA_PLANE]
        decrypt_seen = bool(data_plane)
        # Recipient-attestation-bearing calls (Nitro enclave
        # cryptographic operations) carry a ``Recipient`` block in
        # the request parameters.  We surface this so CT-003 has
        # signal without a second CloudTrail page-pull.
        nitro_attest = [
            e for e in data_plane
            if "Recipient" in (e.get("CloudTrailEvent") or "")
            or "Recipient" in str(e.get("RequestParameters", ""))
        ]
        if not ok:
            audit.record_check(
                "Phase 6: Cloud audit",
                "CloudTrail kms:Decrypt by instance role", "CT-002",
                verdict=Verdict.WARN, observed=False, note=err[:200],
            )
        else:
            from collections import Counter as _C
            ev_counts = _C(e.get("EventName", "?") for e in events)
            breakdown = ", ".join(f"{k}={v}" for k, v in sorted(ev_counts.items()))
            if not decrypt_seen and not events:
                # CloudTrail often lags teardown by several minutes; an
                # empty page is inconclusive, not proof BYOK was skipped.
                audit.record_check(
                    "Phase 6: Cloud audit",
                    "CloudTrail kms:Decrypt by instance role", "CT-002",
                    verdict=Verdict.WARN,
                    observed=False,
                    note=(f"no events in {lookback_minutes}m lookback for "
                          f"key={byok_key_arn[-32:]} — CloudTrail may lag; "
                          "re-check with a wider window"),
                )
            else:
                audit.record_check(
                    "Phase 6: Cloud audit",
                    "CloudTrail kms:Decrypt by instance role", "CT-002",
                    observed=decrypt_seen,
                    note=(f"data_plane={len(data_plane)} of {len(events)} events "
                          f"[{breakdown}] key={byok_key_arn[-32:]}"),
                )
        if tee_platform == "nitro-aws":
            # Now CT-003 can be evaluated for real: PASS if any
            # data-plane KMS event for the BYOK key carried a
            # Recipient field; WARN if BYOK was used but no
            # Recipient-bearing event landed in the lookback
            # window (operator should re-run with a wider window);
            # FAIL if BYOK key was supplied and CloudTrail returned
            # events but none was a data-plane call at all.
            if not ok:
                audit.record_check(
                    "Phase 6: Cloud audit",
                    "CloudTrail NitroEnclave attestation event", "CT-003",
                    verdict=Verdict.WARN, observed=False,
                    note=err[:200],
                )
            elif nitro_attest:
                audit.record_check(
                    "Phase 6: Cloud audit",
                    "CloudTrail NitroEnclave attestation event", "CT-003",
                    observed=True,
                    note=(f"{len(nitro_attest)} Recipient-bearing kms event(s) "
                          f"observed on byok_key_arn within lookback"),
                )
            elif decrypt_seen:
                audit.record_check(
                    "Phase 6: Cloud audit",
                    "CloudTrail NitroEnclave attestation event", "CT-003",
                    verdict=Verdict.WARN,
                    observed=False,
                    note=("data-plane KMS events present but none carried "
                          "a Recipient field; enclave may not have invoked "
                          "kmstool-enclave within the lookback window"),
                )
            else:
                audit.record_check(
                    "Phase 6: Cloud audit",
                    "CloudTrail NitroEnclave attestation event", "CT-003",
                    verdict=Verdict.WARN,
                    observed=False,
                    note=("no data-plane KMS events on byok_key_arn — "
                          "enclave did not exercise envelope encryption "
                          "during this lookback window"),
                )


# ---------------------------- Azure -------------------------------------

def record_azure_activity_log_verdicts(
    audit: BuildAuditTrail,
    *,
    tee_platform: str,
    resource_group: str = "",
    key_vault_name: str = "",
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
) -> None:
    """Emit CT-005 (Key Vault SKR release) for an Azure deploy.

    Uses ``az monitor activity-log list`` because the
    azure-monitor-query SDK isn't a hard dependency.  Falls back to
    ``warn`` when ``az`` is missing.
    """
    if audit is None:
        return
    if not key_vault_name:
        _emit_byok_cloud_check_na(
            audit,
            check_id="CT-005",
            title="Azure Activity Log Key Vault SKR",
            note="BYOK not enabled — no Key Vault SKR release expected",
        )
        return
    import subprocess
    import json as _json

    since = (datetime.datetime.utcnow() - datetime.timedelta(
        minutes=lookback_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        res = subprocess.run(
            [
                "az", "monitor", "activity-log", "list",
                "--start-time", since,
                "--resource-group", resource_group or "",
                "-o", "json",
            ],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        audit.record_check(
            "Phase 6: Cloud audit",
            "Azure Activity Log Key Vault SKR", "CT-005",
            verdict=Verdict.WARN, observed=False,
            note=f"{type(exc).__name__}: {exc}",
        )
        return
    if res.returncode != 0:
        audit.record_check(
            "Phase 6: Cloud audit",
            "Azure Activity Log Key Vault SKR", "CT-005",
            verdict=Verdict.WARN, observed=False,
            note=(res.stderr or "")[:200],
        )
        return
    try:
        events = _json.loads(res.stdout or "[]")
    except Exception:
        events = []
    relevant = [
        e for e in events
        if "Microsoft.KeyVault" in (e.get("resourceId") or "")
        and "release" in (e.get("operationName", {}).get("value", "")).lower()
    ]
    audit.record_check(
        "Phase 6: Cloud audit",
        "Azure Activity Log Key Vault SKR", "CT-005",
        observed=bool(relevant),
        note=f"events={len(relevant)} (of {len(events)} total)",
    )


# ------------------------------ GCP -------------------------------------

def record_gcp_audit_log_verdicts(
    audit: BuildAuditTrail,
    *,
    tee_platform: str,
    project: str = "",
    key_name: str = "",
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
) -> None:
    """Emit CT-006 (cloudkms.useToDecrypt) for a GCP deploy."""
    if audit is None:
        return
    if not (project and key_name):
        _emit_byok_cloud_check_na(
            audit,
            check_id="CT-006",
            title="GCP audit log cloudkms.useToDecrypt",
            note="BYOK not enabled — no cloudkms.useToDecrypt expected",
        )
        return
    import subprocess
    import json as _json

    since = (datetime.datetime.utcnow() - datetime.timedelta(
        minutes=lookback_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # GCP's ``cloudkms_cryptokey`` resource exposes ``crypto_key_id`` as the
    # *short* key name (e.g. ``tee-crafter-byok-smoke``), not the full
    # ``projects/.../cryptoKeys/<name>`` path.  If the caller passed the full
    # path (typical), filter by the short tail; also match on
    # ``protoPayload.resourceName`` so we catch encrypt/decrypt regardless of
    # which CryptoKey label level is set.
    short_key = key_name.rsplit("/cryptoKeys/", 1)[-1]
    flt = (
        'resource.type="cloudkms_cryptokey" '
        f'AND (resource.labels.crypto_key_id="{short_key}" '
        f'OR protoPayload.resourceName=~"{key_name}") '
        'AND protoPayload.methodName=~"Decrypt"'
        f' AND timestamp>="{since}"'
    )
    try:
        res = subprocess.run(
            [
                "gcloud", "logging", "read", flt,
                "--limit", "20", "--format", "json",
                "--project", project,
            ],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        audit.record_check(
            "Phase 6: Cloud audit",
            "GCP audit log cloudkms.useToDecrypt", "CT-006",
            verdict=Verdict.WARN, observed=False,
            note=f"{type(exc).__name__}: {exc}",
        )
        return
    if res.returncode != 0:
        audit.record_check(
            "Phase 6: Cloud audit",
            "GCP audit log cloudkms.useToDecrypt", "CT-006",
            verdict=Verdict.WARN, observed=False,
            note=(res.stderr or "")[:200],
        )
        return
    try:
        events = _json.loads(res.stdout or "[]")
    except Exception:
        events = []
    if events:
        audit.record_check(
            "Phase 6: Cloud audit",
            "GCP audit log cloudkms.useToDecrypt", "CT-006",
            observed=True,
            note=f"events={len(events)} key={key_name}",
        )
        return
    # No events seen.  The most common cause is that the project does not have
    # Cloud KMS Data Access audit logs enabled (Admin Read/Data Read/Data
    # Write).  Surface the remediation explicitly so an operator can fix it
    # without spelunking provider docs.
    audit.record_check(
        "Phase 6: Cloud audit",
        "GCP audit log cloudkms.useToDecrypt", "CT-006",
        verdict=Verdict.WARN, observed=False,
        note=(
            f"events=0 key={key_name}; enable Cloud KMS Data Access audit "
            "logs (Admin Read + Data Read + Data Write) on the project IAM "
            "audit-config so BYOK Decrypt calls land in the audit log"
        ),
    )


# ----------------------------- Dispatch ---------------------------------

def record_cloud_audit_verdicts(
    audit: BuildAuditTrail,
    *,
    tee_platform: str,
    aws_instance_id: str = "",
    aws_byok_key_arn: str = "",
    aws_region: Optional[str] = None,
    azure_resource_group: str = "",
    azure_key_vault: str = "",
    gcp_project: str = "",
    gcp_key_name: str = "",
    build_dir: str = "",
    terraform_outputs: Optional[Dict[str, Any]] = None,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
) -> None:
    """Dispatch to the right per-cloud reader for *tee_platform*.

  When *build_dir* is set, BYOK-gated checks (CT-002/003/005/006) use
  the customer key from staged ``byok.env``, not Terraform's deployment
  ``kms_key_arn``.  Legacy callers may still pass *aws_byok_key_arn* /
  *azure_key_vault* / *gcp_key_name* explicitly; those values win only
  when *build_dir* is empty.
    """
    if audit is None:
        return
    outputs = terraform_outputs or {}
    byok_enabled = False
    if build_dir:
        byok_enabled, aws_key, azure_key, gcp_key = resolve_customer_byok_key(
            tee_platform, build_dir, terraform_outputs=outputs,
        )
        if byok_enabled:
            if aws_key:
                aws_byok_key_arn = aws_key
            if azure_key:
                azure_key_vault = azure_key
            if gcp_key:
                gcp_key_name = gcp_key
        else:
            aws_byok_key_arn = ""
            azure_key_vault = ""
            gcp_key_name = ""
    if tee_platform.endswith("-aws") or tee_platform == "nitro-aws":
        record_aws_cloudtrail_verdicts(
            audit, tee_platform=tee_platform,
            instance_id=aws_instance_id,
            byok_key_arn=aws_byok_key_arn,
            byok_enabled=byok_enabled,
            lookback_minutes=lookback_minutes,
            region=aws_region,
        )
    elif tee_platform.endswith("-azure"):
        record_azure_activity_log_verdicts(
            audit, tee_platform=tee_platform,
            resource_group=azure_resource_group,
            key_vault_name=azure_key_vault,
            lookback_minutes=lookback_minutes,
        )
    elif tee_platform.endswith("-gcp"):
        record_gcp_audit_log_verdicts(
            audit, tee_platform=tee_platform,
            project=gcp_project or (outputs.get("project") or ""),
            key_name=gcp_key_name,
            lookback_minutes=lookback_minutes,
        )


__all__ = [
    "aws_cloudtrail_lookup",
    "resolve_customer_byok_key",
    "record_aws_cloudtrail_verdicts",
    "record_azure_activity_log_verdicts",
    "record_gcp_audit_log_verdicts",
    "record_cloud_audit_verdicts",
]
