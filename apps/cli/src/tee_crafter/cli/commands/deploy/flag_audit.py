"""Audit every dev-hatch env knob into the build provenance.

Every ``DH-*`` and a few cross-cutting knobs from
:mod:`tee_crafter.core.audit.checks` are emitted as a single pass/fail
verdict row keyed by ``check_id`` so a CI verifier can fail-closed when
any production-grade knob has been flipped to a development posture.

The check catalogue is the source of truth for each knob's
``default_expected`` value; this module is purely about reading the
current env and matching it.  See ``docs/audit_matrix.md`` for the full
catalogue and per-platform applicability rules.
"""
from __future__ import annotations

import os

from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.audit.checks import CHECKS


_TRUTHY = {"1", "true", "yes", "y", "on"}
_FALSY = {"0", "false", "no", "n", "off", ""}


def _bool_env(name: str, default: str = "") -> str:
    """Return a normalised string ("1" / "0" / "") for *name*."""
    raw = (os.environ.get(name, default) or "").strip().lower()
    if raw in _TRUTHY:
        return "1"
    if raw in _FALSY:
        return "" if raw == "" else "0"
    return raw  # uninterpreted (matches default_expected exactly when known)


def _raw_env(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").strip()


def _record(
    audit: BuildAuditTrail,
    check_id: str,
    *,
    observed,
    note: str = "",
    evidence_pointer: str = "",
) -> None:
    spec = CHECKS.get(check_id)
    if spec is None:
        return
    audit.record_check(
        "Pipeline Config",
        spec.title,
        check_id,
        observed=observed,
        note=note,
        evidence_pointer=evidence_pointer or "env",
    )


def audit_dev_hatch_flags(
    audit: BuildAuditTrail,
    *,
    tee_platform: str,
    byok_enabled: bool,
    byok_provider: str = "",
    siem_provider: str = "",
    allow_unbaked_ami: bool = False,
) -> None:
    """Emit DH-* + selected DH-style verdicts based on current env.

    Called once per deploy, immediately after the "Pipeline initialized"
    record but before any expensive infra step.  Failing any required
    DH-* row makes a downstream ``verify-provenance --required-checks``
    fail closed.
    """

    def _apply(check_id: str, observed, **kw):
        spec = CHECKS.get(check_id)
        if spec is None:
            return
        if tee_platform and not spec.applies_to(tee_platform):
            return
        _record(audit, check_id, observed=observed, **kw)

    # DH-001  TEE_CRAFTER_PROXY_STRICT_IMDS == "1"
    _apply("DH-001", _bool_env("TEE_CRAFTER_PROXY_STRICT_IMDS", "1") or "1")

    # DH-002  TEE_CRAFTER_PROXY_NO_CREDS expected "0" (dev hatch only)
    _apply("DH-002", _bool_env("TEE_CRAFTER_PROXY_NO_CREDS", "0") or "0")

    # DH-003  TEE_CRAFTER_NRAS_STRICT == "1"
    _apply("DH-003", _bool_env("TEE_CRAFTER_NRAS_STRICT", "1") or "1")

    # DH-004  TEE_CRAFTER_STRICT_TSM == "1"
    _apply("DH-004", _bool_env("TEE_CRAFTER_STRICT_TSM", "1") or "1")

    # DH-005  TEE_CRAFTER_SIEM_FAIL_OPEN == "0"
    _apply("DH-005", _bool_env("TEE_CRAFTER_SIEM_FAIL_OPEN", "0") or "0")

    # DH-006  TEE_CRAFTER_ALLOW_VULNERABLE unset
    _apply("DH-006", _raw_env("TEE_CRAFTER_ALLOW_VULNERABLE"))

    # DH-007  TEE_CRAFTER_ACCEPT_PARTIAL_CC unset
    _apply("DH-007", _raw_env("TEE_CRAFTER_ACCEPT_PARTIAL_CC"))

    # DH-008  TEE_CRAFTER_STRICT_SNP_AK_BINDING == "1"
    _apply("DH-008", _bool_env("TEE_CRAFTER_STRICT_SNP_AK_BINDING", "1") or "1")

    # DH-009  TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS unset.  Repointed: the
    # old TEE_CRAFTER_TDX_ALLOW_MISSING_QE_IDENTITY hatch was deleted along
    # with the hand-copied QE-SVN floor, so auditing it reported "good" about a
    # control that no longer existed.
    _apply("DH-009", _raw_env("TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS"))

    # DH-010  TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL unset
    _apply("DH-010", _raw_env("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL"))

    # DH-011  TEE_CRAFTER_SKIP_POST_DESTROY_SHRED unset
    _apply("DH-011", _raw_env("TEE_CRAFTER_SKIP_POST_DESTROY_SHRED"))

    # DH-012  TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE unset
    _apply("DH-012", _raw_env("TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE"))

    # DH-018  TEE_CRAFTER_TCB_ALLOW_STATUS unset
    _apply("DH-018", _raw_env("TEE_CRAFTER_TCB_ALLOW_STATUS"))

    # DH-013  TF_VAR_allow_nras_broad_internet == "false"
    _apply(
        "DH-013",
        (_raw_env("TF_VAR_allow_nras_broad_internet", "false") or "false").lower(),
    )

    # DH-014  TF_VAR_allow_setup_egress == "false"
    _apply(
        "DH-014",
        (_raw_env("TF_VAR_allow_setup_egress", "false") or "false").lower(),
    )

    # DH-015  TF_VAR_enable_secure_boot == "true" (AWS)
    _apply(
        "DH-015",
        (_raw_env("TF_VAR_enable_secure_boot", "true") or "true").lower(),
    )

    # DH-016  TF_VAR_byok_aws_kms_arn must be set when BYOK is enabled
    #         for snp-aws / gpu-cc-aws (instance-role-gated decrypt).
    if tee_platform in {"snp-aws", "gpu-cc-aws"}:
        arn = _raw_env("TF_VAR_byok_aws_kms_arn")
        observed = bool(arn) if byok_enabled else True
        _apply("DH-016", observed,
               note=(
                   "BYOK enabled; instance role decrypt requires "
                   "TF_VAR_byok_aws_kms_arn to be set."
                   if byok_enabled and not arn else ""
               ))

    # DH-019  TF_VAR_byok_gcp_kms_key_id must be set when BYOK is enabled on
    #         GCP.  `TF_VAR_byok_gcp_kms` (bool) only opens the private
    #         googleapis route; it grants nothing, so checking it here would
    #         pass while the in-TEE decrypt still fails PERMISSION_DENIED.
    if tee_platform in {"snp-gcp", "tdx-gcp", "gpu-cc-gcp"}:
        key_id = _raw_env("TF_VAR_byok_gcp_kms_key_id")
        observed = bool(key_id) if byok_enabled else True
        _apply("DH-019", observed,
               note=(
                   "BYOK enabled; the CVM service account's Cloud KMS "
                   "decrypt binding requires TF_VAR_byok_gcp_kms_key_id."
                   if byok_enabled and not key_id else ""
               ))

    # DH-017  --allow-unbaked-ami / TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI
    unbaked_env = (
        _raw_env("TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI", "")
        .strip().lower() in _TRUTHY
    )
    _apply("DH-017", bool(allow_unbaked_ami or unbaked_env))


__all__ = ["audit_dev_hatch_flags"]
