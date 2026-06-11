"""Shared helpers that translate per-platform Terraform outputs into
ledger verdict rows (DEP-001..005, IAM-003, etc.).

Each per-platform phase module already has a ``audit.record(... "info",
instance_id=...)`` block right after a successful ``terraform apply``;
this module is the single place that turns those raw outputs into
structured pass/fail rows so the matrix renders consistently across
every TEE platform.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from tee_crafter.core.audit import BuildAuditTrail


def record_deploy_outputs_verdicts(
    audit: Optional[BuildAuditTrail],
    outputs: Dict[str, Any],
    *,
    tee_platform: str = "",
) -> None:
    """Emit DEP-002 / DEP-004 (and DEP-005 on AWS) from Terraform outputs.

    ``DEP-001`` is already emitted from
    :mod:`tee_crafter.cli.deployment.common.terraform_step` when
    ``terraform apply`` returns success.  This helper handles the
    structured outputs side: instance running, no public IP, IMDSv2
    required (for AWS, derived from the output marker
    ``imdsv2_required_only=true``).
    """
    if audit is None:
        return
    instance_id = outputs.get("instance_id") or outputs.get("instance_name")
    has_instance = bool(instance_id) and instance_id not in {"N/A", ""}
    audit.record_check(
        "Phase 4: Deployment", "Instance running", "DEP-002",
        observed=bool(has_instance),
        note=f"instance_id={instance_id}",
    )
    public_ip = (
        outputs.get("public_ip")
        or outputs.get("public_ipv4")
        or outputs.get("public_ip_address")
        or ""
    )
    audit.record_check(
        "Phase 4: Deployment", "No public IP (or only via NAT)", "DEP-004",
        expected=True,
        observed=(not public_ip or str(public_ip) in {"N/A"}),
        note=f"public_ip={public_ip or 'none'}",
    )
    if tee_platform.endswith("-aws") or tee_platform in {"nitro-aws", "snp-aws", "gpu-cc-aws"}:
        # AWS Terraform templates set ``imdsv2_required_only=true`` in
        # the launched instance via the ``metadata_options { http_tokens
        # = "required" }`` block.  When the output is missing we can't
        # confirm — emit a warn rather than a fail.
        imdsv2 = outputs.get("imdsv2_required_only")
        if imdsv2 is None:
            from tee_crafter.core.audit import Verdict as _V
            audit.record_check(
                "Phase 4: Deployment", "IMDSv2 required (Terraform state)",
                "DEP-005",
                verdict=_V.WARN,
                observed=False,
                note="imdsv2_required_only output missing — re-apply Terraform "
                     "after upgrading templates (http_tokens=required is set "
                     "in main.tf; output documents it for the ledger)",
            )
        else:
            audit.record_check(
                "Phase 4: Deployment", "IMDSv2 required (Terraform state)",
                "DEP-005",
                expected=True,
                observed=bool(imdsv2),
            )


__all__ = ["record_deploy_outputs_verdicts"]
