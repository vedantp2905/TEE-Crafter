"""Translate ``SiemConfig`` into Terraform variables + auxiliary HCL.

The CLI wires a SIEM exporter inside the TEE; this module handles the
*outside-the-TEE* side: making sure the network plumbing exists so the
exporter can actually reach the collector, and ideally only the
collector.

What it does:

* Decides an effective egress strategy from
  ``siem_config.egress_mode`` + provider + TEE platform:

      auto / public  -> NAT path (sets TF_VAR_allow_setup_egress=true)
      auto / private -> Interface VPC Endpoint(s) only (AWS) for AWS-native
                         sinks (cloudwatch); fail closed for internet-only
                         providers under ``private``
      none            -> no-op (operator owns egress)
* Sets ``TF_VAR_siem_egress_cidrs`` (Terraform list literal) so
  per-platform ``main.template.tf`` can lock the host
  SG / NSG / GCP firewall down to those CIDRs on the chosen
  ``siem_egress_ports``.
* Sets ``TF_VAR_siem_provision_logs_endpoint`` on AWS targets when the
  CloudWatch SIEM provider is selected.
* Writes a ``siem_egress.json`` audit document into ``build_dir`` that
  records the decision so it shows up in the build provenance bundle.

The module is intentionally pure-data (no Terraform exec, no apply) so
it can be unit-tested without the cloud SDKs installed.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


_AWS_PLATFORMS = ("snp-aws", "nitro", "nitro-aws", "gpu-cc-aws")
_AZURE_PLATFORMS = ("snp-azure", "tdx-azure", "gpu-cc-azure", "sgx", "sgx-azure")
_GCP_PLATFORMS = ("snp-gcp", "tdx-gcp", "gpu-cc-gcp")

# Providers whose intake is reachable only over the public internet
# (i.e. no usable Interface VPC Endpoint or in-VPC bypass).
_PUBLIC_INTERNET_PROVIDERS = ("splunk-hec", "datadog")

# Providers that benefit from AWS-side Interface Endpoints.  Empty since
# ``cloudwatch`` was removed from SIEM_PROVIDERS: the sidecar has no exporter
# for it, and provisioning a CloudWatch Logs interface endpoint for a stream
# nothing writes to was worse than not offering the provider.  Kept as a named
# tuple rather than inlined so re-adding a private-capable provider is a
# one-line change.
_AWS_PRIVATE_PROVIDERS: tuple[str, ...] = ()

# Providers that typically run inside / peered to the customer VPC.
_INTRA_VPC_PROVIDERS = ("syslog-cef",)


@dataclass
class EgressDecision:
    """Materialised egress plan; what we'll actually set in Terraform."""

    cloud: str = ""                    # "aws" / "azure" / "gcp" / ""
    needs_public_egress: bool = False  # NAT required
    provision_logs_endpoint: bool = False
    egress_cidrs: List[str] = field(default_factory=list)
    egress_ports: List[int] = field(default_factory=lambda: [443])
    cloudwatch_log_group: str = ""     # for IAM grant
    note: str = ""

    def to_tfvars_env(self) -> Dict[str, str]:
        """Return ``TF_VAR_*`` env vars to set before terraform apply."""
        env: Dict[str, str] = {}
        if self.needs_public_egress:
            env["TF_VAR_allow_setup_egress"] = "true"
        if self.cloud == "aws" and self.provision_logs_endpoint:
            env["TF_VAR_siem_provision_logs_endpoint"] = "true"
        if self.cloud == "aws" and self.cloudwatch_log_group:
            env["TF_VAR_siem_cloudwatch_log_group"] = self.cloudwatch_log_group
        # Lists go through Terraform as JSON when sourced from env vars.
        if self.egress_cidrs:
            env["TF_VAR_siem_egress_cidrs"] = json.dumps(list(self.egress_cidrs))
        if self.egress_ports != [443]:
            env["TF_VAR_siem_egress_ports"] = json.dumps([int(p) for p in self.egress_ports])
        return env

    def describe(self) -> str:
        bits: List[str] = []
        bits.append(f"cloud={self.cloud or 'n/a'}")
        bits.append(f"public_egress={'yes' if self.needs_public_egress else 'no'}")
        if self.cloud == "aws":
            bits.append(f"logs_endpoint={'yes' if self.provision_logs_endpoint else 'no'}")
        if self.egress_cidrs:
            bits.append(f"allowlist_cidrs={','.join(self.egress_cidrs)}")
        else:
            bits.append("allowlist_cidrs=any")
        bits.append(f"ports={','.join(str(p) for p in self.egress_ports)}")
        if self.note:
            bits.append(f"note={self.note}")
        return " ".join(bits)


def _classify_cloud(tee_platform: str) -> str:
    p = (tee_platform or "").lower()
    if p in _AWS_PLATFORMS:
        return "aws"
    if p in _AZURE_PLATFORMS:
        return "azure"
    if p in _GCP_PLATFORMS:
        return "gcp"
    return ""


def decide_egress(
    *,
    provider: str,
    egress_mode: str,
    egress_allowlist_cidrs: Optional[List[str]] = None,
    egress_ports: Optional[List[int]] = None,
    tee_platform: str = "",
    cloudwatch_log_group: str = "",
) -> EgressDecision:
    """Resolve ``--siem-egress`` + provider + platform into a concrete plan.

    Raises ``ValueError`` only when the user *forced* an impossible
    combination (e.g. ``--siem-egress private`` with a Datadog provider
    that has no private intake on the chosen cloud).  ``auto`` always
    succeeds.
    """
    p = (provider or "none").lower()
    mode = (egress_mode or "auto").lower()
    cloud = _classify_cloud(tee_platform)
    cidrs = list(egress_allowlist_cidrs or [])
    ports = list(egress_ports or [443])

    decision = EgressDecision(
        cloud=cloud, egress_cidrs=cidrs, egress_ports=ports,
        cloudwatch_log_group=(cloudwatch_log_group or "") if (p == "cloudwatch" and cloud == "aws") else "",
    )

    if p == "none" or mode == "none":
        decision.note = "siem disabled or --siem-egress none"
        return decision

    if mode == "auto":
        if p in _AWS_PRIVATE_PROVIDERS and cloud == "aws":
            decision.provision_logs_endpoint = True
            decision.note = "auto -> private (AWS Interface VPC Endpoint for logs)"
            return decision
        if p in _INTRA_VPC_PROVIDERS:
            decision.note = "auto -> intra-VPC syslog collector; no NAT required"
            return decision
        # Public-internet path (Splunk Cloud, Datadog, public Azure
        # Monitor DCE, cross-region CloudWatch, etc.).
        decision.needs_public_egress = True
        if not cidrs:
            decision.note = (
                "auto -> NAT egress, allowlist=any. "
                "Pass --siem-egress-cidr to lock the SG down to specific endpoints."
            )
        else:
            decision.note = "auto -> NAT egress restricted to --siem-egress-cidr CIDRs"
        return decision

    if mode == "private":
        if p in _AWS_PRIVATE_PROVIDERS and cloud == "aws":
            decision.provision_logs_endpoint = True
            decision.note = "private -> AWS Interface VPC Endpoint for CloudWatch Logs"
            return decision
        if p in _INTRA_VPC_PROVIDERS:
            decision.note = "private -> intra-VPC syslog collector"
            return decision
        # No azure-monitor branch: removed from SIEM_PROVIDERS (no sidecar
        # exporter), so it cannot reach here.
        raise ValueError(
            f"--siem-egress private is not compatible with --siem {p} on "
            f"{tee_platform or 'this platform'}: this provider needs the "
            "public internet and there is no private alternative on the "
            "selected cloud.  Use --siem-egress public (with optional "
            "--siem-egress-cidr) or switch providers."
        )

    if mode == "public":
        decision.needs_public_egress = True
        # Cloudwatch over public is fine but wasteful; still respected.
        if p in _AWS_PRIVATE_PROVIDERS and cloud == "aws":
            decision.note = "public -> NAT egress (CloudWatch via public endpoints; consider --siem-egress private to save NAT $)"
        elif not cidrs:
            decision.note = "public -> NAT egress, allowlist=any (consider --siem-egress-cidr)"
        else:
            decision.note = "public -> NAT egress restricted to --siem-egress-cidr CIDRs"
        return decision

    # Should be unreachable thanks to validate(), but be defensive.
    raise ValueError(f"unknown --siem-egress mode {mode!r}")


def write_siem_egress_audit(build_dir: str, decision: EgressDecision) -> str:
    """Write a small JSON audit file recording the egress decision."""
    from tee_crafter.core.audit import build_layout as _layout
    os.makedirs(build_dir, exist_ok=True)
    _layout.ensure_dirs(build_dir)
    out = _layout.siem_egress_json(build_dir)
    payload: Dict[str, Any] = {
        "cloud": decision.cloud,
        "needs_public_egress": decision.needs_public_egress,
        "provision_logs_endpoint": decision.provision_logs_endpoint,
        "egress_cidrs": list(decision.egress_cidrs),
        "egress_ports": [int(p) for p in decision.egress_ports],
        "note": decision.note,
        "tfvars_env": decision.to_tfvars_env(),
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    return out


def decision_for_config(siem_config: Any, tee_platform: str) -> EgressDecision:
    """Map a ``SiemConfig`` onto :func:`decide_egress`.

    Extracted so that :func:`apply_siem_egress` and
    :func:`will_open_public_egress` cannot drift apart.  A predicted posture that
    disagrees with the applied one would be the same class of bug as the
    stale-summary defect this exists to fix.
    """
    return decide_egress(
        provider=getattr(siem_config, "provider", "none"),
        egress_mode=getattr(siem_config, "egress_mode", "auto"),
        egress_allowlist_cidrs=list(getattr(siem_config, "egress_allowlist_cidrs", []) or []),
        egress_ports=list(getattr(siem_config, "egress_ports", [443]) or [443]),
        tee_platform=tee_platform,
        cloudwatch_log_group=getattr(siem_config, "log_group", "") or "",
    )


def will_open_public_egress(siem_config: Any, *, tee_platform: str) -> bool:
    """Whether this SIEM config will end up setting ``allow_setup_egress=true``.

    :func:`apply_siem_egress` is what actually sets that variable, and it cannot
    run until ``build_dir`` exists — which is long after the deploy summary has
    already told the operator what the egress posture is.  The summary therefore
    used to describe the operator's *flag* rather than the deployment: a run that
    went on to get a NAT gateway and a default route still printed "Setup egress:
    Locked down".  This lets a caller ask the question early, from the same
    :func:`decide_egress` logic that will answer it later.

    An impossible combination returns ``False`` rather than raising:
    :func:`apply_siem_egress` raises the real, actionable error a moment later,
    and a summary line is the wrong place to surface it.
    """
    if siem_config is None or getattr(siem_config, "provider", "none") == "none":
        return False
    try:
        return decision_for_config(siem_config, tee_platform).needs_public_egress
    except ValueError:
        return False


def apply_siem_egress(
    build_dir: str,
    siem_config: Any,
    *,
    tee_platform: str,
    audit: Any = None,
    console: Any = None,
) -> Tuple[EgressDecision, Dict[str, str]]:
    """Resolve + persist + export the egress decision for *siem_config*.

    Returns ``(decision, tfvars_env)``.  ``tfvars_env`` is also written
    into ``os.environ`` so that the subsequent ``terraform apply`` picks
    it up via ``TF_VAR_*``.
    """
    decision = decision_for_config(siem_config, tee_platform)
    write_siem_egress_audit(build_dir, decision)
    env_overrides = decision.to_tfvars_env()
    for k, v in env_overrides.items():
        os.environ[k] = v
    if audit is not None:
        try:
            audit.record(
                "SIEM Egress",
                "Resolved SIEM network egress strategy",
                "info",
                tee_platform=tee_platform,
                **{
                    "needs_public_egress": decision.needs_public_egress,
                    "provision_logs_endpoint": decision.provision_logs_endpoint,
                    "egress_cidrs": list(decision.egress_cidrs),
                    "egress_ports": [int(p) for p in decision.egress_ports],
                    "note": decision.note,
                },
            )
        except Exception:
            pass
    if console is not None:
        try:
            console.print(f"[dim]SIEM egress: {decision.describe()}[/dim]")
        except Exception:
            pass
    return decision, env_overrides
