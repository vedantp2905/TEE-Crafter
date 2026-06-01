"""General workload network egress allowlist (databases, 3rd-party APIs).

In the container-orchestrated model the user's app owns its own data: it may
open a database connection, call a SaaS API, or pull from object storage. The
TEE seals *processing*; the **network egress boundary** is therefore the
primary data-confidentiality control (a confidential workload that can open
arbitrary outbound sockets can exfiltrate plaintext regardless of the TEE).

Posture
-------
* ``deny`` (default) — no workload egress.  The host can still reach ``443``
  *inside its own VPC* (KMS / attestation VPC endpoints); nothing else leaves.
* ``vpc`` — the workload may reach destinations **inside the VPC** (e.g. a
  private RDS / Cloud SQL / Postgres peered into the deployment VPC) on the
  declared ports.  No NAT gateway is provisioned.
* ``nat`` — the workload needs a **public** destination (managed DB public
  endpoint, SaaS API).  A NAT gateway provides the route, and the security
  group is locked to exactly the resolved CIDRs + ports.

  This module no longer sets ``TF_VAR_allow_setup_egress``.  That variable is
  the *bootstrap* switch: on Azure it widens the ``AllowHTTPSEgress`` NSG rule
  from ``VirtualNetwork`` to ``*`` at priority 110 — ahead of the per-CIDR
  ``AllowSiemEgress*`` rules at 130+ — and adds an ``AllowHTTPEgressSetup``
  rule for port 80 to ``*``; on GCP it adds an EGRESS firewall rule for 80/443
  to ``0.0.0.0/0``; on AWS it adds an SG egress rule for port 80 to
  ``0.0.0.0/0``.  Setting it here meant ``--egress-mode nat`` silently opened
  the internet at higher precedence than the allowlist it had just computed.
  See :data:`NAT_FROM_ALLOWLIST_PLATFORMS` and :func:`nat_route_gap` for how
  the NAT route is obtained instead.

Reuse of the tested allowlist wiring
------------------------------------
Every per-platform ``main.template.tf`` already implements a default-deny SG
whose egress is locked to ``siem_egress_cidrs`` on ``siem_egress_ports`` (with
NAT gated on ``allow_setup_egress``).  Rather than fork that security-critical
HCL across 10 templates, this module **merges** the workload allowlist into the
same ``TF_VAR_siem_egress_cidrs`` / ``TF_VAR_siem_egress_ports`` variables (the
union of SIEM + workload destinations) and writes a separate
``workload_egress.json`` audit document so the compliance bundle records the
workload destinations distinctly from the SIEM ones.

This module is intentionally pure-data (no Terraform exec, no cloud SDKs) so it
can be unit-tested in isolation.
"""
from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

EGRESS_MODES = ("deny", "vpc", "nat")

#: Platforms whose ``main.template.tf`` provisions the NAT gateway / Cloud NAT
#: from a non-empty ``siem_egress_cidrs`` alone::
#:
#:     needs_nat = var.allow_setup_egress || length(var.siem_egress_cidrs) > 0
#:
#: On these platforms ``--egress-mode nat`` gets its route from the allowlist
#: this module already exports, so nothing else has to be switched on.
#: The three AWS templates gate every NAT resource on ``allow_setup_egress``
#: alone (``nitro/main.template.tf`` L244-L309, ``snp/aws`` L209-L277) or on
#: ``allow_nras_egress || allow_setup_egress`` (``gpu_cc/aws`` L210) — see
#: :func:`nat_route_gap`.
NAT_FROM_ALLOWLIST_PLATFORMS = frozenset({
    "snp-azure", "snp-gcp", "tdx-azure", "tdx-gcp",
    "sgx-azure", "gpu-cc-azure", "gpu-cc-gcp",
})

#: Explicit, audited opt-in that restores the old behaviour on the AWS
#: platforms: set ``TF_VAR_allow_setup_egress=true`` so the NAT gateway is
#: created, accepting that the same variable also opens ``0.0.0.0/0`` on
#: port 80 in the host security group.
ALLOW_BLANKET_NAT_ENV = "TEE_CRAFTER_ALLOW_SETUP_EGRESS_NAT"


class EgressSpecError(ValueError):
    """Raised when an ``--egress-allow`` spec is malformed."""


@dataclass
class WorkloadEgressDecision:
    """Materialised workload-egress plan."""

    mode: str = "deny"
    needs_nat: bool = False           # public destination -> NAT route required
    egress_cidrs: List[str] = field(default_factory=list)
    egress_ports: List[int] = field(default_factory=list)
    # Human-readable record of what each spec resolved to (for the audit doc).
    resolved: List[Dict[str, Any]] = field(default_factory=list)
    note: str = ""

    def describe(self) -> str:
        if self.mode == "deny" and not self.egress_cidrs:
            return "workload egress: deny-all (VPC-local 443 only)"
        bits = [f"mode={self.mode}", f"nat={'yes' if self.needs_nat else 'no'}"]
        bits.append(f"cidrs={','.join(self.egress_cidrs) or 'none'}")
        bits.append(f"ports={','.join(str(p) for p in self.egress_ports) or 'none'}")
        if self.note:
            bits.append(f"note={self.note}")
        return " ".join(bits)


def _is_cidr(token: str) -> bool:
    return "/" in token


def _looks_like_ipv4(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def parse_egress_specs(specs: List[str]) -> List[Tuple[str, int]]:
    """Parse ``host:port`` / ``cidr:port`` specs into ``(host_or_cidr, port)``.

    A CIDR spec keeps its mask: ``10.0.0.0/24:5432`` -> ``("10.0.0.0/24", 5432)``.
    ``db.internal:5432`` -> ``("db.internal", 5432)``.
    """
    out: List[Tuple[str, int]] = []
    for raw in specs or []:
        s = raw.strip()
        if not s:
            continue
        # Split on the LAST colon so CIDRs and hostnames keep their shape.
        host, sep, port_s = s.rpartition(":")
        if not sep or not host:
            raise EgressSpecError(
                f"--egress-allow {raw!r} must be 'host:port' or 'cidr:port' "
                "(e.g. db.example.com:5432 or 10.0.5.0/24:5432)")
        try:
            port = int(port_s)
        except ValueError:
            raise EgressSpecError(f"--egress-allow {raw!r}: port {port_s!r} is not an integer")
        if not (0 < port < 65536):
            raise EgressSpecError(f"--egress-allow {raw!r}: port {port} out of range")
        out.append((host, port))
    return out


def _resolve_host_to_cidrs(host: str) -> List[str]:
    """Resolve a hostname (or literal IP) to one ``/32`` CIDR per A record."""
    if _looks_like_ipv4(host):
        return [f"{host}/32"]
    addrs = sorted({
        ai[4][0]
        for ai in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    })
    if not addrs:
        raise EgressSpecError(f"--egress-allow: no A records for host {host!r}")
    return [f"{ip}/32" for ip in addrs]


def decide_workload_egress(
    *,
    egress_mode: str,
    allow_specs: List[str],
    tee_platform: str = "",
    resolver=_resolve_host_to_cidrs,
) -> WorkloadEgressDecision:
    """Resolve ``--egress-mode`` + ``--egress-allow`` into a concrete plan.

    ``resolver`` is injectable so unit tests can avoid real DNS.
    Raises :class:`EgressSpecError` on malformed specs or an impossible
    combination (allowlist entries with ``--egress-mode deny``).
    """
    mode = (egress_mode or "deny").lower()
    if mode not in EGRESS_MODES:
        raise EgressSpecError(f"--egress-mode must be one of {EGRESS_MODES}")

    parsed = parse_egress_specs(allow_specs)

    if mode == "deny":
        if parsed:
            raise EgressSpecError(
                "--egress-allow requires --egress-mode vpc (intra-VPC database) "
                "or nat (public endpoint). Default 'deny' permits no workload egress.")
        return WorkloadEgressDecision(mode="deny", note="deny-all (VPC-local 443 only)")

    cidrs: List[str] = []
    ports: List[int] = []
    resolved: List[Dict[str, Any]] = []
    for host, port in parsed:
        if _is_cidr(host):
            host_cidrs = [host]
        elif _looks_like_ipv4(host):
            host_cidrs = [f"{host}/32"]
        else:
            host_cidrs = resolver(host)
        cidrs.extend(host_cidrs)
        ports.append(port)
        resolved.append({"spec": f"{host}:{port}", "cidrs": host_cidrs, "port": port})

    cidrs = sorted(set(cidrs))
    ports = sorted(set(ports))

    if not parsed:
        # mode vpc/nat with no destinations is a no-op deny.
        return WorkloadEgressDecision(
            mode=mode, note=f"--egress-mode {mode} with no --egress-allow; nothing opened")

    needs_nat = (mode == "nat")
    note = (
        "nat -> public destination(s); SG/NSG/firewall locked to the resolved "
        "CIDRs/ports"
        if needs_nat else
        "vpc -> intra-VPC destination(s); no NAT gateway provisioned"
    )
    return WorkloadEgressDecision(
        mode=mode, needs_nat=needs_nat,
        egress_cidrs=cidrs, egress_ports=ports, resolved=resolved, note=note,
    )


def blanket_nat_override_enabled() -> bool:
    """Whether the operator opted into the ``allow_setup_egress`` NAT route."""
    return os.environ.get(ALLOW_BLANKET_NAT_ENV, "").strip().lower() in (
        "1", "true", "yes", "y", "on")


def nat_route_gap(decision: "WorkloadEgressDecision", tee_platform: str) -> str:
    """Return an error message when ``--egress-mode nat`` has no NAT route.

    Empty string means the plan is deliverable.  The three AWS templates
    create their NAT gateway only when ``allow_setup_egress`` is true, and
    that same variable opens ``0.0.0.0/0`` on port 80 — so we refuse rather
    than quietly pick one of "no route" or "open internet".  The operator can
    accept the blanket rule explicitly via
    :data:`ALLOW_BLANKET_NAT_ENV`; the choice is recorded on EGR-006.
    """
    if not decision.needs_nat or not decision.egress_cidrs:
        return ""
    if tee_platform in NAT_FROM_ALLOWLIST_PLATFORMS:
        return ""
    if blanket_nat_override_enabled():
        return ""
    return (
        f"--egress-mode nat is not wired for --tee-platform {tee_platform}.\n\n"
        "Its Terraform template gates every NAT gateway resource on "
        "`allow_setup_egress`, and that variable also adds an egress rule for "
        "port 80 to 0.0.0.0/0. Enabling it to get the route would open the "
        "internet at wider scope than the allowlist you just declared "
        f"({', '.join(decision.egress_cidrs)}).\n\n"
        "Either:\n"
        "  * use --egress-mode vpc and peer the destination into the "
        "deployment VPC; or\n"
        "  * pick a platform whose template derives the NAT from the "
        "allowlist (snp-azure, snp-gcp, tdx-azure, tdx-gcp, gpu-cc-azure, "
        "gpu-cc-gcp); or\n"
        f"  * accept the blanket rule explicitly with {ALLOW_BLANKET_NAT_ENV}=1 "
        "(recorded as a failed EGR-006 in the build provenance)."
    )


def merge_into_egress_tfvars(
    decision: WorkloadEgressDecision, tee_platform: str = "",
) -> Dict[str, str]:
    """Union the workload allowlist into the existing egress TF variables.

    Returns the ``TF_VAR_*`` env vars that were set.  Reads any values
    already placed by :mod:`siem_egress_terraform` so SIEM + workload
    destinations coexist in one allowlist.

    ``TF_VAR_allow_setup_egress`` is set only under the explicit
    :data:`ALLOW_BLANKET_NAT_ENV` opt-in (see :func:`nat_route_gap`); the
    per-CIDR ``siem_egress_cidrs`` / ``siem_egress_ports`` rules below are the
    narrow rule for the actual destination.
    """
    env: Dict[str, str] = {}
    if not decision.egress_cidrs:
        return env

    existing_cidrs: List[str] = []
    try:
        existing_cidrs = list(json.loads(os.environ.get("TF_VAR_siem_egress_cidrs", "[]") or "[]"))
    except Exception:
        existing_cidrs = []
    combined_cidrs = sorted(set(existing_cidrs) | set(decision.egress_cidrs))
    os.environ["TF_VAR_siem_egress_cidrs"] = json.dumps(combined_cidrs)
    env["TF_VAR_siem_egress_cidrs"] = os.environ["TF_VAR_siem_egress_cidrs"]

    existing_ports: List[int] = [443]
    try:
        existing_ports = [int(p) for p in json.loads(
            os.environ.get("TF_VAR_siem_egress_ports", "[443]") or "[443]")]
    except Exception:
        existing_ports = [443]
    combined_ports = sorted(set(existing_ports) | set(decision.egress_ports) | {443})
    os.environ["TF_VAR_siem_egress_ports"] = json.dumps(combined_ports)
    env["TF_VAR_siem_egress_ports"] = os.environ["TF_VAR_siem_egress_ports"]

    if decision.needs_nat and blanket_nat_override_enabled():
        os.environ["TF_VAR_allow_setup_egress"] = "true"
        env["TF_VAR_allow_setup_egress"] = "true"
    return env


def write_workload_egress_audit(build_dir: str, decision: WorkloadEgressDecision) -> str:
    """Write ``workload_egress.json`` recording the workload egress decision."""
    os.makedirs(build_dir, exist_ok=True)
    out = os.path.join(build_dir, "workload_egress.json")
    payload: Dict[str, Any] = {
        "mode": decision.mode,
        "needs_nat": decision.needs_nat,
        "egress_cidrs": list(decision.egress_cidrs),
        "egress_ports": [int(p) for p in decision.egress_ports],
        "resolved": decision.resolved,
        "note": decision.note,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    return out


def record_workload_egress_audit(audit, decision: WorkloadEgressDecision) -> None:
    """Emit EGR-005/EGR-006 verdict rows so the egress boundary is provable
    from the build provenance alone."""
    if audit is None:
        return
    try:
        audit.record(
            "Workload Egress", "Resolved workload network egress allowlist", "info",
            mode=decision.mode, needs_nat=decision.needs_nat,
            egress_cidrs=list(decision.egress_cidrs),
            egress_ports=[int(p) for p in decision.egress_ports],
            note=decision.note,
        )
    except Exception:
        pass

    # EGR-005 — default-deny unless explicitly allowlisted.
    try:
        audit.record_check(
            "Workload Egress", "Egress is deny-by-default or explicitly allowlisted",
            "EGR-005",
            expected=True, observed=True,
            note=("deny-all" if decision.mode == "deny" and not decision.egress_cidrs
                  else f"{decision.mode}: {len(decision.egress_cidrs)} cidr(s)"),
        )
    except Exception:
        pass

    # EGR-006 — no 0.0.0.0/0 in the EFFECTIVE rule set.  Grading only
    # ``decision.egress_cidrs`` reported observed=True even while
    # ``TF_VAR_allow_setup_egress=true`` was opening 80/443 to the world at
    # higher precedence than that allowlist; the flag is now part of the
    # verdict.
    try:
        wide = [c for c in decision.egress_cidrs if c in ("0.0.0.0/0", "::/0")]
        blanket = os.environ.get(
            "TF_VAR_allow_setup_egress", "false").strip().lower() == "true"
        if wide:
            note = f"WIDE allowlist entries: {wide}"
        elif blanket:
            note = (
                "allowlist is narrow, but TF_VAR_allow_setup_egress=true also "
                "opens 0.0.0.0/0 on 80/443 (Azure NSG priority 110 outranks the "
                f"per-CIDR rules at 130+). Set by {ALLOW_BLANKET_NAT_ENV} or by "
                "an unbaked-AMI deploy."
            )
        else:
            note = "ok"
        audit.record_check(
            "Workload Egress", "Effective egress rules contain no 0.0.0.0/0",
            "EGR-006",
            expected=True, observed=(not wide and not blanket),
            note=note,
        )
    except Exception:
        pass


def apply_workload_egress(
    build_dir: str,
    *,
    egress_mode: str,
    allow_specs: List[str],
    tee_platform: str,
    audit: Any = None,
    console: Any = None,
) -> Tuple[WorkloadEgressDecision, Dict[str, str]]:
    """Resolve + persist + export the workload egress decision.

    Returns ``(decision, tfvars_env)``.  Raises :class:`EgressSpecError` on a
    bad spec/combination so the deploy aborts before provisioning anything.
    """
    decision = decide_workload_egress(
        egress_mode=egress_mode, allow_specs=allow_specs, tee_platform=tee_platform,
    )
    gap = nat_route_gap(decision, tee_platform)
    if gap:
        raise EgressSpecError(gap)
    write_workload_egress_audit(build_dir, decision)
    env = merge_into_egress_tfvars(decision, tee_platform)
    record_workload_egress_audit(audit, decision)
    if console is not None:
        try:
            console.print(f"[dim]Workload egress: {decision.describe()}[/dim]")
        except Exception:
            pass
    return decision, env
