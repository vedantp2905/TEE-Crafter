"""Centralised NRAS egress policy decision for GPU CC deploys.

NET-X / SUP-X: NVIDIA's Remote Attestation Service (NRAS) is reachable only
over the public internet (no AWS/GCP/Azure service endpoints).  The
Terraform templates therefore expose two knobs:

* ``nras_egress_cidrs`` — explicit allow-list of CIDR ranges.
* ``allow_nras_broad_internet`` — broad fallback that opens HTTPS/443 to
  the cloud-provider Internet tag / 0.0.0.0/0 when CIDRs are empty.

Why strict mode is satisfiable, having once not been
----------------------------------------------------
This module used to treat "strict and no CIDRs" as an unavoidable dead end: the
rule was not created, GPU attestation failed, and the only working
configurations were the dev hatch or hand-pinned ranges.  The stated reason was
that NVIDIA publishes no NRAS edge ranges and the endpoint "sits behind a CDN
whose addresses rotate".  The first half is still true.  The second half was
wrong, and it was load-bearing.

Measured on 2026-08-23, ``nras.attestation.nvidia.com`` resolves to a **single**
A record, identical from two independent resolvers (8.8.8.8 and 1.1.1.1), inside
``34.64.0.0/10`` — Google LLC, the range GCP hands to global external
Application Load Balancers.  That is an anycast virtual IP belonging to one
load balancer, which is the opposite of a rotating CDN edge: the whole point of
the address is that it is stable and globally announced.  NVIDIA still offers no
guarantee about it, so hardcoding a constant would be wrong.  Resolving it at
deploy time is not: it is narrow, it is auditable, and it self-heals on the next
deploy if NVIDIA ever does move.

So the production default is now **resolve-and-pin**: strict mode looks up the
NRAS hostname and emits the resulting host routes as ``nras_egress_cidrs``.  The
posture stays fail-closed — if resolution yields nothing, no rule is created and
attestation fails exactly as before, rather than silently widening.

* ``TEE_CRAFTER_NRAS_CIDRS=…``      →  forward as ``TF_VAR_nras_egress_cidrs``
  (an explicit operator allow-list always wins; strict never widens it).
* ``TEE_CRAFTER_NRAS_HOSTS=…``      →  comma-separated hostnames to resolve
  instead of the default.  Needed if you move GPU verification to the SDK's
  local verifier, which talks to ``rim.attestation.nvidia.com`` and
  ``ocsp.ndis.nvidia.com`` rather than to NRAS.
* ``TEE_CRAFTER_NRAS_RESOLVE=0``    →  do not resolve; strict means "no rule",
  the older behaviour, for an air-gapped or offline-verifier deploy.
* ``TEE_CRAFTER_NRAS_STRICT=0`` (dev hatch)  →  fall back to broad
  HTTPS/443 → 0.0.0.0/0 so first-time interactive prototyping works.
  Loud console warning + audit-chain entry so the choice is recorded.

The function never raises — a deploy continues regardless — but every outcome
lands in the audit trail so compliance evidence reflects reality.
"""
from __future__ import annotations

import os
import socket
from typing import List, Optional, Sequence

from tee_crafter.cli.constants import Console

from tee_crafter.core.audit import BuildAuditTrail

#: The endpoint ``core/gpu/nvidia_attestation.NRAS_URL`` posts to.
DEFAULT_NRAS_HOSTS = ("nras.attestation.nvidia.com",)

#: Hosts the ``nv-attestation-sdk`` local verifier needs instead of NRAS, from
#: ``nv_attestation_sdk/utils/config.py`` (``NV_RIM_URL`` / ``NV_OCSP_URL``).
#: Recorded here because "use the local verifier to avoid egress" is a natural
#: idea that does not work: the local path swaps one hostname for two, and
#: ``verifier/cc_admin.py`` calls ``ocsp_certificate_chain_validation``
#: unconditionally with no flag to skip it.
LOCAL_VERIFIER_HOSTS = ("rim.attestation.nvidia.com", "ocsp.ndis.nvidia.com")


def _has_cidrs() -> bool:
    explicit = os.environ.get("TF_VAR_nras_egress_cidrs", "").strip()
    if explicit and explicit not in ("[]", "[ ]"):
        return True
    helper = os.environ.get("TEE_CRAFTER_NRAS_CIDRS", "").strip()
    return bool(helper)


def nras_hosts() -> Sequence[str]:
    """Hostnames strict mode will resolve, honouring ``TEE_CRAFTER_NRAS_HOSTS``."""
    raw = os.environ.get("TEE_CRAFTER_NRAS_HOSTS", "").strip()
    if not raw:
        return DEFAULT_NRAS_HOSTS
    hosts = [h.strip() for h in raw.split(",") if h.strip()]
    return tuple(hosts) or DEFAULT_NRAS_HOSTS


def resolve_host_cidrs(hosts: Optional[Sequence[str]] = None,
                       resolver=None) -> List[str]:
    """Resolve *hosts* to a sorted list of single-address CIDRs.

    Host routes (``/32``, ``/128``) rather than the containing allocation on
    purpose. The enclosing block for NRAS is ``34.64.0.0/10`` — four million
    Google-owned addresses — so widening to it would allow most of GCP and call
    it an allowlist.

    Returns ``[]`` on any resolution failure, and the caller keeps the
    fail-closed posture. Never raises: a DNS hiccup must not be the thing that
    takes down a deploy with a half-written NSG.
    """
    lookup = resolver or socket.getaddrinfo
    found = set()
    for host in (hosts if hosts is not None else nras_hosts()):
        try:
            infos = lookup(host, 443, 0, socket.SOCK_STREAM)
        except Exception:
            continue
        for info in infos:
            family, address = info[0], info[4][0]
            if family == socket.AF_INET:
                found.add(f"{address}/32")
            elif family == socket.AF_INET6:
                found.add(f"{address}/128")
    return sorted(found)


def _materialise_helper_cidrs() -> None:
    """Translate ``TEE_CRAFTER_NRAS_CIDRS=a.b.c.d/32,e.f.g.h/32`` into the
    Terraform-native ``TF_VAR_nras_egress_cidrs`` JSON array.  No-op when
    the operator already set ``TF_VAR_nras_egress_cidrs`` directly."""
    if os.environ.get("TF_VAR_nras_egress_cidrs"):
        return
    raw = os.environ.get("TEE_CRAFTER_NRAS_CIDRS", "").strip()
    if not raw:
        return
    cidrs = [c.strip() for c in raw.split(",") if c.strip()]
    if not cidrs:
        return
    os.environ["TF_VAR_nras_egress_cidrs"] = "[" + ",".join(f'"{c}"' for c in cidrs) + "]"


def apply_nras_egress_policy(
    console: Console,
    cloud: str,
    audit: Optional[BuildAuditTrail],
) -> str:
    """Decide and record the NRAS egress policy for this deploy.

    Returns the chosen policy string for the caller's convenience.  Always
    sets ``TF_VAR_allow_nras_broad_internet`` so the Terraform run is
    deterministic regardless of the module's own variable default.
    """
    _materialise_helper_cidrs()
    # Production default is strict.  Dev hatch ``TEE_CRAFTER_NRAS_STRICT=0``
    # opts INTO the legacy broad-internet fallback.
    strict_env = os.environ.get("TEE_CRAFTER_NRAS_STRICT", "1").strip().lower()
    strict = strict_env not in ("0", "false", "no", "off")
    cidrs_present = _has_cidrs()

    if cidrs_present:
        # Explicit allow-list wins — strict narrows the policy, never
        # rejects a narrow one.
        os.environ.setdefault("TF_VAR_allow_nras_broad_internet", "false")
        policy = "explicit_cidr_allowlist"
        console.print(
            f"[green]NRAS egress policy ({cloud}):[/green] explicit CIDR allow-list "
            f"({os.environ.get('TF_VAR_nras_egress_cidrs', '<unset>')})."
        )
    elif strict:
        os.environ["TF_VAR_allow_nras_broad_internet"] = "false"
        resolve_env = os.environ.get("TEE_CRAFTER_NRAS_RESOLVE", "1").strip().lower()
        may_resolve = resolve_env not in ("0", "false", "no", "off")
        hosts = list(nras_hosts())
        resolved = resolve_host_cidrs(hosts) if may_resolve else []

        if resolved:
            os.environ["TF_VAR_nras_egress_cidrs"] = (
                "[" + ",".join(f'"{c}"' for c in resolved) + "]")
            policy = "resolved_cidr_allowlist"
            console.print(
                f"[green]NRAS egress policy ({cloud}):[/green] strict — resolved "
                f"{', '.join(hosts)} to {', '.join(resolved)} and pinned those "
                f"host routes. No broad-internet rule."
            )
            console.print(
                "[dim]  NVIDIA publishes no NRAS ranges, so this is a "
                "point-in-time lookup: if attestation later fails with a "
                "connection timeout, re-run the deploy to re-resolve.[/dim]"
            )
        else:
            policy = "strict_no_egress"
            reason = ("resolution disabled via TEE_CRAFTER_NRAS_RESOLVE=0"
                      if not may_resolve
                      else f"could not resolve {', '.join(hosts)}")
            console.print(
                f"[yellow]NRAS egress policy ({cloud}):[/yellow] strict "
                f"(production default) and {reason} — NRAS rule will not be "
                "created. GPU attestation will fail until "
                "TEE_CRAFTER_NRAS_CIDRS or TF_VAR_nras_egress_cidrs is set."
            )
    else:
        os.environ["TF_VAR_allow_nras_broad_internet"] = "true"
        policy = "widened_to_internet_default"
        console.print(
            f"[yellow]NRAS egress policy ({cloud}):[/yellow] dev-hatch "
            f"TEE_CRAFTER_NRAS_STRICT=0 — opening HTTPS/443 to the "
            f"cloud-provider Internet tag so NRAS attestation works. "
            f"[bold]Production deploys should pin NVIDIA's published NRAS "
            f"CIDRs via TEE_CRAFTER_NRAS_CIDRS.[/bold]"
        )

    if audit:
        audit.record(
            "Phase 4: Deployment",
            f"NRAS egress policy ({cloud})",
            "pass",
            policy=policy,
            strict_mode=strict,
            cidrs_present=cidrs_present,
            # The resolved set is the whole point of the audit entry: a reader
            # six months later needs to know *which* addresses this deploy
            # trusted, not merely that it resolved something.
            nras_egress_cidrs=os.environ.get("TF_VAR_nras_egress_cidrs", ""),
            allow_nras_broad_internet=os.environ.get("TF_VAR_allow_nras_broad_internet"),
        )
    return policy
