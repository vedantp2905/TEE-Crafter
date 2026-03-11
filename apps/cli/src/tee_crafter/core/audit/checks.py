"""Master catalogue of audit evidence ``check_id``s.

Every pass/fail row in :class:`AuditEvidenceLedger` is keyed by an entry
defined here.  This is the single source of truth: the deployment phases
record observations against these IDs, ``tee-crafter verify-provenance
--required-checks`` consumes them, and ``docs/audit_matrix.md`` is
generated from the same table.

Every spec carries:

* ``category`` — coarse grouping used by the renderer (PC, DH, PKG, …)
* ``severity`` — ``critical`` (production CI gate),
  ``high`` (CI should usually gate),
  ``moderate`` (informational but with a verdict), or
  ``informational`` (visibility only).
* ``default_expected`` — the production-correct observation.  Compared
  against ``observed`` to derive the default verdict; phases may pass
  an explicit verdict when the comparison is non-trivial.
* ``platform_filter`` — set of ``tee_platform`` values this check
  applies to (``frozenset()`` means *all platforms*).
* ``source_kind`` — where the evidence comes from: ``pipeline``,
  ``probe`` (on-instance SSM / Bastion / IAP), or ``cloud_audit``
  (CloudTrail / Azure Activity / GCP Audit).
* ``responsibility`` — who can act on a failure: ``product``,
  ``customer``, or ``shared``.
* ``title`` — short human-readable name.
* ``remediation`` — single-sentence pointer to the fix.

The catalogue is intentionally exhaustive so the production-grade
``--required-checks`` set has stable IDs to anchor to.  IDs are
*append-only*: never re-purpose an ID once shipped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional


class Verdict(str, Enum):
    """Canonical verdict values for an audit evidence row."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    NOT_APPLICABLE = "not_applicable"
    NOT_EVALUATED = "not_evaluated"
    """The check applies to this platform but no evidence was gathered.

    Distinct from :attr:`PASS` (evidence gathered, it matched), from
    :attr:`NOT_APPLICABLE` (the check does not apply, so its absence is
    correct) and from :attr:`WARN` (evidence gathered, it was ambiguous).
    A row must never be ``pass`` because a proxy — an exit code, a
    ``locals()`` lookup, a hardcoded ``True`` — stood in for the check it
    names; ``not_evaluated`` is the honest verdict in that case, and it
    does NOT satisfy a ``--required-checks`` gate.
    """
    INFO = "info"

    @classmethod
    def from_status(cls, status: str) -> "Verdict":
        """Map a free-form trail status string to a canonical verdict."""
        m = (status or "").strip().lower()
        return {
            "pass": cls.PASS,
            "fail": cls.FAIL,
            "warn": cls.WARN,
            "na": cls.NOT_APPLICABLE,
            "n/a": cls.NOT_APPLICABLE,
            "not_applicable": cls.NOT_APPLICABLE,
            "skip": cls.NOT_APPLICABLE,
            "not_evaluated": cls.NOT_EVALUATED,
            "info": cls.INFO,
        }.get(m, cls.INFO)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    INFORMATIONAL = "informational"


class SourceKind(str, Enum):
    PIPELINE = "pipeline"
    PROBE = "probe"
    CLOUD_AUDIT = "cloud_audit"


class Responsibility(str, Enum):
    PRODUCT = "product"
    CUSTOMER = "customer"
    SHARED = "shared"


ALL_PLATFORMS: FrozenSet[str] = frozenset({
    "nitro-aws",
    "snp-aws",
    "snp-azure",
    "snp-gcp",
    "tdx-azure",
    "tdx-gcp",
    "sgx-azure",
    "gpu-cc-aws",
    "gpu-cc-azure",
    "gpu-cc-gcp",
})

AWS_PLATFORMS: FrozenSet[str] = frozenset({
    "nitro-aws", "snp-aws", "gpu-cc-aws",
})
AZURE_PLATFORMS: FrozenSet[str] = frozenset({
    "snp-azure", "tdx-azure", "sgx-azure", "gpu-cc-azure",
})
GCP_PLATFORMS: FrozenSet[str] = frozenset({
    "snp-gcp", "tdx-gcp", "gpu-cc-gcp",
})
GPU_CC_PLATFORMS: FrozenSet[str] = frozenset({
    "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
})
NITRO_PLATFORMS: FrozenSet[str] = frozenset({"nitro-aws"})
SNP_PLATFORMS: FrozenSet[str] = frozenset({"snp-aws", "snp-azure", "snp-gcp"})
TDX_PLATFORMS: FrozenSet[str] = frozenset({"tdx-azure", "tdx-gcp"})
SGX_PLATFORMS: FrozenSet[str] = frozenset({"sgx-azure"})
#: Platforms whose quote is an Intel DCAP quote, and which therefore share the
#: PCK chain, QE-report and TCB-collateral verification path.  ``gpu-cc-gcp``
#: belongs here even though it is a GPU platform: its CPU side is TDX.  Leaving
#: it out of an Intel-wide filter is how it ended up as the only one of the four
#: with no QE-report signature check at all.
INTEL_DCAP_PLATFORMS: FrozenSet[str] = (
    TDX_PLATFORMS | SGX_PLATFORMS | frozenset({"gpu-cc-gcp"})
)


@dataclass(frozen=True)
class CheckSpec:
    """One entry in the master :data:`CHECKS` catalogue."""

    check_id: str
    title: str
    category: str
    severity: Severity
    source_kind: SourceKind
    responsibility: Responsibility
    default_expected: Optional[object] = None
    platform_filter: FrozenSet[str] = field(default_factory=frozenset)
    remediation: str = ""

    def applies_to(self, tee_platform: str) -> bool:
        """Return True when this check applies to *tee_platform*."""
        if not self.platform_filter:
            return True
        return tee_platform in self.platform_filter


def _all() -> FrozenSet[str]:
    return frozenset()


# Categories used in summaries / the rendered matrix.  Order matters: it
# becomes the section order in `audit_evidence.txt` / `.md` / `.html`.
CATEGORIES: List[str] = [
    "PC", "DH", "PKG", "VLN", "IAC", "IAM", "DEP",
    "PDR", "ATT", "SIEM", "BYOK", "EGR", "RES", "CT", "TEAR", "PROV",
]

CATEGORY_TITLES: Dict[str, str] = {
    "PC": "Pipeline & Config",
    "DH": "Dev-hatch posture",
    "PKG": "Packaging",
    "VLN": "Vulnerability gate",
    "IAC": "Infrastructure as Code",
    "IAM": "Identity",
    "DEP": "Deploy",
    "PDR": "Post-deploy runtime probes",
    "ATT": "Attestation",
    "SIEM": "Logging (SIEM)",
    "BYOK": "Customer key release (BYOK)",
    "EGR": "Egress lockdown",
    "RES": "Data residency",
    "CT": "Cloud audit logs",
    "TEAR": "Teardown",
    "PROV": "Provenance",
}


def _spec(
    check_id: str,
    title: str,
    category: str,
    severity: Severity,
    source_kind: SourceKind,
    responsibility: Responsibility = Responsibility.PRODUCT,
    default_expected: Optional[object] = None,
    platform_filter: Optional[FrozenSet[str]] = None,
    remediation: str = "",
) -> CheckSpec:
    return CheckSpec(
        check_id=check_id,
        title=title,
        category=category,
        severity=severity,
        source_kind=source_kind,
        responsibility=responsibility,
        default_expected=default_expected,
        platform_filter=platform_filter or _all(),
        remediation=remediation,
    )


# ----------------------------- Catalogue --------------------------------
_PIPELINE = SourceKind.PIPELINE
_PROBE = SourceKind.PROBE
_CLOUD = SourceKind.CLOUD_AUDIT

CHECKS: Dict[str, CheckSpec] = {}


def _add(spec: CheckSpec) -> None:
    if spec.check_id in CHECKS:
        raise RuntimeError(f"duplicate check_id: {spec.check_id}")
    CHECKS[spec.check_id] = spec


# PC — Pipeline & Config
_add(_spec("PC-001", "tee_platform recognised", "PC",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("PC-002", "flow detected", "PC",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("PC-003", "build_dir writable", "PC",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("PC-004", "cli version recorded", "PC",
           Severity.INFORMATIONAL, _PIPELINE))
_add(_spec("PC-005", "SLSA emitter loaded", "PC",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("PC-006", "Ed25519 signing key loaded", "PC",
           Severity.CRITICAL, _PIPELINE, default_expected="longlived",
           remediation="Run `tee-crafter audit-gen-signing-key` or set "
                       "TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE."))
_add(_spec("PC-007", "Provenance signing succeeded", "PC",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("PC-008", "Hash-chain integrity", "PC",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("PC-009", "Audit ledger emitted", "PC",
           Severity.CRITICAL, _PIPELINE, default_expected=True))


# DH — Dev-hatch posture
_add(_spec("DH-001", "TEE_CRAFTER_PROXY_STRICT_IMDS == 1", "DH",
           Severity.HIGH, _PIPELINE, default_expected="1",
           platform_filter=AWS_PLATFORMS,
           remediation="Unset TEE_CRAFTER_PROXY_STRICT_IMDS or set =1."))
_add(_spec("DH-002", "TEE_CRAFTER_PROXY_NO_CREDS posture", "DH",
           Severity.MODERATE, _PIPELINE, default_expected="0",
           platform_filter=NITRO_PLATFORMS))
_add(_spec("DH-003", "TEE_CRAFTER_NRAS_STRICT == 1", "DH",
           Severity.HIGH, _PIPELINE, default_expected="1",
           platform_filter=GPU_CC_PLATFORMS))
_add(_spec("DH-004", "TEE_CRAFTER_STRICT_TSM == 1", "DH",
           Severity.HIGH, _PIPELINE, default_expected="1",
           platform_filter=frozenset({"tdx-gcp", "gpu-cc-gcp"})))
_add(_spec("DH-005", "TEE_CRAFTER_SIEM_FAIL_OPEN == 0", "DH",
           Severity.HIGH, _PIPELINE, default_expected="0"))
_add(_spec("DH-006", "TEE_CRAFTER_ALLOW_VULNERABLE unset", "DH",
           Severity.HIGH, _PIPELINE, default_expected=""))
_add(_spec("DH-007", "TEE_CRAFTER_ACCEPT_PARTIAL_CC unset", "DH",
           Severity.HIGH, _PIPELINE, default_expected="",
           platform_filter=GPU_CC_PLATFORMS))
_add(_spec("DH-008", "TEE_CRAFTER_STRICT_SNP_AK_BINDING == 1", "DH",
           Severity.HIGH, _PIPELINE, default_expected="1",
           platform_filter=frozenset({"snp-azure"})))
# DH-009 used to audit TEE_CRAFTER_TDX_ALLOW_MISSING_QE_IDENTITY.  That hatch
# is gone: the hand-copied QE-SVN floor and the unsigned qe_identity.json reader
# it belonged to were both deleted when real signature-verified Intel collateral
# landed.  An audit row for an env var that nothing reads reports "unset, good"
# about a control that does not exist -- the same class of empty assurance this
# catalogue exists to prevent -- so the ID is repointed at the hatch that
# actually disables TCB evaluation today, across all four Intel platforms rather
# than just the two TDX ones.
_add(_spec("DH-009", "TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS unset",
           "DH", Severity.HIGH, _PIPELINE, default_expected="",
           platform_filter=INTEL_DCAP_PLATFORMS))
# Widening the accepted tcbStatus set is a real policy decision, not a dev
# hatch: it can only ever add SWHardeningNeeded / ConfigurationNeeded (the
# evaluator refuses OutOfDate and Revoked under every policy), so it is worth
# recording rather than failing on.
_add(_spec("DH-018", "TEE_CRAFTER_TCB_ALLOW_STATUS unset", "DH",
           Severity.MODERATE, _PIPELINE, default_expected="",
           platform_filter=INTEL_DCAP_PLATFORMS))
_add(_spec("DH-010", "TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL unset", "DH",
           Severity.HIGH, _PIPELINE, default_expected=""))
_add(_spec("DH-011", "TEE_CRAFTER_SKIP_POST_DESTROY_SHRED unset", "DH",
           Severity.HIGH, _PIPELINE, default_expected=""))
_add(_spec("DH-012", "TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE unset", "DH",
           Severity.MODERATE, _PIPELINE, default_expected=""))
_add(_spec("DH-013", "TF_VAR_allow_nras_broad_internet == false", "DH",
           Severity.HIGH, _PIPELINE, default_expected="false",
           platform_filter=GPU_CC_PLATFORMS))
_add(_spec("DH-014", "TF_VAR_allow_setup_egress == false", "DH",
           Severity.MODERATE, _PIPELINE, default_expected="false"))
_add(_spec("DH-015", "TF_VAR_enable_secure_boot == true", "DH",
           Severity.HIGH, _PIPELINE, default_expected="true",
           platform_filter=AWS_PLATFORMS))
_add(_spec("DH-016",
           "TF_VAR_byok_aws_kms_arn set when BYOK + SNP/GPU-CC AWS", "DH",
           Severity.HIGH, _PIPELINE, default_expected=True,
           platform_filter=frozenset({"snp-aws", "gpu-cc-aws"})))
# The GCP twin of DH-016.  DH-016 was AWS-only, and so was the control it
# guards: on GCP the CLI exported only the boolean `TF_VAR_byok_gcp_kms`
# (which buys Cloud KMS *reachability*), never the key id, so the CVM service
# account was granted no Cloud KMS role and the in-TEE unwrap failed
# PERMISSION_DENIED with BYOK fully configured.  Both the control and its
# detector are now per-cloud.
_add(_spec("DH-019",
           "TF_VAR_byok_gcp_kms_key_id set when BYOK + GCP", "DH",
           Severity.HIGH, _PIPELINE, default_expected=True,
           platform_filter=GCP_PLATFORMS))
_add(_spec("DH-017", "--allow-unbaked-ami not used", "DH",
           Severity.HIGH, _PIPELINE, default_expected=False,
           platform_filter=AWS_PLATFORMS))


# PKG — Packaging (container flow)
_add(_spec("PKG-001", "Docker image built (tag + digest pinned)", "PKG",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("PKG-002", "Dockerfile sha256 recorded", "PKG",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("PKG-003", "Entrypoint sha256 recorded", "PKG",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("PKG-004", "user_cmd recorded", "PKG",
           Severity.INFORMATIONAL, _PIPELINE))
_add(_spec("PKG-005", "No .env / no secrets in build context", "PKG",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("PKG-006", "Container tar bundle sha256 (nitro)", "PKG",
           Severity.MODERATE, _PIPELINE, default_expected=True,
           platform_filter=NITRO_PLATFORMS))
_add(_spec("PKG-007", "EIF build success + PCR0/1/2 captured", "PKG",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           platform_filter=NITRO_PLATFORMS))
_add(_spec("PKG-008", "AMI tag tee-crafter-secure-boot=enabled", "PKG",
           Severity.HIGH, _PIPELINE, default_expected=True,
           platform_filter=AWS_PLATFORMS))


# VLN — Vulnerability gate
_add(_spec("VLN-001", "Vulnerability scanner ran", "VLN",
           Severity.HIGH, _PIPELINE, default_expected=True))
# "fixable" = the scanner reports an upstream fixed version.  Unfixed distro
# CVEs are counted and recorded but do not fail these checks, matching the
# deploy gate exactly (core/security/vuln_scan.py::VulnScanResult.blocking_*).
# Before 2026-08 these took the raw counts and disagreed with the gate, which
# failed `verify-provenance` on builds the deploy had approved.
# TEE_CRAFTER_VULN_STRICT=1 makes both revert to the raw counts together.
_add(_spec("VLN-002", "fixable critical == 0", "VLN",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("VLN-003", "fixable high <= threshold", "VLN",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("VLN-004", "fixable medium <= threshold", "VLN",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("VLN-005", "Dependency manifest hash-pinned", "VLN",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("VLN-006", "Container base image digest pinned", "VLN",
           Severity.MODERATE, _PIPELINE, default_expected=True))


# IAC — Infrastructure as Code
_add(_spec("IAC-001", "terraform validate clean", "IAC",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("IAC-002", "No SSH ingress in SG/NSG/firewall", "IAC",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("IAC-003", "No 0.0.0.0/0 workload-port ingress", "IAC",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("IAC-004", "KMS key policy attestation-gated (AWS)", "IAC",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           platform_filter=AWS_PLATFORMS))
_add(_spec("IAC-005", "Azure Key Vault SKR release policy present", "IAC",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           platform_filter=AZURE_PLATFORMS))
_add(_spec("IAC-006", "GCP KMS attestation binding present", "IAC",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           platform_filter=GCP_PLATFORMS))
_add(_spec("IAC-007", "VPC endpoints for KMS/SSM/Logs", "IAC",
           Severity.HIGH, _PIPELINE, default_expected=True,
           platform_filter=AWS_PLATFORMS))
_add(_spec("IAC-008", "Secure-Boot variable enabled (baked AMI)", "IAC",
           Severity.HIGH, _PIPELINE, default_expected=True,
           platform_filter=AWS_PLATFORMS))
_add(_spec("IAC-009", "NRAS egress CIDRs narrow", "IAC",
           Severity.HIGH, _PIPELINE, default_expected=True,
           platform_filter=GPU_CC_PLATFORMS))


# IAM — Identity
_add(_spec("IAM-001", "Caller principal recorded", "IAM",
           Severity.MODERATE, _PIPELINE))
_add(_spec("IAM-002", "Caller is non-root (warn if root)", "IAM",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("IAM-003", "Instance profile / Managed Identity attached", "IAM",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("IAM-004", "Required actions simulate-pass", "IAM",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("IAM-005", "Least-privilege boundary policy attached", "IAM",
           Severity.MODERATE, _PIPELINE))


# DEP — Deploy
_add(_spec("DEP-001", "terraform apply success", "DEP",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("DEP-002", "Instance running", "DEP",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("DEP-003", "AMI/image id matches pinned", "DEP",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("DEP-004", "No public IP (or only via NAT)", "DEP",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("DEP-005", "IMDSv2 required (Terraform state)", "DEP",
           Severity.HIGH, _PIPELINE, default_expected=True,
           platform_filter=AWS_PLATFORMS))


# PDR — Post-deploy runtime probes
_add(_spec("PDR-001", "Management plane reachable (SSM/Bastion/IAP)",
           "PDR", Severity.CRITICAL, _PROBE, default_expected=True))
_add(_spec("PDR-002", "cloud-init completed", "PDR",
           Severity.HIGH, _PROBE, default_expected=True))
_add(_spec("PDR-003", "Host TEE service active", "PDR",
           Severity.CRITICAL, _PROBE, default_expected=True))
_add(_spec("PDR-004", "IMDSv2-only on host", "PDR",
           Severity.HIGH, _PROBE, default_expected=True,
           platform_filter=AWS_PLATFORMS))
_add(_spec("PDR-005", "Enclave / CVM started (cpu, ram)", "PDR",
           Severity.CRITICAL, _PROBE, default_expected=True))
_add(_spec("PDR-006", "Host proxy systemd unit active", "PDR",
           Severity.HIGH, _PROBE, default_expected=True,
           platform_filter=NITRO_PLATFORMS))
_add(_spec("PDR-007", "vsock-proxy allowlist == 1 entry", "PDR",
           Severity.HIGH, _PROBE, default_expected=True,
           platform_filter=NITRO_PLATFORMS))
_add(_spec("PDR-008", "No SSH authorized_keys on host", "PDR",
           Severity.HIGH, _PROBE, default_expected=True))
_add(_spec("PDR-009", "Systemd hardening flags loaded", "PDR",
           Severity.HIGH, _PROBE, default_expected=True))
_add(_spec("PDR-010", "No tee_enclave SUDO escape in logs", "PDR",
           Severity.HIGH, _PROBE, default_expected=True))
_add(_spec("PDR-011", "Time sync OK (chrony / systemd-timesyncd)", "PDR",
           Severity.MODERATE, _PROBE, default_expected=True))


# ATT — Attestation (every row reflects what the per-platform
# verifier client.py actually checks at runtime, harvested by
# ``emit_att_verdicts`` from a single ``ATTESTATION_REPORT``
# stdout line).  Build-time concerns (e.g. measurement baseline
# captured, root CA bundled with the client) are folded into the
# runtime checks because the verifier itself reads those baselines
# from ``measurements.json`` / ``trusted_roots/`` at handshake time.
_add(_spec("ATT-001", "Client received attestation report", "ATT",
           Severity.HIGH, _PIPELINE, default_expected=True,
           remediation="Client.py never emitted ATTESTATION_REPORT — "
                       "inspect client_stderr.log for the handshake error."))
_add(_spec("ATT-002", "Attestation signature / cert chain valid", "ATT",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           remediation="Verifier rejected the report signature.  Confirm "
                       "the vendor root CA bundle in trusted_roots/ "
                       "matches the deployed TEE family (AMD/Intel/AWS/"
                       "NVIDIA)."))
_add(_spec("ATT-003", "Measurement matches build baseline", "ATT",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           remediation="PCR / MRENCLAVE / MRTD / RTMR observed by client "
                       "differs from measurements.json — rebuild or "
                       "re-pin the baseline if the change is intentional."))
_add(_spec("ATT-004", "Issuer in pinned allowlist", "ATT",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           remediation="The attestation report's issuer is not in the "
                       "build-time issuer allowlist (`trusted_roots/` "
                       "or platform-specific pin).  Add the issuer or "
                       "rotate the TEE family."))
_add(_spec("ATT-005", "TCB / SVN >= floor (freshness)", "ATT",
           Severity.HIGH, _PIPELINE, default_expected=True,
           remediation="TCB SVN is below the floor configured in "
                       "measurements.json.  Update the firmware / "
                       "microcode on the platform or raise the floor "
                       "after an audit."))
_add(_spec("ATT-006", "Nonce binding present in report", "ATT",
           Severity.HIGH, _PIPELINE, default_expected=True,
           remediation="The attestation report does not carry the "
                       "client-supplied nonce, opening a replay window. "
                       "Re-run; if persistent, the verifier is broken."))
_add(_spec("ATT-007", "TLS SPKI sha256 captured", "ATT",
           Severity.MODERATE, _PIPELINE, default_expected=True,
           remediation="``spki_sha256`` not in ATTESTATION_REPORT.  The "
                       "client cannot bind future TLS connections to "
                       "the attested server pubkey."))
_add(_spec("ATT-008", "Continuous-attestation pulses observed",
           "ATT", Severity.MODERATE, _PIPELINE, default_expected=True,
           remediation="No pulses received during the verify window.  "
                       "For --persistent VM-class runs, check the attested "
                       "ingress proxy / host re-attest loop "
                       "(tee-crafter-attest.timer).  SGX batch uses "
                       "deploy-time attestation only."))
_add(_spec("ATT-009", "nvAttest (NRAS) verdict valid", "ATT",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           platform_filter=GPU_CC_PLATFORMS,
           remediation="NVIDIA NRAS rejected the GPU attestation JWT. "
                       "Inspect nras_token_kid / nras_eat_digest in the "
                       "ATTESTATION_REPORT and confirm the NRAS API "
                       "key + region."))
_add(_spec("ATT-010", "Dual-attestation CPU+GPU bound", "ATT",
           Severity.CRITICAL, _PIPELINE, default_expected=True,
           platform_filter=GPU_CC_PLATFORMS,
           remediation="The CPU TEE report and the NVIDIA NRAS token "
                       "are not cryptographically bound (different "
                       "nonces or measurement digests).  Rebuild the "
                       "GPU-CC client.py with the latest binding "
                       "helper."))


# SIEM — Logging
_add(_spec("SIEM-001", "SIEM provider resolved", "SIEM",
           Severity.MODERATE, _PIPELINE))
_add(_spec("SIEM-002", "fail_open observed value", "SIEM",
           Severity.HIGH, _PIPELINE, default_expected=False))
_add(_spec("SIEM-003", "SIEM sidecar systemd active", "SIEM",
           Severity.HIGH, _PROBE, default_expected=True))
_add(_spec("SIEM-004", "First boot event delivered", "SIEM",
           Severity.HIGH, _PROBE, default_expected=True))
_add(_spec("SIEM-005", "interval_seconds <= 60", "SIEM",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("SIEM-006", "Events signed (sign_events=True)", "SIEM",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("SIEM-007", "Egress CIDRs narrow (no 0.0.0.0/0)", "SIEM",
           Severity.HIGH, _PIPELINE, default_expected=True))


# BYOK — Customer key release
_add(_spec("BYOK-001", "Provider resolved", "BYOK",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("BYOK-002", "Unwrap mode correct for tee_platform", "BYOK",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("BYOK-003", "key_id_tail recorded", "BYOK",
           Severity.INFORMATIONAL, _PIPELINE))
_add(_spec("BYOK-004", "Allowlist size known", "BYOK",
           Severity.INFORMATIONAL, _PIPELINE))
_add(_spec("BYOK-005", "max_attestation_age_seconds <= 600", "BYOK",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("BYOK-006", "byok-stage executed (if requested)", "BYOK",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("BYOK-007", "Secret split (tmpfs relocation) succeeded",
           "BYOK", Severity.HIGH, _PROBE, default_expected=True))
_add(_spec("BYOK-008", "First in-TEE decrypt succeeded", "BYOK",
           Severity.CRITICAL, _PROBE, default_expected=True))
_add(_spec("BYOK-009", "KMS key policy matches expected", "BYOK",
           Severity.CRITICAL, _CLOUD, default_expected=True))
_add(_spec("BYOK-010", "byok_config sha256 recorded", "BYOK",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("BYOK-011", "Key release bound to a vetted measurement", "BYOK",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("BYOK-012", "Application .env envelope-sealed to BYOK key", "BYOK",
           Severity.HIGH, _PIPELINE, default_expected=True,
           remediation="--secrets-env envelope-seals the .env to the BYOK key at build "
                       "time, so the cleartext is only recoverable by a principal that "
                       "can satisfy the key's attestation policy; the sealed bundle rides "
                       "tmpfs only (never host disk / image / byok.json). On CVM the "
                       "tee-crafter-secrets oneshot attested-unseals it to "
                       "/run/tee_crafter/app.env before the workload starts (fail-closed)."))
_add(_spec("BYOK-013", "BYOK runtime fail-closed gate engaged", "BYOK",
           Severity.HIGH, _PIPELINE, default_expected=True,
           remediation="When BYOK is enabled the workload refuses requests until the "
                       "attested DEK release lands (byok_health on direct-code platforms; "
                       "the secrets oneshot Requires= on CVM container mode). Dev hatch "
                       "TEE_CRAFTER_BYOK_FAIL_OPEN=1 disables — never set in production."))
_add(_spec("BYOK-014", "Sealed/baked .env delivered to workload at runtime", "BYOK",
           Severity.HIGH, _PIPELINE, default_expected=True,
           remediation="The secrets oneshot (CVM) / EIF entrypoint (Nitro baked) surfaces "
                       "the .env to the container at /run/tee_crafter/app.env. If this is "
                       "WARN/FAIL the platform/mode does not deliver (Nitro sealed, SGX) — "
                       "carry config in the Dockerfile (ENV) instead."))

# RES — Data residency (only emitted when TEE_CRAFTER_RESIDENCY_POLICY is set)
_add(_spec("RES-001", "Deployment region within residency policy", "RES",
           Severity.HIGH, _PIPELINE, default_expected=True))


# EGR — Egress lockdown
_add(_spec("EGR-001", "NRAS-strict observed", "EGR",
           Severity.HIGH, _PIPELINE, default_expected=True,
           platform_filter=GPU_CC_PLATFORMS))
_add(_spec("EGR-002", "Egress CIDR list narrow", "EGR",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("EGR-003", "setup-egress closed post-bootstrap", "EGR",
           Severity.HIGH, _PROBE, default_expected=True))
_add(_spec("EGR-004", "No public-internet route table by default",
           "EGR", Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("EGR-005", "Workload egress deny-by-default or explicitly allowlisted",
           "EGR", Severity.HIGH, _PIPELINE, default_expected=True,
           remediation="Use --egress-mode vpc/nat with --egress-allow host:port to "
                       "open a database / 3rd-party endpoint; default deny opens nothing."))
_add(_spec("EGR-006", "Workload egress allowlist contains no 0.0.0.0/0",
           "EGR", Severity.HIGH, _PIPELINE, default_expected=True,
           remediation="Replace any 0.0.0.0/0 destination with the specific CIDR(s) "
                       "of the database / API the workload must reach."))


# CT — Cloud audit logs
_add(_spec("CT-001", "CloudTrail RunInstances for instance_id", "CT",
           Severity.MODERATE, _CLOUD, default_expected=True,
           platform_filter=AWS_PLATFORMS))
_add(_spec("CT-002", "CloudTrail kms:Decrypt by instance role", "CT",
           Severity.HIGH, _CLOUD, default_expected=True,
           platform_filter=AWS_PLATFORMS))
_add(_spec("CT-003", "CloudTrail NitroEnclave attestation event",
           "CT", Severity.MODERATE, _CLOUD, default_expected=True,
           platform_filter=NITRO_PLATFORMS))
_add(_spec("CT-004", "CloudTrail Terraform-state bucket event", "CT",
           Severity.INFORMATIONAL, _CLOUD,
           platform_filter=AWS_PLATFORMS))
_add(_spec("CT-005", "Azure Activity Log Key Vault SKR", "CT",
           Severity.HIGH, _CLOUD, default_expected=True,
           platform_filter=AZURE_PLATFORMS))
_add(_spec("CT-006", "GCP audit log cloudkms.useToDecrypt", "CT",
           Severity.HIGH, _CLOUD, default_expected=True,
           platform_filter=GCP_PLATFORMS))
_add(_spec("CT-007", "Cloud-logs heartbeat received (if selected)",
           "CT", Severity.MODERATE, _CLOUD))


# TEAR — Teardown
_add(_spec("TEAR-001", "terraform destroy success", "TEAR",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("TEAR-002", "Post-destroy shred ran", "TEAR",
           Severity.HIGH, _PIPELINE, default_expected=True))
_add(_spec("TEAR-003", "No orphaned KMS aliases", "TEAR",
           Severity.MODERATE, _CLOUD, default_expected=True))
_add(_spec("TEAR-004", "No orphaned security groups", "TEAR",
           Severity.MODERATE, _CLOUD, default_expected=True))
_add(_spec("TEAR-005", "Local docker prune ran", "TEAR",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("TEAR-006", "Build dir contains no key material", "TEAR",
           Severity.HIGH, _PIPELINE, default_expected=True))


# PROV — Provenance artefacts
_add(_spec("PROV-001", "Signing key kind", "PROV",
           Severity.HIGH, _PIPELINE, default_expected="longlived"))
_add(_spec("PROV-002", "build_provenance.sig present", "PROV",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("PROV-003", "Public-key sha256 matches pin", "PROV",
           Severity.HIGH, _PIPELINE))
_add(_spec("PROV-004", "SLSA in-toto attestation present", "PROV",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("PROV-005", "DSSE envelope present", "PROV",
           Severity.MODERATE, _PIPELINE, default_expected=True))
_add(_spec("PROV-006", "Hash chain verifies", "PROV",
           Severity.CRITICAL, _PIPELINE, default_expected=True))
_add(_spec("PROV-007", "Ledger emitted + signed", "PROV",
           Severity.CRITICAL, _PIPELINE, default_expected=True))


# The default "production gate" — what `verify-provenance --required-checks`
# uses when the operator does not pass an explicit list.  Every entry must
# be a key in :data:`CHECKS`.
DEFAULT_REQUIRED_CHECKS: List[str] = [
    "PC-001", "PC-006", "PC-007", "PC-008", "PC-009",
    "PROV-002", "PROV-006", "PROV-007",
    "DH-001", "DH-005", "DH-006", "DH-010", "DH-011",
    "VLN-002",
    "IAC-001", "IAC-002", "IAC-003",
    "DEP-001", "DEP-002",
    # Runtime attestation: the verifier client must actually have
    # received a report, validated its signature/chain, matched the
    # baseline measurement, and bound a fresh nonce.  ATT-004
    # (issuer allowlist) and ATT-005 (TCB freshness) gate against
    # the auditor-visible trust policy.
    "ATT-001", "ATT-002", "ATT-003", "ATT-004", "ATT-005", "ATT-006",
    "TEAR-001",
]


def required_checks_for(tee_platform: str) -> List[str]:
    """Return the default required-check list filtered to *tee_platform*."""
    out: List[str] = []
    for cid in DEFAULT_REQUIRED_CHECKS:
        spec = CHECKS.get(cid)
        if spec is None:
            continue
        if spec.applies_to(tee_platform):
            out.append(cid)
    return out


def filter_checks(
    *,
    category: Optional[str] = None,
    platform: Optional[str] = None,
    source_kind: Optional[SourceKind] = None,
) -> List[CheckSpec]:
    """Return the list of CheckSpec matching the given filters."""
    out: List[CheckSpec] = []
    for spec in CHECKS.values():
        if category and spec.category != category:
            continue
        if platform and not spec.applies_to(platform):
            continue
        if source_kind and spec.source_kind != source_kind:
            continue
        out.append(spec)
    return out


def derive_verdict(expected: object, observed: object) -> Verdict:
    """Compute a default verdict from an ``expected`` / ``observed`` pair.

    Booleans get an exact compare; strings compare case-insensitively;
    anything else uses Python equality.  ``observed is None`` always
    returns :attr:`Verdict.WARN` (we received no evidence).

    When *expected* is ``None`` the check is informational — the
    callsite recorded a value but did not assert a production
    expectation.  We surface that as :attr:`Verdict.INFO` so the
    matrix retains the value without producing a misleading
    ``fail`` against ``None``.
    """
    if observed is None:
        return Verdict.WARN
    if expected is None:
        return Verdict.INFO
    if isinstance(expected, bool) or isinstance(observed, bool):
        return Verdict.PASS if bool(expected) == bool(observed) else Verdict.FAIL
    if isinstance(expected, str) and isinstance(observed, str):
        return (Verdict.PASS
                if expected.strip().lower() == observed.strip().lower()
                else Verdict.FAIL)
    return Verdict.PASS if expected == observed else Verdict.FAIL


__all__ = [
    "ALL_PLATFORMS",
    "AWS_PLATFORMS",
    "AZURE_PLATFORMS",
    "CATEGORIES",
    "CATEGORY_TITLES",
    "CHECKS",
    "CheckSpec",
    "DEFAULT_REQUIRED_CHECKS",
    "GCP_PLATFORMS",
    "GPU_CC_PLATFORMS",
    "NITRO_PLATFORMS",
    "Responsibility",
    "Severity",
    "SGX_PLATFORMS",
    "SNP_PLATFORMS",
    "SourceKind",
    "TDX_PLATFORMS",
    "Verdict",
    "derive_verdict",
    "filter_checks",
    "required_checks_for",
]
