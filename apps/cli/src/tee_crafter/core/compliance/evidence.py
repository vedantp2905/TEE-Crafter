"""EvidenceCollector: extracts typed evidence categories from build provenance."""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from tee_crafter.core.compliance.registry import EvidenceItem, Strength


_PLATFORM_CLOUD = {
    "nitro-aws": "aws",
    "snp-aws": "aws",
    "snp-azure": "azure",
    "snp-gcp": "gcp",
    "tdx-azure": "azure",
    "tdx-gcp": "gcp",
    "sgx-azure": "azure",
    "gpu-cc-gcp": "gcp",
    "gpu-cc-azure": "azure",
    "gpu-cc-aws": "aws",
}

_PLATFORM_TEE_TECH = {
    "nitro-aws": "Nitro Enclaves",
    "snp-aws": "AMD SEV-SNP",
    "snp-azure": "AMD SEV-SNP",
    "snp-gcp": "AMD SEV-SNP",
    "tdx-azure": "Intel TDX",
    "tdx-gcp": "Intel TDX",
    "sgx-azure": "Intel SGX / Gramine",
    "gpu-cc-gcp": "Intel TDX + NVIDIA CC",
    "gpu-cc-azure": "AMD SEV-SNP + NVIDIA CC",
    "gpu-cc-aws": "NitroTPM + NVIDIA CC",
}

_GPU_CC_PLATFORMS = {"gpu-cc-gcp", "gpu-cc-azure", "gpu-cc-aws"}


_EVIDENCE_CHECK_BACKING: Dict[str, List[str]] = {
    "tee_hardware_isolation": ["PC-001", "ATT-003"],
    "ratls_attestation": ["ATT-001", "ATT-002", "ATT-003", "ATT-006"],
    "encryption_in_transit": ["ATT-002", "ATT-006"],
    "zero_ingress_network": ["IAC-002", "IAC-003", "PDR-005"],
    "systemd_sandboxing": ["PDR-008"],
    "docker_hardening": ["PKG-001", "PKG-002", "PKG-003", "PKG-005"],
    "hash_chain_integrity": ["PC-008", "PROV-005"],
    "ed25519_signature": ["PROV-002", "PROV-003"],
    "continuous_attestation": ["ATT-008"],
    "vulnerability_scan": ["VLN-001", "VLN-002", "VLN-003"],
    "vpc_isolation": ["IAC-002", "IAC-003", "IAC-007"],
    "supply_chain_controls": ["PKG-001", "VLN-001"],
    "deployer_least_privilege": ["IAM-001", "IAM-002", "IAM-004"],
    "kms_egress_scoping": ["IAC-004", "BYOK-001"],
    "egress_lockdown_mode": ["DH-006", "SIEM-007"],
    "audit_log_tamper_evidence": ["PC-008", "PROV-005"],
    "log_redaction": ["SIEM-006"],
    "dependency_hash_pinning": ["VLN-001", "PKG-001"],
    "script_hash_pinning": ["PKG-001", "PKG-002"],
    "container_digest_pinning": ["PKG-001", "PKG-002"],
    "measured_boot_vtpm": ["PDR-006"],
    "canonical_measurements_published": ["PKG-001", "ATT-003"],
    "access_control": ["IAM-001", "IAM-002", "PDR-007"],
    "build_reproducibility": ["PKG-002", "PKG-003"],
    "key_rotation_evidence": ["BYOK-001"],
    "data_retention_controls": ["TEAR-002", "TEAR-006"],
    "runtime_audit_logging": ["SIEM-001", "SIEM-006"],
    # Legacy key identifiers retained for framework-mapping stability.  In the
    # container-only product these map to real container controls rather than
    # the removed LLM/AST pipeline (see ``_ast_confinement`` /
    # ``_output_schema_validation`` for the honest, container-era semantics).
    "ast_confinement": ["PKG-001", "PKG-002", "PKG-003"],
    "output_schema_validation": ["TEAR-002", "SIEM-006"],
    "ephemeral_keys": ["BYOK-007"],
    "gpu_confidential_computing": ["ATT-003"],
    "gpu_attestation": ["ATT-001", "ATT-002"],
    "dual_attestation_cpu_gpu": ["ATT-001", "ATT-002", "ATT-003"],
    "attestation_tls_binding": ["ATT-002", "ATT-006"],
    "tcb_freshness": ["ATT-005"],
    "attestation_issuer_allowlist": ["ATT-007"],
    "encryption_at_rest": ["BYOK-001", "BYOK-002"],
    "workload_egress_allowlist": ["EGR-005", "EGR-006"],
}

# Ledger verdicts that count as proof that a backing check actually ran and
# succeeded.  ``not_applicable`` is neutral (the check does not apply to this
# build), so it neither proves nor disproves the claim.  Everything else --
# ``fail``, ``warn``, ``info``, ``not_evaluated`` and "no row at all" -- leaves
# the claim unproven.  See ``AuditEvidenceLedger.sweep_not_evaluated``.
_PROVING_VERDICTS = frozenset({"pass"})
_NEUTRAL_VERDICTS = frozenset({"not_applicable"})


def _find_entries(entries: List[Dict], *, phase: str | None = None,
                  step_contains: str | None = None,
                  status: str | None = None) -> List[Dict]:
    """Filter provenance entries by phase, step substring, or status."""
    results = []
    for e in entries:
        if phase and e.get("phase") != phase:
            continue
        if step_contains and step_contains.lower() not in e.get("step", "").lower():
            continue
        if status and e.get("status") != status:
            continue
        results.append(e)
    return results


def _detect_platform(doc: Dict[str, Any]) -> str:
    """Best-effort detection of TEE platform from provenance entries."""
    for entry in doc.get("entries", []):
        details = entry.get("details", {})
        platform = details.get("platform") or details.get("tee_platform")
        if platform and platform in _PLATFORM_CLOUD:
            return platform
    build_dir = doc.get("build_dir", "")
    for plat in _PLATFORM_CLOUD:
        tag = plat.replace("-", "_")
        if tag in build_dir:
            return plat
    return "unknown"


def _detect_flow(doc: Dict[str, Any]) -> str:
    """Detect the deployment flow.

    The product is container-only (the LLM ingestion / source-handler
    pipeline was removed), so every real build is ``container``.  We still
    return ``unknown`` for malformed/legacy provenance that carries no
    container packaging entry, so downstream evidence collectors can gate
    correctly.
    """
    for e in doc.get("entries", []):
        phase = e.get("phase", "").lower()
        step = e.get("step", "").lower()
        if "container" in phase or "container" in step:
            return "container"
    return "unknown"


def _detect_run_mode(doc: Dict[str, Any]) -> str:
    """Detect the run mode: ``batch`` or ``persistent``.

    A ``Batch Run`` entry (recorded by ``BuildAuditTrail.record_batch_run``)
    is the unambiguous signal that the user container was executed to
    completion under the batch collector.  Absent that, a build that staged
    a long-running service is treated as ``persistent``.
    """
    for e in doc.get("entries", []):
        phase = (e.get("phase", "") or "").lower()
        step = (e.get("step", "") or "").lower()
        if phase == "batch run" or step.startswith("batch_"):
            return "batch"
    return "persistent"


class EvidenceCollector:
    """Reads ``build_provenance.json`` and extracts typed evidence items."""

    def __init__(self, provenance_path: str) -> None:
        self._path = provenance_path
        with open(provenance_path, "r", encoding="utf-8") as f:
            self._doc: Dict[str, Any] = json.load(f)
        self._entries: List[Dict] = self._doc.get("entries", [])
        self.platform = _detect_platform(self._doc)
        self.flow = _detect_flow(self._doc)
        self.run_mode = _detect_run_mode(self._doc)
        self.cloud = _PLATFORM_CLOUD.get(self.platform, "unknown")
        self._entry_blob_lower_cache: str | None = None
        self._entry_blob_cache: str | None = None

    @property
    def chain_head_hash(self) -> str:
        return self._doc.get("chain_head_hash", "")

    @property
    def is_gpu_cc(self) -> bool:
        return self.platform in _GPU_CC_PLATFORMS

    def _all_entries_text_lower(self) -> str:
        if self._entry_blob_lower_cache is None:
            self._entry_blob_lower_cache = self._all_entries_text().lower()
        return self._entry_blob_lower_cache

    def _all_entries_text(self) -> str:
        """Case-preserving variant of ``_all_entries_text_lower``.

        Used by evidence collectors that need to apply regex against the raw
        provenance JSON (e.g. SHA-256 digest pinning detection where the hex
        case is significant for downstream tools).
        """
        if self._entry_blob_cache is None:
            parts: List[str] = []
            for e in self._entries:
                parts.append(e.get("step", "") or "")
                parts.append(e.get("phase", "") or "")
                for k, v in (e.get("details") or {}).items():
                    parts.append(str(k))
                    parts.append(str(v))
            self._entry_blob_cache = "\n".join(parts)
        return self._entry_blob_cache

    def _load_ledger_verdicts(self) -> Dict[str, str]:
        """Load audit_evidence.json sitting next to the provenance file."""
        from tee_crafter.core.audit import build_layout as _layout
        # *self._path* may be ``provenance/build_provenance.json`` (new
        # layout) or top-level (legacy); walk back to the build root so
        # both work.
        prov_dir = os.path.dirname(self._path)
        build_dir = (os.path.dirname(prov_dir)
                     if os.path.basename(prov_dir) == _layout.PROVENANCE_DIR
                     else prov_dir)
        ledger_path = _layout.resolve_audit_evidence_json(build_dir)
        if not os.path.isfile(ledger_path):
            return {}
        try:
            with open(ledger_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except Exception:
            return {}
        return {
            r.get("check_id"): r.get("verdict", "")
            for r in (doc.get("rows") or [])
            if r.get("check_id")
        }

    def _reconcile_with_ledger(
        self, items: List[EvidenceItem],
    ) -> List[EvidenceItem]:
        """Decide, per evidence item, whether an audit check actually proved it.

        A collector can only report what it observed in the build provenance.
        Whether the claim was independently checked is the audit ledger's job
        (``audit_evidence.json``), so this is where ``EvidenceItem.verified``
        gets set.  An item is verified only when *every* backing check for it
        has a ledger row and none of those rows is anything other than ``pass``
        or ``not_applicable``:

        - any backing check with verdict ``fail`` → unverified, capped at
          ``MODERATE``, tagged ``downgraded_by_failed_checks``.
        - any backing check absent, ``not_evaluated``, ``warn`` or ``info`` →
          unverified, capped at ``MODERATE``, tagged
          ``unproven_checks``.  Absence is not evidence, and neither is a
          ``not_evaluated`` row emitted by ``sweep_not_evaluated``.
        - every backing check present and proving → verified, and the item is
          raised to ``STRONG`` because an independent check confirmed it.

        With no ledger at all (staging-only or legacy artifacts) nothing can be
        proved, so every item stays unverified.  That is deliberate: an
        unverified item does not count towards control coverage, so a build
        that never ran its audit checks cannot certify anything.
        """
        from tee_crafter.core.compliance.registry import Strength
        verdicts = self._load_ledger_verdicts()
        for it in items:
            cids = _EVIDENCE_CHECK_BACKING.get(it.key, [])
            if not cids:
                # No backing check is defined, so there is nothing that could
                # prove this item.  Leave it unverified rather than grandfather
                # it in.
                it.artifacts.setdefault("no_backing_checks", True)
                continue
            it.check_ids = list(cids)
            failed = [cid for cid in cids if verdicts.get(cid) == "fail"]
            unproven = [
                cid for cid in cids
                if verdicts.get(cid, "") not in _PROVING_VERDICTS
                and verdicts.get(cid, "") not in _NEUTRAL_VERDICTS
            ]
            proving = [cid for cid in cids if verdicts.get(cid) in _PROVING_VERDICTS]
            if failed:
                it.verified = False
                if it.strength == Strength.STRONG:
                    it.strength = Strength.MODERATE
                it.artifacts.setdefault("downgraded_by_failed_checks", failed)
            elif unproven or not proving:
                it.verified = False
                if it.strength == Strength.STRONG:
                    it.strength = Strength.MODERATE
                it.artifacts.setdefault(
                    "unproven_checks", unproven or list(cids),
                )
            else:
                it.verified = True
                it.strength = Strength.STRONG
                it.artifacts.setdefault("verified_by_checks", proving)
        return items

    def collect_all(self) -> List[EvidenceItem]:
        """Run all evidence collectors and return the full inventory."""
        collectors = [
            self._tee_hardware_isolation,
            self._ratls_attestation,
            self._encryption_in_transit,
            self._encryption_at_rest,
            self._zero_ingress_network,
            self._systemd_sandboxing,
            self._docker_hardening,
            self._hash_chain_integrity,
            self._ed25519_signature,
            self._ast_confinement,
            self._output_schema_validation,
            self._supply_chain_controls,
            self._ephemeral_keys,
            self._build_reproducibility,
            self._access_control,
            self._runtime_audit_logging,
            self._continuous_attestation,
            self._vulnerability_scan,
            self._data_retention,
            self._key_rotation,
            self._vpc_isolation,
            self._gpu_confidential_computing,
            self._gpu_attestation,
            self._dual_attestation_cpu_gpu,
            self._attestation_tls_binding,
            self._tcb_freshness,
            self._attestation_issuer_allowlist,
            self._egress_lockdown_mode,
            self._workload_egress_allowlist,
            self._kms_egress_scoping,
            self._deployer_least_privilege,
            self._audit_log_tamper_evidence,
            self._log_redaction,
            self._dependency_hash_pinning,
            self._script_hash_pinning,
            self._container_digest_pinning,
            self._measured_boot_vtpm,
            self._canonical_measurements_published,
        ]
        items: List[EvidenceItem] = []
        for fn in collectors:
            item = fn()
            if item is not None:
                items.append(item)
        return self._reconcile_with_ledger(items)

    # ---- Helpers for deriving evidence strength from what was collected ----

    def _observed_details(self, *keys: str) -> Dict[str, Any]:
        """Return the subset of *keys* that appear with a truthy value in any
        provenance entry's ``details``."""
        found: Dict[str, Any] = {}
        for e in self._entries:
            for k, v in (e.get("details") or {}).items():
                if k in keys and v not in (None, "", False):
                    found[k] = v
        return found

    @staticmethod
    def _strength_from_observations(observed: int, expected: int) -> Strength:
        """Grade an evidence item by how much of what it claims was observed.

        ``STRONG`` is reserved for items where the build provenance carries the
        full set of artifacts the claim rests on.  Where nothing was observed
        the claim is only as good as the template that produced it, which is
        ``INFORMATIONAL`` — never ``STRONG``.
        """
        if expected <= 0 or observed <= 0:
            return Strength.INFORMATIONAL
        if observed >= expected:
            return Strength.STRONG
        return Strength.MODERATE

    @staticmethod
    def _packaged_path(*parts: str) -> str:
        """Absolute path to a file inside the installed ``tee_crafter`` package."""
        pkg_root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        return os.path.join(pkg_root, *parts)

    #: Commands that would make the batch bundle encrypted / signed.  If a
    #: future revision of the capture script gains any of these, the derived
    #: claim below flips on its own instead of going stale.
    _ENCRYPT_MARKERS = ("openssl enc", "gpg --encrypt", "gpg -e ",
                        "age --encrypt", "age -e ", "sops -e")
    _SIGN_MARKERS = ("openssl dgst -sign", "gpg --sign", "gpg --detach-sig",
                     "cosign sign", "minisign -S")

    def _capture_script_path(self) -> str:
        """Path to the script that actually produces the batch bundle."""
        return self._packaged_path(
            "scripts", "common", "tee_crafter_capture_container.sh")

    def _batch_bundle_facts(self) -> Dict[str, Any]:
        """Derive the batch-output-bundle claims from the script that makes it.

        ``scripts/common/tee_crafter_capture_container.sh`` is what actually
        produces ``/var/lib/tee_crafter/output.tar.gz``, so it — not a
        constant in this file — is the source of truth for whether the
        bundle is encrypted, signed, integrity-checked, and what mode it
        lands at.  An earlier revision hard-coded "encrypted, signed"; the
        script has never done either, and hard-coding the *correct* answer
        instead would only postpone the same drift.
        """
        path = self._capture_script_path()
        facts: Dict[str, Any] = {
            "capture_script": "scripts/common/tee_crafter_capture_container.sh",
        }
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError:
            # Cannot read the producer, so claim nothing about its output.
            facts["capture_script_staged"] = False
            return facts
        facts["capture_script_staged"] = True
        facts["capture"] = "plain_tar_gz" if "tar czf" in text else "unknown"
        facts["integrity"] = ("sha256_sidecar" if "sha256sum" in text
                              else "none_observed")
        facts["bundle_encrypted"] = any(
            m in text for m in self._ENCRYPT_MARKERS)
        facts["bundle_signed"] = any(m in text for m in self._SIGN_MARKERS)
        # The script has no size cap; assert that only by observing one.
        facts["bundle_size_capped"] = "BUNDLE_MAX_BYTES" in text
        mode = re.search(r'chmod\s+(0?[0-7]{3,4})\s+"\$bundle"', text)
        facts["bundle_mode"] = mode.group(1) if mode else "unknown"
        return facts

    def _seccomp_profile(self) -> Dict[str, Any]:
        """Report the seccomp profile that is actually staged into TEE hosts.

        The platform setup scripts inline
        ``templates/common/seccomp-container.json`` via
        ``cli.loaders._inject_security_profiles``, and the systemd units refuse
        to start without ``/etc/tee_crafter/seccomp-container.json``.  So the
        honest source of truth for "is there a custom profile?" is whether that
        packaged file exists — not a hard-coded ``"custom"`` string.
        """
        path = self._packaged_path(
            "templates", "common", "seccomp-container.json")
        if not os.path.isfile(path):
            return {"seccomp": "docker-default", "seccomp_profile_staged": False}
        info: Dict[str, Any] = {
            "seccomp": "custom",
            "seccomp_profile_staged": True,
            "seccomp_profile": "seccomp-container.json",
        }
        try:
            with open(path, "r", encoding="utf-8") as f:
                profile = json.load(f)
            rules = profile.get("syscalls") or []
            info["seccomp_default_action"] = profile.get("defaultAction", "")
            # ``syscalls`` is a list of *rule groups*, each carrying a
            # ``names`` array.  Reporting len(rules) as "syscall rules" read
            # as "this profile mentions 6 syscalls" when it actually
            # allowlists a few hundred across 6 groups, which understates the
            # profile to anyone auditing the number.
            info["seccomp_rule_groups"] = len(rules)
            info["seccomp_syscall_rules"] = sum(
                len(r.get("names") or []) for r in rules
                if isinstance(r, dict))
            info["seccomp_default_deny"] = str(
                profile.get("defaultAction", "")).upper() in (
                "SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS")
        except (OSError, ValueError):
            # The file is staged but unreadable/malformed here; say so rather
            # than assert anything about its contents.
            info["seccomp_profile_parsed"] = False
        return info

    def _tee_hardware_isolation(self) -> Optional[EvidenceItem]:
        artifacts: Dict[str, Any] = {"platform": self.platform}
        tee_tech = _PLATFORM_TEE_TECH.get(self.platform, "Unknown TEE")
        artifacts["tee_technology"] = tee_tech

        measurement_keys = (
            "PCR0", "PCR1", "PCR2", "eif_sha256", "measurement", "mrtd",
            "mrenclave", "mrsigner", "cc_mode", "gpu_model", "gpu_count",
        )
        measurements = self._observed_details(*measurement_keys)
        artifacts.update(measurements)

        # An isolation claim is only as strong as the measurements backing it:
        # a known platform with at least one hardware measurement is STRONG, a
        # known platform with none is MODERATE, and an unrecognised platform
        # tells us nothing at all.
        if self.platform == "unknown":
            strength = Strength.INFORMATIONAL
        elif measurements:
            strength = Strength.STRONG
        else:
            strength = Strength.MODERATE
        artifacts["measurements_observed"] = sorted(measurements)

        if self.is_gpu_cc:
            gpu_desc = " NVIDIA GPU memory is hardware-encrypted via Confidential Computing mode."
        else:
            gpu_desc = ""

        return EvidenceItem(
            key="tee_hardware_isolation",
            title="Hardware TEE Isolation",
            description=f"Workload runs inside {tee_tech} hardware-isolated execution environment. "
                        f"CPU memory encryption prevents host/hypervisor/co-tenant access.{gpu_desc}",
            source="build_provenance.json (platform + measurement entries)",
            artifacts=artifacts,
            strength=strength,
        )

    def _ratls_attestation(self) -> Optional[EvidenceItem]:
        artifacts: Dict[str, Any] = {"platform": self.platform}
        entries = _find_entries(self._entries, step_contains="attestation") + \
                  _find_entries(self._entries, step_contains="pcr") + \
                  _find_entries(self._entries, step_contains="client script")
        binding_keys = ("PCR0", "PCR1", "PCR2", "pcr_values_injected",
                        "client_py_sha256", "root_ca_sha256", "measurement")
        observed: List[str] = []
        for e in entries:
            d = e.get("details", {})
            for k in binding_keys:
                if k in d:
                    artifacts[k] = d[k]
                    if d[k] not in (None, "", False):
                        observed.append(k)

        # The claim is that the serving certificate is bound to a measurement.
        # STRONG needs both halves in the provenance: a measurement *and* the
        # client-side binding that pins it.
        has_measurement = any(
            k in observed for k in ("PCR0", "PCR1", "PCR2", "measurement")
        )
        has_binding = any(
            k in observed for k in ("pcr_values_injected", "client_py_sha256",
                                    "root_ca_sha256")
        )
        artifacts["binding_artifacts_observed"] = sorted(set(observed))
        if has_measurement and has_binding:
            strength = Strength.STRONG
        elif has_measurement or has_binding:
            strength = Strength.MODERATE
        else:
            strength = Strength.INFORMATIONAL

        return EvidenceItem(
            key="ratls_attestation",
            title="Remote Attestation TLS (RA-TLS)",
            description="TLS certificate is bound to hardware attestation report. "
                        "Client verifies TEE identity before sending data.",
            source="build_provenance.json (client template + attestation entries)",
            artifacts=artifacts,
            strength=strength,
        )

    def _encryption_in_transit(self) -> Optional[EvidenceItem]:
        # Nothing about the live TLS channel is observable from a build
        # provenance file, so this is a statement about the template that was
        # generated, not a measurement.  It stays INFORMATIONAL unless the
        # provenance shows the RA-TLS material that the channel is built from,
        # and only the audit ledger (ATT-002 / ATT-006) can raise it further.
        channel = self._observed_details(
            "root_ca_sha256", "client_py_sha256", "pcr_values_injected",
        )
        return EvidenceItem(
            key="encryption_in_transit",
            title="End-to-End Encryption in Transit",
            description="All data transmitted via RA-TLS (attestation-bound TLS) or ECIES "
                        "end-to-end encryption. No plaintext leaves the TEE boundary.",
            source="Generated client/server templates (build_provenance.json)",
            artifacts={
                "protocol": "RA-TLS / ECIES",
                "platform": self.platform,
                "channel_artifacts_observed": sorted(channel),
            },
            strength=(Strength.MODERATE if channel else Strength.INFORMATIONAL),
        )

    def _encryption_at_rest(self) -> Optional[EvidenceItem]:
        tee_tech = _PLATFORM_TEE_TECH.get(self.platform, "Unknown TEE")
        # This is a property of the TEE platform, not of anything this build
        # produced.  Knowing which platform was targeted is the most we can
        # observe, so MODERATE is the ceiling here.
        return EvidenceItem(
            key="encryption_at_rest",
            title="Encryption at Rest (TEE Memory Encryption)",
            description=f"{tee_tech} provides hardware memory encryption. Data in TEE memory "
                        "is never stored in plaintext on disk. Ephemeral keys are never persisted.",
            source="TEE platform property (platform detected from build_provenance.json)",
            artifacts={"tee_technology": tee_tech, "mechanism": "hardware_memory_encryption",
                       "platform": self.platform},
            strength=(Strength.INFORMATIONAL if self.platform == "unknown"
                      else Strength.MODERATE),
        )

    def _zero_ingress_network(self) -> Optional[EvidenceItem]:
        artifacts: Dict[str, Any] = {"cloud": self.cloud}
        tf_entries = _find_entries(self._entries, step_contains="terraform")
        ingress_flags = ("security_group_https_only", "vpc_endpoint_for_kms",
                         "no_ssh_ingress", "kms_policy_pcr_bound")
        asserted: List[str] = []
        for e in tf_entries:
            d = e.get("details", {})
            for k in ingress_flags:
                if k in d:
                    artifacts[k] = d[k]
                    if d[k] is True:
                        asserted.append(k)

        # The two flags that actually carry the zero-ingress claim are
        # ``no_ssh_ingress`` and ``security_group_https_only``; the rest are
        # supporting detail.  Without them this is just an unbacked assertion.
        required = {"no_ssh_ingress", "security_group_https_only"}
        artifacts["ingress_flags_observed"] = sorted(set(asserted))
        strength = self._strength_from_observations(
            len(required & set(asserted)), len(required),
        )

        return EvidenceItem(
            key="zero_ingress_network",
            title="Zero-Ingress Network Isolation",
            description="Security groups / NSGs / firewalls allow zero public inbound traffic. "
                        "Management access via SSM/Bastion/IAP only. No SSH keys or public IPs.",
            source="build_provenance.json (Terraform config entries)",
            artifacts=artifacts,
            strength=strength,
        )

    def _systemd_sandboxing(self) -> Optional[EvidenceItem]:
        # The unit file is written at bake time and is not echoed into the
        # provenance, so nothing here is observed.  PDR-008 (which reads the
        # hardening directives off the deployed host) is what can prove it.
        return EvidenceItem(
            key="systemd_sandboxing",
            title="Systemd Service Sandboxing",
            description="Application service runs under strict systemd sandbox: "
                        "ProtectSystem=strict, NoNewPrivileges, PrivateTmp, "
                        "RestrictNamespaces, SystemCallFilter allowlist, "
                        "ProtectKernelModules/Logs/Tunables, dedicated tee_enclave user.",
            source="Bake-time systemd unit configuration (verified post-deploy by PDR-008)",
            artifacts={"service_user": "tee_enclave", "protect_system": "strict"},
            strength=Strength.INFORMATIONAL,
        )

    def _docker_hardening(self) -> Optional[EvidenceItem]:
        if self.flow != "container":
            return None
        if self.platform == "nitro-aws":
            return EvidenceItem(
                key="docker_hardening",
                title="Enclave Image Boundary (Nitro)",
                description="Container is merged into EIF. Enclave boundary provides "
                            "stronger isolation than Docker security controls.",
                source="Nitro container flow (build_provenance.json EIF entries)",
                artifacts={
                    "mechanism": "eif_boundary",
                    "run_mode": self.run_mode,
                    **self._observed_details("eif_sha256", "PCR0"),
                },
                # The EIF measurement is what makes the enclave boundary
                # checkable; without it this is only an assertion.
                strength=(Strength.STRONG
                          if self._observed_details("eif_sha256", "PCR0")
                          else Strength.INFORMATIONAL),
            )
        # CVM platforms run the user container under a systemd unit.  The
        # persistent unit (``container.service.template``) adds ``--read-only``
        # rootfs; the batch unit (``container.batch.service.template``) runs the
        # image as-is so it can write its output bundle, so it does NOT set
        # ``--read-only``.  Report each mode accurately rather than claiming a
        # read-only rootfs for both (production-honesty: batch ≠ persistent).
        is_batch = self.run_mode == "batch"
        seccomp = self._seccomp_profile()
        artifacts: Dict[str, Any] = {
            "cap_drop": "ALL",
            "apparmor": "tee-crafter-container",
            "no_new_privileges": True,
            "pids_limit": 512,
            "network": "host",
            "read_only_rootfs": not is_batch,
            "run_mode": self.run_mode,
            **seccomp,
        }
        seccomp_clause = (
            "custom seccomp profile" if seccomp["seccomp_profile_staged"]
            else "the Docker default seccomp profile (no custom profile is "
                 "staged in this build)"
        )
        if is_batch:
            description = (
                f"User container runs with --cap-drop ALL, {seccomp_clause}, "
                "AppArmor MAC, no-new-privileges, --pids-limit 512.  Batch mode "
                "runs the image as-is (writable rootfs) to capture its output "
                "bundle; --network host is used (TEE VM has zero ingress)."
            )
        else:
            description = (
                f"User container runs with --cap-drop ALL, {seccomp_clause}, "
                "AppArmor MAC, --read-only rootfs, no-new-privileges, "
                "--pids-limit 512.  --network host is used (TEE VM has zero "
                "ingress; the attested proxy fronts all traffic)."
            )
        return EvidenceItem(
            key="docker_hardening",
            title="Docker Container Hardening",
            description=description,
            source="Bake-time container security config "
                   "(templates/common/seccomp-container.json; "
                   "verified post-deploy by PDR-008)",
            artifacts=artifacts,
            # The run flags are set by the systemd unit at deploy time and are
            # not echoed into the provenance.  The one thing checkable here is
            # whether the custom seccomp profile ships at all.
            strength=(Strength.MODERATE if seccomp["seccomp_profile_staged"]
                      else Strength.INFORMATIONAL),
        )

    def _hash_chain_integrity(self) -> Optional[EvidenceItem]:
        from tee_crafter.core.audit.report import verify_chain
        ok, msg = verify_chain(self._path)
        return EvidenceItem(
            key="hash_chain_integrity",
            title="Hash-Chain Provenance Integrity",
            description="Build provenance is a hash-chained, tamper-evident record. "
                        "Each entry's prev_hash equals SHA-256 of the preceding entry.",
            source=f"verify_chain({os.path.basename(self._path)})",
            artifacts={
                "chain_valid": ok,
                "chain_head_hash": self.chain_head_hash,
                "total_entries": len(self._entries),
                "error": msg if not ok else "",
            },
            strength=Strength.STRONG if ok else Strength.INFORMATIONAL,
        )

    def _ed25519_signature(self) -> Optional[EvidenceItem]:
        from tee_crafter.core.audit.audit import BuildAuditTrail
        ok, msg = BuildAuditTrail.verify_signature(self._path)
        return EvidenceItem(
            key="ed25519_signature",
            title="Ed25519 Provenance Signature",
            description="Provenance document is signed with an ephemeral Ed25519 key. "
                        "Signature covers canonical JSON serialization.",
            source=f"verify_signature({os.path.basename(self._path)})",
            artifacts={"signature_valid": ok, "error": msg if not ok else ""},
            strength=Strength.STRONG if ok else Strength.INFORMATIONAL,
        )

    def _ast_confinement(self) -> Optional[EvidenceItem]:
        # ``ast_confinement`` is a legacy evidence-key identifier (kept stable
        # for framework mappings).  In the container-only product the
        # equivalent control is OS-level *workload confinement*: the user
        # container is constrained by --cap-drop ALL, a custom seccomp profile,
        # AppArmor MAC and no-new-privileges rather than static analysis of
        # generated code.  Only emit when we actually have a hardened container
        # build to point at.
        if self.flow != "container":
            return None
        seccomp = self._seccomp_profile()
        seccomp_clause = (
            "a custom seccomp profile" if seccomp["seccomp_profile_staged"]
            else "the Docker default seccomp profile (no custom profile is "
                 "staged in this build)"
        )
        return EvidenceItem(
            key="ast_confinement",
            title="Workload Confinement (Container Sandbox)",
            description="The user workload runs inside a confined container: "
                        f"--cap-drop ALL, {seccomp_clause}, AppArmor MAC, "
                        "no-new-privileges, and a pids limit.  Combined with the "
                        "TEE boundary this constrains what the workload can do "
                        "even if compromised.",
            source="Bake-time container security config "
                   "(templates/common/seccomp-container.json)",
            artifacts={
                "cap_drop": "ALL",
                "apparmor": "tee-crafter-container", "no_new_privileges": True,
                **seccomp,
            },
            strength=(Strength.MODERATE if seccomp["seccomp_profile_staged"]
                      else Strength.INFORMATIONAL),
        )

    def _output_schema_validation(self) -> Optional[EvidenceItem]:
        # Legacy evidence-key identifier.  The container product does not bound
        # per-response output by JSON schema; the honest container-era control
        # is *output handling*.  Every claim below is read out of the capture
        # script itself by ``_batch_bundle_facts`` rather than asserted here,
        # so the prose cannot drift away from what the script does.
        if self.flow != "container":
            return None
        facts = self._batch_bundle_facts()
        if not facts["capture_script_staged"]:
            description = (
                "The batch capture script is not present in this "
                "installation, so nothing can be said about how the output "
                "bundle is produced or protected. Runtime audit logs are "
                "redacted so no plaintext payloads or secrets are emitted "
                "off the TEE."
            )
        else:
            checked = (
                ("encrypted", facts["bundle_encrypted"]),
                ("signed", facts["bundle_signed"]),
                ("size-capped", facts["bundle_size_capped"]),
            )
            present = [name for name, ok in checked if ok]
            absent = [name for name, ok in checked if not ok]
            clauses = []
            if present:
                clauses.append(", ".join(present))
            if absent:
                clauses.append("NOT " + ", NOT ".join(absent))
            integrity = (
                "a SHA-256 sidecar for post-transfer integrity checking"
                if facts["integrity"] == "sha256_sidecar"
                else "no integrity sidecar")
            description = (
                "Batch output is captured into a gzip tarball at "
                f"/var/lib/tee_crafter/output.tar.gz with {integrity}, "
                f"written mode {facts['bundle_mode']}. The bundle is "
                f"{'; it is '.join(clauses)}. "
                "Runtime audit logs are redacted so no plaintext payloads "
                "or secrets are emitted off the TEE."
            )
        return EvidenceItem(
            key="output_schema_validation",
            title="Output Handling & Redaction",
            description=description,
            source="scripts/common/tee_crafter_capture_container.sh + SIEM redaction",
            artifacts={**facts, "log_redaction": True},
            strength=Strength.INFORMATIONAL,
        )

    def _supply_chain_controls(self) -> Optional[EvidenceItem]:
        return EvidenceItem(
            key="supply_chain_controls",
            title="Supply Chain Controls",
            description="Pinned tool versions (snpguest v0.7.0 with commit-hash verification), "
                        "offline dependency installation (pip --no-index), minimal base images, "
                        "boto3 trimming (Nitro), vsock-proxy allowlist.",
            source="Bake-time supply chain config (verified by PKG-001/VLN-001)",
            artifacts={"offline_install": True, "pinned_versions": True},
            # Asserted by the build pipeline; see dependency/script/container
            # hash-pinning evidence for the parts that are actually observable.
            strength=Strength.INFORMATIONAL,
        )

    def _ephemeral_keys(self) -> Optional[EvidenceItem]:
        return EvidenceItem(
            key="ephemeral_keys",
            title="Ephemeral Cryptographic Keys",
            description="TLS key pairs (ECDH) are generated inside the TEE at boot. "
                        "Never written to persistent storage. Fresh keys per enclave lifecycle.",
            source="Generated server template key generation "
                   "(verified by BYOK-007)",
            artifacts={"key_type": "ECDH", "persistent_storage": False},
            # Key generation happens inside the running TEE; a build provenance
            # file cannot observe it.
            strength=Strength.INFORMATIONAL,
        )

    def _build_reproducibility(self) -> Optional[EvidenceItem]:
        artifacts: Dict[str, Any] = {}
        for e in self._entries:
            d = e.get("details", {})
            for k in ("sha256", "eif_sha256", "main_tf_sha256", "client_py_sha256",
                       "dockerfile_sha256", "vsock_sha256", "image_digest",
                       "tar_sha256", "entrypoint_sha256", "handler_sha256"):
                if k in d and d[k]:
                    label = e.get("step", k)[:60]
                    artifacts[f"{k}@{label}"] = d[k]
        # This item is nothing but the hashes it collected, so its strength is
        # simply how many it found.  Zero hashes previously still reported
        # STRONG.
        hash_count = len(artifacts)
        artifacts["artifact_hash_count"] = hash_count
        if hash_count >= 3:
            strength = Strength.STRONG
        elif hash_count:
            strength = Strength.MODERATE
        else:
            strength = Strength.INFORMATIONAL
        return EvidenceItem(
            key="build_reproducibility",
            title="Build Artifact Hashes",
            description=f"SHA-256 hashes of {hash_count} build artifact(s): source code, "
                        "generated code, Dockerfiles, Terraform configs, enclave images, "
                        "client scripts.",
            source="build_provenance.json (file hash entries throughout)",
            artifacts=artifacts,
            strength=strength,
        )

    def _access_control(self) -> Optional[EvidenceItem]:
        access_method = {
            "aws": "SSM-only (no SSH, no public IP, no bastion)",
            "azure": "Azure Bastion-only (no public SSH)",
            "gcp": "IAP-tunneled SSH only (no external IP)",
        }.get(self.cloud, "Platform-specific restricted access")
        return EvidenceItem(
            key="access_control",
            title="Restricted Management Access",
            description=f"Instance management via {access_method}. "
                        "Dedicated tee_enclave service user with no login shell.",
            source="Terraform + bake-time config (verified by IAM-001/IAM-002/PDR-007)",
            artifacts={"cloud": self.cloud, "access_method": access_method,
                       "service_user": "tee_enclave"},
            # All we actually know here is which cloud was targeted; the access
            # path itself is asserted by the Terraform templates.
            strength=(Strength.INFORMATIONAL if self.cloud == "unknown"
                      else Strength.MODERATE),
        )

    # ---- Evidence about modules that ship into the running TEE ----
    # These describe code deployed into the enclave rather than an
    # artifact the build produced, so a build provenance file cannot
    # observe them; the audit ledger's runtime checks are what raise
    # them above INFORMATIONAL.

    def _runtime_audit_logging(self) -> Optional[EvidenceItem]:
        return EvidenceItem(
            key="runtime_audit_logging",
            title="Runtime Audit Logging",
            description="Request/response metadata is continuously logged inside the TEE "
                        "without recording plaintext payloads. Logs are hash-chained for "
                        "tamper evidence. Includes timestamps, payload sizes, SHA-256 hashes, "
                        "and latency metrics.",
            source="tee_crafter_audit_logger.py (deployed into every TEE build)",
            artifacts={
                "plaintext_logged": False,
                "hash_chain": True,
                "metadata_fields": [
                    "timestamp", "request_size", "request_hash",
                    "response_size", "response_hash", "latency_ms",
                ],
            },
            # Describes a module deployed into the TEE; nothing about its
            # runtime behaviour is observable from the build provenance.
            strength=Strength.INFORMATIONAL,
        )

    def _continuous_attestation(self) -> Optional[EvidenceItem]:
        artifacts: Dict[str, Any] = {
            "default_interval_secs": 300,
            "drift_detection": True,
            "platforms": list(_PLATFORM_TEE_TECH.keys()),
        }
        desc = ("Background daemon inside the TEE periodically re-requests hardware "
                "attestation and compares measurements against the boot-time baseline. "
                "Detects measurement drift or unauthorized runtime modifications.")
        if self.is_gpu_cc:
            artifacts["gpu_cc_monitoring"] = True
            artifacts["gpu_health_check"] = True
            artifacts["gpu_cc_mode_drift_detection"] = True
            desc += (" For GPU CC platforms, the monitor also checks GPU health, "
                     "CC mode status, and NRAS token validity each cycle.")
        return EvidenceItem(
            key="continuous_attestation",
            title="Continuous Attestation Monitoring",
            description=desc,
            source="tee_crafter_attestation_monitor.py (deployed into every TEE build)",
            artifacts=artifacts,
            # Same as the audit logger: this is a module that ships, not a
            # measurement of it running.  ATT-008 is what can prove it.
            strength=Strength.INFORMATIONAL,
        )

    def _vulnerability_scan(self) -> Optional[EvidenceItem]:
        scan_entries = (
            _find_entries(self._entries, step_contains="vulnerability scan")
            + _find_entries(self._entries, step_contains="dependency vulnerability")
        )
        if not scan_entries:
            return None
        artifacts: Dict[str, Any] = {}
        for e in scan_entries:
            d = e.get("details", {})
            for k in ("scanner", "critical", "high", "medium", "low",
                       "total", "passed", "report_path"):
                if k in d:
                    artifacts[k] = d[k]
        passed = artifacts.get("passed", False)
        scan_type = "Container image" if self.flow == "container" else "Dependencies"
        return EvidenceItem(
            key="vulnerability_scan",
            title="Automated Vulnerability Scanning",
            description=f"{scan_type} scanned for known CVEs at build time using "
                        f"{artifacts.get('scanner', 'trivy/grype')}. "
                        f"Found {artifacts.get('total', '?')} vulnerabilities "
                        f"(Critical: {artifacts.get('critical', '?')}, "
                        f"High: {artifacts.get('high', '?')}).",
            source="build_provenance.json (vulnerability scan entry)",
            artifacts=artifacts,
            strength=Strength.STRONG if passed else Strength.MODERATE,
        )

    def _data_retention(self) -> Optional[EvidenceItem]:
        return EvidenceItem(
            key="data_retention_controls",
            title="Data Retention and Destruction Controls",
            description="TEE workloads process data ephemerally in hardware-encrypted memory. "
                        "No plaintext is persisted to disk. TLS key pairs are generated at "
                        "boot and destroyed on enclave termination. Audit logs record only "
                        "cryptographic hashes, never raw payloads.",
            source="TEE architecture: ephemeral processing + key lifecycle "
                   "(docs/security.md, tee_crafter_audit_logger.py)",
            artifacts={
                "persistent_plaintext": False,
                "ephemeral_keys": True,
                "key_destruction_on_shutdown": True,
                "audit_log_contains_plaintext": False,
                "data_at_rest_in_tee": "hardware_encrypted_memory_only",
            },
            # An architectural statement about runtime behaviour; the build
            # provenance carries no artifact that demonstrates it.
            strength=Strength.INFORMATIONAL,
        )

    def _key_rotation(self) -> Optional[EvidenceItem]:
        return EvidenceItem(
            key="key_rotation_evidence",
            title="Attestation-Bound Key Rotation",
            description="ECDH key pairs are automatically rotated on a configurable interval "
                        "(default 3600s). Every rotation is recorded in a hash-chained, "
                        "tamper-evident log with key fingerprints, rotation reason, lifetime, "
                        "and requests served. On platforms with attestation support, each "
                        "rotation includes a fresh hardware attestation measurement.",
            source="tee_crafter_key_rotation.py (deployed into every TEE build)",
            artifacts={
                "default_rotation_interval_secs": 3600,
                "hash_chained_log": True,
                "attestation_bound": True,
                "tracked_metrics": [
                    "key_fingerprint", "rotation_reason", "key_lifetime_secs",
                    "requests_served", "rotation_latency_ms",
                ],
                "rotation_triggers": ["time_based", "max_requests", "event_triggered"],
                "platforms": list(_PLATFORM_TEE_TECH.keys()),
            },
            # Rotation happens at runtime inside the TEE; BYOK-001 is what can
            # prove it, not the build provenance.
            strength=Strength.INFORMATIONAL,
        )

    def _vpc_isolation(self) -> Optional[EvidenceItem]:
        flow_log_detail = {
            "aws": {
                "mechanism": "VPC Flow Logs to CloudWatch Logs",
                "aggregation_interval": "60s",
                "traffic_type": "ALL",
                "retention_days": 30,
            },
            "gcp": {
                "mechanism": "VPC Subnet Flow Logs",
                "aggregation_interval": "5s",
                "flow_sampling": 1.0,
                "metadata": "INCLUDE_ALL_METADATA",
            },
            "azure": {
                "mechanism": "Virtual network flow logs to Storage + Traffic Analytics (Log Analytics)",
                "interval_in_minutes": 10,
                "retention_days": 30,
                "traffic_analytics": True,
            },
        }.get(self.cloud, {})

        return EvidenceItem(
            key="vpc_isolation",
            title="Per-Deployment VPC Isolation with Flow Logging",
            description="Each deployment is provisioned in a dedicated VPC/VNet with its own "
                        "subnets, route tables, and security groups. Network flow logs capture "
                        "all traffic for audit and anomaly detection. No cross-deployment "
                        "network bleed is possible.",
            source="Terraform template (per-deployment VPC + flow log resources)",
            artifacts={
                "cloud": self.cloud,
                "dedicated_vpc": True,
                "flow_logging_enabled": True,
                **flow_log_detail,
            },
            # Only the cloud is observed; the VPC and flow-log resources are
            # asserted by the Terraform template until IAC-002/003/007 confirm.
            strength=(Strength.INFORMATIONAL if not flow_log_detail
                      else Strength.MODERATE),
        )

    # ---- GPU Confidential Computing evidence ----

    def _gpu_confidential_computing(self) -> Optional[EvidenceItem]:
        if not self.is_gpu_cc:
            return None
        artifacts: Dict[str, Any] = {"platform": self.platform, "cloud": self.cloud}
        tee_tech = _PLATFORM_TEE_TECH.get(self.platform, "Unknown")

        cc_entries = (
            _find_entries(self._entries, step_contains="gpu cc mode")
            + _find_entries(self._entries, step_contains="nvidia-smi conf-compute")
            + _find_entries(self._entries, step_contains="gpu driver")
        )
        for e in cc_entries:
            d = e.get("details", {})
            for k in ("cc_mode", "driver_version", "gpu_model", "gpu_count",
                       "cuda_version", "instance_type"):
                if k in d and d[k]:
                    artifacts[k] = d[k]

        pcie_encrypted = self.platform != "gpu-cc-aws"
        artifacts["pcie_link_encrypted"] = pcie_encrypted

        # ``cc_mode`` is the field that says CC was actually turned on; without
        # it, all we know is that a GPU platform was targeted.  An unencrypted
        # PCIe link (AWS) caps the claim regardless.
        if not artifacts.get("cc_mode"):
            strength = Strength.INFORMATIONAL
        elif pcie_encrypted:
            strength = Strength.STRONG
        else:
            strength = Strength.MODERATE

        return EvidenceItem(
            key="gpu_confidential_computing",
            title="NVIDIA GPU Confidential Computing",
            description=f"Workload runs on NVIDIA GPUs with Confidential Computing enabled "
                        f"({tee_tech}). GPU memory is hardware-encrypted and isolated from "
                        f"host/hypervisor access. "
                        + ("CPU-GPU PCIe link is encrypted." if pcie_encrypted
                           else "WARNING: CPU-GPU PCIe link is NOT encrypted by a hardware TEE on AWS."),
            source="build_provenance.json (GPU CC mode + driver entries)",
            artifacts=artifacts,
            strength=strength,
        )

    def _gpu_attestation(self) -> Optional[EvidenceItem]:
        if not self.is_gpu_cc:
            return None
        artifacts: Dict[str, Any] = {"platform": self.platform}

        nras_entries = (
            _find_entries(self._entries, step_contains="nras")
            + _find_entries(self._entries, step_contains="gpu attestation")
            + _find_entries(self._entries, step_contains="nvidia remote attestation")
        )
        for e in nras_entries:
            d = e.get("details", {})
            for k in ("nras_token_valid", "eat_token_hash", "gpu_evidence_type",
                       "attestation_mode", "nras_url"):
                if k in d and d[k]:
                    artifacts[k] = d[k]

        return EvidenceItem(
            key="gpu_attestation",
            title="NVIDIA Remote Attestation (NRAS)",
            description="GPU integrity is verified through the NVIDIA Remote Attestation "
                        "Service (NRAS). GPU firmware, driver, and CC mode are attested and "
                        "an Entity Attestation Token (EAT JWT) is issued and verified.",
            source="build_provenance.json (NRAS attestation entries)",
            artifacts=artifacts,
            # Without an NRAS token or EAT hash in the provenance there is no
            # attestation to point at.
            strength=(Strength.STRONG
                      if artifacts.get("nras_token_valid") or artifacts.get("eat_token_hash")
                      else Strength.INFORMATIONAL),
        )

    def _dual_attestation_cpu_gpu(self) -> Optional[EvidenceItem]:
        if not self.is_gpu_cc:
            return None
        artifacts: Dict[str, Any] = {"platform": self.platform}

        dual_entries = (
            _find_entries(self._entries, step_contains="dual attestation")
            + _find_entries(self._entries, step_contains="combined attestation")
        )
        for e in dual_entries:
            d = e.get("details", {})
            for k in ("cpu_attestation_ok", "gpu_attestation_ok", "combined_valid",
                       "cpu_tee_type", "gpu_tee_type"):
                if k in d and d[k]:
                    artifacts[k] = d[k]

        cpu_tee = {
            "gpu-cc-gcp": "Intel TDX",
            "gpu-cc-azure": "AMD SEV-SNP",
            "gpu-cc-aws": "NitroTPM (instance attestation only)",
        }.get(self.platform, "Unknown")
        artifacts["cpu_tee_type"] = cpu_tee
        artifacts["gpu_tee_type"] = "NVIDIA CC (NRAS)"

        pcie_encrypted = self.platform != "gpu-cc-aws"
        # Both halves have to show up in the provenance before this can claim
        # that both were attested.
        both_attested = bool(
            artifacts.get("cpu_attestation_ok") and artifacts.get("gpu_attestation_ok")
        )
        if not both_attested:
            strength = Strength.INFORMATIONAL
        elif pcie_encrypted:
            strength = Strength.STRONG
        else:
            strength = Strength.MODERATE

        return EvidenceItem(
            key="dual_attestation_cpu_gpu",
            title="Dual Attestation: CPU-TEE + GPU-TEE",
            description=f"Both CPU ({cpu_tee}) and GPU (NVIDIA CC) are independently attested. "
                        f"Client verifies both attestation reports before transmitting data. "
                        + ("End-to-end confidentiality: encrypted PCIe link between CPU-TEE and GPU-TEE."
                           if pcie_encrypted
                           else "NOTE: AWS lacks encrypted PCIe link; CPU-GPU data traverses unencrypted bus."),
            source="build_provenance.json (dual/combined attestation entries)",
            artifacts=artifacts,
            strength=strength,
        )

    # ---- 2026 security-audit supplemental evidence ----

    def _attestation_tls_binding(self) -> Optional[EvidenceItem]:
        blob = self._all_entries_text_lower()
        hints = {
            "spki_or_pinning_in_provenance": "spki" in blob or "x509" in blob,
        }
        return EvidenceItem(
            key="attestation_tls_binding",
            title="Attestation-Bound TLS (RA-TLS) Binding Hardening",
            description="RA-TLS binds the server certificate to hardware attestation. "
                        "Recent templates add belt-and-braces checks (SPKI pinning, "
                        "issuer allowlists, vTPM PCR extensions on GCP GPU CC, and "
                        "Azure SNP vTPM AK binding per docs/security.md).",
            source="Client/server templates (2026 audit)",
            artifacts={"platform": self.platform, **hints},
            strength=(Strength.MODERATE if hints["spki_or_pinning_in_provenance"]
                      else Strength.INFORMATIONAL),
        )

    def _tcb_freshness(self) -> Optional[EvidenceItem]:
        blob = self._all_entries_text_lower()
        has_tcb = any(
            x in blob for x in (
                "isv_svn", "tcb", "qe_identity", "milan", "genoa",
                "module_version", "min_cpu",
            )
        )
        return EvidenceItem(
            key="tcb_freshness",
            title="TCB Freshness and Trusted-Component Version Enforcement",
            description="Templates and clients enforce or pin firmware/TCB-relevant "
                        "components (SGX ISV SVN / TCB evaluation date, TDX module and "
                        "QE identity, AMD Milan vs Genoa certificate selection, GCP "
                        "min_cpu_platform) per provider guidance.",
            source="Platform templates + client verification (2026 audit)",
            artifacts={"platform": self.platform, "tcb_hints_in_provenance": has_tcb},
            strength=Strength.STRONG if has_tcb else Strength.INFORMATIONAL,
        )

    def _attestation_issuer_allowlist(self) -> Optional[EvidenceItem]:
        blob = self._all_entries_text_lower()
        has_allowlist = "maa" in blob or "jwks" in blob or "nras" in blob or "pcs" in blob
        return EvidenceItem(
            key="attestation_issuer_allowlist",
            title="Attestation Issuer and Metadata Allowlisting",
            description="Remote attestation verifiers pin or allowlist attestation "
                        "issuers (Azure MAA JWKS URI, Intel PCS, NVIDIA NRAS endpoints) "
                        "to prevent arbitrary trust anchors.",
            source="Client templates (2026 audit: TDX-2, NRAS URL pin)",
            artifacts={"platform": self.platform, "issuer_pins_in_provenance": has_allowlist},
            strength=Strength.STRONG if has_allowlist else Strength.INFORMATIONAL,
        )

    def _egress_lockdown_mode(self) -> Optional[EvidenceItem]:
        blob = self._all_entries_text_lower()
        mode = "unknown"
        if "locked-down" in blob or "allow_setup_egress=false" in blob:
            mode = "locked-down"
        elif "open-for-setup" in blob or "allow_setup_egress=true" in blob:
            mode = "open-for-setup"
        return EvidenceItem(
            key="egress_lockdown_mode",
            title="Network Egress Lockdown (NET-1)",
            description="Terraform exposes setup_egress_mode (open-for-setup vs "
                        "locked-down). First-boot package installs may use NAT egress; "
                        "production should bake an image and re-apply with locked-down egress.",
            source="Terraform outputs + TF_VAR_allow_setup_egress (docs/compliance.md)",
            artifacts={"mode_observed": mode, "platform": self.platform},
            strength=Strength.STRONG if mode != "unknown" else Strength.INFORMATIONAL,
        )

    def _workload_egress_allowlist(self) -> Optional[EvidenceItem]:
        """Container-orchestrated model: the workload owns its data, so the
        network egress boundary is the primary data-confidentiality control.
        Egress is deny-by-default; databases / 3rd-party APIs are reached only
        via an explicit ``--egress-allow`` allowlist (intra-VPC, or public via a
        NAT gateway whose SG is still locked to the resolved CIDRs/ports)."""
        blob = self._all_entries_text_lower()
        deny_default = "deny-all" in blob or "egr-005" in blob
        no_wide = "0.0.0.0/0" not in blob or "egr-006" in blob
        return EvidenceItem(
            key="workload_egress_allowlist",
            title="Workload Egress Allowlist (EGR-005/006)",
            description="Application egress to databases and 3rd-party services is "
                        "deny-by-default and constrained to an explicit host:port / "
                        "cidr:port allowlist (recorded in workload_egress.json). Public "
                        "destinations route via NAT while the security group stays "
                        "locked to the resolved CIDRs — 0.0.0.0/0 is never opened.",
            source="workload_egress.json + EGR-005/EGR-006 verdicts (docs/security.md)",
            artifacts={
                "platform": self.platform,
                "deny_by_default_or_allowlisted": deny_default,
                "no_wide_open_egress": no_wide,
            },
            strength=Strength.STRONG if (deny_default and no_wide) else Strength.INFORMATIONAL,
        )

    def _kms_egress_scoping(self) -> Optional[EvidenceItem]:
        nitro = self.platform == "nitro-aws"
        return EvidenceItem(
            key="kms_egress_scoping",
            title="Scoped KMS / Attestation Egress (Nitro)",
            description="Nitro deployments scope vsock-proxy and security groups toward "
                        "KMS and attestation endpoints; Terraform may include KMS IP-range "
                        "hints where applicable (Nitro-1).",
            source="Nitro host_proxy template + Terraform (docs/nitro_flow.md)",
            artifacts={"nitro_specific": nitro, "cloud": self.cloud},
            strength=Strength.MODERATE if nitro else Strength.INFORMATIONAL,
        )

    def _deployer_least_privilege(self) -> Optional[EvidenceItem]:
        return EvidenceItem(
            key="deployer_least_privilege",
            title="Deploy-Time IAM Least Privilege",
            description="AWS SSM SendCommand policies are scoped to explicit SSM "
                        "documents (RMT-2) rather than blanket ssm:* on all documents.",
            source="Terraform IAM templates (2026 audit)",
            artifacts={"cloud": self.cloud, "ssm_document_scoped_iam": self.cloud == "aws"},
            strength=Strength.MODERATE if self.cloud == "aws" else Strength.INFORMATIONAL,
        )

    def _audit_log_tamper_evidence(self) -> Optional[EvidenceItem]:
        return EvidenceItem(
            key="audit_log_tamper_evidence",
            title="Runtime Audit Log Tamper Evidence (HMAC Chain)",
            description="Runtime audit logs use an HMAC-chained format (AUD-3) with a "
                        "per-process key and genesis commitment, not a trivial SHA-256-only chain.",
            source="tee_crafter_audit_logger.py (deployed into every TEE build)",
            artifacts={"hmac_chained": True, "genesis_commitment": True},
            # Describes the shipped logger module, not an observed log.
            strength=Strength.INFORMATIONAL,
        )

    def _log_redaction(self) -> Optional[EvidenceItem]:
        return EvidenceItem(
            key="log_redaction",
            title="Sensitive Log Redaction",
            description="Host proxy and application servers avoid logging Authorization "
                        "headers and full attestation payloads (LOG-1).",
            source="host_proxy and app templates (verified by SIEM-006)",
            artifacts={"platform": self.platform},
            # A property of the generated templates; not observable here.
            strength=Strength.INFORMATIONAL,
        )

    def _dependency_hash_pinning(self) -> Optional[EvidenceItem]:
        blob = self._all_entries_text_lower()
        ok = "requirements.lock" in blob or "require-hashes" in blob or "--require-hashes" in blob
        return EvidenceItem(
            key="dependency_hash_pinning",
            title="Dependency Hash Pinning",
            description="Python dependencies can be installed with hash pinning "
                        "(requirements.lock + pip --require-hashes) to reduce "
                        "dependency-substitution risk (F-15 / SUP-1).",
            source="Build pipeline (Dockerfile hardening; prefers requirements.lock when present)",
            artifacts={"hash_pinning_observed_in_provenance": ok},
            strength=Strength.STRONG if ok else Strength.INFORMATIONAL,
        )

    def _script_hash_pinning(self) -> Optional[EvidenceItem]:
        blob = self._all_entries_text_lower()
        ok = "script" in blob and ("sha256" in blob or "checksum" in blob)
        return EvidenceItem(
            key="script_hash_pinning",
            title="Bootstrap Script Integrity (SHA-256 Pinning)",
            description="Setup scripts verify SHA-256 of upstream bootstrap payloads "
                        "(rustup, Azure CLI, Docker install) before execution (SUP-2).",
            source="Platform setup scripts (2026 audit)",
            artifacts={"bootstrap_sha_observed_in_provenance": ok},
            strength=Strength.STRONG if ok else Strength.INFORMATIONAL,
        )

    def _container_digest_pinning(self) -> Optional[EvidenceItem]:
        # Backing catalogue checks: PKG-001 / PKG-002 (see
        # ``_EVIDENCE_CHECK_BACKING`` above).  The previous heuristic was a
        # substring search for
        # "digest" / "sha256:" / "image_digest", which trivially fired on
        # any provenance that mentioned the word "digest" anywhere (e.g.
        # the SHA-256 of the build artefact, a Trivy SBOM, or even an
        # unrelated message).  Now require *at least one* of:
        #   * a Docker pin of the form "image@sha256:<64-hex>"
        #     (e.g. ``FROM ubuntu@sha256:abc…``)
        #   * an explicit ``container_image_digest`` / ``image_digest``
        #     audit field present somewhere in the chain
        # so the evidence only goes STRONG when a real digest pin shows up.
        blob = self._all_entries_text()
        sha_pin_re = re.compile(r"@sha256:[0-9a-fA-F]{64}\b")
        digest_field_re = re.compile(
            r'"(?:container_image_digest|image_digest|container_digest)"\s*:\s*"sha256:[0-9a-fA-F]{64}"'
        )
        sha_pin_match = bool(sha_pin_re.search(blob))
        digest_field_match = bool(digest_field_re.search(blob))
        ok = sha_pin_match or digest_field_match
        return EvidenceItem(
            key="container_digest_pinning",
            title="Container Image Digest Pinning",
            description="Base images and builder images are referenced by digest "
                        "where applicable (e.g. nitro-cli image, FROM image@sha256:…). "
                        "STRONG only when a literal sha256 pin or container_image_digest "
                        "audit field is present.",
            source="Dockerfile templates + provenance image digests",
            artifacts={
                "sha256_pin_observed": sha_pin_match,
                "digest_audit_field_observed": digest_field_match,
            },
            strength=Strength.STRONG if ok else Strength.INFORMATIONAL,
        )

    def _measured_boot_vtpm(self) -> Optional[EvidenceItem]:
        if self.platform != "gpu-cc-gcp":
            return None
        blob = self._all_entries_text_lower()
        has_pcrs = "vtpm" in blob or "1.3.6.1.4.1.59386" in blob or "pcr" in blob
        return EvidenceItem(
            key="measured_boot_vtpm",
            title="Measured Boot / vTPM PCR Binding (GCP GPU CC)",
            description="GCP GPU CC client verifies vTPM PCR values embedded in the "
                        "RA-TLS certificate extension (F-8).",
            source="gpu_cc/gcp client template + attestation flow",
            artifacts={"platform": self.platform, "pcr_hints_in_provenance": has_pcrs},
            strength=Strength.STRONG if has_pcrs else Strength.INFORMATIONAL,
        )

    def _canonical_measurements_published(self) -> Optional[EvidenceItem]:
        if self.platform != "nitro-aws":
            return None
        blob = self._all_entries_text_lower()
        ok = "pcrs.json" in blob or "canonical pcr" in blob or "nitro-7" in blob
        return EvidenceItem(
            key="canonical_measurements_published",
            title="Canonical PCR / Measurement Artifact (Nitro EIF)",
            description="EIF builds can ship a canonical pcrs.json alongside the image "
                        "for offline verifier alignment (Nitro-7).",
            source="Nitro packaging / enclave build pipeline",
            artifacts={"pcrs_json_hint_in_provenance": ok},
            strength=Strength.STRONG if ok else Strength.INFORMATIONAL,
        )
