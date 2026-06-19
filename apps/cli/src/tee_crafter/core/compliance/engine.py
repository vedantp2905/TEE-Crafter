"""ComplianceEngine: matches evidence to controls, produces verdicts."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from tee_crafter.core.compliance.registry import (
    ComplianceControl, ControlVerdict, EvidenceItem,
    FrameworkDefinition, FrameworkRegistry, Responsibility,
    Strength, VerdictStatus, build_default_registry,
)
from tee_crafter.core.compliance.evidence import EvidenceCollector

# GPU-only evidence keys are optional when the workload is not a GPU-CC
# deployment; requiring NRAS/dual-GPU evidence on CPU-only TEE builds is a
# false gap.  See docs/compliance.md.
_GPU_CC_OPTIONAL_KEYS = frozenset({
    "gpu_confidential_computing",
    "gpu_attestation",
    "dual_attestation_cpu_gpu",
})


_CUSTOMER_ACTION_HINTS: Dict[str, str] = {
    "CC1.1": "Establish and document organizational integrity and ethical values policies.",
    "CC2.1": "Implement internal communication procedures for security information.",
    "CC3.1": "Conduct formal risk assessment and document risk treatment decisions.",
    "Req 9.4": "Implement physical access controls for cardholder data environments.",
    "Req 12.1": "Develop and maintain a comprehensive information security policy.",
    "Art 6": "Document the lawful basis for each processing activity (consent, contract, etc.).",
    "Art 28": "Execute a Data Processing Agreement with all processors.",
    "1798.105": "Implement consumer deletion request handling processes. "
                "TEE-Crafter provides ephemeral processing evidence; customer handles request intake.",
    "Art 17": "Implement erasure request intake and verification processes. "
              "TEE-Crafter evidences ephemeral processing and key destruction.",
    "164.310(d)(2)(i)": "Document ePHI disposal policies. TEE-Crafter evidences "
                        "ephemeral key lifecycle and no persistent plaintext.",
    "A.8.10": "Define information retention schedules and deletion procedures.",
    "314.4(c)(5)": "Deploy multi-factor authentication for every individual accessing "
                   "an information system holding customer information. TEE-Crafter "
                   "authenticates machines via RA-TLS; it does not authenticate people.",
    "314.4(c)(6)": "Document customer information retention and disposal schedules.",
    "GV.RM-01": "Document and agree upon organizational risk management strategy.",
    "RS.AN-03": "Establish incident response and forensic investigation procedures.",
    "A.5.1": "Define, approve, and publish information security policies.",
    "A.6.1": "Implement background screening for all personnel.",
    "7.5.1": "Document the legal basis for cross-border PII transfers.",
    "12.a": "Establish security event reporting channels and escalation procedures.",
    "SEF-01": "Implement a security incident management program with defined roles.",
    "314.4(b)": "Conduct periodic risk assessments of customer information security.",
}


def _describe_unproven(unproven: List[EvidenceItem]) -> str:
    """Explain, in the verdict notes, which collected evidence did not count.

    Silently dropping unproven evidence would read as "we found nothing"; an
    auditor needs to see that the evidence exists but its backing check failed
    or never ran.
    """
    if not unproven:
        return ""
    failed_cids = sorted({
        cid for e in unproven
        for cid in e.artifacts.get("downgraded_by_failed_checks", [])
    })
    unproven_cids = sorted({
        cid for e in unproven
        for cid in e.artifacts.get("unproven_checks", [])
    })
    parts = [
        f" {len(unproven)} further evidence item(s) were collected but do not "
        f"count towards coverage: {', '.join(sorted(e.key for e in unproven))}."
    ]
    if failed_cids:
        parts.append(f" Backing audit check(s) failed: {', '.join(failed_cids)}.")
    if unproven_cids:
        parts.append(
            f" Backing audit check(s) not evaluated or not passing: "
            f"{', '.join(unproven_cids)}."
        )
    return "".join(parts)


class ComplianceEngine:
    """Evaluate evidence against framework controls to produce verdicts."""

    def __init__(
        self,
        provenance_path: str,
        registry: Optional[FrameworkRegistry] = None,
        framework_ids: Optional[List[str]] = None,
    ) -> None:
        self._provenance_path = provenance_path
        self._registry = registry or build_default_registry()
        self._framework_ids = framework_ids
        self._collector = EvidenceCollector(provenance_path)
        self._evidence: List[EvidenceItem] = []
        self._evidence_by_key: Dict[str, EvidenceItem] = {}

    def collect_evidence(self) -> List[EvidenceItem]:
        self._evidence = self._collector.collect_all()
        self._evidence_by_key = {e.key: e for e in self._evidence}
        return self._evidence

    @property
    def platform(self) -> str:
        return self._collector.platform

    @property
    def flow(self) -> str:
        return self._collector.flow

    @property
    def cloud(self) -> str:
        return self._collector.cloud

    def _effective_evidence_keys(self, control: ComplianceControl) -> List[str]:
        """Drop GPU-only keys when this build is not GPU Confidential Computing."""
        keys = list(control.evidence_keys)
        if not self._collector.is_gpu_cc:
            keys = [k for k in keys if k not in _GPU_CC_OPTIONAL_KEYS]
        return keys

    def evaluate_control(self, control: ComplianceControl) -> ControlVerdict:
        """Produce a verdict for a single control."""
        if control.responsibility == Responsibility.CUSTOMER:
            return ControlVerdict(
                control=control,
                status=VerdictStatus.CUSTOMER_RESPONSIBILITY,
                responsibility=Responsibility.CUSTOMER,
                evidence=[],
                notes="This control requires organizational policies and processes "
                      "that are outside the scope of TEE-Crafter product evidence.",
                customer_action=_CUSTOMER_ACTION_HINTS.get(control.control_id,
                    "Provide organizational policies, procedures, and documentation."),
            )

        eff_keys = self._effective_evidence_keys(control)
        if not eff_keys:
            return ControlVerdict(
                control=control,
                status=VerdictStatus.NOT_APPLICABLE,
                responsibility=control.responsibility,
                notes="No applicable evidence keys for this deployment profile "
                      "(GPU-only requirements omitted on non-GPU builds).",
            )

        # Coverage is measured in *verified* evidence, not in evidence keys
        # that happen to exist.  An evidence item whose backing audit check
        # failed, or was never evaluated, is collected but unproven, so it does
        # not close the requirement it is mapped to.  See
        # ``EvidenceCollector._reconcile_with_ledger``.
        collected = [
            self._evidence_by_key[key] for key in eff_keys
            if key in self._evidence_by_key
        ]
        matched = [e for e in collected if e.verified]
        unproven = [e for e in collected if not e.verified]

        coverage = len(matched) / len(eff_keys) if eff_keys else 0
        unproven_note = _describe_unproven(unproven)

        if control.responsibility == Responsibility.SHARED:
            if coverage >= 0.5:
                status = VerdictStatus.PARTIAL
                notes = (f"Product provides verified evidence for {len(matched)}/{len(eff_keys)} "
                         f"evidence requirements. Customer organizational controls also needed.")
            elif matched:
                status = VerdictStatus.PARTIAL
                notes = (f"Partial verified product evidence ({len(matched)}/{len(eff_keys)}). "
                         f"Customer organizational controls are the primary requirement.")
            else:
                status = VerdictStatus.GAP
                notes = ("No verified product evidence for this shared-responsibility "
                         "control.")
            return ControlVerdict(
                control=control, status=status, responsibility=Responsibility.SHARED,
                evidence=matched, notes=notes + unproven_note,
                customer_action="Supplement with organizational policies and processes.",
            )

        # SATISFIED is reserved for controls where every evidence requirement
        # is covered by evidence an audit check actually proved.  Anything less
        # is PARTIAL at best -- we never claim "satisfied" without proof
        # (docs/compliance.md).
        all_strong = bool(matched) and all(e.strength == Strength.STRONG for e in matched)
        if coverage == 1.0 and all_strong:
            status = VerdictStatus.SATISFIED
            notes = (f"All {len(eff_keys)} evidence requirements are covered by verified, "
                     f"strong evidence.")
        elif coverage >= 0.5:
            status = VerdictStatus.PARTIAL
            notes = (f"{len(matched)}/{len(eff_keys)} evidence requirements covered by "
                     f"verified evidence.")
        elif matched:
            status = VerdictStatus.PARTIAL
            notes = (f"Partial evidence: {len(matched)}/{len(eff_keys)} requirements covered "
                     f"by verified evidence.")
        else:
            status = VerdictStatus.GAP
            notes = "No verified evidence for this control."

        return ControlVerdict(
            control=control, status=status, responsibility=Responsibility.PRODUCT,
            evidence=matched, notes=notes + unproven_note,
        )

    def evaluate_framework(self, framework: FrameworkDefinition) -> List[ControlVerdict]:
        """Evaluate all controls in a framework."""
        return [self.evaluate_control(c) for c in framework.controls]

    def evaluate_all(self) -> Dict[str, List[ControlVerdict]]:
        """Evaluate all selected frameworks. Returns {framework_id: [verdicts]}."""
        if not self._evidence:
            self.collect_evidence()

        frameworks = self._registry.all()
        if self._framework_ids:
            ids = set(self._framework_ids)
            frameworks = [f for f in frameworks if f.framework_id in ids]

        return {fw.framework_id: self.evaluate_framework(fw) for fw in frameworks}

    def generate_report(self, output_dir: str, formats: Optional[List[str]] = None) -> str:
        """Run evaluation and render reports into output_dir/compliance/.

        Returns the path to the compliance/ directory.
        """
        if formats is None:
            formats = ["json", "md", "html", "srm"]

        results = self.evaluate_all()

        compliance_dir = os.path.join(output_dir, "compliance")
        frameworks_dir = os.path.join(compliance_dir, "frameworks")
        os.makedirs(frameworks_dir, exist_ok=True)

        report_data = self._build_report_data(results)

        if "json" in formats:
            from tee_crafter.core.compliance.renderers.json_renderer import render_json
            render_json(report_data, compliance_dir, frameworks_dir)

        if "md" in formats:
            from tee_crafter.core.compliance.renderers.markdown_renderer import render_markdown
            render_markdown(report_data, compliance_dir)

        if "html" in formats:
            from tee_crafter.core.compliance.renderers.html_renderer import render_html
            render_html(report_data, compliance_dir)

        if "srm" in formats:
            from tee_crafter.core.compliance.renderers.pdf_renderer import render_srm
            render_srm(report_data, compliance_dir)

        return compliance_dir

    def _build_report_data(self, results: Dict[str, List[ControlVerdict]]) -> Dict[str, Any]:
        """Build the canonical report data structure."""
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        head_hash = self._collector.chain_head_hash
        report_id = hashlib.sha256(f"{head_hash}:{ts}".encode()).hexdigest()

        total = satisfied = partial = gap = na = customer = 0
        fw_data: Dict[str, Any] = {}

        for fw_id, verdicts in results.items():
            fw = self._registry.get(fw_id)
            if not fw:
                continue

            fw_satisfied = fw_partial = fw_gap = fw_na = fw_customer = 0
            controls_data = []
            for v in verdicts:
                d = v.to_dict()
                controls_data.append(d)
                total += 1
                if v.status == VerdictStatus.SATISFIED:
                    satisfied += 1; fw_satisfied += 1
                elif v.status == VerdictStatus.PARTIAL:
                    partial += 1; fw_partial += 1
                elif v.status == VerdictStatus.GAP:
                    gap += 1; fw_gap += 1
                elif v.status == VerdictStatus.NOT_APPLICABLE:
                    na += 1; fw_na += 1
                elif v.status == VerdictStatus.CUSTOMER_RESPONSIBILITY:
                    customer += 1; fw_customer += 1

            fw_data[fw_id] = {
                "name": fw.name,
                "version": fw.version,
                "tier": fw.tier,
                # Whether these control IDs and titles came from the standards
                # body's own text or from a third party reproducing it. A
                # control ID reads as a citation, so the distinction belongs
                # next to the numbers rather than in a separate document.
                "source_authority": fw.source_authority,
                "source_url": fw.source_url,
                "controls_evaluated": len(verdicts),
                "satisfied": fw_satisfied,
                "partial": fw_partial,
                "gap": fw_gap,
                "not_applicable": fw_na,
                "customer_responsibility": fw_customer,
                "controls": controls_data,
            }

        product_assessable = total - customer - na
        product_coverage = (
            round((satisfied / product_assessable) * 100, 1)
            if product_assessable > 0 else 0.0
        )
        overall_coverage = (
            round(((satisfied + partial) / total) * 100, 1) if total > 0 else 0.0
        )

        evidence_inventory = [
            {
                "key": e.key,
                "collected": True,
                "verified": e.verified,
                "strength": e.strength.value,
                "check_ids": list(e.check_ids),
            }
            for e in self._evidence
        ]

        return {
            "schema_version": "1.0",
            "report_id": report_id,
            "generated_at": ts,
            "generator_version": "0.1.0",
            "provenance": {
                "file": os.path.basename(self._provenance_path),
                "chain_head_hash": head_hash,
                "chain_valid": self._evidence_by_key.get(
                    "hash_chain_integrity", EvidenceItem(
                        key="", title="", description="", source="",
                    )).artifacts.get("chain_valid", False),
                "signature_valid": self._evidence_by_key.get(
                    "ed25519_signature", EvidenceItem(
                        key="", title="", description="", source="",
                    )).artifacts.get("signature_valid", False),
                "total_entries": len(self._collector._entries),
            },
            "deployment": {
                "tee_platform": self.platform,
                "flow": self.flow,
                "run_mode": self._collector.run_mode,
                "cloud": self.cloud,
            },
            "summary": {
                "frameworks_evaluated": len(fw_data),
                "total_controls": total,
                "by_status": {
                    "satisfied": satisfied,
                    "partial": partial,
                    "gap": gap,
                    "not_applicable": na,
                    "customer_responsibility": customer,
                },
                "product_coverage_pct": product_coverage,
                "overall_coverage_pct": overall_coverage,
            },
            # Stated in the artefact, not just in docs/compliance.md, because a
            # reader who receives only this JSON would otherwise have to infer
            # the grading rule from the numbers -- and the counts look worse
            # than a laxer ladder would produce, so the reason matters.
            "methodology": {
                "satisfied_requires": (
                    "Every evidence requirement for the control is covered by "
                    "evidence that an audit check independently proved (strength "
                    "STRONG). Coverage alone is never enough."
                ),
                "promotion_policy": (
                    "Promote-on-proof. A control reaches SATISFIED only when the "
                    "audit ledger proves it; without a ledger every control is "
                    "PARTIAL at best. The alternative -- start at SATISFIED and "
                    "downgrade on failure -- reports better numbers and is what "
                    "produced the pre-remediation 86.2%/0-gaps result from a "
                    "single-entry provenance file."
                ),
                "unevaluated_is_not_passing": (
                    "A check nobody ran is recorded as not_evaluated and never "
                    "counts toward coverage."
                ),
                "source_authority": (
                    "Each framework declares whether its control identifiers and "
                    "titles were transcribed from the standards body's own text "
                    "(primary) or from a third party reproducing it (secondary). "
                    "Individual controls carry a source_note when the mapping "
                    "required interpretation."
                ),
            },
            "frameworks": fw_data,
            "evidence_inventory": evidence_inventory,
        }
