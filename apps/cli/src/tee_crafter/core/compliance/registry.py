"""Core data model for the compliance report generator."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Responsibility(str, Enum):
    """Who is responsible for satisfying a compliance control."""
    PRODUCT = "product_evidence"
    CUSTOMER = "customer_responsibility"
    SHARED = "shared"


class Strength(str, Enum):
    STRONG = "strong"
    MODERATE = "moderate"
    INFORMATIONAL = "informational"


class VerdictStatus(str, Enum):
    SATISFIED = "satisfied"
    PARTIAL = "partial"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"
    CUSTOMER_RESPONSIBILITY = "customer_responsibility"


@dataclass
class ComplianceControl:
    """A single requirement within a compliance framework."""
    control_id: str
    title: str
    description: str
    evidence_keys: List[str]
    section: str
    responsibility: Responsibility
    source_note: str = ""
    """Provenance caveat for THIS control, surfaced in every report.

    Empty means "the identifier, title and text are a direct transcription of
    the published standard".  Anything else must say what was interpreted and
    why, because an auditor reading a control ID reasonably assumes it is a
    citation.  A mapping that required judgement is still useful; a mapping
    that required judgement and does not say so is a fabrication with a
    footnote missing.
    """

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "evidence_keys": self.evidence_keys,
            "section": self.section,
            "responsibility": self.responsibility.value,
        }
        # Omitted when empty so a clean control stays clean in the JSON, and
        # its presence is a signal rather than noise.
        if self.source_note:
            out["source_note"] = self.source_note
        return out


@dataclass
class EvidenceItem:
    """A piece of cryptographic or configuration evidence extracted from a build.

    ``strength`` describes how good the evidence is; ``verified`` describes
    whether an independent audit check actually confirmed it.  The two are
    deliberately separate: a collector can only report what it observed, and
    only the audit ledger (``audit_evidence.json``) can say that a check ran
    and passed.  Both default to the weakest/safest value so that a collector
    which forgets to set them cannot silently certify anything.
    """
    key: str
    title: str
    description: str
    source: str
    artifacts: Dict[str, Any] = field(default_factory=dict)
    strength: Strength = Strength.INFORMATIONAL
    check_ids: List[str] = field(default_factory=list)
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "artifacts": self.artifacts,
            "strength": self.strength.value,
            "check_ids": list(self.check_ids),
            "verified": self.verified,
        }


@dataclass
class ControlVerdict:
    """The result of evaluating a single control against collected evidence."""
    control: ComplianceControl
    status: VerdictStatus
    responsibility: Responsibility
    evidence: List[EvidenceItem] = field(default_factory=list)
    notes: str = ""
    customer_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control.control_id,
            "title": self.control.title,
            "section": self.control.section,
            "status": self.status.value,
            "responsibility": self.responsibility.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "notes": self.notes,
            "customer_action": self.customer_action,
        }


@dataclass
class FrameworkDefinition:
    """A compliance framework with its controls."""
    framework_id: str
    name: str
    version: str
    tier: str
    description: str
    controls: List[ComplianceControl] = field(default_factory=list)
    source_authority: str = "primary"
    """``"primary"`` or ``"secondary"``.

    ``primary`` means the control identifiers and titles were transcribed from
    the standards body's own published text.  ``secondary`` means they came from
    a third party reproducing it — usually because the body gates the document
    behind registration or payment.

    Four frameworks were **deleted** rather than shipped during remediation
    because every identifier in them was invented and the standard was
    paywalled, so there was no way to check. Shipping a fabricated control ID
    to an auditor is worse than shipping fewer frameworks. This field exists so
    that judgement is visible in the artefact instead of living in a reviewer's
    memory.
    """
    source_url: str = ""
    """Where the text was transcribed from, so a reader can re-check it."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "name": self.name,
            "version": self.version,
            "tier": self.tier,
            "description": self.description,
            "control_count": len(self.controls),
            "source_authority": self.source_authority,
            "source_url": self.source_url,
            # Cheap for a consumer to act on without walking every control.
            "controls_with_source_notes": sum(
                1 for c in self.controls if c.source_note),
        }


class FrameworkRegistry:
    """Central registry of all available compliance frameworks."""

    def __init__(self) -> None:
        self._frameworks: Dict[str, FrameworkDefinition] = {}

    def register(self, framework: FrameworkDefinition) -> None:
        self._frameworks[framework.framework_id] = framework

    def get(self, framework_id: str) -> FrameworkDefinition | None:
        return self._frameworks.get(framework_id)

    def all(self) -> List[FrameworkDefinition]:
        return list(self._frameworks.values())

    def ids(self) -> List[str]:
        return list(self._frameworks.keys())

    def __len__(self) -> int:
        return len(self._frameworks)


def build_default_registry() -> FrameworkRegistry:
    """Construct a registry populated with every built-in framework."""
    from tee_crafter.core.compliance.frameworks import ALL_FRAMEWORKS

    registry = FrameworkRegistry()
    for fw in ALL_FRAMEWORKS:
        registry.register(fw)
    return registry
