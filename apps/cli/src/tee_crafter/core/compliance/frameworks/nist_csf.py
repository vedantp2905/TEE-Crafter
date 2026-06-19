"""NIST Cybersecurity Framework (CSF) 2.0.

Subcategory identifiers and wording are taken from "The NIST Cybersecurity
Framework (CSF) 2.0 Core With Withdrawn CSF 1.1 Elements" (NIST, 2024-03-25).
Three identifiers that this file previously used are CSF 1.1 subcategories that
CSF 2.0 withdrew, and the withdrawal table names their replacements directly:

* ``PR.AC-01`` → withdrawn, incorporated into ``PR.AA-01`` / ``PR.AA-05``
* ``PR.IP-01`` → withdrawn, incorporated into ``PR.PS-01``
* ``RS.AN-01`` → withdrawn, incorporated into ``RS.MA-02``; the surviving
  incident-analysis subcategory this control is really about is ``RS.AN-03``
"""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="nist_csf",
    name="NIST Cybersecurity Framework",
    version="CSF 2.0 (2024)",
    tier="security_framework",
    description="High-level cybersecurity posture framework organized around "
                "Govern, Identify, Protect, Detect, Respond, and Recover functions.",
    controls=[
        ComplianceControl(
            control_id="PR.DS-01",
            title="Data-at-Rest Protection",
            description="The confidentiality, integrity, and availability of data-at-rest "
                        "are protected.",
            evidence_keys=["encryption_at_rest", "tee_hardware_isolation",
                           "gpu_confidential_computing"],
            section="Protect",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="PR.DS-02",
            title="Data-in-Transit Protection",
            description="The confidentiality, integrity, and availability of data-in-transit "
                        "are protected.",
            evidence_keys=["encryption_in_transit", "ratls_attestation",
                           "gpu_confidential_computing"],
            section="Protect",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="PR.AA-01",
            title="Identity Management, Authentication, and Access Control",
            description="Identities and credentials for authorized users, services, and "
                        "hardware are managed by the organization.",
            evidence_keys=["access_control", "tee_hardware_isolation",
                           "ratls_attestation", "gpu_confidential_computing",
                           "dual_attestation_cpu_gpu"],
            section="Protect",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="PR.PS-01",
            title="Platform Security - Configuration Management",
            description="Configuration management practices are established and applied.",
            evidence_keys=["systemd_sandboxing", "docker_hardening",
                           "build_reproducibility", "supply_chain_controls"],
            section="Protect",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="DE.CM-01",
            title="Continuous Monitoring",
            description="Networks and network services are monitored to find potentially "
                        "adverse events.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "runtime_audit_logging", "continuous_attestation",
                           "gpu_attestation"],
            section="Detect",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="ID.AM-01",
            title="Asset Inventory",
            description="Inventories of hardware managed by the organization are maintained.",
            evidence_keys=["build_reproducibility", "vulnerability_scan"],
            section="Identify",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="GV.RM-01",
            title="Risk Management Strategy",
            description="Risk management objectives are established and agreed to by "
                        "organizational stakeholders.",
            evidence_keys=[],
            section="Govern",
            responsibility=Responsibility.CUSTOMER,
        ),
        ComplianceControl(
            control_id="RS.AN-03",
            title="Incident Analysis",
            description="Analysis is performed to determine what has taken place during "
                        "an incident and the root cause of the incident.",
            evidence_keys=[],
            section="Respond",
            responsibility=Responsibility.CUSTOMER,
            source_note=(
                "Substitution involving interpretation, not a direct mapping. "
                "This control was RS.AN-01 under CSF 1.1. The CSF 2.0 "
                "withdrawal table incorporates RS.AN-01 into RS.MA-02 "
                "(incident triage), but the requirement this control actually "
                "describes is root-cause analysis, whose surviving 2.0 "
                "subcategory is RS.AN-03. RS.AN-03 was chosen on that reading. "
                "An auditor following the withdrawal table literally would "
                "expect RS.MA-02 here; every other identifier in this "
                "framework is a direct transcription."
            ),
        ),
    ],
)
