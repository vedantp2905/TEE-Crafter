"""EU Regulation 2024/1689 (AI Act) — selected obligations for high-risk AI (technical measures)."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="eu_ai_act",
    name="EU AI Act",
    version="Reg. 2024/1689 (selected articles)",
    tier="security_framework",
    description="Artificial Intelligence Act: selected technical documentation, logging, "
                "accuracy, robustness and cybersecurity obligations for high-risk AI systems.",
    controls=[
        ComplianceControl(
            control_id="Art 11",
            title="Technical documentation",
            evidence_keys=["build_reproducibility", "hash_chain_integrity",
                           "output_schema_validation", "ast_confinement"],
            description="Technical documentation demonstrating conformity (build provenance, schema, confinement).",
            section="High-risk AI — documentation",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 12",
            title="Record-keeping (automatic logging)",
            evidence_keys=["runtime_audit_logging", "audit_log_tamper_evidence",
                           "log_redaction", "continuous_attestation"],
            description="Logging capabilities ensuring traceability of system operation (metadata-only runtime logs).",
            section="High-risk AI — logging",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Art 15.1",
            title="Accuracy and performance (appropriate for intended purpose)",
            evidence_keys=["output_schema_validation", "ast_confinement",
                           "tee_hardware_isolation"],
            description="Design and development for appropriate level of accuracy and robustness.",
            section="High-risk AI — performance",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 15.2",
            title="Resilience against errors and faults",
            evidence_keys=["continuous_attestation", "ratls_attestation",
                           "vulnerability_scan"],
            description="Resilience against errors, faults and inconsistencies (attestation + scanning).",
            section="High-risk AI — robustness",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 15.3",
            title="Cybersecurity appropriate to the risks",
            evidence_keys=["encryption_in_transit", "zero_ingress_network",
                           "vulnerability_scan", "supply_chain_controls",
                           "dependency_hash_pinning"],
            description="Cybersecurity measures appropriate to the risks and evolution of threats.",
            section="High-risk AI — cybersecurity",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Art 16",
            title="Oversight by natural persons (human oversight)",
            evidence_keys=[],
            description="Human oversight measures (organizational design; product supports auditability).",
            section="High-risk AI — oversight",
            responsibility=Responsibility.CUSTOMER,
        ),
    ],
)
