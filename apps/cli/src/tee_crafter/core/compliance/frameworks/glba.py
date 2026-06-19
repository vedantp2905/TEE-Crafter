"""GLBA Safeguards Rule (Gramm-Leach-Bliley Act).

Paragraph letters follow 16 CFR 314.4 as amended (2023). The requirement text
in this file was already correct but was attached to the wrong subparagraphs:
``(c)(3)`` is encryption (not attack detection), ``(c)(4)`` is secure
development (not disposal), ``(c)(5)`` is multi-factor authentication (it was
occupied by encryption evidence, which left MFA with no control at all),
``(c)(6)`` is secure disposal, ``(c)(7)`` is change management, and testing for
"actual and attempted attacks" is paragraph ``(d)``, not part of ``(c)``.
"""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="glba",
    name="GLBA Safeguards Rule",
    version="16 CFR Part 314 (2023 amendments)",
    tier="industry_specific",
    description="Federal Trade Commission Safeguards Rule under the Gramm-Leach-Bliley Act. "
                "Requires financial institutions to develop, implement, and maintain "
                "an information security program.",
    controls=[
        ComplianceControl(
            control_id="314.4(c)",
            title="Information Security Program - Design and Implementation",
            description="Design and implement safeguards to control the risks identified "
                        "through risk assessment.",
            evidence_keys=["tee_hardware_isolation", "encryption_at_rest",
                           "encryption_in_transit", "systemd_sandboxing",
                           "gpu_confidential_computing"],
            section="Information Security Program",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="314.4(d)",
            title="Testing and Monitoring of Safeguards",
            description="Regularly test or otherwise monitor the effectiveness of the "
                        "safeguards' key controls, systems, and procedures, including "
                        "those to detect actual and attempted attacks on, or intrusions "
                        "into, information systems.",
            evidence_keys=["hash_chain_integrity", "zero_ingress_network",
                           "docker_hardening", "continuous_attestation",
                           "runtime_audit_logging", "vpc_isolation",
                           "gpu_attestation"],
            section="Information Security Program",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="314.4(c)(3)",
            title="Encrypt Customer Information in Transit and at Rest",
            description="Protect by encryption all customer information held or "
                        "transmitted, both in transit over external networks and at rest.",
            evidence_keys=["encryption_in_transit", "encryption_at_rest",
                           "ratls_attestation", "gpu_confidential_computing"],
            section="Information Security Program",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="314.4(c)(5)",
            title="Multi-Factor Authentication",
            description="Implement multi-factor authentication for any individual "
                        "accessing any information system, unless the Qualified "
                        "Individual has approved in writing the use of reasonably "
                        "equivalent or more secure access controls.",
            evidence_keys=[],
            section="Information Security Program",
            responsibility=Responsibility.CUSTOMER,
        ),
        ComplianceControl(
            control_id="314.4(c)(4)",
            title="Secure Development Practices",
            description="Adopt secure development practices for in-house developed "
                        "applications.",
            evidence_keys=["ast_confinement", "build_reproducibility",
                           "supply_chain_controls"],
            section="Information Security Program",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="314.4(c)(8)",
            title="Audit Trail",
            description="Implement procedures and controls to monitor when authorized "
                        "users are accessing customer information.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "runtime_audit_logging", "gpu_attestation",
                           "gpu_confidential_computing",
                           "dual_attestation_cpu_gpu"],
            section="Information Security Program",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="314.4(c)(6)",
            title="Data Retention and Disposal",
            description="Implement procedures for the secure disposal of customer information "
                        "no later than two years after the last date the information is used.",
            evidence_keys=["data_retention_controls", "ephemeral_keys",
                           "encryption_at_rest", "gpu_confidential_computing"],
            section="Information Security Program",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="314.4(b)",
            title="Risk Assessment",
            description="Conduct periodic risk assessments to identify reasonably "
                        "foreseeable risks to customer information.",
            evidence_keys=[],
            section="Information Security Program",
            responsibility=Responsibility.CUSTOMER,
        ),
    ],
)
