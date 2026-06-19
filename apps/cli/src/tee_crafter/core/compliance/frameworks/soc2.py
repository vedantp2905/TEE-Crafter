"""SOC 2 Type II Trust Services Criteria."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="soc2",
    name="SOC 2 Type II Trust Services Criteria",
    version="2017 (with 2022 points of focus)",
    tier="core_regulated",
    description="Trust Services Criteria for security, availability, processing integrity, "
                "confidentiality, and privacy used in SOC 2 Type II audits.",
    controls=[
        ComplianceControl(
            control_id="CC6.1",
            title="Logical Access Security",
            description="The entity implements logical access security software, "
                        "infrastructure, and architectures over protected information "
                        "assets to protect them from security events.",
            evidence_keys=["tee_hardware_isolation", "access_control",
                           "systemd_sandboxing", "gpu_confidential_computing"],
            section="Common Criteria",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="CC6.6",
            title="System Boundary Protection",
            description="The entity implements logical access security measures to "
                        "protect against threats from sources outside its system boundaries.",
            evidence_keys=["zero_ingress_network", "docker_hardening",
                           "vpc_isolation"],
            section="Common Criteria",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="CC6.7",
            title="Data Transmission Security",
            description="The entity restricts the transmission, movement, and removal "
                        "of information to authorized internal and external users and "
                        "processes and protects it during transmission.",
            evidence_keys=["encryption_in_transit", "ratls_attestation",
                           "dual_attestation_cpu_gpu"],
            section="Common Criteria",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="CC7.1",
            title="System Monitoring",
            description="To meet its objectives the entity uses detection and monitoring "
                        "procedures to identify changes to configurations that result in "
                        "the introduction of new vulnerabilities.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "runtime_audit_logging", "continuous_attestation",
                           "gpu_attestation"],
            section="Common Criteria",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="CC7.2",
            title="Anomaly Detection",
            description="The entity monitors system components and the operation of "
                        "those components for anomalies that are indicative of malicious "
                        "acts, natural disasters, and errors.",
            evidence_keys=["hash_chain_integrity", "ast_confinement",
                           "continuous_attestation", "gpu_attestation"],
            section="Common Criteria",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="CC8.1",
            title="Change Management",
            description="The entity authorizes, designs, develops or acquires, configures, "
                        "documents, tests, approves, and implements changes to "
                        "infrastructure, data, software, and procedures.",
            evidence_keys=["build_reproducibility", "supply_chain_controls",
                           "vulnerability_scan", "key_rotation_evidence"],
            section="Common Criteria",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="CC1.1",
            title="COSO Principle 1: Integrity and Ethical Values",
            description="The entity demonstrates a commitment to integrity and ethical values.",
            evidence_keys=[],
            section="Common Criteria",
            responsibility=Responsibility.CUSTOMER,
        ),
        ComplianceControl(
            control_id="CC2.1",
            title="Information and Communication",
            description="The entity obtains or generates and uses relevant, quality "
                        "information to support the functioning of internal control.",
            evidence_keys=[],
            section="Common Criteria",
            responsibility=Responsibility.CUSTOMER,
        ),
        ComplianceControl(
            control_id="CC3.1",
            title="Risk Assessment",
            description="The entity specifies objectives with sufficient clarity to enable "
                        "the identification and assessment of risks relating to objectives.",
            evidence_keys=[],
            section="Common Criteria",
            responsibility=Responsibility.CUSTOMER,
        ),
        ComplianceControl(
            control_id="PI1.1",
            title="Processing Integrity",
            description="The entity implements policies and procedures over system processing "
                        "to result in products, services, and reporting to meet the entity's "
                        "objectives.",
            evidence_keys=["output_schema_validation", "ast_confinement",
                           "ratls_attestation", "gpu_attestation",
                           "dual_attestation_cpu_gpu"],
            section="Processing Integrity",
            responsibility=Responsibility.PRODUCT,
        ),
    ],
)
