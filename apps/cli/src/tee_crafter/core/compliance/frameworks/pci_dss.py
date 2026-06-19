"""PCI DSS v4.0."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="pci_dss",
    name="PCI DSS",
    version="v4.0",
    tier="core_regulated",
    description="Payment Card Industry Data Security Standard for protecting "
                "cardholder data environments.",
    controls=[
        ComplianceControl(
            control_id="Req 3.5",
            title="Protect Stored Account Data",
            description="Primary account numbers (PAN) are secured wherever stored "
                        "using strong cryptography.",
            evidence_keys=["encryption_at_rest", "ephemeral_keys",
                           "gpu_confidential_computing", "key_rotation_evidence",
                           "tee_hardware_isolation"],
            section="Protect Stored Account Data",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Req 4.2",
            title="Protect Data in Transit",
            description="PAN is protected with strong cryptography during transmission "
                        "over open, public networks.",
            evidence_keys=["encryption_in_transit", "gpu_confidential_computing",
                           "ratls_attestation"],
            section="Encrypt Transmission of Cardholder Data",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Req 6.3",
            title="Security Vulnerabilities Identified and Addressed",
            description="Security vulnerabilities are identified and addressed in a "
                        "timely manner.",
            evidence_keys=["ast_confinement", "gpu_attestation",
                           "supply_chain_controls", "vulnerability_scan"],
            section="Develop and Maintain Secure Systems",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Req 7.2",
            title="Access to System Components Restricted",
            description="Access to system components and cardholder data is "
                        "appropriately defined and assigned.",
            evidence_keys=["access_control", "dual_attestation_cpu_gpu",
                           "tee_hardware_isolation", "vpc_isolation",
                           "zero_ingress_network"],
            section="Restrict Access",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Req 9.4",
            title="Physical Access Controls",
            description="Physical access to cardholder data is restricted.",
            evidence_keys=[],
            section="Restrict Physical Access",
            responsibility=Responsibility.CUSTOMER,
        ),
        ComplianceControl(
            control_id="Req 10.2",
            title="Audit Trail Implementation",
            description="Audit logs are implemented to support the detection, alerting, "
                        "and analysis of suspicious activity.",
            evidence_keys=["build_reproducibility", "ed25519_signature",
                           "gpu_attestation", "hash_chain_integrity",
                           "runtime_audit_logging"],
            section="Track and Monitor Access",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Req 11.3",
            title="Vulnerability Management",
            description="External and internal vulnerabilities are regularly identified, "
                        "prioritized, and addressed.",
            evidence_keys=["ast_confinement", "docker_hardening",
                           "gpu_attestation", "supply_chain_controls",
                           "vulnerability_scan"],
            section="Regularly Test Security",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Req 1.3",
            title="Network Segmentation",
            description="Network connections between trusted and untrusted networks "
                        "are controlled and segmented.",
            evidence_keys=["gpu_confidential_computing", "vpc_isolation",
                           "zero_ingress_network"],
            section="Install and Maintain Network Security Controls",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Req 12.1",
            title="Information Security Policy",
            description="A comprehensive information security policy is established, "
                        "published, maintained, and disseminated.",
            evidence_keys=[],
            section="Maintain Security Policy",
            responsibility=Responsibility.CUSTOMER,
        ),
    ],
)
