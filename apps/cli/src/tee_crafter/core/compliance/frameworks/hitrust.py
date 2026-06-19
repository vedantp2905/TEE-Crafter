"""HITRUST CSF v11."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="hitrust",
    name="HITRUST CSF",
    version="v11",
    tier="security_framework",
    description="HITRUST Common Security Framework. Cross-maps HIPAA, NIST, ISO, PCI, "
                "and other frameworks into a unified certification standard.",
    controls=[
        ComplianceControl(
            control_id="01.b",
            title="User Registration",
            description="A formal process for granting and revoking access to information "
                        "systems shall be implemented.",
            evidence_keys=["access_control", "tee_hardware_isolation",
                           "gpu_confidential_computing", "dual_attestation_cpu_gpu"],
            section="01 Access Control",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="01.v",
            title="Information Access Restriction",
            description="Access to information and application system functions by "
                        "users shall be restricted.",
            evidence_keys=["tee_hardware_isolation", "zero_ingress_network",
                           "systemd_sandboxing", "vpc_isolation",
                           "gpu_confidential_computing"],
            section="01 Access Control",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="06.d",
            title="Data Protection and Privacy",
            description="Data protection and privacy shall be ensured as required by "
                        "relevant legislation, regulations, and contractual clauses.",
            evidence_keys=["encryption_at_rest", "encryption_in_transit",
                           "tee_hardware_isolation", "gpu_confidential_computing"],
            section="06 Compliance",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="09.ab",
            title="Monitoring System Use",
            description="Procedures for monitoring use of information processing "
                        "facilities shall be established.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "runtime_audit_logging", "continuous_attestation",
                           "gpu_attestation", "dual_attestation_cpu_gpu"],
            section="09 Communications and Operations Management",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="09.m",
            title="Network Controls",
            description="Networks shall be adequately managed and controlled to "
                        "protect from threats.",
            evidence_keys=["zero_ingress_network", "docker_hardening",
                           "gpu_confidential_computing"],
            section="09 Communications and Operations Management",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="09.s",
            title="Information Exchange Policies",
            description="Formal exchange policies, procedures, and controls shall be "
                        "in place to protect the exchange of information.",
            evidence_keys=["encryption_in_transit", "ratls_attestation",
                           "key_rotation_evidence", "gpu_confidential_computing"],
            section="09 Communications and Operations Management",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="10.a",
            title="Security Requirements Analysis",
            description="Statements of information security requirements for new systems "
                        "or enhancements shall specify security control requirements.",
            evidence_keys=["ast_confinement", "build_reproducibility",
                           "supply_chain_controls", "vulnerability_scan",
                           "gpu_attestation", "dual_attestation_cpu_gpu"],
            section="10 Information Systems Acquisition, Development, Maintenance",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="12.a",
            title="Reporting Information Security Events",
            description="Information security events shall be reported through appropriate "
                        "management channels as quickly as possible.",
            evidence_keys=[],
            section="12 Information Security Incident Management",
            responsibility=Responsibility.CUSTOMER,
        ),
    ],
)
