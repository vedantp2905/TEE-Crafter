"""ISO 27001:2022 Annex A Controls."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="iso_27001",
    name="ISO/IEC 27001:2022 Annex A",
    version="2022",
    tier="security_framework",
    description="Information security management system controls from Annex A "
                "of ISO/IEC 27001:2022.",
    controls=[
        ComplianceControl(
            control_id="A.8.24",
            title="Use of Cryptography",
            description="Rules for the effective use of cryptography, including "
                        "cryptographic key management, shall be defined and implemented.",
            evidence_keys=["encryption_in_transit", "encryption_at_rest",
                           "ephemeral_keys", "ed25519_signature",
                           "key_rotation_evidence", "gpu_confidential_computing"],
            section="A.8 Technological Controls",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="A.8.25",
            title="Secure Development Life Cycle",
            description="Rules for the secure development of software and systems "
                        "shall be established and applied.",
            evidence_keys=["ast_confinement", "build_reproducibility",
                           "supply_chain_controls", "vulnerability_scan",
                           "gpu_attestation"],
            section="A.8 Technological Controls",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="A.8.26",
            title="Application Security Requirements",
            description="Information security requirements shall be identified, "
                        "specified and approved when developing or acquiring applications.",
            evidence_keys=["output_schema_validation", "ast_confinement",
                           "tee_hardware_isolation", "gpu_confidential_computing",
                           "gpu_attestation"],
            section="A.8 Technological Controls",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="A.8.9",
            title="Configuration Management",
            description="Configurations, including security configurations, of hardware, "
                        "software, services and networks shall be established, documented, "
                        "implemented, monitored and reviewed.",
            evidence_keys=["systemd_sandboxing", "docker_hardening",
                           "zero_ingress_network", "build_reproducibility",
                           "gpu_attestation", "dual_attestation_cpu_gpu"],
            section="A.8 Technological Controls",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="A.8.15",
            title="Logging",
            description="Logs that record activities, exceptions, faults and other "
                        "relevant events shall be produced, stored, protected and analysed.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "build_reproducibility", "runtime_audit_logging",
                           "gpu_attestation"],
            section="A.8 Technological Controls",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="A.8.10",
            title="Information Deletion",
            description="Information stored in information systems, devices or in any other "
                        "storage media shall be deleted when no longer required.",
            evidence_keys=["data_retention_controls", "ephemeral_keys",
                           "encryption_at_rest", "gpu_confidential_computing"],
            section="A.8 Technological Controls",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="A.5.23",
            title="Information Security for Use of Cloud Services",
            description="Processes for acquisition, use, management and exit from cloud "
                        "services shall be established.",
            evidence_keys=["tee_hardware_isolation", "zero_ingress_network",
                           "access_control", "vpc_isolation",
                           "gpu_confidential_computing",
                           "dual_attestation_cpu_gpu"],
            section="A.5 Organizational Controls",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="A.5.1",
            title="Policies for Information Security",
            description="Information security policy and topic-specific policies shall be "
                        "defined, approved by management, published, communicated to and "
                        "acknowledged by relevant personnel and interested parties.",
            evidence_keys=[],
            section="A.5 Organizational Controls",
            responsibility=Responsibility.CUSTOMER,
        ),
        ComplianceControl(
            control_id="A.6.1",
            title="Screening",
            description="Background verification checks on all candidates to become "
                        "personnel shall be carried out prior to joining the organization.",
            evidence_keys=[],
            section="A.6 People Controls",
            responsibility=Responsibility.CUSTOMER,
        ),
    ],
)
