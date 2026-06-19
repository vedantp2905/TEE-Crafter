"""NIST 800-53 Rev 5 Security and Privacy Controls."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="nist_800_53",
    name="NIST 800-53 Rev 5",
    version="Rev 5 (Sep 2020)",
    tier="security_framework",
    description="Security and Privacy Controls for Information Systems and Organizations. "
                "Covers SC, AU, CM, SA, AC control families relevant to confidential computing.",
    controls=[
        ComplianceControl(
            control_id="SC-8",
            title="Transmission Confidentiality and Integrity",
            description="Protect the confidentiality and integrity of transmitted information.",
            evidence_keys=["encryption_in_transit", "ratls_attestation",
                           "gpu_confidential_computing", "gpu_attestation",
                           "attestation_tls_binding", "attestation_issuer_allowlist"],
            section="System and Communications Protection",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="SC-12",
            title="Cryptographic Key Establishment and Management",
            description="Establish and manage cryptographic keys when cryptography is "
                        "employed within the system.",
            evidence_keys=["ephemeral_keys", "ratls_attestation", "ed25519_signature",
                           "key_rotation_evidence", "gpu_confidential_computing"],
            section="System and Communications Protection",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="SC-28",
            title="Protection of Information at Rest",
            description="Protect the confidentiality and integrity of information at rest.",
            evidence_keys=["encryption_at_rest", "tee_hardware_isolation",
                           "gpu_confidential_computing"],
            section="System and Communications Protection",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="SC-13",
            title="Cryptographic Protection",
            description="Implement cryptographic mechanisms to prevent unauthorized "
                        "disclosure and detect changes to information.",
            evidence_keys=["encryption_in_transit", "encryption_at_rest",
                           "hash_chain_integrity", "ed25519_signature",
                           "gpu_confidential_computing"],
            section="System and Communications Protection",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="AU-2",
            title="Event Logging",
            description="Identify the types of events that the system is capable of "
                        "logging in support of the audit function.",
            evidence_keys=["hash_chain_integrity", "build_reproducibility",
                           "runtime_audit_logging", "gpu_attestation"],
            section="Audit and Accountability",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="AU-6",
            title="Audit Record Review, Analysis, and Reporting",
            description="Review and analyze system audit records for indications of "
                        "inappropriate or unusual activity.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "runtime_audit_logging", "gpu_attestation"],
            section="Audit and Accountability",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="AU-10",
            title="Non-repudiation",
            description="Provide irrefutable evidence that an individual or process "
                        "performed a specific action.",
            evidence_keys=["ed25519_signature", "hash_chain_integrity",
                           "build_reproducibility", "gpu_attestation",
                           "dual_attestation_cpu_gpu"],
            section="Audit and Accountability",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="CM-3",
            title="Configuration Change Control",
            description="Determine and document the types of changes to the system "
                        "that are configuration-controlled.",
            evidence_keys=["build_reproducibility", "supply_chain_controls",
                           "hash_chain_integrity"],
            section="Configuration Management",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="CM-6",
            title="Configuration Settings",
            description="Establish and document configuration settings for components "
                        "employed within the system.",
            evidence_keys=["systemd_sandboxing", "docker_hardening",
                           "zero_ingress_network", "gpu_confidential_computing"],
            section="Configuration Management",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="SA-11",
            title="Developer Testing and Evaluation",
            description="Require the developer of the system to create and implement "
                        "a security and privacy assessment plan.",
            evidence_keys=["ast_confinement", "build_reproducibility",
                           "supply_chain_controls", "vulnerability_scan"],
            section="System and Services Acquisition",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="SI-7",
            title="Software, Firmware, and Information Integrity",
            description="Employ integrity verification tools to detect unauthorized changes "
                        "to software, firmware, and information.",
            evidence_keys=["continuous_attestation", "hash_chain_integrity",
                           "ed25519_signature", "gpu_attestation",
                           "dual_attestation_cpu_gpu", "tcb_freshness"],
            section="System and Information Integrity",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="RA-5",
            title="Vulnerability Monitoring and Scanning",
            description="Monitor and scan for vulnerabilities in the system and hosted "
                        "applications and remediate discovered vulnerabilities.",
            evidence_keys=["vulnerability_scan", "supply_chain_controls"],
            section="Risk Assessment",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="AC-3",
            title="Access Enforcement",
            description="Enforce approved authorizations for logical access to "
                        "information and system resources.",
            evidence_keys=["tee_hardware_isolation", "access_control",
                           "zero_ingress_network", "gpu_confidential_computing"],
            section="Access Control",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="AC-4",
            title="Information Flow Enforcement",
            description="Enforce approved authorizations for controlling the flow of "
                        "information within the system and between connected systems.",
            evidence_keys=["tee_hardware_isolation", "zero_ingress_network",
                           "output_schema_validation", "vpc_isolation",
                           "gpu_confidential_computing"],
            section="Access Control",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="SC-7",
            title="Boundary Protection",
            description="Monitor and control communications at external managed interfaces "
                        "and at key internal managed interfaces within the system.",
            evidence_keys=["zero_ingress_network", "vpc_isolation",
                           "docker_hardening", "systemd_sandboxing",
                           "gpu_confidential_computing", "egress_lockdown_mode",
                           "kms_egress_scoping"],
            section="System and Communications Protection",
            responsibility=Responsibility.PRODUCT,
        ),
    ],
)
