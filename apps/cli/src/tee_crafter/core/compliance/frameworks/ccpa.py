"""CCPA / CPRA (California Consumer Privacy Act / California Privacy Rights Act)."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="ccpa",
    name="CCPA / CPRA",
    version="Cal. Civ. Code 1798.100 et seq.",
    tier="core_regulated",
    description="California Consumer Privacy Act and California Privacy Rights Act "
                "requirements for protection of consumer personal information.",
    controls=[
        ComplianceControl(
            control_id="1798.100(e)",
            title="Reasonable Security Measures",
            description="A business that collects a consumer's personal information "
                        "shall implement reasonable security procedures and practices.",
            evidence_keys=["encryption_in_transit", "encryption_at_rest",
                           "access_control", "tee_hardware_isolation",
                           "gpu_confidential_computing", "gpu_attestation",
                           "dual_attestation_cpu_gpu"],
            section="Security",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="1798.150",
            title="Data Breach Prevention",
            description="Consumer right of action for unauthorized access and exfiltration, "
                        "theft, or disclosure of nonencrypted or nonredacted personal "
                        "information.",
            evidence_keys=["tee_hardware_isolation", "docker_hardening",
                           "zero_ingress_network", "ephemeral_keys",
                           "gpu_confidential_computing", "gpu_attestation",
                           "dual_attestation_cpu_gpu"],
            section="Security",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="1798.185(a)(15)(A)",
            title="Cybersecurity Audit",
            description="Regulations requiring businesses performing high-risk processing "
                        "to submit annual cybersecurity audits.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "build_reproducibility", "gpu_confidential_computing",
                           "gpu_attestation", "dual_attestation_cpu_gpu"],
            section="Audit",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="1798.105",
            title="Right to Deletion",
            description="A consumer shall have the right to request that a business "
                        "delete personal information collected from the consumer.",
            evidence_keys=["data_retention_controls", "ephemeral_keys",
                           "encryption_at_rest", "gpu_confidential_computing",
                           "dual_attestation_cpu_gpu"],
            section="Consumer Rights",
            responsibility=Responsibility.SHARED,
        ),
    ],
)
