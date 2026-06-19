"""GDPR (General Data Protection Regulation)."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="gdpr",
    name="GDPR",
    version="Regulation (EU) 2016/679",
    tier="core_regulated",
    description="European Union General Data Protection Regulation requirements for "
                "the protection of personal data.",
    controls=[
        ComplianceControl(
            control_id="Art 25",
            title="Data Protection by Design and by Default",
            description="The controller shall implement appropriate technical and "
                        "organisational measures designed to implement data-protection "
                        "principles in an effective manner.",
            evidence_keys=["tee_hardware_isolation", "encryption_at_rest",
                           "encryption_in_transit", "ephemeral_keys",
                           "key_rotation_evidence", "gpu_confidential_computing"],
            section="Principles",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Art 32(1)(a)",
            title="Pseudonymisation and Encryption",
            description="The ability to ensure the ongoing confidentiality, integrity, "
                        "availability and resilience of processing systems and services.",
            evidence_keys=["encryption_at_rest", "encryption_in_transit",
                           "tee_hardware_isolation", "ratls_attestation",
                           "gpu_confidential_computing", "dual_attestation_cpu_gpu"],
            section="Security of Processing",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Art 32(1)(b)",
            title="Confidentiality and Integrity of Processing",
            description="The ability to ensure the ongoing confidentiality, integrity, "
                        "availability and resilience of processing systems and services.",
            evidence_keys=["tee_hardware_isolation", "hash_chain_integrity",
                           "systemd_sandboxing", "docker_hardening",
                           "zero_ingress_network", "gpu_confidential_computing",
                           "gpu_attestation", "dual_attestation_cpu_gpu"],
            section="Security of Processing",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Art 32(1)(d)",
            title="Testing and Evaluation",
            description="A process for regularly testing, assessing and evaluating the "
                        "effectiveness of technical and organisational measures.",
            evidence_keys=["ast_confinement", "build_reproducibility",
                           "supply_chain_controls", "vulnerability_scan",
                           "gpu_confidential_computing", "dual_attestation_cpu_gpu",
                           "gpu_attestation"],
            section="Security of Processing",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 35",
            title="Data Protection Impact Assessment (DPIA)",
            description="Where processing is likely to result in a high risk to rights "
                        "and freedoms, the controller shall carry out an assessment.",
            evidence_keys=["tee_hardware_isolation", "encryption_at_rest",
                           "encryption_in_transit", "output_schema_validation",
                           "hash_chain_integrity"],
            section="Impact Assessment",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 17",
            title="Right to Erasure ('Right to be Forgotten')",
            description="The data subject shall have the right to obtain from the controller "
                        "the erasure of personal data without undue delay.",
            evidence_keys=["data_retention_controls", "ephemeral_keys",
                           "encryption_at_rest"],
            section="Data Subject Rights",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 6",
            title="Lawful Basis for Processing",
            description="Processing shall be lawful only if and to the extent that "
                        "at least one legal basis applies.",
            evidence_keys=[],
            section="Principles",
            responsibility=Responsibility.CUSTOMER,
        ),
        ComplianceControl(
            control_id="Art 28",
            title="Data Processing Agreement",
            description="Processing by a processor shall be governed by a contract "
                        "setting out the subject-matter and duration of the processing.",
            evidence_keys=[],
            section="Processor",
            responsibility=Responsibility.CUSTOMER,
        ),
    ],
)
