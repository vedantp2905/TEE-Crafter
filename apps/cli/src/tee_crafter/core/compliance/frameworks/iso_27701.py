"""ISO/IEC 27701 Privacy Information Management (extension to ISO 27001)."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="iso_27701",
    name="ISO/IEC 27701 Privacy Extension",
    version="2019",
    tier="security_framework",
    description="Privacy Information Management System (PIMS) extension to ISO 27001/27002. "
                "Provides guidance for PII controllers and processors.",
    controls=[
        ComplianceControl(
            control_id="7.2.1",
            title="Purpose Limitation",
            description="The organization shall ensure that PII is only processed for "
                        "the identified purpose(s).",
            evidence_keys=["tee_hardware_isolation", "output_schema_validation",
                           "gpu_confidential_computing", "dual_attestation_cpu_gpu"],
            section="7.2 Conditions for Collection and Processing",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="7.4.5",
            title="PII Minimization",
            description="The organization shall limit the PII processed to that which "
                        "is adequate, relevant and necessary for the identified purpose(s).",
            evidence_keys=["tee_hardware_isolation", "data_retention_controls",
                           "output_schema_validation", "ast_confinement",
                           "gpu_confidential_computing", "dual_attestation_cpu_gpu"],
            section="7.4 Privacy by Design",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="7.4.1",
            title="Limit Collection",
            description="The organization shall limit the collection of PII to that which "
                        "is within the limits of applicable law and adequate, relevant and "
                        "necessary for the identified purpose(s).",
            evidence_keys=["tee_hardware_isolation", "output_schema_validation",
                           "gpu_confidential_computing", "dual_attestation_cpu_gpu"],
            section="7.4 Privacy by Design",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="7.2.8",
            title="Records Related to Processing PII",
            description="The organization shall determine and securely maintain the "
                        "necessary records related to the processing of PII.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "build_reproducibility", "runtime_audit_logging",
                           "gpu_confidential_computing", "gpu_attestation",
                           "dual_attestation_cpu_gpu"],
            section="7.2 Conditions for Collection and Processing",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="7.5.1",
            title="Identify Basis for PII Transfer",
            description="The organization shall identify and document the relevant "
                        "basis for transfers of PII between jurisdictions.",
            evidence_keys=[],
            section="7.5 PII Sharing, Transfer and Disclosure",
            responsibility=Responsibility.CUSTOMER,
        ),
    ],
)
