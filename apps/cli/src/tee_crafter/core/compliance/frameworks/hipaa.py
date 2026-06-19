"""HIPAA Technical Safeguards (45 CFR 164.312)."""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="hipaa",
    name="HIPAA Technical Safeguards",
    version="45 CFR 164.312",
    tier="core_regulated",
    description="Technical safeguards required under the HIPAA Security Rule for "
                "protecting electronic protected health information (ePHI).",
    controls=[
        ComplianceControl(
            control_id="164.312(a)(1)",
            title="Access Control",
            description="Implement technical policies and procedures for information systems "
                        "that maintain ePHI to allow access only to authorized persons or "
                        "software programs.",
            evidence_keys=["tee_hardware_isolation", "zero_ingress_network",
                           "systemd_sandboxing", "access_control",
                           "vpc_isolation", "gpu_confidential_computing",
                           "dual_attestation_cpu_gpu"],
            section="Technical Safeguards",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="164.312(a)(2)(iv)",
            title="Encryption and Decryption",
            description="Implement a mechanism to encrypt and decrypt ePHI.",
            evidence_keys=["encryption_at_rest", "encryption_in_transit",
                           "key_rotation_evidence", "gpu_confidential_computing"],
            section="Technical Safeguards",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="164.312(b)",
            title="Audit Controls",
            description="Implement hardware, software, and/or procedural mechanisms that "
                        "record and examine activity in information systems that contain "
                        "or use ePHI.",
            evidence_keys=["hash_chain_integrity", "ed25519_signature",
                           "build_reproducibility", "runtime_audit_logging",
                           "gpu_attestation", "audit_log_tamper_evidence"],
            section="Technical Safeguards",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="164.312(c)(1)",
            title="Integrity Controls",
            description="Implement policies and procedures to protect ePHI from "
                        "improper alteration or destruction.",
            evidence_keys=["hash_chain_integrity", "ratls_attestation",
                           "continuous_attestation", "gpu_attestation",
                           "dual_attestation_cpu_gpu"],
            section="Technical Safeguards",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="164.310(d)(2)(i)",
            title="Disposal (Data Retention)",
            description="Implement policies and procedures to address the final disposition "
                        "of ePHI, and/or the hardware or electronic media on which it is stored.",
            evidence_keys=["data_retention_controls", "ephemeral_keys",
                           "encryption_at_rest", "gpu_confidential_computing"],
            section="Technical Safeguards",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="164.312(d)",
            title="Person or Entity Authentication",
            description="Implement procedures to verify that a person or entity seeking "
                        "access to ePHI is the one claimed.",
            evidence_keys=["ratls_attestation", "gpu_confidential_computing",
                           "dual_attestation_cpu_gpu"],
            section="Technical Safeguards",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="164.312(e)(1)",
            title="Transmission Security",
            description="Implement technical security measures to guard against "
                        "unauthorized access to ePHI being transmitted over a network.",
            evidence_keys=["encryption_in_transit", "ratls_attestation",
                           "gpu_confidential_computing", "gpu_attestation",
                           "dual_attestation_cpu_gpu", "attestation_tls_binding"],
            section="Technical Safeguards",
            responsibility=Responsibility.PRODUCT,
        ),
    ],
)
