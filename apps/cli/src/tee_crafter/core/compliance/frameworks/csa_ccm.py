"""CSA Cloud Controls Matrix (CCM) v4.0.

The file was labelled v4.0 but carried mostly v3.0.1 semantics: ``AIS-04`` is
"Data Security / Integrity" only in v3.0.1 (in v4.0 it is "Secure Application
Design and Development"), ``DSP-04`` is "Data Classification" rather than
encryption (encryption moved to the CEK domain), ``IAM-02`` is "Strong Password
Policy and Procedures" rather than credential lifecycle, ``IVS-09`` is "Network
Defense" rather than segmentation (segmentation is ``IVS-06``), and ``SEF-02``
is "Service Management Policy and Procedures" rather than incident management
(that is ``SEF-01``). Each control below now uses the v4.0 identifier whose
published title matches the requirement it is evidencing.
"""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="csa_ccm",
    name="CSA Cloud Controls Matrix",
    version="v4.0",
    tier="security_framework",
    description="Cloud Security Alliance Cloud Controls Matrix. Commonly used in "
                "cloud vendor security questionnaires (CAIQ).",
    # CSA gates the CCM spreadsheet behind registration, so these titles were
    # transcribed from a third party reproducing it rather than from CSA's own
    # download. The identifiers and domain structure are stable and widely
    # reproduced, so the risk is a wrong *title*, not a wrong control -- but a
    # reader comparing this report against the registered matrix may find
    # wording differences, and should treat CSA's copy as authoritative.
    # Re-transcribe from the source below to promote this to primary.
    source_authority="secondary",
    source_url="https://cloudsecurityalliance.org/research/cloud-controls-matrix/",
    controls=[
        ComplianceControl(
            control_id="CEK-03",
            title="Data Encryption",
            description="Provide cryptographic protection to data at-rest and in-transit, "
                        "using cryptographic libraries certified to approved standards.",
            evidence_keys=["encryption_in_transit", "encryption_at_rest",
                           "ratls_attestation", "tee_hardware_isolation",
                           "gpu_confidential_computing"],
            section="Cryptography, Encryption and Key Management",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="CEK-12",
            title="Key Rotation",
            description="Define and implement processes and technical measures to rotate "
                        "cryptographic keys.",
            evidence_keys=["key_rotation_evidence", "ephemeral_keys",
                           "gpu_confidential_computing"],
            section="Cryptography, Encryption and Key Management",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="DSP-17",
            title="Sensitive Data Protection",
            description="Define and implement processes to protect sensitive data "
                        "throughout its lifecycle.",
            evidence_keys=["tee_hardware_isolation", "output_schema_validation",
                           "docker_hardening", "gpu_confidential_computing"],
            section="Data Security and Privacy Lifecycle Management",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="CCC-01",
            title="Change Management Policy and Procedures",
            description="Establish policies and procedures for managing the risks "
                        "associated with applying changes to the production environment.",
            evidence_keys=["build_reproducibility", "supply_chain_controls",
                           "hash_chain_integrity", "vulnerability_scan"],
            section="Change Control and Configuration Management",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="IAM-14",
            title="Strong Authentication",
            description="Define, implement and evaluate processes and technical measures "
                        "for authenticating access to systems, application and data assets.",
            evidence_keys=["ratls_attestation", "access_control",
                           "dual_attestation_cpu_gpu", "attestation_tls_binding"],
            section="Identity and Access Management",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="IVS-06",
            title="Segmentation and Segregation",
            description="Design, develop and deploy environments that are logically "
                        "segmented and segregated from each other.",
            evidence_keys=["zero_ingress_network", "vpc_isolation",
                           "systemd_sandboxing", "gpu_confidential_computing",
                           "gpu_attestation"],
            section="Infrastructure and Virtualization Security",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="SEF-01",
            title="Security Incident Management Policy and Procedures",
            description="Establish, document, approve and communicate policies and "
                        "procedures for security incident management.",
            evidence_keys=[],
            section="Security Incident Management, E-Discovery and Cloud Forensics",
            responsibility=Responsibility.CUSTOMER,
        ),
    ],
)
