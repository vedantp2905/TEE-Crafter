"""EU Directive (EU) 2022/2555 (NIS2) — selected cybersecurity measures for essential entities.

Point letters follow Article 21(2) of the Directive verbatim. Two of them were
previously off by a letter: cryptography and encryption is point ``(h)``, not
``(f)`` (which is assessing the effectiveness of risk-management measures), and
human resources security / access control / asset management is point ``(i)``,
not ``(g)`` (which is basic cyber hygiene and training).
"""
from tee_crafter.core.compliance.registry import (
    ComplianceControl, FrameworkDefinition, Responsibility,
)

FRAMEWORK = FrameworkDefinition(
    framework_id="nis2",
    name="EU NIS2 Directive",
    version="2022/2555 (selected articles)",
    tier="security_framework",
    description="Network and Information Security Directive: risk management, incident handling, "
                "supply chain, encryption and authentication for operators of essential services.",
    controls=[
        ComplianceControl(
            control_id="Art 21(2)(a)",
            title="Policies on risk analysis and information system security",
            description="Policies and procedures on risk analysis and security of network and information systems.",
            evidence_keys=["zero_ingress_network", "vpc_isolation", "continuous_attestation",
                           "vulnerability_scan", "egress_lockdown_mode"],
            section="Cybersecurity risk-management measures",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 21(2)(b)",
            title="Incident handling",
            description="Incident handling, including preparation, detection and response.",
            evidence_keys=["runtime_audit_logging", "audit_log_tamper_evidence",
                           "vpc_isolation", "log_redaction"],
            section="Cybersecurity risk-management measures",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 21(2)(d)",
            title="Supply chain security",
            description="Supply chain security related to immediate suppliers or service providers.",
            evidence_keys=["supply_chain_controls", "dependency_hash_pinning",
                           "script_hash_pinning", "build_reproducibility",
                           "container_digest_pinning"],
            section="Cybersecurity risk-management measures",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Art 21(2)(h)",
            title="Cryptography and encryption",
            description="Policies and procedures regarding the use of cryptography and, "
                        "where appropriate, encryption.",
            evidence_keys=["encryption_in_transit", "encryption_at_rest",
                           "ratls_attestation", "ephemeral_keys", "key_rotation_evidence"],
            section="Cybersecurity risk-management measures",
            responsibility=Responsibility.PRODUCT,
        ),
        ComplianceControl(
            control_id="Art 21(2)(i)",
            title="Human resources security and access control",
            description="Human resources security, access control policies and asset "
                        "management.",
            evidence_keys=["access_control", "tee_hardware_isolation", "deployer_least_privilege",
                           "systemd_sandboxing"],
            section="Cybersecurity risk-management measures",
            responsibility=Responsibility.SHARED,
        ),
        ComplianceControl(
            control_id="Art 23",
            title="Reporting obligations — early warning and notification",
            description="Incident reporting to authorities (organizational processes; product supplies audit trail evidence).",
            evidence_keys=["runtime_audit_logging", "hash_chain_integrity",
                           "vpc_isolation"],
            section="Jurisdiction and reporting",
            responsibility=Responsibility.SHARED,
        ),
    ],
)
