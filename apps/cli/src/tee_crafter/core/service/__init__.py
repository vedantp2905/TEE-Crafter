"""Persistent / long-lived RA-TLS service utilities.

Drives the platform-owned attested ingress proxy on VM-class TEEs:
certificate rotation, per-connection re-attestation, and declarative
service policy (TTLs, connection limits, drain-on-failure).
"""
from tee_crafter.core.service.cert_rotation import (
    CertRotator,
    CertRotationConfig,
    RotatedCert,
)
from tee_crafter.core.service.reattest import (
    ConnectionAttestor,
    ReattestResult,
    ReattestPolicy,
)
from tee_crafter.core.service.policy import (
    ServicePolicy,
    OnAttestationFailure,
)

__all__ = [
    "CertRotator",
    "CertRotationConfig",
    "RotatedCert",
    "ConnectionAttestor",
    "ReattestResult",
    "ReattestPolicy",
    "ServicePolicy",
    "OnAttestationFailure",
]
