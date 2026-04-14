"""Declarative policy for persistent RA-TLS services."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List, Optional
from tee_crafter.core.env_flags import interpret


class OnAttestationFailure(str, enum.Enum):
    """What the runtime should do when re-attestation fails."""

    DRAIN = "drain"
    HARD_STOP = "hard_stop"
    WARN = "warn"


@dataclass
class ServicePolicy:
    """High-level configuration for a persistent service template.

    Fields are intentionally simple primitives so the templater can render
    them straight into in-TEE code or into a JSON/env file consumed by the
    running service without serialisation glue.
    """

    cert_ttl_seconds: int = 3600
    """Lifetime of an RA-TLS certificate before forced rotation."""

    cert_grace_seconds: int = 300
    """How long to keep the previous cert valid for in-flight TLS sessions
    after a rotation, so existing long-poll/streaming connections don't
    abort mid-frame."""

    reattest_interval_seconds: int = 600
    """How often the per-connection attestor re-runs platform attestation
    on a long-lived connection."""

    reattest_grace_seconds: int = 60
    """Tolerated lateness for a re-attestation call before it is treated
    as failed (handles brief platform attestation hiccups)."""

    max_concurrent_connections: int = 1024

    on_failure: OnAttestationFailure = OnAttestationFailure.DRAIN
    """How to react when a fresh attestation cannot be obtained."""

    advertise_keepalive: bool = True
    """Whether the service should advertise HTTP/1.1 keep-alive and HTTP/2
    multiplexing.  False forces single-request connections (fall back to
    legacy ``process_request`` semantics, useful for staged rollouts)."""

    streaming_enabled: bool = False
    """Allow Server-Sent Events / WebSocket / gRPC server-streaming.
    Bidirectional streaming requires ``streaming_enabled`` AND
    ``advertise_keepalive``."""

    extra_attestation_hooks: List[str] = field(default_factory=list)
    """Optional extension point: dotted module paths the TEE template
    should import and call on every re-attestation cycle (e.g. to
    refresh BYOK keys or push a SIEM event)."""

    def validate(self) -> List[str]:
        """Return a list of human-readable issues, or empty if valid."""
        errors: List[str] = []
        if self.cert_ttl_seconds <= 0:
            errors.append("cert_ttl_seconds must be > 0")
        if self.cert_grace_seconds < 0:
            errors.append("cert_grace_seconds must be >= 0")
        if self.cert_grace_seconds >= self.cert_ttl_seconds:
            errors.append("cert_grace_seconds must be < cert_ttl_seconds")
        if self.reattest_interval_seconds <= 0:
            errors.append("reattest_interval_seconds must be > 0")
        if self.reattest_interval_seconds > self.cert_ttl_seconds:
            errors.append(
                "reattest_interval_seconds must be <= cert_ttl_seconds "
                "(otherwise a long-lived connection can outlive its cert)"
            )
        if self.reattest_grace_seconds < 0:
            errors.append("reattest_grace_seconds must be >= 0")
        if self.max_concurrent_connections <= 0:
            errors.append("max_concurrent_connections must be > 0")
        return errors

    def is_valid(self) -> bool:
        return not self.validate()

    def describe(self) -> str:
        """Human-readable one-liner for log lines / audit entries."""
        return (
            f"ServicePolicy(cert_ttl={self.cert_ttl_seconds}s, "
            f"reattest_every={self.reattest_interval_seconds}s, "
            f"on_failure={self.on_failure.value}, "
            f"streaming={'on' if self.streaming_enabled else 'off'}, "
            f"max_conns={self.max_concurrent_connections})"
        )

    def to_env(self) -> dict:
        """Render the policy as systemd-friendly env vars (strings)."""
        return {
            "TEE_CRAFTER_CERT_TTL_SEC": str(self.cert_ttl_seconds),
            "TEE_CRAFTER_CERT_GRACE_SEC": str(self.cert_grace_seconds),
            "TEE_CRAFTER_REATTEST_INTERVAL_SEC": str(self.reattest_interval_seconds),
            "TEE_CRAFTER_REATTEST_GRACE_SEC": str(self.reattest_grace_seconds),
            "TEE_CRAFTER_MAX_CONNS": str(self.max_concurrent_connections),
            "TEE_CRAFTER_ON_ATTEST_FAIL": self.on_failure.value,
            "TEE_CRAFTER_KEEPALIVE": "1" if self.advertise_keepalive else "0",
            "TEE_CRAFTER_STREAMING": "1" if self.streaming_enabled else "0",
        }

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "ServicePolicy":
        import os
        e = env if env is not None else os.environ

        def _i(key: str, default: int) -> int:
            try:
                return int(e[key])
            except (KeyError, ValueError, TypeError):
                return default

        def _b(key: str, default: bool) -> bool:
            got = interpret(e.get(key, ""))
            return default if got is None else got

        try:
            on_failure = OnAttestationFailure(
                e.get("TEE_CRAFTER_ON_ATTEST_FAIL", OnAttestationFailure.DRAIN.value)
            )
        except ValueError:
            on_failure = OnAttestationFailure.DRAIN

        return cls(
            cert_ttl_seconds=_i("TEE_CRAFTER_CERT_TTL_SEC", 3600),
            cert_grace_seconds=_i("TEE_CRAFTER_CERT_GRACE_SEC", 300),
            reattest_interval_seconds=_i("TEE_CRAFTER_REATTEST_INTERVAL_SEC", 600),
            reattest_grace_seconds=_i("TEE_CRAFTER_REATTEST_GRACE_SEC", 60),
            max_concurrent_connections=_i("TEE_CRAFTER_MAX_CONNS", 1024),
            on_failure=on_failure,
            advertise_keepalive=_b("TEE_CRAFTER_KEEPALIVE", True),
            streaming_enabled=_b("TEE_CRAFTER_STREAMING", False),
        )
