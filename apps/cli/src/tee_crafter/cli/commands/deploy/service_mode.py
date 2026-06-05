"""CLI plumbing for persistent RA-TLS service mode.

Translates a single ``--service-profile`` CLI flag into a
:class:`ServicePolicy`, validates it, writes a ``service_policy.json`` +
``service_policy.env`` to the staged build dir so downstream Terraform /
systemd templating can pick it up, and records an audit entry.

Public CLI surface is one flag (``--service-profile`` ∈ {``default``,
``long-lived``, ``short-lived``, ``streaming``}).  The 8 individual
knobs (cert-ttl, reattest-*, keepalive, streaming, max-conns,
on-attestation-failure) are gone from the public CLI; the SaaS / dev
operator picks a tested, security-reviewed profile instead.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Optional

from tee_crafter.core.service import (
    ServicePolicy, OnAttestationFailure,
)


# Public profile names (user-facing) -> ServicePolicy preset.
#
# Each preset has been picked + reviewed once, so we don't have to
# re-validate every individual knob combination.
SERVICE_PROFILES = {
    "default": dict(
        enabled=False,
        cert_ttl=3600, cert_grace=300,
        reattest_interval=600, reattest_grace=60,
        keepalive=True, streaming=False,
        max_conns=1024, on_failure="drain",
    ),
    "long-lived": dict(
        enabled=True,
        cert_ttl=86400, cert_grace=600,
        reattest_interval=3600, reattest_grace=60,
        keepalive=True, streaming=False,
        max_conns=1024, on_failure="drain",
    ),
    "short-lived": dict(
        enabled=True,
        cert_ttl=3600, cert_grace=120,
        reattest_interval=600, reattest_grace=30,
        keepalive=True, streaming=False,
        max_conns=256, on_failure="drain",
    ),
    "streaming": dict(
        enabled=True,
        cert_ttl=3600, cert_grace=120,
        reattest_interval=600, reattest_grace=30,
        keepalive=True, streaming=True,
        max_conns=4096, on_failure="drain",
    ),
}


def build_service_policy_from_profile(profile: str) -> tuple[bool, ServicePolicy]:
    """Resolve a ``--service-profile`` value into ``(enabled, policy)``.

    Raises ``ValueError`` for unknown profile names.
    """
    name = (profile or "default").lower()
    if name not in SERVICE_PROFILES:
        raise ValueError(
            f"--service-profile must be one of {sorted(SERVICE_PROFILES)}, "
            f"got {profile!r}"
        )
    spec = SERVICE_PROFILES[name]
    enabled = spec["enabled"]
    policy = build_service_policy(
        enabled=enabled,
        cert_ttl=spec["cert_ttl"], cert_grace=spec["cert_grace"],
        reattest_interval=spec["reattest_interval"],
        reattest_grace=spec["reattest_grace"],
        keepalive=spec["keepalive"], streaming=spec["streaming"],
        max_conns=spec["max_conns"], on_failure=spec["on_failure"],
    )
    return enabled, policy


def build_service_policy(
    *,
    enabled: bool,
    cert_ttl: int,
    cert_grace: int,
    reattest_interval: int,
    reattest_grace: int,
    keepalive: bool,
    streaming: bool,
    max_conns: int,
    on_failure: str,
    extra_hooks: Optional[list] = None,
) -> ServicePolicy:
    """Internal builder used by the profile dispatcher.

    Kept as a separate function (rather than inlined) so test code can
    still construct invalid policies on purpose to exercise validation.
    """
    try:
        on_fail = OnAttestationFailure(on_failure)
    except ValueError:
        raise ValueError(
            f"on_failure must be one of "
            f"{[m.value for m in OnAttestationFailure]}, got {on_failure!r}"
        )
    p = ServicePolicy(
        cert_ttl_seconds=cert_ttl,
        cert_grace_seconds=cert_grace,
        reattest_interval_seconds=reattest_interval,
        reattest_grace_seconds=reattest_grace,
        max_concurrent_connections=max_conns,
        on_failure=on_fail,
        advertise_keepalive=keepalive,
        streaming_enabled=streaming,
        extra_attestation_hooks=list(extra_hooks or []),
    )
    if enabled:
        errs = p.validate()
        if errs:
            raise ValueError("Invalid persistent service policy: " + "; ".join(errs))
    return p


def write_service_policy(build_dir: str, policy: ServicePolicy, *,
                          enabled: bool) -> str:
    """Write ``service_policy.json`` (machine-readable) and
    ``service_policy.env`` (systemd EnvironmentFile-compatible) into
    *build_dir*.  When ``build_dir/app`` exists (CVM / SNP layout), the same
    files are mirrored there so S3 bundles that only ship ``app/`` still
    carry the policy.

    Returns the path to the JSON file at *build_dir* root.
    """
    os.makedirs(build_dir, exist_ok=True)
    json_path = os.path.join(build_dir, "service_policy.json")
    doc = {
        "enabled": bool(enabled),
        "policy": asdict(policy) | {"on_failure": policy.on_failure.value},
        "describe": policy.describe(),
    }
    env_data = policy.to_env()
    env_data["TEE_CRAFTER_SERVICE_MODE"] = "1" if enabled else "0"

    def _write_pair(base: str) -> None:
        os.makedirs(base, exist_ok=True)
        jp = os.path.join(base, "service_policy.json")
        ep = os.path.join(base, "service_policy.env")
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, default=str)
        with open(ep, "w", encoding="utf-8") as f:
            for k, v in sorted(env_data.items()):
                f.write(f"{k}={v}\n")

    _write_pair(build_dir)
    app_dir = os.path.join(build_dir, "app")
    if os.path.isdir(app_dir):
        _write_pair(app_dir)

    return json_path


def record_service_policy_audit(audit, policy: ServicePolicy, *, enabled: bool) -> None:
    """Append the chosen service policy to the build audit trail."""
    if audit is None:
        return
    try:
        audit.record(
            "Service Mode",
            "Persistent RA-TLS policy resolved",
            "info" if enabled else "skip",
            enabled=bool(enabled),
            cert_ttl_seconds=policy.cert_ttl_seconds,
            cert_grace_seconds=policy.cert_grace_seconds,
            reattest_interval_seconds=policy.reattest_interval_seconds,
            reattest_grace_seconds=policy.reattest_grace_seconds,
            max_concurrent_connections=policy.max_concurrent_connections,
            on_failure=policy.on_failure.value,
            advertise_keepalive=policy.advertise_keepalive,
            streaming_enabled=policy.streaming_enabled,
            extra_hooks=list(policy.extra_attestation_hooks),
        )
    except Exception:
        # Audit must never break the deploy.
        pass
