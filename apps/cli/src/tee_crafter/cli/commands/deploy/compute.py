"""Resolve a deploy's compute shape from a chosen instance type.

The public CLI surface is ``--instance-type`` (optional).  When omitted the CLI
deploys the platform's catalog default (:mod:`tee_crafter.core.catalog`); there
are no compute presets.  The instance type fully determines vCPU / RAM / GPU on
every platform.  On Nitro the enclave is a carve-out of the host instance, so
the enclave CPU/RAM are the chosen instance minus a parent reserve
(:func:`nitro_enclave_resources`); the host instance itself is still the chosen
``instance_type``.

Advanced / Enterprise escape hatches (env, audit-logged by the SaaS layer):

  TEE_CRAFTER_COMPUTE_OVERRIDE_CPU            (int)   — Nitro enclave / raw cpu
  TEE_CRAFTER_COMPUTE_OVERRIDE_RAM_MB         (int, MiB)
  TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE  (str)   — same as --instance-type
  TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_MODEL      (str: h100|h200|b200)
  TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_COUNT      (int)
  TEE_CRAFTER_COMPUTE_OVERRIDE_SPOT           (1/0)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from tee_crafter.core import catalog
from tee_crafter.core.env_flags import env_flag

# Nitro enclaves run *beside* the parent OS on the same instance, so the
# enclave cannot claim the whole box — the parent needs cores/RAM to run the
# vsock proxy, nitro-cli and SSM.  We therefore size the enclave as the chosen
# instance minus a fixed parent reserve.  This is instance-relative (scales up
# with bigger instances) and is applied at *deploy* time, so a generic AMI
# baked on the default host runs unchanged on any larger instance.
NITRO_PARENT_VCPU_RESERVE = 2
NITRO_PARENT_RAM_RESERVE_MB = 2048


def nitro_enclave_resources(host_vcpu: int, host_ram_mb: int) -> tuple[int, int]:
    """Enclave (cpu, ram_mb) for a Nitro host shape, leaving parent headroom."""
    cpu = max(2, host_vcpu - NITRO_PARENT_VCPU_RESERVE)
    ram_mb = max(512, host_ram_mb - NITRO_PARENT_RAM_RESERVE_MB)
    return cpu, ram_mb


@dataclass(frozen=True)
class ComputeShape:
    """Resolved compute shape after instance-type + env overrides.

    ``instance_type`` is ``None`` when the operator did not explicitly choose
    one, so downstream code keeps its existing precedence (TF_VAR_* env →
    catalog default).  ``cpu``/``ram_mb`` still reflect the resolved shape.
    """

    cpu: int
    ram_mb: int
    instance_type: Optional[str]
    gpu_model: Optional[str]
    gpu_count: int
    spot: bool


def _int(envvar: str, default: int) -> int:
    raw = os.environ.get(envvar)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _bool(envvar: str, default: bool) -> bool:
    return env_flag(envvar, default=default)


def _str(envvar: str, default: Optional[str]) -> Optional[str]:
    raw = os.environ.get(envvar)
    return raw.strip() if raw and raw.strip() else default


def resolve_shape(
    tee_platform: str,
    instance_type: Optional[str] = None,
    spot: bool = False,
) -> ComputeShape:
    """Resolve ``(tee_platform, --instance-type, --spot)`` into a ComputeShape.

    Raises ``ValueError`` when an explicitly chosen instance type is not a valid
    shape for the platform (catalog miss).
    """
    chosen = _str("TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE", instance_type)
    spot = _bool("TEE_CRAFTER_COMPUTE_OVERRIDE_SPOT", spot)

    effective = chosen or catalog.default_instance_type(tee_platform)
    spec = catalog.lookup(tee_platform, effective) if effective else None
    if spec is None:
        # Prefer the specific reason. "m6a.24xlarge is not a supported instance
        # type" leaves an operator who was already running m6a with no idea why
        # a *larger* instance of the same family stopped being valid.
        reason = (catalog.unsupported_reason(tee_platform, effective)
                  if effective else None)
        detail = f"{reason} " if reason else (
            f"{effective!r} is not a supported instance type for "
            f"{tee_platform}. ")
        raise ValueError(
            f"{detail}List options with `tee-crafter list-instances "
            f"--tee-platform {tee_platform}`."
        )

    cpu = _int("TEE_CRAFTER_COMPUTE_OVERRIDE_CPU", spec.vcpu)
    ram_mb = _int("TEE_CRAFTER_COMPUTE_OVERRIDE_RAM_MB", spec.ram_mb)
    if tee_platform == "nitro-aws":
        # cpu/ram_mb are the *enclave* shape on Nitro (not the whole VM).
        # Reserve parent headroom from the host spec unless the operator pinned
        # an explicit enclave size via the override env vars.
        if os.environ.get("TEE_CRAFTER_COMPUTE_OVERRIDE_CPU") is None:
            cpu = nitro_enclave_resources(spec.vcpu, spec.ram_mb)[0]
        if os.environ.get("TEE_CRAFTER_COMPUTE_OVERRIDE_RAM_MB") is None:
            ram_mb = nitro_enclave_resources(spec.vcpu, spec.ram_mb)[1]
    gpu_model = _str("TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_MODEL", spec.gpu_model)
    gpu_count = _int("TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_COUNT", spec.gpu_count)
    return ComputeShape(
        cpu=cpu,
        ram_mb=ram_mb,
        instance_type=effective,
        gpu_model=gpu_model,
        gpu_count=gpu_count,
        spot=spot,
    )
