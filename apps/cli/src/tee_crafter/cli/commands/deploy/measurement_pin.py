"""Deploy-time auto-pinning from the launch-measurement registry.

``bake-ami`` records each image's launch measurement(s) under
``tee_crafter/measurements/<platform>/<image_id>.json``.  SNP-family bakes
store **one digest per (CPU generation, vCPU tier)** so any size in the
supported family works after a single bake; TDX stores a single MRTD.  At
deploy time we resolve the allowlist
and feed it into three fail-closed consumers with **zero operator action**:

1. the client verifier (``EXPECTED_MEASUREMENTS`` allowlist) so the
   post-deploy attestation check is bound to the vetted image rather than
   trust-on-first-use (``"unknown"``);
2. the BYOK key-release policy (``allowed_measurement_sha256``) so a customer
   key is only ever released to that image;
3. the sealed-``.env`` release policy (same BYOK orchestrator/allowlist).

When sealed-``.env`` or BYOK is requested for a **CVM** image that has no
registry entry, :func:`enforce` fails closed (hard stop) unless the operator
sets ``TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1``.  Nitro/SGX pin via their
build-time PCR0 / MRENCLAVE flow and are intentionally out of scope here.
"""
from __future__ import annotations

import hashlib
import os
from typing import List, Optional

from tee_crafter.core.measurements import measurement_value, measurement_values

#: Platforms whose launch measurement is only knowable after boot and must be
#: captured at bake time (the auto-pin registry covers exactly these).
CVM_PLATFORMS = frozenset({
    "snp-aws", "snp-azure", "snp-gcp",
    "tdx-azure", "tdx-gcp",
    "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
})

ALLOW_UNPINNED_ENV = "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT"


def allow_unpinned() -> bool:
    """Dev hatch: permit sealed/BYOK on an unpinned CVM image."""
    return os.environ.get(ALLOW_UNPINNED_ENV, "").strip().lower() in (
        "1", "true", "yes", "on")


def resolve_all(tee_platform: str, image_id: Optional[str]) -> List[str]:
    """Return all pinned measurement hex values for ``(platform, image_id)``."""
    if not image_id or tee_platform not in CVM_PLATFORMS:
        return []
    return measurement_values(tee_platform, image_id)


def resolve(tee_platform: str, image_id: Optional[str]) -> Optional[str]:
    """Return the primary pinned measurement hex (first allowlist entry)."""
    if not image_id or tee_platform not in CVM_PLATFORMS:
        return None
    return measurement_value(tee_platform, image_id)


def policy_sha256(raw_measurement_hex: str) -> str:
    """Derive the policy allowlist value from a raw measurement.

    The key-release orchestrator compares ``SHA-256(MEASUREMENT)`` (a 64-hex
    digest), matching :meth:`AttestationProvider.fresh`.  The registry stores
    the raw measurement (e.g. the 96-hex SNP SHA-384), so we hash its bytes.
    """
    raw = (raw_measurement_hex or "").strip().lower()
    return hashlib.sha256(bytes.fromhex(raw)).hexdigest()


def policy_sha256_list(raw_measurements: List[str]) -> List[str]:
    """Derive BYOK allowlist entries from a list of raw measurements."""
    out: List[str] = []
    for raw in raw_measurements or []:
        digest = policy_sha256(raw)
        if digest not in out:
            out.append(digest)
    return out


def enforce(
    console,
    *,
    tee_platform: str,
    image_id: Optional[str],
    pinned_measurements: Optional[List[str]] = None,
    sealed_or_byok: bool,
    pinned_measurement: Optional[str] = None,
) -> bool:
    """Fail closed when sealed/BYOK is requested without a pinned measurement.

    Returns ``True`` when the deploy may proceed, ``False`` (after printing a
    panel) when it must abort.  Only engages for CVM platforms; Nitro/SGX
    return ``True`` (pinned via their own build-time flow).

    ``pinned_measurement`` is accepted for backward compatibility; prefer
    ``pinned_measurements``.
    """
    if pinned_measurements is None and pinned_measurement:
        pinned_measurements = [pinned_measurement]
    if not sealed_or_byok or tee_platform not in CVM_PLATFORMS:
        return True
    if pinned_measurements:
        return True
    if allow_unpinned():
        try:
            console.print(
                f"[yellow]⚠ {ALLOW_UNPINNED_ENV}=1: proceeding with sealed/BYOK on "
                f"an UNPINNED {tee_platform} image ({image_id}). Key release is "
                f"NOT bound to a vetted measurement — dev/prototyping only.[/yellow]")
        except Exception:
            pass
        return True
    try:
        from tee_crafter.cli.constants import Panel
        console.print(Panel.fit(
            f"[bold red]No pinned measurement for {image_id}[/bold red]\n\n"
            f"Sealed --secrets-env / BYOK release on [magenta]{tee_platform}[/magenta] "
            f"is fail-closed: the customer key may only be released to an image whose "
            f"launch measurement was captured and vetted at bake time.\n\n"
            f"This image has no entry in the measurement registry. Re-bake it with "
            f"[bold]tee-crafter internal bake-ami[/bold] (capture is automatic), or "
            f"set [bold]{ALLOW_UNPINNED_ENV}=1[/bold] for dev/prototyping only.",
            border_style="red"))
    except Exception:
        pass
    return False
