"""Measurement-capture strategy per TEE+cloud.

The *specs* of every instance type (vCPU, RAM, CPU generation, GPU) live in
:mod:`tee_crafter.core.catalog`.  This module decides, from that catalog, **what
to measure at bake time** and how the deploy gates a chosen shape:

* **AMD SEV-SNP** launch ``MEASUREMENT`` folds in the firmware/microcode of the
  host CPU and one VMSA per vCPU, so it can vary with both **CPU generation**
  (Milan vs Genoa) and **vCPU count** (RAM and family name do not matter).  The
  bake therefore walks each supported generation and, within it, the vCPU tiers
  ascending — with an early-stop independence probe: if the two smallest tiers
  of a generation produce the same digest, that generation is vCPU-independent
  (e.g. IGVM-launched CVMs that start extra vCPUs after measurement) and one
  digest covers every size of that generation.

* **Intel TDX** ``MRTD`` measures the initial TD image only, so it is
  generation- and vCPU-independent — one capture covers the whole family.

* **gpu-cc-aws** is NitroTPM (no SEV-SNP); it self-pins its measured-boot PCR
  digest at runtime, not via the SEV-SNP bake reader.

Override the captured vCPU tiers with ``TEE_CRAFTER_SNP_CAPTURE_VCPUS``
(comma-separated) to pre-pin very large shapes (subject to vCPU quota).
"""
from __future__ import annotations

import os
import re
from typing import List, Optional

from tee_crafter.core import catalog

#: SNP platforms whose launch digest *may* vary with CPU gen and/or vCPU count.
SNP_VCPU_SENSITIVE_PLATFORMS = frozenset({
    "snp-aws", "snp-azure", "snp-gcp", "gpu-cc-azure",
})

#: Intel TDX platforms — MRTD is gen/vCPU-independent (single capture).
TDX_SINGLE_CAPTURE_PLATFORMS = frozenset({
    "tdx-azure", "tdx-gcp", "gpu-cc-gcp",
})

#: Platforms not auto-captured from a booted SEV-SNP/TDX instance: Nitro and
#: SGX (build-time deterministic) and gpu-cc-aws (NitroTPM measured boot).
SELF_PIN_PLATFORMS = frozenset({"nitro-aws", "sgx-azure", "gpu-cc-aws"})

#: CPU generations to capture per SNP platform (clouds that expose distinct
#: SKUs per generation are captured for each; GCP N2D shares one name across
#: gens via ``--min-cpu-platform`` and is captured at its default Milan).
#: ``snp-aws`` is Milan-only, not because Genoa hardware is absent but because
#: AWS exposes no ``amd-sev-snp`` processor feature on any ``m7a``/``c7a``/``r7a``
#: type — checked in us-east-1, us-east-2 and us-west-2 (see
#: :data:`tee_crafter.core.catalog._AWS_SNP_CAPABLE_FAMILIES`).  Listing Genoa
#: here made the bake try to boot SEV-SNP instances that cannot exist.
_SNP_CAPTURE_GENS = {
    "snp-aws": ["milan"],
    "snp-azure": ["milan", "genoa"],
    "snp-gcp": ["milan"],
    "gpu-cc-azure": ["genoa"],
}

_DEFAULT_SNP_CAPTURE_VCPUS: List[int] = [2, 4, 8, 16, 32, 48, 64, 96]

#: Platforms where picking an instance type does **not** decide which host CPU
#: generation the VM lands on.
#:
#: This exists because the bake and the deploy learn the generation two
#: different ways, and on Azure they disagree.  Capture reads the model line off
#: the booted VM (``core/measurements/capture.py``), so a variant records what
#: the CPU *was*.  The deploy has no VM yet, so it can only ask the catalog what
#: the instance type *implies* — and for ``Standard_DCas_v5`` the catalog says
#: ``milan`` while live probes on that exact size produced two different launch
#: digests, which is a host-generation difference (see the measurement notes in
#: ``docs/measurements.md``).  Comparing an observed label against an implied one
#: therefore rejects images that are fine.
#:
#: Where the two *do* agree, keep comparing them — it is a real guard:
#:
#: * ``snp-aws`` — ``m6a`` is Milan and ``m7a`` is Genoa; different families,
#:   different hardware, so the family name determines the generation.
#: * ``snp-gcp`` — one ``n2d`` name spans generations, but the bake and the
#:   deploy both pin ``min_cpu_platform``, which is what makes it determined.
#:
#: ``gpu-cc-azure`` is listed too, and that is by analogy rather than from
#: evidence: nothing has been observed about which generations its single SKU
#: lands on. Listing it changes nothing today — one SKU and one expected
#: generation means the gen comparison is vacuous either way — and if Azure ever
#: schedules it across generations the analogy is the safer of the two guesses.
_HOST_GEN_NOT_SELECTABLE = frozenset({"snp-azure", "gpu-cc-azure"})


def host_gen_is_selectable(platform: str) -> bool:
    """Does choosing an instance type determine the host CPU generation?

    ``False`` means a deploy cannot know the generation before the VM boots, so
    a gen-vs-gen comparison against bake-time data is not meaningful.
    """
    return (platform or "") not in _HOST_GEN_NOT_SELECTABLE


#: Keys a capture variant may use to record the shape it measured, in the order
#: the per-cloud capture paths write them.
_VARIANT_SHAPE_KEYS = ("instance_type", "vm_size", "machine_type")


def variant_shape(variant: dict) -> Optional[str]:
    """The instance shape a captured variant refers to, whichever key it used."""
    for key in _VARIANT_SHAPE_KEYS:
        value = variant.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def shape_series(platform: str, shape: str) -> Optional[str]:
    """A coarse grouping of *shape* that the operator genuinely chooses.

    Returns ``None`` when the platform has no such axis, which means "do not
    discriminate on this".

    This exists because :data:`_HOST_GEN_NOT_SELECTABLE` throws away too much on
    Azure. It is true that picking ``Standard_DC2as_v5`` does not decide whether
    you land on Milan or Genoa silicon -- so comparing CPU generations there
    rejects images that work. But picking ``v5`` versus ``v6`` *is* a choice, and
    the two are different SKU families on different firmware. Ignoring the whole
    shape and matching on vCPU count alone let a ``Standard_DC2as_v6`` deploy sail
    through against a record whose only variants were ``..._v5`` at the same vCPU
    count, and the mismatch surfaced later as a failed attestation on a VM that
    was already billing.

    Deliberately only the version suffix, not the full family. ``DC`` versus
    ``EC`` differ in RAM per vCPU, which is not an input to the launch
    measurement, so discriminating on it would refuse shapes with no evidence
    that they differ. The version is where there is a reason to expect a
    different digest.
    """
    if platform not in ("snp-azure", "gpu-cc-azure"):
        return None
    match = re.search(r"_(v[0-9]+)$", shape or "")
    return match.group(1) if match else None


def expected_host_gens(platform: str) -> List[str]:
    """CPU generations this platform is expected to be able to present.

    The same list the bake walks, which is the point: if capture came back with
    fewer generations than this, the bake did not see everything the platform
    can schedule, and a deploy may land on an unpinned one.
    """
    return list(_SNP_CAPTURE_GENS.get(platform, []))


# --------------------------------------------------------------------------
# Thin delegations to the catalog (kept here so callers have one import).
# --------------------------------------------------------------------------

def instance_family_ok(platform: str, instance_type: str) -> bool:
    """True when ``instance_type`` belongs to a supported family."""
    return catalog.is_in_family(platform, instance_type)


def instance_vcpu(platform: str, instance_type: str) -> Optional[int]:
    """vCPU count for an instance type (from the catalog)."""
    return catalog.instance_vcpu(platform, instance_type)


def instance_gen(platform: str, instance_type: str) -> Optional[str]:
    """CPU generation for an instance type (from the catalog)."""
    return catalog.instance_gen(platform, instance_type)


def default_instance_type(platform: str) -> Optional[str]:
    return catalog.default_instance_type(platform)


# --------------------------------------------------------------------------
# Capture-shape selection
# --------------------------------------------------------------------------

def snp_capture_vcpus() -> List[int]:
    """vCPU tiers to attempt at bake for SNP-sensitive platforms.

    Overridable via ``TEE_CRAFTER_SNP_CAPTURE_VCPUS`` (comma-separated).
    """
    raw = os.environ.get("TEE_CRAFTER_SNP_CAPTURE_VCPUS", "").strip()
    if raw:
        out: List[int] = []
        for tok in raw.split(","):
            tok = tok.strip()
            if tok.isdigit() and int(tok) > 0 and int(tok) not in out:
                out.append(int(tok))
        if out:
            return sorted(out)
    return list(_DEFAULT_SNP_CAPTURE_VCPUS)


def _snp_representative(platform: str, gen: str, vcpu: int) -> Optional[str]:
    """A concrete instance type of ``gen`` + ``vcpu`` for capture.

    The candidate is graded through :func:`catalog.lookup` rather than returned
    as-built.  This function used to compose ``m6a.{size}`` from the vCPU table
    alone, so it emitted shapes AWS does not offer SEV-SNP on — every vCPU tier
    above 32 for ``m6a`` (past the 128 GiB SEV-SNP ceiling), and the whole
    ``m7a`` line.  The bake then tried to boot them.
    """
    if platform == "snp-aws":
        size = catalog._AWS_VCPU_SIZE.get(vcpu)
        if not size:
            return None
        fam = "m6a" if gen == "milan" else "m7a"
        candidate = f"{fam}.{size}"
        return candidate if catalog.lookup(platform, candidate) else None
    if platform == "snp-azure":
        ver = "v5" if gen == "milan" else "v6"
        return f"Standard_DC{vcpu}as_{ver}"
    if platform == "snp-gcp":
        return f"n2d-standard-{vcpu}"
    if platform == "gpu-cc-azure":
        return catalog.default_instance_type(platform)
    return None


def capture_shapes(platform: str) -> List[str]:
    """Return the instance shapes to boot for ``platform`` measurement capture.

    SNP-sensitive platforms yield shapes grouped by CPU generation and, within
    a generation, ascending vCPU (so the orchestrator can run an early-stop
    independence probe per generation).  TDX captures once; self-pin platforms
    capture none.
    """
    if platform in SELF_PIN_PLATFORMS:
        return []
    if platform == "gpu-cc-azure":
        dit = catalog.default_instance_type(platform)
        return [dit] if dit else []
    if platform in SNP_VCPU_SENSITIVE_PLATFORMS:
        shapes: List[str] = []
        for gen in _SNP_CAPTURE_GENS.get(platform, ["milan"]):
            for vcpu in snp_capture_vcpus():
                rep = _snp_representative(platform, gen, vcpu)
                if rep and rep not in shapes:
                    shapes.append(rep)
        return shapes
    if platform in TDX_SINGLE_CAPTURE_PLATFORMS:
        dit = catalog.default_instance_type(platform)
        return [dit] if dit else []
    return []
