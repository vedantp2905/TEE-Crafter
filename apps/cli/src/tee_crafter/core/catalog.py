"""Instance catalog — the single source of truth for selectable shapes.

Per TEE+cloud this enumerates the concrete instance types a workload may run
on, each annotated with its **vCPU**, **RAM**, **CPU generation** and (for GPU
platforms) **GPU model / count**.  It powers three things:

1. **CLI / UI selection** — `--instance-type` (CLI) and the eventual web UI list
   shapes from :func:`enumerate_instances`; :func:`lookup` resolves any chosen
   type (even a size not pre-listed) to its specs to display vCPU/RAM/GPU.
2. **Defaults** — :func:`default_instance_type` is what the CLI deploys when the
   operator does not pass ``--instance-type`` (no compute presets).
3. **Measurement capture + gating** — :mod:`tee_crafter.core.measurements.shapes`
   derives the vCPU tiers and CPU generations to bake from this catalog, and
   deploy gates the chosen shape against the captured measurements.

CPU generation matters because an AMD SEV-SNP launch measurement folds in the
firmware/microcode of the host CPU: Milan (Zen 3) and Genoa (Zen 4) produce
different digests, so they are captured and pinned separately.

RAM values are the cloud's published memory-per-vCPU for the family and are
exact for the enumerated sizes; :func:`lookup` computes them for arbitrary sizes
from the same per-family ratio.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

GIB = 1024


@dataclass(frozen=True)
class InstanceSpec:
    """Resolved specs for one instance type."""

    instance_type: str
    vcpu: int
    ram_mb: int
    cpu_gen: Optional[str] = None          # milan | genoa | sapphire-rapids | None
    gpu_model: Optional[str] = None        # h100 | h200 | b200 | None
    gpu_count: int = 0

    def summary(self) -> str:
        ram_gib = self.ram_mb / GIB
        base = f"{self.vcpu} vCPU, {ram_gib:g} GiB"
        if self.gpu_count:
            base += f", {self.gpu_count}\u00d7{(self.gpu_model or 'gpu').upper()}"
        if self.cpu_gen:
            base += f" ({self.cpu_gen})"
        return base


# --------------------------------------------------------------------------
# AWS size token → vCPU (shared by SNP M*a/C*a/R*a and Nitro C6a hosts).
# --------------------------------------------------------------------------
_AWS_SIZE_VCPU: Dict[str, int] = {
    "large": 2, "xlarge": 4, "2xlarge": 8, "4xlarge": 16, "8xlarge": 32,
    "12xlarge": 48, "16xlarge": 64, "24xlarge": 96, "32xlarge": 128,
    "48xlarge": 192, "metal": 192,
}
_AWS_VCPU_SIZE: Dict[int, str] = {v: k for k, v in _AWS_SIZE_VCPU.items()
                                  if k != "metal"}

#: RAM (MiB) per vCPU by AWS family letter.
_AWS_RAM_PER_VCPU = {"m": 4 * GIB, "c": 2 * GIB, "r": 8 * GIB}

#: AWS SNP families by CPU generation.
#:
#: Genoa (``m7a``/``c7a``/``r7a``) is listed here for the generation label only.
#: It is **not** selectable — see :data:`_AWS_SNP_MAX_RAM_MB` and
#: :func:`unsupported_reason`.  AWS reports no ``amd-sev-snp`` processor feature
#: on any 7a type.
_AWS_SNP_FAMILIES = {
    "milan": ["m6a", "c6a", "r6a"],
    "genoa": ["m7a", "c7a", "r7a"],
}

#: SEV-SNP families AWS actually exposes the feature on, and the guest-memory
#: ceiling it stops at.
#:
#: From ``ec2:DescribeInstanceTypes`` — ``ProcessorInfo.SupportedFeatures``
#: contains ``amd-sev-snp`` — checked in **us-east-2, us-east-1 and us-west-2**
#: on 2026-08-21, which agreed exactly.  Of the 69 ``m/c/r`` ``6a``/``7a`` types
#: those regions publish, only 16 carry the feature:
#:
#:     c6a.large … c6a.16xlarge      (up to 64 vCPU / 128 GiB)
#:     m6a.large … m6a.8xlarge       (up to 32 vCPU / 128 GiB)
#:     r6a.large … r6a.4xlarge       (up to 16 vCPU / 128 GiB)
#:
#: Two things make that a real answer rather than an API gap.  The three
#: families cut off at *different* vCPU counts but the *same* 128 GiB of
#: memory, which is a coherent hardware ceiling rather than an arbitrary list.
#: And ``_INSTANCE_RULES["snp-aws"]`` in
#: ``cli/commands/deploy/platform.py`` has always restricted deploys to the 6a
#: families, so the CLI already refused Genoa at preflight while this catalog
#: happily enumerated it — ``list-instances`` advertised shapes the very next
#: step rejected.  This makes the catalog agree with the gate.
#:
#: Re-check with:
#:     aws ec2 describe-instance-types \
#:       --filters Name=instance-type,Values='m6a.*,c6a.*,r6a.*,m7a.*,c7a.*,r7a.*' \
#:       --query "InstanceTypes[?contains(ProcessorInfo.SupportedFeatures,
#:                'amd-sev-snp')].InstanceType"
_AWS_SNP_CAPABLE_FAMILIES = frozenset({"m6a", "c6a", "r6a"})
_AWS_SNP_MAX_RAM_MB = 128 * GIB

#: Azure confidential families → ``(cpu_gen, ram_per_vcpu, vcpu_tiers, ram_overrides)``.
#:
#: The ``ads``/``eds`` rows are the **local-temp-disk** variants of the same
#: silicon (Azure appends ``d`` for "has a local disk").  They are separate SKUs
#: rather than an option on the base SKU, so a name-pattern catalog has to list
#: them or ``lookup`` returns ``None`` for a VM size Azure will happily sell you.
#:
#: Every field below was measured, not assumed: ``az vm list-skus`` was read in
#: six regions (westus, westus3, eastus, eastus2, westeurope, northeurope) on
#: 2026-08-22 and the 12 families agreed on vCPU count and MemoryGB for every
#: size in every region they appear in — no conflicts. Three things that a flat
#: "DC = 4 GiB/vCPU, EC = 8 GiB/vCPU, tiers 2…96" model got wrong:
#:
#: 1. **Tiers are per-family, not global.** ``DCes_v6``/``DCeds_v6`` publish a
#:    128-vCPU size; ``ECes_v6``/``ECeds_v6`` stop at **64**. Appending 128 to a
#:    shared list would have made ``lookup`` advertise ``Standard_DC128as_v6``,
#:    which Azure does not sell — the same failure shape as the ``snp-aws``
#:    Genoa split, a catalog enumerating more than the cloud offers. Hence a
#:    per-family tier tuple, and ``lookup`` rejecting an off-tier vCPU count.
#: 2. **EC RAM is not a flat ratio.** ``ECas_v5``/``ECads_v5`` span 6, 7 and 8
#:    GiB/vCPU; ``ECas_v6``/``ECads_v6`` span 7 and 8. Only ``ECes_v6`` /
#:    ``ECeds_v6`` are genuinely flat 8. The deviating sizes are listed
#:    explicitly in ``ram_overrides`` rather than approximated by a second
#:    ratio, because ``InstanceSpec.ram_mb`` feeds sizing and cost output.
#: 3. **``ECas_v5``/``ECads_v5`` have a 20-vCPU size**, which no other
#:    confidential family does.
_DC_TIERS = (2, 4, 8, 16, 32, 48, 64, 96)
_DC_TIERS_128 = (2, 4, 8, 16, 32, 48, 64, 96, 128)
_EC_V5_TIERS = (2, 4, 8, 16, 20, 32, 48, 64, 96)
_EC_V6_TIERS = (2, 4, 8, 16, 32, 48, 64, 96)
_ECES_V6_TIERS = (2, 4, 8, 16, 32, 48, 64)
#: Sizes where Azure departs from the family's GiB/vCPU ratio (vCPU → ram_mb).
_EC_V5_RAM = {32: 192 * GIB, 96: 672 * GIB}
_EC_V6_RAM = {96: 672 * GIB}

_AZURE_SNP_FAMILIES = {
    ("DC", "as", "v5"): ("milan", 4 * GIB, _DC_TIERS, {}),
    ("EC", "as", "v5"): ("milan", 8 * GIB, _EC_V5_TIERS, _EC_V5_RAM),
    ("DC", "as", "v6"): ("genoa", 4 * GIB, _DC_TIERS, {}),
    ("EC", "as", "v6"): ("genoa", 8 * GIB, _EC_V6_TIERS, _EC_V6_RAM),
    ("DC", "ads", "v5"): ("milan", 4 * GIB, _DC_TIERS, {}),
    ("EC", "ads", "v5"): ("milan", 8 * GIB, _EC_V5_TIERS, _EC_V5_RAM),
    ("DC", "ads", "v6"): ("genoa", 4 * GIB, _DC_TIERS, {}),
    ("EC", "ads", "v6"): ("genoa", 8 * GIB, _EC_V6_TIERS, _EC_V6_RAM),
}
#: Azure TDX families: DCes/ECes v6 and their DCeds/ECeds local-disk variants
#: (Intel Sapphire Rapids).  Intel TDX went GA on Azure in February 2026 across
#: DCesv6, DCedsv6, ECesv6 and ECedsv6 — the ``d`` pair was missing here.
_AZURE_TDX_FAMILIES = {
    ("DC", "es", "v6"): ("sapphire-rapids", 4 * GIB, _DC_TIERS_128, {}),
    ("EC", "es", "v6"): ("sapphire-rapids", 8 * GIB, _ECES_V6_TIERS, {}),
    ("DC", "eds", "v6"): ("sapphire-rapids", 4 * GIB, _DC_TIERS_128, {}),
    ("EC", "eds", "v6"): ("sapphire-rapids", 8 * GIB, _ECES_V6_TIERS, {}),
}

#: GCP N2D (SNP) sub-families → ram_per_vcpu.  Milan or Genoa by min-cpu-platform.
_GCP_N2D = {"standard": 4 * GIB, "highmem": 8 * GIB, "highcpu": 1 * GIB}
_GCP_N2D_VCPU = [2, 4, 8, 16, 32, 48, 64, 80, 96, 128, 224]
#: GCP C3 (TDX) — Sapphire Rapids.
_GCP_C3 = {"standard": 4 * GIB, "highmem": 8 * GIB, "highcpu": 2 * GIB}
_GCP_C3_VCPU = [4, 8, 22, 44, 88, 176]

#: GPU CC catalog: platform → list of (instance_type, vcpu, ram_mb, model, count).
_GPU_CATALOG: Dict[str, List[InstanceSpec]] = {
    "gpu-cc-gcp": [
        InstanceSpec("a3-highgpu-1g", 26, 234 * GIB, "sapphire-rapids", "h100", 1),
        InstanceSpec("a3-highgpu-2g", 52, 468 * GIB, "sapphire-rapids", "h100", 2),
        InstanceSpec("a3-highgpu-4g", 104, 936 * GIB, "sapphire-rapids", "h100", 4),
        InstanceSpec("a3-highgpu-8g", 208, 1872 * GIB, "sapphire-rapids", "h100", 8),
    ],
    "gpu-cc-azure": [
        InstanceSpec("Standard_NCC40ads_H100_v5", 40, 320 * GIB, "genoa", "h100", 1),
    ],
    "gpu-cc-aws": [
        InstanceSpec("p5.4xlarge", 16, 256 * GIB, "sapphire-rapids", "h100", 1),
        InstanceSpec("p5.48xlarge", 192, 2048 * GIB, "sapphire-rapids", "h100", 8),
        InstanceSpec("p5en.48xlarge", 192, 2048 * GIB, "sapphire-rapids", "h200", 8),
        InstanceSpec("p6-b200.48xlarge", 192, 2048 * GIB, "sapphire-rapids", "b200", 8),
    ],
}

#: SGX (Gramine) — Azure DCsv3 / DCdsv3, Intel Ice Lake SGX.
#:
#: From ``az vm list-skus --location westus --resource-type virtualMachines``,
#: read on 2026-08-22: Azure publishes **16** ``Standard_DC*_v3`` SKUs — eight
#: vCPU tiers, each in a ``s_v3`` and a ``ds_v3`` (local temp disk) variant —
#: at a flat 8 GiB per vCPU with no exceptions:
#:
#:     DC1  8 GiB    DC2  16 GiB   DC4  32 GiB   DC8   64 GiB
#:     DC16 128 GiB  DC24 192 GiB  DC32 256 GiB  DC48 384 GiB
#:
#: This list previously stopped at ``DC16s_v3`` and omitted the ``ds`` family
#: outright, so ``list-instances`` showed 4 of the 16 shapes a deploy would
#: accept — both ``templates/sgx/main.template.tf`` ("Must be a DCsv3/DCdsv3
#: series") and ``deployment/sgx/enclave_start.py`` already named the wider set.
#:
#: Azure does not publish SGX **EPC** size as a SKU capability (the only
#: enclave-adjacent one is ``EncryptionAtHostSupported``), so nothing here
#: describes how large an enclave a tier can actually hold.  ``DC1`` is listed
#: because Azure offers it, but the default 4 GiB enclave
#: (``gsc.DEFAULT_ENCLAVE_SIZE``) is not a good fit for a 1-vCPU/8-GiB host.
#:
#: Re-check with:
#:     az vm list-skus --location westus --resource-type virtualMachines \
#:       --query "[?starts_with(name,'Standard_DC') && contains(name,'_v3')]
#:                .{n:name,caps:capabilities}"
_SGX_AZURE_TIERS = (1, 2, 4, 8, 16, 24, 32, 48)
_SGX_AZURE = [
    InstanceSpec(f"Standard_DC{v}{suffix}_v3", v, v * 8 * GIB, "intel-sgx")
    for v in _SGX_AZURE_TIERS
    for suffix in ("s", "ds")
]

#: Graviton (arm64) Nitro Enclaves hosts, by family generation digit → the size
#: tokens that generation actually offers.
#:
#: Taken from ``ec2:DescribeInstanceTypes`` in us-east-2 on 2026-08-21, filtered
#: on ``nitro-enclaves-support=supported`` **and**
#: ``processor-info.supported-architecture=arm64``.  Not from prose: an earlier
#: revision of two shipping docs claimed Graviton was supported end to end via
#: ``--instance-type`` while :func:`lookup` rejected every Graviton type
#: outright, so this list is generated from the API's own answer.  Note that
#: Graviton2/3 stop at ``16xlarge`` and Graviton4-and-later add ``24xlarge`` and
#: ``48xlarge`` but never ``32xlarge`` — the sizes differ per generation, so
#: they are enumerated rather than derived.
_AWS_NITRO_GRAVITON_SIZES: Dict[str, List[str]] = {
    "6": ["large", "xlarge", "2xlarge", "4xlarge", "8xlarge", "12xlarge",
          "16xlarge"],
    "7": ["large", "xlarge", "2xlarge", "4xlarge", "8xlarge", "12xlarge",
          "16xlarge"],
    "8": ["large", "xlarge", "2xlarge", "4xlarge", "8xlarge", "12xlarge",
          "16xlarge", "24xlarge", "48xlarge"],
    "9": ["large", "xlarge", "2xlarge", "4xlarge", "8xlarge", "12xlarge",
          "16xlarge", "24xlarge", "48xlarge"],
}

#: Deliberately coarse.  ``DescribeInstanceTypes`` reports these as
#: ``Manufacturer: "AWS"`` with no generation string, so writing "graviton2" for
#: ``c6g`` and "graviton4" for ``c8g`` would be a mapping this code cannot
#: check — exactly the kind of unverifiable prose claim that put Graviton on the
#: open-items list in the first place.  The generation is already legible in the
#: instance type itself, and unlike AMD SEV-SNP (where Milan and Genoa produce
#: different launch measurements) a Nitro PCR0 is derived from the enclave image
#: at build time, not from the host CPU — so nothing downstream branches on this
#: value for ``nitro-aws``.  ``nitro-aws`` is in
#: :data:`~tee_crafter.core.measurements.shapes.SELF_PIN_PLATFORMS`, so
#: ``capture_shapes`` returns before any per-generation capture.
_GRAVITON_CPU_GEN = "graviton"


#: Smallest host TEE-Crafter can place an enclave on.  An enclave is a
#: carve-out of the parent instance and ``nitro_enclave_resources`` holds back
#: ``NITRO_PARENT_VCPU_RESERVE = 2`` vCPU for the parent's vsock proxy,
#: ``nitro-cli`` and SSM — so on a 2-vCPU host the reserve consumes the whole
#: box and the enclave floor claims it straight back.
#:
#: Note this is *our* limit on arm64, not AWS's: ``DescribeInstanceTypes``
#: reports ``c6g.large`` (2 vCPU) as ``NitroEnclavesSupport: supported`` while
#: the x86 ``c6a.large`` is ``unsupported``.  The refusal message says which
#: reason applies, because "AWS cannot" and "we will not" are different facts
#: and an operator sizing a deployment needs to know which one they hit.
_NITRO_MIN_VCPU = 4


def _graviton_nitro_specs() -> List[InstanceSpec]:
    out: List[InstanceSpec] = []
    for gen_digit, sizes in _AWS_NITRO_GRAVITON_SIZES.items():
        for letter in ("c", "m", "r"):
            for tok in sizes:
                vcpu = _AWS_SIZE_VCPU[tok]
                if vcpu < _NITRO_MIN_VCPU:
                    continue
                out.append(InstanceSpec(
                    f"{letter}{gen_digit}g.{tok}", vcpu,
                    vcpu * _AWS_RAM_PER_VCPU[letter], _GRAVITON_CPU_GEN))
    return out


#: Nitro hosts — AWS C6a (Milan, x86_64) is the default Secure-Boot-capable
#: host; the Graviton families follow it.  Graviton matters beyond cost: it is
#: the only architecture whose enclave image an Apple Silicon workstation can
#: build natively, without the Rosetta-backed amd64 path.
_NITRO_AWS = [
    InstanceSpec(f"c6a.{tok}", v, v * _AWS_RAM_PER_VCPU["c"], "milan")
    for tok, v in (("xlarge", 4), ("2xlarge", 8), ("4xlarge", 16),
                   ("8xlarge", 32), ("16xlarge", 64))
] + _graviton_nitro_specs()

#: Default instance type per platform (what the CLI deploys with no flag).
DEFAULT_INSTANCE_TYPE: Dict[str, str] = {
    "snp-aws":      "m6a.large",
    "snp-azure":    "Standard_DC2as_v5",
    "snp-gcp":      "n2d-standard-2",
    "tdx-azure":    "Standard_DC2es_v6",
    "tdx-gcp":      "c3-standard-4",
    "gpu-cc-gcp":   "a3-highgpu-1g",
    "gpu-cc-azure": "Standard_NCC40ads_H100_v5",
    "gpu-cc-aws":   "p5.4xlarge",
    "sgx-azure":    "Standard_DC2s_v3",
    "nitro-aws":    "c6a.xlarge",
}


# --------------------------------------------------------------------------
# Lookup (parse-based — resolves any size, not just the enumerated ones)
# --------------------------------------------------------------------------

def instance_architecture(instance_type: Optional[str]) -> Optional[str]:
    """``"arm64"`` or ``"x86_64"`` for an AWS instance type, ``None`` if empty.

    The single definition of this rule.  It previously existed as six separate
    copies — in ``terraform_gen`` (picking the base AMI), ``baking/nitro``
    (picking the bake host image), ``enclave`` (twice, picking the Docker build
    platform), ``deploy/validators`` and ``cli/preflight`` — in **two
    inconsistent variants**.  Four used ``re.search(r"\\dg", family)`` and two
    used ``re.search(r"\\dg$", family)``, and the anchored form is wrong: it
    classifies every ``d``/``n`` Graviton variant as x86_64, because
    ``c6gd``/``c6gn``/``m8gd``/``x2gd`` do not end in ``g``.  A deploy on
    ``c6gd.xlarge`` would therefore have been handed an x86_64 base AMI.

    The unanchored form is the correct one: it needs a digit immediately
    followed by ``g``, which the Graviton families all have and the AMD (``6a``,
    ``7a``), Intel and GPU (``g4dn``, ``g5``, ``p5en``) families all lack.
    """
    if not instance_type:
        return None
    family = instance_type.split(".")[0]
    return "arm64" if re.search(r"\dg", family) else "x86_64"


def unsupported_reason(platform: str, instance_type: str) -> Optional[str]:
    """Why ``instance_type`` cannot run ``platform``, or ``None`` if it can.

    Separate from :func:`lookup` so a refusal can *explain itself*.  ``lookup``
    returning ``None`` is all ``resolve_shape`` needs to reject a shape, but
    "m6a.24xlarge is not a supported instance type" tells an operator nothing
    about why a bigger instance of the family they were already using stopped
    being valid.  Both callers use this: :func:`resolve_shape` appends it to the
    ``ValueError`` it raises, and the deploy preflight checks it against the
    *effective* type, which may come from ``TF_VAR_instance_type`` and therefore
    never reaches ``resolve_shape`` at all.

    Only covers shapes the hardware or the platform genuinely cannot run.  A
    merely un-enumerated size is not an error, which is why ``lookup`` still
    resolves arbitrary sizes.
    """
    s = (instance_type or "").strip()
    if not s or "." not in s:
        return None
    family, _, token = s.partition(".")
    family = family.lower()

    if platform in ("nitro-aws", "snp-aws"):
        # Bare metal has no Nitro hypervisor to carve an enclave out of, and no
        # SEV-SNP: DescribeInstanceTypes reports NitroEnclavesSupport
        # "unsupported" for every *.metal / *.metal-NNxl type in both the AMD
        # and Graviton families.
        if token == "metal" or token.startswith("metal-"):
            return (f"{s} is a bare-metal instance. AWS reports no Nitro "
                    f"Enclaves or SEV-SNP support on bare metal, because there "
                    f"is no Nitro hypervisor beneath it to host the TEE.")

    if platform == "snp-aws":
        if family not in _AWS_SNP_CAPABLE_FAMILIES:
            gen = "Genoa" if family.endswith("7a") else None
            extra = (" AWS reports no amd-sev-snp processor feature on any 7a "
                     "(Genoa) type in us-east-1, us-east-2 or us-west-2."
                     if gen else "")
            return (f"{s} cannot run AMD SEV-SNP.{extra} Supported families: "
                    f"{', '.join(sorted(_AWS_SNP_CAPABLE_FAMILIES))}.")
        spec = _aws_amd_spec(s)
        if spec and spec.ram_mb > _AWS_SNP_MAX_RAM_MB:
            return (f"{s} has {spec.ram_mb // GIB} GiB of memory. AWS exposes "
                    f"SEV-SNP only up to {_AWS_SNP_MAX_RAM_MB // GIB} GiB of "
                    f"guest memory, so the largest SNP shapes are "
                    f"c6a.16xlarge, m6a.8xlarge and r6a.4xlarge — all "
                    f"{_AWS_SNP_MAX_RAM_MB // GIB} GiB.")

    if platform == "nitro-aws":
        vcpu = _AWS_SIZE_VCPU.get(token)
        if vcpu is not None and vcpu < _NITRO_MIN_VCPU:
            arm = instance_architecture(s) == "arm64"
            why = (
                "TEE-Crafter reserves 2 vCPU for the parent instance (vsock "
                "proxy, nitro-cli, SSM), so a 2-vCPU host leaves the enclave "
                "nothing. AWS itself does report enclave support on 2-vCPU "
                "Graviton"
                if arm else
                "AWS reports NitroEnclavesSupport 'unsupported' on 2-vCPU "
                "x86 instances, and TEE-Crafter additionally reserves 2 vCPU "
                "for the parent instance"
            )
            return (f"{s} has {vcpu} vCPU, below the {_NITRO_MIN_VCPU} vCPU "
                    f"minimum. {why}.")
    return None


def _aws_amd_spec(s: str) -> Optional[InstanceSpec]:
    """Parse an AMD ``[mcr][67]a.<size>`` type without any capability gating."""
    m = re.match(r"^([mcr])([67])a\.(\w+)$", s)
    if not m:
        return None
    letter, gen_digit, token = m.group(1), m.group(2), m.group(3)
    vcpu = _AWS_SIZE_VCPU.get(token)
    if vcpu is None:
        return None
    gen = "milan" if gen_digit == "6" else "genoa"
    return InstanceSpec(s, vcpu, vcpu * _AWS_RAM_PER_VCPU[letter], gen)


def lookup(platform: str, instance_type: str) -> Optional[InstanceSpec]:
    """Resolve ``instance_type`` to its specs, or ``None`` if not in-family.

    Also returns ``None`` for a shape the platform cannot physically run (see
    :func:`unsupported_reason`), so nothing downstream has to re-check.
    """
    s = (instance_type or "").strip()
    if not s:
        return None
    if unsupported_reason(platform, s):
        return None

    # GPU + SGX platforms: exact catalog match.
    if platform in _GPU_CATALOG:
        for spec in _GPU_CATALOG[platform]:
            if spec.instance_type == s:
                return spec
        return None
    if platform == "sgx-azure":
        for spec in _SGX_AZURE:
            if spec.instance_type == s:
                return spec
        # There used to be a ``Standard_DC(\d+)s_v3`` catch-all here, from when
        # this catalog listed only four tiers.  It was wrong in both directions:
        # ``Standard_DC3s_v3`` resolved even though Azure sells no 3-vCPU tier
        # (Terraform then got a size Azure rejects, so the operator saw an
        # opaque ARM error instead of this CLI's own message), while the real
        # ``Standard_DC24ds_v3`` returned None because the pattern never
        # covered the ``ds`` variants.  ``_SGX_AZURE`` now carries all 16 SKUs
        # ``az vm list-skus`` publishes, so an exact match is the whole answer.
        return None

    if platform in ("snp-aws", "nitro-aws"):
        amd = _aws_amd_spec(s)
        if amd is not None:
            return amd
        if re.match(r"^([mcr])([67])a\.", s):
            return None  # in-family but an unknown size token
        # Graviton (arm64) hosts are valid for Nitro only.  AMD SEV-SNP is an
        # AMD CPU feature, so an arm64 type is not merely unlisted for
        # ``snp-aws`` — it cannot work, and resolving it would hand Terraform an
        # instance type the platform can never launch.
        if platform != "nitro-aws":
            return None
        m = re.match(r"^([mcr])([6789])g\.(\w+)$", s)
        if not m:
            return None
        letter, gen_digit, token = m.group(1), m.group(2), m.group(3)
        sizes = _AWS_NITRO_GRAVITON_SIZES.get(gen_digit)
        if sizes is None:
            return None
        # The size token must exist *for this generation*, not merely somewhere
        # in ``_AWS_SIZE_VCPU``.  Checking only the global table accepted types
        # AWS does not sell — ``m8g.32xlarge`` (no generation has a 32xlarge)
        # and ``c6g.24xlarge`` (6g and 7g stop at 16xlarge) both resolved — and
        # handed Terraform an instance type EC2 refuses, so the operator got an
        # opaque ``InvalidParameterValue`` from AWS instead of this CLI's own
        # refusal.  That defeats the point of resolving shapes up front.
        if token not in sizes:
            return None
        vcpu = _AWS_SIZE_VCPU.get(token)
        if vcpu is None:
            return None
        return InstanceSpec(s, vcpu, vcpu * _AWS_RAM_PER_VCPU[letter],
                            _GRAVITON_CPU_GEN)

    if platform in ("snp-azure", "tdx-azure"):
        # The optional ``d`` is Azure's local-temp-disk marker: DC2es_v6 and
        # DC2eds_v6 are both real, distinct SKUs.
        m = re.match(r"^Standard_([DE])C(\d+)(a|e)(d?)s_(v[56])$", s)
        if not m:
            return None
        de, vcpu_s, ae, disk, ver = (m.group(1), m.group(2), m.group(3),
                                     m.group(4), m.group(5))
        # SNP uses the AMD ``as``/``ads`` families; TDX the Intel ``es``/``eds``.
        if platform == "snp-azure":
            families, expect_ae = _AZURE_SNP_FAMILIES, "a"
        else:
            families, expect_ae = _AZURE_TDX_FAMILIES, "e"
        if ae != expect_ae:
            return None
        meta = families.get((de + "C", ae + disk + "s", ver))
        if not meta:
            return None
        gen, ram_per, tiers, ram_overrides = meta
        v = int(vcpu_s)
        # Per-family tier gate: the vCPU counts differ by family (DCes_v6 goes
        # to 128, ECes_v6 stops at 64), so a size that merely *parses* is not
        # necessarily one Azure sells.
        if v not in tiers:
            return None
        return InstanceSpec(s, v, ram_overrides.get(v, v * ram_per), gen)

    if platform == "snp-gcp":
        m = re.match(r"^n2d-(standard|highmem|highcpu)-(\d+)$", s)
        if not m:
            return None
        ram_per = _GCP_N2D[m.group(1)]
        v = int(m.group(2))
        return InstanceSpec(s, v, v * ram_per, "milan")
    if platform == "tdx-gcp":
        m = re.match(r"^c3-(standard|highmem|highcpu)-(\d+)$", s)
        if not m:
            return None
        ram_per = _GCP_C3[m.group(1)]
        v = int(m.group(2))
        return InstanceSpec(s, v, v * ram_per, "sapphire-rapids")

    return None


# --------------------------------------------------------------------------
# Enumeration (for the UI / `list-instances`)
# --------------------------------------------------------------------------

def enumerate_instances(platform: str) -> List[InstanceSpec]:
    """Return the curated, ordered list of supported shapes for ``platform``."""
    out: List[InstanceSpec] = []
    if platform in _GPU_CATALOG:
        return list(_GPU_CATALOG[platform])
    if platform == "sgx-azure":
        return list(_SGX_AZURE)
    if platform == "nitro-aws":
        return list(_NITRO_AWS)

    if platform == "snp-aws":
        for _gen, families in _AWS_SNP_FAMILIES.items():
            for fam in families:
                for _v, tok in sorted(_AWS_VCPU_SIZE.items()):
                    spec = lookup(platform, f"{fam}.{tok}")
                    if spec:
                        out.append(spec)
    elif platform in ("snp-azure", "tdx-azure"):
        families = _AZURE_SNP_FAMILIES if platform == "snp-azure" else _AZURE_TDX_FAMILIES
        for (de, ae, ver), (_gen, _ram, tiers, _ovr) in families.items():
            for v in tiers:
                spec = lookup(platform, f"Standard_{de}{v}{ae}_{ver}")
                if spec:
                    out.append(spec)
    elif platform == "snp-gcp":
        for sub in _GCP_N2D:
            for v in _GCP_N2D_VCPU:
                spec = lookup(platform, f"n2d-{sub}-{v}")
                if spec:
                    out.append(spec)
    elif platform == "tdx-gcp":
        for sub in _GCP_C3:
            for v in _GCP_C3_VCPU:
                spec = lookup(platform, f"c3-{sub}-{v}")
                if spec:
                    out.append(spec)
    return out


def default_instance_type(platform: str) -> Optional[str]:
    """Default instance type the CLI deploys when none is given."""
    return DEFAULT_INSTANCE_TYPE.get(platform)


def default_spec(platform: str) -> Optional[InstanceSpec]:
    dit = DEFAULT_INSTANCE_TYPE.get(platform)
    return lookup(platform, dit) if dit else None


def instance_vcpu(platform: str, instance_type: str) -> Optional[int]:
    spec = lookup(platform, instance_type)
    return spec.vcpu if spec else None


def instance_gen(platform: str, instance_type: str) -> Optional[str]:
    spec = lookup(platform, instance_type)
    return spec.cpu_gen if spec else None


def is_in_family(platform: str, instance_type: str) -> bool:
    return lookup(platform, instance_type) is not None
