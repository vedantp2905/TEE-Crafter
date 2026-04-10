"""Deterministic Nitro Terraform generation — no model is involved.

Terraform for ``nitro-aws`` is produced by literal ``__TOKEN__`` substitution
into the reviewed HCL at ``templates/nitro/main.template.tf``.  Given the same
(cpu, ram, instance_type) the output is byte-for-byte identical, which is what
lets the build provenance pin a Terraform hash at all.

This module lived under ``tee_crafter/llm/`` until it was moved here.  The
package name was the only thing about it that was ever LLM-flavoured: the
imports below are ``os``/``re``/``typing`` and nothing else, and no generated
or model-authored text has ever reached a ``.tf`` file.  Keeping it under
``llm/`` made the project's central design claim ("no LLM touches
infrastructure code") look false to anyone reading the source tree.

Companion modules in this package: :mod:`tee_crafter.core.iac.iac` (Terraform
staging / apply / destroy) and :mod:`tee_crafter.core.iac.platforms`
(per-platform staging).  This module is deliberately *not* re-exported from
``tee_crafter.core.iac.__init__``: import it by its full path so the
substitution engine stays easy to locate.
"""

import os
from typing import Dict

# Nitro Enclaves host options.
#
# Default tier is **x86_64 (AMD Milan: c6a / m6a / r6a)** since 2026: Secure
# Boot enrollment on the bake instance is only validated for x86_64 (the
# AL2023 ``amazon-linux-sb-keys`` package only ships pre-signed PK/KEK/db
# blobs for x86_64).  Graviton (``c6g`` / ``m6g`` / ``r6g``) is still
# selectable when the caller explicitly wants arm64 — it just bakes without
# Secure Boot until the arm64 keys are end-to-end validated.
NITRO_X86_INSTANCES = [
    # Compute Optimized (c6a) — preferred for typical enclaves (CPU > RAM)
    {"type": "c6a.xlarge", "vcpu": 4, "ram_gib": 8},
    {"type": "c6a.2xlarge", "vcpu": 8, "ram_gib": 16},
    {"type": "c6a.4xlarge", "vcpu": 16, "ram_gib": 32},
    {"type": "c6a.8xlarge", "vcpu": 32, "ram_gib": 64},
    # General Purpose (m6a)
    {"type": "m6a.xlarge", "vcpu": 4, "ram_gib": 16},
    {"type": "m6a.2xlarge", "vcpu": 8, "ram_gib": 32},
    {"type": "m6a.4xlarge", "vcpu": 16, "ram_gib": 64},
    {"type": "m6a.8xlarge", "vcpu": 32, "ram_gib": 128},
    # Memory Optimized (r6a)
    {"type": "r6a.xlarge", "vcpu": 4, "ram_gib": 32},
    {"type": "r6a.2xlarge", "vcpu": 8, "ram_gib": 64},
    {"type": "r6a.4xlarge", "vcpu": 16, "ram_gib": 128},
]

# Defined Graviton instance types — retained for callers that explicitly opt
# into arm64 via ``select_instance_type(arch="arm64", ...)``.  No longer the
# default tier.
GRAVITON_INSTANCES = [
    # General Purpose (m6g)
    {"type": "m6g.xlarge", "vcpu": 4, "ram_gib": 16},
    {"type": "m6g.2xlarge", "vcpu": 8, "ram_gib": 32},
    {"type": "m6g.4xlarge", "vcpu": 16, "ram_gib": 64},
    {"type": "m6g.8xlarge", "vcpu": 32, "ram_gib": 128},
    # Compute Optimized (c6g)
    {"type": "c6g.xlarge", "vcpu": 4, "ram_gib": 8},
    {"type": "c6g.2xlarge", "vcpu": 8, "ram_gib": 16},
    {"type": "c6g.4xlarge", "vcpu": 16, "ram_gib": 32},
    {"type": "c6g.8xlarge", "vcpu": 32, "ram_gib": 64},
    # Memory Optimized (r6g)
    {"type": "r6g.xlarge", "vcpu": 4, "ram_gib": 32},
    {"type": "r6g.2xlarge", "vcpu": 8, "ram_gib": 64},
]

# Backward-compat alias: anywhere we used to iterate ``GRAVITON_INSTANCES`` as
# "the menu of host options" we now iterate ``NITRO_INSTANCES`` (x86_64 first).
NITRO_INSTANCES = NITRO_X86_INSTANCES

def _load_terraform_template() -> str:
    """Loads the Terraform HCL template from disk."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # tee_crafter/core/iac/ -> up two levels to tee_crafter/, then into templates/
    template_path = os.path.join(
        current_dir, "..", "..", "templates", "nitro", "main.template.tf")

    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def select_instance_type(req_cpu: int, req_ram_mb: int, *, arch: str = "x86_64") -> str:
    """Pick the smallest Nitro host that fits the enclave requirements.

    Host sizing constraints:

    * Host vCPU >= Enclave vCPU + 2 (overhead).
    * Host RAM >= Enclave RAM + 2 GiB (host OS overhead).

    ``arch`` selects which menu of host options to choose from:

    * ``"x86_64"`` (default since 2026) iterates :data:`NITRO_X86_INSTANCES`
      (AMD Milan: ``c6a`` first, then ``m6a`` / ``r6a``).  Required for
      Secure-Boot-enrolled bakes — ``amazon-linux-sb-keys`` on AL2023 only
      ships pre-signed PK/KEK/db blobs for x86_64.
    * ``"arm64"`` iterates :data:`GRAVITON_INSTANCES` for callers that
      explicitly opted out of Secure Boot to use Graviton.
    """
    min_host_cpu = req_cpu + 2
    min_host_ram_gib = (req_ram_mb / 1024) + 2

    if (arch or "").lower() == "arm64":
        menu = GRAVITON_INSTANCES
        fallback = "m6g.4xlarge"
    else:
        menu = NITRO_X86_INSTANCES
        fallback = "m6a.4xlarge"

    for inst in menu:
        if inst["vcpu"] >= min_host_cpu and inst["ram_gib"] >= min_host_ram_gib:
            return inst["type"]

    return fallback


def generate_terraform_code(
    cpu: int,
    ram: int,
    pcr_hashes: Dict[str, str],
    debug_build_dir: str | None = None,
    instance_type: str | None = None,
) -> str:
    """Generates a complete AWS Terraform configuration (main.tf) using a deterministic template."""
    
    if not instance_type:
        instance_type = select_instance_type(cpu, ram)
    
    # Load template
    template_code = _load_terraform_template()
    
    # Simple string replacement
    # Note: We use manual replacement instead of .format() to avoid conflicts with HCL braces
    code = template_code
    code = code.replace("__INSTANCE_TYPE__", instance_type)
    code = code.replace("__CPU_COUNT__", str(cpu))

    from tee_crafter.core.catalog import instance_architecture
    ami_arch = instance_architecture(instance_type) or "x86_64"
    code = code.replace("__AMI_ARCH__", ami_arch)

    # Treat "ram" parameter as the enclave memory (MiB) requested via nitro-cli.
    enclave_memory_mb = max(ram, 512)
    code = code.replace("__RAM_MB__", str(enclave_memory_mb))

    # Configure allocator.yaml following AWS guidance:
    # - allocator memory_mib must be >= enclave --memory
    # - leave headroom for the host OS
    # - add a small safety buffer above enclave memory
    host = next(
        (i for i in (*NITRO_X86_INSTANCES, *GRAVITON_INSTANCES)
         if i["type"] == instance_type),
        None,
    )
    if host is not None:
        host_ram_mb = host["ram_gib"] * 1024
        # Reserve enclave_memory + 1 GiB, but keep at least 1 GiB for the host.
        allocator_mb = min(host_ram_mb - 1024, enclave_memory_mb + 1024)
        allocator_mb = max(allocator_mb, enclave_memory_mb)
    else:
        # Fallback if we somehow don't know the host specs.
        allocator_mb = enclave_memory_mb + 1024

    code = code.replace("__ALLOCATOR_MB__", str(int(allocator_mb)))

    # Default __BATCH_MODE__ to false; the batch orchestrator overrides it
    # to "true" before staging when --batch is in effect.
    if "__BATCH_MODE__" in code:
        code = code.replace("__BATCH_MODE__", "false")

    return code
