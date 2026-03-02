import os
from typing import Dict, Tuple

# We keep these imports to preserve the interface expected by main.py
from nitro_agent.core.iac import stage_terraform, verify_terraform_syntax

# Defined Graviton instance types with their specs (vCPU, RAM in GiB)
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

def _load_terraform_template() -> str:
    """Loads the Terraform HCL template from disk."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level to nitro_agent, then into templates
    template_path = os.path.join(current_dir, "..", "templates", "main.template.tf")
    
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def select_instance_type(req_cpu: int, req_ram_mb: int) -> str:
    """
    Selects the smallest Graviton instance that fits the requirements.
    We need:
      - Host vCPU > Enclave vCPU + 2 (overhead)
      - Host RAM > Enclave RAM + 2GB (overhead for OS)
    """
    # Safety margins
    min_host_cpu = req_cpu + 2
    min_host_ram_gib = (req_ram_mb / 1024) + 2

    for inst in GRAVITON_INSTANCES:
        if inst["vcpu"] >= min_host_cpu and inst["ram_gib"] >= min_host_ram_gib:
            return inst["type"]
    
    # Fallback if nothing fits (unlikely for reasonable requests)
    return "m6g.4xlarge"


def generate_terraform_code(
    cpu: int,
    ram: int,
    pcr_hashes: Dict[str, str],
    max_retries: int = 1, # Unused but kept for signature compatibility
    prompt_iac: str = "", # Unused but kept for signature compatibility
    debug_build_dir: str | None = None,
) -> str:
    """
    Generates a complete AWS Terraform configuration (main.tf) using a deterministic template.
    Replaces the previous LLM-based generation.
    """
    
    instance_type = select_instance_type(cpu, ram)
    
    # Load template
    template_code = _load_terraform_template()
    
    # Simple string replacement
    # Note: We use manual replacement instead of .format() to avoid conflicts with HCL braces
    code = template_code
    code = code.replace("__INSTANCE_TYPE__", instance_type)
    code = code.replace("__CPU_COUNT__", str(cpu))

    # Treat "ram" parameter as the enclave memory (MiB) requested via nitro-cli.
    enclave_memory_mb = max(ram, 512)
    code = code.replace("__RAM_MB__", str(enclave_memory_mb))

    # Configure allocator.yaml following AWS guidance:
    # - allocator memory_mib must be >= enclave --memory
    # - leave headroom for the host OS
    # - add a small safety buffer above enclave memory
    host = next((i for i in GRAVITON_INSTANCES if i["type"] == instance_type), None)
    if host is not None:
        host_ram_mb = host["ram_gib"] * 1024
        # Reserve enclave_memory + 1 GiB, but keep at least 1 GiB for the host.
        allocator_mb = min(host_ram_mb - 1024, enclave_memory_mb + 1024)
        allocator_mb = max(allocator_mb, enclave_memory_mb)
    else:
        # Fallback if we somehow don't know the host specs.
        allocator_mb = enclave_memory_mb + 1024

    code = code.replace("__ALLOCATOR_MB__", str(int(allocator_mb)))

    return code


def generate_terraform_fix_for_apply_error(
    current_main_tf: str,
    apply_stderr: str,
    apply_stdout: str,
    cpu: int,
    ram: int,
    prompt_iac: str,
    pcr_hashes: Dict[str, str],
    debug_build_dir: str | None = None,
) -> str:
    """
    Legacy function signature for compatibility.
    Since we are using static templates, we don't support LLM-based fixing.
    """
    raise NotImplementedError("Auto-fixing Terraform via LLM is disabled in deterministic mode.")

# Helper to maintain compatibility if extract_terraform_code is imported elsewhere
def extract_terraform_code(llm_output: str) -> str:
    return llm_output
