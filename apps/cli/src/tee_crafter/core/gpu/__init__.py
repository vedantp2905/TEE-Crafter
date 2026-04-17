"""NVIDIA Confidential GPU compute: instance constraint map and preflight validation."""
from __future__ import annotations

from typing import Optional

GPU_CC_INSTANCES: dict[str, dict[str, dict[int, str]]] = {
    "gpu-cc-gcp": {
        "h100": {
            1: "a3-highgpu-1g",
            2: "a3-highgpu-2g",
            4: "a3-highgpu-4g",
            8: "a3-highgpu-8g",
        },
    },
    "gpu-cc-azure": {
        "h100": {
            1: "Standard_NCC40ads_H100_v5",
        },
    },
    "gpu-cc-aws": {
        "h100": {1: "p5.4xlarge", 8: "p5.48xlarge"},
        "h200": {8: "p5en.48xlarge"},
        "b200": {8: "p6-b200.48xlarge"},
    },
}

GPU_CC_DEFAULTS: dict[str, tuple[str, int]] = {
    "gpu-cc-gcp": ("h100", 1),
    "gpu-cc-azure": ("h100", 1),
    "gpu-cc-aws": ("h100", 1),
}

GPU_CC_PLATFORMS = frozenset(GPU_CC_INSTANCES.keys())

# NCC H100 v5 confidential GPU SKUs are not available in West US; product default matches bake-ami.
GPU_CC_AZURE_LOCATION = "eastus2"

_CLOUD_LABEL = {
    "gpu-cc-gcp": "GCP",
    "gpu-cc-azure": "Azure",
    "gpu-cc-aws": "AWS",
}


class GpuPreflightError(Exception):
    """Raised when the GPU model/count combination is invalid for the platform."""


def resolve_gpu_instance(
    platform: str,
    gpu_model: Optional[str] = None,
    gpu_count: Optional[int] = None,
    instance_type_override: Optional[str] = None,
) -> str:
    """Resolve (platform, gpu_model, gpu_count) to a concrete instance type.

    If *instance_type_override* is provided, it is returned directly
    (user explicitly chose an instance).

    Raises ``GpuPreflightError`` with a helpful message on invalid combos.
    """
    if instance_type_override:
        return instance_type_override

    if platform not in GPU_CC_INSTANCES:
        raise GpuPreflightError(
            f"Unknown GPU CC platform: {platform}. "
            f"Valid: {', '.join(sorted(GPU_CC_INSTANCES))}"
        )

    default_model, default_count = GPU_CC_DEFAULTS[platform]
    model = (gpu_model or default_model).lower()
    count = gpu_count if gpu_count is not None else default_count

    cloud = _CLOUD_LABEL.get(platform, platform)
    models_for_platform = GPU_CC_INSTANCES[platform]

    if model not in models_for_platform:
        supported = ", ".join(sorted(models_for_platform))
        raise GpuPreflightError(
            f"{model.upper()} is not available for confidential GPU on {cloud}. "
            f"Supported models: {supported}"
        )

    counts_for_model = models_for_platform[model]
    if count not in counts_for_model:
        valid_counts = ", ".join(str(c) for c in sorted(counts_for_model))
        alt_clouds = [
            c for c, m in GPU_CC_INSTANCES.items()
            if c != platform and model in m
        ]
        hint = ""
        if alt_clouds:
            hint = f" Consider {', '.join(alt_clouds)} for {count}x {model.upper()}."
        raise GpuPreflightError(
            f"{count}x {model.upper()} not available on {cloud}. "
            f"Supported GPU counts for {model.upper()}: {valid_counts}.{hint}"
        )

    return counts_for_model[count]


def is_gpu_cc_platform(platform: str) -> bool:
    """Return True if the platform string is a GPU CC platform."""
    return platform in GPU_CC_PLATFORMS
