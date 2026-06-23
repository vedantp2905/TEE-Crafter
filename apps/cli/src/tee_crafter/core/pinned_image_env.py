"""Pinned image / AMI resolution from environment variables.

Public CLI still accepts ``--ami-id`` (and ``TEE_CRAFTER_AMI_ID``).  When
those are unset, we fall back to per-platform variables so operators can
keep a single ``.env`` with every baked image they care about.

This module lives under ``tee_crafter.core`` so the local GUI can import
it **without** loading ``tee_crafter.cli.commands`` (whose ``__init__``
eager-imports the full CLI tree, including remote SSH helpers that may
reconfigure process-wide logging when debug env vars are set).

Naming convention (2026): one variable per platform family — see
``.env.example`` section "Pinned images".
"""
from __future__ import annotations

import os
from typing import Final

# tee_platform -> env var holding the baked image id for that platform.
#
# ``nitro-aws`` is deliberately absent: it is the one platform that spans two
# CPU architectures, and a single variable cannot hold two AMIs.  Its pins live
# in :data:`PLATFORM_PINNED_IMAGE_ENV_BY_ARCH` instead.  There is no
# architecture-agnostic ``AWS_NITRO_AMI`` fallback, because "the AMI for Nitro"
# is not a well-defined thing — an arm64 instance cannot boot an x86_64 image,
# so a generic value is right at most half the time and produces an
# architecture-mismatch failure the rest of the time.
PLATFORM_PINNED_IMAGE_ENV: Final[dict[str, str]] = {
    "snp-aws": "AWS_SNP_AMI",
    "gpu-cc-aws": "AWS_GPU_CC_AMI",
    "sgx-azure": "AZURE_SGX_IMAGE",
    "tdx-azure": "AZURE_TDX_IMAGE",
    "snp-azure": "AZURE_SNP_IMAGE",
    "gpu-cc-azure": "AZURE_GPU_CC_IMAGE",
    "tdx-gcp": "GCP_TDX_IMAGE",
    "snp-gcp": "GCP_SNP_IMAGE",
    "gpu-cc-gcp": "GCP_GPU_CC_IMAGE",
}

#: Platforms where **one** pinned image cannot cover the platform, because the
#: chosen instance type decides the CPU architecture and an AMI serves exactly
#: one architecture.
#:
#: ``nitro-aws`` runs on x86_64 (``c6a`` and friends) *and* on Graviton
#: (``c/m/r`` ``6g``–``9g``), and the two need separately baked AMIs: an arm64
#: instance cannot boot an x86_64 image.  They also differ in posture — UEFI
#: Secure Boot enrolment is x86_64-only, because AL2023's
#: ``amazon-linux-sb-keys`` package ships pre-signed PK/KEK/db for x86_64 — so
#: these are genuinely two images with two different security properties, not
#: two builds of one thing.
#:
#: ``snp-aws`` is not here: SEV-SNP is an AMD CPU feature, so it is x86_64 by
#: construction and one pin is the whole platform.
PLATFORM_PINNED_IMAGE_ENV_BY_ARCH: Final[dict[str, dict[str, str]]] = {
    "nitro-aws": {
        "x86_64": "AWS_NITRO_AMI_X86_64",
        "arm64": "AWS_NITRO_AMI_ARM64",
    },
}

LEGACY_GLOBAL = "TEE_CRAFTER_AMI_ID"

ALL_PINNED_IMAGE_ENV_KEYS: Final[frozenset[str]] = frozenset(
    {
        LEGACY_GLOBAL,
        *PLATFORM_PINNED_IMAGE_ENV.values(),
        *(name
          for per_arch in PLATFORM_PINNED_IMAGE_ENV_BY_ARCH.values()
          for name in per_arch.values()),
    },
)


def arch_pinned_image_env_key(
    tee_platform: str, instance_type: str | None
) -> str | None:
    """The architecture-specific pin variable for this platform+instance type.

    ``None`` when the platform has a single architecture, or when the instance
    type is unknown so the architecture cannot be decided.
    """
    per_arch = PLATFORM_PINNED_IMAGE_ENV_BY_ARCH.get(tee_platform)
    if not per_arch:
        return None
    from tee_crafter.core.catalog import instance_architecture

    arch = instance_architecture(instance_type)
    return per_arch.get(arch) if arch else None


def effective_pinned_image_from_env(
    tee_platform: str,
    *,
    cli_or_explicit: str | None = None,
    instance_type: str | None = None,
) -> str | None:
    """Resolve pinned image id from flags + environment.

    Precedence (highest first):

    1. Non-empty *cli_or_explicit* (``--ami-id`` from Click or GUI body).
    2. ``TEE_CRAFTER_AMI_ID`` (legacy global pin).
    3. The **architecture-specific** variable, for a platform that spans two
       architectures — ``AWS_NITRO_AMI_ARM64`` / ``AWS_NITRO_AMI_X86_64``.
    4. The platform-wide variable (``AWS_SNP_AMI``, ``AZURE_TDX_IMAGE``, …).

    Steps 3 and 4 are mutually exclusive per platform: ``nitro-aws`` has only
    the architecture-specific pair, and every other platform has only the
    platform-wide variable.  There is no generic ``AWS_NITRO_AMI`` to fall back
    to, on purpose — an arm64 instance cannot boot an x86_64 AMI, so a single
    "Nitro AMI" would silently be the wrong image whenever the operator chose
    the other architecture.  Returning ``None`` here instead makes the deploy
    say which variable is missing.
    """
    if cli_or_explicit and (s := cli_or_explicit.strip()):
        return s
    legacy = _env_image(LEGACY_GLOBAL)
    if legacy:
        return legacy
    arch_key = arch_pinned_image_env_key(tee_platform, instance_type)
    if arch_key:
        v = _env_image(arch_key)
        if v:
            return v
    key = PLATFORM_PINNED_IMAGE_ENV.get(tee_platform)
    if not key:
        return None
    return _env_image(key) or None


def _env_image(key: str) -> str:
    """Read *key* as an image id, dropping a trailing ``# ...`` comment.

    The documented way to run this CLI is ``docker run --env-file .env``, and
    Docker's ``--env-file`` parser does **not** treat ``#`` as a comment once a
    value has started — it takes the rest of the line verbatim.  A shell that
    sources the same file does strip it.  So::

        AWS_SNP_AMI=ami-0dc3a149b36b33fff   # snp-aws-20260822, Milan x86_64

    is an AMI id on the host and an AMI id *plus a comment* inside the
    container, which is how a deploy came to fail with
    ``InvalidAMIID.Malformed: Invalid id: "ami-0dc3a149b36b33fff   # snp-aws-..."``.
    Annotating a pinned image with what it is and when it was baked is the
    natural thing to do, so this accepts it rather than punishing it.

    Safe because these values are AMI ids, Azure gallery resource IDs and GCP
    image URIs, none of which can contain ``#``.  Scoped to image variables
    only, deliberately — this is not a general-purpose env sanitiser.
    """
    raw = os.environ.get(key, "")
    return raw.split("#", 1)[0].strip()
