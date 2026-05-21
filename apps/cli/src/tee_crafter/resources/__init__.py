"""Canonical systemd unit loader — single source of truth for all TEE platforms.

Both bake-time shell scripts and deploy-time Python code read from the same
``.service`` files stored in ``resources/systemd/``.
"""

import os

_SYSTEMD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "systemd")

_CONTAINER_CFG: dict[str, tuple[str, str, str, str]] = {
    # platform -> (description, after_service, tar_path, extra_run_flags)
    #
    # extra_run_flags is spliced into the `docker run` line just before the
    # image name.  It is not GPU-specific (it was named gpu_flags, which is
    # why the SGX row sat empty): the batch unit runs with --cap-drop ALL and
    # no devices, so a graminized SGX container needs /dev/sgx_enclave and
    # /dev/sgx_provision passed in explicitly, plus the aesmd socket for DCAP
    # quote generation.  Without them the enclave cannot start at all.
    "gpu-cc-azure": (
        "TEE-Crafter User Container (GPU-CC-Azure)",
        "tee-crafter-gpu-cc.service nvidia-cdi-generate.service nvidia-persistenced.service",
        "/opt/tee-crafter-gpu-cc/user_container.tar",
        "--runtime=nvidia --gpus all \\\n  ",
    ),
    "gpu-cc-gcp": (
        "TEE-Crafter User Container (GPU-CC-GCP)",
        "tee-crafter-gpu-cc.service nvidia-cdi-generate.service nvidia-persistenced.service",
        "/opt/tee-crafter-gpu-cc/user_container.tar",
        "--runtime=nvidia --gpus all \\\n  ",
    ),
    "gpu-cc-aws": (
        "TEE-Crafter User Container (GPU-CC-AWS)",
        "tee-crafter-gpu-cc.service nvidia-cdi-generate.service nvidia-persistenced.service",
        "/opt/tee-crafter-gpu-cc/user_container.tar",
        "--runtime=nvidia --gpus all \\\n  ",
    ),
    "snp-azure": (
        "TEE-Crafter User Container (SNP-Azure)",
        "tee-crafter-snp.service",
        "/opt/tee-crafter-snp/user_container.tar",
        "",
    ),
    "snp-aws": (
        "TEE-Crafter User Container (SNP-AWS)",
        "tee-crafter-snp.service",
        "/opt/tee-crafter-snp/user_container.tar",
        "",
    ),
    "snp-gcp": (
        "TEE-Crafter User Container (SNP-GCP)",
        "tee-crafter-snp.service",
        "/opt/tee-crafter-snp/user_container.tar",
        "",
    ),
    "tdx-azure": (
        "TEE-Crafter User Container (TDX)",
        "tee-crafter-tdx.service",
        "/opt/tee-crafter-tdx/user_container.tar",
        "",
    ),
    "tdx-gcp": (
        "TEE-Crafter User Container (TDX-GCP)",
        "tee-crafter-tdx.service",
        "/opt/tee-crafter-tdx/user_container.tar",
        "",
    ),
    "sgx-azure": (
        "TEE-Crafter User Container (SGX-Azure)",
        "sgx-enclave.service",
        "/home/azureuser/sgx-app/user_container.tar",
        "--device /dev/sgx_enclave --device /dev/sgx_provision \\\n  "
        "-v /var/run/aesmd:/var/run/aesmd \\\n  ",
    ),
}

#: Platforms that can run an arbitrary user container image, i.e. every
#: platform :data:`_CONTAINER_CFG` has a unit for.  ``nitro-aws`` is
#: deliberately absent: a Nitro Enclave boots a signed EIF built from a
#: fixed image, so it cannot execute an operator-supplied OCI image.
#: :mod:`tee_crafter.cli.preflight` reads this to reject
#: ``--batch --tee-platform nitro-aws`` *before* Terraform apply — the
#: alternative (letting ``load_container_batch_unit`` raise after the
#: instance is billing) leaked infrastructure on every run.
CONTAINER_PLATFORMS: frozenset[str] = frozenset(_CONTAINER_CFG)


def load_unit(platform: str, **fmt_kwargs: str) -> str:
    """Load a canonical ``.service`` file for *platform*.

    Optional ``fmt_kwargs`` are applied with :meth:`str.format` so that
    templates like ``sgx-azure.service`` (which contains ``{remote_base}``)
    get their placeholders filled.
    """
    path = os.path.join(_SYSTEMD_DIR, f"{platform}.service")
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    if fmt_kwargs:
        content = content.format(**fmt_kwargs)
    return content


#: platform -> install root for the staged app bundle + venv.
_REMOTE_BASE: dict[str, str] = {
    "gpu-cc-azure": "/opt/tee-crafter-gpu-cc",
    "gpu-cc-gcp": "/opt/tee-crafter-gpu-cc",
    "gpu-cc-aws": "/opt/tee-crafter-gpu-cc",
    "snp-azure": "/opt/tee-crafter-snp",
    "snp-aws": "/opt/tee-crafter-snp",
    "snp-gcp": "/opt/tee-crafter-snp",
    "tdx-azure": "/opt/tee-crafter-tdx",
    "tdx-gcp": "/opt/tee-crafter-tdx",
}


def _secrets_dep_block(platform: str) -> str:
    """``Requires=``/``After=`` lines binding the container unit to the secrets
    oneshot — only for CVM platforms that ship one (empty for SGX)."""
    if platform in _REMOTE_BASE:
        return ("Requires=tee-crafter-secrets.service\n"
                "After=tee-crafter-secrets.service\n")
    return ""


def load_secrets_unit(platform: str) -> str:
    """Render the ``tee-crafter-secrets`` oneshot for *platform* (CVM only).

    The CVM container unit ``Requires=`` + ``After=`` this oneshot so a
    fail-closed secret bootstrap (sealed-.env unseal / BYOK release) keeps the
    workload stopped.  Nitro/SGX deliver secrets in their own entrypoint and
    have no secrets oneshot.
    """
    remote_base = _REMOTE_BASE.get(platform)
    if remote_base is None:
        raise ValueError(f"No secrets unit config for platform: {platform}")
    tpl_path = os.path.join(_SYSTEMD_DIR, "secrets.service.template")
    with open(tpl_path, "r", encoding="utf-8") as fh:
        template = fh.read()
    return template.format(
        tee_platform=platform,
        remote_base=remote_base,
        tmpfs_dir=f"tee-crafter-{platform}",
    )


def load_container_unit(platform: str) -> str:
    """Render the container-mode systemd unit for *platform*."""
    cfg = _CONTAINER_CFG.get(platform)
    if cfg is None:
        raise ValueError(f"No container unit config for platform: {platform}")
    desc, after, tar, extra = cfg
    tpl_path = os.path.join(_SYSTEMD_DIR, "container.service.template")
    with open(tpl_path, "r", encoding="utf-8") as fh:
        template = fh.read()
    return template.format(
        description=desc,
        after_service=after,
        container_tar_path=tar,
        extra_run_flags=extra,
        secrets_dep=_secrets_dep_block(platform),
    )


def load_container_batch_unit(platform: str, *, batch_timeout_sec: int = 3600) -> str:
    """Render the container *batch* (oneshot) systemd unit for *platform*.

    Differs from :func:`load_container_unit` in three important ways:

    * ``Type=oneshot`` so the user image runs to completion and we collect
      output, rather than being treated as a long-running service.
    * ``--read-only`` is intentionally lifted — diff capture only works if
      the user image can write to its own writable layer.
    * ``ExecStopPost`` invokes ``tee_crafter_capture_container.sh`` to docker-
      diff and docker-cp the output bundle into ``/var/lib/tee_crafter``.
    """
    cfg = _CONTAINER_CFG.get(platform)
    if cfg is None:
        raise ValueError(f"No container unit config for platform: {platform}")
    desc, after, tar, extra = cfg
    tpl_path = os.path.join(_SYSTEMD_DIR, "container.batch.service.template")
    with open(tpl_path, "r", encoding="utf-8") as fh:
        template = fh.read()
    return template.format(
        description=desc,
        after_service=after,
        container_tar_path=tar,
        extra_run_flags=extra,
        batch_timeout_sec=int(batch_timeout_sec),
        secrets_dep=_secrets_dep_block(platform),
    )


