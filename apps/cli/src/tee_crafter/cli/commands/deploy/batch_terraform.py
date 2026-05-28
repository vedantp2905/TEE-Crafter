"""Deterministic Terraform staging for the unified ``--batch`` container path.

``deploy <ctx> --batch`` reuses the standard container ``run_container_phases``
build dir, but that helper does not stage Terraform — the per-platform service
deploy branches normally do.  In batch mode those branches are skipped, so
:func:`tee_crafter.cli.commands.deploy.batch_dispatch.dispatch_batch_container`
calls :func:`stage_batch_terraform` to render the same per-platform ``main.tf``.

This is plain, deterministic IaC rendering (no LLM, no source translation, no
``process_request`` wrapping): it reuses the same per-platform templates and
``stage_*_terraform`` helpers as the service-mode deploy path so batch runs
inherit every infrastructure fix without duplication.
"""
from __future__ import annotations

import os


def stage_batch_terraform(
    build_dir: str,
    tee_platform: str,
    *,
    audit=None,
    cpu: int | None = None,
    ram_mb: int | None = None,
) -> None:
    """Render and write ``main.tf`` (+ measurements file) for *tee_platform*.

    *cpu* / *ram_mb* matter for Nitro AWS: :func:`tee_crafter.core.iac.terraform_gen.generate_terraform_code`
    substitutes ``__CPU_COUNT__``, ``__ALLOCATOR_MB__``, ``__AMI_ARCH__``, etc.
    Defaults match the CLI ``standard`` preset (2 vCPU / 4096 MiB) when omitted.
    """
    template_root = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "templates",
    )

    def _load(name: str) -> str:
        with open(os.path.join(template_root, name), "r", encoding="utf-8") as f:
            return f.read()

    instance_env = (
        os.getenv("TF_VAR_instance_type")
        or os.getenv("TF_VAR_vm_size")
        or os.getenv("TF_VAR_machine_type") or ""
    )

    _cpu = int(cpu) if cpu is not None else int(
        os.getenv("TEE_CRAFTER_BATCH_CPU") or "2",
    )
    _ram = int(ram_mb) if ram_mb is not None else int(
        os.getenv("TEE_CRAFTER_BATCH_RAM_MB") or "4096",
    )

    if tee_platform == "nitro-aws":
        # Run the same substitution pipeline as the service-mode deploy path
        # (``flow_build.generate_terraform_code``) — the raw template embeds
        # placeholders like ``__ALLOCATOR_MB__`` / ``__CPU_COUNT__`` that are not
        # valid HCL until expanded to numeric literals.
        from tee_crafter.core.iac import stage_terraform
        from tee_crafter.core.iac.terraform_gen import (
            generate_terraform_code, select_instance_type,
        )

        code = generate_terraform_code(
            cpu=_cpu, ram=_ram, pcr_hashes={}, debug_build_dir=build_dir,
        )
        # Service mode forces batch_mode false inside ``generate_terraform_code`` —
        # flip it for batch orchestration.
        code = code.replace('batch_mode = "false"', 'batch_mode = "true"')

        picked = select_instance_type(_cpu, _ram)
        if instance_env:
            code = code.replace(
                f'default = "{picked}"',
                f'default = "{instance_env}"',
                1,
            )

        # No EIF in container-batch staging — inject placeholder PCRs so
        # ``stage_terraform`` can inline them and drop the variables, matching the
        # post-``build-enclave`` service deploy path well enough for
        # ``terraform init``/``apply``.  (Batch container on Nitro runs Docker on
        # the host, not an attested enclave; PCR binding is not exercised here.)
        _BATCH_PCR_FILL = {"PCR0": "0" * 96, "PCR1": "0" * 96, "PCR2": "0" * 96}
        stage_terraform(build_dir, code, pcr_hashes=_BATCH_PCR_FILL)
    elif tee_platform == "sgx-azure":
        from tee_crafter.core.iac import stage_sgx_terraform
        tf = _load(os.path.join("sgx", "main.template.tf"))
        tf = tf.replace("__INSTANCE_TYPE__", instance_env or "Standard_DC2s_v3")
        stage_sgx_terraform(build_dir, tf, {"MRENCLAVE": "unknown", "MRSIGNER": "unknown"})
    else:
        from tee_crafter.cli.commands.deploy.platform import (
            PLATFORM_CONFIGS, _get_platform_fns,
        )
        if tee_platform not in PLATFORM_CONFIGS:
            raise ValueError(f"Unsupported batch platform: {tee_platform}")
        _, tf_tpl, _, default_inst, meas_init, _, _ = PLATFORM_CONFIGS[tee_platform]
        _, _, _, _, stage_tf_fn, _ = _get_platform_fns(tee_platform)
        tf = _load(tf_tpl).replace("__INSTANCE_TYPE__", instance_env or default_inst)
        stage_tf_fn(build_dir, tf, dict(meas_init))

    if audit is not None:
        audit.record("Phase 1: Batch", "Terraform staged", "pass",
                     tee_platform=tee_platform)
