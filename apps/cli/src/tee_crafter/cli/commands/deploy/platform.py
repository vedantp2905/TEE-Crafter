"""Per-platform tables + staging helpers for the unified container deploy path.

This module holds the platform descriptor tables (:data:`PLATFORM_CONFIGS` /
:data:`_INSTANCE_RULES`) and the small staging helpers (:func:`_load_template`,
:func:`_get_platform_fns`, :func:`_extract_user_code`,
:func:`_stage_runtime_bootstrap`) shared by ``deploy_container``'s per-platform
branches.

The legacy source+handler deploy entrypoints (``deploy_vm_platform`` /
``deploy_nitro``) were removed together with the ingestion pipeline: there is no
more LLM code translation or ``process_request`` handler model. The only input
is the user's container, run as-is.
"""
import os
import re

PLATFORM_CONFIGS = {
    "tdx-azure": ("tdx/azure/app.template.py", "tdx/azure/main.template.tf", "client_tdx.py", "Standard_DC2es_v6", {"MRTD": "unknown"}, "MRTD", "TDX"),
    "snp-aws": ("snp/aws/app.template.py", "snp/aws/main.template.tf", "client_snp_aws.py", "m6a.xlarge", {"measurement": "unknown"}, "Measurement", "SNP-AWS"),
    "snp-azure": ("snp/azure/app.template.py", "snp/azure/main.template.tf", "client_snp_azure.py", "Standard_DC2as_v5", {"measurement": "unknown"}, "Measurement", "SNP-Azure"),
    "snp-gcp": ("snp/gcp/app.template.py", "snp/gcp/main.template.tf", "client_snp_gcp.py", "n2d-standard-2", {"measurement": "unknown"}, "Measurement", "SNP-GCP"),
    "tdx-gcp": ("tdx/gcp/app.template.py", "tdx/gcp/main.template.tf", "client_tdx_gcp.py", "c3-standard-4", {"MRTD": "unknown"}, "MRTD", "TDX-GCP"),
    "gpu-cc-gcp": ("gpu_cc/gcp/app.template.py", "gpu_cc/gcp/main.template.tf", "client_gpu_cc_gcp.py", "a3-highgpu-1g", {"MRTD": "unknown"}, "MRTD", "GPU-CC-GCP"),
    "gpu-cc-azure": ("gpu_cc/azure/app.template.py", "gpu_cc/azure/main.template.tf", "client_gpu_cc_azure.py", "Standard_NCC40ads_H100_v5", {"measurement": "unknown"}, "Measurement", "GPU-CC-Azure"),
    "gpu-cc-aws": ("gpu_cc/aws/app.template.py", "gpu_cc/aws/main.template.tf", "client_gpu_cc_aws.py", "p5.4xlarge", {"measurement": "unknown"}, "Measurement", "GPU-CC-AWS"),
}

_INSTANCE_RULES = {
    "tdx-azure": ("TF_VAR_vm_size", "Standard_DC2es_v6", lambda s: any(s.startswith(p) for p in ("Standard_DC", "Standard_EC")), "TDX requires an Azure DCesv6/ECesv6 VM"),
    "snp-aws": ("TF_VAR_instance_type", "m6a.xlarge", lambda s: s.split(".")[0].lower() in ("m6a", "c6a", "r6a"), "SNP-AWS requires an M6a, C6a, or R6a instance"),
    "snp-azure": ("TF_VAR_vm_size", "Standard_DC2as_v5", lambda s: any(s.startswith(p) for p in ("Standard_DC", "Standard_EC")), "SNP-Azure requires a DCasv5/ECasv5/v6 VM"),
    "snp-gcp": ("TF_VAR_machine_type", "n2d-standard-2", lambda s: s.startswith("n2d-"), "SNP-GCP requires an N2D machine type"),
    "tdx-gcp": ("TF_VAR_machine_type", "c3-standard-4", lambda s: s.startswith("c3-"), "TDX-GCP requires a C3 machine type"),
    "gpu-cc-gcp": ("TF_VAR_machine_type", "a3-highgpu-1g", lambda s: s.startswith("a3-"), "GPU-CC-GCP requires an A3 machine type"),
    "gpu-cc-azure": ("TF_VAR_vm_size", "Standard_NCC40ads_H100_v5", lambda s: "NCC" in s and "H100" in s, "GPU-CC-Azure requires an NCC H100 v5 VM"),
    "gpu-cc-aws": ("TF_VAR_instance_type", "p5.4xlarge", lambda s: s.split(".")[0].lower() in ("p5", "p5en", "p6-b200"), "GPU-CC-AWS requires a P5, P5en, or P6 instance"),
}


def _load_template(name: str) -> str:
    # This file lives in: tee_crafter/cli/commands/deploy
    # The shared templates live in: tee_crafter/templates
    tpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "templates")
    with open(os.path.join(tpl_dir, name), "r", encoding="utf-8") as f:
        return f.read()


def _stage_runtime_bootstrap(build_dir: str) -> None:
    """Copy ``tee_crafter_runtime_bootstrap.py`` into the build dir.

    The shared bootstrap drives both SIEM and BYOK auto-wiring at TEE
    startup; staging it next to the app means the user never has to
    import a TEE-Crafter library themselves.  No-op on copy errors so
    misconfigured templates still build.
    """
    import shutil
    common = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "..", "..", "templates", "common")
    app_dir = os.path.join(build_dir, "app")
    # Both the SIEM/BYOK runtime bootstrap (imported in-process by the app
    # templates) and the CVM secret-bootstrap oneshot entry (run on the host by
    # tee-crafter-secrets.service) ship next to the app bundle.
    for name in ("tee_crafter_runtime_bootstrap.py",
                 "tee_crafter_secret_bootstrap.py"):
        src = os.path.join(common, name)
        if not os.path.isfile(src):
            continue
        for dst_root in (build_dir, app_dir):
            try:
                if os.path.isdir(dst_root):
                    shutil.copy(src, os.path.join(dst_root, name))
            except Exception:
                pass
    # Stage the baked plaintext app.env (no-BYOK --secrets-env path) beside the
    # secret-bootstrap script so the oneshot can copy it to tmpfs at boot.
    baked_env = os.path.join(build_dir, "app.env")
    try:
        if os.path.isfile(baked_env) and os.path.isdir(app_dir):
            shutil.copy(baked_env, os.path.join(app_dir, "app.env"))
    except Exception:
        pass


def _extract_user_code(vsock_code: str) -> tuple[str, str]:
    """Pull staged proxy imports and ``process_request`` body from vsock source."""
    user_imports, user_logic = "", "    return data"
    m = re.search(
        r"# PROXY IMPORTS \(injected by TEE-Crafter at staging time\)\n# =+\n(.*?)\n# =+",
        vsock_code, re.DOTALL)
    if m:
        user_imports = m.group(1).strip()
    m = re.search(
        r"def process_request\(data\):\s*\n\s*(\"\"\"|''').*?\1\s*\n(.*?)\n# =+",
        vsock_code, re.DOTALL)
    if m:
        user_logic = m.group(2)
    return user_imports, user_logic


def _get_platform_fns(platform: str):
    if platform == "tdx-azure":
        from tee_crafter.core.builder import stage_tdx_artifacts, render_tdx_client_template
        from tee_crafter.core.iac import stage_tdx_terraform
        from tee_crafter.cli.deployment.tdx.phase import run_tdx_deployment_phase
        return stage_tdx_artifacts, "tdx_code", render_tdx_client_template, {"mrtd": "unknown"}, stage_tdx_terraform, run_tdx_deployment_phase
    if platform == "snp-aws":
        from tee_crafter.core.builder import stage_snp_aws_artifacts, render_snp_aws_client_template
        from tee_crafter.core.iac import stage_snp_aws_terraform
        from tee_crafter.cli.deployment.snp.aws_phase import run_snp_aws_deployment_phase
        return stage_snp_aws_artifacts, "snp_code", render_snp_aws_client_template, {"measurement": "unknown"}, stage_snp_aws_terraform, run_snp_aws_deployment_phase
    if platform == "snp-azure":
        from tee_crafter.core.builder import stage_snp_azure_artifacts, render_snp_azure_client_template
        from tee_crafter.core.iac import stage_snp_azure_terraform
        from tee_crafter.cli.deployment.snp.azure_phase import run_snp_azure_deployment_phase
        return stage_snp_azure_artifacts, "snp_code", render_snp_azure_client_template, None, stage_snp_azure_terraform, run_snp_azure_deployment_phase
    if platform == "snp-gcp":
        from tee_crafter.core.builder import stage_snp_gcp_artifacts, render_snp_gcp_client_template
        from tee_crafter.core.iac import stage_snp_gcp_terraform
        from tee_crafter.cli.deployment.snp.gcp_phase import run_snp_gcp_deployment_phase
        return stage_snp_gcp_artifacts, "snp_code", render_snp_gcp_client_template, {"measurement": "unknown"}, stage_snp_gcp_terraform, run_snp_gcp_deployment_phase
    if platform == "tdx-gcp":
        from tee_crafter.core.builder import stage_tdx_gcp_artifacts, render_tdx_gcp_client_template
        from tee_crafter.core.iac import stage_tdx_gcp_terraform
        from tee_crafter.cli.deployment.tdx.gcp_phase import run_tdx_gcp_deployment_phase
        return stage_tdx_gcp_artifacts, "tdx_code", render_tdx_gcp_client_template, {"mrtd": "unknown"}, stage_tdx_gcp_terraform, run_tdx_gcp_deployment_phase
    if platform == "gpu-cc-gcp":
        from tee_crafter.core.builder import stage_gpu_cc_gcp_artifacts, render_gpu_cc_gcp_client_template
        from tee_crafter.core.iac import stage_gpu_cc_gcp_terraform
        from tee_crafter.cli.deployment.gpu_cc.gcp_phase import run_gpu_cc_gcp_deployment_phase
        return stage_gpu_cc_gcp_artifacts, "tdx_code", render_gpu_cc_gcp_client_template, {"mrtd": "unknown"}, stage_gpu_cc_gcp_terraform, run_gpu_cc_gcp_deployment_phase
    if platform == "gpu-cc-azure":
        from tee_crafter.core.builder import stage_gpu_cc_azure_artifacts, render_gpu_cc_azure_client_template
        from tee_crafter.core.iac import stage_gpu_cc_azure_terraform
        from tee_crafter.cli.deployment.gpu_cc.azure_phase import run_gpu_cc_azure_deployment_phase
        return stage_gpu_cc_azure_artifacts, "snp_code", render_gpu_cc_azure_client_template, {"measurement": "unknown"}, stage_gpu_cc_azure_terraform, run_gpu_cc_azure_deployment_phase
    if platform == "gpu-cc-aws":
        from tee_crafter.core.builder import stage_gpu_cc_aws_artifacts, render_gpu_cc_aws_client_template
        from tee_crafter.core.iac import stage_gpu_cc_aws_terraform
        from tee_crafter.cli.deployment.gpu_cc.aws_phase import run_gpu_cc_aws_deployment_phase
        return stage_gpu_cc_aws_artifacts, "snp_code", render_gpu_cc_aws_client_template, {"measurement": "unknown"}, stage_gpu_cc_aws_terraform, run_gpu_cc_aws_deployment_phase
    raise ValueError(f"Unknown platform: {platform}")


#: Every platform's deployment phase, keyed by platform id, as
#: ``(import path, function name, measurement keyword)``.
#:
#: :func:`_get_platform_fns` above already resolves the phase for the eight
#: confidential-VM platforms, but it also resolves seven other things a caller
#: has to have built first (staging fn, renderer, Terraform stager…) and it does
#: not know ``nitro-aws`` or ``sgx-azure`` at all.  ``deploy-from-build`` needs
#: the phase and nothing else, for all ten.
#:
#: The third element is the phase's measurement parameter name: ``nitro-aws``
#: calls it ``hashes`` (PCR0/1/2) and the other nine call it ``measurements``.
_DEPLOYMENT_PHASES: dict[str, tuple[str, str, str]] = {
    "nitro-aws": ("tee_crafter.cli.deployment.nitro.phase",
                  "run_nitro_deployment_phase", "hashes"),
    "sgx-azure": ("tee_crafter.cli.deployment.sgx.phase",
                  "run_sgx_deployment_phase", "measurements"),
    "tdx-azure": ("tee_crafter.cli.deployment.tdx.phase",
                  "run_tdx_deployment_phase", "measurements"),
    "tdx-gcp": ("tee_crafter.cli.deployment.tdx.gcp_phase",
                "run_tdx_gcp_deployment_phase", "measurements"),
    "snp-aws": ("tee_crafter.cli.deployment.snp.aws_phase",
                "run_snp_aws_deployment_phase", "measurements"),
    "snp-azure": ("tee_crafter.cli.deployment.snp.azure_phase",
                  "run_snp_azure_deployment_phase", "measurements"),
    "snp-gcp": ("tee_crafter.cli.deployment.snp.gcp_phase",
                "run_snp_gcp_deployment_phase", "measurements"),
    "gpu-cc-gcp": ("tee_crafter.cli.deployment.gpu_cc.gcp_phase",
                   "run_gpu_cc_gcp_deployment_phase", "measurements"),
    "gpu-cc-azure": ("tee_crafter.cli.deployment.gpu_cc.azure_phase",
                     "run_gpu_cc_azure_deployment_phase", "measurements"),
    "gpu-cc-aws": ("tee_crafter.cli.deployment.gpu_cc.aws_phase",
                   "run_gpu_cc_aws_deployment_phase", "measurements"),
}

#: Platforms whose deploy phase can be re-driven from a build directory.
RESUMABLE_PLATFORMS: tuple[str, ...] = tuple(sorted(_DEPLOYMENT_PHASES))

#: The Terraform variable that carries the instance type / VM size, per platform.
#:
#: :data:`_INSTANCE_RULES` above has this for the eight confidential-VM platforms
#: but not for ``nitro-aws`` or ``sgx-azure``, and the two names differ:
#: ``templates/nitro/main.template.tf`` declares ``instance_type`` while
#: ``templates/sgx/main.template.tf`` declares ``vm_size``.  Defaulting the
#: missing pair to ``TF_VAR_instance_type`` would make ``--instance-type`` on an
#: ``sgx-azure`` resume set a variable the template does not declare: Terraform
#: ignores unknown ``TF_VAR_*`` silently, so the flag would appear to work and
#: change nothing.
INSTANCE_TYPE_TF_VAR: dict[str, str] = {
    "nitro-aws": "TF_VAR_instance_type",
    "sgx-azure": "TF_VAR_vm_size",
    **{p: rule[0] for p, rule in _INSTANCE_RULES.items()},
}


def deployment_phase_for(platform: str):
    """Return ``(phase_fn, measurement_kwarg)`` for *platform*.

    Imported lazily, one platform at a time: the phase modules pull in the cloud
    SDK and SSH machinery for their own cloud, and importing all ten to answer a
    question about one is what makes ``--help`` slow.
    """
    entry = _DEPLOYMENT_PHASES.get(platform)
    if entry is None:
        raise ValueError(
            f"No deployment phase for platform {platform!r}. "
            f"Known: {', '.join(RESUMABLE_PLATFORMS)}")
    module_path, fn_name, meas_kwarg = entry
    import importlib

    return getattr(importlib.import_module(module_path), fn_name), meas_kwarg
