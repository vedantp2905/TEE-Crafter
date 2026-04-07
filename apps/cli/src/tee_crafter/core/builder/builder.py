import os
import shutil
import datetime
import json
import uuid
from typing import Optional

from tee_crafter.core.builder.runtime_modules import (
    copy_source_tree,
    RUNTIME_MODULES,
    copy_runtime_modules,
)


def _load_template(filename: str) -> str:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, "..", "..", "templates", filename)
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def _common_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates", "common")


# The runtime-module list and the fail-closed copy live in one place now:
# ``builder.py`` and ``platforms.py`` each carried their own copy, and both
# skipped missing files silently.  See ``runtime_modules`` for why that matters.
_RUNTIME_MODULES = RUNTIME_MODULES


def _copy_runtime_modules(dest_dir: str) -> None:
    """Copy runtime audit/attestation modules into the build (fail-closed)."""
    copy_runtime_modules(dest_dir)


def render_container_dockerfile_template(
    user_image_tag: str, container_port: int
) -> str:
    """Returns the container-mode Dockerfile template with user image and port injected."""
    tpl = _load_template(os.path.join("common", "Dockerfile.container.template"))
    return (
        tpl.replace("__USER_IMAGE__", user_image_tag)
        .replace("__CONTAINER_PORT__", str(container_port))
    )


def render_client_template(pcr_hashes: Optional[dict] = None, root_ca: str = "") -> str:
    """Renders the Nitro Python client script template, injecting root CA and PCR hashes."""
    template_str = _load_template(os.path.join("nitro", "client.template.py"))
    pcr_bindings_str = "{}"
    if pcr_hashes:
        pcr_bindings_str = json.dumps(pcr_hashes, indent=4)
    client_code = template_str.replace("{root_ca}", root_ca.strip())
    client_code = client_code.replace("{pcr_bindings}", pcr_bindings_str)
    return client_code

def render_host_proxy_template() -> str:
    """Returns the static Nitro Host API Proxy script."""
    return _load_template(os.path.join("nitro", "host_proxy.template.py"))

def stage_artifacts(
    source_dir: str,
    vsock_code: str,
    dockerfile_content: str,
    base_build_dir: str = "build",
    stage_label: str = "nitro",
) -> str:
    """
    Saves the generated vsock wrapper (and for Nitro: Dockerfile, host_proxy) into a
    single timestamped build directory per platform.
    Returns the absolute path to the build directory.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    deploy_id = uuid.uuid4().hex[:8]
    source_name = os.path.basename(os.path.abspath(source_dir)) or "app"
    build_dir_name = f"{source_name}_{stage_label}_{base_build_dir}_{timestamp}_{deploy_id}"
    build_path = os.path.abspath(os.path.join("builds", build_dir_name))
    os.makedirs(build_path, exist_ok=True)

    # Container-orchestrated model: TEE-Crafter no longer consumes an
    # application output_schema.json. The user's container owns its I/O; the
    # in-TEE ``_OUTPUT_SCHEMA`` placeholder is left as ``None`` (inert). The
    # confidentiality boundary is enforced by attestation + default-deny
    # network egress, not by per-response shape validation.

    if stage_label in (
        "sgx-azure",
        "tdx-azure",
        "snp-aws",
        "snp-azure",
        "snp-gcp",
        "tdx-gcp",
        "gpu-cc-gcp",
        "gpu-cc-azure",
        "gpu-cc-aws",
    ):
        app_path = os.path.join(build_path, "app")
        os.makedirs(app_path, exist_ok=True)
        copy_source_tree(source_dir, app_path)
        with open(os.path.join(build_path, "app_vsock.py"), "w", encoding="utf-8") as f:
            f.write(vsock_code)
        _copy_runtime_modules(app_path)
        return build_path

    copy_source_tree(source_dir, build_path)
    with open(os.path.join(build_path, "app_vsock.py"), "w", encoding="utf-8") as f:
        f.write(vsock_code)
    with open(os.path.join(build_path, "Dockerfile"), "w", encoding="utf-8") as f:
        f.write(dockerfile_content)
    with open(os.path.join(build_path, "host_proxy.py"), "w", encoding="utf-8") as f:
        f.write(render_host_proxy_template())
    nsm_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates", "common", "nsm_main.rs")
    if os.path.isfile(nsm_src):
        shutil.copy2(nsm_src, os.path.join(build_path, "nsm_main.rs"))
    _copy_runtime_modules(build_path)
    return build_path


def stage_container_artifacts(
    source_dir: str,
    vsock_code: str,
    dockerfile_content: str,
    base_build_dir: str = "build",
    stage_label: str = "nitro",
    container_image_tar: str | None = None,
) -> str:
    """Stage artifacts for container-mode deployments.

    Similar to ``stage_artifacts`` but:
    - For Nitro: uses the container Dockerfile template (multi-stage merge)
    - For CVMs: also copies the container image tarball for ``docker load``
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    deploy_id = uuid.uuid4().hex[:8]
    source_name = os.path.basename(os.path.abspath(source_dir)) or "app"
    build_dir_name = f"{source_name}_container_{stage_label}_{base_build_dir}_{timestamp}_{deploy_id}"
    build_path = os.path.abspath(os.path.join("builds", build_dir_name))
    os.makedirs(build_path, exist_ok=True)


    if stage_label in (
        "sgx-azure",
        "tdx-azure",
        "snp-aws",
        "snp-azure",
        "snp-gcp",
        "tdx-gcp",
        "gpu-cc-gcp",
        "gpu-cc-azure",
        "gpu-cc-aws",
    ):
        app_path = os.path.join(build_path, "app")
        os.makedirs(app_path, exist_ok=True)
        copy_source_tree(source_dir, app_path)
        with open(os.path.join(build_path, "app_vsock.py"), "w", encoding="utf-8") as f:
            f.write(vsock_code)
        _copy_runtime_modules(app_path)
        if container_image_tar and os.path.isfile(container_image_tar):
            shutil.copy2(container_image_tar, os.path.join(build_path, "user_container.tar"))
        return build_path

    copy_source_tree(source_dir, build_path)
    with open(os.path.join(build_path, "app_vsock.py"), "w", encoding="utf-8") as f:
        f.write(vsock_code)
    with open(os.path.join(build_path, "Dockerfile"), "w", encoding="utf-8") as f:
        f.write(dockerfile_content)
    with open(os.path.join(build_path, "host_proxy.py"), "w", encoding="utf-8") as f:
        f.write(render_host_proxy_template())
    nsm_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates", "common", "nsm_main.rs")
    if os.path.isfile(nsm_src):
        shutil.copy2(nsm_src, os.path.join(build_path, "nsm_main.rs"))
    _copy_runtime_modules(build_path)
    return build_path
