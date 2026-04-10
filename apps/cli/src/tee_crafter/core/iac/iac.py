from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Tuple, Dict, Any

logger = logging.getLogger(__name__)

LOCKFILE_NAME = ".terraform.lock.hcl"


def _template_root() -> str:
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates")


def template_lockfile_path(template_subdir: str) -> str:
    """Path to the provider lockfile shipped beside a platform's template.

    *template_subdir* is the path under ``templates/`` — ``"nitro"``,
    ``"snp/aws"``, ``"gpu_cc/gcp"`` and so on.
    """
    return os.path.join(_template_root(), template_subdir, LOCKFILE_NAME)


def stage_provider_lock(build_dir: str, template_subdir: str) -> str | None:
    """Copy a platform's provider lockfile into *build_dir*.

    ``terraform init`` only honours a lockfile in the directory it runs in, and
    every terraform invocation here runs inside *build_dir*.  A lockfile that
    ships beside the template but is never copied pins nothing: each apply
    re-resolves to the newest provider the ``~> 5.0`` constraint allows, so two
    builds of the same commit can embed different provider versions.  For a
    project whose premise is reproducible, attestable builds, that is a real
    gap rather than a cosmetic one.

    Returns the staged path, or ``None`` if no lockfile shipped for this
    platform.  A missing lockfile is not fatal — terraform still works, just
    unpinned — but it is logged at WARNING, because silent un-pinning is
    indistinguishable from a pinned build in the output.  Regenerate with
    ``.github/scripts/generate_provider_locks.py``.
    """
    src = template_lockfile_path(template_subdir)
    if not os.path.isfile(src):
        logger.warning(
            "no %s shipped for template %r; terraform will resolve providers "
            "unpinned and this build is not reproducible. Regenerate with "
            ".github/scripts/generate_provider_locks.py",
            LOCKFILE_NAME, template_subdir)
        return None
    dst = os.path.join(build_dir, LOCKFILE_NAME)
    shutil.copyfile(src, dst)
    return dst


def stage_terraform(
    build_dir: str,
    terraform_code: str,
    pcr_hashes: dict | None = None,
    lockfile_src: str | None = None,
    template_subdir: str = "nitro",
) -> str:
    """
    Write the generated Terraform to the build directory.

    This saves main.tf, the canonical Terraform used for deployment / validation.
    If ``pcr_hashes`` are provided, it injects them directly into the HCL,
    replacing variable placeholders and removing the now-unused variable blocks.

    ``lockfile_src`` explicitly overrides where the ``.terraform.lock.hcl``
    comes from.  When it is omitted, the lockfile shipped beside
    ``templates/<template_subdir>/`` is staged automatically — see
    :func:`stage_provider_lock` for why staging it matters.  Passing
    ``template_subdir=""`` skips lockfile staging entirely.

    Returns the path to main.tf.
    """
    os.makedirs(build_dir, exist_ok=True)

    if lockfile_src and os.path.isfile(lockfile_src):
        shutil.copyfile(
            lockfile_src, os.path.join(build_dir, LOCKFILE_NAME))
    elif not lockfile_src and template_subdir:
        stage_provider_lock(build_dir, template_subdir)

    processed_code = terraform_code
    if pcr_hashes:
        for i in range(3):
            pcr_key = f"PCR{i}"
            if pcr_key in pcr_hashes:
                processed_code = processed_code.replace(
                    f"var.pcr{i}_hash", f'"{pcr_hashes[pcr_key]}"'
                )
        after_removal = re.sub(
            r'variable "pcr[0-2]_hash" \{[^{}]*\}', "", processed_code, flags=re.DOTALL
        )
        if after_removal.strip():
            processed_code = after_removal

    final = processed_code.strip()
    if not final:
        final = terraform_code.strip() or "# Terraform generation produced no output"
    main_tf_path = os.path.join(build_dir, "main.tf")
    with open(main_tf_path, "w", encoding="utf-8") as f:
        f.write(final)

    return main_tf_path


def verify_terraform_syntax(build_dir: str) -> Tuple[bool, str]:
    """
    Run ``terraform validate`` in the given directory.

    Returns:
        (is_valid, message) — is_valid is True on success; message is empty or
        contains a human-readable error.
    """
    terraform_bin = shutil.which("terraform")
    if terraform_bin is None:
        return (
            False,
            "Terraform is not installed or not in PATH. "
            "Install Terraform to enable IaC validation.",
        )

    try:
        subprocess.run(
            [terraform_bin, "init", "-input=false", "-no-color"],
            cwd=build_dir, check=True, capture_output=True, text=True, timeout=120,
        )
        subprocess.run(
            [terraform_bin, "validate", "-no-color"],
            cwd=build_dir, check=True, capture_output=True, text=True, timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        return False, stderr or stdout or str(exc)
    except subprocess.TimeoutExpired as exc:
        stdout = (getattr(exc, "stdout", None) or "").strip()
        stderr = (getattr(exc, "stderr", None) or "").strip()
        msg = (
            "Terraform validation timed out. This is usually caused by a slow/hung "
            "`terraform init` while downloading providers. "
            "Try re-running, ensure network access to `registry.terraform.io`, or run "
            "`terraform init` manually in the build directory.\n"
        )
        detail = stderr or stdout
        if detail:
            msg += f"\nLast output:\n{detail[:2000]}"
        return False, msg
    except FileNotFoundError:
        return (
            False,
            "Terraform is not installed or not in PATH. "
            "Install Terraform to enable IaC validation.",
        )
    return True, ""


def get_terraform_outputs(build_dir: str) -> Dict[str, Any]:
    """Run ``terraform output -json`` and return a flat {key: value} dictionary."""
    terraform_bin = shutil.which("terraform")
    if terraform_bin is None:
        return {}
    try:
        result = subprocess.run(
            [terraform_bin, "output", "-json"],
            cwd=build_dir, check=True, capture_output=True, text=True,
        )
        outputs_raw = json.loads(result.stdout)
        return {key: data.get("value") for key, data in outputs_raw.items()}
    except Exception:
        return {}
