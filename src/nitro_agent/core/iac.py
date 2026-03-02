from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Tuple, Dict, Any


def stage_terraform(
    build_dir: str,
    terraform_code: str,
    pcr_hashes: dict | None = None,
) -> str:
    """
    Write the generated Terraform to the build directory.

    This saves main.tf, the canonical Terraform used for deployment / validation.

    If `pcr_hashes` are provided, it injects them directly into the HCL,
    replacing variable placeholders and removing the now-unused variable blocks.

    Returns the path to main.tf.
    """
    os.makedirs(build_dir, exist_ok=True)

    processed_code = terraform_code
    if pcr_hashes:
        # Inject concrete PCR hash values
        for i in range(3):
            pcr_key = f"PCR{i}"
            if pcr_key in pcr_hashes:
                processed_code = processed_code.replace(
                    f"var.pcr{i}_hash", f'"{pcr_hashes[pcr_key]}"'
                )

        # Remove the variable definitions for the PCR hashes (no longer needed)
        after_removal = re.sub(
            r'variable "pcr[0-2]_hash" \{[^{}]*\}', "", processed_code, flags=re.DOTALL
        )
        # If removal would leave the file empty (e.g. model only output variable blocks), keep injected code without removal
        if after_removal.strip():
            processed_code = after_removal

    # Never write an empty main.tf
    final = processed_code.strip()
    if not final:
        final = terraform_code.strip() or "# Terraform generation produced no output"
    main_tf_path = os.path.join(build_dir, "main.tf")
    with open(main_tf_path, "w", encoding="utf-8") as f:
        f.write(final)

    return main_tf_path


def verify_terraform_syntax(build_dir: str) -> Tuple[bool, str]:
    """
    Run `terraform validate` in the given directory.

    Returns:
        (is_valid, message)
        - is_valid: True if validation succeeded, False otherwise.
        - message : empty string on success, otherwise a human‑readable error.
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
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [terraform_bin, "validate", "-no-color"],
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        message = stderr or stdout or str(exc)
        return False, message
    except FileNotFoundError:
        # Extra safety in case terraform disappears between which() and run().
        return (
            False,
            "Terraform is not installed or not in PATH. "
            "Install Terraform to enable IaC validation.",
        )

    return True, ""


def run_terraform_apply(
    build_dir: str, auto_approve: bool = False, timeout_seconds: int = 600
) -> Tuple[bool, str, str]:
    """
    Run `terraform apply` in the build directory.
    
    Args:
        build_dir: Directory containing main.tf
        auto_approve: If True, passes -auto-approve to skip interactive confirmation.
        timeout_seconds: Maximum time to wait for the apply to complete.
        
    Returns:
        (success, stdout, stderr)
    """
    terraform_bin = shutil.which("terraform")
    if terraform_bin is None:
        return (
            False,
            "",
            "Terraform is not installed or not in PATH. Install Terraform to enable deployment.",
        )

    cmd = [terraform_bin, "apply", "-input=false", "-no-color"]
    if auto_approve:
        cmd.append("-auto-approve")

    try:
        # Ensure we are initialized (idempotent)
        subprocess.run(
            [terraform_bin, "init", "-input=false", "-no-color"],
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Run apply
        result = subprocess.run(
            cmd,
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return True, result.stdout, result.stderr

    except subprocess.CalledProcessError as exc:
        return False, exc.stdout or "", exc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return (
            False,
            exc.stdout or "" if hasattr(exc, "stdout") else "",
            f"Terraform apply timed out after {timeout_seconds} seconds. {exc.stderr or ''}",
        )
    except Exception as e:
        return False, "", str(e)


def get_terraform_outputs(build_dir: str) -> Dict[str, Any]:
    """
    Run `terraform output -json` to extract outputs like public_ip or instance_id.
    Returns a dictionary of outputs.
    """
    terraform_bin = shutil.which("terraform")
    if terraform_bin is None:
        return {}

    try:
        result = subprocess.run(
            [terraform_bin, "output", "-json"],
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        # Parse JSON: {"public_ip": {"sensitive": false, "type": "string", "value": "1.2.3.4"}}
        outputs_raw = json.loads(result.stdout)
        
        # Flatten structure to just key: value
        outputs = {}
        for key, data in outputs_raw.items():
            outputs[key] = data.get("value")
            
        return outputs
    except Exception:
        return {}


def run_terraform_destroy(build_dir: str) -> Tuple[bool, str]:
    """
    Run `terraform destroy -auto-approve` in the build directory.
    Returns (success, message).
    """
    terraform_bin = shutil.which("terraform")
    if terraform_bin is None:
        return False, "Terraform is not installed or not in PATH."

    try:
        # We assume init has run before, but running it again is safe/idempotent
        subprocess.run(
            [terraform_bin, "init", "-input=false", "-no-color"],
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )

        subprocess.run(
            [terraform_bin, "destroy", "-auto-approve", "-input=false", "-no-color"],
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        return True, "Resources destroyed successfully."

    except subprocess.CalledProcessError as exc:
        msg = exc.stderr or exc.stdout or str(exc)
        return False, f"Terraform destroy failed: {msg}"
    except Exception as e:
        return False, f"Terraform destroy failed: {str(e)}"

