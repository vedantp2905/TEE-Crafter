"""SGX / Gramine manifest signing and measurement extraction."""
import os
import re
import shutil
import subprocess
from typing import Dict, Tuple


def sign_gramine_manifest(build_dir: str) -> Tuple[bool, Dict[str, str], str]:
    """Run ``gramine-sgx-sign`` and extract MRENCLAVE / MRSIGNER.

    Returns (success, measurements, message).
    """
    gramine_sign = shutil.which("gramine-sgx-sign")
    if gramine_sign is None:
        return False, {}, (
            "gramine-sgx-sign is not installed or not in PATH. "
            "Install Gramine to enable SGX manifest signing.")
    manifest_path = os.path.join(build_dir, "app_gramine.manifest.toml")
    if not os.path.isfile(manifest_path):
        return False, {}, f"Manifest not found: {manifest_path}"
    gramine_manifest = shutil.which("gramine-manifest")
    if not gramine_manifest:
        return False, {}, (
            "gramine-manifest is not installed or not in PATH. "
            "Install Gramine to enable SGX manifest preprocessing.")
    processed = manifest_path.replace(".toml", ".processed.toml")
    try:
        subprocess.run(
            [gramine_manifest, "--no-check", manifest_path, processed],
            cwd=build_dir, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return False, {}, f"gramine-manifest preprocessing failed:\n{e.stderr}\n{e.stdout}"
    if not os.path.isfile(processed):
        return False, {}, f"gramine-manifest ran but did not produce output: {processed}"
    manifest_path = processed
    sig_file = os.path.join(build_dir, "app_gramine.sig")
    manifest_sgx = os.path.join(build_dir, "app_gramine.manifest.sgx")
    try:
        result = subprocess.run(
            [gramine_sign, "--manifest", manifest_path, "--output", manifest_sgx],
            cwd=build_dir, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        return False, {}, f"gramine-sgx-sign failed:\n{e.stderr}\n{e.stdout}"
    output = result.stdout + "\n" + result.stderr
    measurements: Dict[str, str] = {}
    mrenclave_match = (
        re.search(r"Measurement:\s*([0-9a-fA-F]{64})", output)
        or re.search(r"Measurement:\s*\n\s*([0-9a-fA-F]{64})", output)
        or re.search(r"mr_enclave\s*[:=]\s*([0-9a-fA-F]{64})", output))
    mrsigner_match = re.search(r"mr_signer\s*[:=]\s*([0-9a-fA-F]{64})", output)
    if mrenclave_match:
        measurements["MRENCLAVE"] = mrenclave_match.group(1).lower()
    if mrsigner_match:
        measurements["MRSIGNER"] = mrsigner_match.group(1).lower()
    if os.path.isfile(sig_file):
        sigstruct_view = shutil.which("gramine-sgx-sigstruct-view")
        if sigstruct_view:
            try:
                view_result = subprocess.run(
                    [sigstruct_view, sig_file], capture_output=True, text=True, check=True)
                view_out = view_result.stdout
                if not measurements.get("MRENCLAVE"):
                    m = re.search(r"mr_enclave\s*[:=]\s*([0-9a-fA-F]{64})", view_out)
                    if m:
                        measurements["MRENCLAVE"] = m.group(1).lower()
                if not measurements.get("MRSIGNER"):
                    s = re.search(r"mr_signer\s*[:=]\s*([0-9a-fA-F]{64})", view_out)
                    if s:
                        measurements["MRSIGNER"] = s.group(1).lower()
            except subprocess.CalledProcessError:
                pass
    if not measurements.get("MRENCLAVE"):
        return False, {}, f"Could not extract MRENCLAVE from signing output:\n{output}"
    return True, measurements, f"Successfully signed manifest. MRENCLAVE={measurements.get('MRENCLAVE', 'N/A')}"
