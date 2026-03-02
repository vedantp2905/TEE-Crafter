import re
import os
import json
import subprocess
import shutil
import datetime
from typing import Dict, Tuple

def check_docker_running() -> bool:
    """Check if the Docker daemon is running and accessible."""
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(
            ["docker", "info"],
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

def pull_builder_image() -> None:
    """
    Ensures the nitro-cli builder image exists. If not present locally,
    builds a temporary builder image from amazonlinux:2023 with
    aws-nitro-enclaves-cli and docker installed.
    """
    builder_tag = "nitro-cli-builder:latest"
    
    # Check if the image already exists locally
    try:
        res = subprocess.run(["docker", "image", "inspect", builder_tag], capture_output=True)
        if res.returncode == 0:
            return  # Image exists
    except Exception:
        pass

    # Dockerfile content for the builder image
    dockerfile = """
FROM amazonlinux:2023

# Install dependencies for nitro-cli
RUN dnf update -y && \
    dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker

# We need the docker CLI inside to communicate with the host's docker daemon
# The entrypoint will just be nitro-cli
ENTRYPOINT ["nitro-cli"]
"""
    
    # Create a temporary directory to build the builder image
    temp_dir = f".nitro_builder_{datetime.datetime.now().strftime('%H%M%S')}"
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        with open(os.path.join(temp_dir, "Dockerfile"), "w") as f:
            f.write(dockerfile)
        
        subprocess.run(
            ["docker", "build", "-t", builder_tag, "."],
            cwd=temp_dir,
            check=True,
            capture_output=True
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def parse_enclave_cid(run_enclave_output: str) -> str:
    """
    Parses the output of `nitro-cli run-enclave` to extract the EnclaveCID.
    Handles both legacy text output and JSON output.
    """
    if not run_enclave_output:
        return ""
        
    # First, try JSON-style output (newer nitro-cli versions).
    try:
        data = json.loads(run_enclave_output)
        cid = data.get("EnclaveCID")
        if isinstance(cid, int) or (isinstance(cid, str) and cid.isdigit()):
            return str(cid)
    except Exception:
        # Not pure JSON; fall back to text/regex parsing below.
        pass

    # Look for EnclaveCID: 16 or "EnclaveCID": 16
    match = re.search(r"\"?EnclaveCID\"?\s*:\s*(\d+)", run_enclave_output)
    if match:
        return match.group(1)
    
    # Sometimes it prints it in a nested JSON block within stdout. Let's try to extract any JSON block.
    try:
        start = run_enclave_output.find('{')
        end = run_enclave_output.rfind('}') + 1
        if start != -1 and end != 0:
            json_str = run_enclave_output[start:end]
            data = json.loads(json_str)
            cid = data.get("EnclaveCID")
            if cid is not None:
                return str(cid)
    except Exception:
        pass
        
    return ""


def build_enclave(build_dir: str) -> Tuple[bool, Dict[str, str], str]:
    """
    Builds the Docker image from the given build_dir, then runs a local Docker 
    container to execute `nitro-cli build-enclave`, generating the .eif file 
    and extracting the PCR hashes.
    
    Returns:
        Tuple containing:
        - bool: Success status
        - Dict[str, str]: Dictionary of PCR hashes (PCR0, PCR1, PCR2) if successful
        - str: Error message or status message
    """
    if not check_docker_running():
        return False, {}, "Docker is not running or not installed. Please start Docker Desktop/daemon."

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    app_tag = f"nitro-app-{timestamp}:latest"
    # Parent instance is always Graviton (ARM); build image for linux/arm64.
    platform = "linux/arm64"

    # 1. Build the user's application image for Graviton (arm64)
    try:
        # Use Docker's built-in multi-arch support to target linux/arm64.
        # Modern Docker/BuildKit setups route this through buildx under the hood.
        subprocess.run(
            ["docker", "build", "--platform", platform, "-t", app_tag, "."],
            cwd=build_dir,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        return False, {}, f"Failed to build application Docker image:\n{e.stderr or ''}\n{e.stdout or ''}"

    # 2. Ensure builder image is available
    try:
        pull_builder_image()
    except Exception as e:
        # Cleanup app image
        subprocess.run(["docker", "rmi", app_tag], capture_output=True)
        return False, {}, f"Failed to prepare nitro-cli builder environment: {str(e)}"

    # 3. Run nitro-cli build-enclave via Docker
    eif_filename = "app.eif"
    
    # We mount the docker socket so the container can access the `app_tag` we just built
    # We mount the `build_dir` to `/workspace` so the resulting .eif is saved back to the host
    abs_build_dir = os.path.abspath(build_dir)
    
    cmd = [
        "docker", "run", "--rm",
        "--privileged",  # Required for some nitro-cli operations
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{abs_build_dir}:/workspace",
        "nitro-cli-builder:latest",
        "build-enclave",
        "--docker-uri", app_tag,
        "--output-file", f"/workspace/{eif_filename}"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        # 4. Parse the output for PCR hashes
        output_str = result.stdout
        
        # The output of nitro-cli build-enclave is typically JSON or contains JSON
        # We need to find the JSON block in case there's other output
        hashes = {}
        try:
            # Try to find JSON block
            start = output_str.find('{')
            end = output_str.rfind('}') + 1
            if start != -1 and end != 0:
                json_str = output_str[start:end]
                data = json.loads(json_str)
                measurements = data.get("Measurements", {})
                hashes["PCR0"] = measurements.get("PCR0", "")
                hashes["PCR1"] = measurements.get("PCR1", "")
                hashes["PCR2"] = measurements.get("PCR2", "")
            else:
                 # Fallback regex parsing if JSON fails or not found
                 pcr0 = re.search(r"PCR0\s*:\s*([0-9a-f]+)", output_str)
                 pcr1 = re.search(r"PCR1\s*:\s*([0-9a-f]+)", output_str)
                 pcr2 = re.search(r"PCR2\s*:\s*([0-9a-f]+)", output_str)

                 if pcr0: hashes["PCR0"] = pcr0.group(1)
                 if pcr1: hashes["PCR1"] = pcr1.group(1)
                 if pcr2: hashes["PCR2"] = pcr2.group(1)
        except Exception:
             pass # Will be caught by the check below

        
        if not hashes["PCR0"]:
            # Cleanup app image
            subprocess.run(["docker", "rmi", app_tag], capture_output=True)
            return False, {}, f"Could not find PCR0 in nitro-cli output: {output_str}"

        # 5. Cleanup the app image
        subprocess.run(["docker", "rmi", app_tag], capture_output=True)

        return True, hashes, f"Successfully built {eif_filename}"

    except subprocess.CalledProcessError as e:
        # Cleanup app image
        subprocess.run(["docker", "rmi", app_tag], capture_output=True)
        return False, {}, f"Failed to build Enclave Image File (EIF):\n{e.stderr}\n{e.stdout}"
    except Exception as e:
        # Cleanup app image
        subprocess.run(["docker", "rmi", app_tag], capture_output=True)
        return False, {}, f"Unexpected error during enclave build: {str(e)}"


def get_enclave_hashes(eif_path: str) -> Tuple[bool, Dict[str, str], str]:
    """
    Extracts PCR hashes from an existing .eif file using nitro-cli describe-eif.
    
    Returns:
        (success, hashes, message)
    """
    if not os.path.exists(eif_path):
        return False, {}, f"EIF file not found: {eif_path}"

    # Ensure builder image is available
    try:
        pull_builder_image()
    except Exception as e:
        return False, {}, f"Failed to prepare nitro-cli builder environment: {str(e)}"

    abs_eif_path = os.path.abspath(eif_path)
    eif_dir = os.path.dirname(abs_eif_path)
    eif_name = os.path.basename(abs_eif_path)
    
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{eif_dir}:/workspace",
        "nitro-cli-builder:latest",
        "describe-eif",
        "--eif-path", f"/workspace/{eif_name}"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        output_str = result.stdout
        hashes = {}
        
        # Parse output for PCRs
        try:
            # Try to find JSON block
            start = output_str.find('{')
            end = output_str.rfind('}') + 1
            if start != -1 and end != 0:
                json_str = output_str[start:end]
                data = json.loads(json_str)
                measurements = data.get("Measurements", {})
                hashes["PCR0"] = measurements.get("PCR0", "")
                hashes["PCR1"] = measurements.get("PCR1", "")
                hashes["PCR2"] = measurements.get("PCR2", "")
            else:
                 # Fallback regex parsing if JSON fails or not found
                 pcr0 = re.search(r"PCR0\s*:\s*([0-9a-f]+)", output_str)
                 pcr1 = re.search(r"PCR1\s*:\s*([0-9a-f]+)", output_str)
                 pcr2 = re.search(r"PCR2\s*:\s*([0-9a-f]+)", output_str)
                 
                 if pcr0: hashes["PCR0"] = pcr0.group(1)
                 if pcr1: hashes["PCR1"] = pcr1.group(1)
                 if pcr2: hashes["PCR2"] = pcr2.group(1)

        except Exception:
             pass

        if not hashes.get("PCR0"):
            return False, {}, f"Could not extract PCR hashes from output: {output_str}"

        return True, hashes, "Successfully extracted hashes."

    except subprocess.CalledProcessError as e:
        return False, {}, f"Failed to describe EIF:\n{e.stderr}\n{e.stdout}"
    except Exception as e:
        return False, {}, f"Unexpected error during EIF description: {str(e)}"
