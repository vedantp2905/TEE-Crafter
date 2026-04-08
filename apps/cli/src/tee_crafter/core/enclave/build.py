"""Nitro Enclave EIF build and hash extraction."""
import json
import os
import re
import subprocess
import datetime
from typing import Dict, Tuple


def _enc():
    from tee_crafter.core import enclave
    return enclave


def build_enclave(
    build_dir: str,
    platform: str = "linux/amd64",
) -> Tuple[bool, Dict[str, str], str]:
    """Build the Docker image and run ``nitro-cli build-enclave`` to produce the .eif.

    *platform* is the Docker ``--platform`` value (e.g. ``linux/arm64``).
    Callers resolve it once via ``resolve_docker_platform()`` and pass it in.

    Returns (success, pcr_hashes, message).
    """
    enc = _enc()
    if not enc.check_docker_running():
        return False, {}, "Docker is not running or not installed. Please start Docker Desktop/daemon."
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    app_tag = f"nitro-app-{timestamp}:latest"
    build_cmd = ["docker", "build", "--platform", platform, "--load"]
    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"
    build_cmd.extend(["-t", app_tag, "."])
    try:
        subprocess.run(build_cmd, cwd=build_dir, capture_output=True, text=True, check=True, env=env)
    except subprocess.CalledProcessError as e:
        return False, {}, f"Failed to build application Docker image:\n{e.stderr or ''}\n{e.stdout or ''}"
    try:
        builder_tag = enc.pull_builder_image(platform)
    except Exception as e:
        subprocess.run(["docker", "rmi", app_tag], capture_output=True)
        return False, {}, f"Failed to prepare nitro-cli builder environment: {str(e)}"
    eif_filename = "app.eif"
    abs_build_dir = os.path.abspath(build_dir)
    container_name = f"nitro-eif-builder-{timestamp}"
    run_cmd = ["docker", "run", "--name", container_name, "--platform", platform]
    run_cmd.extend([
        "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock",
        builder_tag, "build-enclave", "--docker-uri", app_tag,
        "--output-file", f"/tmp/{eif_filename}",
    ])
    try:
        result = subprocess.run(run_cmd, capture_output=True, text=True, check=True)
        cp_result = subprocess.run(
            ["docker", "cp", f"{container_name}:/tmp/{eif_filename}",
             os.path.join(abs_build_dir, eif_filename)],
            capture_output=True, text=True)
        if cp_result.returncode != 0:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
            subprocess.run(["docker", "rmi", app_tag], capture_output=True)
            return False, {}, f"Failed to copy EIF from builder container:\n{cp_result.stderr}"
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        hashes = _parse_pcr_output(result.stdout)
        if not hashes.get("PCR0"):
            subprocess.run(["docker", "rmi", app_tag], capture_output=True)
            return False, {}, f"Could not find PCR0 in nitro-cli output: {result.stdout}"
        subprocess.run(["docker", "rmi", app_tag], capture_output=True)
        # Nitro-7: persist the canonical PCR set next to the EIF so that
        # downstream tooling (clients, auditors, CI) can pin against a
        # single authoritative file instead of re-parsing `nitro-cli
        # describe-eif` output every time.  We intentionally write a
        # UTF-8, sorted, stable-JSON representation so that the file
        # hashes deterministically across runs for the same EIF.
        try:
            pcrs_path = os.path.join(abs_build_dir, "pcrs.json")
            canonical = {
                "eif_filename": eif_filename,
                "built_at_utc": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "pcrs": {k: v for k, v in sorted(hashes.items())},
                "source": "nitro-cli build-enclave",
                "schema": 1,
            }
            with open(pcrs_path, "w", encoding="utf-8") as _pf:
                json.dump(canonical, _pf, indent=2, sort_keys=True)
                _pf.write("\n")
            try:
                os.chmod(pcrs_path, 0o644)
            except OSError:
                pass
        except Exception:
            pass
        return True, hashes, f"Successfully built {eif_filename}"
    except subprocess.CalledProcessError as e:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        subprocess.run(["docker", "rmi", app_tag], capture_output=True)
        detail = f"{e.stderr}\n{e.stdout}"
        # nitro-cli reports only "E48 EIF building error" plus a Go backtrace
        # when linuxkit dies under QEMU emulation.  Append the cause and the
        # two configurations measured to work.
        return False, {}, (
            f"Failed to build Enclave Image File (EIF):\n{detail}"
            + enc.emulated_eif_build_diagnosis(platform, detail)
        )
    except Exception as e:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        subprocess.run(["docker", "rmi", app_tag], capture_output=True)
        return False, {}, f"Unexpected error during enclave build: {str(e)}"


def get_enclave_hashes(eif_path: str) -> Tuple[bool, Dict[str, str], str]:
    """Extract PCR hashes from an existing .eif file using ``nitro-cli describe-eif``."""
    if not os.path.exists(eif_path):
        return False, {}, f"EIF file not found: {eif_path}"
    try:
        builder_tag = _enc().pull_builder_image()
    except Exception as e:
        return False, {}, f"Failed to prepare nitro-cli builder environment: {str(e)}"
    abs_eif_path = os.path.abspath(eif_path)
    # Stage the EIF with `docker cp` rather than a bind mount.  A `-v` source
    # path is resolved by the *host* daemon, but the CLI normally runs inside
    # its own re-exec container (`cli/main.py::_exec_tee_crafter_in_docker`)
    # with only the docker socket passed through.  A container-local path such
    # as /workspace/builds/<build>/ therefore does not exist on the host, so
    # Docker silently creates an *empty* directory there and mounts that;
    # nitro-cli then reports "E35 EIF file parsing error" against a perfectly
    # valid EIF and `deploy-from-build` fails 100% of the time on nitro-aws.
    # `docker cp` streams the file through the daemon API, so it is correct
    # whether or not the caller is itself containerised — the same reason
    # `build_enclave` above copies the EIF *out* with `docker cp`.
    container_name = f"nitro-eif-describe-{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    created = subprocess.run(
        ["docker", "create", "--name", container_name, builder_tag,
         "describe-eif", "--eif-path", "/tmp/app.eif"],
        capture_output=True, text=True)
    if created.returncode != 0:
        return False, {}, f"Failed to create describe-eif container:\n{created.stderr}"
    try:
        cp = subprocess.run(
            ["docker", "cp", abs_eif_path, f"{container_name}:/tmp/app.eif"],
            capture_output=True, text=True)
        if cp.returncode != 0:
            return False, {}, f"Failed to copy EIF into describe container:\n{cp.stderr}"
        result = subprocess.run(["docker", "start", "-a", container_name],
                                capture_output=True, text=True)
        if result.returncode != 0:
            return False, {}, f"Failed to describe EIF:\n{result.stderr}\n{result.stdout}"
        hashes = _parse_pcr_output(result.stdout)
        if not hashes.get("PCR0"):
            return False, {}, f"Could not extract PCR hashes from output: {result.stdout}"
        return True, hashes, "Successfully extracted hashes."
    except Exception as e:
        return False, {}, f"Unexpected error during EIF description: {str(e)}"
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


def _parse_pcr_output(output_str: str) -> Dict[str, str]:
    """Parse PCR hashes from nitro-cli JSON or text output."""
    hashes: Dict[str, str] = {}
    try:
        start = output_str.find('{')
        end = output_str.rfind('}') + 1
        if start != -1 and end != 0:
            data = json.loads(output_str[start:end])
            measurements = data.get("Measurements", {})
            hashes["PCR0"] = measurements.get("PCR0", "")
            hashes["PCR1"] = measurements.get("PCR1", "")
            hashes["PCR2"] = measurements.get("PCR2", "")
        else:
            pcr0 = re.search(r"PCR0\s*:\s*([0-9a-f]+)", output_str)
            pcr1 = re.search(r"PCR1\s*:\s*([0-9a-f]+)", output_str)
            pcr2 = re.search(r"PCR2\s*:\s*([0-9a-f]+)", output_str)
            if pcr0: hashes["PCR0"] = pcr0.group(1)
            if pcr1: hashes["PCR1"] = pcr1.group(1)
            if pcr2: hashes["PCR2"] = pcr2.group(1)
    except Exception:
        pass
    return hashes
