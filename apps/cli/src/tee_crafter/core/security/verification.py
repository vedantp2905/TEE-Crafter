"""Container build verification.

A single deterministic helper that performs a ``docker build`` dry-run of a
staged build directory. Used by the Nitro EIF path (``flow_build``) to surface
Dockerfile / dependency errors before the slow ``nitro-cli build-enclave`` step.

This module deliberately contains **no** source-translation or handler-shape
heuristics — the product runs the user's container as-is, so the only thing
worth verifying locally is that the image actually builds.
"""

import os
import shutil
import subprocess
import datetime
from typing import Tuple


def verify_docker_build(build_dir: str, platform: str | None = None) -> Tuple[bool, str]:
    """Attempt to build the Dockerfile in *build_dir* as a pre-flight dry-run.

    Returns ``(True, build_output)`` or ``(False, error_output)``.

    When *platform* is set (e.g. ``linux/amd64`` for Nitro on x86), it is passed
    to ``docker build --platform`` so the dry-run matches ``build_enclave``.
    Without it, Docker defaults to the host arch (e.g. linux/arm64 on Apple
    Silicon), which breaks ``FROM`` of a single-arch image built for the EC2
    target.
    """
    if not shutil.which("docker"):
        return False, "Docker is not installed or not in PATH."

    timestamp = datetime.datetime.now().strftime("%H%M%S")
    tag_name = f"nitro-verify-{timestamp}"

    build_cmd = ["docker", "build", "-t", tag_name, "."]
    env = os.environ.copy()
    if platform:
        env["DOCKER_BUILDKIT"] = "1"
        build_cmd = ["docker", "build", "--platform", platform, "--load", "-t", tag_name, "."]

    try:
        result = subprocess.run(
            build_cmd,
            cwd=build_dir,
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        subprocess.run(["docker", "rmi", tag_name], capture_output=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, f"Docker Build Failed:\n{e.stderr}\n{e.stdout}"
    except Exception as e:
        return False, f"Verification Error: {str(e)}"
