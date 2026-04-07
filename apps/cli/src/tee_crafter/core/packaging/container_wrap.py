"""Container wrapping utilities for Docker-in-TEE deployments.

Parses a user's Dockerfile to extract EXPOSE ports and CMD, then generates
the platform-specific proxy code that sits between the RA-TLS attestation
layer and the user's containerized application.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from typing import Optional


class ContainerValidationError(Exception):
    """Raised when the user's Dockerfile or container config is invalid."""


def parse_dockerfile(dockerfile_path: str) -> dict:
    """Extract metadata from a Dockerfile (EXPOSE ports, CMD, ENTRYPOINT).

    Returns a dict with keys:
        - ``expose_ports``: list[int] of exposed ports
        - ``cmd``: raw CMD string or None
        - ``entrypoint``: raw ENTRYPOINT string or None
        - ``from_image``: the base image from the final FROM
    """
    dockerfile_path = os.path.abspath(dockerfile_path)
    if not os.path.isfile(dockerfile_path):
        raise ContainerValidationError(f"Dockerfile not found: {dockerfile_path}")

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        content = f.read()

    expose_ports: list[int] = []
    cmd: Optional[str] = None
    entrypoint: Optional[str] = None
    from_image: Optional[str] = None

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue

        if stripped.upper().startswith("FROM "):
            parts = stripped.split()
            if len(parts) >= 2:
                from_image = parts[1]

        if stripped.upper().startswith("EXPOSE "):
            for token in stripped.split()[1:]:
                token = token.split("/")[0]  # strip /tcp, /udp
                try:
                    expose_ports.append(int(token))
                except ValueError:
                    pass

        if stripped.upper().startswith("CMD "):
            cmd = stripped[4:].strip()

        if stripped.upper().startswith("ENTRYPOINT "):
            entrypoint = stripped[11:].strip()

    return {
        "expose_ports": expose_ports,
        "cmd": cmd,
        "entrypoint": entrypoint,
        "from_image": from_image,
    }


def _validate_port(port: int) -> int:
    if not (1 <= port <= 65535):
        raise ContainerValidationError(
            f"Invalid container port {port}: must be between 1 and 65535"
        )
    return port


def detect_container_port(dockerfile_path: str, override: int | None = None) -> int:
    """Determine the port the user's container listens on.

    Priority: explicit ``override`` > first EXPOSE in Dockerfile > default 8080.
    """
    if override is not None:
        return _validate_port(override)
    meta = parse_dockerfile(dockerfile_path)
    if meta["expose_ports"]:
        return _validate_port(meta["expose_ports"][0])
    return 8080


def _inspect_image_field(image_tag: str, field: str) -> str | list[str] | None:
    """Read a single Config field from a Docker image via ``docker inspect``."""
    r = subprocess.run(
        ["docker", "inspect", f"--format={{{{json .Config.{field}}}}}", image_tag],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    val = json.loads(r.stdout.strip())
    return val


def extract_image_startup_cmd(image_tag: str) -> str:
    """Extract the effective startup command from a built Docker image.

    Combines ENTRYPOINT and CMD into a single shell command string.
    Raises ``ContainerValidationError`` if the image has no CMD/ENTRYPOINT.
    """
    ep = _inspect_image_field(image_tag, "Entrypoint")
    cmd = _inspect_image_field(image_tag, "Cmd")

    parts: list[str] = []
    if isinstance(ep, list):
        parts.extend(ep)
    if isinstance(cmd, list):
        parts.extend(cmd)

    if not parts:
        raise ContainerValidationError(
            "Docker image has no CMD or ENTRYPOINT — cannot determine how to "
            "start the user's server. Add a CMD to your Dockerfile."
        )
    return shlex.join(parts)


def extract_image_workdir(image_tag: str) -> str:
    """Return the WORKDIR from a Docker image, defaulting to ``/``."""
    val = _inspect_image_field(image_tag, "WorkingDir")
    return val if isinstance(val, str) and val else "/"


def generate_nitro_entrypoint(
    user_cmd: str, container_port: int, workdir: str = "/"
) -> str:
    """Generate the ``tee_entrypoint.sh`` that runs inside a Nitro EIF.

    The script brings up loopback networking, ``cd``s into the user's
    original WORKDIR, starts the user's HTTP server in the background,
    waits for the port to accept connections, then execs the TEE-Crafter
    RA-TLS/vsock proxy as PID 1.
    """
    return f"""\
#!/bin/sh
set -e

# Loopback is required for both the user server and the KMS vsock proxy
ip link set lo up 2>/dev/null || true
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

# Run user's server from its original WORKDIR
cd {shlex.quote(workdir)}

# Load app config/secrets into the environment before starting the user
# server.  Two sources, both optional:
#   * /tee-crafter-runtime/app.env  — plaintext config baked into the measured
#     image (no-BYOK --secrets-env path); empty when unused.
#   * /run/tee_crafter/app.env      — runtime-decrypted secrets written by the
#     in-TEE bootstrap after an attestation-gated release (BYOK --secrets-env).
#   * /tee-crafter-runtime/siem.env.public — non-secret SIEM settings, measured
#     with the image.  It has to be in the environment before app_vsock.py
#     execs, because that is what decides whether the in-enclave exporter
#     starts and whether siem_health arms the fail-closed gate.  The bearer
#     credential is not in this file; it arrives via the attested secrets path
#     above.
for _tc_envf in /tee-crafter-runtime/app.env /run/tee_crafter/app.env \\
                /tee-crafter-runtime/siem.env.public; do
  if [ -s "$_tc_envf" ]; then
    set -a
    . "$_tc_envf"
    set +a
  fi
done

# Start user's HTTP server in background
{user_cmd} &
USER_PID=$!

# Wait for the server to accept connections (up to 60 s)
ATTEMPTS=0
while [ $ATTEMPTS -lt 120 ]; do
  if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', {container_port})); s.close()" 2>/dev/null; then
    break
  fi
  ATTEMPTS=$((ATTEMPTS + 1))
  sleep 0.5
done

if [ $ATTEMPTS -ge 120 ]; then
  echo "ERROR: User server did not start on port {container_port} within 60 s" >&2
fi

# Hand off to TEE-Crafter RA-TLS proxy (foreground)
exec python3 /tee-crafter-runtime/app_vsock.py
"""


def generate_cvm_proxy_process_request(container_port: int) -> str:
    """Generate the ``process_request`` body that forwards to a local container.

    Used by CVM proxy templates (TDX/SNP) where the user's container runs
    alongside the RA-TLS server inside the confidential VM.
    """
    return f"""\
    import logging as _proxy_logging
    _proxy_logger = _proxy_logging.getLogger("tee_crafter.container_proxy")
    try:
        _resp = requests.post(
            "http://127.0.0.1:{container_port}/",
            json=data,
            timeout=300,
        )
        _resp.raise_for_status()
        return _resp.json()
    except requests.exceptions.ConnectionError:
        return {{"error": "Container not reachable", "status": "connection_refused"}}
    except requests.exceptions.Timeout:
        return {{"error": "Container request timed out", "status": "timeout"}}
    except Exception as _e:
        _proxy_logger.exception("Proxy forwarding error")
        return {{"error": "Internal proxy error", "status": "proxy_error"}}"""


def build_cvm_vsock_from_container(
    container_port: int,
) -> str:
    """Build an ``app_vsock.py``-compatible string where ``process_request``
    forwards to a local container.

    Produces the marker-delimited format that the downstream extractor
    (:func:`tee_crafter.cli.commands.deploy.platform._extract_user_code`) reads
    when staging the per-platform CVM/SGX app.
    """
    tpl_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates"
    )
    vsock_tpl_path = os.path.join(tpl_dir, "nitro", "app_vsock.template.py")
    with open(vsock_tpl_path, "r", encoding="utf-8") as f:
        template = f.read()

    imports = "import requests"
    logic = generate_cvm_proxy_process_request(container_port)

    result = template.replace("{user_imports}", imports)
    result = result.replace("{user_logic}", logic)
    return result
