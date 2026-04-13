"""Azure VM management via Azure Bastion – SSH/SCP operations.

Replaces direct SSH with Azure Bastion tunnels, mirroring AWS SSM
Session Manager for zero-public-IP secure access.
"""
import logging
import os
import subprocess
import time
from typing import Tuple

from tee_crafter.core.env_flags import env_hatch_open
from tee_crafter.core.remote.azure_ssh_tunnel import (  # noqa: F401 – re-exports
    BastionTunnel, SSHPortForward,
)

logger = logging.getLogger(__name__)

DEBUG = any(
    env_hatch_open(var)
    for var in ("TEE_CRAFTER_DEBUG_SGX", "TEE_CRAFTER_DEBUG_TDX", "TEE_CRAFTER_DEBUG")
)
if DEBUG:
    logging.basicConfig(level=logging.DEBUG, format="[tee_crafter] %(levelname)s %(name)s: %(message)s")
    for noisy_logger in (
        "botocore", "boto3", "urllib3", "s3transfer",
        "aiosqlite", "sqlalchemy.engine", "sqlalchemy.pool",
    ):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=30", "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3", "-o", "LogLevel=ERROR",
]

# ---------------------------------------------------------------------------
#  SSH connection multiplexing (ControlMaster/ControlPath)
# ---------------------------------------------------------------------------
#
# A typical Azure deploy issues ~30-40 ssh/scp calls (setup, capability
# probes, env upload, service start, journal tails, …).  Without
# multiplexing each one repeats the full TCP + SSH KEX + auth handshake,
# costing ~1-3 s per call, all on top of the Bastion local listener
# which itself has connection-rate limits and is the most common source
# of the ``kex_exchange_identification`` flakes we now retry around.
#
# OpenSSH's ControlMaster lets the first call open a master channel
# (over Bastion's localhost port-forward), then every subsequent call
# reuses that established channel as a sub-session — sub-second connect
# time, no fresh handshake, no extra load on Bastion's KEX limiter.
# ControlPersist keeps the master alive for a few minutes after the
# last client disconnects so the next phase doesn't pay the cost.
#
# Footprint:
# - Path lives under ``$TMPDIR`` so concurrent deploys don't collide.
# - Keyed by ``%h:%p:%r`` (host, port, user) so unrelated tunnels
#   stay isolated.
# - Disabled via ``TEE_CRAFTER_SSH_MUX=0`` for debugging.

# The directory choice and the ControlPath length check live in
# `core.remote.ssh_mux`, shared with gcp_ssh: a ControlPath is a Unix socket
# path capped at ~104 bytes, and building it from $TMPDIR unconditionally
# breaks on macOS hosts.  See that module for the full reasoning.
from tee_crafter.core.remote.ssh_mux import (  # noqa: E402
    mux_enabled as _mux_enabled,
    ssh_mux_opts as _ssh_mux_opts,
)


def close_ssh_mux(host: str = "localhost", port: int = 22, user: str = "azureuser",
                  ssh_private_key_path: str | None = None) -> None:
    """Tear down the multiplexed SSH master for *host:port:user*.

    Called by the orchestrator just before the Bastion tunnel is torn
    down — otherwise the master would linger for ``ControlPersist``
    seconds against a now-dead local listener and the next deploy
    would block trying to reuse a dead socket.
    """
    if not _mux_enabled():
        return
    try:
        argv = ["ssh", *_SSH_OPTS, *_ssh_mux_opts()]
        if ssh_private_key_path:
            argv += _ssh_key_args(ssh_private_key_path)
        argv += [
            "-O", "exit", "-p", str(port), f"{user}@{host}",
        ]
        subprocess.run(argv, capture_output=True, text=True, timeout=5)
    except Exception:
        pass

# See ``core/remote/gcp_ssh.py`` for the rationale: these substrings only
# appear when the local ssh/scp client failed at the transport layer (e.g.
# Azure Bastion local listener reset, sshd MaxStartups limiter, etc.) and
# are therefore safe to retry without masking genuine remote-command errors.
_TRANSIENT_SSH_MARKERS = (
    "kex_exchange_identification",
    "ssh_exchange_identification",
    "connection reset by peer",
    "connection closed by",
    "connection refused",
    "banner exchange",
    "client_loop: send disconnect",
    "port forwarding failed",
    "broken pipe",
    "no route to host",
)


def _is_transient_ssh_error(stream: str) -> bool:
    """Return True iff stderr/stdout looks like a retryable SSH transport error."""
    if not stream:
        return False
    low = stream.lower()
    return any(marker in low for marker in _TRANSIENT_SSH_MARKERS)


def _ssh_retry_config() -> Tuple[int, float]:
    """Read retry knobs from env (shared with GCP helper)."""
    try:
        retries = int(os.getenv("TEE_CRAFTER_SSH_RETRIES", "4"))
    except ValueError:
        retries = 4
    try:
        backoff = float(os.getenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", "2.0"))
    except ValueError:
        backoff = 2.0
    return max(1, min(retries, 10)), max(0.1, min(backoff, 30.0))


def _run_with_ssh_retry(argv: list, *, timeout: int, op_label: str = "SSH"):
    """Run ``subprocess.run(argv)`` with bounded retry on transient SSH errors."""
    retries, base_backoff = _ssh_retry_config()
    last_result = None
    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            if attempt < retries:
                sleep_s = min(base_backoff * (2 ** (attempt - 1)), 30.0)
                if DEBUG:
                    logger.info("[%s] attempt %d/%d timed out after %ss — retrying in %.1fs",
                                op_label, attempt, retries, timeout, sleep_s)
                time.sleep(sleep_s)
                continue
            return subprocess.CompletedProcess(
                argv, 124, "",
                f"{op_label} command timed out after {timeout}s (attempt {attempt}/{retries})")
        if result.returncode == 0:
            return result
        combined = (result.stderr or "") + "\n" + (result.stdout or "")
        if attempt < retries and _is_transient_ssh_error(combined):
            sleep_s = min(base_backoff * (2 ** (attempt - 1)), 30.0)
            snippet = (result.stderr or result.stdout or "").strip()
            if DEBUG:
                logger.info(
                    "[%s] transient SSH error on attempt %d/%d (rc=%d) — retrying in %.1fs: %s",
                    op_label, attempt, retries, result.returncode, sleep_s, snippet[:200])
            last_result = result
            time.sleep(sleep_s)
            continue
        return result
    return last_result if last_result is not None else subprocess.CompletedProcess(
        argv, 1, "", f"{op_label}: retries exhausted")


def _ssh_key_args(ssh_private_key_path: str) -> list[str]:
    return ["-i", ssh_private_key_path]


def wait_for_ssh(ssh_private_key_path: str, user: str = "azureuser",
                 timeout: int = 300, *, host: str = "localhost", port: int = 22) -> bool:
    """Wait until SSH is reachable on host:<port>.

    Uses exponential-backoff polling (2 s → 10 s cap) instead of a
    flat 10 s sleep so we discover SSH-ready VMs ~7-9 s earlier on the
    common case (custom AMI, no cloud-init churn).  When the VM is
    still booting we naturally back off to avoid hammering the
    Bastion local listener.
    """
    if not os.path.isfile(ssh_private_key_path):
        logger.error("[SSH] Key file does not exist: %s (cwd=%s)", ssh_private_key_path, os.getcwd())
        return False
    start = time.time()
    attempt = 0
    last_err = ""
    sleep_s = 2.0
    while time.time() - start < timeout:
        attempt += 1
        try:
            result = subprocess.run(
                ["ssh", *_SSH_OPTS, *_ssh_mux_opts(),
                 *_ssh_key_args(ssh_private_key_path),
                 "-p", str(port), f"{user}@{host}", "echo ok"],
                capture_output=True, text=True, timeout=20)
            if result.returncode == 0 and "ok" in result.stdout:
                return True
            err_snippet = (result.stderr or "").strip()[:200]
            if err_snippet != last_err:
                logger.debug("[SSH] attempt %d rc=%d: %s", attempt, result.returncode, err_snippet)
                last_err = err_snippet
        except subprocess.TimeoutExpired:
            logger.debug("[SSH] attempt %d timed out", attempt)
        except Exception as e:
            logger.debug("[SSH] attempt %d exception: %s", attempt, e)
        time.sleep(sleep_s)
        sleep_s = min(sleep_s * 1.5, 10.0)
    logger.warning("[SSH] gave up after %d attempts (%ds). Last error: %s",
                   attempt, int(time.time() - start), last_err)
    return False


def run_ssh_command(command: str, ssh_private_key_path: str, user: str = "azureuser",
                    timeout: int = 120, *, host: str = "localhost", port: int = 22) -> Tuple[bool, str, str]:
    """Execute a shell command on the VM via SSH. Returns (success, stdout, stderr).

    Transient SSH transport errors (KEX resets, banner exchange failures,
    refused connections from the Bastion local listener) are retried with
    bounded exponential backoff. Genuine remote-command failures are not
    retried.
    """
    if DEBUG:
        preview = command[:200] + "..." if len(command) > 200 else command
        logger.info("[SSH] %s:%d cmd=%s", host, port, preview)
    try:
        result = _run_with_ssh_retry(
            ["ssh", *_SSH_OPTS, *_ssh_mux_opts(),
             *_ssh_key_args(ssh_private_key_path),
             "-p", str(port), f"{user}@{host}", command],
            timeout=max(timeout, 30), op_label="SSH")
        success = result.returncode == 0
        if DEBUG and not success:
            logger.warning("[SSH] rc=%d stdout=%d bytes stderr=%d bytes",
                           result.returncode, len(result.stdout), len(result.stderr))
        return success, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def upload_file_via_scp(local_path: str, remote_path: str, ssh_private_key_path: str,
                        user: str = "azureuser", timeout: int = 120,
                        *, host: str = "localhost", port: int = 22) -> Tuple[bool, str]:
    """Upload a single file to the VM via SCP (with transient-error retry)."""
    if DEBUG:
        logger.info("[SCP] %s -> %s@%s:%d:%s", local_path, user, host, port, remote_path)
    remote_dir = os.path.dirname(remote_path)
    if remote_dir:
        run_ssh_command(f"sudo mkdir -p '{remote_dir}'", ssh_private_key_path, user,
                        timeout=30, host=host, port=port)
    try:
        result = _run_with_ssh_retry(
            ["scp", *_SSH_OPTS, *_ssh_mux_opts(),
             *_ssh_key_args(ssh_private_key_path),
             "-P", str(port), local_path, f"{user}@{host}:{remote_path}"],
            timeout=timeout, op_label="SCP")
        if result.returncode == 0:
            return True, "Success"
        return False, f"SCP failed: {(result.stderr or result.stdout or '').strip()}"
    except Exception as e:
        return False, str(e)


def upload_directory_via_scp(local_dir: str, remote_dir: str, ssh_private_key_path: str,
                             user: str = "azureuser", timeout: int = 300,
                             *, host: str = "localhost", port: int = 22) -> Tuple[bool, str]:
    """Recursively upload a directory to the VM via SCP (with transient-error retry)."""
    run_ssh_command(f"sudo mkdir -p '{remote_dir}'", ssh_private_key_path, user,
                    timeout=30, host=host, port=port)
    try:
        result = _run_with_ssh_retry(
            ["scp", "-r", *_SSH_OPTS, *_ssh_mux_opts(),
             *_ssh_key_args(ssh_private_key_path),
             "-P", str(port), local_dir, f"{user}@{host}:{remote_dir}"],
            timeout=timeout, op_label="SCP")
        if result.returncode == 0:
            return True, "Success"
        return False, f"SCP failed: {(result.stderr or result.stdout or '').strip()}"
    except Exception as e:
        return False, str(e)


def download_file_via_scp(remote_path: str, local_path: str, ssh_private_key_path: str,
                          user: str = "azureuser", timeout: int = 600,
                          *, host: str = "localhost", port: int = 22) -> Tuple[bool, str]:
    """Download a single file from the VM via SCP (with transient-error retry)."""
    if DEBUG:
        logger.info("[SCP-down] %s@%s:%d:%s -> %s", user, host, port, remote_path, local_path)
    local_dir = os.path.dirname(local_path) or "."
    os.makedirs(local_dir, exist_ok=True)
    try:
        result = _run_with_ssh_retry(
            ["scp", *_SSH_OPTS, *_ssh_mux_opts(),
             *_ssh_key_args(ssh_private_key_path),
             "-P", str(port), f"{user}@{host}:{remote_path}", local_path],
            timeout=timeout, op_label="SCP")
        if result.returncode == 0:
            return True, "Success"
        return False, f"SCP download failed: {(result.stderr or result.stdout or '').strip()}"
    except Exception as e:
        return False, str(e)


def download_directory_via_scp(remote_dir: str, local_dir: str, ssh_private_key_path: str,
                               user: str = "azureuser", timeout: int = 900,
                               *, host: str = "localhost", port: int = 22) -> Tuple[bool, str]:
    """Recursively download a directory from the VM via SCP (with transient-error retry)."""
    os.makedirs(local_dir, exist_ok=True)
    try:
        result = _run_with_ssh_retry(
            ["scp", "-r", *_SSH_OPTS, *_ssh_mux_opts(),
             *_ssh_key_args(ssh_private_key_path),
             "-P", str(port), f"{user}@{host}:{remote_dir}", local_dir],
            timeout=timeout, op_label="SCP")
        if result.returncode == 0:
            return True, "Success"
        return False, f"SCP download failed: {(result.stderr or result.stdout or '').strip()}"
    except Exception as e:
        return False, str(e)
