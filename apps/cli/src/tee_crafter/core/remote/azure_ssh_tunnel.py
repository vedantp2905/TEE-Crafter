"""Azure Bastion tunnel and SSH port-forwarding classes."""
import logging
import os
import socket
import subprocess
import time
from typing import Optional
from tee_crafter.core.env_flags import env_hatch_open

logger = logging.getLogger(__name__)

DEBUG = any(
    env_hatch_open(var)
    for var in ("TEE_CRAFTER_DEBUG_SGX", "TEE_CRAFTER_DEBUG_TDX", "TEE_CRAFTER_DEBUG")
)

_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=30", "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3", "-o", "LogLevel=ERROR",
]


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ssh_key_args(ssh_private_key_path: str) -> list[str]:
    return ["-i", ssh_private_key_path]


class BastionTunnel:
    """Azure Bastion tunnel providing local port forwarding to a VM."""

    def __init__(self, bastion_name: str, resource_group: str,
                 vm_resource_id: str, resource_port: int):
        self.bastion_name = bastion_name
        self.resource_group = resource_group
        self.vm_resource_id = vm_resource_id
        self.resource_port = resource_port
        self.local_port: int = 0
        self._proc: Optional[subprocess.Popen] = None
        self._log_file = None

    def start(self, timeout: int = 300) -> int:
        import tempfile as _tmpmod
        self.local_port = _find_free_port()
        cmd = [
            "az", "network", "bastion", "tunnel",
            "--name", self.bastion_name, "--resource-group", self.resource_group,
            "--target-resource-id", self.vm_resource_id,
            "--resource-port", str(self.resource_port), "--port", str(self.local_port),
        ]
        if DEBUG:
            logger.info("[Bastion tunnel] starting: local=%d -> remote=%d vm=%s",
                        self.local_port, self.resource_port, self.vm_resource_id)
        self._log_file = _tmpmod.NamedTemporaryFile(
            mode="w", suffix="-bastion-tunnel.log", delete=False)
        self._proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=self._log_file, stderr=subprocess.STDOUT)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=2):
                    if DEBUG:
                        logger.info("[Bastion tunnel] ready on localhost:%d", self.local_port)
                    return self.local_port
            except OSError:
                if self._proc.poll() is not None:
                    log_tail = self._read_log_tail()
                    raise RuntimeError(
                        f"Bastion tunnel exited early (rc={self._proc.returncode}): {log_tail}")
                time.sleep(3)
        log_tail = self._read_log_tail()
        self.stop()
        raise TimeoutError(
            f"Bastion tunnel to port {self.resource_port} did not become ready "
            f"within {timeout}s. Tunnel log:\n{log_tail}")

    def _read_log_tail(self, max_bytes: int = 2000) -> str:
        try:
            if self._log_file:
                self._log_file.flush()
                with open(self._log_file.name, "r", errors="replace") as f:
                    content = f.read()
                return content[-max_bytes:] if len(content) > max_bytes else content
        except Exception:
            pass
        return "(no log)"

    def stop(self) -> None:
        # Tear down the SSH ControlMaster *before* killing the Bastion
        # tunnel.  Otherwise the master would linger for ``ControlPersist``
        # seconds against a now-dead local listener; the next deploy
        # would then block trying to reuse a dead socket.
        if self.local_port:
            try:
                from tee_crafter.core.remote.azure_ssh import close_ssh_mux
                close_ssh_mux(host="localhost", port=self.local_port)
            except Exception:
                pass
        if self._proc and self._proc.poll() is None:
            if DEBUG:
                logger.info("[Bastion tunnel] stopping pid=%d", self._proc.pid)
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if hasattr(self, "_log_file") and self._log_file:
            try:
                self._log_file.close()
                os.unlink(self._log_file.name)
            except Exception:
                pass
            self._log_file = None

    def __enter__(self) -> "BastionTunnel":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


class SSHPortForward:
    """Local port forward through an existing SSH tunnel."""

    def __init__(self, ssh_private_key_path: str, user: str,
                 ssh_tunnel_port: int, remote_port: int):
        self.ssh_key = ssh_private_key_path
        self.user = user
        self.ssh_tunnel_port = ssh_tunnel_port
        self.remote_port = remote_port
        self.local_port: int = 0
        self._proc: Optional[subprocess.Popen] = None

    def start(self, timeout: int = 30) -> int:
        self.local_port = _find_free_port()
        cmd = [
            "ssh", *_SSH_OPTS, *_ssh_key_args(self.ssh_key),
            "-p", str(self.ssh_tunnel_port),
            "-L", f"{self.local_port}:localhost:{self.remote_port}",
            "-N", f"{self.user}@localhost",
        ]
        if DEBUG:
            logger.info("[SSH-fwd] %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=2):
                    if DEBUG:
                        logger.info("[SSH-fwd] ready localhost:%d -> VM:%d",
                                    self.local_port, self.remote_port)
                    return self.local_port
            except OSError:
                if self._proc.poll() is not None:
                    raise RuntimeError(
                        f"SSH port forward exited early (rc={self._proc.returncode})")
                time.sleep(1)
        self.stop()
        raise TimeoutError(
            f"SSH port forward localhost:{self.local_port} -> VM:{self.remote_port} "
            f"did not become ready within {timeout}s")

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def __enter__(self) -> "SSHPortForward":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
