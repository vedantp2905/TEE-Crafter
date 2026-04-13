"""GCP IAP tunnel and SSH port-forwarding classes."""
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
    for var in ("TEE_CRAFTER_DEBUG_GCP", "TEE_CRAFTER_DEBUG")
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


class IAPTunnel:
    """GCP IAP TCP tunnel providing local port forwarding to a VM."""

    def __init__(self, instance_name: str, zone: str, project: str, remote_port: int):
        self.instance_name = instance_name
        self.zone = zone
        self.project = project
        self.remote_port = remote_port
        self.local_port: int = 0
        self._proc: Optional[subprocess.Popen] = None
        self._log_file = None

    _TRANSIENT_ERRORS = ("Failed to lookup instance", "failed to connect to backend",
                         "connection refused", "Could not connect", "try again")

    def start(self, timeout: int = 300) -> int:
        import tempfile as _tmpmod
        deadline = time.time() + timeout
        last_log = ""

        while time.time() < deadline:
            self.local_port = _find_free_port()
            cmd = [
                "gcloud", "compute", "start-iap-tunnel",
                self.instance_name, str(self.remote_port),
                f"--local-host-port=localhost:{self.local_port}",
                f"--zone={self.zone}", f"--project={self.project}",
            ]
            if DEBUG:
                logger.info("[IAP tunnel] starting: local=%d -> remote=%d instance=%s zone=%s",
                            self.local_port, self.remote_port, self.instance_name, self.zone)
            self._log_file = _tmpmod.NamedTemporaryFile(
                mode="w", suffix="-iap-tunnel.log", delete=False)
            self._proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=self._log_file, stderr=subprocess.STDOUT)

            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", self.local_port), timeout=2):
                        if DEBUG:
                            logger.info("[IAP tunnel] ready on localhost:%d", self.local_port)
                        return self.local_port
                except OSError:
                    if self._proc.poll() is not None:
                        last_log = self._read_log_tail()
                        if any(err in last_log for err in self._TRANSIENT_ERRORS):
                            if DEBUG:
                                logger.info("[IAP tunnel] transient failure, retrying in 10s…")
                            # Ensure the previous tunnel process/log are cleaned up before retrying.
                            self.stop()
                            time.sleep(10)
                            break  # retry outer loop
                        raise RuntimeError(
                            f"IAP tunnel exited early (rc={self._proc.returncode}): {last_log}")
                    time.sleep(3)
            else:
                last_log = self._read_log_tail()
                self.stop()
                raise TimeoutError(
                    f"IAP tunnel to port {self.remote_port} did not become ready "
                    f"within {timeout}s. Tunnel log:\n{last_log}")

        self.stop()
        raise TimeoutError(
            f"IAP tunnel to port {self.remote_port} did not become ready "
            f"within {timeout}s (retries exhausted). Last log:\n{last_log}")

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
        # Close the SSH multiplexed master before the IAP tunnel goes
        # away, otherwise the next deploy blocks on a dead socket while
        # ControlPersist still considers the master alive.
        if getattr(self, "local_port", 0):
            try:
                from tee_crafter.core.remote.gcp_ssh import close_ssh_mux
                close_ssh_mux(host="localhost", port=self.local_port)
            except Exception:
                pass
        if self._proc and self._proc.poll() is None:
            if DEBUG:
                logger.info("[IAP tunnel] stopping pid=%d", self._proc.pid)
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

    def __enter__(self) -> "IAPTunnel":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


class SSHPortForward:
    """Local port forward through an existing SSH tunnel (via IAP)."""

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
