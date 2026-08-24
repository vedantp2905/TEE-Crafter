"""AWS Systems Manager (SSM) operations for EC2 instances."""
import time
import json
import logging
import socket
import subprocess
from typing import Tuple, Optional

import boto3
from botocore.exceptions import ClientError

from tee_crafter.core.remote.ssm_s3 import upload_file_via_s3  # noqa: F401 – re-export
from tee_crafter.core.env_flags import env_hatch_open

logger = logging.getLogger(__name__)

DEBUG = any(
    env_hatch_open(var)
    for var in ("TEE_CRAFTER_DEBUG_SNP_AWS", "TEE_CRAFTER_DEBUG_NITRO", "TEE_CRAFTER_DEBUG")
)
if DEBUG:
    logging.basicConfig(level=logging.DEBUG, format="[tee_crafter] %(levelname)s %(name)s: %(message)s")
    for noisy_logger in (
        "botocore", "boto3", "urllib3", "s3transfer",
        "aiosqlite", "sqlalchemy.engine", "sqlalchemy.pool",
    ):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def wait_for_ssm(instance_id: str, region: str, timeout: int = 300) -> bool:
    """Wait for the EC2 instance to become online and registered with SSM."""
    ssm = boto3.client('ssm', region_name=region)
    start_time = time.time()
    last_error = None
    while time.time() - start_time < timeout:
        try:
            response = ssm.describe_instance_information(
                InstanceInformationFilterList=[
                    {'key': 'InstanceIds', 'valueSet': [instance_id]}])
            info_list = response.get('InstanceInformationList', [])
            if info_list and info_list[0].get('PingStatus') == 'Online':
                return True
            last_error = None
        except ClientError as e:
            last_error = e
            logger.debug("SSM describe_instance_information: %s", e)
        time.sleep(10)
    if last_error:
        logger.warning("SSM wait timed out. instance_id=%s region=%s last_error=%s",
                       instance_id, region, last_error)
    return False


def run_ssm_command(instance_id: str, command: str, region: str,
                    timeout: int = 120) -> Tuple[bool, str, str]:
    """Execute a shell command on the EC2 instance via SSM. Returns (success, stdout, stderr)."""
    timeout = max(timeout, 30)
    if DEBUG:
        cmd_preview = command[:200] + "..." if len(command) > 200 else command
        logger.info("[SSM] send_command instance_id=%s region=%s timeout=%d cmd_preview=%s",
                    instance_id, region, timeout, cmd_preview)
    ssm = boto3.client('ssm', region_name=region)
    # RMT-2: tee-crafter only ever issues `AWS-RunShellScript` and
    # `AWS-StartPortForwardingSession`.  The IAM policy output by the
    # Terraform module pins the same allowlist; this module-level
    # constant documents the mirroring contract so static review tools
    # can cross-check that the library does not silently begin calling
    # other SSM documents.
    _SSM_DOC = "AWS-RunShellScript"
    assert _SSM_DOC in ("AWS-RunShellScript",), (
        "RMT-2: only AWS-RunShellScript is permitted from tee-crafter; "
        "any new document requires an IAM policy update."
    )
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id], DocumentName=_SSM_DOC,
            Parameters={'commands': [command]}, TimeoutSeconds=timeout)
        command_id = response['Command']['CommandId']
        if DEBUG:
            logger.info("[SSM] CommandId=%s", command_id)
        start_time = time.time()
        while time.time() - start_time < timeout + 10:
            try:
                invocations = ssm.list_command_invocations(
                    CommandId=command_id, InstanceId=instance_id,
                    Details=True)['CommandInvocations']
                if invocations:
                    status = invocations[0]['Status']
                    if status in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                        stdout = invocations[0].get('CommandPlugins', [{}])[0].get('Output', '')
                        stderr = "" if status == 'Success' else stdout
                        if DEBUG and status != 'Success':
                            logger.warning("[SSM] Command failed status=%s stdout_len=%d stderr_len=%d",
                                           status, len(stdout), len(stderr))
                        return (status == 'Success', stdout, stderr)
            except ClientError as e:
                if DEBUG:
                    logger.debug("[SSM] list_command_invocations ClientError: %s", e)
            time.sleep(2)
        if DEBUG:
            logger.warning("[SSM] Timed out waiting for CommandId=%s", command_id)
        return False, "", "Command timed out while polling SSM."
    except Exception as e:
        logger.warning("[SSM] send_command failed: %s", e)
        return False, "", str(e)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SSMPortForward:
    """Context manager that opens an SSM port-forwarding session."""

    def __init__(self, instance_id: str, remote_port: int, region: str):
        self.instance_id = instance_id
        self.remote_port = remote_port
        self.region = region
        self.local_port: int = 0
        self._proc: Optional[subprocess.Popen] = None

    def start(self, timeout: int = 30) -> int:
        self.local_port = _find_free_port()
        params = json.dumps({
            "portNumber": [str(self.remote_port)],
            "localPortNumber": [str(self.local_port)]})
        cmd = [
            "aws", "ssm", "start-session", "--target", self.instance_id,
            "--document-name", "AWS-StartPortForwardingSession",
            "--parameters", params, "--region", self.region]
        if DEBUG:
            logger.info("[SSM tunnel] starting: local=%d -> remote=%d instance=%s",
                        self.local_port, self.remote_port, self.instance_id)
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=1):
                    if DEBUG:
                        logger.info("[SSM tunnel] ready on localhost:%d", self.local_port)
                    return self.local_port
            except OSError:
                if self._proc.poll() is not None:
                    _, err = self._proc.communicate()
                    raise RuntimeError(
                        f"SSM port-forward exited early (rc={self._proc.returncode}): "
                        f"{err.decode(errors='replace')[:500]}")
                time.sleep(1)
        self.stop()
        raise TimeoutError(
            f"SSM port-forward to {self.instance_id}:{self.remote_port} "
            f"did not become ready within {timeout}s")

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            if DEBUG:
                logger.info("[SSM tunnel] stopping pid=%d", self._proc.pid)
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def __enter__(self) -> "SSMPortForward":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
