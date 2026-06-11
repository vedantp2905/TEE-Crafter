"""Cross-platform file download from a TEE host back to the build directory.

Batch mode produces a single ``output.tar.gz`` plus a sidecar
``output.tar.gz.sha256`` on the remote TEE.  This module exposes one entry
point — :func:`download_batch_bundle` — that picks the right transport for the
caller's platform without exposing any cloud SDK details to the orchestrator:

* Azure / GCP CVMs → SSH/SCP (Bastion or IAP tunnel established by the caller)
* AWS SSM-managed instances → S3 round trip (no public IP, no presigned URL)
* AWS Nitro Enclaves → vsock collector wrote the tarball to the host filesystem,
  then we pull it down via SSM/S3.

A platform-side ``max_output_size`` byte budget is enforced after download
(or, for SCP transports, after the local file lands).  Bundles that exceed
the budget are deleted and an error is returned, so the orchestrator never
silently truncates a large output.  The cap is internalised — there is no
public CLI flag; the SaaS orchestrator picks a tier-appropriate value
(2 GiB by default for local CLI deploys).
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DownloadResult:
    success: bool
    local_path: str
    sha256: str
    size_bytes: int
    message: str


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _enforce_size(local_path: str, max_output_size: Optional[int]) -> Tuple[bool, int, str]:
    if not os.path.isfile(local_path):
        return False, 0, "file not present after download"
    size = os.path.getsize(local_path)
    if max_output_size and size > max_output_size:
        try:
            os.unlink(local_path)
        except OSError:
            pass
        return False, size, (
            f"bundle is {size} bytes which exceeds the configured "
            f"max_output_size={max_output_size}; removed local copy"
        )
    return True, size, ""


def _verify_sha(local_bundle: str, expected_sha_hex: Optional[str]) -> Tuple[bool, str, str]:
    actual = _sha256_of(local_bundle)
    if expected_sha_hex and actual.lower() != expected_sha_hex.lower():
        return False, actual, f"sha256 mismatch (expected {expected_sha_hex}, got {actual})"
    return True, actual, ""


def download_batch_bundle(
    *,
    platform: str,
    local_path: str,
    remote_bundle_path: str = "/var/lib/tee_crafter/output.tar.gz",
    remote_sha_path: Optional[str] = "/var/lib/tee_crafter/output.tar.gz.sha256",
    max_output_size: Optional[int] = None,
    # SCP (Azure/GCP) ------------------------------------------------------
    ssh_private_key_path: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_host: str = "localhost",
    ssh_port: int = 22,
    # AWS SSM/S3 ----------------------------------------------------------
    aws_instance_id: Optional[str] = None,
    aws_region: Optional[str] = None,
    aws_bucket: Optional[str] = None,
    aws_object_key: Optional[str] = None,
    timeout: int = 600,
) -> DownloadResult:
    """Pull the batch ``output.tar.gz`` from *platform*'s TEE host to *local_path*."""
    is_azure = platform in ("tdx-azure", "snp-azure", "sgx-azure", "gpu-cc-azure")
    is_gcp = platform in ("tdx-gcp", "snp-gcp", "gpu-cc-gcp")
    is_aws_ssm = platform in ("snp-aws", "gpu-cc-aws", "nitro-aws")

    expected_sha = None
    if remote_sha_path:
        expected_sha = _read_remote_sha(
            platform=platform,
            remote_sha_path=remote_sha_path,
            ssh_private_key_path=ssh_private_key_path,
            ssh_user=ssh_user, ssh_host=ssh_host, ssh_port=ssh_port,
            aws_instance_id=aws_instance_id, aws_region=aws_region,
        )

    if is_azure:
        from tee_crafter.core.remote.azure_ssh import download_file_via_scp
        ok, msg = download_file_via_scp(
            remote_bundle_path, local_path, ssh_private_key_path,
            user=ssh_user or "azureuser", timeout=timeout,
            host=ssh_host, port=ssh_port)
    elif is_gcp:
        from tee_crafter.core.remote.gcp_ssh import download_file_via_scp
        ok, msg = download_file_via_scp(
            remote_bundle_path, local_path, ssh_private_key_path,
            user=ssh_user or "tee_admin", timeout=timeout,
            host=ssh_host, port=ssh_port)
    elif is_aws_ssm:
        if not (aws_instance_id and aws_region and aws_bucket and aws_object_key):
            return DownloadResult(False, local_path, "", 0,
                                  "AWS S3 download requires aws_instance_id/region/bucket/object_key")
        from tee_crafter.core.remote.ssm_s3 import download_file_via_s3
        ok, msg = download_file_via_s3(
            instance_id=aws_instance_id, remote_path=remote_bundle_path,
            bucket_name=aws_bucket, object_name=aws_object_key,
            local_path=local_path, region=aws_region, timeout=timeout)
    else:
        return DownloadResult(False, local_path, "", 0,
                              f"no batch download transport for platform '{platform}'")

    if not ok:
        return DownloadResult(False, local_path, "", 0, msg)

    size_ok, size, size_msg = _enforce_size(local_path, max_output_size)
    if not size_ok:
        return DownloadResult(False, local_path, "", size, size_msg)

    sha_ok, sha_hex, sha_msg = _verify_sha(local_path, expected_sha)
    if not sha_ok:
        return DownloadResult(False, local_path, sha_hex, size, sha_msg)

    return DownloadResult(True, local_path, sha_hex, size, "ok")


def _read_remote_sha(
    *,
    platform: str,
    remote_sha_path: str,
    ssh_private_key_path: Optional[str],
    ssh_user: Optional[str],
    ssh_host: str, ssh_port: int,
    aws_instance_id: Optional[str], aws_region: Optional[str],
) -> Optional[str]:
    """Best-effort fetch of the bundle's sidecar ``.sha256`` for verification."""
    is_azure = platform in ("tdx-azure", "snp-azure", "sgx-azure", "gpu-cc-azure")
    is_gcp = platform in ("tdx-gcp", "snp-gcp", "gpu-cc-gcp")
    is_aws = platform in ("snp-aws", "gpu-cc-aws", "nitro-aws")
    cmd = f"sudo cat {remote_sha_path} 2>/dev/null || true"
    try:
        if is_azure:
            from tee_crafter.core.remote.azure_ssh import run_ssh_command
            ok, out, _ = run_ssh_command(cmd, ssh_private_key_path,
                                          user=ssh_user or "azureuser",
                                          host=ssh_host, port=ssh_port, timeout=20)
        elif is_gcp:
            from tee_crafter.core.remote.gcp_ssh import run_ssh_command
            ok, out, _ = run_ssh_command(cmd, ssh_private_key_path,
                                          user=ssh_user or "tee_admin",
                                          host=ssh_host, port=ssh_port, timeout=20)
        elif is_aws and aws_instance_id and aws_region:
            from tee_crafter.core.remote.ssm import run_ssm_command
            ok, out, _ = run_ssm_command(aws_instance_id, cmd, aws_region, timeout=30)
        else:
            return None
        if not ok or not out:
            return None
        first = out.strip().split()[0] if out.strip() else ""
        return first if len(first) == 64 else None
    except Exception as e:
        logger.debug("Could not read remote sha: %s", e)
        return None


def wait_for_oneshot_completion(
    *,
    platform: str,
    service_name: str,
    timeout: int,
    poll_interval: int = 10,
    ssh_private_key_path: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_host: str = "localhost",
    ssh_port: int = 22,
    aws_instance_id: Optional[str] = None,
    aws_region: Optional[str] = None,
    activation_grace_sec: int = 120,
    journal_since: Optional[str] = None,
) -> Tuple[bool, str, str]:
    """Poll a Type=oneshot service until it exits. Returns (ok, exit_state, last_journal).

    After ``systemctl start --no-block`` the orchestrator has to infer the
    unit's fate from outside, and for ``Type=oneshot`` + ``RemainAfterExit=no``
    ``systemctl show`` is not enough on its own: systemd releases a successful
    unit's runtime state as soon as it returns to inactive, so ``inactive`` /
    ``Result=success`` / ``ExecMainStartTimestampMonotonic=0`` describes a run
    that finished, a run still queued behind a dependency, a job that was
    cancelled, and a unit that was never started — all four identically.
    Measured on systemd 257; the table is in
    ``batch._start_oneshot_and_wait`` and the harness transcript in
    ``tests/cli/test_oneshot_activation_probe.py``.

    Three signals are therefore combined:

    * ``systemctl list-jobs`` — a listed job means queued or running, so keep
      waiting.  This is the only thing that separates "slow to be scheduled"
      from "cancelled", and reading ``inactive`` as completion is what raced
      ExecStopPost (which builds the output tarball) and tore the VM down
      before the bundle existed.
    * ``ActiveState`` — ``failed`` is durable and conclusive; the running
      states mean carry on.
    * the journal — the only durable record of a *successful* oneshot.
      ``journal_since`` scopes it to this invocation (pass the timestamp taken
      immediately before ``systemctl start``); without it a rolling window is
      used, which is safe for a fresh VM but could see a previous run's
      ``Finished`` line on a reused one.

    If the unit neither runs nor holds a pending job within
    ``activation_grace_sec``, that is surfaced as ``not-activated`` so the
    caller can dump the journal.
    """
    is_azure = platform in ("tdx-azure", "snp-azure", "sgx-azure", "gpu-cc-azure")
    is_gcp = platform in ("tdx-gcp", "snp-gcp", "gpu-cc-gcp")
    is_aws = platform in ("snp-aws", "gpu-cc-aws", "nitro-aws")
    started_polling = time.time()
    deadline = started_polling + max(timeout, poll_interval * 2)
    last_state = ""
    seen_running = False
    running_states = {"activating", "active", "deactivating", "reloading"}
    since_arg = f'--since "{journal_since}"' if journal_since else '--since "-300s"'
    while time.time() < deadline:
        cmd = (f"systemctl is-active {service_name} 2>/dev/null; "
               f"systemctl show {service_name} "
               "-p Result -p ExecMainStatus -p ActiveState -p SubState "
               "-p ExecMainStartTimestampMonotonic 2>/dev/null; "
               f"echo JOBS=$(systemctl list-jobs --no-legend 2>/dev/null "
               f"| grep -Fc '{service_name}'); "
               # Only lines systemd itself emitted count.  The unit's own stdout
               # lands in the same journal, so an unfiltered grep for
               # "Finished" would happily match a user container printing
               # "Finished processing" and call the run complete.
               f"echo JMARK=$(sudo journalctl -u {service_name} --no-pager "
               f"{since_arg} 2>/dev/null "
               "| grep -oE 'systemd\\[[0-9]+\\]: "
               "(Dependency failed|Finished|[^ ]+ Failed with result)' "
               "| sed -E 's/.*systemd\\[[0-9]+\\]: //' | tail -1)")
        if is_azure:
            from tee_crafter.core.remote.azure_ssh import run_ssh_command
            _, out, _ = run_ssh_command(cmd, ssh_private_key_path,
                                         user=ssh_user or "azureuser",
                                         host=ssh_host, port=ssh_port, timeout=15)
        elif is_gcp:
            from tee_crafter.core.remote.gcp_ssh import run_ssh_command
            _, out, _ = run_ssh_command(cmd, ssh_private_key_path,
                                         user=ssh_user or "tee_admin",
                                         host=ssh_host, port=ssh_port, timeout=15)
        elif is_aws and aws_instance_id and aws_region:
            from tee_crafter.core.remote.ssm import run_ssm_command
            _, out, _ = run_ssm_command(aws_instance_id, cmd, aws_region, timeout=15)
        else:
            return False, "no-transport", ""
        text = (out or "").strip()
        last_state = text
        first_line = text.splitlines()[0] if text else ""
        active_state = ""
        sub_state = ""
        exec_started_mono = ""
        jobs_pending = 0
        jmark = ""
        for line in text.splitlines():
            if line.startswith("ActiveState="):
                active_state = line.split("=", 1)[1].strip()
            elif line.startswith("SubState="):
                sub_state = line.split("=", 1)[1].strip()
            elif line.startswith("ExecMainStartTimestampMonotonic="):
                exec_started_mono = line.split("=", 1)[1].strip()
            elif line.startswith("JOBS="):
                raw = line.split("=", 1)[1].strip()
                jobs_pending = int(raw) if raw.isdigit() else 0
            elif line.startswith("JMARK="):
                jmark = line.split("=", 1)[1].strip()
        # `Result` is deliberately not consulted.  It is populated ("success")
        # from the moment the unit is loaded, so treating a non-empty Result as
        # "it ran" made `seen_running` true on the very first poll and turned
        # this whole loop into a single unconditional success.
        if (active_state in running_states or first_line in running_states
                or (exec_started_mono and exec_started_mono != "0")):
            seen_running = True
        # A pending job means queued-or-running.  Nothing else to decide, and
        # it must not count against the activation grace period.
        if jobs_pending > 0:
            time.sleep(poll_interval)
            continue
        if first_line in ("inactive", "failed"):
            # When inactive, also require SubState=dead — anything else
            # (start-pre, start, stop, stop-post, …) means the unit is
            # still transitioning and ExecStopPost may not have run yet.
            still_transitioning = (
                first_line == "inactive" and sub_state and sub_state != "dead"
            )
            if not still_transitioning:
                if "Dependency failed" in jmark:
                    return False, "dependency-failed", text
                if "Failed with result" in jmark or first_line == "failed":
                    return True, "failed", text
                if "Finished" in jmark or seen_running:
                    return True, first_line, text
            if not seen_running and (time.time() - started_polling) > activation_grace_sec:
                return False, "not-activated", text
        time.sleep(poll_interval)
    return False, "timeout", last_state
