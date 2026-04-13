"""S3-based file upload for SSM-managed EC2 instances."""
import logging
import os
import time
from typing import Tuple

import boto3

logger = logging.getLogger(__name__)


def _get_ssm():
    from tee_crafter.core.remote import ssm
    return ssm


def upload_file_via_s3(
    local_path: str, bucket_name: str, object_name: str,
    instance_id: str, remote_path: str, region: str,
    timeout: int = 120, retries: int = 2,
) -> Tuple[bool, str]:
    """Upload a local file to S3, then SSM-download it on the instance.

    No presigned URLs -- credentials never leave the instance.
    """
    _ssm = _get_ssm()
    DEBUG = _ssm.DEBUG
    if DEBUG:
        logger.info("[S3 upload] local_path=%s bucket=%s key=%s instance_id=%s remote_path=%s region=%s",
                    local_path, bucket_name, object_name, instance_id, remote_path, region)
    from botocore.config import Config as BotoConfig
    from boto3.s3.transfer import TransferConfig
    s3 = boto3.client(
        's3', region_name=region,
        config=BotoConfig(connect_timeout=30, read_timeout=60,
                          retries={"max_attempts": 3, "mode": "adaptive"}))
    transfer_cfg = TransferConfig(
        multipart_threshold=8 * 1024 * 1024,
        multipart_chunksize=8 * 1024 * 1024, max_concurrency=10)
    file_size_mb = os.path.getsize(local_path) / (1024 * 1024) if os.path.exists(local_path) else 0
    logger.info("[S3 upload] Uploading %.1f MB to s3://%s/%s (region=%s)",
                file_size_mb, bucket_name, object_name, region)
    upload_start = time.time()
    try:
        s3.upload_file(local_path, bucket_name, object_name, Config=transfer_cfg)
        logger.info("[S3 upload] Upload succeeded in %.1fs: s3://%s/%s",
                    time.time() - upload_start, bucket_name, object_name)
    except Exception as e:
        elapsed = time.time() - upload_start
        logger.warning("[S3 upload] Failed after %.1fs: %s", elapsed, e)
        return False, f"Failed to upload to S3 after {elapsed:.1f}s: {e}"
    remote_dir = os.path.dirname(remote_path) or "/"
    tmp_path = f"{remote_path}.tmp"
    s3_uri = f"s3://{bucket_name}/{object_name}"
    download_cmd = (
        f"set -e; export PATH=\"/usr/local/bin:/usr/bin:$PATH\"; "
        f"sudo mkdir -p '{remote_dir}'; "
        f"echo '[SSM] starting aws s3 cp'; "
        f"aws s3 cp '{s3_uri}' '{tmp_path}' --region {region}; "
        f"echo '[SSM] s3 cp done'; "
        f"sudo mv '{tmp_path}' '{remote_path}'; "
        f"ls -lh '{remote_path}'")
    last_err = ""
    stdout = ""
    for attempt in range(1, retries + 1):
        logger.info("[S3 download] attempt %d/%d, timeout=%ds", attempt, retries, timeout)
        dl_start = time.time()
        success, stdout, stderr = _ssm.run_ssm_command(instance_id, download_cmd, region, timeout=timeout)
        dl_elapsed = time.time() - dl_start
        if success:
            logger.info("[S3 download] Success on attempt %d in %.1fs. stdout: %s",
                        attempt, dl_elapsed, (stdout or "")[:300])
            return True, "Success"
        last_err = stderr or stdout or "(no output)"
        logger.warning("[S3 download] attempt %d failed in %.1fs. stdout=%s stderr=%s",
                       attempt, dl_elapsed, (stdout or "")[:300], (stderr or "")[:300])
        if attempt < retries:
            time.sleep(15)
    return False, (
        f"Failed to download from S3 to instance: {last_err}"
        f" [bucket={bucket_name} key={object_name} region={region}]"
        f" Full SSM stdout: {stdout[:500] if stdout else '(none)'}")


def download_file_via_s3(
    instance_id: str, remote_path: str, bucket_name: str, object_name: str,
    local_path: str, region: str,
    timeout: int = 300, retries: int = 2,
) -> Tuple[bool, str]:
    """Download a file from a remote SSM-managed instance via an S3 round-trip.

    The instance uploads ``remote_path`` to ``s3://bucket_name/object_name`` using
    its instance role, then we pull it down to ``local_path``. No credentials
    leave the instance; no presigned URLs are involved.
    """
    _ssm = _get_ssm()
    DEBUG = _ssm.DEBUG
    if DEBUG:
        logger.info("[S3 download] instance=%s remote=%s -> s3://%s/%s -> local=%s region=%s",
                    instance_id, remote_path, bucket_name, object_name, local_path, region)
    s3_uri = f"s3://{bucket_name}/{object_name}"
    upload_cmd = (
        f"set -e; export PATH=\"/usr/local/bin:/usr/bin:$PATH\"; "
        f"if [ ! -f '{remote_path}' ]; then echo '[SSM] missing {remote_path}' >&2; exit 2; fi; "
        f"echo '[SSM] aws s3 cp {remote_path} {s3_uri}'; "
        f"aws s3 cp '{remote_path}' '{s3_uri}' --region {region}; "
        f"echo '[SSM] upload done'")
    last_err = ""
    stdout = ""
    for attempt in range(1, retries + 1):
        logger.info("[S3 download] remote upload attempt %d/%d", attempt, retries)
        success, stdout, stderr = _ssm.run_ssm_command(instance_id, upload_cmd, region, timeout=timeout)
        if success:
            break
        last_err = stderr or stdout or "(no output)"
        logger.warning("[S3 download] remote upload attempt %d failed: %s", attempt, last_err[:300])
        if attempt < retries:
            time.sleep(10)
    else:
        return False, f"Remote could not push {remote_path} to S3: {last_err}"

    from botocore.config import Config as BotoConfig
    s3 = boto3.client(
        's3', region_name=region,
        config=BotoConfig(connect_timeout=30, read_timeout=120,
                          retries={"max_attempts": 3, "mode": "adaptive"}))
    local_dir = os.path.dirname(local_path) or "."
    os.makedirs(local_dir, exist_ok=True)
    dl_start = time.time()
    try:
        s3.download_file(bucket_name, object_name, local_path)
    except Exception as e:
        return False, f"Local S3 download failed: {e}"
    elapsed = time.time() - dl_start
    size_mb = os.path.getsize(local_path) / (1024 * 1024) if os.path.exists(local_path) else 0
    logger.info("[S3 download] Local pull succeeded: %.1f MB in %.1fs", size_mb, elapsed)
    try:
        s3.delete_object(Bucket=bucket_name, Key=object_name)
    except Exception as e:
        logger.warning("[S3 download] Could not delete s3://%s/%s: %s", bucket_name, object_name, e)
    return True, "Success"
