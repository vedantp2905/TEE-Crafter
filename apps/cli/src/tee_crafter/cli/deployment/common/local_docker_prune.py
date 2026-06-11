"""Remove only the Docker image recorded for a specific deploy build directory."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess

logger = logging.getLogger("tee_crafter.docker_prune")

# Written by container pipeline (see flow_container).  Must stay in sync with _USER_APP_IMAGE_REPO + tag format.
PIPELINE_IMAGE_MARKER = "local_pipeline_image.txt"
_PIPELINE_IMAGE_TAG_RE = re.compile(r"^tee-crafter-user-app:[0-9a-f]{16}$", re.IGNORECASE)


def write_pipeline_image_marker(build_dir: str, image_tag: str) -> None:
    """Record the ``tee-crafter-user-app:<id>`` tag for this build so teardown/destroy can remove it only."""
    tag = (image_tag or "").strip()
    if not _PIPELINE_IMAGE_TAG_RE.match(tag):
        logger.warning("Not recording invalid pipeline image tag: %r", image_tag)
        return
    path = os.path.join(os.path.abspath(build_dir), PIPELINE_IMAGE_MARKER)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(tag + "\n")
    except OSError as e:
        logger.warning("Could not write %s: %s", path, e)


def prune_pipeline_local_image(build_dir: str) -> bool:
    """``docker rmi -f`` only the image tag listed in *build_dir*'s pipeline marker file.

    Skipped when ``TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE`` is set, the marker is missing,
    the tag is not a strict ``tee-crafter-user-app:<16-hex>`` value, or ``docker`` is absent.
    The marker file is removed after a successful ``rmi`` attempt (or if the image was
    already absent).

    Returns True if ``docker rmi`` was invoked (return code may still be non-zero if stale).
    """
    if os.environ.get("TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE", "").strip().lower() in (
        "1", "true", "yes",
    ):
        logger.debug("Local Docker prune skipped (TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE).")
        return False
    if not shutil.which("docker"):
        return False
    path = os.path.join(os.path.abspath(build_dir), PIPELINE_IMAGE_MARKER)
    if not os.path.isfile(path):
        return False
    try:
        with open(path, encoding="utf-8") as f:
            tag = f.readline().strip()
    except OSError as e:
        logger.debug("Could not read pipeline image marker: %s", e)
        return False
    if not tag or not _PIPELINE_IMAGE_TAG_RE.match(tag):
        logger.warning("Invalid pipeline image tag in %s, skipping docker rmi.", path)
        return False
    try:
        rm = subprocess.run(
            ["docker", "rmi", "-f", tag],
            capture_output=True,
            text=True,
            timeout=600,
        )
        err_blob = ((rm.stderr or "") + (rm.stdout or "")).lower()
        gone = rm.returncode == 0 or "no such image" in err_blob
        if not gone:
            logger.debug("docker rmi %s failed: %s", tag, (rm.stderr or rm.stdout or "")[:400])
            return False
        try:
            os.unlink(path)
        except OSError:
            pass
        summary_path = os.path.join(os.path.abspath(build_dir), "docker_prune_summary.txt")
        try:
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(f"docker rmi -f {tag}\nreturncode={rm.returncode}\n")
        except OSError as e:
            logger.debug("Could not write %s: %s", summary_path, e)
        try:
            from tee_crafter.cli.constants import console

            console.print(f"[dim]Removed local pipeline Docker image {tag}.[/dim]")
        except Exception:
            logger.info("Removed local pipeline Docker image %s.", tag)
        return True
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as e:
        logger.debug("Local pipeline image prune skipped: %s", e)
        return False
