"""Warn when the CLI image is older than the checkout it is mounted on.

The CLI runs as ``docker run -v $PWD:/workspace tee-crafter …``, and the image
carries its **own copy** of the source: ``apps/cli/Dockerfile`` does
``COPY src/ src/`` into ``/opt/tee-crafter`` and installs from there.
``/workspace`` is the working directory for build outputs — nothing imports from
it. So editing ``apps/cli/src/…`` changes nothing about what a deploy runs until
``make docker-build-cli`` is re-run.

That is a reasonable design and a very sharp edge, because the failure is
**silent and looks like success**. On 2026-08-23 a change to the SEV-SNP
certificate-quote binding (v1 → v2) was deployed to real hardware on two
platforms and both runs passed — with the *old* code on both sides of the
channel. App and client were consistently v1, so the client verified happily.
The result read exactly like a successful verification of the new code. Two live
VMs proved nothing, and the only reason it was caught was an unrelated
``--byok`` flag that the stale image rejected outright.

Templates make it worse rather than better: they are data files read from the
installed package at run time, so a template edit is subject to the same trap
while *looking* like it should not be — nothing about "editing a file the deploy
reads" suggests a rebuild is needed.

This module compares the two trees and says so. It only warns: a mismatch is
normal and harmless while iterating on docs or tests, and blocking would be
wrong. What matters is that "I verified this on hardware" is never said about a
run that used different code.
"""
from __future__ import annotations

import hashlib
import os
from typing import Optional
from tee_crafter.core.env_flags import env_hatch_open

#: Where the Dockerfile installs the package inside the image.
IMAGE_SRC = "/opt/tee-crafter/src/tee_crafter"

#: Where the repo checkout is mounted.
WORKSPACE_SRC = "/workspace/apps/cli/src/tee_crafter"

#: Set by the docker wrapper.  Outside the container there is no second copy to
#: disagree with, so the check does not apply.
IN_DOCKER_ENV = "TEE_CRAFTER_IN_DOCKER"

#: Escape hatch for anyone who genuinely wants the installed copy and does not
#: want to hear about it (CI running from a published image with no mount).
SKIP_ENV = "TEE_CRAFTER_SKIP_STALE_IMAGE_CHECK"

#: Only the parts whose content changes what a deploy *does*.  Tests and
#: ``__pycache__`` are excluded so an unrelated test edit does not cry wolf.
_RELEVANT_SUFFIXES = (".py", ".toml", ".sh", ".tf", ".template", ".json",
                      ".service", ".rules")


def _tree_digest(root: str) -> Optional[str]:
    """Stable digest over the files that decide a deploy's behaviour."""
    if not os.path.isdir(root):
        return None
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in ("__pycache__", "tests", ".pytest_cache"))
        rel_dir = os.path.relpath(dirpath, root)
        for name in sorted(filenames):
            if not name.endswith(_RELEVANT_SUFFIXES):
                continue
            rel = os.path.normpath(os.path.join(rel_dir, name))
            h.update(rel.encode("utf-8", "replace"))
            h.update(b"\0")
            try:
                with open(os.path.join(dirpath, name), "rb") as fh:
                    h.update(hashlib.sha256(fh.read()).digest())
            except OSError:
                h.update(b"<unreadable>")
    return h.hexdigest()


def stale_image_warning() -> str:
    """A warning to print, or ``""`` when there is nothing to say."""
    if os.environ.get(IN_DOCKER_ENV, "") != "1":
        return ""
    if env_hatch_open(SKIP_ENV):
        return ""
    installed = _tree_digest(IMAGE_SRC)
    mounted = _tree_digest(WORKSPACE_SRC)
    # No mount, or not the layout we expect: nothing to compare, stay quiet.
    if not installed or not mounted or installed == mounted:
        return ""
    return (
        "This CLI image was built from a different source tree than the one "
        "mounted at /workspace.\n"
        f"  image   ({IMAGE_SRC}): {installed[:16]}…\n"
        f"  mounted ({WORKSPACE_SRC}): {mounted[:16]}…\n\n"
        "The deploy runs the image's copy. Local edits to apps/cli/src — "
        "including templates, setup scripts and Terraform, which are read at "
        "run time and so look like they should not need a rebuild — will NOT "
        "take effect.\n\n"
        "Rebuild before treating this run as evidence:\n"
        "  make docker-build-cli\n\n"
        "This is not a hypothetical: two live SEV-SNP runs on 2026-08-23 "
        "'verified' a binding change that was not in the image. Both passed, "
        "because the old code was consistent on both sides of the channel."
    )
