"""Nitro Enclave and SGX/Gramine Docker image management."""
import re
import os
import json
import subprocess
import shutil
import datetime
from typing import Dict, Tuple

from tee_crafter.core.enclave.build import build_enclave, get_enclave_hashes  # noqa: F401
from tee_crafter.core.enclave.sgx import sign_gramine_manifest  # noqa: F401


def check_docker_running() -> bool:
    """Check if the Docker daemon is running and accessible."""
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def _has_buildx() -> bool:
    """Check if Docker buildx is available (required for cross-platform builds)."""
    try:
        r = subprocess.run(["docker", "buildx", "version"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _host_docker_platform() -> str:
    """Return the Docker platform string matching the host architecture."""
    import platform as _plat
    machine = _plat.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "linux/arm64"
    return "linux/amd64"


#: Signatures of the QEMU/linuxkit failure described in
#: :func:`emulated_eif_build_diagnosis`.  ``lfstack`` is the Go runtime abort
#: itself; ``E48`` is the only thing nitro-cli puts in front of the operator.
_EMULATION_FAILURE_MARKERS = ("lfstack", "E48", "invalid packing")


def emulated_eif_build_diagnosis(target_platform: str, output: str) -> str:
    """Explain an amd64-on-arm64 EIF build failure, or return ``""``.

    ``nitro-cli build-enclave`` shells out to ``linuxkit`` to assemble the
    enclave's bootstrap ramfs.  linuxkit is a Go program, and Go's ``lfstack``
    packs a pointer and a counter into one 64-bit word assuming pointers fit in
    48 bits.  Under **QEMU's** amd64-on-aarch64 emulation the guest gets
    addresses above that range, so linuxkit aborts with
    ``runtime: lfstack.push invalid packing`` and nitro-cli surfaces only the
    generic ``E48 EIF building error`` plus a Go backtrace.  Nothing in that
    output mentions emulation, so the operator's next move is usually to
    re-run it.

    This deliberately **diagnoses after the fact instead of refusing up
    front**, because the emulator matters and cannot be detected reliably:

    * darwin/arm64, Docker 29.6.1, **QEMU** backend, target ``linux/amd64``
      -> reproducible ``lfstack`` abort.
    * same host and Docker, **Rosetta** backend
      (``UseVirtualizationFrameworkRosetta``), target ``linux/amd64``
      -> ``Enclave Image successfully created`` with a real PCR0.
    * same host, native ``linux/arm64`` -> builds fine either way.

    An earlier version of this code refused every amd64-on-arm64 build up
    front, which would have blocked the Rosetta configuration that measurably
    works.  There is no dependable signal to tell the two backends apart from
    where this runs: the Docker Desktop setting lives in the operator's
    ``~/Library`` (invisible to the CLI's own container), and an amd64 guest
    shows no ``/run/rosetta`` or binfmt marker.  So the build is attempted, and
    only its *failure* is annotated.
    """
    if "amd64" not in (target_platform or "") or _host_docker_platform() != "linux/arm64":
        return ""
    if not any(m in (output or "") for m in _EMULATION_FAILURE_MARKERS):
        return ""
    return (
        "\n"
        f"This looks like the QEMU emulation failure, not a problem with your "
        f"image: building {target_platform} on an arm64 host runs linuxkit "
        "under emulation, and Go's lfstack assumes pointers fit in 48 bits, "
        "which QEMU's amd64-on-aarch64 mode violates.\n"
        "Two known-good options:\n"
        "  * Switch Docker Desktop to the Rosetta backend (Settings > General > "
        "'Use Rosetta for x86_64/amd64 emulation'), which was measured to build "
        "this successfully on the same machine. Needs Rosetta 2 installed "
        "(`softwareupdate --install-rosetta`).\n"
        "  * Build on an x86_64 Linux host (CI runner, EC2 instance).\n"
        "Native linux/arm64 (Graviton) builds are unaffected.\n"
    )


# Nitro-4: default base image for the nitro-cli builder container.
# We ship a *tag*, but strongly recommend digest-pinning via the
# TEE_CRAFTER_NITRO_BUILDER_BASE environment variable in production:
#
#   export TEE_CRAFTER_NITRO_BUILDER_BASE='public.ecr.aws/amazonlinux/amazonlinux@sha256:...'
#
# A digest pin prevents an attacker who compromises the upstream
# registry from swapping the base image between PCR measurements.
# Amazon Linux publishes image digests at:
#   https://gallery.ecr.aws/amazonlinux/amazonlinux
_DEFAULT_NITRO_BUILDER_BASE = "public.ecr.aws/amazonlinux/amazonlinux:2023"


def _resolve_nitro_builder_base() -> tuple[str, bool]:
    """Return (base_image_ref, is_digest_pinned)."""
    override = os.environ.get("TEE_CRAFTER_NITRO_BUILDER_BASE", "").strip()
    ref = override or _DEFAULT_NITRO_BUILDER_BASE
    return ref, "@sha256:" in ref


def pull_builder_image(platform: str | None = None) -> str:
    """Ensures the nitro-cli builder image exists. Returns the builder tag."""
    if platform is None:
        platform = _host_docker_platform()
    arch_suffix = "arm64" if "arm64" in platform else "amd64"
    base_ref, digest_pinned = _resolve_nitro_builder_base()
    digest_fragment = "pinned" if digest_pinned else "tag"
    builder_tag = f"nitro-cli-builder-{digest_fragment}:{arch_suffix}"
    try:
        res = subprocess.run(["docker", "image", "inspect", builder_tag], capture_output=True)
        if res.returncode == 0:
            return builder_tag
    except Exception:
        pass
    if not digest_pinned:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "Nitro-4: nitro-cli builder base image is not digest-pinned (%s). "
            "Set TEE_CRAFTER_NITRO_BUILDER_BASE to "
            "'public.ecr.aws/amazonlinux/amazonlinux@sha256:<digest>' for "
            "reproducible EIF PCRs.",
            base_ref,
        )
    dockerfile = (
        f"FROM {base_ref}\n\n"
        "RUN dnf update -y && \\\n"
        "    dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker\n\n"
        "ENTRYPOINT [\"nitro-cli\"]\n")
    temp_dir = f".nitro_builder_{datetime.datetime.now().strftime('%H%M%S')}"
    os.makedirs(temp_dir, exist_ok=True)
    try:
        with open(os.path.join(temp_dir, "Dockerfile"), "w") as f:
            f.write(dockerfile)
        cmd = ["docker", "build", "--platform", platform, "--load", "-t", builder_tag, "."]
        env = os.environ.copy()
        env["DOCKER_BUILDKIT"] = "1"
        subprocess.run(cmd, cwd=temp_dir, check=True, capture_output=True, env=env)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    return builder_tag


def parse_enclave_cid(run_enclave_output: str) -> str:
    """Parse ``nitro-cli run-enclave`` output to extract the EnclaveCID."""
    if not run_enclave_output:
        return ""
    try:
        data = json.loads(run_enclave_output)
        cid = data.get("EnclaveCID")
        if isinstance(cid, int) or (isinstance(cid, str) and cid.isdigit()):
            return str(cid)
    except Exception:
        pass
    match = re.search(r"\"?EnclaveCID\"?\s*:\s*(\d+)", run_enclave_output)
    if match:
        return match.group(1)
    try:
        start = run_enclave_output.find('{')
        end = run_enclave_output.rfind('}') + 1
        if start != -1 and end != 0:
            data = json.loads(run_enclave_output[start:end])
            cid = data.get("EnclaveCID")
            if cid is not None:
                return str(cid)
    except Exception:
        pass
    return ""


def _docker_platform_from_aws_ami(ami_id: str) -> str | None:
    """Return ``linux/amd64`` or ``linux/arm64`` from an EC2 AMI id, or None."""
    if not ami_id or not ami_id.startswith("ami-"):
        return None
    try:
        import boto3
        region = (
            os.getenv("TF_VAR_aws_region")
            or os.getenv("AWS_REGION")
            or boto3.Session().region_name
            or "us-east-2"
        )
        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_images(ImageIds=[ami_id])
        imgs = resp.get("Images") or []
        if not imgs:
            return None
        img = imgs[0]
        arch = img.get("Architecture") or ""
        if not arch:
            al = img.get("Architectures") or []
            arch = al[0] if al else ""
        arch = (arch or "").lower()
        if arch == "arm64":
            return "linux/arm64"
        if arch in ("x86_64", "i386"):
            return "linux/amd64"
    except Exception:
        return None
    return None


def _resolve_platform(
    instance_type: str | None = None,
    *,
    enclave_cpu: int = 2,
    enclave_ram_mib: int = 4096,
) -> str:
    """Docker ``linux/$ARCH`` for Nitro image builds (must match EC2 + enclave).

    Precedence:

    1. Explicit *instance_type* (non-empty wins over env).
    2. ``TF_VAR_instance_type`` when *instance_type* is empty.
    3. ``TF_VAR_custom_ami_id`` (``ami-…``): EC2 DescribeImages ``Architecture``.
    4. ``select_instance_type(enclave_cpu, enclave_ram_mib)`` — same default family
       as ``generate_terraform_code`` for Nitro.
    """
    inst = (instance_type or "").strip() or os.environ.get("TF_VAR_instance_type", "").strip()
    if inst:
        from tee_crafter.core.catalog import instance_architecture
        return ("linux/arm64" if instance_architecture(inst) == "arm64"
                else "linux/amd64")

    ami_id = os.environ.get("TF_VAR_custom_ami_id", "").strip()
    plat = _docker_platform_from_aws_ami(ami_id)
    if plat:
        return plat

    try:
        from tee_crafter.core.iac.terraform_gen import select_instance_type
        inst = select_instance_type(enclave_cpu, enclave_ram_mib)
    except Exception:
        # Match the canonical Nitro default in ``cli/preflight.py``
        # (``c6a.xlarge``, AMD Milan / x86_64).  See ``docs/security.md``
        # §15.1A — Secure Boot enrollment is x86_64-only, so the default
        # Nitro host is now x86_64.
        inst = "c6a.xlarge"
    from tee_crafter.core.catalog import instance_architecture
    return ("linux/arm64" if instance_architecture(inst) == "arm64"
            else "linux/amd64")
