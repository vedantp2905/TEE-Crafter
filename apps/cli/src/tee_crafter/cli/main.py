"""
TEE-Crafter CLI entrypoint.

Commands and deployment logic are split across:
- cli/constants.py      – PIPELINE_VERSION, console
- cli/loaders.py        – load_remote_setup_template, load_root_ca
- cli/audit_helpers.py  – save_audit_trail
- cli/cloud_auth.py     – bootstrap_cloud_auth, validate_gcp_auth
- cli/deployment/       – Terraform apply, SSM/SSH setup, enclave/proxy, client run, phase orchestration
- cli/commands/         – destroy, verify-provenance, deploy-from-build, deploy
"""

from __future__ import annotations

import click
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NoReturn
from dotenv import find_dotenv, load_dotenv

from tee_crafter.cli.constants import console
from tee_crafter.cli.commands import register_commands

# Load ``.env`` from the directory the user runs ``tee-crafter`` from
# (walking upward), matching the workspace that gets bind-mounted into the
# Docker re-exec.  In this monorepo that's the repo root.
load_dotenv(find_dotenv(usecwd=True))

_IN_DOCKER_ENV = "TEE_CRAFTER_IN_DOCKER"

_PLATFORMS_REQUIRING_AMD64 = {"sgx-azure"}

# Subcommands that must run on the *host* (never re-execed inside Docker).
# Currently empty: every command works inside the re-exec container, which is
# where the pinned toolchain (Terraform, cloud CLIs, Gramine/GSC) lives.
_HOST_ONLY_SUBCOMMANDS: frozenset[str] = frozenset()


def _configure_cli_logging() -> None:
    """Ensure INFO-level CLI logs emit without requiring callers to configure logging."""
    root = logging.getLogger()
    if root.handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )


def _package_root() -> Path:
    """The CLI package root (``apps/cli``): holds the CLI Dockerfiles,
    ``src/`` and ``pyproject.toml``.  This is the Docker **build context**
    when the CLI builds its own image."""
    return Path(__file__).resolve().parents[3]


def _workspace_root() -> Path:
    """The directory bind-mounted into the re-exec container as
    ``/workspace``: the user's current working directory, where ``--source``
    paths, ``.env`` and ``.gcloud`` live.  Running ``tee-crafter`` from this
    monorepo's root makes the workspace the repo root."""
    return Path.cwd()


def _host_arch() -> str:
    """Return 'arm64' or 'amd64' matching the host machine."""
    import platform as _plat
    return "arm64" if _plat.machine().lower() in ("arm64", "aarch64") else "amd64"


def _docker_image() -> str:
    return os.environ.get("TEE_CRAFTER_DOCKER_IMAGE", "tee-crafter")


def _is_informational_invocation(argv: list[str]) -> bool:
    """True for invocations that only print text and touch nothing.

    ``--help`` / ``--version`` / a bare ``tee-crafter`` need none of the pinned
    toolchain: ``register_commands(cli)`` has already run on the host, so Click
    can render every command's help locally.  Re-execing them would build a
    multi-hundred-megabyte image just to print a usage string — and
    ``tee-crafter --help`` is the first command in the README, so that is what a
    new user's first minute looks like.
    """
    args = argv[1:]
    if not args:
        return True
    return any(a in ("--help", "-h", "--version") for a in args)


def _should_exec_in_docker(argv: list[str]) -> bool:
    if os.environ.get(_IN_DOCKER_ENV) == "1":
        return False
    if _is_informational_invocation(argv):
        return False
    if _detect_top_level_subcommand(argv) in _HOST_ONLY_SUBCOMMANDS:
        return False
    return True


def _docker_image_exists(image: str) -> bool:
    return subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    ).returncode == 0


#: Label carrying the fingerprint of the sources the image was built from.
SOURCE_FINGERPRINT_LABEL = "com.tee-crafter.source-fingerprint"
#: Set to skip the staleness check (CI with a pre-built image, air-gapped hosts).
SKIP_STALENESS_ENV = "TEE_CRAFTER_SKIP_IMAGE_STALENESS_CHECK"


def _source_fingerprint(repo: Path) -> str:
    """Hash the sources baked into the CLI image.

    The repository is **not** bind-mounted into the re-exec container — the image
    is built from ``apps/cli`` — and ``_ensure_image`` returned early whenever the
    tag already existed. So editing Python and re-running ``deploy`` silently
    exercised the *previous* build. That is not a hypothetical: on 2026-08-22 it
    produced two clean-looking ``sgx-azure`` runs that were executing deleted
    code, and the error they printed pointed at the wrong cause entirely. The
    Dockerfile's own error text ("means the image is stale — rebuild it") shows
    the trap was known; nothing detected it.

    Returns ``""`` when the tree cannot be read, which disables the check rather
    than blocking the run.
    """
    import hashlib

    roots = [repo / "src", repo / "Dockerfile"]
    extra = repo / "requirements.txt"
    if extra.is_file():
        roots.append(extra)
    digest = hashlib.sha256()
    hashed = 0
    try:
        for root in roots:
            if root.is_file():
                files = [root]
            elif root.is_dir():
                files = sorted(
                    p for p in root.rglob("*")
                    if p.is_file() and "__pycache__" not in p.parts
                    and p.suffix not in (".pyc", ".pyo")
                )
            else:
                continue
            for path in files:
                digest.update(str(path.relative_to(repo)).encode())
                digest.update(path.read_bytes())
                hashed += 1
    except OSError:
        return ""
    if not hashed:
        # Nothing readable: hashing zero files would still yield a stable digest,
        # which would look like a real answer and silently pin the check to an
        # empty tree.  Say "unknown" instead so the caller skips the comparison.
        return ""
    return digest.hexdigest()[:16]


def _image_fingerprint(image: str) -> str:
    """The fingerprint label recorded on *image*, or ``""`` if absent."""
    res = subprocess.run(
        ["docker", "image", "inspect", image, "--format",
         "{{index .Config.Labels \"" + SOURCE_FINGERPRINT_LABEL + "\"}}"],
        capture_output=True, text=True, check=False,
    )
    if res.returncode != 0:
        return ""
    val = (res.stdout or "").strip()
    return "" if val in ("<no value>", "none") else val


def _docker_pull(image: str) -> bool:
    """Try to pull the image from a registry. Returns True on success."""
    if "/" not in image:
        return False
    res = subprocess.run(
        ["docker", "pull", image],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    return res.returncode == 0


def _docker_build(
    image: str,
    repo: Path,
    platform: str | None = None,
    dockerfile_name: str = "Dockerfile",
    build_args: dict[str, str] | None = None,
) -> None:
    dockerfile = repo / dockerfile_name
    if not dockerfile.is_file():
        raise click.ClickException(
            f"Dockerfile not found at {dockerfile}. Docker is a hard prerequisite for TEE-Crafter."
        )
    arch_label = platform or "native arch"
    console.print(f"[yellow]Building {image} ({arch_label}, {dockerfile_name})...[/yellow]")
    # Stamp the sources' fingerprint so the next run can tell whether this image
    # still matches the checkout — see _source_fingerprint.
    fingerprint = _source_fingerprint(repo)
    label_args: list[str] = []
    if fingerprint:
        label_args = ["--label", f"{SOURCE_FINGERPRINT_LABEL}={fingerprint}"]
    build_cmd = ["docker", "buildx", "build", "--load", *label_args]
    if platform:
        build_cmd += ["--platform", platform]
    for k, v in (build_args or {}).items():
        build_cmd += ["--build-arg", f"{k}={v}"]
    build_cmd += ["-t", image, "-f", str(dockerfile), str(repo)]
    res = subprocess.run(build_cmd, check=False)
    if res.returncode != 0:
        console.print("[dim]buildx failed, falling back to docker build...[/dim]")
        fallback = ["docker", "build", "--load", *label_args]
        if platform:
            fallback += ["--platform", platform]
        for k, v in (build_args or {}).items():
            fallback += ["--build-arg", f"{k}={v}"]
        fallback += ["-t", image, "-f", str(dockerfile), str(repo)]
        res = subprocess.run(fallback, check=False)
        if res.returncode != 0:
            raise click.ClickException("Docker build failed.")


def _ensure_image(
    image: str,
    repo: Path,
    platform: str | None = None,
    dockerfile_name: str = "Dockerfile",
    build_args: dict[str, str] | None = None,
) -> None:
    """Ensure the CLI image is available locally: check local -> pull -> build.

    A locally present image is reused only when its recorded source fingerprint
    still matches the checkout; otherwise it is rebuilt.  Without that check,
    editing the CLI's Python and re-running silently ran the previous build,
    because the sources live *in* the image rather than being bind-mounted.
    """
    if _docker_image_exists(image):
        if os.environ.get(SKIP_STALENESS_ENV, "").strip().lower() in (
                "1", "true", "yes", "y", "on"):
            return
        want = _source_fingerprint(repo)
        have = _image_fingerprint(image)
        if not want:
            return  # cannot read the tree; do not block on a check we can't make
        if have == want:
            return
        if not have:
            # Pre-dates the label (or came from a registry).  Rebuilding an
            # unlabelled image once is cheap and makes it self-describing after.
            console.print(
                f"[yellow]Image '{image}' carries no source fingerprint; "
                f"rebuilding so it matches this checkout.[/yellow]")
        else:
            console.print(
                f"[yellow]Image '{image}' was built from different sources "
                f"({have} != {want}); rebuilding.[/yellow]\n"
                f"[dim]Set {SKIP_STALENESS_ENV}=1 to reuse it anyway.[/dim]")
        _docker_build(
            image, repo, platform=platform,
            dockerfile_name=dockerfile_name, build_args=build_args,
        )
        return
    console.print(f"[dim]Image '{image}' not found locally.[/dim]")
    if _docker_pull(image):
        console.print(f"[green]Pulled {image} from registry.[/green]")
        return
    _docker_build(
        image,
        repo,
        platform=platform,
        dockerfile_name=dockerfile_name,
        build_args=build_args,
    )


def _detect_tee_platform(argv: list[str]) -> str | None:
    """Extract --tee-platform value from CLI args.

    Lower-cased because every ``--tee-platform`` option is declared
    ``click.Choice(..., case_sensitive=False)``: ``--tee-platform SGX-AZURE``
    is a valid invocation, and comparing the raw argv token against the
    lowercase platform slugs would miss it.  Missing the match here is not
    cosmetic — it silently picks the arm64 CLI image for ``sgx-azure``
    (:data:`_PLATFORMS_REQUIRING_AMD64`), where the Gramine signing tools
    are absent.  ``cloud_auth.cloud_for_platform`` normalises the same way.
    """
    for i, arg in enumerate(argv):
        if arg == "--tee-platform" and i + 1 < len(argv):
            return argv[i + 1].strip().lower()
        if arg.startswith("--tee-platform="):
            return arg.split("=", 1)[1].strip().lower()
    return None


def _detect_top_level_subcommand(argv: list[str]) -> str | None:
    """Return the first non-option token after the binary name (the Click group)."""
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        return arg
    return None


def _resolve_cli_image(
    base_image: str,
    tee_platform: str | None,
) -> tuple[str, str | None, str, dict[str, str]]:
    """Return ``(image_tag, docker_platform, dockerfile_name, build_args)``.

    Selection rules:

    * ``tee-crafter deploy ... --tee-platform sgx-azure`` on a non-amd64
      host uses ``tee-crafter:amd64`` and forces ``--platform linux/amd64``
      so the bundled Gramine / GSC signing tools are available.
    * Everything else uses the lean ``tee-crafter:latest`` image.
    """
    host = _host_arch()
    needs_amd64 = tee_platform in _PLATFORMS_REQUIRING_AMD64
    if needs_amd64 and host != "amd64":
        return f"{base_image}:amd64", "linux/amd64", "Dockerfile", {}
    return base_image, None, "Dockerfile", {}


def _exec_tee_crafter_in_docker(argv: list[str]) -> NoReturn:
    if not shutil.which("docker"):
        raise click.ClickException(
            "Docker is required to run TEE-Crafter.\n"
            "Install Docker Desktop (macOS) or Docker Engine (Linux) and try again."
        )

    build_ctx = _package_root()    # apps/cli — holds the Dockerfiles + src/
    workspace = _workspace_root()  # user's CWD — --source paths, .env, .gcloud
    base_image = _docker_image()
    tee_platform = _detect_tee_platform(argv)
    image, docker_platform, dockerfile_name, build_args = _resolve_cli_image(
        base_image, tee_platform,
    )
    _ensure_image(
        image,
        build_ctx,
        platform=docker_platform,
        dockerfile_name=dockerfile_name,
        build_args=build_args,
    )

    env_file = workspace / ".env"
    tty_flags = ["-it"] if sys.stdin.isatty() else ["-i"]
    docker_args: list[str] = [
        "docker", "run", "--rm", *tty_flags,
        "--network", "host",
        "--add-host", "host.docker.internal:host-gateway",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{workspace}:/workspace",
        "-w", "/workspace",
        "-e", f"{_IN_DOCKER_ENV}=1",
    ]

    if docker_platform:
        docker_args += ["--platform", docker_platform]

    if env_file.is_file():
        docker_args += ["--env-file", str(env_file)]

    for host_dir, container_dir in [
        (Path.home() / ".config" / "gcloud", "/root/.config/gcloud"),
    ]:
        if host_dir.is_dir():
            docker_args += ["-v", f"{host_dir}:{container_dir}"]

    # SIEM-SEC-6 / SLSA: persist the operator's provenance signing key
    # across container re-execs.  Without this mount every container
    # invocation gets a fresh ``/root/.tee-crafter`` so:
    #
    #   1. ``tee-crafter audit-gen-signing-key`` writes the key to a
    #      container layer that is deleted by ``--rm`` on exit; the
    #      next ``tee-crafter deploy`` therefore has *no* long-lived
    #      key configured, ``load_signing_key()`` raises, both the
    #      Ed25519 sidecars *and* the SLSA Provenance v1 emission are
    #      skipped, and every build silently ships an unsigned
    #      ``build_provenance.json``.
    #   2. Operators can't pin a stable fingerprint because every
    #      invocation produces a different key.
    #
    # Auto-create the host directory so first-time users don't have
    # to know about it; chmod 0700 keeps the host PEM operator-only.
    host_audit_dir = Path.home() / ".tee-crafter"
    try:
        host_audit_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        pass
    if host_audit_dir.is_dir():
        docker_args += ["-v", f"{host_audit_dir}:/root/.tee-crafter"]

    # Persist bake-time launch-measurement pins across container re-execs.
    # ``bake-ami`` auto-pins into the packaged ``tee_crafter/measurements``
    # registry, but inside the ``--rm`` container that path
    # (``/opt/tee-crafter/src/tee_crafter/measurements``) is a throwaway layer,
    # so pins would vanish on exit and ``deploy`` (a separate container) would
    # never see them.  Bind-mount the host's packaged registry and point
    # ``TEE_CRAFTER_MEASUREMENTS_DIR`` at it so bake writes, and deploy reads,
    # the operator's repo copy (apps/cli/src/tee_crafter/measurements).
    host_meas_dir = build_ctx / "src" / "tee_crafter" / "measurements"
    try:
        host_meas_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    if host_meas_dir.is_dir():
        container_meas_dir = "/opt/tee-crafter-measurements"
        docker_args += [
            "-v", f"{host_meas_dir}:{container_meas_dir}",
            "-e", f"TEE_CRAFTER_MEASUREMENTS_DIR={container_meas_dir}",
        ]

    # Allow host wrappers (CI runners, automation scripts) to inject
    # extra bind mounts so absolute paths they pass via argv (e.g.
    # `--source /workspace/clone`) are visible inside the re-exec
    # container.  Format: comma-separated "host:container" pairs; when
    # ":container" is omitted the host path is mounted at the same path
    # inside the container so absolute argv paths just work.
    extra_mounts = os.environ.get("TEE_CRAFTER_EXTRA_DOCKER_MOUNTS", "").strip()
    if extra_mounts:
        for spec in extra_mounts.split(","):
            spec = spec.strip()
            if not spec:
                continue
            host_part, _, container_part = spec.partition(":")
            host_path = Path(host_part).expanduser().resolve()
            if not host_path.exists():
                continue
            container_path = container_part or str(host_path)
            docker_args += ["-v", f"{host_path}:{container_path}"]

    workspace_gcloud = workspace / ".gcloud"
    if workspace_gcloud.is_dir():
        docker_args += ["-e", "CLOUDSDK_CONFIG=/workspace/.gcloud"]

    docker_args += _env_passthrough_args()
    docker_args += [image] + argv[1:]
    os.execvp("docker", docker_args)


#: Wrapper-owned variables that must NOT be inherited from the host.
#:
#: ``TEE_CRAFTER_IN_DOCKER`` is the recursion guard and is set explicitly to 1.
#: ``TEE_CRAFTER_MEASUREMENTS_DIR`` is rewritten to the *container* mount point,
#: so inheriting the operator's host path would point the registry at a
#: directory that does not exist inside the container.  The remaining two only
#: mean anything to this wrapper, which has already read them.
_WRAPPER_OWNED_ENV = frozenset({
    _IN_DOCKER_ENV,
    "TEE_CRAFTER_MEASUREMENTS_DIR",
    "TEE_CRAFTER_DOCKER_IMAGE",
    "TEE_CRAFTER_EXTRA_DOCKER_MOUNTS",
})


def _env_passthrough_args(environ=None) -> list[str]:
    """Forward the operator's ``TEE_CRAFTER_*`` / ``TF_VAR_*`` environment.

    Without this the CLI silently discards every one of them.  Only the
    workspace ``.env`` file (via ``--env-file``) and three explicitly-set
    variables crossed into the container, so a documented knob exported in the
    shell — ``TEE_CRAFTER_ALLOW_NO_SECURE_BOOT=1 tee-crafter deploy …`` — did
    nothing at all.  Worse, the CLI's own refusals *instruct* the operator to
    set exactly these variables, so the advice could not be followed:

        UEFI Secure Boot is not proven for this image
        … accept the weaker posture explicitly with
          TEE_CRAFTER_ALLOW_NO_SECURE_BOOT=1

    ``TF_VAR_*`` is included because Terraform runs inside the container too.

    Names are passed as bare ``-e NAME`` rather than ``-e NAME=value``: Docker
    then reads the value from this process's own environment, so it never
    appears in the ``docker`` command line where ``ps`` would expose it to any
    other local user.  That matters because several of these legitimately hold
    secrets (SIEM tokens, API keys).
    """
    from tee_crafter.core.pinned_image_env import ALL_PINNED_IMAGE_ENV_KEYS

    env = os.environ if environ is None else environ
    names = sorted(
        name for name in env
        if (name.startswith("TEE_CRAFTER_")
            or name.startswith("TF_VAR_")
            # The pinned-image variables match neither prefix by design
            # (AWS_NITRO_AMI_ARM64, AZURE_SGX_IMAGE, GCP_TDX_IMAGE, …), so they
            # have to be named. They were dropped for the same reason as the
            # rest: only ``.env`` crossed into the container, so exporting one
            # in a shell did nothing.
            or name in ALL_PINNED_IMAGE_ENV_KEYS)
        and name not in _WRAPPER_OWNED_ENV
    )
    args: list[str] = []
    for name in names:
        args += ["-e", name]
    return args


@click.group()
def cli():
    """TEE-Crafter: deploy a Dockerfile / OCI image into a TEE (requires --batch or --persistent) with attestation, audit, and signed provenance."""
    pass


register_commands(cli)


def main():
    _configure_cli_logging()
    argv = sys.argv[:]
    if _should_exec_in_docker(argv):
        _exec_tee_crafter_in_docker(argv)
    from tee_crafter.cli.cloud_auth import bootstrap_cloud_auth
    bootstrap_cloud_auth(_detect_tee_platform(argv))
    cli()


if __name__ == "__main__":
    main()
