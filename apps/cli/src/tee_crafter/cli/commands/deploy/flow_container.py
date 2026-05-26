"""Container-mode flow: build from the user's Dockerfile, run the image as-is.

This is the single deployment flow. It builds the user's container, scans it,
records its measurement, and returns a 5-tuple consumed by the downstream
platform code (Nitro EIF build, CVM deploy phases, etc.). There is no LLM and no
source translation — the legacy ingestion pipeline has been removed.

For Nitro: generates a multi-stage Dockerfile merging user image + runtime.
For CVMs: generates a proxy ``app_vsock.py`` that forwards to the user's
          container on localhost, plus saves the container image tarball.
"""

import hashlib
import logging
import fnmatch
import os
import subprocess
import uuid


from tee_crafter.core.audit import sha256_hex
from tee_crafter.core.builder.builder import (
    render_container_dockerfile_template,
    stage_container_artifacts,
)
from tee_crafter.core.packaging.container_wrap import (
    build_cvm_vsock_from_container,
    detect_container_port,
    extract_image_startup_cmd,
    extract_image_workdir,
    generate_nitro_entrypoint,
    ContainerValidationError,
)
from tee_crafter.cli.constants import Panel, console, PIPELINE_VERSION
from tee_crafter.cli.deployment.common.local_docker_prune import write_pipeline_image_marker

logger = logging.getLogger("tee_crafter.flow_container")

# Must not reuse the CLI image name (``tee-crafter``, ``tee-crafter:latest``,
# ``tee-crafter:amd64``): ``docker build -t`` would retag the CLI on the host
# daemon and ``docker save`` / parallel deploys break unpredictably.
_USER_APP_IMAGE_REPO = "tee-crafter-user-app"



def _dockerignore_patterns(source_path):
    """Patterns from ``.dockerignore``, or an empty tuple when absent.

    Deliberately literal: comments, blank lines and negations (``!``) are
    dropped, and a trailing ``/`` is stripped so a directory rule still matches
    its name.  Negations are *not* honoured as un-excludes — treating a file as
    shielded when it might not be would weaken the check, and PKG-005 defaults
    to flagging.
    """
    path = os.path.join(source_path, ".dockerignore")
    if not os.path.isfile(path):
        return ()
    pats = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                pats.append(line.rstrip("/"))
    except OSError:
        return ()
    return tuple(pats)

def _emit_container_vln_verdicts(audit, vuln_result, *, ran: bool,
                                  error: str = "") -> None:
    """Emit VLN-001..006 structured rows for the deploy-container scan.

    Without this the container flow would only write a free-form ``Vulnerability scan``
    row and VLN-001/002/003/004/005 end up swept as WARN by
    ``_sweep_missing_required_checks`` at save time.

    ``VLN-006`` (container base image digest pinned) is recorded later by
    the per-platform Dockerfile renderer (``stage_container_artifacts``
    paths), so we deliberately do not emit it here.
    """
    phase = "Phase 1: Container"
    if not ran or vuln_result is None or not getattr(vuln_result, "success", False):
        # Scanner missing / failed to run.  Emit VLN-001 explicitly as
        # info-not-evidence so the sweep doesn't fire a noisy WARN.
        audit.record_check(
            phase, "Vulnerability scanner ran", "VLN-001",
            observed=False,
            note=(error or
                  (getattr(vuln_result, "error", "") or "scanner unavailable"))[:200],
        )
        # VLN-002/003/004 are platform-required: surface them as warn
        # rows with an explanatory note instead of letting the sweep
        # fill them in with a generic remediation pointer.
        for cid, title in (
            ("VLN-002", "critical == 0"),
            ("VLN-003", "high <= threshold"),
            ("VLN-004", "medium <= threshold"),
        ):
            from tee_crafter.core.audit import Verdict as _V
            audit.record_check(
                phase, title, cid,
                verdict=_V.WARN, observed=False,
                note="scanner did not run on container image; "
                     "install Trivy or Grype to gate this build",
            )
        return

    high_t = _int_env("TEE_CRAFTER_VULN_HIGH_THRESHOLD", 0)
    med_t = _int_env("TEE_CRAFTER_VULN_MEDIUM_THRESHOLD", 25)
    # Read the same ``blocking_*`` numbers the deploy gate reads.  These used to
    # take the raw counts, which meant the gate could pass an image with no
    # fixable findings while VLN-002 recorded ``fail`` from ``critical=4`` — and
    # VLN-002 is in DEFAULT_REQUIRED_CHECKS, so `verify-provenance` then failed
    # CI on a build the deploy had just approved.  Observed on the live snp-aws
    # run of 2026-08-21 (VLN-002/003/004 all ``fail``, deploy gate ``pass``).
    # The raw and unfixed totals stay in the note so nothing is lost.
    crit = int(getattr(vuln_result, "blocking_critical", 0) or 0)
    high = int(getattr(vuln_result, "blocking_high", 0) or 0)
    med = int(getattr(vuln_result, "blocking_medium", 0) or 0)
    raw_c = int(getattr(vuln_result, "critical", 0) or 0)
    raw_h = int(getattr(vuln_result, "high", 0) or 0)
    raw_m = int(getattr(vuln_result, "medium", 0) or 0)

    audit.record_check(
        phase, "Vulnerability scanner ran", "VLN-001",
        observed=True,
        note=f"scanner={vuln_result.scanner} report={vuln_result.report_path}",
    )
    audit.record_check(
        phase, "fixable critical == 0", "VLN-002",
        expected=True, observed=(crit == 0),
        note=(f"fixable_critical={crit} (total={raw_c}, "
              f"no upstream fix={raw_c - crit})"),
    )
    audit.record_check(
        phase, "fixable high <= threshold", "VLN-003",
        expected=True, observed=(high <= high_t),
        note=(f"fixable_high={high} threshold={high_t} (total={raw_h}, "
              f"no upstream fix={raw_h - high})"),
    )
    audit.record_check(
        phase, "fixable medium <= threshold", "VLN-004",
        expected=True, observed=(med <= med_t),
        note=(f"fixable_medium={med} threshold={med_t} (total={raw_m}, "
              f"no upstream fix={raw_m - med})"),
    )


def _int_env(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
        return v if v >= 0 else default
    except ValueError:
        return default


def _new_user_image_tag() -> str:
    return f"{_USER_APP_IMAGE_REPO}:{uuid.uuid4().hex[:16]}"

_NITRO_PLATFORM = "nitro-aws"
_CVM_PLATFORMS = ("tdx-azure", "tdx-gcp", "snp-aws", "snp-azure", "snp-gcp",
                  "gpu-cc-gcp", "gpu-cc-azure", "gpu-cc-aws")
_SGX_PLATFORM = "sgx-azure"


def resolve_docker_platform(
    tee_platform: str,
    instance_type: str | None = None,
    enclave_cpu: int = 2,
    enclave_ram_mib: int = 4096,
) -> str:
    """Single source of truth: what ``--platform`` value do we pass to Docker?

    * Nitro: depends on the EC2 instance family — Graviton (``c6g``, ``c7g``,
      ``m6g``, ``r6g``, etc.) → ``linux/arm64``; everything else → ``linux/amd64``.
      The default Nitro host since 2026 is ``c6a.xlarge`` (x86_64) so that the
      default bake can enroll UEFI Secure Boot (see ``docs/nitro_flow.md`` and
      ``docs/security.md`` §15.1A).
    * Everything else (CVM / SGX / GPU-CC): always ``linux/amd64``.
    """
    if tee_platform != _NITRO_PLATFORM:
        return "linux/amd64"
    from tee_crafter.core.enclave import _resolve_platform
    return _resolve_platform(
        instance_type,
        enclave_cpu=enclave_cpu,
        enclave_ram_mib=enclave_ram_mib,
    )


def exposed_port_count(image_tag: str) -> int:
    """How many ports *image_tag* declares, or ``0`` if that cannot be read.

    Reading the built image rather than grepping the Dockerfile for ``EXPOSE``
    is deliberate: a port inherited from the base image (``FROM nginx``) never
    appears in the user's Dockerfile but is exactly as fatal to a batch run.
    """
    result = subprocess.run(
        ["docker", "image", "inspect", image_tag,
         "--format", "{{len .Config.ExposedPorts}}"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return 0
    try:
        return int((result.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def warn_if_batch_image_looks_like_a_server(
    image_tag: str, *, batch_timeout: int,
) -> bool:
    """Warn, at build time, when ``--batch`` is handed a long-running server.

    Batch mode runs the user image as-is and captures what it wrote once it
    exits.  A server never exits, so the oneshot sits until ``TimeoutStartSec``
    — an hour by default — and then fails with nothing captured.

    This check used to run on the VM, after ``docker load``, which is far too
    late to be useful: the operator had already paid roughly twenty minutes of
    Terraform and Bastion provisioning to be told their image was the wrong
    shape.  Here it costs one ``docker image inspect`` against an image that is
    already local, before any cloud resource exists.

    ``ExposedPorts`` is the discriminator, and it separates the four shipped
    examples cleanly: ``docker_flask_api``, ``hello_http`` and
    ``gpu_confidential_inference`` each declare 8080, while
    ``fintech_fraud_detection`` — the only batch-shaped one — declares none.
    It is a heuristic, so this only warns: a batch job is free to expose a port,
    and refusing on that basis would be wrong.

    Returns whether a warning was emitted (for tests).
    """
    count = exposed_port_count(image_tag)
    if count <= 0:
        return False
    console.print(
        f"[bold yellow]! This image exposes {count} port(s), which usually means "
        f"a long-running server.[/bold yellow]\n"
        f"[yellow]  Batch mode waits for the container to exit and captures what "
        f"it wrote. A server never exits, so this will sit for up to "
        f"{batch_timeout}s and then fail with nothing captured.\n"
        f"  A batch image should read its input, write its output and exit — see "
        f"examples/fintech_fraud_detection. Use --persistent for a server."
        f"[/yellow]")
    return True


#: Name the Nitro EIF overlay COPYs, at the build-dir root.
EIF_SIEM_ENV_PUBLIC = "siem.env.public"


def _stage_siem_env_public_for_eif(build_dir: str) -> str:
    """Put ``siem.env.public`` where the Docker build context can COPY it.

    ``write_siem_config`` writes the canonical copy under ``<build_dir>/siem/``.
    The EIF overlay's ``COPY siem.env.public`` resolves against the build-dir
    root, so the file is mirrored here — and an empty placeholder is written
    when SIEM is off, because an unconditional ``COPY`` of a missing file fails
    the whole image build.

    Only the *public* half is ever copied.  ``siem_mode.SECRET_ENV_KEYS`` keeps
    the Splunk HEC token and Datadog API key out of this file precisely so that
    baking it into a measured, published image does not leak a live credential;
    those reach the enclave over the attested ``--secrets-env`` channel instead.
    """
    from tee_crafter.core.audit import build_layout as _layout

    dest = os.path.join(build_dir, EIF_SIEM_ENV_PUBLIC)
    src = _layout.siem_env_public(build_dir)
    if os.path.isfile(src) and os.path.abspath(src) != os.path.abspath(dest):
        with open(src, "r", encoding="utf-8") as fh:
            body = fh.read()
    elif os.path.isfile(dest):
        return dest
    else:
        body = "# tee-crafter SIEM env (empty: --siem not enabled)\n"
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(dest, 0o644)
    return dest


def _cleanup_user_image(image_tag: str) -> None:
    """Remove the locally-built user image."""
    try:
        subprocess.run(
            ["docker", "rmi", image_tag],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        logger.debug("Image cleanup skipped: %s", image_tag)


def _build_user_image(source_dir: str, platform: str, image_tag: str) -> str:
    """Build the user's Docker image and return its ``sha256`` digest.

    Always passes ``--platform`` so the resulting image matches the remote
    TEE instance architecture, regardless of the local host arch.
    """
    logger.info("Building %s from %s (platform=%s)", image_tag, source_dir, platform)

    env = dict(os.environ)
    env["DOCKER_BUILDKIT"] = "1"
    build_cmd = ["docker", "build", "--platform", platform, "--load", "-t", image_tag, "."]

    result = subprocess.run(build_cmd, cwd=source_dir, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raise ContainerValidationError(
            f"docker build failed:\n{result.stderr}\n{result.stdout}"
        )

    digest_result = subprocess.run(
        ["docker", "inspect", "--format={{.Id}}", image_tag],
        capture_output=True, text=True,
    )
    return digest_result.stdout.strip() if digest_result.returncode == 0 else "unknown"


def _save_user_image(dest_path: str, image_tag: str) -> str:
    """Save the user image as a tarball for upload to CVM."""
    tar_path = os.path.join(dest_path, "user_container.tar")
    result = subprocess.run(
        ["docker", "save", "-o", tar_path, image_tag],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise ContainerValidationError(f"docker save failed:\n{result.stderr}")
    tar_size_mb = os.path.getsize(tar_path) / (1024 * 1024)
    if tar_size_mb > 2048:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] Container image tarball is "
            f"{tar_size_mb:.0f} MB — large images increase upload time to CVM."
        )
    return tar_path


def run_container_phases(
    progress,
    audit,
    source: str,
    container_port: int | None,
    tee_platform: str,
    instance_type: str | None = None,
    enclave_cpu: int = 2,
    enclave_ram: int = 4096,
    batch: bool = False,
    batch_timeout: int = 3600,
):
    """Container-mode pipeline: Dockerfile → build → stage → ready for deploy.

    Returns ``(build_dir, source_summary)`` or ``None`` on failure.

    ``batch`` is threaded in purely so the server-image heuristic can run here,
    against the freshly built image, instead of on the VM twenty minutes later
    — see :func:`warn_if_batch_image_looks_like_a_server`.

    The container is run as-is: TEE-Crafter never reads, injects, or measures
    an application data file. The user's Dockerfile orchestrates how the
    workload obtains its data (bundled files, object storage, a database
    connection, …) inside the sealed TEE boundary.
    """
    source_path = os.path.abspath(source)
    dockerfile_path = os.path.join(source_path, "Dockerfile")

    if not os.path.isfile(dockerfile_path):
        console.print(
            "[bold red]Error:[/bold red] No Dockerfile found in source directory."
        )
        audit.record("Phase 1: Container", "Dockerfile check", "fail")
        return None

    effective_port = detect_container_port(dockerfile_path, container_port)

    docker_platform = resolve_docker_platform(
        tee_platform, instance_type, enclave_cpu, enclave_ram,
    )

    user_image_tag = _new_user_image_tag()

    # -- Step 1: Build user Docker image ----------------------------------------
    task = progress.add_task(
        f"[yellow]Step 1: Building user Docker image ({docker_platform})...[/yellow]",
        total=None,
    )
    try:
        image_digest = _build_user_image(source_path, docker_platform, user_image_tag)
    except ContainerValidationError as e:
        progress.update(task, description=f"[bold red]✗ Step 1 Failed: {e}[/bold red]")
        console.print(f"[red]{e}[/red]")
        audit.record("Phase 1: Container", "Docker build", "fail", error=str(e)[:500])
        return None

    progress.update(
        task, description=f"[green]✓ Step 1: User image built ({user_image_tag}).[/green]"
    )
    # Before Terraform, not after: the whole point is that the operator hears
    # about a mis-shaped batch image while nothing has been provisioned yet.
    if batch:
        warn_if_batch_image_looks_like_a_server(
            user_image_tag, batch_timeout=batch_timeout)
    audit.record(
        "Phase 1: Container", "Docker image built", "pass",
        image_tag=user_image_tag, image_digest=image_digest,
        docker_platform=docker_platform, container_port=effective_port,
    )
    audit.record_check(
        "Phase 1: Container", "Docker image built (tag + digest pinned)",
        "PKG-001",
        observed=bool(user_image_tag and image_digest),
        note=f"tag={user_image_tag} digest={image_digest}",
    )
    # PKG-006 — bundle digest is captured later by the Nitro EIF step
    # (which writes the .tar bundle's sha256).  We emit PKG-002/003 here
    # because the Dockerfile + entrypoint have already been staged.
    try:
        from tee_crafter.core.audit import sha256_file
        df_path = os.path.join(source_path, "Dockerfile")
        if os.path.isfile(df_path):
            df_sha = sha256_file(df_path)
            audit.record_check(
                "Phase 1: Container", "Dockerfile sha256 recorded", "PKG-002",
                observed=bool(df_sha), note=df_sha[:16],
            )
        entry_path = os.path.join(source_path, "entrypoint.sh")
        if os.path.isfile(entry_path):
            entry_sha = sha256_file(entry_path)
            audit.record_check(
                "Phase 1: Container", "Entrypoint sha256 recorded", "PKG-003",
                observed=bool(entry_sha), note=entry_sha[:16],
            )
    except Exception:
        pass
    # PKG-005 — .env / secret hygiene check on the build context.
    #
    # ``.dockerignore`` is honoured, because it genuinely removes a path from
    # the context: `docker build` never sends it to the daemon, so no COPY can
    # put it in the image.  Ignoring it made the check unsatisfiable for the
    # correct fix — you ship a `.dockerignore`, the file is provably excluded,
    # and PKG-005 still failed HIGH.  A gate that cannot be satisfied is one
    # people learn to skip (the same reasoning as the fixable-vs-unfixed
    # vulnerability gate).  A file that is present *and* not excluded is still
    # flagged, which is the case that matters.
    try:
        excluded = _dockerignore_patterns(source_path)
        sensitive, shielded = [], []
        for name in (".env", ".env.local", "credentials.json", "id_rsa", "id_ed25519"):
            if not os.path.isfile(os.path.join(source_path, name)):
                continue
            if any(fnmatch.fnmatch(name, pat) for pat in excluded):
                shielded.append(name)
            else:
                sensitive.append(name)
        if sensitive:
            note = f"flagged={sensitive}"
        elif shielded:
            note = f"clean (.dockerignore excludes {shielded} from the context)"
        else:
            note = "clean"
        audit.record_check(
            "Phase 1: Container", "No .env / no secrets in build context",
            "PKG-005",
            observed=(len(sensitive) == 0),
            note=note,
        )
    except Exception:
        pass

    # -- Step 1b: Vulnerability scan -------------------------------------------
    task_vuln = progress.add_task(
        "[yellow]Step 1b: Scanning image for vulnerabilities...[/yellow]", total=None,
    )
    # Production gating: any CRITICAL or HIGH CVE aborts the deploy unless
    # the operator explicitly opts out via ``TEE_CRAFTER_ALLOW_VULNERABLE=1``
    # (also surfaced as ``--allow-vulnerable`` on ``tee-crafter deploy`` and
    # ``deploy-container``).  Trivy / Grype not being installed does NOT
    # abort — the scan is best-effort observability, gating only triggers
    # when a scanner actually ran and reported findings.
    _allow_vulnerable = os.environ.get("TEE_CRAFTER_ALLOW_VULNERABLE", "").strip().lower() in (
        "1", "true", "yes", "y", "on",
    )
    _scan_gate_failed: tuple[str, "object"] | None = None
    try:
        from tee_crafter.core.security.vuln_scan import scan_image
        # Per-run subdirectory.  ``scan_image`` writes a fixed
        # ``trivy_report.json`` / ``grype_report.json`` inside whatever
        # directory it is handed, so a shared ``<source>/.tee_crafter_scan``
        # meant two concurrent deploys of the same source overwrote each
        # other's report — and the ``report_path`` recorded in each build's
        # provenance then pointed at the *other* run's findings.  The image
        # tag's uuid suffix is unique per run.
        scan_dir = os.path.join(source_path, ".tee_crafter_scan",
                                user_image_tag.rsplit(":", 1)[-1])
        from tee_crafter.core.security.vuln_scan import (
            count_ignore_entries, ignore_file_for,
        )
        _ignore_file = ignore_file_for(source_path)
        _ignored_n = count_ignore_entries(_ignore_file)
        if _ignored_n:
            console.print(
                f"[dim]Vulnerability scan: honouring "
                f"{os.path.basename(_ignore_file)} ({_ignored_n} accepted "
                f"finding{'s' if _ignored_n != 1 else ''}); recorded in the "
                f"build provenance.[/dim]")
        vuln_result = scan_image(user_image_tag, scan_dir,
                                 ignore_file=_ignore_file)
        if vuln_result.success:
            summary = (
                f"C:{vuln_result.critical} H:{vuln_result.high} "
                f"M:{vuln_result.medium} L:{vuln_result.low}"
            )
            # "Clean" now means "nothing left to act on", so an image sitting on
            # unfixed distro CVEs must not be described as clean — that is the
            # sentence an auditor would quote back.  Name the number instead.
            _unfixed = vuln_result.unfixed_critical + vuln_result.unfixed_high
            if vuln_result.passed and _unfixed:
                progress.update(
                    task_vuln,
                    description=(
                        f"[green]✓ Step 1b: no fixable CRITICAL/HIGH "
                        f"({vuln_result.scanner}); {_unfixed} unfixed upstream "
                        f"(C:{vuln_result.unfixed_critical} "
                        f"H:{vuln_result.unfixed_high}) — no patch exists yet."
                        f"[/green]"
                    ),
                )
            elif vuln_result.passed:
                progress.update(
                    task_vuln,
                    description=f"[green]✓ Step 1b: Vulnerability scan clean ({vuln_result.scanner}).[/green]",
                )
            elif _allow_vulnerable:
                progress.update(
                    task_vuln,
                    description=(
                        f"[yellow]⚠ Step 1b: Vulnerabilities found ({summary}) — "
                        f"continuing because TEE_CRAFTER_ALLOW_VULNERABLE is set.[/yellow]"
                    ),
                )
            else:
                progress.update(
                    task_vuln,
                    description=(
                        f"[red]✗ Step 1b: Vulnerability gate failed ({summary}).[/red]"
                    ),
                )
                _scan_gate_failed = (summary, vuln_result)
            audit.record(
                "Phase 1: Container", "Vulnerability scan",
                "pass" if (vuln_result.passed or _allow_vulnerable) else "fail",
                scanner=vuln_result.scanner,
                critical=vuln_result.critical, high=vuln_result.high,
                medium=vuln_result.medium, low=vuln_result.low,
                total=vuln_result.total, passed=vuln_result.passed,
                report_path=vuln_result.report_path,
                gate_allowed=bool(_allow_vulnerable),
                # Both halves of the split, plus any accepted risks: demoting a
                # finding from blocking to informational is only defensible if
                # the numbers survive in the provenance.
                fixable_critical=vuln_result.fixable_critical,
                fixable_high=vuln_result.fixable_high,
                unfixed_critical=vuln_result.unfixed_critical,
                unfixed_high=vuln_result.unfixed_high,
                accepted_findings=_ignored_n,
                accepted_findings_file=(
                    os.path.basename(_ignore_file) if _ignore_file else ""),
            )
            _emit_container_vln_verdicts(audit, vuln_result, ran=True)
        else:
            # A gate that did not run is not a gate that passed.  The audit
            # ledger already says so (VLN-001 observed=False, VLN-002/3/4
            # WARN), but this progress line is what the operator actually
            # reads, and a dim green tick next to "skipped" is indistinguishable
            # from a clean scan in a list of twenty rows.
            progress.update(
                task_vuln,
                description=(
                    f"[yellow]⚠ Step 1b: Vulnerability scan did NOT run "
                    f"({vuln_result.error[:60]}) — not a pass.[/yellow]"
                ),
            )
            audit.record(
                "Phase 1: Container", "Vulnerability scan", "skipped",
                scanner=vuln_result.scanner, error=vuln_result.error[:200],
            )
            _emit_container_vln_verdicts(audit, vuln_result, ran=False)
    except Exception as e:
        progress.update(
            task_vuln,
            description=(
                f"[yellow]⚠ Step 1b: Vulnerability scan did NOT run ({e}) "
                f"— not a pass.[/yellow]"
            ),
        )
        logger.debug("Vulnerability scan error: %s", e)
        _emit_container_vln_verdicts(audit, None, ran=False, error=str(e))

    if _scan_gate_failed is not None:
        summary, vuln_result = _scan_gate_failed
        report_path = getattr(vuln_result, "report_path", "") or "(no report path)"
        from tee_crafter.core.security.vuln_scan import STRICT_ENV as _VULN_STRICT_ENV
        _strict_on = os.environ.get(_VULN_STRICT_ENV, "").strip().lower() in (
            "1", "true", "yes", "y", "on")
        _blocking = (f"C:{vuln_result.blocking_critical} "
                     f"H:{vuln_result.blocking_high}")
        if _strict_on:
            _why = (f"[yellow]{_VULN_STRICT_ENV}=1[/yellow] is set, so every "
                    f"CRITICAL/HIGH blocks — including the "
                    f"{vuln_result.unfixed_critical + vuln_result.unfixed_high} "
                    f"with no upstream fix.")
            _how = (f"Unset [yellow]{_VULN_STRICT_ENV}[/yellow] to block only on "
                    f"findings you can actually patch.")
        else:
            _why = ("These have a fixed version available upstream, so they are "
                    "patchable today.")
            _how = ("Bump the affected packages (or the base image) and rerun. "
                    "Findings with no upstream fix do not block and are listed "
                    "separately above.")
        console.print(Panel.fit(
            f"[bold red]Vulnerability gate failed[/bold red]\n\n"
            f"Blocking (fixable) CRITICAL/HIGH: [yellow]{_blocking}[/yellow]\n"
            f"All findings: [yellow]{summary}[/yellow]\n"
            f"No upstream fix: [yellow]C:{vuln_result.unfixed_critical} "
            f"H:{vuln_result.unfixed_high}[/yellow]\n\n"
            f"Report: [cyan]{report_path}[/cyan]\n\n"
            f"{_why}\n{_how}\n\n"
            f"To override entirely (NOT for production), export\n"
            f"  [yellow]TEE_CRAFTER_ALLOW_VULNERABLE=1[/yellow]\n"
            f"or pass [yellow]--allow-vulnerable[/yellow] to the deploy command.",
            border_style="red",
        ))
        return None

    # -- Step 2: Platform-specific packaging ------------------------------------
    if tee_platform == _NITRO_PLATFORM:
        result = _stage_nitro_container(
            progress, audit, source_path, effective_port,
            user_image_tag=user_image_tag,
        )
    elif tee_platform in _CVM_PLATFORMS:
        result = _stage_cvm_container(
            progress, audit, source_path, effective_port,
            tee_platform,
            user_image_tag=user_image_tag,
        )
    elif tee_platform == _SGX_PLATFORM:
        result = _stage_cvm_container(
            progress, audit, source_path, effective_port,
            tee_platform,
            user_image_tag=user_image_tag,
        )
        # SGX is batch-only (v1), and there is deliberately
        # No local graminize step: `gsc` builds for the Docker daemon's native
        # architecture and Gramine is x86-only, so this only ever worked on an
        # amd64 host.  `batch.graminize_on_vm` does it on the SGX VM instead,
        # where the enclave actually runs.  The fail-closed behaviour moved with
        # it — a failed graminize aborts the deploy from there.
    else:
        console.print(f"[bold red]Unknown platform: {tee_platform}[/bold red]")
        return None

    # CVM/SGX: drop the user image as soon as the tarball is saved — nothing else needs it locally.
    # Nitro: the combined Dockerfile in build_dir still has ``FROM <user_image_tag>`` for Steps 5–6
    # (verify_docker_build + nitro-cli build-enclave); removal happens right after a successful EIF
    # build in ``deploy_container._deploy_nitro_container`` via the same marker-driven prune.
    if result is not None and tee_platform != _NITRO_PLATFORM:
        _cleanup_user_image(user_image_tag)
    if result is not None:
        build_dir = result[0]
        write_pipeline_image_marker(build_dir, user_image_tag)
    return result


def _stage_nitro_container(
    progress, audit, source_path, container_port,
    *,
    user_image_tag: str,
):
    """Nitro path: user image as base + TEE overlay + entrypoint for both processes.

    Also saves the user image as ``user_container.tar`` so the batch
    container path (``deploy-container --batch``) can ship it to the host
    VM the same way every other platform does.  The standard nitro
    service-mode pipeline ignores this tarball (it builds the EIF from the
    user image directly), so its presence is a no-op there.
    """
    task = progress.add_task(
        "[yellow]Step 3: Generating Nitro container Dockerfile...[/yellow]", total=None
    )

    try:
        user_cmd = extract_image_startup_cmd(user_image_tag)
        user_workdir = extract_image_workdir(user_image_tag)
    except ContainerValidationError as e:
        progress.update(task, description=f"[bold red]✗ Step 3 Failed: {e}[/bold red]")
        console.print(f"[red]{e}[/red]")
        audit.record("Phase 2: Container Packaging", "CMD extraction", "fail", error=str(e))
        return None

    dockerfile_content = render_container_dockerfile_template(user_image_tag, container_port)
    entrypoint_content = generate_nitro_entrypoint(user_cmd, container_port, user_workdir)
    vsock_code = build_cvm_vsock_from_container(container_port)

    build_dir = stage_container_artifacts(
        source_dir=source_path,
        vsock_code=vsock_code,
        dockerfile_content=dockerfile_content,
        stage_label="nitro",
    )

    with open(os.path.join(build_dir, "tee_entrypoint.sh"), "w", encoding="utf-8") as f:
        f.write(entrypoint_content)
    os.chmod(os.path.join(build_dir, "tee_entrypoint.sh"), 0o755)

    # The container overlay always COPYs app.env; guarantee it exists (empty
    # unless --secrets-env later bakes plaintext config into it).
    from tee_crafter.cli.commands.deploy.secret_env import ensure_build_app_env
    ensure_build_app_env(build_dir)

    # Same contract for the SIEM half.  The overlay COPYs siem.env.public into
    # the EIF so the in-enclave exporter and the fail-closed gate can see
    # whether SIEM is on; an unconditional COPY needs the file to exist even
    # when --siem was not passed.  ``write_siem_config`` puts the real one under
    # ``siem/``, so this both hoists that copy to the build-dir root (where the
    # Docker build context expects it) and writes an empty placeholder when
    # there is nothing to hoist.
    _stage_siem_env_public_for_eif(build_dir)

    # Persist user_container.tar so deploy-container --batch can ship it to
    # the host VM via SSM/S3 (same flow used by every other platform).  The
    # standard nitro service-mode deploy does not read this file — it
    # builds the EIF straight from the user image — so creating it is
    # additive and the service-mode path is unaffected.
    task_save = progress.add_task(
        "[yellow]Step 3b: Saving user container image (for batch transport)...[/yellow]",
        total=None,
    )
    try:
        tar_path = _save_user_image(build_dir, user_image_tag)
        h = hashlib.sha256()
        with open(tar_path, "rb") as _tf:
            for chunk in iter(lambda: _tf.read(1 << 20), b""):
                h.update(chunk)
        tar_sha256 = h.hexdigest()
        progress.update(
            task_save,
            description="[green]✓ Step 3b: Container image saved as tarball.[/green]",
        )
        audit.record(
            "Phase 2: Container Packaging", "Container image saved (nitro batch transport)",
            "pass",
            tar_path=tar_path, tar_sha256=tar_sha256,
            tar_size_mb=round(os.path.getsize(tar_path) / (1024 * 1024), 1),
        )
    except ContainerValidationError as e:
        progress.update(
            task_save, description=f"[bold red]✗ Step 3b Failed: {e}[/bold red]"
        )
        audit.record(
            "Phase 2: Container Packaging", "Container image save (nitro batch transport)",
            "fail", error=str(e),
        )
        return None

    audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir=build_dir)
    progress.update(
        task,
        description=f"[green]✓ Step 3: Nitro container artifacts staged in {os.path.basename(build_dir)}.[/green]",
    )
    audit.record(
        "Phase 2: Container Packaging", "Nitro multi-stage Dockerfile", "pass",
        dockerfile_sha256=sha256_hex(dockerfile_content),
        entrypoint_sha256=sha256_hex(entrypoint_content),
        user_cmd=user_cmd, container_port=container_port,
    )

    source_summary = f"[container mode: {user_image_tag}, port {container_port}]"
    return build_dir, source_summary


#: Explicit, audited opt-in to ship a NON-ENCLAVE image on ``sgx-azure``.
#: Without GSC the container runs as an ordinary process on the SGX VM: there
#: is no enclave, no MRENCLAVE, and nothing to attest — but the deploy used to
#: report success anyway, which is worse than failing.
def _stage_cvm_container(
    progress, audit, source_path, container_port,
    tee_platform,
    *,
    user_image_tag: str,
):
    """CVM path: proxy vsock + container tarball for docker-load in guest."""
    task = progress.add_task(
        f"[yellow]Step 3: Staging {tee_platform.upper()} container artifacts...[/yellow]",
        total=None,
    )

    vsock_code = build_cvm_vsock_from_container(container_port)
    build_dir = stage_container_artifacts(
        source_dir=source_path,
        vsock_code=vsock_code,
        dockerfile_content="",
        stage_label=tee_platform,
    )

    from tee_crafter.cli.deployment.common.wheel_manager import ensure_tee_deps_in_requirements
    ensure_tee_deps_in_requirements(os.path.join(build_dir, "app", "requirements.txt"))

    task_save = progress.add_task(
        "[yellow]Step 3b: Saving user container image...[/yellow]", total=None
    )
    try:
        tar_path = _save_user_image(build_dir, user_image_tag)
        h = hashlib.sha256()
        with open(tar_path, "rb") as _tf:
            for chunk in iter(lambda: _tf.read(1 << 20), b""):
                h.update(chunk)
        tar_sha256 = h.hexdigest()
        progress.update(
            task_save,
            description="[green]✓ Step 3b: Container image saved as tarball.[/green]",
        )
        audit.record(
            "Phase 2: Container Packaging", "Container image saved", "pass",
            tar_path=tar_path, tar_sha256=tar_sha256,
            tar_size_mb=round(os.path.getsize(tar_path) / (1024 * 1024), 1),
        )
    except ContainerValidationError as e:
        progress.update(
            task_save, description=f"[bold red]✗ Step 3b Failed: {e}[/bold red]"
        )
        audit.record(
            "Phase 2: Container Packaging", "Container image save", "fail",
            error=str(e),
        )
        return None

    digest_path = os.path.join(build_dir, "app", "container_digest.txt")
    with open(digest_path, "w", encoding="utf-8") as _df:
        _df.write(f"sha256:{tar_sha256}\n")
    logger.info("Container image digest written to %s", digest_path)

    audit.set_metadata(pipeline_version=PIPELINE_VERSION, build_dir=build_dir)
    progress.update(
        task,
        description=f"[green]✓ Step 3: {tee_platform.upper()} container artifacts staged.[/green]",
    )
    audit.record(
        "Phase 2: Container Packaging", f"{tee_platform} proxy + tarball", "pass",
        container_port=container_port,
        vsock_sha256=sha256_hex(vsock_code),
        container_image_digest=f"sha256:{tar_sha256}",
    )

    source_summary = f"[container mode: {user_image_tag}, port {container_port}]"
    return build_dir, source_summary
