"""Shared orchestration for tunneled (SSH) cloud deployment phases.

Before this module, every ``deployment/<platform>/<cloud>_phase.py`` carried a
~150-line near-identical copy of the same flow:

    [optional pre-apply hooks] -> terraform apply loop -> on success: read
    outputs + render panel + record verdicts -> open SSH tunnel (IAP on GCP,
    Bastion on Azure) -> (custom image: wait for SSH [+ optional hook]) |
    (base image: cloud-init setup) -> per-platform client verify -> post-deploy
    probes -> teardown / audit emit.

The GCP trio (snp/tdx/gpu-cc) and the Azure trio (snp/tdx/gpu-cc) only differed
in a handful of values and a couple of optional hooks, so they now reduce to a
:class:`TunneledPhaseConfig` + a call to :func:`run_tunneled_deployment_phase`.
The AWS/SSM phases diverge more (S3 upload, SIEM/BYOK sidecars, explicit
service start) so they keep their bespoke middle but share
:func:`handle_apply_failure` and :func:`finalize_phase`.

Behaviour note (deliberate normalisation): post-deploy probes now run **after**
a successful client verification on every cloud.  GCP already did this (the
service is only up once the client has uploaded artefacts + started it, so
probing earlier records ``observed=none`` and under-reports controls like
PDR-003).  The Azure phases previously probed *before* the client; they now
match GCP, which is the correct ordering.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

from tee_crafter.cli.constants import Console, KEEP_ON_FAILURE_ENV, keep_on_failure
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.iac import get_terraform_outputs
from tee_crafter.cli.deployment.common.terraform_step import (
    run_terraform_apply_loop,
    cleanup_resources,
)
from tee_crafter.cli.audit_helpers import save_audit_trail


@dataclass
class TunnelConn:
    """Connection handle for a deployed VM, built from Terraform outputs.

    ``tunnel`` is any object exposing ``start(timeout=...)``, ``stop()`` and a
    ``local_port`` attribute (``IAPTunnel`` on GCP, ``BastionTunnel`` on Azure).
    """
    tunnel: Any
    ssh_key_path: str
    admin_user: str


@dataclass
class TunneledPhaseConfig:
    """Per-(platform x cloud) parameters for :func:`run_tunneled_deployment_phase`."""

    tee_platform: str          # provenance slug, e.g. "snp-gcp"
    cloud_label: str           # human label for messages, e.g. "SNP GCP"
    tunnel_label: str          # "IAP" or "Bastion"

    # (outputs, measurements) -> rich renderable shown after a successful apply.
    render_panel: Callable[[dict, dict], Any]
    # (outputs, build_dir) -> TunnelConn, or None when outputs are insufficient
    # (which skips post-deploy automation but still finalises/teardowns).
    build_conn: Callable[[dict, str], Optional[TunnelConn]]
    # Cloud-init setup for a base (non-baked) image. Signature mirrors the
    # existing run_ssh_cloudinit_* helpers.
    setup_fn: Callable[..., bool]
    # (ssh_key_path, admin_user, port) -> bool : wait for SSH on a baked image.
    wait_for_ssh: Callable[[str, str, int], bool]
    # The per-platform client verifier. Returns True on a verified attestation.
    # (progress, console, build_dir, ssh_key_path, port, admin_user, audit,
    #  measurements, outputs) -> bool  (GCP uses outputs for instance/zone/project;
    #  Azure ignores it).
    run_client: Callable[..., bool]
    # The cloud's ``run_ssh_command`` (used to drive post-deploy probes).
    run_remote: Callable[..., tuple]

    # Optional: record Terraform outputs into the audit chain.
    record_outputs: Optional[Callable[[BuildAuditTrail, dict], None]] = None
    # Optional: side effects before terraform apply (Azure RG cleanup + network
    # watcher, GPU-CC NRAS egress policy).
    pre_apply: Optional[Callable[[Console, Optional[BuildAuditTrail]], None]] = None
    # Optional: extra work on the baked-image path after SSH is reachable
    # (GPU-CC: patch the unit's app filename + inject the NRAS key).
    on_custom_ami: Optional[Callable[[str, str, int], None]] = None


def destroy_on_failure(
    console: Console, build_dir: str, audit: Optional[BuildAuditTrail],
    *, destroy_fn, context: str, step: str,
) -> Optional[bool]:
    """Tear down after a failed deploy unless ``--keep-on-failure``.

    Returns ``None`` when no teardown was attempted (``--keep-on-failure``),
    otherwise the destroy's own success flag.  Callers treat "not ``None``"
    as ``destroy_already_run``.

    Previously this only happened when the operator had *also* passed
    ``--teardown`` (i.e. asked for a successful run to be torn down), which is
    a different intent entirely: a failed ``terraform apply`` without
    ``--teardown`` left a half-built VPC — and on GPU platforms a
    ``p5.4xlarge`` plus a NAT gateway — running indefinitely, while the CLI
    exited 0.  ``nitro-aws`` was the only phase that already destroyed
    unconditionally; this makes the other nine match it.
    """
    if keep_on_failure():
        console.print(
            f"[yellow]--keep-on-failure set: leaving resources up for "
            f"debugging.[/yellow]\n"
            f"[dim]Tear down with: [bold]tee-crafter destroy --build-dir "
            f"{os.path.abspath(build_dir)}[/bold][/dim]"
        )
        if audit:
            audit.record("Phase 5: Post-Deploy", step, "skip",
                         reason=f"{KEEP_ON_FAILURE_ENV} set")
        return None
    console.print(f"[yellow]Cleaning up failed deployment ({context})...[/yellow]")
    ok = destroy_fn(console, build_dir, context=context)
    console.print(
        "[green]✓ Resources destroyed.[/green]" if ok
        else "[bold red]✗ Cleanup failed — resources may still be billing. "
             f"Run: tee-crafter destroy --build-dir {os.path.abspath(build_dir)}"
             "[/bold red]"
    )
    if audit:
        audit.record("Phase 5: Post-Deploy", step, "pass" if ok else "fail")
    return bool(ok)


def handle_apply_failure(
    console: Console, build_dir: str, audit: Optional[BuildAuditTrail],
    teardown: bool, last_error_msg: str, *, destroy_fn, attempts: Optional[int] = None,
) -> bool:
    """Render the shared Terraform-apply-failure block. Returns ``destroy_already_run``."""
    if attempts:
        console.print(f"\n[bold red]Deployment failed after {attempts} Terraform apply attempts.[/bold red]")
    else:
        console.print("\n[bold red]Deployment failed.[/bold red]")
    console.print(f"[red]Last Error:[/red] {last_error_msg}\n")
    if audit:
        rec = {"attempts": attempts} if attempts else {}
        audit.record("Phase 4: Deployment", "Terraform apply", "fail", **rec)
    return destroy_on_failure(
        console, build_dir, audit, destroy_fn=destroy_fn,
        context="Post-failure cleanup",
        step="Terraform destroy (apply failed)",
    ) is not None


def finalize_phase(
    console: Console, build_dir: str, audit: Optional[BuildAuditTrail],
    teardown: bool, destroy_already_run: bool, *, tee_platform: str,
    outputs: dict, destroy_fn, prior_teardown_ok: Optional[bool] = None,
) -> None:
    """Render the shared teardown tail + emit teardown/cloud audit + save trail."""
    teardown_ok = prior_teardown_ok
    if teardown and not destroy_already_run:
        console.print("[yellow]Step 9: Executing teardown...[/yellow]")
        teardown_ok = destroy_fn(console, build_dir, context="Teardown")
        console.print(
            "[green]✓ Step 9: Resources destroyed.[/green]" if teardown_ok
            else "[bold red]✗ Step 9 Failed (teardown).[/bold red]"
        )
        if audit:
            audit.record("Phase 5: Post-Deploy", "Terraform destroy (teardown)",
                         "pass" if teardown_ok else "fail")
    elif not destroy_already_run:
        console.print(
            f"\n[dim]To tear down: "
            f"[bold]tee-crafter destroy --build-dir {os.path.abspath(build_dir)}[/bold][/dim]"
        )
    if audit:
        from tee_crafter.cli.audit_helpers import emit_teardown_and_cloud_audit
        emit_teardown_and_cloud_audit(
            audit, tee_platform=tee_platform,
            teardown_ok=teardown_ok,
            outputs=outputs or {},
            build_dir=build_dir,
        )
        save_audit_trail(audit, build_dir, console)


def _run_probes_after_client(
    cfg: TunneledPhaseConfig, console: Console, audit: Optional[BuildAuditTrail],
    build_dir: str, conn: TunnelConn, port: int,
) -> None:
    """Run post-deploy probes over the open tunnel (best effort)."""
    try:
        from tee_crafter.cli.deployment.common.post_deploy_probes import (
            run_post_deploy_probes,
        )

        def _probe_remote(c, _k=conn.ssh_key_path, _u=conn.admin_user, _p=port):
            return cfg.run_remote(c, _k, user=_u, port=_p, timeout=60)

        run_post_deploy_probes(
            audit, tee_platform=cfg.tee_platform,
            build_dir=build_dir, run_remote=_probe_remote,
        )
    except Exception as exc:
        console.print(
            f"[yellow]Post-deploy probes skipped: "
            f"{type(exc).__name__}: {exc}[/yellow]"
        )


def run_tunneled_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, measurements: dict,
    auto_approve: bool, teardown: bool, audit: Optional[BuildAuditTrail],
    custom_ami: Optional[str], *, cfg: TunneledPhaseConfig,
) -> bool:
    """Generic IAP/Bastion deployment phase shared by the GCP + Azure platforms.

    Returns ``True`` only when Terraform applied *and* the post-deploy
    automation verified the attestation; the CLI turns ``False`` into a
    non-zero exit.
    """
    if cfg.pre_apply is not None:
        cfg.pre_apply(console, audit)

    apply_success, last_error_msg = run_terraform_apply_loop(
        console, build_dir, auto_approve, audit)
    destroy_already_run = False
    outputs: dict = {}
    prior_teardown_ok: Optional[bool] = None
    automation_success = False

    if not apply_success:
        destroy_already_run = handle_apply_failure(
            console, build_dir, audit, teardown, last_error_msg,
            destroy_fn=cleanup_resources)
    else:
        console.print(
            f"\n[bold green]Step 7 complete.[/bold green] "
            f"{cfg.cloud_label} infrastructure deployed.\n"
        )
        outputs = get_terraform_outputs(build_dir)
        console.print(cfg.render_panel(outputs, measurements))
        if audit and cfg.record_outputs is not None:
            cfg.record_outputs(audit, outputs)

        # Pin the BYOK key to the role Terraform just created, before the
        # workload can ask for the DEK. Fail closed: continuing would run
        # against whatever policy the key happened to carry, which on a fresh
        # key is `kms:*` -- no measurement condition and no narrowing to this
        # deploy's role. This call was missing from every flow that goes through
        # this runner, so `--byok aws-kms` silently did nothing here.
        from tee_crafter.cli.deployment.common.byok_key_policy import (
            pin_byok_key_after_apply,
        )
        _pinned, _pin_detail = pin_byok_key_after_apply(
            console=console, build_dir=build_dir,
            tee_platform=cfg.tee_platform, outputs=outputs, audit=audit)
        if not _pinned:
            console.print(
                "[bold red]✗ BYOK key could not be pinned to this deploy's "
                f"instance role: {_pin_detail}[/bold red]\n"
                "[red]Refusing to continue: an unpinned key is one any matching "
                "role in the account can read.[/red]")
            if audit:
                audit.record("Phase 4: Deployment",
                             "BYOK key policy pinned to instance role", "fail",
                             tee_platform=cfg.tee_platform,
                             reason=_pin_detail[:200])
            destroy_already_run = handle_apply_failure(
                console, build_dir, audit, teardown,
                f"BYOK key pinning failed: {_pin_detail}",
                destroy_fn=cleanup_resources)
            return False

        conn = cfg.build_conn(outputs, build_dir)
        if conn is not None:
            console.print(f"[yellow]Opening {cfg.tunnel_label} tunnel to VM port 22...[/yellow]")
            tunnel = conn.tunnel
            try:
                tunnel.start(timeout=300)
                console.print(
                    f"[green]✓ {cfg.tunnel_label} tunnel ready "
                    f"(localhost:{tunnel.local_port} -> VM:22)[/green]"
                )
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console, transient=False,
                ) as progress:
                    if custom_ami:
                        t = progress.add_task(
                            "[yellow]Waiting for SSH on custom-image VM...[/yellow]",
                            total=None)
                        ok = cfg.wait_for_ssh(
                            conn.ssh_key_path, conn.admin_user, tunnel.local_port)
                        progress.update(
                            t, description="[green]✓ SSH online (custom image).[/green]"
                            if ok else "[bold red]✗ SSH timed out.[/bold red]")
                        if ok and cfg.on_custom_ami is not None:
                            cfg.on_custom_ami(
                                conn.ssh_key_path, conn.admin_user, tunnel.local_port)
                    else:
                        ok = cfg.setup_fn(
                            progress, console, conn.ssh_key_path, build_dir, cpu, ram,
                            audit, admin_user=conn.admin_user,
                            tunnel_port=tunnel.local_port)
                    if ok:
                        automation_success = cfg.run_client(
                            progress, console, build_dir, conn.ssh_key_path,
                            tunnel.local_port, conn.admin_user, audit, measurements,
                            outputs)
                        # Probes run *after* a successful client verify: the
                        # service is only confirmed up at that point.
                        if automation_success:
                            _run_probes_after_client(
                                cfg, console, audit, build_dir, conn,
                                tunnel.local_port)
            except Exception as e:
                console.print(f"[bold red]{cfg.tunnel_label} tunnel failed:[/bold red]", end=" ")
                console.print(str(e), markup=False)
                if audit:
                    audit.record("Phase 5: Post-Deploy",
                                 f"{cfg.tunnel_label} tunnel (SSH)", "fail", reason=str(e))
            finally:
                tunnel.stop()

        if automation_success:
            console.print(
                f"\n[bold green]{cfg.cloud_label} deployment pipeline complete.[/bold green]\n")
        else:
            console.print(
                "\n[bold yellow]Infrastructure deployed, but post-deployment "
                "did not fully succeed.[/bold yellow]\n")
            prior_teardown_ok = destroy_on_failure(
                console, build_dir, audit, destroy_fn=cleanup_resources,
                context="Automation-failure cleanup",
                step="Terraform destroy (on failure)")
            destroy_already_run = prior_teardown_ok is not None

    finalize_phase(
        console, build_dir, audit, teardown, destroy_already_run,
        tee_platform=cfg.tee_platform, outputs=outputs,
        destroy_fn=cleanup_resources, prior_teardown_ok=prior_teardown_ok)
    return bool(apply_success and automation_success)
