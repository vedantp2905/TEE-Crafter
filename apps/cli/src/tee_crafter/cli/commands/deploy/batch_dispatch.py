"""High-level batch deploy dispatch: run Terraform, harvest outputs, run batch.

This sits between the CLI (``deploy --batch`` / ``deploy-container --batch``) and
the platform-agnostic orchestrator in :mod:`tee_crafter.cli.commands.deploy.batch`.
Its only job is to:

1. Provision (or skip provisioning of) the TEE for the operator's chosen
   platform — exactly the same Terraform apply path the standard pipeline uses.
2. Translate that platform's Terraform outputs into a single
   :class:`BatchTransport` describing how the orchestrator should reach the
   TEE host (SCP via Bastion/IAP, SSM via SSM/S3, or vsock via Nitro host).
3. Open Azure Bastion / GCP IAP tunnels for the duration of the batch run, so
   SCP/SSH off ``localhost:<tunnel_port>`` works without exposing the VM.
4. Hand control to :func:`run_batch_container_deploy`, then tear down (or not)
   per ``--teardown``.

This is deliberately *not* layered on top of the existing per-platform "phase"
modules: those are tied to the long-running RA-TLS service contract that batch
mode replaces.  Batch mode bypasses them on purpose so a failure in the
service-mode phase code can never silently change batch behavior.
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Optional


from tee_crafter.cli.commands.deploy.batch import (
    BatchResult, BatchTransport,
    run_batch_container_deploy,
)
from tee_crafter.cli.constants import Console, console as _default_console, Panel
from tee_crafter.core.audit import BuildAuditTrail

logger = logging.getLogger(__name__)

_AZURE = ("tdx-azure", "snp-azure", "sgx-azure", "gpu-cc-azure")
_GCP = ("tdx-gcp", "snp-gcp", "gpu-cc-gcp")
_AWS_VM = ("snp-aws", "gpu-cc-aws")
_NITRO = ("nitro-aws",)


def _resolve_aws_region() -> str:
    import boto3
    return (os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION")
            or boto3.Session().region_name or "us-east-2")


@contextmanager
def _platform_tunnel(platform: str, build_dir: str, console: Console):
    """Open the right tunnel for *platform* and yield a populated BatchTransport.

    Yields ``(transport, automation_ok_message)``.  On exit the tunnel is
    closed.  AWS platforms have no tunnel; the context manager is a no-op
    apart from filling in instance/region/bucket coords.
    """
    from tee_crafter.core.iac import get_terraform_outputs
    outputs = get_terraform_outputs(build_dir)

    if platform in _AZURE:
        from tee_crafter.core.remote.azure_ssh import BastionTunnel, wait_for_ssh
        vm_id = outputs.get("vm_id", "")
        bastion_name = outputs.get("bastion_name", "")
        rg = outputs.get("resource_group", "")
        ssh_key_path = outputs.get("ssh_private_key_path", "")
        admin_user = outputs.get("admin_username", "azureuser")
        if ssh_key_path and not os.path.isabs(ssh_key_path):
            ssh_key_path = os.path.join(os.path.abspath(build_dir), ssh_key_path)
        if not (vm_id and bastion_name and rg and ssh_key_path):
            raise RuntimeError(
                "Azure batch dispatch missing terraform outputs "
                "(vm_id/bastion_name/resource_group/ssh_private_key_path)"
            )
        if not os.path.isfile(ssh_key_path):
            raise RuntimeError(
                f"Azure batch dispatch: SSH private key not found at {ssh_key_path}"
            )
        console.print("[yellow]Opening Bastion tunnel for batch run...[/yellow]")
        tunnel = BastionTunnel(bastion_name, rg, vm_id, 22)
        tunnel.start(timeout=300)
        console.print(
            f"[green]✓ Bastion tunnel ready (localhost:{tunnel.local_port} -> VM:22).[/green]"
        )
        try:
            # The VM is fresh out of terraform apply; OpenSSH may still be
            # coming up. Without this wait the first ``run_remote`` /
            # ``upload`` calls in run_batch_container_deploy silently fail
            # (capture_output=True hides the SSH errors) and the batch
            # returns a BatchResult(success=False) with no on-screen trace.
            console.print(
                "[yellow]Waiting for SSH on VM (up to 5m)...[/yellow]"
            )
            if not wait_for_ssh(
                ssh_key_path, user=admin_user,
                host="localhost", port=tunnel.local_port, timeout=300,
            ):
                raise RuntimeError(
                    f"SSH did not come online on localhost:{tunnel.local_port} "
                    f"within 300s (Bastion tunnel up but VM unreachable). "
                    f"Check Azure portal boot diagnostics for {vm_id}."
                )
            console.print("[green]✓ SSH ready on VM.[/green]")
            yield BatchTransport(
                platform=platform,
                ssh_private_key_path=ssh_key_path,
                ssh_user=admin_user, ssh_host="localhost",
                ssh_port=tunnel.local_port,
            )
        finally:
            tunnel.stop()
        return

    if platform in _GCP:
        from tee_crafter.core.remote.gcp_ssh import IAPTunnel, wait_for_ssh
        instance_name = outputs.get("instance_name", "")
        zone = outputs.get("instance_zone", "")
        project = outputs.get("project", "")
        ssh_key_path = outputs.get("ssh_private_key_path", "")
        admin_user = outputs.get("admin_username", "tee_admin")
        if ssh_key_path and not os.path.isabs(ssh_key_path):
            ssh_key_path = os.path.join(os.path.abspath(build_dir), ssh_key_path)
        if not (instance_name and zone and ssh_key_path):
            raise RuntimeError(
                "GCP batch dispatch missing terraform outputs "
                "(instance_name/instance_zone/ssh_private_key_path)"
            )
        if not os.path.isfile(ssh_key_path):
            raise RuntimeError(
                f"GCP batch dispatch: SSH private key not found at {ssh_key_path}"
            )
        console.print("[yellow]Opening IAP tunnel for batch run...[/yellow]")
        tunnel = IAPTunnel(instance_name, zone, project, 22)
        tunnel.start(timeout=300)
        console.print(
            f"[green]✓ IAP tunnel ready (localhost:{tunnel.local_port} -> VM:22).[/green]"
        )
        try:
            console.print(
                "[yellow]Waiting for SSH on instance (up to 5m)...[/yellow]"
            )
            if not wait_for_ssh(
                ssh_key_path, user=admin_user,
                host="localhost", port=tunnel.local_port, timeout=300,
            ):
                raise RuntimeError(
                    f"SSH did not come online on localhost:{tunnel.local_port} "
                    f"within 300s (IAP tunnel up but instance unreachable). "
                    f"Check GCP serial-console output for {instance_name}."
                )
            console.print("[green]✓ SSH ready on instance.[/green]")
            yield BatchTransport(
                platform=platform,
                ssh_private_key_path=ssh_key_path,
                ssh_user=admin_user, ssh_host="localhost",
                ssh_port=tunnel.local_port,
            )
        finally:
            tunnel.stop()
        return

    if platform in _AWS_VM or platform in _NITRO:
        instance_id = outputs.get("instance_id", "")
        bucket = outputs.get("deployment_bucket", "")
        region = _resolve_aws_region()
        if not (instance_id and bucket):
            raise RuntimeError(
                "AWS batch dispatch missing terraform outputs "
                "(instance_id/deployment_bucket)"
            )
        from tee_crafter.core.remote.ssm import wait_for_ssm
        if not wait_for_ssm(instance_id, region):
            raise RuntimeError(f"SSM did not come online for {instance_id}")
        yield BatchTransport(
            platform=platform,
            aws_instance_id=instance_id,
            aws_region=region,
            aws_bucket=bucket,
        )
        return

    raise ValueError(f"Unsupported batch platform: {platform}")


def _ensure_batch_terraform_staged(
    build_dir: str,
    tee_platform: str,
    audit: Optional[BuildAuditTrail],
    console: Console,
    *,
    cpu: int | None = None,
    ram_mb: int | None = None,
) -> bool:
    """Make sure ``build_dir`` has a ``main.tf`` for *tee_platform*.

    The container batch flow reuses the standard ``run_container_phases`` build
    dir, but that helper does not stage Terraform — the per-platform deploy
    branches (``_deploy_cvm_container`` / ``_deploy_nitro_container`` / ...)
    normally do.  In batch mode we skip those branches, so we stage the same
    ``main.tf`` here using the shared ``stage_batch_terraform`` helper.

    Idempotent: if a ``main.tf`` already exists this is a no-op.
    """
    if os.path.isfile(os.path.join(build_dir, "main.tf")):
        return True
    from tee_crafter.cli.commands.deploy.batch_terraform import (
        stage_batch_terraform,
    )
    try:
        stage_batch_terraform(
            build_dir, tee_platform, audit=audit, cpu=cpu, ram_mb=ram_mb,
        )
        return True
    except Exception as e:
        console.print(Panel.fit(
            f"[bold red]Failed to stage Terraform for batch deploy[/bold red]\n\n"
            f"{e}",
            border_style="red",
        ))
        if audit is not None:
            audit.record("Batch Dispatch", "Stage terraform", "fail",
                         tee_platform=tee_platform, error=str(e)[:300])
        return False


def _terraform_apply_for_batch(build_dir: str, auto_approve: bool,
                                audit: Optional[BuildAuditTrail],
                                console: Console) -> bool:
    from tee_crafter.cli.deployment.common.terraform_step import run_terraform_apply_loop
    ok, msg = run_terraform_apply_loop(console, build_dir, auto_approve, audit)
    if not ok:
        console.print(Panel.fit(
            f"[bold red]Terraform apply failed[/bold red]\n\n{msg}",
            border_style="red",
        ))
    return ok


def _maybe_teardown(build_dir: str, teardown: bool, console: Console,
                    audit: Optional[BuildAuditTrail],
                    *, failed: bool = False) -> None:
    """Tear down after a batch run.

    Three cases:

    * ``--teardown`` — the operator asked for teardown on the happy path.
    * *failed* and no ``--keep-on-failure`` — the batch did not complete, so the
      VM (and any NAT gateway) is billing for nothing.  This branch did not
      exist: batch mode only ever destroyed on ``--teardown``, so a failed
      ``terraform apply``, a tunnel/SSH failure, or a container that never ran
      left the whole stack up while the CLI exited non-zero.  The persistent
      phases have destroyed on failure since ``phase_runner.destroy_on_failure``
      landed; this makes batch match them.
    * otherwise — print the ``tee-crafter destroy`` hint and leave it running.
    """
    from tee_crafter.cli.deployment.common.terraform_step import cleanup_resources

    if failed and not teardown:
        from tee_crafter.cli.deployment.common.phase_runner import destroy_on_failure
        destroy_on_failure(
            console, build_dir, audit, destroy_fn=cleanup_resources,
            context="Batch-failure cleanup",
            step="Terraform destroy (batch failed)")
        return
    if not teardown:
        console.print(
            f"\n[dim]Resources left running. "
            f"Tear down with: [bold]tee-crafter destroy --build-dir "
            f"{os.path.abspath(build_dir)}[/bold][/dim]"
        )
        return
    ok = cleanup_resources(console, build_dir, context="Batch teardown")
    if audit is not None:
        audit.record("Batch Teardown", "Terraform destroy",
                     "pass" if ok else "fail")


def dispatch_batch_container(
    *,
    build_dir: str,
    tee_platform: str,
    container_tar_path: str,
    do_deploy: bool,
    auto_approve: bool,
    teardown: bool,
    batch_timeout: int,
    max_output_size: Optional[int],
    input_dir: Optional[str],
    audit: Optional[BuildAuditTrail],
    console: Optional[Console] = None,
    cpu: int | None = None,
    ram_mb: int | None = None,
) -> Optional[BatchResult]:
    """Run mode A end-to-end: terraform apply → docker batch → teardown."""
    console = console or _default_console
    if not do_deploy:
        console.print(
            f"\n[bold green]Batch container staged (no deploy).[/bold green]\n"
            f"Build dir: [cyan]{os.path.abspath(build_dir)}[/cyan]\n"
            f"Image tarball: [cyan]{container_tar_path}[/cyan]\n"
            f"Run with [bold]--deploy --auto-approve[/bold] to apply Terraform "
            f"and run the batch job.\n"
        )
        return None

    if not _ensure_batch_terraform_staged(
        build_dir, tee_platform, audit, console,
        cpu=cpu, ram_mb=ram_mb,
    ):
        # Nothing is provisioned yet, so this is a plain "did not run" — but it
        # must still surface as a failure.  Returning ``None`` here meant the
        # caller's ``batch_result is not None`` guard skipped the raise and the
        # CLI exited 0 after failing to stage any Terraform at all.
        _maybe_teardown(build_dir, teardown, console, audit)
        return BatchResult(False, message="could not stage Terraform for the batch deploy")

    if not _terraform_apply_for_batch(build_dir, auto_approve, audit, console):
        # Partial state from a failed apply still bills (VPC endpoints, NAT,
        # a half-created VM), so this is a failure teardown, not a no-op hint.
        _maybe_teardown(build_dir, teardown, console, audit, failed=True)
        return BatchResult(False, message="terraform apply failed")

    # Pin the BYOK key to the role Terraform just created, before the batch
    # container can ask for the DEK. Batch reached this point without ever
    # rewriting the key policy, so `--byok aws-kms --batch` ran against the
    # key's existing policy -- `kms:*` on a fresh key. Fail closed, and tear
    # down, because the VM is already billing.
    from tee_crafter.core.iac import get_terraform_outputs
    from tee_crafter.cli.deployment.common.byok_key_policy import (
        pin_byok_key_after_apply,
    )
    _pinned, _pin_detail = pin_byok_key_after_apply(
        console=console, build_dir=build_dir, tee_platform=tee_platform,
        outputs=get_terraform_outputs(build_dir), audit=audit)
    if not _pinned:
        console.print(Panel.fit(
            "[bold red]BYOK key could not be pinned[/bold red]\n\n"
            f"{_pin_detail}\n\n"
            "[red]Refusing to run the batch: an unpinned key is one any "
            "matching role in the account can read.[/red]",
            border_style="red"))
        if audit:
            audit.record("Phase 4: Deployment",
                         "BYOK key policy pinned to instance role", "fail",
                         tee_platform=tee_platform, reason=_pin_detail[:200])
        _maybe_teardown(build_dir, teardown, console, audit, failed=True)
        return BatchResult(False, message=f"BYOK key pinning failed: {_pin_detail}")

    result: Optional[BatchResult] = None
    try:
        with _platform_tunnel(tee_platform, build_dir, console) as transport:
            # Batch runs the user's Docker image on the host VM using the
            # platform's transport (SSM/S3 on AWS, SCP over the tunnel
            # elsewhere) and ``docker run`` with the hardening flags from
            # ``container.batch.service.template``.  The image is never loaded
            # into a Nitro Enclave: the EIF path is wired for the long-running
            # RA-TLS service, not the docker-diff capture model batch uses.
            # ``preflight._check_container_batch_supported`` already rejects
            # ``--batch`` on ``nitro-aws`` for exactly that reason, so if you
            # need TEE-protected batch execution on AWS, pick ``snp-aws``.
            #
            # (This used to point at a ``--batch-entrypoint`` "mode B" that ran
            # inside the enclave.  No such flag exists on ``deploy``, and the
            # supporting pieces were unreachable — the ``__BATCH_APP_UNIT__``
            # placeholder that would have installed the unit appeared in no
            # setup script.  They have since been deleted rather than left as
            # dead code that looks like a working execution mode.)
            result = run_batch_container_deploy(
                build_dir=build_dir, transport=transport,
                container_tar_local=container_tar_path,
                bundle_max_bytes=max_output_size,
                batch_timeout=batch_timeout,
                input_dir_local=input_dir,
                audit=audit, console=console,
            )
    except Exception as e:
        # Surface the failure on the returned BatchResult so the CLI exits
        # non-zero.  Without this, a tunnel/SSH/SCP exception was caught,
        # ``result`` stayed ``None``, and the outer deploy_container command
        # fell through to a silent ``return`` with rc=0 — the bug behind "the
        # run reported success but the container never ran".
        from traceback import format_exc
        console.print(f"[bold red]Batch dispatch failed:[/bold red] {e}")
        console.print(f"[dim]{format_exc()[-2000:]}[/dim]")
        if audit is not None:
            audit.record("Batch Dispatch", "Run batch container", "fail",
                         error=str(e)[:300])
        result = BatchResult(False, message=f"batch dispatch failed: {e}")
    else:
        # A *returned* failure needs printing too.  The ``except`` arm above
        # covers exceptions, but ``run_batch_container_deploy`` reports most
        # failures by returning ``BatchResult(False, message=...)`` — a failed
        # bundle download, a capture-script install, a systemd unit that never
        # activated.  Nothing printed that message, so the operator saw
        # "Running batch ..." followed straight by "Cleaning up failed
        # deployment" with no reason given, and the reason was sitting on the
        # returned object.  Observed on both the snp-azure and tdx-azure batch
        # deploys on 2026-08-22.
        if result is not None and not result.success:
            console.print(
                f"[bold red]Batch run failed:[/bold red] "
                f"{result.message or '(no reason recorded)'}")
            if audit is not None:
                audit.record("Batch Dispatch", "Run batch container", "fail",
                             error=(result.message or "")[:300])
    finally:
        # A batch that never produced a successful result leaves a live VM (and
        # on the NAT-backed platforms a gateway) billing.  ``--keep-on-failure``
        # opts out, exactly as it does on the persistent phases.
        _maybe_teardown(
            build_dir, teardown, console, audit,
            failed=(result is None or not result.success),
        )
    return result
