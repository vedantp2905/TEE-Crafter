"""Orchestrate deployment phase: Terraform apply, post-deploy automation, teardown."""
import os
from tee_crafter.cli.constants import Console
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.core.iac import get_terraform_outputs, run_terraform_destroy
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.deployment.common.terraform_step import (
    cleanup_resources, run_terraform_apply_loop,
)
from tee_crafter.cli.deployment.common.phase_runner import destroy_on_failure
from tee_crafter.cli.deployment.common.vpc_endpoints import detect_and_skip_existing_vpc_endpoints
from tee_crafter.cli.deployment.nitro.setup import run_ssm_cloudinit_nitro_setup
from tee_crafter.cli.deployment.common.enclave_proxy import run_eif_upload_enclave_proxy
from tee_crafter.cli.deployment.common.client_step import run_client_step
from tee_crafter.cli.deployment.common.siem_sidecar import install_siem_sidecar
from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.core.remote.ssm import run_ssm_command


def run_nitro_deployment_phase(
    console: Console, build_dir: str, cpu: int, ram: int, hashes: dict,
    auto_approve: bool, teardown: bool, source_code=None,
    data_sample_str=None, audit: BuildAuditTrail | None = None,
    custom_ami: str | None = None,
) -> bool:
    """Execute Terraform apply, post-deploy automation (SSM, enclave, client), optional teardown.

    Returns ``True`` only when the enclave client verified the attestation.
    """
    detect_and_skip_existing_vpc_endpoints(console, build_dir)
    max_retries = min(2, max(1, int(os.getenv("TEE_CRAFTER_PHASE4_MAX_RETRIES", "2"))))
    apply_success, last_error_msg = run_terraform_apply_loop(console, build_dir, auto_approve, audit)
    destroy_already_run = False
    automation_success = False
    # Teardown evidence must come from the teardown itself.  These were read
    # via ``locals().get(...)``, which resolves to whatever same-named local
    # happens to exist — and ``d_msg`` is also assigned by an earlier cleanup
    # path, so a run that tore nothing down could report that path's message as
    # its teardown result.  ``None`` means "not evaluated", which the ledger
    # treats as distinct from a pass.
    d_success: bool | None = None
    d_msg: str = ""
    outputs: dict = {}

    if not apply_success:
        console.print(f"\n[bold red]Deployment failed after {max_retries} Terraform apply attempts.[/bold red]")
        console.print(f"[red]Last Error:[/red] {last_error_msg}\n")
        if audit:
            audit.record("Phase 4: Deployment", "Terraform apply", "fail", attempts=max_retries)
            audit.record_check(
                "Phase 4: Deployment", "terraform apply success", "DEP-001",
                observed=False, note=last_error_msg[:200],
            )
        console.print("[yellow]Cleaning up partial state with Terraform destroy...[/yellow]")
        d_ok, d_msg = run_terraform_destroy(build_dir)
        destroy_already_run = True
        console.print("[green]✓ Cleanup complete.[/green]" if d_ok else f"[dim]Cleanup: {d_msg}[/dim]")
    else:
        console.print("\n[bold green]Step 7 complete.[/bold green] Infrastructure deployed via Terraform.\n")
        outputs = get_terraform_outputs(build_dir)
        instance_id = outputs.get("instance_id", "N/A")
        bucket_name = outputs.get("deployment_bucket", "N/A")
        private_ip = outputs.get("private_ip", "N/A")
        console.print(Panel(
            f"[cyan]Instance ID:[/cyan] {instance_id}\n"
            f"[cyan]Private IP:[/cyan] {private_ip}\n"
            f"[cyan]S3 Bucket:[/cyan] {bucket_name}",
            title="[bold green]Deployment Outputs[/bold green]", border_style="green"))
        if audit:
            audit.record("Phase 4: Deployment", "Infrastructure outputs", "info",
                         instance_id=instance_id,
                         deployment_kms_key_arn=outputs.get("kms_key_arn", "N/A"))
            from tee_crafter.cli.deployment.common.deploy_verdicts import (
                record_deploy_outputs_verdicts,
            )
            record_deploy_outputs_verdicts(audit, outputs, tee_platform="nitro-aws")
        if instance_id != "N/A" and bucket_name != "N/A":
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          console=console, transient=False) as progress:
                if custom_ami:
                    ok, aws_region = _handle_custom_ami(
                        progress, console, instance_id, ram, audit, cpu)
                else:
                    ok, aws_region = run_ssm_cloudinit_nitro_setup(
                        progress, console, instance_id, bucket_name, build_dir, cpu, ram, audit)
                if ok:
                    cid = run_eif_upload_enclave_proxy(
                        progress, console, build_dir, instance_id, bucket_name, cpu, ram, audit, aws_region)
                    if cid:
                        # SIEM export now runs INSIDE the enclave (see
                        # app_vsock.start_in_enclave_siem_export).  The host
                        # sidecar is still installed alongside it: it keeps the
                        # boot-anchored heartbeat the SOC has always received,
                        # and it is what a fleet dashboard watches when the
                        # enclave itself is what has stopped.  The in-enclave
                        # exporter is the one whose verdict the fail-closed gate
                        # reads.  See docs/siem.md.
                        _push_siem_env_to_nitro_host(
                            console, build_dir, instance_id, aws_region,
                            bucket_name)
                        _run = lambda c, _i=instance_id, _r=aws_region: run_ssm_command(_i, c, _r, timeout=60)
                        # Arm the enclave's own TLS path to the collector before
                        # the sidecar, so the in-enclave exporter has somewhere
                        # to deliver on its first tick.
                        from tee_crafter.cli.deployment.common.siem_sidecar import (
                            install_enclave_egress,
                        )
                        install_enclave_egress(
                            console=console, build_dir=build_dir,
                            tee_platform="nitro-aws", run_remote=_run,
                        )
                        install_siem_sidecar(
                            console=console, build_dir=build_dir,
                            tee_platform="nitro-aws",
                            run_remote=_run,
                            audit=audit,
                        )
                        from tee_crafter.cli.deployment.common.byok_sidecar import install_byok_sidecar
                        install_byok_sidecar(
                            console=console, build_dir=build_dir,
                            tee_platform="nitro-aws",
                            run_remote=_run,
                            audit=audit,
                        )
                        try:
                            from tee_crafter.cli.deployment.common.post_deploy_probes import (
                                run_post_deploy_probes,
                            )
                            run_post_deploy_probes(
                                audit,
                                tee_platform="nitro-aws",
                                build_dir=build_dir,
                                run_remote=_run,
                            )
                        except Exception as exc:
                            console.print(
                                f"[yellow]Post-deploy probes skipped: "
                                f"{type(exc).__name__}: {exc}[/yellow]"
                            )
                        automation_success = run_client_step(
                            progress, console, build_dir, instance_id, aws_region, outputs, audit)
                    else:
                        console.print("[yellow]Enclave setup did not complete. Skipping client run.[/yellow]")
        if automation_success:
            console.print("\n[bold green]Deployment pipeline complete.[/bold green]\n")
        else:
            console.print("\n[bold yellow]Infrastructure deployed, but post-deployment automation did not fully succeed.[/bold yellow]\n")
            destroy_already_run = destroy_on_failure(
                console, build_dir, audit, destroy_fn=cleanup_resources,
                context="Automation-failure cleanup",
                step="Terraform destroy (on failure)") is not None
    if teardown and not destroy_already_run:
        console.print("[yellow]Step 9: Executing Terraform destroy (teardown)...[/yellow]")
        d_success, d_msg = run_terraform_destroy(build_dir)
        console.print("[green]✓ Step 9: Resources destroyed successfully.[/green]" if d_success
                      else f"[bold red]✗ Step 9 Failed (destroy):[/bold red] {d_msg}")
        if audit:
            audit.record("Phase 5: Post-Deploy", "Terraform destroy (teardown)",
                         "pass" if d_success else "fail")
    elif not destroy_already_run:
        console.print(f"\n[dim]To tear down: [bold]tee-crafter destroy --build-dir {os.path.abspath(build_dir)}[/bold][/dim]")
    if audit:
        from tee_crafter.cli.audit_helpers import emit_teardown_and_cloud_audit
        emit_teardown_and_cloud_audit(
            audit, tee_platform="nitro-aws",
            teardown_ok=d_success,
            teardown_msg=d_msg or "",
            outputs=outputs or {},
            build_dir=build_dir,
        )
        save_audit_trail(audit, build_dir, console)
    return bool(apply_success and automation_success)


def _push_siem_env_to_nitro_host(console, build_dir, instance_id, aws_region,
                                 bucket_name):
    """Copy build_dir/siem.env + siem_export.py + measurements.json to
    /opt/tee-crafter/ on the Nitro EC2 host so the sidecar systemd unit
    can read them.

    The token-bearing ``siem.env`` is staged through the deployment S3
    bucket (SSE-KMS by default — see ``aws_s3_bucket_server_side_encryption_
    configuration.deployment_bucket_encryption`` in
    ``templates/nitro/main.template.tf``) rather than interpolated into the
    SSM command body.  SSM retains command bodies for 30 days and CloudTrail
    records ``SendCommand`` parameters, so a base64'd bearer token in the
    body is a durable, queryable copy of the credential — base64 is an
    encoding, not encryption.  Only the S3 URI travels in the command now,
    and the object is deleted once the instance has pulled it.

    The non-secret half (``siem.env.public``), the exporter script and the
    measurements document carry no credentials and stay inline.

    No-op when SIEM is disabled (siem.env absent / empty).
    """
    import base64 as _b64
    import json as _json
    from tee_crafter.core.audit import build_layout as _layout
    siem_env_path = None
    for cand in (_layout.siem_env(build_dir),
                 os.path.join(build_dir, "siem.env"),
                 os.path.join(build_dir, "app", "siem.env")):
        if os.path.isfile(cand):
            siem_env_path = cand
            break
    if not siem_env_path:
        return
    siem_script_path = None
    for cand in (os.path.join(build_dir, "siem_export.py"),
                 os.path.join(build_dir, "app", "siem_export.py")):
        if os.path.isfile(cand):
            siem_script_path = cand
            break
    if not siem_script_path:
        return
    script_b64 = _b64.b64encode(open(siem_script_path, "rb").read()).decode("ascii")
    # Heartbeat provider needs a measurement.  PCR0 lives in
    # ``pcrs.json`` (canonical, written by ``nitro-cli build-enclave``).
    # Older builds may only have it inside the build_provenance audit
    # trail entries (``Phase X.details.pcrs.PCR0``), so fall through to
    # that path before giving up.
    meas_doc = {}
    pcrs_path = os.path.join(build_dir, "pcrs.json")
    if os.path.isfile(pcrs_path):
        try:
            with open(pcrs_path, "r", encoding="utf-8") as f:
                pcrs_obj = _json.load(f)
            pcr0 = (pcrs_obj.get("pcrs", {}) or {}).get("PCR0") or pcrs_obj.get("PCR0")
            if isinstance(pcr0, str) and pcr0:
                meas_doc["measurement"] = pcr0.lower()
                meas_doc["pcr0"] = pcr0.lower()
        except Exception:
            pass
    if "measurement" not in meas_doc:
        prov = _layout.resolve_provenance_json(build_dir)
        if os.path.isfile(prov):
            try:
                with open(prov, "r", encoding="utf-8") as f:
                    prov_obj = _json.load(f)
                for k in ("eif_pcr0", "pcr0", "measurement"):
                    v = prov_obj.get(k)
                    if isinstance(v, str) and v:
                        meas_doc["measurement"] = v.lower()
                        meas_doc["pcr0"] = v.lower()
                        break
                if "measurement" not in meas_doc:
                    for entry in prov_obj.get("entries", []) or []:
                        d = (entry or {}).get("details", {}) or {}
                        pcr0 = (d.get("pcrs", {}) or {}).get("PCR0") or d.get("pcr0")
                        if isinstance(pcr0, str) and pcr0:
                            meas_doc["measurement"] = pcr0.lower()
                            meas_doc["pcr0"] = pcr0.lower()
                            break
            except Exception:
                pass
    meas_doc.setdefault("pipeline_version", "nitro-aws-sidecar")
    meas_b64 = _b64.b64encode(
        _json.dumps(meas_doc).encode("utf-8")).decode("ascii")
    # SIEM-SEC-2: stage the token-bearing siem.env on tmpfs at
    # /run/tee-crafter-nitro-aws/, not on the boot disk.  The
    # non-secret half (siem.env.public) — provider, endpoint, index
    # gates — can live on disk so the sidecar still has its config
    # after a reboot wipes /run.
    pub_env_path = None
    for cand in (_layout.siem_env_public(build_dir),
                 os.path.join(build_dir, "siem.env.public"),
                 os.path.join(build_dir, "app", "siem.env.public")):
        if os.path.isfile(cand):
            pub_env_path = cand
            break
    pub_b64 = ""
    if pub_env_path:
        pub_b64 = _b64.b64encode(open(pub_env_path, "rb").read()).decode("ascii")
    if not bucket_name or bucket_name == "N/A":
        console.print(
            "[yellow]SIEM: no deployment bucket in the Terraform outputs; "
            "refusing to put the SIEM token in an SSM command body.[/yellow]")
        return
    if not _stage_secret_env_via_s3(
        console, siem_env_path, bucket_name, instance_id, aws_region,
    ):
        return
    cmd = (
        "set -eu;"
        " sudo mkdir -p /opt/tee-crafter;"
        # Public half (non-secret) -> persistent for reboot survival.
        + (f" echo {pub_b64} | base64 -d | sudo tee /opt/tee-crafter/siem.env.public >/dev/null;"
           " sudo chmod 0640 /opt/tee-crafter/siem.env.public;"
           " sudo chown tee_enclave:tee_enclave /opt/tee-crafter/siem.env.public;"
           if pub_b64 else "")
        + f" echo {script_b64} | base64 -d | sudo tee /opt/tee-crafter/siem_export.py >/dev/null;"
        f" echo {meas_b64} | base64 -d | sudo tee /opt/tee-crafter/measurements.json >/dev/null;"
        " sudo chmod 0755 /opt/tee-crafter/siem_export.py;"
        " sudo chown tee_enclave:tee_enclave /opt/tee-crafter/siem_export.py 2>/dev/null || true;"
        " sudo /usr/bin/python3 -c 'import cryptography' 2>/dev/null"
        " || sudo /usr/bin/python3 -m pip install --quiet cryptography 2>&1 | tail -3"
    )
    ok, out, err = run_ssm_command(instance_id, cmd, aws_region, timeout=120)
    if not ok:
        console.print(f"[yellow]SIEM: failed to stage siem.env on Nitro host: "
                      f"{(err or out or '')[-200:]}[/yellow]")


def _stage_secret_env_via_s3(console, local_env_path, bucket_name,
                             instance_id, aws_region) -> bool:
    """Deliver the token-bearing ``siem.env`` to the host's tmpfs via S3.

    Uses the same upload-then-``aws s3 cp`` pattern as
    :func:`tee_crafter.core.remote.ssm_s3.upload_file_via_s3`; the object
    inherits the deployment bucket's SSE-KMS default and is deleted in a
    ``finally`` so the credential does not outlive the staging step.
    """
    import uuid as _uuid
    from tee_crafter.core.remote.ssm_s3 import upload_file_via_s3
    key = f"siem-staging/{_uuid.uuid4().hex}.env"
    staged = "/run/tee-crafter-nitro-aws/siem.env.staged"
    try:
        ok, msg = upload_file_via_s3(
            local_env_path, bucket_name, key, instance_id, staged,
            aws_region, timeout=120,
        )
        if not ok:
            console.print(
                f"[yellow]SIEM: could not stage siem.env via S3: {msg[:200]}[/yellow]")
            return False
        # ``upload_file_via_s3`` writes as the SSM user; move it into place
        # with the ownership/mode the sidecar unit expects.  Only the path
        # travels in this command body — never the token.
        ok, out, err = run_ssm_command(
            instance_id,
            "set -eu;"
            " sudo install -d -m 0700 -o tee_enclave -g tee_enclave"
            " /run/tee-crafter-nitro-aws;"
            f" sudo install -m 0600 -o tee_enclave -g tee_enclave"
            f" {staged} /run/tee-crafter-nitro-aws/siem.env;"
            f" sudo shred -u {staged} 2>/dev/null || sudo rm -f {staged}",
            aws_region, timeout=60,
        )
        if not ok:
            console.print(
                f"[yellow]SIEM: could not install siem.env on the host: "
                f"{(err or out or '')[-200:]}[/yellow]")
            return False
        return True
    finally:
        try:
            import boto3
            boto3.client("s3", region_name=aws_region).delete_object(
                Bucket=bucket_name, Key=key)
        except Exception as exc:
            console.print(
                f"[yellow]SIEM: could not delete staged s3://{bucket_name}/{key}: "
                f"{exc}[/yellow]")


def _handle_custom_ami(progress, console, instance_id, ram, audit, cpu=2):
    """Wait for SSM on a custom AMI instance and verify allocator readiness."""
    from tee_crafter.core.remote.ssm import wait_for_ssm
    boto3_region = __import__("boto3").Session().region_name
    aws_region = os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION") or boto3_region or "us-east-2"
    t = progress.add_task("[yellow]Waiting for SSM on custom-AMI instance...[/yellow]", total=None)
    console.print(f"[dim]Nitro debug: waiting for SSM (instance_id={instance_id}, region={aws_region})[/dim]")
    ok = wait_for_ssm(instance_id, aws_region)
    progress.update(t, description="[green]✓ SSM online (custom AMI, setup skipped).[/green]" if ok
                    else "[bold red]✗ SSM timed out.[/bold red]")
    if audit and ok:
        audit.record("Phase 5: Post-Deploy", "SSM agent online (custom AMI)", "pass")
    if ok:
        from tee_crafter.cli.deployment.nitro.allocator import verify_allocator_readiness
        # A failed reservation is fatal, not advisory.  An enclave whose memory
        # was never reserved cannot launch, and the previous "warn and proceed"
        # behaviour hid a memory failure behind a network-looking timeout at
        # step 8d — see the module docstring in nitro/allocator.py.
        reserved = verify_allocator_readiness(
            progress, console, instance_id, aws_region, ram, cpu)
        if audit:
            audit.record("Phase 5: Post-Deploy", "Nitro allocator reserved the enclave memory",
                         "pass" if reserved else "fail", requested_mib=ram)
        if not reserved:
            return False, aws_region
    return ok, aws_region
