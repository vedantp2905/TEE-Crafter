"""Pre-flight resource checks for deploy and bake-ami.

Validates that the target cloud account has sufficient quota and capacity
for the requested instance type *before* starting expensive Terraform or
bake workflows.  Failures are reported as clear, actionable error messages.
"""

from __future__ import annotations

import os
import subprocess

import click
from tee_crafter.cli.constants import Panel

from tee_crafter.cli.constants import console
from tee_crafter.core.env_flags import env_hatch_open

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_preflight(
    tee_platform: str,
    instance_type: str | None,
    region: str | None,
    use_spot: bool = False,
) -> None:
    """Run cloud-specific preflight checks.  Raises ``click.ClickException``
    on unrecoverable quota / permission problems."""

    cloud = _cloud_for_platform(tee_platform)
    if cloud == "aws":
        _preflight_aws(tee_platform, instance_type, region or "us-east-2", use_spot)
    elif cloud == "gcp":
        _preflight_gcp(tee_platform, instance_type, region or "us-central1-a", use_spot)
    elif cloud == "azure":
        default_loc = "eastus2" if tee_platform == "gpu-cc-azure" else "westus"
        _preflight_azure(tee_platform, instance_type, region or default_loc, use_spot)


# ---------------------------------------------------------------------------
# Offline combination gate — runs before ANY cloud resource is created
# ---------------------------------------------------------------------------

def validate_deploy_combination(
    *,
    tee_platform: str,
    batch_mode: bool,
    instance_type: str | None,
    egress_mode: str,
    egress_allow: list[str],
    secrets_env_path: str | None,
    siem_config=None,
) -> None:
    """Reject impossible ``deploy`` flag combinations *before* any spend.

    Purely local: no cloud SDK calls, no DNS beyond what ``--egress-allow``
    already needs, no container build.  Every check here used to fire either
    after ``terraform apply`` (leaking a running instance) or after the full
    container build (wasting minutes on a doomed run).

    Raises :class:`click.ClickException` so the CLI exits non-zero.
    """
    _check_container_batch_supported(tee_platform, batch_mode)
    _check_instance_shape(tee_platform, instance_type)
    _check_instance_capability(tee_platform, instance_type)
    _check_graviton_secure_boot(tee_platform, instance_type)
    _check_secrets_env(secrets_env_path)
    _check_siem_egress(tee_platform, siem_config)
    _check_workload_egress(tee_platform, egress_mode, egress_allow)


def _effective_instance_type(tee_platform: str, instance_type: str | None) -> str | None:
    """The instance type Terraform will actually use.

    ``--instance-type`` is one of three inputs: ``TF_VAR_instance_type`` /
    ``TF_VAR_vm_size`` / ``TF_VAR_machine_type`` are read straight from the
    environment by Terraform, and the catalog default applies when neither is
    set.  Anything grading the operator's *choice* rather than this value has a
    blind spot.
    """
    from tee_crafter.cli.commands.deploy.platform import _INSTANCE_RULES
    from tee_crafter.core import catalog

    rule = _INSTANCE_RULES.get(tee_platform)
    env_var = rule[0] if rule else "TF_VAR_instance_type"
    return (
        os.environ.get(env_var)
        or instance_type
        or catalog.default_instance_type(tee_platform)
    )


def _check_instance_capability(tee_platform: str, instance_type: str | None) -> None:
    """Refuse shapes the hardware cannot run, with the reason.

    ``resolve_shape`` already rejects these — but only on the ``--instance-type``
    path, and it runs *before* this gate, so this is not redundant: it is the
    only check that sees a ``TF_VAR_instance_type`` override, which Terraform
    honours and ``resolve_shape`` never observes.
    """
    from tee_crafter.core import catalog

    effective = _effective_instance_type(tee_platform, instance_type)
    if not effective:
        return
    reason = catalog.unsupported_reason(tee_platform, effective)
    if not reason:
        return
    env_var = (_instance_env_var(tee_platform) if os.environ.get(
        _instance_env_var(tee_platform)) else None)
    source = f"{env_var} (environment)" if env_var else (
        "--instance-type" if instance_type else "the catalog default")
    raise click.ClickException(
        f"{reason}\n\n"
        f"  Effective instance type: {effective}\n"
        f"  Chosen by: {source}\n\n"
        f"List runnable shapes with: tee-crafter list-instances "
        f"--tee-platform {tee_platform}"
    )


def _instance_env_var(tee_platform: str) -> str:
    from tee_crafter.cli.commands.deploy.platform import _INSTANCE_RULES
    rule = _INSTANCE_RULES.get(tee_platform)
    return rule[0] if rule else "TF_VAR_instance_type"


def _check_graviton_secure_boot(tee_platform: str, instance_type: str | None) -> None:
    """UEFI Secure Boot enrolment is x86_64-only; Graviton cannot have it.

    AL2023's ``amazon-linux-sb-keys`` package ships pre-signed PK/KEK/db for
    x86_64 only, so ``bake-ami`` refuses ``--enable-secure-boot`` on an arm64
    bake host and tags the resulting AMI ``tee-crafter-secure-boot=disabled``.
    Asking a *deploy* to assert Secure Boot on a Graviton host is therefore
    asking for a posture no arm64 AMI can carry.  Terraform would otherwise
    fail this at the instance ``precondition`` — after the VPC, NAT gateway,
    S3 bucket and IAM roles had all been created.
    """
    if tee_platform != "nitro-aws":
        return
    effective = _effective_instance_type(tee_platform, instance_type)
    if not effective or "." not in effective:
        return
    from tee_crafter.core import catalog
    if catalog.instance_architecture(effective) != "arm64":
        return
    if not env_hatch_open("TF_VAR_enable_secure_boot"):
        return
    raise click.ClickException(
        f"TF_VAR_enable_secure_boot=true cannot be satisfied on {effective}.\n\n"
        f"UEFI Secure Boot enrolment is x86_64-only: AL2023's "
        f"amazon-linux-sb-keys package ships pre-signed PK/KEK/db for x86_64, "
        f"so no arm64 AMI can carry the tee-crafter-secure-boot=enabled tag "
        f"that the instance precondition requires.\n\n"
        f"Either deploy on an x86_64 host (the nitro-aws default is "
        f"c6a.xlarge), or keep {effective} and accept a Secure-Boot-disabled "
        f"posture by unsetting TF_VAR_enable_secure_boot and setting "
        f"TEE_CRAFTER_ALLOW_NO_SECURE_BOOT=1."
    )


def _check_container_batch_supported(tee_platform: str, batch_mode: bool) -> None:
    """``--batch`` runs the operator's OCI image as-is; Nitro cannot do that."""
    if not batch_mode:
        return
    from tee_crafter.resources import CONTAINER_PLATFORMS
    if tee_platform in CONTAINER_PLATFORMS:
        return
    raise click.ClickException(
        f"--batch with --tee-platform {tee_platform} is not supported for "
        "container workloads: Nitro Enclaves cannot run arbitrary container "
        "images. Use a CVM platform (snp-*, tdx-*), where the whole VM is "
        "the TEE."
    )


def _check_instance_shape(tee_platform: str, instance_type: str | None) -> None:
    """Apply the per-platform shape rule to the *effective* instance type.

    ``--instance-type`` is only one of three inputs: ``TF_VAR_instance_type``
    / ``TF_VAR_vm_size`` / ``TF_VAR_machine_type`` are read directly by
    Terraform, and the catalog default applies when neither is set.  The gate
    in ``deploy_container._deploy_cvm_container`` only ever saw a non-``None``
    ``ComputeShape.instance_type``, so the env-var branch was unreachable
    while Terraform still honoured the override.  Grade the value Terraform
    will actually use.
    """
    from tee_crafter.cli.commands.deploy.platform import _INSTANCE_RULES
    rule = _INSTANCE_RULES.get(tee_platform)
    if rule is None:
        return
    env_var, default, check_fn, err_msg = rule
    from tee_crafter.core import catalog
    effective = (
        os.environ.get(env_var)
        or instance_type
        or catalog.default_instance_type(tee_platform)
        or default
    )
    if check_fn(effective):
        return
    source = f"{env_var} (environment)" if os.environ.get(env_var) else "--instance-type"
    raise click.ClickException(
        f"{err_msg}.\n\n"
        f"  Effective instance type: {effective}\n"
        f"  Chosen by: {source}\n\n"
        f"List valid shapes with: tee-crafter list-instances "
        f"--tee-platform {tee_platform}"
    )


def _check_secrets_env(secrets_env_path: str | None) -> None:
    if not secrets_env_path:
        return
    from tee_crafter.cli.commands.deploy.secret_env import (
        load_dotenv_plaintext, SecretEnvError,
    )
    try:
        load_dotenv_plaintext(secrets_env_path)
    except SecretEnvError as exc:
        raise click.ClickException(f"Invalid --secrets-env: {exc}")


def _check_siem_egress(tee_platform: str, siem_config) -> None:
    """Validate the SIEM egress plan without writing any Terraform."""
    if siem_config is None or getattr(siem_config, "provider", "none") == "none":
        return
    from tee_crafter.cli.commands.deploy.siem_egress_terraform import decide_egress
    try:
        decide_egress(
            provider=getattr(siem_config, "provider", "none"),
            egress_mode=getattr(siem_config, "egress_mode", "auto"),
            egress_allowlist_cidrs=list(
                getattr(siem_config, "egress_allowlist_cidrs", []) or []),
            egress_ports=list(getattr(siem_config, "egress_ports", [443]) or [443]),
            tee_platform=tee_platform,
            cloudwatch_log_group=getattr(siem_config, "log_group", "") or "",
        )
    except ValueError as exc:
        raise click.ClickException(f"Invalid --siem-config egress settings: {exc}")


def _check_workload_egress(tee_platform: str, egress_mode: str,
                           egress_allow: list[str]) -> None:
    """Resolve ``--egress-mode`` / ``--egress-allow`` and gate NAT availability."""
    from tee_crafter.cli.commands.deploy.workload_egress import (
        decide_workload_egress, nat_route_gap, EgressSpecError,
    )
    try:
        decision = decide_workload_egress(
            egress_mode=egress_mode, allow_specs=list(egress_allow),
            tee_platform=tee_platform,
        )
    except EgressSpecError as exc:
        raise click.ClickException(f"Invalid --egress-allow / --egress-mode: {exc}")
    gap = nat_route_gap(decision, tee_platform)
    if gap:
        raise click.ClickException(gap)


def _cloud_for_platform(platform: str) -> str:
    if platform in ("nitro-aws", "snp-aws", "gpu-cc-aws"):
        return "aws"
    if platform in ("snp-gcp", "tdx-gcp", "gpu-cc-gcp"):
        return "gcp"
    return "azure"


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

_AWS_QUOTA_CODES = {
    "p": ("L-417A185B", "Running On-Demand P instances"),
    "m6a": ("L-1216C47A", "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances"),
    "c6a": ("L-1216C47A", "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances"),
    "r6a": ("L-1216C47A", "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances"),
    "c6g": ("L-1216C47A", "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances"),
}

_AWS_VCPU_MAP = {
    "xlarge": 4, "2xlarge": 8, "4xlarge": 16, "8xlarge": 32,
    "12xlarge": 48, "16xlarge": 64, "24xlarge": 96, "large": 2, "metal": 192,
}


def _vcpus_for_instance(instance_type: str) -> int:
    parts = instance_type.split(".")
    if len(parts) == 2:
        suffix = parts[1]
        return _AWS_VCPU_MAP.get(suffix, 4)
    return 4


def _preflight_aws(platform: str, instance_type: str | None, region: str, use_spot: bool) -> None:
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        return

    try:
        ec2 = boto3.client("ec2", region_name=region)
        sq = boto3.client("service-quotas", region_name=region)
    except (NoCredentialsError, Exception):
        console.print("[yellow]Preflight: AWS credentials not configured, skipping checks.[/yellow]")
        return

    inst = instance_type or _default_instance(platform)
    family = inst.split(".")[0].lower()
    vcpus_needed = _vcpus_for_instance(inst)

    # Check instance type availability in region
    try:
        resp = ec2.describe_instance_type_offerings(
            LocationType="region",
            Filters=[{"Name": "instance-type", "Values": [inst]}],
        )
        if not resp.get("InstanceTypeOfferings"):
            raise click.ClickException(
                f"Instance type {inst} is not available in {region}.\n"
                f"Run: aws ec2 describe-instance-type-offerings --location-type region "
                f"--filters Name=instance-type,Values={inst} --region {region}")
    except ClientError as exc:
        # Say that the check did not run. `except ClientError: pass` made this
        # a silent no-op, and the least-privilege policy in docs/aws_setup.md
        # did not grant ec2:DescribeInstanceTypeOfferings — so for anyone
        # following that page, a documented preflight check quietly did
        # nothing. Not fatal (the deploy will surface a bad instance type
        # anyway, just later and less clearly), but it must not be invisible.
        console.print(
            "[yellow]Preflight: could not confirm "
            f"{inst} is offered in {region} "
            f"({exc.response.get('Error', {}).get('Code', 'ClientError')}) — "
            "check skipped, not passed. Grant "
            "ec2:DescribeInstanceTypeOfferings to enable it.[/yellow]")

    if use_spot:
        # Dry-run spot request to check capacity
        try:
            run_kwargs: dict = {
                "ImageId": "ami-00000000000000000",
                "InstanceType": inst,
                "MinCount": 1, "MaxCount": 1,
                "DryRun": True,
                "InstanceMarketOptions": {
                    "MarketType": "spot",
                    "SpotOptions": {"InstanceInterruptionBehavior": "terminate"},
                },
            }
            ec2.run_instances(**run_kwargs)
        except ClientError as e:
            code = (e.response or {}).get("Error", {}).get("Code", "")
            if code == "DryRunOperation":
                pass  # Permission granted
            elif code == "InsufficientInstanceCapacity":
                console.print(Panel.fit(
                    f"[bold yellow]Preflight Warning: Spot Capacity[/bold yellow]\n\n"
                    f"No spot capacity for [cyan]{inst}[/cyan] in [cyan]{region}[/cyan] right now.\n"
                    f"The deployment will retry for up to 10 minutes.\n\n"
                    f"To use on-demand instead: drop the [bold]--spot[/bold] flag.",
                    border_style="yellow"))
            elif "OptInRequired" in code or "Unauthorized" in code:
                console.print(f"[yellow]Preflight: {code} — skipping spot dry-run.[/yellow]")
    else:
        # Check on-demand vCPU quota
        quota_key = family if family in _AWS_QUOTA_CODES else family[0]
        if quota_key in _AWS_QUOTA_CODES:
            quota_code, quota_name = _AWS_QUOTA_CODES[quota_key]
            try:
                resp = sq.get_service_quota(ServiceCode="ec2", QuotaCode=quota_code)
                limit = resp.get("Quota", {}).get("Value", 0)
                if limit < vcpus_needed:
                    raise click.ClickException(
                        f"Insufficient On-Demand vCPU quota for {inst} in {region}.\n\n"
                        f"  Quota: {quota_name}\n"
                        f"  Current limit: {int(limit)} vCPUs\n"
                        f"  Required: {vcpus_needed} vCPUs\n\n"
                        f"Request an increase at:\n"
                        f"  https://console.aws.amazon.com/servicequotas/home/services/ec2/quotas/{quota_code}\n\n"
                        f"Or use spot instances: pass [bold]--spot[/bold] "
                        f"(requires spot quota)")
                console.print(
                    f"[green]Preflight:[/green] On-Demand {quota_name} quota: "
                    f"{int(limit)} vCPUs (need {vcpus_needed}) — OK")
            except ClientError as exc:
                # Same reasoning as the instance-type check above: this was
                # `except ClientError: pass`, and servicequotas:GetServiceQuota
                # was missing from the documented policy, so the quota check
                # docs/aws_setup.md advertises silently did nothing. A deploy
                # that then hits the quota fails much later, mid-apply, with a
                # raw EC2 error instead of the actionable message above.
                console.print(
                    f"[yellow]Preflight: could not read the {quota_name} quota "
                    f"({exc.response.get('Error', {}).get('Code', 'ClientError')})"
                    " — check skipped, not passed. Grant "
                    "servicequotas:GetServiceQuota to enable it.[/yellow]")


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------

def _preflight_gcp(platform: str, instance_type: str | None, zone: str, use_spot: bool) -> None:
    region = "-".join(zone.split("-")[:2])
    inst = instance_type or _default_instance(platform)

    # ``machineTypes.get`` answers two different questions with one exit code:
    # "that shape does not exist here" and "Compute Engine could not answer".
    # Reporting both as "may not be available" misattributes a Google-side
    # outage to the user's zone choice -- observed 2026-08-21, when every
    # ``machineTypes`` call in this project returned HTTP 503 ``backendError``
    # while ``regions``, ``zones`` and ``instances`` all answered normally.
    vcpus = 0
    probe_failed = ""
    try:
        result = subprocess.run(
            ["gcloud", "compute", "machine-types", "describe", inst,
             f"--zone={zone}", "--format=value(guestCpus)"],
            capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            stderr = (result.stderr or "").lower()
            # Match the resource-not-found shape specifically ("The resource
            # '...' was not found"), not a bare "not found".  A bare match also
            # catches credential failures -- gcloud's impersonation error is
            # "Gaia id not found for email <sa>" -- and reporting those as
            # "machine type may not be available" sends the operator to check
            # zone capacity when the real problem is their auth.  Seen for
            # real during the first GCP bake on 2026-08-21.
            if "was not found" in stderr or "404" in stderr:
                console.print(Panel.fit(
                    f"[bold yellow]Preflight Warning[/bold yellow]\n\n"
                    f"Machine type [cyan]{inst}[/cyan] may not be available in "
                    f"[cyan]{zone}[/cyan].\n"
                    f"Check: gcloud compute machine-types list --zones={zone} "
                    f"--filter=\"name={inst}\"",
                    border_style="yellow"))
            else:
                lines = (result.stderr or "").strip().splitlines()
                probe_failed = lines[-1][:160] if lines else ""
                console.print(
                    f"[yellow]Preflight: could not read machine type {inst} in "
                    f"{zone} — availability check skipped, not passed. "
                    f"{probe_failed}[/yellow]")
        else:
            vcpus = int(result.stdout.strip()) if result.stdout.strip() else 0
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass

    # Fall through to the quota check even when the shape probe failed.  An
    # early ``return`` here meant one unavailable API silently disabled the
    # quota check as well -- the same shape as the AWS ``except ClientError:
    # pass`` above, where a check the docs advertised did nothing at all.
    if vcpus == 0:
        vcpus = _gcp_vcpus(inst)
    if vcpus == 0:
        console.print(
            f"[yellow]Preflight: vCPU count for {inst} is unknown — GCP CPU "
            f"quota check skipped, not passed.[/yellow]")
        return

    # Check regional CPU quota
    try:
        quota_result = subprocess.run(
            ["gcloud", "compute", "regions", "describe", region,
             "--format=json(quotas)"],
            capture_output=True, text=True, timeout=30)
        if quota_result.returncode == 0:
            import json
            data = json.loads(quota_result.stdout)
            quotas = data.get("quotas", [])

            # Both the machine family's own quota and the aggregate ``CPUS``
            # quota gate a launch, and the family one is usually the smaller:
            # this project reports N2D_CPUS=8 / C3_CPUS=8 against CPUS=32, so
            # checking only ``CPUS`` would pass a shape the family quota
            # refuses.  docs/gcp_setup.md documents N2D_CPUS / C3_CPUS as the
            # gating metrics, so checking only the aggregate also disagreed
            # with our own setup guide.
            if use_spot:
                metrics = ["PREEMPTIBLE_CPUS"]
            else:
                family = inst.split("-")[0].upper()
                metrics = [f"{family}_CPUS", "CPUS"]
            by_metric = {q.get("metric"): q for q in quotas}

            checked = []
            for metric in metrics:
                q = by_metric.get(metric)
                if q is None:
                    continue
                limit = q.get("limit", 0)
                usage = q.get("usage", 0)
                available = limit - usage
                if available < vcpus:
                    mode = "Spot (preemptible)" if use_spot else "On-Demand"
                    raise click.ClickException(
                        f"Insufficient GCP {mode} CPU quota in {region}.\n\n"
                        f"  Metric: {metric}\n"
                        f"  Limit: {limit}, Used: {usage}, Available: {available}\n"
                        f"  Required: {vcpus} vCPUs for {inst}\n\n"
                        f"Request an increase at:\n"
                        f"  https://console.cloud.google.com/iam-admin/quotas?metric={metric}")
                checked.append(f"{metric} {available}/{int(limit)}")
            if checked:
                console.print(
                    f"[green]Preflight:[/green] GCP CPU quota in {region}: "
                    f"{', '.join(checked)} available (need {vcpus}) — OK")
            else:
                console.print(
                    f"[yellow]Preflight: none of {', '.join(metrics)} appeared in "
                    f"the {region} quota list — CPU quota check skipped, not "
                    f"passed.[/yellow]")

            # Check GPU quota for GPU platforms
            if platform in ("gpu-cc-gcp",):
                for q in quotas:
                    if "GPU" in q.get("metric", ""):
                        limit = q.get("limit", 0)
                        usage = q.get("usage", 0)
                        if limit == 0:
                            console.print(Panel.fit(
                                f"[bold yellow]Preflight Warning: GPU Quota[/bold yellow]\n\n"
                                f"GPU quota ({q['metric']}) is 0 in {region}.\n"
                                f"Request an increase before deploying.",
                                border_style="yellow"))
                        break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------

def _preflight_azure(platform: str, instance_type: str | None, location: str, use_spot: bool) -> None:
    if platform == "gpu-cc-azure":
        from tee_crafter.core.gpu import GPU_CC_AZURE_LOCATION

        location = GPU_CC_AZURE_LOCATION
    inst = instance_type or _default_instance(platform)

    try:
        # Check VM SKU availability
        result = subprocess.run(
            ["az", "vm", "list-skus", "--location", location, "--size", inst,
             "--query", f"[?name=='{inst}']", "--output", "json"],
            capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            import json
            skus = json.loads(result.stdout) if result.stdout.strip() else []
            if not skus:
                raise click.ClickException(
                    f"VM size {inst} is not available in {location}.\n"
                    f"Check: az vm list-skus --location {location} --size {inst}")
            restrictions = skus[0].get("restrictions", [])
            if restrictions:
                for r in restrictions:
                    reason = r.get("reasonCode", "")
                    if reason == "NotAvailableForSubscription":
                        console.print(Panel.fit(
                            f"[bold yellow]Preflight Warning[/bold yellow]\n\n"
                            f"VM size [cyan]{inst}[/cyan] is restricted in [cyan]{location}[/cyan].\n"
                            f"You may need to request quota access.",
                            border_style="yellow"))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return

    # Check vCPU quota
    try:
        result = subprocess.run(
            ["az", "vm", "list-usage", "--location", location, "--output", "json"],
            capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            import json
            usages = json.loads(result.stdout) if result.stdout.strip() else []

            # Find the family quota matching our VM
            family_prefix = _azure_family_prefix(inst)
            for u in usages:
                name_val = u.get("name", {}).get("value", "")
                local_name = u.get("name", {}).get("localizedValue", "")
                if family_prefix and family_prefix.lower() in name_val.lower():
                    limit = u.get("limit", 0)
                    current = u.get("currentValue", 0)
                    available = limit - current
                    vcpus = _azure_vcpus(inst)
                    if available < vcpus:
                        raise click.ClickException(
                            f"Insufficient Azure vCPU quota in {location}.\n\n"
                            f"  Family: {local_name}\n"
                            f"  Limit: {limit}, Used: {current}, Available: {available}\n"
                            f"  Required: {vcpus} vCPUs for {inst}\n\n"
                            f"Request an increase at:\n"
                            f"  Azure Portal → Subscriptions → Usage + quotas → search \"{local_name}\"")
                    console.print(
                        f"[green]Preflight:[/green] Azure {local_name}: "
                        f"{available}/{limit} available (need {vcpus}) — OK")
                    break

            # Also check total regional vCPUs
            for u in usages:
                if u.get("name", {}).get("value", "") == "cores":
                    limit = u.get("limit", 0)
                    current = u.get("currentValue", 0)
                    available = limit - current
                    vcpus = _azure_vcpus(inst)
                    if available < vcpus:
                        raise click.ClickException(
                            f"Insufficient Azure Total Regional vCPUs in {location}.\n\n"
                            f"  Limit: {limit}, Used: {current}, Available: {available}\n"
                            f"  Required: {vcpus} vCPUs for {inst}\n\n"
                            f"Request an increase at:\n"
                            f"  Azure Portal → Subscriptions → Usage + quotas → \"Total Regional vCPUs\"")
                    break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def _azure_family_prefix(vm_size: str) -> str:
    """Map VM size to its quota family name prefix."""
    lower = vm_size.lower()
    if "ncc" in lower and "h100" in lower:
        return "NCCads2023"
    if "dc" in lower and "as" in lower and "v5" in lower:
        return "standardDCASv5"
    if "dc" in lower and "es" in lower and "v6" in lower:
        return "standardDCESv6"
    if "dc" in lower and "s" in lower and "v3" in lower:
        return "standardDCSv3"
    if "ec" in lower:
        return "standardECAS"
    return ""


def _azure_vcpus(vm_size: str) -> int:
    """Rough vCPU estimate from Azure VM size name."""
    import re
    m = re.search(r"(\d+)", vm_size.replace("Standard_", ""))
    return int(m.group(1)) if m else 4


# GPU shapes whose name does not encode the vCPU count.  ``a3-highgpu-1g``
# trails with the *GPU* count, so the generic parse below would read 1 vCPU
# and wave through a shape that needs 26 (the figure in the quota table in
# docs/gcp_setup.md).  Only shapes whose vCPU count we have actually
# confirmed belong here -- a wrong number is worse than no number, because
# the caller reports "skipped, not passed" for 0 but silently trusts a value.
_GCP_VCPU_OVERRIDES = {
    "a3-highgpu-1g": 26,
}


def _gcp_vcpus(machine_type: str) -> int:
    """vCPU count parsed from a GCP machine-type name, or ``0`` if unknown.

    Fallback for when ``machineTypes.get`` cannot answer.  GCP's
    ``<family>-<class>-<n>`` names put the vCPU count last for the CPU shapes
    we deploy (``n2d-standard-2`` -> 2, ``c3-standard-4`` -> 4).  Returning
    ``0`` rather than a guess keeps an unrecognised name from being quota
    checked against a made-up number.
    """
    import re
    if machine_type in _GCP_VCPU_OVERRIDES:
        return _GCP_VCPU_OVERRIDES[machine_type]
    m = re.search(r"-(\d+)$", machine_type)
    return int(m.group(1)) if m else 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PLATFORM_DEFAULTS = {
    # Default to c6a.xlarge (AMD Milan / x86_64) since 2026: Secure Boot is on by
    # default for non-GPU AWS platforms (see ``docs/security.md`` §15.1A) and the
    # AL2023 ``amazon-linux-sb-keys`` blobs are x86_64-only.  Graviton hosts
    # (``c6g.*``, ``c7g.*``, etc.) still work end-to-end for Nitro but cannot
    # currently enroll SB at bake time.
    "nitro-aws": "c6a.xlarge",
    "sgx-azure": "Standard_DC2s_v3",
    "tdx-azure": "Standard_DC2es_v6",
    "snp-aws": "m6a.xlarge",
    "snp-azure": "Standard_DC2as_v5",
    "snp-gcp": "n2d-standard-2",
    "tdx-gcp": "c3-standard-4",
    "gpu-cc-aws": "p5.4xlarge",
    "gpu-cc-gcp": "a3-highgpu-1g",
    "gpu-cc-azure": "Standard_NCC40ads_H100_v5",
}


def _default_instance(platform: str) -> str:
    return _PLATFORM_DEFAULTS.get(platform, "")
