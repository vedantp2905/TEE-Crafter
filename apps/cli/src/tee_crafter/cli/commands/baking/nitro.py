"""Nitro (AWS) AMI baking."""
import time

import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.cli.constants import console
from tee_crafter.core import catalog
from tee_crafter.cli.commands.baking.common.helpers import (
    load_setup_script, resolve_base_ami, get_default_subnet, get_ssm_instance_profile,
)

# Default bake host for Nitro.  Flipped from c6g.xlarge (Graviton/arm64) to
# c6a.xlarge (AMD Milan/x86_64) in May 2026 so the *default* bake produces a
# Secure-Boot-enrolled AMI: the AL2023 ``amazon-linux-sb-keys`` PK/KEK/db
# blobs only ship pre-signed for x86_64, so SB enrollment is x86_64-only
# (see ``docs/security.md`` §15.1A and ``docs/nitro_flow.md`` "UEFI Secure
# Boot").  Graviton is still fully supported as ``--instance-type c7g.xlarge``
# / ``c6g.xlarge`` etc., it just bakes without SB until the arm64 keys are
# end-to-end validated.
_NITRO_INSTANCE_TYPE = "c6a.xlarge"
_IMAGE_WAIT_DELAY_SECONDS = 15
_IMAGE_WAIT_MAX_ATTEMPTS = 240  # 60 minutes


def _verify_secure_boot_enrolled(instance_id: str, region: str) -> None:
    """Run `mokutil --sb-state` over SSM and abort the bake unless SB is on.

    Identical contract to :func:`tee_crafter.cli.commands.baking.snp._verify_secure_boot_enrolled`
    but specialised for the Nitro/AL2023 bake (which uses the
    ``amazon-linux-sb-keys`` package and therefore must additionally have
    succeeded against the Amazon Linux Secure Boot Signing CA).
    """
    from tee_crafter.core.remote.ssm import run_ssm_command
    ok, stdout, stderr = run_ssm_command(
        instance_id,
        "mokutil --sb-state 2>&1 || true; "
        "od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null "
        "| awk '{print \"SecureBoot_byte=\" $5}' | head -1",
        region, timeout=60,
    )
    combined = (stdout or "") + (stderr or "")
    if not ok or "SecureBoot enabled" not in combined or "SecureBoot_byte=1" not in combined:
        raise click.ClickException(
            "Secure Boot verification failed on the Nitro bake instance — "
            "refusing to tag this AMI as SB-enrolled.\n"
            f"mokutil output:\n{combined[-1500:]}"
        )


def bake_nitro_ami(
    region: str, instance_type: str | None, subnet_id: str | None,
    enclave_ram: int, enclave_cpu: int, *, use_spot: bool = False,
    enable_secure_boot: bool = False,
) -> str:
    """Bake a Nitro AMI on AWS.

    When ``enable_secure_boot`` is True the bake script enrolls the AWS-shipped
    ``amazon-linux-sb-keys`` PK/KEK/db blobs into the bake instance's UEFI
    NVRAM via ``efi-updatevar``; ``aws ec2 create-image`` then captures that
    NVRAM into ``Image.UefiData`` so every instance launched from the AMI
    boots with UEFI Secure Boot enforcing.  ``nitro_enclaves`` is a
    *builtin* kernel module on AL2023 (verified empirically — see
    ``docs/security.md``), so enabling SB neither requires nor breaks any
    out-of-tree modules.
    """
    inst_type = instance_type or _NITRO_INSTANCE_TYPE
    architecture = catalog.instance_architecture(inst_type) or "x86_64"

    # Refuse impossible bakes first — before any spend, and before boto3 is
    # even constructed, so an operator with no credentials configured still
    # gets this message rather than a NoRegionError.  Both checks used to fire
    # only *after* run_instances plus a wait of up to three minutes for the SSM
    # agent, so `bake-ami --instance-type c7g.xlarge` (Secure Boot is on by
    # default) launched a Graviton instance and then errored out on a
    # contradiction knowable from the instance type alone.
    if enable_secure_boot and architecture != "x86_64":
        raise click.ClickException(
            f"--enable-secure-boot cannot be satisfied on {inst_type}.\n\n"
            f"UEFI Secure Boot enrolment needs an x86_64 bake host: AL2023's "
            f"amazon-linux-sb-keys package ships pre-signed PK/KEK/db for "
            f"x86_64 only, so there is nothing to enrol on arm64.\n\n"
            f"Either bake on x86_64 (the default is {_NITRO_INSTANCE_TYPE}), or "
            f"pass --no-enable-secure-boot to bake a Graviton AMI without it. "
            f"The resulting AMI is tagged tee-crafter-secure-boot=disabled, so "
            f"deploying it also needs TEE_CRAFTER_ALLOW_NO_SECURE_BOOT=1."
        )
    _reason = catalog.unsupported_reason("nitro-aws", inst_type)
    if _reason:
        raise click.ClickException(
            f"{_reason}\n\nThe bake host must itself be able to run an "
            f"enclave: the bake exercises the allocator and `nitro-cli "
            f"build-enclave` before capturing the AMI."
        )

    import boto3
    from tee_crafter.core.remote.ssm import wait_for_ssm, run_ssm_command
    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam", region_name=region)

    sb_label = "[green]ENABLED[/green]" if enable_secure_boot else "[yellow]disabled[/yellow]"
    console.print(Panel.fit(
        f"[bold blue]TEE-Crafter: Bake AMI (Nitro)[/bold blue]\n\n"
        f"Region: [green]{region}[/green]\nInstance type: [cyan]{inst_type}[/cyan]\n"
        f"Platform: [magenta]NITRO[/magenta]\n"
        f"UEFI Secure Boot: {sb_label}", border_style="blue"))
    instance_id = None
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=False) as progress:
            t = progress.add_task("[yellow]Resolving base AMI...[/yellow]", total=None)
            base_ami = resolve_base_ami(ec2, "nitro-aws", region, architecture=architecture)
            progress.update(t, description=f"[green]✓ Base AMI: {base_ami}[/green]")
            t = progress.add_task("[yellow]Ensuring IAM instance profile...[/yellow]", total=None)
            profile_name = get_ssm_instance_profile(iam)
            progress.update(t, description=f"[green]✓ Instance profile: {profile_name}[/green]")
            t = progress.add_task("[yellow]Resolving subnet...[/yellow]", total=None)
            resolved_subnet = subnet_id or get_default_subnet(ec2)
            progress.update(t, description=f"[green]✓ Subnet: {resolved_subnet}[/green]")
            subnet_info = ec2.describe_subnets(SubnetIds=[resolved_subnet])["Subnets"][0]
            vpc_id = subnet_info["VpcId"]
            default_sg = ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                         {"Name": "group-name", "Values": ["default"]}],
            )["SecurityGroups"][0]["GroupId"]
            t = progress.add_task("[yellow]Launching temporary bake instance...[/yellow]", total=None)
            user_data_script = (
                "#!/bin/bash\nset -x\n"
                "echo -e 'nameserver 8.8.8.8\\noptions timeout:2 attempts:3' > /etc/resolv.conf\n"
                "dnf install -y amazon-ssm-agent 2>/dev/null || true\n"
                "systemctl enable amazon-ssm-agent 2>/dev/null || true\n"
                "systemctl start amazon-ssm-agent 2>/dev/null || true\n")
            run_kwargs = dict(
                ImageId=base_ami, InstanceType=inst_type, MinCount=1, MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": resolved_subnet,
                                    "Groups": [default_sg], "AssociatePublicIpAddress": True}],
                MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1},
                BlockDeviceMappings=[{"DeviceName": "/dev/xvda",
                                     "Ebs": {"VolumeSize": 30, "VolumeType": "gp3", "Encrypted": True}}],
                TagSpecifications=[{"ResourceType": "instance",
                                    "Tags": [{"Key": "Name", "Value": "tee-crafter-bake-nitro"},
                                             {"Key": "Project", "Value": "tee-crafter"}]}],
                UserData=user_data_script)
            if use_spot:
                run_kwargs["InstanceMarketOptions"] = {
                    "MarketType": "spot",
                    "SpotOptions": {"InstanceInterruptionBehavior": "terminate"},
                }
            resp = ec2.run_instances(**run_kwargs)
            instance_id = resp["Instances"][0]["InstanceId"]
            progress.update(t, description=f"[green]✓ Instance launched: {instance_id}[/green]")
            t = progress.add_task("[yellow]Waiting for instance to reach running state...[/yellow]", total=None)
            ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
            progress.update(t, description="[green]✓ Instance running.[/green]")
            t = progress.add_task("[yellow]Waiting for SSM agent (up to 3 min)...[/yellow]", total=None)
            if not wait_for_ssm(instance_id, region, timeout=180):
                raise click.ClickException("SSM agent did not come online within 3 minutes.")
            progress.update(t, description="[green]✓ SSM agent online.[/green]")
            t = progress.add_task("[yellow]Running Nitro setup script via SSM (this may take 10+ min)...[/yellow]", total=None)
            allocator_mb = max(512, enclave_ram) + 1024
            # (The Graviton/Secure-Boot contradiction is refused before the
            # instance is launched — see the top of this function.)
            ok, stdout, stderr = run_ssm_command(
                instance_id,
                load_setup_script(
                    "nitro-aws",
                    allocator_mb=allocator_mb, cpu=enclave_cpu, aws_region=region,
                    enable_secure_boot=enable_secure_boot,
                ),
                region, timeout=1200,
            )
            if not ok:
                console.print(f"[bold red]Setup script failed:[/bold red]\n{stderr[:2000]}")
                raise click.ClickException("Setup script failed on the bake instance.")
            progress.update(t, description="[green]✓ Nitro setup complete.[/green]")
            if enable_secure_boot:
                t = progress.add_task("[yellow]Verifying Secure Boot is enrolled in firmware NVRAM...[/yellow]", total=None)
                _verify_secure_boot_enrolled(instance_id, region)
                progress.update(t, description="[green]✓ Secure Boot enrolled and enforcing.[/green]")
            t = progress.add_task("[yellow]Cleaning up before AMI snapshot...[/yellow]", total=None)
            run_ssm_command(instance_id,
                            "rm -rf /tmp/* /var/tmp/* /root/.bash_history /home/*/.bash_history; "
                            "cloud-init clean --logs 2>/dev/null || true; sync", region, timeout=60)
            progress.update(t, description="[green]✓ Cleanup done.[/green]")
            t = progress.add_task("[yellow]Stopping instance for AMI creation...[/yellow]", total=None)
            ec2.stop_instances(InstanceIds=[instance_id])
            ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id])
            progress.update(t, description="[green]✓ Instance stopped.[/green]")
            t = progress.add_task("[yellow]Creating AMI (this may take up to ~60 minutes)...[/yellow]", total=None)
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            ami_name = f"tee-crafter-nitro-{timestamp}"
            # Generic AMI: the enclave allocator (memory_mib + cpu_count) is
            # rewritten to the deploy-time enclave shape at launch (see
            # nitro/allocator.py).  The baked values are only a baseline, so we
            # advertise the dynamic-allocator contract instead of a hard cap —
            # this AMI runs unchanged on any instance size >= the catalog floor.
            ami_tags = [
                {"Key": "Name", "Value": ami_name},
                {"Key": "tee-crafter-platform", "Value": "nitro-aws"},
                {"Key": "Project", "Value": "tee-crafter"},
                {"Key": "tee-crafter-allocator", "Value": "dynamic"},
                {"Key": "tee-crafter-baked-enclave-ram-mib", "Value": str(enclave_ram)},
                {"Key": "tee-crafter-baked-enclave-cpu", "Value": str(enclave_cpu)},
                {"Key": "tee-crafter-secure-boot",
                 "Value": "enabled" if enable_secure_boot else "disabled"},
            ]
            ami_resp = ec2.create_image(
                InstanceId=instance_id, Name=ami_name, NoReboot=True,
                Description="TEE-Crafter Nitro AMI with pre-baked dependencies"
                            + (" (UEFI Secure Boot enrolled)" if enable_secure_boot else ""),
                TagSpecifications=[{"ResourceType": "image", "Tags": ami_tags}])
            ami_id = ami_resp["ImageId"]
            progress.update(t, description=f"[yellow]AMI {ami_id} creation in progress...[/yellow]")
            ec2.get_waiter("image_available").wait(
                ImageIds=[ami_id],
                WaiterConfig={"Delay": _IMAGE_WAIT_DELAY_SECONDS, "MaxAttempts": _IMAGE_WAIT_MAX_ATTEMPTS},
            )
            progress.update(t, description=f"[green]✓ AMI ready: {ami_id}[/green]")
            # Record the snapshot create-image just made.  DeregisterImage does
            # not delete it and this identity cannot list snapshots, so the id
            # is only knowable while the AMI still exists.
            from tee_crafter.cli.commands.baking.common.ebs_ledger import (
                record_backing_snapshots, retirement_hint,
            )
            _snaps = record_backing_snapshots(
                ec2, ami_id, platform="nitro-aws", region=region,
                ami_name=ami_name)
            _hint = retirement_hint(ami_id, _snaps, region)
            t = progress.add_task("[yellow]Terminating bake instance...[/yellow]", total=None)
            ec2.terminate_instances(InstanceIds=[instance_id])
            instance_id = None
            progress.update(t, description="[green]✓ Instance terminated.[/green]")
        sb_line = ("UEFI Secure Boot: [green]enrolled in AMI NVRAM[/green]\n"
                   if enable_secure_boot else "")
        console.print(Panel.fit(
            f"[bold green]AMI Bake Complete[/bold green]\n\nAMI ID: [cyan]{ami_id}[/cyan]\n"
            f"AMI Name: [cyan]{ami_name}[/cyan]\nPlatform: [magenta]Nitro[/magenta]\n"
            f"Region: [green]{region}[/green]\n"
            f"{sb_line}\nUse with deploy:\n"
            f"  [bold]tee-crafter deploy --ami-id {ami_id} --tee-platform nitro-aws ...[/bold]"
            + (f"\n\n[yellow]{_hint}[/yellow]" if _hint else ""),
            border_style="green"))
        return ami_id
    except (KeyboardInterrupt, click.Abort):
        console.print("\n[bold yellow]Interrupted. Cleaning up...[/bold yellow]")
        if instance_id:
            try: ec2.terminate_instances(InstanceIds=[instance_id])
            except Exception: console.print(f"[red]Could not terminate {instance_id}.[/red]")
        raise click.Abort()
    except Exception as e:
        if instance_id:
            try: ec2.terminate_instances(InstanceIds=[instance_id])
            except Exception: pass
        raise click.ClickException(str(e)) if not isinstance(e, click.ClickException) else e
