"""AMD SEV-SNP (AWS) AMI baking."""
import time

import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.cli.constants import console
from tee_crafter.cli.commands.baking.common.helpers import (
    load_setup_script, resolve_base_ami, get_default_subnet, get_ssm_instance_profile,
)
from tee_crafter.cli.commands.baking.snp_azure import (  # noqa: F401 – re-export
    bake_snp_azure_image,
)

_SNP_AWS_INSTANCE_TYPE = "m6a.large"
_VALID_SNP_AWS_FAMILIES = ("m6a", "c6a", "r6a", "m7a", "c7a", "r7a")
_IMAGE_WAIT_DELAY_SECONDS = 15
_IMAGE_WAIT_MAX_ATTEMPTS = 240  # 60 minutes


def _verify_secure_boot_enrolled(instance_id: str, region: str) -> None:
    """Run `mokutil --sb-state` over SSM and fail the bake unless SB is enabled.

    Called only when ``--enable-secure-boot`` is passed.  The point is to
    refuse to produce an AMI tagged ``tee-crafter-secure-boot=enabled`` if
    the in-VM ``efi-updatevar`` chain silently failed (e.g., dbx EIO that
    actually broke the rest of the enrollment, or a kernel that doesn't
    expose ``efivars``).
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
            "Secure Boot verification failed on the bake instance — "
            "refusing to tag this AMI as SB-enrolled.\n"
            f"mokutil output:\n{combined[-1500:]}"
        )


def bake_snp_aws_ami(
    region: str, instance_type: str | None, subnet_id: str | None,
    enclave_ram: int, enclave_cpu: int, *, use_spot: bool = False,
    enable_secure_boot: bool = False,
) -> str:
    """Bake an AWS AMI with AMD SEV-SNP dependencies pre-installed.

    When ``enable_secure_boot`` is True the bake script enrolls a tee-crafter
    Platform Key + KEK and a UEFI db containing both the Microsoft UEFI CA
    2011 (so shim/grub/kernel continue to verify) and a self-signed
    tee-crafter db cert.  ``aws ec2 create-image`` captures the resulting
    UEFI NVRAM into ``Image.UefiData``, so every instance launched from
    the AMI boots with Secure Boot enforcing on its first boot.  The
    function refuses to mark the bake successful unless ``mokutil --sb-state``
    reports ``SecureBoot enabled`` post-enrollment.
    """
    import boto3
    from tee_crafter.core.remote.ssm import wait_for_ssm, run_ssm_command
    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam", region_name=region)
    inst_type = instance_type or _SNP_AWS_INSTANCE_TYPE
    family = inst_type.split(".")[0]
    if family not in _VALID_SNP_AWS_FAMILIES:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] Instance type [cyan]{inst_type}[/cyan] "
            f"(family {family}) may not support SEV-SNP. "
            f"Recommended families: {', '.join(_VALID_SNP_AWS_FAMILIES)}")
    sb_label = "[green]ENABLED[/green]" if enable_secure_boot else "[yellow]disabled[/yellow]"
    console.print(Panel.fit(
        f"[bold blue]TEE-Crafter: Bake AMI (AMD SEV-SNP on AWS)[/bold blue]\n\n"
        f"Region: [green]{region}[/green]\nInstance type: [cyan]{inst_type}[/cyan]\n"
        f"Platform: [magenta]SNP-AWS[/magenta]\n"
        f"UEFI Secure Boot: {sb_label}", border_style="blue"))
    instance_id = None
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=False) as progress:
            t = progress.add_task("[yellow]Resolving base AMI...[/yellow]", total=None)
            base_ami = resolve_base_ami(ec2, "snp-aws", region, architecture="x86_64")
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
            t = progress.add_task("[yellow]Launching temporary bake instance with SEV-SNP...[/yellow]", total=None)
            user_data_script = (
                "#!/bin/bash\nset -x\n"
                "echo -e 'nameserver 8.8.8.8\\noptions timeout:2 attempts:3' > /etc/resolv.conf\n"
                "apt-get update -y 2>/dev/null || dnf install -y amazon-ssm-agent 2>/dev/null || true\n"
                "snap install amazon-ssm-agent --classic 2>/dev/null || true\n"
                "systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service 2>/dev/null || true\n"
                "systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service 2>/dev/null || true\n"
                "systemctl enable amazon-ssm-agent 2>/dev/null || true\n"
                "systemctl start amazon-ssm-agent 2>/dev/null || true\n")
            run_kwargs = dict(
                ImageId=base_ami, InstanceType=inst_type, MinCount=1, MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                CpuOptions={"AmdSevSnp": "enabled"},
                NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": resolved_subnet,
                                    "Groups": [default_sg], "AssociatePublicIpAddress": True}],
                MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1},
                BlockDeviceMappings=[{"DeviceName": "/dev/sda1",
                                     "Ebs": {"VolumeSize": 30, "VolumeType": "gp3", "Encrypted": True}}],
                TagSpecifications=[{"ResourceType": "instance",
                                    "Tags": [{"Key": "Name", "Value": "tee-crafter-bake-snp-aws"},
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
            t = progress.add_task("[yellow]Waiting for SSM agent (up to 5 min)...[/yellow]", total=None)
            if not wait_for_ssm(instance_id, region, timeout=300):
                raise click.ClickException("SSM agent did not come online within 5 minutes.")
            progress.update(t, description="[green]✓ SSM agent online.[/green]")
            t = progress.add_task("[yellow]Running SNP setup script via SSM (10+ min)...[/yellow]", total=None)
            ok, stdout, stderr = run_ssm_command(
                instance_id,
                load_setup_script("snp-aws", enable_secure_boot=enable_secure_boot),
                region, timeout=1200,
            )
            if not ok:
                console.print(f"[bold red]Setup script failed:[/bold red]\n{((stdout or '') + (stderr or ''))[-3000:]}")
                raise click.ClickException("SNP setup script failed on the bake instance.")
            progress.update(t, description="[green]✓ SNP setup complete.[/green]")
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
            ami_name = f"tee-crafter-snp-aws-{timestamp}"
            ami_tags = [
                {"Key": "Name", "Value": ami_name},
                {"Key": "tee-crafter-platform", "Value": "snp-aws"},
                {"Key": "Project", "Value": "tee-crafter"},
                {"Key": "tee-crafter-max-enclave-ram-mib", "Value": str(enclave_ram)},
                {"Key": "tee-crafter-max-enclave-cpu", "Value": str(enclave_cpu)},
                {"Key": "tee-crafter-secure-boot",
                 "Value": "enabled" if enable_secure_boot else "disabled"},
            ]
            ami_resp = ec2.create_image(
                InstanceId=instance_id, Name=ami_name, NoReboot=True,
                Description="TEE-Crafter AMD SEV-SNP AMI with pre-baked dependencies"
                            + (" (UEFI Secure Boot enrolled)" if enable_secure_boot else ""),
                TagSpecifications=[{"ResourceType": "image", "Tags": ami_tags}])
            ami_id = ami_resp["ImageId"]
            progress.update(t, description=f"[yellow]AMI {ami_id} creation in progress...[/yellow]")
            ec2.get_waiter("image_available").wait(
                ImageIds=[ami_id],
                WaiterConfig={"Delay": _IMAGE_WAIT_DELAY_SECONDS, "MaxAttempts": _IMAGE_WAIT_MAX_ATTEMPTS},
            )
            progress.update(t, description=f"[green]✓ AMI ready: {ami_id}[/green]")

            # NitroTPM, so that BYOK key release on this platform can be gated
            # on a measurement rather than only on the caller's IAM identity.
            # AWS KMS evaluates kms:RecipientAttestation:NitroTPMPCR<n> against a
            # signed attestation document, which an instance can only produce
            # when its AMI declares TpmSupport=v2.0 -- and only RegisterImage can
            # set that, never CreateImage. See core/keys/nitrotpm.py.
            #
            # Ordering is deliberate: register before the snapshot ledger, so the
            # ledger records the AMI that survives. Doing it the other way round
            # files the snapshots under an AMI id that register_nitro_tpm_ami
            # then deregisters, and a bake's snapshots are the expensive part to
            # lose track of.
            if enable_secure_boot:
                t = progress.add_task(
                    "[yellow]Enabling NitroTPM v2.0 on the AMI...[/yellow]",
                    total=None)
                from tee_crafter.cli.commands.baking.common.nitro_tpm_ami import (
                    NitroTpmAmiError, register_nitro_tpm_ami,
                )
                try:
                    tpm_ami_id, _boot_mode = register_nitro_tpm_ami(
                        ec2, source_ami_id=ami_id, name=f"{ami_name}-tpm",
                        description=(
                            "TEE-Crafter AMD SEV-SNP AMI (UEFI Secure Boot + "
                            "NitroTPM v2.0) with pre-baked dependencies"),
                        tags=ami_tags + [
                            {"Key": "tee-crafter-nitro-tpm", "Value": "v2.0"}],
                        waiter_delay=_IMAGE_WAIT_DELAY_SECONDS,
                        waiter_max_attempts=_IMAGE_WAIT_MAX_ATTEMPTS,
                    )
                except NitroTpmAmiError as exc:
                    # Never fail the bake over this. The image is still a
                    # perfectly good SEV-SNP image; what it loses is the
                    # *option* of measurement-gated key release, and the gating
                    # table already reports that state honestly as iam-scoped.
                    progress.update(t, description=(
                        "[yellow]! NitroTPM not enabled; key release stays "
                        "identity-gated.[/yellow]"))
                    console.print(
                        f"[yellow]NitroTPM could not be enabled on {ami_id}: "
                        f"{exc}\nThe image is usable. BYOK key release on it "
                        f"remains IAM-scoped rather than measurement-gated.[/yellow]")
                else:
                    if tpm_ami_id != ami_id:
                        ami_id = tpm_ami_id
                        ami_name = f"{ami_name}-tpm"
                    progress.update(t, description=(
                        f"[green]✓ NitroTPM v2.0 enabled: {ami_id}[/green]"))
            else:
                # PCR7 is the Secure Boot policy digest, so without Secure Boot
                # the register that matters has nothing to attest to.
                console.print(
                    "[dim]Secure Boot disabled, so NitroTPM was not enabled: "
                    "PCR7 measures the Secure Boot policy and would be "
                    "meaningless here. BYOK key release stays IAM-scoped.[/dim]")

            # Record the snapshot create-image just made.  DeregisterImage does
            # not delete it and this identity cannot list snapshots, so the id
            # is only knowable while the AMI still exists.
            from tee_crafter.cli.commands.baking.common.ebs_ledger import (
                record_backing_snapshots, retirement_hint,
            )
            _snaps = record_backing_snapshots(
                ec2, ami_id, platform="snp-aws", region=region,
                ami_name=ami_name)
            _hint = retirement_hint(ami_id, _snaps, region)
            t = progress.add_task("[yellow]Terminating bake instance...[/yellow]", total=None)
            ec2.terminate_instances(InstanceIds=[instance_id])
            instance_id = None
            progress.update(t, description="[green]✓ Instance terminated.[/green]")
            progress.add_task(
                "[yellow]Capturing launch measurement (auto-pin)...[/yellow]", total=None)
        # Outside the progress block so the throwaway instance's own spinners
        # render cleanly.
        from tee_crafter.cli.commands.baking.common.measurement_capture import (
            capture_platform_measurements,
        )
        capture_platform_measurements("snp-aws", ami_id, region=region)
        sb_line = ("UEFI Secure Boot: [green]enrolled in AMI NVRAM[/green]\n"
                   if enable_secure_boot else "")
        console.print(Panel.fit(
            f"[bold green]AMI Bake Complete[/bold green]\n\nAMI ID: [cyan]{ami_id}[/cyan]\n"
            f"AMI Name: [cyan]{ami_name}[/cyan]\nPlatform: [magenta]SNP-AWS (AMD SEV-SNP)[/magenta]\n"
            f"Region: [green]{region}[/green]\n"
            f"{sb_line}\nUse with deploy:\n"
            f"  [bold]tee-crafter deploy --ami-id {ami_id} --tee-platform snp-aws ...[/bold]"
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
