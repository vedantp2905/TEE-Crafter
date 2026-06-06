"""NVIDIA Confidential GPU image baking (AWS / GCP / Azure).

Each function provisions a temporary VM with an NVIDIA GPU, runs the
platform-specific setup script (NVIDIA drivers + CUDA + nv-attestation-sdk
+ CPU-TEE dependencies), then captures a golden image.  The resulting image
is passed to ``tee-crafter deploy --ami-id ... --tee-platform gpu-cc-*``.
"""

import os
import subprocess
import tempfile
import time

import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.cli.constants import console

# ---------------------------------------------------------------------------
# AWS  (gpu-cc-aws)  — P5 / P5en / P6 with NitroTPM
# ---------------------------------------------------------------------------

_GPU_CC_AWS_INSTANCE_TYPE = "p5.4xlarge"
_VALID_GPU_CC_AWS_FAMILIES = ("p5", "p5en", "p6")
_IMAGE_WAIT_DELAY_SECONDS = 15
_IMAGE_WAIT_MAX_ATTEMPTS = 240  # ~60 minutes


def bake_gpu_cc_aws_ami(
    region: str, instance_type: str | None, subnet_id: str | None,
    enclave_ram: int, enclave_cpu: int, *, use_spot: bool = False,
) -> str:
    """Bake an AWS AMI for GPU CC (NVIDIA CC + NitroTPM)."""
    import boto3
    from botocore.exceptions import ClientError
    from tee_crafter.core.remote.ssm import wait_for_ssm, run_ssm_command
    from tee_crafter.cli.commands.baking.common.helpers import (
        resolve_base_ami, get_default_subnet, get_default_subnet_in_az, get_ssm_instance_profile,
        load_setup_script,
    )

    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam", region_name=region)
    inst_type = instance_type or _GPU_CC_AWS_INSTANCE_TYPE
    family = inst_type.split(".")[0]
    if family not in _VALID_GPU_CC_AWS_FAMILIES:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] Instance type [cyan]{inst_type}[/cyan] "
            f"(family {family}) may not support NVIDIA CC + NitroTPM. "
            f"Recommended families: {', '.join(_VALID_GPU_CC_AWS_FAMILIES)}")

    console.print(Panel.fit(
        f"[bold blue]TEE-Crafter: Bake AMI (GPU CC on AWS)[/bold blue]\n\n"
        f"Region: [green]{region}[/green]\nInstance type: [cyan]{inst_type}[/cyan]\n"
        f"Platform: [magenta]GPU-CC-AWS (NVIDIA CC + NitroTPM)[/magenta]",
        border_style="blue"))

    instance_id = None
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=False) as progress:
            t = progress.add_task("[yellow]Resolving base AMI...[/yellow]", total=None)
            base_ami = resolve_base_ami(ec2, "gpu-cc-aws", region, architecture="x86_64")
            progress.update(t, description=f"[green]✓ Base AMI: {base_ami}[/green]")

            t = progress.add_task("[yellow]Ensuring IAM instance profile...[/yellow]", total=None)
            profile_name = get_ssm_instance_profile(iam)
            progress.update(t, description=f"[green]✓ Instance profile: {profile_name}[/green]")

            t = progress.add_task("[yellow]Resolving subnet...[/yellow]", total=None)
            if subnet_id:
                resolved_subnet = subnet_id
            elif region == "us-east-2":
                resolved_subnet = get_default_subnet_in_az(ec2, "us-east-2a")
            else:
                resolved_subnet = get_default_subnet(ec2)
            progress.update(t, description=f"[green]✓ Subnet: {resolved_subnet}[/green]")

            subnet_info = ec2.describe_subnets(SubnetIds=[resolved_subnet])["Subnets"][0]
            vpc_id = subnet_info["VpcId"]
            default_sg = ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                         {"Name": "group-name", "Values": ["default"]}],
            )["SecurityGroups"][0]["GroupId"]

            t = progress.add_task(
                f"[yellow]Launching temporary GPU bake instance ({inst_type})...[/yellow]", total=None)
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
                NetworkInterfaces=[{
                    "DeviceIndex": 0, "SubnetId": resolved_subnet,
                    "Groups": [default_sg], "AssociatePublicIpAddress": True,
                }],
                MetadataOptions={
                    "HttpTokens": "required", "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
                BlockDeviceMappings=[{
                    "DeviceName": "/dev/sda1",
                    "Ebs": {"VolumeSize": 100, "VolumeType": "gp3", "Encrypted": True},
                }],
                TagSpecifications=[{
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": "tee-crafter-bake-gpu-cc-aws"},
                        {"Key": "Project", "Value": "tee-crafter"},
                    ],
                }],
                UserData=user_data_script,
            )
            if use_spot:
                run_kwargs["InstanceMarketOptions"] = {
                    "MarketType": "spot",
                    "SpotOptions": {"InstanceInterruptionBehavior": "terminate"},
                }
            # Capacity on P instances can be transient. Wait up to 10 minutes for AWS to
            # allocate capacity before failing the bake.
            deadline = time.monotonic() + int(os.getenv("TEE_CRAFTER_AWS_GPU_CAPACITY_WAIT_SECONDS", "600"))
            attempt = 0
            while True:
                attempt += 1
                try:
                    resp = ec2.run_instances(**run_kwargs)
                    instance_id = resp["Instances"][0]["InstanceId"]
                    progress.update(t, description=f"[green]✓ Instance launched: {instance_id}[/green]")
                    break
                except ClientError as e:
                    code = (e.response or {}).get("Error", {}).get("Code", "")
                    if code != "InsufficientInstanceCapacity" or time.monotonic() >= deadline:
                        raise
                    sleep_s = min(20 + (attempt * 5), 60)
                    progress.update(
                        t,
                        description=(
                            f"[yellow]No capacity yet ({code}). Waiting {sleep_s}s "
                            f"(up to 10 min total)...[/yellow]"
                        ),
                    )
                    time.sleep(sleep_s)

            t = progress.add_task("[yellow]Waiting for instance to reach running state...[/yellow]", total=None)
            ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
            progress.update(t, description="[green]✓ Instance running.[/green]")

            t = progress.add_task("[yellow]Waiting for SSM agent (up to 5 min)...[/yellow]", total=None)
            if not wait_for_ssm(instance_id, region, timeout=300):
                raise click.ClickException("SSM agent did not come online within 5 minutes.")
            progress.update(t, description="[green]✓ SSM agent online.[/green]")

            t = progress.add_task(
                "[yellow]Running GPU CC setup script via SSM (15+ min)...[/yellow]", total=None)
            ok, stdout, stderr = run_ssm_command(
                instance_id, load_setup_script("gpu-cc-aws"), region, timeout=1200)
            if not ok:
                console.print(
                    f"[bold red]Setup script failed:[/bold red]\n"
                    f"{((stdout or '') + (stderr or ''))[-3000:]}")
                raise click.ClickException("GPU CC AWS setup script failed on the bake instance.")
            progress.update(t, description="[green]✓ GPU CC setup complete.[/green]")

            t = progress.add_task("[yellow]Cleaning up before AMI snapshot...[/yellow]", total=None)
            run_ssm_command(
                instance_id,
                "rm -rf /tmp/* /var/tmp/* /root/.bash_history /home/*/.bash_history; "
                "cloud-init clean --logs 2>/dev/null || true; sync",
                region, timeout=60)
            progress.update(t, description="[green]✓ Cleanup done.[/green]")

            t = progress.add_task("[yellow]Stopping instance for AMI creation...[/yellow]", total=None)
            ec2.stop_instances(InstanceIds=[instance_id])
            ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id])
            progress.update(t, description="[green]✓ Instance stopped.[/green]")

            t = progress.add_task(
                "[yellow]Creating AMI (this may take up to ~60 minutes)...[/yellow]", total=None)
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            ami_name = f"tee-crafter-gpu-cc-aws-{timestamp}"
            ami_resp = ec2.create_image(
                InstanceId=instance_id, Name=ami_name, NoReboot=True,
                Description="TEE-Crafter GPU CC AMI (NVIDIA CC + NitroTPM) with pre-baked dependencies",
                TagSpecifications=[{
                    "ResourceType": "image",
                    "Tags": [
                        {"Key": "Name", "Value": ami_name},
                        {"Key": "tee-crafter-platform", "Value": "gpu-cc-aws"},
                        {"Key": "Project", "Value": "tee-crafter"},
                        {"Key": "tee-crafter-max-enclave-ram-mib", "Value": str(enclave_ram)},
                        {"Key": "tee-crafter-max-enclave-cpu", "Value": str(enclave_cpu)},
                    ],
                }],
            )
            ami_id = ami_resp["ImageId"]
            progress.update(t, description=f"[yellow]AMI {ami_id} creation in progress...[/yellow]")
            ec2.get_waiter("image_available").wait(
                ImageIds=[ami_id],
                WaiterConfig={"Delay": _IMAGE_WAIT_DELAY_SECONDS,
                              "MaxAttempts": _IMAGE_WAIT_MAX_ATTEMPTS},
            )
            progress.update(t, description=f"[green]✓ AMI ready: {ami_id}[/green]")

            # NitroTPM can only be turned on by RegisterImage, and CreateImage
            # above cannot set it — so re-register over the snapshots it just
            # made.  Without this the AMI reports TpmSupport: null and the
            # deploy's `require_nitro_tpm` postcondition refuses it, which is
            # the correct behaviour for a non-attestable image and a dead end
            # for this platform.
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
                        "TEE-Crafter GPU CC AMI (NVIDIA CC + NitroTPM v2.0) "
                        "with pre-baked dependencies"),
                    tags=[
                        {"Key": "Name", "Value": f"{ami_name}-tpm"},
                        {"Key": "tee-crafter-platform", "Value": "gpu-cc-aws"},
                        {"Key": "Project", "Value": "tee-crafter"},
                        {"Key": "tee-crafter-nitro-tpm", "Value": "v2.0"},
                        {"Key": "tee-crafter-max-enclave-ram-mib",
                         "Value": str(enclave_ram)},
                        {"Key": "tee-crafter-max-enclave-cpu",
                         "Value": str(enclave_cpu)},
                    ],
                    waiter_delay=_IMAGE_WAIT_DELAY_SECONDS,
                    waiter_max_attempts=_IMAGE_WAIT_MAX_ATTEMPTS,
                )
            except NitroTpmAmiError as exc:
                # Keep the AMI we have rather than failing the whole bake, and
                # say exactly what the operator now cannot do with it.
                progress.update(t, description=(
                    "[yellow]! NitroTPM not enabled; AMI is not "
                    "attestable.[/yellow]"))
                console.print(
                    f"[yellow]NitroTPM could not be enabled on {ami_id}: "
                    f"{exc}\nThe image is usable, but a deploy must pass "
                    f"require_nitro_tpm=false and CPU-side attestation will be "
                    f"refused.[/yellow]")
            else:
                if tpm_ami_id != ami_id:
                    ami_id = tpm_ami_id
                    ami_name = f"{ami_name}-tpm"
                progress.update(t, description=(
                    f"[green]✓ NitroTPM v2.0 enabled: {ami_id}[/green]"))

            # Record the snapshot create-image just made.  DeregisterImage does
            # not delete it and this identity cannot list snapshots, so the id
            # is only knowable while the AMI still exists.
            from tee_crafter.cli.commands.baking.common.ebs_ledger import (
                record_backing_snapshots, retirement_hint,
            )
            _snaps = record_backing_snapshots(
                ec2, ami_id, platform="gpu-cc-aws", region=region,
                ami_name=ami_name)
            _hint = retirement_hint(ami_id, _snaps, region)

            t = progress.add_task("[yellow]Terminating bake instance...[/yellow]", total=None)
            ec2.terminate_instances(InstanceIds=[instance_id])
            instance_id = None
            progress.update(t, description="[green]✓ Instance terminated.[/green]")

        # gpu-cc-aws is NitroTPM (no SEV-SNP), so there is no launch
        # measurement to read.  What the client compares against is PCR4 and
        # PCR7 from the finished AMI, captured on a cheap probe instance --
        # those registers are properties of the boot chain and the Secure Boot
        # policy, not of the GPU, so paying for a p5 to read them would buy
        # nothing.  This used to print "self-pins at runtime", which meant in
        # practice that nothing recorded them and the client had no reference.
        from tee_crafter.cli.commands.baking.common.measurement_capture import (
            capture_nitrotpm_pcrs,
        )
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      transient=True, console=console) as progress:
            progress.add_task(
                "[yellow]Capturing NitroTPM PCRs on a probe instance...[/yellow]",
                total=None)
            _pcrs = capture_nitrotpm_pcrs(ami_id, region, platform="gpu-cc-aws")
        if not _pcrs:
            console.print(
                "[yellow]No NitroTPM PCRs recorded for this image. The client "
                "will still verify the attestation document's signature and "
                "chain, but cannot check that the boot chain is the one this "
                "bake produced.[/yellow]")

        console.print(Panel.fit(
            f"[bold green]AMI Bake Complete[/bold green]\n\nAMI ID: [cyan]{ami_id}[/cyan]\n"
            f"AMI Name: [cyan]{ami_name}[/cyan]\n"
            f"Platform: [magenta]GPU-CC-AWS (NVIDIA CC + NitroTPM)[/magenta]\n"
            f"Region: [green]{region}[/green]\n\nUse with deploy:\n"
            f"  [bold]tee-crafter deploy --ami-id {ami_id} --tee-platform gpu-cc-aws ...[/bold]"
            + (f"\n\n[yellow]{_hint}[/yellow]" if _hint else ""),
            border_style="green"))
        return ami_id
    except (KeyboardInterrupt, click.Abort):
        console.print("\n[bold yellow]Interrupted. Cleaning up...[/bold yellow]")
        if instance_id:
            try:
                ec2.terminate_instances(InstanceIds=[instance_id])
            except Exception:
                console.print(f"[red]Could not terminate {instance_id}.[/red]")
        raise click.Abort()
    except Exception as e:
        if instance_id:
            try:
                ec2.terminate_instances(InstanceIds=[instance_id])
            except Exception:
                pass
        raise click.ClickException(str(e)) if not isinstance(e, click.ClickException) else e


# ---------------------------------------------------------------------------
# GCP  (gpu-cc-gcp)  — A3 High-GPU with Intel TDX
# ---------------------------------------------------------------------------

_GPU_CC_GCP_MACHINE_TYPE = "a3-highgpu-1g"
_GCP_DEFAULT_ZONE = "us-central1-a"


def _gcloud(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["gcloud", *args, "--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise click.ClickException(f"gcloud {' '.join(args[:3])}... failed:\n{result.stderr[:1000]}")
    return result


def _get_project() -> str:
    res = subprocess.run(["gcloud", "config", "get-value", "project"],
                         capture_output=True, text=True)
    project = res.stdout.strip()
    if not project or res.returncode != 0:
        raise click.ClickException(
            "No GCP project configured. Run: gcloud config set project <PROJECT_ID>")
    return project


def bake_gpu_cc_gcp_image(
    zone: str, machine_type: str | None, enclave_ram: int, enclave_cpu: int,
    *, use_spot: bool = False,
) -> str:
    """Bake a GCP custom image for GPU CC (NVIDIA CC + Intel TDX on A3)."""
    from tee_crafter.cli.commands.baking.common.helpers import load_setup_script

    mtype = machine_type or _GPU_CC_GCP_MACHINE_TYPE
    project = _get_project()
    instance_name = f"tee-crafter-bake-gpu-cc-{int(time.time())}"

    console.print(Panel.fit(
        f"[bold blue]TEE-Crafter: Bake Image (GPU CC on GCP)[/bold blue]\n\n"
        f"Project: [green]{project}[/green]\nZone: [green]{zone}[/green]\n"
        f"Machine type: [cyan]{mtype}[/cyan]\n"
        f"Platform: [magenta]GPU-CC-GCP (NVIDIA CC + TDX)[/magenta]",
        border_style="blue"))

    ssh_key_path = None
    instance_created = False
    instance_deleted = False
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=False) as progress:
            t = progress.add_task("[yellow]Generating SSH key...[/yellow]", total=None)
            ssh_key_dir = tempfile.mkdtemp(prefix="tee_crafter_bake_gpu_cc_gcp_")
            ssh_key_path = os.path.join(ssh_key_dir, "bake_key")
            subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096",
                           "-f", ssh_key_path, "-N", ""],
                          capture_output=True, check=True)
            os.chmod(ssh_key_path, 0o600)
            with open(f"{ssh_key_path}.pub", "r") as f:
                pub_key = f.read().strip()
            progress.update(t, description="[green]✓ SSH key generated.[/green]")

            t = progress.add_task(
                f"[yellow]Creating GCP GPU CC VM ({mtype})...[/yellow]", total=None)
            create_args = [
                "compute", "instances", "create", instance_name,
                f"--project={project}", f"--zone={zone}", f"--machine-type={mtype}",
                "--image-family=ubuntu-2204-lts", "--image-project=ubuntu-os-cloud",
                "--boot-disk-size=200GB", "--boot-disk-type=pd-ssd",
                "--confidential-compute-type=TDX",
                "--maintenance-policy=TERMINATE",
                f"--metadata=ssh-keys=tee_bake:{pub_key}",
                "--shielded-secure-boot", "--shielded-vtpm",
                "--shielded-integrity-monitoring",
                "--accelerator=type=nvidia-h100-80gb,count=1",
                "--scopes=cloud-platform",
            ]
            if use_spot:
                create_args.extend(["--provisioning-model=SPOT", "--instance-termination-action=STOP"])
            _gcloud(*create_args)
            instance_created = True
            progress.update(t, description=f"[green]✓ VM created: {instance_name}[/green]")

            t = progress.add_task(
                "[yellow]Waiting for SSH via IAP (up to 5 min)...[/yellow]", total=None)
            time.sleep(30)
            from tee_crafter.core.remote.gcp_ssh import (
                IAPTunnel, wait_for_ssh, run_ssh_command, upload_file_via_scp,
            )
            with IAPTunnel(instance_name, zone, project, 22) as tunnel:
                if not wait_for_ssh(ssh_key_path, user="tee_bake", timeout=300,
                                    host="localhost", port=tunnel.local_port):
                    raise click.ClickException(
                        "SSH did not become available within 5 minutes.")
                progress.update(t, description="[green]✓ SSH available via IAP.[/green]")

                t = progress.add_task(
                    "[yellow]Running GPU CC GCP setup script (15+ min)...[/yellow]", total=None)
                setup_body = load_setup_script("gpu-cc-gcp")
                setup_filename = "setup_gpu_cc_gcp.sh"
                setup_tmp = os.path.join(ssh_key_dir, setup_filename)
                with open(setup_tmp, "w", encoding="utf-8") as f:
                    f.write(setup_body)
                scp_ok, scp_msg = upload_file_via_scp(
                    setup_tmp, f"/home/tee_bake/{setup_filename}",
                    ssh_key_path, user="tee_bake",
                    host="localhost", port=tunnel.local_port)
                if not scp_ok:
                    raise click.ClickException(f"Failed to upload setup script: {scp_msg}")
                run_ssh_command(f"chmod +x /home/tee_bake/{setup_filename}",
                                ssh_key_path, user="tee_bake",
                                host="localhost", port=tunnel.local_port)
                ok, _, stderr = run_ssh_command(
                    f"sudo /home/tee_bake/{setup_filename}",
                    ssh_key_path, user="tee_bake", timeout=1200,
                    host="localhost", port=tunnel.local_port)
                if not ok:
                    console.print(
                        f"[bold red]Setup script failed:[/bold red]\n{stderr[:2000]}")
                    raise click.ClickException("GPU CC GCP setup script failed.")
                progress.update(t, description="[green]✓ GPU CC GCP setup complete.[/green]")

                t = progress.add_task(
                    "[yellow]Cleaning up before image capture...[/yellow]", total=None)
                run_ssh_command(
                    "sudo rm -rf /tmp/* /var/tmp/* /root/.bash_history "
                    "/home/*/.bash_history; "
                    "sudo cloud-init clean --logs 2>/dev/null || true; sync",
                    ssh_key_path, user="tee_bake", timeout=60,
                    host="localhost", port=tunnel.local_port)
                progress.update(t, description="[green]✓ Cleanup done.[/green]")

            t = progress.add_task("[yellow]Stopping instance...[/yellow]", total=None)
            _gcloud("compute", "instances", "stop", instance_name,
                    f"--zone={zone}", f"--project={project}")
            progress.update(t, description="[green]✓ Instance stopped.[/green]")

            t = progress.add_task(
                "[yellow]Creating custom image (may take several minutes)...[/yellow]",
                total=None)
            timestamp = time.strftime("%Y%m%d-%H%M%S").lower()
            image_name = f"tee-crafter-gpu-cc-gcp-{timestamp}"
            _gcloud(
                "compute", "images", "create", image_name,
                f"--source-disk={instance_name}", f"--source-disk-zone={zone}",
                f"--project={project}",
                "--guest-os-features=TDX_CAPABLE,UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE,GVNIC",
                "--labels=tee-crafter-platform=gpu-cc-gcp,project=tee-crafter",
            )
            image_uri = f"projects/{project}/global/images/{image_name}"
            progress.update(t, description=f"[green]✓ Image ready: {image_name}[/green]")

            t = progress.add_task("[yellow]Deleting bake instance...[/yellow]", total=None)
            _gcloud("compute", "instances", "delete", instance_name,
                    f"--zone={zone}", f"--project={project}", "--quiet")
            instance_deleted = True
            progress.update(t, description="[green]✓ Bake instance deleted.[/green]")
            progress.add_task("[yellow]Capturing launch measurement (auto-pin)...[/yellow]", total=None)

        from tee_crafter.cli.commands.baking.common.measurement_capture import (
            capture_platform_measurements,
        )
        capture_platform_measurements(
            "gpu-cc-gcp", image_uri, zone=zone,
            min_cpu_platform="Intel Sapphire Rapids",
        )

        console.print(Panel.fit(
            f"[bold green]Image Bake Complete[/bold green]\n\n"
            f"Image: [cyan]{image_uri}[/cyan]\n"
            f"Platform: [magenta]GPU-CC-GCP (NVIDIA CC + TDX)[/magenta]\n"
            f"Zone: [green]{zone}[/green]\n\n"
            f"Use with deploy:\n  [bold]tee-crafter deploy --ami-id {image_uri} "
            f"--tee-platform gpu-cc-gcp ...[/bold]", border_style="green"))
        return image_uri
    except (KeyboardInterrupt, click.Abort):
        if instance_created and not instance_deleted:
            _gcloud("compute", "instances", "delete", instance_name,
                    f"--zone={zone}", f"--project={_get_project()}", "--quiet", check=False)
            instance_deleted = True
        raise click.Abort()
    except click.ClickException:
        if instance_created and not instance_deleted:
            _gcloud("compute", "instances", "delete", instance_name,
                    f"--zone={zone}", f"--project={_get_project()}", "--quiet", check=False)
            instance_deleted = True
        raise
    except Exception as e:
        if instance_created and not instance_deleted:
            _gcloud("compute", "instances", "delete", instance_name,
                    f"--zone={zone}", f"--project={_get_project()}", "--quiet", check=False)
            instance_deleted = True
        raise click.ClickException(str(e))
    finally:
        if ssh_key_path:
            import shutil
            shutil.rmtree(os.path.dirname(ssh_key_path), ignore_errors=True)
        if instance_created and not instance_deleted:
            try:
                console.print(
                    f"[yellow]Cleanup: deleting bake instance {instance_name}...[/yellow]")
                _gcloud("compute", "instances", "delete", instance_name,
                        f"--zone={zone}", f"--project={project}", "--quiet", check=False)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Azure  (gpu-cc-azure)  — NCC H100 v5 with AMD SEV-SNP
# ---------------------------------------------------------------------------

_GPU_CC_AZURE_VM_SIZE = "Standard_NCC40ads_H100_v5"
# Ephemeral bake resources: the resource group below is deleted when the bake
# finishes, so a fixed name meant two concurrent bakes of this platform shared
# one group and whichever finished first deleted the other's live VM.  These are
# name *prefixes*; ``bake_run_suffix()`` appends a per-run token in the bake
# function.  The persistent images RG / gallery / image definition stay fixed —
# they are the shared destination every bake publishes into.
_GPU_CC_AZURE_BAKE_RG_PREFIX = "tee-crafter-bake-gpu-cc-rg"
_GPU_CC_AZURE_IMAGES_RESOURCE_GROUP = "tee-crafter-images-gpu-cc-rg"
_GPU_CC_AZURE_VM_NAME_PREFIX = "tee-crafter-bake-gpu-cc-vm"
_GPU_CC_AZURE_GALLERY_NAME = "tee_crafter_gpu_cc_gallery"
_GPU_CC_AZURE_GALLERY_IMAGE_DEFINITION = "tee_crafter_gpu_cc_ubuntu"
_GPU_CC_AZURE_VHD_STORAGE_ACCOUNT = "teecraftergpuccvhd"
_GPU_CC_AZURE_VHD_CONTAINER = "vhds"
_VALID_GPU_CC_AZURE_PREFIXES = ("Standard_NCC",)


def bake_gpu_cc_azure_image(
    location: str, vm_size: str | None, enclave_ram: int, enclave_cpu: int,
    *, use_spot: bool = False,
) -> str:
    """Bake an Azure VM Image for GPU CC (NVIDIA CC + AMD SEV-SNP on NCC H100 v5)."""
    from tee_crafter.cli.commands.baking.common.helpers import (
        az_cli, bake_run_suffix, create_azure_cvm,
    )
    from tee_crafter.cli.commands.baking.common.azure_gallery import capture_vhd_to_gallery

    size = vm_size or _GPU_CC_AZURE_VM_SIZE
    if not any(size.startswith(p) for p in _VALID_GPU_CC_AZURE_PREFIXES):
        console.print(
            f"[bold yellow]Warning:[/bold yellow] VM size [cyan]{size}[/cyan] may not have "
            "NVIDIA CC + SEV-SNP support. Azure NCC H100 v5 series recommended.")

    console.print(Panel.fit(
        f"[bold blue]TEE-Crafter: Bake Image (GPU CC on Azure)[/bold blue]\n\n"
        f"Location: [green]{location}[/green]\nVM size: [cyan]{size}[/cyan]\n"
        f"Platform: [magenta]GPU-CC-AZURE (NVIDIA CC + SEV-SNP)[/magenta]",
        border_style="blue"))

    # Per-run names for the throwaway bake resource group + VM so two bakes of
    # this platform can run at once without one's `az group delete` taking out
    # the other's VM.
    run_suffix = bake_run_suffix()
    bake_rg = f"{_GPU_CC_AZURE_BAKE_RG_PREFIX}-{run_suffix}"
    vm_name = f"{_GPU_CC_AZURE_VM_NAME_PREFIX}-{run_suffix}"
    ssh_key_path = None
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=False) as progress:
            t = progress.add_task(
                "[yellow]Ensuring persistent images resource group...[/yellow]", total=None)
            az_cli("group", "create", "--name", _GPU_CC_AZURE_IMAGES_RESOURCE_GROUP,
                   "--location", location)
            progress.update(
                t, description=f"[green]✓ Images RG: {_GPU_CC_AZURE_IMAGES_RESOURCE_GROUP}[/green]")

            t = progress.add_task(
                "[yellow]Creating temporary bake resource group...[/yellow]", total=None)
            for _attempt in range(18):
                rg_res = az_cli("group", "create", "--name", bake_rg,
                                "--location", location, check=False)
                if rg_res.returncode == 0:
                    break
                if "ResourceGroupBeingDeleted" in rg_res.stderr:
                    progress.update(
                        t, description="[yellow]Waiting for previous bake RG deletion...[/yellow]")
                    time.sleep(10)
                    continue
                raise click.ClickException(
                    f"az group create failed:\n{rg_res.stderr[:1000]}")
            else:
                raise click.ClickException(
                    f"Resource group {bake_rg} stuck in deprovisioning.")
            progress.update(
                t, description=f"[green]✓ Bake RG: {bake_rg}[/green]")

            t = progress.add_task("[yellow]Generating SSH key...[/yellow]", total=None)
            ssh_key_dir = tempfile.mkdtemp(prefix="tee_crafter_bake_gpu_cc_")
            ssh_key_path = os.path.join(ssh_key_dir, "bake_key")
            subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096",
                           "-f", ssh_key_path, "-N", ""],
                          capture_output=True, check=True)
            os.chmod(ssh_key_path, 0o600)
            progress.update(t, description="[green]✓ SSH key generated.[/green]")

            t = progress.add_task(
                f"[yellow]Creating Azure GPU CC VM ({size})...[/yellow]", total=None)
            # Secure Boot must be OFF for GPU CC Azure. Azure NCC H100 v5 VMs
            # expose the GPU with PCI ID 10de:2321 (GA103), which is NOT supported
            # by any pre-built signed kernel module. Only the DKMS-compiled
            # nvidia-headless-550-open module can initialize this device.
            public_ip = create_azure_cvm(
                progress, t,
                resource_group=bake_rg,
                vm_name=vm_name, location=location, size=size,
                ssh_pub_key=f"{ssh_key_path}.pub", platform_label="gpu-cc-azure",
                use_spot=use_spot, secure_boot=False)
            progress.update(
                t, description=f"[green]✓ GPU CC VM created. Public IP: {public_ip}[/green]")

            _run_gpu_cc_azure_setup_and_deprovision(
                progress, ssh_key_path, ssh_key_dir, public_ip, location)

            t = progress.add_task("[yellow]Deallocating VM...[/yellow]", total=None)
            az_cli("vm", "deallocate",
                   "--resource-group", bake_rg,
                   "--name", vm_name)
            progress.update(t, description="[green]✓ VM deallocated.[/green]")

            t = progress.add_task("[yellow]Generalizing VM...[/yellow]", total=None)
            az_cli("vm", "generalize",
                   "--resource-group", bake_rg,
                   "--name", vm_name)
            progress.update(t, description="[green]✓ VM generalized.[/green]")

            image_id, image_name = capture_vhd_to_gallery(
                progress, az_cli,
                bake_rg=bake_rg,
                images_rg=_GPU_CC_AZURE_IMAGES_RESOURCE_GROUP,
                vm_name=vm_name, location=location,
                gallery_name=_GPU_CC_AZURE_GALLERY_NAME,
                image_def=_GPU_CC_AZURE_GALLERY_IMAGE_DEFINITION,
                storage_acct=_GPU_CC_AZURE_VHD_STORAGE_ACCOUNT,
                storage_env_var="TEE_CRAFTER_GPU_CC_STORAGE_ACCOUNT",
                vhd_container=_GPU_CC_AZURE_VHD_CONTAINER,
                blob_prefix="tee-crafter-gpu-cc-azure-",
                publisher="tee-crafter", offer="gpu-cc", sku="22-04",
                run_suffix=run_suffix)

            t = progress.add_task(
                "[yellow]Deleting temporary bake resources...[/yellow]", total=None)
            az_cli("group", "delete", "--name", bake_rg,
                   "--yes", "--no-wait", check=False)
            progress.update(t, description="[green]✓ Bake resources cleanup initiated.[/green]")
            progress.add_task("[yellow]Capturing launch measurement (auto-pin)...[/yellow]", total=None)

        from tee_crafter.cli.commands.baking.common.measurement_capture import (
            capture_platform_measurements,
        )
        capture_platform_measurements("gpu-cc-azure", image_id, location=location)

        console.print(Panel.fit(
            f"[bold green]Image Bake Complete[/bold green]\n\n"
            f"Image ID: [cyan]{image_id}[/cyan]\nImage Name: [cyan]{image_name}[/cyan]\n"
            f"Resource Group: [cyan]{_GPU_CC_AZURE_IMAGES_RESOURCE_GROUP}[/cyan]\n"
            f"Platform: [magenta]GPU-CC-Azure (NVIDIA CC + SEV-SNP)[/magenta]\n"
            f"Location: [green]{location}[/green]\n\n"
            f"Use with deploy:\n  [bold]tee-crafter deploy --ami-id {image_id} "
            f"--tee-platform gpu-cc-azure ...[/bold]",
            border_style="green"))
        return image_id
    except (KeyboardInterrupt, click.Abort):
        console.print(
            "\n[bold yellow]Interrupted. Cleaning up Azure bake resources...[/bold yellow]")
        az_cli("group", "delete", "--name", bake_rg,
               "--yes", "--no-wait", check=False)
        raise click.Abort()
    except click.ClickException:
        az_cli("group", "delete", "--name", bake_rg,
               "--yes", "--no-wait", check=False)
        raise
    except Exception as e:
        az_cli("group", "delete", "--name", bake_rg,
               "--yes", "--no-wait", check=False)
        raise click.ClickException(str(e))
    finally:
        if ssh_key_path:
            import shutil
            shutil.rmtree(os.path.dirname(ssh_key_path), ignore_errors=True)


def _run_gpu_cc_azure_setup_and_deprovision(
    progress, ssh_key_path, ssh_key_dir, public_ip, location,
):
    """Run GPU CC setup script, diagnostics, and deprovision on the Azure bake VM."""
    from tee_crafter.core.remote.azure_ssh import (
        wait_for_ssh, run_ssh_command, upload_file_via_scp,
    )
    from tee_crafter.cli.commands.baking.common.helpers import load_setup_script

    t = progress.add_task("[yellow]Waiting for SSH (up to 3 min)...[/yellow]", total=None)
    if not wait_for_ssh(ssh_key_path, timeout=180, host=public_ip):
        raise click.ClickException("SSH did not become available within 3 minutes.")
    progress.update(t, description="[green]✓ SSH available.[/green]")

    t = progress.add_task(
        "[yellow]Running GPU CC Azure setup script via SSH (15+ min)...[/yellow]", total=None)
    setup_tmp = os.path.join(ssh_key_dir, "setup_gpu_cc_azure.sh")
    with open(setup_tmp, "w", encoding="utf-8") as f:
        f.write(load_setup_script("gpu-cc-azure"))
    scp_ok, scp_msg = upload_file_via_scp(
        setup_tmp, "/home/azureuser/setup_gpu_cc_azure.sh",
        ssh_key_path, host=public_ip)
    if not scp_ok:
        raise click.ClickException(f"Failed to upload setup script: {scp_msg}")
    run_ssh_command("chmod +x /home/azureuser/setup_gpu_cc_azure.sh",
                    ssh_key_path, host=public_ip)
    ok, stdout, stderr = run_ssh_command(
        "sudo /home/azureuser/setup_gpu_cc_azure.sh",
        ssh_key_path, timeout=7200, host=public_ip)
    if not ok:
        combined = (stderr or "") + ("\n--- stdout ---\n" + (stdout or ""))[:4000]
        console.print(f"[bold red]Setup script failed:[/bold red]\n{combined[:8000]}")
        raise click.ClickException("GPU CC Azure setup script failed on the bake VM.")
    progress.update(t, description="[green]✓ GPU CC Azure setup complete.[/green]")

    t = progress.add_task(
        "[yellow]Deprovisioning VM for image capture...[/yellow]", total=None)
    ok, out, err = run_ssh_command(
        "sudo rm -rf /tmp/* /var/tmp/* /root/.bash_history /home/*/.bash_history; "
        "sudo cloud-init clean --logs 2>/dev/null || true; sync; "
        "sudo waagent -deprovision+user -force; sync",
        ssh_key_path, timeout=120, host=public_ip)
    if not ok:
        err_lower = (err or "").lower()
        if any(s in err_lower for s in ("connection closed", "closed by remote", "broken pipe")):
            progress.update(
                t, description="[green]✓ VM deprovisioned (session closed by waagent).[/green]")
        else:
            raise click.ClickException(
                f"Deprovision failed: {(err or out or 'unknown')[:500]}")
    else:
        progress.update(t, description="[green]✓ VM deprovisioned.[/green]")
