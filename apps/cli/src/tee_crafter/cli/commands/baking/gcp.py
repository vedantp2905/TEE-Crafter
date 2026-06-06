"""GCP Confidential VM image baking (AMD SEV-SNP + Intel TDX)."""
import os
import subprocess
import tempfile
import time

import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.cli.constants import console

_SNP_GCP_MACHINE_TYPE = "n2d-standard-2"
_TDX_GCP_MACHINE_TYPE = "c3-standard-4"
_GCP_DEFAULT_ZONE = "us-central1-a"


def _gcloud(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["gcloud", *args, "--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise click.ClickException(f"gcloud {' '.join(args[:3])}... failed:\n{result.stderr[:1000]}")
    return result


def _get_project() -> str:
    res = subprocess.run(["gcloud", "config", "get-value", "project"], capture_output=True, text=True)
    project = res.stdout.strip()
    if not project or res.returncode != 0:
        raise click.ClickException("No GCP project configured. Run: gcloud config set project <PROJECT_ID>")
    return project


def _load_gcp_setup_script(platform: str) -> str:
    from tee_crafter.cli.loaders import _inject_security_profiles, _inject_systemd_units

    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts")
    if platform == "snp-gcp":
        path = os.path.join(script_dir, "snp_gcp", "setup_snp_gcp.sh")
    elif platform == "tdx-gcp":
        path = os.path.join(script_dir, "tdx_gcp", "setup_tdx_gcp.sh")
    else:
        raise click.ClickException(f"Unknown GCP bake platform: {platform}")
    with open(path, "r", encoding="utf-8") as f:
        content = _inject_security_profiles(f.read())
    return _inject_systemd_units(content, platform)


def _bake_gcp_image(
    zone: str, machine_type: str, instance_name: str, platform: str,
    confidential_type: str, min_cpu_platform: str | None,
    guest_os_features: str, label_platform: str, platform_display: str,
    *, use_spot: bool = False,
) -> str:
    """Generic GCP CVM image bake workflow."""
    project = _get_project()
    console.print(Panel.fit(
        f"[bold blue]TEE-Crafter: Bake Image ({platform_display})[/bold blue]\n\n"
        f"Project: [green]{project}[/green]\nZone: [green]{zone}[/green]\n"
        f"Machine type: [cyan]{machine_type}[/cyan]\nPlatform: [magenta]{label_platform.upper()}[/magenta]",
        border_style="blue"))
    ssh_key_path = None
    instance_created = False
    instance_deleted = False
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=False) as progress:
            t = progress.add_task("[yellow]Generating SSH key...[/yellow]", total=None)
            ssh_key_dir = tempfile.mkdtemp(prefix=f"tee_crafter_bake_{label_platform.replace('-', '_')}_")
            ssh_key_path = os.path.join(ssh_key_dir, "bake_key")
            subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", ssh_key_path, "-N", ""],
                          capture_output=True, check=True)
            os.chmod(ssh_key_path, 0o600)
            with open(f"{ssh_key_path}.pub", "r") as f:
                pub_key = f.read().strip()
            progress.update(t, description="[green]✓ SSH key generated.[/green]")
            t = progress.add_task(f"[yellow]Creating GCP {platform_display} VM ({machine_type})...[/yellow]", total=None)
            create_args = [
                "compute", "instances", "create", instance_name,
                f"--project={project}", f"--zone={zone}", f"--machine-type={machine_type}",
                "--image-family=ubuntu-2204-lts", "--image-project=ubuntu-os-cloud",
                "--boot-disk-size=30GB", "--boot-disk-type=pd-ssd",
                f"--confidential-compute-type={confidential_type}",
                "--maintenance-policy=TERMINATE",
                # Bake needs outbound internet access for `apt-get update` in setup scripts.
                # If the project doesn't have Cloud NAT configured, a private-only VM will fail with
                # "Network is unreachable". Allow ephemeral public egress during bake.
                f"--metadata=ssh-keys=tee_bake:{pub_key}",
                "--shielded-secure-boot", "--shielded-vtpm", "--shielded-integrity-monitoring",
                "--scopes=cloud-platform",
            ]
            if use_spot:
                create_args.extend(["--provisioning-model=SPOT", "--instance-termination-action=STOP"])
            if min_cpu_platform:
                create_args.append(f"--min-cpu-platform={min_cpu_platform}")
            _gcloud(*create_args)
            instance_created = True
            progress.update(t, description=f"[green]✓ VM created: {instance_name}[/green]")
            t = progress.add_task("[yellow]Waiting for SSH via IAP (up to 5 min)...[/yellow]", total=None)
            time.sleep(30)
            from tee_crafter.core.remote.gcp_ssh import IAPTunnel, wait_for_ssh, run_ssh_command, upload_file_via_scp
            with IAPTunnel(instance_name, zone, project, 22) as tunnel:
                if not wait_for_ssh(ssh_key_path, user="tee_bake", timeout=300,
                                    host="localhost", port=tunnel.local_port):
                    raise click.ClickException("SSH did not become available within 5 minutes.")
                progress.update(t, description="[green]✓ SSH available via IAP.[/green]")
                t = progress.add_task(f"[yellow]Running {label_platform} setup script...[/yellow]", total=None)
                setup_body = _load_gcp_setup_script(label_platform)
                setup_filename = f"setup_{label_platform.replace('-', '_')}.sh"
                setup_tmp = os.path.join(ssh_key_dir, setup_filename)
                with open(setup_tmp, "w", encoding="utf-8") as f:
                    f.write(setup_body)
                scp_ok, scp_msg = upload_file_via_scp(setup_tmp, f"/home/tee_bake/{setup_filename}",
                                                      ssh_key_path, user="tee_bake",
                                                      host="localhost", port=tunnel.local_port)
                if not scp_ok:
                    raise click.ClickException(f"Failed to upload setup script: {scp_msg}")
                run_ssh_command(f"chmod +x /home/tee_bake/{setup_filename}", ssh_key_path,
                                user="tee_bake", host="localhost", port=tunnel.local_port)
                ok, _, stderr = run_ssh_command(f"sudo /home/tee_bake/{setup_filename}", ssh_key_path,
                                                user="tee_bake", timeout=900,
                                                host="localhost", port=tunnel.local_port)
                if not ok:
                    console.print(f"[bold red]Setup script failed:[/bold red]\n{stderr[:2000]}")
                    raise click.ClickException(f"{platform_display} setup script failed.")
                progress.update(t, description=f"[green]✓ {platform_display} setup complete.[/green]")
                t = progress.add_task("[yellow]Cleaning up before image capture...[/yellow]", total=None)
                run_ssh_command(
                    "sudo rm -rf /tmp/* /var/tmp/* /root/.bash_history /home/*/.bash_history; "
                    "sudo cloud-init clean --logs 2>/dev/null || true; sync",
                    ssh_key_path, user="tee_bake", timeout=60,
                    host="localhost", port=tunnel.local_port)
                progress.update(t, description="[green]✓ Cleanup done.[/green]")
            t = progress.add_task("[yellow]Stopping instance...[/yellow]", total=None)
            _gcloud("compute", "instances", "stop", instance_name, f"--zone={zone}", f"--project={project}")
            progress.update(t, description="[green]✓ Instance stopped.[/green]")
            t = progress.add_task("[yellow]Creating custom image (may take several minutes)...[/yellow]", total=None)
            timestamp = time.strftime("%Y%m%d-%H%M%S").lower()
            image_name = f"tee-crafter-{label_platform}-{timestamp}"
            _gcloud("compute", "images", "create", image_name,
                    f"--source-disk={instance_name}", f"--source-disk-zone={zone}", f"--project={project}",
                    f"--guest-os-features={guest_os_features}",
                    f"--labels=tee-crafter-platform={label_platform},project=tee-crafter")
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
            label_platform, image_uri, zone=zone,
            confidential_type=confidential_type,
            min_cpu_platform=min_cpu_platform,
        )
        console.print(Panel.fit(
            f"[bold green]Image Bake Complete[/bold green]\n\nImage: [cyan]{image_uri}[/cyan]\n"
            f"Platform: [magenta]{platform_display}[/magenta]\nZone: [green]{zone}[/green]\n\n"
            f"Use with deploy:\n  [bold]tee-crafter deploy --ami-id {image_uri} "
            f"--tee-platform {label_platform} ...[/bold]", border_style="green"))
        return image_uri
    except (KeyboardInterrupt, click.Abort):
        _gcloud("compute", "instances", "delete", instance_name,
                f"--zone={zone}", f"--project={_get_project()}", "--quiet", check=False)
        instance_deleted = True
        raise click.Abort()
    except click.ClickException:
        _gcloud("compute", "instances", "delete", instance_name,
                f"--zone={zone}", f"--project={_get_project()}", "--quiet", check=False)
        instance_deleted = True
        raise
    except Exception as e:
        _gcloud("compute", "instances", "delete", instance_name,
                f"--zone={zone}", f"--project={_get_project()}", "--quiet", check=False)
        instance_deleted = True
        raise click.ClickException(str(e))
    finally:
        if ssh_key_path:
            import shutil
            shutil.rmtree(os.path.dirname(ssh_key_path), ignore_errors=True)
        # Best-effort teardown on any unexpected failure.
        # Some failures happen before we reach the explicit "delete instance" step.
        if instance_created and not instance_deleted:
            try:
                console.print(f"[yellow]Cleanup: deleting bake instance {instance_name}...[/yellow]")
                _gcloud(
                    "compute", "instances", "delete", instance_name,
                    f"--zone={zone}", f"--project={project}", "--quiet", check=False
                )
                instance_deleted = True
            except Exception:
                pass


def bake_snp_gcp_image(zone: str, machine_type: str | None, enclave_ram: int, enclave_cpu: int, *, use_spot: bool = False) -> str:
    """Bake a GCP custom image with AMD SEV-SNP dependencies pre-installed."""
    return _bake_gcp_image(
        zone=zone, machine_type=machine_type or _SNP_GCP_MACHINE_TYPE,
        instance_name=f"tee-crafter-bake-snp-{int(time.time())}",
        platform="SNP-GCP", confidential_type="SEV_SNP", min_cpu_platform="AMD Milan",
        guest_os_features="SEV_SNP_CAPABLE,UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE,GVNIC",
        label_platform="snp-gcp", platform_display="AMD SEV-SNP on GCP",
        use_spot=use_spot)


def bake_tdx_gcp_image(zone: str, machine_type: str | None, enclave_ram: int, enclave_cpu: int, *, use_spot: bool = False) -> str:
    """Bake a GCP custom image with Intel TDX dependencies pre-installed."""
    return _bake_gcp_image(
        zone=zone, machine_type=machine_type or _TDX_GCP_MACHINE_TYPE,
        instance_name=f"tee-crafter-bake-tdx-{int(time.time())}",
        # TDX-5 / SUP-X: pin the bake VM to Sapphire-Rapids-or-newer for the
        # same reason the runtime Terraform does — Confidential VM TDX is only
        # supported on SPR (TDX 1.0/1.5) and EMR (TDX 1.5+) C3 hosts; without
        # the floor the bake can silently land on a non-TDX host and produce
        # an image whose drivers were never exercised under TDX.
        platform="TDX-GCP", confidential_type="TDX", min_cpu_platform="Intel Sapphire Rapids",
        guest_os_features="TDX_CAPABLE,UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE,GVNIC",
        label_platform="tdx-gcp", platform_display="Intel TDX on GCP",
        use_spot=use_spot)
