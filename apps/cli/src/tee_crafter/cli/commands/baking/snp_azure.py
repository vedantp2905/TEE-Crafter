"""AMD SEV-SNP Azure image baking."""
import os
import subprocess
import tempfile
import time

import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.cli.constants import console
from tee_crafter.cli.commands.baking.common.helpers import (
    az_cli, bake_run_suffix, create_azure_cvm, load_setup_script,
)
from tee_crafter.cli.commands.baking.common.azure_gallery import capture_vhd_to_gallery

_SNP_AZURE_VM_SIZE = "Standard_DC2as_v5"
_SNP_AZURE_LOCATION = "westus"
# Ephemeral bake resources: the resource group below is deleted when the bake
# finishes, so a fixed name meant two concurrent bakes of this platform shared
# one group and whichever finished first deleted the other's live VM.  These are
# name *prefixes*; ``bake_run_suffix()`` appends a per-run token in the bake
# function.  The persistent images RG / gallery / image definition stay fixed —
# they are the shared destination every bake publishes into.
_SNP_AZURE_BAKE_RG_PREFIX = "tee-crafter-bake-snp-rg"
_SNP_AZURE_IMAGES_RESOURCE_GROUP = "tee-crafter-images-snp-rg"
_SNP_AZURE_VM_NAME_PREFIX = "tee-crafter-bake-snp-vm"
_SNP_AZURE_GALLERY_NAME = "tee_crafter_snp_gallery"
_SNP_AZURE_GALLERY_IMAGE_DEFINITION = "tee_crafter_snp_ubuntu"
_SNP_AZURE_VHD_STORAGE_ACCOUNT = "teecraftersnpvhd"
_SNP_AZURE_VHD_CONTAINER = "vhds"
_VALID_SNP_AZURE_PREFIXES = ("Standard_DC", "Standard_EC")


def bake_snp_azure_image(
    location: str, vm_size: str | None, enclave_ram: int, enclave_cpu: int,
    *, use_spot: bool = False,
) -> str:
    """Bake an Azure VM Image with AMD SEV-SNP dependencies pre-installed."""
    size = vm_size or _SNP_AZURE_VM_SIZE
    if not any(size.startswith(p) for p in _VALID_SNP_AZURE_PREFIXES):
        console.print(
            f"[bold yellow]Warning:[/bold yellow] VM size [cyan]{size}[/cyan] may not have SEV-SNP support. "
            "Azure DCasv5/ECasv5 or DCadsv5/ECadsv5 series recommended.")
    console.print(Panel.fit(
        f"[bold blue]TEE-Crafter: Bake Image (AMD SEV-SNP on Azure)[/bold blue]\n\n"
        f"Location: [green]{location}[/green]\nVM size: [cyan]{size}[/cyan]\n"
        f"Platform: [magenta]SNP-AZURE[/magenta]", border_style="blue"))
    # Per-run names for the throwaway bake resource group + VM so two bakes of
    # this platform can run at once without one's `az group delete` taking out
    # the other's VM.
    run_suffix = bake_run_suffix()
    bake_rg = f"{_SNP_AZURE_BAKE_RG_PREFIX}-{run_suffix}"
    vm_name = f"{_SNP_AZURE_VM_NAME_PREFIX}-{run_suffix}"
    ssh_key_path = None
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=False) as progress:
            t = progress.add_task("[yellow]Ensuring persistent images resource group...[/yellow]", total=None)
            az_cli("group", "create", "--name", _SNP_AZURE_IMAGES_RESOURCE_GROUP, "--location", location)
            progress.update(t, description=f"[green]✓ Images RG: {_SNP_AZURE_IMAGES_RESOURCE_GROUP}[/green]")
            t = progress.add_task("[yellow]Creating temporary bake resource group...[/yellow]", total=None)
            for _attempt in range(18):
                rg_res = az_cli("group", "create", "--name", bake_rg,
                                "--location", location, check=False)
                if rg_res.returncode == 0:
                    break
                if "ResourceGroupBeingDeleted" in rg_res.stderr:
                    progress.update(t, description="[yellow]Waiting for previous bake RG deletion...[/yellow]")
                    time.sleep(10)
                    continue
                raise click.ClickException(f"az group create failed:\n{rg_res.stderr[:1000]}")
            else:
                raise click.ClickException(f"Resource group {bake_rg} stuck in deprovisioning.")
            progress.update(t, description=f"[green]✓ Bake RG: {bake_rg}[/green]")
            t = progress.add_task("[yellow]Generating SSH key...[/yellow]", total=None)
            ssh_key_dir = tempfile.mkdtemp(prefix="tee_crafter_bake_snp_")
            ssh_key_path = os.path.join(ssh_key_dir, "bake_key")
            subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", ssh_key_path, "-N", ""],
                          capture_output=True, check=True)
            os.chmod(ssh_key_path, 0o600)
            progress.update(t, description="[green]✓ SSH key generated.[/green]")
            t = progress.add_task(f"[yellow]Creating Azure SNP VM ({size})...[/yellow]", total=None)
            public_ip = create_azure_cvm(progress, t, resource_group=bake_rg,
                                         vm_name=vm_name, location=location, size=size,
                                         ssh_pub_key=f"{ssh_key_path}.pub", platform_label="snp-azure",
                                         use_spot=use_spot)
            progress.update(t, description=f"[green]✓ SNP VM created. Public IP: {public_ip}[/green]")
            _run_setup_and_deprovision(progress, ssh_key_path, ssh_key_dir, public_ip, location)
            t = progress.add_task("[yellow]Deallocating VM...[/yellow]", total=None)
            az_cli("vm", "deallocate", "--resource-group", bake_rg,
                   "--name", vm_name)
            progress.update(t, description="[green]✓ VM deallocated.[/green]")
            t = progress.add_task("[yellow]Generalizing VM...[/yellow]", total=None)
            az_cli("vm", "generalize", "--resource-group", bake_rg,
                   "--name", vm_name)
            progress.update(t, description="[green]✓ VM generalized.[/green]")
            image_id, image_name = capture_vhd_to_gallery(
                progress, az_cli, bake_rg=bake_rg,
                images_rg=_SNP_AZURE_IMAGES_RESOURCE_GROUP, vm_name=vm_name,
                location=location, gallery_name=_SNP_AZURE_GALLERY_NAME,
                image_def=_SNP_AZURE_GALLERY_IMAGE_DEFINITION,
                storage_acct=_SNP_AZURE_VHD_STORAGE_ACCOUNT,
                storage_env_var="TEE_CRAFTER_SNP_STORAGE_ACCOUNT",
                vhd_container=_SNP_AZURE_VHD_CONTAINER,
                blob_prefix="tee-crafter-snp-azure-",
                publisher="tee-crafter", offer="snp", sku="22-04",
                run_suffix=run_suffix)
            t = progress.add_task("[yellow]Deleting temporary bake resources...[/yellow]", total=None)
            az_cli("group", "delete", "--name", bake_rg,
                   "--yes", "--no-wait", check=False)
            progress.update(t, description="[green]✓ Bake resources cleanup initiated.[/green]")
            progress.add_task("[yellow]Capturing launch measurement (auto-pin)...[/yellow]", total=None)
        from tee_crafter.cli.commands.baking.common.measurement_capture import (
            capture_platform_measurements,
        )
        capture_platform_measurements("snp-azure", image_id, location=location)
        console.print(Panel.fit(
            f"[bold green]Image Bake Complete[/bold green]\n\n"
            f"Image ID: [cyan]{image_id}[/cyan]\nImage Name: [cyan]{image_name}[/cyan]\n"
            f"Resource Group: [cyan]{_SNP_AZURE_IMAGES_RESOURCE_GROUP}[/cyan]\n"
            f"Platform: [magenta]SNP-Azure (AMD SEV-SNP)[/magenta]\nLocation: [green]{location}[/green]\n\n"
            f"Use with deploy:\n  [bold]tee-crafter deploy --ami-id {image_id} --tee-platform snp-azure ...[/bold]",
            border_style="green"))
        return image_id
    except (KeyboardInterrupt, click.Abort):
        console.print("\n[bold yellow]Interrupted. Cleaning up Azure bake resources...[/bold yellow]")
        az_cli("group", "delete", "--name", bake_rg, "--yes", "--no-wait", check=False)
        raise click.Abort()
    except click.ClickException:
        az_cli("group", "delete", "--name", bake_rg, "--yes", "--no-wait", check=False)
        raise
    except Exception as e:
        az_cli("group", "delete", "--name", bake_rg, "--yes", "--no-wait", check=False)
        raise click.ClickException(str(e))
    finally:
        if ssh_key_path:
            import shutil
            shutil.rmtree(os.path.dirname(ssh_key_path), ignore_errors=True)


def _run_setup_and_deprovision(progress, ssh_key_path, ssh_key_dir, public_ip, location):
    """Run setup script, diagnostics, and deprovision on the bake VM."""
    from tee_crafter.core.remote.azure_ssh import wait_for_ssh, run_ssh_command, upload_file_via_scp
    t = progress.add_task("[yellow]Waiting for SSH (up to 3 min)...[/yellow]", total=None)
    if not wait_for_ssh(ssh_key_path, timeout=180, host=public_ip):
        raise click.ClickException("SSH did not become available within 3 minutes.")
    progress.update(t, description="[green]✓ SSH available.[/green]")
    t = progress.add_task("[yellow]Running SNP setup script via SSH (10+ min)...[/yellow]", total=None)
    setup_tmp = os.path.join(ssh_key_dir, "setup_snp_azure.sh")
    with open(setup_tmp, "w", encoding="utf-8") as f:
        f.write(load_setup_script("snp-azure"))
    scp_ok, scp_msg = upload_file_via_scp(setup_tmp, "/home/azureuser/setup_snp_azure.sh",
                                          ssh_key_path, host=public_ip)
    if not scp_ok:
        raise click.ClickException(f"Failed to upload setup script: {scp_msg}")
    run_ssh_command("chmod +x /home/azureuser/setup_snp_azure.sh", ssh_key_path, host=public_ip)
    ok, stdout, stderr = run_ssh_command("sudo /home/azureuser/setup_snp_azure.sh",
                                         ssh_key_path, timeout=900, host=public_ip)
    if not ok:
        console.print(f"[bold red]Setup script failed:[/bold red]\n{stderr[:2000]}")
        raise click.ClickException("SNP Azure setup script failed on the bake VM.")
    progress.update(t, description="[green]✓ SNP setup complete.[/green]")
    t = progress.add_task("[yellow]Deprovisioning VM for image capture...[/yellow]", total=None)
    ok, out, err = run_ssh_command(
        "sudo rm -rf /tmp/* /var/tmp/* /root/.bash_history /home/*/.bash_history; "
        "sudo cloud-init clean --logs 2>/dev/null || true; sync; "
        "sudo waagent -deprovision+user -force; sync",
        ssh_key_path, timeout=120, host=public_ip)
    if not ok:
        err_lower = (err or "").lower()
        if any(s in err_lower for s in ("connection closed", "closed by remote", "broken pipe")):
            progress.update(t, description="[green]✓ VM deprovisioned (session closed by waagent).[/green]")
        else:
            raise click.ClickException(f"Deprovision failed: {(err or out or 'unknown')[:500]}")
    else:
        progress.update(t, description="[green]✓ VM deprovisioned.[/green]")
