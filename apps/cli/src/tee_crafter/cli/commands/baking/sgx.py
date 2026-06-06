"""SGX (Azure) image baking."""
import os
import tempfile
import time

import click
from tee_crafter.cli.constants import Panel
from tee_crafter.cli.constants import Progress, SpinnerColumn, TextColumn

from tee_crafter.cli.constants import console
from tee_crafter.cli.commands.baking.common.helpers import (
    az_cli, bake_run_suffix, load_setup_script,
)
from tee_crafter.cli.commands.baking.common.azure_gallery import capture_vhd_to_gallery

_SGX_VM_SIZE = "Standard_DC2s_v3"
_SGX_AZURE_LOCATION = "westus"
# Ephemeral bake resources: the resource group below is deleted when the bake
# finishes, so a fixed name meant two concurrent bakes of this platform shared
# one group and whichever finished first deleted the other's live VM.  These are
# name *prefixes*; ``bake_run_suffix()`` appends a per-run token in the bake
# function.  The persistent images RG / gallery / image definition stay fixed —
# they are the shared destination every bake publishes into.
_SGX_BAKE_RG_PREFIX = "tee-crafter-bake-sgx-rg"
_SGX_IMAGES_RESOURCE_GROUP = "tee-crafter-images-sgx-rg"
_SGX_VM_NAME_PREFIX = "tee-crafter-bake-sgx-vm"
# Trusted Launch VMs cannot be captured to a managed image — we have to
# go through an Azure Compute Gallery image version (see
# capture_vhd_to_gallery's docstring).  Names mirror TDX/SNP-Azure.
_SGX_GALLERY_NAME = "tee_crafter_sgx_gallery"
_SGX_GALLERY_IMAGE_DEFINITION = "tee_crafter_sgx_ubuntu"
_SGX_VHD_STORAGE_ACCOUNT = "teecraftersgxvhd"
_SGX_VHD_CONTAINER = "vhds"
DEFAULT_LOCATION = _SGX_AZURE_LOCATION


def bake_sgx_azure_image(
    location: str, vm_size: str | None, enclave_ram: int, enclave_cpu: int,
    *, use_spot: bool = False,
) -> str:
    """Bake an Azure VM Image with SGX/Gramine dependencies pre-installed."""
    import json as _json
    import subprocess
    size = vm_size or _SGX_VM_SIZE
    if not size.startswith("Standard_DC"):
        console.print(
            f"[bold yellow]Warning:[/bold yellow] VM size [cyan]{size}[/cyan] may not have SGX support. "
            "Azure DCsv3/DCdsv3 series recommended.")
    console.print(Panel.fit(
        f"[bold blue]TEE-Crafter: Bake Image (SGX/Gramine on Azure)[/bold blue]\n\n"
        f"Location: [green]{location}[/green]\nVM size: [cyan]{size}[/cyan]\n"
        f"Platform: [magenta]SGX[/magenta]", border_style="blue"))
    # Per-run names for the throwaway bake resource group + VM so two bakes of
    # this platform can run at once without one's `az group delete` taking out
    # the other's VM.
    run_suffix = bake_run_suffix()
    bake_rg = f"{_SGX_BAKE_RG_PREFIX}-{run_suffix}"
    vm_name = f"{_SGX_VM_NAME_PREFIX}-{run_suffix}"
    ssh_key_path = None
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=False) as progress:
            t = progress.add_task("[yellow]Ensuring persistent images resource group...[/yellow]", total=None)
            az_cli("group", "create", "--name", _SGX_IMAGES_RESOURCE_GROUP, "--location", location)
            progress.update(t, description=f"[green]✓ Images RG: {_SGX_IMAGES_RESOURCE_GROUP}[/green]")
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
            ssh_key_dir = tempfile.mkdtemp(prefix="tee_crafter_bake_")
            ssh_key_path = os.path.join(ssh_key_dir, "bake_key")
            subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", ssh_key_path, "-N", ""],
                          capture_output=True, check=True)
            os.chmod(ssh_key_path, 0o600)
            progress.update(t, description="[green]✓ SSH key generated.[/green]")
            t = progress.add_task(f"[yellow]Creating Azure VM ({size})...[/yellow]", total=None)
            # Trusted Launch + UEFI Secure Boot + vTPM — matches the deploy
            # Terraform posture (`secure_boot_enabled` / `vtpm_enabled` on
            # `azurerm_linux_virtual_machine`) so the bake VM exercises the same
            # firmware path as production (parity with `create_azure_cvm` for
            # snp-azure / tdx-azure bakes).
            vm_result = az_cli(
                "vm", "create", "--resource-group", bake_rg, "--name", vm_name,
                "--location", location, "--size", size,
                "--image", "Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest",
                "--admin-username", "azureuser", "--ssh-key-values", f"{ssh_key_path}.pub",
                "--public-ip-sku", "Standard",
                "--security-type", "TrustedLaunch",
                "--enable-secure-boot", "true",
                "--enable-vtpm", "true",
                *(["--priority", "Spot", "--eviction-policy", "Deallocate", "--max-price", "-1"] if use_spot else []))
            public_ip = _json.loads(vm_result.stdout).get("publicIpAddress", "")
            progress.update(t, description=f"[green]✓ VM created. Public IP: {public_ip}[/green]")
            _run_setup_and_deprovision(progress, ssh_key_path, ssh_key_dir, public_ip,
                                        location, enclave_ram)
            t = progress.add_task("[yellow]Deallocating VM for image capture...[/yellow]", total=None)
            az_cli("vm", "deallocate", "--resource-group", bake_rg, "--name", vm_name)
            progress.update(t, description="[green]✓ VM deallocated.[/green]")
            t = progress.add_task("[yellow]Generalizing VM...[/yellow]", total=None)
            az_cli("vm", "generalize", "--resource-group", bake_rg, "--name", vm_name)
            progress.update(t, description="[green]✓ VM generalized.[/green]")
            # Trusted Launch VMs can only be captured into a Compute Gallery
            # image version — ``az image create`` (managed images) fails with
            # ``OperationNotAllowed: Creation of managed images are not
            # supported for virtual machine with TrustedLaunch security type``.
            # See ``capture_vhd_to_gallery`` for the shared implementation
            # (also used by SNP-Azure / TDX-Azure / GPU-CC-Azure).
            image_id, image_name = capture_vhd_to_gallery(
                progress, az_cli, bake_rg=bake_rg,
                images_rg=_SGX_IMAGES_RESOURCE_GROUP, vm_name=vm_name,
                location=location, gallery_name=_SGX_GALLERY_NAME,
                image_def=_SGX_GALLERY_IMAGE_DEFINITION,
                storage_acct=_SGX_VHD_STORAGE_ACCOUNT,
                storage_env_var="TEE_CRAFTER_SGX_STORAGE_ACCOUNT",
                vhd_container=_SGX_VHD_CONTAINER, blob_prefix="tee-crafter-sgx-",
                publisher="tee-crafter", offer="sgx", sku="22-04",
                security_type_feature="TrustedLaunchSupported",
                run_suffix=run_suffix,
            )
            t = progress.add_task("[yellow]Deleting temporary bake resources...[/yellow]", total=None)
            az_cli("group", "delete", "--name", bake_rg, "--yes", "--no-wait", check=False)
            progress.update(t, description="[green]✓ Bake resources cleanup initiated.[/green]")
        console.print(Panel.fit(
            f"[bold green]Image Bake Complete[/bold green]\n\nImage ID: [cyan]{image_id}[/cyan]\n"
            f"Image Name: [cyan]{image_name}[/cyan]\n"
            f"Resource Group: [cyan]{_SGX_IMAGES_RESOURCE_GROUP}[/cyan]\n"
            f"Platform: [magenta]SGX/Gramine[/magenta]\nLocation: [green]{location}[/green]\n\n"
            f"Use with deploy:\n  [bold]tee-crafter deploy --ami-id {image_id} --tee-platform sgx-azure ...[/bold]",
            border_style="green"))
        return image_id
    except (KeyboardInterrupt, click.Abort):
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


def _run_setup_and_deprovision(progress, ssh_key_path, ssh_key_dir, public_ip,
                                location, enclave_ram):
    """Run SGX setup script and deprovision on the bake VM."""
    from tee_crafter.core.remote.azure_ssh import wait_for_ssh, run_ssh_command, upload_file_via_scp
    t = progress.add_task("[yellow]Waiting for SSH (up to 3 min)...[/yellow]", total=None)
    if not wait_for_ssh(ssh_key_path, timeout=180, host=public_ip):
        raise click.ClickException("SSH did not become available within 3 minutes.")
    progress.update(t, description="[green]✓ SSH available.[/green]")
    t = progress.add_task("[yellow]Running SGX/Gramine setup script via SSH (10+ min)...[/yellow]", total=None)
    enclave_size = f"{min(max(256, enclave_ram), 1024)}M"
    setup_tmp = os.path.join(ssh_key_dir, "setup_sgx.sh")
    with open(setup_tmp, "w", encoding="utf-8") as f:
        f.write(load_setup_script("sgx-azure", aws_region=location, enclave_size=enclave_size))
    scp_ok, scp_msg = upload_file_via_scp(setup_tmp, "/home/azureuser/setup_sgx.sh",
                                          ssh_key_path, host=public_ip)
    if not scp_ok:
        raise click.ClickException(f"Failed to upload setup script: {scp_msg}")
    run_ssh_command("chmod +x /home/azureuser/setup_sgx.sh", ssh_key_path, host=public_ip)
    ok, stdout, stderr = run_ssh_command("sudo /home/azureuser/setup_sgx.sh",
                                         ssh_key_path, timeout=900, host=public_ip)
    if not ok:
        console.print(f"[bold red]Setup script failed:[/bold red]\n{stderr[:2000]}")
        raise click.ClickException("Setup script failed on the bake VM.")
    progress.update(t, description="[green]✓ SGX/Gramine setup complete.[/green]")
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
