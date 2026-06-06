"""Shared Azure Compute Gallery VHD capture for CVM bake workflows."""
import json
import subprocess
import time

import click


def capture_vhd_to_gallery(
    progress, az_cli_fn, *, bake_rg, images_rg, vm_name, location,
    gallery_name, image_def, storage_acct, storage_env_var,
    vhd_container, blob_prefix, publisher, offer, sku,
    security_type_feature="ConfidentialVmSupported",
    run_suffix="",
):
    """Capture a generalized Azure VM to a Compute Gallery via VHD copy.

    ``security_type_feature`` is the value of the
    ``sig image-definition --features SecurityType=…`` flag and must match
    the bake VM's actual security profile:

    * ``"ConfidentialVmSupported"`` for SNP-Azure / TDX / GPU-CC-Azure
      (the VM was created with ``--security-type ConfidentialVM``).
    * ``"TrustedLaunchSupported"`` for SGX-Azure (the VM was created with
      ``--security-type TrustedLaunch``).  ``az image create`` cannot
      capture a Trusted Launch VM into a managed image — Azure rejects
      it with ``OperationNotAllowed: Creation of managed images are not
      supported for virtual machine with TrustedLaunch security type`` —
      so SGX bakes must go through this gallery path too.

    ``run_suffix`` is the caller's per-bake token (see
    :func:`~tee_crafter.cli.commands.baking.common.helpers.bake_run_suffix`).
    It is mixed into the VHD blob name so two bakes of the same platform that
    start within the same second do not write to the same blob — the name was
    previously ``{blob_prefix}{YYYYmmdd-HHMMSS}.vhd`` and nothing else.

    Returns (image_id, image_name).
    """
    t = progress.add_task("[yellow]Capturing VM to Compute Gallery (VHD)...[/yellow]", total=None)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    image_version = time.strftime("%Y.%m%d.%H%M%S")
    blob_tag = f"{timestamp}-{run_suffix}" if run_suffix else timestamp
    vhd_blob_name = f"{blob_prefix}{blob_tag}.vhd"

    vm_show = az_cli_fn("vm", "show", "--resource-group", bake_rg, "--name", vm_name)
    disk_name = json.loads(vm_show.stdout).get("storageProfile", {}).get("osDisk", {}).get("name")
    if not disk_name:
        raise click.ClickException("Could not get OS disk name from VM.")

    grant_res = az_cli_fn("disk", "grant-access", "--resource-group", bake_rg,
                          "--name", disk_name, "--duration-in-seconds", "3600", "--access", "Read")
    grant_info = json.loads(grant_res.stdout)
    disk_sas_url = (
        grant_info.get("accessSas") or grant_info.get("accessSAS")
        or grant_info.get("properties", {}).get("output", {}).get("accessSas")
        or grant_info.get("properties", {}).get("output", {}).get("accessSAS") or "")
    if not disk_sas_url:
        raise click.ClickException("Could not get disk SAS URL from grant-access.")

    # Storage account names are globally unique across *all* Azure tenants, so
    # the historical hard-coded name is resolved to a subscription-scoped one
    # unless the operator pinned it through ``storage_env_var``.
    from tee_crafter.cli.commands.baking.common.helpers import (
        azure_vhd_storage_account,
    )
    storage_name = azure_vhd_storage_account(storage_acct, storage_env_var)
    az_cli_fn("storage", "account", "create", "--resource-group", images_rg,
              "--name", storage_name, "--location", location, "--sku", "Standard_LRS", check=False)
    keys_res = az_cli_fn("storage", "account", "keys", "list",
                         "--resource-group", images_rg, "--account-name", storage_name)
    account_key = json.loads(keys_res.stdout)[0]["value"]
    az_cli_fn("storage", "container", "create", "--account-name", storage_name,
              "--account-key", account_key, "--name", vhd_container, check=False)

    copy_res = subprocess.run(
        ["az", "storage", "blob", "copy", "start",
         "--destination-container", vhd_container, "--destination-blob", vhd_blob_name,
         "--source-uri", disk_sas_url, "--account-name", storage_name, "--account-key", account_key],
        capture_output=True, text=True)
    if copy_res.returncode != 0:
        raise click.ClickException(f"Blob copy start failed: {copy_res.stderr or copy_res.stdout or 'unknown'}")

    # Blob copy time varies a lot by region and transient load.
    # Allow up to ~30 minutes for the VHD copy to complete.
    for _ in range(360):
        time.sleep(5)
        show_res = subprocess.run(
            ["az", "storage", "blob", "show", "--account-name", storage_name,
             "--account-key", account_key, "--container-name", vhd_container,
             "--name", vhd_blob_name, "-o", "json"],
            capture_output=True, text=True)
        if show_res.returncode != 0:
            continue
        copy_status = json.loads(show_res.stdout).get("properties", {}).get("copy", {})
        if copy_status.get("status") == "success":
            break
        if copy_status.get("status") == "failed":
            raise click.ClickException(f"Blob copy failed: {copy_status.get('statusDescription', 'unknown')}")
    else:
        raise click.ClickException("Blob copy did not complete within 30 minutes.")

    az_cli_fn("disk", "revoke-access", "--resource-group", bake_rg, "--name", disk_name, check=False)

    gallery_res = az_cli_fn("sig", "create", "--resource-group", images_rg,
                            "--gallery-name", gallery_name, check=False)
    if gallery_res.returncode != 0:
        err = (gallery_res.stderr or gallery_res.stdout or "").lower()
        if "already exists" not in err:
            raise click.ClickException(f"Failed to create gallery: {gallery_res.stderr or gallery_res.stdout}")

    def_res = az_cli_fn("sig", "image-definition", "show", "--resource-group", images_rg,
                        "--gallery-name", gallery_name, "--gallery-image-definition", image_def, check=False)
    if def_res.returncode != 0:
        az_cli_fn("sig", "image-definition", "create", "--resource-group", images_rg,
                  "--gallery-name", gallery_name, "--gallery-image-definition", image_def,
                  "--publisher", publisher, "--offer", offer, "--sku", sku,
                  "--os-type", "Linux", "--os-state", "Generalized", "--hyper-v-generation", "V2",
                  "--features", f"SecurityType={security_type_feature}")

    stg_show = az_cli_fn("storage", "account", "show", "--name", storage_name,
                         "--resource-group", images_rg)
    storage_id = json.loads(stg_show.stdout).get("id", "")
    blob_uri = f"https://{storage_name}.blob.core.windows.net/{vhd_container}/{vhd_blob_name}"

    az_cli_fn("sig", "image-version", "create", "--resource-group", images_rg,
              "--gallery-name", gallery_name, "--gallery-image-definition", image_def,
              "--gallery-image-version", image_version,
              "--os-vhd-storage-account", storage_id, "--os-vhd-uri", blob_uri)
    ver_show = az_cli_fn("sig", "image-version", "show", "--resource-group", images_rg,
                         "--gallery-name", gallery_name, "--gallery-image-definition", image_def,
                         "--gallery-image-version", image_version)
    image_id = json.loads(ver_show.stdout).get("id", "")
    image_name = f"{image_def}-{image_version}"
    progress.update(t, description=f"[green]✓ Image captured: {image_name}[/green]")
    return image_id, image_name
