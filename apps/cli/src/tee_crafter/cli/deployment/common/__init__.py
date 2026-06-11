"""Shared deployment infrastructure (Terraform, VPC, SSM, tunnels)."""

import subprocess


def ensure_azure_network_watcher(console, location: str) -> None:
    """Create NetworkWatcherRG and NetworkWatcher_<region> if absent.

    Azure flow logs require a Network Watcher in the target region.  Many
    subscriptions don't have one pre-provisioned, which causes Terraform to
    fail on the ``data.azurerm_network_watcher`` lookup.
    """
    nw_name = f"NetworkWatcher_{location.replace(' ', '')}"
    try:
        check = subprocess.run(
            ["az", "network", "watcher", "show",
             "--name", nw_name, "--resource-group", "NetworkWatcherRG",
             "--query", "provisioningState", "-o", "tsv"],
            capture_output=True, text=True, timeout=30,
        )
        if check.returncode == 0 and "Succeeded" in check.stdout:
            return
    except Exception:
        pass

    console.print(f"[dim]Provisioning Network Watcher ({nw_name}) for flow logs...[/dim]")
    try:
        subprocess.run(
            ["az", "group", "create", "--name", "NetworkWatcherRG",
             "--location", location, "-o", "none"],
            capture_output=True, timeout=30,
        )
        subprocess.run(
            ["az", "network", "watcher", "configure",
             "--resource-group", "NetworkWatcherRG",
             "--locations", location, "--enabled", "true", "-o", "none"],
            capture_output=True, timeout=60,
        )
    except Exception as e:
        console.print(f"[yellow]Warning: could not provision Network Watcher: {e}[/yellow]")
