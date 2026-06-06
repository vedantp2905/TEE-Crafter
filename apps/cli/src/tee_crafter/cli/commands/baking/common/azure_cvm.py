"""Azure Confidential VM creation with smart retry for CVM bake workflows."""
import time

import click

_CVM_IMAGE = "Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest"
_MAX_CVM_CREATE_RETRIES = 3

_NON_RETRIABLE_PATTERNS = [
    "quotaexceeded", "skuNotavailable", "operationnotallowed",
    "authorizationfailed", "invalidauthenticationtoken",
    "linkedauthorizationfailed", "requestdisallowedbypolicy",
]

_QUOTA_HELP = (
    "Your Azure subscription does not have enough vCPU quota for the requested "
    "VM family in this region.\n\n"
    "To fix this, do ONE of the following:\n\n"
    "  1) Request a quota increase (Portal → Subscriptions → {sub_id}\n"
    "     → Usage + quotas → search \"{family}\" → Request increase)\n\n"
    "  2) Try a region that already has quota:\n"
    "     tee-crafter internal bake-ami --tee-platform {platform} --region <other-region>\n"
    "     Common CVM regions: eastus, westus2, northeurope, westeurope\n\n"
    "  3) Use a smaller VM family by passing --instance-type to\n"
    "     `tee-crafter internal bake-ami` (or to `tee-crafter deploy`)."
)


def _get_az_cli():
    from tee_crafter.cli.commands.baking.common.helpers import az_cli
    return az_cli


def _status(progress, task, description: str) -> None:
    """Update the spinner if there is one.

    Callers that are not driving a ``rich`` Progress (the measurement-capture
    path) pass ``progress=None`` so they can still reuse the retry logic below;
    without this they would have to duplicate it, which is how the Azure CLI
    SDK-bug recovery came to exist on the bake path but not the measurement
    path in the first place.
    """
    if progress is not None:
        progress.update(task, description=description)


def _extract_quota_details(stderr: str) -> dict:
    """Pull the quota subject, subscription, location and numbers out of the error.

    Sample of the real message, captured from ARM on 2026-08-22 by asking for a
    ``Standard_DC16as_v5`` in ``westus`` (family limit 8), read out of
    ``az vm create --debug`` because azure-cli 2.89.1 on Python 3.14 eats the
    response body itself::

        Operation could not be completed as it results in exceeding approved
        standardDCASv5Family Cores quota. Additional details - Deployment
        Model: Resource Manager, Location: westus, Current Limit: 8, Current
        Usage: 0, Additional Required: 16, (Minimum) New Limit Required: 16.
        ... %7B%22location%22:%22westus%22,...%22resourceName%22:%22standardDCASv5Family%22,
        %22quotaRequest%22:%7B%22properties%22:%7B%22limit%22:16,...

    Two things about that text drove this rewrite.

    First, the **subject** of the message is the phrase after "exceeding
    approved", and it is not always a VM family — "Total Regional Cores" uses
    the same sentence with the same ``Current Limit:`` field.  Scraping
    ``resourceName`` out of the portal URL instead means a regional-cores
    refusal gets reported against whatever family name happens to appear
    elsewhere in the text, with the regional limit attached to it.  That is how
    a family whose real limit is 8 came to be reported as ``limit=48``.

    Second, every field here used to have a **plausible-looking default**
    (``standardDCASv5Family`` / ``westus`` / ``0``).  When the message did not
    match — which is routine, because the SDK bug above replaces it with a
    Python traceback — the operator was shown a fully-populated hint that had
    been invented, and ``limit=0`` looked like a real quota of zero.  Nothing
    is defaulted now: unmatched fields come back ``None`` and the caller says
    so.  ``sub_id`` keeps a placeholder because it is only interpolated into a
    portal URL, where a visible ``<your-subscription>`` is self-explanatory.
    """
    import re
    # Same percent-encoding problem as ``resourceName`` below: the id sits in
    # ``%22subscriptionId%22:%22<guid>%22``.  The old separator class
    # ``[":%\s]+`` could not cross the digits in ``%22``, so this never matched
    # and the hint's portal link always read ``<your-subscription>`` even when
    # the error carried the real id.  A bounded lazy gap plus the full GUID
    # shape is both simpler and encoding-agnostic.
    sub = re.search(r"subscriptionId.{0,16}?"
                    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                    stderr, re.I)
    # The authoritative subject: "... exceeding approved <subject> quota".
    subject = re.search(r"exceeding approved\s+(.+?)\s+quota", stderr, re.I)
    # ``resourceName`` sits inside a percent-encoded portal URL:
    # ``%22resourceName%22:%22standardDCASv5Family%22``.  The old separator
    # class was ``[":%\s]+``, which cannot cross the ``2`` in ``%22``, so this
    # never matched and every message fell through to the hard-coded family
    # default.  Skip any run of non-letters instead.
    family = re.search(r"resourceName[^A-Za-z]{0,12}(standard\w+Family)",
                       stderr, re.I)
    loc = re.search(r"Location:\s*([\w]+)", stderr)
    # Anchored to the exact labels.  "(Minimum) New Limit Required" is the
    # amount being *asked for*, not the ceiling, and must not be read as one.
    limit = re.search(r"Current Limit:\s*(\d+)", stderr)
    usage = re.search(r"Current Usage:\s*(\d+)", stderr)
    required = re.search(r"Additional Required:\s*(\d+)", stderr)
    subject_txt = subject.group(1).strip() if subject else None
    return {
        "sub_id": sub.group(1) if sub else "<your-subscription>",
        "subject": subject_txt,
        # ``family`` is what the portal search box needs; fall back to the
        # subject only when it actually names a family.
        "family": (family.group(1) if family
                   else (subject_txt if subject_txt
                         and "family" in subject_txt.lower() else None)),
        "location": loc.group(1) if loc else None,
        "limit": int(limit.group(1)) if limit else None,
        "usage": int(usage.group(1)) if usage else None,
        "required": int(required.group(1)) if required else None,
    }


def _quota_message(details: dict, platform_label: str) -> str:
    """Operator-facing text for a quota refusal, saying only what was parsed."""
    subject = details["subject"] or details["family"] or "the requested VM family"
    where = f" in {details['location']}" if details["location"] else ""
    if details["limit"] is None:
        numbers = (
            "\nAzure did not report a limit in its error text, so the ceiling "
            "below is unknown — check Portal → Subscriptions → Usage + quotas.")
    else:
        parts = [f"limit={details['limit']}"]
        if details["usage"] is not None:
            parts.append(f"in use={details['usage']}")
        if details["required"] is not None:
            parts.append(f"this request needs {details['required']}")
        numbers = f" ({', '.join(parts)})"
    head = f"Azure vCPU quota exceeded for {subject}{where}{numbers}"
    if not head.endswith("\n"):
        head += "\n"
    help_kwargs = dict(details)
    help_kwargs["family"] = details["family"] or subject
    help_kwargs["location"] = details["location"] or "<region>"
    return head + "\n" + _QUOTA_HELP.format(platform=platform_label, **help_kwargs)


def _classify_error(stderr: str) -> str:
    """Return a category tag for the Azure CLI failure."""
    lower = stderr.lower()
    if "quotaexceeded" in lower:
        return "quota"
    for pat in _NON_RETRIABLE_PATTERNS:
        if pat.lower() in lower:
            return "non_retry"
    if "already consumed" in lower:
        return "sdk_bug"
    return "transient"


def create_azure_cvm(
    progress, task,
    resource_group: str, vm_name: str, location: str, size: str, ssh_pub_key: str,
    *, platform_label: str = "snp-azure", use_spot: bool = False,
    secure_boot: bool = True, image: str = "",
) -> str:
    """Create an Azure Confidential VM (SEV-SNP / TDX) with smart retry.

    *image* defaults to the Canonical CVM marketplace image used for baking;
    pass a gallery image-version ARM ID to boot a already-baked image instead
    (the measurement-capture path does this).

    ``progress`` may be ``None`` for callers with no spinner.

    Returns the VM's public IP address.
    """
    import json as _json
    az_cli = _get_az_cli()
    create_args = [
        "vm", "create", "--resource-group", resource_group, "--name", vm_name,
        "--location", location, "--size", size, "--image", image or _CVM_IMAGE,
        "--admin-username", "azureuser", "--ssh-key-values", ssh_pub_key,
        "--public-ip-sku", "Standard", "--security-type", "ConfidentialVM",
        "--os-disk-security-encryption-type", "VMGuestStateOnly",
        "--enable-secure-boot", str(secure_boot).lower(), "--enable-vtpm", "true",
    ]
    if use_spot:
        create_args.extend(["--priority", "Spot", "--eviction-policy", "Deallocate", "--max-price", "-1"])
    for attempt in range(1, _MAX_CVM_CREATE_RETRIES + 1):
        res = az_cli(*create_args, check=False)
        if res.returncode == 0 and res.stdout.strip():
            return _json.loads(res.stdout).get("publicIpAddress", "")

        stderr = res.stderr or ""
        category = _classify_error(stderr)
        if category == "quota":
            details = _extract_quota_details(stderr)
            raise click.ClickException(
                _quota_message(details, platform_label))
        if category == "non_retry":
            raise click.ClickException(f"Azure rejected the VM request (not retriable):\n{stderr[:4000]}")
        if category == "sdk_bug":
            ip = _handle_sdk_bug(az_cli, progress, task, resource_group, vm_name, stderr,
                                 attempt, platform_label)
            if ip is not None:
                return ip
            if attempt < _MAX_CVM_CREATE_RETRIES:
                az_cli("vm", "delete", "--resource-group", resource_group,
                       "--name", vm_name, "--yes", "--no-wait", check=False)
                time.sleep(15)
                continue
            raise click.ClickException(
                f"az vm create failed after {_MAX_CVM_CREATE_RETRIES} attempts "
                f"(Azure CLI SDK bug).\n\n{stderr[:4000]}")
        if attempt < _MAX_CVM_CREATE_RETRIES:
            _status(progress, task,
                    f"[yellow]az vm create failed (attempt {attempt}); retrying...[/yellow]")
            az_cli("vm", "delete", "--resource-group", resource_group,
                   "--name", vm_name, "--yes", "--no-wait", check=False)
            time.sleep(15)
            continue
        raise click.ClickException(
            f"az vm create failed after {_MAX_CVM_CREATE_RETRIES} attempts:\n{stderr[:4000]}")
    raise click.ClickException("az vm create failed: unexpected retry loop exit")


def _handle_sdk_bug(az_cli, progress, task, resource_group, vm_name, stderr, attempt, platform_label):
    """Check if VM was actually created despite SDK error. Returns IP or None."""
    import json as _json
    _status(progress, task,
            f"[yellow]Azure CLI SDK bug (attempt {attempt}/{_MAX_CVM_CREATE_RETRIES}); "
            f"checking if VM was created...[/yellow]")
    time.sleep(20)
    show_res = az_cli("vm", "show", "--resource-group", resource_group,
                      "--name", vm_name, "--show-details", check=False)
    if show_res.returncode == 0 and show_res.stdout.strip():
        vm_info = _json.loads(show_res.stdout)
        power, pip = vm_info.get("powerState", ""), vm_info.get("publicIps", "")
        if "running" in power.lower() and pip:
            return pip
        if power:
            _status(progress, task, f"[yellow]VM exists (state={power}); waiting for Running...[/yellow]")
            az_cli("vm", "wait", "--custom", "instanceView.statuses[?code=='PowerState/running']",
                   "--resource-group", resource_group, "--name", vm_name, "--timeout", "600", check=False)
            show2 = az_cli("vm", "show", "--resource-group", resource_group,
                           "--name", vm_name, "--show-details", check=False)
            if show2.returncode == 0 and show2.stdout.strip():
                pip2 = _json.loads(show2.stdout).get("publicIps", "")
                if pip2:
                    return pip2
    if any(p in stderr.lower() for p in _NON_RETRIABLE_PATTERNS):
        if "quotaexceeded" in stderr.lower():
            raise click.ClickException(
                _quota_message(_extract_quota_details(stderr), platform_label))
        raise click.ClickException(f"Azure rejected the VM request:\n{stderr[:4000]}")
    return None
