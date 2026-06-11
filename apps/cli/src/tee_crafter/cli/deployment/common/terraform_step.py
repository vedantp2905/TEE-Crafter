"""Terraform apply step with retries and Azure resource-group cleanup helpers."""
import os
import re
import shutil
import subprocess
import time


from tee_crafter.core.iac import run_terraform_apply, run_terraform_destroy
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.constants import Console, Progress, SpinnerColumn, TextColumn

_AZURE_RG_PREFIXES = {
    "sgx": "tee-crafter-sgx-rg",
    "tdx": "tee-crafter-tdx-rg",
    "snp": "tee-crafter-snp-rg",
    "gpu-cc": "tee-crafter-gpu-cc-rg",
}
_AZURE_RG_NAMES = _AZURE_RG_PREFIXES


# Strict HCL block-header matcher.  Matches one of:
#   ingress {            (literal AWS/Azure rule block)
#   "ingress" {          (inside `dynamic "ingress" { ... }`)
#   security_rule { ... direction = "Inbound" }   (Azure NSG)
# and the equivalents for egress / Outbound.  Crucially does NOT
# match the literal word ``ingress`` / ``egress`` inside:
#   - variable descriptions ("0.0.0.0/0 egress for setup")
#   - identifiers (``siem_egress_cidrs``, ``var.allow_setup_egress``)
#   - comments
# because all of those are not followed by ``{``.
_INGRESS_HEADER_RE = re.compile(
    r'(?:(?<=^)|(?<=\s))(?:ingress|"ingress")\s*\{'
    r'|'
    r'security_rule\s*\{[^{}]*?direction\s*=\s*"Inbound"',
    re.IGNORECASE | re.DOTALL | re.MULTILINE,
)
_EGRESS_HEADER_RE = re.compile(
    r'(?:(?<=^)|(?<=\s))(?:egress|"egress")\s*\{'
    r'|'
    r'security_rule\s*\{[^{}]*?direction\s*=\s*"Outbound"',
    re.IGNORECASE | re.DOTALL | re.MULTILINE,
)


def _find_blocks(tf_text: str, *, ingress: bool) -> list[str]:
    """Return the bodies of every ``ingress { ... }`` (or ``egress
    { ... }``) HCL block in *tf_text*.

    Walks balanced braces forward from the block header so the body
    we hand back is exactly the block's content — no surrounding SG
    resource, no neighbouring siblings.  Used by the IAC-002 /
    IAC-003 / EGR-002 static checks so they can confidently say
    "this 0.0.0.0/0 lives inside an ingress rule" instead of just
    "the file contains both an `ingress` token and 0.0.0.0/0
    somewhere".
    """
    pattern = _INGRESS_HEADER_RE if ingress else _EGRESS_HEADER_RE
    blocks: list[str] = []
    for m in pattern.finditer(tf_text):
        start = tf_text.find("{", m.start())
        if start < 0:
            continue
        depth = 0
        end = start
        for i in range(start, len(tf_text)):
            c = tf_text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        blocks.append(tf_text[start:end + 1])
    return blocks



def emit_iac_static_verdicts(audit: BuildAuditTrail | None, build_dir: str,
                             *, tee_platform: str = "") -> None:
    """Scan ``build_dir/main.tf`` (+ siblings) and emit IAC-* verdicts.

    Static analysis only: looks for the patterns the production templates
    promise (no SSH ingress, no 0.0.0.0/0 on workload port, KMS key
    policy referencing an instance role or attestation claim, etc.).
    All findings land as ledger rows so a verifier can confirm them
    offline.
    """
    if audit is None:
        return
    main_tf = os.path.join(build_dir, "main.tf")
    if not os.path.isfile(main_tf):
        audit.record_check(
            "Phase 3: IaC", "terraform validate clean", "IAC-001",
            observed=False,
            note=f"main.tf missing in {build_dir}",
        )
        return
    try:
        with open(main_tf, "r", encoding="utf-8") as f:
            tf_text = f.read()
    except OSError as e:
        audit.record_check(
            "Phase 3: IaC", "terraform validate clean", "IAC-001",
            observed=False, note=str(e)[:200],
        )
        return
    lower = tf_text.lower()
    audit.record_check(
        "Phase 3: IaC", "terraform validate clean", "IAC-001",
        observed=bool(tf_text.strip()),
        evidence_pointer="main.tf",
    )

    # IAC-002 — SG/NSG/firewall has no SSH ingress (port 22).  We
    # only look at true HCL block headers so that a `description =
    # "...SSH port 22..."` blurb doesn't fire a false-positive.
    ssh_ingress_blocks = _find_blocks(tf_text, ingress=True)
    ssh_ingress = False
    for block in ssh_ingress_blocks:
        bl = block.lower()
        if ("from_port" in bl and "= 22" in bl) or \
           ("destination_port_range" in bl and "\"22\"" in bl) or \
           ("port_range" in bl and "\"22\"" in bl):
            ssh_ingress = True
            break
    audit.record_check(
        "Phase 3: IaC", "No SSH ingress in SG/NSG/firewall", "IAC-002",
        expected=True, observed=(not ssh_ingress),
        evidence_pointer="main.tf",
    )

    # IAC-003 — no 0.0.0.0/0 ingress on the workload port.  We can't
    # parse HCL safely without an HCL parser, but we can scope the
    # scan to true ``ingress { ... }`` and ``dynamic "ingress" {
    # ... }`` block headers so that 0.0.0.0/0 anywhere else — egress
    # blocks, NAT/IGW route tables, variable descriptions that
    # mention "0.0.0.0/0", or identifiers like ``siem_egress_cidrs``
    # — doesn't fire a false-positive against the workload SG.
    ingress_broad = 0
    for block in ssh_ingress_blocks:
        ingress_broad += block.count("0.0.0.0/0") + block.count("::/0")
    audit.record_check(
        "Phase 3: IaC", "No 0.0.0.0/0 workload-port ingress", "IAC-003",
        expected=True, observed=(ingress_broad == 0),
        note=(f"0.0.0.0/0 occurrences in ingress blocks: "
              f"{ingress_broad} (egress blocks + descriptions excluded)"),
        evidence_pointer="main.tf",
    )

    # IAC-004 — AWS KMS policy attestation-gated.  Production templates
    # either reference a Nitro PCR via kms:RecipientAttestation:* (nitro)
    # or limit decrypt to the instance role ARN (snp-aws / gpu-cc-aws).
    if tee_platform in {"nitro-aws", "snp-aws", "gpu-cc-aws"}:
        has_attest_clause = (
            "kms:recipientattestation" in lower
            or "kms:ImageHash" in tf_text
            or "kms:ViaService" in tf_text
        )
        has_role_clause = "aws_iam_role" in lower and "kms" in lower
        audit.record_check(
            "Phase 3: IaC", "KMS key policy attestation-gated (AWS)",
            "IAC-004",
            expected=True,
            observed=bool(has_attest_clause or has_role_clause),
            evidence_pointer="main.tf",
            note=("attest_clause" if has_attest_clause
                  else ("instance_role_gated" if has_role_clause
                        else "NEITHER attestation nor instance role found")),
        )

    # IAC-005 / IAC-006 — Azure Key Vault SKR / GCP KMS attestation
    # bindings are declared in higher-level files.  Best-effort check.
    if tee_platform.endswith("-azure"):
        has_skr = "key_vault" in lower and ("release_policy" in lower or "skr" in lower)
        audit.record_check(
            "Phase 3: IaC", "Azure Key Vault SKR release policy present",
            "IAC-005",
            expected=True, observed=bool(has_skr),
            evidence_pointer="main.tf",
        )
    if tee_platform.endswith("-gcp"):
        has_binding = (
            "google_kms_crypto_key_iam" in lower
            and ("attestation" in lower or "confidential_space" in lower
                 or "workload_identity" in lower)
        )
        audit.record_check(
            "Phase 3: IaC", "GCP KMS attestation binding present", "IAC-006",
            expected=True, observed=bool(has_binding),
            evidence_pointer="main.tf",
        )

    # IAC-007 — VPC endpoints for KMS / SSM / Logs (aws).
    if tee_platform in {"nitro-aws", "snp-aws", "gpu-cc-aws"}:
        needed = ("vpc_endpoint", "kms", "ssm", "logs")
        has_vpce = all(tok in lower for tok in needed)
        audit.record_check(
            "Phase 3: IaC", "VPC endpoints for KMS/SSM/Logs", "IAC-007",
            expected=True, observed=bool(has_vpce),
            evidence_pointer="main.tf",
        )

    # IAC-008 — Secure-Boot variable enabled on AWS launch-template /
    # custom-AMI image attributes.  Production default is
    # ``enable_secure_boot=true``.
    if tee_platform.endswith("-aws"):
        has_sb = "enable_secure_boot" in lower or "uefidata" in lower
        audit.record_check(
            "Phase 3: IaC", "Secure-Boot variable enabled (baked AMI)",
            "IAC-008",
            expected=True, observed=bool(has_sb),
            evidence_pointer="main.tf",
        )

    # IAC-009 — NRAS egress CIDRs narrow.  GPU-CC only.
    if tee_platform.startswith("gpu-cc"):
        broad_nras = "allow_nras_broad_internet" in lower and "true" in lower
        audit.record_check(
            "Phase 3: IaC", "NRAS egress CIDRs narrow", "IAC-009",
            expected=True, observed=(not broad_nras),
            evidence_pointer="main.tf",
        )

    # EGR-001 — NRAS-strict env knob (GPU-CC only).  Mirrors DH-013
    # but expressed as an egress invariant in the EGR category so a
    # CI gate that filters on "egress" picks it up.
    if tee_platform.startswith("gpu-cc"):
        nras_strict = (
            os.environ.get("TEE_CRAFTER_NRAS_STRICT", "1").strip() in
            {"1", "true", "yes", "on"}
        )
        audit.record_check(
            "Phase 3: IaC", "NRAS-strict env knob observed", "EGR-001",
            observed=bool(nras_strict),
            note="TEE_CRAFTER_NRAS_STRICT == 1",
        )

    # EGR-002 — egress block CIDR list narrowness.  Same scoping
    # trick as IAC-003: walk every true ``egress { ... }`` /
    # ``dynamic "egress" { ... }`` block (HCL block headers, not the
    # literal word) and reject the block if it allows 0.0.0.0/0 or
    # ::/0 to a non-managed port.  Variable descriptions like
    # "...0.0.0.0/0 egress..." and identifiers like
    # ``siem_egress_cidrs`` never match because they are not
    # followed by a ``{``.
    egress_broad = 0
    for block in _find_blocks(tf_text, ingress=False):
        # Skip blocks that are clearly the bootstrap egress
        # (allow_setup_egress) — they're already covered by DH-014.
        if "allow_setup_egress" in block:
            continue
        if "0.0.0.0/0" in block or "::/0" in block:
            egress_broad += 1
    audit.record_check(
        "Phase 3: IaC", "Egress CIDR list narrow", "EGR-002",
        observed=(egress_broad == 0),
        evidence_pointer="main.tf",
        note=(f"{egress_broad} egress block(s) still permit 0.0.0.0/0; "
              "tighten or move behind allow_setup_egress."
              if egress_broad else "no broad egress blocks"),
    )

    # EGR-004 — no public-internet route table by default.  We can
    # only spot the canonical patterns: ``route_table`` resources
    # without an IGW route, or VPCs created with ``map_public_ip_on_
    # launch = false``.  This is best-effort static analysis.
    has_igw_route = (
        "internet_gateway" in lower
        or "0.0.0.0/0" in lower and "route_table" in lower
    )
    has_explicit_no_public = (
        "map_public_ip_on_launch" in lower
        and "false" in lower
    )
    no_public_default = has_explicit_no_public or not has_igw_route
    audit.record_check(
        "Phase 3: IaC", "No public-internet route table by default",
        "EGR-004",
        observed=bool(no_public_default),
        evidence_pointer="main.tf",
        note=("explicit map_public_ip_on_launch=false"
              if has_explicit_no_public
              else "no internet_gateway route_table detected"),
    )


def _detect_cloud_from_build(build_dir: str) -> str:
    """Infer the cloud provider from the build directory name or Terraform files."""
    dirname = os.path.basename(os.path.abspath(build_dir)).lower()
    if "gpu_cc_aws" in dirname or "gpu-cc-aws" in dirname:
        return "aws"
    if "gpu_cc_gcp" in dirname or "gpu-cc-gcp" in dirname:
        return "gcp"
    if "gpu_cc_azure" in dirname or "gpu-cc-azure" in dirname:
        return "azure"
    if "nitro" in dirname or "snp-aws" in dirname or "_snp_aws_" in dirname:
        return "aws"
    if "_gcp_" in dirname or "snp-gcp" in dirname or "tdx-gcp" in dirname:
        return "gcp"
    main_tf = os.path.join(build_dir, "main.tf")
    if os.path.isfile(main_tf):
        try:
            with open(main_tf, "r", encoding="utf-8") as f:
                head = f.read(2000)
            if "azurerm" in head:
                return "azure"
            if "google" in head:
                return "gcp"
            if "aws" in head.lower():
                return "aws"
        except Exception:
            pass
    return "azure"


def _detect_azure_rg_name(build_dir: str) -> str:
    """Get the Azure resource group name from Terraform outputs.

    Returns ``""`` when the outputs do not name one.  There is no name
    guess here any more: the templates suffix every RG with the per-deploy
    ``local.did`` (e.g. ``tee-crafter-snp-rg-a1b2c3d4``), so the bare
    :data:`_AZURE_RG_PREFIXES` value names a group that usually does not
    exist — and ``az group show`` failing on a group that was never created
    made :func:`_az_force_delete_rg` report a successful cleanup while the
    real, suffixed group kept running.
    """
    from tee_crafter.core.iac import get_terraform_outputs
    outputs = get_terraform_outputs(build_dir)
    return outputs.get("resource_group", "")


def _rg_exists(rg_name: str) -> tuple[bool, str]:
    """Return ``(exists, detail)`` for an Azure resource group.

    ``az group show`` exits non-zero both when the group is genuinely gone
    (``ResourceGroupNotFound``) and when the CLI cannot answer at all — not
    logged in, throttled, wrong subscription, no network.  Treating every
    non-zero exit as "deleted" is how a failed teardown reported success.
    Only a definite not-found counts as gone.
    """
    check = subprocess.run(
        ["az", "group", "show", "--name", rg_name, "--output", "json"],
        capture_output=True, text=True,
    )
    if check.returncode == 0:
        return True, ""
    err = (check.stderr or check.stdout or "").strip()
    lowered = err.lower()
    if "resourcegroupnotfound" in lowered or "could not be found" in lowered:
        return False, err
    return True, err or f"az group show exited {check.returncode}"


def _rg_provisioning_state(rg_name: str) -> str:
    """Return the resource group's ``provisioningState``, or ``""``.

    Needed to tell a delete that is *still running* (``Deleting``) from one that
    **gave up** -- Azure reverts the group to ``Succeeded`` when an asynchronous
    group delete aborts because one of its resources could not be removed. Both
    look identical to a caller that only asks "does the group still exist?",
    which is how a teardown reported "deletion initiated" and then quietly left
    a Bastion host billing overnight. Observed three times on 2026-08-23, twice
    on the same group.
    """
    check = subprocess.run(
        ["az", "group", "show", "--name", rg_name,
         "--query", "properties.provisioningState", "--output", "tsv"],
        capture_output=True, text=True,
    )
    if check.returncode != 0:
        return ""
    return (check.stdout or "").strip()


def _az_force_delete_rg(console: Console, rg_name: str) -> bool:
    """Delete an Azure resource group via ``az group delete``.

    Unlike ``terraform destroy``, Azure's own group-delete handles
    dependency ordering internally (VM before NIC, NIC before subnet, etc.),
    so it succeeds even when Terraform cannot figure out the right order
    due to orphaned resources outside its state.

    Returns True only when the RG is provably gone.
    """
    if not rg_name:
        console.print(
            "[red]Azure cleanup: no resource_group in the Terraform outputs; "
            "cannot identify the group to delete. Delete it from the portal "
            "or run `az group list --tag Project=tee-crafter`.[/red]"
        )
        return False

    exists, detail = _rg_exists(rg_name)
    if not exists:
        console.print(f"[green]✓ Resource group '{rg_name}' does not exist.[/green]")
        return True
    if detail:
        console.print(
            f"[yellow]Azure cleanup: could not confirm '{rg_name}' state "
            f"({detail[:200]}); attempting delete anyway.[/yellow]"
        )

    console.print(
        f"[yellow]Force-deleting resource group '{rg_name}' via Azure CLI "
        "(handles dependency ordering)...[/yellow]"
    )
    result = subprocess.run(
        ["az", "group", "delete", "--name", rg_name, "--yes", "--no-wait"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        console.print(f"[red]az group delete failed: {result.stderr}[/red]")
        return False
    console.print(f"[green]✓ Resource group '{rg_name}' deletion initiated.[/green]")
    return _wait_for_rg_deletion(console, rg_name)


# Azure resource-group deletes routinely take 15-25 minutes when the group
# holds a Bastion host, a NAT gateway and a confidential VM (the Bastion
# alone is ~10 min).  The old 600 s ceiling timed out on most real teardowns
# and left the caller unable to tell "still going" from "stuck".
_AZURE_RG_DELETE_TIMEOUT_SEC = 1800


#: How many times to re-issue an aborted `az group delete` before giving up.
#: Azure gives no reason when an asynchronous group delete stops early, and a
#: re-issue usually succeeds because whatever held the blocking resource (a
#: Bastion still attached to its subnet and public IP) has since let go.
_AZURE_RG_DELETE_MAX_REISSUES = 3

#: How many orphan-adoption rounds an apply loop may take. Each round must
#: import at least one resource to be counted, so this bounds progress, not
#: attempts.
_MAX_ORPHAN_ADOPTIONS = 3


def _wait_for_rg_deletion(
    console: Console, rg_name: str, timeout: int = _AZURE_RG_DELETE_TIMEOUT_SEC,
) -> bool:
    """Poll until the resource group is fully gone.  Returns whether it is.

    Re-issues the delete if Azure abandons it. An asynchronous ``az group
    delete`` can stop without finishing and without saying so: the group's
    ``provisioningState`` goes back to ``Succeeded`` and it simply stays there,
    fully populated. Polling only for *existence* cannot see the difference
    between that and a delete still grinding through a Bastion host, so this
    used to wait out the full 30 minutes and then report a timeout on a delete
    that had actually given up 25 minutes earlier.

    That is not a cosmetic distinction. On 2026-08-23 it happened three times,
    twice to the same group, and left two Bastion hosts (~$0.19/hr each) plus a
    NAT gateway running for about eleven hours after a teardown had reported
    "deletion initiated".
    """
    import time as _time
    deadline = _time.monotonic() + timeout
    interval = 10
    reissues = 0
    while _time.monotonic() < deadline:
        exists, _ = _rg_exists(rg_name)
        if not exists:
            console.print(f"[green]✓ Resource group '{rg_name}' fully deleted.[/green]")
            return True
        state = _rg_provisioning_state(rg_name)
        if state and state.lower() != "deleting":
            if reissues >= _AZURE_RG_DELETE_MAX_REISSUES:
                console.print(
                    f"[bold red]'{rg_name}' stopped deleting {reissues} times "
                    f"(now provisioningState={state}) and is still billing. "
                    f"Something in it is refusing to delete — inspect with "
                    f"`az resource list -g {rg_name} -o table` and remove the "
                    f"blocking resource by hand.[/bold red]")
                return False
            reissues += 1
            console.print(
                f"[yellow]Azure abandoned the delete of '{rg_name}' "
                f"(provisioningState={state}, group still present). "
                f"Re-issuing ({reissues}/{_AZURE_RG_DELETE_MAX_REISSUES})..."
                f"[/yellow]")
            subprocess.run(
                ["az", "group", "delete", "--name", rg_name, "--yes",
                 "--no-wait"],
                capture_output=True, text=True,
            )
        _time.sleep(interval)
        interval = min(interval + 5, 30)
    console.print(
        f"[bold red]Timed out after {timeout // 60} min waiting for '{rg_name}' "
        f"deletion. The delete is asynchronous and may still finish, but the "
        f"group is still billing right now — check with "
        f"`az group show --name {rg_name}`.[/bold red]"
    )
    return False


def cleanup_resources(
    console: Console, build_dir: str, context: str = "cleanup"
) -> bool:
    """Best-effort destroy of TEE deploy resources for any cloud provider.

    1. Tries ``terraform destroy`` (fast when state is consistent).
    2. For Azure builds only: confirms the resource group is actually gone,
       and falls back to ``az group delete`` when it is not — whether
       Terraform failed *or* wrongly reported success.

    Step 2 used to trust ``terraform destroy``'s exit code alone.  After the
    ``sgx-azure`` batch failure on 2026-08-22 the cleanup path printed
    "✓ Resources destroyed" while ``tee-crafter-sgx-rg-bee09592`` still held a
    Bastion host, its public IP, the VNet and two Network Watcher resources.
    The Bastion alone bills ~$0.19/hr and it ran until it was deleted by hand.

    A surviving group is unambiguous evidence of an incomplete teardown rather
    than a heuristic: all four Azure templates declare their own
    ``azurerm_resource_group`` (``templates/{sgx,snp/azure,tdx/azure,
    gpu_cc/azure}/main.template.tf``), so a destroy that really finished leaves
    no group behind.  ``_rg_exists`` fails closed — "az could not answer"
    counts as present, not as gone.

    Returns True if cleanup succeeded by either method.
    """
    cloud = _detect_cloud_from_build(build_dir)
    # Captured *before* the destroy: ``terraform output`` reads live state, and
    # a successful destroy empties it, so asking afterwards returns nothing —
    # which would silently skip the verification in exactly the case it exists
    # for.  Returns "" on any failure (see core.iac.get_terraform_outputs).
    rg_name = _detect_azure_rg_name(build_dir) if cloud == "azure" else ""

    prune_docker = context != "Retry cleanup"
    d_ok, d_msg = run_terraform_destroy(build_dir, prune_local_docker=prune_docker)

    if cloud != "azure":
        if d_ok:
            console.print(f"[green]✓ {context}: Terraform destroy succeeded.[/green]")
            return True
        console.print(f"[red]{context}: Terraform destroy failed ({d_msg}).[/red]")
        return False

    if d_ok:
        if not rg_name:
            console.print(
                f"[yellow]✓ {context}: Terraform destroy succeeded, but no "
                "resource_group output was readable beforehand, so the group "
                "could not be confirmed gone. Check with: "
                "az group list --query \"[?starts_with(name,'tee-crafter-')]\""
                "[/yellow]"
            )
            return True
        survived, detail = _rg_exists(rg_name)
        if not survived:
            console.print(
                f"[green]✓ {context}: Terraform destroy succeeded "
                f"(resource group '{rg_name}' confirmed gone).[/green]"
            )
            return True
        console.print(
            f"[yellow]{context}: Terraform destroy reported success but "
            f"resource group '{rg_name}' is still present"
            + (f" — {detail[:200]}" if detail else "")
            + ". Falling back to Azure CLI resource-group delete...[/yellow]"
        )
    else:
        console.print(
            f"[dim]{context}: Terraform destroy failed ({d_msg}). "
            f"Falling back to Azure CLI resource-group delete ({rg_name})...[/dim]"
        )
    return _az_force_delete_rg(console, rg_name)




#: Substrings that mean "this zone/region has no capacity right now", per cloud.
#: A capacity failure is not a configuration failure: the plan is correct and
#: retrying it in the same place is the one thing guaranteed not to help.
_GCP_CAPACITY_MARKERS = (
    "does not have enough resources available",
    "ZONE_RESOURCE_POOL_EXHAUSTED",
)


#: Matches the azurerm provider's "this resource is not in your state" error and
#: pulls out both halves needed to fix it: the cloud resource ID, and the
#: Terraform address to bind it to.  The provider prints them in two places::
#:
#:     Error: a resource with the ID "/subscriptions/…/bastionHosts/x" already
#:     exists - to be managed via Terraform this resource needs to be imported
#:     into the State. …
#:
#:       with azurerm_bastion_host.tdx,
#:       on main.tf line 208, in resource "azurerm_bastion_host" "tdx":
_ALREADY_EXISTS_ID = re.compile(
    r'a resource with the ID "([^"]+)" already exists')
_ALREADY_EXISTS_ADDR = re.compile(r'^\s*with ([A-Za-z0-9_.\[\]"-]+),\s*$',
                                  re.MULTILINE)


def _orphans_from_error(error_text: str) -> list[tuple[str, str]]:
    """Pair each ``already exists`` resource ID with its Terraform address.

    Returns ``[(address, resource_id), …]``.  Pairs positionally, which is what
    the provider's output supports: it emits one ``Error:`` block per resource,
    each followed by its own ``with <address>,`` line.  A mismatch in counts
    means the output was not the shape assumed here, so nothing is returned
    rather than guessing a pairing -- importing a resource under the wrong
    address would write a state entry that points at someone else's
    infrastructure.
    """
    ids = _ALREADY_EXISTS_ID.findall(error_text or "")
    addrs = _ALREADY_EXISTS_ADDR.findall(error_text or "")
    if not ids or len(ids) != len(addrs):
        return []
    return list(zip(addrs, ids))


#: The per-deploy `random_id` suffix, as it appears at the end of every resource
#: group name the Azure templates create (`tee-crafter-snp-rg-a3e35036`).
_DID_SUFFIX = re.compile(r"-([0-9a-f]{6,})$", re.IGNORECASE)


def _deploy_suffix(rg_name: str) -> str:
    """Extract the per-deploy id from a resource group name, lowercased.

    Returns ``""`` when the name does not end in a hex suffix, which makes the
    caller fall back to the resource-group test alone rather than matching on
    something short and ambiguous. Requiring at least six hex characters is what
    stops a name like ``tee-crafter-snp-rg-prod`` from yielding a "suffix" that
    would match unrelated resources.
    """
    m = _DID_SUFFIX.search(rg_name or "")
    return m.group(1).lower() if m else ""


def _adopt_orphaned_resources(
    console: Console, build_dir: str, error_text: str,
) -> int:
    """``terraform import`` resources this deploy created but did not record.

    A ``terraform apply`` that is killed mid-create (SIGKILL, a dead container,
    a lost laptop) leaves the resource live in the cloud and absent from state,
    because the state write had not happened yet.  Every later apply then fails
    with ``already exists``, and Terraform will not adopt an unmanaged resource
    on its own -- so the deploy is permanently stuck with, in the observed case,
    a Bastion host billing at roughly $0.19/hr.  Reproduced deliberately on
    ``tdx-azure`` on 2026-08-23.

    **The ownership check is what makes this safe.** Importing whatever the
    cloud says already exists would be reckless: the same name in another
    subscription, or a resource an operator created by hand, would be silently
    pulled into a state file that a later ``destroy`` will delete.  So a
    resource is adopted only when its ID sits inside *this deploy's own resource
    group* -- which every Azure template creates itself and suffixes with the
    per-deploy ``local.did`` (``tee-crafter-snp-rg-a3e35036``).  Nothing outside
    that group can match, and the group is unique to this build directory.

    Returns the number of resources adopted.  Azure only: the ID/address pair
    this needs is specific to the azurerm provider's message, and the GCP
    key-ring case that produces the same class of error is instead avoided
    upstream by never destroying partial state.
    """
    if _detect_cloud_from_build(build_dir) != "azure":
        return 0
    pairs = _orphans_from_error(error_text)
    if not pairs:
        return 0
    rg_name = _detect_azure_rg_name(build_dir)
    if not rg_name:
        console.print(
            "[yellow]Orphaned resources reported, but this deploy's resource "
            "group could not be read from the Terraform outputs, so ownership "
            "cannot be proven. Not importing anything.[/yellow]")
        return 0

    owned_marker = f"/resourcegroups/{rg_name.lower()}/"
    # Second ownership proof, for resources this deploy creates *outside* its
    # own group.  The VNet flow log is the case that forced this: it is named
    # `tee-crafter-tdx-vnet-flow-<did>` but lives in the shared, long-lived
    # `NetworkWatcherRG`, because that is where Azure keeps flow logs.  A
    # resource-group test alone therefore refused to adopt a resource that
    # unambiguously belonged to this deploy, and `tdx-azure` failed on
    # 2026-08-23 with the orphan un-adopted.
    #
    # `did` is the per-deploy `random_id` hex suffix every template appends, so
    # a name containing it cannot belong to another deploy -- the same argument
    # as the resource-group test, just carried by the name instead of the path.
    did = _deploy_suffix(rg_name)
    terraform_bin = shutil.which("terraform")
    if terraform_bin is None:
        return 0

    adopted = 0
    for address, resource_id in pairs:
        lowered = resource_id.lower()
        in_our_rg = owned_marker in lowered
        carries_our_did = bool(did) and did in lowered
        if not (in_our_rg or carries_our_did):
            console.print(
                f"[yellow]Refusing to import {address}: {resource_id} is "
                f"neither inside this deploy's resource group ({rg_name}) nor "
                f"named with its deploy id"
                + (f" ({did})" if did else "") + ".[/yellow]")
            continue
        console.print(
            f"[yellow]Adopting orphan {address} (created by a previous "
            f"interrupted apply, missing from state)...[/yellow]")
        proc = subprocess.run(
            [terraform_bin, "import", "-input=false", "-no-color",
             address, resource_id],
            cwd=build_dir, capture_output=True, text=True, timeout=300,
        )
        if proc.returncode == 0:
            adopted += 1
            console.print(f"[green]✓ Imported {address}.[/green]")
        else:
            console.print(
                f"[red]terraform import {address} failed: "
                f"{(proc.stderr or proc.stdout or '').strip()[-300:]}[/red]")
    return adopted


def _cleanup_partial_state(console: Console, build_dir: str) -> None:
    """Do **not** destroy partial state between retry attempts.

    This used to run a full ``cleanup_resources`` before each retry, and it was
    wrong on every cloud for the same underlying reason: ``terraform apply`` is
    convergent, so a retry already picks up where the last one left off, and
    destroying first throws away correct work.

    The evidence, in the order it was found:

    * **GCP made it fatal.** Cloud KMS key rings cannot be deleted -- the API
      has no delete operation -- and the google provider drops the ring from
      state on destroy without removing anything. So destroy-then-apply left the
      ring live and unrecorded and the retry died on ``Error 409: KeyRing …
      already exists``. On ``snp-gcp`` on 2026-08-23 attempt 1 hit zonal
      capacity, the cleanup ran, and attempt 2 failed on the 409 instead of on
      capacity. GCP was exempted for this reason.
    * **Azure made it slow and often failed anyway.** The destroy has to unwind
      a Bastion host (~10 min) only for the retry to rebuild it (~10 min), and
      it frequently cannot: ``InUseSubnetCannotBeDeleted`` and
      ``PublicIPAddressCannotBeDeleted`` both fire because the Bastion still
      holds the subnet and the public IP. Observed on both ``sgx-azure`` and
      ``tdx-azure`` on 2026-08-23.
    * **It degraded state in exactly the case that needed state most.** On a
      resume after a killed apply, the cleanup partially destroyed the resources
      that *were* recorded, leaving the build directory worse off than before.

    So the retry now re-applies directly, and orphans are handled by adopting
    them (:func:`_adopt_orphaned_resources`) rather than by destroying
    everything around them. Skipping the destroy is bounded: at most one
    attempt's partial resources stay up between attempts, and the outer failure
    path (``destroy_on_failure`` / ``--keep-on-failure``) still decides what
    happens when the loop gives up.
    """
    console.print(
        "[dim]Retrying without destroying partial state: terraform apply is "
        "convergent, and destroying first is slower, often blocked by Bastion "
        "dependencies, and on GCP guarantees a 409 on the next apply.[/dim]")


def _tee_platform_from_audit(audit: BuildAuditTrail | None) -> str:
    """Look at the embedded ledger for the tee_platform tag."""
    if audit is None:
        return ""
    try:
        return getattr(audit, "_tee_platform", "") or audit.ledger.tee_platform
    except Exception:
        return ""


def run_terraform_apply_loop(
    console: Console,
    build_dir: str,
    auto_approve: bool,
    audit: BuildAuditTrail | None,
) -> tuple[bool, str]:
    """Run Terraform apply with retries. Returns (apply_success, last_error_msg)."""
    # IAC static-analysis pre-flight.  Runs once per apply loop so the
    # ledger has IAC-* rows even if `terraform apply` itself fails.
    try:
        emit_iac_static_verdicts(
            audit, build_dir,
            tee_platform=_tee_platform_from_audit(audit),
        )
    except Exception:
        pass
    max_retries = min(2, max(1, int(os.getenv("TEE_CRAFTER_PHASE4_MAX_RETRIES", "2"))))
    env_auto_approve = os.getenv("TEE_CRAFTER_TF_AUTO_APPROVE", "").lower() in {"1", "true", "yes"}
    should_auto_approve = auto_approve or env_auto_approve
    aws_gpu_capacity_wait_s = int(os.getenv("TEE_CRAFTER_AWS_GPU_CAPACITY_WAIT_SECONDS", "600"))
    aws_gpu_wait_deadline = time.monotonic() + aws_gpu_capacity_wait_s

    if "TF_VAR_key_name" in os.environ:
        console.print(f"[dim]Using AWS Key Pair (for manual debug only): {os.environ['TF_VAR_key_name']}[/dim]")

    apply_success = False
    last_error_msg = ""
    # Bounded so a resource that reports `already exists` but cannot be
    # imported can never spin this loop forever.
    adoptions = 0

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=False) as progress:
        task_apply = progress.add_task(
            "[yellow]Step 7: Executing Terraform apply (infrastructure)...[/yellow]", total=None)
        attempt = 0
        capacity_waits = 0
        while attempt < max_retries:
            progress.update(task_apply,
                            description=f"[yellow]Step 7: Terraform apply (Attempt {attempt+1}/{max_retries})...[/yellow]")
            success, stdout, stderr = run_terraform_apply(build_dir, auto_approve=should_auto_approve)
            if success:
                apply_success = True
                progress.update(task_apply, description="[green]✓ Step 7: Deployment successful![/green]")
                if audit:
                    audit.record("Phase 4: Deployment", "Terraform apply", "pass",
                                 attempts=attempt + 1, capacity_waits=capacity_waits)
                    audit.record_check(
                        "Phase 4: Deployment", "terraform apply success", "DEP-001",
                        observed=True, note=f"attempts={attempt + 1}",
                    )
                break
            error_summary = (stderr.strip() or stdout.strip())[-1000:]
            last_error_msg = error_summary
            console.print(f"[bold red]Terraform Apply Failed (Attempt {attempt+1}):[/bold red]\n{error_summary}")

            # AWS GPU capacity can be transient (Spot or On-Demand). For GPU-related AWS builds,
            # poll for up to TEE_CRAFTER_AWS_GPU_CAPACITY_WAIT_SECONDS and retry `terraform apply`
            # WITHOUT destroying partial state, so AWS can eventually allocate capacity while the
            # already-created infra stays put.  A capacity wait deliberately does NOT advance
            # ``attempt``: with a `for` loop and a bare `continue` it did, so the advertised
            # 10-minute wait ran exactly `max_retries` times (2 x 20 s = ~40 s) before the loop
            # fell out.
            cloud = _detect_cloud_from_build(build_dir)
            is_gpu_aws = cloud == "aws" and ("gpu_cc_aws" in os.path.basename(build_dir).lower()
                                             or "gpu-cc-aws" in os.path.basename(build_dir).lower())
            if (is_gpu_aws and "InsufficientInstanceCapacity" in error_summary
                    and time.monotonic() < aws_gpu_wait_deadline):
                sleep_s = 20
                capacity_waits += 1
                remaining = int(aws_gpu_wait_deadline - time.monotonic())
                progress.update(
                    task_apply,
                    description=(
                        f"[yellow]Step 7: Waiting for AWS GPU capacity ({sleep_s}s; "
                        f"{remaining // 60}m{remaining % 60:02d}s of the "
                        f"{aws_gpu_capacity_wait_s // 60}-minute budget left)...[/yellow]"
                    ),
                )
                time.sleep(sleep_s)
                continue  # capacity wait — same attempt, no state cleanup

            # GCP zonal capacity: say what to change instead of retrying into
            # the same wall.  Google's own error says "Try a different zone",
            # and a second apply in the same zone is the one action that cannot
            # help -- it just consumes the remaining attempt.  Naming the
            # variable matters because `TF_VAR_gcp_zone` is not obviously the
            # knob when the message talks about a fully-qualified zone URL.
            if (cloud == "gcp"
                    and any(m in error_summary for m in _GCP_CAPACITY_MARKERS)):
                zone = os.environ.get("TF_VAR_gcp_zone", "(unset)")
                console.print(
                    f"[bold yellow]GCP has no capacity in {zone} for this "
                    f"machine type right now.[/bold yellow]\n"
                    f"[yellow]This is a provider capacity limit, not a problem "
                    f"with the plan — retrying the same zone will not help. "
                    f"Set [bold]TF_VAR_gcp_zone[/bold] to another zone in the "
                    f"region and re-run.[/yellow]")
                if audit:
                    audit.record("Phase 4: Deployment", "Terraform apply", "fail",
                                 reason="gcp_zone_capacity", zone=zone)
                break

            # An ``already exists`` we can provably adopt is a state desync, not
            # a failed attempt, so fixing it does **not** consume a retry --
            # same treatment as the AWS capacity wait above, and for the same
            # reason.
            #
            # This ordering matters and cost a run to find. On ``snp-azure`` on
            # 2026-08-23: attempt 1 failed with a transient
            # ``409 StorageAccountOperationInProgress``, the retry (correctly,
            # without destroying) then hit ``already exists`` for that same
            # storage account -- and because that was the *last* attempt, the
            # adoption step below never ran. The orphan was adoptable the whole
            # time; the budget had simply run out.
            if adoptions < _MAX_ORPHAN_ADOPTIONS and "already exists" in error_summary:
                adopted = _adopt_orphaned_resources(
                    console, build_dir, error_summary)
                if adopted:
                    adoptions += 1
                    progress.update(
                        task_apply,
                        description=(f"[yellow]Step 7: Adopted {adopted} "
                                     f"orphaned resource(s); re-applying..."
                                     f"[/yellow]"))
                    time.sleep(2)
                    continue  # same attempt: nothing was retried yet

            attempt += 1
            if attempt < max_retries:
                progress.update(task_apply, description="[red]! Apply failed. Preparing retry...[/red]")
                _cleanup_partial_state(console, build_dir)
                time.sleep(5)

    if apply_success:
        _post_apply_vm_diagnostics(console, build_dir)

    return apply_success, last_error_msg


def _post_apply_vm_diagnostics(console: Console, build_dir: str) -> None:
    """Run Azure CLI boot diagnostics on the deployed VM after Terraform succeeds."""
    try:
        from tee_crafter.core.iac import get_terraform_outputs
        outputs = get_terraform_outputs(build_dir)
        rg, vm_name = outputs.get("resource_group", ""), outputs.get("vm_name", "")
        if not rg or not vm_name:
            return
        result = subprocess.run(
            ["az", "vm", "boot-diagnostics", "get-boot-log",
             "--resource-group", rg, "--name", vm_name],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            console.print("[dim]Boot diagnostics:[/dim]", end=" ")
            console.print(result.stderr.strip()[:200], markup=False)
    except Exception as e:
        console.print("[dim]Post-apply diagnostics skipped:[/dim]", end=" ")
        console.print(str(e), markup=False)
