"""Platform-specific Terraform staging + terraform apply/destroy execution."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Tuple, Dict, Any

from tee_crafter.core.iac.iac import stage_provider_lock
from tee_crafter.core.env_flags import env_hatch_open


#: Default wall-clock budget for ``terraform destroy``.
#:
#: This was 900 s, which is shorter than a routine Azure resource-group delete
#: (Bastion + VNet + managed-disk teardown regularly exceeds 30 minutes).  A
#: timeout is reported as a failure, and the post-destroy secret shred only runs
#: on success — so the short budget meant a *successful but slow* teardown left
#: SSH private keys and ``siem.env`` / ``byok.env`` behind in the build
#: directory while telling the operator the destroy had failed.
_DESTROY_TIMEOUT_DEFAULT = 2700  # 45 minutes


def _destroy_timeout_seconds() -> int:
    """Wall-clock budget for ``terraform destroy``, overridable for slow tenants."""
    raw = os.environ.get("TEE_CRAFTER_DESTROY_TIMEOUT", "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return _DESTROY_TIMEOUT_DEFAULT


def _stage_measurement_terraform(build_dir, terraform_code, replacements,
                                 fallback_label, template_subdir=""):
    """Generic Terraform staging: inject measurement variable defaults and write main.tf.

    *template_subdir* names the directory under ``templates/`` this platform's
    HCL came from, so the provider lockfile shipped beside it can be staged into
    *build_dir*.  ``terraform init`` only honours a lockfile in its own working
    directory, so skipping this silently un-pins every provider.
    """
    os.makedirs(build_dir, exist_ok=True)
    if template_subdir:
        stage_provider_lock(build_dir, template_subdir)
    processed = terraform_code
    for var_name, value in replacements.items():
        if value:
            processed = processed.replace(
                f'variable "{var_name}" {{\n  type        = string\n  default     = ""',
                f'variable "{var_name}" {{\n  type        = string\n  default     = "{value}"',
            )
    final = processed.strip()
    if not final:
        final = terraform_code.strip() or f"# {fallback_label} Terraform generation produced no output"
    main_tf_path = os.path.join(build_dir, "main.tf")
    with open(main_tf_path, "w", encoding="utf-8") as f:
        f.write(final)
    return main_tf_path


def stage_sgx_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"mrenclave": m.get("MRENCLAVE", ""), "mrsigner": m.get("MRSIGNER", "")}, "SGX",
        template_subdir="sgx")


def stage_tdx_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"mrtd": m.get("MRTD", "")}, "TDX",
        template_subdir="tdx/azure")


def stage_snp_aws_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"measurement": m.get("measurement", "")}, "SNP AWS",
        template_subdir="snp/aws")


def stage_snp_azure_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"measurement": m.get("measurement", "")}, "SNP Azure",
        template_subdir="snp/azure")


def stage_snp_gcp_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"measurement": m.get("measurement", "")}, "SNP GCP",
        template_subdir="snp/gcp")


def stage_tdx_gcp_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"mrtd": m.get("MRTD", "")}, "TDX GCP",
        template_subdir="tdx/gcp")


def stage_gpu_cc_gcp_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"mrtd": m.get("MRTD", "")}, "GPU CC GCP",
        template_subdir="gpu_cc/gcp")


def stage_gpu_cc_azure_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"measurement": m.get("measurement", "")}, "GPU CC Azure",
        template_subdir="gpu_cc/azure")


def stage_gpu_cc_aws_terraform(build_dir, terraform_code, measurements=None) -> str:
    m = measurements or {}
    return _stage_measurement_terraform(build_dir, terraform_code,
        {"measurement": m.get("measurement", "")}, "GPU CC AWS",
        template_subdir="gpu_cc/aws")


def _try_import_existing_gcp_resources(build_dir: str, terraform_bin: str) -> None:
    """Best-effort import of pre-existing GCP resources into Terraform state.

    Prevents 409 ``alreadyExists`` errors when redeploying over remnants of
    a previous teardown that left VPC / service-account / firewall resources
    still present in the GCP project.  Each import is attempted independently;
    failures (resource absent, already in state) are silently ignored.
    """
    main_tf = os.path.join(build_dir, "main.tf")
    if not os.path.isfile(main_tf):
        return
    with open(main_tf, "r", encoding="utf-8") as f:
        content = f.read(4000)
    if "hashicorp/google" not in content:
        return

    if "tee-crafter-snp-" in content:
        prefix = "snp"
    elif "tee-crafter-tdx-" in content:
        prefix = "tdx"
    else:
        return

    project = os.environ.get("TF_VAR_gcp_project", "")
    if not project:
        return
    region = os.environ.get("TF_VAR_gcp_region", "us-central1")

    imports = [
        ("google_compute_network.vpc",
         f"projects/{project}/global/networks/tee-crafter-{prefix}-vpc"),
        ("google_compute_subnetwork.subnet",
         f"projects/{project}/regions/{region}/subnetworks/tee-crafter-{prefix}-subnet"),
        ("google_compute_firewall.allow_iap_ssh",
         f"projects/{project}/global/firewalls/tee-crafter-{prefix}-allow-iap-ssh"),
        ("google_compute_firewall.deny_all_ingress",
         f"projects/{project}/global/firewalls/tee-crafter-{prefix}-deny-ingress"),
        ("google_compute_firewall.allow_egress_internal",
         f"projects/{project}/global/firewalls/tee-crafter-{prefix}-allow-egress-internal"),
        ("google_compute_firewall.allow_egress_metadata",
         f"projects/{project}/global/firewalls/tee-crafter-{prefix}-allow-egress-metadata"),
        ("google_compute_firewall.allow_egress_dns",
         f"projects/{project}/global/firewalls/tee-crafter-{prefix}-allow-egress-dns"),
        ("google_compute_firewall.deny_all_egress",
         f"projects/{project}/global/firewalls/tee-crafter-{prefix}-deny-egress"),
        ("google_service_account.vm_sa",
         f"projects/{project}/serviceAccounts/tee-crafter-{prefix}-vm@{project}.iam.gserviceaccount.com"),
    ]

    for tf_addr, gcp_id in imports:
        try:
            subprocess.run(
                [terraform_bin, "import", "-input=false", "-no-color", tf_addr, gcp_id],
                cwd=build_dir, capture_output=True, text=True, timeout=60,
            )
        except Exception:
            pass


def run_terraform_apply(
    build_dir: str, auto_approve: bool = False, timeout_seconds: int = 3600
) -> Tuple[bool, str, str]:
    """Run ``terraform apply`` in the build directory.

    Returns (success, stdout, stderr).
    """
    terraform_bin = shutil.which("terraform")
    if terraform_bin is None:
        return (
            False, "",
            "Terraform is not installed or not in PATH. Install Terraform to enable deployment.",
        )

    cmd = [terraform_bin, "apply", "-input=false", "-no-color"]
    if auto_approve:
        cmd.append("-auto-approve")

    try:
        subprocess.run(
            [terraform_bin, "init", "-input=false", "-no-color"],
            cwd=build_dir, check=True, capture_output=True, text=True, timeout=120,
        )
        _try_import_existing_gcp_resources(build_dir, terraform_bin)
        result = subprocess.run(
            cmd, cwd=build_dir, check=True, capture_output=True, text=True, timeout=timeout_seconds,
        )
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as exc:
        return False, exc.stdout or "", exc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return (
            False,
            exc.stdout or "" if hasattr(exc, "stdout") else "",
            f"Terraform apply timed out after {timeout_seconds} seconds. {exc.stderr or ''}",
        )
    except Exception as e:
        return False, "", str(e)


def run_terraform_destroy(
    build_dir: str, *, prune_local_docker: bool = True,
) -> Tuple[bool, str]:
    """Run ``terraform destroy -auto-approve``. Returns (success, message).

    Always passes ``-refresh=false``. Our Azure templates lock down the
    artifacts storage account's data plane to the VM subnet via
    ``azurerm_storage_account_network_rules`` (with
    ``default_action = "Deny"``). Terraform's pre-destroy refresh calls
    the blob data-plane API to read ``azurerm_storage_container`` and
    gets ``403 AuthorizationFailure`` because the deployer is outside
    the allowed subnet. Skipping refresh lets destroy build the plan
    from state and apply it in reverse-dependency order — the network
    rules resource is destroyed first (control-plane PATCH that resets
    ``default_action`` to ``Allow``), which re-opens data-plane access
    in time for the container and account deletes to succeed.

    The flag is also safe for the AWS / GCP flows: the AzureRM, AWS and
    Google providers all treat a 404 from the cloud's delete API as a
    successful destroy, so a stale state row that no longer exists in
    the cloud will not cause the destroy to error.

    When *prune_local_docker* is True (default), removes only the Docker image tag
    recorded for this *build_dir* (``local_pipeline_image.txt`` from container deploy).
    Skipped for Terraform retry cleanup.  Set ``TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE=1``
    to disable.  Non-container builds have no marker file and are a no-op.
    """
    terraform_bin = shutil.which("terraform")
    if terraform_bin is None:
        return False, "Terraform is not installed or not in PATH."

    ok, msg = False, ""
    try:
        subprocess.run(
            [terraform_bin, "init", "-input=false", "-no-color"],
            cwd=build_dir, check=True, capture_output=True, text=True, timeout=120,
        )
        _try_import_existing_gcp_resources(build_dir, terraform_bin)
        subprocess.run(
            [terraform_bin, "destroy", "-auto-approve", "-input=false",
             "-no-color", "-refresh=false"],
            cwd=build_dir, check=True, capture_output=True, text=True,
            timeout=_destroy_timeout_seconds(),
        )
        ok, msg = True, "Resources destroyed successfully."
    except subprocess.CalledProcessError as exc:
        err = exc.stderr or exc.stdout or str(exc)
        ok, msg = False, f"Terraform destroy failed: {err}"
    except subprocess.TimeoutExpired:
        # A timeout is NOT the same as a failure: the provider may still be
        # deleting.  Azure resource-group deletes routinely exceed 30 min, and
        # the previous hard-coded 900 s made a slow-but-successful teardown look
        # like a failure — which then skipped the secret shred below, silently
        # leaving SSH keys and siem/byok env files in the build directory.
        ok, msg = False, (
            f"Terraform destroy timed out after {_destroy_timeout_seconds()}s. "
            "The provider may still be deleting — check the cloud console before "
            "re-running. Secrets in the build directory were NOT shredded; run "
            "`tee-crafter destroy` again once deletion completes, or shred the "
            "directory manually."
        )
    except Exception as e:
        ok, msg = False, f"Terraform destroy failed: {str(e)}"
    finally:
        # Post-destroy secret shred — only when destroy actually succeeded.
        # If destroy failed we keep the files so the operator can re-run with
        # the same SSH key / state to finish teardown.  Disable via
        # ``TEE_CRAFTER_SKIP_POST_DESTROY_SHRED=1`` if you want to archive
        # the build dir as-is for forensics.
        if ok and not env_hatch_open("TEE_CRAFTER_SKIP_POST_DESTROY_SHRED"):
            try:
                from tee_crafter.core.iac.post_destroy_shred import (
                    shred_post_destroy,
                )

                shred_post_destroy(build_dir)
            except Exception:
                pass
        if prune_local_docker:
            try:
                from tee_crafter.cli.deployment.common.local_docker_prune import (
                    prune_pipeline_local_image,
                )

                prune_pipeline_local_image(build_dir)
            except Exception:
                pass
    return ok, msg
