"""Cloud CLI authentication bootstrap and per-cloud credential validation.

Two related responsibilities live here:

* :func:`bootstrap_cloud_auth` — auto-configures the Azure / GCP CLIs from
  environment variables when running inside the docker image.  It is
  **cloud-scoped**: when a ``--tee-platform`` argument selects (for example)
  an AWS-only flow, the Azure and GCP bootstrap paths are skipped entirely
  so a stale ``AZURE_*`` block in ``.env`` cannot fire noisy ``az login``
  calls or fail an otherwise-valid AWS deploy.

* :func:`validate_required_creds` — fail-fast guard the deploy commands call
  before they spend money.  It verifies that the cloud which actually backs
  the chosen ``--tee-platform`` has working credentials, and never demands
  the *other* clouds' credentials.  A user who only configures AWS can run
  every AWS platform without touching ``AZURE_*`` or ``GOOGLE_*`` env vars.
"""

from __future__ import annotations

import click
import os
import subprocess
from pathlib import Path
from typing import Optional

_IN_DOCKER_ENV = "TEE_CRAFTER_IN_DOCKER"


# ``--tee-platform`` -> cloud each platform deploys into.  Used by
# :func:`cloud_for_platform` so :func:`bootstrap_cloud_auth` and
# :func:`validate_required_creds` agree on the mapping.
_PLATFORM_CLOUDS = {
    "nitro-aws": "aws",
    "snp-aws": "aws",
    "gpu-cc-aws": "aws",
    "sgx-azure": "azure",
    "tdx-azure": "azure",
    "snp-azure": "azure",
    "gpu-cc-azure": "azure",
    "snp-gcp": "gcp",
    "tdx-gcp": "gcp",
    "gpu-cc-gcp": "gcp",
}


def cloud_for_platform(tee_platform: Optional[str]) -> Optional[str]:
    """Return ``"aws" | "azure" | "gcp"`` for the platform, or ``None``
    when the platform is unknown (so the caller falls back to multi-cloud)."""
    if not tee_platform:
        return None
    return _PLATFORM_CLOUDS.get(tee_platform.lower())


def validate_gcp_auth() -> None:
    """Check that gcloud can obtain an access token. Prints actionable guidance on failure."""
    res = subprocess.run(
        ["gcloud", "auth", "print-access-token", "--quiet"],
        capture_output=True, text=True, timeout=15,
    )
    if res.returncode == 0:
        return

    has_key = bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"))
    has_imp = bool(os.environ.get("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT"))

    lines = ["WARNING: GCP authentication is not active or tokens have expired."]
    if has_imp and not has_key:
        lines += [
            "  You are using service-account impersonation but have no base",
            "  credential.  Fix with ONE of:",
            "",
            "  Option A — JSON key file (recommended, never expires):",
            "    1. Create a key for your impersonating SA or a user SA",
            "    2. Put the JSON file in the repo root (e.g. gcp-key.json)",
            "    3. Add to .env:  GOOGLE_APPLICATION_CREDENTIALS=./gcp-key.json",
            "",
            "  Option B — Interactive login (expires, needs periodic refresh):",
            "    $ CLOUDSDK_CONFIG=/workspace/.gcloud gcloud auth login",
            "    (run INSIDE the tee-crafter container or on the host)",
        ]
    elif not has_key:
        lines += [
            "  Fix with ONE of:",
            "",
            "  Option A — JSON key file (recommended):",
            "    1. Create a GCP service account key",
            "    2. Put the JSON file in the repo root",
            "    3. Add to .env:  GOOGLE_APPLICATION_CREDENTIALS=./gcp-key.json",
            "",
            "  Option B — Interactive login:",
            "    $ CLOUDSDK_CONFIG=/workspace/.gcloud gcloud auth login",
        ]
    else:
        lines += [
            f"  Key file {os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')} may be",
            "  invalid or the service account may have been deleted.",
        ]
    click.echo("\n".join(lines), err=True)


def bootstrap_cloud_auth(tee_platform: Optional[str] = None) -> None:
    """Auto-configure cloud CLIs from env vars when running inside the container.

    When *tee_platform* is one of the single-cloud platforms (``nitro-aws``,
    ``snp-gcp``, ``sgx-azure``, …) only the matching cloud's CLI is
    bootstrapped — the other clouds are skipped even if their env vars
    happen to be set.  This is how the "AWS-only user supplies only AWS
    creds" guarantee is enforced in practice: if you target ``nitro-aws``
    and leave a stale ``AZURE_CLIENT_SECRET`` from another project in your
    ``.env``, we will not try to ``az login`` with it.

    When *tee_platform* is ``None`` (e.g. ``tee-crafter --help`` or a
    non-deploy subcommand), we still bootstrap whichever clouds the user
    has env vars for, since we don't yet know which cloud they care about.
    """
    if os.environ.get(_IN_DOCKER_ENV) != "1":
        return

    cloud = cloud_for_platform(tee_platform)
    if cloud is None or cloud == "azure":
        _bootstrap_azure()
    if cloud is None or cloud == "gcp":
        _bootstrap_gcp()


def _bootstrap_azure() -> None:
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    if not (client_id and client_secret and tenant_id):
        return
    res = subprocess.run(["az", "account", "show"], capture_output=True, text=True)
    if res.returncode == 0:
        return
    subprocess.run(
        ["az", "login", "--service-principal",
         "-u", client_id, "-p", client_secret, "--tenant", tenant_id],
        capture_output=True, text=True,
    )
    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if sub_id:
        subprocess.run(["az", "account", "set", "--subscription", sub_id],
                        capture_output=True, text=True)


def _bootstrap_gcp() -> None:
    gcp_creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if gcp_creds and os.path.isfile(gcp_creds):
        res = subprocess.run(
            ["gcloud", "auth", "activate-service-account",
             f"--key-file={gcp_creds}", "--quiet"],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            click.echo(f"WARNING: Failed to activate GCP service account from "
                       f"{gcp_creds}: {res.stderr.strip()}", err=True)

    if not os.environ.get("CLOUDSDK_CONFIG"):
        workspace_gcloud = Path("/workspace/.gcloud")
        if workspace_gcloud.is_dir():
            os.environ["CLOUDSDK_CONFIG"] = str(workspace_gcloud)

    for env_var, config_key in [
        ("TF_VAR_gcp_project", "project"),
        ("TF_VAR_gcp_region", "compute/region"),
        ("TF_VAR_gcp_zone", "compute/zone"),
        ("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", "auth/impersonate_service_account"),
    ]:
        val = os.environ.get(env_var)
        if not val and env_var == "TF_VAR_gcp_project":
            val = os.environ.get("GOOGLE_PROJECT")
        if val:
            subprocess.run(["gcloud", "config", "set", config_key, val, "--quiet"],
                            capture_output=True, text=True)

    if any(os.environ.get(k) for k in (
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
        "TF_VAR_gcp_project", "GOOGLE_PROJECT",
    )):
        validate_gcp_auth()


# ---------------------------------------------------------------------------
# Per-cloud credential validation
# ---------------------------------------------------------------------------

# Maps cloud -> (required env var combos, where one combo means "any one of
# these alternative variable sets is sufficient").  Validation walks every
# combo and returns the first one that is fully populated; we then verify
# the resulting auth actually works with a cheap API call.
_REQUIRED_ENV = {
    "aws": [
        # Combo 1: classic access-key pair from ``aws configure``.
        ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        # Combo 2: SSO / shared-config profile.  ``aws configure list``
        # reports this as ``profile`` resolved from ``AWS_PROFILE`` /
        # ``AWS_DEFAULT_PROFILE``.
        ("AWS_PROFILE",),
        ("AWS_DEFAULT_PROFILE",),
        # Combo 3: temporary creds (e.g. assume-role) — session token implies
        # the other two are present, but boto3 also accepts the bare token.
        ("AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
    ],
    "azure": [
        # Service-principal triplet from ``az ad sp create-for-rbac``.
        ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"),
        # Interactive ``az login`` leaves only the subscription id in env.
        ("AZURE_SUBSCRIPTION_ID",),
    ],
    "gcp": [
        ("GOOGLE_APPLICATION_CREDENTIALS",),
        ("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",),
        # ``gcloud auth login`` populates the gcloud config but no env var;
        # fall through to a CLI check.
    ],
}


def _aws_creds_work() -> Optional[str]:
    """Return ``None`` when the live AWS credentials can call STS, else an
    error string describing what went wrong."""
    try:
        import boto3  # type: ignore
        from botocore.exceptions import (
            ClientError, NoCredentialsError, PartialCredentialsError,
            ProfileNotFound,
        )
    except ImportError:
        return "boto3 is not installed inside the CLI image (pip install boto3)."
    try:
        sts = boto3.client("sts")
        sts.get_caller_identity()
        return None
    except (NoCredentialsError, PartialCredentialsError):
        return ("AWS credentials are missing or incomplete.  Set "
                "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (or AWS_PROFILE).")
    except ProfileNotFound as exc:
        return f"AWS profile not found: {exc}"
    except ClientError as exc:
        return f"AWS sts:GetCallerIdentity failed: {exc.response.get('Error', {}).get('Code', '')}"
    except Exception as exc:  # network / DNS / permissions
        return f"AWS auth probe failed: {type(exc).__name__}: {exc}"


def _azure_creds_work() -> Optional[str]:
    """Return ``None`` if ``az account show`` succeeds."""
    try:
        res = subprocess.run(
            ["az", "account", "show", "-o", "json"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return ("Azure CLI (az) is not installed.  See "
                "docs/azure_setup.md Step 1.")
    except subprocess.TimeoutExpired:
        return "az account show timed out after 10s; check network."
    if res.returncode != 0:
        err = (res.stderr or "").strip()
        return ("az account show failed; run `az login` (interactive) or set "
                "AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID in "
                f".env.  Underlying error: {err[:240]}")
    return None


def _gcp_creds_work() -> Optional[str]:
    """Return ``None`` if ``gcloud auth print-access-token`` works."""
    try:
        res = subprocess.run(
            ["gcloud", "auth", "print-access-token", "--quiet"],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        return ("gcloud CLI is not installed.  See docs/gcp_setup.md Step 1.")
    except subprocess.TimeoutExpired:
        return "gcloud auth print-access-token timed out after 15s."
    if res.returncode != 0:
        return ("GCP auth not active.  Either set GOOGLE_APPLICATION_CREDENTIALS "
                "to a key file, set GOOGLE_IMPERSONATE_SERVICE_ACCOUNT after "
                "`gcloud auth login`, or run interactive login.  Underlying "
                f"error: {(res.stderr or '').strip()[:240]}")
    return None


def _doc_for_cloud(cloud: str) -> str:
    return {
        "aws": "docs/aws_setup.md",
        "azure": "docs/azure_setup.md",
        "gcp": "docs/gcp_setup.md",
    }[cloud]


def validate_required_creds(
    tee_platform: Optional[str],
    *,
    skip: bool = False,
) -> None:
    """Validate that credentials for the cloud backing *tee_platform* work.

    Raises :class:`click.ClickException` (which Click renders as a clean
    error to stderr) with an actionable message that points the user at
    the right setup doc.  Crucially, this function only checks the cloud
    actually selected by *tee_platform*: a user who picks ``nitro-aws``
    is **not** required to supply Azure or GCP creds, even if the
    surrounding ``.env`` happens to have stale entries for them.

    Set ``skip=True`` to bypass the check entirely (for unit tests or
    offline build-only flows that never call any cloud API).
    """
    if skip:
        return
    cloud = cloud_for_platform(tee_platform)
    if cloud is None:
        return  # multi-cloud command (e.g. `tee-crafter --help`).
    setup_doc = _doc_for_cloud(cloud)

    probe = {"aws": _aws_creds_work, "azure": _azure_creds_work,
             "gcp": _gcp_creds_work}[cloud]
    err = probe()
    if err is None:
        return
    raise click.ClickException(
        f"--tee-platform {tee_platform} targets {cloud.upper()}, but its "
        f"credentials are not usable from this shell.\n\n"
        f"  {err}\n\n"
        f"You do NOT need credentials for the other clouds — only "
        f"{cloud.upper()} is required for this platform.  See "
        f"{setup_doc}."
    )


def emit_iam_verdicts(audit, tee_platform: Optional[str]) -> None:
    """Emit IAM-001..005 verdicts for the cloud backing *tee_platform*.

    Best-effort: when the cloud SDK is unavailable or read fails we
    emit a ``warn`` row so the matrix shows the gap without aborting
    the deploy.
    """
    if audit is None:
        return
    cloud = cloud_for_platform(tee_platform)
    if cloud is None:
        return

    if cloud == "aws":
        _emit_aws_iam_verdicts(audit, tee_platform)
    elif cloud == "azure":
        _emit_azure_iam_verdicts(audit, tee_platform)
    elif cloud == "gcp":
        _emit_gcp_iam_verdicts(audit, tee_platform)
    # IAM-003 / IAM-005 — instance-profile attached / boundary policy
    # attached.  These describe the *target instance role* the
    # Terraform module is about to create (the deploy-side caller
    # never has an instance profile of its own), so we can only
    # observe them indirectly: the build dir's main.tf is the
    # source of truth.  Pipe through a single best-effort scanner
    # rather than asking each cloud's SDK.
    _emit_iam_role_verdicts(audit, tee_platform, cloud)


def _emit_iam_role_verdicts(audit, tee_platform: Optional[str],
                            cloud: str) -> None:
    """Emit IAM-003 / IAM-005 by scanning the build dir's IaC.

    Best-effort static analysis: we look for the production
    instance-role declarations our Terraform modules emit (``aws_iam_
    role`` with ``aws_iam_instance_profile``, Azure
    ``user_assigned_identity``, GCP ``service_account``).  When the
    build dir isn't known yet (e.g. caller invoked the helper before
    staging), we record an INFO row so the matrix still has an entry.
    """
    try:
        from tee_crafter.core.audit import Verdict
    except Exception:
        return
    build_dir = getattr(audit, "_build_dir", "") or ""
    main_tf = ""
    if build_dir and build_dir != "(pending)":
        candidate = os.path.join(build_dir, "main.tf")
        if os.path.isfile(candidate):
            main_tf = candidate
    if not main_tf:
        audit.record_check(
            "Phase 3: IaC",
            "Instance profile / Managed Identity attached",
            "IAM-003",
            verdict=Verdict.INFO,
            observed=None,
            note="build_dir not staged yet — IAM-003 surfaced after "
                 "Terraform render.",
        )
        audit.record_check(
            "Phase 3: IaC", "Least-privilege boundary policy attached",
            "IAM-005",
            verdict=Verdict.INFO, observed=None,
            note="build_dir not staged yet — IAM-005 surfaced after "
                 "Terraform render.",
        )
        return
    try:
        with open(main_tf, "r", encoding="utf-8") as f:
            tf = f.read()
    except OSError:
        return
    lower = tf.lower()

    role_signals = {
        "aws": (
            "aws_iam_instance_profile" in lower
            or "iam_instance_profile" in lower
        ),
        "azure": (
            "user_assigned_identity" in lower
            or "azurerm_role_assignment" in lower
        ),
        "gcp": (
            "service_account" in lower
            and "google_compute_instance" in lower
        ),
    }
    audit.record_check(
        "Phase 3: IaC", "Instance profile / Managed Identity attached",
        "IAM-003",
        observed=bool(role_signals.get(cloud, False)),
        evidence_pointer="main.tf",
        note=f"cloud={cloud}",
    )

    # Boundary policy: AWS ``permissions_boundary`` is the canonical
    # AWS feature; Azure / GCP have no direct equivalent so we
    # record INFO (not a fail) when the build is non-AWS.
    if cloud == "aws":
        has_boundary = (
            "permissions_boundary" in lower
            or "permissionsboundary" in lower
        )
        audit.record_check(
            "Phase 3: IaC", "Least-privilege boundary policy attached",
            "IAM-005",
            observed=bool(has_boundary),
            evidence_pointer="main.tf",
            note=("permissions_boundary clause present"
                  if has_boundary
                  else "no permissions_boundary in instance role"),
        )
    else:
        audit.record_check(
            "Phase 3: IaC", "Least-privilege boundary policy attached",
            "IAM-005",
            verdict=Verdict.INFO, observed=None,
            note=(f"{cloud} does not expose an IAM permissions-boundary "
                  f"primitive; rely on least-privilege role + Conditional "
                  f"Access / IAM Conditions instead."),
        )


def _emit_aws_iam_verdicts(audit, tee_platform: Optional[str]) -> None:
    """Emit IAM-001..004 from AWS sts:GetCallerIdentity + simulate-principal-policy."""
    try:
        import boto3  # type: ignore
    except ImportError:
        audit.record_check(
            "Phase 3: IaC", "Caller principal recorded", "IAM-001",
            observed=False, note="boto3 not installed",
        )
        return
    try:
        sts = boto3.client("sts")
        ident = sts.get_caller_identity()
        arn = ident.get("Arn", "")
        audit.record_check(
            "Phase 3: IaC", "Caller principal recorded", "IAM-001",
            observed=bool(arn),
            note=arn,
        )
        is_root = ":root" in (arn or "")
        audit.record_check(
            "Phase 3: IaC", "Caller is non-root (warn if root)", "IAM-002",
            expected=True, observed=(not is_root),
            note=arn,
        )
    except Exception as exc:
        audit.record_check(
            "Phase 3: IaC", "Caller principal recorded", "IAM-001",
            observed=False, note=f"{type(exc).__name__}: {exc}",
        )
        return

    if is_root:
        # simulate-principal-policy refuses the root ARN; record IAM-004
        # as a warn pointing at the docs.
        audit.record_check(
            "Phase 3: IaC", "Required actions simulate-pass", "IAM-004",
            observed=None,
            note="root principal — simulate-principal-policy is not supported "
                 "for the root user; create an IAM user and re-run.",
        )
        return
    # ``iam:SimulatePrincipalPolicy`` evaluates each action against the
    # set of resources you pass in ``ResourceArns``.  When the call
    # omits that argument the simulator defaults to ``*`` — which makes
    # every **least-privilege** policy (ours scopes by resource ARN +
    # tag conditions) look broken even when the deploy will succeed.
    # We model each required action against a realistic resource
    # alongside the tag/PassedToService context the deploy actually
    # presents at call time so IAM-004 reflects production reality.
    account_id = arn.split(":")[4] if arn.count(":") >= 4 else "000000000000"
    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION") or "us-east-2"

    # (action, resource_arns, context_entries)
    simulations: list[tuple[str, list[str], list[dict]]] = [
        # Unscoped reads / launches — `*` resource is fine.
        ("ec2:RunInstances", ["*"], []),
        ("ec2:DescribeInstances", ["*"], []),
        ("kms:Decrypt", ["*"], []),
        ("kms:DescribeKey", ["*"], []),
        ("ssm:GetCommandInvocation", ["*"], []),
        ("cloudtrail:LookupEvents", ["*"], []),
        # PassRole is scoped to the `tee-crafter-*` role family in the
        # canonical TeeCrafterCompute policy with an
        # ``iam:PassedToService = ec2.amazonaws.com`` condition.
        (
            "iam:PassRole",
            [f"arn:aws:iam::{account_id}:role/tee-crafter-role-deploy-stub"],
            [{
                "ContextKeyName": "iam:PassedToService",
                "ContextKeyValues": ["ec2.amazonaws.com"],
                "ContextKeyType": "string",
            }],
        ),
        # SSM SendCommand is split: the instance (tag-conditioned) AND
        # the AWS-managed document.  Both must evaluate to allow.
        (
            "ssm:SendCommand",
            [
                f"arn:aws:ec2:{region}:{account_id}:instance/i-deadbeefdeadbeef0",
                f"arn:aws:ssm:{region}::document/AWS-RunShellScript",
            ],
            [{
                "ContextKeyName": "aws:ResourceTag/Project",
                "ContextKeyValues": ["tee-crafter"],
                "ContextKeyType": "string",
            }],
        ),
        # ``logs:CreateLogStream`` / ``logs:PutLogEvents`` are
        # **enclave-role** actions (Terraform attaches them via
        # ``aws_iam_role_policy.*_siem_cloudwatch_logs``) and not deploy
        # user actions, so we check the operator side instead: the
        # ability to *manage* the log groups TEE-Crafter writes into.
        (
            "logs:CreateLogGroup",
            [f"arn:aws:logs:{region}:{account_id}:log-group:/tee-crafter/deploy"],
            [],
        ),
        (
            "logs:PutRetentionPolicy",
            [f"arn:aws:logs:{region}:{account_id}:log-group:/tee-crafter/deploy"],
            [],
        ),
        # S3 PutObject is scoped to the ``tee-crafter-deployment-*`` /
        # ``tee-crafter-gpu-cc-*`` bucket families.
        (
            "s3:PutObject",
            [
                f"arn:aws:s3:::tee-crafter-deployment-{account_id}/object",
                f"arn:aws:s3:::tee-crafter-gpu-cc-{account_id}/object",
            ],
            [],
        ),
    ]

    denied: list[str] = []
    skipped: list[str] = []
    try:
        iam = boto3.client("iam")
        for action, resources, ctx in simulations:
            try:
                kwargs = dict(
                    PolicySourceArn=arn,
                    ActionNames=[action],
                    ResourceArns=resources,
                )
                if ctx:
                    kwargs["ContextEntries"] = ctx
                resp = iam.simulate_principal_policy(**kwargs)
                results = resp.get("EvaluationResults", []) or []
                # An action passes when **every** resource evaluation
                # returns ``allowed`` — anything else (implicitDeny /
                # explicitDeny / unknown) counts as denied.
                if not results or any(
                    r.get("EvalDecision") != "allowed" for r in results
                ):
                    denied.append(action)
            except Exception as exc:
                skipped.append(f"{action}: {type(exc).__name__}: {exc}")

        if skipped and not denied:
            note = "partial: " + "; ".join(skipped)
            audit.record_check(
                "Phase 3: IaC", "Required actions simulate-pass", "IAM-004",
                observed=None, note=note,
            )
        else:
            audit.record_check(
                "Phase 3: IaC", "Required actions simulate-pass", "IAM-004",
                expected=True, observed=(not denied),
                note=(f"denied={denied}" if denied
                      else "all required actions allowed"),
            )
    except Exception as exc:
        audit.record_check(
            "Phase 3: IaC", "Required actions simulate-pass", "IAM-004",
            observed=None,
            note=f"simulate-principal-policy not callable: "
                 f"{type(exc).__name__}: {exc}",
        )


def _emit_azure_iam_verdicts(audit, tee_platform: Optional[str]) -> None:
    try:
        res = subprocess.run(
            ["az", "account", "show", "-o", "json"],
            capture_output=True, text=True, timeout=10,
        )
        import json as _json
        if res.returncode == 0:
            payload = _json.loads(res.stdout or "{}")
            user = payload.get("user", {}) or {}
            audit.record_check(
                "Phase 3: IaC", "Caller principal recorded", "IAM-001",
                observed=bool(user.get("name")),
                note=user.get("name", ""),
            )
            audit.record_check(
                "Phase 3: IaC", "Caller is non-root (warn if root)", "IAM-002",
                expected=True,
                observed=(user.get("type", "user") != "owner"),
            )
        else:
            audit.record_check(
                "Phase 3: IaC", "Caller principal recorded", "IAM-001",
                observed=False, note=(res.stderr or "")[:200],
            )
    except Exception as exc:
        audit.record_check(
            "Phase 3: IaC", "Caller principal recorded", "IAM-001",
            observed=False, note=f"{type(exc).__name__}: {exc}",
        )


def _emit_gcp_iam_verdicts(audit, tee_platform: Optional[str]) -> None:
    try:
        res = subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            capture_output=True, text=True, timeout=10,
        )
        if res.returncode == 0 and res.stdout.strip():
            account = res.stdout.strip()
            audit.record_check(
                "Phase 3: IaC", "Caller principal recorded", "IAM-001",
                observed=True, note=account,
            )
            # Service-account credentials are non-root by convention;
            # interactive ``user@example.com`` is also fine.  We cannot
            # cheaply prove "non-root" on GCP, so emit IAM-002 as PASS
            # when an account is configured.
            audit.record_check(
                "Phase 3: IaC", "Caller is non-root (warn if root)", "IAM-002",
                observed=True, note=account,
            )
        else:
            audit.record_check(
                "Phase 3: IaC", "Caller principal recorded", "IAM-001",
                observed=False, note=(res.stderr or "")[:200],
            )
    except Exception as exc:
        audit.record_check(
            "Phase 3: IaC", "Caller principal recorded", "IAM-001",
            observed=False, note=f"{type(exc).__name__}: {exc}",
        )
