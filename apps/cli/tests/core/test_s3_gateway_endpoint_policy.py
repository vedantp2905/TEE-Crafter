"""The S3 gateway endpoint policy must scope its principal by condition.

An EC2 instance reaches S3 as an assumed-role session
(``arn:aws:sts::<acct>:assumed-role/<role>/<instance-id>``).  In an *interface*
endpoint policy, ``Principal = { AWS = "<role-arn>" }`` matches that session —
which is why the KMS / SSM / SSMMessages / EC2Messages policies work, verified
live by a ``kms:GenerateRandom`` call from inside the deployment.  In the S3
*gateway* endpoint policy the same form does **not** match, and every request
is refused with:

    is not authorized to perform: s3:ListBucket ... because no VPC endpoint
    policy allows the s3:ListBucket action

Measured on a live ``nitro-aws`` deploy (2026-08-20): ``aws s3 cp`` of the
168 MB EIF failed ``HeadObject 403`` on all three retries, so ``Step 8d`` could
never complete and attestation never ran.  Rewriting only that one policy to
``Principal = "*"`` plus ``ArnEquals aws:PrincipalArn`` made the identical
command succeed at 37 MiB/s against the same bucket, role and instance.

``aws:PrincipalArn`` resolves to the *role* ARN for a role session, so the
rewrite is exactly as tight as the original intent: this deployment's enclave
role and nothing else.

These assertions are deliberately two-sided.  The asymmetry between the gateway
policy and the interface policies looks like an inconsistency, and the obvious
"cleanup" is to make them match — which silently reintroduces a defect that
bricks every AWS deploy and only shows up on real hardware.
"""

import json
import pathlib
import shutil
import subprocess

import pytest

TEMPLATES = pathlib.Path(__file__).resolve().parents[2] / "src" / "tee_crafter" / "templates"

AWS_TEMPLATES = [
    "nitro/main.template.tf",
    "snp/aws/main.template.tf",
    "gpu_cc/aws/main.template.tf",
]

#: The exact form that fails on a gateway endpoint.
BROKEN_PRINCIPAL = "Principal = { AWS = local.endpoint_policy_principal }"


def _read(rel: str) -> str:
    path = TEMPLATES / rel
    assert path.is_file(), f"missing template: {path}"
    return path.read_text(encoding="utf-8")


def _s3_endpoint_policy_block(source: str) -> str:
    """Return just the ``s3_endpoint_policy`` jsonencode block.

    Scoped rather than whole-file so the interface-endpoint policies — which
    legitimately keep the ``Principal`` form — cannot satisfy or break these
    assertions by accident.
    """
    marker = "s3_endpoint_policy = jsonencode({"
    start = source.index(marker)
    end = source.index("\n  })", start)
    return source[start:end]


class TestS3GatewayEndpointPolicy:
    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_scopes_principal_by_condition(self, rel):
        block = _s3_endpoint_policy_block(_read(rel))
        assert 'Principal = "*"' in block
        assert '"aws:PrincipalArn" = local.endpoint_policy_principal' in block
        assert "ArnEquals" in block

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_does_not_use_the_principal_element(self, rel):
        block = _s3_endpoint_policy_block(_read(rel))
        assert BROKEN_PRINCIPAL not in block, (
            f"{rel}: the S3 gateway endpoint policy is back to the Principal-element "
            "form, which does not match an assumed-role session. This bricks Step 8d "
            "(EIF download) on every AWS deploy with HeadObject 403."
        )

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_every_statement_is_scoped(self, rel):
        """No statement may be left open to the whole account.

        ``Principal = "*"`` without the condition would make the endpoint
        readable by any principal in any account that can route to it.
        """
        block = _s3_endpoint_policy_block(_read(rel))
        assert block.count('Principal = "*"') == block.count("ArnEquals"), (
            f"{rel}: a wildcard Principal is not paired 1:1 with an "
            f"aws:PrincipalArn condition"
        )

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_policy_is_not_detached_when_setup_egress_is_open(self, rel):
        """``allow_setup_egress`` must not remove the policy from the endpoint.

        It used to: the resource read ``local.endpoint_policies_active &&
        !var.allow_setup_egress ? local.s3_endpoint_policy : null``.  That is a
        bigger loss than it looks.  On a gateway endpoint the policy is what
        pins access to *this deployment's role* — it governs who may use the
        endpoint, not whether egress exists — so detaching it let any principal
        in the VPC reach the artifact bucket path through the endpoint.

        And it fired on a path nobody was thinking about.
        ``siem_egress_terraform`` sets ``TF_VAR_allow_setup_egress=true`` for the
        NAT path, so simply adding ``--siem`` to an otherwise locked-down deploy
        silently dropped the control, with nothing in the output saying so.
        """
        source = _read(rel)
        assert "!var.allow_setup_egress ? local.s3_endpoint_policy" not in source, (
            f"{rel}: the S3 gateway endpoint policy is detached again when "
            "allow_setup_egress is true. That also drops the aws:PrincipalArn "
            "condition, which is the actual access control here, and --siem "
            "turns it on without telling the operator."
        )
        assert (
            "policy            = local.endpoint_policies_active ? "
            "local.s3_endpoint_policy : null"
        ) in source

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_setup_path_widens_reads_only(self, rel):
        """The setup-egress relaxation must not become a write or wildcard grant.

        Package mirrors need reads from buckets we deliberately do not enumerate
        (their names are region- and distro-version-specific and would rot here),
        so ``s3:GetObject`` widens to ``*``.  Nothing else may: writes stay
        scoped to this deployment's bucket, and the principal condition stays on.
        """
        block = _s3_endpoint_policy_block(_read(rel))
        start = block.index("var.allow_setup_egress ? [")
        branch = block[start:]
        assert 'Sid       = "SetupPackageRepoReads"' in branch
        assert 'Action    = "s3:GetObject"' in branch
        assert 'Resource  = "*"' in branch
        assert '"aws:PrincipalArn" = local.endpoint_policy_principal' in branch
        for forbidden in ("s3:PutObject", "s3:DeleteObject", "s3:*", '"*"]'):
            assert forbidden not in branch, (
                f"{rel}: the setup-egress statement grants {forbidden}. Only "
                "reads may widen; writes stay scoped to the deployment bucket."
            )

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_interface_endpoint_policies_use_the_condition_form(self, rel):
        """The asymmetry is gone, and the reason it existed turned out to be wrong.

        This test used to assert the opposite — that the interface endpoints
        *keep* the ``Principal`` form, on the grounds that it was "verified
        working on live hardware, so there is no reason to churn". It invited
        its own revisiting if that was ever deliberate, which is what happened.

        The premise was false. On 2026-08-23 both ``nitro-aws`` and ``snp-aws``
        failed ``terraform apply`` at every interface endpoint with
        ``InvalidPolicyDocument: UnknownError`` — deterministically, and through
        the automatic retry, because the retry destroys and recreates the role
        and races IAM propagation again. ``CreateVpcEndpoint`` validates that a
        Principal named in the policy *exists*, and the role is created in the
        same apply.

        Proven side by side against the live EC2 API with a deliberately
        nonexistent role ARN, identical in every other respect:

            Principal = {AWS: <nonexistent arn>}                -> InvalidPolicyDocument
            Principal = "*" + ArnEquals aws:PrincipalArn: same  -> endpoint created

        The condition form is equivalent in effect (only that role's calls are
        allowed; a caller with no ``aws:PrincipalArn`` fails the condition and is
        denied) and is not existence-checked, so it cannot race. It also makes
        the interface endpoints consistent with the S3 gateway policy, which had
        already moved to the condition form.
        """
        source = _read(rel)
        block = _s3_endpoint_policy_block(source)
        outside = source.replace(block, "")
        assert BROKEN_PRINCIPAL not in outside, (
            f"{rel}: an interface-endpoint policy is back on the Principal "
            "form. CreateVpcEndpoint existence-checks a named Principal, and "
            "the role is created in the same apply, so this fails with "
            "InvalidPolicyDocument. Use local.endpoint_principal_condition."
        )
        assert "endpoint_principal_condition" in outside, (
            f"{rel}: the interface endpoints no longer restrict to the "
            "deployment role at all — that is a widening, not a fix."
        )

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_the_condition_pins_the_deployment_role(self, rel):
        """`Principal = "*"` is only safe because the condition narrows it."""
        source = _read(rel)
        start = source.index("endpoint_principal_condition = {")
        block = source[start:start + 300]
        assert 'ArnEquals' in block
        assert '"aws:PrincipalArn" = local.endpoint_policy_principal' in block


HAVE_TERRAFORM = shutil.which("terraform") is not None

#: Stand-ins for the two locals the policy interpolates.  Both are opaque
#: strings at this level, so literals are faithful.
_HARNESS_PREAMBLE = """
variable "allow_setup_egress" {
  type = bool
}

variable "aws_region" {
  type    = string
  default = "us-east-2"
}

locals {
  deployment_bucket_arn     = "arn:aws:s3:::tee-crafter-deployment-abc123"
  endpoint_policy_principal = "arn:aws:iam::111122223333:role/tee-crafter-enclave"
"""


def _full_policy_local(source: str) -> str:
    marker = "  s3_endpoint_policy = jsonencode({"
    start = source.index(marker)
    end = source.index("\n  })", start) + len("\n  })")
    return source[start:end]


@pytest.mark.skipif(not HAVE_TERRAFORM, reason="terraform binary not on PATH")
class TestS3GatewayPolicyEvaluates:
    """Evaluate the real HCL instead of asserting about its text.

    The text assertions above cannot tell whether ``concat`` plus a conditional
    tuple actually produces the statement list intended — that is a property of
    Terraform's evaluator, and the surrounding tests would pass just as happily
    on HCL that fails to parse or silently yields two statements in both modes.
    This lifts the policy local out of the template verbatim, feeds it literals
    for the two interpolated locals, and reads back the rendered JSON.

    Offline: the extracted snippet declares no providers, so
    ``terraform init -backend=false`` downloads nothing.
    """

    def _render(self, tmp_path, rel: str, allow_setup_egress: bool) -> dict:
        work = tmp_path / rel.replace("/", "_")
        work.mkdir(parents=True, exist_ok=True)
        (work / "main.tf").write_text(
            _HARNESS_PREAMBLE + _full_policy_local(_read(rel)) + "\n}\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
            cwd=work, check=True, capture_output=True, timeout=180,
        )
        result = subprocess.run(
            ["terraform", "console", "-no-color",
             f"-var=allow_setup_egress={str(allow_setup_egress).lower()}"],
            cwd=work, input="local.s3_endpoint_policy\n",
            capture_output=True, text=True, check=True, timeout=180,
        )
        # `terraform console` prints the string result as a quoted, escaped
        # JSON literal, so it needs unquoting before parsing.
        return json.loads(json.loads(result.stdout.strip().splitlines()[-1]))

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_locked_down_has_exactly_the_two_scoped_statements(self, rel, tmp_path):
        doc = self._render(tmp_path, rel, allow_setup_egress=False)
        assert [s["Sid"] for s in doc["Statement"]] == [
            "DeploymentBucket", "SsmAgentManagedBuckets",
        ]

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    def test_setup_path_adds_a_read_statement(self, rel, tmp_path):
        doc = self._render(tmp_path, rel, allow_setup_egress=True)
        assert [s["Sid"] for s in doc["Statement"]] == [
            "DeploymentBucket", "SsmAgentManagedBuckets", "SetupPackageRepoReads",
        ]
        widened = doc["Statement"][-1]
        assert widened["Action"] == "s3:GetObject"
        assert widened["Resource"] == "*"

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    @pytest.mark.parametrize("allow_setup_egress", [False, True])
    def test_every_rendered_statement_pins_the_principal(
        self, rel, allow_setup_egress, tmp_path,
    ):
        """The invariant that survives both modes, checked on rendered JSON.

        This is the assertion the detach-on-setup-egress bug violated: with no
        policy attached there were no statements at all, so nothing pinned the
        principal.
        """
        doc = self._render(tmp_path, rel, allow_setup_egress=allow_setup_egress)
        assert doc["Statement"]
        for statement in doc["Statement"]:
            assert statement["Principal"] == "*"
            assert statement["Condition"]["ArnEquals"]["aws:PrincipalArn"] == (
                "arn:aws:iam::111122223333:role/tee-crafter-enclave"
            )

    @pytest.mark.parametrize("rel", AWS_TEMPLATES)
    @pytest.mark.parametrize("allow_setup_egress", [False, True])
    def test_writes_are_never_widened_beyond_the_deployment_bucket(
        self, rel, allow_setup_egress, tmp_path,
    ):
        doc = self._render(tmp_path, rel, allow_setup_egress=allow_setup_egress)
        for statement in doc["Statement"]:
            actions = statement["Action"]
            actions = [actions] if isinstance(actions, str) else actions
            if not any(a in ("s3:PutObject", "s3:AbortMultipartUpload")
                       for a in actions):
                continue
            resources = statement["Resource"]
            resources = [resources] if isinstance(resources, str) else resources
            for resource in resources:
                assert resource.startswith(
                    "arn:aws:s3:::tee-crafter-deployment-abc123"), (
                    f"{rel}: a write action is allowed on {resource!r}"
                )
