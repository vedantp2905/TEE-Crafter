"""`terraform destroy` leaked one CloudWatch log group per AWS deployment.

Every AWS template provisions a per-deployment VPC Flow Log for the audit
trail: a `aws_cloudwatch_log_group` with 30-day retention, an IAM role the
`vpc-flow-logs.amazonaws.com` service assumes, and an `aws_flow_log`. On
teardown Terraform printed "Destroy complete" and exited 0, yet the log group
was still there afterwards.

Measured on a real snp-aws deploy in us-east-2 on 2026-08-21 by sampling the
group's CreationTime every 20 seconds across the destroy:

    00:37:45  /tee-crafter/snp-vpc-flow-logs/a97b3666  created=00:31:15  retention=30
    00:38:05  /tee-crafter/snp-vpc-flow-logs/a97b3666  created=00:37:53  retention=null

The CreationTime moved, so Terraform did delete the group — and the flow-log
delivery service re-created it seconds later via `logs:CreateLogGroup`, which
the delivery role granted on `Resource = "*"`. The replacement carries no
retention policy, so it never expires. 75 orphaned groups had accumulated in
the test account, the oldest four months old.

Two changes close it, and this module pins both:

1. The delivery role no longer gets `logs:CreateLogGroup` at all. Terraform
   creates the group, so the service never needs to.
2. `aws_iam_role.flow_log_role` gains `depends_on` on the log group, which
   inverts the destroy order — role and inline policy go first, so no valid
   credentials exist by the time the group is deleted. Terraform only orders a
   destroy where a dependency exists, and nothing previously tied the two.

A control stack with both changes reached FlowLogStatus=ACTIVE /
DeliverLogsStatus=SUCCESS and left nothing behind after destroy.
"""

import os
import re

import pytest

import tee_crafter

_TEMPLATE_ROOT = os.path.join(os.path.dirname(tee_crafter.__file__), "templates")

#: The AWS templates that provision VPC Flow Logs. Azure/GCP/SGX use different
#: (or no) flow-log plumbing and are out of scope here.
AWS_TEMPLATES = {
    "nitro": os.path.join(_TEMPLATE_ROOT, "nitro", "main.template.tf"),
    "snp-aws": os.path.join(_TEMPLATE_ROOT, "snp", "aws", "main.template.tf"),
    "gpu-cc-aws": os.path.join(_TEMPLATE_ROOT, "gpu_cc", "aws", "main.template.tf"),
}


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _block(text, kind, name):
    """Return the body of a single `resource "<kind>" "<name>" { ... }` block.

    Brace-counting rather than a regex on the whole block: the policy bodies
    contain nested `jsonencode({...})`, which a non-greedy match would cut
    short and a greedy one would run past.
    """
    header = re.search(
        r'^resource\s+"%s"\s+"%s"\s*\{' % (re.escape(kind), re.escape(name)),
        text, re.MULTILINE,
    )
    assert header, f'no resource "{kind}" "{name}" block found'
    depth, i = 1, header.end()
    while depth and i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    assert depth == 0, f'unbalanced braces in resource "{kind}" "{name}"'
    return text[header.end():i - 1]


def _strip_comments(body):
    return "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )


@pytest.fixture(params=sorted(AWS_TEMPLATES), ids=sorted(AWS_TEMPLATES))
def template(request):
    path = AWS_TEMPLATES[request.param]
    assert os.path.exists(path), path
    return _read(path)


class TestBlockExtractor:
    """The helper the assertions below lean on, checked against known input."""

    def test_extracts_a_body_with_nested_braces(self):
        text = (
            'resource "aws_iam_role_policy" "p" {\n'
            "  policy = jsonencode({ Statement = [{ Effect = \"Allow\" }] })\n"
            "}\n"
            'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        )
        body = _block(text, "aws_iam_role_policy", "p")
        assert "jsonencode" in body
        assert "aws_vpc" not in body, "ran past the closing brace"

    def test_missing_block_is_an_error_not_an_empty_pass(self):
        with pytest.raises(AssertionError):
            _block('resource "aws_vpc" "v" {}\n', "aws_iam_role_policy", "nope")


class TestFlowLogDeliveryRole:
    def test_create_log_group_is_not_granted(self, template):
        """The grant that let the service resurrect the deleted group."""
        policy = _strip_comments(
            _block(template, "aws_iam_role_policy", "flow_log_policy"))
        assert "logs:CreateLogGroup" not in policy, (
            "the flow-log delivery role can re-create the log group after "
            "terraform destroy deletes it, leaking a never-expiring group "
            "per deployment")

    def test_writes_are_scoped_to_this_deployments_group(self, template):
        """`Resource = "*"` for PutLogEvents let the role write anywhere."""
        policy = _strip_comments(
            _block(template, "aws_iam_role_policy", "flow_log_policy"))
        assert "logs:PutLogEvents" in policy, "delivery can no longer write"
        assert "aws_cloudwatch_log_group.vpc_flow_logs.arn" in policy, (
            "write actions are not scoped to the deployment's own log group")

    def test_role_is_destroyed_before_the_log_group(self, template):
        """Without this `depends_on` the destroy order is unconstrained."""
        role = _block(template, "aws_iam_role", "flow_log_role")
        depends = re.search(r"depends_on\s*=\s*\[([^\]]*)\]", role)
        assert depends, (
            "aws_iam_role.flow_log_role has no depends_on, so Terraform may "
            "delete the log group while the delivery role is still valid")
        assert "aws_cloudwatch_log_group.vpc_flow_logs" in depends.group(1)

    def test_the_service_principal_is_unchanged(self, template):
        """Guards the fix against being 'passed' by deleting the role."""
        role = _block(template, "aws_iam_role", "flow_log_role")
        assert "vpc-flow-logs.amazonaws.com" in role


class TestAuditTrailStillIntact:
    """The leak fix must not quietly disable the flow log or its retention."""

    def test_log_group_keeps_a_retention_policy(self, template):
        group = _block(template, "aws_cloudwatch_log_group", "vpc_flow_logs")
        assert re.search(r"retention_in_days\s*=\s*\d+", group), (
            "a group with no retention never expires — the exact state the "
            "leaked replacements were left in")

    def test_flow_log_still_targets_the_group_and_role(self, template):
        flow = _block(template, "aws_flow_log", "vpc")
        assert "aws_cloudwatch_log_group.vpc_flow_logs.arn" in flow
        assert "aws_iam_role.flow_log_role.arn" in flow
        assert re.search(r'traffic_type\s*=\s*"ALL"', flow)
