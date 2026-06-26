"""The BYOK key gets pinned to the instance role during the deploy.

On `snp-aws` and `gpu-cc-aws` AWS offers no attestation condition key, so the
caller's principal is the entire control on the customer's DEK. The role's name
carries a per-deploy suffix, which used to leave only two options: create the
key by hand mid-deploy, or pin `role/tee-crafter-<plat>-role-*` with
`--allow-wildcard-role` — a pattern anyone able to create a matching role name
satisfies. Neither is acceptable for a DEK.

So the key is now created with no decrypt grant and pinned once Terraform has
made the role. These tests cover the three things that make that safe: the
right statement is rewritten and nothing else is touched, the pin is an exact
`ArnEquals`, and every failure path is a refusal rather than a shrug.

`nitro-aws` is deliberately excluded — it gates on
`kms:RecipientAttestation:PCR*`, a real attestation condition, and rewriting
that into an identity check would be a downgrade.
"""
from __future__ import annotations

import json

import pytest

from tee_crafter.cli.deployment.common.byok_key_policy import (
    DECRYPT_SID, IAM_ONLY_AWS_PLATFORMS, instance_role_arn_from_outputs,
    pin_byok_key_to_instance_role, pin_statement, unwrap_staged_config,
)

ACCOUNT = "950771918023"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/tee-crafter-snp-role-a1b2c3d4"
KEY = f"arn:aws:kms:us-east-2:{ACCOUNT}:key/9e4dc198-5a49-4262-bf9a-e544b93fb647"


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, *a, **k):
        self.lines.append(" ".join(str(x) for x in a))

    @property
    def text(self):
        return "\n".join(self.lines)


class _Kms:
    """Minimal KMS double recording what the policy became."""

    def __init__(self, policy, *, get_raises=None, put_raises=None):
        self._policy = policy
        self.put = None
        self._get_raises = get_raises
        self._put_raises = put_raises

    def get_key_policy(self, **kw):
        if self._get_raises:
            raise self._get_raises
        return {"Policy": json.dumps(self._policy)}

    def put_key_policy(self, **kw):
        if self._put_raises:
            raise self._put_raises
        self.put = json.loads(kw["Policy"])


def _admin_only_policy():
    """A key created with no decrypt grant — the recommended starting state."""
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "AllowKeyManagementByAccount", "Effect": "Allow",
         "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
         "Action": ["kms:Describe*"], "Resource": "*"}]}


def _wildcard_policy():
    """The dangerous state this replaces."""
    p = _admin_only_policy()
    p["Statement"].append({
        "Sid": DECRYPT_SID, "Effect": "Allow", "Principal": {"AWS": "*"},
        "Action": ["kms:Decrypt"], "Resource": "*",
        "Condition": {"ArnLike": {
            "aws:PrincipalArn": f"arn:aws:iam::{ACCOUNT}:role/tee-crafter-snp-role-*"}}})
    return p


_DEFAULT = object()  # so `cfg=None` can mean "BYOK is off", not "use default"


def _run(policy, *, outputs=None, cfg=_DEFAULT, platform="snp-aws", kms=None):
    console = _Console()
    client = kms if kms is not None else _Kms(policy)
    ok, detail = pin_byok_key_to_instance_role(
        console=console, build_dir="/build", tee_platform=platform,
        outputs=outputs if outputs is not None else {"instance_role_arn": ROLE},
        region="us-east-2", audit=None, kms_client=client,
        read_byok_config=lambda _b: (
            {"provider": "aws-kms", "key_id": KEY} if cfg is _DEFAULT else cfg))
    return ok, detail, client, console


class TestThePin:
    def test_a_key_with_no_grant_gets_one(self):
        ok, _d, kms, _c = _run(_admin_only_policy())
        assert ok
        stmt = next(s for s in kms.put["Statement"] if s["Sid"] == DECRYPT_SID)
        assert stmt["Condition"]["ArnEquals"]["aws:PrincipalArn"] == ROLE

    def test_a_wildcard_grant_is_replaced_not_appended(self):
        """The failure that would matter: leaving the old ArnLike in place
        means the pin changes nothing."""
        ok, _d, kms, _c = _run(_wildcard_policy())
        assert ok
        decrypts = [s for s in kms.put["Statement"] if s["Sid"] == DECRYPT_SID]
        assert len(decrypts) == 1
        assert "ArnLike" not in decrypts[0]["Condition"]
        assert decrypts[0]["Condition"]["ArnEquals"]["aws:PrincipalArn"] == ROLE

    def test_the_caller_account_is_still_required(self):
        _ok, _d, kms, _c = _run(_admin_only_policy())
        stmt = next(s for s in kms.put["Statement"] if s["Sid"] == DECRYPT_SID)
        assert stmt["Condition"]["StringEquals"]["kms:CallerAccount"] == ACCOUNT

    def test_other_statements_survive(self):
        """Rewriting by Sid, not by index, so an operator's own statements on
        the key are not collateral."""
        policy = _admin_only_policy()
        policy["Statement"].append({"Sid": "OperatorsOwnThing", "Effect": "Allow",
                                    "Principal": {"AWS": "*"},
                                    "Action": ["kms:DescribeKey"], "Resource": "*"})
        _ok, _d, kms, _c = _run(policy)
        assert any(s["Sid"] == "OperatorsOwnThing" for s in kms.put["Statement"])
        assert any(s["Sid"] == "AllowKeyManagementByAccount"
                   for s in kms.put["Statement"])

    def test_an_already_pinned_key_is_not_rewritten(self):
        pinned = pin_statement(_admin_only_policy(), ROLE, ACCOUNT)
        ok, detail, kms, _c = _run(pinned)
        assert ok and "already pinned" in detail
        assert kms.put is None


class TestItRefusesRatherThanProceeding:
    def test_a_missing_role_output_fails(self):
        ok, detail, kms, _c = _run(_admin_only_policy(), outputs={})
        assert not ok and "instance_role_arn" in detail
        assert kms.put is None

    def test_a_non_role_arn_is_not_accepted(self):
        ok, _d, _k, _c = _run(
            _admin_only_policy(),
            outputs={"instance_role_arn": f"arn:aws:iam::{ACCOUNT}:user/someone"})
        assert not ok

    def test_a_config_without_a_key_id_fails(self):
        ok, detail, _k, _c = _run(_admin_only_policy(),
                                  cfg={"provider": "aws-kms", "key_id": ""})
        assert not ok and "key_id" in detail

    def test_an_unreadable_policy_fails(self):
        kms = _Kms(_admin_only_policy(), get_raises=RuntimeError("AccessDenied"))
        ok, detail, _k, _c = _run(None, kms=kms)
        assert not ok and "current key policy" in detail

    def test_a_failed_put_fails(self):
        kms = _Kms(_admin_only_policy(), put_raises=RuntimeError("AccessDenied"))
        ok, detail, _k, _c = _run(None, kms=kms)
        assert not ok and "PutKeyPolicy" in detail


class TestWhenThereIsNothingToDo:
    def test_nitro_is_left_alone(self):
        """It gates on kms:RecipientAttestation:PCR* — a real attestation
        condition. Overwriting that with an identity check is a downgrade."""
        assert "nitro-aws" not in IAM_ONLY_AWS_PLATFORMS
        ok, _d, kms, _c = _run(_admin_only_policy(), platform="nitro-aws")
        assert ok and kms.put is None

    def test_byok_off_is_a_no_op(self):
        ok, _d, kms, _c = _run(_admin_only_policy(), cfg=None)
        assert ok and kms.put is None

    def test_a_non_aws_provider_is_a_no_op(self):
        ok, _d, kms, _c = _run(_admin_only_policy(),
                               cfg={"provider": "gcp-kms", "key_id": "x"})
        assert ok and kms.put is None


class TestTheOutputExists:
    """The pin is unreachable without it, so the templates are asserted too."""

    @pytest.mark.parametrize("rel", ["snp/aws", "gpu_cc/aws"])
    def test_terraform_publishes_the_role_arn(self, rel):
        import pathlib
        p = (pathlib.Path(__file__).resolve().parents[2] / "src" / "tee_crafter"
             / "templates" / rel / "main.template.tf")
        src = p.read_text(encoding="utf-8")
        assert 'output "instance_role_arn"' in src
        assert "local.enclave_role_arn" in src

    @pytest.mark.parametrize("arn,ok", [
        (ROLE, True),
        ("", False),
        ("not-an-arn", False),
        (f"arn:aws:iam::{ACCOUNT}:user/someone", False),
    ])
    def test_output_reader(self, arn, ok):
        got = instance_role_arn_from_outputs({"instance_role_arn": arn})
        assert bool(got) is ok


class TestBothConfigShapes:
    """The staged `byok.json` is an envelope; `--byok-config` is flat.

    Reading only the flat shape aborted a live `snp-aws` deploy on 2026-08-23
    with "BYOK config has no key_id" — fail-closed, but on a file that was
    perfectly well-formed. The pin runs against whatever the deploy staged, so
    it has to understand that shape.
    """

    def test_the_staged_envelope_is_unwrapped(self):
        doc = {"provider": "aws-kms", "enabled": True, "describe": "...",
               "config": {"provider": "aws-kms", "key_id": KEY,
                          "region": "us-east-2", "unwrap": "direct_bytes"}}
        got = unwrap_staged_config(doc)
        assert got["key_id"] == KEY and got["provider"] == "aws-kms"

    def test_a_flat_config_is_returned_as_is(self):
        doc = {"provider": "aws-kms", "key_id": KEY}
        assert unwrap_staged_config(doc) == doc

    def test_the_envelope_provider_wins(self):
        """The envelope records what the deploy actually selected."""
        doc = {"provider": "aws-kms", "enabled": True,
               "config": {"provider": "stale", "key_id": KEY}}
        assert unwrap_staged_config(doc)["provider"] == "aws-kms"

    def test_an_envelope_with_no_inner_key_id_is_left_alone(self):
        doc = {"provider": "aws-kms", "config": {"region": "us-east-2"}}
        assert unwrap_staged_config(doc) == doc

    def test_the_real_staged_shape_pins(self):
        """End to end through `pin_byok_key_to_instance_role`."""
        staged = {"provider": "aws-kms", "enabled": True,
                  "config": {"provider": "aws-kms", "key_id": KEY,
                             "region": "us-east-2"}}
        ok, _d, kms, _c = _run(_admin_only_policy(),
                               cfg=unwrap_staged_config(staged))
        assert ok
        stmt = next(s for s in kms.put["Statement"] if s["Sid"] == DECRYPT_SID)
        assert stmt["Condition"]["ArnEquals"]["aws:PrincipalArn"] == ROLE
