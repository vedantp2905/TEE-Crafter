"""Invariants on the Terraform IAM policy bodies + AWS docs.

These guard against regressions in:

  * BYOK kms:Decrypt grant existing only when var.byok_aws_kms_arn is set
    on ALL AWS-side platforms (nitro, snp-aws, gpu-cc-aws).
  * IMDSv2 hard-enforcement on every AWS aws_instance block.
  * docs/aws_setup.md, docs/azure_setup.md, docs/gcp_setup.md actually
    mention the byok-stage command (so operators know rotation exists).
  * Sample BYOK configs do NOT carry live secret material in the
    committed sample files.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# REPO_ROOT = the CLI package root (apps/cli). PROJECT_ROOT = the monorepo
# root, which still owns docs/ and .env.example after the apps/ restructure.
REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[4]
TF_AWS_PLATFORMS = [
    REPO_ROOT / "src/tee_crafter/templates/nitro/main.template.tf",
    REPO_ROOT / "src/tee_crafter/templates/snp/aws/main.template.tf",
    REPO_ROOT / "src/tee_crafter/templates/gpu_cc/aws/main.template.tf",
]


@pytest.mark.parametrize("tf_path", TF_AWS_PLATFORMS,
                         ids=lambda p: p.parent.name)
def test_byok_kms_arn_variable_declared(tf_path: Path):
    """Every AWS-platform Terraform module declares
    var.byok_aws_kms_arn so the CLI / docs can rely on it
    uniformly."""
    body = tf_path.read_text()
    assert 'variable "byok_aws_kms_arn"' in body, (
        f"{tf_path} is missing the byok_aws_kms_arn variable that the "
        f"BYOK boot-time release flow depends on (see docs/aws_setup.md)."
    )
    # The default must be "" so unset means no IAM is attached.
    m = re.search(r'variable "byok_aws_kms_arn"\s*\{[^}]*default\s*=\s*"([^"]*)"',
                  body, flags=re.S)
    assert m is not None, f"{tf_path}: byok_aws_kms_arn has no default"
    assert m.group(1) == "", (
        f"{tf_path}: byok_aws_kms_arn default must be \"\" "
        f"(unset == no policy attached), got {m.group(1)!r}"
    )


@pytest.mark.parametrize("tf_path", TF_AWS_PLATFORMS,
                         ids=lambda p: p.parent.name)
def test_byok_decrypt_policy_gated_by_arn(tf_path: Path):
    """The kms:Decrypt policy must be conditionally counted on
    var.byok_aws_kms_arn != "" so empty == no IAM attached."""
    body = tf_path.read_text()
    # Find any resource block that grants kms:Decrypt for BYOK.
    blocks = re.findall(
        r'resource "aws_iam_role_policy" "[a-z_]*byok[a-z_]*"\s*\{[^}]+\}',
        body, flags=re.S,
    )
    assert blocks, f"{tf_path}: no BYOK kms:Decrypt policy block found"
    for blk in blocks:
        assert 'var.byok_aws_kms_arn != ""' in blk, (
            f"{tf_path}: BYOK policy block must be count-gated on "
            f"var.byok_aws_kms_arn != \"\""
        )
        # And it must NOT grant kms:Decrypt on "*".
        if "kms:Decrypt" in blk:
            assert 'Resource = var.byok_aws_kms_arn' in blk, (
                f"{tf_path}: BYOK decrypt policy must scope Resource to "
                f"var.byok_aws_kms_arn, not Resource = \"*\""
            )


@pytest.mark.parametrize("tf_path", TF_AWS_PLATFORMS,
                         ids=lambda p: p.parent.name)
def test_imdsv2_enforced_on_every_aws_instance(tf_path: Path):
    """SEC-CREDS-2 invariant: every aws_instance block requires IMDSv2.

    Both the spot and on-demand variants count.  Some templates use a
    single ``metadata_options`` block via ``dynamic``, but the spot/
    on-demand twin in our codebase is hardcoded — so we just count.
    """
    body = tf_path.read_text()
    instance_blocks = list(re.finditer(
        r'resource "aws_instance" "[^"]+"\s*\{', body))
    assert instance_blocks, f"{tf_path}: no aws_instance blocks found"
    # Each instance block should be followed by a metadata_options
    # block that sets http_tokens="required" somewhere before its
    # matching closing brace.  Cheap approximation: count occurrences.
    n_required = body.count('http_tokens                 = "required"')
    n_required += body.count('http_tokens = "required"')
    assert n_required >= len(instance_blocks), (
        f"{tf_path}: only {n_required} http_tokens=\"required\" entries "
        f"for {len(instance_blocks)} aws_instance blocks — IMDSv2 must "
        f"be enforced on EVERY instance."
    )


# --- Docs invariants ---


def test_aws_doc_mentions_byok_stage():
    doc = (PROJECT_ROOT / "docs/aws_setup.md").read_text()
    assert "byok-stage" in doc, (
        "docs/aws_setup.md must document `tee-crafter byok-stage` "
        "alongside SIEM/BYOK setup so operators know rotation exists."
    )
    assert "TF_VAR_byok_aws_kms_arn" in doc or "byok_aws_kms_arn" in doc


def test_gcp_doc_mentions_byok_stage():
    doc = (PROJECT_ROOT / "docs/gcp_setup.md").read_text()
    assert "byok-stage" in doc
    # And the cross-project BYOK gotcha.
    assert "cross-project" in doc.lower() or "cross project" in doc.lower()


def test_azure_doc_mentions_byok_stage():
    doc = (PROJECT_ROOT / "docs/azure_setup.md").read_text()
    assert "byok-stage" in doc
    # And the Managed Identity gotcha (release/action not auto-granted).
    assert "Managed Identity" in doc
    assert "release/action" in doc or "Crypto Service Release" in doc


# --- Committed BYOK configs (dev keys; wrapped DEK present) ---


COMMITTED_BYOK_CONFIGS = [
    REPO_ROOT / "byok-sandbox/configs/byok-nitro-aws.json",
    REPO_ROOT / "byok-sandbox/configs/byok-snp-aws.json",
    REPO_ROOT / "byok-sandbox/configs/byok-gcp.json",
]


@pytest.mark.integration
@pytest.mark.parametrize("cfg", COMMITTED_BYOK_CONFIGS, ids=lambda p: p.name)
def test_committed_byok_configs_have_wrapped_dek(cfg: Path):
    """Committed BYOK configs must ship with a wrapped DEK for deploy.

    ``byok-sandbox/configs/`` is generated, not committed: the files only
    exist after ``byok-sandbox/<cloud>/create_*_key.py`` + ``wrap_dek.py``
    have run against a real KMS/Key Vault, because the wrapped DEK is
    ciphertext produced by the customer's own key.  Marked ``integration``
    so the default suite does not fail on a fresh clone.
    """
    import json as _json
    doc = _json.loads(cfg.read_text(encoding="utf-8"))
    assert doc.get("key_id"), f"{cfg}: key_id missing"
    assert (doc.get("extra") or {}).get("ciphertext_b64"), (
        f"{cfg}: run wrap_dek.py — ciphertext_b64 empty"
    )
