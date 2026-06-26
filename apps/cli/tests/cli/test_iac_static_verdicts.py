"""Regression tests for ``emit_iac_static_verdicts`` (IAC-001..009)."""
from __future__ import annotations


from tee_crafter.core.audit import BuildAuditTrail, Verdict
from tee_crafter.cli.deployment.common.terraform_step import (
    emit_iac_static_verdicts,
)


_EGRESS_ONLY_TF = """
resource "aws_security_group" "workload" {
  name = "x"
  ingress {
    from_port   = 5005
    to_port     = 5005
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "extra_egress" {
  egress {
    cidr_blocks = ["0.0.0.0/0", "::/0"]
  }
}
"""

_INGRESS_BROAD_TF = """
resource "aws_security_group" "workload" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def test_iac_003_ignores_broad_egress(tmp_path):
    """0.0.0.0/0 in an ``egress {}`` block must NOT fail IAC-003."""
    (tmp_path / "main.tf").write_text(_EGRESS_ONLY_TF, encoding="utf-8")
    audit = BuildAuditTrail()
    audit.set_tee_platform("snp-aws")
    emit_iac_static_verdicts(audit, str(tmp_path), tee_platform="snp-aws")
    row = audit.ledger.get("IAC-003")
    assert row is not None
    assert row.verdict == Verdict.PASS.value, row.note


def test_iac_003_flags_broad_ingress(tmp_path):
    """0.0.0.0/0 in an ``ingress {}`` block must fail IAC-003."""
    (tmp_path / "main.tf").write_text(_INGRESS_BROAD_TF, encoding="utf-8")
    audit = BuildAuditTrail()
    audit.set_tee_platform("snp-aws")
    emit_iac_static_verdicts(audit, str(tmp_path), tee_platform="snp-aws")
    row = audit.ledger.get("IAC-003")
    assert row is not None
    assert row.verdict == Verdict.FAIL.value, row.note
