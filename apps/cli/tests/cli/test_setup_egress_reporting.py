"""The deploy summary must describe the deployment, not the operator's flag.

``--siem`` with a public collector needs a NAT gateway, so
``siem_egress_terraform.apply_siem_egress`` sets
``TF_VAR_allow_setup_egress=true``.  But it cannot run until ``build_dir``
exists, and ``build_dir`` is not created until the container build — long after
``_resolve_ami_id`` has already printed the pinned-image panel.  So the panel
read "Setup egress: Locked down" on runs that then got a NAT gateway and a
0.0.0.0/0 route.

The security-group rules did stay restricted to the SIEM allowlist plus the VPC
CIDR and the S3 prefix list, so this was a misleading summary rather than an open
egress hole.  It still cost real debugging time — while chasing an unrelated
failure, the summary was read as evidence that no NAT existed — and this project
has been wrong about per-platform posture claims five times, twice in ways that
were live attestation bypasses.  A posture line that does not track the posture
is the same failure mode in miniature.

The fix asks the egress planner up front what it will decide later.
:func:`test_prediction_matches_application` is the assertion that matters: a
prediction that can drift from what is applied is worse than no prediction.
"""

import os
from dataclasses import dataclass, field
from typing import List

import pytest

from tee_crafter.cli.commands.deploy import deploy_helpers
from tee_crafter.cli.commands.deploy.siem_egress_terraform import (
    apply_siem_egress,
    will_open_public_egress,
)


@dataclass
class FakeSiemConfig:
    provider: str = "none"
    egress_mode: str = "auto"
    egress_allowlist_cidrs: List[str] = field(default_factory=list)
    egress_ports: List[int] = field(default_factory=lambda: [443])
    log_group: str = ""


class FakeConsole:
    def __init__(self):
        self.rendered = []

    def print(self, renderable=None, *args, **_kw):
        # Panel.fit() keeps the text on `.renderable`; plain strings arrive
        # as-is.  Either way we only care about the words.
        text = getattr(renderable, "renderable", renderable)
        self.rendered.append(str(text))

    @property
    def text(self):
        return "\n".join(self.rendered)


class FakeAudit:
    def __init__(self):
        self.records = []

    def record(self, phase, item, verdict, **fields):
        self.records.append((phase, item, verdict, fields))

    def record_check(self, *a, **kw):
        pass


#: (provider, egress_mode) -> whether a NAT gateway is required.
#: ``syslog-cef`` collectors run inside or peered to the VPC; ``splunk-hec`` and
#: ``datadog`` intake is public-internet only.
EGRESS_CASES = [
    ("none", "auto", False),
    ("syslog-cef", "auto", False),
    ("syslog-cef", "private", False),
    ("splunk-hec", "auto", True),
    ("splunk-hec", "public", True),
    ("datadog", "auto", True),
    ("datadog", "public", True),
    ("splunk-hec", "none", False),
]


class TestWillOpenPublicEgress:
    @pytest.mark.parametrize("provider,mode,expected", EGRESS_CASES)
    def test_predicts_the_nat_path(self, provider, mode, expected):
        config = FakeSiemConfig(provider=provider, egress_mode=mode)
        assert will_open_public_egress(
            config, tee_platform="nitro-aws") is expected

    def test_no_siem_config_at_all(self):
        assert will_open_public_egress(None, tee_platform="nitro-aws") is False

    def test_impossible_combination_predicts_false_without_raising(self):
        """``--siem-egress private`` with a public-only provider is rejected.

        ``apply_siem_egress`` raises the real, actionable error moments later.
        A summary line is the wrong place to surface it, and raising from here
        would turn a cosmetic call into a new failure path.
        """
        config = FakeSiemConfig(provider="splunk-hec", egress_mode="private")
        assert will_open_public_egress(
            config, tee_platform="nitro-aws") is False

    @pytest.mark.parametrize("provider,mode,expected", EGRESS_CASES)
    def test_prediction_matches_application(
        self, provider, mode, expected, tmp_path, monkeypatch,
    ):
        """The anti-drift check.

        Prediction and application must come from one code path.  Two
        implementations of "will this open egress?" would eventually disagree,
        and a summary that confidently states the wrong posture is exactly the
        defect being fixed here — so assert they agree on every case rather than
        trusting that they were written from the same intent.
        """
        monkeypatch.delenv("TF_VAR_allow_setup_egress", raising=False)
        config = FakeSiemConfig(provider=provider, egress_mode=mode)

        predicted = will_open_public_egress(config, tee_platform="nitro-aws")
        _decision, tfvars = apply_siem_egress(
            str(tmp_path / "build"), config, tee_platform="nitro-aws")
        applied = tfvars.get("TF_VAR_allow_setup_egress") == "true"

        assert predicted is applied is expected


class TestPinnedImagePanel:
    """The panel must not claim a posture the run will not have."""

    @pytest.fixture
    def harness(self, monkeypatch):
        console = FakeConsole()
        monkeypatch.setattr(deploy_helpers, "console", console)
        # Both of these call EC2; the panel's wording does not depend on them.
        monkeypatch.setattr(
            deploy_helpers, "validate_custom_ami_architecture",
            lambda *_a, **_kw: True)
        monkeypatch.setattr(
            deploy_helpers, "propagate_secure_boot_var_from_ami",
            lambda *_a, **_kw: "true")
        monkeypatch.setenv("AWS_NITRO_AMI_X86_64", "ami-0123456789abcdef0")
        monkeypatch.delenv("TEE_CRAFTER_AMI_ID", raising=False)
        return console

    def _resolve(self, siem_opens_egress: bool):
        audit = FakeAudit()
        resolved = deploy_helpers._resolve_ami_id(
            ami_id=None, tee_platform="nitro-aws", deploy=True, audit=audit,
            cpu=2, ram=6144, instance_type="c6a.xlarge",
            siem_opens_egress=siem_opens_egress,
        )
        return resolved, audit

    def test_locked_down_when_nothing_reopens_egress(self, harness):
        resolved, audit = self._resolve(siem_opens_egress=False)
        assert resolved == "ami-0123456789abcdef0"
        assert "Locked down" in harness.text
        assert os.environ["TF_VAR_allow_setup_egress"] == "false"
        assert any(f.get("setup_egress") == "locked-down"
                   for *_h, f in audit.records)

    def test_says_nat_when_siem_will_reopen_egress(self, harness):
        resolved, audit = self._resolve(siem_opens_egress=True)
        assert resolved == "ami-0123456789abcdef0"
        assert "Locked down" not in harness.text, (
            "the panel claims a locked-down posture on a run that goes on to "
            "get a NAT gateway and a default route"
        )
        assert "NAT gateway" in harness.text
        assert "--siem" in harness.text
        assert any(f.get("setup_egress") == "nat-for-siem"
                   for *_h, f in audit.records)

    def test_the_posture_reaches_the_audit_trail_either_way(self, harness):
        """A summary line scrolls past; the provenance record is what is kept."""
        for opens in (False, True):
            _resolved, audit = self._resolve(siem_opens_egress=opens)
            assert any("setup_egress" in f for *_h, f in audit.records)
