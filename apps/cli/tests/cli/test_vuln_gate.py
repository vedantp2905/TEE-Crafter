"""Tests for the Trivy/Grype vulnerability gate (G-3) in flow_container."""

from __future__ import annotations

from unittest.mock import patch


from tee_crafter.cli.commands.deploy import flow_container
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.security.vuln_scan import VulnScanResult


class _ProgressShim:
    """Minimal Progress shim that records task descriptions."""

    def __init__(self):
        self.tasks: dict[int, str] = {}
        self._next = 0

    def add_task(self, description, total=None):
        task_id = self._next
        self._next += 1
        self.tasks[task_id] = description
        return task_id

    def update(self, task_id, description=None, **_):
        if description is not None:
            self.tasks[task_id] = description


def _fake_vuln_result(*, critical: int, high: int) -> VulnScanResult:
    return VulnScanResult(
        scanner="trivy",
        image="user-image:latest",
        success=True,
        critical=critical,
        high=high,
        medium=0,
        low=0,
        report_path="/tmp/vuln-report.json",
        raw={},
    )


def _setup_common(monkeypatch, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Dockerfile").write_text("FROM python:3.11-slim\nCMD echo hi\n")

    monkeypatch.setattr(
        flow_container, "detect_container_port", lambda *a, **k: 8080,
    )
    monkeypatch.setattr(
        flow_container, "resolve_docker_platform", lambda *a, **k: "linux/amd64",
    )
    monkeypatch.setattr(
        flow_container, "_build_user_image", lambda *a, **k: "sha256:deadbeef",
    )
    monkeypatch.setattr(
        flow_container, "_new_user_image_tag",
        lambda: "tee-crafter-user-app:test",
    )
    return src


def test_gate_blocks_when_high_severity(monkeypatch, tmp_path):
    src = _setup_common(monkeypatch, tmp_path)
    monkeypatch.delenv("TEE_CRAFTER_ALLOW_VULNERABLE", raising=False)
    with patch(
        "tee_crafter.core.security.vuln_scan.scan_image",
        return_value=_fake_vuln_result(critical=2, high=4),
    ):
        progress = _ProgressShim()
        audit = BuildAuditTrail()
        result = flow_container.run_container_phases(
            progress, audit,
            source=str(src),
            container_port=8080, tee_platform="snp-aws",
        )
    assert result is None, "Vulnerability gate should abort the deploy"


def test_gate_allows_with_opt_in(monkeypatch, tmp_path):
    src = _setup_common(monkeypatch, tmp_path)
    monkeypatch.setenv("TEE_CRAFTER_ALLOW_VULNERABLE", "1")

    # Short-circuit the post-scan platform staging — we only care about
    # whether the gate blocked the pipeline before that stage.
    monkeypatch.setattr(
        flow_container, "_stage_cvm_container",
        lambda *a, **k: ("/tmp/build", "summary", "{}", "{}", "/tmp/build/user_container.tar"),
    )

    with patch(
        "tee_crafter.core.security.vuln_scan.scan_image",
        return_value=_fake_vuln_result(critical=2, high=4),
    ):
        progress = _ProgressShim()
        audit = BuildAuditTrail()
        result = flow_container.run_container_phases(
            progress, audit,
            source=str(src),
            container_port=8080, tee_platform="snp-aws",
        )
    assert result is not None
    # The audit trail should record gate_allowed=True so the override is
    # visible in compliance reports.
    matched = [
        e for e in audit._entries
        if e.step == "Vulnerability scan"
    ]
    assert matched
    assert matched[-1].details.get("gate_allowed") is True


def test_gate_clean_scan_passes(monkeypatch, tmp_path):
    src = _setup_common(monkeypatch, tmp_path)
    monkeypatch.delenv("TEE_CRAFTER_ALLOW_VULNERABLE", raising=False)
    monkeypatch.setattr(
        flow_container, "_stage_cvm_container",
        lambda *a, **k: ("/tmp/build", "summary", "{}", "{}", "/tmp/build/user_container.tar"),
    )
    with patch(
        "tee_crafter.core.security.vuln_scan.scan_image",
        return_value=_fake_vuln_result(critical=0, high=0),
    ):
        progress = _ProgressShim()
        audit = BuildAuditTrail()
        result = flow_container.run_container_phases(
            progress, audit,
            source=str(src),
            container_port=8080, tee_platform="snp-aws",
        )
    assert result is not None
