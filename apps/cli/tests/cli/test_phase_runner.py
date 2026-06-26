"""Unit tests for the shared tunneled deployment-phase runner.

These lock in the orchestration contract that the per-(platform x cloud) phase
shims rely on: pre-apply hooks fire, the panel renders, the client runs, and —
critically — post-deploy probes run *after* a successful client verification
(never before, and never when the client failed). No real cloud is touched;
every external step is monkeypatched.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tee_crafter.cli.deployment.common import phase_runner as pr
from tee_crafter.cli.deployment.common.phase_runner import (
    TunnelConn,
    TunneledPhaseConfig,
    run_tunneled_deployment_phase,
)


class _FakeTunnel:
    def __init__(self):
        self.local_port = 12345
        self.started = False
        self.stopped = False

    def start(self, timeout=None):
        self.started = True

    def stop(self):
        self.stopped = True


def _make_cfg(events, *, client_result=True, tunnel=None, with_pre_apply=True):
    tunnel = tunnel or _FakeTunnel()

    def _run_client(progress, console, build_dir, key, port, user, audit, meas, outputs):
        events.append("client")
        return client_result

    cfg = TunneledPhaseConfig(
        tee_platform="snp-gcp", cloud_label="SNP GCP", tunnel_label="IAP",
        render_panel=lambda o, m: "PANEL",
        build_conn=lambda o, b: TunnelConn(tunnel=tunnel, ssh_key_path="/k", admin_user="u"),
        setup_fn=lambda *a, **k: (events.append("setup"), True)[1],
        wait_for_ssh=lambda k, u, p: True,
        run_client=_run_client,
        run_remote=lambda *a, **k: (True, "", ""),
        record_outputs=lambda audit, o: events.append("record_outputs"),
        pre_apply=(lambda console, audit: events.append("pre_apply")) if with_pre_apply else None,
    )
    return cfg, tunnel


@pytest.fixture
def patched(monkeypatch):
    """Patch every external boundary of the runner; return a captured-events list."""
    events: list[str] = []
    monkeypatch.setattr(pr, "run_terraform_apply_loop",
                        lambda *a, **k: (events.append("apply"), (True, ""))[1])
    monkeypatch.setattr(pr, "get_terraform_outputs", lambda b: {"instance_name": "vm"})
    monkeypatch.setattr(pr, "cleanup_resources",
                        lambda *a, **k: events.append("cleanup") or True)
    monkeypatch.setattr(pr, "save_audit_trail", lambda *a, **k: None)
    import tee_crafter.cli.audit_helpers as ah
    monkeypatch.setattr(ah, "emit_teardown_and_cloud_audit", lambda *a, **k: None)
    import tee_crafter.cli.deployment.common.post_deploy_probes as pdp
    monkeypatch.setattr(pdp, "run_post_deploy_probes",
                        lambda *a, **k: events.append("probes"))
    return events


def test_happy_path_probes_run_after_client(patched):
    events = patched
    cfg, tunnel = _make_cfg(events)
    run_tunneled_deployment_phase(
        MagicMock(), "/build", 2, 4, {"measurement": "abc"},
        auto_approve=True, teardown=False, audit=MagicMock(), custom_ami=None, cfg=cfg)

    assert "client" in events and "probes" in events
    # Probes must come strictly after the client verification.
    assert events.index("probes") > events.index("client")
    # Pre-apply fires before terraform apply.
    assert events.index("pre_apply") < events.index("apply")
    assert tunnel.started and tunnel.stopped


def test_probes_skipped_when_client_fails(patched):
    events = patched
    cfg, tunnel = _make_cfg(events, client_result=False)
    run_tunneled_deployment_phase(
        MagicMock(), "/build", 2, 4, {}, auto_approve=True, teardown=False,
        audit=MagicMock(), custom_ami=None, cfg=cfg)

    assert "client" in events
    assert "probes" not in events
    assert tunnel.stopped


def test_custom_ami_uses_wait_and_hook_not_setup(patched, monkeypatch):
    events = patched
    cfg, tunnel = _make_cfg(events)
    hook_calls = []
    cfg.on_custom_ami = lambda k, u, p: hook_calls.append((k, u, p))

    run_tunneled_deployment_phase(
        MagicMock(), "/build", 2, 4, {}, auto_approve=True, teardown=False,
        audit=MagicMock(), custom_ami="my-image", cfg=cfg)

    # Baked-image path skips cloud-init setup and runs the custom-AMI hook.
    assert "setup" not in events
    assert hook_calls == [("/k", "u", 12345)]
    assert "client" in events


def test_teardown_triggers_cleanup(patched):
    events = patched
    cfg, tunnel = _make_cfg(events)
    run_tunneled_deployment_phase(
        MagicMock(), "/build", 2, 4, {}, auto_approve=True, teardown=True,
        audit=MagicMock(), custom_ami=None, cfg=cfg)
    assert "cleanup" in events
