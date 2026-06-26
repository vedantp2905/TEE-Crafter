"""Tests for ``wait_for_oneshot_completion`` race avoidance.

Background
----------
A previous version of this function treated ``systemctl is-active`` returning
``inactive`` as proof the oneshot service had run to completion.  But that
sentinel is also what systemd prints during the brief window between
``systemctl start --no-block`` and the unit actually transitioning to
``activating``.  In practice, the orchestrator on a fast SSH link would poll
during the queued-but-not-yet-started window, see ``inactive``, declare the
job done, then try to download an output tarball that ``ExecStopPost``
hadn't built yet — failing with ``scp: /var/lib/.../output.tar.gz: No such
file or directory``.

These tests pin the corrected behaviour: completion is only accepted once
the unit has been observed in a *running* state (or systemd has recorded an
``ExecMainStartTimestamp``/``Result``), so a freshly-queued service can't
masquerade as a completed one.
"""
from __future__ import annotations

import sys
import os
from typing import Iterator, List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tee_crafter.cli.deployment.common import file_download as fd  # noqa: E402


def _fake_ssh_factory(scripted_outputs: List[str]):
    """Return an ``run_ssh_command`` stub that yields each scripted reply in turn.

    Signature matches both Azure and GCP variants of ``run_ssh_command`` so
    the same stub can be installed on either module reference.
    """
    iterator: Iterator[str] = iter(scripted_outputs)

    def _stub(cmd, ssh_private_key_path, *, user, host, port, timeout):  # noqa: ARG001
        try:
            text = next(iterator)
        except StopIteration:
            text = scripted_outputs[-1]
        return True, text, ""

    return _stub


def _patch_azure_ssh(monkeypatch: pytest.MonkeyPatch, outputs: List[str]) -> None:
    import tee_crafter.core.remote.azure_ssh as azure_ssh

    monkeypatch.setattr(azure_ssh, "run_ssh_command", _fake_ssh_factory(outputs))


def _patch_sleep(monkeypatch: pytest.MonkeyPatch) -> List[float]:
    sleeps: List[float] = []

    def _no_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(fd.time, "sleep", _no_sleep)
    return sleeps


def test_premature_inactive_is_not_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    """First poll sees ``inactive`` (pre-start) — must NOT declare done.

    Subsequent polls show the unit activating, then completing.  The
    function should return ok=True with ``inactive`` only after that
    legitimate completion, never on the first stale ``inactive`` reading.
    """
    outputs = [
        # Poll 1: pre-start sentinel (the bug case).
        "inactive\n"
        "Result=\n"
        "ExecMainStatus=0\n"
        "ActiveState=inactive\n"
        "SubState=dead\n"
        "ExecMainStartTimestampMonotonic=0\n",
        # Poll 2: actually running now.
        "active\n"
        "Result=\n"
        "ExecMainStatus=0\n"
        "ActiveState=active\n"
        "SubState=running\n"
        "ExecMainStartTimestampMonotonic=12345\n",
        # Poll 3: legitimate completion (Result is set, SubState=dead).
        "inactive\n"
        "Result=success\n"
        "ExecMainStatus=0\n"
        "ActiveState=inactive\n"
        "SubState=dead\n"
        "ExecMainStartTimestampMonotonic=12345\n",
    ]
    _patch_azure_ssh(monkeypatch, outputs)
    _patch_sleep(monkeypatch)

    ok, state, _ = fd.wait_for_oneshot_completion(
        platform="sgx-azure",
        service_name="tee-crafter-batch.service",
        timeout=60,
        poll_interval=1,
        ssh_private_key_path="/dev/null",
        ssh_user="azureuser",
        ssh_host="localhost",
        ssh_port=22,
    )
    assert ok is True
    assert state == "inactive"


def test_completion_after_running_state_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    outputs = [
        "activating\nActiveState=activating\nSubState=start\nResult=\nExecMainStartTimestampMonotonic=0\n",
        "inactive\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainStartTimestampMonotonic=99\n",
    ]
    _patch_azure_ssh(monkeypatch, outputs)
    _patch_sleep(monkeypatch)

    ok, state, _ = fd.wait_for_oneshot_completion(
        platform="sgx-azure",
        service_name="tee-crafter-batch.service",
        timeout=60,
        poll_interval=1,
        ssh_private_key_path="/dev/null",
        ssh_user="azureuser",
        ssh_host="localhost",
        ssh_port=22,
    )
    assert ok is True
    assert state == "inactive"


def test_fast_job_post_completion_observed_via_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """A trivial job can complete between polls; we never observe a running state.

    The function must still accept completion when ``Result`` is populated
    (proof the unit ran), instead of declaring ``not-activated``.
    """
    outputs = [
        # First poll catches the unit already finished.  Active=inactive,
        # SubState=dead, but Result=success and ExecMainStart timestamp
        # is non-zero — those two together prove the unit ran.
        "inactive\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainStartTimestampMonotonic=42\n",
    ]
    _patch_azure_ssh(monkeypatch, outputs)
    _patch_sleep(monkeypatch)

    ok, state, _ = fd.wait_for_oneshot_completion(
        platform="sgx-azure",
        service_name="tee-crafter-batch.service",
        timeout=60,
        poll_interval=1,
        ssh_private_key_path="/dev/null",
        ssh_user="azureuser",
        ssh_host="localhost",
        ssh_port=22,
    )
    assert ok is True
    assert state == "inactive"


def test_never_activated_is_surfaced(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the unit never leaves ``inactive`` and Result stays empty, the
    function should not silently succeed — it returns ``not-activated``
    after the grace period so the caller can dump the journal.
    """
    fixed_inactive = (
        "inactive\nActiveState=inactive\nSubState=dead\nResult=\nExecMainStartTimestampMonotonic=0\n"
    )
    _patch_azure_ssh(monkeypatch, [fixed_inactive] * 50)
    _patch_sleep(monkeypatch)

    ok, state, _ = fd.wait_for_oneshot_completion(
        platform="sgx-azure",
        service_name="tee-crafter-batch.service",
        timeout=60,
        poll_interval=1,
        ssh_private_key_path="/dev/null",
        ssh_user="azureuser",
        ssh_host="localhost",
        ssh_port=22,
        activation_grace_sec=2,
    )
    assert ok is False
    assert state == "not-activated"


def test_substate_running_blocks_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ActiveState=inactive`` with ``SubState != dead`` means systemd is
    still tearing the unit down (e.g. running ExecStopPost).  We must not
    declare completion until SubState=dead, otherwise the orchestrator
    races ExecStopPost — which on this codebase is what builds
    /var/lib/tee_crafter/output.tar.gz.
    """
    outputs = [
        # Activated.
        "active\nActiveState=active\nSubState=running\nResult=\nExecMainStartTimestampMonotonic=7\n",
        # ExecStart finished but ExecStopPost still running.
        "inactive\nActiveState=inactive\nSubState=stop-post\nResult=\nExecMainStartTimestampMonotonic=7\n",
        # ExecStopPost done.
        "inactive\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainStartTimestampMonotonic=7\n",
    ]
    _patch_azure_ssh(monkeypatch, outputs)
    _patch_sleep(monkeypatch)

    ok, state, last = fd.wait_for_oneshot_completion(
        platform="sgx-azure",
        service_name="tee-crafter-batch.service",
        timeout=60,
        poll_interval=1,
        ssh_private_key_path="/dev/null",
        ssh_user="azureuser",
        ssh_host="localhost",
        ssh_port=22,
    )
    assert ok is True
    assert state == "inactive"
    assert "SubState=dead" in last
