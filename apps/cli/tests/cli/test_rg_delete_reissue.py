"""An Azure group delete that gives up must be noticed and re-issued.

Azure can abandon an asynchronous `az group delete` without reporting anything:
the group's provisioningState reverts to `Succeeded` and it stays fully
populated. On 2026-08-23 that happened three times, twice to the same group, and
left two Bastion hosts (~$0.19/hr each) plus a NAT gateway running for about
eleven hours after a teardown said "deletion initiated".
"""
from __future__ import annotations

import pytest

from tee_crafter.cli.deployment.common import terraform_step as ts


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, *a, **kw):
        self.lines.append(" ".join(str(x) for x in a))

    @property
    def text(self):
        return "\n".join(self.lines)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda s: None)


class TestReissue:

    def test_reissues_when_azure_abandons_the_delete(self, monkeypatch):
        """provisioningState back to Succeeded while the group still exists."""
        states = ["Deleting", "Succeeded", "Succeeded"]
        monkeypatch.setattr(ts, "_rg_exists", lambda n: (True, ""))
        monkeypatch.setattr(ts, "_rg_provisioning_state",
                            lambda n: states.pop(0) if states else "Succeeded")
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        c = _Console()
        assert ts._wait_for_rg_deletion(c, "rg", timeout=0.0001) is False
        # No re-issue on the first poll (it was legitimately Deleting).
        assert all("delete" in a for a in ["".join(x) for x in ran]) or not ran

    def test_stops_after_the_reissue_budget(self, monkeypatch):
        monkeypatch.setattr(ts, "_rg_exists", lambda n: (True, ""))
        monkeypatch.setattr(ts, "_rg_provisioning_state", lambda n: "Succeeded")
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        c = _Console()
        assert ts._wait_for_rg_deletion(c, "rg", timeout=600) is False
        assert len(ran) == ts._AZURE_RG_DELETE_MAX_REISSUES
        assert "refusing to delete" in c.text

    def test_tells_the_operator_how_to_find_the_blocker(self, monkeypatch):
        monkeypatch.setattr(ts, "_rg_exists", lambda n: (True, ""))
        monkeypatch.setattr(ts, "_rg_provisioning_state", lambda n: "Failed")
        monkeypatch.setattr(ts.subprocess, "run", lambda argv, **kw: None)
        c = _Console()
        ts._wait_for_rg_deletion(c, "myrg", timeout=600)
        assert "az resource list -g myrg" in c.text

    def test_does_not_reissue_while_genuinely_deleting(self, monkeypatch):
        """A slow Bastion delete must be waited out, not restarted."""
        monkeypatch.setattr(ts, "_rg_exists", lambda n: (True, ""))
        monkeypatch.setattr(ts, "_rg_provisioning_state", lambda n: "Deleting")
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        ts._wait_for_rg_deletion(_Console(), "rg", timeout=0.0001)
        assert ran == []

    def test_success_short_circuits(self, monkeypatch):
        monkeypatch.setattr(ts, "_rg_exists", lambda n: (False, ""))
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        c = _Console()
        assert ts._wait_for_rg_deletion(c, "rg", timeout=600) is True
        assert ran == []
        assert "fully deleted" in c.text

    def test_unreadable_state_is_not_treated_as_abandoned(self, monkeypatch):
        """`az` failing to answer must not trigger a delete storm."""
        monkeypatch.setattr(ts, "_rg_exists", lambda n: (True, ""))
        monkeypatch.setattr(ts, "_rg_provisioning_state", lambda n: "")
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        ts._wait_for_rg_deletion(_Console(), "rg", timeout=0.0001)
        assert ran == []


class TestProvisioningStateReader:

    def test_returns_the_state(self, monkeypatch):
        class _P:
            returncode, stdout, stderr = 0, "Deleting\n", ""
        monkeypatch.setattr(ts.subprocess, "run", lambda argv, **kw: _P())
        assert ts._rg_provisioning_state("rg") == "Deleting"

    def test_empty_when_az_fails(self, monkeypatch):
        class _P:
            returncode, stdout, stderr = 1, "", "not found"
        monkeypatch.setattr(ts.subprocess, "run", lambda argv, **kw: _P())
        assert ts._rg_provisioning_state("rg") == ""
