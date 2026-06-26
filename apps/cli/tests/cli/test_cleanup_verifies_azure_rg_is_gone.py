"""``terraform destroy`` exiting 0 is not proof the resources are gone.

After the ``sgx-azure`` batch failure on 2026-08-22 the cleanup path printed
"✓ Resources destroyed" while ``tee-crafter-sgx-rg-bee09592`` still held a
Bastion host, its public IP, the VNet and two Network Watcher resources.  The
Bastion alone bills ~$0.19/hr; it ran until someone noticed and deleted it by
hand.  ``cleanup_resources`` had taken the destroy's exit code as the whole
answer.

The check added for it is not a heuristic.  All four Azure templates declare
their own ``azurerm_resource_group``, so a destroy that really finished leaves
no group behind — a surviving group is a completed-but-incomplete teardown by
definition.  These tests pin the three things that make the check worth having:

* a success that is contradicted by the cloud escalates to ``az group delete``
  rather than being reported as a success;
* the resource-group name is read *before* the destroy, because
  ``terraform output`` reads live state and a successful destroy empties it —
  reading afterwards would return nothing and skip the check in exactly the
  case it exists for;
* "az could not answer" is treated as *present*, never as gone, matching the
  fail-closed contract ``_rg_exists`` already documents.
"""
from __future__ import annotations

import pytest

from tee_crafter.cli.deployment.common import terraform_step


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, *args, **kwargs):
        self.lines.append(" ".join(str(a) for a in args))

    @property
    def text(self):
        return "\n".join(self.lines)


@pytest.fixture
def harness(monkeypatch):
    """Drive ``cleanup_resources`` with every cloud call stubbed.

    Returns a callable taking the outcomes to simulate and reporting what the
    function did: its verdict, whether the force-delete ran, and at what point
    the resource-group name was looked up.
    """
    def _run(*, cloud="azure", destroy_ok=True, rg_name="tee-crafter-sgx-rg-bee09592",
             rg_exists=(False, ""), force_delete_ok=True):
        events = []
        console = _Console()

        monkeypatch.setattr(terraform_step, "_detect_cloud_from_build",
                            lambda _b: cloud)

        def _rg_name(_build_dir):
            events.append("read-rg-name")
            return rg_name
        monkeypatch.setattr(terraform_step, "_detect_azure_rg_name", _rg_name)

        def _destroy(_build_dir, prune_local_docker=True):
            events.append("destroy")
            return destroy_ok, "" if destroy_ok else "state lock"
        monkeypatch.setattr(terraform_step, "run_terraform_destroy", _destroy)

        def _exists(name):
            events.append(f"rg-exists:{name}")
            return rg_exists
        monkeypatch.setattr(terraform_step, "_rg_exists", _exists)

        def _force(_console, name):
            events.append(f"force-delete:{name}")
            return force_delete_ok
        monkeypatch.setattr(terraform_step, "_az_force_delete_rg", _force)

        verdict = terraform_step.cleanup_resources(console, "/build", context="cleanup")
        return verdict, events, console.text

    return _run


class TestASuccessfulDestroyIsVerified:
    def test_a_surviving_group_is_not_reported_as_success(self, harness):
        """The 2026-08-22 regression, in one assertion."""
        ok, events, text = harness(destroy_ok=True, rg_exists=(True, ""))
        assert "force-delete:tee-crafter-sgx-rg-bee09592" in events
        assert ok is True  # because the force-delete then succeeded
        assert "still present" in text

    def test_a_surviving_group_that_cannot_be_deleted_fails(self, harness):
        ok, _events, _text = harness(destroy_ok=True, rg_exists=(True, ""),
                                     force_delete_ok=False)
        assert ok is False

    def test_a_confirmed_gone_group_passes_without_escalating(self, harness):
        ok, events, text = harness(destroy_ok=True, rg_exists=(False, ""))
        assert ok is True
        assert not any(e.startswith("force-delete") for e in events)
        assert "confirmed gone" in text

    def test_az_being_unable_to_answer_counts_as_present(self, harness):
        """``_rg_exists`` fails closed; cleanup must honour that rather than
        reading the empty-ish answer as a clean teardown."""
        ok, events, text = harness(destroy_ok=True,
                                   rg_exists=(True, "Please run 'az login'"))
        assert any(e.startswith("force-delete") for e in events)
        assert "az login" in text
        assert ok is True


class TestTheGroupNameIsReadBeforeTheDestroy:
    def test_name_lookup_precedes_destroy(self, harness):
        """``terraform output`` reads live state.  A successful destroy empties
        it, so a lookup afterwards returns "" and the check silently no-ops."""
        _ok, events, _text = harness(destroy_ok=True, rg_exists=(True, ""))
        assert events.index("read-rg-name") < events.index("destroy")

    def test_an_unknown_group_name_is_flagged_not_silently_passed(self, harness):
        ok, events, text = harness(destroy_ok=True, rg_name="")
        assert ok is True
        assert not any(e.startswith("rg-exists") for e in events)
        assert "could not be confirmed gone" in text


class TestNonAzureAndFailurePathsAreUnchanged:
    def test_aws_success_does_not_consult_azure(self, harness):
        ok, events, _text = harness(cloud="aws", destroy_ok=True)
        assert ok is True
        assert events == ["destroy"]

    def test_aws_failure_still_fails(self, harness):
        ok, events, text = harness(cloud="aws", destroy_ok=False)
        assert ok is False
        assert not any(e.startswith("force-delete") for e in events)
        assert "Terraform destroy failed" in text

    def test_azure_failure_still_falls_back_to_group_delete(self, harness):
        ok, events, _text = harness(destroy_ok=False)
        assert ok is True
        assert "force-delete:tee-crafter-sgx-rg-bee09592" in events
        # The failure path never needed the existence probe — it escalates
        # regardless, and _az_force_delete_rg does its own check.
        assert not any(e.startswith("rg-exists") for e in events)
