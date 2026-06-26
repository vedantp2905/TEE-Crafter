"""The Azure measurement VM must inherit the bake path's SDK-bug recovery.

azure-cli 2.89.1 on Python 3.14 intermittently reports a *successful*
``az vm create`` as a failure: ``ERROR: The content for this response was
already consumed``.  ``create_azure_cvm`` has always handled that — it waits,
re-checks with ``az vm show``, and uses the VM if it actually came up.

``capture_azure_cvm_measurement`` called ``az vm create`` directly and treated
any non-zero exit as fatal, so it lost the measurement to a bug the bake three
lines earlier had just survived.  Observed on the real ``snp-azure`` bake of
2026-08-22: bake VM up via the recovery, measurement VM failed 3/3, image left
unpinned — which in turn makes ``deploy`` refuse sealed ``--secrets-env`` and
BYOK for that image.

These tests pin the fix at the level that matters: the capture path *routes
through* ``create_azure_cvm`` (so it cannot silently regain its own copy of the
logic), the shared creator tolerates ``progress=None``, and it honours the
``image`` override so the measurement VM boots the baked image rather than the
Canonical marketplace one.
"""
from __future__ import annotations

import types

import click
import pytest

from tee_crafter.cli.commands.baking.common import azure_cvm


def _res(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


SDK_BUG = "ERROR: The content for this response was already consumed"


def _stub_side_effects(monkeypatch):
    """Neutralise the capture path's real-world side effects.

    ``capture_azure_cvm_measurement`` imports ``os``, ``subprocess`` and
    ``az_cli`` *inside* the function, so they are not attributes of the
    measurement_capture module and have to be patched at their source.
    """
    import os
    import subprocess
    from tee_crafter.cli.commands.baking.common import helpers

    monkeypatch.setattr(helpers, "az_cli", lambda *a, **k: _res(0, "{}"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _res(0, ""))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: None)


class TestErrorClassification:
    def test_already_consumed_is_the_sdk_bug(self):
        assert azure_cvm._classify_error(SDK_BUG) == "sdk_bug"

    def test_classification_is_case_insensitive(self):
        assert azure_cvm._classify_error("ALREADY CONSUMED") == "sdk_bug"

    def test_quota_wins_over_everything(self):
        assert azure_cvm._classify_error("QuotaExceeded blah") == "quota"

    def test_unknown_is_transient(self):
        assert azure_cvm._classify_error("connection reset") == "transient"


class TestProgressIsOptional:
    def test_status_helper_tolerates_none(self):
        azure_cvm._status(None, None, "anything")  # must not raise

    def test_status_helper_updates_when_present(self):
        seen = {}

        class P:
            def update(self, task, description):
                seen["task"], seen["desc"] = task, description

        azure_cvm._status(P(), "t1", "hello")
        assert seen == {"task": "t1", "desc": "hello"}


class TestSdkBugRecovery:
    def _install(self, monkeypatch, calls, script):
        def fake_az(*args, check=True):
            calls.append(args)
            for prefix, result in script:
                if args[:len(prefix)] == prefix:
                    return result(args) if callable(result) else result
            return _res(1, "", "unexpected call")
        monkeypatch.setattr(azure_cvm, "_get_az_cli", lambda: fake_az)
        monkeypatch.setattr(azure_cvm.time, "sleep", lambda *_a: None)

    def test_create_recovers_when_the_vm_actually_exists(self, monkeypatch):
        """The whole point: a bogus failure must not lose the VM."""
        calls = []
        self._install(monkeypatch, calls, [
            (("vm", "create"), _res(1, "", SDK_BUG)),
            (("vm", "show"), _res(0, '{"powerState": "VM running", "publicIps": "20.0.0.7"}')),
        ])
        ip = azure_cvm.create_azure_cvm(
            None, None, "rg", "measure-vm", "westus", "Standard_DC2as_v5", "/tmp/k.pub")
        assert ip == "20.0.0.7"
        assert any(c[:2] == ("vm", "show") for c in calls), "never re-checked with vm show"

    def test_create_gives_up_by_raising_after_retries(self, monkeypatch):
        calls = []
        self._install(monkeypatch, calls, [
            (("vm", "create"), _res(1, "", SDK_BUG)),
            (("vm", "show"), _res(1, "", "not found")),
            (("vm", "delete"), _res(0, "")),
        ])
        with pytest.raises(click.ClickException):
            azure_cvm.create_azure_cvm(
                None, None, "rg", "measure-vm", "westus", "Standard_DC2as_v5", "/tmp/k.pub")
        assert sum(1 for c in calls if c[:2] == ("vm", "create")) == 3

    def test_happy_path_needs_no_show(self, monkeypatch):
        calls = []
        self._install(monkeypatch, calls, [
            (("vm", "create"), _res(0, '{"publicIpAddress": "20.0.0.9"}')),
        ])
        assert azure_cvm.create_azure_cvm(
            None, None, "rg", "vm", "westus", "s", "k.pub") == "20.0.0.9"
        assert not any(c[:2] == ("vm", "show") for c in calls)


class TestImageOverride:
    def test_default_is_the_canonical_cvm_marketplace_image(self, monkeypatch):
        seen = {}

        def fake_az(*args, check=True):
            seen["args"] = args
            return _res(0, '{"publicIpAddress": "1.2.3.4"}')
        monkeypatch.setattr(azure_cvm, "_get_az_cli", lambda: fake_az)
        azure_cvm.create_azure_cvm(None, None, "rg", "vm", "westus", "s", "k.pub")
        args = seen["args"]
        assert args[args.index("--image") + 1] == azure_cvm._CVM_IMAGE

    def test_explicit_image_is_used(self, monkeypatch):
        seen = {}
        gallery_id = ("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute"
                      "/galleries/g/images/i/versions/2026.0822.065045")

        def fake_az(*args, check=True):
            seen["args"] = args
            return _res(0, '{"publicIpAddress": "1.2.3.4"}')
        monkeypatch.setattr(azure_cvm, "_get_az_cli", lambda: fake_az)
        azure_cvm.create_azure_cvm(None, None, "rg", "vm", "westus", "s", "k.pub",
                                   image=gallery_id)
        args = seen["args"]
        assert args[args.index("--image") + 1] == gallery_id


class TestCapturePathRoutesThroughTheSharedCreator:
    """Guard against the capture path re-growing its own `az vm create`."""

    def test_it_calls_create_azure_cvm_with_the_baked_image(self, monkeypatch, tmp_path):
        from tee_crafter.cli.commands.baking.common import measurement_capture as mc

        recorded = {}

        def fake_create(progress, task, rg, name, location, size, pubkey, **kw):
            recorded.update(rg=rg, name=name, location=location, size=size,
                            image=kw.get("image"), platform=kw.get("platform_label"),
                            progress=progress)
            return "20.1.2.3"

        monkeypatch.setattr(azure_cvm, "create_azure_cvm", fake_create)
        _stub_side_effects(monkeypatch)
        import tee_crafter.core.remote.azure_ssh as assh
        monkeypatch.setattr(assh, "wait_for_ssh", lambda *a, **k: True)
        monkeypatch.setattr(assh, "run_ssh_command",
                            lambda *a, **k: (True, "TEE_CRAFTER_MEASUREMENT=" + "ab" * 48, ""))

        gallery_id = "/subscriptions/s/.../versions/2026.0822.065045"
        out = mc.capture_azure_cvm_measurement(
            gallery_id, "westus", vm_size="Standard_DC2as_v5",
            platform="snp-azure", store=False)

        assert recorded["image"] == gallery_id, (
            "measurement VM must boot the baked gallery image")
        assert recorded["progress"] is None, "capture path has no spinner to drive"
        assert recorded["platform"] == "snp-azure"
        assert out == "ab" * 48

    def test_a_giveup_is_reported_and_never_fails_the_bake(self, monkeypatch):
        """ClickException from the creator must become a warning + None."""
        from tee_crafter.cli.commands.baking.common import measurement_capture as mc

        def boom(*a, **k):
            raise click.ClickException("Azure vCPU quota exceeded for X")

        warned = []
        monkeypatch.setattr(azure_cvm, "create_azure_cvm", boom)
        monkeypatch.setattr(mc, "_warn", lambda m: warned.append(m))
        _stub_side_effects(monkeypatch)

        out = mc.capture_azure_cvm_measurement(
            "/img", "westus", vm_size="Standard_DC2as_v5",
            platform="snp-azure", store=False)

        assert out is None
        assert warned, "give-up must be surfaced, not swallowed"
        assert "quota exceeded" in warned[0].lower()
        # Must come from the dedicated ClickException arm, not the catch-all:
        # the generic handler formats `repr(exc)`, which would still contain the
        # quota text and so would pass the assertion above on its own.
        assert warned[0].startswith("could not launch Azure measurement VM"), warned[0]
        assert "unexpected error" not in warned[0].lower()
        # The bake continues: no exception escaped.

    def test_no_raw_vm_create_remains_in_the_capture_source(self):
        """Cheap structural backstop for the same regression."""
        import inspect
        from tee_crafter.cli.commands.baking.common import measurement_capture as mc
        src = inspect.getsource(mc.capture_azure_cvm_measurement)
        assert "create_azure_cvm(" in src
        assert '"vm", "create"' not in src, (
            "capture path grew its own az vm create again; it will lose "
            "measurements to the azure-cli SDK bug")
