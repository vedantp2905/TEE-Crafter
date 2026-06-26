"""A batch run that does not succeed must not leave the TEE billing.

``phase_runner.destroy_on_failure`` already covered the persistent phases: a
failed ``terraform apply`` *or* a failed attestation tears the stack down unless
``--keep-on-failure`` is set.  Batch mode never got that treatment — it only
destroyed on ``--teardown``, so a failed apply, a dead Bastion/IAP tunnel, or a
container that never ran all left the VM (and, on the NAT-backed platforms, a
gateway) running while the CLI exited non-zero.

Two of those paths also returned ``None``, which the caller in
``deploy_container`` reads as "staged, --deploy not passed" — so they exited 0.
"""
from __future__ import annotations

import pytest

from tee_crafter.cli.commands.deploy import batch_dispatch
from tee_crafter.cli.commands.deploy.batch import BatchResult
from tee_crafter.cli.constants import KEEP_ON_FAILURE_ENV


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, *args, **kwargs):
        self.lines.append(" ".join(str(a) for a in args))

    @property
    def text(self):
        return "\n".join(self.lines)


@pytest.fixture
def destroyed(monkeypatch):
    """Record every ``cleanup_resources`` call made by the dispatcher."""
    calls = []

    def _cleanup(console, build_dir, context=""):
        calls.append(context)
        return True

    monkeypatch.setattr(
        "tee_crafter.cli.deployment.common.terraform_step.cleanup_resources",
        _cleanup,
    )
    monkeypatch.delenv(KEEP_ON_FAILURE_ENV, raising=False)
    return calls


def _dispatch(tmp_path, monkeypatch, *, apply_ok=True, staged_ok=True,
              batch_result=None, tunnel_raises=None, teardown=False):
    monkeypatch.setattr(
        batch_dispatch, "_ensure_batch_terraform_staged",
        lambda *a, **k: staged_ok,
    )
    monkeypatch.setattr(
        batch_dispatch, "_terraform_apply_for_batch", lambda *a, **k: apply_ok,
    )

    from contextlib import contextmanager

    @contextmanager
    def _tunnel(platform, build_dir, console):
        if tunnel_raises is not None:
            raise tunnel_raises
        yield object()

    monkeypatch.setattr(batch_dispatch, "_platform_tunnel", _tunnel)
    monkeypatch.setattr(
        batch_dispatch, "run_batch_container_deploy",
        lambda **kwargs: batch_result,
    )
    tar = tmp_path / "user_container.tar"
    tar.write_bytes(b"")
    return batch_dispatch.dispatch_batch_container(
        build_dir=str(tmp_path), tee_platform="snp-aws",
        container_tar_path=str(tar), do_deploy=True, auto_approve=True,
        teardown=teardown, batch_timeout=60, max_output_size=None,
        input_dir=None, audit=None, console=_Console(),
        cpu=2, ram_mb=4096,
    )


class TestFailureTearsDown:
    def test_failed_terraform_apply(self, tmp_path, monkeypatch, destroyed):
        result = _dispatch(tmp_path, monkeypatch, apply_ok=False)
        assert destroyed == ["Batch-failure cleanup"]
        assert result is not None and not result.success

    def test_failed_batch_run(self, tmp_path, monkeypatch, destroyed):
        result = _dispatch(
            tmp_path, monkeypatch,
            batch_result=BatchResult(False, message="container exited 1"),
        )
        assert destroyed == ["Batch-failure cleanup"]
        assert not result.success

    def test_tunnel_exception(self, tmp_path, monkeypatch, destroyed):
        result = _dispatch(
            tmp_path, monkeypatch, tunnel_raises=RuntimeError("bastion down"),
        )
        assert destroyed == ["Batch-failure cleanup"]
        assert not result.success

    def test_staging_failure_exits_non_zero(self, tmp_path, monkeypatch, destroyed):
        """Nothing is provisioned yet, so no destroy — but it must still be a
        failure rather than the ``None`` that read as rc=0."""
        result = _dispatch(tmp_path, monkeypatch, staged_ok=False)
        assert destroyed == []
        assert result is not None and not result.success


class TestKeepOnFailureOptsOut:
    def test_keep_on_failure_leaves_resources(self, tmp_path, monkeypatch,
                                              destroyed):
        monkeypatch.setenv(KEEP_ON_FAILURE_ENV, "1")
        result = _dispatch(
            tmp_path, monkeypatch,
            batch_result=BatchResult(False, message="container exited 1"),
        )
        assert destroyed == []
        assert not result.success


class TestSuccessIsUnchanged:
    def test_success_without_teardown_keeps_resources(self, tmp_path, monkeypatch,
                                                      destroyed):
        result = _dispatch(tmp_path, monkeypatch, batch_result=BatchResult(True))
        assert destroyed == []
        assert result.success

    def test_success_with_teardown_destroys(self, tmp_path, monkeypatch, destroyed):
        result = _dispatch(
            tmp_path, monkeypatch, batch_result=BatchResult(True), teardown=True,
        )
        assert destroyed == ["Batch teardown"]
        assert result.success

    def test_no_deploy_still_returns_none(self, tmp_path, monkeypatch, destroyed):
        """``--deploy`` absent is "staged, nothing provisioned" — the one case
        the caller is supposed to read as ``None`` / rc=0."""
        tar = tmp_path / "user_container.tar"
        tar.write_bytes(b"")
        result = batch_dispatch.dispatch_batch_container(
            build_dir=str(tmp_path), tee_platform="snp-aws",
            container_tar_path=str(tar), do_deploy=False, auto_approve=False,
            teardown=False, batch_timeout=60, max_output_size=None,
            input_dir=None, audit=None, console=_Console(),
        )
        assert result is None
        assert destroyed == []
