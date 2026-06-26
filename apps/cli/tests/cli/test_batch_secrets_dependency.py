"""The CVM batch path must ship the script its own systemd dependency runs.

Every CVM container unit carries ``Requires=tee-crafter-secrets.service``
(``resources._secrets_dep_block``), and that oneshot executes
``<remote_base>/app/tee_crafter_secret_bootstrap.py``. The batch path uploaded
only ``user_container.tar``, so the script was never on the VM:

    can't open file '/opt/tee-crafter-snp/app/tee_crafter_secret_bootstrap.py'

systemd cancelled the container unit's job, the container never started, the
``ExecStopPost`` capture hook found no container and exited 1, and the deploy
failed several steps later with
``scp: /var/lib/tee_crafter/output.tar.gz: No such file or directory`` — a
symptom that points nowhere near the cause. Reproduced on ``snp-azure`` and
``tdx-azure`` on 2026-08-22 and confirmed on the live VM.

What made it survive so long is the second half, covered by
``TestNeverRanIsNotSuccess``: the activation probe treated a non-empty
``Result=`` as proof the unit had run. A unit whose job was cancelled reports
``Result=success`` with ``ExecMainStartTimestampMonotonic=0``, because systemd
never executed it and "success" is that field's initial value. So the probe
returned ACTIVATED for a unit that never started, and every downstream step
proceeded on that basis.

Uploading the script is the fix rather than dropping the ``Requires=`` when no
secrets were requested: the oneshot is a fail-closed gate, and deciding locally
that "there are no secrets, so skip the gate" puts the gate behind a guess.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

import tee_crafter.cli.commands.deploy.batch as batch_mod
from tee_crafter.cli.commands.deploy.batch import BatchTransport
from tee_crafter.cli.constants import Console

SCRIPT = "tee_crafter_secret_bootstrap.py"


def _transport(platform: str) -> BatchTransport:
    return BatchTransport(platform=platform, ssh_private_key_path="/dev/null",
                          ssh_user="tee_admin")


def _harness(tmp_path: Path, *, platform: str, stage_script: bool,
             stage_env: bool = False):
    """Return ``(upload_mock, ssh_calls, run)`` for the upload helper."""
    if stage_script:
        app = tmp_path / "app"
        app.mkdir(exist_ok=True)
        (app / SCRIPT).write_text("# stub\n")
    if stage_env:
        app = tmp_path / "app"
        app.mkdir(exist_ok=True)
        (app / "app.env").write_text("SECRET=1\n")

    upload_mock = MagicMock(return_value=(True, "ok"))
    ssh_calls: list[str] = []

    def fake_run_remote(cmd, timeout=60):
        ssh_calls.append(cmd)
        return True, "", ""

    def run():
        return batch_mod._upload_secret_bootstrap(
            _transport(platform), fake_run_remote, upload_mock, Console(),
            build_dir=str(tmp_path),
        )

    return upload_mock, ssh_calls, run


class TestTheScriptIsUploaded:
    @pytest.mark.parametrize("platform", ["snp-azure", "tdx-azure", "snp-gcp",
                                          "snp-aws", "gpu-cc-azure"])
    def test_cvm_platforms_upload_it(self, tmp_path, platform):
        upload_mock, ssh_calls, run = _harness(
            tmp_path, platform=platform, stage_script=True)
        ok, msg = run()
        assert ok, msg
        uploaded = [c.args[0] for c in upload_mock.call_args_list]
        assert any(p.endswith(SCRIPT) for p in uploaded), uploaded

    def test_it_lands_under_the_platform_remote_base(self, tmp_path):
        from tee_crafter.resources import _REMOTE_BASE
        upload_mock, ssh_calls, run = _harness(
            tmp_path, platform="snp-azure", stage_script=True)
        ok, _ = run()
        assert ok
        base = _REMOTE_BASE["snp-azure"]
        assert any(f"{base}/app/{SCRIPT}" in c for c in ssh_calls), ssh_calls

    def test_it_is_staged_through_tmp_not_written_directly(self, tmp_path):
        """The remote base is root-owned; scp as the login user cannot write it."""
        upload_mock, _, run = _harness(
            tmp_path, platform="snp-azure", stage_script=True)
        run()
        for call in upload_mock.call_args_list:
            remote = call.args[1]
            if remote.endswith(SCRIPT):
                assert remote.startswith("/tmp/"), remote

    def test_the_remote_app_dir_is_created_first(self, tmp_path):
        _, ssh_calls, run = _harness(
            tmp_path, platform="snp-azure", stage_script=True)
        run()
        mkdirs = [i for i, c in enumerate(ssh_calls) if "mkdir -p" in c]
        moves = [i for i, c in enumerate(ssh_calls) if "mv " in c]
        assert mkdirs and moves and min(mkdirs) < min(moves)

    def test_a_build_dir_root_copy_is_accepted(self, tmp_path):
        """``platform.py`` stages the script in both build_dir and build_dir/app."""
        (tmp_path / SCRIPT).write_text("# stub\n")
        upload_mock, _, run = _harness(
            tmp_path, platform="snp-azure", stage_script=False)
        ok, msg = run()
        assert ok, msg
        assert any(c.args[0].endswith(SCRIPT)
                   for c in upload_mock.call_args_list)


class TestSgxHasNoSecretsOneshot:
    def test_sgx_is_a_noop(self, tmp_path):
        """SGX is not in ``_REMOTE_BASE`` and its unit has no Requires=."""
        upload_mock, ssh_calls, run = _harness(
            tmp_path, platform="sgx-azure", stage_script=False)
        ok, msg = run()
        assert ok and msg == ""
        assert upload_mock.call_args_list == []
        assert ssh_calls == []

    def test_the_sgx_unit_really_has_no_secrets_requirement(self):
        """Guard the premise above rather than trusting the comment."""
        from tee_crafter.resources import load_container_batch_unit
        unit = load_container_batch_unit("sgx-azure")
        assert "tee-crafter-secrets.service" not in unit

    @pytest.mark.parametrize("platform", ["snp-azure", "tdx-azure", "snp-gcp"])
    def test_cvm_units_do_require_it(self, platform):
        from tee_crafter.resources import load_container_batch_unit
        unit = load_container_batch_unit(platform)
        assert "Requires=tee-crafter-secrets.service" in unit, (
            "if this stops being true the upload is unnecessary — but so is "
            "this whole test file, so re-read it rather than deleting the upload")


class TestMissingScriptFailsClosed:
    def test_absent_script_is_an_error_not_a_warning(self, tmp_path):
        ok, msg = _harness(tmp_path, platform="snp-azure",
                           stage_script=False)[2]()
        assert not ok
        assert SCRIPT in msg

    def test_no_upload_is_attempted_when_absent(self, tmp_path):
        upload_mock, ssh_calls, run = _harness(
            tmp_path, platform="snp-azure", stage_script=False)
        run()
        assert upload_mock.call_args_list == []


class TestAppEnvRidesAlong:
    def test_app_env_is_uploaded_when_present(self, tmp_path):
        upload_mock, ssh_calls, run = _harness(
            tmp_path, platform="snp-azure", stage_script=True, stage_env=True)
        ok, msg = run()
        assert ok, msg
        assert any(c.args[0].endswith("app.env")
                   for c in upload_mock.call_args_list)

    def test_app_env_is_installed_0600(self, tmp_path):
        _, ssh_calls, run = _harness(
            tmp_path, platform="snp-azure", stage_script=True, stage_env=True)
        run()
        assert any("chmod 0600" in c and "app.env" in c for c in ssh_calls), ssh_calls

    def test_absent_app_env_is_fine(self, tmp_path):
        upload_mock, _, run = _harness(
            tmp_path, platform="snp-azure", stage_script=True, stage_env=False)
        ok, _ = run()
        assert ok
        assert not any(c.args[0].endswith("app.env")
                       for c in upload_mock.call_args_list)


class TestNeverRanIsNotSuccess:
    """``Result=success`` with a zero start timestamp means it never executed."""

    def _probe(self) -> str:
        import inspect
        return inspect.getsource(batch_mod._start_oneshot_and_wait)

    def test_the_result_only_shortcut_is_gone(self):
        src = self._probe()
        assert 'echo ACTIVATED:ran:result=$result' not in src, (
            "a non-empty Result= does not mean the unit ran; a job cancelled by "
            "a failed Requires= reports Result=success with no execution")

    def test_never_ran_is_reported_as_its_own_state(self):
        src = self._probe()
        assert "NEVER_RAN" in src

    def test_never_ran_is_no_longer_inferred_from_the_state_fields(self):
        """It was, and that was the *next* bug.

        ``inactive`` + ``Result=success`` + a zero start timestamp does mean
        "never executed" — but it equally means "queued behind a dependency
        that has not finished yet", and that is what an Azure CVM's secrets
        oneshot looks like for the first minute.  ``systemctl list-jobs`` is
        the discriminator; see ``test_oneshot_activation_probe.py`` for the
        measured state table.
        """
        src = self._probe()
        assert 'started\\" = \\"0\\"' not in src and '$started" = "0"' not in src
        assert "systemctl list-jobs" in src

    def test_never_ran_is_treated_as_failure(self):
        src = self._probe()
        assert 'startswith(("NOT_ACTIVATED", "NEVER_RAN",' in src

    def test_the_started_timestamp_shortcut_survives(self):
        """A non-zero start timestamp *is* valid evidence the unit ran."""
        src = self._probe()
        assert 'ACTIVATED:ran:started=$started' in src

    def test_the_journal_is_printed_not_discarded(self):
        """Dropping it is what left only the SCP error to debug from."""
        src = self._probe()
        assert "journalctl" in src
        assert "console.print" in src


class TestTheServerImageWarningMovedToBuildTime:
    """It used to run here, on the VM.  See test_batch_server_image_preflight."""

    def test_the_vm_side_check_is_gone(self):
        assert not hasattr(batch_mod, "_warn_if_server_image")

    def test_the_batch_path_no_longer_warns_after_docker_load(self):
        """Warning here costs the operator ~20 min of Terraform first."""
        import inspect
        src = inspect.getsource(batch_mod.run_batch_container_deploy)
        assert "_warn_if_server_image" not in src
