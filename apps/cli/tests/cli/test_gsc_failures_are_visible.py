"""A failing ``gsc build`` has to look like a failing ``gsc build``.

``graminize_on_vm`` used to run::

    run_remote(f"sudo gsc build {image} {manifest} 2>&1 | tail -40")

A shell pipeline exits with the status of its **last** command, and ``tail``
succeeds unconditionally, so ``ok`` was ``True`` however GSC had actually
fared.  Both ``gsc build`` and ``gsc sign-image`` therefore always "passed",
and the only thing that caught the problem was the ``docker image inspect``
afterwards — which could say nothing more useful than ``gsc reported success
but gsc-<image> does not exist on the VM``.

The output that would have explained it was not lost by accident either: it was
assigned to ``out`` and then printed only inside ``if not ok:``, a branch that
had become unreachable.

Measured on a real ``sgx-azure`` batch deploy on 2026-08-22: the run failed with
exactly that message and not one line of GSC's own output, which is why B9 ("no
MRENCLAVE has ever been measured") had stayed open through several attempts —
each attempt destroyed the evidence along with the VM.

The replacement redirects GSC's output to a log on the VM and returns the exit
status in a sentinel line, so no amount of piping can launder it.
"""
from __future__ import annotations

import inspect

from tee_crafter.cli.commands.deploy import batch as batch_mod


class _Recorder:
    """Captures the command and replays a scripted ``(ok, stdout, stderr)``."""

    def __init__(self, stdout="", *, ok=True, stderr=""):
        self.commands: list[str] = []
        self._ok, self._stdout, self._stderr = ok, stdout, stderr

    def __call__(self, cmd, timeout=60):
        self.commands.append(cmd)
        return self._ok, self._stdout, self._stderr


class TestTheExitStatusSurvives:
    def test_a_nonzero_gsc_is_a_failure(self):
        run = _Recorder("TEE_CRAFTER_RC=1\nsome gsc error\n")
        ok, out, err = batch_mod._run_gsc(
            run, "gsc build x y", log="/tmp/l.log", timeout=10)
        assert not ok
        assert "exited 1" in err

    def test_a_zero_gsc_is_a_success(self):
        run = _Recorder("TEE_CRAFTER_RC=0\nSuccessfully built\n")
        ok, _, err = batch_mod._run_gsc(
            run, "gsc build x y", log="/tmp/l.log", timeout=10)
        assert ok and err == ""

    def test_a_missing_marker_is_a_failure_not_a_pass(self):
        """Absence of evidence must not read as success — that was the bug."""
        run = _Recorder("some output with no marker at all\n")
        ok, _, err = batch_mod._run_gsc(
            run, "gsc build x y", log="/tmp/l.log", timeout=10)
        assert not ok
        assert "exit status is\nunknown" in err or "unknown" in err

    def test_a_transport_failure_is_a_failure(self):
        run = _Recorder("", ok=False, stderr="ssh died")
        ok, _, err = batch_mod._run_gsc(
            run, "gsc build x y", log="/tmp/l.log", timeout=10)
        assert not ok
        assert "could not run" in err

    def test_the_marker_is_read_from_its_own_line(self):
        """A log line merely containing the marker text must not be mistaken."""
        run = _Recorder("TEE_CRAFTER_RC=0\nnote: TEE_CRAFTER_RC=1 appears here\n")
        ok, _, _ = batch_mod._run_gsc(
            run, "gsc build x y", log="/tmp/l.log", timeout=10)
        assert ok


class TestTheDiagnosticsSurvive:
    def test_output_is_redirected_to_a_log_on_the_vm(self):
        run = _Recorder("TEE_CRAFTER_RC=0\n")
        batch_mod._run_gsc(run, "gsc build x y", log="/tmp/keep.log", timeout=10)
        assert "> /tmp/keep.log 2>&1" in run.commands[0]

    def test_the_log_is_tailed_back_to_the_operator(self):
        run = _Recorder("TEE_CRAFTER_RC=0\n")
        batch_mod._run_gsc(run, "gsc build x y", log="/tmp/keep.log", timeout=10)
        assert "tail -80 /tmp/keep.log" in run.commands[0]

    def test_the_failure_message_carries_the_log_text(self):
        run = _Recorder("TEE_CRAFTER_RC=127\napt-key: not found\n")
        _, out, _ = batch_mod._run_gsc(
            run, "gsc build x y", log="/tmp/l.log", timeout=10)
        assert "apt-key: not found" in out


class TestTheOldBugCannotComeBack:
    def test_no_gsc_invocation_pipes_into_tail(self):
        src = inspect.getsource(batch_mod.graminize_on_vm)
        assert "| tail -" not in src, (
            "piping gsc into tail discards its exit status; use _run_gsc")

    def test_graminize_routes_both_commands_through_the_wrapper(self):
        src = inspect.getsource(batch_mod.graminize_on_vm)
        assert src.count("_run_gsc(") == 2

    def test_the_missing_image_error_points_at_the_logs(self):
        """The message an operator actually hits should say where to look."""
        src = inspect.getsource(batch_mod.graminize_on_vm)
        assert "tee-crafter-gsc-build.log" in src
        assert "TEE_CRAFTER_KEEP_ON_FAILURE=1" in src
