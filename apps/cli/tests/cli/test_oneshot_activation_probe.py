"""What a ``Type=oneshot`` unit's state actually tells you, and what it doesn't.

The batch path starts its unit with ``systemctl start --no-block`` and then has
to work out from the outside what became of it.  That turned out to be much
harder than the original code assumed, because ``systemctl show`` reports the
*same* thing in four different situations.  Measured on real systemd 257
(Debian 13) in a throwaway privileged container, one scenario at a time:

    situation                 | jobs | ActiveState | Result    | InvocationID
    --------------------------|------|-------------|-----------|-------------
    never started             |  0   | inactive    | success   | (empty)
    queued behind a slow dep  |  1   | inactive    | success   | (empty)
    job cancelled (dep died)  |  0   | inactive    | success   | (empty)
    running                   |  1   | activating  | success   | set
    finished successfully     |  0   | inactive    | success   | (empty)
    exited non-zero           |  0   | failed      | exit-code | set

Two results from that run drive the current design.

**A successful oneshot leaves no trace in its own unit state.**  Polling a unit
that ran ``/bin/sleep 2`` every second::

    t=1s jobs=1 ActiveState=activating InvocationID=c0a47099… ExecMainStart=77341083025
    t=2s jobs=1 ActiveState=activating InvocationID=c0a47099… ExecMainStart=77341083025
    t=3s jobs=0 ActiveState=inactive   InvocationID=          ExecMainStart=0
    t=4s jobs=0 ActiveState=inactive   InvocationID=          ExecMainStart=0

systemd releases the runtime state of a successful ``RemainAfterExit=no`` unit
the moment it goes back to inactive, so ``ExecMainStartTimestampMonotonic`` is
**not** durable evidence that anything ran.  A unit that finished and a unit
that was never touched are byte-identical.  Only a *failed* unit keeps its
state (``ActiveState=failed``, ``Result=exit-code``, ``ExecMainStatus=7``).

**``systemctl list-jobs`` is the one signal that separates queued from
cancelled.**  Sampling a unit queued behind a 40-second dependency::

    t=4s  jobs=1 Result=success ExecMainStart=0 ActiveState=inactive SubState=dead
    t=8s  jobs=1 Result=success ExecMainStart=0 ActiveState=inactive SubState=dead
    t=12s jobs=1 Result=success ExecMainStart=0 ActiveState=inactive SubState=dead

That is exactly the shape the old probe classified as NEVER_RAN, and it is what
broke the ``snp-azure`` and ``tdx-azure`` batch runs on 2026-08-22: the secrets
oneshot took longer than the probe's 30-second window, so the probe declared
the job cancelled and the orchestrator tore the deployment down — while the
journal showed the batch unit starting normally 30 seconds later, and
``systemctl --failed`` listed nothing at all.

The real probe was then run against that container to confirm it now reports
``QUEUED:inactive:jobs=1`` for the same scenario, and the waiter's poll command
was run against all three terminal states::

    finished OK   -> inactive / JOBS=0 / JMARK=Finished
    exited 7      -> failed   / JOBS=0 / JMARK=bad.service: Failed with result
    never started -> inactive / JOBS=0 / JMARK=

One more trap the same container exposed: the unit's own stdout goes to the
same journal, so a container printing ``Finished processing the data`` makes an
unfiltered ``grep Finished`` match twice.  Both journal reads therefore accept
only lines systemd itself emitted (``systemd[1]: …``); with the decoy present,
the naive filter matched 2 lines and the strict one matched only systemd's.
"""
from __future__ import annotations


import pytest

import tee_crafter.cli.commands.deploy.batch as batch_mod
from tee_crafter.cli.constants import Console
from tee_crafter.cli.deployment.common import file_download as fd


class _Clock:
    """Fake ``time`` module: ``sleep`` advances a counter, nothing blocks."""

    def __init__(self) -> None:
        self.now = 1_000_000.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(seconds, 1)


def _poll(monkeypatch, replies, *, timeout=3600, grace=120, since=None):
    """Drive the waiter with a canned sequence of remote poll outputs.

    The last reply repeats, so a test can express "and it stays like that".
    """
    clock = _Clock()
    monkeypatch.setattr(fd, "time", clock)
    seen: list[str] = []

    def fake_ssh(cmd, key, user=None, host=None, port=None, timeout=None):
        seen.append(cmd)
        idx = min(len(seen) - 1, len(replies) - 1)
        return True, replies[idx], ""

    import tee_crafter.core.remote.azure_ssh as az
    monkeypatch.setattr(az, "run_ssh_command", fake_ssh)
    result = fd.wait_for_oneshot_completion(
        platform="snp-azure", service_name="u.service", timeout=timeout,
        poll_interval=10, activation_grace_sec=grace, journal_since=since,
    )
    return result, seen


def _state(active, *, sub="dead", jobs=0, jmark="", result="success",
           started="0", first=None):
    return "\n".join([
        first if first is not None else active,
        f"Result={result}",
        "ExecMainStatus=0",
        f"ActiveState={active}",
        f"SubState={sub}",
        f"ExecMainStartTimestampMonotonic={started}",
        f"JOBS={jobs}",
        f"JMARK={jmark}",
    ])


class TestQueuedIsNotCancelled:
    """The regression that broke two live deploys."""

    def test_a_pending_job_keeps_the_waiter_waiting(self, monkeypatch):
        queued = _state("inactive", jobs=1)
        done = _state("inactive", jobs=0, jmark="Finished")
        (ok, state, _), seen = _poll(monkeypatch, [queued] * 5 + [done])
        assert ok and state == "inactive"
        assert len(seen) == 6

    def test_a_long_queue_does_not_burn_the_activation_grace(self, monkeypatch):
        """20 polls queued is 200s of fake time — past the 120s grace."""
        queued = _state("inactive", jobs=1)
        done = _state("inactive", jobs=0, jmark="Finished")
        (ok, state, _), _ = _poll(monkeypatch, [queued] * 20 + [done], grace=120)
        assert ok, f"grace period fired while a job was still pending: {state}"

    def test_the_probe_asks_list_jobs_and_reports_queued(self):
        import inspect
        src = inspect.getsource(batch_mod._start_oneshot_and_wait)
        assert "systemctl list-jobs" in src
        assert "echo QUEUED:" in src

    def test_the_probe_window_is_no_longer_thirty_seconds(self):
        import inspect
        src = inspect.getsource(batch_mod._start_oneshot_and_wait)
        assert "seq 1 30" not in src, (
            "30s was shorter than the secrets oneshot takes on an Azure CVM")


class TestTerminalStatesAreDistinguishable:
    def test_finished_is_success(self, monkeypatch):
        (ok, state, _), _ = _poll(
            monkeypatch, [_state("inactive", jmark="Finished")])
        assert ok and state == "inactive"

    def test_nonzero_exit_is_reported_as_failed(self, monkeypatch):
        (ok, state, _), _ = _poll(monkeypatch, [
            _state("failed", sub="failed", result="exit-code",
                   started="77362515542",
                   jmark="u.service: Failed with result")])
        # ok=True on purpose: the output bundle of a failed run is exactly what
        # the operator needs, and the exit code is read back out of it.
        assert ok and state == "failed"

    def test_dependency_failure_is_its_own_state(self, monkeypatch):
        (ok, state, _), _ = _poll(
            monkeypatch, [_state("inactive", jmark="Dependency failed")])
        assert not ok and state == "dependency-failed"

    def test_never_ran_is_not_success(self, monkeypatch):
        """No job, no journal marker, never running: the old code said success."""
        (ok, state, _), _ = _poll(
            monkeypatch, [_state("inactive")] * 40, grace=120)
        assert not ok and state == "not-activated"

    def test_result_success_alone_proves_nothing(self, monkeypatch):
        """`Result` is populated from load time; it used to short-circuit here."""
        import inspect
        src = inspect.getsource(fd.wait_for_oneshot_completion)
        assert 'result_val and result_val != ""' not in src
        (ok, state, _), _ = _poll(
            monkeypatch, [_state("inactive", result="success")] * 40)
        assert not ok, "Result=success was accepted as completion again"


class TestExecStopPostIsNotRacedAway:
    def test_a_transitioning_unit_is_not_treated_as_finished(self, monkeypatch):
        """``SubState=stop-post`` is the capture hook still running."""
        mid = _state("inactive", sub="stop-post", jmark="Finished")
        done = _state("inactive", sub="dead", jmark="Finished")
        (ok, state, _), seen = _poll(monkeypatch, [mid] * 3 + [done])
        assert ok and len(seen) == 4


class TestJournalReadsAreScopedAndFiltered:
    def test_since_is_threaded_into_the_poll(self, monkeypatch):
        _, seen = _poll(monkeypatch, [_state("inactive", jmark="Finished")],
                        since="2026-08-22 10:18:23")
        assert '--since "2026-08-22 10:18:23"' in seen[0]

    def test_a_rolling_window_is_used_when_no_marker_is_given(self, monkeypatch):
        _, seen = _poll(monkeypatch, [_state("inactive", jmark="Finished")])
        assert "--since" in seen[0]

    @pytest.mark.parametrize("source", [
        lambda: __import__("inspect").getsource(fd.wait_for_oneshot_completion),
        lambda: __import__("inspect").getsource(
            batch_mod._start_oneshot_and_wait),
    ])
    def test_only_systemd_emitted_lines_are_matched(self, source):
        """A user container printing "Finished processing" must not count."""
        src = source()
        assert "systemd" in src and "[0-9]+" in src, (
            "the journal grep must be anchored to systemd's own log lines; a "
            "bare 'Finished' also matches the workload's stdout")

    def test_the_probe_scopes_the_journal_to_this_invocation(self):
        import inspect
        src = inspect.getsource(batch_mod._start_oneshot_and_wait)
        assert "T0=$(date -u" in src
        assert '--since \\"$T0\\"' in src or '--since "$T0"' in src


class TestSecretsDependencyIsStartedFirst:
    """Attribution: a failed gate should name itself, not the workload."""

    def _run(self, platform, *, start_ok):
        calls: list[str] = []

        def fake_run_remote(cmd, timeout=60):
            calls.append(cmd)
            if f"systemctl start {batch_mod._SECRETS_UNIT}" in cmd:
                return start_ok, "", "Job for tee-crafter-secrets.service failed"
            return True, "journal line", ""

        printed: list[str] = []

        class _Cap(Console):
            def print(self, *a, **k):
                printed.append(" ".join(str(x) for x in a))

        transport = batch_mod.BatchTransport(
            platform=platform, ssh_private_key_path="/dev/null",
            ssh_user="tee_admin")
        ok, msg = batch_mod._start_secrets_dependency(
            transport, fake_run_remote, _Cap())
        return ok, msg, calls, "\n".join(printed)

    @pytest.mark.parametrize("platform", ["snp-azure", "tdx-azure", "snp-gcp",
                                          "snp-aws", "gpu-cc-azure"])
    def test_cvm_platforms_start_it(self, platform):
        ok, _, calls, _ = self._run(platform, start_ok=True)
        assert ok
        assert any(f"systemctl start {batch_mod._SECRETS_UNIT}" in c
                   for c in calls), calls

    def test_it_is_reset_failed_first(self):
        """It already ran (and failed) at boot, before the script was uploaded."""
        _, _, calls, _ = self._run("snp-azure", start_ok=True)
        assert any("reset-failed tee-crafter-secrets.service" in c
                   for c in calls), calls

    def test_it_is_started_blocking(self):
        """--no-block here would put us back to guessing from the outside."""
        _, _, calls, _ = self._run("snp-azure", start_ok=True)
        starts = [c for c in calls
                  if f"systemctl start {batch_mod._SECRETS_UNIT}" in c]
        assert starts and all("--no-block" not in c for c in starts)

    def test_failure_aborts_the_run_and_names_the_unit(self):
        ok, msg, _, _ = self._run("snp-azure", start_ok=False)
        assert not ok
        assert batch_mod._SECRETS_UNIT in msg

    def test_failure_prints_that_units_journal(self):
        _, _, calls, printed = self._run("snp-azure", start_ok=False)
        assert any(f"journalctl -u {batch_mod._SECRETS_UNIT}" in c
                   for c in calls), calls
        assert printed.strip(), "the journal was fetched and thrown away"

    def test_sgx_is_a_noop(self):
        ok, msg, calls, _ = self._run("sgx-azure", start_ok=False)
        assert ok and msg == "" and calls == []

    def test_it_runs_before_the_batch_unit_is_started(self):
        import inspect
        src = inspect.getsource(batch_mod._start_oneshot_and_wait)
        assert src.index("_start_secrets_dependency") < src.index(
            "systemctl start --no-block")


class TestTheFailureJournalIsPrinted:
    def test_the_batch_failure_path_prints_what_it_fetches(self):
        import inspect
        src = inspect.getsource(batch_mod.collect_batch_output)
        i = src.index("Batch oneshot did not complete")
        window = src[i:i + 700]
        assert "journalctl" in window
        assert "console.print" in window, (
            "this call used to fetch 100 journal lines and discard them")
