"""Transient-SSH-error retry behavior in ``core/remote/{gcp_ssh,azure_ssh}.py``.

Regression coverage for the
``kex_exchange_identification: read: Connection reset by peer`` failure that
killed post-deploy on ``snp-gcp`` (and analogous Bastion-side failures on
``sgx-azure`` / ``snp-azure`` / ``tdx-azure``). The fix retries only SSH
transport-layer errors so genuine remote-command failures are still returned
on the first attempt.
"""

from __future__ import annotations

import subprocess

import pytest

from tee_crafter.core.remote import azure_ssh, gcp_ssh


# --- pattern detection -------------------------------------------------------

@pytest.mark.parametrize("text", [
    "kex_exchange_identification: read: Connection reset by peer",
    "kex_exchange_identification: Connection closed by remote host",
    "ssh_exchange_identification: read: Connection reset by peer",
    "ssh: connect to host localhost port 64537: Connection refused",
    "Connection closed by 127.0.0.1 port 12345",
    "banner exchange: Connection to 127.0.0.1 port 22: invalid format",
    "client_loop: send disconnect: Broken pipe",
    "port forwarding failed for listen port 0",
    "ssh: connect to host x port 22: No route to host",
])
@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_transient_markers_are_detected(mod, text):
    assert mod._is_transient_ssh_error(text) is True
    assert mod._is_transient_ssh_error(text.upper()) is True
    assert mod._is_transient_ssh_error(text.lower()) is True


@pytest.mark.parametrize("text", [
    "",
    "Permission denied (publickey).",
    "bash: pip: command not found",
    "ModuleNotFoundError: No module named 'foo'",
    "sudo: a password is required",
    "Some other unrelated error",
])
@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_non_transient_errors_are_not_retried(mod, text):
    assert mod._is_transient_ssh_error(text) is False


# --- retry config knobs ------------------------------------------------------

@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_retry_config_defaults(mod, monkeypatch):
    monkeypatch.delenv("TEE_CRAFTER_SSH_RETRIES", raising=False)
    monkeypatch.delenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", raising=False)
    retries, backoff = mod._ssh_retry_config()
    assert retries == 4
    assert backoff == pytest.approx(2.0)


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_retry_config_clamps_extremes(mod, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRIES", "9999")
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", "9999")
    retries, backoff = mod._ssh_retry_config()
    assert retries == 10
    assert backoff == 30.0

    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRIES", "0")
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", "0")
    retries, backoff = mod._ssh_retry_config()
    assert retries == 1
    assert backoff == pytest.approx(0.1)


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_retry_config_invalid_falls_back_to_defaults(mod, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRIES", "not-a-number")
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", "not-a-float")
    retries, backoff = mod._ssh_retry_config()
    assert retries == 4
    assert backoff == pytest.approx(2.0)


# --- _run_with_ssh_retry behavior -------------------------------------------

def _cp(rc, stderr="", stdout=""):
    return subprocess.CompletedProcess(["ssh"], rc, stdout, stderr)


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_success_short_circuits_no_retry(mod, monkeypatch):
    """A successful first attempt must not retry / sleep."""
    calls = {"runs": 0, "sleeps": 0}

    def fake_run(argv, capture_output, text, timeout):
        calls["runs"] += 1
        return _cp(0, stdout="ok")

    def fake_sleep(_):
        calls["sleeps"] += 1

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.time, "sleep", fake_sleep)

    out = mod._run_with_ssh_retry(["ssh", "echo", "ok"], timeout=5, op_label="SSH")
    assert out.returncode == 0
    assert out.stdout == "ok"
    assert calls["runs"] == 1
    assert calls["sleeps"] == 0


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_non_transient_failure_does_not_retry(mod, monkeypatch):
    """A real remote command failure (e.g. exit 1) must not be retried."""
    calls = {"runs": 0, "sleeps": 0}

    def fake_run(argv, capture_output, text, timeout):
        calls["runs"] += 1
        return _cp(1, stderr="ModuleNotFoundError: foo")

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.time, "sleep", lambda _: calls.__setitem__("sleeps", calls["sleeps"] + 1))

    out = mod._run_with_ssh_retry(["ssh", "python", "-c", "import foo"], timeout=5, op_label="SSH")
    assert out.returncode == 1
    assert "ModuleNotFoundError" in out.stderr
    assert calls["runs"] == 1
    assert calls["sleeps"] == 0


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_transient_then_success_is_recovered(mod, monkeypatch):
    """A KEX reset on the first attempt must be retried and succeed."""
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRIES", "3")
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", "0.1")
    seq = iter([
        _cp(255, stderr="kex_exchange_identification: read: Connection reset by peer"),
        _cp(0, stdout="recovered"),
    ])
    calls = {"runs": 0, "sleeps": 0}

    def fake_run(argv, capture_output, text, timeout):
        calls["runs"] += 1
        return next(seq)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.time, "sleep", lambda _: calls.__setitem__("sleeps", calls["sleeps"] + 1))

    out = mod._run_with_ssh_retry(["ssh", "true"], timeout=5, op_label="SSH")
    assert out.returncode == 0
    assert out.stdout == "recovered"
    assert calls["runs"] == 2
    assert calls["sleeps"] == 1


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_transient_persists_returns_last_failure(mod, monkeypatch):
    """When every attempt is transient, the last CompletedProcess is returned."""
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRIES", "3")
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", "0.01")
    calls = {"runs": 0}

    def fake_run(argv, capture_output, text, timeout):
        calls["runs"] += 1
        return _cp(255, stderr="kex_exchange_identification: read: Connection reset by peer")

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.time, "sleep", lambda _: None)

    out = mod._run_with_ssh_retry(["ssh", "true"], timeout=5, op_label="SSH")
    assert calls["runs"] == 3
    assert out.returncode == 255
    assert "kex_exchange_identification" in out.stderr


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_timeout_then_success_is_recovered(mod, monkeypatch):
    """A first-attempt timeout must be retried."""
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRIES", "3")
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", "0.01")
    calls = {"runs": 0}

    def fake_run(argv, capture_output, text, timeout):
        calls["runs"] += 1
        if calls["runs"] == 1:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)
        return _cp(0, stdout="ok")

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.time, "sleep", lambda _: None)

    out = mod._run_with_ssh_retry(["ssh", "true"], timeout=2, op_label="SSH")
    assert out.returncode == 0
    assert out.stdout == "ok"
    assert calls["runs"] == 2


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_persistent_timeout_returns_synthetic_failure(mod, monkeypatch):
    """All-attempts-time-out is surfaced as a non-zero CompletedProcess."""
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRIES", "2")
    monkeypatch.setenv("TEE_CRAFTER_SSH_RETRY_BACKOFF", "0.01")

    def fake_run(argv, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.time, "sleep", lambda _: None)

    out = mod._run_with_ssh_retry(["ssh", "true"], timeout=2, op_label="SSH")
    assert out.returncode != 0
    assert "timed out" in out.stderr


# --- run_ssh_command wraps retry correctly ----------------------------------

@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_run_ssh_command_returns_success_tuple(mod, monkeypatch):
    monkeypatch.setattr(mod, "_run_with_ssh_retry",
                        lambda argv, *, timeout, op_label: _cp(0, stdout="hello"))
    ok, out, err = mod.run_ssh_command("echo hello", "/key", port=22)
    assert ok is True
    assert out == "hello"
    assert err == ""


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_run_ssh_command_returns_failure_tuple(mod, monkeypatch):
    monkeypatch.setattr(mod, "_run_with_ssh_retry",
                        lambda argv, *, timeout, op_label: _cp(2, stderr="bad"))
    ok, out, err = mod.run_ssh_command("false", "/key", port=22)
    assert ok is False
    assert err == "bad"


# --- scp helpers also use retry helper --------------------------------------

@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_upload_file_via_scp_uses_retry_helper(mod, monkeypatch, tmp_path):
    local = tmp_path / "f.txt"
    local.write_text("x")

    # Stub run_ssh_command so the mkdir -p preamble doesn't try to retry.
    monkeypatch.setattr(mod, "run_ssh_command", lambda *a, **kw: (True, "", ""))

    captured = {}

    def fake_retry(argv, *, timeout, op_label):
        captured["argv"] = argv
        captured["op_label"] = op_label
        return _cp(0)

    monkeypatch.setattr(mod, "_run_with_ssh_retry", fake_retry)

    ok, msg = mod.upload_file_via_scp(str(local), "/remote/f", "/key", port=22)
    assert ok is True
    assert msg == "Success"
    assert captured["argv"][0] == "scp"
    assert captured["op_label"] == "SCP"


@pytest.mark.parametrize("mod", [gcp_ssh, azure_ssh])
def test_upload_file_via_scp_surfaces_transient_after_retries(mod, monkeypatch, tmp_path):
    local = tmp_path / "f.txt"
    local.write_text("x")

    monkeypatch.setattr(mod, "run_ssh_command", lambda *a, **kw: (True, "", ""))
    monkeypatch.setattr(
        mod, "_run_with_ssh_retry",
        lambda argv, *, timeout, op_label: _cp(
            1, stderr="kex_exchange_identification: read: Connection reset by peer"),
    )

    ok, msg = mod.upload_file_via_scp(str(local), "/remote/f", "/key", port=22)
    assert ok is False
    assert "kex_exchange_identification" in msg
