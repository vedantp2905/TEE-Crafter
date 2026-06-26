"""Tests for the deploy-time performance optimizations.

Covers:
1. SSH connection multiplexing options shape (azure + gcp).
2. ``_ssh_mux_opts`` honours the disable env var.
3. ``make_tarball_fast`` falls back to Python tarfile when pigz is
   unavailable, and produces a valid gzip archive in both paths.
4. ``wait_for_ssh`` uses exponential backoff between probes.
"""
from __future__ import annotations

import os
import sys
import tarfile
import time

import pytest


# ---------------------------------------------------------------------------
#  1. SSH ControlMaster options
# ---------------------------------------------------------------------------

def test_azure_ssh_mux_opts_present_by_default(tmp_path, monkeypatch):
    """Default deploy must request ControlMaster multiplexing."""
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
    # Re-import to ensure module-level _MUX_DIR picks up the patched TMPDIR
    sys.modules.pop("tee_crafter.core.remote.azure_ssh", None)
    from tee_crafter.core.remote.azure_ssh import _ssh_mux_opts

    opts = _ssh_mux_opts()
    assert "-o" in opts
    assert any(o.startswith("ControlMaster=") for o in opts)
    assert any(o.startswith("ControlPath=") for o in opts)
    assert any(o.startswith("ControlPersist=") for o in opts)


def test_gcp_ssh_mux_opts_present_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
    sys.modules.pop("tee_crafter.core.remote.gcp_ssh", None)
    from tee_crafter.core.remote.gcp_ssh import _ssh_mux_opts

    opts = _ssh_mux_opts()
    assert any(o.startswith("ControlMaster=") for o in opts)


def test_ssh_mux_can_be_disabled(monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_SSH_MUX", "0")
    sys.modules.pop("tee_crafter.core.remote.azure_ssh", None)
    sys.modules.pop("tee_crafter.core.remote.gcp_ssh", None)
    from tee_crafter.core.remote.azure_ssh import _ssh_mux_opts as az_opts
    from tee_crafter.core.remote.gcp_ssh import _ssh_mux_opts as gcp_opts

    assert az_opts() == []
    assert gcp_opts() == []


def test_close_ssh_mux_is_best_effort(monkeypatch):
    """close_ssh_mux must not raise even if the socket is missing."""
    sys.modules.pop("tee_crafter.core.remote.azure_ssh", None)
    from tee_crafter.core.remote.azure_ssh import close_ssh_mux

    close_ssh_mux(host="localhost", port=65535)  # nothing here, must not raise


# ---------------------------------------------------------------------------
#  2. Parallel-gzip tarball helper
# ---------------------------------------------------------------------------

def _make_tree(root):
    """Create a tiny directory tree so the tar helper has something to add."""
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "a.txt"), "w") as f:
        f.write("hello\n")
    sub = os.path.join(root, "sub")
    os.makedirs(sub, exist_ok=True)
    with open(os.path.join(sub, "b.txt"), "w") as f:
        f.write("world\n")


def _read_tar_members(tar_path):
    with tarfile.open(tar_path, "r:gz") as tar:
        return sorted(m.name for m in tar.getmembers())


def test_make_tarball_fast_python_fallback(tmp_path):
    """Force the Python tarfile path; output must be a valid gzip tar."""
    src = tmp_path / "src"
    _make_tree(str(src))
    out = tmp_path / "out.tar.gz"

    from tee_crafter.cli.deployment.common.wheel_manager import make_tarball_fast

    ok = make_tarball_fast(str(out), [(str(src), "app")], force_python=True)
    assert ok
    assert out.exists() and out.stat().st_size > 0
    members = _read_tar_members(str(out))
    # Should contain the renamed root directory
    assert any(m == "app" or m.startswith("app/") for m in members)
    assert any(m.endswith("a.txt") for m in members)
    assert any(m.endswith("b.txt") for m in members)


def test_make_tarball_fast_pigz_path(tmp_path):
    """If pigz is on the host, the fast path should produce the same gzip."""
    import shutil

    if not (shutil.which("pigz") and shutil.which("tar")):
        pytest.skip("pigz/tar not available on this host")

    src = tmp_path / "src"
    _make_tree(str(src))
    out = tmp_path / "out_pigz.tar.gz"

    from tee_crafter.cli.deployment.common.wheel_manager import make_tarball_fast

    ok = make_tarball_fast(str(out), [(str(src), "app")], force_python=False)
    assert ok
    assert out.exists() and out.stat().st_size > 0
    # Must still be a valid gzip tar
    members = _read_tar_members(str(out))
    assert any(m.endswith("a.txt") for m in members)
    assert any(m.endswith("b.txt") for m in members)


def test_make_tarball_fast_multi_member(tmp_path):
    """Multiple roots map to distinct arcnames inside the tarball."""
    src_a = tmp_path / "a"
    src_b = tmp_path / "b"
    _make_tree(str(src_a))
    _make_tree(str(src_b))
    out = tmp_path / "two.tar.gz"

    from tee_crafter.cli.deployment.common.wheel_manager import make_tarball_fast

    make_tarball_fast(
        str(out),
        [(str(src_a), "app"), (str(src_b), "wheels")],
        force_python=True,
    )
    members = _read_tar_members(str(out))
    assert any(m.startswith("app") for m in members)
    assert any(m.startswith("wheels") for m in members)


# ---------------------------------------------------------------------------
#  3. Exponential-backoff wait_for_ssh
# ---------------------------------------------------------------------------

def test_wait_for_ssh_uses_short_initial_sleep(monkeypatch, tmp_path):
    """First sleep must be ≤ 3 s (i.e. *not* the legacy flat 10 s)."""
    key = tmp_path / "k"
    key.write_text("dummy")

    sys.modules.pop("tee_crafter.core.remote.azure_ssh", None)
    az = __import__("tee_crafter.core.remote.azure_ssh", fromlist=["wait_for_ssh"])

    sleep_calls: list[float] = []
    monkeypatch.setattr(az.time, "sleep", lambda s: sleep_calls.append(s))

    # Force every subprocess.run to return rc=255 ("connection refused") so
    # the function loops through the backoff sleeps.
    class _FakeRun:
        def __init__(self, *a, **kw):
            self.returncode = 255
            self.stdout = ""
            self.stderr = "Connection refused"

    monkeypatch.setattr(az.subprocess, "run",
                        lambda *a, **kw: _FakeRun())

    # Use a tiny timeout so we bail quickly after a handful of attempts.
    start = time.monotonic()
    ok = az.wait_for_ssh(str(key), timeout=5, host="127.0.0.1", port=65535)
    elapsed = time.monotonic() - start

    assert ok is False
    assert sleep_calls, "expected at least one backoff sleep"
    assert sleep_calls[0] <= 3.0, f"first backoff was {sleep_calls[0]}s, expected <= 3s"
    # Backoff must grow (or at least never shrink) over time.
    for prev, curr in zip(sleep_calls, sleep_calls[1:]):
        assert curr >= prev, f"backoff regressed: {sleep_calls}"
    # And must be capped at 10 s.
    assert max(sleep_calls) <= 10.0
    # The whole loop fits inside the timeout budget plus a tiny epsilon
    # (the inner subprocess.run is mocked so we don't actually wait 20s
    # per attempt — we should only consume ``timeout`` of wall clock).
    assert elapsed < 30.0
