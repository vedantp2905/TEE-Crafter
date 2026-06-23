"""A ControlPath must fit in a Unix socket path, or multiplexing must be off.

``ControlPath`` names a Unix domain socket, and ``sockaddr_un.sun_path`` is
104 bytes on macOS/BSD and 108 on Linux — far below ``PATH_MAX``, and OpenSSH
rejects anything longer with ``ControlPath too long``.

``azure_ssh`` and ``gcp_ssh`` each built ``$TMPDIR/tee-crafter-ssh-mux-<uid>/cm-%C``
directly.  Inside the CLI's container ``TMPDIR`` is unset, so that is
``/tmp/...`` at ~70 bytes and fine.  On a macOS *host* ``TMPDIR`` is
``/var/folders/qz/<random>/T/`` and the total reaches 116, so **every** ssh and
scp call fails.  Worse, it fails in a way that looks transient: the retry
wrapper saw ``ControlPath too long`` and retried 27 times across 246 seconds
before giving up.  Hit for real on 2026-08-22 running the Azure measurement
capture outside the container.

Two properties are pinned below. The length arithmetic must budget for what
``%C`` *expands to* (40 hex chars), not the two-character token — checking the
literal is the mistake that would let the bug back in. And the fallback order
must degrade rather than fail: shorter directory first, and unmultiplexed
(``[]``) as the last resort, since paying the handshake per call is slow but
correct.
"""
from __future__ import annotations

import os

import pytest

from tee_crafter.core.remote import ssh_mux

#: A real macOS value, which is what makes the naive path overflow.
MACOS_TMPDIR = "/var/folders/qz/8dtvzp1d3sngtpt1rggldxm00000gn/T/"


def _expanded_len(control_path: str) -> int:
    """Length ssh will actually try to bind, with %C expanded."""
    return len(control_path.replace("%C", "x" * 40))


def _control_path(opts: list[str]) -> str | None:
    for opt in opts:
        if opt.startswith("ControlPath="):
            return opt.split("=", 1)[1]
    return None


class TestLengthArithmetic:
    def test_percent_c_budget_is_the_expansion_not_the_token(self):
        """40, not 2 — the whole bug in one constant."""
        assert ssh_mux._PERCENT_C_EXPANDED == 40

    def test_macos_tmpdir_candidate_does_not_fit(self):
        naive = os.path.join(MACOS_TMPDIR, "tee-crafter-ssh-mux-501")
        assert not ssh_mux._fits(naive)
        assert _expanded_len(f"{naive}/cm-%C") > 104

    def test_tmp_candidate_fits(self):
        assert ssh_mux._fits("/tmp/tee-crafter-ssh-mux-501")

    def test_limit_matches_the_platform(self):
        import sys
        expected = 104 if sys.platform == "darwin" else 108
        assert ssh_mux._SUN_PATH_LIMIT == expected


class TestSelection:
    def test_macos_tmpdir_falls_back_to_a_short_path(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", MACOS_TMPDIR)
        monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
        path = _control_path(ssh_mux.ssh_mux_opts())
        assert path is not None, "should still multiplex, just from a shorter dir"
        assert _expanded_len(path) <= ssh_mux._SUN_PATH_LIMIT
        assert not path.startswith("/var/folders")

    def test_short_tmpdir_is_used_as_is(self, monkeypatch, tmp_path):
        monkeypatch.setenv("TMPDIR", "/tmp")
        monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
        path = _control_path(ssh_mux.ssh_mux_opts())
        assert path is not None and path.startswith("/tmp/")
        assert _expanded_len(path) <= ssh_mux._SUN_PATH_LIMIT

    def test_every_candidate_that_is_offered_fits(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", MACOS_TMPDIR)
        chosen = ssh_mux.mux_dir()
        assert chosen is not None and ssh_mux._fits(chosen)

    def test_disable_env_var_wins(self, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_SSH_MUX", "0")
        assert ssh_mux.ssh_mux_opts() == []

    @pytest.mark.parametrize("val", ["0", "false", "no"])
    def test_disable_accepts_the_documented_spellings(self, monkeypatch, val):
        monkeypatch.setenv("TEE_CRAFTER_SSH_MUX", val)
        assert ssh_mux.ssh_mux_opts() == []

    def test_unmultiplexed_when_nothing_fits(self, monkeypatch):
        """Degrade to correctness rather than emit a path ssh will reject."""
        monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
        monkeypatch.setattr(ssh_mux, "_fits", lambda _d: False)
        assert ssh_mux.ssh_mux_opts() == []

    def test_unmultiplexed_when_the_dir_cannot_be_created(self, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
        monkeypatch.setattr(ssh_mux.os, "makedirs",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
        assert ssh_mux.ssh_mux_opts() == []

    def test_persist_is_configurable(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", "/tmp")
        monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
        monkeypatch.setenv("TEE_CRAFTER_SSH_MUX_PERSIST", "42s")
        assert "ControlPersist=42s" in ssh_mux.ssh_mux_opts()


class TestBothTransportsShareOneImplementation:
    """azure_ssh and gcp_ssh must not drift back to private copies."""

    def test_azure_delegates(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", MACOS_TMPDIR)
        monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
        from tee_crafter.core.remote.azure_ssh import _ssh_mux_opts
        path = _control_path(_ssh_mux_opts())
        assert path is not None
        assert _expanded_len(path) <= ssh_mux._SUN_PATH_LIMIT

    def test_gcp_delegates(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", MACOS_TMPDIR)
        monkeypatch.delenv("TEE_CRAFTER_SSH_MUX", raising=False)
        from tee_crafter.core.remote.gcp_ssh import _ssh_mux_opts
        path = _control_path(_ssh_mux_opts())
        assert path is not None
        assert _expanded_len(path) <= ssh_mux._SUN_PATH_LIMIT

    def test_both_resolve_to_the_shared_function(self):
        from tee_crafter.core.remote.azure_ssh import _ssh_mux_opts as az
        from tee_crafter.core.remote.gcp_ssh import _ssh_mux_opts as gcp
        assert az is ssh_mux.ssh_mux_opts
        assert gcp is ssh_mux.ssh_mux_opts

    def test_neither_module_still_builds_its_own_controlpath(self):
        import inspect
        from tee_crafter.core.remote import azure_ssh, gcp_ssh
        for mod in (azure_ssh, gcp_ssh):
            src = inspect.getsource(mod)
            assert "ControlPath=" not in src, (
                f"{mod.__name__} builds a ControlPath again; it will overflow "
                f"sun_path on macOS hosts")
