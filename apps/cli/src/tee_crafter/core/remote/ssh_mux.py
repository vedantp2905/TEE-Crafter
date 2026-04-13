"""Shared OpenSSH ControlMaster/ControlPath selection.

Multiplexing is worth a lot on both Azure (Bastion) and GCP (IAP): a deploy
issues 30-40 ssh/scp calls and without a shared master each one repeats the
full TCP + KEX + auth handshake, which is also the main source of the
``kex_exchange_identification`` flakes we retry around.

The subtlety this module exists for is that a ControlPath is a **Unix domain
socket path**, and those have a hard length limit far below ``PATH_MAX``:
104 bytes on macOS/BSD, 108 on Linux.  ``azure_ssh`` and ``gcp_ssh`` each used
to build ``$TMPDIR/tee-crafter-ssh-mux-<uid>/cm-%C`` independently, which is
fine in the CLI's container (``TMPDIR`` unset, so ``/tmp``, ~70 bytes) and
guaranteed to fail on a macOS host, where ``TMPDIR`` looks like
``/var/folders/qz/8dtvzp1d3sngtpt1rggldxm00000gn/T/`` and the total reaches 116.

That failure is nasty rather than loud: ``os.makedirs`` succeeds, so the old
guard did not catch it, and every ssh invocation then fails with
``ControlPath too long`` — which the retry wrapper reads as a transient error
and retries ~27 times over four minutes before giving up.  Observed on
2026-08-22 running the Azure measurement capture outside the container.

So: build the candidate, measure it *including* what ``%C`` expands to, and
fall back to a shorter directory — or to no multiplexing at all — rather than
emitting a path OpenSSH will reject.
"""
from __future__ import annotations

import os
import sys

#: ``%C`` is a hash of (connection, host, port, user); OpenSSH expands it to
#: 40 lowercase hex characters.  We must budget for the expansion, not for the
#: two-character token, or the check passes and ssh still fails.
_PERCENT_C_EXPANDED = 40
_BASENAME = "cm-"

#: Hard kernel limits on ``sockaddr_un.sun_path`` (including the NUL).  Keep a
#: few bytes of margin rather than sitting exactly on the boundary.
_SUN_PATH_LIMIT = 104 if sys.platform == "darwin" else 108
_MARGIN = 4


def _uid() -> str:
    return str(os.getuid()) if hasattr(os, "getuid") else "u"


def _candidates() -> list[str]:
    """Directories to try, longest-lived and most-isolated first.

    ``$TMPDIR`` first because it is per-user and cleaned by the OS, so
    concurrent deploys by different users cannot collide.  ``/tmp`` next
    because it is short and always present.  The last one trades the
    descriptive name for bytes, for pathological ``TMPDIR`` values.
    """
    uid = _uid()
    out = []
    tmpdir = os.environ.get("TMPDIR", "/tmp")
    for base, name in ((tmpdir, f"tee-crafter-ssh-mux-{uid}"),
                       ("/tmp", f"tee-crafter-ssh-mux-{uid}"),
                       ("/tmp", f"tc-mux-{uid}")):
        path = os.path.join(base, name)
        if path not in out:
            out.append(path)
    return out


def _fits(directory: str) -> bool:
    """Would ``<directory>/cm-%C`` fit in a Unix socket path once expanded?"""
    full = len(os.path.join(directory, _BASENAME)) + _PERCENT_C_EXPANDED
    return full <= _SUN_PATH_LIMIT - _MARGIN


def mux_enabled() -> bool:
    return os.environ.get("TEE_CRAFTER_SSH_MUX", "1").strip() not in ("0", "false", "no")


def mux_dir() -> str | None:
    """First candidate directory that is short enough *and* creatable."""
    for directory in _candidates():
        if not _fits(directory):
            continue
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        except OSError:
            continue
        return directory
    return None


def ssh_mux_opts() -> list[str]:
    """ControlMaster/Path/Persist options, or ``[]`` to run unmultiplexed.

    Returning ``[]`` is always safe: every call site then pays the handshake
    per connection, which is slower but correct.  Preferring that over an
    over-long ControlPath is the whole point.
    """
    if not mux_enabled():
        return []
    directory = mux_dir()
    if directory is None:
        return []
    persist = os.environ.get("TEE_CRAFTER_SSH_MUX_PERSIST", "5m")
    return [
        "-o", "ControlMaster=auto",
        "-o", f"ControlPath={directory}/{_BASENAME}%C",
        "-o", f"ControlPersist={persist}",
    ]
