"""Suite-wide guard: no test may leave a seccomp filter on the test process.

A seccomp filter is irreversible for the life of a process, and the filter this
project installs denies process creation on purpose.  So a single test that
loads it in-process rather than in a subprocess silently breaks every *later*
test that shells out -- ``subprocess.run`` returns
``PermissionError: [Errno 1] Operation not permitted`` at exec.

That happened: 33 failures and 58 errors on Linux CI, and none of them named the
test responsible.  It was also invisible locally, because macOS has no seccomp
at all, so the install is a no-op there and the whole suite passed.

The fixture below turns that cascade into one failure on the test that actually
did it.  It is cheap: two reads of ``/proc/self/status`` per test, and a no-op
on any platform without that file.
"""
from __future__ import annotations

import pytest


def _seccomp_mode() -> int | None:
    """Value of the ``Seccomp:`` field for this process.

    0 = disabled, 1 = strict, 2 = filter loaded.  ``None`` when the platform
    does not report it (macOS, or a kernel without CONFIG_SECCOMP), which makes
    the guard inert rather than noisy.
    """
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("Seccomp:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


@pytest.fixture(autouse=True)
def _forbid_seccomp_leak():
    before = _seccomp_mode()
    yield
    after = _seccomp_mode()
    if before is None or after is None or before == after:
        return
    pytest.fail(
        f"this test left a seccomp filter on the pytest process "
        f"(Seccomp: {before} -> {after}).\n"
        "Filters cannot be removed, so every later test that spawns a "
        "subprocess will now fail with PermissionError at exec.\n"
        "Exercise the real filter in a subprocess, or stub the install "
        "(patch `_install_once` / `_try_install_seccomp_once`) if the test is "
        "about something else.",
        pytrace=False,
    )
