"""The Nitro allocator readiness check must measure hugepages across all sizes.

Background, because the assertions here look arbitrary without it.
``nitro-enclaves-allocator`` reserves the enclave's memory largest-page-size
first (``set_required_hugepages`` in aws/aws-nitro-enclaves-cli), so a 6144 MiB
request usually lands partly or wholly on 1 GiB pages.  ``HugePages_Total`` in
``/proc/meminfo`` counts only the *default* size — 2048 kB on both x86_64 and
Graviton — and the kernel says so explicitly:

    Hugetlb: is the total amount of memory (in kB), consumed by huge pages of
    all sizes.  If huge pages of different sizes are in use, this number will
    exceed HugePages_Total * Hugepagesize.
        -- Documentation/admin-guide/mm/hugetlbpage.rst

Reading ``HugePages_Total`` therefore under-counts, and on 2026-08-21 it
under-counted to zero on a ``c7g.xlarge``: the old code concluded nothing was
reserved, wrote 3072 to ``/proc/sys/vm/nr_hugepages`` — a *second* 6 GiB of
2 MiB pages on an 8 GiB host — and the resulting memory pressure stopped the SSM
agent.  Every later SSM call timed out, so the deploy failed at "step 8d cannot
download the enclave image from S3": a memory bug that presented as a network
bug and cost hours.

The single most important assertion in this file is
``test_never_writes_to_the_default_size_pool``.  That write is what did the
damage, and it looks like a helpful fallback, so it is exactly the thing a future
cleanup would restore.
"""

import pytest

from tee_crafter.cli.deployment.nitro import allocator as alloc


# --- Fixtures ------------------------------------------------------------
#
# The two ``HugePages_Total`` / ``Hugepagesize`` readings below are verbatim from
# the live runs (arm64: 0, x86_64: 1536, 2048 kB on both).  The ``Hugetlb`` line
# and the sysfs pool sweep are reconstructions: the old probe ran
# ``grep -i hugepages /proc/meminfo``, and "Hugetlb" does not contain the string
# "hugepages", so the field that would have told the truth was filtered out
# before anyone could read it.  The reconstruction is the arithmetic the kernel
# documents — 6 x 1 GiB on arm64, 3 x 1 GiB + 1536 x 2 MiB on x86_64 — chosen to
# total the 6144 MiB that both runs requested.

#: Graviton ``c7g.xlarge``: the whole reservation landed on 1 GiB pages, so the
#: default-size counter reads zero.  The allocator succeeded.
ARM64_ALL_1GIB = """active
MemTotal:        8028460 kB
MemAvailable:    1402180 kB
HugePages_Total:       0
Hugepagesize:       2048 kB
Hugetlb:         6291456 kB
pool hugepages-1048576kB 6
pool hugepages-2048kB 0
pool hugepages-32768kB 0
pool hugepages-64kB 0
"""

#: x86_64 ``c6a.xlarge``: a mixed allocation.  ``HugePages_Total`` reads 1536 —
#: 3072 MiB — against the same 6144 MiB request, because the rest is on 1 GiB
#: pages.  This deploy succeeded, so the old check passed for the wrong reason.
X86_MIXED = """active
MemTotal:        8025372 kB
MemAvailable:    1338764 kB
HugePages_Total:    1536
Hugepagesize:       2048 kB
Hugetlb:         6291456 kB
pool hugepages-1048576kB 3
pool hugepages-2048kB 1536
"""

#: The allocator refused: it rolls every reservation back and returns
#: ERR_INSUFFICIENT_MEMORY rather than partially reserving, and ``main`` turns
#: that into a non-zero exit, so the unit reports ``failed``.
FAILED_UNIT = """failed
MemTotal:        2028460 kB
MemAvailable:     902180 kB
HugePages_Total:       0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
pool hugepages-1048576kB 0
pool hugepages-2048kB 0
"""

#: Active, but the pools hold less than was asked for.  This contradicts the
#: allocator's all-or-nothing contract, so something else on the host moved the
#: pools — refuse rather than launch an enclave that cannot fit.
ACTIVE_BUT_SHORT = """active
MemTotal:        8028460 kB
MemAvailable:    5402180 kB
HugePages_Total:     602
Hugepagesize:       2048 kB
Hugetlb:         1232896 kB
pool hugepages-1048576kB 0
pool hugepages-2048kB 602
"""

#: A kernel that exports no ``Hugetlb`` and no readable sysfs pools.  The
#: reservation is unmeasurable, which is not the same as measurably zero.
UNMEASURABLE = """active
MemTotal:        8028460 kB
MemAvailable:    1402180 kB
HugePages_Total:       0
Hugepagesize:       2048 kB
"""


class FakeProgress:
    def __init__(self):
        self.descriptions = []

    def add_task(self, description, total=None):
        self.descriptions.append(description)
        return "task-0"

    def update(self, task, description=None, **_kw):
        if description is not None:
            self.descriptions.append(description)

    @property
    def final(self):
        return self.descriptions[-1]


class FakeConsole:
    def __init__(self):
        self.lines = []

    def print(self, *args, **_kw):
        self.lines.append(" ".join(str(a) for a in args))

    @property
    def text(self):
        return "\n".join(self.lines)


class FakeSsm:
    """Records every command issued and replays a fixed probe response."""

    def __init__(self, probe_response):
        self.probe_response = probe_response
        self.commands = []

    def __call__(self, instance_id, command, region, timeout=120):
        self.commands.append(command)
        if "/proc/meminfo" in command:
            return True, self.probe_response, ""
        if "journalctl" in command:
            return True, "nitro-enclaves-allocator: Insufficient memory", ""
        return True, "", ""


@pytest.fixture(autouse=True)
def _no_sleeping(monkeypatch):
    monkeypatch.setattr(alloc.time, "sleep", lambda _s: None)


def _run(monkeypatch, probe_response, ram=6144, cpu=2):
    ssm = FakeSsm(probe_response)
    monkeypatch.setattr(
        "tee_crafter.core.remote.ssm.run_ssm_command", ssm, raising=True)
    progress, console = FakeProgress(), FakeConsole()
    ok = alloc.verify_allocator_readiness(
        progress, console, "i-0123456789abcdef0", "us-east-2", ram, cpu)
    return ok, progress, console, ssm


class TestReservedMib:
    def test_counts_1gib_pages_the_default_counter_cannot_see(self):
        """The arm64 regression, stated as arithmetic.

        ``HugePages_Total`` is 0 here and the reservation is 6144 MiB.  Any
        implementation that reads the default-size counter returns 0 and gets
        this backwards.
        """
        assert alloc.reserved_mib(ARM64_ALL_1GIB) == 6144

    def test_does_not_stop_at_the_default_size(self):
        """x86_64: 1536 x 2 MiB is 3072 MiB, but 6144 MiB is reserved."""
        assert alloc.reserved_mib(X86_MIXED) == 6144
        # Spelling out the wrong answer, so a regression to it is unmistakable.
        assert alloc.reserved_mib(X86_MIXED) != 1536 * 2

    def test_falls_back_to_the_sysfs_sweep_without_hugetlb(self):
        no_hugetlb = "\n".join(
            line for line in ARM64_ALL_1GIB.splitlines()
            if not line.startswith("Hugetlb:")
        )
        assert alloc.reserved_mib(no_hugetlb) == 6144

    def test_unmeasurable_is_none_not_zero(self):
        assert alloc.reserved_mib(UNMEASURABLE) is None

    def test_zero_is_measurable_zero(self):
        assert alloc.reserved_mib(FAILED_UNIT) == 0

    def test_pool_breakdown_names_each_size(self):
        assert alloc.describe_pools(ARM64_ALL_1GIB) == "6 x 1024 MiB"
        assert alloc.describe_pools(X86_MIXED) == "3 x 1024 MiB, 1536 x 2 MiB"
        assert alloc.describe_pools(FAILED_UNIT) == "no hugepages reserved"


class TestServiceState:
    @pytest.mark.parametrize("probe,expected", [
        (ARM64_ALL_1GIB, "active"),
        (FAILED_UNIT, "failed"),
        ("activating\nMemTotal: 100 kB\n", "activating"),
    ])
    def test_reads_the_bare_systemctl_line(self, probe, expected):
        assert alloc._service_state(probe) == expected

    def test_no_state_line_is_none(self):
        assert alloc._service_state("MemTotal: 100 kB\n") is None


class TestVerifyAllocatorReadiness:
    def test_graviton_all_1gib_is_ready(self, monkeypatch):
        """The exact case that used to be misread as a failed allocation."""
        ok, progress, _console, _ssm = _run(monkeypatch, ARM64_ALL_1GIB)
        assert ok is True
        assert "6144 MiB reserved" in progress.final
        assert "6 x 1024 MiB" in progress.final

    def test_x86_mixed_is_ready_and_reports_the_full_amount(self, monkeypatch):
        ok, progress, _console, _ssm = _run(monkeypatch, X86_MIXED)
        assert ok is True
        assert "6144 MiB reserved" in progress.final

    def test_never_writes_to_the_default_size_pool(self, monkeypatch):
        """The destructive action, asserted absent on the path that triggered it.

        Writing ``nr_pages`` to ``/proc/sys/vm/nr_hugepages`` requests pages of
        the *default* size, system-wide, **in addition to** what the allocator
        already reserved on the enclave's NUMA node — and the allocator writes
        per-size, per-node counters under /sys instead.  On the Graviton run that
        asked for a second 6 GiB on an 8 GiB host and took the SSM agent down
        with it.
        """
        _ok, _progress, _console, ssm = _run(monkeypatch, ARM64_ALL_1GIB)
        issued = "\n".join(ssm.commands)
        assert "/proc/sys/vm/nr_hugepages" not in issued

    def test_failed_unit_aborts(self, monkeypatch):
        ok, progress, console, _ssm = _run(monkeypatch, FAILED_UNIT)
        assert ok is False
        assert "did not reserve" in progress.final
        # The operator needs the numbers and a next step, not just a refusal.
        assert "6144 MiB" in console.text
        assert "--enclave-ram" in console.text

    def test_failed_unit_shows_the_journal(self, monkeypatch):
        _ok, _progress, console, ssm = _run(monkeypatch, FAILED_UNIT)
        assert any("journalctl" in c for c in ssm.commands)
        assert "Insufficient memory" in console.text

    def test_active_but_short_aborts(self, monkeypatch):
        """Do not launch an enclave that cannot fit in what was reserved."""
        ok, progress, console, _ssm = _run(monkeypatch, ACTIVE_BUT_SHORT)
        assert ok is False
        assert "less than the enclave needs" in progress.final
        assert "1204 MiB" in console.text          # what is actually reserved
        assert "6144 MiB request" in console.text  # what was asked for

    def test_unmeasurable_proceeds_on_the_unit_state(self, monkeypatch):
        """Active + unreadable counter is not a reason to block the deploy.

        The allocator reports active only after a complete reservation, so the
        unit state alone is sound evidence.  Say plainly that the cross-check
        did not run rather than inventing a number.
        """
        ok, progress, _console, _ssm = _run(monkeypatch, UNMEASURABLE)
        assert ok is True
        assert "unreadable" in progress.final

    def test_configures_the_allocator_to_the_requested_shape(self, monkeypatch):
        _ok, _progress, _console, ssm = _run(
            monkeypatch, ARM64_ALL_1GIB, ram=12288, cpu=4)
        issued = "\n".join(ssm.commands)
        assert "memory_mib: 12288" in issued
        assert "cpu_count: 4" in issued
        assert "systemctl restart nitro-enclaves-allocator.service" in issued

    def test_probe_asks_for_hugetlb_and_the_per_size_pools(self):
        """A probe that never captures the right field cannot be judged on it.

        The original probe was ``grep -i hugepages /proc/meminfo``, which filters
        out ``Hugetlb`` — the field name has no "hugepages" in it.
        """
        assert "Hugetlb" in alloc._PROBE
        assert "/sys/kernel/mm/hugepages/hugepages-*" in alloc._PROBE
