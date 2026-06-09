"""Nitro Enclave allocator readiness verification for custom-AMI deployments.

Why this module is fussy about *how* it measures the reservation
---------------------------------------------------------------
``nitro-enclaves-allocator`` reserves the enclave's memory as hugepages
**largest page size first**: it lists the sizes available under
``/sys/devices/system/node/<n>/hugepages/``, sorts them descending, and takes as
many of each as the kernel will give before moving to the next smaller size
(``bootstrap/nitro-enclaves-allocator``, ``set_required_hugepages`` — see
https://github.com/aws/aws-nitro-enclaves-cli).  A 6144 MiB request therefore
usually lands partly or wholly on **1 GiB** pages.

``HugePages_Total`` in ``/proc/meminfo`` counts only the *default* page size —
``Hugepagesize``, which is 2048 kB on both x86_64 and Graviton.  The kernel
documents the distinction, and names the one field that spans sizes:

    Hugetlb: is the total amount of memory (in kB), consumed by huge pages of
    all sizes.  If huge pages of different sizes are in use, this number will
    exceed HugePages_Total * Hugepagesize.
        -- Documentation/admin-guide/mm/hugetlbpage.rst

So reading ``HugePages_Total`` to judge the reservation measures the wrong
thing, and on real hardware (2026-08-21) it was wrong in both directions:

* ``c7g.xlarge`` (Graviton): the allocator placed all 6144 MiB on 1 GiB pages,
  so ``HugePages_Total`` read **0**.  The old code took that for "nothing was
  reserved" and wrote ``3072`` to ``/proc/sys/vm/nr_hugepages`` — asking for a
  *second* 6 GiB, this time in 2 MiB pages, on an 8 GiB host that had already
  given up 6 GiB.  The kernel produced 602 pages after heavy reclaim, the
  resulting memory pressure stopped the SSM agent, and every later SSM call
  timed out.  The visible symptom was "step 8d cannot download the enclave
  image from S3": a memory bug wearing a network bug's clothes.
* ``c6a.xlarge`` (x86_64): ``HugePages_Total`` read **1536** — 3072 MiB — against
  the same 6144 MiB request, the remainder being on 1 GiB pages.  That deploy
  succeeded, so the check "passed" while under-counting the reservation by half.
  Nothing was wrong with ``--enclave-ram``; the field simply could not see the
  larger pages.

There is also no need to second-guess the service.  ``set_required_hugepages``
rolls every reservation back and returns ``ERR_INSUFFICIENT_MEMORY`` unless it
placed the *whole* request, and ``main`` turns that into ``fail "$?"``.  A
``nitro-enclaves-allocator.service`` reporting ``active`` has therefore reserved
exactly ``memory_mib``; one that could not reports ``failed``.  We read
``Hugetlb`` as a cross-check on that contract rather than as a substitute for
it, and we no longer "help" by writing to the default-size pool.
"""
from __future__ import annotations

import re
import time
from typing import Dict, Optional, Tuple

#: systemd states we stop polling on.  ``activating`` is not among them: the
#: unit is a oneshot, so it means the allocation is still in progress.
_TERMINAL_STATES = ("active", "failed", "inactive")

_ALL_SYSTEMD_STATES = _TERMINAL_STATES + (
    "activating", "deactivating", "reloading",
)

#: One SSM round-trip that captures everything needed to judge the outcome:
#: the unit state, the memory context, and the per-size hugepage pools.
#:
#: ``;`` rather than ``&&`` between the parts on purpose — ``systemctl
#: is-active`` exits non-zero for a unit that is not active, and that is exactly
#: the case where the rest of the output matters most.
_PROBE = (
    "systemctl is-active nitro-enclaves-allocator.service; "
    "grep -E '^(MemTotal|MemAvailable|HugePages_Total|Hugepagesize|Hugetlb):' "
    "/proc/meminfo; "
    "for d in /sys/kernel/mm/hugepages/hugepages-*; do "
    'if [ -d "$d" ]; then '
    'echo "pool ${d##*/} $(cat "$d/nr_hugepages" 2>/dev/null)"; '
    "fi; done; true"
)

_JOURNAL = (
    "sudo journalctl -u nitro-enclaves-allocator.service -n 40 --no-pager "
    "2>&1 || true"
)


def _service_state(probe_output: str) -> Optional[str]:
    """The allocator unit's systemd state, or ``None`` if the probe said nothing.

    ``systemctl is-active`` prints the bare state on its own line.  Nothing else
    in :data:`_PROBE` can produce one of these words alone on a line, so an
    exact line match is unambiguous.
    """
    for line in (probe_output or "").splitlines():
        candidate = line.strip()
        if candidate in _ALL_SYSTEMD_STATES:
            return candidate
    return None


def _meminfo_value(probe_output: str, key: str) -> Optional[int]:
    """A ``/proc/meminfo`` value by key, in whatever unit the file uses.

    The ``kB`` suffix is optional because the counters differ: ``MemTotal`` and
    ``Hugetlb`` carry it, ``HugePages_Total`` (a page count) does not.
    """
    match = re.search(
        rf"^{re.escape(key)}:\s+(\d+)(?:\s*kB)?\s*$",
        probe_output or "", re.MULTILINE,
    )
    return int(match.group(1)) if match else None


def hugepage_pools(probe_output: str) -> Dict[int, int]:
    """``{page size in kB: pages reserved}`` from the sysfs sweep in :data:`_PROBE`."""
    pools: Dict[int, int] = {}
    for match in re.finditer(
        r"^pool\s+hugepages-(\d+)kB\s+(\d+)\s*$", probe_output or "", re.MULTILINE,
    ):
        pools[int(match.group(1))] = int(match.group(2))
    return pools


def reserved_mib(probe_output: str) -> Optional[int]:
    """Hugepage memory reserved across **every** page size, in MiB.

    ``Hugetlb`` is preferred because it is the only ``/proc/meminfo`` field that
    spans page sizes.  The sysfs per-size sweep is the fallback for a kernel too
    old to export it.  ``HugePages_Total`` is deliberately never consulted — it
    counts one size only, which is the bug this module exists to not repeat.

    ``None`` means the reservation could not be measured, which is different
    from measuring zero and is treated differently by the caller.
    """
    hugetlb_kb = _meminfo_value(probe_output, "Hugetlb")
    if hugetlb_kb is not None:
        return hugetlb_kb // 1024
    pools = hugepage_pools(probe_output)
    if pools:
        return sum(size_kb * count for size_kb, count in pools.items()) // 1024
    return None


def describe_pools(probe_output: str) -> str:
    """Human-readable per-size breakdown, e.g. ``6 x 1024 MiB``.

    Printed on both the success and failure paths so the *shape* of the
    allocation is visible in the deploy log.  Had this been printed originally,
    "0 pages of the default size, 6 pages of 1 GiB" would have read as an
    obvious success rather than an obvious failure.
    """
    used = {size: count for size, count in hugepage_pools(probe_output).items() if count}
    if not used:
        return "no hugepages reserved"
    return ", ".join(
        f"{count} x {size_kb // 1024} MiB"
        for size_kb, count in sorted(used.items(), reverse=True)
    )


def _memory_context(probe_output: str) -> str:
    total = _meminfo_value(probe_output, "MemTotal")
    available = _meminfo_value(probe_output, "MemAvailable")
    bits = []
    if total is not None:
        bits.append(f"host MemTotal {total // 1024} MiB")
    if available is not None:
        bits.append(f"MemAvailable {available // 1024} MiB")
    return ", ".join(bits) or "host memory unknown"


def _poll_for_terminal_state(
    run_ssm, console, instance_id: str, aws_region: str, polls: int = 18,
) -> Tuple[Optional[str], str]:
    """Poll the allocator until its unit reaches a terminal state.

    Returns ``(state, last_probe_output)``.  The probe output is retained from
    the most recent poll that produced any, so a final flaky SSM call cannot
    erase the evidence gathered by the ones before it.
    """
    state: Optional[str] = None
    last_output = ""
    for poll in range(polls):
        _ok, out, _err = run_ssm(instance_id, _PROBE, aws_region, timeout=30)
        if out:
            last_output = out
        state = _service_state(out or "")
        console.print(
            f"[dim]Nitro debug: allocator poll {poll}: "
            f"state={state or 'unknown'}[/dim]")
        if out:
            console.print(f"[dim]{out.strip()[:800]}[/dim]")
        if state in _TERMINAL_STATES:
            return state, last_output
        time.sleep(10)
    return state, last_output


def verify_allocator_readiness(
    progress, console, instance_id, aws_region, ram, cpu=2,
) -> bool:
    """Align the Nitro Enclaves allocator with the deploy-time enclave shape.

    Called when deploying onto a custom AMI.  The AMI is *generic* — its baked
    ``allocator.yaml`` is only a baseline — so we rewrite ``memory_mib`` and
    ``cpu_count`` to the requested enclave shape (instance minus parent reserve)
    and restart the allocator before launching the enclave.  That is what lets a
    single AMI baked on the default host run on any larger instance.

    Returns ``True`` when the enclave's memory is genuinely reserved.  Returning
    ``False`` aborts the deploy, which is the point: an enclave whose memory was
    not reserved cannot launch, and continuing past this used to wedge the host
    badly enough to take the SSM agent with it.
    """
    from tee_crafter.core.remote.ssm import run_ssm_command as _run_ssm
    enclave_memory = max(512, int(ram))
    enclave_cpu = max(2, int(cpu))
    t_alloc = progress.add_task(
        "[yellow]Verifying Nitro allocator readiness...[/yellow]", total=None)

    # Always size the allocator to the deploy request (generic-AMI model): the
    # baked default may be smaller or larger than what this instance should run.
    console.print(f"[dim]Nitro debug: setting allocator to "
                  f"memory_mib={enclave_memory}, cpu_count={enclave_cpu} "
                  f"and restarting...[/dim]")
    _run_ssm(
        instance_id,
        f"sudo sed -i 's/^memory_mib:.*/memory_mib: {enclave_memory}/' "
        f"/etc/nitro_enclaves/allocator.yaml && "
        f"sudo sed -i 's/^cpu_count:.*/cpu_count: {enclave_cpu}/' "
        f"/etc/nitro_enclaves/allocator.yaml && "
        f"sudo systemctl restart nitro-enclaves-allocator.service",
        aws_region, timeout=90)
    time.sleep(5)

    state, probe = _poll_for_terminal_state(
        _run_ssm, console, instance_id, aws_region)

    if state != "active":
        progress.update(t_alloc, description=(
            "[bold red]✗ Nitro allocator did not reserve the enclave's memory."
            "[/bold red]"))
        _ok, journal, _err = _run_ssm(instance_id, _JOURNAL, aws_region, timeout=30)
        console.print(
            f"[red]The allocator unit is [bold]{state or 'unreachable'}[/bold] "
            f"after requesting {enclave_memory} MiB "
            f"({_memory_context(probe)}).[/red]\n"
            f"[red]It refuses rather than partially reserving, so the enclave "
            f"cannot launch. Reduce --enclave-ram or use a larger instance."
            f"[/red]")
        if journal:
            console.print(f"[dim]{journal.strip()[-1200:]}[/dim]")
        return False

    reserved = reserved_mib(probe)
    if reserved is None:
        # No Hugetlb field and no readable sysfs pools.  The unit is active, and
        # the allocator only reports active after a complete reservation, so
        # trust that contract rather than blocking the deploy on a missing
        # counter — but say plainly that the cross-check did not run.
        progress.update(t_alloc, description=(
            f"[yellow]! Allocator active for {enclave_memory} MiB; hugepage "
            f"total unreadable, proceeding on the unit state alone.[/yellow]"))
        return True

    if reserved < enclave_memory:
        progress.update(t_alloc, description=(
            "[bold red]✗ Nitro allocator reserved less than the enclave needs."
            "[/bold red]"))
        console.print(
            f"[red]The allocator reports active, but only {reserved} MiB of "
            f"hugepages are reserved against a {enclave_memory} MiB request "
            f"({describe_pools(probe)}; {_memory_context(probe)}).[/red]\n"
            f"[red]That contradicts the allocator's own all-or-nothing "
            f"contract, so something else on the host changed the hugepage "
            f"pools. Refusing to launch an enclave that cannot fit.[/red]")
        return False

    progress.update(t_alloc, description=(
        f"[green]✓ Nitro allocator ready: {reserved} MiB reserved for a "
        f"{enclave_memory} MiB enclave ({describe_pools(probe)}).[/green]"))
    return True
