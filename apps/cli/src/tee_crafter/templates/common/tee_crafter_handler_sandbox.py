"""SIEM-SEC-5 / SBX-1: per-request sandbox around user ``process_request``.

The enclave-side template invokes the user-supplied ``process_request``
inside the same Python interpreter as the security-critical RA-TLS /
attestation logic.  A bug or malicious dependency in user code
therefore has direct access to:

* the ECDH private key
* the cached attestation report
* file descriptors holding the SIEM bearer token
* every other live socket in the process

We can't change that without a full process split (the long-horizon
"hybrid trust partitioning" item).  What we *can* do today, cheaply,
is fence the user handler with two complementary defences:

1. **`prctl(PR_SET_NO_NEW_PRIVS)`** + a **seccomp** filter that denies
   the worst exit-hatch syscalls (``fork``, ``vfork``, ``clone``
   without ``CLONE_THREAD``, ``execve``, ``execveat``, ``ptrace``,
   ``unshare``, ``mount``, ``umount2``, ``setns``, ``pivot_root``,
   ``chroot``, ``kexec_load``, ``init_module``, ``finit_module``,
   ``delete_module``, ``perf_event_open``, ``bpf``, ``userfaultfd``,
   ``personality``, ``io_uring_setup``).  These are the syscalls that
   let user code escape the enclave's Python interpreter sandbox,
   load native code outside of ``ctypes``, or set up syscall
   interposition.
2. A **per-request RLIMIT fence**: ``RLIMIT_CPU`` always (default 30 s
   of CPU *per request*), plus ``RLIMIT_AS`` / ``RLIMIT_FSIZE`` when the
   operator configures them.  The limits are restored when the handler
   returns.

   What the fence deliberately does NOT do: it does not set
   ``RLIMIT_NPROC``.  Python's GIL + libc TLS allocate threads up front
   and numpy / torch workloads need intra-op threads, so clamping NPROC
   would break ordinary workloads to buy protection that the seccomp
   ``clone``/``fork`` rules already provide.  Earlier revisions of this
   docstring claimed ``RLIMIT_NPROC=1``; the code never set it.  It also
   claimed ``RLIMIT_FSIZE=0``, which the fence skipped because 0 was
   overloaded to mean "unset" — see
   ``TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_FSIZE_MB`` below for the
   corrected semantics.

Both defences are best-effort.  When ``libseccomp2`` is absent (Alpine
images, Gramine SGX) we fall back to RLIMIT-only with a logged
warning; when even prctl is denied (some unprivileged container
runtimes) we fall fully open with a warning and continue serving.
The wrap call NEVER raises into the request path.

**Parent-filter awareness.**  TEE-Crafter's per-platform systemd units
install a strict ``SystemCallFilter=@system-service @resources``
allowlist.  That filter ALSO denies ``seccomp(2)`` itself — the syscall
this module would use to install its own filter.  Calling
``seccomp_load()`` while running under that parent filter does NOT
return EPERM; it produces a fatal ``SIGSYS`` and core-dumps the whole
service before any Python exception handler can run.  We therefore
probe ``/proc/self/status`` for an existing ``Seccomp:`` filter mode
BEFORE invoking ``seccomp_load()``; if a parent filter is active we skip
our install entirely.

Be clear about what that costs: the systemd filter is **not** equivalent
coverage.  ``@system-service`` includes ``@process``, which permits
``fork``, ``vfork``, ``clone``, ``execve`` and ``execveat`` — precisely
the exit hatches item 1 exists to close.  systemd's denylist covers
``@privileged`` / ``@module`` / ``@mount`` / ``@reboot`` and thus
overlaps on ``mount``, ``setns``, ``init_module``, ``ptrace`` and
friends, but under a parent filter the process-creation hatches stay
open and only the RLIMIT fence applies.  ``status_snapshot()["seccomp_
source"] == "parent"`` is therefore a *degraded* state, not a
substitute; run the workload without ``SystemCallFilter=`` (or
foreground the sandbox before systemd's filter lands) if you need the
process-creation denials.

Knobs:

* ``TEE_CRAFTER_HANDLER_SANDBOX=0``  — disable entirely (debug only).
* ``TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_CPU_SEC`` — CPU-seconds allowed
  *per request*, default 30.  ``RLIMIT_CPU`` is a cumulative
  process-lifetime counter, so the fence re-bases it against the CPU
  time already consumed on every call; setting a bare 30 (as an earlier
  revision did) SIGXCPU'd a persistent service after ~30 s of aggregate
  CPU, i.e. after a few dozen requests.
* ``TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_AS_MB`` — virtual-memory limit
  per request.  Unset = no clamp.
* ``TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_FSIZE_MB`` — max bytes the
  handler may write, in MiB.  Unset = no clamp; an explicit ``0`` now
  means a genuine zero-byte limit (the handler cannot write at all)
  rather than being silently ignored.
* ``TEE_CRAFTER_HANDLER_SANDBOX_FORCE_SECCOMP=1`` — install our seccomp
  filter even when a parent filter is detected.  This will SIGSYS the
  process under TEE-Crafter's default systemd hardening; only useful
  in test harnesses that run without ``SystemCallFilter=`` and want to
  exercise the seccomp install path explicitly.
"""
from __future__ import annotations

import logging
import os
import resource
import sys

logger = logging.getLogger("tee_crafter.handler_sandbox")

# These are intentionally module-level so test code can monkeypatch
# them.  At runtime they're filled by ``_try_install_seccomp_once``.
_HAVE_PRCTL = False
_HAVE_SECCOMP = False
_PARENT_SECCOMP = False  # True when systemd/docker already installed a filter.
_SECCOMP_LIB = None  # ctypes handle if libseccomp is available.
_INSTALL_ATTEMPTED = False  # Idempotency latch for the lazy installer.

#: CPU seconds allowed per request when the operator sets no knob.
DEFAULT_CPU_SEC = 30


def _env_int(name: str, default):
    """Read an int knob.  Unset / unparseable / negative -> *default*.

    *default* may be ``None``, meaning "operator did not configure this
    limit"; that is distinct from an explicit ``0``, which the fence
    applies literally.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        return default
    return v if v >= 0 else default


def _is_disabled() -> bool:
    """Only a recognised falsy spelling takes the sandbox off."""
    return os.environ.get(
        "TEE_CRAFTER_HANDLER_SANDBOX", "1").strip().lower() in (
        "0", "false", "no", "n", "off")


def _force_seccomp() -> bool:
    """Test-only escape hatch: install our seccomp filter even when a
    parent filter is already active (will SIGSYS under systemd).
    """
    return os.environ.get(
        "TEE_CRAFTER_HANDLER_SANDBOX_FORCE_SECCOMP", "").strip().lower() in (
        "1", "true", "yes", "on")


def _detect_parent_seccomp_filter() -> bool:
    """Return True iff /proc/self/status reports an active seccomp filter.

    systemd's ``SystemCallFilter=`` (and Docker's ``--security-opt
    seccomp=...``) install a kernel filter against the calling process,
    visible as ``Seccomp: 2`` (filter mode) in ``/proc/self/status``.
    When such a filter is active and does NOT include ``seccomp(2)`` in
    its allowlist (TEE-Crafter's per-platform units do not), invoking
    ``seccomp_load()`` from here produces SIGSYS, not EPERM, and there
    is no way to catch it in-process.

    A ``True`` here means only "something is filtering us", NOT "we may
    not nest our own filter" — seccomp filters are additive, and Docker's
    default profile permits ``seccomp(2)``.  Treating the two as the same
    thing meant the in-app filter never installed under *any* container,
    which is now the only deployment model, so ``fork()``/``execve`` stayed
    open for user code.  Use :func:`_probe_seccomp_load_permitted` to tell
    the cases apart.
    """
    try:
        with open("/proc/self/status", "r", encoding="ascii") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    try:
                        mode = int(line.split(":", 1)[1].strip())
                    except (ValueError, IndexError):
                        return False
                    return mode > 0  # 1=STRICT, 2=FILTER
    except OSError:
        pass
    return False


def _load_empty_allow_filter() -> bool:
    """Load a permit-everything seccomp filter.  Used only by the probe.

    Loading it is a no-op security-wise (the default action is ALLOW and no
    rules are added); the point is purely to find out whether ``seccomp(2)``
    is reachable at all in this context.
    """
    import ctypes
    import ctypes.util
    name = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
    lib = ctypes.CDLL(name, use_errno=True)
    seccomp_init = lib.seccomp_init
    seccomp_init.restype = ctypes.c_void_p
    seccomp_init.argtypes = [ctypes.c_uint32]
    ctx = seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not ctx:
        return False
    load = lib.seccomp_load
    load.restype = ctypes.c_int
    load.argtypes = [ctypes.c_void_p]
    return load(ctx) == 0


def _probe_seccomp_load_permitted() -> bool:
    """Return True iff ``seccomp_load()`` is permitted under the parent filter.

    Run in a throwaway forked child.  If the parent filter answers
    ``seccomp(2)`` with SIGSYS or KILL_PROCESS — which is what systemd's
    ``SystemCallFilter=`` does via ``@privileged`` — it costs us the child
    instead of taking down the request server, and there is no way to catch
    that signal in the process that made the call.

    Conservative in every failure direction: if we cannot fork, cannot reap,
    or the child dies for any reason, the answer is "not permitted" and the
    caller falls back to the RLIMIT-only fence.  Only a clean exit 0 counts.

    ``fork`` here is deliberate rather than ``subprocess``: it needs no
    ``execve`` (which some parent filters also deny) and inherits the
    ``PR_SET_NO_NEW_PRIVS`` that unprivileged seccomp requires, which
    ``_install_once`` has already set.
    """
    try:
        pid = os.fork()
    except OSError as exc:
        logger.info("seccomp probe: cannot fork (%s); assuming denied", exc)
        return False
    if pid == 0:
        code = 1
        try:
            if _load_empty_allow_filter():
                code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    try:
        _, status = os.waitpid(pid, 0)
    except OSError:
        return False
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def _set_no_new_privs() -> bool:
    """Best-effort prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)."""
    global _HAVE_PRCTL
    if _HAVE_PRCTL:
        return True
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # PR_SET_NO_NEW_PRIVS = 38 on Linux.
        rc = libc.prctl(38, 1, 0, 0, 0)
        if rc == 0:
            _HAVE_PRCTL = True
            return True
    except Exception as e:
        # WARNING for the same reason as the seccomp path below: losing
        # NO_NEW_PRIVS means a setuid binary reachable from user code can
        # regain privileges, and that is not an informational event.
        logger.warning(
            "handler sandbox DEGRADED: prctl PR_SET_NO_NEW_PRIVS unavailable "
            "(%s), so privilege escalation via setuid is not blocked",
            type(e).__name__)
    return False


# Syscalls we block.  The list is curated to defend against the
# specific exit hatches enumerated in the module docstring without
# breaking common Python workloads (sockets, file I/O, numpy / torch,
# threading).  These names use the POSIX-portable form; libseccomp
# maps them to the right syscall numbers per architecture.
_DENY_SYSCALLS = (
    "fork", "vfork",
    # ``clone`` is deliberately absent from this unconditional list: it
    # is how pthreads are created as well as how processes are forked.
    # It gets an argument-filtered rule instead — see _CLONE_THREAD and
    # ``_add_clone_rule``.  Without that rule the filter blocked nothing
    # on x86-64, where glibc's ``fork()`` is implemented via
    # ``clone``(56) rather than the legacy ``fork``(57) syscall.
    "clone3",
    "execve", "execveat",
    "ptrace",
    "unshare", "mount", "umount2", "setns", "pivot_root", "chroot",
    "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module",
    "perf_event_open", "bpf",
    "userfaultfd",
    "personality",
    "io_uring_setup", "io_uring_register",
    "process_vm_readv", "process_vm_writev",
    "setuid", "setgid", "setreuid", "setregid",
    "setresuid", "setresgid",
    "capset",
)

#: ``CLONE_THREAD`` (linux/sched.h).  ``clone`` with this flag creates a
#: thread in the current process; without it, a new process.
_CLONE_THREAD = 0x00010000

#: Syscalls denied via a *masked-argument* rule rather than outright.
#: ``arg`` is the syscall argument index, ``mask``/``value`` express
#: ``(argN & mask) == value``.  On x86-64 and aarch64 ``clone``'s flags
#: are argument 0; s390/s390x swap arguments 0 and 1, so the rule is
#: skipped there rather than silently filtering the wrong argument.
_MASKED_DENY_SYSCALLS = (
    # Deny clone() when CLONE_THREAD is clear -> block process creation,
    # allow pthread_create.
    ("clone", 0, _CLONE_THREAD, 0),
)

#: Report ``clone3`` as ENOSYS rather than EPERM.  glibc >= 2.34 tries
#: ``clone3`` first for pthread_create and only falls back to ``clone``
#: on ENOSYS; answering EPERM would break threading outright.  This is
#: the same trick the default Docker seccomp profile uses.
_ENOSYS_SYSCALLS = ("clone3",)


def _try_install_seccomp_once() -> bool:
    """Compile + load a thread-local seccomp filter.

    Returns ``True`` if libseccomp was found AND the filter loaded.
    The filter applies process-wide on the calling thread; it does NOT
    apply per-request — that would mean re-compiling on every call,
    which is wasteful.  Since seccomp filters are monotonic (you can
    only ever add more restrictions), installing once at first use is
    safe and idempotent.

    Safety: refuses to call ``seccomp(2)`` when a parent filter is
    already installed (see ``_detect_parent_seccomp_filter``), because
    TEE-Crafter's per-platform systemd ``SystemCallFilter=`` denies the
    ``seccomp`` syscall via ``@privileged`` and the kernel responds
    with SIGSYS, not EPERM.  In that case we record
    ``_PARENT_SECCOMP = True`` for ``status_snapshot`` and run with the
    RLIMIT fence only — the systemd filter does NOT replace the
    process-creation denials this function installs (see the module
    docstring).
    """
    global _HAVE_SECCOMP, _PARENT_SECCOMP, _SECCOMP_LIB
    if _HAVE_SECCOMP or _PARENT_SECCOMP:
        return True
    if (_detect_parent_seccomp_filter() and not _force_seccomp()
            and not _probe_seccomp_load_permitted()):
        # A parent filter is active AND it will not let us nest another one.
        # Skipping is the only safe option: calling seccomp_load() here would
        # take the process down with an uncatchable signal.
        _PARENT_SECCOMP = True
        logger.warning(
            "handler sandbox: parent seccomp filter active and seccomp(2) is "
            "denied to us (probe child did not survive); skipping in-app "
            "filter to avoid SIGSYS. Coverage is DEGRADED: systemd's "
            "@system-service allowlist includes @process, so "
            "fork/vfork/clone/execve stay permitted for user code. Only the "
            "RLIMIT fence applies.")
        return True
    try:
        import ctypes
        import ctypes.util
        name = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
        lib = ctypes.CDLL(name, use_errno=True)
        _SECCOMP_LIB = lib

        # int seccomp_init(uint32_t def_action);  SCMP_ACT_ALLOW=0x7fff0000
        seccomp_init = lib.seccomp_init
        seccomp_init.restype = ctypes.c_void_p
        seccomp_init.argtypes = [ctypes.c_uint32]
        ctx = seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
        if not ctx:
            return False

        # int seccomp_syscall_resolve_name(const char*);
        resolve = lib.seccomp_syscall_resolve_name
        resolve.restype = ctypes.c_int
        resolve.argtypes = [ctypes.c_char_p]

        # int seccomp_rule_add(scmp_filter_ctx, uint32_t action, int syscall, unsigned int arg_cnt);
        rule_add = lib.seccomp_rule_add
        rule_add.restype = ctypes.c_int
        rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                             ctypes.c_int, ctypes.c_uint32]

        # int seccomp_rule_add_array(scmp_filter_ctx, uint32_t action,
        #                            int syscall, unsigned int arg_cnt,
        #                            const struct scmp_arg_cmp *arg_array);
        # The array form takes the comparisons by pointer; the variadic
        # ``seccomp_rule_add`` passes 24-byte structs by value, which
        # ctypes cannot marshal reliably.
        class _ScmpArgCmp(ctypes.Structure):
            _fields_ = [
                ("arg", ctypes.c_uint),
                ("op", ctypes.c_int),
                ("datum_a", ctypes.c_uint64),
                ("datum_b", ctypes.c_uint64),
            ]

        rule_add_array = lib.seccomp_rule_add_array
        rule_add_array.restype = ctypes.c_int
        rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                   ctypes.c_int, ctypes.c_uint32,
                                   ctypes.POINTER(_ScmpArgCmp)]
        SCMP_CMP_MASKED_EQ = 7  # enum scmp_compare, seccomp.h

        # SCMP_ACT_ERRNO(x) — encoded high byte 0x00050000 | errno.
        # Per libseccomp's seccomp.h: SCMP_ACT_ERRNO(x) = (0x00050000U | ((x) & 0x0000ffffU))
        EPERM = 1
        ENOSYS = 38
        deny_action = 0x00050000 | EPERM
        enosys_action = 0x00050000 | ENOSYS

        installed = 0
        for name_str in _DENY_SYSCALLS:
            sc_no = resolve(name_str.encode("ascii"))
            if sc_no < 0:
                continue  # syscall doesn't exist on this kernel; OK.
            action = (enosys_action if name_str in _ENOSYS_SYSCALLS
                      else deny_action)
            rc = rule_add(ctx, action, sc_no, 0)
            if rc == 0:
                installed += 1

        # Masked-argument rules.  ``clone`` must stay available for
        # pthread_create (CLONE_THREAD set) while process creation
        # (CLONE_THREAD clear) is denied.
        machine = os.uname().machine if hasattr(os, "uname") else ""
        for name_str, arg_idx, mask, value in _MASKED_DENY_SYSCALLS:
            if machine.startswith("s390"):
                # s390/s390x swap clone's first two arguments; filtering
                # arg 0 there would gate the wrong value.
                logger.warning(
                    "handler sandbox: skipping masked %s rule on %s "
                    "(argument order differs); process creation is NOT "
                    "blocked on this architecture", name_str, machine)
                continue
            sc_no = resolve(name_str.encode("ascii"))
            if sc_no < 0:
                continue
            cmp_ = _ScmpArgCmp(arg=arg_idx, op=SCMP_CMP_MASKED_EQ,
                               datum_a=mask, datum_b=value)
            rc = rule_add_array(ctx, deny_action, sc_no, 1,
                                ctypes.byref(cmp_))
            if rc == 0:
                installed += 1
            else:
                logger.warning(
                    "handler sandbox: masked %s rule failed (rc=%d); "
                    "process creation via %s is NOT blocked",
                    name_str, rc, name_str)

        # int seccomp_load(scmp_filter_ctx);
        load = lib.seccomp_load
        load.restype = ctypes.c_int
        load.argtypes = [ctypes.c_void_p]
        rc = load(ctx)
        if rc != 0:
            logger.warning("seccomp_load returned %d; sandbox half-engaged", rc)
            return False
        _HAVE_SECCOMP = True
        logger.info("handler sandbox: seccomp filter installed "
                    "(%d/%d syscall rules)", installed,
                    len(_DENY_SYSCALLS) + len(_MASKED_DENY_SYSCALLS))
        return True
    except Exception as e:
        # WARNING, not INFO.  Explicitly disabling this sandbox logs at
        # WARNING (see _is_disabled), so an *unrequested* loss of the same
        # fence was the quieter of the two — which is backwards: nobody chose
        # this one, so nobody is looking for it.  The RLIMIT fence still
        # applies; the syscall fence does not.
        logger.warning(
            "handler sandbox DEGRADED: libseccomp not available (%s), so user "
            "code runs with RLIMIT fencing only and no syscall filter",
            type(e).__name__)
        return False


def _install_once() -> None:
    """One-shot install of prctl + seccomp.  Idempotent.

    Deliberately NOT invoked at module import time: doing so used to
    SIGSYS the whole process under systemd's ``SystemCallFilter=``,
    which is the default for every TEE-Crafter per-platform unit (see
    module docstring).  Instead, the first call to :func:`sandbox_wrap`
    runs this once; that gives the application server a chance to
    finish setting up before the in-handler filter is installed, and
    it lets us inspect ``/proc/self/status`` to detect a parent filter
    that would otherwise turn the install into a fatal signal.
    """
    global _INSTALL_ATTEMPTED
    if _INSTALL_ATTEMPTED or _is_disabled():
        return
    _INSTALL_ATTEMPTED = True
    _set_no_new_privs()
    _try_install_seccomp_once()


def _cpu_seconds_used() -> float:
    """Total CPU seconds (user + system) this process has consumed."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def _resource_fence(*, cpu_seconds, as_bytes, fsize_bytes):
    """Clamp RLIMITs around a user handler call.

    Returns a stack of (resource, prev_soft, prev_hard) tuples so
    callers can restore.  ``None`` means "operator did not configure
    this limit, leave it alone"; an explicit ``0`` is applied literally,
    so ``RLIMIT_FSIZE=0`` really does forbid writes instead of being
    read as "unset".

    ``RLIMIT_CPU`` is special: the kernel counts it against the CPU time
    consumed by the whole *process lifetime*, not by this call.  Setting
    a flat ``cpu_seconds`` on a persistent service therefore SIGXCPU's it
    once aggregate CPU crosses the threshold, regardless of how cheap any
    individual request was.  We re-base the ceiling against
    :func:`_cpu_seconds_used` on every request so the budget is genuinely
    per-request.

    We intentionally do *not* lower RLIMIT_NPROC — Python's GIL + libc
    TLS allocate threads up front, and user numpy/torch workloads need
    intra-op threads.  The seccomp ``fork``/``vfork``/``clone`` rules
    cover process creation, which is the actual threat.
    """
    snapshots = []
    limits = []
    if cpu_seconds is not None and cpu_seconds >= 0:
        limits.append(
            (resource.RLIMIT_CPU, int(_cpu_seconds_used()) + cpu_seconds))
    if fsize_bytes is not None and fsize_bytes >= 0:
        limits.append((resource.RLIMIT_FSIZE, fsize_bytes))
    if as_bytes is not None and as_bytes > 0:
        # A zero address-space limit would kill the interpreter outright,
        # so RLIMIT_AS keeps "0 == unset".
        limits.append((resource.RLIMIT_AS, as_bytes))
    for r, soft in limits:
        try:
            prev_soft, prev_hard = resource.getrlimit(r)
            new_soft = min(soft, prev_hard) if prev_hard > 0 else soft
            resource.setrlimit(r, (new_soft, prev_hard))
            snapshots.append((r, prev_soft, prev_hard))
        except (ValueError, OSError) as e:
            logger.info("resource_fence: could not clamp %s: %s", r, e)
    return snapshots


def _resource_unfence(snapshots) -> None:
    for r, soft, hard in snapshots:
        try:
            resource.setrlimit(r, (soft, hard))
        except (ValueError, OSError):
            pass


def sandbox_wrap(fn):
    """Decorator: invoke ``fn`` under prctl + seccomp + rlimit fences.

    Returns the unwrapped ``fn`` when sandboxing is disabled via env.
    Safe to chain after :func:`tee_crafter_audit_logger.wrap_process_request`
    and :func:`siem_health.fail_closed_wrap`.
    """
    if _is_disabled():
        logger.warning("HANDLER SANDBOX DISABLED via env; user code runs unfenced")
        return fn

    import functools

    cpu = _env_int("TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_CPU_SEC", DEFAULT_CPU_SEC)
    as_mb = _env_int("TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_AS_MB", None)
    fsize_mb = _env_int("TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_FSIZE_MB", None)

    as_bytes = None if as_mb is None else as_mb * 1024 * 1024
    fsize_bytes = None if fsize_mb is None else fsize_mb * 1024 * 1024

    @functools.wraps(fn)
    def _wrapper(data):
        if not _INSTALL_ATTEMPTED:
            try:
                _install_once()
            except Exception:  # noqa: BLE001 — must never raise.
                logger.warning(
                    "handler sandbox: install_once raised; continuing "
                    "with RLIMIT-only protection.", exc_info=True)
        snapshots = _resource_fence(
            cpu_seconds=cpu, as_bytes=as_bytes, fsize_bytes=fsize_bytes)
        try:
            return fn(data)
        finally:
            _resource_unfence(snapshots)

    return _wrapper


def status_snapshot() -> dict:
    """Return a small dict describing the current sandbox state.

    Useful for ``/healthz`` and the SIEM ``extra`` field on attestation
    events so operators can confirm the fence is engaged on a running
    enclave.
    """
    return {
        "enabled": not _is_disabled(),
        "install_attempted": _INSTALL_ATTEMPTED,
        "have_prctl_no_new_privs": _HAVE_PRCTL,
        "have_seccomp": _HAVE_SECCOMP,
        "parent_seccomp_filter": _PARENT_SECCOMP,
        "seccomp_source": (
            "in-app" if _HAVE_SECCOMP
            else "parent" if _PARENT_SECCOMP
            else "none"),
        # Parsed with the same "unset / unparseable -> default" rule the
        # fence itself uses.  A bare ``int(os.environ.get(...))`` here
        # raised ValueError on a mistyped knob, which took down whatever
        # /healthz endpoint called this.
        "rlimit_cpu_sec": _env_int(
            "TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_CPU_SEC", DEFAULT_CPU_SEC),
        "rlimit_as_mb": _env_int(
            "TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_AS_MB", None),
        "rlimit_fsize_mb": _env_int(
            "TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_FSIZE_MB", None),
        # ``clone`` is denied by an argument-filtered rule, so it belongs
        # in the operator-visible list even though it is not in
        # _DENY_SYSCALLS.
        "denied_syscalls": list(_DENY_SYSCALLS) + [
            name for name, *_ in _MASKED_DENY_SYSCALLS],
        "masked_denied_syscalls": [
            {"syscall": name, "arg": arg, "mask": hex(mask), "value": value}
            for name, arg, mask, value in _MASKED_DENY_SYSCALLS
        ],
        "platform": sys.platform,
    }
