"""The in-TEE runtime modules every build must carry, and the fail-closed copy.

``builder.py`` and ``platforms.py` each used to keep their own ``_RUNTIME_MODULES``
tuple and their own ``_copy_runtime_modules``, both of which did::

    if os.path.isfile(src):
        shutil.copy2(src, ...)

That skip is fail-open, and two of the modules in the list are security gates:

* ``siem_health.py``  — SIEM-SEC-4.  The in-TEE app imports it and refuses
  requests when the SIEM sidecar cannot prove log freshness.
* ``byok_health.py``  — the BYOK equivalent.  Refuses requests when the
  attestation-gated DEK release did not land.

If either file is absent from the installation the old code copied what it
could, returned normally, and shipped a build whose app falls through the gate
import and serves requests with no SIEM freshness proof and no BYOK release
check — with nothing on screen and nothing in the provenance to say so.

"Absent from the installation" is not hypothetical.  ``seccomp-container.json``
was missing from the repository entirely and broke bake on 9 of 10 platforms,
and a wheel built without ``templates/**/*`` in
``[tool.setuptools.package-data]`` (``apps/cli/pyproject.toml``) drops this whole
directory while a source checkout looks fine.

So a missing runtime module is now fatal, matching the treatment
:func:`tee_crafter.core.builder.platforms._load_trust_anchor` already gives
missing attestation trust anchors.
"""
from __future__ import annotations

import os
import shutil


class MissingRuntimeModule(RuntimeError):
    """A module the in-TEE runtime imports is not present in the installation.

    Always fatal.  Shipping the build anyway produces a TEE that looks healthy
    and silently runs without one of its gates.
    """


#: Modules copied from ``templates/common/`` into every build directory.
#: Keep the annotations: they are the only record of what breaks when one of
#: these goes missing.
RUNTIME_MODULES: tuple[str, ...] = (
    "tee_crafter_audit_logger.py",
    "tee_crafter_attestation_monitor.py",
    "tee_crafter_key_rotation.py",
    "tee_crafter_runtime_bootstrap.py",
    # NOTE: staged into every build but currently imported by nothing — see the
    # module-level audit note in templates/common/tee_crafter_service_runtime.py.
    # Kept in the list so removing it is a deliberate decision rather than a
    # silent drop.
    "tee_crafter_service_runtime.py",
    # Self-contained SIEM sidecar that ``tee-crafter-siem.service`` exec's on the
    # VM host.  Required for Nitro and SGX (host-side heartbeat), both of which
    # stage from the build_dir root.  Missing this is the cause of
    # ``can't open file '/opt/tee-crafter/siem_export.py'`` at boot.
    "siem_export.py",
    # SECURITY GATE — SIEM-SEC-4 fail-closed.  Imported by the in-enclave app
    # template; reads the health-state JSON the sidecar writes each tick and
    # refuses requests when SIEM cannot prove freshness.  Production default is
    # fail-closed; dev hatch TEE_CRAFTER_SIEM_FAIL_OPEN=1 disables.
    "siem_health.py",
    # SECURITY GATE — BYOK fail-closed (mirrors siem_health).  Refuses requests
    # when BYOK was requested but the attested DEK release did not land.
    # Production default fail-closed; dev hatch TEE_CRAFTER_BYOK_FAIL_OPEN=1.
    "byok_health.py",
    # SIEM-SEC-5 in-process handler sandbox.  Per-request seccomp + rlimit fence
    # around user code.  Loaded lazily by the template so platforms without
    # seccomp support fall open with a warning, but it must be in the bundle for
    # that lazy import to have anything to find.
    "tee_crafter_handler_sandbox.py",
    # Also a CLIENT_SUPPORT_MODULE, and in-TEE for a different reason.  On an
    # Azure paravisor CVM the guest cannot produce verifiable evidence by
    # itself: the vTPM yields a raw MAC'd TDREPORT, so the *guest* has to
    # exchange it for an MAA token before putting anything in its RA-TLS
    # certificate.  ``azure_guest_token()`` lives here; the client-side copy
    # verifies what this one fetches.  Both halves being one file is what keeps
    # the nonce-binding convention from drifting between them.
    "tee_crafter_maa.py",
)

#: Subset whose absence removes an enforcement boundary rather than a feature.
#: Named separately so the error message can say what the operator is losing.
_SECURITY_GATES = frozenset({"siem_health.py", "byok_health.py"})


def common_templates_dir() -> str:
    """``tee_crafter/templates/common`` — the source of the runtime modules."""
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates", "common",
    )


def copy_runtime_modules(dest_dir: str) -> None:
    """Copy every module in :data:`RUNTIME_MODULES` into *dest_dir*.

    Raises :class:`MissingRuntimeModule` if any of them is absent, listing all
    of the missing names at once so a broken installation is diagnosed in one
    pass rather than one rebuild per file.
    """
    base = common_templates_dir()
    missing: list[str] = []
    for name in RUNTIME_MODULES:
        src = os.path.join(base, name)
        if not os.path.isfile(src):
            missing.append(name)
            continue
        shutil.copy2(src, os.path.join(dest_dir, name))
    if not missing:
        return

    gates = sorted(n for n in missing if n in _SECURITY_GATES)
    detail = "\n".join(f"  - {n}" for n in missing)
    gate_note = ""
    if gates:
        gate_note = (
            "\n\n"
            + ", ".join(gates)
            + " enforce the in-TEE fail-closed gates. A build staged without "
            "them serves requests with no SIEM freshness proof and/or no BYOK "
            "release check, and reports success while doing it."
        )
    raise MissingRuntimeModule(
        f"{len(missing)} in-TEE runtime module(s) are missing from the "
        f"installation at {os.path.abspath(base)}:\n"
        f"{detail}{gate_note}\n\n"
        "Reinstall tee-crafter, or restore the files from the repository. If "
        "you built a wheel, check that 'templates/**/*' is listed under "
        "[tool.setuptools.package-data] in apps/cli/pyproject.toml. Refusing "
        "to stage an incomplete build."
    )


#: Modules staged next to the generated ``client.py`` rather than into the
#: in-TEE ``app/`` directory.
#:
#: ``RUNTIME_MODULES`` above is the *in-TEE* set: those land in
#: ``build_dir/app/`` and are imported by the workload. The verifier client is a
#: different program on a different machine — it runs on the operator's host and
#: connects *to* the TEE — so anything it imports has to be copied beside it.
CLIENT_SUPPORT_MODULES: tuple[str, ...] = (
    # Shared Intel DCAP TCB status evaluator. All four Intel clients import it
    # (sgx-azure, tdx-azure, tdx-gcp, gpu-cc-gcp) and exit 1 when it is absent,
    # so a build staged without it fails closed on every connection.  Being one
    # shared module is deliberate: four copies of one verifier drifting apart is
    # the direct cause of the worst bugs found in this codebase, including a
    # platform that had no QE-report signature check at all.
    "tee_crafter_tcb_eval.py",
    # MAA token verifier for the Azure vTPM (HCLA) evidence path.  tdx-azure's
    # client refused that path outright because an HCLA blob is not checkable
    # client-side; the only party who can make it verifiable is Microsoft Azure
    # Attestation, so the client now verifies MAA's signed JWT instead.  Staged
    # here for the same reason as the TCB evaluator: one implementation, beside
    # the client that imports it.
    "tee_crafter_maa.py",
)


def copy_client_support_modules(dest_dir: str) -> None:
    """Copy :data:`CLIENT_SUPPORT_MODULES` into the client's directory.

    *dest_dir* is where ``client.py`` was written — the module must sit beside
    it, because the deploy runs the client with that directory as the working
    directory and therefore as ``sys.path[0]``.

    Fatal when a module is missing, for the same reason
    :func:`copy_runtime_modules` is: a silent skip produces a build that looks
    fine and then refuses every connection at verify time, with the cause a
    directory away from the error.
    """
    base = common_templates_dir()
    missing: list[str] = []
    for name in CLIENT_SUPPORT_MODULES:
        src = os.path.join(base, name)
        if not os.path.isfile(src):
            missing.append(name)
            continue
        shutil.copy2(src, os.path.join(dest_dir, name))
    if missing:
        raise MissingRuntimeModule(
            f"{len(missing)} client-side support module(s) are missing from the "
            f"installation:\n"
            + "\n".join(f"  - {n}" for n in missing)
            + "\n\nThe generated verifier client imports these and exits 1 "
              "without them, so every attestation would fail closed. This "
              "usually means a wheel built without `templates/**/*` in "
              "[tool.setuptools.package-data]."
        )


# ---------------------------------------------------------------------------
# User-source staging
# ---------------------------------------------------------------------------
#: Names never copied out of the user's source directory into a build.
#:
#: ``.env`` is the one that matters: secrets belong in ``--secrets-env``, which
#: seals them to the BYOK key and delivers them at runtime, whereas anything
#: left here is copied into the build context and baked into the measured
#: image.  ``PKG-005`` ("No .env / no secrets in build context", HIGH) exists to
#: catch exactly that.
SOURCE_IGNORE = (
    'venv', '.git', '__pycache__', '.env', '*.pyc', '.cursor', 'node_modules',
    'build_*',
)

#: Directories skipped by name regardless of the glob patterns above.
SOURCE_SKIP_DIRS = frozenset({
    "venv", ".git", "__pycache__", ".cursor", "node_modules",
})


def copy_source_tree(source_dir: str, dest_dir: str) -> None:
    """Copy a user source tree into a build, honouring :data:`SOURCE_IGNORE`.

    Lives here, beside the runtime-module list, for the same reason that list
    does: there were **five** hand-rolled copies of this loop (one in
    ``platforms.py``, four in ``builder.py``), each pairing
    ``shutil.ignore_patterns`` with ``copytree`` for directories and a bare
    ``shutil.copy2`` for files.  ``copytree`` consults the matcher; ``copy2``
    does not, so every one of them ignored ``.env`` *inside* subdirectories and
    copied a top-level ``.env`` straight into the measured image.

    Caught by ``PKG-005`` on a real ``snp-gcp`` deploy (2026-08-21) reporting
    ``flagged=['.env']`` -- and it survived the first fix because only the
    ``platforms.py`` copy was corrected while the container flow went through
    ``builder.py``.  One implementation now, so a partial fix is not possible.
    """
    ignore_func = shutil.ignore_patterns(*SOURCE_IGNORE)
    names = os.listdir(source_dir)
    ignored = ignore_func(source_dir, names)
    for item in names:
        if item in ignored:
            continue
        s = os.path.join(source_dir, item)
        d = os.path.join(dest_dir, item)
        if os.path.isdir(s):
            if item not in SOURCE_SKIP_DIRS:
                shutil.copytree(s, d, ignore=ignore_func)
        else:
            shutil.copy2(s, d)
