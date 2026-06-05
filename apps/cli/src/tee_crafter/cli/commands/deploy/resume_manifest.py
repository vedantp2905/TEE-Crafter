"""What ``deploy-from-build`` needs in order to finish a deploy it did not start.

A build directory is already self-describing about *what* to deploy: ``main.tf``
plus its ``terraform.tfstate``, the staged ``app/`` bundle, the rendered client.
Two things, though, live only in the process that ran ``tee-crafter deploy`` and
vanish when it exits:

* **The TEE platform.** It selects which of the ten deployment phases to run.
  Losing it is how ``deploy-from-build`` came to hardcode ``nitro-aws`` and then
  fail on ``app.eif not found`` for every confidential-VM build directory.
* **The ``TF_VAR_*`` environment.** Terraform reads these from the process
  environment; nothing in this repo writes a ``.tfvars`` file. Losing them is
  the more dangerous of the two, because Terraform would not error — it would
  quietly fall back to each variable's ``default`` and converge the *existing*
  state onto a different plan than the one that was half-applied. An NSG rule
  that was present at apply time would simply be deleted.

Also recorded: the enclave/VM shape and the launch measurements, because on
three platforms the measurements are not decoration. ``sgx-azure`` uploads them
to the VM as ``measurements.json``, and ``snp-gcp`` and ``gpu-cc-azure`` hand
them to the client runner. A resume that guessed ``{}`` there would weaken the
check rather than fail, so a resume without a manifest is refused outright.

The manifest is written on both the ``--deploy`` and the ``--no-deploy`` path,
before anything that can fail, so a build directory that exists at all is
resumable.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

#: Manifest filename, at the top level of the build directory next to
#: ``main.tf`` and ``terraform.tfstate`` — the files it describes.
MANIFEST_NAME = "deploy_manifest.json"

#: Bumped only for a change a reader cannot handle by ignoring new keys.
MANIFEST_VERSION = 1

#: Prefix of the environment variables Terraform itself reads.
TF_VAR_PREFIX = "TF_VAR_"


def manifest_path(build_dir: str) -> str:
    return os.path.join(build_dir, MANIFEST_NAME)


def _tf_var_env(env: Optional[dict] = None) -> dict:
    src = os.environ if env is None else env
    return {k: v for k, v in sorted(src.items()) if k.startswith(TF_VAR_PREFIX)}


def write_manifest(
    build_dir: str,
    *,
    tee_platform: str,
    cpu: int,
    ram: int,
    measurements: Optional[dict] = None,
    custom_ami: Optional[str] = None,
    env: Optional[dict] = None,
) -> Optional[str]:
    """Record everything ``deploy-from-build`` cannot rediscover.

    Best effort: a build directory that cannot take this file is not worth
    aborting a deploy over, and the reader refuses clearly when it is missing.
    Returns the path written, or ``None``.
    """
    doc: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "tee_platform": tee_platform,
        "cpu": int(cpu),
        "ram": int(ram),
        "measurements": dict(measurements or {}),
        "custom_ami": custom_ami or "",
        "tf_vars": _tf_var_env(env),
    }
    try:
        path = manifest_path(build_dir)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.write("\n")
        return path
    except OSError:
        return None


def read_manifest(build_dir: str) -> Optional[dict]:
    """Load the manifest, or ``None`` when absent/unreadable/not a dict."""
    try:
        with open(manifest_path(build_dir), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def provenance_platform(build_dir: str) -> str:
    """The ``tee_platform`` recorded in ``build_provenance.json``, if any.

    A weaker source than the manifest — it is written by ``save_audit_trail`` at
    the *end* of a deploy, so the build directories most in need of a resume are
    exactly the ones that do not have it. Consulted anyway so build directories
    from before this manifest existed still identify their platform.
    """
    try:
        from tee_crafter.core.audit import build_layout as _layout

        with open(_layout.resolve_provenance_json(build_dir), "r",
                  encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, ImportError):
        return ""
    return str(doc.get("tee_platform") or "") if isinstance(doc, dict) else ""


def resolve_platform(build_dir: str) -> tuple[str, str]:
    """Return ``(tee_platform, source)`` for *build_dir*, or ``("", "")``.

    Deliberately does **not** fall back to parsing the directory name. The name
    carries a staging label, not a platform id: a Nitro build directory is
    ``..._container_nitro_build_...`` while the platform is ``nitro-aws``. Close
    enough to look usable, wrong often enough to be a trap.
    """
    doc = read_manifest(build_dir)
    if doc and doc.get("tee_platform"):
        return str(doc["tee_platform"]), MANIFEST_NAME
    prov = provenance_platform(build_dir)
    if prov:
        return prov, "build_provenance.json"
    return "", ""


def apply_tf_vars(
    manifest: dict, *, env: Optional[dict] = None,
) -> tuple[list[str], list[tuple[str, str, str]], list[str]]:
    """Make the ``TF_VAR_*`` environment exactly the one the manifest recorded.

    Returns ``(restored, overridden, cleared)`` for the caller to report:

    * ``restored`` — names set from the manifest.
    * ``overridden`` — ``(name, ambient_value, manifest_value)`` where the two
      disagreed. The manifest wins: it is the value the existing Terraform
      state was applied with, and a resume's job is to converge that state, not
      to quietly re-plan it. An operator who wants a different value should run
      ``tee-crafter deploy`` rather than a resume.
    * ``cleared`` — ``TF_VAR_*`` names present now but absent at apply time.
      Removed for the same reason: leaving them set would hand Terraform an
      input the half-applied plan never had.

    Two names are expected to be cleared on a GPU-CC resume and that is fine:
    ``TF_VAR_nras_egress_cidrs`` and ``TF_VAR_allow_nras_broad_internet`` are
    set by the phase's own ``pre_apply`` hook
    (:mod:`~tee_crafter.cli.deployment.common.nras_egress`), which runs again on
    the resume and re-resolves NVIDIA's attestation addresses from scratch —
    the right behaviour, since those addresses rotate.
    """
    target = manifest.get("tf_vars")
    if not isinstance(target, dict):
        return [], [], []
    environ = os.environ if env is None else env
    restored: list[str] = []
    overridden: list[tuple[str, str, str]] = []
    for name, value in sorted(target.items()):
        value = str(value)
        current = environ.get(name)
        if current is not None and current != value:
            overridden.append((name, current, value))
        environ[name] = value
        restored.append(name)
    cleared = [k for k in _tf_var_env(environ) if k not in target]
    for name in cleared:
        environ.pop(name, None)
    return restored, overridden, sorted(cleared)


#: Terraform's local-backend state lock.  A file, written next to the state.
STATE_LOCK_NAME = ".terraform.tfstate.lock.info"


def read_state_lock(build_dir: str) -> dict | None:
    """Return the parsed Terraform state lock in *build_dir*, or ``None``.

    Terraform writes this file while it holds the state lock and removes it on
    a clean exit -- including on SIGINT, which it traps.  So a lock left on
    disk means the previous ``terraform apply`` did *not* exit cleanly: it was
    SIGKILLed, the container was torn out from under it, or the machine died.

    That is precisely the situation this command exists to recover from, and it
    is also the situation in which the recovery cannot proceed: the next
    ``terraform apply`` fails with "Error acquiring the state lock", so a
    resume against a half-applied CVM stops before it plans anything while the
    already-created Bastion and NAT gateway keep billing.

    Returns ``None`` for a malformed or unreadable file rather than raising --
    the caller's decision does not depend on the contents, only on presence,
    and refusing to resume because we could not *parse* a lock we are about to
    break would be the wrong failure.
    """
    path = os.path.join(build_dir, STATE_LOCK_NAME)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def describe_state_lock(lock: dict) -> str:
    """One-line human summary of a state lock, for an operator-facing message."""
    if not lock:
        return "unreadable lock file"
    who = lock.get("Who") or "unknown"
    created = lock.get("Created") or "unknown time"
    op = lock.get("Operation") or "unknown operation"
    return f"{op} by {who}, started {created}"


def clear_state_lock(build_dir: str) -> bool:
    """Delete the local state lock.  Returns whether it is now gone.

    Deliberately a plain file delete rather than ``terraform force-unlock``:
    ``force-unlock`` needs the lock ID *and* a working ``terraform init`` in
    the directory, and on a local backend it does exactly this and nothing
    more.  Do not reach for this on a remote backend -- there the lock is held
    by the backend, not by this file, and deleting a local artefact would not
    release it.  Every platform here uses the local backend (the templates
    declare no ``backend`` block).
    """
    path = os.path.join(build_dir, STATE_LOCK_NAME)
    try:
        os.remove(path)
    except FileNotFoundError:
        return True
    except Exception:
        return False
    return not os.path.exists(path)
