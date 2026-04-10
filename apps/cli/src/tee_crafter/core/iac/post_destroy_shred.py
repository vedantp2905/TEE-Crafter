"""Best-effort secret shredding after a successful terraform destroy.

The build directory keeps a number of files that are *ephemeral by
contract* — they are generated per deploy, never reused, and authorise
only resources that have been destroyed — but still want positive
cleanup so the operator's workstation does not accumulate sensitive
material on disk:

* ``*ssh_key*``                        — Ed25519/RSA SSH key minted by
  ``local_sensitive_file.ssh_private_key`` in the Azure / GCP / GPU-CC / SGX
  templates.  The matching VM has already been deleted by the time we
  run, so the key authorises nothing live, but operators routinely
  archive ``builds/`` directories for compliance and we do not want
  PRIVATE-KEY material sitting in those archives.

  The glob is deliberately loose.  It used to be ``*_ssh_key.pem``, and only
  2 of the 7 templates that mint a key write a ``.pem`` suffix — ``sgx``,
  ``tdx/azure``, ``snp/gcp``, ``tdx/gcp`` and ``gpu_cc/gcp`` all write
  extension-less names, so 5 of 7 private keys survived teardown.  This is
  filename drift, not a one-off bug, which is why
  ``tests/core/test_post_destroy_shred.py`` now walks every
  ``local_sensitive_file`` in all 10 templates and asserts each filename is
  covered here.
* ``app.env`` / ``app/app.env``        — the operator's ``--secrets-env``
  dotenv.  In plaintext mode (no BYOK, or a non-sealable provider) this is
  the entire secret set in cleartext.
* ``terraform.tfstate.backup``         — the pre-destroy state snapshot.
  Always contains the SSH key (it is a ``sensitive`` resource), plus any
  other values flagged ``sensitive = true``.  After destroy succeeds the
  current ``terraform.tfstate`` is already empty, so the backup is the
  last remaining copy of these secrets in the build dir.
* ``*_authorised_keys.tmp``            — temporary OS-login authorised
  keys staged during GCP IAP deploy; sometimes left behind on aborted
  runs.
* ``siem.env`` / ``app/siem.env``      — flattened SIEM bearer / API
  secrets generated at build time (same material is re-staged to VM
  tmpfs during deploy; keeping a plaintext copy in ``builds/`` after
  destroy is unnecessary and widens workstation backup exposure).
* ``byok.env`` / ``app/byok.env``      — environment used for
  attestation-gated KMS unwrap; shredded with the build directory on
  successful destroy.

Files are overwritten with zeros before unlinking on best-effort
filesystems (POSIX overwrite-then-unlink — note that journaled or
COW filesystems may keep copies, which is acknowledged in the security
docs; the goal here is to remove the obvious filesystem-level copy
rather than to defeat a forensic adversary).
"""
from __future__ import annotations

import datetime
import fnmatch
import os
import glob
import logging
from typing import List

logger = logging.getLogger(__name__)


_SHRED_GLOBS = (
    # One loose glob instead of an enumeration that has to be kept in sync
    # with 10 Terraform templates.  Matches `sgx_ssh_key`, `tdx_ssh_key`,
    # `snp_gcp_ssh_key`, `gpu_cc_gcp_ssh_key`, `snp_ssh_key.pem`, ... The old
    # list also named `tdx_ssh_key.pem`, which no template has ever produced.
    "*ssh_key*",
    "terraform.tfstate.backup",
    "*_authorised_keys.tmp",
    "*_authorized_keys.tmp",
    # SIEM / BYOK flattened secrets — both the new layout (``siem/``,
    # ``byok/``) and the legacy top-level + app-staging locations are
    # included so a half-migrated build dir still gets cleaned up.
    # See docs/security.md §16.4.
    "siem/siem.env",
    "byok/byok.env",
    "siem.env",
    "byok.env",
    "app/siem.env",
    "app/byok.env",
    # Plaintext --secrets-env dotenv (build root and app-staging copy).
    "app.env",
    "app/app.env",
)


#: Chunk size for the zero-fill pass.  This bounds *memory*, not how much of
#: the file gets overwritten — see :func:`_overwrite_and_unlink`.
_ZERO_CHUNK = 1024 * 1024


def _overwrite_and_unlink(path: str) -> bool:
    """Best-effort overwrite-with-zeros then unlink.

    The whole file is overwritten.  This used to write
    ``b"\\x00" * min(size, 8 * 1024 * 1024)``, silently leaving anything past
    8 MiB intact — which is exactly wrong for ``terraform.tfstate.backup``, the
    largest file in the list and the one the module docstring calls "the last
    remaining copy of these secrets".  Zeros are streamed in
    :data:`_ZERO_CHUNK` blocks so a large state file does not materialise a
    same-sized buffer in memory.

    Returns True on success or if the file does not exist.  Never raises.
    """
    try:
        if not os.path.isfile(path):
            return True
        size = os.path.getsize(path)
        if size > 0:
            try:
                with open(path, "r+b") as f:
                    remaining = size
                    while remaining > 0:
                        n = min(remaining, _ZERO_CHUNK)
                        f.write(b"\x00" * n)
                        remaining -= n
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError:
                        pass
            except OSError as exc:
                logger.debug("could not overwrite %s: %s", path, exc)
        os.unlink(path)
        return True
    except OSError as exc:
        logger.debug("could not unlink %s: %s", path, exc)
        return False


def is_covered_by_shred_globs(relative_path: str) -> bool:
    """True when *relative_path* would be shredded by :func:`shred_post_destroy`.

    *relative_path* is interpreted relative to the build directory, with ``/``
    separators.  Matching is segment-wise so it mirrors :mod:`glob` (where
    ``*`` never spans a directory boundary) rather than plain
    :func:`fnmatch.fnmatch` (where it does).

    Exposed so tests can assert coverage of every file the Terraform templates
    write without reaching into ``_SHRED_GLOBS``; the filename drift this
    guards against is the whole reason FIX 6 exists.
    """
    parts = [p for p in relative_path.replace("\\", "/").split("/") if p and p != "."]
    for pattern in _SHRED_GLOBS:
        pat_parts = [p for p in pattern.split("/") if p]
        if len(pat_parts) != len(parts):
            continue
        if all(fnmatch.fnmatch(seg, pat)
               for seg, pat in zip(parts, pat_parts)):
            return True
    return False


def _write_manifest(build_dir: str, removed: List[str]) -> None:
    """Append a non-secret audit trail so operators know what was cleared.

    This is **not** a substitute for CI logs: it only records basenames
    and timestamps so you can reconcile shredding with compliance tickets
    without retaining the secret bytes.  If ``terraform destroy`` failed,
    this function is never called and secrets stay on disk for retry /
    forensics (same policy as SSH keys).
    """
    manifest = os.path.join(build_dir, "post_destroy_shred_manifest.txt")
    ts = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# TEE-Crafter post-destroy shred manifest",
        f"# UTC timestamp: {ts}",
        f"# Absolute build_dir: {os.path.abspath(build_dir)}",
        "# Files overwritten+unlinked (paths relative to build_dir):",
    ]
    for p in sorted(removed):
        rel = os.path.relpath(p, build_dir)
        lines.append(rel.replace("\\", "/"))
    lines.append("# End of manifest — no secret contents are ever stored here.")
    try:
        with open(manifest, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as exc:
        logger.warning("could not append shred manifest %s: %s", manifest, exc)


def shred_post_destroy(build_dir: str) -> List[str]:
    """Shred well-known ephemeral secret files inside *build_dir*.

    Returns the list of paths that were unlinked.  Idempotent; safe to
    call multiple times.

    Appends a human-readable ``post_destroy_shred_manifest.txt``
    (basenames / relative paths only, UTC timestamp) so workstation
    ``builds/`` archives retain an auditable record of what was cleared
    without keeping the cryptographic material.
    """
    if not build_dir or not os.path.isdir(build_dir):
        return []
    removed: List[str] = []
    for pattern in _SHRED_GLOBS:
        for path in glob.glob(os.path.join(build_dir, pattern)):
            if _overwrite_and_unlink(path):
                removed.append(path)
    if removed:
        _write_manifest(build_dir, removed)
    return removed


__all__ = ["shred_post_destroy", "is_covered_by_shred_globs"]
