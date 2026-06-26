"""The two things that stopped `sgx-azure --batch` from ever running its workload.

Both were found on real SGX hardware on 2026-08-23, one after the other, and
neither was visible from the code:

1. **AppArmor denied ``open("/")``.** The batch profile ends with
   ``/** rwlkmix,`` and reads as "allow everything" — but in AppArmor ``/**``
   matches paths with at least one character after the slash and does *not*
   match the root directory. Gramine's loader opens ``/`` while building its own
   filesystem view, so every batch run died at::

       [P1:T1:] error: Mounting "file:/" (chroot) under / failed: EACCES
       [P1:T1:] error: libos_init() failed in init_mount_root: EACCES

   which names a Gramine mount and reads like a manifest problem. The kernel was
   unambiguous: ``apparmor="DENIED" operation="open" name="/" comm="loader"``.
   Adding ``/ rwlkmix,`` made the enclave start. The *strict* profile has
   carried ``/ r,`` all along, so service mode never hit it — this was drift
   between two profiles, not an oversight in both.

2. **Gramine could not read ``/input``.** With the enclave finally starting, the
   workload failed on ``cannot open /input/data.json: Permission denied``.
   ``/input`` is a docker bind mount the batch unit adds at run time, so it is
   not in the image and GSC cannot infer it; Gramine refuses any host file it
   was not told about, by design.

The second fix is **not yet confirmed on hardware** — it needs another batch
run. These tests hold the shape of both fixes so a regression is caught for
free, which is the point when the alternative costs a VM.
"""
from __future__ import annotations

import os
import re
import tomllib

import pytest

_PROFILES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "templates", "common")


def _profile(name: str) -> str:
    with open(os.path.join(_PROFILES, name), encoding="utf-8") as fh:
        return fh.read()


def _fs_rules(text: str) -> list[str]:
    """Bare filesystem allow rules, comments stripped."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if re.fullmatch(r"/(\*\*)?\s+[rwlkmixa]+,", line):
            out.append(line)
    return out


class TestAppArmorAllowsTheRootDirectory:

    @pytest.mark.parametrize("profile", [
        "apparmor-batch-container", "apparmor-container",
    ])
    def test_a_rule_covers_the_bare_root(self, profile):
        """``/**`` is not enough — the root directory needs its own rule."""
        rules = _fs_rules(_profile(profile))
        assert any(r.startswith("/ ") for r in rules), (
            f"{profile} has no rule for the bare '/': {rules}. Gramine's "
            f"loader opens '/' and will fail with EACCES.")

    def test_the_batch_profile_grants_read_on_root(self):
        rules = _fs_rules(_profile("apparmor-batch-container"))
        root = [r for r in rules if r.startswith("/ ")]
        assert root, "no bare-'/' rule"
        assert "r" in root[0], f"root rule must grant read: {root[0]}"

    def test_the_star_star_rule_is_still_there(self):
        """The fix adds a rule; it must not have replaced the broad one.

        Batch mode runs arbitrary user images, so path allowlisting is
        deliberately not the confinement mechanism here.
        """
        assert any(r.startswith("/** ")
                   for r in _fs_rules(_profile("apparmor-batch-container")))

    def test_the_dangerous_denies_survived(self):
        """Confinement in batch mode comes from these, not from path scoping."""
        text = _profile("apparmor-batch-container")
        for rule in ("deny mount,", "deny pivot_root,",
                     "deny capability sys_admin,", "deny /proc/kcore rwklx,",
                     "deny /sys/kernel/** rwklx,",
                     "deny ptrace (read, readby, trace, tracedby),"):
            assert rule in text, rule

    def test_the_two_profiles_do_not_drift_on_root_again(self):
        """The bug was one profile having the rule and the other not."""
        for name in ("apparmor-batch-container", "apparmor-container"):
            assert any(r.startswith("/ ") for r in _fs_rules(_profile(name))), name


class TestTheGscFragmentDeclaresNoHostPaths:
    """The fragment must name neither ``/input`` nor ``/output``.

    This class asserted the opposite twice, and hardware settled it on
    2026-08-23.  ``finalize_manifest.py`` reads ``sgx.trusted_files``,
    ``sgx.allowed_files`` *and* ``sgx.protected_files`` out of the fragment
    (finalize_manifest.py:48-55) and pushes all three through
    ``expand_trusted_files``, which requires each path to exist in the image at
    build time and then records a sha256 for it *in trusted_files*
    (finalize_manifest.py:38-46).  So naming a host path here is doubly wrong:
    the build dies if the path is absent, and the path becomes measured if it
    is present.

    Two corrections worth keeping visible, because each cost a hardware run:

    * The first fix blamed ``fs.mounts``.  ``finalize_manifest.py`` never reads
      ``fs.mounts`` at all; ``allowed_files`` was the cause the whole time, and
      removing the mount while keeping ``allowed_files`` left the build failing
      identically.
    * GSC reports it as ``NameError: name 'ManifestError' is not defined`` --
      a bug in GSC, which never defines that class -- so the exception naming
      the missing path is replaced by one that does not.
    """

    @pytest.fixture(scope="class")
    def manifest(self):
        from tee_crafter.cli.deployment.sgx.gsc import build_manifest

        return build_manifest()

    def test_it_is_valid_toml(self, manifest):
        assert tomllib.loads(manifest)

    @pytest.mark.parametrize("key", ["allowed_files", "trusted_files",
                                     "protected_files"])
    def test_no_host_path_is_declared_in_the_fragment(self, manifest, key):
        doc = tomllib.loads(manifest)
        declared = doc.get("sgx", {}).get(key, [])
        assert declared == [], f"sgx.{key} breaks `gsc build`: {declared}"

    def test_no_mount_either(self, manifest):
        doc = tomllib.loads(manifest)
        mounts = doc.get("fs", {}).get("mounts", [])
        assert not any(m.get("path") in ("/input", "/output") for m in mounts)

    def test_the_enclave_geometry_is_still_declared(self, manifest):
        doc = tomllib.loads(manifest)
        assert doc["sgx"]["remote_attestation"] == "dcap"
        assert doc["sgx"]["enclave_size"]
        assert isinstance(doc["sgx"]["max_threads"], int)
