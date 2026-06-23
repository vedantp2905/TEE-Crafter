"""configfs-tsm needs a *pre-created* report entry, not a group-writable parent.

Found on real hardware 2026-08-21.  `tdx-gcp` could not start at all:

    configfs-tsm failed ( Permission denied:
      '/sys/kernel/config/tsm/report/teecrafter_1647_.../inblob')
    and TEE_CRAFTER_STRICT_TSM=1 — refusing silent fallback to
    /dev/tdx-guest ioctl (GPU-10)

The unit's privileged ``ExecStartPre`` chgrp'd ``/sys/kernel/config/tsm/report/``
to ``kvm`` so the unprivileged ``tee_enclave`` user could ``mkdir`` an entry --
and the ``mkdir`` *does* succeed.  But configfs creates the attribute files
inside a fresh entry itself, root-owned.  Measured on a GCP TDX C3 VM,
kernel ``6.8.0-1066-gcp``::

    drwxrwxr-x root kvm   /sys/kernel/config/tsm/report/
    mkdir OK
    -r--r--r-- 1 root root  generation
    --w------- 1 root root  inblob        <- mode 0200, no group bits
    -r--r--r-- 1 root root  outblob
    INBLOB WRITE DENIED

Group ownership of the parent cannot reach the children, and only root can
chown them -- which it can only do *after* they exist.  So the privileged step
pre-creates ``tee-crafter-0`` and hands its ``inblob`` to the ``kvm`` group;
verified on the same host with the real unit line, yielding an 8000-byte
``tdx_guest`` quote to the unprivileged user, and again on a second write to the
same entry (so reuse works).

`snp-gcp` never hit this because ``/dev/sev-guest`` is a pre-existing device
node the privileged step really can chgrp.  That asymmetry is why the bug
survived: the platform that shared the unit pattern also had a device to fall
back on.
"""

import ast
import os
import pathlib

import pytest

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "tee_crafter"
_UNITS = _SRC / "resources" / "systemd"
_TEMPLATES = _SRC / "templates"

#: Platforms whose app fetches a quote through configfs-tsm and whose unit must
#: therefore pre-create the entry.  `gpu_cc/gcp` belongs here even though it is
#: a GPU platform: it disables the ioctl fallback entirely, so configfs is not
#: merely its primary path, it is its only one.
CONFIGFS_PLATFORMS = [
    ("tdx-gcp.service", "tdx/gcp"),
    ("tdx-azure.service", "tdx/azure"),
    ("gpu-cc-gcp.service", "gpu_cc/gcp"),
]

ENTRY = "/sys/kernel/config/tsm/report/tee-crafter-0"


def _unit(name):
    return (_UNITS / name).read_text()


def _template(rel):
    return (_TEMPLATES / rel / "app.template.py").read_text()


def _pool_fragment(rel):
    """The module-level pool helpers, lifted out of the template.

    Templates are not importable Python until rendered, so the fragment is
    compiled on its own.  That is the point: a syntax or scoping error in this
    code path is otherwise invisible until a deploy reaches attestation.
    """
    src = _template(rel)
    return src[src.index("_TSM_SERVICE_ENTRY = "):src.index("def _find_tdx_device")]


class TestUnitPreCreatesTheEntry:
    @pytest.mark.parametrize("unit,_rel", CONFIGFS_PLATFORMS)
    def test_entry_is_created_privileged(self, unit, _rel):
        pre = [ln for ln in _unit(unit).splitlines() if ln.startswith("ExecStartPre=")]
        assert pre, f"{unit} has no ExecStartPre"
        line = "\n".join(pre)
        # The `+` prefix is what makes it run with full privilege despite User=.
        assert line.startswith("ExecStartPre=+"), (
            f"{unit}: the tsm prep must be privileged or it cannot chown anything")
        assert f"mkdir -p {ENTRY}" in line, f"{unit} does not pre-create {ENTRY}"

    @pytest.mark.parametrize("unit,_rel", CONFIGFS_PLATFORMS)
    def test_inblob_is_handed_to_the_service_group(self, unit, _rel):
        """Chowning the parent is what failed; the child must be chowned."""
        line = _unit(unit)
        assert f"chgrp kvm {ENTRY}/inblob" in line, (
            f"{unit}: inblob is root-owned when configfs creates it, so the "
            f"unprivileged service cannot write it without this")
        assert f"chmod 0660 {ENTRY}/inblob" in line, (
            f"{unit}: inblob is mode 0200 (owner-write only) when created")

    @pytest.mark.parametrize("unit,_rel", CONFIGFS_PLATFORMS)
    def test_group_membership_is_declared(self, unit, _rel):
        """The chgrp is useless unless the service actually joins that group."""
        assert "SupplementaryGroups=kvm" in _unit(unit)

    @pytest.mark.parametrize("unit,_rel", CONFIGFS_PLATFORMS)
    def test_protect_kernel_tunables_stays_off(self, unit, _rel):
        """`yes` remounts /sys read-only and breaks the mkdir outright."""
        assert "ProtectKernelTunables=no" in _unit(unit)


class TestAppPrefersThePreCreatedEntry:
    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_fragment_compiles(self, _unit, rel):
        prelude = ("import os, threading as _threading, time as _time\n"
                   '_TSM_REPORT_DIR = "/sys/kernel/config/tsm/report"\n')
        ast.parse(prelude + _pool_fragment(rel))

    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_reports_no_entry_when_absent(self, _unit, rel):
        """On a host with no pool, it must return None -- not raise, not lie."""
        ns = {}
        prelude = ("import os, threading as _threading, time as _time\n"
                   '_TSM_REPORT_DIR = "/sys/kernel/config/tsm/report"\n')
        exec(compile(prelude + _pool_fragment(rel), rel, "exec"), ns)
        assert ns["_pooled_tsm_entry"]() is None

    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_detects_a_writable_entry(self, _unit, rel, tmp_path, monkeypatch):
        """Point the module at a fake report dir and prove it finds the entry."""
        fake_report = tmp_path / "report"
        entry = fake_report / "tee-crafter-0"
        entry.mkdir(parents=True)
        (entry / "inblob").write_bytes(b"")
        ns = {}
        prelude = ("import os, threading as _threading, time as _time\n"
                   f'_TSM_REPORT_DIR = {str(fake_report)!r}\n')
        exec(compile(prelude + _pool_fragment(rel), rel, "exec"), ns)
        assert ns["_pooled_tsm_entry"]() == str(entry)

    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_unwritable_entry_is_not_used(self, _unit, rel, tmp_path):
        """A present-but-unwritable inblob is the exact production failure.

        If it were treated as usable, the app would take the pooled path and
        fail on the write instead of falling back.
        """
        if os.geteuid() == 0:
            pytest.skip("root can write regardless of mode")
        fake_report = tmp_path / "report"
        entry = fake_report / "tee-crafter-0"
        entry.mkdir(parents=True)
        inblob = entry / "inblob"
        inblob.write_bytes(b"")
        inblob.chmod(0o400)          # readable, not writable — like mode 0200 to others
        ns = {}
        prelude = ("import os, threading as _threading, time as _time\n"
                   f'_TSM_REPORT_DIR = {str(fake_report)!r}\n')
        exec(compile(prelude + _pool_fragment(rel), rel, "exec"), ns)
        assert ns["_pooled_tsm_entry"]() is None

    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_getter_actually_uses_the_pooled_entry(self, _unit, rel, tmp_path):
        """Behavioural, not textual.

        Asserting that the lock and the helper *exist* passed happily on a
        mutant that replaced the call with ``entry = None`` -- the fix looked
        present while the pooled path was dead and every quote fell back to
        creating an entry the service cannot write.  So drive the function.
        """
        fake_report = tmp_path / "report"
        entry = fake_report / "tee-crafter-0"
        entry.mkdir(parents=True)
        (entry / "inblob").write_bytes(b"")

        ns = {}
        prelude = ("import os, threading as _threading, time as _time\n"
                   f'_TSM_REPORT_DIR = {str(fake_report)!r}\n')
        exec(compile(prelude + _pool_fragment(rel), rel, "exec"), ns)

        seen = []

        def _recorder(entry_path, report_data):
            seen.append(entry_path)
            return b"quote-bytes"

        ns["_read_quote_from_tsm_entry"] = _recorder
        out = ns["_get_tdx_quote_configfs"](b"\x00" * 64)

        assert out == b"quote-bytes"
        assert seen == [str(entry)], (
            f"{rel}: expected the pre-created entry to be used, got {seen}")
        # And it must not have created a private entry alongside it.
        assert sorted(p.name for p in fake_report.iterdir()) == ["tee-crafter-0"]

    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_getter_falls_back_when_no_pool_exists(self, _unit, rel, tmp_path):
        """The root/older-image path must still create and clean up its own."""
        fake_report = tmp_path / "report"
        fake_report.mkdir(parents=True)

        ns = {}
        prelude = ("import os, threading as _threading, time as _time\n"
                   f'_TSM_REPORT_DIR = {str(fake_report)!r}\n')
        exec(compile(prelude + _pool_fragment(rel), rel, "exec"), ns)

        seen = []

        def _recorder(entry_path, report_data):
            seen.append(entry_path)
            return b"fallback-quote"

        ns["_read_quote_from_tsm_entry"] = _recorder
        out = ns["_get_tdx_quote_configfs"](b"\x00" * 64)

        assert out == b"fallback-quote"
        assert len(seen) == 1 and "teecrafter_" in seen[0]
        # rmdir in the finally block must leave the directory clean.
        assert list(fake_report.iterdir()) == []

    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_pooled_path_is_serialised(self, _unit, rel):
        """inblob-write + outblob-read is one transaction on a shared entry."""
        frag = _pool_fragment(rel)
        getter = frag[frag.index("def _get_tdx_quote_configfs"):]
        assert "_TSM_ENTRY_LOCK" in getter

    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_root_fallback_survives(self, _unit, rel):
        """Running as root (or an older image) must still work."""
        frag = _pool_fragment(rel)
        getter = frag[frag.index("def _get_tdx_quote_configfs"):]
        assert "os.makedirs(entry_path)" in getter
        assert "os.rmdir(entry_path)" in getter

    @pytest.mark.parametrize("_unit,rel", CONFIGFS_PLATFORMS)
    def test_reader_honours_its_argument(self, _unit, rel):
        """Regression: the extracted reader briefly rebuilt its own entry name,
        clobbering the parameter and referencing an unimported uuid module."""
        frag = _pool_fragment(rel)
        reader = frag[frag.index("def _read_quote_from_tsm_entry"):
                      frag.index("def _get_tdx_quote_configfs")]
        assert "entry_name" not in reader
        assert "_uuid_tdx" not in reader
        assert reader.count("entry_path") >= 3
