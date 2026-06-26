"""A batch run must ship the script its SIEM sidecar unit exec's.

``--batch`` uploads ``user_container.tar`` and the input directory and nothing
else. The persistent path gets ``siem_export.py`` onto the VM for free, because
the per-platform phase modules ship the whole build directory; batch skips those
modules entirely. So when ``_install_siem_for_batch`` was added it installed a
unit whose ``ExecStart`` is ``<app_dir>/siem_export.py`` and left the file
absent.

Measured on a live ``sgx-azure --batch --siem datadog`` run (2026-08-23)::

    /usr/bin/python3: can't open file
    '/opt/tee-crafter-sgx/siem_export.py': [Errno 2] No such file or directory
    tee-crafter-siem.service: Scheduled restart job, restart counter is at 12

The output gate behaved correctly and withheld the bundle — *"no siem.health on
the host — the SIEM sidecar never ticked"* — so nothing unaudited was handed
over. But ``sgx-azure`` is batch-only, which makes this the whole story for the
platform: SIEM had never once worked there.

Exactly the shape of the ``_upload_secret_bootstrap`` bug one unit over, which
is why the fix mirrors it, and why the destination path now comes from the same
``sidecar_app_dir`` the unit renderer uses instead of being spelled out twice.
"""
from __future__ import annotations

import os

import pytest

from tee_crafter.cli.commands.deploy import batch as batch_mod
from tee_crafter.cli.deployment.common.siem_sidecar import (
    _LAYOUT, render_sidecar_unit, sidecar_app_dir,
)


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, *a, **k):
        self.lines.append(" ".join(str(x) for x in a))

    @property
    def text(self):
        return "\n".join(self.lines)


@pytest.fixture
def build_dir(tmp_path):
    d = tmp_path / "build"
    (d / "siem").mkdir(parents=True)
    (d / "siem" / "siem.env").write_text(
        "TEE_CRAFTER_SIEM_ENABLED=1\nTEE_CRAFTER_SIEM=datadog\n"
        "TEE_CRAFTER_SIEM_API_KEY=secret\n",
        encoding="utf-8")
    (d / "siem_export.py").write_text("# the exporter\n", encoding="utf-8")
    return d


@pytest.fixture
def run(monkeypatch):
    """Drive ``_install_siem_for_batch`` with the remote side faked out."""
    def _go(build_dir, *, platform="sgx-azure", upload_ok=True,
            exporter_present=True):
        if not exporter_present:
            os.remove(os.path.join(str(build_dir), "siem_export.py"))
        cmds, uploads = [], []
        console = _Console()

        def _run_remote(cmd, timeout=None):
            cmds.append(cmd)
            return True, "", ""

        def _upload(local, remote, timeout=600):
            uploads.append((local, remote))
            return (True, "") if upload_ok else (False, "scp refused")

        monkeypatch.setattr(
            "tee_crafter.cli.deployment.common.siem_sidecar."
            "install_siem_sidecar", lambda **kw: True)

        batch_mod._install_siem_for_batch(
            _run_remote, _upload, console,
            build_dir=str(build_dir), tee_platform=platform, audit=None)
        return cmds, uploads, console.text
    return _go


class TestTheExporterReachesTheVm:
    def test_it_is_uploaded(self, build_dir, run):
        _cmds, uploads, _text = run(build_dir)
        assert uploads, "siem_export.py was never uploaded"
        assert uploads[0][0].endswith("siem_export.py")

    def test_it_lands_where_the_unit_looks_for_it(self, build_dir, run):
        """The assertion that would have caught the live failure: the install
        destination and the unit's ExecStart must agree."""
        cmds, _uploads, _text = run(build_dir, platform="sgx-azure")
        dest = f"{sidecar_app_dir('sgx-azure')}/siem_export.py"
        assert dest == "/opt/tee-crafter-sgx/siem_export.py"
        assert any(dest in c for c in cmds), cmds
        assert f"ExecStart=/usr/bin/python3 {dest}" in render_sidecar_unit(
            "sgx-azure")

    @pytest.mark.parametrize("platform", sorted(_LAYOUT))
    def test_destination_matches_the_unit_on_every_platform(
            self, build_dir, run, platform):
        cmds, _uploads, _text = run(build_dir, platform=platform)
        dest = f"{sidecar_app_dir(platform)}/siem_export.py"
        assert any(dest in c for c in cmds)
        assert dest in render_sidecar_unit(platform)

    def test_the_app_dir_is_created_first(self, build_dir, run):
        cmds, _uploads, _text = run(build_dir)
        mk = next(i for i, c in enumerate(cmds) if c.startswith("sudo mkdir"))
        mv = next(i for i, c in enumerate(cmds) if "mv " in c)
        assert mk < mv

    def test_it_is_installed_root_owned_and_world_readable(self, build_dir, run):
        cmds, _uploads, _text = run(build_dir)
        install = next(c for c in cmds if "mv " in c)
        assert "chown root:root" in install
        assert "chmod 0644" in install


class TestFailuresAreVisibleButNotFatal:
    """``_withhold_output_if_unaudited`` decides the run's fate on delivered
    evidence; this step only has to be loud."""

    def test_a_failed_upload_warns_and_returns(self, build_dir, run):
        _cmds, _uploads, text = run(build_dir, upload_ok=False)
        assert "could not stage siem_export.py" in text

    def test_a_missing_exporter_warns_and_skips_only_itself(self, build_dir, run):
        """The two artefacts are independent: a missing exporter must not
        suppress the env file, or one gap would mask the other on the next
        run."""
        _cmds, uploads, text = run(build_dir, exporter_present=False)
        assert not any(u[0].endswith("siem_export.py") for u in uploads)
        assert any(u[0].endswith("siem.env") for u in uploads)
        assert "will not export" in text

    def test_siem_off_stages_nothing(self, build_dir, run):
        (build_dir / "siem" / "siem.env").write_text(
            "TEE_CRAFTER_SIEM_ENABLED=0\n", encoding="utf-8")
        cmds, uploads, _text = run(build_dir)
        assert (cmds, uploads) == ([], [])


class TestTheEnvFileIsStagedToo:
    """Staging the exporter was necessary and not sufficient.

    With `siem_export.py` present but no `siem.env`, the unit starts, the
    exporter reads no `TEE_CRAFTER_SIEM_ENABLED`, logs *"SIEM disabled
    (TEE_CRAFTER_SIEM_ENABLED!=1); exiting"* and stops — so the run still ends
    in "no siem.health on the host". Observed on a live `sgx-azure` batch run
    on 2026-08-23, one layer past the previous failure.

    The install script relocates `<app_dir>/siem.env` onto tmpfs (SIEM-SEC-2)
    and the unit reads it with `EnvironmentFile=-`, where the `-` means
    optional — which is why its absence is silent rather than a unit failure.
    """

    def test_the_env_file_is_uploaded(self, build_dir, run):
        _cmds, uploads, _t = run(build_dir)
        assert any(u[0].endswith("siem.env") for u in uploads), uploads

    def test_it_lands_in_the_dir_the_install_script_relocates_from(
            self, build_dir, run):
        cmds, _u, _t = run(build_dir, platform="sgx-azure")
        assert any(f"{sidecar_app_dir('sgx-azure')}/siem.env" in c for c in cmds)

    def test_the_token_bearing_file_is_not_world_readable(self, build_dir, run):
        """It carries the HEC token / API key until tmpfs relocation."""
        cmds, _u, _t = run(build_dir)
        install = next(c for c in cmds if "siem.env" in c and "chmod" in c)
        assert "chmod 0600" in install
        assert "chmod 0644" not in install

    def test_the_exporter_stays_world_readable(self, build_dir, run):
        cmds, _u, _t = run(build_dir)
        install = next(c for c in cmds
                       if "siem_export.py" in c and "chmod" in c)
        assert "chmod 0644" in install

    def test_a_missing_env_file_warns_and_does_not_abort_the_exporter_upload(
            self, build_dir, run):
        import os as _os
        _os.remove(str(build_dir / "siem" / "siem.env"))
        # is_siem_enabled reads siem.env, so re-enable via the legacy location.
        (build_dir / "siem.env").write_text(
            "TEE_CRAFTER_SIEM_ENABLED=1\n", encoding="utf-8")
        _cmds, uploads, _t = run(build_dir)
        assert any(u[0].endswith("siem_export.py") for u in uploads)
