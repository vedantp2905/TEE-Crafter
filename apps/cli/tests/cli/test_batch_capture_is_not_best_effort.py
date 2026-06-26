"""The batch capture hook is the only source of output, so it must not be advisory.

``container.batch.service.template`` wired the hook as
``ExecStopPost=-/usr/local/bin/tee_crafter_capture_container.sh``.  The leading
dash tells systemd to discard the exit status, so a run that captured nothing
still reported success and the operator found out only when the
``output.tar.gz`` download 404'd.

Removing the dash alone would not have fixed it, which is the more interesting
half.  The script runs under ``set -uo pipefail`` — note the absent ``-e`` — and
its tail was::

    ( cd "$out" && tar czf "$bundle" . )
    sha256sum "$bundle" | awk '{print $1}' > "${bundle}.sha256"
    ...
    exit 0

so a failed ``tar`` fell straight through to ``exit 0``.  Both ends lied
independently: systemd ignored the status, and the status was 0 regardless.

These tests execute the real script against a stub ``docker`` rather than
grepping it, because the failure mode is entirely about exit codes and a
string match cannot see one.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[4]
SCRIPT = (REPO / "apps" / "cli" / "src" / "tee_crafter" / "scripts" / "common"
          / "tee_crafter_capture_container.sh")
UNIT = (REPO / "apps" / "cli" / "src" / "tee_crafter" / "resources" / "systemd"
        / "container.batch.service.template")

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="needs bash to execute the hook")


def _stub_bin(tmp_path: pathlib.Path, *, container_exists: bool) -> pathlib.Path:
    """A PATH containing a fake ``docker`` and a portable ``sha256sum``.

    ``sha256sum`` is coreutils-only; macOS ships ``shasum``.  Stubbing it keeps
    the test hermetic on either platform instead of skipping on developer
    machines, where this script is most likely to be edited.
    """
    binp = tmp_path / "bin"
    binp.mkdir()

    inspect_rc = 0 if container_exists else 1
    (binp / "docker").write_text(
        "#!/usr/bin/env bash\n"
        'case "$1" in\n'
        f"  inspect) exit {inspect_rc} ;;\n"
        '  logs)    echo "user stdout"; exit 0 ;;\n'
        '  diff)    echo "A /app/report.json"; exit 0 ;;\n'
        '  cp)      dest="${3}"; mkdir -p "$(dirname "$dest")";'
        '           echo "captured" > "$dest"; exit 0 ;;\n'
        "  rm)      exit 0 ;;\n"
        "  *)       exit 0 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    (binp / "docker").chmod(0o755)

    if shutil.which("sha256sum") is None:
        (binp / "sha256sum").write_text(
            '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n', encoding="utf-8")
        (binp / "sha256sum").chmod(0o755)
    return binp


def _run(tmp_path: pathlib.Path, *, container_exists: bool = True,
         bundle_dir: pathlib.Path | None = None,
         extra_env: dict | None = None) -> subprocess.CompletedProcess:
    """Run the hook with ``/var/lib/tee_crafter`` redirected into *tmp_path*.

    The bundle path is hard-coded in the script, so the script is copied with
    that one absolute prefix rewritten — the alternative is running the test as
    root against the real path.
    """
    bundle_dir = bundle_dir or (tmp_path / "varlib")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    body = SCRIPT.read_text(encoding="utf-8").replace(
        "/var/lib/tee_crafter/output.tar.gz", f"{bundle_dir}/output.tar.gz")
    local = tmp_path / "capture.sh"
    local.write_text(body, encoding="utf-8")
    local.chmod(0o755)

    out = tmp_path / "capture"
    out.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["PATH"] = f"{_stub_bin(tmp_path, container_exists=container_exists)}:{env['PATH']}"
    env.update(extra_env or {})
    return subprocess.run(
        ["bash", str(local), "tee-crafter-batch", str(out)],
        capture_output=True, text=True, env=env)


class TestTheHappyPathStillWorks:
    def test_it_exits_zero_and_writes_a_bundle(self, tmp_path):
        result = _run(tmp_path)
        bundle = tmp_path / "varlib" / "output.tar.gz"
        assert result.returncode == 0, result.stderr
        assert bundle.is_file() and bundle.stat().st_size > 0

    def test_it_writes_a_non_empty_checksum_sidecar(self, tmp_path):
        _run(tmp_path)
        sidecar = tmp_path / "varlib" / "output.tar.gz.sha256"
        assert sidecar.is_file()
        assert len(sidecar.read_text(encoding="utf-8").strip()) == 64


class TestAFailedBundleIsAFailedRun:
    """The regression: these all used to exit 0."""

    def test_an_unwritable_bundle_path_exits_two(self, tmp_path):
        """``tar`` cannot create the archive, so there is no output at all."""
        readonly = tmp_path / "readonly"
        readonly.mkdir()
        readonly.chmod(0o500)
        try:
            result = _run(tmp_path, bundle_dir=readonly)
        finally:
            readonly.chmod(0o700)
        assert result.returncode == 2, (
            f"expected exit 2, got {result.returncode}\n{result.stderr}")
        assert "FATAL" in result.stderr

    def test_the_failure_says_which_artefact_is_missing(self, tmp_path):
        readonly = tmp_path / "readonly2"
        readonly.mkdir()
        readonly.chmod(0o500)
        try:
            result = _run(tmp_path, bundle_dir=readonly)
        finally:
            readonly.chmod(0o700)
        assert "output.tar.gz" in result.stderr


class TestAMissingContainerIsStillReported:
    def test_it_exits_one(self, tmp_path):
        result = _run(tmp_path, container_exists=False)
        assert result.returncode == 1

    def test_it_still_bundles_the_reason(self, tmp_path):
        """Exit 1 is a real failure, but the operator gets evidence anyway."""
        _run(tmp_path, container_exists=False)
        bundle = tmp_path / "varlib" / "output.tar.gz"
        assert bundle.is_file() and bundle.stat().st_size > 0
        listing = subprocess.run(
            ["tar", "tzf", str(bundle)], capture_output=True, text=True)
        assert "_meta/error.txt" in listing.stdout


class TestTheUnitNoLongerDiscardsTheStatus:
    def test_execstoppost_has_no_leading_dash(self):
        line = next(
            ln for ln in UNIT.read_text(encoding="utf-8").splitlines()
            if ln.startswith("ExecStopPost=")
        )
        assert not line.startswith("ExecStopPost=-"), (
            "the leading dash makes systemd ignore a failed capture, which is "
            "the whole defect: the unit reports success with no output")
        assert "tee_crafter_capture_container.sh" in line

    def test_the_unit_explains_why(self):
        """So the dash does not get re-added by someone tidying up."""
        text = UNIT.read_text(encoding="utf-8")
        assert "deliberately NO leading `-`" in text

    def test_capture_still_runs_after_a_failed_user_image(self):
        """ExecStopPost fires regardless of ExecStart's fate; keep saying so."""
        assert "Always run capture, even on user-image failure" in UNIT.read_text(
            encoding="utf-8")
