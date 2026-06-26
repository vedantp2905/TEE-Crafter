"""The BYOK relocation must actually restart the units that read the file.

On snp-azure on 2026-08-23 the secrets oneshot ran at 21:27:49 and failed with
"no wrapped DEK supplied"; the tmpfs byok.env it reads was not written until
21:28. Nothing then re-ran it, so a correct wrapped DEK sat on disk beside a
permanently failed release.

Three separate reasons the old restart step could not have helped:

* ``tee-crafter-secrets.service`` was not in its list at all.
* ``try-restart`` is a no-op on a *failed* oneshot -- it only acts on units that
  are currently running.
* the unit names it did list were wrong: ``tee-crafter-{tee_platform}.service``
  renders ``tee-crafter-snp-azure.service`` while the real unit is
  ``tee-crafter-snp.service``, and ``container.service`` should have been
  ``tee-crafter-container.service``.
"""
from __future__ import annotations

import subprocess
import tempfile
import os

import pytest

from tee_crafter.cli.deployment.common.byok_sidecar import _install_script

CVM = ["snp-aws", "snp-azure", "snp-gcp", "tdx-azure", "tdx-gcp",
       "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp"]


@pytest.mark.parametrize("platform", CVM)
class TestEveryCvmPlatform:

    def test_script_is_valid_shell(self, platform):
        s = _install_script(platform)
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write(s)
            path = fh.name
        try:
            r = subprocess.run(["bash", "-n", path], capture_output=True,
                               text=True)
            assert r.returncode == 0, r.stderr
        finally:
            os.unlink(path)

    def test_the_secrets_oneshot_is_restarted(self, platform):
        s = _install_script(platform)
        assert "tee-crafter-secrets.service" in s

    def test_it_uses_restart_not_try_restart_for_the_oneshot(self, platform):
        """`try-restart` skips a failed unit, which is exactly the state it is in."""
        s = _install_script(platform)
        assert "systemctl restart tee-crafter-secrets.service" in s
        assert "try-restart tee-crafter-secrets.service" not in s

    def test_it_resets_the_failed_state_first(self, platform):
        """A unit past its start-limit refuses to start again otherwise."""
        s = _install_script(platform)
        assert "reset-failed tee-crafter-secrets.service" in s

    def test_workload_units_are_discovered_not_hardcoded(self, platform):
        s = _install_script(platform)
        assert "tee-crafter-*.service" in s

    def test_no_stale_hardcoded_unit_names(self, platform):
        """Names that matched nothing, so the step silently did nothing."""
        s = _install_script(platform)
        body = s.split("# Then every other")[0] if "# Then every other" in s else s
        assert f"tee-crafter-{platform}.service" not in body
        for stale in ("for U in container.service", " container.batch.service"):
            assert stale not in s

    def test_the_secrets_unit_is_not_restarted_twice(self, platform):
        """The discovery loop skips it: it was already handled, in order."""
        s = _install_script(platform)
        assert '*secrets*) continue' in s

    def test_a_failure_says_where_to_look(self, platform):
        s = _install_script(platform)
        assert "journalctl -u tee-crafter-secrets" in s


class TestNonCvmPlatformsAreStillNoOps:

    @pytest.mark.parametrize("platform", ["nitro-aws", "sgx-azure"])
    def test_no_op(self, platform):
        s = _install_script(platform)
        assert "no-op" in s
        assert "systemctl" not in s
