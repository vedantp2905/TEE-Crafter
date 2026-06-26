"""BYOK-SEC-1 must relocate ``byok.env`` before the workload is started.

``tee-crafter-secrets.service`` reads the wrapped DEK out of the tmpfs
``byok.env`` that the relocation step installs, and
``tee-crafter-container.service`` has ``Requires=`` on that oneshot.  Relocating
*after* starting the workload therefore loses the container, observed on
snp-azure 2026-08-23:

    22:02:45  secrets oneshot starts, "no wrapped DEK supplied", exits 1
    22:02:46  container: "Dependency failed", never starts
    22:02:57  relocation runs; oneshot re-runs and succeeds

The oneshot recovers (that part is covered by test_byok_sidecar_restart) but the
container does not, and no restart loop in the sidecar can fix it: systemd
leaves a dependency-blocked unit ``inactive`` with ``Result=success``, which is
byte-for-byte indistinguishable from a unit that was never meant to start.
Read off the live VM:

    tee-crafter-container.service  enabled=disabled active=inactive failed=inactive
    Result=success  ActiveState=inactive  SubState=dead

``try-restart`` skips it (not running), ``restart`` would also start units that
are deliberately down, and keying on ``failed`` matches nothing.  So ordering is
the fix, and this test pins the ordering.
"""
from __future__ import annotations

import os

import pytest


_SRC = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "cli", "deployment", "common",
    "azure_bastion_client.py")


@pytest.fixture(scope="module")
def src():
    with open(_SRC, encoding="utf-8") as f:
        return f.read()


def _call_index(src: str) -> int:
    return src.index("install_byok_sidecar(\n")


class TestOrdering:

    def test_the_relocation_is_called_exactly_once(self, src):
        """Two call sites would reintroduce the race on whichever runs first."""
        assert src.count("install_byok_sidecar(\n") == 1

    def test_it_runs_before_the_container_service_is_started(self, src):
        container_start = src.index('svc = "tee-crafter-container.service"')
        assert _call_index(src) < container_start

    def test_it_runs_before_the_app_service_is_started(self, src):
        app_start = src.index("sudo systemctl start {service_name}")
        assert _call_index(src) < app_start

    def test_it_runs_after_the_artifacts_are_uploaded(self, src):
        """It moves ``app/byok.env``, which only exists once the bundle is
        unpacked on the VM."""
        unpacked = src.index("tar xzf app_bundle.tar.gz")
        assert unpacked < _call_index(src)

    def test_the_siem_sidecar_is_still_installed_after_startup(self, src):
        """SIEM is not part of this change: it installs its own unit and gates
        nothing the workload needs to start."""
        assert src.index("install_siem_sidecar(") > src.index(
            'svc = "tee-crafter-container.service"')


class TestTheOldPositionIsGone:

    def test_no_byok_call_remains_in_the_post_start_block(self, src):
        after = src[src.index("install_siem_sidecar("):]
        assert "install_byok_sidecar(" not in after

    def test_a_note_explains_why_it_moved(self, src):
        """So the next person does not group it back with the SIEM sidecar."""
        after = src[src.index("install_siem_sidecar("):]
        assert "BYOK-SEC-1 is deliberately *not* here" in after
