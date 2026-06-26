"""The BYOK secret must reach the VM before the workload container is started.

Found on real GCP hardware 2026-08-21, on both `snp-gcp` and `tdx-gcp`.  Every
deploy with ``--byok gcp-kms --secrets-env`` logged::

    Starting SNP GCP user container...
    SNP GCP: container service status='inactive'
    systemd: Dependency failed for TEE-Crafter User Container (SNP-GCP).
    ...
    BYOK-SEC-1: relocating byok.env to tmpfs (snp-gcp)      <- afterwards
    ✓ BYOK secret env on tmpfs; disk copy shredded.

``tee-crafter-container.service`` ``Requires=`` the secrets oneshot, and that
oneshot reads the wrapped DEK from ``/run/tee-crafter-<platform>/byok.env`` —
a path that does not exist until ``install_byok_sidecar`` relocates it there.
So the container's one and only start attempt raced a secret that had not been
delivered: the fail-closed bootstrap refused (correctly), systemd reported a
dependency failure, and nothing retried.

The deploy still reported success, because everything it *did* check was
genuinely fine — attestation verified, SIEM events flowed, the sealed env was
staged.  The workload simply never ran.  That is the "the thing is running is
not the thing is working" shape again, one level down: the *platform* was
working and the *payload* was not.

This is ordering, so it cannot be caught by unit-testing either function in
isolation; the test reads the call order out of the module.
"""

import inspect
import re

import pytest

from tee_crafter.cli.deployment.common import gcp_phase_client

#: Marker strings, in the order they must appear in the source.
BYOK_INSTALL = "install_byok_sidecar("
SIEM_INSTALL = "install_siem_sidecar("
CONTAINER_START = 'Starting {platform} user container'


def _src():
    return inspect.getsource(gcp_phase_client)


def _pos(needle):
    src = _src()
    # Skip the `from ... import` line so we match the *call*, not the import.
    for m in re.finditer(re.escape(needle), src):
        line_start = src.rfind("\n", 0, m.start()) + 1
        line = src[line_start:src.find("\n", m.start())]
        if "import" in line:
            continue
        return m.start()
    raise AssertionError(f"{needle!r} not found as a call in gcp_phase_client")


class TestSidecarsPrecedeTheContainer:
    def test_byok_is_installed_before_the_container_starts(self):
        assert _pos(BYOK_INSTALL) < _src().index(CONTAINER_START), (
            "the container unit Requires= the secrets oneshot, which cannot "
            "succeed until the wrapped DEK is at /run/tee-crafter-*/byok.env")

    def test_siem_is_installed_before_the_container_starts(self):
        """Moved together; keep them together so neither drifts back."""
        assert _pos(SIEM_INSTALL) < _src().index(CONTAINER_START)

    def test_container_start_is_still_present(self):
        """Guard against 'fixing' the order by deleting the start entirely."""
        assert CONTAINER_START in _src()
        assert "tee-crafter-container.service" in _src()

    def test_only_one_byok_install_site(self):
        """Two call sites would make the order ambiguous again."""
        calls = [m for m in re.finditer(re.escape(BYOK_INSTALL), _src())
                 if "import" not in _src()[_src().rfind("\n", 0, m.start()) + 1:
                                           _src().find("\n", m.start())]]
        assert len(calls) == 1, f"expected one install_byok_sidecar call, got {len(calls)}"


class TestContainerUnitStillFailsClosed:
    """The ordering fix must not turn the dependency into a soft one.

    The whole point of ``Requires=`` on the secrets oneshot is that a workload
    never starts without its attested secret.  Fixing the race by loosening
    that would trade a visible failure for a silent one.
    """

    def test_container_unit_requires_the_secrets_oneshot(self):
        import pathlib
        unit = (pathlib.Path(gcp_phase_client.__file__).resolve()
                .parents[3] / "resources" / "systemd"
                / "container.service.template").read_text()
        assert "Requires=" in unit

    def test_secrets_unit_is_oneshot_and_remains(self):
        import pathlib
        unit = (pathlib.Path(gcp_phase_client.__file__).resolve()
                .parents[3] / "resources" / "systemd"
                / "secrets.service.template").read_text()
        assert "RemainAfterExit=yes" in unit
        assert "Type=oneshot" in unit


@pytest.mark.parametrize("needle", [BYOK_INSTALL, SIEM_INSTALL])
def test_installs_are_reachable_not_dead_code(needle):
    """Both calls must sit under the tee_platform_slug guard, not be orphaned."""
    src = _src()
    at = _pos(needle)
    preceding = src[:at]
    assert "if tee_platform_slug:" in preceding
