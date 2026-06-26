"""``tdx-azure`` cannot attest unless the workload can read the TCG event log.

Microsoft's ``AttestationClient`` assembles the ``/attest/AzureGuest`` request
from the vTPM quote, the HCL hardware report and the TCG event log.  The kernel
exports that log as ``-r--r----- root root``, and the unit runs as
``tee_enclave`` -- so the client cannot read it.  It does not fail on that; it
sends the request without the log, and MAA answers::

    {"error":{"code":"InvalidParameter","message":"The requested item is not
     found","innererror":{"code":"MissingKey","message":"TcgLogs is empty in
     attestation request."}}}

which reads like a platform or api-version problem and is not one.  The app
crash-looped on it (``tee-crafter-tdx.service`` restart counter climbing, every
attempt dying in ``_create_ratls_context``).

Isolated on tee-crafter-tdx-vm-a5d16b8b, 2026-08-23, same binary, same VM:

    sudo /usr/local/bin/AttestationClient -o token              -> eyJhbGciOi...
    sudo -u tee_enclave /usr/local/bin/AttestationClient -o ... -> TcgLogs empty

and after one ``chgrp tee_enclave`` on the log, the second became the first.
With the fix installed in the unit the app obtained a 7937-byte MAA token and
the client verified ``tdxvm (azure-compliant-cvm)`` end to end.
"""
from __future__ import annotations

import os
import re

import pytest


_UNITS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "resources", "systemd")

TCG_LOG = "/sys/kernel/security/tpm0/binary_bios_measurements"


def _unit(name: str) -> str:
    with open(os.path.join(_UNITS, name), encoding="utf-8") as f:
        return f.read()


def _exec_start_pre(unit: str) -> str:
    for line in unit.splitlines():
        if line.startswith("ExecStartPre="):
            return line
    return ""


@pytest.fixture(scope="module")
def tdx_azure():
    return _unit("tdx-azure.service")


class TestTheLogIsMadeReadable:

    def test_the_unit_grants_the_group(self, tdx_azure):
        pre = _exec_start_pre(tdx_azure)
        assert TCG_LOG in pre, pre
        assert "chgrp tee_enclave" in pre

    def test_it_runs_privileged(self, tdx_azure):
        """Only a ``+``-prefixed line escapes ``User=tee_enclave``.

        Without the prefix the chgrp runs as the same unprivileged user that
        cannot read the file, so it fails and the unit starts anyway.
        """
        assert _exec_start_pre(tdx_azure).startswith("ExecStartPre=+")

    def test_it_does_not_abort_the_unit_when_the_log_is_absent(self, tdx_azure):
        """Not every TDX SKU exports one; a missing log must not block startup.

        The clause is guarded by ``[ -e ... ]`` and the line ends in ``true``.
        """
        pre = _exec_start_pre(tdx_azure)
        assert '[ -e "$L" ]' in pre or f"[ -e {TCG_LOG} ]" in pre, pre
        assert pre.rstrip().endswith("true'")

    def test_the_group_matches_the_units_own_group(self, tdx_azure):
        """chgrp to a group the service is not in would be a silent no-op."""
        assert "Group=tee_enclave" in tdx_azure


class TestItDoesNotReachForACapability:
    """``AmbientCapabilities=CAP_DAC_READ_SEARCH`` would also fix this.

    It is rejected deliberately: it would let the workload read *every* file on
    the box, where the group grant opens one append-only kernel log.  This unit
    already dropped ``CAP_DAC_OVERRIDE`` for the same reason, and re-adding a
    cousin of it to fix an unrelated bug would quietly undo that.
    """

    def test_the_capability_bounding_set_is_still_empty(self, tdx_azure):
        assert re.search(r"^CapabilityBoundingSet=\s*$", tdx_azure, re.M)

    def test_no_ambient_capabilities(self, tdx_azure):
        assert not re.search(r"^AmbientCapabilities=\S", tdx_azure, re.M)

    def test_no_dac_capability_is_granted_by_any_directive(self, tdx_azure):
        """Checks directives, not raw text.

        Both capability names appear in this unit's own comments, explaining why
        they are *not* used, so a substring search over the whole file fails on
        the documentation rather than on a real grant.
        """
        granted = [
            line for line in tdx_azure.splitlines()
            if not line.lstrip().startswith("#")
            and re.match(r"^(Ambient|)Capabilit", line)
            and "CAP_DAC" in line
        ]
        assert granted == [], granted

    def test_no_new_privileges_still_set(self, tdx_azure):
        assert "NoNewPrivileges=yes" in tdx_azure


class TestOnlyTheAzurePlatformNeedsIt:
    """``tdx-gcp`` reaches MAA-equivalent evidence through configfs-tsm.

    Adding the grant there would widen access for no reason -- ``tdx-gcp`` never
    invokes ``AttestationClient`` (only ``tdx/azure/*.template.py`` and
    ``templates/common/tee_crafter_maa.py`` reference it).
    """

    def test_tdx_gcp_does_not_grant_the_log(self):
        assert TCG_LOG not in _unit("tdx-gcp.service")

    @pytest.mark.parametrize("name", ["snp-azure.service", "gpu-cc-azure.service"])
    def test_other_azure_units_are_untouched(self, name):
        """Their apps read the vTPM directly (``tpm2_nvread 0x01400001``)."""
        assert TCG_LOG not in _unit(name)
