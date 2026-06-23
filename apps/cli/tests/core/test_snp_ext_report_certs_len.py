"""`SNP_GET_EXT_REPORT` must ask for the certs_len the kernel reported.

The two-phase dance is: call with ``certs_len=0``, read the required size the
kernel writes back, then retry with exactly that size. The retry used to be
``max(required_len, 8 * 4096)`` — "allocate plenty" — which is wrong here,
because the VMM validates ``certs_len`` and rejects a value it did not ask for.

Measured on real AWS SEV-SNP hardware (m6a, 2026-08-20), the guest logged these
two ioctls back to back and then never produced a report:

    phase 1 (certs_len=0)     -> errno=5  EIO,    vmm_err=0x1 (INVALID_LEN),
                                 returned_certs_len=4096
    phase 2 (certs_len=32768) -> errno=22 EINVAL, fw_err=0xFF

RA-TLS then failed with ``SSLEOFError`` and the deploy surfaced only
"SNP client verification failed" — nothing pointing at the buffer size.

These are source-level assertions on the shipped templates rather than a
behavioural test: exercising the real ioctl needs an SEV-SNP guest, and the
defect was a single arithmetic decision that a text assertion pins exactly.
"""

import pathlib
import re

import pytest

TEMPLATES = pathlib.Path(__file__).resolve().parents[2] / "src" / "tee_crafter" / "templates"

SNP_APP_TEMPLATES = [
    "snp/aws/app.template.py",
    "snp/azure/app.template.py",
    "snp/gcp/app.template.py",
]


def _src(rel: str) -> str:
    p = TEMPLATES / rel
    assert p.is_file(), f"missing template: {p}"
    return p.read_text(encoding="utf-8")


class TestExtReportCertsLen:
    @pytest.mark.parametrize("rel", SNP_APP_TEMPLATES)
    def test_uses_the_kernel_reported_length(self, rel):
        src = _src(rel)
        assert "buf_size = required_len if required_len > 0 else 8 * 4096" in src, (
            f"{rel}: phase 2 no longer asks for the kernel-reported certs_len"
        )

    @pytest.mark.parametrize("rel", SNP_APP_TEMPLATES)
    def test_does_not_inflate_the_buffer_past_what_was_asked(self, rel):
        """The specific regression: a floor that overrides the kernel."""
        src = _src(rel)
        assert not re.search(r"buf_size\s*=\s*max\(\s*required_len", src), (
            f"{rel}: reintroduced `max(required_len, ...)`. The VMM rejects a "
            "certs_len it did not ask for — measured EINVAL on AWS SEV-SNP when "
            "the kernel asked for 4096 and the guest requested 32768."
        )

    @pytest.mark.parametrize("rel", SNP_APP_TEMPLATES)
    def test_phase_one_still_probes_with_zero(self, rel):
        """The fix must not remove the probe that produces required_len."""
        src = _src(rel)
        assert "_do_ext_report_ioctl(dev, report_data, 0)" in src, (
            f"{rel}: phase 1 probe (certs_len=0) is gone, so required_len can "
            "never be learned and the fallback guess is all that is left"
        )

    @pytest.mark.parametrize("rel", SNP_APP_TEMPLATES)
    def test_non_enospc_errors_still_capture_required_len(self, rel):
        """AWS answers the probe with EIO, not ENOSPC.

        The handler's documented expectation is ENOSPC; on AWS the kernel
        returned EIO with ``vmm_err=0x1``. The non-ENOSPC branch is therefore
        the one that actually runs, and it must still harvest
        ``returned_certs_len`` — otherwise required_len stays 0 and the guess
        is used again.
        """
        src = _src(rel)
        assert "if returned_len > 0:" in src and "required_len = returned_len" in src, (
            f"{rel}: the non-ENOSPC path no longer records the kernel's "
            "required certs_len"
        )
