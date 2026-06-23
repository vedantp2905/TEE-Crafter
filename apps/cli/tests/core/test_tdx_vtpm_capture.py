"""Azure TDX bakes must pin an MRTD, and must read it at the *Azure* offset.

``tdx-azure`` bakes were finishing with the image unpinned and this in the log::

    TEE_CRAFTER_MEASUREMENT_ERROR=OSError(6, 'No such device or address')

errno 6 is ENXIO.  On Azure ``/sys/kernel/config/tsm/report`` **exists**, so the
"configfs-tsm not available" guard in ``TDX_READER_SNIPPET`` never fires; the
directory is there but the TSM provider cannot service a quote request.  Seen on
a real ``Standard_DC2es_v6`` on 2026-08-22.  Azure exposes the evidence through
the vTPM instead, which is what ``TDX_VTPM_HCL_SNIPPET`` reads.

The framing is the dangerous part, and it is why these tests plant a decoy.
MRTD lives at a different offset in each format:

* DCAP quote — TD report body at 48, MRTD at body+136 → **184**
* Azure HCLA — TDREPORT at 32, MRTD at report+528    → **560**

Reading an HCLA blob at 184 does not fail.  It returns 48 bytes of a different
field, which is a well-formed 96-hex-character measurement that gets stored,
enforced, and never matches anything — a fail-closed deploy with no clue as to
the cause.  So ``test_azure_framing_is_not_read_at_the_dcap_offset`` fills
*both* offsets with different bytes and insists on the Azure one; a reader that
picked 184 would still produce a measurement and would still "pass" a test that
only checked that a measurement came out.

Both offsets are transcribed from ``_read_mrtd_from_quote`` in
``templates/tdx/azure/app.template.py`` — the reader the runtime verifies
against.  If they ever diverge, capture pins something verification rejects.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from tee_crafter.core.measurements import capture

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("python3") is None,
    reason="needs bash and python3 to execute the generated reader chain",
)

AZURE_MRTD_OFF = 32 + 528
DCAP_MRTD_OFF = 48 + 136
AZURE_MRTD = "cd" * 48
DCAP_DECOY = "ee" * 48
NV_SIZE = 2600


def _blob(*, magic: bytes = b"HCLA", size: int = NV_SIZE,
          azure_mrtd: str | None = AZURE_MRTD,
          dcap_mrtd: str | None = DCAP_DECOY) -> bytes:
    b = bytearray(size)
    b[0:len(magic)] = magic
    if azure_mrtd and size >= AZURE_MRTD_OFF + 48:
        b[AZURE_MRTD_OFF:AZURE_MRTD_OFF + 48] = bytes.fromhex(azure_mrtd)
    if dcap_mrtd and size >= DCAP_MRTD_OFF + 48:
        b[DCAP_MRTD_OFF:DCAP_MRTD_OFF + 48] = bytes.fromhex(dcap_mrtd)
    return bytes(b)


def _stub_tpm(tmp_path, blob: bytes | None, *, readpublic: bool = True):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    if readpublic:
        rp = bindir / "tpm2_nvreadpublic"
        rp.write_text(f"#!/bin/sh\necho '  size: {NV_SIZE}'\n")
        rp.chmod(0o755)
    nv = bindir / "tpm2_nvread"
    if blob is None:
        nv.write_text("#!/bin/sh\necho 'ERROR: nv index unavailable' >&2\nexit 1\n")
    else:
        data = tmp_path / "nv.bin"
        data.write_bytes(blob)
        nv.write_text(f"#!/bin/sh\ncat {data}\n")
    nv.chmod(0o755)
    return bindir


def _run(cmd: str, extra_path=None):
    import os
    env = dict(os.environ)
    if extra_path is not None:
        env["PATH"] = f"{extra_path}:{env['PATH']}"
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                          timeout=120, env=env)


class TestGeneratedShell:
    @pytest.mark.parametrize("sudo", [False, True])
    def test_is_valid_bash(self, tmp_path, sudo):
        script = tmp_path / "cmd.sh"
        script.write_text(capture.tdx_capture_command(sudo=sudo))
        res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr

    def test_both_readers_are_present_and_wrapped(self):
        cmd = capture.tdx_capture_command()
        assert "configfs-tsm" in cmd
        assert "0x01400001" in cmd
        assert cmd.count("rc=$?") == 2
        assert cmd.rstrip().endswith("exit $rc")

    def test_configfs_is_attempted_first(self):
        cmd = capture.tdx_capture_command()
        assert cmd.index("configfs-tsm") < cmd.index("0x01400001")


class TestAzureFraming:
    def test_azure_framing_is_not_read_at_the_dcap_offset(self, tmp_path):
        """The decoy test: both offsets are populated, only one is correct."""
        bindir = _stub_tpm(tmp_path, _blob())
        res = _run(capture.tdx_capture_command(), extra_path=str(bindir))
        got = capture.parse_measurement_line(res.stdout + res.stderr)
        assert got == AZURE_MRTD, (
            f"read {got} — that is the DCAP offset (184); an HCLA blob puts MRTD "
            f"at {AZURE_MRTD_OFF}")
        assert got != DCAP_DECOY
        assert res.returncode == 0

    def test_framing_is_reported(self, tmp_path):
        bindir = _stub_tpm(tmp_path, _blob())
        res = _run(capture.tdx_capture_command(), extra_path=str(bindir))
        assert "TEE_CRAFTER_MEASUREMENT_FRAMING=azure-hcla" in res.stderr

    def test_non_hcla_blob_falls_back_to_dcap_framing(self, tmp_path):
        """Without the HCLA magic the evidence is a plain quote."""
        bindir = _stub_tpm(tmp_path, _blob(magic=b"\x04\x00\x81\x00"))
        res = _run(capture.tdx_capture_command(), extra_path=str(bindir))
        got = capture.parse_measurement_line(res.stdout + res.stderr)
        assert got == DCAP_DECOY, "a non-HCLA blob must be read at offset 184"
        assert "TEE_CRAFTER_MEASUREMENT_FRAMING=dcap" in res.stderr

    def test_all_zero_mrtd_is_rejected(self, tmp_path):
        """An all-zero slice means the offset is wrong, not that MRTD is zero."""
        bindir = _stub_tpm(tmp_path, _blob(azure_mrtd=None))
        res = _run(capture.tdx_capture_command(), extra_path=str(bindir))
        combined = res.stdout + res.stderr
        assert capture.parse_measurement_line(combined) is None
        assert "all zero" in combined
        assert res.returncode != 0

    def test_short_blob_is_rejected(self, tmp_path):
        bindir = _stub_tpm(tmp_path, _blob(size=400))
        res = _run(capture.tdx_capture_command(), extra_path=str(bindir))
        combined = res.stdout + res.stderr
        assert capture.parse_measurement_line(combined) is None
        assert "too short for MRTD" in combined

    def test_offsets_match_the_runtime_reader(self):
        """Pin the two constants against the app template that verifies them."""
        import pathlib
        src = pathlib.Path(capture.__file__).resolve().parents[2] / (
            "templates/tdx/azure/app.template.py")
        text = src.read_text()
        assert "mrtd_offset = 32 + 528" in text, (
            "the runtime's Azure MRTD offset moved; capture would now pin a "
            "measurement verification rejects")
        assert "mrtd_offset = 48 + 136" in text
        assert "AZURE_MRTD_OFF = 32 + 528" in capture.TDX_VTPM_HCL_SNIPPET
        assert "DCAP_MRTD_OFF = 48 + 136" in capture.TDX_VTPM_HCL_SNIPPET


class TestFailureModes:
    def test_nvread_failure_yields_no_measurement(self, tmp_path):
        bindir = _stub_tpm(tmp_path, None)
        res = _run(capture.tdx_capture_command(), extra_path=str(bindir))
        combined = res.stdout + res.stderr
        assert capture.parse_measurement_line(combined) is None
        assert "every auth hierarchy" in combined
        assert res.returncode != 0

    def test_works_without_nvreadpublic(self, tmp_path):
        """Size discovery is best-effort; 2600 is the documented default."""
        bindir = _stub_tpm(tmp_path, _blob(), readpublic=False)
        res = _run(capture.tdx_capture_command(), extra_path=str(bindir))
        assert capture.parse_measurement_line(res.stdout + res.stderr) == AZURE_MRTD

    def test_no_readers_available_is_nonzero(self, tmp_path):
        res = _run(capture.tdx_capture_command())
        assert res.returncode != 0
        assert capture.parse_measurement_line(res.stdout + res.stderr) is None

    def test_the_enxio_case_reaches_the_vtpm_reader(self, tmp_path):
        """The exact bug: configfs present-but-broken must not end the chain.

        Simulated by making the configfs reader fail (it does, on any host
        without TDX) and asserting the vTPM reader still produced the value.
        """
        bindir = _stub_tpm(tmp_path, _blob())
        res = _run(capture.tdx_capture_command(), extra_path=str(bindir))
        assert capture.parse_measurement_line(res.stdout + res.stderr) == AZURE_MRTD


class TestPlatformDispatch:
    def test_tdx_azure_gets_the_vtpm_reader(self):
        assert "0x01400001" in capture.capture_command("tdx-azure", sudo=True)

    @pytest.mark.parametrize("platform", ["tdx-gcp", "gpu-cc-gcp"])
    def test_gcp_tdx_still_prefers_configfs(self, platform):
        cmd = capture.capture_command(platform)
        assert cmd.index("configfs-tsm") < cmd.index("0x01400001")

    def test_snp_platforms_do_not_get_the_tdx_reader(self):
        cmd = capture.capture_command("snp-aws")
        assert "configfs-tsm" not in cmd
        assert "AZURE_MRTD_OFF" not in cmd
