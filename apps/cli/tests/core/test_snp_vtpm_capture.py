"""Azure SNP bakes must be able to pin a measurement, so the reader chain runs.

Azure Hyper-V confidential VMs do not expose ``/dev/sev-guest`` — that device is
the KVM guest driver.  Both readers the SNP capture chain originally had needed
it (the ioctl directly, and ``snpguest`` under the hood), so every ``snp-azure``
and ``gpu-cc-azure`` bake finished "successfully" with the image left unpinned,
and ``deploy`` then refused sealed ``--secrets-env`` and BYOK for it.  Confirmed
on real hardware 2026-08-22: opening ``/dev/sev-guest`` on a live
``Standard_DC2as_v5`` CVM raised ``FileNotFoundError`` (ENOENT — absent, not
permission-denied).

Azure publishes the report pre-made in vTPM NV index ``0x01400001`` instead: a
32-byte HCL header (magic ``HCLA``) followed by the standard 1184-byte AMD SNP
report, MEASUREMENT still at offset 0x90.  ``SNP_VTPM_HCL_SNIPPET`` reads that.

Two things are pinned here, and the second is the one that matters:

* the chain reaches the vTPM reader **and stops** once it succeeds;
* the readers are each wrapped in a **subshell**.  ``SNP_SNPGUEST_SNIPPET``
  begins with ``set -e``, which — inlined into the caller — aborts the whole
  script the moment ``snpguest`` fails.  So appending the vTPM reader as a third
  branch without subshells produces a command that never reaches it, and the
  symptom is *identical* to the original bug: image left unpinned.  A test that
  only checked "the snippet is present in the string" would pass against that
  broken arrangement, which is why the tests below execute the shell.
"""
from __future__ import annotations

import shutil
import struct
import subprocess

import pytest

from tee_crafter.core.measurements import capture

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("python3") is None,
    reason="needs bash and python3 to execute the generated reader chain",
)

KNOWN_MEASUREMENT = "ab" * 48  # 48 bytes -> 96 hex chars


def _hcl_blob(
    *,
    magic: bytes = b"HCLA",
    version: int = 2,
    measurement_hex: str = KNOWN_MEASUREMENT,
    report_size: int = 1184,
) -> bytes:
    """Build a synthetic Azure HCL report the way the platform frames it."""
    header = magic + struct.pack("<I", 1) + b"\x00" * 24
    assert len(header) == 32
    report = bytearray(report_size)
    if report_size >= 4:
        struct.pack_into("<I", report, 0, version)
    meas = bytes.fromhex(measurement_hex)
    assert len(meas) == 48, "MEASUREMENT is a 48-byte SHA-384"
    if report_size >= 0x90 + 48:
        report[0x90:0x90 + 48] = meas
    return header + bytes(report)


def _stub_tpm2_nvread(tmp_path, blob: bytes | None, *, exit_code: int = 0):
    """Put a fake ``tpm2_nvread`` on PATH; ``blob=None`` means "fail"."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "tpm2_nvread"
    if blob is None:
        stub.write_text(
            "#!/bin/sh\n"
            "echo 'ERROR: nv index not found' >&2\n"
            f"exit {exit_code or 1}\n"
        )
    else:
        data = tmp_path / "hcl.bin"
        data.write_bytes(blob)
        stub.write_text(f"#!/bin/sh\ncat {data}\n")
    stub.chmod(0o755)
    return bindir


def _run(cmd: str, extra_path=None):
    import os
    env = dict(os.environ)
    if extra_path is not None:
        env["PATH"] = f"{extra_path}:{env['PATH']}"
    return subprocess.run(
        ["bash", "-c", cmd], capture_output=True, text=True, timeout=120, env=env,
    )


class TestGeneratedShellIsValid:
    def test_snp_chain_is_syntactically_valid_bash(self, tmp_path):
        script = tmp_path / "cmd.sh"
        script.write_text(capture.snp_capture_command())
        res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr

    def test_sudo_variant_is_also_valid_bash(self, tmp_path):
        script = tmp_path / "cmd.sh"
        script.write_text(capture.snp_capture_command(sudo=True))
        res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr


class TestVtpmReaderIsReached:
    """The whole point: on Azure the first reader fails and the chain continues."""

    def test_vtpm_path_yields_the_measurement(self, tmp_path):
        bindir = _stub_tpm2_nvread(tmp_path, _hcl_blob())
        res = _run(capture.snp_capture_command(), extra_path=str(bindir))
        combined = res.stdout + res.stderr
        assert capture.parse_measurement_line(combined) == KNOWN_MEASUREMENT
        assert res.returncode == 0, combined

    def test_success_short_circuits_snpguest(self, tmp_path):
        """Once vTPM works, the CLI-scraping fallback must not run."""
        bindir = _stub_tpm2_nvread(tmp_path, _hcl_blob())
        marker = tmp_path / "snpguest-ran"
        sg = bindir / "snpguest"
        sg.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
        sg.chmod(0o755)
        res = _run(capture.snp_capture_command(), extra_path=str(bindir))
        assert res.returncode == 0
        assert not marker.exists(), "snpguest ran even though the vTPM read succeeded"

    def test_snpguest_is_still_reachable_when_vtpm_fails(self, tmp_path):
        """The third reader must not be stranded behind the second."""
        bindir = _stub_tpm2_nvread(tmp_path, None)
        marker = tmp_path / "snpguest-ran"
        sg = bindir / "snpguest"
        sg.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
        sg.chmod(0o755)
        res = _run(capture.snp_capture_command(), extra_path=str(bindir))
        assert marker.exists(), (
            "snpguest was never invoked; a set -e leak or a missing subshell has "
            "stranded the last reader in the chain")
        assert res.returncode != 0
        assert capture.parse_measurement_line(res.stdout + res.stderr) is None

    def test_all_readers_failing_is_a_nonzero_exit_and_no_measurement(self, tmp_path):
        res = _run(capture.snp_capture_command())
        assert res.returncode != 0
        assert capture.parse_measurement_line(res.stdout + res.stderr) is None


class TestSubshellIsolation:
    """``set -e`` inside SNP_SNPGUEST_SNIPPET must not escape into the chain."""

    def test_snpguest_snippet_still_sets_e(self):
        """Guard the premise: if this stops being true the subshell is moot,
        but so is the bug, and this test should be re-read rather than deleted."""
        assert "set -e" in capture.SNP_SNPGUEST_SNIPPET

    def test_a_command_after_the_chain_still_runs(self, tmp_path):
        """The chain must not abort its caller when every reader fails."""
        bindir = _stub_tpm2_nvread(tmp_path, None)
        marker = tmp_path / "after"
        # `exit $rc` ends the script, so a caller composing the chain with other
        # work has to run it in a subshell; what must not happen is the chain
        # killing that caller via a leaked `set -e`.
        cmd = f"( {capture.snp_capture_command()} )\ntouch {marker}\n"
        _run(cmd, extra_path=str(bindir))
        assert marker.exists()

    def test_each_reader_is_wrapped(self):
        cmd = capture.snp_capture_command()
        # Three readers, each opened as a subshell, plus the `exit $rc` tail.
        assert cmd.count("rc=$?") == 3, cmd
        assert cmd.rstrip().endswith("exit $rc")


class TestHclFraming:
    """Framing must match ``_get_snp_report_via_vtpm`` in the app template."""

    @pytest.mark.parametrize(
        "kwargs, expect",
        [
            ({"magic": b"XXXX"}, "bad HCL magic"),
            ({"version": 1}, "unexpected SNP report version"),
            ({"report_size": 200}, "HCL report too small"),
        ],
    )
    def test_malformed_reports_are_rejected(self, tmp_path, kwargs, expect):
        bindir = _stub_tpm2_nvread(tmp_path, _hcl_blob(**kwargs))
        res = _run(capture.snp_capture_command(), extra_path=str(bindir))
        combined = res.stdout + res.stderr
        assert expect in combined, combined
        assert capture.parse_measurement_line(combined) is None

    def test_nv_index_and_header_size_match_the_runtime_reader(self):
        snippet = capture.SNP_VTPM_HCL_SNIPPET
        assert "0x01400001" in snippet
        assert 'HCL_MAGIC = b"HCLA"' in snippet
        assert "HCL_HEADER_SIZE = 32" in snippet
        assert "SNP_REPORT_SIZE = 1184" in snippet
        assert "0x90" in snippet

    def test_measurement_offset_agrees_with_the_pure_parser(self):
        """The snippet's slice and ``parse_snp_measurement`` must not drift."""
        blob = _hcl_blob()
        report = blob[32:32 + 1184]
        assert capture.parse_snp_measurement(report) == KNOWN_MEASUREMENT


class TestAzurePlatformsAreCovered:
    @pytest.mark.parametrize("platform", ["snp-azure", "gpu-cc-azure"])
    def test_azure_snp_platforms_get_the_vtpm_reader(self, platform):
        cmd = capture.capture_command(platform, sudo=True)
        assert "0x01400001" in cmd, (
            f"{platform} runs on Azure Hyper-V, where /dev/sev-guest is absent; "
            "without the vTPM reader its bakes cannot pin a measurement")

    @pytest.mark.parametrize("platform", ["snp-aws", "snp-gcp"])
    def test_non_azure_snp_platforms_keep_the_device_reader_first(self, platform):
        cmd = capture.capture_command(platform)
        assert "/dev/sev-guest" in cmd
        assert cmd.index("/dev/sev-guest") < cmd.index("0x01400001"), (
            "AWS/GCP expose the guest driver; it must stay the first attempt")

    def test_tdx_platforms_do_not_get_the_snp_reader(self):
        """TDX must not get the SNP reader — but the NV index is *not* the tell.

        Azure serves both TDX and SNP evidence from the same vTPM index
        ``0x01400001``, so ``tdx-azure`` legitimately contains that string (see
        ``TDX_VTPM_HCL_SNIPPET``). What must not leak in is the SNP-specific
        framing: the 1184-byte report and the 0x90 MEASUREMENT offset. An
        earlier version of this test asserted on the NV index and would have
        started failing the moment the TDX vTPM reader was added, for no real
        reason.
        """
        cmd = capture.capture_command("tdx-azure", sudo=True)
        assert "configfs-tsm" in cmd
        assert "/dev/sev-guest" not in cmd
        assert "SNP_REPORT_SIZE = 1184" not in cmd
        assert "snpguest" not in cmd
