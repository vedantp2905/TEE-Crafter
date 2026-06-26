"""An unconfirmed SIEM export must fail the deploy — but only where it bites.

Two genuinely different situations, and the old blanket warning conflated them:

* **Preventive-gate platform, fail-closed** — the eight CVM platforms run the
  exporter inside the VM and load ``siem.env.public`` via the systemd unit's
  ``EnvironmentFile=``, so ``TEE_CRAFTER_SIEM_ENABLED=1`` is set in the same
  namespace that reads ``siem.health``.  A dark channel means the workload
  answers ``{"error":"siem_blackout"}`` to every caller: deployed, not serving.
  The command must not exit 0.
* **Detective-only platform, or fail-open** — ``nitro-aws`` and ``sgx-azure``
  run the exporter host-side and pass no SIEM environment across the TEE
  boundary (the nitro ``Dockerfile`` does not ``COPY`` ``siem.env.public`` into
  the EIF; the Gramine manifest sets ``insecure__use_host_env = false``), so the
  gate is inert and the workload keeps serving.  What is lost is SOC
  visibility.  Loud warning, successful deploy.

Failing the deploy on a detective-only platform would be a false alarm that
teaches operators to ignore the check.  Passing it on a preventive platform
reports success for a workload that answers nothing.  Both directions are
asserted.
"""

import pytest

from tee_crafter.cli.deployment.common import siem_sidecar


class FakeConsole:
    def __init__(self):
        self.lines = []

    def print(self, *args, **_kw):
        self.lines.append(" ".join(str(a) for a in args))

    @property
    def text(self):
        return "\n".join(self.lines)


class FakeAudit:
    def record(self, *a, **kw):
        pass

    def record_check(self, *a, **kw):
        pass


def _build_dir(tmp_path, fail_open: bool):
    d = tmp_path / "build"
    d.mkdir(exist_ok=True)
    (d / "siem.env").write_text(
        "TEE_CRAFTER_SIEM=splunk-hec\n"
        "TEE_CRAFTER_SIEM_ENABLED=1\n"
        f"TEE_CRAFTER_SIEM_FAIL_OPEN={'1' if fail_open else '0'}\n",
        encoding="utf-8",
    )
    return str(d)


PREVENTIVE = sorted(siem_sidecar.PREVENTIVE_GATE_PLATFORMS)
DETECTIVE = sorted(siem_sidecar.DETECTIVE_ONLY_GATE_PLATFORMS)


class TestPlatformClassification:
    def test_only_sgx_azure_is_detective_only(self):
        """``nitro-aws`` left this set when export moved into the enclave.

        ``sgx-azure`` cannot follow it: the platform is batch-only, so there is
        no request path for a request gate to guard.  Its preventive control is
        ``batch._withhold_output_if_unaudited``.
        """
        assert DETECTIVE == ["sgx-azure"]

    def test_the_nine_request_serving_platforms_are_preventive(self):
        assert PREVENTIVE == [
            "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
            "nitro-aws",
            "snp-aws", "snp-azure", "snp-gcp",
            "tdx-azure", "tdx-gcp",
        ]

    def test_the_two_sets_are_disjoint_and_cover_all_ten(self):
        assert not (siem_sidecar.PREVENTIVE_GATE_PLATFORMS
                    & siem_sidecar.DETECTIVE_ONLY_GATE_PLATFORMS)
        assert len(PREVENTIVE) + len(DETECTIVE) == 10

    @pytest.mark.parametrize("platform", PREVENTIVE)
    def test_preventive(self, platform):
        assert siem_sidecar.gate_is_preventive(platform) is True

    @pytest.mark.parametrize("platform", DETECTIVE)
    def test_detective(self, platform):
        assert siem_sidecar.gate_is_preventive(platform) is False

    def test_unknown_platform_is_assumed_preventive(self):
        """Fail toward the false alarm, not toward the unaudited PHI workload."""
        assert siem_sidecar.gate_is_preventive("some-future-tee") is True


class TestFailOpenReader:
    @pytest.mark.parametrize("raw,expected", [
        ("0", False), ("1", True), ("true", True), ("yes", True),
        ("on", True), ("false", False), ("", False),
    ])
    def test_recognised_values(self, tmp_path, raw, expected):
        d = tmp_path / "b"
        d.mkdir()
        (d / "siem.env").write_text(
            f"TEE_CRAFTER_SIEM_FAIL_OPEN={raw}\n", encoding="utf-8")
        assert siem_sidecar.siem_fail_open(str(d)) is expected

    def test_a_typo_leaves_the_strict_posture_in_force(self, tmp_path):
        """Mirrors siem_health.is_fail_closed.

        The earlier form of that function tested the *falsy* set, so
        ``FAIL_OPEN=2`` silently disabled the gate. Same trap avoided here.
        """
        d = tmp_path / "b"
        d.mkdir()
        (d / "siem.env").write_text(
            "TEE_CRAFTER_SIEM_FAIL_OPEN=2\n", encoding="utf-8")
        assert siem_sidecar.siem_fail_open(str(d)) is False

    def test_missing_file_is_fail_closed(self, tmp_path):
        assert siem_sidecar.siem_fail_open(str(tmp_path / "nope")) is False


class TestEscalation:
    def _flag(self, tmp_path, platform, fail_open, batch=False):
        console, audit = FakeConsole(), FakeAudit()
        siem_sidecar._flag_unverified_export(
            console, audit, _build_dir(tmp_path, fail_open), platform, "fail",
            batch=batch)
        return console, audit

    def test_preventive_fail_closed_blocks_the_deploy(self, tmp_path):
        console, audit = self._flag(tmp_path, "snp-aws", fail_open=False)
        assert siem_sidecar.siem_export_blocked_deploy(audit) == "snp-aws"
        assert "will not serve traffic" in console.text

    def test_detective_only_does_not_block(self, tmp_path):
        """sgx-azure: no request path, so nothing to refuse at request time."""
        console, audit = self._flag(tmp_path, "sgx-azure", fail_open=False)
        assert siem_sidecar.siem_export_blocked_deploy(audit) == ""
        assert "host-side" in console.text
        assert "will not serve traffic" not in console.text

    def test_nitro_now_blocks_like_the_cvm_platforms(self, tmp_path):
        """The C8 change: in-enclave export makes the gate real on Nitro."""
        console, audit = self._flag(tmp_path, "nitro-aws", fail_open=False)
        assert siem_sidecar.siem_export_blocked_deploy(audit) == "nitro-aws"
        assert "will not serve traffic" in console.text

    def test_batch_mode_blocks_but_says_output_not_traffic(self, tmp_path):
        """A batch run serves no requests; promising a request gate is wrong."""
        console, audit = self._flag(
            tmp_path, "snp-aws", fail_open=False, batch=True)
        assert siem_sidecar.siem_export_blocked_deploy(audit) == "snp-aws"
        assert "will not hand over its output" in console.text
        assert "will not serve traffic" not in console.text

    def test_fail_open_does_not_block(self, tmp_path):
        console, audit = self._flag(tmp_path, "snp-aws", fail_open=True)
        assert siem_sidecar.siem_export_blocked_deploy(audit) == ""
        assert "fail_open is set" in console.text

    def test_a_clean_audit_object_reports_no_block(self):
        assert siem_sidecar.siem_export_blocked_deploy(FakeAudit()) == ""
        assert siem_sidecar.siem_export_blocked_deploy(None) == ""

    @pytest.mark.parametrize("platform", PREVENTIVE)
    def test_every_preventive_platform_blocks(self, tmp_path, platform):
        _console, audit = self._flag(tmp_path, platform, fail_open=False)
        assert siem_sidecar.siem_export_blocked_deploy(audit) == platform


class TestBothDeployCommandsCheckTheSeam:
    """The seam is only worth having if it is actually consulted.

    ``install_siem_sidecar`` still returns ``True``, and all six call sites
    discard it — that is why the verdict travels on the audit object instead.
    If a future edit drops these checks, the flag becomes write-only and the
    whole mechanism silently reverts to reporting success.
    """

    @pytest.mark.parametrize("module", [
        "tee_crafter.cli.commands.deploy.deploy_container",
        "tee_crafter.cli.commands.deploy.from_build",
    ])
    def test_calls_siem_export_blocked_deploy(self, module):
        import importlib
        import inspect
        src = inspect.getsource(importlib.import_module(module))
        assert "siem_export_blocked_deploy(audit)" in src
