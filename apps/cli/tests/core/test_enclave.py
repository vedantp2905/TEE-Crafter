"""Tests for `core/enclave/`: CID parsing, platform resolution."""

import json
import subprocess
from unittest.mock import MagicMock

import boto3

from tee_crafter.core import enclave
from tee_crafter.core.enclave import build as build_mod
# The package re-exports these from the submodule, so `_host_docker_platform`
# has to be patched where the function body resolves it: the submodule.
from tee_crafter.core.enclave import enclave as enclave_mod
from tee_crafter.core.enclave import _resolve_platform, parse_enclave_cid
from tee_crafter.cli.commands.deploy.flow_container import resolve_docker_platform


class TestParseEnclaveCid:
    def test_json_output(self):
        output = json.dumps({"EnclaveCID": 16, "EnclaveID": "i-1234"})
        assert parse_enclave_cid(output) == "16"

    def test_json_string_cid(self):
        output = json.dumps({"EnclaveCID": "42"})
        assert parse_enclave_cid(output) == "42"

    def test_text_output(self):
        output = 'Started enclave with EnclaveCID: 16, ...'
        assert parse_enclave_cid(output) == "16"

    def test_quoted_key(self):
        output = '"EnclaveCID": 99'
        assert parse_enclave_cid(output) == "99"

    def test_nested_json(self):
        output = 'some text { "EnclaveCID": 5 } more text'
        assert parse_enclave_cid(output) == "5"

    def test_empty_output(self):
        assert parse_enclave_cid("") == ""

    def test_none_like_empty(self):
        assert parse_enclave_cid("") == ""

    def test_no_cid_found(self):
        assert parse_enclave_cid("random text without any CID") == ""

    def test_non_numeric_cid(self):
        output = json.dumps({"EnclaveCID": "not-a-number"})
        result = parse_enclave_cid(output)
        assert result == "not-a-number"

    def test_multiline_json(self):
        output = "Building...\n" + json.dumps({"EnclaveCID": 10, "Measurements": {}}) + "\nDone."
        assert parse_enclave_cid(output) == "10"


class TestResolvePlatform:
    """Tests for the low-level Nitro-only ``_resolve_platform``."""

    def test_graviton_instance(self):
        assert _resolve_platform("m6g.xlarge") == "linux/arm64"

    def test_x86_instance(self):
        assert _resolve_platform("m6i.xlarge") == "linux/amd64"

    def test_c7g_graviton(self):
        assert _resolve_platform("c7g.2xlarge") == "linux/arm64"

    def test_r6i_x86(self):
        assert _resolve_platform("r6i.large") == "linux/amd64"

    def test_none_defaults_to_x86_64(self, monkeypatch):
        """Nitro default flipped to x86_64 (c6a) in 2026 so the default bake
        can enroll UEFI Secure Boot — AL2023 ``amazon-linux-sb-keys`` only
        ships pre-signed for x86_64.  Graviton is still selectable explicitly.
        """
        monkeypatch.delenv("TF_VAR_instance_type", raising=False)
        monkeypatch.delenv("TF_VAR_custom_ami_id", raising=False)
        assert _resolve_platform(None) == "linux/amd64"

    def test_empty_string(self, monkeypatch):
        monkeypatch.delenv("TF_VAR_instance_type", raising=False)
        monkeypatch.delenv("TF_VAR_custom_ami_id", raising=False)
        assert _resolve_platform("") == "linux/amd64"

    def test_r6gd_graviton(self):
        assert _resolve_platform("r6gd.2xlarge") == "linux/arm64"

    def test_env_fallback_graviton(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_instance_type", "c7g.xlarge")
        assert _resolve_platform(None) == "linux/arm64"

    def test_env_fallback_x86(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_instance_type", "c6a.xlarge")
        assert _resolve_platform(None) == "linux/amd64"

    def test_explicit_overrides_env(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_instance_type", "c7g.xlarge")
        assert _resolve_platform("m6i.xlarge") == "linux/amd64"

    def test_custom_ami_amd64(self, monkeypatch):
        monkeypatch.delenv("TF_VAR_instance_type", raising=False)
        monkeypatch.setenv("TF_VAR_custom_ami_id", "ami-deadbeef")
        fake = MagicMock()
        fake.describe_images.return_value = {"Images": [{"Architecture": "x86_64"}]}
        monkeypatch.setattr(boto3, "client", lambda name, region_name=None: fake if name == "ec2" else MagicMock())
        assert _resolve_platform(None) == "linux/amd64"

    def test_custom_ami_arm64(self, monkeypatch):
        monkeypatch.delenv("TF_VAR_instance_type", raising=False)
        monkeypatch.setenv("TF_VAR_custom_ami_id", "ami-c0ffee")
        fake = MagicMock()
        fake.describe_images.return_value = {"Images": [{"Architecture": "arm64"}]}
        monkeypatch.setattr(boto3, "client", lambda name, region_name=None: fake if name == "ec2" else MagicMock())
        assert _resolve_platform(None) == "linux/arm64"

    def test_instance_type_overrides_custom_ami_env(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_custom_ami_id", "ami-should_not_matter")
        fake = MagicMock()
        monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)
        assert _resolve_platform("m6i.large") == "linux/amd64"
        fake.describe_images.assert_not_called()


class TestResolveDockerPlatform:
    """Tests for the unified ``resolve_docker_platform`` entry point."""

    def test_nitro_graviton(self):
        assert resolve_docker_platform("nitro-aws", "m6g.xlarge") == "linux/arm64"

    def test_nitro_x86(self):
        assert resolve_docker_platform("nitro-aws", "m6i.xlarge") == "linux/amd64"

    def test_snp_always_amd64(self):
        assert resolve_docker_platform("snp-aws") == "linux/amd64"
        assert resolve_docker_platform("snp-azure") == "linux/amd64"
        assert resolve_docker_platform("snp-gcp") == "linux/amd64"

    def test_tdx_always_amd64(self):
        assert resolve_docker_platform("tdx-azure") == "linux/amd64"
        assert resolve_docker_platform("tdx-gcp") == "linux/amd64"

    def test_sgx_always_amd64(self):
        assert resolve_docker_platform("sgx-azure") == "linux/amd64"

    def test_gpu_cc_always_amd64(self):
        assert resolve_docker_platform("gpu-cc-gcp") == "linux/amd64"
        assert resolve_docker_platform("gpu-cc-azure") == "linux/amd64"
        assert resolve_docker_platform("gpu-cc-aws") == "linux/amd64"


class TestEmulatedEifBuildDiagnosis:
    """An amd64-on-arm64 EIF failure must name the emulator as the cause.

    This is a *post-hoc diagnosis*, not a pre-flight refusal, and the
    difference is load-bearing. Measured on one darwin/arm64 machine with
    Docker 29.6.1:

      * QEMU backend, target linux/amd64  -> linuxkit aborts with
        "runtime: lfstack.push invalid packing"; nitro-cli reports only E48.
      * Rosetta backend, same target      -> "Enclave Image successfully
        created" with a real PCR0.

    An earlier version refused every amd64-on-arm64 build up front, which would
    have blocked the Rosetta case that works. There is no reliable way to tell
    the backends apart from inside the CLI (the Docker setting is in the
    operator's ~/Library, and an amd64 guest exposes no /run/rosetta or binfmt
    marker), so the build is attempted and only its failure is annotated.
    """

    QEMU_FAILURE = (
        "Linuxkit reported an error while creating the bootstrap ramfs: "
        "\"runtime: lfstack.push invalid packing: node=0xffff6f1b6880 "
        "cnt=0x1\nfatal error: lfstack.push\n\" "
        "[ E48 ] EIF building error."
    )

    def test_diagnoses_the_qemu_failure(self, monkeypatch):
        monkeypatch.setattr(enclave_mod, "_host_docker_platform", lambda: "linux/arm64")
        msg = enclave.emulated_eif_build_diagnosis("linux/amd64", self.QEMU_FAILURE)
        assert msg
        # Must name Rosetta *as the backend to switch to*. A bare "Rosetta"
        # substring is not enough: the message also mentions installing
        # "Rosetta 2", so a weaker assertion passes even if the actual advice
        # is gutted (found by mutation).
        assert "Rosetta backend" in msg, "the working configuration must be named"
        assert "x86_64 Linux host" in msg
        assert "lfstack" in msg or "48 bits" in msg

    def test_silent_when_the_failure_is_something_else(self, monkeypatch):
        """Don't blame emulation for unrelated build errors."""
        monkeypatch.setattr(enclave_mod, "_host_docker_platform", lambda: "linux/arm64")
        assert enclave.emulated_eif_build_diagnosis(
            "linux/amd64", "docker: no space left on device") == ""

    def test_silent_for_native_arm64_target(self, monkeypatch):
        monkeypatch.setattr(enclave_mod, "_host_docker_platform", lambda: "linux/arm64")
        assert enclave.emulated_eif_build_diagnosis(
            "linux/arm64", self.QEMU_FAILURE) == ""

    def test_silent_on_amd64_hosts(self, monkeypatch):
        """Only the measured direction is diagnosed."""
        monkeypatch.setattr(enclave_mod, "_host_docker_platform", lambda: "linux/amd64")
        assert enclave.emulated_eif_build_diagnosis(
            "linux/amd64", self.QEMU_FAILURE) == ""

    def test_no_preflight_refusal_blocks_a_working_rosetta_build(self, monkeypatch, tmp_path):
        """build_enclave must actually attempt the build on an arm64 host.

        Regression guard for the over-broad refusal: if a pre-flight check is
        reintroduced, `docker` is never invoked and this fails.
        """
        monkeypatch.setattr(enclave_mod, "_host_docker_platform", lambda: "linux/arm64")
        monkeypatch.setattr(enclave, "check_docker_running", lambda: True)
        monkeypatch.setattr(enclave_mod, "check_docker_running", lambda: True)
        calls = []

        def _run(cmd, *a, **k):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 1, "", "boom")

        monkeypatch.setattr(build_mod.subprocess, "run", _run)
        ok, _, message = build_mod.build_enclave(str(tmp_path), platform="linux/amd64")
        assert ok is False
        assert calls, "build_enclave refused up front instead of attempting the build"
        assert any(c[:2] == ["docker", "build"] for c in calls), calls
        # An unrelated failure must not be blamed on emulation.
        assert "Rosetta" not in message

    def test_survives_the_console_markup_layer(self, monkeypatch):
        """E48 must still be readable after strip_rich_markup eats brackets."""
        monkeypatch.setattr(enclave_mod, "_host_docker_platform", lambda: "linux/arm64")
        msg = enclave.emulated_eif_build_diagnosis("linux/amd64", self.QEMU_FAILURE)
        from tee_crafter.cli.constants import strip_rich_markup
        rendered = strip_rich_markup(msg)
        assert "Rosetta" in rendered and "48 bits" in rendered


class TestGetEnclaveHashesAvoidsHostBindMount:
    """`get_enclave_hashes` must not bind-mount a caller-local path.

    `-v` source paths are resolved by the host Docker daemon, but the CLI runs
    inside its own re-exec container with only the socket passed through.
    Mounting /workspace/builds/<build>/ therefore mounted an *empty* directory
    that Docker had just created on the host, and nitro-cli reported
    "E35 EIF file parsing error" against a valid 168 MB EIF — reproduced on a
    real x86_64 host, where the stray empty directory was left behind at the
    exact timestamp of the error log.
    """

    def _fake_docker(self, calls, describe_stdout):
        def _run(cmd, *a, **k):
            calls.append(list(cmd))
            out = ""
            if cmd[:2] == ["docker", "start"]:
                out = describe_stdout
            return subprocess.CompletedProcess(cmd, 0, out, "")
        return _run

    def test_uses_docker_cp_not_a_bind_mount(self, monkeypatch, tmp_path):
        eif = tmp_path / "app.eif"
        eif.write_bytes(b"not-a-real-eif")
        measurements = json.dumps({"Measurements": {
            "PCR0": "a" * 96, "PCR1": "b" * 96, "PCR2": "c" * 96}})
        calls = []
        monkeypatch.setattr(enclave_mod, "pull_builder_image", lambda *a, **k: "builder:amd64")
        monkeypatch.setattr(enclave, "pull_builder_image", lambda *a, **k: "builder:amd64")
        monkeypatch.setattr(build_mod.subprocess, "run",
                            self._fake_docker(calls, measurements))

        ok, hashes, msg = build_mod.get_enclave_hashes(str(eif))

        assert ok is True, msg
        assert hashes["PCR0"] == "a" * 96
        flat = [" ".join(c) for c in calls]
        # The defect: any `-v <caller-local path>:...` argument.
        assert not any("-v" in c for c in calls), f"bind mount reintroduced: {flat}"
        assert any(c[:2] == ["docker", "cp"] for c in calls), flat
        # And the EIF must be the *source* of the cp, read from the caller's
        # own filesystem, not a path handed to the host daemon to resolve.
        cp = next(c for c in calls if c[:2] == ["docker", "cp"])
        assert cp[2] == str(eif)
        assert cp[3].endswith(":/tmp/app.eif")

    def test_removes_the_container_even_when_describe_fails(self, monkeypatch, tmp_path):
        eif = tmp_path / "app.eif"
        eif.write_bytes(b"x")
        calls = []

        def _run(cmd, *a, **k):
            calls.append(list(cmd))
            if cmd[:2] == ["docker", "start"]:
                return subprocess.CompletedProcess(cmd, 1, "", "E35 parsing error")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(enclave_mod, "pull_builder_image", lambda *a, **k: "builder:amd64")
        monkeypatch.setattr(enclave, "pull_builder_image", lambda *a, **k: "builder:amd64")
        monkeypatch.setattr(build_mod.subprocess, "run", _run)

        ok, hashes, msg = build_mod.get_enclave_hashes(str(eif))
        assert ok is False
        assert "E35" in msg
        assert any(c[:3] == ["docker", "rm", "-f"] for c in calls), calls
