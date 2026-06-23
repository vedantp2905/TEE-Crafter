"""Tests for `core/iac/`: Terraform staging, PCR injection, variable removal."""

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tee_crafter.core.iac import (
    stage_terraform,
    stage_sgx_terraform,
    stage_tdx_terraform,
    stage_snp_aws_terraform,
    stage_snp_azure_terraform,
    stage_snp_gcp_terraform,
    stage_tdx_gcp_terraform,
    stage_gpu_cc_aws_terraform,
    stage_gpu_cc_azure_terraform,
    stage_gpu_cc_gcp_terraform,
)
from tee_crafter.core.iac.platforms import run_terraform_destroy


class TestStageTerraform:
    def test_creates_main_tf(self, tmp_path):
        build_dir = str(tmp_path / "build")
        code = 'resource "aws_instance" "main" {}'
        path = stage_terraform(build_dir, code)
        assert os.path.isfile(path)
        assert path.endswith("main.tf")
        content = open(path).read()
        assert "aws_instance" in content

    def test_creates_directory(self, tmp_path):
        build_dir = str(tmp_path / "new" / "build")
        stage_terraform(build_dir, "resource {}")
        assert os.path.isdir(build_dir)

    def test_pcr_injection(self, tmp_path):
        build_dir = str(tmp_path)
        code = 'policy = var.pcr0_hash\npolicy1 = var.pcr1_hash\npolicy2 = var.pcr2_hash'
        hashes = {"PCR0": "abc", "PCR1": "def", "PCR2": "ghi"}
        path = stage_terraform(build_dir, code, pcr_hashes=hashes)
        content = open(path).read()
        assert '"abc"' in content
        assert '"def"' in content
        assert '"ghi"' in content
        assert "var.pcr0_hash" not in content

    def test_variable_removal(self, tmp_path):
        build_dir = str(tmp_path)
        code = (
            'variable "pcr0_hash" {\n  type = string\n  default = ""\n}\n'
            'resource "aws_instance" "main" {\n  ami = "test"\n}'
        )
        hashes = {"PCR0": "abc"}
        path = stage_terraform(build_dir, code, pcr_hashes=hashes)
        content = open(path).read()
        assert "aws_instance" in content

    def test_no_empty_file(self, tmp_path):
        build_dir = str(tmp_path)
        path = stage_terraform(build_dir, "")
        content = open(path).read().strip()
        assert content != ""

    def test_no_pcr_hashes(self, tmp_path):
        build_dir = str(tmp_path)
        code = 'resource "test" "a" {}'
        path = stage_terraform(build_dir, code)
        content = open(path).read()
        assert 'resource "test" "a" {}' in content

    def test_lockfile_is_staged_next_to_main_tf(self, tmp_path):
        """`terraform init` only honours a lockfile in its working directory."""
        src = tmp_path / "template" / ".terraform.lock.hcl"
        src.parent.mkdir(parents=True)
        src.write_text('provider "registry.terraform.io/hashicorp/aws" {}\n')
        build_dir = str(tmp_path / "build")
        stage_terraform(build_dir, "resource {}", lockfile_src=str(src))
        staged = os.path.join(build_dir, ".terraform.lock.hcl")
        assert os.path.isfile(staged)
        assert "hashicorp/aws" in open(staged).read()

    def test_missing_lockfile_is_not_an_error(self, tmp_path):
        """No lockfile yet just means un-pinned resolution, not a failed build."""
        build_dir = str(tmp_path / "build")
        path = stage_terraform(
            build_dir, "resource {}",
            lockfile_src=str(tmp_path / "nope" / ".terraform.lock.hcl"))
        assert os.path.isfile(path)
        assert not os.path.exists(
            os.path.join(build_dir, ".terraform.lock.hcl"))


class TestStageSgxTerraform:
    def test_creates_main_tf(self, tmp_path):
        code = 'variable "mrenclave" {\n  type        = string\n  default     = ""\n}'
        path = stage_sgx_terraform(str(tmp_path), code)
        assert os.path.isfile(path)

    def test_injects_mrenclave(self, tmp_path):
        code = 'variable "mrenclave" {\n  type        = string\n  default     = ""\n}'
        measurements = {"MRENCLAVE": "abc123"}
        path = stage_sgx_terraform(str(tmp_path), code, measurements)
        content = open(path).read()
        assert "abc123" in content

    def test_injects_mrsigner(self, tmp_path):
        code = 'variable "mrsigner" {\n  type        = string\n  default     = ""\n}'
        measurements = {"MRSIGNER": "def456"}
        path = stage_sgx_terraform(str(tmp_path), code, measurements)
        content = open(path).read()
        assert "def456" in content

    def test_empty_code_fallback(self, tmp_path):
        path = stage_sgx_terraform(str(tmp_path), "")
        content = open(path).read()
        assert "SGX Terraform" in content


class TestStageTdxTerraform:
    def test_creates_main_tf(self, tmp_path):
        code = 'variable "mrtd" {\n  type        = string\n  default     = ""\n}'
        path = stage_tdx_terraform(str(tmp_path), code)
        assert os.path.isfile(path)

    def test_injects_mrtd(self, tmp_path):
        code = 'variable "mrtd" {\n  type        = string\n  default     = ""\n}'
        measurements = {"MRTD": "tdx123"}
        path = stage_tdx_terraform(str(tmp_path), code, measurements)
        content = open(path).read()
        assert "tdx123" in content


class TestStageSnpAwsTerraform:
    def test_creates_main_tf(self, tmp_path):
        code = 'variable "measurement" {\n  type        = string\n  default     = ""\n}'
        path = stage_snp_aws_terraform(str(tmp_path), code)
        assert os.path.isfile(path)

    def test_injects_measurement(self, tmp_path):
        code = 'variable "measurement" {\n  type        = string\n  default     = ""\n}'
        measurements = {"measurement": "snp_aws_hash"}
        path = stage_snp_aws_terraform(str(tmp_path), code, measurements)
        content = open(path).read()
        assert "snp_aws_hash" in content


class TestStageSnpAzureTerraform:
    def test_creates_main_tf(self, tmp_path):
        code = 'variable "measurement" {\n  type        = string\n  default     = ""\n}'
        path = stage_snp_azure_terraform(str(tmp_path), code)
        assert os.path.isfile(path)

    def test_injects_measurement(self, tmp_path):
        code = 'variable "measurement" {\n  type        = string\n  default     = ""\n}'
        measurements = {"measurement": "snp_azure_hash"}
        path = stage_snp_azure_terraform(str(tmp_path), code, measurements)
        content = open(path).read()
        assert "snp_azure_hash" in content

    def test_empty_code_fallback(self, tmp_path):
        path = stage_snp_azure_terraform(str(tmp_path), "")
        content = open(path).read()
        assert "SNP Azure Terraform" in content


class TestRunTerraformDestroy:
    """``terraform destroy`` must run with ``-refresh=false`` so the
    pre-destroy state refresh does not call the locked-down Azure
    storage account's blob data plane (which 403s the deployer)."""

    def _run(self, build_dir):
        with patch("tee_crafter.core.iac.platforms.shutil.which",
                   return_value="/usr/bin/terraform"), \
             patch("tee_crafter.core.iac.platforms.subprocess.run") as run_mock:
            run_mock.return_value = MagicMock(stdout="", stderr="")
            ok, _msg = run_terraform_destroy(build_dir, prune_local_docker=False)
            return ok, run_mock

    def test_destroy_skips_refresh(self, tmp_path):
        ok, run_mock = self._run(str(tmp_path))
        assert ok is True
        destroy_call = next(
            c for c in run_mock.call_args_list
            if isinstance(c.args[0], list) and "destroy" in c.args[0]
        )
        cmd = destroy_call.args[0]
        assert "-refresh=false" in cmd, (
            "terraform destroy must be invoked with -refresh=false; "
            f"got: {cmd!r}"
        )
        assert "-auto-approve" in cmd
        assert "-input=false" in cmd
        assert "-no-color" in cmd

    def test_destroy_surfaces_error_message(self, tmp_path):
        with patch("tee_crafter.core.iac.platforms.shutil.which",
                   return_value="/usr/bin/terraform"), \
             patch("tee_crafter.core.iac.platforms.subprocess.run") as run_mock:
            def fake_run(cmd, *args, **kwargs):
                if "destroy" in cmd:
                    raise subprocess.CalledProcessError(
                        returncode=1, cmd=cmd, output="", stderr="boom"
                    )
                return MagicMock(stdout="", stderr="")
            run_mock.side_effect = fake_run
            ok, msg = run_terraform_destroy(str(tmp_path), prune_local_docker=False)
            assert ok is False
            assert "boom" in msg


class TestProviderLockStaging:
    """Every platform must stage its provider lockfile into the build dir.

    `terraform init` only reads `.terraform.lock.hcl` from the directory it runs
    in. A lockfile that ships beside the template but is never copied pins
    nothing: each apply re-resolves to the newest provider the `~> 5.0`
    constraint allows, so two builds of the same commit can embed different
    provider versions. That was the state before — the parameter existed and no
    production caller passed it.
    """

    # (staging function, kwargs, template subdir under templates/)
    PLATFORMS = [
        (stage_sgx_terraform, {}, "sgx"),
        (stage_tdx_terraform, {}, "tdx/azure"),
        (stage_snp_aws_terraform, {}, "snp/aws"),
        (stage_snp_azure_terraform, {}, "snp/azure"),
        (stage_snp_gcp_terraform, {}, "snp/gcp"),
        (stage_tdx_gcp_terraform, {}, "tdx/gcp"),
        (stage_gpu_cc_aws_terraform, {}, "gpu_cc/aws"),
        (stage_gpu_cc_azure_terraform, {}, "gpu_cc/azure"),
        (stage_gpu_cc_gcp_terraform, {}, "gpu_cc/gcp"),
    ]

    def test_every_platform_ships_a_lockfile(self):
        """Read the shipped files directly — not via the code under test."""
        import tee_crafter
        root = os.path.join(os.path.dirname(tee_crafter.__file__), "templates")
        for _, _, subdir in self.PLATFORMS + [(None, None, "nitro")]:
            lock = os.path.join(root, subdir, ".terraform.lock.hcl")
            assert os.path.isfile(lock), f"{subdir} ships no lockfile"
            body = open(lock, encoding="utf-8").read()
            # A lockfile that pins a version but carries no checksums
            # authenticates nothing.
            assert "h1:" in body or "zh:" in body, f"{subdir} lockfile has no hashes"

    @pytest.mark.parametrize("fn,kwargs,subdir", PLATFORMS,
                             ids=[p[2] for p in PLATFORMS])
    def test_platform_staging_copies_lockfile(self, tmp_path, fn, kwargs, subdir):
        build_dir = str(tmp_path / subdir.replace("/", "_"))
        fn(build_dir, 'resource "x" "y" {}', **kwargs)
        staged = os.path.join(build_dir, ".terraform.lock.hcl")
        assert os.path.isfile(staged), f"{subdir} did not stage its lockfile"
        assert "provider " in open(staged, encoding="utf-8").read()

    def test_nitro_staging_copies_lockfile_without_explicit_src(self, tmp_path):
        build_dir = str(tmp_path / "nitro")
        stage_terraform(build_dir, 'resource "x" "y" {}')
        assert os.path.isfile(os.path.join(build_dir, ".terraform.lock.hcl"))

    def test_explicit_src_wins_over_shipped(self, tmp_path):
        src = tmp_path / "custom" / ".terraform.lock.hcl"
        src.parent.mkdir(parents=True)
        src.write_text('provider "registry.terraform.io/hashicorp/custom" {}\n')
        build_dir = str(tmp_path / "build")
        stage_terraform(build_dir, "resource {}", lockfile_src=str(src))
        staged = open(os.path.join(build_dir, ".terraform.lock.hcl"),
                      encoding="utf-8").read()
        assert "hashicorp/custom" in staged

    def test_opt_out_stages_nothing(self, tmp_path):
        build_dir = str(tmp_path / "build")
        stage_terraform(build_dir, "resource {}", template_subdir="")
        assert not os.path.exists(
            os.path.join(build_dir, ".terraform.lock.hcl"))

    def test_unknown_subdir_warns_and_does_not_raise(self, tmp_path, caplog):
        """Silent un-pinning is indistinguishable from a pinned build."""
        from tee_crafter.core.iac.iac import stage_provider_lock
        build_dir = str(tmp_path / "build")
        os.makedirs(build_dir)
        with caplog.at_level("WARNING"):
            assert stage_provider_lock(build_dir, "no/such/platform") is None
        assert "unpinned" in caplog.text
