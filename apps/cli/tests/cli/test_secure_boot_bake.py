"""Tests for the `bake-ami --enable-secure-boot` wire-up.

Covers:

* The shared shell fragment (``scripts/common/secure_boot_enroll_aws.sh``)
  is loadable, non-empty, and contains the marker strings the in-VM
  enrollment relies on for both Ubuntu (snp-aws) and AL2023 (nitro-aws).
* :func:`tee_crafter.cli.loaders.inject_secure_boot_block` substitutes
  the ``__SECURE_BOOT_ENROLL__`` placeholder correctly in both modes
  (enabled → real enrollment block; disabled → no-op echo).
* :func:`tee_crafter.cli.commands.baking.common.helpers.load_setup_script`
  honours the new ``enable_secure_boot`` kwarg for ``snp-aws`` and
  ``nitro-aws`` without ``KeyError`` on Python ``str.format`` interaction.
* The Terraform templates for ``nitro-aws`` and ``snp-aws`` carry the
  new ``enable_secure_boot`` variable + the ``custom_for_sb_check``
  data source + the launch-time precondition + the
  ``secure_boot_mode`` output.
* The full SB-on / SB-off matrix across all platforms documented in
  ``docs/security.md`` matches the Terraform reality:
    - sgx/snp-azure/tdx-azure → ``secure_boot_enabled = true`` literal
    - snp-gcp/tdx-gcp → ``enable_secure_boot = true`` literal
    - gpu-cc-azure/gpu-cc-gcp → ``var.enable_secure_boot`` (default
      ``false``) — kept OFF for now.
    - nitro/snp-aws → ``var.enable_secure_boot`` + AMI-tag precondition
"""

import os

import click
import pytest


_TEMPLATE_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "templates",
)


class TestSecureBootEnrollFragment:
    def test_fragment_loads(self):
        from tee_crafter.cli.loaders import _load_secure_boot_enroll_block

        block = _load_secure_boot_enroll_block()
        assert isinstance(block, str)
        assert len(block) > 500, "SB enroll fragment is suspiciously short"

    def test_fragment_handles_both_distros(self):
        from tee_crafter.cli.loaders import _load_secure_boot_enroll_block

        block = _load_secure_boot_enroll_block()
        assert "amazon-linux-sb-keys" in block, "AL2023 path is missing"
        assert "/usr/lib/shim/shimx64.efi.signed" in block, "Ubuntu shim path is missing"
        assert "Microsoft Corporation UEFI CA 2011" in block, (
            "MS UEFI CA 2011 extraction is missing — Ubuntu SB enrollment would brick"
        )

    def test_fragment_aborts_without_verified_signature(self):
        from tee_crafter.cli.loaders import _load_secure_boot_enroll_block

        block = _load_secure_boot_enroll_block()
        assert "sbverify --cert signing-CA.crt" in block, (
            "Pre-enrollment verify-back against signing-CA.crt is missing"
        )

    def test_fragment_verifies_post_enrollment(self):
        from tee_crafter.cli.loaders import _load_secure_boot_enroll_block

        block = _load_secure_boot_enroll_block()
        assert "mokutil --sb-state" in block
        assert "SecureBoot enabled" in block
        assert "exit 1" in block, "Failure path must abort the bake"


class TestInjectSecureBootBlock:
    def test_disabled_replaces_with_noop(self):
        from tee_crafter.cli.loaders import inject_secure_boot_block

        rendered = inject_secure_boot_block(
            "echo before\n__SECURE_BOOT_ENROLL__\necho after\n",
            enable=False,
        )
        assert "__SECURE_BOOT_ENROLL__" not in rendered
        assert "Secure Boot enrollment skipped" in rendered
        assert "amazon-linux-sb-keys" not in rendered

    def test_enabled_injects_full_block(self):
        from tee_crafter.cli.loaders import inject_secure_boot_block

        rendered = inject_secure_boot_block(
            "echo before\n__SECURE_BOOT_ENROLL__\necho after\n",
            enable=True,
        )
        assert "__SECURE_BOOT_ENROLL__" not in rendered
        assert "amazon-linux-sb-keys" in rendered
        assert "Microsoft Corporation UEFI CA 2011" in rendered

    def test_no_placeholder_is_noop(self):
        from tee_crafter.cli.loaders import inject_secure_boot_block

        original = "echo hello world\n"
        assert inject_secure_boot_block(original, enable=True) == original
        assert inject_secure_boot_block(original, enable=False) == original


class TestLoadSetupScriptSecureBoot:
    @pytest.mark.parametrize("enable", [False, True])
    def test_snp_aws_handles_flag(self, enable):
        from tee_crafter.cli.commands.baking.common.helpers import load_setup_script

        script = load_setup_script("snp-aws", enable_secure_boot=enable)
        assert "__SECURE_BOOT_ENROLL__" not in script
        if enable:
            assert "amazon-linux-sb-keys" in script
            assert "Microsoft Corporation UEFI CA 2011" in script
        else:
            assert "Secure Boot enrollment skipped" in script

    @pytest.mark.parametrize("enable", [False, True])
    def test_nitro_aws_handles_flag(self, enable):
        from tee_crafter.cli.commands.baking.common.helpers import load_setup_script

        script = load_setup_script(
            "nitro-aws",
            allocator_mb=4096, cpu=2, aws_region="us-east-2",
            enable_secure_boot=enable,
        )
        assert "__SECURE_BOOT_ENROLL__" not in script
        if enable:
            assert "amazon-linux-sb-keys" in script
            assert "sbverify --cert signing-CA.crt" in script
        else:
            assert "Secure Boot enrollment skipped" in script

    def test_other_platforms_ignore_flag(self):
        """Azure/GCP setup scripts don't carry the SB placeholder; passing the
        kwarg must be a silent no-op."""
        from tee_crafter.cli.commands.baking.common.helpers import load_setup_script

        for platform in ("snp-azure", "snp-gcp", "tdx-azure", "tdx-gcp",
                         "sgx-azure", "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp"):
            script = load_setup_script(platform, enable_secure_boot=True)
            assert isinstance(script, str)
            assert "__SECURE_BOOT_ENROLL__" not in script, (
                f"{platform} script must not carry the AWS SB placeholder"
            )
            # GPU CC bake scripts have their own (different) Canonical-signed
            # module probe and must not pull in the AWS-specific enrollment
            # block; the AWS fragment's distinctive amazon-linux-sb-keys
            # phrase must not appear.
            assert "amazon-linux-sb-keys" not in script, (
                f"{platform} accidentally pulled in the AWS SB enrollment block"
            )


class TestBakeAmiInternalGuard:
    """bake_ami_internal must refuse --enable-secure-boot on non-AWS platforms.

    The CLI callback normalises this for the operator (silently no-ops the
    default `True` on non-AWS), but the programmatic entry point preserves
    a strict contract so library callers can't quietly ship an AMI/image
    whose attestation posture doesn't match its stated intent.
    """

    @pytest.mark.parametrize("platform", [
        "sgx-azure", "tdx-azure", "snp-azure", "snp-gcp", "tdx-gcp",
        "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
    ])
    def test_rejects_sb_on_non_aws(self, platform):
        from tee_crafter.cli.commands.bake_ami import bake_ami_internal

        with pytest.raises(click.ClickException) as exc:
            bake_ami_internal(
                tee_platform=platform,
                region="us-east-2",
                enable_secure_boot=True,
            )
        assert "only applies to" in str(exc.value.message).lower()

    def test_accepts_sb_on_nitro_and_snp_aws(self, monkeypatch):
        """The guard should allow --enable-secure-boot for nitro/snp-aws.

        We don't actually run the bake (which would need AWS); we just
        verify the guard doesn't reject before delegating to the real
        bake function.  Stub the bake function to capture the kwarg.
        """
        from tee_crafter.cli.commands import bake_ami as bake_ami_mod

        captured = {}

        def fake_bake_snp(*args, **kwargs):
            captured["snp"] = kwargs
            return "ami-fake-snp"

        def fake_bake_nitro(*args, **kwargs):
            captured["nitro"] = kwargs
            return "ami-fake-nitro"

        monkeypatch.setattr(bake_ami_mod, "bake_snp_aws_ami", fake_bake_snp)
        monkeypatch.setattr(bake_ami_mod, "bake_nitro_ami", fake_bake_nitro)

        for platform, key in (("snp-aws", "snp"), ("nitro-aws", "nitro")):
            bake_ami_mod.bake_ami_internal(
                tee_platform=platform,
                region="us-east-2",
                enable_secure_boot=True,
            )
            assert captured[key]["enable_secure_boot"] is True, (
                f"{platform} bake didn't receive enable_secure_boot=True"
            )


class TestBakeAmiCliDefaultsOn:
    """Since 2026 `--enable-secure-boot` defaults to True for nitro/snp-aws.

    Non-AWS platforms get a silent downgrade to False when the operator
    relies on the default, so `bake-ami --tee-platform sgx-azure` still
    works without explicit overrides.  Explicit `--enable-secure-boot` on
    those platforms still errors out to flag the unsupported request.
    """

    def _runner(self):
        from click.testing import CliRunner

        return CliRunner()

    def _invoke(self, runner, monkeypatch, extra_args):
        from tee_crafter.cli.commands import bake_ami as bake_ami_mod

        captured = {}

        def fake_bake_internal(**kwargs):
            captured.update(kwargs)
            return "ami-fake"

        monkeypatch.setattr(bake_ami_mod, "bake_ami_internal", fake_bake_internal)
        monkeypatch.setattr(
            "tee_crafter.cli.preflight.run_preflight",
            lambda *a, **kw: None,
        )
        # These cases assert on the Secure-Boot flag normalisation, not on the
        # operator's cloud credentials.  ``bake-ami`` probes the target cloud
        # before it spends money; stub it so the flag logic is reachable
        # offline.  (The probe deliberately runs *after* the offline guards —
        # ``test_explicit_enable_secure_boot_errors_on_non_aws`` relies on
        # that ordering and does not need this stub.)
        monkeypatch.setattr(
            "tee_crafter.cli.cloud_auth.validate_required_creds",
            lambda *a, **kw: None,
        )

        from tee_crafter.cli.main import cli

        return runner.invoke(cli, ["internal", "bake-ami", *extra_args]), captured

    def test_default_is_true_for_snp_aws(self, monkeypatch):
        runner = self._runner()
        result, captured = self._invoke(runner, monkeypatch,
                                        ["--tee-platform", "snp-aws"])
        assert result.exit_code == 0, result.output
        assert captured["enable_secure_boot"] is True, (
            "snp-aws bake-ami must default to enable_secure_boot=True"
        )

    def test_default_is_true_for_nitro_aws(self, monkeypatch):
        runner = self._runner()
        result, captured = self._invoke(runner, monkeypatch,
                                        ["--tee-platform", "nitro-aws"])
        assert result.exit_code == 0, result.output
        assert captured["enable_secure_boot"] is True

    def test_no_enable_secure_boot_opts_out(self, monkeypatch):
        runner = self._runner()
        result, captured = self._invoke(runner, monkeypatch, [
            "--tee-platform", "snp-aws", "--no-enable-secure-boot",
        ])
        assert result.exit_code == 0, result.output
        assert captured["enable_secure_boot"] is False

    @pytest.mark.parametrize("platform", [
        "sgx-azure", "tdx-azure", "snp-azure", "snp-gcp", "tdx-gcp",
        "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
    ])
    def test_default_downgrades_silently_on_non_aws(self, platform, monkeypatch):
        """Default `--enable-secure-boot=True` on non-AWS platforms must NOT
        raise — the CLI callback normalises it to False before invoking the
        internal entry point."""
        runner = self._runner()
        result, captured = self._invoke(runner, monkeypatch,
                                        ["--tee-platform", platform])
        assert result.exit_code == 0, result.output
        assert captured["enable_secure_boot"] is False, (
            f"{platform} should have SB silently downgraded to False"
        )

    @pytest.mark.parametrize("platform", [
        "sgx-azure", "tdx-azure", "snp-azure", "snp-gcp", "tdx-gcp",
        "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
    ])
    def test_explicit_enable_secure_boot_errors_on_non_aws(self, platform, monkeypatch):
        """An EXPLICIT --enable-secure-boot on a non-AWS platform must still
        error, even though the default value is the same — to flag the
        operator's unsupported request."""
        runner = self._runner()
        result, _ = self._invoke(runner, monkeypatch, [
            "--tee-platform", platform, "--enable-secure-boot",
        ])
        assert result.exit_code != 0, (
            f"{platform} should reject explicit --enable-secure-boot"
        )
        assert "only applies to" in (result.output or "").lower()


class TestTerraformTemplatesAws:
    """Verify the new SB Terraform machinery on the AWS templates."""

    @pytest.mark.parametrize("template_rel_path", [
        "nitro/main.template.tf",
        "snp/aws/main.template.tf",
    ])
    def test_has_enable_secure_boot_variable_default_true(self, template_rel_path):
        """Since 2026, the AWS templates default `enable_secure_boot = true` so
        Secure Boot matches the Azure/GCP non-GPU posture out of the box."""
        path = os.path.join(_TEMPLATE_ROOT, template_rel_path)
        with open(path) as f:
            content = f.read()
        assert 'variable "enable_secure_boot"' in content
        assert "default     = true" in content or "default = true" in content
        assert "default     = false" not in content.split('variable "enable_secure_boot"')[1].split("variable")[0], (
            f"{template_rel_path} still has default = false in the SB variable block"
        )

    @pytest.mark.parametrize("template_rel_path", [
        "nitro/main.template.tf",
        "snp/aws/main.template.tf",
    ])
    def test_has_custom_ami_tag_check(self, template_rel_path):
        path = os.path.join(_TEMPLATE_ROOT, template_rel_path)
        with open(path) as f:
            content = f.read()
        assert 'data "aws_ami" "custom_for_sb_check"' in content
        assert 'tags["tee-crafter-secure-boot"]' in content
        assert "enabled" in content

    @pytest.mark.parametrize("template_rel_path", [
        "nitro/main.template.tf",
        "snp/aws/main.template.tf",
    ])
    def test_has_precondition(self, template_rel_path):
        path = os.path.join(_TEMPLATE_ROOT, template_rel_path)
        with open(path) as f:
            content = f.read()
        assert "precondition" in content
        assert "tee-crafter-secure-boot=enabled" in content

    @pytest.mark.parametrize("template_rel_path", [
        "nitro/main.template.tf",
        "snp/aws/main.template.tf",
    ])
    def test_precondition_requires_custom_ami(self, template_rel_path):
        """The precondition must REJECT enable_secure_boot=true with no
        custom_ami_id — stock Canonical / AL2023 images are not SB-enrolled
        and would silently boot un-locked-down otherwise."""
        path = os.path.join(_TEMPLATE_ROOT, template_rel_path)
        with open(path) as f:
            content = f.read()
        # The expression must contain `var.custom_ami_id != ""` (AND, not OR)
        # so passing enable_secure_boot=true without a baked AMI fails fast.
        assert 'var.custom_ami_id != ""' in content, (
            f"{template_rel_path}: precondition must require a non-empty "
            f"custom_ami_id when enable_secure_boot is true"
        )

    @pytest.mark.parametrize("template_rel_path", [
        "nitro/main.template.tf",
        "snp/aws/main.template.tf",
    ])
    def test_has_secure_boot_mode_output(self, template_rel_path):
        path = os.path.join(_TEMPLATE_ROOT, template_rel_path)
        with open(path) as f:
            content = f.read()
        assert 'output "secure_boot_mode"' in content


class TestSecureBootMatrixAcrossAllPlatforms:
    """The README/security.md SB matrix must match the Terraform reality.

    Non-AWS, non-GPU platforms hard-enable SB (the literal `= true`).
    Both GPU CC cloud templates expose a variable defaulting to false.
    GPU-CC-AWS uses NitroTPM but is intentionally SB-off (no toggle).
    AWS Nitro / SNP-AWS expose the new opt-in variable defaulting to
    false (real enforcement comes from the AMI bake).
    """

    HARD_ON_AZURE = ("sgx", "snp/azure", "tdx/azure")
    HARD_ON_GCP = ("snp/gcp", "tdx/gcp")
    GPU_OFF_BY_DEFAULT = ("gpu_cc/azure", "gpu_cc/gcp")
    GPU_AWS_NO_TOGGLE = ("gpu_cc/aws",)
    AWS_OPT_IN = ("nitro", "snp/aws")

    @pytest.mark.parametrize("plat", HARD_ON_AZURE)
    def test_azure_hard_secure_boot(self, plat):
        path = os.path.join(_TEMPLATE_ROOT, plat, "main.template.tf")
        with open(path) as f:
            content = f.read()
        assert "secure_boot_enabled = true" in content, (
            f"{plat} should hard-code secure_boot_enabled = true"
        )
        assert "vtpm_enabled        = true" in content

    @pytest.mark.parametrize("plat", HARD_ON_GCP)
    def test_gcp_hard_secure_boot(self, plat):
        path = os.path.join(_TEMPLATE_ROOT, plat, "main.template.tf")
        with open(path) as f:
            content = f.read()
        assert "enable_secure_boot          = true" in content, (
            f"{plat} should hard-code enable_secure_boot = true"
        )

    @pytest.mark.parametrize("plat", GPU_OFF_BY_DEFAULT)
    def test_gpu_secure_boot_variable_default_false(self, plat):
        path = os.path.join(_TEMPLATE_ROOT, plat, "main.template.tf")
        with open(path) as f:
            content = f.read()
        assert 'variable "enable_secure_boot"' in content
        # Variable exists with default false → operator can opt in but
        # the platform stays SB-off by default (NVIDIA DKMS).
        assert "default = false" in content or "default     = false" in content

    @pytest.mark.parametrize("plat", AWS_OPT_IN)
    def test_aws_secure_boot_opt_in(self, plat):
        path = os.path.join(_TEMPLATE_ROOT, plat, "main.template.tf")
        with open(path) as f:
            content = f.read()
        assert 'variable "enable_secure_boot"' in content
        assert 'data "aws_ami" "custom_for_sb_check"' in content, (
            f"{plat} AWS template must check the AMI tag at launch time"
        )

    def test_gpu_cc_aws_intentionally_no_toggle(self):
        """gpu-cc-aws keeps SB off (informational output only — no toggle)."""
        path = os.path.join(_TEMPLATE_ROOT, "gpu_cc/aws/main.template.tf")
        with open(path) as f:
            content = f.read()
        assert 'output "secure_boot_mode"' in content
        assert 'off (gpu-cc-aws' in content


class TestSgxAzureBakeTrustedLaunch:
    """SGX bake must create a Trusted Launch VM with SB + vTPM (parity with deploy)."""

    def test_az_vm_create_includes_trusted_launch_flags(self):
        import tee_crafter.cli.commands.baking.sgx as sgx_mod

        src = open(sgx_mod.__file__, encoding="utf-8").read()
        assert '"--security-type", "TrustedLaunch"' in src, (
            "SGX bake must pass --security-type TrustedLaunch to az vm create"
        )
        assert '"--enable-secure-boot", "true"' in src
        assert '"--enable-vtpm", "true"' in src

    def test_sgx_bake_uses_gallery_capture_with_trusted_launch_feature(self):
        """Trusted Launch VMs cannot be captured to a managed image.

        Azure rejects ``az image create`` against a Trusted Launch VM with
        ``OperationNotAllowed: Creation of managed images are not supported
        for virtual machine with TrustedLaunch security type``.  The SGX
        bake must therefore route through ``capture_vhd_to_gallery`` (the
        same path SNP-Azure / TDX / GPU-CC-Azure already use), passing
        ``security_type_feature="TrustedLaunchSupported"`` on the SIG
        image definition.
        """
        import tee_crafter.cli.commands.baking.sgx as sgx_mod

        src = open(sgx_mod.__file__, encoding="utf-8").read()
        assert "capture_vhd_to_gallery(" in src, (
            "SGX bake must use the shared capture_vhd_to_gallery helper "
            "(managed-image capture is rejected for Trusted Launch VMs)."
        )
        assert 'security_type_feature="TrustedLaunchSupported"' in src, (
            "SGX bake must pass TrustedLaunchSupported as the SIG "
            "image-definition SecurityType feature."
        )
        # And the legacy managed-image path must be gone — keeping it would
        # silently regress to the OperationNotAllowed error.
        assert '"image", "create"' not in src, (
            "SGX bake should no longer call `az image create` (Trusted Launch "
            "VMs cannot be captured into managed images)."
        )

    def test_capture_vhd_to_gallery_uses_security_type_parameter(self):
        """The helper must respect the caller-supplied SecurityType feature."""
        import tee_crafter.cli.commands.baking.common.azure_gallery as gallery_mod

        src = open(gallery_mod.__file__, encoding="utf-8").read()
        assert 'security_type_feature="ConfidentialVmSupported"' in src, (
            "capture_vhd_to_gallery must default to ConfidentialVmSupported "
            "so existing TDX/SNP-Azure/GPU-CC callers are unchanged."
        )
        assert 'f"SecurityType={security_type_feature}"' in src, (
            "capture_vhd_to_gallery must format SecurityType from the "
            "caller-supplied feature string, not hard-code one value."
        )
