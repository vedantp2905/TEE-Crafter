"""Tests for cli/loaders.py: template and certificate loading."""


import pytest


class TestLoadSetupTemplates:
    def test_load_nitro_setup(self):
        from tee_crafter.cli.loaders import load_nitro_setup_template
        template = load_nitro_setup_template()
        assert isinstance(template, str)
        assert len(template) > 0

    def test_load_sgx_setup(self):
        from tee_crafter.cli.loaders import load_sgx_setup_template
        template = load_sgx_setup_template()
        assert isinstance(template, str)
        assert len(template) > 0

    def test_load_tdx_setup(self):
        from tee_crafter.cli.loaders import load_tdx_setup_template
        template = load_tdx_setup_template()
        assert isinstance(template, str)
        assert len(template) > 0

    def test_load_snp_aws_setup(self):
        from tee_crafter.cli.loaders import load_snp_aws_setup_template
        template = load_snp_aws_setup_template()
        assert isinstance(template, str)
        assert len(template) > 0

    def test_load_snp_azure_setup(self):
        from tee_crafter.cli.loaders import load_snp_azure_setup_template
        template = load_snp_azure_setup_template()
        assert isinstance(template, str)
        assert len(template) > 0


class TestContainerBatchSecurityOpts:
    """The container.batch.service unit must apply the batch AppArmor
    profile, SELinux MCS label, seccomp profile, and pre-flight checks
    (G-2)."""

    @pytest.mark.parametrize(
        "platform",
        ["snp-aws", "snp-azure", "snp-gcp", "tdx-azure", "tdx-gcp",
         "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp"],
    )
    def test_batch_unit_has_hardening(self, platform):
        from tee_crafter.resources import load_container_batch_unit
        unit = load_container_batch_unit(platform)
        assert "--security-opt seccomp=/etc/tee_crafter/seccomp-container.json" in unit
        assert "--security-opt apparmor=tee-crafter-batch-container" in unit
        assert "--security-opt label=type:container_runtime_t" in unit
        assert "--security-opt no-new-privileges:true" in unit
        assert "--cap-drop ALL" in unit
        assert "ExecStartPre=/usr/bin/test -f /etc/apparmor.d/tee-crafter-batch-container" in unit
        assert "ExecStartPre=/usr/bin/test -f /etc/tee_crafter/seccomp-container.json" in unit


class TestBatchAppArmorInjection:
    """Loader must substitute the batch AppArmor profile into setup scripts
    so every TEE platform's AMI ships both confinement profiles (G-2)."""

    @pytest.mark.parametrize(
        "loader_name",
        [
            "load_snp_aws_setup_template",
            "load_snp_azure_setup_template",
            "load_sgx_setup_template",
            "load_tdx_setup_template",
            "load_gpu_cc_aws_setup_template",
            "load_gpu_cc_gcp_setup_template",
            "load_gpu_cc_azure_setup_template",
        ],
    )
    def test_apparmor_batch_profile_inlined(self, loader_name):
        import tee_crafter.cli.loaders as loaders
        template = getattr(loaders, loader_name)()
        assert "__APPARMOR_BATCH_PROFILE__" not in template, (
            f"{loader_name} still contains unsubstituted "
            "__APPARMOR_BATCH_PROFILE__ placeholder"
        )
        assert "tee-crafter-batch-container" in template, (
            f"{loader_name} is missing the batch AppArmor profile install"
        )
        assert "profile tee-crafter-batch-container" in template, (
            f"{loader_name} is missing the profile body"
        )


class TestLoadRootCAs:
    def test_load_nitro_root_ca(self):
        from tee_crafter.cli.loaders import load_nitro_root_ca
        ca = load_nitro_root_ca()
        # A trust anchor must be a real certificate, never an empty string:
        # an empty anchor produces a client that accepts any attestation
        # document while still printing PASSED.
        assert "BEGIN CERTIFICATE" in ca

    def test_missing_trust_anchor_is_fatal(self):
        """A missing anchor must raise, not degrade to ``""``.

        The previous loaders returned an empty string when the PEM was absent,
        which is exactly what happens in an installed wheel built without
        ``certs/*.pem`` in package-data — invisible from a source checkout.
        """
        from tee_crafter.core.builder.platforms import (
            MissingTrustAnchor, _load_trust_anchor,
        )
        with pytest.raises(MissingTrustAnchor):
            _load_trust_anchor("no-such-anchor.pem")

    def test_intel_anchor_is_the_dcap_root_not_the_retired_epid_root(self):
        """DCAP PCK certs chain to ``CN=Intel SGX Root CA``.

        The retired ``CN=Intel SGX Attestation Report Signing CA`` (EPID/IAS)
        shipped here previously and could never validate a DCAP chain.
        """
        from cryptography import x509
        from tee_crafter.core.builder.platforms import _load_intel_root_ca
        cert = x509.load_pem_x509_certificate(_load_intel_root_ca().encode())
        assert "Intel SGX Root CA" in cert.subject.rfc4514_string()
        assert cert.subject == cert.issuer, "DCAP anchor must be self-signed"
