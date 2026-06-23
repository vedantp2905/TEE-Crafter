"""Tests for family validation, vCPU parsing, and capture-shape selection."""
from tee_crafter.core.measurements import shapes


def test_family_validation_follows_actual_sev_snp_capability():
    """Not "the whole family, any size" — only what AWS exposes SEV-SNP on.

    This test previously accepted ``r6a.48xlarge`` and ``m6a.metal``.
    ``ec2:DescribeInstanceTypes`` reports no ``amd-sev-snp`` feature on either:
    SEV-SNP stops at 128 GiB of guest memory, and bare metal has no Nitro
    hypervisor to host a CVM at all.
    """
    for it in ("m6a.large", "c6a.xlarge", "r6a.4xlarge", "c6a.16xlarge"):
        assert shapes.instance_family_ok("snp-aws", it) is True
    for it in ("r6a.48xlarge", "m6a.metal", "m6a.12xlarge", "m7a.large"):
        assert shapes.instance_family_ok("snp-aws", it) is False
    assert shapes.instance_family_ok("snp-aws", "t3.large") is False
    # Azure DCas/ECas v5 and v6 are both accepted.
    assert shapes.instance_family_ok("snp-azure", "Standard_DC2as_v5") is True
    assert shapes.instance_family_ok("snp-azure", "Standard_EC16as_v6") is True
    assert shapes.instance_family_ok("snp-azure", "Standard_DC2es_v6") is False
    # GCP N2D family.
    assert shapes.instance_family_ok("snp-gcp", "n2d-standard-32") is True
    assert shapes.instance_family_ok("snp-gcp", "n2-standard-2") is False


def test_vcpu_parsing_across_clouds():
    assert shapes.instance_vcpu("snp-aws", "m6a.large") == 2
    assert shapes.instance_vcpu("snp-aws", "m6a.xlarge") == 4
    assert shapes.instance_vcpu("snp-aws", "c6a.8xlarge") == 32
    assert shapes.instance_vcpu("snp-aws", "c6a.16xlarge") == 64
    # r6a.48xlarge used to answer 192 here. It is now None, because SEV-SNP is
    # not available on it at all — see test_family_validation_* above.
    assert shapes.instance_vcpu("snp-aws", "r6a.48xlarge") is None
    assert shapes.instance_vcpu("snp-azure", "Standard_DC16as_v5") == 16
    assert shapes.instance_vcpu("snp-azure", "Standard_EC8as_v6") == 8
    assert shapes.instance_vcpu("snp-gcp", "n2d-standard-64") == 64
    assert shapes.instance_vcpu("gpu-cc-azure", "Standard_NCC40ads_H100_v5") == 40


def test_snp_aws_captures_milan_only_ascending():
    """AWS SEV-SNP is Milan-only, so there is one generation to capture.

    This test used to require ``{"milan", "genoa"}``. Genoa was never
    capturable: AWS reports no ``amd-sev-snp`` feature on any 7a type, so the
    bake would have tried to boot instances that cannot run a CVM.
    """
    caps = shapes.capture_shapes("snp-aws")
    gens = [shapes.instance_gen("snp-aws", it) for it in caps]
    assert set(gens) == {"milan"}
    vcpus = [shapes.instance_vcpu("snp-aws", it) for it in caps]
    assert vcpus == sorted(vcpus)
    assert vcpus[:2] == [2, 4]
    # And it stops at the SEV-SNP memory ceiling rather than the vCPU table.
    assert max(vcpus) == 32          # m6a.8xlarge = 128 GiB
    assert all(it.startswith("m6a.") for it in caps)


def test_snp_capture_vcpus_env_override_still_respects_capability(monkeypatch):
    """The override selects *from* runnable shapes; it cannot invent them.

    Previously this asserted a 128-vCPU capture shape came back. There is no
    128-vCPU SEV-SNP instance on AWS, so honouring the override literally meant
    the bake booted something impossible.
    """
    monkeypatch.setenv("TEE_CRAFTER_SNP_CAPTURE_VCPUS", "2,4,128")
    assert shapes.snp_capture_vcpus() == [2, 4, 128]
    caps = shapes.capture_shapes("snp-aws")
    assert [shapes.instance_vcpu("snp-aws", it) for it in caps] == [2, 4]


def test_snp_azure_still_captures_both_generations():
    """Guards against 'fixing' AWS by flattening every cloud to one gen.

    Azure really does ship distinct Milan (v5) and Genoa (v6) SNP SKUs.
    """
    caps = shapes.capture_shapes("snp-azure")
    assert {shapes.instance_gen("snp-azure", it) for it in caps} == {"milan", "genoa"}


def test_snp_gcp_single_gen_capture():
    # GCP N2D shares one SKU name across gens; capture the default (Milan).
    caps = shapes.capture_shapes("snp-gcp")
    assert all(shapes.instance_gen("snp-gcp", it) == "milan" for it in caps)


def test_tdx_captures_once_for_all_supported():
    # TDX MRTD is vCPU-independent: capture only the default shape.
    caps = shapes.capture_shapes("tdx-gcp")
    assert caps == [shapes.default_instance_type("tdx-gcp")]


def test_gpu_cc_aws_self_pins_no_capture():
    # NitroTPM, not SEV-SNP — never auto-captured at bake.
    assert shapes.capture_shapes("gpu-cc-aws") == []
    assert "gpu-cc-aws" in shapes.SELF_PIN_PLATFORMS
