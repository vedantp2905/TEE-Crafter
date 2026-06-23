"""Tests for the instance catalog (specs, lookup, enumeration, defaults)."""
from tee_crafter.core import catalog


def test_lookup_aws_snp_is_milan_only_with_correct_ram():
    """SEV-SNP on AWS is Milan-only — 6a families, up to 128 GiB.

    This test used to assert that ``r7a.4xlarge`` resolved as Genoa. It does
    not any more, and that is the fix rather than the regression:
    ``ec2:DescribeInstanceTypes`` reports no ``amd-sev-snp`` processor feature
    on any 7a type in us-east-1, us-east-2 or us-west-2, and
    ``_INSTANCE_RULES["snp-aws"]`` had always refused Genoa at preflight — so
    the catalog was advertising shapes the very next step rejected. The Genoa
    RAM-ratio coverage this test used to provide moved to ``nitro-aws`` below,
    where a 7a instance is legitimate.
    """
    milan = catalog.lookup("snp-aws", "m6a.2xlarge")
    assert milan.vcpu == 8 and milan.cpu_gen == "milan"
    assert milan.ram_mb == 8 * 4096  # m = 4 GiB/vCPU
    r_milan = catalog.lookup("snp-aws", "r6a.4xlarge")
    assert r_milan.vcpu == 16 and r_milan.ram_mb == 16 * 8192  # r = 8 GiB/vCPU
    assert catalog.lookup("snp-aws", "t3.large") is None
    # Genoa is refused for SNP, with a reason.
    assert catalog.lookup("snp-aws", "r7a.4xlarge") is None
    assert "Genoa" in catalog.unsupported_reason("snp-aws", "r7a.4xlarge")


def test_lookup_nitro_still_distinguishes_milan_from_genoa():
    """Nitro needs no SEV-SNP, so 7a hosts stay valid there."""
    genoa = catalog.lookup("nitro-aws", "r7a.4xlarge")
    assert genoa.vcpu == 16 and genoa.cpu_gen == "genoa"
    assert genoa.ram_mb == 16 * 8192  # r = 8 GiB/vCPU
    assert catalog.lookup("nitro-aws", "c6a.xlarge").cpu_gen == "milan"


def test_azure_snp_vs_tdx_family_isolation():
    # DCas = SNP (AMD); DCes = TDX (Intel). They must not cross-resolve.
    assert catalog.lookup("snp-azure", "Standard_DC4as_v5").cpu_gen == "milan"
    assert catalog.lookup("snp-azure", "Standard_EC8as_v6").cpu_gen == "genoa"
    assert catalog.lookup("snp-azure", "Standard_DC4es_v6") is None
    assert catalog.lookup("tdx-azure", "Standard_DC4es_v6").cpu_gen == "sapphire-rapids"
    assert catalog.lookup("tdx-azure", "Standard_DC4as_v5") is None


def test_gpu_specs_carry_model_and_count():
    spec = catalog.lookup("gpu-cc-gcp", "a3-highgpu-4g")
    assert spec.gpu_model == "h100" and spec.gpu_count == 4
    assert "4×H100" in spec.summary()


def test_defaults_resolve():
    for plat in ("snp-aws", "snp-azure", "snp-gcp", "tdx-azure", "tdx-gcp",
                 "gpu-cc-gcp", "gpu-cc-azure", "gpu-cc-aws", "sgx-azure", "nitro-aws"):
        dit = catalog.default_instance_type(plat)
        assert dit, plat
        assert catalog.lookup(plat, dit) is not None, plat


def test_enumerate_nonempty_and_in_family():
    for plat in ("snp-aws", "snp-azure", "snp-gcp", "tdx-gcp"):
        specs = catalog.enumerate_instances(plat)
        assert specs
        for s in specs:
            assert catalog.is_in_family(plat, s.instance_type)
