"""The GPU and AWS catalogue entries, checked against what the clouds publish.

The Azure confidential (DC/EC) families were measured per-family earlier; the
GPU and AWS families were still derived from a flat ratio with nothing behind
them.  The numbers asserted here were read from the live APIs on 2026-08-22 and
are pinned so a future edit has to disagree with a recorded answer rather than
with an assumption:

* ``aws ec2 describe-instance-types`` in ``us-east-2`` for all 33
  ``m6a``/``c6a``/``r6a`` types, and in ``us-east-2`` + ``us-east-1`` for the
  four P5/P6 types (both regions agreed exactly).
* ``gcloud compute machine-types describe`` in ``us-central1-a`` for the four
  ``a3-highgpu-*`` types.
* ``az vm list-skus --location westus`` for ``Standard_NCC40ads_H100_v5`` and
  every ``Standard_DC*_v3``.

Two things came out of doing it.  The AWS ratio model turned out to be exactly
right for all 33 types including ``metal`` — so it stays, now with evidence.
The SGX list did not: it named 4 of the 16 SKUs Azure actually sells, and the
regex that papered over the gap accepted tiers that do not exist while still
missing the ``ds`` variants that do.
"""
from __future__ import annotations

import pytest

from tee_crafter.core import catalog as c
from tee_crafter.core.catalog import GIB

# ---------------------------------------------------------------------------
# aws ec2 describe-instance-types --region us-east-2
#   --filters Name=instance-type,Values=m6a.*,c6a.*,r6a.*
#   --query 'InstanceTypes[].[InstanceType,VCpuInfo.DefaultVCpus,
#                             MemoryInfo.SizeInMiB]'
# All 33 published types.  vCPU and MiB verbatim from the API.
# ---------------------------------------------------------------------------
AWS_6A = [
    ("c6a.large", 2, 4096), ("c6a.xlarge", 4, 8192), ("c6a.2xlarge", 8, 16384),
    ("c6a.4xlarge", 16, 32768), ("c6a.8xlarge", 32, 65536),
    ("c6a.12xlarge", 48, 98304), ("c6a.16xlarge", 64, 131072),
    ("c6a.24xlarge", 96, 196608), ("c6a.32xlarge", 128, 262144),
    ("c6a.48xlarge", 192, 393216), ("c6a.metal", 192, 393216),
    ("m6a.large", 2, 8192), ("m6a.xlarge", 4, 16384), ("m6a.2xlarge", 8, 32768),
    ("m6a.4xlarge", 16, 65536), ("m6a.8xlarge", 32, 131072),
    ("m6a.12xlarge", 48, 196608), ("m6a.16xlarge", 64, 262144),
    ("m6a.24xlarge", 96, 393216), ("m6a.32xlarge", 128, 524288),
    ("m6a.48xlarge", 192, 786432), ("m6a.metal", 192, 786432),
    ("r6a.large", 2, 16384), ("r6a.xlarge", 4, 32768),
    ("r6a.2xlarge", 8, 65536), ("r6a.4xlarge", 16, 131072),
    ("r6a.8xlarge", 32, 262144), ("r6a.12xlarge", 48, 393216),
    ("r6a.16xlarge", 64, 524288), ("r6a.24xlarge", 96, 786432),
    ("r6a.32xlarge", 128, 1048576), ("r6a.48xlarge", 192, 1572864),
    ("r6a.metal", 192, 1572864),
]

#: ``(instance_type, vcpu, ram_mib, gpu_count, gpu_model)`` — us-east-2 and
#: us-east-1 returned identical values.
AWS_GPU = [
    ("p5.4xlarge", 16, 262144, 1, "h100"),
    ("p5.48xlarge", 192, 2097152, 8, "h100"),
    ("p5en.48xlarge", 192, 2097152, 8, "h200"),
    ("p6-b200.48xlarge", 192, 2097152, 8, "b200"),
]

#: ``gcloud compute machine-types describe --zone us-central1-a``; the
#: accelerator type reported is ``nvidia-h100-80gb`` for all four.
GCP_GPU = [
    ("a3-highgpu-1g", 26, 239616, 1, "h100"),
    ("a3-highgpu-2g", 52, 479232, 2, "h100"),
    ("a3-highgpu-4g", 104, 958464, 4, "h100"),
    ("a3-highgpu-8g", 208, 1916928, 8, "h100"),
]

#: Every ``Standard_DC*_v3`` SKU ``az vm list-skus --location westus`` returns:
#: eight tiers, each with an ``s`` and a ``ds`` variant, flat 8 GiB per vCPU.
SGX_TIERS = [1, 2, 4, 8, 16, 24, 32, 48]


class TestAwsAmdFamilies:
    """The ratio model, checked type by type against the API."""

    @pytest.mark.parametrize("name,vcpu,mib", AWS_6A)
    def test_vcpu_and_ram_match_the_api(self, name, vcpu, mib):
        """Checked on the spec parser, not through ``lookup``.

        ``lookup`` applies the platform gates on top, and those legitimately
        refuse some of these types — ``*.large`` is below the 4-vCPU Nitro
        Enclaves minimum and ``*.metal`` has no Nitro hypervisor beneath it to
        host a TEE.  What is being verified here is the vCPU/RAM model, which
        has to be right for every type AWS publishes whether or not a given
        platform will accept it.
        """
        spec = c._aws_amd_spec(name)
        assert spec is not None, f"{name} does not parse"
        assert spec.vcpu == vcpu
        assert spec.ram_mb == mib

    @pytest.mark.parametrize("name", ["c6a.large", "m6a.large", "r6a.large"])
    def test_two_vcpu_types_are_still_refused_for_nitro(self, name):
        assert c.lookup("nitro-aws", name) is None
        assert "4 vCPU minimum" in c.unsupported_reason("nitro-aws", name)

    @pytest.mark.parametrize("name", ["c6a.metal", "m6a.metal", "r6a.metal"])
    def test_bare_metal_is_still_refused_everywhere(self, name):
        for platform in ("nitro-aws", "snp-aws"):
            assert c.lookup(platform, name) is None
            assert "bare-metal" in c.unsupported_reason(platform, name)

    def test_all_thirty_three_are_covered(self):
        assert len(AWS_6A) == 33

    def test_the_letter_ratios_are_the_ones_observed(self):
        """m=4, c=2, r=8 GiB per vCPU — the API agrees on every size."""
        assert c._AWS_RAM_PER_VCPU == {"m": 4 * GIB, "c": 2 * GIB, "r": 8 * GIB}

    def test_metal_is_192_vcpu(self):
        """``metal`` is the one token whose name does not encode its size."""
        assert c._AWS_SIZE_VCPU["metal"] == 192


class TestGpuCatalogues:
    @pytest.mark.parametrize("name,vcpu,mib,count,model", AWS_GPU)
    def test_aws_gpu_specs(self, name, vcpu, mib, count, model):
        spec = c.lookup("gpu-cc-aws", name)
        assert spec is not None, f"{name} does not resolve"
        assert (spec.vcpu, spec.ram_mb) == (vcpu, mib)
        assert (spec.gpu_count, spec.gpu_model) == (count, model)

    @pytest.mark.parametrize("name,vcpu,mib,count,model", GCP_GPU)
    def test_gcp_gpu_specs(self, name, vcpu, mib, count, model):
        spec = c.lookup("gpu-cc-gcp", name)
        assert spec is not None, f"{name} does not resolve"
        assert (spec.vcpu, spec.ram_mb) == (vcpu, mib)
        assert (spec.gpu_count, spec.gpu_model) == (count, model)

    def test_azure_gpu_spec(self):
        """``az vm list-skus --size Standard_NCC40ads``: 40 vCPU, 320 GB, 1 GPU."""
        spec = c.lookup("gpu-cc-azure", "Standard_NCC40ads_H100_v5")
        assert spec is not None
        assert (spec.vcpu, spec.ram_mb) == (40, 320 * GIB)
        assert (spec.gpu_count, spec.gpu_model) == (1, "h100")

    def test_gcp_ram_per_vcpu_is_nine_gib(self):
        """9 GiB/vCPU — not one of the 2/4/8 ratios the other families use, so a
        ratio-derived guess would have been wrong for every A3 shape."""
        for name, vcpu, mib, _, _ in GCP_GPU:
            spec = c.lookup("gpu-cc-gcp", name)
            assert spec.ram_mb == mib
            assert spec.ram_mb / spec.vcpu == 9 * GIB


class TestSgxAzureSkus:
    @pytest.mark.parametrize("vcpu", SGX_TIERS)
    @pytest.mark.parametrize("suffix", ["s", "ds"])
    def test_every_published_sku_resolves(self, vcpu, suffix):
        name = f"Standard_DC{vcpu}{suffix}_v3"
        spec = c.lookup("sgx-azure", name)
        assert spec is not None, f"{name} is published by Azure but unknown here"
        assert spec.vcpu == vcpu
        assert spec.ram_mb == vcpu * 8 * GIB

    def test_all_sixteen_are_enumerated(self):
        names = {s.instance_type for s in c.enumerate_instances("sgx-azure")}
        assert len(names) == 16

    def test_the_local_disk_variants_are_included(self):
        """``templates/sgx/main.template.tf`` accepts DCdsv3; the catalog didn't."""
        names = {s.instance_type for s in c.enumerate_instances("sgx-azure")}
        assert "Standard_DC24ds_v3" in names

    @pytest.mark.parametrize("name", [
        "Standard_DC3s_v3",     # no 3-vCPU tier exists
        "Standard_DC64s_v3",    # DCsv3 stops at 48
        "Standard_DC100s_v3",
        "Standard_DC0s_v3",
    ])
    def test_unpublished_tiers_are_refused(self, name):
        """A generic ``DC(\\d+)s_v3`` fallback used to accept all of these and
        hand Terraform a size Azure rejects."""
        assert c.lookup("sgx-azure", name) is None

    def test_the_regex_fallback_is_gone(self):
        """Behaviourally covered above; this pins the mechanism too, so the
        pattern cannot come back in a slightly different spelling."""
        import inspect
        src = inspect.getsource(c.lookup)
        assert "re.match(r\"^Standard_DC" not in src
