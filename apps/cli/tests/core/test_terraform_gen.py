"""Tests for core/iac/terraform_gen.py: instance selection, Terraform generation."""

from tee_crafter.core.iac.terraform_gen import (
    GRAVITON_INSTANCES,
    NITRO_X86_INSTANCES,
    NITRO_INSTANCES,
    select_instance_type,
)


class TestGravitonInstances:
    def test_not_empty(self):
        assert len(GRAVITON_INSTANCES) > 0

    def test_has_required_fields(self):
        for inst in GRAVITON_INSTANCES:
            assert "type" in inst
            assert "vcpu" in inst
            assert "ram_gib" in inst

    def test_sorted_by_vcpu(self):
        families = {}
        for inst in GRAVITON_INSTANCES:
            family = inst["type"].split(".")[0]
            families.setdefault(family, []).append(inst["vcpu"])
        for family, vcpus in families.items():
            assert vcpus == sorted(vcpus), f"{family} instances not sorted by vCPU"


class TestNitroX86Instances:
    def test_not_empty(self):
        assert len(NITRO_X86_INSTANCES) > 0

    def test_alias_matches(self):
        assert NITRO_INSTANCES is NITRO_X86_INSTANCES

    def test_has_required_fields(self):
        for inst in NITRO_X86_INSTANCES:
            assert "type" in inst
            assert "vcpu" in inst
            assert "ram_gib" in inst

    def test_only_x86_families(self):
        """Every entry must be a known AMD x86_64 family (c6a / m6a / r6a)."""
        for inst in NITRO_X86_INSTANCES:
            family = inst["type"].split(".")[0]
            assert family in {"c6a", "m6a", "r6a"}, family

    def test_no_graviton_overlap(self):
        x86 = {i["type"] for i in NITRO_X86_INSTANCES}
        graviton = {i["type"] for i in GRAVITON_INSTANCES}
        assert x86.isdisjoint(graviton)


class TestSelectInstanceType:
    def test_default_picks_x86_64(self):
        """Without arch, the selector must return an x86_64 host so the default
        bake can enroll UEFI Secure Boot."""
        result = select_instance_type(2, 4096)
        assert result in [i["type"] for i in NITRO_X86_INSTANCES]
        family = result.split(".")[0]
        assert family in {"c6a", "m6a", "r6a"}

    def test_arch_x86_64_explicit(self):
        result = select_instance_type(2, 4096, arch="x86_64")
        assert result in [i["type"] for i in NITRO_X86_INSTANCES]

    def test_arch_arm64_returns_graviton(self):
        result = select_instance_type(2, 4096, arch="arm64")
        assert result in [i["type"] for i in GRAVITON_INSTANCES]

    def test_exact_fit(self):
        result = select_instance_type(2, 12288)
        inst = next(i for i in NITRO_X86_INSTANCES if i["type"] == result)
        assert inst["vcpu"] >= 4
        assert inst["ram_gib"] >= 14

    def test_large_requirements_fallback_x86(self):
        result = select_instance_type(100, 999999)
        assert result == "m6a.4xlarge"

    def test_large_requirements_fallback_arm64(self):
        result = select_instance_type(100, 999999, arch="arm64")
        assert result == "m6g.4xlarge"

    def test_zero_cpu(self):
        result = select_instance_type(0, 1024)
        assert result in [i["type"] for i in NITRO_X86_INSTANCES]

    def test_minimum_overhead(self):
        result = select_instance_type(2, 8192)
        inst = next(i for i in NITRO_X86_INSTANCES if i["type"] == result)
        assert inst["vcpu"] >= 4
        assert inst["ram_gib"] * 1024 >= 8192 + 2048
