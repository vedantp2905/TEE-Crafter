"""The CLI used to accept instance shapes the hardware cannot run.

Three separate ways a doomed deploy got past the gates:

**1. SEV-SNP shapes that have no SEV-SNP.** `catalog.lookup`'s `snp-aws` branch
accepted any `[mcr][67]a.<size>`, and `enumerate_instances` advertised the lot.
`ec2:DescribeInstanceTypes` disagrees: of the 69 such types published in
us-east-2, us-east-1 and us-west-2, exactly 16 carry `amd-sev-snp` in
`ProcessorInfo.SupportedFeatures`, and the three regions agree exactly.

    c6a.large … c6a.16xlarge     (≤ 64 vCPU / 128 GiB)
    m6a.large … m6a.8xlarge      (≤ 32 vCPU / 128 GiB)
    r6a.large … r6a.4xlarge      (≤ 16 vCPU / 128 GiB)

Two things say that is a real answer and not a hole in the API. The three
families stop at *different* vCPU counts but the *same* 128 GiB, which is a
coherent hardware ceiling rather than an arbitrary list. And
`_INSTANCE_RULES["snp-aws"]` has always restricted deploys to the 6a families,
so the CLI already refused Genoa at preflight while this catalog enumerated it
— `list-instances` advertised shapes the very next step rejected.

**2. Bare metal.** `_AWS_SIZE_VCPU` maps `metal` to 192, so `c6a.metal` and
`m6a.metal` resolved. `DescribeInstanceTypes` reports
`NitroEnclavesSupport: unsupported` for every `*.metal` / `*.metal-NNxl` type:
there is no Nitro hypervisor beneath bare metal to host the TEE.

**3. Hosts too small to carve an enclave out of.** Note the asymmetry, which is
why the refusal message distinguishes the two causes: AWS reports 2-vCPU
`c6a.large` as `unsupported`, but 2-vCPU `c6g.large` as **supported**. On
Graviton the limit is ours, not AWS's — `nitro_enclave_resources` reserves 2
vCPU for the parent, so the enclave gets nothing. "AWS cannot" and "we will
not" are different facts and an operator sizing a deployment needs to know
which one they hit.

Separately, `bake-ami --instance-type c7g.xlarge` (Secure Boot is **on** by
default) used to launch the instance and wait up to three minutes for the SSM
agent *before* refusing, on a contradiction knowable from the instance type
alone: AL2023's `amazon-linux-sb-keys` ships pre-signed PK/KEK/db for x86_64
only, so there is nothing to enrol on arm64.
"""

import click
import pytest

from tee_crafter.cli import preflight
from tee_crafter.cli.commands.deploy.compute import resolve_shape
from tee_crafter.core import catalog

GIB = 1024

#: Exactly the 16 types AWS reports amd-sev-snp on.
SNP_CAPABLE = [
    "c6a.large", "c6a.xlarge", "c6a.2xlarge", "c6a.4xlarge", "c6a.8xlarge",
    "c6a.12xlarge", "c6a.16xlarge",
    "m6a.large", "m6a.xlarge", "m6a.2xlarge", "m6a.4xlarge", "m6a.8xlarge",
    "r6a.large", "r6a.xlarge", "r6a.2xlarge", "r6a.4xlarge",
]

#: In-family by the old regex, but AWS exposes no SEV-SNP on them.
SNP_NOT_CAPABLE = [
    "m6a.12xlarge", "m6a.16xlarge", "m6a.24xlarge", "m6a.48xlarge",
    "c6a.24xlarge", "c6a.32xlarge", "c6a.48xlarge",
    "r6a.8xlarge", "r6a.12xlarge", "r6a.16xlarge",
    "m7a.large", "m7a.xlarge", "c7a.large", "c7a.2xlarge", "r7a.large",
]


@pytest.fixture(autouse=True)
def _no_tf_var_overrides(monkeypatch):
    """These gates read TF_VAR_*; a leaked value would silently skew results."""
    for var in ("TF_VAR_instance_type", "TF_VAR_vm_size", "TF_VAR_machine_type",
                "TF_VAR_enable_secure_boot",
                "TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE"):
        monkeypatch.delenv(var, raising=False)


class TestSevSnpCapability:
    @pytest.mark.parametrize("itype", SNP_CAPABLE)
    def test_capable_types_are_accepted(self, itype):
        """Positive control: the gate must not just reject everything."""
        assert catalog.unsupported_reason("snp-aws", itype) is None
        assert catalog.lookup("snp-aws", itype) is not None

    @pytest.mark.parametrize("itype", SNP_NOT_CAPABLE)
    def test_types_without_the_feature_are_refused(self, itype):
        assert catalog.lookup("snp-aws", itype) is None
        with pytest.raises(ValueError):
            resolve_shape("snp-aws", itype)

    @pytest.mark.parametrize("itype", SNP_NOT_CAPABLE)
    def test_the_refusal_explains_itself(self, itype):
        """A bare 'not supported' leaves an operator scaling up mystified."""
        reason = catalog.unsupported_reason("snp-aws", itype)
        assert reason, f"{itype} refused with no reason"
        assert itype in reason
        assert "SEV-SNP" in reason

    def test_genoa_refusal_names_the_generation_and_the_evidence(self):
        reason = catalog.unsupported_reason("snp-aws", "m7a.xlarge")
        assert "Genoa" in reason
        assert "amd-sev-snp" in reason

    def test_memory_ceiling_refusal_states_the_number(self):
        reason = catalog.unsupported_reason("snp-aws", "r6a.8xlarge")
        assert "256 GiB" in reason and "128 GiB" in reason

    def test_the_ceiling_is_where_the_api_puts_it(self):
        """c6a.16xl, m6a.8xl and r6a.4xl are all exactly 128 GiB — the cap."""
        for itype in ("c6a.16xlarge", "m6a.8xlarge", "r6a.4xlarge"):
            spec = catalog.lookup("snp-aws", itype)
            assert spec is not None and spec.ram_mb == 128 * GIB
        # ...and one size up in each family is over it.
        for itype in ("c6a.24xlarge", "m6a.12xlarge", "r6a.8xlarge"):
            assert catalog.lookup("snp-aws", itype) is None

    def test_resolve_shape_surfaces_the_reason_not_a_generic_message(self):
        with pytest.raises(ValueError) as exc:
            resolve_shape("snp-aws", "m6a.24xlarge")
        assert "128 GiB" in str(exc.value)

    def test_enumeration_matches_the_capable_set_exactly(self):
        """list-instances must not advertise what the next step rejects."""
        offered = {s.instance_type for s in catalog.enumerate_instances("snp-aws")}
        assert offered == set(SNP_CAPABLE)


class TestBareMetal:
    @pytest.mark.parametrize("platform,itype", [
        ("snp-aws", "m6a.metal"), ("snp-aws", "c6a.metal"),
        ("nitro-aws", "c6a.metal"), ("nitro-aws", "c8g.metal-48xl"),
        ("nitro-aws", "m8g.metal-24xl"), ("nitro-aws", "c6g.metal"),
    ])
    def test_metal_is_refused(self, platform, itype):
        assert catalog.lookup(platform, itype) is None
        reason = catalog.unsupported_reason(platform, itype)
        assert reason and "bare-metal" in reason

    def test_non_metal_of_the_same_family_still_works(self):
        """Positive control against a too-greedy 'metal' match."""
        assert catalog.lookup("nitro-aws", "c8g.48xlarge") is not None
        assert catalog.lookup("nitro-aws", "c6a.xlarge") is not None


class TestHostTooSmallForAnEnclave:
    def test_x86_two_vcpu_is_refused_citing_aws(self):
        reason = catalog.unsupported_reason("nitro-aws", "c6a.large")
        assert reason and "NitroEnclavesSupport" in reason

    def test_arm_two_vcpu_is_refused_citing_our_own_reserve(self):
        """AWS *does* support enclaves on c6g.large; the limit is ours."""
        reason = catalog.unsupported_reason("nitro-aws", "c6g.large")
        assert reason
        assert "TEE-Crafter reserves 2 vCPU" in reason
        assert "NitroEnclavesSupport" not in reason, (
            "blames AWS for a limit AWS does not impose on Graviton")

    def test_four_vcpu_is_the_boundary(self):
        assert catalog.unsupported_reason("nitro-aws", "c6g.xlarge") is None
        assert catalog.unsupported_reason("nitro-aws", "c6a.xlarge") is None


class TestPreflightCoversTheEnvVarRoute:
    """`resolve_shape` runs before the preflight and never sees TF_VAR_*.

    Terraform reads `TF_VAR_instance_type` straight from the environment, so a
    gate that only grades `--instance-type` has a blind spot precisely where an
    operator is most likely to be scripting.
    """

    def test_tf_var_instance_type_is_refused(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_instance_type", "m6a.24xlarge")
        with pytest.raises(click.ClickException) as exc:
            preflight._check_instance_capability("snp-aws", None)
        msg = str(exc.value)
        assert "128 GiB" in msg
        assert "TF_VAR_instance_type (environment)" in msg, (
            "operator cannot tell where the rejected value came from")

    def test_resolve_shape_does_not_see_that_route(self, monkeypatch):
        """Documents *why* the preflight check is not redundant."""
        monkeypatch.setenv("TF_VAR_instance_type", "m6a.24xlarge")
        shape = resolve_shape("snp-aws", None)   # falls back to the default
        assert shape.instance_type == catalog.default_instance_type("snp-aws")

    def test_a_runnable_env_override_passes(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_instance_type", "c6a.4xlarge")
        preflight._check_instance_capability("snp-aws", None)

    def test_the_flag_route_names_the_flag(self):
        with pytest.raises(click.ClickException) as exc:
            preflight._check_instance_capability("nitro-aws", "c6a.metal")
        assert "--instance-type" in str(exc.value)


class TestGravitonSecureBoot:
    """Secure Boot enrolment is x86_64-only, so Graviton cannot assert it."""

    @pytest.mark.parametrize("itype", ["c7g.xlarge", "m8g.2xlarge", "r6g.4xlarge"])
    def test_graviton_plus_secure_boot_is_refused(self, monkeypatch, itype):
        monkeypatch.setenv("TF_VAR_enable_secure_boot", "true")
        with pytest.raises(click.ClickException) as exc:
            preflight._check_graviton_secure_boot("nitro-aws", itype)
        msg = str(exc.value)
        assert "x86_64-only" in msg
        assert "TEE_CRAFTER_ALLOW_NO_SECURE_BOOT=1" in msg, (
            "refuses without telling the operator the way forward")

    @pytest.mark.parametrize("itype", ["c6a.xlarge", "m6a.4xlarge"])
    def test_x86_plus_secure_boot_is_fine(self, monkeypatch, itype):
        monkeypatch.setenv("TF_VAR_enable_secure_boot", "true")
        preflight._check_graviton_secure_boot("nitro-aws", itype)

    def test_graviton_without_asking_for_secure_boot_is_fine(self, monkeypatch):
        """The supported Graviton path must stay open."""
        monkeypatch.delenv("TF_VAR_enable_secure_boot", raising=False)
        preflight._check_graviton_secure_boot("nitro-aws", "c7g.xlarge")

    def test_graviton_with_secure_boot_explicitly_off_is_fine(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_enable_secure_boot", "false")
        preflight._check_graviton_secure_boot("nitro-aws", "c7g.xlarge")

    def test_other_platforms_are_untouched(self, monkeypatch):
        monkeypatch.setenv("TF_VAR_enable_secure_boot", "true")
        preflight._check_graviton_secure_boot("snp-aws", "m6a.large")


class TestBakeRefusesBeforeSpending:
    """The bake must refuse before `run_instances`, not after an SSM wait."""

    def test_secure_boot_on_graviton_raises(self):
        from tee_crafter.cli.commands.baking.nitro import bake_nitro_ami
        with pytest.raises(click.ClickException) as exc:
            bake_nitro_ami("us-east-2", "c7g.xlarge", None, 4096, 2,
                           enable_secure_boot=True)
        msg = str(exc.value)
        assert "x86_64" in msg
        assert "--no-enable-secure-boot" in msg

    def test_unrunnable_bake_host_raises(self):
        from tee_crafter.cli.commands.baking.nitro import bake_nitro_ami
        with pytest.raises(click.ClickException) as exc:
            bake_nitro_ami("us-east-2", "c6a.metal", None, 4096, 2,
                           enable_secure_boot=False)
        assert "bare-metal" in str(exc.value)

    def test_it_refuses_without_touching_aws(self, monkeypatch):
        """Any boto3 client here means an API call, i.e. spend or latency.

        `bake_nitro_ami` imports boto3 inside the function, so patching the
        module attribute is what a real call would go through.
        """
        import boto3
        from tee_crafter.cli.commands.baking.nitro import bake_nitro_ami

        def _explode(*a, **k):
            raise AssertionError("bake called AWS before refusing")

        monkeypatch.setattr(boto3, "client", _explode)
        with pytest.raises(click.ClickException):
            bake_nitro_ami("us-east-2", "c7g.xlarge", None, 4096, 2,
                           enable_secure_boot=True)


class TestUnrelatedPlatformsUnaffected:
    @pytest.mark.parametrize("platform,itype", [
        ("snp-azure", "Standard_DC2as_v5"),
        ("tdx-azure", "Standard_DC2es_v6"),
        ("snp-gcp", "n2d-standard-2"),
        ("tdx-gcp", "c3-standard-4"),
        ("sgx-azure", "Standard_DC2s_v3"),
        ("gpu-cc-aws", "p5.4xlarge"),
        ("gpu-cc-gcp", "a3-highgpu-1g"),
        ("gpu-cc-azure", "Standard_NCC40ads_H100_v5"),
    ])
    def test_defaults_still_resolve(self, platform, itype):
        assert catalog.unsupported_reason(platform, itype) is None
        assert catalog.lookup(platform, itype) is not None

    def test_every_platform_default_is_runnable(self):
        """A default that its own gate rejects would break the no-flag path."""
        for platform in catalog.DEFAULT_INSTANCE_TYPE:
            dit = catalog.default_instance_type(platform)
            assert catalog.unsupported_reason(platform, dit) is None, platform
            assert catalog.lookup(platform, dit) is not None, platform

    def test_non_aws_types_are_never_flagged_as_metal(self):
        assert catalog.unsupported_reason("snp-gcp", "n2d-standard-96") is None
