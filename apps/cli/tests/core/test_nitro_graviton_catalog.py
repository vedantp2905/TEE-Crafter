"""Graviton hosts for Nitro Enclaves.

Two shipping docs used to claim Graviton was supported end to end via
``--instance-type``. It was not: ``catalog.lookup`` matched only
``^([mcr])([67])a\\.(\\w+)$``, so every Graviton type returned ``None`` and
``resolve_shape`` raised before a deploy could start. Nothing executes a
sentence in a document, which is why the claim survived two audit passes.

The support itself is real, and taken from the API rather than from prose.
``ec2:DescribeInstanceTypes`` in us-east-2 on 2026-08-21, filtered on
``nitro-enclaves-support=supported`` and
``processor-info.supported-architecture=arm64``, returns the ``c/m/r`` families
at generations 6g through 9g. Verified specs from the same call:

    c6g.large     2 vCPU    4096 MiB   arm64   supported
    m6g.large     2 vCPU    8192 MiB   arm64   supported
    r6g.large     2 vCPU   16384 MiB   arm64   supported
    c8g.48xlarge  192 vCPU 393216 MiB  arm64   supported

so the ``c``/``m``/``r`` ratios in ``_AWS_RAM_PER_VCPU`` (2 / 4 / 8 GiB per
vCPU) hold for Graviton unchanged. A deliberately misspelt filter name was used
as a control: ``DescribeInstanceTypes`` rejects an unknown filter with
``InvalidParameterValue`` rather than returning an empty list, so the arm64
result set is a real answer and not a silently-empty one.

Two boundaries this module pins, because both are easy to break by widening the
regex carelessly:

* **SEV-SNP must keep rejecting Graviton.** SEV-SNP is an AMD CPU feature. An
  arm64 type there is not merely unlisted — it can never launch, and resolving
  it would hand Terraform an impossible instance type.
* **2-vCPU hosts stay out of the offered list.** An enclave is a carve-out and
  the parent keeps ``NITRO_PARENT_VCPU_RESERVE = 2`` vCPU, so a 2-vCPU host has
  nothing left. The x86 list already starts at ``c6a.xlarge``.
"""

import pytest

from tee_crafter.cli.commands.deploy.compute import (
    NITRO_PARENT_VCPU_RESERVE,
    resolve_shape,
)
from tee_crafter.core import catalog

GIB = 1024

#: (instance_type, vcpu, ram_mb) read back from DescribeInstanceTypes.
#:
#: The 2-vCPU ``*.large`` rows that used to sit here were removed once
#: TEE-Crafter began refusing hosts too small to carve an enclave out of — a
#: shape ``lookup`` rightly rejects cannot also be asserted to resolve. The
#: ``16xlarge`` rows below already pin all three memory ratios (c = 2, m = 4,
#: r = 8 GiB per vCPU), and the refusal itself is covered in
#: ``test_unrunnable_shapes_refused.py::TestHostTooSmallForAnEnclave``.
API_VERIFIED = [
    ("c6g.16xlarge", 64, 131072),
    ("m6g.16xlarge", 64, 262144),
    ("r6g.16xlarge", 64, 524288),
    ("c8g.48xlarge", 192, 393216),
]


class TestGravitonResolves:
    """The regression itself: these used to raise from resolve_shape."""

    @pytest.mark.parametrize("itype", [
        "c6g.xlarge", "m6g.4xlarge", "r6g.16xlarge",
        "c7g.xlarge", "m7g.8xlarge", "r7g.2xlarge",
        "c8g.48xlarge", "m8g.24xlarge", "r8g.xlarge",
        "c9g.xlarge", "m9g.48xlarge", "r9g.12xlarge",
    ])
    def test_lookup_resolves_every_graviton_family(self, itype):
        spec = catalog.lookup("nitro-aws", itype)
        assert spec is not None, f"{itype} rejected; resolve_shape would raise"
        assert spec.instance_type == itype
        assert spec.vcpu >= 2

    @pytest.mark.parametrize("itype", ["c7g.xlarge", "m8g.4xlarge", "r6g.2xlarge"])
    def test_resolve_shape_no_longer_raises(self, itype):
        """The failing call from the original report, end to end."""
        shape = resolve_shape("nitro-aws", itype)
        assert shape.instance_type == itype
        host = catalog.lookup("nitro-aws", itype)
        # cpu/ram on Nitro are the *enclave* carve-out, not the whole host.
        assert shape.cpu == max(2, host.vcpu - NITRO_PARENT_VCPU_RESERVE)
        assert shape.ram_mb < host.ram_mb

    @pytest.mark.parametrize("itype,vcpu,ram_mb", API_VERIFIED)
    def test_specs_match_the_ec2_api(self, itype, vcpu, ram_mb):
        spec = catalog.lookup("nitro-aws", itype)
        assert (spec.vcpu, spec.ram_mb) == (vcpu, ram_mb)


class TestSnpStillRejectsGraviton:
    """SEV-SNP is an AMD feature; arm64 there is impossible, not just unlisted."""

    @pytest.mark.parametrize("itype", [
        "c6g.xlarge", "m7g.large", "r8g.4xlarge", "c9g.48xlarge",
    ])
    def test_snp_aws_rejects_arm64(self, itype):
        assert catalog.lookup("snp-aws", itype) is None
        with pytest.raises(ValueError):
            resolve_shape("snp-aws", itype)

    @pytest.mark.parametrize("itype", ["m6a.large", "c6a.2xlarge", "r6a.4xlarge"])
    def test_snp_aws_still_accepts_amd(self, itype):
        """Guards against 'fixing' the above by rejecting everything.

        These are SEV-SNP-capable per ``ec2:DescribeInstanceTypes``. The
        original version of this control used ``c7a.2xlarge`` and
        ``r6a.8xlarge``, which turned out to have no ``amd-sev-snp`` feature at
        all — so it was asserting the wrong thing, not merely a different thing.
        """
        assert catalog.lookup("snp-aws", itype) is not None


class TestX86PathUnchanged:
    @pytest.mark.parametrize("itype,gen", [
        ("c6a.xlarge", "milan"), ("m6a.4xlarge", "milan"),
        ("c7a.2xlarge", "genoa"), ("r7a.4xlarge", "genoa"),
    ])
    def test_nitro_distinguishes_amd_generations(self, itype, gen):
        """Nitro accepts both AMD generations; it needs no SEV-SNP.

        Originally this looped over ``nitro-aws`` *and* ``snp-aws`` with the
        same types. The two platforms have different capability rules, so that
        was only ever passing because neither had any: Nitro cannot use 2-vCPU
        hosts, and SNP cannot use Genoa at all.
        """
        spec = catalog.lookup("nitro-aws", itype)
        assert spec is not None and spec.cpu_gen == gen

    @pytest.mark.parametrize("itype,gen", [
        ("c6a.xlarge", "milan"), ("m6a.4xlarge", "milan"),
    ])
    def test_snp_keeps_its_generation_label(self, itype, gen):
        spec = catalog.lookup("snp-aws", itype)
        assert spec is not None and spec.cpu_gen == gen

    def test_nitro_default_is_unchanged(self):
        """Adding Graviton must not silently move anyone's default host."""
        assert catalog.default_instance_type("nitro-aws") == "c6a.xlarge"
        assert catalog.lookup("nitro-aws", "c6a.xlarge").cpu_gen == "milan"


class TestOfferedList:
    def test_graviton_appears_in_enumeration(self):
        offered = catalog.enumerate_instances("nitro-aws")
        gv = [s for s in offered if s.cpu_gen == "graviton"]
        assert gv, "list-instances would still show x86 only"
        assert {s.instance_type.split(".")[0][0] for s in gv} == {"c", "m", "r"}

    def test_no_host_too_small_to_run_an_enclave_is_offered(self):
        """A 2-vCPU host has nothing left after the parent reserve."""
        for spec in catalog.enumerate_instances("nitro-aws"):
            assert spec.vcpu > NITRO_PARENT_VCPU_RESERVE, (
                f"{spec.instance_type} leaves the parent no vCPU")

    def test_lookup_is_permissive_only_for_runnable_unoffered_sizes(self):
        """Un-enumerated is fine; unrunnable is not.

        This test originally asserted that ``c6a.large`` and ``c6g.large`` still
        resolved, on the grounds that ``lookup`` was documented as permissive.
        They no longer do, and that is deliberate: a 2-vCPU host cannot host an
        enclave once the parent reserve is taken. Permissiveness now means
        "resolves sizes the curated list happens not to name", which is a
        different claim — so the test asserts the distinction rather than the
        old blanket rule.
        """
        offered = {s.instance_type for s in catalog.enumerate_instances("nitro-aws")}
        # Runnable but not enumerated (the curated Nitro x86 list is c6a only).
        for runnable in ("c7a.2xlarge", "m6a.4xlarge"):
            assert runnable not in offered
            assert catalog.lookup("nitro-aws", runnable) is not None
        # Unrunnable: refused, not merely absent from the list.
        for unrunnable in ("c6a.large", "c6g.large", "c6a.metal"):
            assert unrunnable not in offered
            assert catalog.lookup("nitro-aws", unrunnable) is None
            assert catalog.unsupported_reason("nitro-aws", unrunnable)

    def test_sizes_a_generation_does_not_sell_are_not_offered(self):
        """Graviton has 24xlarge and 48xlarge but never 32xlarge; 6g/7g cap at 16xlarge."""
        offered = {s.instance_type for s in catalog.enumerate_instances("nitro-aws")}
        assert not [t for t in offered if ".32xlarge" in t]
        assert "c8g.48xlarge" in offered
        assert "c6g.48xlarge" not in offered
        assert "c7g.24xlarge" not in offered

    def test_every_offered_shape_round_trips_through_lookup(self):
        for spec in catalog.enumerate_instances("nitro-aws"):
            assert catalog.lookup("nitro-aws", spec.instance_type) == spec


class TestArchitectureDerivation:
    """The AMI-arch plumbing already existed; confirm Graviton lands on arm64.

    ``terraform_gen.generate_terraform_code`` derives ``__AMI_ARCH__`` with
    ``re.search(r"\\dg", family)``. This is the rule that decides which base AMI
    the deployment launches, so a Graviton type resolving to ``x86_64`` would
    produce a host that cannot boot the image.
    """

    @pytest.mark.parametrize("itype,expected", [
        ("c6a.xlarge", "x86_64"), ("m7a.large", "x86_64"), ("r6a.4xlarge", "x86_64"),
        ("c6g.xlarge", "arm64"), ("m8g.large", "arm64"), ("r9g.2xlarge", "arm64"),
    ])
    def test_family_maps_to_the_right_ami_architecture(self, itype, expected):
        assert catalog.instance_architecture(itype) == expected

    def test_the_generator_uses_the_shared_rule(self):
        """This test used to pin the regex literal inline in ``terraform_gen``.

        There were six such copies in two inconsistent variants, so the rule is
        now defined once in ``catalog.instance_architecture`` and delegated to.
        Asserting the delegation is the stronger check: an inline copy could
        drift, whereas a caller of the shared function cannot.
        """
        import inspect

        from tee_crafter.core.iac import terraform_gen
        src = inspect.getsource(terraform_gen.generate_terraform_code)
        assert "instance_architecture(instance_type)" in src
        assert 'r"\\dg"' not in src, "re-introduced a private copy of the rule"


class TestSizeTokenIsGenerationScoped:
    """A size must exist *for its generation*, not merely somewhere in AWS.

    ``lookup`` validated the generation against ``_AWS_NITRO_GRAVITON_SIZES``
    and then read the size token out of the global ``_AWS_SIZE_VCPU`` table,
    never checking that the token belonged to that generation.  So
    ``m8g.32xlarge`` (no Graviton generation has a 32xlarge) and
    ``c6g.24xlarge`` (6g and 7g stop at 16xlarge) both resolved, and Terraform
    was handed an instance type EC2 refuses — the operator got an opaque
    ``InvalidParameterValue`` from AWS instead of this CLI's own refusal, which
    is the exact thing resolving shapes up front is supposed to prevent.

    Found while fact-checking ``docs/nitro_flow.md``, which claimed the sizes
    were "enumerated rather than derived". The *enumeration* was right; the
    lookup path derived.
    """

    @pytest.mark.parametrize("itype", [
        "m8g.32xlarge", "c8g.32xlarge", "r9g.32xlarge",  # no 32xlarge exists
        "c6g.24xlarge", "m7g.24xlarge",                  # 6g/7g stop at 16xlarge
        "c6g.48xlarge", "r7g.48xlarge",
    ])
    def test_sizes_absent_from_the_generation_do_not_resolve(self, itype):
        assert catalog.lookup("nitro-aws", itype) is None

    @pytest.mark.parametrize("itype,vcpu", [
        ("c6g.16xlarge", 64), ("c7g.16xlarge", 64),
        ("m8g.24xlarge", 96), ("m8g.48xlarge", 192),
        ("r9g.24xlarge", 96),
    ])
    def test_sizes_present_in_the_generation_still_resolve(self, itype, vcpu):
        spec = catalog.lookup("nitro-aws", itype)
        assert spec is not None and spec.vcpu == vcpu

    def test_two_vcpu_large_is_refused_not_resolved(self):
        """``docs/nitro_flow.md`` claimed ``large`` "resolves if you name it
        explicitly". It does not — ``_NITRO_MIN_VCPU`` refuses it, because the
        parent reserves 2 vCPU and a 2-vCPU host has nothing left. The doc has
        been corrected; this pins the actual behaviour.
        """
        for itype in ("c7g.large", "c6g.large", "m8g.large"):
            assert catalog.lookup("nitro-aws", itype) is None
            reason = catalog.unsupported_reason("nitro-aws", itype)
            assert reason and "4 vCPU minimum" in reason
