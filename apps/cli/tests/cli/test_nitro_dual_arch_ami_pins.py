"""``nitro-aws`` needs two pinned AMIs, and had room for one.

Nitro runs on x86_64 (``c6a.*``) and on Graviton (``c/m/r`` ``6g``–``9g``), and
an AMI serves exactly one architecture. The pin table held a single
``AWS_NITRO_AMI`` per platform, so an operator keeping both builds had to
hand-edit ``.env`` or pass ``--ami-id`` on every deploy — and forgetting did not
produce a helpful message, it produced an architecture mismatch later in
``validate_custom_ami_architecture``.

There is now **no** platform-wide ``AWS_NITRO_AMI`` at all, not even as a
fallback. "The Nitro AMI" is not a well-defined thing: an arm64 instance cannot
boot an x86_64 image, so a generic value would be the wrong image whenever the
operator chose the other architecture — silently right half the time is the
worst of the three options. Missing the pin now produces a refusal that names
the exact variable and the bake command that produces it.

They are also not two builds of one thing. UEFI Secure Boot enrolment is
x86_64-only, because AL2023's ``amazon-linux-sb-keys`` package ships pre-signed
PK/KEK/db for x86_64, so an arm64 Nitro AMI is always tagged
``tee-crafter-secure-boot=disabled``. The two pins carry different security
postures, which is a second reason not to collapse them into one slot.

``snp-aws`` deliberately has no arm64 pin: AMD SEV-SNP is an AMD CPU feature.

Also covers the architecture rule itself, which existed as six copies in two
inconsistent variants. Four used ``re.search(r"\\dg", family)`` and two used the
anchored ``re.search(r"\\dg$", family)``. The anchored form classifies every
``d``/``n`` Graviton variant as x86_64 — ``c6gd``, ``c6gn``, ``m8gd``, ``x2gd``
do not end in ``g`` — so a ``c6gd.xlarge`` deploy would have been handed an
x86_64 base AMI and an x86_64 enclave image. All six now delegate to
``catalog.instance_architecture``.
"""

import pytest

from tee_crafter.core import catalog
from tee_crafter.core.pinned_image_env import (
    ALL_PINNED_IMAGE_ENV_KEYS,
    PLATFORM_PINNED_IMAGE_ENV_BY_ARCH,
    arch_pinned_image_env_key,
    effective_pinned_image_from_env,
)

X86 = "AWS_NITRO_AMI_X86_64"
ARM = "AWS_NITRO_AMI_ARM64"


@pytest.fixture(autouse=True)
def _clean_pins(monkeypatch):
    for key in ALL_PINNED_IMAGE_ENV_KEYS | {"TF_VAR_instance_type"}:
        monkeypatch.delenv(key, raising=False)


class TestArchitectureRule:
    @pytest.mark.parametrize("itype,expected", [
        # Plain Graviton families.
        ("c6g.xlarge", "arm64"), ("m7g.large", "arm64"), ("r8g.4xlarge", "arm64"),
        ("c9g.48xlarge", "arm64"),
        # The d/n variants the anchored regex used to call x86_64.
        ("c6gd.xlarge", "arm64"), ("c6gn.2xlarge", "arm64"),
        ("m8gd.large", "arm64"), ("x2gd.4xlarge", "arm64"), ("i4g.xlarge", "arm64"),
        # AMD / Intel / GPU families must stay x86_64.
        ("c6a.xlarge", "x86_64"), ("m7a.large", "x86_64"), ("r6a.4xlarge", "x86_64"),
        ("p5.4xlarge", "x86_64"), ("p5en.48xlarge", "x86_64"),
        ("g4dn.xlarge", "x86_64"), ("g5.2xlarge", "x86_64"),
    ])
    def test_architecture_of(self, itype, expected):
        assert catalog.instance_architecture(itype) == expected

    @pytest.mark.parametrize("empty", [None, ""])
    def test_unknown_is_none_not_a_guess(self, empty):
        assert catalog.instance_architecture(empty) is None

    def test_every_caller_shares_the_one_definition(self):
        """Six copies in two variants is how the c6gd bug survived."""
        from tee_crafter.cli.commands.deploy.validators import (
            get_instance_architecture,
        )
        for itype in ("c6gd.xlarge", "c6a.xlarge", "m8g.large", "p5en.48xlarge"):
            assert (get_instance_architecture(itype)
                    == catalog.instance_architecture(itype))

    def test_no_module_reimplements_the_regex(self):
        """A seventh copy would drift like the first six did."""
        import pathlib

        import tee_crafter
        root = pathlib.Path(tee_crafter.__file__).parent
        offenders = []
        for path in root.rglob("*.py"):
            if path.name == "catalog.py":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("*"):
                    continue
                if 'r"\\dg' in line or "r'\\dg" in line:
                    offenders.append(f"{path.name}: {stripped[:70]}")
        assert not offenders, "architecture rule re-implemented in: " + "; ".join(offenders)


class TestPerArchitecturePinSelection:
    def test_x86_instance_picks_the_x86_pin(self, monkeypatch):
        monkeypatch.setenv(X86, "ami-x86")
        monkeypatch.setenv(ARM, "ami-arm")
        assert effective_pinned_image_from_env(
            "nitro-aws", instance_type="c6a.xlarge") == "ami-x86"

    def test_graviton_instance_picks_the_arm_pin(self, monkeypatch):
        monkeypatch.setenv(X86, "ami-x86")
        monkeypatch.setenv(ARM, "ami-arm")
        assert effective_pinned_image_from_env(
            "nitro-aws", instance_type="c7g.xlarge") == "ami-arm"

    def test_the_d_variant_picks_arm_too(self, monkeypatch):
        """c6gd is Graviton; the old anchored regex would have said x86_64."""
        monkeypatch.setenv(X86, "ami-x86")
        monkeypatch.setenv(ARM, "ami-arm")
        assert effective_pinned_image_from_env(
            "nitro-aws", instance_type="c6gd.xlarge") == "ami-arm"

    def test_no_instance_type_resolves_nothing_rather_than_guessing(self, monkeypatch):
        """Architecture is undecidable, so neither pin may be used.

        The deploy path never hits this: it passes the catalog default when no
        instance type was given, so the architecture is always known there.
        """
        monkeypatch.setenv(X86, "ami-x86")
        monkeypatch.setenv(ARM, "ami-arm")
        assert effective_pinned_image_from_env("nitro-aws") is None


class TestPrecedence:
    def test_explicit_flag_beats_every_pin(self, monkeypatch):
        monkeypatch.setenv(X86, "ami-x86")
        monkeypatch.setenv(ARM, "ami-arm")
        assert effective_pinned_image_from_env(
            "nitro-aws", cli_or_explicit=" ami-flag ",
            instance_type="c7g.xlarge") == "ami-flag"

    def test_legacy_global_beats_the_arch_pins(self, monkeypatch):
        """Documented order: TEE_CRAFTER_AMI_ID outranks per-platform pins."""
        monkeypatch.setenv("TEE_CRAFTER_AMI_ID", "ami-legacy")
        monkeypatch.setenv(ARM, "ami-arm")
        assert effective_pinned_image_from_env(
            "nitro-aws", instance_type="c7g.xlarge") == "ami-legacy"

    def test_a_stale_generic_variable_is_ignored(self, monkeypatch):
        """AWS_NITRO_AMI is retired; a leftover value must not be picked up.

        Silently honouring it would reintroduce exactly the bug this replaced —
        one value serving two architectures.
        """
        monkeypatch.setenv("AWS_NITRO_AMI", "ami-stale-generic")
        for itype in ("c6a.xlarge", "c7g.xlarge", None):
            assert effective_pinned_image_from_env(
                "nitro-aws", instance_type=itype) is None

    def test_the_other_architectures_pin_is_not_substituted(self, monkeypatch):
        """Half-configured is common: one arch baked, the other not.

        Falling back to the arch that *is* set would hand Terraform an image the
        instance cannot boot.
        """
        monkeypatch.setenv(X86, "ami-x86")
        assert effective_pinned_image_from_env(
            "nitro-aws", instance_type="c7g.xlarge") is None
        monkeypatch.delenv(X86)
        monkeypatch.setenv(ARM, "ami-arm")
        assert effective_pinned_image_from_env(
            "nitro-aws", instance_type="c6a.xlarge") is None

    def test_nothing_set_is_none(self):
        assert effective_pinned_image_from_env(
            "nitro-aws", instance_type="c7g.xlarge") is None


class TestOtherPlatformsUnchanged:
    def test_snp_aws_has_no_arch_split(self):
        """SEV-SNP is an AMD feature, so snp-aws is x86_64 by construction."""
        assert "snp-aws" not in PLATFORM_PINNED_IMAGE_ENV_BY_ARCH
        assert arch_pinned_image_env_key("snp-aws", "m6a.large") is None

    def test_snp_aws_pin_still_resolves(self, monkeypatch):
        monkeypatch.setenv("AWS_SNP_AMI", "ami-snp")
        assert effective_pinned_image_from_env(
            "snp-aws", instance_type="m6a.large") == "ami-snp"

    @pytest.mark.parametrize("platform,var,value", [
        ("gpu-cc-aws", "AWS_GPU_CC_AMI", "ami-gpu"),
        ("tdx-gcp", "GCP_TDX_IMAGE", "projects/p/global/images/tdx"),
        ("sgx-azure", "AZURE_SGX_IMAGE", "/subscriptions/x/images/sgx"),
    ])
    def test_single_arch_platforms_resolve_as_before(
            self, monkeypatch, platform, var, value):
        monkeypatch.setenv(var, value)
        assert effective_pinned_image_from_env(platform) == value

    def test_arch_keys_are_registered_for_env_scrubbing(self):
        """Anything that enumerates pin variables must see the new ones.

        ``ALL_PINNED_IMAGE_ENV_KEYS`` is what callers use to clear or report
        pins; a variable missing from it would be invisible to them.
        """
        assert {X86, ARM} <= ALL_PINNED_IMAGE_ENV_KEYS
        assert "AWS_NITRO_AMI" not in ALL_PINNED_IMAGE_ENV_KEYS


class TestDocumented:
    def test_env_example_documents_both_variables(self):
        import pathlib

        import tee_crafter
        repo = pathlib.Path(tee_crafter.__file__).parents[3].parent
        example = repo / ".env.example"
        if not example.is_file():          # packaged install, not a checkout
            pytest.skip(".env.example not present in this layout")
        text = example.read_text(encoding="utf-8")
        assert X86 in text and ARM in text
        # And says why arm64 cannot carry Secure Boot, so the pairing is clear.
        assert "amazon-linux-sb-keys" in text


class TestMissingPinRefusal:
    """The refusal must name the variable, not just say "set the per-platform one".

    With one pin per architecture, "set the per-platform variable" is not
    actionable: an operator who set the x86_64 pin and then chose a Graviton
    host needs to be told which of the two is missing, and that the bake needs a
    matching --instance-type to produce it.
    """

    def _panel(self, monkeypatch, instance_type):
        from tee_crafter.cli.commands.deploy import deploy_helpers

        captured = []
        monkeypatch.setattr(deploy_helpers.console, "print",
                            lambda *a, **k: captured.append(a[0] if a else ""))

        class _Audit:
            def record(self, *a, **k):
                pass

        result = deploy_helpers._resolve_ami_id(
            ami_id=None, tee_platform="nitro-aws", deploy=True,
            audit=_Audit(), cpu=2, ram=4096, instance_type=instance_type)
        assert result is None
        return "\n".join(getattr(p, "renderable", str(p)) for p in captured)

    def test_graviton_refusal_names_the_arm_variable(self, monkeypatch):
        monkeypatch.setenv(X86, "ami-x86")
        text = self._panel(monkeypatch, "c7g.xlarge")
        assert ARM in text
        assert "arm64" in text
        # And the bake command that actually produces an arm64 AMI.
        assert "--no-enable-secure-boot" in text

    def test_x86_refusal_names_the_x86_variable(self, monkeypatch):
        monkeypatch.setenv(ARM, "ami-arm")
        text = self._panel(monkeypatch, "c6a.xlarge")
        assert X86 in text
        assert "x86_64" in text
        assert "--no-enable-secure-boot" not in text, (
            "x86_64 can enrol Secure Boot; suggesting the opt-out is wrong")

    def test_the_flag_name_survives_rich_markup(self, monkeypatch):
        """"[--deploy]" was parsed as a markup tag and dropped."""
        text = self._panel(monkeypatch, "c7g.xlarge")
        assert "--deploy" in text

    def test_other_platforms_get_their_own_variable_named(self, monkeypatch):
        from tee_crafter.cli.commands.deploy import deploy_helpers

        captured = []
        monkeypatch.setattr(deploy_helpers.console, "print",
                            lambda *a, **k: captured.append(a[0] if a else ""))

        class _Audit:
            def record(self, *a, **k):
                pass

        assert deploy_helpers._resolve_ami_id(
            ami_id=None, tee_platform="snp-aws", deploy=True,
            audit=_Audit(), cpu=2, ram=4096, instance_type="m6a.large") is None
        text = "\n".join(getattr(p, "renderable", str(p)) for p in captured)
        assert "AWS_SNP_AMI" in text
        assert ARM not in text and X86 not in text
