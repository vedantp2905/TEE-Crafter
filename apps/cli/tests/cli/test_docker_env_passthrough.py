"""Exported ``TEE_CRAFTER_*`` variables never reached the CLI.

The CLI re-execs itself inside its own Docker image. The wrapper mounted the
workspace and forwarded the workspace ``.env`` file plus three variables it sets
itself — and dropped everything else. So every documented ``TEE_CRAFTER_*``
knob exported in a shell did nothing:

    TEE_CRAFTER_ALLOW_NO_SECURE_BOOT=1 tee-crafter deploy …    # silently ignored

Found by following the CLI's own advice. Deploying a Graviton AMI (which cannot
carry Secure Boot, because AL2023 ships pre-signed PK/KEK/db for x86_64 only)
prints:

    UEFI Secure Boot is not proven for this image
    ami-07976d819736278f1 is tagged tee-crafter-secure-boot='disabled'
    … accept the weaker posture explicitly with
      TEE_CRAFTER_ALLOW_NO_SECURE_BOOT=1

Setting it changed nothing, because the wrapper discarded it on the way in. A
refusal whose stated remedy cannot work is worse than no remedy: it sends the
operator looking for a mistake they did not make.

``TF_VAR_*`` is covered too — Terraform runs inside the container as well, so
``TF_VAR_enable_secure_boot`` and friends were equally lost.

The values are forwarded as bare ``-e NAME``, never ``-e NAME=value``. Docker
reads the value from the client process's own environment, so it stays out of
the ``docker`` command line where ``ps`` would show it to any other local user
— which matters because several of these hold secrets. Verified against Docker
directly: ``FOO=hunter2 docker run --rm -e FOO alpine sh -c 'echo $FOO'``
prints ``hunter2``, and ``-e SOMETHING_UNSET`` leaves the variable absent
rather than empty.
"""

import pytest

from tee_crafter.cli.main import (
    _IN_DOCKER_ENV,
    _WRAPPER_OWNED_ENV,
    _env_passthrough_args,
)


def _names(args):
    """The variable names in a ``['-e', 'A', '-e', 'B']`` list."""
    assert all(flag == "-e" for flag in args[0::2]), args
    return args[1::2]


class TestForwarding:
    def test_the_variable_from_the_live_failure_is_forwarded(self):
        args = _env_passthrough_args({"TEE_CRAFTER_ALLOW_NO_SECURE_BOOT": "1"})
        assert _names(args) == ["TEE_CRAFTER_ALLOW_NO_SECURE_BOOT"]

    @pytest.mark.parametrize("name", [
        "TEE_CRAFTER_ALLOW_NO_SECURE_BOOT",
        "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT",
        "TEE_CRAFTER_FMSPC",
        "TEE_CRAFTER_SNP_CAPTURE_VCPUS",
        "TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE",
        "TEE_CRAFTER_KEEP_ON_FAILURE",
        "TF_VAR_instance_type",
        "TF_VAR_enable_secure_boot",
    ])
    def test_documented_knobs_are_forwarded(self, name):
        assert _names(_env_passthrough_args({name: "x"})) == [name]

    def test_unrelated_variables_are_not_forwarded(self):
        """Forwarding the whole environment would be a different, worse bug."""
        args = _env_passthrough_args({
            "PATH": "/usr/bin", "HOME": "/root", "AWS_SECRET_ACCESS_KEY": "s",
            "SHELL": "/bin/zsh", "LANG": "C",
        })
        assert args == []

    def test_output_is_deterministic(self):
        """Same environment, same flags — so a diff of two runs means something."""
        env = {"TF_VAR_b": "2", "TEE_CRAFTER_A": "1", "TEE_CRAFTER_C": "3"}
        assert _env_passthrough_args(env) == _env_passthrough_args(env)
        assert _names(_env_passthrough_args(env)) == [
            "TEE_CRAFTER_A", "TEE_CRAFTER_C", "TF_VAR_b"]

    def test_empty_environment_adds_nothing(self):
        assert _env_passthrough_args({}) == []


class TestValuesStayOutOfArgv:
    """``ps aux`` must not reveal a forwarded secret."""

    def test_no_value_appears_in_the_flags(self):
        secret = "tok_ThisMustNotAppearInArgv"
        args = _env_passthrough_args({"TEE_CRAFTER_SIEM_TOKEN": secret})
        assert _names(args) == ["TEE_CRAFTER_SIEM_TOKEN"]
        assert secret not in " ".join(args)

    def test_no_flag_uses_the_name_equals_value_form(self):
        args = _env_passthrough_args({
            "TEE_CRAFTER_SIEM_TOKEN": "t", "TF_VAR_x": "y"})
        assert not [a for a in args if "=" in a]


class TestWrapperOwnedVariables:
    """Some variables are the wrapper's to set and must not be inherited."""

    def test_recursion_guard_is_not_inherited(self):
        """Inheriting it would make the container skip its own re-exec guard."""
        assert _env_passthrough_args({_IN_DOCKER_ENV: "1"}) == []

    def test_measurements_dir_is_not_inherited(self):
        """The wrapper rewrites this to the container mount point.

        Passing the host path through would point the measurement registry at a
        directory that does not exist inside the container, so bake-time pins
        would silently fail to persist.
        """
        assert _env_passthrough_args(
            {"TEE_CRAFTER_MEASUREMENTS_DIR": "/Users/x/repo/measurements"}) == []

    @pytest.mark.parametrize("name", sorted(_WRAPPER_OWNED_ENV))
    def test_every_wrapper_owned_variable_is_excluded(self, name):
        assert _env_passthrough_args({name: "v"}) == []

    def test_exclusions_do_not_swallow_similar_names(self):
        """A prefix-match bug here would silently drop real knobs."""
        env = {
            "TEE_CRAFTER_MEASUREMENTS_DIR_EXTRA": "a",
            "TEE_CRAFTER_DOCKER_IMAGE_TAG": "b",
        }
        assert set(_names(_env_passthrough_args(env))) == set(env)


class TestWiredIntoTheWrapper:
    def test_the_docker_invocation_calls_it(self):
        """A helper nothing calls would pass every test above and fix nothing."""
        import inspect

        from tee_crafter.cli import main
        src = inspect.getsource(main._exec_tee_crafter_in_docker)
        assert "_env_passthrough_args()" in src

    def test_it_is_applied_before_the_image_argument(self):
        """Docker only accepts flags before the image name."""
        import inspect

        from tee_crafter.cli import main
        src = inspect.getsource(main._exec_tee_crafter_in_docker)
        assert src.index("_env_passthrough_args()") < src.index("[image] + argv[1:]")


class TestPinnedImageVariables:
    """The pin variables match neither prefix, so they must be named.

    ``AWS_NITRO_AMI_ARM64`` / ``AWS_NITRO_AMI_X86_64`` / ``AZURE_SGX_IMAGE`` /
    ``GCP_TDX_IMAGE`` and friends are documented ``.env`` knobs that were
    equally lost when exported in a shell — the first version of this
    passthrough missed them because it only matched on prefix, which is how the
    gap was found: setting ``AWS_NITRO_AMI_ARM64`` and deploying a Graviton host
    still resolved no image.
    """

    @pytest.mark.parametrize("name", [
        "AWS_NITRO_AMI_ARM64", "AWS_NITRO_AMI_X86_64",
        "AWS_SNP_AMI", "AWS_GPU_CC_AMI",
        "AZURE_SGX_IMAGE", "AZURE_TDX_IMAGE", "AZURE_SNP_IMAGE",
        "GCP_TDX_IMAGE", "GCP_SNP_IMAGE", "GCP_GPU_CC_IMAGE",
        "TEE_CRAFTER_AMI_ID",
    ])
    def test_pin_variables_are_forwarded(self, name):
        assert _names(_env_passthrough_args({name: "img-1"})) == [name]

    def test_every_registered_pin_key_is_forwarded(self):
        """Adding a pin variable must not silently fail to reach the container."""
        from tee_crafter.core.pinned_image_env import ALL_PINNED_IMAGE_ENV_KEYS
        env = {name: "v" for name in ALL_PINNED_IMAGE_ENV_KEYS}
        assert set(_names(_env_passthrough_args(env))) == set(ALL_PINNED_IMAGE_ENV_KEYS)

    def test_unrelated_aws_variables_are_still_not_forwarded(self):
        """Only the documented pin names — not the whole AWS_* namespace."""
        assert _env_passthrough_args({
            "AWS_SECRET_ACCESS_KEY": "s", "AWS_PROFILE": "p",
            "AWS_NITRO_AMI_TYPO": "x",
        }) == []

    def test_the_retired_generic_nitro_variable_is_not_forwarded(self):
        """AWS_NITRO_AMI no longer exists; forwarding it would imply it does.

        nitro-aws pins one AMI per architecture, so there is nothing for a
        single value to mean.
        """
        assert _env_passthrough_args({"AWS_NITRO_AMI": "ami-stale"}) == []
