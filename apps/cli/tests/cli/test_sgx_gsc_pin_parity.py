"""The GSC pins in the CLI image and on the SGX VM must be the same pins.

``sgx-azure --batch`` graminizes on the SGX VM, so GSC is installed twice from
two files that cannot see each other:

* ``apps/cli/Dockerfile`` — for the CLI container;
* ``scripts/sgx_azure/setup_sgx.sh`` — baked into the SGX VM image, which is
  where graminizing actually happens.

Duplication is unavoidable (the setup script runs on a VM with no checkout), so
the risk is drift: bumping one and not the other means the enclave is built by a
different GSC than the one that was reviewed, and MRENCLAVE changes for reasons
nobody recorded. These tests are the thing that makes the duplication safe.

The commit pin specifically matters. ``v1.9`` — the newest tag — has
``extract_user_from_image_config`` doing ``config['User']`` unguarded, and Docker
omits that key when an image sets no ``USER`` (confirmed on Docker 29.6.1, where
even ``python:3.12-slim``'s config has no ``User``). So on the tag, ``gsc build``
dies with ``KeyError: 'User'`` for essentially every user image. Upstream fixed
it in 0b2ba93, which is after v1.9 and in no release, hence a SHA.
"""
from __future__ import annotations

import pathlib
import re

import pytest

# .../<repo>/apps/cli/tests/cli/<this file>  -> parents[4] is the repo root.
REPO = pathlib.Path(__file__).resolve().parents[4]
DOCKERFILE = REPO / "apps" / "cli" / "Dockerfile"
SETUP = (REPO / "apps" / "cli" / "src" / "tee_crafter" / "scripts"
         / "sgx_azure" / "setup_sgx.sh")

#: The upstream commit that replaced config['User'] with config.get('User').
EXPECTED_GSC_REF = "0b2ba9312c6120b5ebe2e55fb2bd7315b334361e"
EXPECTED_GRAMINE_BRANCH = "v1.9"


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def setup_text() -> str:
    return SETUP.read_text(encoding="utf-8")


def _one(pattern: str, text: str, what: str) -> str:
    found = re.findall(pattern, text)
    assert len(found) == 1, f"expected exactly one {what}, found {found}"
    return found[0]


class TestPinsAgree:
    def test_gsc_ref_matches(self, dockerfile_text, setup_text):
        docker_ref = _one(r"ARG GSC_REF=([0-9a-f]{40}|v[\d.]+)",
                          dockerfile_text, "GSC_REF in the Dockerfile")
        vm_ref = _one(r"(?m)^GSC_REF=([0-9a-f]{40}|v[\d.]+)",
                      setup_text, "GSC_REF in setup_sgx.sh")
        assert docker_ref == vm_ref, (
            "the CLI image and the SGX VM would install different GSC revisions")

    def test_gramine_branch_matches(self, dockerfile_text, setup_text):
        docker_branch = _one(r"ARG GRAMINE_BRANCH=(\S+)", dockerfile_text,
                             "GRAMINE_BRANCH in the Dockerfile")
        vm_branch = _one(r"(?m)^GRAMINE_BRANCH=(\S+)", setup_text,
                         "GRAMINE_BRANCH in setup_sgx.sh")
        assert docker_branch == vm_branch


class TestPinIsTheFixedRevision:
    def test_gsc_ref_is_the_user_fix_commit(self, dockerfile_text):
        ref = _one(r"ARG GSC_REF=(\S+)", dockerfile_text, "GSC_REF")
        assert ref == EXPECTED_GSC_REF, (
            "GSC moved off the commit that fixes KeyError: 'User'. If this is a "
            "deliberate bump, confirm the new revision still has "
            "config.get('User') and update EXPECTED_GSC_REF.")

    def test_gramine_branch_is_a_release(self, dockerfile_text):
        branch = _one(r"ARG GRAMINE_BRANCH=(\S+)", dockerfile_text,
                      "GRAMINE_BRANCH")
        assert branch == EXPECTED_GRAMINE_BRANCH
        assert re.fullmatch(r"v\d+\.\d+(\.\d+)?", branch), (
            "Gramine should track a release tag, not a floating branch")

    def test_the_pin_is_not_a_tag(self, dockerfile_text):
        """A tag would silently reintroduce the bug: no release has the fix."""
        ref = _one(r"ARG GSC_REF=(\S+)", dockerfile_text, "GSC_REF")
        assert not ref.startswith("v"), (
            "no GSC *release* contains the config.get('User') fix yet; pinning a "
            "tag brings back KeyError: 'User' on every modern-built image")

    def test_the_pin_is_not_a_branch(self, dockerfile_text):
        ref = _one(r"ARG GSC_REF=(\S+)", dockerfile_text, "GSC_REF")
        assert re.fullmatch(r"[0-9a-f]{40}", ref), (
            "pin an immutable commit, not a moving branch, or the CLI image is "
            "not reproducible")


class TestBothSidesVerifyTheFixIsPresent:
    """Neither install should succeed quietly on a revision lacking the fix."""

    def test_dockerfile_greps_for_the_fix(self, dockerfile_text):
        assert "config.get('User')" in dockerfile_text, (
            "the image build should assert the fix is present rather than "
            "trusting the SHA")

    def test_setup_script_greps_for_the_fix(self, setup_text):
        assert "config.get('User')" in setup_text

    def test_dockerfile_decouples_the_two_pins(self, dockerfile_text):
        """One ARG for both would force GSC and Gramine to move together."""
        assert "ARG GSC_REF=" in dockerfile_text
        assert "ARG GRAMINE_BRANCH=" in dockerfile_text
        # The Gramine branch, not the GSC ref, must land in config.yaml.
        assert 'Branch:     \\"${GRAMINE_BRANCH}\\"' in dockerfile_text \
            or 'Branch:     \\"${GRAMINE_BRANCH}\\"' in dockerfile_text.replace('\\\\', '\\')


class TestSetupScriptShape:
    def test_setup_script_installs_gsc(self, setup_text):
        assert "gramineproject/gsc.git" in setup_text
        assert "/usr/local/bin/gsc" in setup_text

    def test_setup_script_escapes_braces_for_str_format(self, setup_text):
        """The script is rendered with ``str.format``; literal braces double up.

        A single ``{`` would raise at render time, so this is really a guard on
        the whole file, but the GSC block is the newest place to get it wrong.
        """
        from tee_crafter.cli.commands.baking.common.helpers import load_setup_script
        rendered = load_setup_script("sgx-azure", aws_region="westus",
                                     enclave_size="1024M")
        assert "${GSC_REF}" in rendered
        assert "${GRAMINE_BRANCH}" in rendered
        assert f"GSC_REF={EXPECTED_GSC_REF}" in rendered

    def test_rendered_script_is_valid_bash(self, tmp_path):
        import shutil
        import subprocess
        if shutil.which("bash") is None:
            pytest.skip("bash not available")
        from tee_crafter.cli.commands.baking.common.helpers import load_setup_script
        script = tmp_path / "setup.sh"
        script.write_text(load_setup_script("sgx-azure", aws_region="westus",
                                            enclave_size="1024M"))
        res = subprocess.run(["bash", "-n", str(script)],
                             capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
