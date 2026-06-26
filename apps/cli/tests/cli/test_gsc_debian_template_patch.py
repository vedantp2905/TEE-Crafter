"""GSC's Debian template has to survive Debian 13, and the patch has to ship.

``sgx-azure`` graminizes on the SGX VM with GSC pinned at 0b2ba93.  That commit's
``templates/debian/Dockerfile.compile.template`` adds Intel's SGX apt repository
with ``apt-key``, and ``templates/ubuntu/Dockerfile.compile.template`` is a
single Jinja ``extends`` of it, so the call is on the shared path.

Measured on 2026-08-22 by rendering the real pinned template through Jinja and
building the rendered install block for ``linux/amd64``:

    base            GSC as shipped                      with the patch
    debian:11       ok                                  ok
    debian:12       ok                                  ok
    debian:13       FAIL  apt-key: not found (127)      ok
    ubuntu:22.04    ok                                  ok
    ubuntu:24.04    ok                                  ok

Fixing ``apt-key`` alone is not sufficient and that is the part worth
remembering: Debian 13 ships apt 3.0.3, which verifies with ``sqv`` (Sequoia)
rather than ``gpgv``, and Sequoia rejects Intel's signature with "Malformed MPI:
leading bit is not set", so ``apt-get update`` then reports the repository as
unsigned.  ``gpgv`` on the same InRelease and key says ``Good signature from
"CN=Intel(R) Software Development Products"``, so the signature is genuine and
Sequoia is merely stricter.  The patch therefore also installs ``gpgv`` and
points apt at it.  It does **not** use ``[trusted=yes]``; verification stays on.

Why this is load-bearing rather than nice-to-have: three of the four shipped
examples are built on ``python:3.12-slim``, which reports ``debian:13``, and
``fintech_fraud_detection`` -- the only batch-shaped example, on a platform that
is batch-only -- is one of them.

These tests cannot run ``gsc build`` (it needs SGX hardware and compiles Gramine
from source), so they pin the parts that can silently rot: the patch's own
logic, the brace-free invariant that keeps it renderable, and the fact that both
GSC install sites actually invoke it and assert its post-condition.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[4]
PATCH_PY = (REPO / "apps" / "cli" / "src" / "tee_crafter" / "scripts"
            / "sgx_azure" / "patch_gsc_debian_template.py")
SETUP_SH = (REPO / "apps" / "cli" / "src" / "tee_crafter" / "scripts"
            / "sgx_azure" / "setup_sgx.sh")
DOCKERFILE = REPO / "apps" / "cli" / "Dockerfile"

#: Post-condition both install sites grep for.
SENTINEL = "signed-by=/etc/apt/keyrings/intel-sgx.asc"


def _load():
    spec = importlib.util.spec_from_file_location(
        "patch_gsc_debian_template", str(PATCH_PY))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


patch_mod = _load()


#: A faithful excerpt of the pinned upstream template -- enough context that the
#: replacement has to land in the right place.
UPSTREAM_EXCERPT = """\
COPY intel-sgx-deb.key /

RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' \\
    > /etc/apt/sources.list.d/intel-sgx.list \\
    && apt-key add /intel-sgx-deb.key

RUN env DEBIAN_FRONTEND=noninteractive apt-get update \\
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y libsgx-dcap-quote-verify-dev
"""


class TestThePatchTransformsTheUpstreamTemplate:
    def test_the_excerpt_really_contains_what_we_target(self):
        """Guard the premise: if this drifts, every test below is vacuous."""
        assert patch_mod.OLD_BLOCK in UPSTREAM_EXCERPT

    def test_apt_key_is_gone_afterwards(self):
        out, status = patch_mod.patch_text(UPSTREAM_EXCERPT)
        assert status == "applied"
        assert "apt-key" not in out

    def test_the_keyring_is_wired_up(self):
        out, _ = patch_mod.patch_text(UPSTREAM_EXCERPT)
        assert SENTINEL in out
        assert "cp /intel-sgx-deb.key /etc/apt/keyrings/intel-sgx.asc" in out

    def test_gpgv_is_installed_because_debian_13_ships_only_sqv(self):
        out, _ = patch_mod.patch_text(UPSTREAM_EXCERPT)
        assert "gpgv" in out
        assert 'APT::Key::gpgvcommand "/usr/bin/gpgv";' in out

    def test_verification_is_never_disabled(self):
        """The whole point is to keep verifying, just with a different verifier.
        ``trusted=yes`` would install Intel's SGX libraries unverified."""
        out, _ = patch_mod.patch_text(UPSTREAM_EXCERPT)
        assert "trusted=yes" not in out
        assert "trusted=yes" not in patch_mod.NEW_BLOCK

    def test_the_rest_of_the_template_is_untouched(self):
        out, _ = patch_mod.patch_text(UPSTREAM_EXCERPT)
        assert "COPY intel-sgx-deb.key /" in out
        assert "libsgx-dcap-quote-verify-dev" in out

    def test_the_line_continuations_stay_balanced(self):
        """A dropped trailing backslash turns one RUN into a broken two."""
        for line in patch_mod.NEW_BLOCK.splitlines()[:-1]:
            assert line.rstrip().endswith("\\"), line
        assert not patch_mod.NEW_BLOCK.splitlines()[-1].rstrip().endswith("\\")


class TestIdempotenceAndFailureModes:
    def test_running_twice_is_a_no_op(self):
        """The VM image is baked once and the script re-runs on boot."""
        once, _ = patch_mod.patch_text(UPSTREAM_EXCERPT)
        twice, status = patch_mod.patch_text(once)
        assert status == "already"
        assert twice == once

    def test_a_template_without_the_block_is_an_error(self):
        """If upstream reformats, fail at bake time rather than half-applying."""
        _, status = patch_mod.patch_text("FROM debian:13\n")
        assert status not in ("applied", "already")
        assert "found 0" in status

    def test_two_occurrences_are_an_error(self):
        doubled = UPSTREAM_EXCERPT + "\n" + UPSTREAM_EXCERPT
        _, status = patch_mod.patch_text(doubled)
        assert status not in ("applied", "already")
        assert "found 2" in status

    def test_main_reports_a_missing_checkout(self, tmp_path):
        assert patch_mod.main(["prog", str(tmp_path)]) == 1

    def test_main_rejects_wrong_arity(self):
        assert patch_mod.main(["prog"]) == 2

    def test_main_patches_a_real_tree(self, tmp_path):
        tpl = tmp_path / "templates" / "debian"
        tpl.mkdir(parents=True)
        target = tpl / "Dockerfile.compile.template"
        target.write_text(UPSTREAM_EXCERPT, encoding="utf-8")
        assert patch_mod.main(["prog", str(tmp_path)]) == 0
        assert SENTINEL in target.read_text(encoding="utf-8")
        # and again, unchanged
        assert patch_mod.main(["prog", str(tmp_path)]) == 0


class TestTheScriptStaysRenderable:
    """It is inlined into ``setup_sgx.sh``, which one caller renders with
    ``str.format()``; a bare brace there raises KeyError or mangles output."""

    def test_the_patch_script_has_no_braces_at_all(self):
        text = PATCH_PY.read_text(encoding="utf-8")
        offenders = [
            (text[:i].count("\n") + 1, text[max(0, i - 40):i + 40])
            for i, c in enumerate(text) if c in "{}"
        ]
        assert not offenders, (
            "braces found (no f-strings, dicts or sets, and none in the "
            "docstring either): %r" % offenders[:3])

    def test_the_placeholder_is_registered_in_the_loader(self):
        from tee_crafter.cli import loaders
        assert "__GSC_DEBIAN_PATCH_SCRIPT__" in loaders._INLINED_HELPERS

    def test_the_setup_script_still_references_the_placeholder(self):
        assert "__GSC_DEBIAN_PATCH_SCRIPT__" in SETUP_SH.read_text(encoding="utf-8")


class TestTheRenderedSetupScriptCarriesThePatch:
    @pytest.fixture(scope="class")
    def rendered(self):
        from tee_crafter.cli.commands.baking.common.helpers import load_setup_script
        return load_setup_script("sgx-azure")

    def test_the_placeholder_was_substituted(self, rendered):
        assert "__GSC_DEBIAN_PATCH_SCRIPT__" not in rendered

    def test_the_script_body_is_present(self, rendered):
        assert "def patch_text" in rendered
        assert patch_mod.OLD_BLOCK.splitlines()[-1] in rendered

    def test_the_heredoc_is_balanced(self, rendered):
        assert rendered.count("TEE_CRAFTER_GSC_PATCH_EOF") == 2

    def test_the_inlined_copy_is_byte_identical_to_the_source(self, rendered):
        marker = "TEE_CRAFTER_GSC_PATCH_EOF"
        body = rendered.split("<<'%s'\n" % marker, 1)[1].split(
            "\n%s" % marker, 1)[0]
        assert body == PATCH_PY.read_text(encoding="utf-8").rstrip("\n")

    def test_it_is_actually_invoked(self, rendered):
        """Match the interpreter and the on-VM path, not just the filename.

        The inlined script's own docstring ends with
        ``Usage: patch_gsc_debian_template.py /opt/gsc``, so a looser assertion
        passes on the documentation while the real invocation is broken -- which
        is exactly what a mutation of the calling line proved.
        """
        assert ('"$GSC_VENV/bin/python" '
                "/opt/tee-crafter-gsc/patch_gsc_debian_template.py "
                "/opt/gsc") in rendered

    def test_the_post_condition_is_asserted(self, rendered):
        """Surface it in cloud-init output, not 20 minutes later as a failed
        ``gsc build``."""
        assert SENTINEL in rendered
        assert "still uses apt-key" in rendered


class TestBothGscInstallSitesAgree:
    """GSC is installed twice -- CLI image and SGX VM -- from two files that
    cannot see each other.  Same reasoning as ``test_sgx_gsc_pin_parity``."""

    def test_the_dockerfile_runs_the_patch(self):
        assert ("python3.12 /opt/tee-crafter/patch_gsc_debian_template.py "
                "/opt/gsc") in DOCKERFILE.read_text(encoding="utf-8")

    def test_the_dockerfile_copies_the_patch_before_using_it(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        copy_at = text.index("COPY src/tee_crafter/scripts/sgx_azure/"
                             "patch_gsc_debian_template.py")
        run_at = text.index("patch_gsc_debian_template.py /opt/gsc")
        assert copy_at < run_at, (
            "the main `COPY src/ src/` lands after the GSC layer, so the patch "
            "needs its own earlier COPY")

    def test_the_dockerfile_asserts_the_post_condition(self):
        assert SENTINEL in DOCKERFILE.read_text(encoding="utf-8")

    def test_both_sites_check_the_same_sentinel(self):
        assert SENTINEL in SETUP_SH.read_text(encoding="utf-8")
        assert SENTINEL in DOCKERFILE.read_text(encoding="utf-8")
        assert SENTINEL == patch_mod.SENTINEL
