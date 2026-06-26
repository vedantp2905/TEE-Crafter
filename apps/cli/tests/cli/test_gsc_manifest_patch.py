"""The batch I/O paths are declared between ``gsc build`` and ``gsc sign-image``.

Why that seam and not the manifest fragment: ``gsc build`` finalizes the
manifest, and its finalizer demands that every path named in the *fragment*
exist in the image at build time and then measures it (see
test_sgx_batch_enclave_prereqs).  ``/input`` is a run-time bind mount, so it can
never satisfy that.  ``gsc sign-image`` only runs ``gramine-sgx-sign`` over
whatever manifest it finds (templates/Dockerfile.common.sign.template) -- it does
not re-run the finalizer -- so a declaration inserted in between survives *and*
is covered by MRENCLAVE.

Proven end to end on real SGX hardware (tee-crafter-sgx-vm-79dba104, 2026-08-23):
``gsc build`` on a fragment naming no host path, this patch, then
``gsc sign-image``, then a run with the genuine read-only bind mount::

    A /input
    C /output
    A /output/results.json      <- docker diff, i.e. the batch capture path
    txns: 3

The same run prints Gramine's ``insecure configurations`` banner for
``sgx.allowed_files``, which is accurate and is surfaced to the operator rather
than hidden; see :mod:`tee_crafter.cli.deployment.sgx.gsc`.
"""
from __future__ import annotations

import re
import tomllib

import pytest

from tee_crafter.cli.deployment.sgx.gsc import (
    BATCH_ALLOWED_PATHS,
    gsc_unsigned_image_name,
    manifest_patch_dockerfile,
)


IMAGE = "gsc-tee-crafter:latest-unsigned"


def _run_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if line.startswith("RUN "):
            return line
    raise AssertionError(f"no RUN line in:\n{dockerfile}")


def _sed_payload(dockerfile: str) -> str:
    """The text the ``sed`` append actually inserts into the manifest."""
    m = re.search(r"sed -i '1a ([^']+)'", _run_line(dockerfile))
    assert m, _run_line(dockerfile)
    return m.group(1)


class TestTheInsertedTomlIsValid:
    """The whole point of returning a Dockerfile rather than a shell string.

    An earlier version built this as nested shell quoting and the inner double
    quotes collapsed, yielding ``allowed_files = [ file:/input, file:/output ]``
    -- valid shell, invalid TOML, and it would have been signed.  Caught by
    reading the rendered command before running it, not by a test, which is why
    there is now a test.
    """

    def test_the_payload_parses_as_toml(self):
        payload = _sed_payload(manifest_patch_dockerfile(IMAGE))
        doc = tomllib.loads(payload)
        assert doc["allowed_files"] == list(BATCH_ALLOWED_PATHS)

    def test_the_paths_keep_their_double_quotes(self):
        payload = _sed_payload(manifest_patch_dockerfile(IMAGE))
        for path in BATCH_ALLOWED_PATHS:
            assert f'"{path}"' in payload, payload

    def test_it_lands_under_the_sgx_table(self):
        """Appending after line 1 puts the key in ``[sgx]``.

        tomli_w writes the table header first, then scalar keys, then the
        ``[[sgx.trusted_files]]`` tables -- so line 1 is ``[sgx]`` and line 2 is
        inside it.  Appended anywhere past the first ``[[sgx.trusted_files]]``
        header it would parse as a key of that table instead: valid TOML,
        silently no allowed_files at all.
        """
        assert "sed -i '1a " in _run_line(manifest_patch_dockerfile(IMAGE))

    def test_both_input_and_output_are_declared(self):
        """Output too, not just input.

        Baking the input into the image made ``/input`` work on hardware and the
        run still died on ``cannot create /output/results.json: Permission
        denied`` -- Gramine denies creating an undeclared file just as it denies
        reading one.
        """
        assert set(BATCH_ALLOWED_PATHS) == {"file:/input", "file:/output"}


class TestItRefusesToCorruptAManifest:

    def test_the_insert_is_guarded_on_the_first_line(self):
        """A GSC layout change must fail the build, not sign bad TOML."""
        run = _run_line(manifest_patch_dockerfile(IMAGE))
        assert "head -1" in run
        assert r"grep -qx '\[sgx\]'" in run

    def test_the_result_is_verified_before_the_layer_commits(self):
        run = _run_line(manifest_patch_dockerfile(IMAGE))
        assert "grep -q '^allowed_files'" in run

    def test_the_guard_precedes_the_edit(self):
        run = _run_line(manifest_patch_dockerfile(IMAGE))
        assert run.index("head -1") < run.index("sed -i")


class TestItDoesNotPromoteTheWorkloadToRoot:
    """``USER root`` is needed to edit the manifest and must not survive.

    The sign stage is ``FROM <unsigned>`` and copies only the signature back, so
    a ``USER root`` left in this layer would silently become the *signed*
    image's user.
    """

    def test_a_non_root_user_is_restored(self):
        df = manifest_patch_dockerfile(IMAGE, "appuser")
        assert df.rstrip().endswith("USER appuser")

    def test_root_is_used_only_for_the_edit(self):
        df = manifest_patch_dockerfile(IMAGE, "appuser")
        assert df.index("USER root") < df.index("RUN ")
        assert df.index("RUN ") < df.index("USER appuser")

    @pytest.mark.parametrize("user", ["", "   ", "\n"])
    def test_no_user_line_is_appended_when_the_image_has_none(self, user):
        """An empty ``Config.User`` means root already; ``USER`` would be noise.

        Left as-is rather than defaulting to something: ``docker inspect -f
        '{{.Config.User}}'`` prints an empty line for such an image, and that
        empty string is what reaches this function.
        """
        df = manifest_patch_dockerfile(IMAGE, user)
        assert df.count("USER ") == 1, df
        assert "USER root" in df

    def test_the_from_names_the_unsigned_image(self):
        df = manifest_patch_dockerfile(gsc_unsigned_image_name("tee-crafter:latest"))
        assert df.startswith("FROM gsc-tee-crafter:latest-unsigned\n")
