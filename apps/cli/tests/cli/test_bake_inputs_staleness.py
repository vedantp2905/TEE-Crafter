"""A baked image can be older than a fix that only applies at bake time.

``stale_image_check`` catches one version of this — the CLI image being older
than the checkout — and it is well covered elsewhere. It cannot catch this one:
a VM image is baked once and reused for weeks, so a change to something that is
*baked into* the image never reaches an existing image, and nothing in a deploy
says so.

The cost, on 2026-08-24: an ``sgx-azure --batch`` deploy died with Gramine unable
to mount its root filesystem, because AppArmor denied ``open("/")``. The fix
(``/ rwlkmix,`` in ``apparmor-batch-container``) was already committed to the
working tree *and* already covered by a test — but the image being deployed had
been baked hours before it landed. The symptom named a Gramine mount, so it read
as a fresh regression in the enclave manifest rather than a stale image.

The distinction that makes this tractable: ``templates/common/*.py`` and the
Terraform templates are re-rendered and re-uploaded on **every** deploy, so they
cannot go stale. The security profiles, systemd units and setup scripts are
substituted into a script that runs **once**, at bake. Hashing that rendered
script therefore covers exactly the inputs that can go stale, and nothing else.
"""
from __future__ import annotations

import pytest

from tee_crafter.cli.loaders import bake_inputs_digest

PLATFORMS = [
    "nitro-aws", "sgx-azure", "tdx-azure", "snp-aws", "snp-azure",
    "snp-gcp", "tdx-gcp", "gpu-cc-aws", "gpu-cc-gcp", "gpu-cc-azure",
]


class TestTheDigestCoversWhatItClaimsTo:

    @pytest.mark.parametrize("platform", PLATFORMS)
    def test_every_platform_produces_a_digest(self, platform):
        digest = bake_inputs_digest(platform)
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)

    def test_an_unknown_platform_is_empty_not_an_error(self):
        """A diagnostic must not be able to fail a bake."""
        assert bake_inputs_digest("not-a-platform") == ""
        assert bake_inputs_digest("") == ""

    def test_platforms_do_not_share_a_digest(self):
        """Each platform bakes a different script; a shared digest would mean
        the loader table is wired to the wrong file somewhere."""
        seen = {}
        for platform in PLATFORMS:
            digest = bake_inputs_digest(platform)
            assert digest not in seen, (
                f"{platform} and {seen[digest]} hash identically")
            seen[digest] = platform

    def test_it_is_stable_across_calls(self):
        assert bake_inputs_digest("snp-aws") == bake_inputs_digest("snp-aws")

    @pytest.mark.parametrize("platform", ["sgx-azure", "snp-aws", "snp-gcp"])
    def test_the_apparmor_profile_is_inside_the_digest(self, platform,
                                                       monkeypatch):
        """The regression that motivated this. Editing the batch AppArmor
        profile must move the digest, or a deploy could never notice that an
        image predates the fix."""
        import tee_crafter.cli.loaders as loaders

        before = bake_inputs_digest(platform)
        real = loaders._inject_security_profiles

        def tampered(content: str) -> str:
            return real(content).replace("/ rwlkmix,", "# removed for test")

        monkeypatch.setattr(loaders, "_inject_security_profiles", tampered)
        assert bake_inputs_digest(platform) != before

    def test_a_systemd_unit_change_is_inside_the_digest(self, monkeypatch):
        """Units are baked in too — the batch unit's docker run flags are the
        reason /input is mounted at all."""
        import tee_crafter.cli.loaders as loaders

        before = bake_inputs_digest("snp-aws")
        real = loaders._inject_systemd_units

        def tampered(content, platform, **kw):
            return real(content, platform, **kw) + "\n# tampered\n"

        monkeypatch.setattr(loaders, "_inject_systemd_units", tampered)
        assert bake_inputs_digest("snp-aws") != before


class TestTheDeployWarning:

    @staticmethod
    def _run(stored_digest, platform="snp-aws"):
        from tee_crafter.cli.commands.deploy.deploy_container import (
            _warn_if_image_predates_bake_inputs,
        )

        class _Console:
            def __init__(self):
                self.text = ""

            def print(self, msg):
                self.text += str(msg) + "\n"

        class _Registry:
            @staticmethod
            def lookup(_platform, _image):
                if stored_digest is None:
                    return None
                return {"bake_inputs_sha256": stored_digest}

        console = _Console()
        fired = _warn_if_image_predates_bake_inputs(
            console, platform, "img-1", _Registry())
        return fired, console.text

    def test_it_warns_when_the_digest_differs(self):
        fired, text = self._run("0" * 64)
        assert fired is True
        assert "re-bake" in text.lower() or "bake-ami" in text

    def test_it_is_silent_when_the_digest_matches(self):
        fired, _ = self._run(bake_inputs_digest("snp-aws"))
        assert fired is False

    def test_it_is_silent_when_nothing_was_stored(self):
        """Records predating this feature carry no digest. "Unknown" is not
        "stale", and warning on every old record would train operators to
        ignore the warning that matters."""
        fired, _ = self._run(None)
        assert fired is False
        fired, _ = self._run("")
        assert fired is False

    def test_it_is_silent_for_a_platform_with_no_bake_script(self):
        fired, _ = self._run("0" * 64, platform="not-a-platform")
        assert fired is False

    def test_the_warning_names_what_does_and_does_not_refresh(self):
        """An operator has to be able to tell why some fixes need a re-bake and
        others do not, or the advice is just noise."""
        _, text = self._run("0" * 64)
        assert "deploy-time" in text.lower()
        assert "apparmor" in text.lower() or "seccomp" in text.lower()

    def test_it_does_not_block_the_deploy(self):
        """Deliberately a warning: an older image is often the vetted baseline
        you meant to deploy."""
        fired, text = self._run("0" * 64)
        assert fired is True
        assert "harmless" in text.lower()
