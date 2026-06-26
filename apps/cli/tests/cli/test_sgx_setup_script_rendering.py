"""``setup_sgx.sh`` has exactly one correct way to be rendered, and it had two.

The script writes every literal shell brace doubled so that a caller *could*
render it with ``str.format()``.  The bake path undid the doubling with
``.replace("{{", "{")``; ``core.builder.platforms.render_sgx_setup_script``
instead called ``.format(aws_region=..., enclave_size=...)`` on the same text.
That second path could never work — the assembled script carries 49 unescaped
braces (an ``awk '{print $1}'``, the injected seccomp JSON, the AppArmor
profiles, the ``docker image ls --format`` line) — so it raised
``KeyError: 'print $1'`` for as long as it existed.

Nothing caught it because the path is unreachable: ``sgx-azure`` is batch-only,
``--batch`` returns before ``run_sgx_deployment_phase``, and ``--persistent`` is
refused at parse time.  It was a loaded gun for whoever re-enables persistent
SGX, which is exactly the kind of thing a test should hold rather than a
comment.

Both substitution parameters were also vestigial: ``aws_region`` and
``enclave_size`` appear in ``setup_sgx.sh`` only inside its header comment, so
the "rendering" never substituted anything even in principle.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[4]
SETUP_SH = (REPO / "apps" / "cli" / "src" / "tee_crafter" / "scripts"
            / "sgx_azure" / "setup_sgx.sh")


def _rendered() -> str:
    from tee_crafter.cli.loaders import render_sgx_setup_script
    return render_sgx_setup_script()


class TestEveryCallerRendersItTheSameWay:
    """Three entry points, one result — that is the whole point of the fix."""

    def test_core_builder_matches_the_loader(self):
        from tee_crafter.core.builder.platforms import render_sgx_setup_script
        assert render_sgx_setup_script() == _rendered()

    def test_the_bake_path_matches_the_loader(self):
        from tee_crafter.cli.commands.baking.common.helpers import load_setup_script
        assert load_setup_script("sgx-azure") == _rendered()

    def test_the_deploy_path_no_longer_raises(self):
        """The actual regression: this used to be ``KeyError: 'print $1'``."""
        from tee_crafter.core.builder.platforms import render_sgx_setup_script
        assert len(render_sgx_setup_script()) > 1000


class TestTheRenderedScriptIsRunnable:
    def test_it_parses_as_bash(self):
        rendered = _rendered()
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                         encoding="utf-8") as handle:
            handle.write(rendered)
            path = handle.name
        result = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_the_awk_that_broke_format_survives_intact(self):
        """``sha256sum | awk '{print $1}'`` is the literal that raised KeyError."""
        assert "awk '{print $1}'" in _rendered()

    def test_the_docker_format_string_is_go_template_not_doubled(self):
        """Quad braces in source are the way to spell a literal ``{{`` here.

        ``docker image ls --format '{{.Repository}}'`` needs Go template braces
        to survive the un-doubling, so the source spells them ``{{{{``.  Getting
        this backwards produces a silently broken ``docker image ls``.
        """
        assert "{{{{.Repository}}}}" in SETUP_SH.read_text(encoding="utf-8")
        assert "{{.Repository}}:{{.Tag}}" in _rendered()

    def test_the_seccomp_json_still_parses(self):
        import json
        match = re.search(r"SECCOMP_EOF'\n(.*?)\nSECCOMP_EOF", _rendered(), re.S)
        assert match, "seccomp heredoc missing from the rendered script"
        assert json.loads(match.group(1))["defaultAction"]


class TestTheVestigialSubstitutionsAreGone:
    def test_the_renderer_takes_no_arguments(self):
        """A signature that accepts them invites a caller to believe they work."""
        import inspect

        from tee_crafter.core.builder.platforms import render_sgx_setup_script
        assert not inspect.signature(render_sgx_setup_script).parameters

    def test_the_script_declares_no_substitution_placeholders(self):
        """If someone adds one back, they must also add a substituting caller."""
        source = SETUP_SH.read_text(encoding="utf-8")
        for stale in ("{aws_region}", "{enclave_size}"):
            assert stale not in source

    def test_the_header_warns_against_a_format_caller(self):
        header = "\n".join(
            SETUP_SH.read_text(encoding="utf-8").splitlines()[:10])
        assert "do not add a str.format()" in header


class TestNoCallerReintroducesFormat:
    """A grep-level guard: ``.format()`` on this template is always a bug."""

    def test_no_source_file_formats_the_sgx_template(self):
        src = REPO / "apps" / "cli" / "src" / "tee_crafter"
        offenders = []
        for path in src.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            if re.search(r"load_sgx_setup_template\(\)\s*\.format\(", text):
                offenders.append(str(path.relative_to(REPO)))
        assert not offenders, (
            "setup_sgx.sh is full of literal shell braces; .format() on it "
            "raises KeyError. Use loaders.render_sgx_setup_script(). "
            f"Offenders: {offenders}")
