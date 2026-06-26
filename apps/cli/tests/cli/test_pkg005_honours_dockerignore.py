"""PKG-005 must be satisfiable by the correct fix: a `.dockerignore`.

PKG-005 ("No .env / no secrets in build context", HIGH) checks the *source*
directory, because that is what `docker build` receives as its context.  It
originally checked only whether the file existed — so the correct remedy, a
`.dockerignore` that provably keeps the file out of the context, still failed
the gate.  Observed across four real GCP deploys on 2026-08-21: the example
ships a `.env` for `--secrets-env` (which seals it to the BYOK key and delivers
it at runtime), and PKG-005 flagged it every time with no way to clear it short
of deleting a file the example needs.

An unsatisfiable gate is one people learn to skip — the same argument that
reshaped the vulnerability gate around *fixable* findings.  `.dockerignore` is
sound to honour: Docker never sends an excluded path to the daemon, so no COPY
can place it in the image.

A file that is present and *not* excluded is still flagged. That is the case
that matters, and the parametrised tests below pin both directions.
"""

import pathlib

from tee_crafter.cli.commands.deploy.flow_container import _dockerignore_patterns

#: Repo root, resolved from this file rather than the CWD.  `examples/` sits at
#: the root while `pyproject.toml`'s `testpaths` points at `apps/cli/tests`, so a
#: relative "examples/..." resolved fine from the repo root and yielded an empty
#: pattern list — a spurious failure — when pytest was run from `apps/cli`, which
#: is where the config that configures it lives.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]


class TestPatternParsing:
    def test_absent_file_yields_no_patterns(self, tmp_path):
        assert _dockerignore_patterns(str(tmp_path)) == ()

    def test_comments_and_blanks_are_dropped(self, tmp_path):
        (tmp_path / ".dockerignore").write_text(
            "# a comment\n\n.env\n\n  \n*.pem\n")
        assert _dockerignore_patterns(str(tmp_path)) == (".env", "*.pem")

    def test_negations_are_not_treated_as_excludes(self, tmp_path):
        """`!x` re-includes in Docker, so it must never mark x as shielded."""
        (tmp_path / ".dockerignore").write_text(".env\n!.env\n")
        assert _dockerignore_patterns(str(tmp_path)) == (".env",)

    def test_trailing_slash_is_stripped(self, tmp_path):
        (tmp_path / ".dockerignore").write_text("__pycache__/\nvenv/\n")
        assert _dockerignore_patterns(str(tmp_path)) == ("__pycache__", "venv")

    def test_unreadable_file_is_not_fatal(self, tmp_path):
        d = tmp_path / ".dockerignore"
        d.mkdir()          # a directory where a file is expected
        assert _dockerignore_patterns(str(tmp_path)) == ()


class TestVerdict:
    """Drive the recorded verdict through a minimal audit double."""

    def _run(self, tmp_path, files, dockerignore=None):
        import fnmatch
        import os
        for name in files:
            (tmp_path / name).write_text("SECRET=1\n")
        if dockerignore is not None:
            (tmp_path / ".dockerignore").write_text(dockerignore)
        # Mirror of the check body in flow_container; kept in step by
        # test_matches_the_shipped_logic below.
        excluded = _dockerignore_patterns(str(tmp_path))
        sensitive, shielded = [], []
        for name in (".env", ".env.local", "credentials.json", "id_rsa", "id_ed25519"):
            if not os.path.isfile(os.path.join(str(tmp_path), name)):
                continue
            if any(fnmatch.fnmatch(name, pat) for pat in excluded):
                shielded.append(name)
            else:
                sensitive.append(name)
        return sensitive, shielded

    def test_env_without_dockerignore_is_flagged(self, tmp_path):
        sensitive, shielded = self._run(tmp_path, [".env"])
        assert sensitive == [".env"] and shielded == []

    def test_env_with_dockerignore_is_shielded(self, tmp_path):
        sensitive, shielded = self._run(tmp_path, [".env"], dockerignore=".env\n")
        assert sensitive == [] and shielded == [".env"]

    def test_glob_pattern_shields(self, tmp_path):
        sensitive, shielded = self._run(tmp_path, [".env"], dockerignore=".env*\n")
        assert sensitive == [] and shielded == [".env"]

    def test_unrelated_pattern_does_not_shield(self, tmp_path):
        """The dangerous false negative: a .dockerignore that misses the file."""
        sensitive, shielded = self._run(
            tmp_path, [".env"], dockerignore="*.pyc\nnode_modules\n")
        assert sensitive == [".env"] and shielded == []

    def test_partial_shield_still_flags_the_rest(self, tmp_path):
        sensitive, shielded = self._run(
            tmp_path, [".env", "id_rsa"], dockerignore=".env\n")
        assert sensitive == ["id_rsa"] and shielded == [".env"]

    def test_clean_dir_is_clean(self, tmp_path):
        sensitive, shielded = self._run(tmp_path, [])
        assert sensitive == [] and shielded == []


class TestShippedExampleIsClean:
    def test_example_dockerignore_excludes_its_env(self):
        """The example ships a .env on purpose; it must not reach the image."""
        import fnmatch
        pats = _dockerignore_patterns(str(_REPO_ROOT / "examples" / "docker_flask_api"))
        assert any(fnmatch.fnmatch(".env", p) for p in pats), (
            f"examples/docker_flask_api/.dockerignore does not exclude .env: {pats}")

    def test_matches_the_shipped_logic(self):
        """Guard against this test file drifting from the real check."""
        import inspect
        from tee_crafter.cli.commands.deploy import flow_container
        src = inspect.getsource(flow_container)
        body = src[src.index("# PKG-005"):src.index("# -- Step 1b")]
        assert "_dockerignore_patterns(source_path)" in body
        assert "fnmatch.fnmatch(name, pat)" in body
        # The verdict must still be driven by `sensitive`, not by `shielded`.
        assert "observed=(len(sensitive) == 0)" in body
