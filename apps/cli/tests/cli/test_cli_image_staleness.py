"""A reused CLI image must actually match the sources it claims to run.

``tee-crafter`` re-executes itself inside a Docker image built from ``apps/cli``.
The repository is **not** bind-mounted — the Python lives *in* the image — and
``_ensure_image`` returned as soon as the tag existed. So editing the CLI and
re-running ``deploy`` silently exercised the previous build.

This is not theoretical. On 2026-08-22 two ``sgx-azure`` deploys ran code that
had already been deleted from the tree, and the error they printed named a cause
that no longer existed, sending the investigation the wrong way twice. The
Dockerfile's own failure text ("means the image is stale — rebuild it") shows the
trap was known; nothing detected it.

The fix stamps a fingerprint of the sources as an image label at build time and
compares it before reuse. What these tests care about is that the fingerprint
answers the question it is used for:

* it must change when the *content* changes, and not when only mtimes do —
  mtime sensitivity would rebuild constantly and get switched off;
* it must ignore ``__pycache__``, which Python rewrites under the tree being
  hashed, for the same reason;
* an unreadable tree must yield ``""`` rather than the digest of zero files,
  because a stable-looking digest for "I could not look" is exactly the kind of
  clean-looking empty result this project has been bitten by before.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tee_crafter.cli import main as cli_main

REPO_CLI = Path(cli_main.__file__).resolve().parents[3]


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A throwaway copy of ``apps/cli`` (sources + Dockerfile only)."""
    dst = tmp_path / "cli"
    (dst / "src" / "tee_crafter").mkdir(parents=True)
    (dst / "src" / "tee_crafter" / "mod.py").write_text("x = 1\n")
    (dst / "Dockerfile").write_text("FROM scratch\n")
    return dst


class TestFingerprintSensitivity:
    def test_stable_across_calls(self, tree):
        assert cli_main._source_fingerprint(tree) == cli_main._source_fingerprint(tree)

    def test_content_change_is_detected(self, tree):
        before = cli_main._source_fingerprint(tree)
        p = tree / "src" / "tee_crafter" / "mod.py"
        p.write_text(p.read_text() + "# edit\n")
        assert cli_main._source_fingerprint(tree) != before

    def test_same_length_edit_is_detected(self, tree):
        """Length-preserving edits are the ones a size-based check would miss."""
        p = tree / "src" / "tee_crafter" / "mod.py"
        p.write_text("x = 1\n")
        before = cli_main._source_fingerprint(tree)
        p.write_text("x = 2\n")
        assert len(p.read_text()) == 6
        assert cli_main._source_fingerprint(tree) != before

    def test_dockerfile_change_is_detected(self, tree):
        before = cli_main._source_fingerprint(tree)
        (tree / "Dockerfile").write_text("FROM scratch\n# edit\n")
        assert cli_main._source_fingerprint(tree) != before

    def test_new_file_is_detected(self, tree):
        before = cli_main._source_fingerprint(tree)
        (tree / "src" / "tee_crafter" / "extra.py").write_text("y = 2\n")
        assert cli_main._source_fingerprint(tree) != before

    def test_deleted_file_is_detected(self, tree):
        (tree / "src" / "tee_crafter" / "extra.py").write_text("y = 2\n")
        before = cli_main._source_fingerprint(tree)
        (tree / "src" / "tee_crafter" / "extra.py").unlink()
        assert cli_main._source_fingerprint(tree) != before

    def test_rename_is_detected(self, tree):
        """The path is hashed too, so a pure rename must not be invisible."""
        p = tree / "src" / "tee_crafter" / "mod.py"
        before = cli_main._source_fingerprint(tree)
        p.rename(p.with_name("renamed.py"))
        assert cli_main._source_fingerprint(tree) != before


class TestFingerprintInsensitivity:
    def test_mtime_only_change_is_ignored(self, tree):
        before = cli_main._source_fingerprint(tree)
        os.utime(tree / "src" / "tee_crafter" / "mod.py", (0, 0))
        assert cli_main._source_fingerprint(tree) == before

    @pytest.mark.parametrize("name", ["mod.pyc", "mod.pyo"])
    def test_compiled_artifacts_are_ignored(self, tree, name):
        before = cli_main._source_fingerprint(tree)
        (tree / "src" / "tee_crafter" / name).write_bytes(b"junk")
        assert cli_main._source_fingerprint(tree) == before

    def test_pycache_is_ignored(self, tree):
        before = cli_main._source_fingerprint(tree)
        pc = tree / "src" / "tee_crafter" / "__pycache__"
        pc.mkdir()
        (pc / "mod.cpython-312.pyc").write_bytes(b"junk")
        assert cli_main._source_fingerprint(tree) == before


class TestUnreadableTreeIsUnknown:
    def test_missing_tree_returns_empty(self, tmp_path):
        assert cli_main._source_fingerprint(tmp_path / "nope") == ""

    def test_empty_tree_returns_empty(self, tmp_path):
        """Hashing zero files yields a stable digest; that must not pass for one."""
        (tmp_path / "cli").mkdir()
        assert cli_main._source_fingerprint(tmp_path / "cli") == ""

    def test_real_checkout_is_not_empty(self):
        """Guard the premise: the checks above only mean something if the real
        tree does produce a fingerprint."""
        fp = cli_main._source_fingerprint(REPO_CLI)
        assert fp and len(fp) == 16


class TestReuseDecision:
    """``_ensure_image`` must rebuild on a mismatch and reuse on a match."""

    def _wire(self, monkeypatch, *, exists: bool, image_fp: str, source_fp: str):
        calls: list[str] = []
        monkeypatch.setattr(cli_main, "_docker_image_exists", lambda i: exists)
        monkeypatch.setattr(cli_main, "_image_fingerprint", lambda i: image_fp)
        monkeypatch.setattr(cli_main, "_source_fingerprint", lambda r: source_fp)
        monkeypatch.setattr(cli_main, "_docker_pull",
                            lambda i: calls.append("pull") or False)
        monkeypatch.setattr(
            cli_main, "_docker_build",
            lambda *a, **k: calls.append("build"))
        monkeypatch.delenv(cli_main.SKIP_STALENESS_ENV, raising=False)
        return calls

    def test_matching_fingerprint_reuses(self, monkeypatch, tmp_path):
        calls = self._wire(monkeypatch, exists=True, image_fp="aaa", source_fp="aaa")
        cli_main._ensure_image("img", tmp_path)
        assert calls == []

    def test_mismatched_fingerprint_rebuilds(self, monkeypatch, tmp_path):
        calls = self._wire(monkeypatch, exists=True, image_fp="aaa", source_fp="bbb")
        cli_main._ensure_image("img", tmp_path)
        assert calls == ["build"], (
            "a stale image was reused; this is the bug the label exists to catch")

    def test_unlabelled_image_rebuilds_once(self, monkeypatch, tmp_path):
        calls = self._wire(monkeypatch, exists=True, image_fp="", source_fp="bbb")
        cli_main._ensure_image("img", tmp_path)
        assert calls == ["build"]

    def test_unknown_source_fingerprint_reuses(self, monkeypatch, tmp_path):
        """Cannot read the tree -> do not block the run on a check we can't make."""
        calls = self._wire(monkeypatch, exists=True, image_fp="aaa", source_fp="")
        cli_main._ensure_image("img", tmp_path)
        assert calls == []

    def test_skip_env_reuses_even_on_mismatch(self, monkeypatch, tmp_path):
        calls = self._wire(monkeypatch, exists=True, image_fp="aaa", source_fp="bbb")
        monkeypatch.setenv(cli_main.SKIP_STALENESS_ENV, "1")
        cli_main._ensure_image("img", tmp_path)
        assert calls == []

    def test_absent_image_still_pulls_then_builds(self, monkeypatch, tmp_path):
        calls = self._wire(monkeypatch, exists=False, image_fp="", source_fp="bbb")
        cli_main._ensure_image("img", tmp_path)
        assert calls == ["pull", "build"]


class TestBuildStampsTheLabel:
    def test_build_passes_the_label(self, monkeypatch, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch\n")
        seen: list[list[str]] = []

        class _Res:
            returncode = 0

        def fake_run(cmd, **kw):
            seen.append(list(cmd))
            return _Res()

        monkeypatch.setattr(cli_main.subprocess, "run", fake_run)
        monkeypatch.setattr(cli_main, "_source_fingerprint", lambda r: "deadbeefdeadbeef")
        cli_main._docker_build("img", tmp_path)
        assert seen, "no docker command issued"
        flat = " ".join(seen[0])
        assert cli_main.SOURCE_FINGERPRINT_LABEL in flat
        assert "deadbeefdeadbeef" in flat

    def test_no_label_when_fingerprint_unknown(self, monkeypatch, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch\n")
        seen: list[list[str]] = []

        class _Res:
            returncode = 0

        monkeypatch.setattr(cli_main.subprocess, "run",
                            lambda cmd, **kw: (seen.append(list(cmd)), _Res())[1])
        monkeypatch.setattr(cli_main, "_source_fingerprint", lambda r: "")
        cli_main._docker_build("img", tmp_path)
        assert cli_main.SOURCE_FINGERPRINT_LABEL not in " ".join(seen[0])
