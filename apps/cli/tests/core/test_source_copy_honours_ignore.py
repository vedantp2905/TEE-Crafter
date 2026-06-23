"""`_IGNORE` must apply to top-level files, not only to nested ones.

Found by ``PKG-005`` on a real ``snp-gcp`` deploy (2026-08-21): the check
"No .env / no secrets in build context" failed with ``flagged=['.env']``.

``_copy_source`` built a ``shutil.ignore_patterns`` matcher and passed it to
``copytree`` — which only sees files *inside subdirectories*.  Top-level entries
went through a bare ``shutil.copy2`` that never consulted it, so a ``.env``
sitting beside the Dockerfile was copied into the build context and baked into
the measured image.  ``.env`` is in ``_IGNORE`` precisely to stop that; secrets
are meant to travel via ``--secrets-env``, which seals them to the BYOK key and
delivers them at runtime.

The detector was right and the copier was wrong, which is the useful shape here:
a passing pipeline with a failing audit row meant the row was doing its job.
"""

import inspect
import os

import pytest

from tee_crafter.core.builder import builder as builder_mod
from tee_crafter.core.builder.platforms import _copy_source
from tee_crafter.core.builder.runtime_modules import SOURCE_IGNORE as _IGNORE
from tee_crafter.core.builder.runtime_modules import copy_source_tree


def _tree(root):
    out = set()
    for dirpath, _dirs, files in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        for f in files:
            out.add(f if rel == "." else os.path.join(rel, f))
    return out


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src"
    (d / "sub").mkdir(parents=True)
    (d / "Dockerfile").write_text("FROM scratch\n")
    (d / "app.py").write_text("x = 1\n")
    (d / ".env").write_text("API_TOKEN=shhh\n")
    (d / "stale.pyc").write_bytes(b"\x00")
    (d / "sub" / "nested.py").write_text("y = 2\n")
    (d / "sub" / ".env").write_text("NESTED=shhh\n")
    return d


class TestTopLevelIgnores:
    def test_top_level_env_is_not_copied(self, src, tmp_path):
        dst = tmp_path / "app"
        dst.mkdir()
        _copy_source(str(src), str(dst))
        assert ".env" not in _tree(dst), (
            "a .env beside the Dockerfile reaches the measured image")

    def test_top_level_pyc_is_not_copied(self, src, tmp_path):
        """Same bug, same blast radius: `*.pyc` is in _IGNORE too."""
        dst = tmp_path / "app"
        dst.mkdir()
        _copy_source(str(src), str(dst))
        assert "stale.pyc" not in _tree(dst)

    def test_nested_env_still_excluded(self, src, tmp_path):
        """The case that already worked must keep working."""
        dst = tmp_path / "app"
        dst.mkdir()
        _copy_source(str(src), str(dst))
        assert os.path.join("sub", ".env") not in _tree(dst)

    def test_real_sources_are_still_copied(self, src, tmp_path):
        """An over-broad ignore would silently ship an empty build context."""
        dst = tmp_path / "app"
        dst.mkdir()
        _copy_source(str(src), str(dst))
        got = _tree(dst)
        assert "Dockerfile" in got
        assert "app.py" in got
        assert os.path.join("sub", "nested.py") in got

    def test_env_is_actually_in_the_ignore_list(self):
        """Pins the intent the copier now implements."""
        assert ".env" in _IGNORE

    def test_container_flow_uses_the_same_copier(self):
        """The reason the first fix did not work.

        Only ``platforms._copy_source`` was corrected, but a container deploy
        stages its source through ``builder.py``, which carried four more
        hand-rolled copies of the same loop.  PKG-005 kept reporting
        ``flagged=['.env']`` on the next real deploy.  One implementation now.
        """
        src = inspect.getsource(builder_mod)
        assert "copy_source_tree(" in src, "builder.py must use the shared copier"
        assert "for item in os.listdir(source_dir)" not in src, (
            "builder.py still hand-rolls a source copy loop")

    def test_platforms_delegates_rather_than_duplicating(self):
        src = inspect.getsource(_copy_source)
        assert "copy_source_tree" in src
        assert "shutil.copy2" not in src

    def test_shared_copier_excludes_top_level_env(self, src, tmp_path):
        """Exercise the canonical entry point directly, not just the wrapper."""
        dst = tmp_path / "direct"
        dst.mkdir()
        copy_source_tree(str(src), str(dst))
        assert ".env" not in _tree(dst)
        assert "Dockerfile" in _tree(dst)

    def test_ignored_dirs_are_skipped_at_top_level(self, tmp_path):
        d = tmp_path / "src"
        (d / "venv" / "lib").mkdir(parents=True)
        (d / "venv" / "lib" / "junk.py").write_text("j = 1\n")
        (d / "node_modules").mkdir()
        (d / "node_modules" / "pkg.js").write_text("//\n")
        (d / "keep.py").write_text("k = 1\n")
        dst = tmp_path / "app"
        dst.mkdir()
        _copy_source(str(d), str(dst))
        got = _tree(dst)
        assert "keep.py" in got
        assert not any(p.startswith("venv") for p in got)
        assert not any(p.startswith("node_modules") for p in got)
