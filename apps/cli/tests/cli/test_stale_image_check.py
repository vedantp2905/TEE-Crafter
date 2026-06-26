"""The guard against "verified on hardware" being said about the wrong code.

Context in ``cli/stale_image_check``: the CLI image carries its own copy of the
source, so local edits do not affect a deploy until ``make docker-build-cli``.
On 2026-08-23 that silently invalidated two live SEV-SNP runs — both passed,
with the old code consistently on both sides of the channel, which is
indistinguishable from success.
"""
from __future__ import annotations

import pytest

from tee_crafter.cli import stale_image_check as sic


def _tree(root, files):
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return str(root)


@pytest.fixture(autouse=True)
def _in_docker(monkeypatch):
    monkeypatch.setenv(sic.IN_DOCKER_ENV, "1")
    monkeypatch.delenv(sic.SKIP_ENV, raising=False)


def _point_at(monkeypatch, image, workspace):
    monkeypatch.setattr(sic, "IMAGE_SRC", image)
    monkeypatch.setattr(sic, "WORKSPACE_SRC", workspace)


def test_identical_trees_are_silent(tmp_path, monkeypatch):
    files = {"a.py": "x = 1\n", "t/b.tf": "resource {}\n"}
    _point_at(monkeypatch,
              _tree(tmp_path / "img", files), _tree(tmp_path / "ws", files))
    assert sic.stale_image_warning() == ""


def test_a_changed_python_file_is_reported(tmp_path, monkeypatch):
    _point_at(monkeypatch,
              _tree(tmp_path / "img", {"a.py": "old\n"}),
              _tree(tmp_path / "ws", {"a.py": "new\n"}))
    w = sic.stale_image_warning()
    assert "make docker-build-cli" in w
    assert "different source tree" in w


@pytest.mark.parametrize("rel", [
    "templates/x.template", "scripts/s.sh", "templates/m.tf",
    "resources/u.service", "x.json", "y.toml", "z.rules",
])
def test_every_behaviour_bearing_file_type_counts(tmp_path, monkeypatch, rel):
    """Templates, scripts and Terraform are read at run time.

    That makes them the *most* likely thing to be edited without a rebuild —
    nothing about editing a file the deploy reads suggests one is needed.
    """
    _point_at(monkeypatch,
              _tree(tmp_path / "img", {rel: "old\n"}),
              _tree(tmp_path / "ws", {rel: "new\n"}))
    assert sic.stale_image_warning() != "", rel


def test_tests_and_pycache_are_ignored(tmp_path, monkeypatch):
    """Editing a test does not change what a deploy does."""
    _point_at(monkeypatch,
              _tree(tmp_path / "img",
                    {"a.py": "same\n", "tests/t.py": "old\n",
                     "__pycache__/a.pyc": "old\n"}),
              _tree(tmp_path / "ws",
                    {"a.py": "same\n", "tests/t.py": "new\n",
                     "__pycache__/a.pyc": "new\n"}))
    assert sic.stale_image_warning() == ""


def test_a_new_file_in_the_checkout_is_reported(tmp_path, monkeypatch):
    """The `azure_guest_attestation.sh` case: present locally, absent in image."""
    _point_at(monkeypatch,
              _tree(tmp_path / "img", {"a.py": "same\n"}),
              _tree(tmp_path / "ws",
                    {"a.py": "same\n", "scripts/common/new.sh": "echo hi\n"}))
    assert sic.stale_image_warning() != ""


def test_outside_docker_there_is_nothing_to_compare(tmp_path, monkeypatch):
    monkeypatch.delenv(sic.IN_DOCKER_ENV, raising=False)
    _point_at(monkeypatch,
              _tree(tmp_path / "img", {"a.py": "old\n"}),
              _tree(tmp_path / "ws", {"a.py": "new\n"}))
    assert sic.stale_image_warning() == ""


def test_no_mount_is_silent(tmp_path, monkeypatch):
    """A published image with no checkout mounted is a normal way to run."""
    _point_at(monkeypatch, _tree(tmp_path / "img", {"a.py": "x\n"}),
              str(tmp_path / "does-not-exist"))
    assert sic.stale_image_warning() == ""


def test_the_escape_hatch_works(tmp_path, monkeypatch):
    monkeypatch.setenv(sic.SKIP_ENV, "1")
    _point_at(monkeypatch,
              _tree(tmp_path / "img", {"a.py": "old\n"}),
              _tree(tmp_path / "ws", {"a.py": "new\n"}))
    assert sic.stale_image_warning() == ""


def test_the_deploy_command_calls_it_before_building(tmp_path):
    """Placement matters: after the build it would be a post-mortem."""
    import inspect

    from tee_crafter.cli.commands.deploy import deploy_container

    src = inspect.getsource(deploy_container)
    assert "stale_image_warning()" in src
    # The container build itself lives in flow_container.run_container_phases;
    # the warning has to come before that call, or it is a post-mortem.
    assert src.index("stale_image_warning()") < src.index(
        "run_container_phases("), "warning must precede the container build"
