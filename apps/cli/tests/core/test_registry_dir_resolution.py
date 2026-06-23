"""How the measurement registry root resolves.

``TEE_CRAFTER_MEASUREMENTS_DIR`` used to be read once, at module import, into a
module-level constant.  Anything that set the variable *after* the first import
of ``tee_crafter.core.measurements.registry`` was silently ignored.  Production
never hit it because the Docker wrapper exports the variable with
``docker run -e`` before the interpreter starts, but the consequence for anyone
else was quiet and bad: a bake writes pins to one directory while deploy reads
another, and a missing pin is what makes sealed-``.env`` / BYOK fail closed.

The precedence assertion matters as much as the laziness one.  Twenty-six test
sites redirect the registry by assigning ``registry._REGISTRY_DIR`` a tmpdir.
Those tests must keep passing on a developer machine that exports
``TEE_CRAFTER_MEASUREMENTS_DIR`` for its own reasons -- if the environment
outranked the explicit assignment, that export would silently point every one
of them at the real packaged registry, and a test that *writes* would edit
checked-in pin records.
"""
from __future__ import annotations

import os

import pytest

from tee_crafter.core.measurements import registry


@pytest.fixture(autouse=True)
def _neutral_env(monkeypatch):
    """Start every case from "no override of either kind"."""
    monkeypatch.delenv("TEE_CRAFTER_MEASUREMENTS_DIR", raising=False)
    monkeypatch.setattr(registry, "_REGISTRY_DIR", None)


def test_unset_falls_back_to_the_packaged_directory():
    assert registry.registry_dir() == registry._PACKAGED_REGISTRY_DIR


def test_the_packaged_directory_is_the_one_inside_the_package():
    """Guards the three dirname() hops in _PACKAGED_REGISTRY_DIR.

    registry.py lives at tee_crafter/core/measurements/registry.py, so the
    default has to climb three levels to reach tee_crafter/ before appending
    'measurements'.  An extra or missing hop still yields a plausible-looking
    absolute path, which is exactly the kind of mistake a test should catch.
    """
    resolved = registry._PACKAGED_REGISTRY_DIR
    parent = os.path.dirname(resolved)

    assert os.path.basename(resolved) == "measurements"
    # The parent must be the package root itself, not core/ or core/measurements/.
    assert os.path.basename(parent) == "tee_crafter"
    assert os.path.isdir(os.path.join(parent, "core")), (
        f"{parent} does not look like the tee_crafter package root")
    assert os.sep + os.path.join("core", "measurements") not in resolved


def test_the_env_var_is_honoured_when_set_after_import(monkeypatch, tmp_path):
    """The regression this module exists for."""
    monkeypatch.setenv("TEE_CRAFTER_MEASUREMENTS_DIR", str(tmp_path))
    assert registry.registry_dir() == str(tmp_path)


def test_the_env_var_is_re_read_on_every_call(monkeypatch, tmp_path):
    """Not merely cached on first call -- two different values in one process."""
    first, second = tmp_path / "a", tmp_path / "b"
    monkeypatch.setenv("TEE_CRAFTER_MEASUREMENTS_DIR", str(first))
    assert registry.registry_dir() == str(first)
    monkeypatch.setenv("TEE_CRAFTER_MEASUREMENTS_DIR", str(second))
    assert registry.registry_dir() == str(second)


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_a_blank_env_var_falls_back_rather_than_resolving_to_cwd(monkeypatch,
                                                                blank):
    """A blank export must not make the registry relative to the CWD."""
    monkeypatch.setenv("TEE_CRAFTER_MEASUREMENTS_DIR", blank)
    resolved = registry.registry_dir()
    assert resolved == registry._PACKAGED_REGISTRY_DIR
    assert os.path.isabs(resolved)


def test_an_explicit_assignment_outranks_the_env_var(monkeypatch, tmp_path):
    """The guard that keeps the other 26 redirect sites hermetic."""
    explicit, from_env = tmp_path / "explicit", tmp_path / "from_env"
    monkeypatch.setenv("TEE_CRAFTER_MEASUREMENTS_DIR", str(from_env))
    monkeypatch.setattr(registry, "_REGISTRY_DIR", str(explicit))
    assert registry.registry_dir() == str(explicit)


def test_record_paths_follow_the_resolved_root(monkeypatch, tmp_path):
    """Resolution has to reach the callers, not just registry_dir()."""
    monkeypatch.setenv("TEE_CRAFTER_MEASUREMENTS_DIR", str(tmp_path))
    path = registry._path("snp-aws", "ami-0123")
    assert path == os.path.join(str(tmp_path), "snp-aws", "ami-0123.json")


def test_listing_follows_the_resolved_root(monkeypatch, tmp_path):
    """records_for_platform() reads the same root, and an absent one is empty."""
    monkeypatch.setenv("TEE_CRAFTER_MEASUREMENTS_DIR", str(tmp_path))
    assert registry.records_for_platform("snp-aws") == []

    directory = tmp_path / "snp-aws"
    directory.mkdir()
    (directory / "ami-1.json").write_text(
        '{"platform": "snp-aws", "image_id": "ami-1", "measurement": "ab"}',
        encoding="utf-8")
    records = registry.records_for_platform("snp-aws")
    assert [r["image_id"] for r in records] == ["ami-1"]
