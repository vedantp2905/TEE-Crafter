"""A build must not be staged without its in-TEE runtime modules.

``builder.py`` and ``platforms.py`` each kept their own copy of the module list
and their own copy loop, and both did ``if os.path.isfile(src): copy2(...)`` —
so a missing file was skipped in silence.  Two entries in that list are
enforcement boundaries (``siem_health.py``, ``byok_health.py``), and a build
staged without them serves requests with no SIEM freshness proof and no BYOK
release check while reporting success.

This mirrors the treatment ``platforms._load_trust_anchor`` already gives a
missing attestation trust anchor.
"""
from __future__ import annotations

import os

import pytest

from tee_crafter.core.builder import runtime_modules
from tee_crafter.core.builder.runtime_modules import (
    RUNTIME_MODULES,
    MissingRuntimeModule,
    copy_runtime_modules,
)


SECURITY_GATES = ("siem_health.py", "byok_health.py")


@pytest.fixture
def fake_common(tmp_path, monkeypatch):
    """A stand-in ``templates/common`` we can delete files from."""
    common = tmp_path / "common"
    common.mkdir()
    for name in RUNTIME_MODULES:
        (common / name).write_text(f"# {name}\n")
    monkeypatch.setattr(runtime_modules, "common_templates_dir", lambda: str(common))
    return common


class TestAllModulesPresent:
    def test_every_module_ships_with_the_package(self):
        base = runtime_modules.common_templates_dir()
        missing = [n for n in RUNTIME_MODULES
                   if not os.path.isfile(os.path.join(base, n))]
        assert missing == [], missing

    def test_copy_writes_every_module(self, tmp_path, fake_common):
        dest = tmp_path / "build"
        dest.mkdir()
        copy_runtime_modules(str(dest))
        assert sorted(p.name for p in dest.iterdir()) == sorted(RUNTIME_MODULES)

    def test_security_gates_are_in_the_list(self):
        for gate in SECURITY_GATES:
            assert gate in RUNTIME_MODULES

    def test_builder_and_platforms_share_one_list(self):
        """They used to be two hand-maintained tuples that could drift."""
        from tee_crafter.core.builder import builder, platforms
        assert builder._RUNTIME_MODULES is RUNTIME_MODULES
        assert platforms._RUNTIME_MODULES is RUNTIME_MODULES


class TestMissingModuleIsFatal:
    @pytest.mark.parametrize("gate", SECURITY_GATES)
    def test_missing_security_gate_raises(self, tmp_path, fake_common, gate):
        (fake_common / gate).unlink()
        dest = tmp_path / "build"
        dest.mkdir()
        with pytest.raises(MissingRuntimeModule) as exc:
            copy_runtime_modules(str(dest))
        assert gate in str(exc.value)
        assert "fail-closed" in str(exc.value)

    def test_missing_non_gate_module_also_raises(self, tmp_path, fake_common):
        (fake_common / "siem_export.py").unlink()
        dest = tmp_path / "build"
        dest.mkdir()
        with pytest.raises(MissingRuntimeModule) as exc:
            copy_runtime_modules(str(dest))
        assert "siem_export.py" in str(exc.value)

    def test_all_missing_names_reported_at_once(self, tmp_path, fake_common):
        for name in RUNTIME_MODULES[:3]:
            (fake_common / name).unlink()
        dest = tmp_path / "build"
        dest.mkdir()
        with pytest.raises(MissingRuntimeModule) as exc:
            copy_runtime_modules(str(dest))
        for name in RUNTIME_MODULES[:3]:
            assert name in str(exc.value)

    def test_error_names_the_packaging_cause(self, tmp_path, fake_common):
        (fake_common / "byok_health.py").unlink()
        dest = tmp_path / "build"
        dest.mkdir()
        with pytest.raises(MissingRuntimeModule) as exc:
            copy_runtime_modules(str(dest))
        assert "package-data" in str(exc.value)

    @pytest.mark.parametrize(
        "copier",
        ["tee_crafter.core.builder.builder",
         "tee_crafter.core.builder.platforms"],
    )
    def test_both_call_sites_are_fail_closed(self, tmp_path, fake_common, copier):
        """Regression guard: neither module may re-grow its own skip loop."""
        import importlib
        mod = importlib.import_module(copier)
        (fake_common / "siem_health.py").unlink()
        dest = tmp_path / "build"
        dest.mkdir()
        with pytest.raises(MissingRuntimeModule):
            mod._copy_runtime_modules(str(dest))
