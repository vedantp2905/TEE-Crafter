"""A deploy panel must never print a placeholder when a real value is present.

`tdx/phase.py` read `measurements.get('MRTD')` while the pipeline populated the
canonical lowercase `mrtd` *and* an uppercase `MRTD` placeholder of literal
"unknown". So a run whose MRTD was correctly pinned printed

    MRTD: unknown

to the operator -- the exact opposite of the truth, on the line they would check
to see whether attestation was pinned. Nothing security-relevant read the
uppercase key, which is why it survived: the damage was entirely in what the
human was told.
"""
from __future__ import annotations

import importlib

import pytest

# (module, canonical key as populated by the pipeline, a stale/placeholder alias)
CASES = [
    ("tee_crafter.cli.deployment.tdx.phase", "mrtd", "MRTD"),
    ("tee_crafter.cli.deployment.tdx.gcp_phase", "mrtd", "MRTD"),
    ("tee_crafter.cli.deployment.snp.azure_phase", "measurement", "MEASUREMENT"),
    ("tee_crafter.cli.deployment.snp.gcp_phase", "measurement", "MEASUREMENT"),
    ("tee_crafter.cli.deployment.gpu_cc.azure_phase", "measurement",
     "MEASUREMENT"),
]

REAL = "a2e61f1316e9e367e9c1f7a0adc98c48eb13875c399c85d286cee5ea2b05e57f"
PLACEHOLDERS = ("unknown", "pending", "")


def _panel_text(module_name: str, measurements: dict) -> str:
    mod = importlib.import_module(module_name)
    render = getattr(mod, "_render_panel", None)
    if render is None:
        pytest.skip(f"{module_name} has no _render_panel")
    panel = render({}, measurements)
    return str(getattr(panel, "renderable", panel))


@pytest.mark.parametrize("module,canonical,alias", CASES)
class TestPanelsPreferTheRealValue:

    def test_canonical_key_alone_is_shown(self, module, canonical, alias):
        text = _panel_text(module, {canonical: REAL})
        assert REAL in text

    def test_canonical_wins_over_a_placeholder_alias(self, module, canonical,
                                                     alias):
        """The exact shape the pipeline produced on tdx-azure."""
        text = _panel_text(module, {alias: "unknown", canonical: REAL})
        assert REAL in text, f"{module} showed the placeholder, not the value"
        assert "unknown" not in text

    def test_no_placeholder_leaks_when_a_value_exists(self, module, canonical,
                                                     alias):
        text = _panel_text(module, {canonical: REAL, alias: ""})
        for junk in PLACEHOLDERS:
            if junk:
                assert junk not in text
