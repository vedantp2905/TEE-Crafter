"""Every `TEE_CRAFTER_*` variable named in the docs must exist in the code.

The failure this guards against is one-directional and quiet: a variable gets
renamed or deleted in the code, the documentation keeps naming it, and an
operator sets something that does nothing. For a knob that *weakens* a default
that is merely useless, but for one that is supposed to *harden* — pinning a
measurement, requiring SMT off, forcing strict egress — silently doing nothing is
the dangerous direction.

The reverse is deliberately not asserted. Plenty of variables are legitimately
undocumented: per-collector SIEM knobs, template internals, and the on-instance
transcript markers (`TEE_CRAFTER_MEASUREMENT=<hex>`, `TEE_CRAFTER_PCR4=<hex>`)
that a capture snippet *prints* rather than reads. Requiring prose for each would
make the suite fail for adding an internal constant, which trains people to
delete tests.

`docs/cli_reference.md` carries a generated index of every real read site, and
`docs/security.md` §19 carries prose for the security-relevant subset.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "tee_crafter"
DOCS = REPO.parents[1] / "docs"

_VAR = re.compile(r"TEE_CRAFTER_[A-Z0-9_]+")

#: Documented deliberately while not existing as a variable. Each needs a reason.
_EXPECTED_ABSENT = {
    # Named in docs and in a source comment only, to record that such a flag was
    # considered and rejected in favour of an explicit URL. Adding it as a real
    # variable would be the thing the comment argues against.
    "TEE_CRAFTER_ALLOW_MIXED_PCS_HOSTS",
}


def _all_source_text() -> str:
    parts = []
    for path in SRC.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.suffix in (".pyc", ".pyo"):
            continue
        try:
            parts.append(path.read_text(errors="replace"))
        except OSError:
            continue
    return "\n".join(parts)


def _documented_vars() -> dict:
    """var -> sorted list of docs files naming it."""
    found: dict = {}
    for doc in sorted(DOCS.glob("*.md")):
        for name in set(_VAR.findall(doc.read_text(errors="replace"))):
            found.setdefault(name, []).append(doc.name)
    return {k: sorted(v) for k, v in found.items()}


def test_docs_directory_was_found():
    """Guard against the path drifting and every assertion below vacuously
    passing on an empty set."""
    assert DOCS.is_dir(), f"docs directory not found at {DOCS}"
    assert _documented_vars(), "no TEE_CRAFTER_* variables found in any doc"


@pytest.mark.parametrize("name", sorted(_documented_vars()))
def test_documented_variable_exists_in_the_code(name):
    if name in _EXPECTED_ABSENT:
        pytest.skip(f"{name} is documented as deliberately-not-implemented")
    assert name in _all_source_text.cache, (  # type: ignore[attr-defined]
        f"{name} is named in {', '.join(_documented_vars()[name])} but appears "
        f"nowhere under src/tee_crafter. Either it was renamed or removed in the "
        f"code and the docs were not updated, or the docs invented it.")


# Reading every source file once per parametrised case is slow enough to matter,
# so cache it on the function object.
_all_source_text.cache = _all_source_text()  # type: ignore[attr-defined]
