"""One spelling of a boolean env var must mean one thing everywhere.

Four truthy sets had grown up independently, so ``on`` was honoured at some call
sites and silently ignored at others.  Silently ignored is only safe in one
direction: for an opt-in hatch it leaves the safe state, but for a protection
that is meant to be ON it is how ``=true`` turned a check off.

Two things are asserted here.  First, the semantics of the shared helper --
especially that an *unrecognised* value resolves to the safe state, which is a
different constant for a gate than for a hatch.  Second, that the copies of the
tuples living in ``tee_crafter/templates`` still match the package.  Those files
are staged onto the instance (and the ``client.template.py`` verifiers are handed
to whoever checks the attestation), so they cannot import the package and have to
repeat the values.  A copy that drifts is exactly the bug this module exists to
prevent, and it would otherwise be invisible.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from tee_crafter.core.env_flags import (
    FALSY,
    TRUTHY,
    env_flag,
    env_gate_enabled,
    env_hatch_open,
    interpret,
)

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "tee_crafter"

VAR = "TEE_CRAFTER_TEST_ONLY_FLAG"

#: Values nobody listed.  Each must resolve to the safe state, not to True.
UNRECOGNISED = ["", "  ", "maybe", "2", "-1", "onn", "tru", "'1'", "1 1", "no!"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(VAR, raising=False)


# --------------------------------------------------------------------------
# interpret()
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw", TRUTHY)
def test_every_truthy_spelling_is_true(raw):
    assert interpret(raw) is True
    assert interpret(raw.upper()) is True
    assert interpret(f"  {raw}  ") is True


@pytest.mark.parametrize("raw", FALSY)
def test_every_falsy_spelling_is_false(raw):
    assert interpret(raw) is False
    assert interpret(raw.upper()) is False


@pytest.mark.parametrize("raw", UNRECOGNISED)
def test_unrecognised_is_neither(raw):
    assert interpret(raw) is None


def test_unset_is_neither():
    assert interpret(None) is None


def test_the_two_tuples_do_not_overlap():
    """An overlap would make one spelling both true and false."""
    assert not (set(TRUTHY) & set(FALSY))


# --------------------------------------------------------------------------
# gate vs hatch: unrecognised resolves to the SAFE state, which differs
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw", UNRECOGNISED)
def test_a_gate_stays_on_for_an_unrecognised_value(monkeypatch, raw):
    """The regression: `=true` must never be what disables a protection."""
    monkeypatch.setenv(VAR, raw)
    assert env_gate_enabled(VAR) is True


@pytest.mark.parametrize("raw", UNRECOGNISED)
def test_a_hatch_stays_shut_for_an_unrecognised_value(monkeypatch, raw):
    monkeypatch.setenv(VAR, raw)
    assert env_hatch_open(VAR) is False


def test_a_gate_is_on_when_unset():
    assert env_gate_enabled(VAR) is True


def test_a_hatch_is_shut_when_unset():
    assert env_hatch_open(VAR) is False


@pytest.mark.parametrize("raw", FALSY)
def test_a_gate_is_off_only_for_an_explicit_falsy(monkeypatch, raw):
    monkeypatch.setenv(VAR, raw)
    assert env_gate_enabled(VAR) is False


@pytest.mark.parametrize("raw", TRUTHY)
def test_a_gate_stays_on_for_every_truthy_spelling(monkeypatch, raw):
    """`=true`, `=yes`, `=on`, `=y` must all keep a protection enabled."""
    monkeypatch.setenv(VAR, raw)
    assert env_gate_enabled(VAR) is True


@pytest.mark.parametrize("raw", TRUTHY)
def test_a_hatch_opens_for_every_truthy_spelling(monkeypatch, raw):
    monkeypatch.setenv(VAR, raw)
    assert env_hatch_open(VAR) is True


# --------------------------------------------------------------------------
# env_flag(): neutral settings fall back to the caller's default
# --------------------------------------------------------------------------

@pytest.mark.parametrize("default", [True, False])
@pytest.mark.parametrize("raw", UNRECOGNISED)
def test_env_flag_falls_back_on_unrecognised(monkeypatch, raw, default):
    monkeypatch.setenv(VAR, raw)
    assert env_flag(VAR, default=default) is default


@pytest.mark.parametrize("default", [True, False])
def test_env_flag_falls_back_when_unset(default):
    assert env_flag(VAR, default=default) is default


def test_env_flag_lets_an_explicit_value_win(monkeypatch):
    monkeypatch.setenv(VAR, "on")
    assert env_flag(VAR, default=False) is True
    monkeypatch.setenv(VAR, "off")
    assert env_flag(VAR, default=True) is False


# --------------------------------------------------------------------------
# the staged copies must not drift
# --------------------------------------------------------------------------

def _tuple_literal(text: str, name: str):
    m = re.search(rf'^{name}\s*=\s*\(([^)]*)\)', text, re.M)
    assert m, f"{name} not found"
    return tuple(re.findall(r'"([^"]*)"', m.group(1)))


def test_service_runtime_template_tuples_match_the_package():
    """This template repeats the tuples; drift would change flag meaning
    inside the TEE while the package kept the old behaviour."""
    text = (SRC / "templates" / "common" /
            "tee_crafter_service_runtime.py").read_text()
    assert _tuple_literal(text, "_TRUTHY") == TRUTHY
    assert _tuple_literal(text, "_FALSY") == FALSY


#: Gates whose safe state is ON.  Each is read inside a standalone template that
#: cannot import the package, so the fail-closed shape is written out by hand.
#: An ``== "1"`` comparison here is the defect this guards: it makes every
#: spelling other than the literal ``1`` disable the protection.
_GATE_SITES = [
    ("templates/snp/azure/client.template.py", "TEE_CRAFTER_STRICT_SNP_AK_BINDING"),
    ("templates/gpu_cc/azure/client.template.py", "TEE_CRAFTER_STRICT_SNP_AK_BINDING"),
    ("templates/nitro/host_proxy.template.py", "TEE_CRAFTER_PROXY_STRICT_IMDS"),
    ("templates/common/tee_crafter_runtime_bootstrap.py",
     "TEE_CRAFTER_BYOK_REQUIRE_SIGNED_AUDIT"),
]


@pytest.mark.parametrize("rel,var", _GATE_SITES)
def test_safe_on_gates_are_not_compared_against_a_single_spelling(rel, var):
    text = (SRC / rel).read_text()
    assert var in text, f"{var} no longer read in {rel}"
    # Strip comments so a comment quoting `== "1"` cannot satisfy or fail this.
    code = "\n".join(re.sub(r'#.*$', '', ln) for ln in text.split("\n"))
    for m in re.finditer(rf'{var}"[^\n]*', code):
        frag = m.group(0)
        assert '== "1"' not in frag, (
            f'{rel} compares {var} against the literal "1". Every other '
            f'spelling -- including "true" and "on" -- then disables the '
            f'protection. Use `not in ("0","false","no","n","off")`.')
