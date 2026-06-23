"""Nitro must refuse a build with no pinned PCRs.

Nitro was the one platform with no unpinned-measurement gate, and it is the
default `--tee-platform`. `render_client_template` substitutes an empty dict
when no PCRs are passed, and the client's verification loop is

    for pcr_key, expected_val in EXPECTED_PCRS.items():
        ...

which over an empty dict iterates zero times, checks nothing, and falls through
to print success. A Nitro attestation document proves an enclave is *genuine*;
only the PCRs say *which* enclave image booted. So an unpinned client accepted
any genuine enclave in the account -- the same empty-allowlist fail-open that
`KeyReleasePolicy.allowed_measurement_sha256` was hardened against.

These tests read the rendered source rather than executing the client (which
needs vsock, cbor2 and a live enclave), so they assert the gate exists and is
ordered before the loop. The behavioural half is covered by the `_render`
compile check plus the ordering assertion: a gate placed after the loop would
still pass a naive "is the string present" test.
"""
from __future__ import annotations

import re

import pytest

from tee_crafter.core.builder.builder import render_client_template


def _render(pcr_hashes):
    src = render_client_template(pcr_hashes=pcr_hashes, root_ca="")
    compile(src, "client.py", "exec")  # rendered output must be valid Python
    return src


def test_unpinned_build_renders_an_empty_expected_pcrs():
    """The precondition for the bug. If this changes, re-read the gate."""
    assert "EXPECTED_PCRS = {}" in _render(None)


def test_pinned_build_renders_the_measurements():
    src = _render({"PCR0": "ab" * 48, "PCR1": "cd" * 48})
    assert "ab" * 48 in src
    assert "cd" * 48 in src
    assert "EXPECTED_PCRS = {}" not in src


@pytest.mark.parametrize("pcrs", [None, {}])
def test_gate_is_present_for_every_unpinned_shape(pcrs):
    src = _render(pcrs)
    assert "if not EXPECTED_PCRS:" in src
    assert "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT" in src
    assert "sys.exit(1)" in src


def test_gate_runs_before_the_verification_loop():
    """Ordering is the whole point.

    A check placed after the loop would satisfy a substring test while leaving
    the zero-iteration pass intact.
    """
    src = _render(None)
    gate = src.index("if not EXPECTED_PCRS:")
    loop = src.index("for pcr_key, expected_val in EXPECTED_PCRS.items():")
    assert gate < loop, "the empty-PCR gate must precede the verification loop"


def test_opt_out_is_exactly_one_and_warns_loudly():
    src = _render(None)
    # Guard the house convention: `== "1"`, not a truthy-string parse, so
    # "true"/"yes"/"0"/"01" do not open it.
    assert re.search(
        r'os\.environ\.get\(_ALLOW_UNPINNED_ENV,\s*"0"\)\s*==\s*"1"', src)
    # And the escape hatch must announce itself.
    assert "WARNING" in src
    assert "NOT bound to any particular enclave image" in src


def test_gate_does_not_fire_on_a_pinned_build():
    """The fatal branch must be unreachable when PCRs are present.

    Asserted structurally: the gate is guarded by `if not EXPECTED_PCRS`, and a
    pinned render puts a non-empty dict there.
    """
    src = _render({"PCR0": "ab" * 48})
    gate = src.index("if not EXPECTED_PCRS:")
    decl = src.index("EXPECTED_PCRS = {")
    assert decl < gate
    rendered_decl = src[decl:src.index("\n", decl)]
    assert rendered_decl.strip() != "EXPECTED_PCRS = {}"
