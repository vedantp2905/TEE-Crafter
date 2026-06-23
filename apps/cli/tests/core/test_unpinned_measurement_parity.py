"""Every client that *can* pin a measurement must fail closed without one.

Why a parity test instead of nine per-platform tests
----------------------------------------------------
"Unpinned measurements are now fatal on all 10 platforms" is exactly the shape
of claim this codebase has gotten wrong twice, both times hiding a live
attestation bypass. Auditing it by hand found:

* the gate is behaviourally tested on ``sgx``, ``tdx-azure``, ``tdx-gcp``,
  ``gpu-cc-azure`` and ``gpu-cc-gcp``, and source-asserted on ``nitro``;
* the three SEV-SNP clients had **no** coverage at all — the code is correct,
  but nothing said so;
* and ``gpu-cc-aws`` has no gate whatsoever, because it has no CPU-side
  attestation and therefore no measurement to pin (tracker C5/C12). The "all
  10" phrasing was wrong about it.

So the claim is asserted here, once, over every client, with ``gpu-cc-aws``
named as the explicit exception rather than quietly passing.

These are source-structure assertions, not behavioural ones. They cannot prove
the gate fires; they can prove it exists, is reachable, has exactly one opt-out,
and that the default branch terminates. Behavioural coverage of the fatal path
lives in the per-platform files listed above.
"""
from __future__ import annotations

import ast
import os
import re

import pytest

import tee_crafter

_TEMPLATES = os.path.join(
    os.path.dirname(os.path.abspath(tee_crafter.__file__)), "templates")

HATCH = "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT"

#: Every client template, keyed by platform.
CLIENTS = {
    "nitro-aws": "nitro/client.template.py",
    "sgx-azure": "sgx/client.template.py",
    "tdx-azure": "tdx/azure/client.template.py",
    "tdx-gcp": "tdx/gcp/client.template.py",
    "snp-aws": "snp/aws/client.template.py",
    "snp-azure": "snp/azure/client.template.py",
    "snp-gcp": "snp/gcp/client.template.py",
    "gpu-cc-azure": "gpu_cc/azure/client.template.py",
    "gpu-cc-gcp": "gpu_cc/gcp/client.template.py",
    "gpu-cc-aws": "gpu_cc/aws/client.template.py",
}

#: The one platform with no CPU measurement to pin. Its only "measurement" is a
#: hash of the self-asserted NitroTPM PCR JSON, which nothing signs, so a pin
#: there would be theatre. Named explicitly so that *acquiring* a real CPU
#: anchor (tracker C5) makes this test fail and demand a decision.
NO_MEASUREMENT_TO_PIN = {"gpu-cc-aws"}

#: How many distinct gates each client is expected to carry, and in which
#: functions. Pinned by name because a *count* alone would let a gate move
#: while another was deleted.
#:
#: `gpu-cc-gcp` has two: the MRTD comparison in `verify_ratls_connection` and
#: the vTPM measured-boot check in `verify_vtpm_pcrs`. They guard different
#: evidence, so losing either is a real regression — and a test that only
#: asserted "at least one gate exists" did not notice when one was removed
#: (found by mutation).
EXPECTED_GATES = {
    "nitro-aws": {"verify_attestation"},
    "sgx-azure": {"require_pinned_measurements"},
    "tdx-azure": {"_verify_dcap_attestation"},
    "tdx-gcp": {"_verify_dcap_attestation"},
    "snp-aws": {"verify_ratls_connection"},
    "snp-azure": {"verify_ratls_connection"},
    "snp-gcp": {"verify_ratls_connection"},
    "gpu-cc-azure": {"verify_snp_evidence"},
    "gpu-cc-gcp": {"verify_ratls_connection", "verify_vtpm_pcrs"},
    "gpu-cc-aws": set(),
}

#: Matches a genuine environment read of the hatch, not a docstring mention.
_ENV_READ = re.compile(
    r"(?:environ\.get|getenv)\(\s*[\"']" + HATCH
    + r"|_ALLOW_UNPINNED_ENV\s*=\s*[\"']" + HATCH)


def _source(rel: str) -> str:
    with open(os.path.join(_TEMPLATES, rel), encoding="utf-8") as fh:
        return fh.read()


def _gate_functions(src) -> set:
    """Names of functions containing an unpinned-measurement gate."""
    tree = ast.parse(src)
    names = set()
    for scope in ast.walk(tree):
        if not isinstance(scope, ast.FunctionDef):
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.If):
                continue
            test_src = ast.get_source_segment(src, node.test) or ""
            if HATCH in test_src or "_allow_unpinned_measurement" in test_src:
                names.add(scope.name)
                break
    return names


@pytest.mark.parametrize("platform", sorted(CLIENTS))
def test_each_client_gates_exactly_where_expected(platform):
    """Pin *which* functions gate, not just that some function does.

    Two gates guarding different evidence means deleting one is a real
    regression that "a gate exists" cannot see.
    """
    found = _gate_functions(_source(CLIENTS[platform]))
    expected = EXPECTED_GATES[platform]
    assert found == expected, (
        f"{platform}: unpinned-measurement gates moved. Expected "
        f"{sorted(expected)}, found {sorted(found)}. If this is intentional, "
        f"update EXPECTED_GATES and say why in the commit.")


@pytest.mark.parametrize("platform", sorted(set(CLIENTS) - NO_MEASUREMENT_TO_PIN))
def test_client_reads_the_hatch_exactly_once(platform):
    """One opt-out, not several.

    Two independent reads mean two things to audit and two chances for one of
    them to be checked with the wrong polarity.
    """
    src = _source(CLIENTS[platform])
    reads = _ENV_READ.findall(src)
    assert len(reads) == 1, (
        f"{platform}: expected exactly one environment read of {HATCH}, "
        f"found {len(reads)}")


@pytest.mark.parametrize("platform", sorted(NO_MEASUREMENT_TO_PIN))
def test_platforms_without_a_measurement_have_no_gate(platform):
    """The exception, asserted rather than assumed.

    If this platform ever gains real CPU attestation, this test fails and the
    gate has to be added deliberately — instead of the platform silently
    remaining the one that never checks.
    """
    src = _source(CLIENTS[platform])
    assert not _ENV_READ.findall(src), (
        f"{platform} now reads {HATCH}. If it gained a real CPU measurement, "
        f"remove it from NO_MEASUREMENT_TO_PIN and give it the same gate as "
        f"the others; if not, drop the read.")


def _terminators(node) -> list:
    """`sys.exit(...)` / `exit(...)` / `raise` nodes anywhere under *node*."""
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Raise):
            out.append(sub)
        elif isinstance(sub, ast.Call):
            fn = sub.func
            if isinstance(fn, ast.Attribute) and fn.attr == "exit":
                out.append(sub)
            elif isinstance(fn, ast.Name) and fn.id == "exit":
                out.append(sub)
    return out


@pytest.mark.parametrize("platform", sorted(set(CLIENTS) - NO_MEASUREMENT_TO_PIN))
def test_a_terminating_path_exists_outside_the_opt_out_branch(platform):
    """Not taking the hatch must be able to kill the process.

    Deliberately shape-agnostic. The tree uses three different, all correct,
    arrangements:

    * ``if allow: warn / elif hatch: warn / else: exit``  (SEV-SNP)
    * ``if not pinned: if not hatch(): exit``             (Nitro)
    * ``if hatch: warn; return`` then a bare ``exit`` after (SGX)

    Asserting on any one of them would have failed the other two, and an
    assertion tuned to one shape is how a real gap hides behind a green test.
    What matters in every arrangement is the same: the enclosing scope contains
    a terminator that is **not** inside the hatch-satisfied branch, so an
    unpinned build cannot merely warn and continue.
    """
    src = _source(CLIENTS[platform])
    tree = ast.parse(src)

    # Scoped to the function that *contains* the gate, not the whole file.
    # An earlier version of this test looked file-wide, which made it nearly
    # vacuous: replacing every `sys.exit(1)` in a client with `pass` left the
    # test green on all nine platforms, because some unrelated exit elsewhere
    # in the file still satisfied it. Mutation testing is the only reason that
    # was caught.
    gates = []  # (enclosing_function, gate_if_node)
    for scope in ast.walk(tree):
        if not isinstance(scope, ast.FunctionDef):
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.If):
                continue
            test_src = ast.get_source_segment(src, node.test) or ""
            if HATCH in test_src or "_allow_unpinned_measurement" in test_src:
                gates.append((scope, node))

    assert gates, (
        f"{platform}: found no if/elif testing {HATCH} inside a function, so "
        f"there is no unpinned-measurement gate to speak of")

    # Bare `f(...)` statements anywhere in the file, i.e. calls whose result
    # is thrown away. Used to check that a verdict-returning gate is actually
    # consumed by its caller.
    discarded = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            fn = node.value.func
            if isinstance(fn, ast.Name):
                discarded.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                discarded.add(fn.attr)

    def refuses_by_return(scope, opt_out_ids) -> bool:
        """The gate signals refusal to its caller instead of exiting.

        Legitimate and used by two clients: `verify_vtpm_pcrs` returns False
        and `verify_snp_evidence` returns {"ok": False}, and in both cases the
        caller does `conn.close(); FATAL; sys.exit(1)`. Requiring an in-scope
        exit would fail those for using a return value, which is not a defect.
        Two conditions, both necessary: a falsy verdict is returned outside the
        opt-out branch, and no call site discards the result.
        """
        # Names bound to a dict literal whose "ok" starts False — the
        # default-deny accumulator idiom (`out = {"ok": False, ...}`, set True
        # only after every check passes, `return out` on each failure).
        # gpu-cc-azure's verify_snp_evidence uses it, and it is arguably the
        # strongest of these shapes: a new early return is refusing by default.
        deny_by_default = set()
        for node in ast.walk(scope):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
                continue
            for k, val in zip(node.value.keys, node.value.values):
                if (isinstance(k, ast.Constant) and k.value == "ok"
                        and isinstance(val, ast.Constant) and val.value is False):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            deny_by_default.add(tgt.id)

        returns_falsy = False
        for node in ast.walk(scope):
            if not isinstance(node, ast.Return) or id(node) in opt_out_ids:
                continue
            v = node.value
            if isinstance(v, ast.Constant) and v.value is False:
                returns_falsy = True
            elif isinstance(v, ast.Name) and v.id in deny_by_default:
                returns_falsy = True
            elif isinstance(v, ast.Dict):
                for k, val in zip(v.keys, v.values):
                    if (isinstance(k, ast.Constant) and k.value == "ok"
                            and isinstance(val, ast.Constant)
                            and val.value is False):
                        returns_falsy = True
        return returns_falsy and scope.name not in discarded

    for scope, gate in gates:
        test_src = ast.get_source_segment(src, gate.test) or ""
        negated = test_src.lstrip().startswith("not ")
        satisfied = gate.orelse if negated else gate.body
        opt_out_terms, opt_out_nodes = set(), set()
        for stmt in satisfied:
            opt_out_terms.update(id(t) for t in _terminators(stmt))
            opt_out_nodes.update(id(n) for n in ast.walk(stmt))

        in_scope = [t for t in _terminators(scope) if id(t) not in opt_out_terms]
        assert in_scope or refuses_by_return(scope, opt_out_nodes), (
            f"{platform}: {scope.name}() gates on {HATCH} but neither exits "
            f"nor returns a refusal outside the opt-out branch — an unpinned "
            f"build would warn and carry on. Gate test: {test_src[:70]!r}")


@pytest.mark.parametrize("platform", sorted(set(CLIENTS) - NO_MEASUREMENT_TO_PIN))
def test_the_opt_out_warns_loudly(platform):
    """Taking the hatch must say what was given up, in the output.

    A silent opt-out is worse than no opt-out: the run looks like a verified
    one. Requiring the word alongside the hatch keeps the warning attached to
    the branch rather than drifting into a docstring.
    """
    src = _source(CLIENTS[platform])
    tree = ast.parse(src)

    # Three things this assertion learned the hard way, each from a client
    # that warns perfectly well but not in the shape being looked for:
    #  * the hatch may be named literally or via the module constant holding
    #    it (`_ALLOW_UNPINNED_ENV`) — equally visible to an operator;
    #  * the banner is usually several consecutive `print()` calls, so
    #    "WARNING" and the variable name land in *different* calls;
    #  * Nitro puts the fatal exit in the gate's body and the warning *after*
    #    it, so the warning is in no branch of the gate at all.
    #
    # Scoping to the enclosing function is therefore deliberately weaker than
    # "in the opt-out branch": it proves the gate's function warns and names
    # the variable, not that the warning is unreachable-unless-opted-out.
    # Asserting the stronger property would mean rewriting three clients to a
    # single shape for the test's benefit.
    names = (HATCH, "_ALLOW_UNPINNED_ENV")

    def gate_scopes():
        """Function (or module) scopes containing an unpinned-measurement gate."""
        for scope in list(ast.walk(tree)):
            if not isinstance(scope, (ast.FunctionDef, ast.Module)):
                continue
            seg = (src if isinstance(scope, ast.Module)
                   else ast.get_source_segment(src, scope) or "")
            for node in ast.walk(scope):
                if not isinstance(node, ast.If):
                    continue
                test_src = ast.get_source_segment(src, node.test) or ""
                if (HATCH in test_src
                        or "_allow_unpinned_measurement" in test_src):
                    yield scope, seg
                    break

    warned = False
    for scope, seg in gate_scopes():
        if isinstance(scope, ast.Module):
            continue  # module scope is the whole file; too coarse to mean much
        if "WARNING" in seg.upper() and any(n in seg for n in names):
            warned = True
            break

    assert warned, (
        f"{platform}: the function implementing the {HATCH} gate prints no "
        f"WARNING naming the variable, so an operator who set it would not "
        f"see what it cost them")
