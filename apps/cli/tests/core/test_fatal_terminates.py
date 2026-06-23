"""Every printed ``FATAL`` must actually stop something.

A ``FATAL:`` line that does not terminate is the worst fail-open this codebase
can produce: the operator is told verification failed, the log says FATAL, and
the connection proceeds anyway. Nobody re-reads a log that appears to have
refused.

There are two legitimate shapes, and this asserts the disjunction rather than
forcing one of them:

1. **Terminate in place** — ``sys.exit(1)`` or ``raise`` reachable in the same
   block. Used by the top-level verification flows.
2. **Record and return a verdict** — set a flag (``passed = False``) or an
   error field (``out["error"] = ...``) and let the caller act. Used by the
   per-check helpers (``verify_guest_policy``, ``verify_tcb_version``, …) that
   report several problems before returning one answer.

Shape 2 is only safe if the caller consumes the verdict, so that is asserted
too: no verdict-returning function may be called as a bare statement anywhere
in the templates. ``bool("absent") is True``, and this project has already
shipped a tri-state return read as a boolean, so a discarded verdict is not a
hypothetical.

This is a source-structure invariant, not a behavioural one. It cannot prove a
given FATAL is reachable; it can prove none of them is a dead end.
"""
from __future__ import annotations

import ast
import glob
import os

import pytest

import tee_crafter

_TEMPLATES = os.path.join(
    os.path.dirname(os.path.abspath(tee_crafter.__file__)), "templates")

TEMPLATE_FILES = sorted(
    glob.glob(os.path.join(_TEMPLATES, "**", "*.py"), recursive=True))
assert TEMPLATE_FILES, "no template sources found"


def _rel(path: str) -> str:
    return os.path.relpath(path, _TEMPLATES)


def _is_fatal_print(node) -> bool:
    if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)):
        return False
    fn = node.value.func
    if not (isinstance(fn, ast.Name) and fn.id == "print"):
        return False
    for arg in node.value.args:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if "FATAL" in sub.value:
                    return True
    return False


def _terminates(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Raise):
            return True
        if isinstance(sub, ast.Call):
            fn = sub.func
            if isinstance(fn, ast.Attribute) and fn.attr == "exit":
                return True
            if isinstance(fn, ast.Name) and fn.id == "exit":
                return True
    return False


def _records_failure(block) -> bool:
    """A falsy flag assignment, an error-field write, or a return."""
    for stmt in block:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Assign):
                if (isinstance(sub.value, ast.Constant)
                        and sub.value.value is False):
                    return True
                if any(isinstance(t, ast.Subscript) for t in sub.targets):
                    return True
            if isinstance(sub, ast.Return):
                return True
    return False


def _fatal_sites(tree, src):
    """Yield (stmt, following_statements) for every FATAL print."""
    for parent in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(parent, field, None)
            if not isinstance(block, list):
                continue
            for i, stmt in enumerate(block):
                if _is_fatal_print(stmt):
                    yield stmt, block[i:]


@pytest.mark.parametrize("path", TEMPLATE_FILES, ids=_rel)
def test_every_fatal_either_terminates_or_records_failure(path):
    src = open(path, encoding="utf-8").read()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        pytest.skip("template is not parseable standalone")

    dead_ends = []
    for stmt, rest in _fatal_sites(tree, src):
        if any(_terminates(s) for s in rest):
            continue
        if _records_failure(rest):
            continue
        dead_ends.append(stmt.lineno)

    assert not dead_ends, (
        f"{_rel(path)}: FATAL printed at line(s) {dead_ends} with no "
        f"terminator and no recorded failure — the message says the check "
        f"failed but nothing acts on it")


def test_the_invariant_actually_covers_something():
    """Guard against the parametrised test passing because it found nothing.

    If a refactor renamed FATAL to something else, every case above would pass
    vacuously and the invariant would quietly stop being enforced.
    """
    total = 0
    for path in TEMPLATE_FILES:
        try:
            tree = ast.parse(open(path, encoding="utf-8").read())
        except SyntaxError:
            continue
        total += sum(1 for _ in _fatal_sites(tree, ""))
    assert total > 100, (
        f"only {total} FATAL sites found; this invariant is meant to cover the "
        f"whole verification surface (was 189). Did the wording change?")


def test_no_verdict_returning_function_is_called_and_discarded():
    """Shape 2 is only fail-closed if the caller looks at the answer.

    Scoped to functions that print FATAL and return a verdict, since those are
    the ones where discarding the result converts a refusal into a pass.
    """
    problems = []
    for path in TEMPLATE_FILES:
        src = open(path, encoding="utf-8").read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue

        verdict_fns = set()
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            prints_fatal = any(_is_fatal_print(n) for n in ast.walk(fn))
            returns_value = any(
                isinstance(n, ast.Return) and n.value is not None
                for n in ast.walk(fn))
            if prints_fatal and returns_value:
                verdict_fns.add(fn.name)

        for node in ast.walk(tree):
            if not (isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Call)):
                continue
            fn = node.value.func
            name = (fn.id if isinstance(fn, ast.Name)
                    else fn.attr if isinstance(fn, ast.Attribute) else None)
            if name in verdict_fns:
                problems.append(f"{_rel(path)}:{node.lineno} {name}()")

    assert not problems, (
        "verdict-returning FATAL function(s) called as a bare statement, so "
        "the refusal is discarded: " + ", ".join(problems))
