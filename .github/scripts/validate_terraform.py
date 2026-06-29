#!/usr/bin/env python3
"""Run `terraform validate` against every platform template, credential-free.

Why this exists
---------------
No platform template declared `required_version`, and the `random` and `local`
providers were unpinned in all ten while `.terraform.lock.hcl` was gitignored —
so every deploy re-resolved providers from the registry. `terraform validate`
needs no cloud credentials and would have caught it.

The templates are not valid HCL as committed: they carry `__PLACEHOLDER__`
tokens that the CLI substitutes at stage time. Each is therefore rendered into
a scratch directory with inert values before validation.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE_ROOT = REPO / "apps/cli/src/tee_crafter/templates"

# Inert stand-ins. Values only need to be type-correct for `validate`; they are
# never applied. Keep this in sync with the substitutions the CLI performs.
PLACEHOLDER_VALUES = {
    "__INSTANCE_TYPE__": "t3.micro",
    "__BATCH_MODE__": "false",
    "__PCR0__": "0" * 96,
    "__PCR1__": "0" * 96,
    "__PCR2__": "0" * 96,
    "__MRENCLAVE__": "0" * 64,
    "__MRSIGNER__": "0" * 64,
    "__MEASUREMENT__": "0" * 96,
    "__MRTD__": "0" * 96,
    "__DEPLOYMENT_ID__": "ci0000",
    "__REGION__": "us-east-2",
    "__ZONE__": "us-central1-a",
    "__PROJECT_ID__": "ci-project",
    "__IMAGE_ID__": "ami-00000000000000000",
    # These two are the only placeholders that appear UNQUOTED in any template,
    # because they back `type = number` variables.  The generic fallback below
    # emits a bare word, which HCL then reads as a variable reference and
    # rejects with "Variables not allowed" — so they must be substituted here
    # with real numbers.  Checked with:
    #   grep -rhoE '(^|[^"])(__[A-Z0-9_]+__)([^"]|$)' .../main.template.tf
    "__ALLOCATOR_MB__": "3072",
    "__CPU_COUNT__": "2",
}

GENERIC_PLACEHOLDER = re.compile(r"__[A-Z0-9_]+__")


def render(text: str) -> str:
    for token, value in PLACEHOLDER_VALUES.items():
        text = text.replace(token, value)
    # Anything still unsubstituted becomes an inert bare word.  That is only
    # valid where the template already wraps the placeholder in quotes; see the
    # note on __ALLOCATOR_MB__ above for the exception.
    return GENERIC_PLACEHOLDER.sub("ci-placeholder", text)


def main() -> int:
    if not shutil.which("terraform"):
        print("terraform not installed; skipping", file=sys.stderr)
        return 0

    templates = sorted(TEMPLATE_ROOT.rglob("main.template.tf"))
    if not templates:
        print(f"no templates found under {TEMPLATE_ROOT}", file=sys.stderr)
        return 1

    failures: list[str] = []
    for tpl in templates:
        name = tpl.relative_to(TEMPLATE_ROOT).parent.as_posix()
        with tempfile.TemporaryDirectory(prefix="tfval_") as tmp:
            out = pathlib.Path(tmp) / "main.tf"
            out.write_text(render(tpl.read_text(encoding="utf-8")), encoding="utf-8")

            init = subprocess.run(
                ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
                cwd=tmp, capture_output=True, text=True,
            )
            if init.returncode != 0:
                failures.append(f"{name}: init failed\n{init.stderr.strip()[:1500]}")
                print(f"  {name}: INIT FAILED")
                continue

            res = subprocess.run(
                ["terraform", "validate", "-no-color"],
                cwd=tmp, capture_output=True, text=True,
            )
            if res.returncode != 0:
                failures.append(f"{name}: validate failed\n{res.stderr.strip()[:1500]}")
                print(f"  {name}: INVALID")
            else:
                print(f"  {name}: ok")

    if failures:
        print("\nterraform validate FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"--- {f}\n", file=sys.stderr)
        return 1

    print(f"\nall {len(templates)} platform templates validate cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
