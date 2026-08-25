#!/usr/bin/env python3
"""Assert that every data file the CLI opens at runtime is tracked by git.

Why this exists
---------------
A bare ``*.json`` line in ``.gitignore`` once silently excluded
``templates/common/seccomp-container.json`` — a file that ``cli/loaders.py``
opens unconditionally and that nine of the ten platform setup scripts embed.
``bake-ami`` therefore raised ``FileNotFoundError`` on every platform except
``nitro-aws``, and nothing caught it: the file was present in the author's
working copy, so only a fresh clone (or CI) could ever have noticed.

The same rule also excluded the entire ``measurements/`` baseline registry,
which made the measurement-pinning feature unable to ship its own data.

This script walks the *exported* tree (``git archive``), finds the data files
the package expects, and fails if any is absent.  Run it against a directory
produced by ``git archive HEAD | tar -x -C <dir>``.
"""

from __future__ import annotations

import pathlib
import sys

# Files the CLI opens by a literal path at runtime.  Keep this list in sync
# with cli/loaders.py and core/builder/platforms.py.
REQUIRED_RELATIVE = [
    "apps/cli/src/tee_crafter/certs/nitro-root.pem",
    "apps/cli/src/tee_crafter/certs/intel-sgx-dcap-root.pem",
    "apps/cli/src/tee_crafter/certs/amd-ark-milan.pem",
    "apps/cli/src/tee_crafter/certs/amd-ark-genoa.pem",
    # Loaded by platforms._load_amd_ask_ca for the VCEK-signing chain.  Omitted
    # from this list until 2026-08 even though it is opened by a literal path,
    # which is exactly the gap this script exists to close: a stray .gitignore
    # rule would have silently broken SEV-SNP verification on Milan hosts that
    # return a VCEK (GCP) while every other platform kept passing.
    "apps/cli/src/tee_crafter/certs/amd-ask-milan.pem",
    "apps/cli/src/tee_crafter/certs/nvidia-nras-intermediate.pem",
    "apps/cli/src/tee_crafter/templates/common/seccomp-container.json",
    "apps/cli/src/tee_crafter/templates/common/apparmor-container",
    "apps/cli/src/tee_crafter/templates/common/apparmor-batch-container",
]

# Placeholders that platform setup scripts substitute at stage time.  If a
# script still contains one of these, the file backing it must exist.
PLACEHOLDER_BACKING = {
    "__SECCOMP_PROFILE__": "apps/cli/src/tee_crafter/templates/common/seccomp-container.json",
    "__APPARMOR_PROFILE__": "apps/cli/src/tee_crafter/templates/common/apparmor-container",
    "__APPARMOR_BATCH_PROFILE__": "apps/cli/src/tee_crafter/templates/common/apparmor-batch-container",
}


def main(root_arg: str) -> int:
    root = pathlib.Path(root_arg).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    problems: list[str] = []

    for rel in REQUIRED_RELATIVE:
        if not (root / rel).is_file():
            problems.append(f"missing required data file: {rel}")

    scripts_dir = root / "apps/cli/src/tee_crafter/scripts"
    if scripts_dir.is_dir():
        for script in sorted(scripts_dir.rglob("*.sh")):
            try:
                text = script.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:  # pragma: no cover - unreadable file
                problems.append(f"could not read {script}: {exc}")
                continue
            for placeholder, backing in PLACEHOLDER_BACKING.items():
                if placeholder in text and not (root / backing).is_file():
                    rel_script = script.relative_to(root)
                    problems.append(
                        f"{rel_script} contains {placeholder} but {backing} is not in the tree"
                    )

    if problems:
        print("Tracked-path check FAILED:\n", file=sys.stderr)
        for p in sorted(set(problems)):
            print(f"  - {p}", file=sys.stderr)
        print(
            "\nA file the code opens is not in the exported tree. This is almost "
            "always an over-broad .gitignore rule. Check with:\n"
            "  git check-ignore -v <path>",
            file=sys.stderr,
        )
        return 1

    print(f"tracked-path check OK ({len(REQUIRED_RELATIVE)} data files present)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
