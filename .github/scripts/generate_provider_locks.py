#!/usr/bin/env python3
"""Generate a ``.terraform.lock.hcl`` next to every platform template.

Why this exists
---------------
The templates constrain providers pessimistically (``aws = "~> 6.0"``), which
pins a *range*, not a build.  Two applies a month apart can resolve different
provider versions, which is at odds with a project whose whole thesis is
reproducible, attestable builds.  A lockfile records the exact versions and
their checksums.

``terraform init`` only honours a lockfile in the directory it runs in, so
:func:`tee_crafter.core.iac.stage_terraform` copies the lockfile into the build
directory.  This script produces the file it copies.

Platforms
---------
``terraform providers lock`` records one ``h1:`` checksum per target platform,
because each platform is a distinct provider zip.

What a missing platform actually costs, measured on terraform 1.x against
``gpu_cc/aws`` on 2026-08-22 (an earlier version of this note claimed ``init``
would "fail closed", which is not what happens):

* ``init`` **rewrites the staged lockfile** to add the h1 hash it needs, and
  says so: "Terraform has made some changes to the provider dependency
  selections recorded in the .terraform.lock.hcl file."  Exit 0.
* with ``-lockfile=readonly`` it prints "Warning: Provider lock file not
  updated" and still exits 0.
* provider *versions* are unaffected -- those are pinned by ``version =``.
* *authentication* is unaffected -- that rides on the ``zh:`` hashes, which
  come from the registry's signed ``SHA256SUMS`` and cover every platform at
  once.  Strip the ``zh:`` hashes as well and ``init`` does fail closed:
  "Error: Invalid provider hash set", exit 1.

So this is build hygiene, not a security or version-drift hole: the cost is
that the staged artifact stops matching the shipped one. We record:

* ``linux_amd64``  — where terraform actually runs, because the CLI re-execs
  itself into a linux/amd64 container for all real work.
* ``darwin_arm64`` — an Apple Silicon host running with
  ``TEE_CRAFTER_IN_DOCKER=1`` (i.e. deliberately outside the re-exec).
* ``linux_arm64``  — the same escape hatch on a Graviton or arm64 Linux host.

To support another host, add it to ``PLATFORMS`` and re-run.  Adding platforms
costs download time, not correctness.

Always regenerate through this script rather than running ``terraform providers
lock`` by hand.  A hand-run with the wrong ``-platform`` set produces a lockfile
that looks complete — right versions, real checksums — but silently omits a
platform, and the omission only shows up as ``terraform init`` rewriting the
staged copy on the affected host.  That happened during the aws 6 / azurerm 5 /
google 7 bump: ``linux_arm64`` was passed where ``darwin_arm64`` was meant, so
all ten lockfiles lost their Apple Silicon hashes.

``--check`` now compares each provider's ``h1:`` count against ``len(PLATFORMS)``,
which catches a lockfile that is short a platform.  Be clear about what that does
*not* catch: the lockfile format records no platform names anywhere, so a
substitution of equal size is invisible to it — and that is exactly the shape of
the bump above, where two platforms were passed and two were expected.  The
count check would have passed.  Cardinality is the most a static check can do
here; running this script is what actually guarantees the right platform set.

Usage: ``python3 .github/scripts/generate_provider_locks.py [--check]``

``--check`` verifies a lockfile exists for every template, names the providers
it pins, and confirms every platform in ``PLATFORMS`` is covered — all without
touching the network.  That is what CI runs; the full generation needs to
download every provider on every platform (multiple GB) and is a manual,
occasional step.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_ROOT = REPO_ROOT / "apps/cli/src/tee_crafter/templates"
LOCK_NAME = ".terraform.lock.hcl"

PLATFORMS = ("linux_amd64", "darwin_arm64", "linux_arm64")

# Kept in sync with validate_terraform.py -- see the note there about
# __ALLOCATOR_MB__ / __CPU_COUNT__ being the only unquoted placeholders.
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
    "__ALLOCATOR_MB__": "3072",
    "__CPU_COUNT__": "2",
}
GENERIC_PLACEHOLDER = re.compile(r"__[A-Z0-9_]+__")


def render(text: str) -> str:
    for token, value in PLACEHOLDER_VALUES.items():
        text = text.replace(token, value)
    return GENERIC_PLACEHOLDER.sub("ci-placeholder", text)


def templates() -> list[Path]:
    return sorted(TEMPLATE_ROOT.rglob("main.template.tf"))


#: One ``provider "<source>" { ... }`` block, non-greedy up to its closing brace.
_BLOCK_RE = re.compile(r'provider "([^"]+)" \{(.*?)\n\}', re.DOTALL)


def provider_blocks(body: str) -> list[tuple[str, str, int]]:
    """Return ``(source, version, h1_count)`` for each provider in a lockfile.

    ``h1:`` hashes are per-platform: ``terraform providers lock`` records one
    per ``-platform`` it was given, because each platform is a distinct provider
    zip with a distinct hash.  ``zh:`` hashes come from the registry's signed
    ``SHA256SUMS`` and cover every platform at once, so they say nothing about
    which platforms were locked -- counting them would always pass.
    """
    out: list[tuple[str, str, int]] = []
    for source, block in _BLOCK_RE.findall(body):
        version = re.search(r'version\s*=\s*"([^"]+)"', block)
        out.append((source, version.group(1) if version else "?",
                    block.count('"h1:')))
    return out


def check() -> int:
    missing: list[str] = []
    for tpl in templates():
        name = tpl.relative_to(TEMPLATE_ROOT).parent.as_posix()
        lock = tpl.parent / LOCK_NAME
        if not lock.is_file():
            missing.append(name)
            print(f"  {name}: MISSING {LOCK_NAME}")
            continue
        body = lock.read_text(encoding="utf-8")
        blocks = provider_blocks(body)
        # A lockfile with no h1:/zh: hashes pins a version but authenticates
        # nothing, which is the failure mode worth catching.
        if "h1:" not in body and "zh:" not in body:
            missing.append(name)
            print(f"  {name}: {LOCK_NAME} has no checksums")
            continue
        # Platform coverage.  This compares *how many* platforms each provider
        # was locked for against len(PLATFORMS); it cannot verify *which* ones,
        # because the lockfile format does not record platform names anywhere.
        # A hand-run that passes the right number of wrong platforms still
        # slips through -- hence "always regenerate through this script".
        short = [(s.rsplit("/", 1)[-1], v, n) for s, v, n in blocks]
        thin = [(p, n) for p, _, n in short if n != len(PLATFORMS)]
        if thin:
            missing.append(name)
            print(f"  {name}: {LOCK_NAME} covers {len(PLATFORMS)} platform(s) "
                  f"{PLATFORMS} but " + ", ".join(
                      f"{p} has {n} h1 hash(es)" for p, n in thin))
            continue
        pins = ", ".join(f"{p}={v}" for p, v, _ in short)
        print(f"  {name}: ok ({pins})")
    if missing:
        print(f"\n{len(missing)} template(s) without a usable lockfile: "
              f"{', '.join(missing)}", file=sys.stderr)
        return 1
    print(f"\nall {len(templates())} templates have a provider lockfile "
          f"covering {len(PLATFORMS)} platforms")
    return 0


def generate() -> int:
    if not shutil.which("terraform"):
        print("terraform not installed; cannot generate lockfiles",
              file=sys.stderr)
        return 1

    # Share one plugin cache across all ten templates, otherwise every provider
    # is downloaded ten times.
    cache = REPO_ROOT / ".terraform-plugin-cache"
    cache.mkdir(exist_ok=True)
    env = dict(os.environ, TF_PLUGIN_CACHE_DIR=str(cache),
               TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1")

    failures: list[str] = []
    for tpl in templates():
        name = tpl.relative_to(TEMPLATE_ROOT).parent.as_posix()
        with tempfile.TemporaryDirectory() as work:
            (Path(work) / "main.tf").write_text(
                render(tpl.read_text(encoding="utf-8")), encoding="utf-8")
            cmd = ["terraform", "providers", "lock"]
            cmd += [f"-platform={p}" for p in PLATFORMS]
            res = subprocess.run(cmd, cwd=work, env=env,
                                 capture_output=True, text=True)
            if res.returncode != 0:
                failures.append(name)
                print(f"  {name}: LOCK FAILED")
                print((res.stderr or res.stdout)[-1500:], file=sys.stderr)
                continue
            produced = Path(work) / LOCK_NAME
            if not produced.is_file():
                failures.append(name)
                print(f"  {name}: terraform produced no {LOCK_NAME}")
                continue
            shutil.copyfile(produced, tpl.parent / LOCK_NAME)
            print(f"  {name}: ok")

    if failures:
        print(f"\nFAILED: {', '.join(failures)}", file=sys.stderr)
        return 1
    print(f"\nwrote {LOCK_NAME} for all {len(templates())} templates")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify lockfiles exist and carry checksums; no network")
    args = ap.parse_args()
    return check() if args.check else generate()


if __name__ == "__main__":
    raise SystemExit(main())
