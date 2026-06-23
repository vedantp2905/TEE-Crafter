"""A shipped lockfile must cover every platform an operator can run from.

``.terraform.lock.hcl`` records one ``h1:`` hash per platform it was locked
for, because each platform is a separate provider zip.  Miss a platform and
``terraform init`` on that host *rewrites* the staged lockfile to add the hash
it needs, so the artifact terraform ran against stops matching the one the repo
ships.

Scope of the harm, measured rather than assumed (terraform 1.x, ``gpu_cc/aws``,
2026-08-22): versions stay pinned by ``version =``, and authentication rides on
the registry-signed ``zh:`` hashes — strip only the ``h1:`` hashes and ``init``
warns and exits 0; strip the ``zh:`` hashes too and it fails with "Invalid
provider hash set", exit 1.  So this is build hygiene, not a verification or
version-drift hole.  It is worth a test because the rewrite is silent and
because the fix is free.

This is not hypothetical.  During the aws 6 / azurerm 5 / google 7 bump the ten
lockfiles were regenerated with a hand-run ``terraform providers lock
-platform=linux_amd64 -platform=linux_arm64`` instead of through
``.github/scripts/generate_provider_locks.py``, whose ``PLATFORMS`` names
``darwin_arm64``.  Every lockfile came out with correct versions, real
checksums, and no Apple Silicon coverage.  The old ``--check`` asserted only
that *some* hash existed, so it passed; the symptom surfaced as ``init``
reporting "Terraform has made some changes to the provider dependency
selections recorded in the .terraform.lock.hcl file" while planning
``gpu_cc/aws`` on 2026-08-22.

What these tests can and cannot do: the lockfile format records hash *counts*
but never platform *names*, so coverage is only checkable by cardinality.  A
regeneration that passes the right number of wrong platforms is not detectable
here — which includes the incident above, where two platforms were passed and
two were expected.  These tests catch it only because ``PLATFORMS`` grew to
three at the same time.  That is why the generator's docstring insists on
regenerating through the script rather than by hand: running it is the only
thing that actually guarantees the platform set.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
GEN_SCRIPT = REPO_ROOT / ".github/scripts/generate_provider_locks.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_provider_locks", str(GEN_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load_generator()

LOCKFILES = sorted(
    (REPO_ROOT / "apps/cli/src/tee_crafter/templates").rglob(
        ".terraform.lock.hcl"))


def test_the_lockfiles_were_found():
    """Guard the premise: every parametrised test below is vacuous if empty."""
    assert len(LOCKFILES) == 10, (
        f"expected 10 shipped lockfiles, found {len(LOCKFILES)}")


class TestTheGeneratorTargetsTheHostsWeSupport:
    def test_linux_amd64_is_covered(self):
        """Where terraform actually runs — the CLI re-execs into linux/amd64."""
        assert "linux_amd64" in gen.PLATFORMS

    def test_darwin_arm64_is_covered(self):
        """An Apple Silicon host outside the re-exec (TEE_CRAFTER_IN_DOCKER=1).
        This is the platform the hand-run regeneration dropped."""
        assert "darwin_arm64" in gen.PLATFORMS

    def test_no_duplicates(self):
        """A duplicate would inflate the expected h1 count and make every
        shipped lockfile look thin."""
        assert len(set(gen.PLATFORMS)) == len(gen.PLATFORMS)


class TestEveryShippedLockfileCoversEveryPlatform:
    @pytest.mark.parametrize(
        "lock", LOCKFILES,
        ids=[str(p.parent.relative_to(
            REPO_ROOT / "apps/cli/src/tee_crafter/templates")) for p in LOCKFILES])
    def test_each_provider_has_one_h1_per_platform(self, lock):
        blocks = gen.provider_blocks(lock.read_text(encoding="utf-8"))
        assert blocks, f"{lock} parsed to zero provider blocks"
        for source, version, h1 in blocks:
            assert h1 == len(gen.PLATFORMS), (
                f"{source} {version} has {h1} h1 hash(es) but "
                f"{len(gen.PLATFORMS)} platforms are targeted "
                f"{gen.PLATFORMS} — terraform init will rewrite this lockfile "
                f"on any uncovered host")

    @pytest.mark.parametrize(
        "lock", LOCKFILES,
        ids=[str(p.parent.relative_to(
            REPO_ROOT / "apps/cli/src/tee_crafter/templates")) for p in LOCKFILES])
    def test_registry_signed_hashes_are_present_too(self, lock):
        """``zh:`` hashes come from the registry's signed SHA256SUMS.  They do
        not prove platform coverage, but losing them would drop the signature
        chain that authenticates the h1 hashes in the first place."""
        assert "zh:" in lock.read_text(encoding="utf-8"), lock


class TestProviderBlockParsing:
    """``provider_blocks`` is the oracle the check depends on, so it gets its
    own tests rather than being trusted."""

    SAMPLE = '''# This file is maintained automatically by "terraform init".
provider "registry.terraform.io/hashicorp/aws" {
  version     = "6.61.0"
  constraints = "~> 6.0"
  hashes = [
    "h1:AAAA=",
    "h1:BBBB=",
    "h1:CCCC=",
    "zh:1111",
    "zh:2222",
  ]
}

provider "registry.terraform.io/hashicorp/random" {
  version     = "3.9.0"
  constraints = "~> 3.0"
  hashes = [
    "h1:DDDD=",
    "zh:3333",
  ]
}
'''

    def test_both_providers_are_found(self):
        blocks = gen.provider_blocks(self.SAMPLE)
        assert [b[0] for b in blocks] == [
            "registry.terraform.io/hashicorp/aws",
            "registry.terraform.io/hashicorp/random",
        ]

    def test_versions_are_read_not_constraints(self):
        blocks = dict((s.rsplit("/", 1)[-1], v)
                      for s, v, _ in gen.provider_blocks(self.SAMPLE))
        assert blocks == {"aws": "6.61.0", "random": "3.9.0"}

    def test_h1_hashes_are_counted_per_provider(self):
        counts = dict((s.rsplit("/", 1)[-1], n)
                      for s, _, n in gen.provider_blocks(self.SAMPLE))
        assert counts == {"aws": 3, "random": 1}

    def test_zh_hashes_are_not_counted(self):
        """Counting zh: would make the check always pass — the registry ships
        one signed SHA256SUMS covering all platforms regardless of what was
        locked."""
        counts = dict((s.rsplit("/", 1)[-1], n)
                      for s, _, n in gen.provider_blocks(self.SAMPLE))
        # 2 zh for aws, 1 for random; if they leaked in the counts would be 5/2.
        assert counts["aws"] == 3 and counts["random"] == 1

    def test_a_provider_with_no_version_does_not_crash(self):
        blocks = gen.provider_blocks(
            'provider "registry.terraform.io/x/y" {\n  hashes = ["h1:Z="]\n}\n')
        assert blocks == [("registry.terraform.io/x/y", "?", 1)]

    def test_empty_input_yields_nothing(self):
        assert gen.provider_blocks("") == []


class TestCheckActuallyFailsOnAThinLockfile:
    """Mutation tests: build a fake template tree and confirm ``check()``
    returns non-zero for the exact defect that shipped."""

    def _tree(self, tmp_path, lock_body):
        tpl = tmp_path / "fakeplat"
        tpl.mkdir()
        (tpl / "main.template.tf").write_text("# nothing\n")
        (tpl / ".terraform.lock.hcl").write_text(lock_body)
        return tmp_path

    def _lock(self, h1_count):
        hashes = "\n".join(f'    "h1:{i}=",' for i in range(h1_count))
        return (f'provider "registry.terraform.io/hashicorp/aws" {{\n'
                f'  version = "6.61.0"\n  hashes = [\n{hashes}\n'
                f'    "zh:deadbeef",\n  ]\n}}\n')

    def test_full_coverage_passes(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(
            gen, "TEMPLATE_ROOT", self._tree(tmp_path, self._lock(len(gen.PLATFORMS))))
        assert gen.check() == 0
        assert "ok (aws=6.61.0)" in capsys.readouterr().out

    def test_one_platform_short_fails(self, tmp_path, monkeypatch, capsys):
        """The shipped defect: a lockfile missing exactly one platform."""
        monkeypatch.setattr(
            gen, "TEMPLATE_ROOT",
            self._tree(tmp_path, self._lock(len(gen.PLATFORMS) - 1)))
        assert gen.check() == 1
        out = capsys.readouterr().out
        assert "h1 hash(es)" in out and "aws" in out

    def test_zh_only_lockfile_fails(self, tmp_path, monkeypatch):
        """Registry-signed hashes alone pin nothing per-platform."""
        body = ('provider "registry.terraform.io/hashicorp/aws" {\n'
                '  version = "6.61.0"\n  hashes = [\n    "zh:dead",\n  ]\n}\n')
        monkeypatch.setattr(gen, "TEMPLATE_ROOT", self._tree(tmp_path, body))
        assert gen.check() == 1

    def test_no_hashes_at_all_fails(self, tmp_path, monkeypatch):
        body = ('provider "registry.terraform.io/hashicorp/aws" {\n'
                '  version = "6.61.0"\n}\n')
        monkeypatch.setattr(gen, "TEMPLATE_ROOT", self._tree(tmp_path, body))
        assert gen.check() == 1

    def test_a_missing_lockfile_still_fails(self, tmp_path, monkeypatch):
        tpl = tmp_path / "fakeplat"
        tpl.mkdir()
        (tpl / "main.template.tf").write_text("# nothing\n")
        monkeypatch.setattr(gen, "TEMPLATE_ROOT", tmp_path)
        assert gen.check() == 1


class TestProviderVersionsAgreeAcrossTemplates:
    """Ten templates resolving the same provider to different versions would
    mean two platforms attest against different infrastructure code paths."""

    def test_each_provider_pins_one_version_repo_wide(self):
        seen: dict[str, dict[str, list[str]]] = {}
        for lock in LOCKFILES:
            name = str(lock.parent.name)
            for source, version, _ in gen.provider_blocks(
                    lock.read_text(encoding="utf-8")):
                short = source.rsplit("/", 1)[-1]
                seen.setdefault(short, {}).setdefault(version, []).append(name)
        disagreements = {p: v for p, v in seen.items() if len(v) > 1}
        assert not disagreements, (
            f"providers pinned to more than one version: {disagreements}")
