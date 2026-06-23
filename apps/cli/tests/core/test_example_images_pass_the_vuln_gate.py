"""The shipped example images have to survive their own vulnerability gate.

``examples/gpu_confidential_inference`` had never been built or scanned — its
base is multi-gigabyte, so it got skipped every time.  Built and scanned on
2026-08-22 with the same Trivy invocation ``core.security.vuln_scan`` makes, and
scored through ``_parse_trivy_report`` plus the thresholds in
``cli/commands/deploy/flow_container.py`` (fixable CRITICAL == 0, fixable
HIGH <= 0, fixable MEDIUM <= 25):

    base pytorch/pytorch:2.5.1-cuda12.4    blocking  C:22  H:283  M:2464  FAIL
    base 2.6.0 + apt upgrade + pip floors  blocking  C:0   H:2    M:3     FAIL
    ... plus .trivyignore                  blocking  C:0   H:0    M:3     PASS

Of the 2,723 fixable OS findings, 2,565 were ``linux-libc-dev`` alone; the rest
of the CRITICALs were the same package.  On the Python side the one blocking
CRITICAL was ``torch`` 2.5.1 (CVE-2025-32434, fixed in 2.6.0), which is why the
base image moved rather than being papered over.

These tests cannot run Trivy — that needs Docker and a 3.4 GB image — so they
pin the *structure* of the fix instead: the OS-patch step, the discoverability
of the accepted-risk file through the same helper the gate uses, and the one
invariant that would silently undo the whole thing, which is
``requirements.txt`` pinning a torch version older than the base image's.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tee_crafter.core.security.vuln_scan import (
    IGNORE_FILE_NAME,
    count_ignore_entries,
    ignore_file_for,
)

EXAMPLES = Path(__file__).resolve().parents[4] / "examples"

#: Every example that ships a Dockerfile the CLI can be pointed at.
EXAMPLE_DIRS = sorted(
    p.parent for p in EXAMPLES.glob("*/Dockerfile")
)

GPU = EXAMPLES / "gpu_confidential_inference"

_ID_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$")


def test_the_examples_directory_was_found():
    """Guard the premise: everything below is vacuous if this list is empty."""
    assert EXAMPLE_DIRS, f"no example Dockerfiles under {EXAMPLES}"
    assert GPU in EXAMPLE_DIRS


class TestOsPatchesAreApplied:
    @pytest.mark.parametrize("d", EXAMPLE_DIRS, ids=lambda p: p.name)
    def test_every_example_upgrades_its_base_packages(self, d):
        """A published base image lags the distro archive by however long since
        it was built, and the gate counts every fixable OS finding."""
        text = (d / "Dockerfile").read_text()
        assert "apt-get upgrade" in text, (
            f"{d.name} never applies distro security updates")

    @pytest.mark.parametrize("d", EXAMPLE_DIRS, ids=lambda p: p.name)
    def test_the_apt_lists_are_cleaned_up(self, d):
        """Otherwise the package lists ship inside the measured image."""
        text = (d / "Dockerfile").read_text()
        assert "rm -rf /var/lib/apt/lists" in text, d.name


class TestAcceptedRiskFilesAreWellFormed:
    @pytest.mark.parametrize(
        "d", [p for p in EXAMPLE_DIRS if (p / IGNORE_FILE_NAME).is_file()],
        ids=lambda p: p.name)
    def test_entries_are_valid_advisory_ids(self, d):
        for line in (d / IGNORE_FILE_NAME).read_text().splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            assert _ID_RE.match(entry), (
                f"{d.name}/{IGNORE_FILE_NAME}: {entry!r} is not a CVE or GHSA id")

    @pytest.mark.parametrize(
        "d", [p for p in EXAMPLE_DIRS if (p / IGNORE_FILE_NAME).is_file()],
        ids=lambda p: p.name)
    def test_every_entry_is_explained(self, d):
        """An unexplained accepted risk is indistinguishable from a suppressed
        one.  Each id must have a comment somewhere above it."""
        text = (d / IGNORE_FILE_NAME).read_text()
        entries = [l.strip() for l in text.splitlines()
                   if l.strip() and not l.lstrip().startswith("#")]
        comments = [l for l in text.splitlines() if l.lstrip().startswith("#")]
        assert entries, f"{d.name} ships an empty {IGNORE_FILE_NAME}"
        assert len(comments) >= len(entries), (
            f"{d.name}/{IGNORE_FILE_NAME} has {len(entries)} entries and only "
            f"{len(comments)} comment lines")

    @pytest.mark.parametrize(
        "d", [p for p in EXAMPLE_DIRS if (p / IGNORE_FILE_NAME).is_file()],
        ids=lambda p: p.name)
    def test_the_gate_can_find_it(self, d):
        """Resolved through the same helper ``scan_image`` uses, so a misnamed
        or misplaced file fails here rather than silently blocking a deploy."""
        found = ignore_file_for(str(d))
        assert found, f"{d.name}: ignore_file_for() does not see the file"
        assert count_ignore_entries(found) >= 1


class TestTheGpuExampleStaysAheadOfTheTorchCve:
    """CVE-2025-32434 is a fixable CRITICAL, and the gate blocks on those."""

    def _base_torch_version(self) -> str:
        m = re.search(r"^FROM pytorch/pytorch:(\d+\.\d+\.\d+)-",
                      (GPU / "Dockerfile").read_text(), re.M)
        assert m, "could not read the base image's torch version"
        return m.group(1)

    def _pinned_torch_version(self) -> str:
        m = re.search(r"^torch==(\d+\.\d+\.\d+)",
                      (GPU / "requirements.txt").read_text(), re.M)
        assert m, "requirements.txt does not pin torch"
        return m.group(1)

    @staticmethod
    def _key(v: str):
        return tuple(int(x) for x in v.split("."))

    def test_the_base_image_is_at_least_2_6_0(self):
        assert self._key(self._base_torch_version()) >= (2, 6, 0), (
            "torch < 2.6.0 carries CVE-2025-32434 (fixable CRITICAL), which "
            "fails VLN-002 and blocks the deploy")

    def test_the_pin_matches_the_base(self):
        """The Dockerfile runs ``pip install -r requirements.txt`` *after* the
        base image is in place, so a stale pin here does not merely disagree
        with the base — it reinstalls the vulnerable torch over it."""
        assert self._pinned_torch_version() == self._base_torch_version()

    def test_torchvision_is_pinned_alongside_torch(self):
        """torchvision declares an exact ``torch==`` dependency, so an
        unmatched pair makes pip resolve one of the two backwards."""
        text = (GPU / "requirements.txt").read_text()
        assert re.search(r"^torchvision==\d+\.\d+\.\d+", text, re.M)

    def test_the_security_floors_come_after_the_requirements_install(self):
        """Ordering is load-bearing: requirements.txt pins the CUDA stack, and
        anything it drags in must not pull an upgraded package back down."""
        text = (GPU / "Dockerfile").read_text()
        assert text.index("-r requirements.txt") < text.index("pillow>=")

    @pytest.mark.parametrize("pkg,floor", [
        ("pillow", "12.3.0"), ("urllib3", "2.7.0"), ("setuptools", "83.0.0"),
        ("wheel", "0.46.2"), ("requests", "2.33.0"), ("idna", "3.15"),
        ("Jinja2", "3.1.6"), ("filelock", "3.20.3"), ("h2", "4.4.1"),
        ("Brotli", "1.2.0"), ("soupsieve", "2.8.4"), ("pip", "26.1.2"),
    ])
    def test_each_flagged_package_has_its_fixed_version_as_a_floor(self, pkg, floor):
        """Floors are the versions Trivy named, not round numbers."""
        text = (GPU / "Dockerfile").read_text()
        assert f'"{pkg}>={floor}"' in text, (
            f"{pkg} floor missing or below the fixed version {floor}")


class TestTheGpuHandlerReadsARealAttribute:
    """Found while building the image the gate had never seen."""

    def test_device_memory_uses_total_memory(self):
        text = (GPU / "handler.py").read_text()
        assert "props.total_memory" in text
        # Attribute accesses only — the comment explaining the bug names the
        # misspelling, and matching prose here would fail on the fix itself.
        assert not re.search(r"\.total_mem\b", text), (
            "torch._C._CudaDeviceProperties defines total_memory and has no "
            "__getattr__, so total_mem raised AttributeError in _ensure_model "
            "— which process_request calls first, failing every request")
