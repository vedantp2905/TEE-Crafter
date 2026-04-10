"""Automated vulnerability scanning for container images.

Integrates with Trivy (preferred) or Grype at build time to scan Docker images
for known CVEs.  Results are recorded in the audit trail and saved alongside
build artifacts for compliance reporting.

Gracefully degrades if neither scanner is installed.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict

logger = logging.getLogger("tee_crafter.vuln_scan")


#: Demand zero CRITICAL/HIGH regardless of whether a fix exists upstream.
STRICT_ENV = "TEE_CRAFTER_VULN_STRICT"


def _strict() -> bool:
    return os.environ.get(STRICT_ENV, "").strip().lower() in (
        "1", "true", "yes", "y", "on")


@dataclass
class VulnScanResult:
    """Aggregated vulnerability scan output.

    Counts are split by whether the finding is *actionable* — i.e. whether the
    scanner knows of a fixed version.  The gate blocks on the actionable ones.

    That split is the whole point, and it was learned the hard way.  Scanning
    the flagship example (`examples/docker_flask_api`, a `python:3.12-slim`
    base) on 2026-08-21 produced 4 CRITICAL / 15 HIGH, of which **17 of 19 had
    no fix available** — Debian had marked them `affected` or `fix_deferred` —
    and **not one CRITICAL was fixable**.  The gate demanded zero and therefore
    could not be satisfied by any amount of work, on any current Debian or
    Alpine Python base (all four candidates were scanned; all carried the same
    unfixed `util-linux` CVEs).

    An unsatisfiable gate is worse than a narrower one, because the only way
    past it is ``--allow-vulnerable``, which switches off the check entirely and
    becomes routine.  Blocking on "there is a fix and you have not applied it"
    is a gate that means something and that a maintainer can actually clear.
    Unfixed findings are still counted, still recorded in the provenance, and
    still printed — they are demoted from blocking, not hidden — and
    ``TEE_CRAFTER_VULN_STRICT=1`` restores zero-tolerance for operators whose
    policy demands it.
    """
    scanner: str
    image: str
    success: bool
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    total: int = 0
    error: str = ""
    report_path: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    #: Findings the scanner reports a fixed version for, by severity.
    fixable_critical: int = 0
    fixable_high: int = 0
    fixable_medium: int = 0

    @property
    def unfixed_critical(self) -> int:
        return max(0, self.critical - self.fixable_critical)

    @property
    def unfixed_high(self) -> int:
        return max(0, self.high - self.fixable_high)

    @property
    def unfixed_medium(self) -> int:
        return max(0, self.medium - self.fixable_medium)

    # ``blocking_*`` is the single source of truth for "does this count against
    # us".  Both the deploy gate and the VLN-002/003/004 ledger checks read it,
    # because they used to disagree: the gate passed on an image with no fixable
    # findings while the ledger recorded VLN-002 ``fail`` from the raw count —
    # and VLN-002 is in DEFAULT_REQUIRED_CHECKS, so `verify-provenance` then
    # failed CI on a build the deploy had approved.
    @property
    def blocking_critical(self) -> int:
        return self.critical if _strict() else self.fixable_critical

    @property
    def blocking_high(self) -> int:
        return self.high if _strict() else self.fixable_high

    @property
    def blocking_medium(self) -> int:
        return self.medium if _strict() else self.fixable_medium

    @property
    def passed(self) -> bool:
        """True if the scan succeeded with nothing left to act on.

        Under ``TEE_CRAFTER_VULN_STRICT=1`` this reverts to the original
        zero-CRITICAL/HIGH rule.
        """
        return (self.success
                and self.blocking_critical == 0
                and self.blocking_high == 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "image": self.image,
            "success": self.success,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "unknown": self.unknown,
            "total": self.total,
            "passed": self.passed,
            "error": self.error,
            "report_path": self.report_path,
            "fixable_critical": self.fixable_critical,
            "fixable_high": self.fixable_high,
            "fixable_medium": self.fixable_medium,
            "unfixed_critical": self.unfixed_critical,
            "unfixed_high": self.unfixed_high,
            "unfixed_medium": self.unfixed_medium,
            "strict": _strict(),
        }


def _has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _run_trivy(image: str, report_dir: str,
               ignore_file: str = "") -> VulnScanResult:
    """Run ``trivy image`` and parse JSON output."""
    report_path = os.path.join(report_dir, "trivy_report.json")

    cmd = [
        "trivy", "image",
        "--format", "json",
        "--output", report_path,
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
        "--no-progress",
        image,
    ]
    if ignore_file and os.path.isfile(ignore_file):
        # Per-source accepted-risk list.  The alternative an app author reaches
        # for otherwise is ``--allow-vulnerable``, which switches the scan off
        # wholesale; a checked-in ``.trivyignore`` is reviewable in a PR, names
        # the specific CVE IDs, and leaves every other finding blocking.  Its
        # use and entry count go into the build provenance so an auditor sees
        # that risks were accepted rather than absent.
        cmd[-1:-1] = ["--ignorefile", ignore_file]
    logger.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return VulnScanResult(
            scanner="trivy", image=image, success=False,
            error="Trivy scan timed out after 600s",
        )
    except FileNotFoundError:
        return VulnScanResult(
            scanner="trivy", image=image, success=False,
            error="trivy not found on PATH",
        )

    if proc.returncode not in (0, 1):
        return VulnScanResult(
            scanner="trivy", image=image, success=False,
            error=f"trivy exit code {proc.returncode}: {proc.stderr[:500]}",
        )

    return _parse_trivy_report(image, report_path)


def _parse_trivy_report(image: str, report_path: str) -> VulnScanResult:
    """Parse Trivy JSON report and count vulnerabilities by severity."""
    if not os.path.isfile(report_path):
        return VulnScanResult(
            scanner="trivy", image=image, success=False,
            error="Trivy report file not created",
        )

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        return VulnScanResult(
            scanner="trivy", image=image, success=False,
            error=f"Failed to parse Trivy report: {exc}",
        )

    counts: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0,
    }
    fixable: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    results = data.get("Results") or []
    for result in results:
        for vuln in result.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
            if sev in fixable and _trivy_is_fixable(vuln):
                fixable[sev] += 1

    total = sum(counts.values())

    return VulnScanResult(
        scanner="trivy",
        image=image,
        success=True,
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        unknown=counts["UNKNOWN"],
        total=total,
        report_path=report_path,
        fixable_critical=fixable["CRITICAL"],
        fixable_high=fixable["HIGH"],
        fixable_medium=fixable["MEDIUM"],
        raw={"results_count": len(results)},
    )


#: Trivy ``Status`` values that mean "no patch you can apply".
#: https://trivy.dev/latest/docs/configuration/filtering/  (vulnerability status)
_TRIVY_UNFIXED_STATUSES = frozenset({
    "affected", "fix_deferred", "will_not_fix", "end_of_life", "unknown",
})


def _trivy_is_fixable(vuln: Dict[str, Any]) -> bool:
    """Whether Trivy reports an upstream fix for *vuln*.

    Deliberately an **allowlist of not-fixable**, not a check for
    ``status == "fixed"``.  A status this function has never heard of — a new
    Trivy release, a different distro's vocabulary — then counts as fixable and
    therefore *blocks*.  That is the safe direction: over-reporting costs a
    maintainer one look at the report, while under-reporting lets a genuinely
    patchable CRITICAL through the gate, which is the failure this whole change
    exists to prevent.

    ``FixedVersion`` is the fallback for reports that omit ``Status``.
    """
    status = (vuln.get("Status") or "").strip().lower()
    if status:
        return status not in _TRIVY_UNFIXED_STATUSES
    return bool((vuln.get("FixedVersion") or "").strip())


def _run_grype(image: str, report_dir: str) -> VulnScanResult:
    """Run ``grype`` and parse JSON output."""
    report_path = os.path.join(report_dir, "grype_report.json")

    cmd = [
        "grype", image,
        "-o", "json",
        "--file", report_path,
    ]
    logger.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return VulnScanResult(
            scanner="grype", image=image, success=False,
            error="Grype scan timed out after 600s",
        )
    except FileNotFoundError:
        return VulnScanResult(
            scanner="grype", image=image, success=False,
            error="grype not found on PATH",
        )

    if proc.returncode not in (0, 1):
        return VulnScanResult(
            scanner="grype", image=image, success=False,
            error=f"grype exit code {proc.returncode}: {proc.stderr[:500]}",
        )

    return _parse_grype_report(image, report_path)


def _parse_grype_report(image: str, report_path: str) -> VulnScanResult:
    """Parse Grype JSON report and count vulnerabilities by severity."""
    if not os.path.isfile(report_path):
        return VulnScanResult(
            scanner="grype", image=image, success=False,
            error="Grype report file not created",
        )

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        return VulnScanResult(
            scanner="grype", image=image, success=False,
            error=f"Failed to parse Grype report: {exc}",
        )

    counts: Dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0,
    }
    fixable: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0}
    for match in data.get("matches") or []:
        vuln = match.get("vulnerability", {})
        sev = vuln.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1
        if sev in fixable and _grype_is_fixable(vuln):
            fixable[sev] += 1

    total = sum(counts.values())

    return VulnScanResult(
        scanner="grype",
        image=image,
        success=True,
        critical=counts["Critical"],
        high=counts["High"],
        medium=counts["Medium"],
        low=counts["Low"],
        unknown=counts["Unknown"],
        total=total,
        report_path=report_path,
        fixable_critical=fixable["Critical"],
        fixable_high=fixable["High"],
        fixable_medium=fixable["Medium"],
        raw={"matches_count": total},
    )


def _grype_is_fixable(vuln: Dict[str, Any]) -> bool:
    """Whether Grype reports an upstream fix for *vuln*.

    Grype nests this as ``vulnerability.fix = {"versions": [...], "state":
    "fixed"|"not-fixed"|"wont-fix"|"unknown"}``.  Same bias as the Trivy side:
    an unrecognised state counts as fixable, because a false "you can fix this"
    costs a look at the report and a false "nothing to do" ships a patchable
    CRITICAL.
    """
    fix = vuln.get("fix") or {}
    state = (fix.get("state") or "").strip().lower()
    if state:
        return state == "fixed"
    return bool(fix.get("versions"))


#: An app author's accepted-risk list, read from the source directory.
IGNORE_FILE_NAME = ".trivyignore"


def ignore_file_for(source_path: str) -> str:
    """Path to *source_path*'s ``.trivyignore``, or ``""`` if absent."""
    if not source_path:
        return ""
    candidate = os.path.join(source_path, IGNORE_FILE_NAME)
    return candidate if os.path.isfile(candidate) else ""


def count_ignore_entries(ignore_file: str) -> int:
    """Number of non-comment entries, for the provenance record."""
    if not ignore_file or not os.path.isfile(ignore_file):
        return 0
    try:
        with open(ignore_file, "r", encoding="utf-8") as f:
            return sum(1 for line in f
                       if line.strip() and not line.lstrip().startswith("#"))
    except OSError:
        return 0


def scan_image(image: str, report_dir: str,
               ignore_file: str = "") -> VulnScanResult:
    """Scan a Docker image for vulnerabilities.

    Tries Trivy first, falls back to Grype, and gracefully returns a
    not-available result if neither is installed.

    *ignore_file* is an optional ``.trivyignore`` of CVE IDs the app author has
    reviewed and accepted.  Only Trivy honours it; Grype takes a different
    format, and silently ignoring the file there would be worse than not
    supporting it, so the fallback path leaves every finding blocking.
    """
    os.makedirs(report_dir, exist_ok=True)

    if _has_tool("trivy"):
        logger.info("Using Trivy for vulnerability scanning")
        return _run_trivy(image, report_dir, ignore_file=ignore_file)

    if _has_tool("grype"):
        logger.info("Using Grype for vulnerability scanning (Trivy not found)")
        return _run_grype(image, report_dir)

    logger.warning(
        "No vulnerability scanner found (install trivy or grype for automated scanning)"
    )
    return VulnScanResult(
        scanner="none",
        image=image,
        success=False,
        error="No vulnerability scanner available. Install trivy or grype.",
    )
