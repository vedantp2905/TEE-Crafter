"""The vulnerability gate must block on findings someone can actually fix.

Scanning the flagship example (`examples/docker_flask_api`, a `python:3.12-slim`
base) on 2026-08-21 produced 4 CRITICAL / 15 HIGH, and **17 of the 19 had no
upstream fix** — Debian had them as `affected` or `fix_deferred`.  Not one
CRITICAL was fixable.  `python:3.13-slim`, `python:3.14-slim` and
`python:3.13-alpine` were all scanned too and carry the same unfixed
`util-linux` CVEs, so no base-image choice satisfies a zero-tolerance rule.

A gate that cannot be satisfied is worse than a narrower one: the only way past
it is `--allow-vulnerable`, which disables the check completely and becomes
routine.  So the gate now blocks on "a fix exists and you have not applied it",
which is both meaningful and clearable, while unfixed findings stay counted, in
the provenance, and on screen.

The assertions below pin three things a well-meaning cleanup would break:
unfixed findings must not block, fixable ones must, and the strict escape hatch
must restore the old behaviour exactly.
"""

import json

import pytest

from tee_crafter.core.security import vuln_scan
from tee_crafter.core.security.vuln_scan import (
    STRICT_ENV,
    VulnScanResult,
    _parse_trivy_report,
)


def _trivy_report(vulns):
    return {"Results": [{"Target": "img", "Vulnerabilities": vulns}]}


def _v(sev, status=None, fixed_version=None, vid="CVE-0000-0001"):
    out = {"Severity": sev, "VulnerabilityID": vid, "PkgName": "pkg"}
    if status is not None:
        out["Status"] = status
    if fixed_version is not None:
        out["FixedVersion"] = fixed_version
    return out


def _parse(tmp_path, vulns):
    p = tmp_path / "trivy_report.json"
    p.write_text(json.dumps(_trivy_report(vulns)), encoding="utf-8")
    return _parse_trivy_report("img", str(p))


class TestFixabilityClassification:
    def test_debian_unfixed_statuses_are_not_fixable(self, tmp_path):
        """The real-world case: the distro has declined or deferred."""
        res = _parse(tmp_path, [
            _v("CRITICAL", status="affected"),
            _v("CRITICAL", status="fix_deferred"),
            _v("HIGH", status="will_not_fix"),
            _v("HIGH", status="end_of_life"),
        ])
        assert (res.critical, res.high) == (2, 2)
        assert (res.fixable_critical, res.fixable_high) == (0, 0)
        assert (res.unfixed_critical, res.unfixed_high) == (2, 2)

    def test_fixed_status_is_fixable(self, tmp_path):
        res = _parse(tmp_path, [
            _v("HIGH", status="fixed", fixed_version="78.1.1"),
            _v("CRITICAL", status="fixed", fixed_version="2.0"),
        ])
        assert (res.fixable_critical, res.fixable_high) == (1, 1)

    def test_missing_status_falls_back_to_fixed_version(self, tmp_path):
        """Some reports omit ``Status``; a FixedVersion still means actionable."""
        res = _parse(tmp_path, [
            _v("HIGH", fixed_version="1.2.1"),
            _v("HIGH"),
        ])
        assert res.fixable_high == 1

    def test_unknown_status_counts_as_fixable(self, tmp_path):
        """Bias toward over-reporting.

        A false "you can fix this" costs one look at the report.  A false
        "nothing to do" ships a patchable CRITICAL through the gate.
        """
        res = _parse(tmp_path, [_v("CRITICAL", status="some_new_state")])
        assert res.fixable_critical == 1


class TestGateDecision:
    def test_unfixed_only_passes(self, monkeypatch):
        monkeypatch.delenv(STRICT_ENV, raising=False)
        res = VulnScanResult(
            scanner="trivy", image="i", success=True,
            critical=4, high=15, fixable_critical=0, fixable_high=0)
        assert res.passed is True
        assert (res.blocking_critical, res.blocking_high) == (0, 0)

    def test_one_fixable_high_blocks(self, monkeypatch):
        monkeypatch.delenv(STRICT_ENV, raising=False)
        res = VulnScanResult(
            scanner="trivy", image="i", success=True,
            critical=4, high=15, fixable_critical=0, fixable_high=1)
        assert res.passed is False
        assert res.blocking_high == 1

    def test_strict_restores_zero_tolerance(self, monkeypatch):
        monkeypatch.setenv(STRICT_ENV, "1")
        res = VulnScanResult(
            scanner="trivy", image="i", success=True,
            critical=4, high=15, fixable_critical=0, fixable_high=0)
        assert res.passed is False
        assert (res.blocking_critical, res.blocking_high) == (4, 15)

    def test_a_failed_scan_never_passes(self, monkeypatch):
        """No scanner output is not a clean bill of health."""
        monkeypatch.delenv(STRICT_ENV, raising=False)
        res = VulnScanResult(scanner="trivy", image="i", success=False)
        assert res.passed is False

    def test_clean_image_passes_either_way(self, monkeypatch):
        for strict in ("", "1"):
            if strict:
                monkeypatch.setenv(STRICT_ENV, strict)
            else:
                monkeypatch.delenv(STRICT_ENV, raising=False)
            res = VulnScanResult(scanner="trivy", image="i", success=True)
            assert res.passed is True

    def test_provenance_records_both_numbers(self, monkeypatch):
        """The audit trail must not lose the unfixed count.

        Demoting a finding from blocking to informational is only defensible if
        it is still written down.
        """
        monkeypatch.delenv(STRICT_ENV, raising=False)
        d = VulnScanResult(
            scanner="trivy", image="i", success=True,
            critical=4, high=15, fixable_critical=0, fixable_high=0).to_dict()
        assert d["critical"] == 4 and d["high"] == 15
        assert d["unfixed_critical"] == 4 and d["unfixed_high"] == 15
        assert d["fixable_critical"] == 0 and d["fixable_high"] == 0
        assert d["strict"] is False


class TestGateAndLedgerAgree:
    """The deploy gate and the VLN-002/003/004 ledger checks must not disagree.

    They did.  The gate read ``fixable_*`` while the ledger read the raw counts,
    so the live ``snp-aws`` run of 2026-08-21 approved a deploy *and* recorded
    ``VLN-002 fail | critical=4``.  ``VLN-002`` is in
    ``DEFAULT_REQUIRED_CHECKS``, so ``verify-provenance --required-checks auto``
    would then have failed CI on a build the deploy had just passed — the same
    "two implementations of one question" shape as the stale egress summary.

    Both now read ``blocking_*``.  These assertions exist so a future edit
    cannot re-introduce the split silently.
    """

    def _ledger_verdicts(self, res, high_t=0, med_t=25):
        return {
            "VLN-002": res.blocking_critical == 0,
            "VLN-003": res.blocking_high <= high_t,
            "VLN-004": res.blocking_medium <= med_t,
        }

    def test_unfixed_only_passes_gate_and_ledger_together(self, monkeypatch):
        monkeypatch.delenv(STRICT_ENV, raising=False)
        # The real shape of the example image: lots of unfixed distro CVEs.
        res = VulnScanResult(
            scanner="trivy", image="i", success=True,
            critical=4, high=13, medium=47,
            fixable_critical=0, fixable_high=0, fixable_medium=0)
        assert res.passed is True
        assert all(self._ledger_verdicts(res).values())

    def test_a_fixable_critical_fails_gate_and_ledger_together(self, monkeypatch):
        monkeypatch.delenv(STRICT_ENV, raising=False)
        res = VulnScanResult(
            scanner="trivy", image="i", success=True,
            critical=1, high=0, medium=0, fixable_critical=1)
        assert res.passed is False
        assert self._ledger_verdicts(res)["VLN-002"] is False

    def test_strict_flips_gate_and_ledger_together(self, monkeypatch):
        monkeypatch.setenv(STRICT_ENV, "1")
        res = VulnScanResult(
            scanner="trivy", image="i", success=True,
            critical=4, high=13, medium=47,
            fixable_critical=0, fixable_high=0, fixable_medium=0)
        assert res.passed is False
        v = self._ledger_verdicts(res)
        assert v["VLN-002"] is False and v["VLN-003"] is False

    def test_ledger_reads_blocking_not_raw(self):
        """Named directly, because reverting to `critical` is the regression."""
        import inspect
        from tee_crafter.cli.commands.deploy import flow_container
        src = inspect.getsource(flow_container._emit_container_vln_verdicts)
        assert 'getattr(vuln_result, "blocking_critical"' in src
        assert 'getattr(vuln_result, "blocking_high"' in src
        assert 'getattr(vuln_result, "blocking_medium"' in src


class TestGrypeFixability:
    @pytest.mark.parametrize("fix,expected", [
        ({"state": "fixed", "versions": ["2.0"]}, True),
        ({"state": "not-fixed", "versions": []}, False),
        ({"state": "wont-fix", "versions": []}, False),
        ({"state": "unknown", "versions": []}, False),
        ({"versions": ["2.0"]}, True),
        ({}, False),
    ])
    def test_states(self, fix, expected):
        assert vuln_scan._grype_is_fixable({"fix": fix}) is expected
