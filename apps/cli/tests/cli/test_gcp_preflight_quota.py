"""GCP preflight must not let one dead API disable a different check.

On 2026-08-21, while configuring GCP for this project, every
``compute.googleapis.com`` ``machineTypes`` call returned HTTP 503
``backendError`` -- confirmed against the REST endpoint directly -- while
``regions``, ``zones``, ``networks`` and ``instances`` all answered normally.
Two defects surfaced under that condition:

1. ``_preflight_gcp`` reported the failure as "machine type may not be
   available in <zone>", attributing a Google-side outage to the operator's
   zone choice, and then ``return``ed -- which silently skipped the regional
   CPU quota check as well.  That is the same shape as the AWS
   ``except ClientError: pass`` fixed earlier in this file: a check the setup
   docs advertise, doing nothing, while printing nothing that says so.

2. The quota check only ever read the aggregate ``CPUS`` metric, but
   ``docs/gcp_setup.md`` documents ``N2D_CPUS`` / ``C3_CPUS`` as the gating
   metrics -- and they are the smaller ones in practice (this project reports
   ``N2D_CPUS=8`` and ``C3_CPUS=8`` against ``CPUS=32``).  A shape that the
   family quota refuses would pass preflight and fail mid-apply.

These are the first tests for ``preflight.py``'s GCP branch; it had none.
"""

import json

import click
import pytest

from tee_crafter.cli import preflight
from tee_crafter.cli.preflight import _gcp_vcpus, run_preflight


# The 503 body Compute Engine actually returned, trimmed to the line gcloud
# prints on stderr.
_BACKEND_ERROR = (
    "ERROR: (gcloud.compute.machine-types.describe) Could not fetch resource:\n"
    " - Internal error. Please try again or contact Google Support. "
    "(Code: '659931670446B.6903B27.517DE68')"
)


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _quota_json(**metrics):
    """Build a ``regions describe --format=json(quotas)`` payload."""
    return json.dumps({
        "quotas": [
            {"metric": m, "limit": float(lim), "usage": float(use)}
            for m, (lim, use) in metrics.items()
        ]
    })


def _fake_run(*, machine_type, quotas):
    """Stub ``subprocess.run`` for the two gcloud calls the branch makes."""
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if "machine-types" in cmd:
            return machine_type
        if "regions" in cmd:
            return quotas
        raise AssertionError(f"unexpected command: {cmd}")

    run.calls = calls
    return run


class TestGcpVcpuFallback:
    @pytest.mark.parametrize("name,expected", [
        ("n2d-standard-2", 2),
        ("c3-standard-4", 4),
        ("n2d-standard-16", 16),
        # Trailing token is the GPU count, not vCPUs -- the generic parse
        # would read 1 and wave through a shape that needs 26.
        ("a3-highgpu-1g", 26),
        # Unknown shapes return 0 so the caller reports "skipped, not
        # passed" instead of quota-checking against a guess.
        ("weird-shape-xl", 0),
        ("", 0),
    ])
    def test_parses_or_admits_ignorance(self, name, expected):
        assert _gcp_vcpus(name) == expected


class TestQuotaCheckSurvivesMachineTypeOutage:
    def test_quota_still_checked_when_machine_types_returns_503(
            self, monkeypatch, capsys):
        """The regression: a 503 here used to skip the quota check entirely."""
        run = _fake_run(
            machine_type=_Result(returncode=1, stderr=_BACKEND_ERROR),
            # N2D_CPUS is exhausted; the deploy must still be refused.
            quotas=_Result(stdout=_quota_json(
                N2D_CPUS=(8, 8), CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)

        with pytest.raises(click.ClickException) as exc:
            run_preflight("snp-gcp", "n2d-standard-2", "us-central1-a")

        assert "N2D_CPUS" in str(exc.value)
        # Proves the second gcloud call happened rather than being skipped.
        assert any("regions" in c for c in run.calls)

    def test_503_is_not_reported_as_unavailable_shape(
            self, monkeypatch, capsys):
        """A Google outage must not be blamed on the operator's zone."""
        run = _fake_run(
            machine_type=_Result(returncode=1, stderr=_BACKEND_ERROR),
            quotas=_Result(stdout=_quota_json(N2D_CPUS=(8, 0), CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)
        run_preflight("snp-gcp", "n2d-standard-2", "us-central1-a")

        out = capsys.readouterr().out
        assert "skipped, not passed" in out
        assert "may not be available" not in out

    def test_impersonation_failure_is_not_reported_as_unavailable_shape(
            self, monkeypatch, capsys):
        """A credential error must not be blamed on zone capacity.

        The first GCP bake matched exactly this: gcloud's impersonation error
        says "Gaia id not found for email <sa>", and a bare ``"not found" in
        stderr`` test classified it as a missing machine type, telling the
        operator to go check zone availability for an auth problem.
        """
        run = _fake_run(
            machine_type=_Result(
                returncode=1,
                stderr="ERROR: (gcloud.compute.machine-types.describe) "
                       "Gaia id not found for email "
                       "tee-crafter-deployer@example.iam.gserviceaccount.com"),
            quotas=_Result(stdout=_quota_json(N2D_CPUS=(8, 0), CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)
        run_preflight("snp-gcp", "n2d-standard-2", "us-central1-a")

        out = capsys.readouterr().out
        assert "may not be available" not in out
        assert "skipped, not passed" in out

    def test_genuine_404_still_warns_about_availability(
            self, monkeypatch, capsys):
        """The real "wrong zone" case must keep its actionable message."""
        run = _fake_run(
            machine_type=_Result(
                returncode=1,
                stderr="ERROR: ... was not found in zone us-central1-a"),
            quotas=_Result(stdout=_quota_json(N2D_CPUS=(8, 0), CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)
        run_preflight("snp-gcp", "n2d-standard-2", "us-central1-a")

        assert "may not be available" in capsys.readouterr().out

    def test_unknown_shape_reports_skipped_rather_than_guessing(
            self, monkeypatch, capsys):
        run = _fake_run(
            machine_type=_Result(returncode=1, stderr=_BACKEND_ERROR),
            quotas=_Result(stdout=_quota_json(CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)
        run_preflight("snp-gcp", "weird-shape-xl", "us-central1-a")

        out = capsys.readouterr().out
        assert "quota check skipped, not passed" in out


class TestFamilyQuotaIsChecked:
    def test_family_quota_refusal_is_caught_though_aggregate_is_fine(
            self, monkeypatch):
        """N2D_CPUS=8 must refuse a 16-vCPU shape even with CPUS=32 free.

        Reading only ``CPUS`` passed this and failed later, mid-apply.
        """
        run = _fake_run(
            machine_type=_Result(stdout="16\n"),
            quotas=_Result(stdout=_quota_json(
                N2D_CPUS=(8, 0), CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)

        with pytest.raises(click.ClickException) as exc:
            run_preflight("snp-gcp", "n2d-standard-16", "us-central1-a")
        assert "N2D_CPUS" in str(exc.value)

    def test_aggregate_quota_refusal_still_caught(self, monkeypatch):
        run = _fake_run(
            machine_type=_Result(stdout="16\n"),
            quotas=_Result(stdout=_quota_json(
                N2D_CPUS=(64, 0), CPUS=(8, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)

        with pytest.raises(click.ClickException) as exc:
            run_preflight("snp-gcp", "n2d-standard-16", "us-central1-a")
        assert "Metric: CPUS" in str(exc.value)

    def test_both_metrics_reported_when_sufficient(self, monkeypatch, capsys):
        run = _fake_run(
            machine_type=_Result(stdout="2\n"),
            quotas=_Result(stdout=_quota_json(
                N2D_CPUS=(8, 0), CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)
        run_preflight("snp-gcp", "n2d-standard-2", "us-central1-a")

        out = capsys.readouterr().out
        assert "N2D_CPUS" in out and "CPUS" in out

    def test_tdx_uses_c3_family_metric(self, monkeypatch):
        run = _fake_run(
            machine_type=_Result(stdout="4\n"),
            quotas=_Result(stdout=_quota_json(C3_CPUS=(2, 0), CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)

        with pytest.raises(click.ClickException) as exc:
            run_preflight("tdx-gcp", "c3-standard-4", "us-central1-a")
        assert "C3_CPUS" in str(exc.value)

    def test_spot_checks_preemptible_not_family(self, monkeypatch):
        """PREEMPTIBLE_CPUS defaults to 0 in most projects, including this one."""
        run = _fake_run(
            machine_type=_Result(stdout="2\n"),
            quotas=_Result(stdout=_quota_json(
                PREEMPTIBLE_CPUS=(0, 0), N2D_CPUS=(8, 0), CPUS=(32, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)

        with pytest.raises(click.ClickException) as exc:
            run_preflight("snp-gcp", "n2d-standard-2", "us-central1-a",
                          use_spot=True)
        assert "PREEMPTIBLE_CPUS" in str(exc.value)
        assert "Spot (preemptible)" in str(exc.value)

    def test_absent_metrics_report_skipped(self, monkeypatch, capsys):
        """A quota list naming neither metric is not a pass."""
        run = _fake_run(
            machine_type=_Result(stdout="2\n"),
            quotas=_Result(stdout=_quota_json(SSD_TOTAL_GB=(500, 0))),
        )
        monkeypatch.setattr(preflight.subprocess, "run", run)
        run_preflight("snp-gcp", "n2d-standard-2", "us-central1-a")

        assert "skipped, not" in capsys.readouterr().out
