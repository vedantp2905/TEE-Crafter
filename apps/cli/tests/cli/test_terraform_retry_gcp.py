"""A Terraform retry must not be the thing that breaks the retry.

Observed on `snp-gcp`, 2026-08-23:

1. Attempt 1 failed on zonal capacity — ``us-central1-a`` "does not have enough
   resources available". The plan was fine; the zone was full.
2. The retry ran ``terraform destroy`` to clear partial state.
3. Attempt 2 failed with ``Error 409: KeyRing … already exists``.

Step 3 is the bug. Cloud KMS **key rings cannot be deleted** — the API has no
delete operation — and the Terraform google provider handles a keyring destroy
by dropping it from state and leaving it in place. So the cleanup produced a
state file that no longer knew about a resource that still existed, and the next
apply tried to create it again.

Net effect: on GCP, cleaning up before a retry *guaranteed* the retry would fail
for any deploy that got as far as creating the ring. Which is every deploy that
gets as far as creating a VM, since the ring comes first.

**Widened on 2026-08-23 from "GCP only" to every cloud.** GCP was where the
cleanup was outright fatal, so it was exempted first, but the same day produced
two more reasons that are not GCP-specific:

* On Azure the destroy has to unwind a Bastion host (~10 min) so the retry can
  rebuild it (~10 min), and it often cannot even do that --
  ``InUseSubnetCannotBeDeleted`` and ``PublicIPAddressCannotBeDeleted`` both fire
  while the Bastion still holds the subnet and the public IP. Seen on both
  ``sgx-azure`` and ``tdx-azure``.
* On a resume after a killed apply, the cleanup partially destroyed the
  resources that *were* recorded in state, leaving the build directory worse off
  than the half-applied state it was called to repair.

``terraform apply`` is convergent on every cloud, which was always the real
argument. Orphans left by a killed apply are now adopted by
``_adopt_orphaned_resources`` instead of being destroyed along with everything
near them -- see ``test_orphan_adoption.py``.
"""
from __future__ import annotations

import pytest

from tee_crafter.cli.constants import console
from tee_crafter.cli.deployment.common import terraform_step as ts


def _build_dir(tmp_path, name: str, provider: str):
    d = tmp_path / name
    d.mkdir()
    (d / "main.tf").write_text(f'provider "{provider}" {{}}\n')
    return str(d)


class TestGcpRetriesDoNotDestroyState:

    def test_gcp_skips_the_cleanup(self, tmp_path, monkeypatch, capsys):
        called = []
        monkeypatch.setattr(ts, "cleanup_resources",
                            lambda *a, **kw: called.append(kw.get("context")))
        bd = _build_dir(tmp_path, "app_container_snp-gcp_build_1", "google")
        ts._cleanup_partial_state(console, bd)
        assert called == [], "destroyed state on GCP — reintroduces the 409"

    def test_it_says_why_it_skipped(self, tmp_path, monkeypatch, capsys):
        """Silence would look like the cleanup ran and found nothing."""
        monkeypatch.setattr(ts, "cleanup_resources", lambda *a, **kw: None)
        bd = _build_dir(tmp_path, "app_container_tdx-gcp_build_1", "google")
        ts._cleanup_partial_state(console, bd)
        out = capsys.readouterr().out
        assert "convergent" in out
        # The GCP 409 is the sharpest of the three reasons, so it stays named.
        assert "409" in out

    @pytest.mark.parametrize("name,provider", [
        ("app_container_snp-aws_build_1", "aws"),
        ("app_container_nitro_build_1", "aws"),
        ("app_container_snp-azure_build_1", "azurerm"),
        ("app_container_tdx-azure_build_1", "azurerm"),
    ])
    def test_aws_and_azure_do_not_clean_up_either(self, tmp_path, monkeypatch,
                                                 name, provider):
        """Widened: destroying before a retry throws away correct work anywhere.

        This asserted the opposite until 2026-08-23. It was not wrong about GCP
        being the worst case; it was wrong that AWS and Azure benefit. On Azure
        the destroy is slow, frequently blocked by the Bastion's hold on the
        subnet and public IP, and on a resume it corrupted the state it was
        meant to repair.
        """
        called = []
        monkeypatch.setattr(ts, "cleanup_resources",
                            lambda *a, **kw: called.append(kw.get("context")))
        ts._cleanup_partial_state(
            console, _build_dir(tmp_path, name, provider))
        assert called == []

    @pytest.mark.parametrize("name", [
        "app_container_snp-gcp_build_1",
        "app_container_tdx-gcp_build_1",
        "app_container_gpu-cc-gcp_build_1",
    ])
    def test_all_three_gcp_platforms_are_covered(self, tmp_path, monkeypatch,
                                                 name):
        """All three create a keyring, so all three had the bug."""
        called = []
        monkeypatch.setattr(ts, "cleanup_resources",
                            lambda *a, **kw: called.append(1))
        ts._cleanup_partial_state(
            console, _build_dir(tmp_path, name, "google"))
        assert called == [], name


class TestGcpCapacityIsReportedNotRetried:

    def test_the_markers_match_googles_wording(self):
        """Both spellings Google uses for zonal exhaustion."""
        real = ("Error waiting for instance to create: The zone "
                "'projects/p/zones/us-central1-a' does not have enough "
                "resources available to fulfill the request.")
        assert any(m in real for m in ts._GCP_CAPACITY_MARKERS)
        assert any(m in "Error: ZONE_RESOURCE_POOL_EXHAUSTED"
                   for m in ts._GCP_CAPACITY_MARKERS)

    def test_an_unrelated_gcp_error_is_not_treated_as_capacity(self):
        """A real config error must still consume a retry, not short-circuit."""
        for msg in ("Error 409: KeyRing already exists",
                    "Error 403: Permission denied",
                    "Invalid value for field 'machineType'"):
            assert not any(m in msg for m in ts._GCP_CAPACITY_MARKERS), msg
