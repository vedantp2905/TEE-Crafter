"""A killed apply orphans resources; the retry must adopt them, not recreate.

Reproduced on `tdx-azure` on 2026-08-23: SIGKILL mid-create left a Bastion host
live in Azure and absent from state, so every later apply failed with
`already exists` and the Bastion billed at ~$0.19/hr with no way forward short
of deleting the resource group by hand.
"""
from __future__ import annotations

import pytest

from tee_crafter.cli.deployment.common import terraform_step as ts


RG = "tee-crafter-tdx-rg-eebe215f"


def _err(resource_id: str, address: str = "azurerm_bastion_host.tdx") -> str:
    return (
        f'\nError: a resource with the ID "{resource_id}" already exists - to '
        f'be managed via Terraform this resource needs to be imported into the '
        f'State. Please see the resource documentation for '
        f'"azurerm_bastion_host" for more information\n'
        f'\n  with {address},\n'
        f'  on main.tf line 208, in resource "azurerm_bastion_host" "tdx":\n'
    )


def _id(rg: str = RG, name: str = "tee-crafter-tdx-bastion-eebe215f") -> str:
    return (f"/subscriptions/abc/resourceGroups/{rg}/providers/"
            f"Microsoft.Network/bastionHosts/{name}")


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, *a, **kw):
        self.lines.append(" ".join(str(x) for x in a))

    @property
    def text(self):
        return "\n".join(self.lines)


class TestParser:

    def test_pairs_id_with_address(self):
        assert ts._orphans_from_error(_err(_id())) == [
            ("azurerm_bastion_host.tdx", _id())]

    def test_handles_two_orphans(self):
        text = _err(_id(), "azurerm_bastion_host.tdx") + _err(
            _id(name="pip"), "azurerm_public_ip.bastion")
        got = ts._orphans_from_error(text)
        assert [a for a, _ in got] == [
            "azurerm_bastion_host.tdx", "azurerm_public_ip.bastion"]

    def test_empty_on_unrelated_error(self):
        assert ts._orphans_from_error("Error: quota exceeded") == []

    def test_empty_when_counts_disagree(self):
        """Never guess a pairing: a wrong address writes state for someone else."""
        text = _err(_id()) + '\nError: a resource with the ID "x" already exists\n'
        assert ts._orphans_from_error(text) == []

    def test_empty_on_none(self):
        assert ts._orphans_from_error("") == []


class TestOwnershipGuard:
    """The guard is the whole safety argument for importing automatically."""

    @pytest.fixture(autouse=True)
    def _azure(self, monkeypatch):
        monkeypatch.setattr(ts, "_detect_cloud_from_build", lambda d: "azure")
        monkeypatch.setattr(ts, "_detect_azure_rg_name", lambda d: RG)

    def test_imports_a_resource_inside_our_resource_group(self, monkeypatch):
        calls = []

        class _P:
            returncode, stdout, stderr = 0, "", ""

        monkeypatch.setattr(ts.shutil, "which", lambda x: "/usr/bin/terraform")
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: calls.append(argv) or _P())
        c = _Console()
        assert ts._adopt_orphaned_resources(c, "/b", _err(_id())) == 1
        assert calls[0][1] == "import"
        assert calls[0][-2:] == ["azurerm_bastion_host.tdx", _id()]

    def test_refuses_a_resource_in_a_foreign_resource_group(self, monkeypatch):
        """Different RG *and* not carrying our deploy id -> not ours.

        Both ownership proofs have to miss. A resource in a foreign group whose
        name still ends in this deploy's `did` is ours (that is the flow-log
        case), so the negative test has to vary the name too.
        """
        monkeypatch.setattr(ts.shutil, "which", lambda x: "/usr/bin/terraform")
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        c = _Console()
        foreign = _id(rg="someone-elses-rg", name="their-bastion-ffffffff")
        assert ts._adopt_orphaned_resources(c, "/b", _err(foreign)) == 0
        assert ran == []
        assert "Refusing to import" in c.text

    def test_refuses_when_our_rg_is_unknown(self, monkeypatch):
        """Cannot prove ownership -> do nothing."""
        monkeypatch.setattr(ts, "_detect_azure_rg_name", lambda d: "")
        monkeypatch.setattr(ts.shutil, "which", lambda x: "/usr/bin/terraform")
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        c = _Console()
        assert ts._adopt_orphaned_resources(c, "/b", _err(_id())) == 0
        assert ran == []
        assert "ownership cannot be proven" in c.text.replace("\n", " ")

    def test_case_insensitive_resource_group_match(self, monkeypatch):
        """Azure echoes resource group names in varying case."""
        class _P:
            returncode, stdout, stderr = 0, "", ""

        monkeypatch.setattr(ts.shutil, "which", lambda x: "/usr/bin/terraform")
        monkeypatch.setattr(ts.subprocess, "run", lambda argv, **kw: _P())
        c = _Console()
        assert ts._adopt_orphaned_resources(
            c, "/b", _err(_id(rg=RG.upper()))) == 1

    def test_reports_a_failed_import_instead_of_counting_it(self, monkeypatch):
        class _P:
            returncode, stdout, stderr = 1, "", "boom"

        monkeypatch.setattr(ts.shutil, "which", lambda x: "/usr/bin/terraform")
        monkeypatch.setattr(ts.subprocess, "run", lambda argv, **kw: _P())
        c = _Console()
        assert ts._adopt_orphaned_resources(c, "/b", _err(_id())) == 0
        assert "failed" in c.text


class TestNonAzureIsUntouched:

    @pytest.mark.parametrize("cloud", ["aws", "gcp"])
    def test_no_import_attempted(self, monkeypatch, cloud):
        monkeypatch.setattr(ts, "_detect_cloud_from_build", lambda d: cloud)
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        assert ts._adopt_orphaned_resources(_Console(), "/b", _err(_id())) == 0
        assert ran == []


class TestNoDestroyBeforeRetry:
    """The retry must not throw away correct work on any cloud."""

    @pytest.mark.parametrize("cloud", ["azure", "aws", "gcp"])
    def test_cleanup_never_destroys(self, monkeypatch, cloud):
        monkeypatch.setattr(ts, "_detect_cloud_from_build", lambda d: cloud)
        called = []
        monkeypatch.setattr(ts, "cleanup_resources",
                            lambda *a, **kw: called.append(a) or True)
        ts._cleanup_partial_state(_Console(), "/b")
        assert called == [], f"{cloud}: retry destroyed partial state"

    def test_explains_why(self, monkeypatch):
        monkeypatch.setattr(ts, "_detect_cloud_from_build", lambda d: "azure")
        c = _Console()
        ts._cleanup_partial_state(c, "/b")
        assert "convergent" in c.text


class TestDeploySuffixOwnership:
    """Resources this deploy creates *outside* its own resource group.

    The VNet flow log forced this: Azure keeps flow logs in the shared,
    long-lived `NetworkWatcherRG`, so a resource-group test alone refused to
    adopt `tee-crafter-tdx-vnet-flow-<did>` even though the name carries this
    deploy's own id. `tdx-azure` failed on 2026-08-23 for exactly that reason.
    """

    FLOW_ID = ("/subscriptions/abc/resourceGroups/NetworkWatcherRG/providers/"
               "Microsoft.Network/networkWatchers/NetworkWatcher_westus/"
               "flowLogs/tee-crafter-tdx-vnet-flow-0d83a757")

    @pytest.fixture(autouse=True)
    def _azure(self, monkeypatch):
        monkeypatch.setattr(ts, "_detect_cloud_from_build", lambda d: "azure")
        monkeypatch.setattr(ts, "_detect_azure_rg_name",
                            lambda d: "tee-crafter-tdx-rg-0d83a757")
        monkeypatch.setattr(ts.shutil, "which", lambda x: "/usr/bin/terraform")

    def test_adopts_flow_log_in_the_shared_network_watcher_group(self,
                                                                 monkeypatch):
        class _P:
            returncode, stdout, stderr = 0, "", ""
        calls = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: calls.append(argv) or _P())
        c = _Console()
        n = ts._adopt_orphaned_resources(
            c, "/b", _err(self.FLOW_ID, "azurerm_network_watcher_flow_log.vnet"))
        assert n == 1, c.text
        assert calls[0][-1] == self.FLOW_ID

    def test_still_refuses_a_foreign_deploys_flow_log(self, monkeypatch):
        """Same shared group, different deploy id -> not ours."""
        ran = []
        monkeypatch.setattr(ts.subprocess, "run",
                            lambda argv, **kw: ran.append(argv))
        foreign = self.FLOW_ID.replace("0d83a757", "ffffffff")
        c = _Console()
        assert ts._adopt_orphaned_resources(
            c, "/b", _err(foreign, "azurerm_network_watcher_flow_log.vnet")) == 0
        assert ran == []
        assert "Refusing to import" in c.text


class TestDeploySuffix:

    @pytest.mark.parametrize("rg,expected", [
        ("tee-crafter-snp-rg-a3e35036", "a3e35036"),
        ("tee-crafter-tdx-rg-0d83a757", "0d83a757"),
        ("tee-crafter-gpu-cc-rg-DEADBEEF", "deadbeef"),
    ])
    def test_extracts_the_hex_suffix(self, rg, expected):
        assert ts._deploy_suffix(rg) == expected

    @pytest.mark.parametrize("rg", [
        "tee-crafter-snp-rg-prod",   # not hex
        "tee-crafter-snp-rg",        # no suffix
        "tee-crafter-snp-rg-abc",    # too short to be unambiguous
        "",
    ])
    def test_refuses_ambiguous_suffixes(self, rg):
        assert ts._deploy_suffix(rg) == ""


class TestAdoptionDoesNotConsumeARetry:
    """An adoptable orphan is a state desync, not a failed attempt.

    On snp-azure on 2026-08-23: attempt 1 failed with a transient
    ``409 StorageAccountOperationInProgress``; the retry then hit
    ``already exists`` for that same storage account -- and because that was the
    *last* attempt, the adoption step never ran. The orphan was adoptable the
    whole time; only the retry budget had run out. So an adoption round now
    re-applies without advancing ``attempt``, mirroring the AWS capacity wait.
    """

    def test_budget_is_bounded(self):
        """A resource that says `already exists` but cannot be imported must
        not spin the loop forever."""
        assert 1 <= ts._MAX_ORPHAN_ADOPTIONS <= 5

    def test_adoption_round_is_gated_on_actually_importing_something(self):
        src = open(ts.__file__, encoding="utf-8").read()
        # The `continue` must sit behind a truthy `adopted`, otherwise a
        # permanently-unimportable resource loops until the agent cap.
        assert "if adopted:" in src
        assert "adoptions += 1" in src

    def test_it_only_triggers_on_already_exists(self):
        src = open(ts.__file__, encoding="utf-8").read()
        assert '"already exists" in error_summary' in src

    def test_cleanup_is_not_run_on_an_adoption_round(self):
        """Adopting then destroying would undo the import immediately."""
        src = open(ts.__file__, encoding="utf-8").read()
        adoption_block = src.split("if adoptions <")[1].split("attempt += 1")[0]
        assert "_cleanup_partial_state" not in adoption_block
