"""Two bakes of the same platform must not fight over Azure resource names.

Every Azure bake used to name its throwaway resource group and VM after the
platform alone (``tee-crafter-bake-tdx-rg`` / ``-vm``) and end by deleting that
resource group, so a second concurrent bake either had its live VM deleted
mid-run or sat in the ``ResourceGroupBeingDeleted`` retry loop until it gave up.

The VHD staging storage account was worse: Azure storage account names share a
single namespace across **all** Azure tenants, so ``teecraftertdxvhd`` is
first-come-first-served globally.  Once anyone owns it, ``az storage account
create`` fails for everyone else and the bake dies on the following ``keys
list``.
"""
from __future__ import annotations

import re

import pytest

from tee_crafter.cli.commands.baking.common import helpers


AZURE_BAKE_MODULES = [
    ("tee_crafter.cli.commands.baking.tdx",
     "_TDX_BAKE_RG_PREFIX", "_TDX_VM_NAME_PREFIX", "_TDX_VHD_STORAGE_ACCOUNT"),
    ("tee_crafter.cli.commands.baking.sgx",
     "_SGX_BAKE_RG_PREFIX", "_SGX_VM_NAME_PREFIX", "_SGX_VHD_STORAGE_ACCOUNT"),
    ("tee_crafter.cli.commands.baking.snp_azure",
     "_SNP_AZURE_BAKE_RG_PREFIX", "_SNP_AZURE_VM_NAME_PREFIX",
     "_SNP_AZURE_VHD_STORAGE_ACCOUNT"),
    ("tee_crafter.cli.commands.baking.gpu_cc",
     "_GPU_CC_AZURE_BAKE_RG_PREFIX", "_GPU_CC_AZURE_VM_NAME_PREFIX",
     "_GPU_CC_AZURE_VHD_STORAGE_ACCOUNT"),
]


class TestBakeRunSuffix:
    def test_two_calls_differ(self, monkeypatch):
        monkeypatch.delenv(helpers.BAKE_SUFFIX_ENV, raising=False)
        assert helpers.bake_run_suffix() != helpers.bake_run_suffix()

    def test_suffix_is_azure_name_safe(self, monkeypatch):
        monkeypatch.delenv(helpers.BAKE_SUFFIX_ENV, raising=False)
        s = helpers.bake_run_suffix()
        assert re.fullmatch(r"[a-z0-9]{1,12}", s), s

    def test_env_override_is_honoured_and_sanitised(self, monkeypatch):
        monkeypatch.setenv(helpers.BAKE_SUFFIX_ENV, "CI-Run_42")
        assert helpers.bake_run_suffix() == "cirun42"

    def test_blank_override_falls_back_to_random(self, monkeypatch):
        monkeypatch.setenv(helpers.BAKE_SUFFIX_ENV, "___")
        s = helpers.bake_run_suffix()
        assert re.fullmatch(r"[a-z0-9]{8}", s), s


class TestEphemeralNamesArePrefixesOnly:
    @pytest.mark.parametrize(
        "module_name,rg_attr,vm_attr,_sa", AZURE_BAKE_MODULES,
        ids=[m[0].rsplit(".", 1)[-1] for m in AZURE_BAKE_MODULES],
    )
    def test_bake_names_are_suffixed(self, module_name, rg_attr, vm_attr, _sa,
                                     monkeypatch):
        import importlib
        mod = importlib.import_module(module_name)
        monkeypatch.setenv(helpers.BAKE_SUFFIX_ENV, "abc123")
        suffix = helpers.bake_run_suffix()
        rg = f"{getattr(mod, rg_attr)}-{suffix}"
        vm = f"{getattr(mod, vm_attr)}-{suffix}"
        assert rg.endswith("-abc123")
        assert vm.endswith("-abc123")
        # Azure limits: RG <= 90 chars, Linux VM name <= 64.
        assert len(rg) <= 90
        assert len(vm) <= 64

    def test_prefixes_are_distinct_per_platform(self):
        import importlib
        rgs = set()
        for module_name, rg_attr, _vm, _sa in AZURE_BAKE_MODULES:
            rgs.add(getattr(importlib.import_module(module_name), rg_attr))
        assert len(rgs) == len(AZURE_BAKE_MODULES), rgs


class TestVhdStorageAccountName:
    def test_explicit_env_wins(self, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_TDX_STORAGE_ACCOUNT", "mypinnedacct")
        assert helpers.azure_vhd_storage_account(
            "teecraftertdxvhd", "TEE_CRAFTER_TDX_STORAGE_ACCOUNT") == "mypinnedacct"

    def test_falls_back_to_legacy_name_when_subscription_unknown(self, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_TDX_STORAGE_ACCOUNT", raising=False)
        monkeypatch.setattr(helpers, "azure_subscription_fingerprint", lambda: "")
        assert helpers.azure_vhd_storage_account(
            "teecraftertdxvhd", "TEE_CRAFTER_TDX_STORAGE_ACCOUNT") == "teecraftertdxvhd"

    @pytest.mark.parametrize(
        "base", ["teecraftertdxvhd", "teecraftersgxvhd", "teecraftersnpvhd",
                 "teecraftergpuccvhd"],
    )
    def test_derived_name_obeys_azure_storage_rules(self, base, monkeypatch):
        """3-24 chars, lowercase alphanumeric only."""
        monkeypatch.delenv("TEE_CRAFTER_X_STORAGE_ACCOUNT", raising=False)
        monkeypatch.setattr(
            helpers, "azure_subscription_fingerprint", lambda: "deadbeef")
        name = helpers.azure_vhd_storage_account(base, "TEE_CRAFTER_X_STORAGE_ACCOUNT")
        assert 3 <= len(name) <= 24, (name, len(name))
        assert re.fullmatch(r"[a-z0-9]+", name), name
        assert name.endswith("deadbeef")

    def test_two_subscriptions_get_different_names(self, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_X_STORAGE_ACCOUNT", raising=False)
        monkeypatch.setattr(
            helpers, "azure_subscription_fingerprint", lambda: "aaaaaaaa")
        a = helpers.azure_vhd_storage_account("teecraftertdxvhd", "TEE_CRAFTER_X_STORAGE_ACCOUNT")
        monkeypatch.setattr(
            helpers, "azure_subscription_fingerprint", lambda: "bbbbbbbb")
        b = helpers.azure_vhd_storage_account("teecraftertdxvhd", "TEE_CRAFTER_X_STORAGE_ACCOUNT")
        assert a != b

    def test_same_subscription_is_stable_across_bakes(self, monkeypatch):
        """Not per-run random: a per-bake account would leak one storage
        account per bake into the persistent images resource group."""
        monkeypatch.delenv("TEE_CRAFTER_X_STORAGE_ACCOUNT", raising=False)
        monkeypatch.setattr(
            helpers, "azure_subscription_fingerprint", lambda: "cafef00d")
        first = helpers.azure_vhd_storage_account("teecraftersnpvhd", "TEE_CRAFTER_X_STORAGE_ACCOUNT")
        second = helpers.azure_vhd_storage_account("teecraftersnpvhd", "TEE_CRAFTER_X_STORAGE_ACCOUNT")
        assert first == second

    def test_fingerprint_reads_subscription_id(self, monkeypatch):
        import subprocess

        class _Res:
            returncode = 0
            stdout = '{"id": "11111111-2222-3333-4444-555555555555"}'

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Res())
        fp = helpers.azure_subscription_fingerprint()
        assert re.fullmatch(r"[0-9a-f]{8}", fp), fp

    def test_fingerprint_empty_when_az_missing(self, monkeypatch):
        import subprocess

        def _boom(*a, **k):
            raise FileNotFoundError("az")

        monkeypatch.setattr(subprocess, "run", _boom)
        assert helpers.azure_subscription_fingerprint() == ""


class _Progress:
    def add_task(self, *a, **k):
        return 1

    def update(self, *a, **k):
        pass


class _AzResult:
    def __init__(self, stdout="{}", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def _fake_az(*args, check=True):
    """Just enough ``az`` to get ``capture_vhd_to_gallery`` to the blob copy."""
    joined = " ".join(args)
    if joined.startswith("vm show"):
        return _AzResult('{"storageProfile": {"osDisk": {"name": "osdisk-1"}}}')
    if joined.startswith("disk grant-access"):
        return _AzResult('{"accessSas": "https://sas.example/disk"}')
    if joined.startswith("storage account keys list"):
        return _AzResult('[{"value": "k1"}]')
    return _AzResult()


class _CopyAbort(RuntimeError):
    pass


class TestVhdBlobName:
    """Two bakes starting in the same second would otherwise both write to
    ``{prefix}{YYYYmmdd-HHMMSS}.vhd``."""

    def _blob_name_for(self, monkeypatch, run_suffix):
        from tee_crafter.cli.commands.baking.common import azure_gallery

        monkeypatch.setattr(
            helpers, "azure_subscription_fingerprint", lambda: "deadbeef")
        captured = {}

        def _fake_subprocess_run(cmd, **kwargs):
            if "copy" in cmd and "start" in cmd:
                captured["blob"] = cmd[cmd.index("--destination-blob") + 1]
                captured["account"] = cmd[cmd.index("--account-name") + 1]
                raise _CopyAbort
            return _AzResult()

        monkeypatch.setattr(azure_gallery.subprocess, "run", _fake_subprocess_run)
        with pytest.raises(_CopyAbort):
            azure_gallery.capture_vhd_to_gallery(
                _Progress(), _fake_az,
                bake_rg="bake-rg", images_rg="images-rg", vm_name="vm",
                location="westus", gallery_name="g", image_def="d",
                storage_acct="teecraftertdxvhd",
                storage_env_var="TEE_CRAFTER_UNSET_STORAGE_ACCOUNT",
                vhd_container="vhds", blob_prefix="tee-crafter-tdx-",
                publisher="p", offer="o", sku="s",
                run_suffix=run_suffix,
            )
        return captured

    def test_distinct_suffixes_give_distinct_blobs(self, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_UNSET_STORAGE_ACCOUNT", raising=False)
        a = self._blob_name_for(monkeypatch, "aaa11111")["blob"]
        b = self._blob_name_for(monkeypatch, "bbb22222")["blob"]
        assert a != b
        assert a.endswith("-aaa11111.vhd") and b.endswith("-bbb22222.vhd")

    def test_storage_account_is_subscription_scoped(self, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_UNSET_STORAGE_ACCOUNT", raising=False)
        account = self._blob_name_for(monkeypatch, "aaa11111")["account"]
        assert account == "teecraftertdxvhddeadbeef"
        assert len(account) <= 24

    def test_omitting_run_suffix_keeps_the_legacy_timestamp_name(self, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_UNSET_STORAGE_ACCOUNT", raising=False)
        blob = self._blob_name_for(monkeypatch, "")["blob"]
        assert re.fullmatch(r"tee-crafter-tdx-\d{8}-\d{6}\.vhd", blob), blob
