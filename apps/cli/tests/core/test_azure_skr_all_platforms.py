"""``--byok azure-skr`` must work on every Azure confidential-VM platform.

``snp-azure`` and ``gpu-cc-azure`` once had no working BYOK path at all.  ``--byok azure-kv`` refuses on any Azure CVM for two independent
reasons — the adapter has no authenticated transport, and Key Vault wraps the
released key to ``TpmEphemeralEncryptionKey`` whose private half is sealed to
the vTPM — and the replacement, ``--byok azure-skr``, delegates both to
``AzureAttestSKR``, a binary that only ``scripts/tdx_azure/setup_tdx.sh``
installed.  Neither platform was *broken*: both failed closed and said why.
They simply had no BYOK option.

Three things had to be true to close it, and each has tests below:

1. The binary is in all three bakes, from **one** copy of the install block.
2. The VM has a managed identity to authenticate the ``release`` call with, and
   the NSG lets it reach MAA — Secure Key Release attests *before* it releases,
   so a deny-all egress blocks it at the first hop.
3. An ``azure-skr`` deploy that cannot work is refused at build time rather
   than inside a VM that is already billing.
"""
from __future__ import annotations

import os
import re
import subprocess

import pytest

AZURE_CVM_PLATFORMS = ("tdx-azure", "snp-azure", "gpu-cc-azure")

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "src", "tee_crafter")

_SETUP_SCRIPTS = {
    "tdx-azure": ("tdx_azure", "setup_tdx.sh"),
    "snp-azure": ("snp_azure", "setup_snp_azure.sh"),
    "gpu-cc-azure": ("gpu_cc_azure", "setup_gpu_cc_azure.sh"),
}

_TEMPLATES = {
    "tdx-azure": ("tdx", "azure"),
    "snp-azure": ("snp", "azure"),
    "gpu-cc-azure": ("gpu_cc", "azure"),
}


def _rendered(platform: str) -> str:
    from tee_crafter.cli.loaders import (
        load_gpu_cc_azure_setup_template, load_snp_azure_setup_template,
        load_tdx_setup_template,
    )

    return {
        "tdx-azure": load_tdx_setup_template,
        "snp-azure": load_snp_azure_setup_template,
        "gpu-cc-azure": load_gpu_cc_azure_setup_template,
    }[platform]()


def _raw_setup(platform: str) -> str:
    parts = _SETUP_SCRIPTS[platform]
    with open(os.path.join(_SRC, "scripts", *parts), encoding="utf-8") as fh:
        return fh.read()


def _template(platform: str) -> str:
    parts = _TEMPLATES[platform]
    with open(os.path.join(_SRC, "templates", *parts, "main.template.tf"),
              encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# 1. The binary, from one copy of the install block
# --------------------------------------------------------------------------- #

class TestTheBinaryIsBakedEverywhere:

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_azure_attest_skr_is_installed(self, platform):
        assert "/usr/local/bin/AzureAttestSKR" in _rendered(platform)

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_the_install_is_idempotent(self, platform):
        """The script runs twice: once at bake (egress open), once per deploy.

        A second run that tried to re-download would fail the deploy on a VM
        that is already paid for, so the block must skip when both binaries are
        already present.
        """
        rendered = _rendered(platform)
        assert "already baked, skipping" in rendered
        assert 'if [ -x "$GA_CLIENT" ] && [ -x "$GA_SKR" ]; then' in rendered

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_a_missing_binary_is_fatal_not_a_warning(self, platform):
        """Checked outside the skip-branch, so a stale image stops here."""
        rendered = _rendered(platform)
        assert 'for _bin in "$GA_CLIENT" "$GA_SKR"; do' in rendered
        assert re.search(r"FATAL: \$_bin is missing", rendered)

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_no_leftover_placeholders(self, platform):
        """A literal ``__FOO__`` in an uploaded script is a silent no-op.

        This is not hypothetical: ``deployment/tdx/setup.py`` and
        ``deployment/snp/azure_setup.py`` used to inject only the security
        profiles, so they uploaded scripts still containing ``__SYSTEMD_UNIT__``
        — which would have swallowed the guest-attestation block too.
        """
        leftover = sorted(set(re.findall(r"__[A-Z][A-Z_]{3,}__",
                                         _rendered(platform))))
        assert leftover == [], leftover

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_the_rendered_script_is_valid_bash(self, platform):
        proc = subprocess.run(["bash", "-n", "/dev/stdin"],
                              input=_rendered(platform),
                              capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_each_script_says_why_it_needs_the_tool(self, platform):
        """``GA_PURPOSE`` lands in the FATAL message, so it must be set.

        The reason differs per platform and that matters: on ``tdx-azure``
        ``AttestationClient`` is the only route to any verifiable evidence,
        while ``snp-azure`` and ``gpu-cc-azure`` attest fine on their own and
        only need ``AzureAttestSKR`` for key release.  An operator reading a
        failed bake should get the reason that applies to them.
        """
        raw = _raw_setup(platform)
        assert re.search(r'^GA_PURPOSE="', raw, re.M), platform
        if platform == "tdx-azure":
            assert "DCAP" in raw
        else:
            assert "azure-skr" in raw

    def test_the_install_block_exists_exactly_once_in_the_repo(self):
        """One copy, or the three will drift.

        ``build_ga_tool`` is the block's distinctive symbol.  Before C4 it
        appeared once (in ``setup_tdx.sh``); the wrong fix would be to appear
        three times.
        """
        hits = []
        for root, _dirs, files in os.walk(os.path.join(_SRC, "scripts")):
            for name in files:
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    if "build_ga_tool()" in fh.read():
                        hits.append(os.path.relpath(path, _SRC))
        assert hits == [os.path.join("scripts", "common",
                                     "azure_guest_attestation.sh")], hits

    def test_the_fragment_does_not_name_its_own_placeholder(self):
        """Otherwise ``test_no_leftover_placeholders`` can never fail."""
        with open(os.path.join(_SRC, "scripts", "common",
                               "azure_guest_attestation.sh"),
                  encoding="utf-8") as fh:
            assert "__AZURE_GUEST_ATTESTATION__" not in fh.read()

    def test_the_fragment_does_no_user_or_group_work(self):
        """It is inlined before the enclave user exists.

        A ``usermod -aG tss tee_enclave`` in the fragment would silently do
        nothing on a first bake, and then vTPM access would fail at release
        time.  Each platform script does it after user creation instead.
        """
        with open(os.path.join(_SRC, "scripts", "common",
                               "azure_guest_attestation.sh"),
                  encoding="utf-8") as fh:
            body = fh.read()
        code = "\n".join(ln for ln in body.splitlines()
                         if not ln.lstrip().startswith("#"))
        for forbidden in ("usermod", "useradd", "groupadd"):
            assert forbidden not in code, forbidden

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_the_service_account_gets_vtpm_access(self, platform):
        """Both binaries read /dev/tpmrm0, which is root:tss 0660."""
        assert re.search(r"usermod -aG tss", _raw_setup(platform)), platform


# --------------------------------------------------------------------------- #
# 2. Identity + reachability
# --------------------------------------------------------------------------- #

class TestTerraformSupportsTheRelease:

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_the_vm_gets_a_managed_identity_when_byok_is_on(self, platform):
        """Key Vault authorises ``release`` against an AAD principal.

        The in-TEE caller gets its token from IMDS, so with no identity there is
        no way to authenticate the release call at all — however good the
        attestation is.
        """
        tf = _template(platform)
        assert 'dynamic "identity" {' in tf
        block = tf.split('dynamic "identity" {', 1)[1][:200]
        assert "var.byok_azure_kv" in block, "identity must be BYOK-gated"
        assert 'type = "SystemAssigned"' in block

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_the_principal_id_is_an_output(self, platform):
        """The grant cannot be pre-made: the principal exists only after apply."""
        assert 'output "vm_identity_principal_id"' in _template(platform)

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_maa_is_reachable_under_deny_all_egress(self, platform):
        """SKR attests *before* it releases, so MAA is the first hop."""
        tf = _template(platform)
        assert "AzureAttestation" in tf
        assert "local.maa_destination" in tf

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_no_regional_azure_attestation_tag_is_emitted(self, platform):
        """Azure publishes no ``AzureAttestation.<Region>``.

        Verified with ``az network list-service-tags``, which returns exactly
        ``AzureAttestation`` for every location — unlike ``AzureKeyVault``,
        which has dozens of regional variants.  Emitting a regional suffix here
        failed an apply *after* the VM had been created, which is the expensive
        way to learn it.
        """
        tf = _template(platform)
        assert 'AzureAttestation.${' not in tf
        assert '"AzureAttestation."' not in tf

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_key_vault_egress_is_still_byok_gated(self, platform):
        """The new rule must not have widened the default posture."""
        tf = _template(platform)
        assert "AllowKeyVaultEgress" in tf
        assert "DenyAllOutbound" in tf

    @pytest.mark.parametrize("platform", ("snp-azure", "gpu-cc-azure"))
    def test_maa_egress_is_gated_on_byok_on_the_snp_platforms(self, platform):
        """These two never talk to MAA except for SKR.

        Attestation reads a SEV-SNP report and verifies it against AMD's root,
        so an unconditional MAA rule would grant egress that nothing uses.
        ``tdx-azure`` differs: there MAA *is* the attestation path, so its rule
        is gated on ``attest_maa_egress`` instead.
        """
        tf = _template(platform)
        rule = tf.split("AllowMaaEgressForSkr", 1)[0]
        gate = rule.rsplit('dynamic "security_rule" {', 1)[1]
        assert "var.byok_azure_kv" in gate, gate[:300]


# --------------------------------------------------------------------------- #
# 3. Refuse before spending
# --------------------------------------------------------------------------- #

class TestBuildTimeRefusal:

    def _err(self, provider, platform, monkeypatch, endpoint=None):
        from tee_crafter.cli.commands.deploy.byok_mode import (
            azure_skr_prerequisite_error,
        )
        if endpoint is None:
            monkeypatch.delenv("TEE_CRAFTER_MAA_ENDPOINT", raising=False)
        else:
            monkeypatch.setenv("TEE_CRAFTER_MAA_ENDPOINT", endpoint)
        return azure_skr_prerequisite_error(provider, platform)

    @pytest.mark.parametrize("platform", AZURE_CVM_PLATFORMS)
    def test_all_three_azure_cvms_are_accepted(self, platform, monkeypatch):
        assert self._err("azure-skr", platform, monkeypatch,
                         "https://sharedwus.wus.attest.azure.net") == ""

    @pytest.mark.parametrize("platform", (
        "snp-aws", "snp-gcp", "tdx-gcp", "nitro-aws", "sgx-azure",
        "gpu-cc-aws", "gpu-cc-gcp",
    ))
    def test_non_azure_cvm_platforms_are_refused_with_the_alternative(
            self, platform, monkeypatch):
        err = self._err("azure-skr", platform, monkeypatch,
                        "https://sharedwus.wus.attest.azure.net")
        assert platform in err
        assert "aws-kms" in err and "gcp-kms" in err

    def test_sgx_azure_is_refused_even_though_it_is_azure(self, monkeypatch):
        """No paravisor, no vTPM-sealed KEK — an enclave, not a CVM."""
        err = self._err("azure-skr", "sgx-azure", monkeypatch, "https://a/")
        assert "TpmEphemeralEncryptionKey" in err

    def test_a_missing_maa_endpoint_is_refused(self, monkeypatch):
        err = self._err("azure-skr", "snp-azure", monkeypatch)
        assert "TEE_CRAFTER_MAA_ENDPOINT is required" in err
        assert "no safe default" in err

    def test_a_plaintext_maa_endpoint_is_refused(self, monkeypatch):
        err = self._err("azure-skr", "snp-azure", monkeypatch,
                        "http://sharedwus.wus.attest.azure.net")
        assert "https://" in err

    @pytest.mark.parametrize("provider", (
        "none", "aws-kms", "azure-kv", "gcp-kms", "external-hsm"))
    def test_other_providers_are_not_second_guessed(self, provider,
                                                    monkeypatch):
        assert self._err(provider, "snp-aws", monkeypatch) == ""

    def test_key_vault_egress_is_opened_for_azure_skr_on_all_three(
            self, monkeypatch):
        """Reachability is separate from the binary and was already wired.

        Asserted here so a future narrowing of ``_AZURE_KV_PROVIDERS`` cannot
        leave ``azure-skr`` with a deny-all path to the vault.
        """
        from tee_crafter.cli.commands.deploy.byok_mode import (
            ByokConfig, export_byok_tf_vars,
        )
        for platform in AZURE_CVM_PLATFORMS:
            monkeypatch.delenv("TF_VAR_byok_azure_kv", raising=False)
            cfg = ByokConfig(
                provider="azure-skr",
                key_id="https://v.vault.azure.net/keys/k/1")
            out = export_byok_tf_vars(cfg, platform)
            assert out.get("TF_VAR_byok_azure_kv") == "true", platform


# --------------------------------------------------------------------------- #
# The guest needs the wrapped DEK and the MAA endpoint, not just the key id
# --------------------------------------------------------------------------- #

class TestAzureSkrRuntimeEnvPropagation:
    """Regression: the guest's byok.env carried nothing to unwrap.

    Observed on a live snp-azure CVM on 2026-08-23 -- the tmpfs byok.env had
    TEE_CRAFTER_BYOK_KEY_ID and _UNWRAP but no wrapped DEK and no MAA endpoint,
    both of which core/keys/azure_skr_tool.py reads from the environment.  So
    AzureAttestSKR could never have been invoked with real inputs.
    """

    WRAPPED = "QUJDRA=="
    MAA = "https://sharedwus.wus.attest.azure.net"

    def _cfg(self, tmp_path, provider="azure-skr"):
        import json as _json
        p = tmp_path / "byok.json"
        p.write_text(_json.dumps({
            "key_id": "https://v.vault.azure.net/keys/dek/1",
            "unwrap": "direct_bytes"}))
        from tee_crafter.cli.commands.deploy.byok_mode import build_byok_config
        return build_byok_config(provider=provider, raw_policy_path=str(p))

    def test_wrapped_dek_and_maa_reach_the_runtime_env(self, tmp_path,
                                                       monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK", self.WRAPPED)
        monkeypatch.setenv("TEE_CRAFTER_MAA_ENDPOINT", self.MAA)
        env = self._cfg(tmp_path).to_env()
        assert env["TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK"] == self.WRAPPED
        assert env["TEE_CRAFTER_MAA_ENDPOINT"] == self.MAA

    def test_names_match_what_the_skr_tool_reads(self, tmp_path, monkeypatch):
        """Guard against a rename drifting the two halves apart."""
        from tee_crafter.core.keys import azure_skr_tool as t
        monkeypatch.setenv(t.WRAPPED_DEK_ENV, self.WRAPPED)
        monkeypatch.setenv(t.MAA_ENDPOINT_ENV, self.MAA)
        env = self._cfg(tmp_path).to_env()
        assert env[t.WRAPPED_DEK_ENV] == self.WRAPPED
        assert env[t.MAA_ENDPOINT_ENV] == self.MAA

    def test_absent_values_are_not_emitted_blank(self, tmp_path, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK", raising=False)
        monkeypatch.delenv("TEE_CRAFTER_MAA_ENDPOINT", raising=False)
        env = self._cfg(tmp_path).to_env()
        assert "TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK" not in env
        assert "TEE_CRAFTER_MAA_ENDPOINT" not in env

    def test_other_providers_do_not_pick_these_up(self, tmp_path, monkeypatch):
        """azure-kv and aws-kms have no use for them; stay quiet."""
        import json as _json
        monkeypatch.setenv("TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK", self.WRAPPED)
        monkeypatch.setenv("TEE_CRAFTER_MAA_ENDPOINT", self.MAA)
        p = tmp_path / "k.json"
        p.write_text(_json.dumps({
            "key_id": "arn:aws:kms:us-east-2:1:key/a", "region": "us-east-2"}))
        from tee_crafter.cli.commands.deploy.byok_mode import build_byok_config
        env = build_byok_config(
            provider="aws-kms", raw_policy_path=str(p)).to_env()
        assert "TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK" not in env
        assert "TEE_CRAFTER_MAA_ENDPOINT" not in env

    def test_wrapped_dek_is_classified_as_a_secret(self):
        """It must land on tmpfs only, never in byok.env.public."""
        from tee_crafter.cli.commands.deploy.byok_mode import (
            SECRET_ENV_KEYS, is_byok_secret_key,
        )
        assert "TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK" in SECRET_ENV_KEYS
        assert is_byok_secret_key("TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK")

    def test_maa_endpoint_is_not_a_secret(self):
        """It is a public authority URL; keeping it public aids debugging."""
        from tee_crafter.cli.commands.deploy.byok_mode import is_byok_secret_key
        assert not is_byok_secret_key("TEE_CRAFTER_MAA_ENDPOINT")
