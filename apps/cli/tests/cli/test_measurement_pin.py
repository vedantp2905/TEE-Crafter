"""Tests for deploy-time measurement auto-pinning + fail-closed gate."""
from __future__ import annotations

import hashlib

import pytest

from tee_crafter.cli.commands.deploy import measurement_pin as mp
from tee_crafter.core.measurements import registry


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, msg):
        self.lines.append(str(msg))


class TestResolve:
    def test_resolve_hits_registry(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        registry.store("snp-aws", "ami-1", "ab" * 48)
        assert mp.resolve("snp-aws", "ami-1") == "ab" * 48

    def test_resolve_non_cvm_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        registry.store("nitro-aws", "ami-1", "ab" * 48)
        assert mp.resolve("nitro-aws", "ami-1") is None

    def test_policy_sha256(self):
        meas = "ab" * 48
        assert mp.policy_sha256(meas) == hashlib.sha256(bytes.fromhex(meas)).hexdigest()


class TestEnforce:
    def test_passes_when_pinned(self):
        con = _Console()
        assert mp.enforce(con, tee_platform="snp-aws", image_id="ami-1",
                          pinned_measurements=["ab" * 48], sealed_or_byok=True) is True

    def test_fail_closed_when_unpinned(self, monkeypatch):
        monkeypatch.delenv(mp.ALLOW_UNPINNED_ENV, raising=False)
        con = _Console()
        ok = mp.enforce(con, tee_platform="snp-aws", image_id="ami-x",
                        pinned_measurements=[], sealed_or_byok=True)
        assert ok is False
        assert any("No pinned measurement" in ln for ln in con.lines)

    def test_dev_hatch_allows_unpinned(self, monkeypatch):
        monkeypatch.setenv(mp.ALLOW_UNPINNED_ENV, "1")
        con = _Console()
        assert mp.enforce(con, tee_platform="snp-aws", image_id="ami-x",
                          pinned_measurements=[], sealed_or_byok=True) is True

    def test_non_cvm_always_passes(self):
        con = _Console()
        assert mp.enforce(con, tee_platform="nitro-aws", image_id="ami-x",
                          pinned_measurements=[], sealed_or_byok=True) is True

    def test_no_gate_when_not_sealed_or_byok(self, monkeypatch):
        monkeypatch.delenv(mp.ALLOW_UNPINNED_ENV, raising=False)
        con = _Console()
        assert mp.enforce(con, tee_platform="snp-aws", image_id="ami-x",
                          pinned_measurements=[], sealed_or_byok=False) is True

    def test_policy_sha256_list(self):
        m1, m2 = "ab" * 48, "cd" * 48
        digests = mp.policy_sha256_list([m1, m2])
        assert len(digests) == 2
        assert digests[0] == mp.policy_sha256(m1)


class TestPinnedClientRendersOnEveryPlatform:
    """Every CVM platform must render its client when a pin is present.

    ``_deploy_cvm_container`` used to add ``client_kwargs["measurements"]``
    for all of them, but only the SEV-SNP-family renderers declare that
    parameter.  On ``tdx-azure`` / ``tdx-gcp`` / ``gpu-cc-gcp`` /
    ``gpu-cc-aws`` — the four with the weakest attestation — the render call
    raised ``TypeError`` the moment an image had a bake-time pin, i.e.
    exactly when the operator had done the right thing.
    """

    @pytest.mark.parametrize("platform", [
        "tdx-azure", "snp-aws", "snp-azure", "snp-gcp",
        "tdx-gcp", "gpu-cc-gcp", "gpu-cc-azure", "gpu-cc-aws",
    ])
    def test_render_with_pin_present(self, platform):
        from tee_crafter.cli.commands.deploy.deploy_container import _renderer_accepts
        from tee_crafter.cli.commands.deploy.platform import _get_platform_fns
        from tee_crafter.core.measurements import PLATFORM_MEASUREMENT_FIELD

        _, _, render_fn, client_kwargs, _, _ = _get_platform_fns(platform)
        pinned = ["ab" * 48, "cd" * 48]
        kwargs = dict(client_kwargs or {})
        if platform == "snp-azure":
            kwargs.setdefault("measurement", "unknown")
            kwargs.setdefault("processor_family", "milan")
        field = PLATFORM_MEASUREMENT_FIELD.get(platform, "measurement")
        kwargs[field] = pinned[0]
        kwargs["container_digest"] = "sha256:" + "0" * 64
        if _renderer_accepts(render_fn, "measurements"):
            kwargs["measurements"] = pinned
        rendered = render_fn(**kwargs)
        if platform == "gpu-cc-aws":
            # The one platform with no CPU-side attestation at all: there is
            # nothing to compare a measurement against, so the pin is
            # deliberately NOT baked in (tracker C5/C12).  It previously was —
            # as a constant no code read — and this assertion passed on the
            # string's mere presence, which is what made the dead pin look
            # enforced.  Assert the absence so re-adding it has to be
            # deliberate.
            assert pinned[0] not in rendered, (
                "gpu-cc-aws must not bake a CPU measurement pin it cannot "
                "enforce")
            return
        assert pinned[0] in rendered, f"{platform}: pin not baked into client"

    def test_renderer_accepts_matches_signatures(self):
        """Guard the mapping itself: the SNP family takes an allowlist, the
        TDX / GPU-CC-{gcp,aws} renderers take a single measurement."""
        from tee_crafter.cli.commands.deploy.deploy_container import _renderer_accepts
        from tee_crafter.core.builder import platforms as plat

        for name in ("render_snp_aws_client_template",
                     "render_snp_azure_client_template",
                     "render_snp_gcp_client_template",
                     "render_gpu_cc_azure_client_template"):
            assert _renderer_accepts(getattr(plat, name), "measurements"), name
        for name in ("render_tdx_client_template",
                     "render_tdx_gcp_client_template",
                     "render_gpu_cc_gcp_client_template",
                     "render_gpu_cc_aws_client_template"):
            assert not _renderer_accepts(getattr(plat, name), "measurements"), name
