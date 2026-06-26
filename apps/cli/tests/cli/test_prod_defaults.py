"""Pin the production-correct defaults for every dev-hatch knob.

The TEE-Crafter posture is **single production path**: the default
behaviour (no env vars set) is the production-correct path.  Each
dev hatch must be explicitly opted into by setting an env var.

This test file enforces that contract — if anyone flips a default
back to "permissive" / "log-only" / "fall through", these tests
fail loudly.
"""
from __future__ import annotations

from pathlib import Path

import pytest

# REPO_ROOT = the CLI package root (apps/cli). PROJECT_ROOT = the monorepo
# root, which still owns .env.example after the apps/ restructure.
REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[4]


# ---------------------------------------------------------------------------
# 1. SIEM fail-closed by default
# ---------------------------------------------------------------------------

def test_siemconfig_defaults_to_fail_closed():
    from tee_crafter.cli.commands.deploy.siem_mode import SiemConfig
    cfg = SiemConfig(provider="splunk-hec")
    assert cfg.fail_open is False, (
        "SiemConfig.fail_open default must be False (production posture). "
        "Dev hatch is opt-in via siem.json fail_open: true."
    )


def test_siem_health_engages_with_no_env_knob():
    """When SIEM is enabled but the operator did not set
    TEE_CRAFTER_SIEM_FAIL_OPEN at all, the gate must default to
    fail-closed (production)."""
    import os
    import importlib

    snap = dict(os.environ)
    try:
        for k in list(os.environ):
            if k.startswith("TEE_CRAFTER_SIEM"):
                del os.environ[k]
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        # Crucially: no TEE_CRAFTER_SIEM_FAIL_OPEN set.
        # Force a fresh import so module-level caches see the env state.
        from tee_crafter.templates.common import siem_health
        importlib.reload(siem_health)
        assert siem_health.is_fail_closed() is True, (
            "SIEM gate must default to fail-closed when no env knob is set."
        )
    finally:
        os.environ.clear()
        os.environ.update(snap)


# ---------------------------------------------------------------------------
# 2. host_proxy: STRICT_IMDS the default
# ---------------------------------------------------------------------------

def test_host_proxy_strict_imds_is_default():
    """host_proxy.template.py must read STRICT_IMDS with default '1'."""
    src = (REPO_ROOT
           / "src/tee_crafter/templates/nitro/host_proxy.template.py"
          ).read_text()
    assert 'TEE_CRAFTER_PROXY_STRICT_IMDS", "1"' in src, (
        "host_proxy must default _STRICT_IMDS read to '1' (production)."
    )


# ---------------------------------------------------------------------------
# 3. STRICT_TSM ON by default in GCP TDX + GPU-CC GCP
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    REPO_ROOT / "src/tee_crafter/templates/gpu_cc/gcp/app.template.py",
    REPO_ROOT / "src/tee_crafter/templates/tdx/gcp/app.template.py",
])
def test_strict_tsm_is_default_on(path: Path):
    src = path.read_text()
    # The read should default to "1", and the comparison should be
    # "not in (off/false/0)" style — making strict the default.
    assert 'TEE_CRAFTER_STRICT_TSM", "1"' in src, (
        f"{path}: STRICT_TSM read default must be '1' (production); "
        f"strict ioctl-fallback refusal is the default posture."
    )


# ---------------------------------------------------------------------------
# 4. NRAS strict by default
# ---------------------------------------------------------------------------

def test_nras_strict_is_default():
    """nras_egress.py must default to strict (no broad-internet
    fallback unless the operator explicitly opts in)."""
    src = (REPO_ROOT
           / "src/tee_crafter/cli/deployment/common/nras_egress.py"
          ).read_text()
    # The strict read must default to "1".
    assert 'TEE_CRAFTER_NRAS_STRICT", "1"' in src, (
        "nras_egress must default TEE_CRAFTER_NRAS_STRICT read to '1' "
        "(production)."
    )


@pytest.mark.parametrize("resolved,expected_policy", [
    ([], "strict_no_egress"),
    (["34.120.45.54/32"], "resolved_cidr_allowlist"),
])
def test_nras_strict_path_no_cidrs_does_not_open_internet(
        monkeypatch, resolved, expected_policy):
    """When neither TEE_CRAFTER_NRAS_CIDRS nor TF_VAR_nras_egress_cidrs
    is set and no dev-hatch flag is on, the broad-internet TF var must
    end up FALSE.

    Strict mode now resolves the NRAS hostname and pins host routes rather than
    creating no rule at all, so there are two strict outcomes. The invariant
    this test guards is the one in the docstring above and it holds for both:
    neither may widen to the provider Internet tag. Only the dev hatch may.

    The resolver is stubbed deliberately. Letting this reach real DNS would make
    a production-defaults guard fail on an offline CI runner, which is exactly
    the kind of unrelated red that gets a security test deleted.
    """
    import os

    from tee_crafter.cli.constants import Console
    from tee_crafter.cli.deployment.common import nras_egress

    monkeypatch.setattr(nras_egress, "resolve_host_cidrs",
                        lambda *a, **k: list(resolved))

    snap = dict(os.environ)
    try:
        for k in (
            "TEE_CRAFTER_NRAS_STRICT", "TEE_CRAFTER_NRAS_CIDRS",
            "TEE_CRAFTER_NRAS_RESOLVE", "TEE_CRAFTER_NRAS_HOSTS",
            "TF_VAR_nras_egress_cidrs", "TF_VAR_allow_nras_broad_internet",
        ):
            os.environ.pop(k, None)
        console = Console()
        policy = nras_egress.apply_nras_egress_policy(
            console, cloud="gcp", audit=None,
        )
        assert policy == expected_policy, (
            f"expected {expected_policy} with resolved={resolved!r}, "
            f"got {policy!r}"
        )
        assert os.environ["TF_VAR_allow_nras_broad_internet"] == "false"
        # Whatever destination was allowed, it must be a bounded list -- never
        # the Internet tag standing in for one.
        assert os.environ.get("TF_VAR_nras_egress_cidrs", "") in (
            "", '["34.120.45.54/32"]')
    finally:
        os.environ.clear()
        os.environ.update(snap)


def test_nras_dev_hatch_opens_internet():
    """The dev hatch TEE_CRAFTER_NRAS_STRICT=0 must be the ONLY way to
    re-enable the broad-internet fallback."""
    import os

    from tee_crafter.cli.constants import Console
    from tee_crafter.cli.deployment.common import nras_egress

    snap = dict(os.environ)
    try:
        for k in (
            "TEE_CRAFTER_NRAS_CIDRS",
            "TF_VAR_nras_egress_cidrs", "TF_VAR_allow_nras_broad_internet",
        ):
            os.environ.pop(k, None)
        os.environ["TEE_CRAFTER_NRAS_STRICT"] = "0"
        console = Console()
        policy = nras_egress.apply_nras_egress_policy(
            console, cloud="gcp", audit=None,
        )
        assert policy == "widened_to_internet_default"
        assert os.environ["TF_VAR_allow_nras_broad_internet"] == "true"
    finally:
        os.environ.clear()
        os.environ.update(snap)


# ---------------------------------------------------------------------------
# 5. Attestation drift: auto-kill on by default (production)
# ---------------------------------------------------------------------------

def test_attestation_drift_kill_default_is_three():
    """tee_crafter_attestation_monitor must default the drift-kill
    threshold to 3 (auto-shutdown after 3 consecutive drift samples)."""
    src = (REPO_ROOT
           / "src/tee_crafter/templates/common/tee_crafter_attestation_monitor.py"
          ).read_text()
    assert 'TEE_ATTESTATION_DRIFT_KILL", "3"' in src, (
        "MON-1: production default for TEE_ATTESTATION_DRIFT_KILL must "
        "be '3' (auto-shutdown on persistent drift)."
    )


# ---------------------------------------------------------------------------
# 6. .env.example documents every dev hatch as "dev hatch" / production default
# ---------------------------------------------------------------------------

# ``TEE_CRAFTER_TDX_ALLOW_MISSING_QE_IDENTITY`` used to be listed here.  It has
# no read site left anywhere under src/ -- only two comments recording its
# deletion -- so the assertion was satisfied purely by the "Retired:" prose in
# §14, and tidying that prose would have failed the suite for no reason.
@pytest.mark.parametrize("knob", [
    # --- build / deploy gates ---
    "TEE_CRAFTER_ALLOW_VULNERABLE",
    "TEE_CRAFTER_VULN_STRICT",
    "TEE_CRAFTER_ACCEPT_PARTIAL_CC",
    "TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI",
    "TEE_CRAFTER_ALLOW_NO_SECURE_BOOT",
    "TEE_CRAFTER_ALLOW_SETUP_EGRESS_NAT",
    "TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL",
    "TEE_CRAFTER_SKIP_BUILD_INTEGRITY_CHECK",
    "TEE_CRAFTER_FORCE_UNLOCK",
    # --- attestation / measurement ---
    "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT",
    "TEE_CRAFTER_REQUIRE_PINNED_MEASUREMENT",
    "TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT",
    "TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS",
    "TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION",
    "TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS",
    "TEE_CRAFTER_TCB_ALLOW_STATUS",
    "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN",
    "TEE_CRAFTER_ALLOW_NON_ENCLAVE_SGX",
    # --- per-platform hardening ---
    "TEE_CRAFTER_NRAS_STRICT",
    "TEE_CRAFTER_STRICT_TSM",
    "TEE_CRAFTER_STRICT_SNP_AK_BINDING",
    "TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED",
    "TEE_CRAFTER_PROXY_STRICT_IMDS",
    "TEE_CRAFTER_PROXY_NO_CREDS",
    # --- key release ---
    "TEE_CRAFTER_BYOK_FAIL_OPEN",
    "TEE_CRAFTER_BYOK_ALLOW_ANY_MEASUREMENT",
    "TEE_CRAFTER_BYOK_REQUIRE_SIGNED_AUDIT",
    "TEE_CRAFTER_SECRETS_FAIL_OPEN",
    # --- runtime / observability ---
    "TEE_CRAFTER_SIEM_FAIL_OPEN",
    "TEE_CRAFTER_SIEM_X_ALLOW_INSECURE",
    "TEE_CRAFTER_HANDLER_SANDBOX",
    "TEE_CRAFTER_HANDLER_SANDBOX_FORCE_SECCOMP",
    "TEE_ATTESTATION_DRIFT_KILL",
    # --- teardown / local tooling ---
    "TEE_CRAFTER_SKIP_POST_DESTROY_SHRED",
    "TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE",
    "TEE_CRAFTER_SKIP_IMAGE_STALENESS_CHECK",
    "TEE_CRAFTER_SKIP_STALE_IMAGE_CHECK",
])
def test_env_example_marks_knob_as_dev_hatch_or_documented(knob: str):
    """Every dev hatch / opt-in operational knob must be present in
    .env.example so prototypers can discover the toggle, and the
    comment around it must indicate the production default."""
    body = (PROJECT_ROOT / ".env.example").read_text()
    assert knob in body, (
        f"{knob} is not documented in .env.example.  Add a stanza "
        f"with the production default and a 'dev hatch' annotation."
    )
