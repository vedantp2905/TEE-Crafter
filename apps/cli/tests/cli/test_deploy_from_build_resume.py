"""``deploy-from-build`` must be able to resume a confidential-VM deploy.

The bug this file covers cost a VM, a Bastion, a VNet and a storage account on
2026-08-23.  A ``terraform apply`` for ``tdx-azure``
died on an invalid NSG service tag; 22 resources had already been created and
were sound; the build directory held a valid ``terraform.tfstate``.  The only
command that can take a build directory hardcoded ``tee_platform="nitro-aws"``
and demanded an ``app.eif``, so it failed with ``app.eif not found`` and
destroy-and-redeploy was the only way forward.

Every test here drives the real Click command with the real dispatch, stubbing
only the boundary that spends money (the deployment phase) — the previous
failure was *in* the dispatch, so a test that stubbed the dispatch would have
stayed green through it.

Two properties get the most attention because they are the ones that fail
silently rather than loudly:

* the phase that runs matches the platform recorded in the build directory, and
* the ``TF_VAR_*`` environment the resumed apply sees is the one the original
  apply saw.  Terraform reads those from the process environment; nothing here
  writes a ``.tfvars`` file.  A missing variable is not an error to Terraform,
  it is a fallback to the variable's ``default`` — so a resume that lost them
  would converge the *existing* state onto a different plan and delete, say,
  the NSG rule the original apply had created.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from tee_crafter.cli.commands.deploy import resume_manifest
from tee_crafter.cli.commands.deploy.platform import (
    _DEPLOYMENT_PHASES, RESUMABLE_PLATFORMS, deployment_phase_for,
)


def _phase_name(platform: str) -> str:
    """The phase name from the table, not from a (possibly patched) lookup."""
    return _DEPLOYMENT_PHASES[platform][1]

ALL_PLATFORMS = (
    "nitro-aws", "sgx-azure", "tdx-azure", "tdx-gcp",
    "snp-aws", "snp-azure", "snp-gcp",
    "gpu-cc-gcp", "gpu-cc-azure", "gpu-cc-aws",
)

#: Instance/VM shapes that exist in the catalog for each platform, so
#: ``resolve_shape`` does not reject the manifest we hand it.
_SHAPE_VAR = {
    "nitro-aws": ("TF_VAR_instance_type", "c6a.xlarge"),
    "snp-aws": ("TF_VAR_instance_type", "m6a.xlarge"),
    "gpu-cc-aws": ("TF_VAR_instance_type", "p5.4xlarge"),
    "sgx-azure": ("TF_VAR_vm_size", "Standard_DC2s_v3"),
    "tdx-azure": ("TF_VAR_vm_size", "Standard_DC2es_v6"),
    "snp-azure": ("TF_VAR_vm_size", "Standard_DC2as_v5"),
    "gpu-cc-azure": ("TF_VAR_vm_size", "Standard_NCC40ads_H100_v5"),
    "tdx-gcp": ("TF_VAR_machine_type", "c3-standard-4"),
    "snp-gcp": ("TF_VAR_machine_type", "n2d-standard-2"),
    "gpu-cc-gcp": ("TF_VAR_machine_type", "a3-highgpu-1g"),
}


def _cli():
    from tee_crafter.cli.commands.deploy.from_build import register

    group = click.Group()
    register(group)
    return group


def _build_dir(
    tmp_path: Path, platform: str, *, manifest: bool = True,
    provenance_platform: str = "", tf_vars: dict | None = None,
    measurements: dict | None = None, custom_ami: str = "img-recorded",
) -> Path:
    """A build directory shaped like a half-applied deploy of *platform*."""
    d = tmp_path / f"build_{platform}"
    d.mkdir(exist_ok=True)
    (d / "main.tf").write_text("# terraform\n")
    (d / "terraform.tfstate").write_text('{"version": 4, "resources": []}')
    if platform == "nitro-aws":
        (d / "app.eif").write_bytes(b"NOT-A-REAL-EIF")
    if manifest:
        var, value = _SHAPE_VAR[platform]
        vars_ = {var: value}
        vars_.update(tf_vars or {})
        (d / resume_manifest.MANIFEST_NAME).write_text(json.dumps({
            "manifest_version": 1,
            "tee_platform": platform,
            "cpu": 2,
            "ram": 4096,
            "measurements": (
                {"measurement": "aa" * 48} if measurements is None
                else measurements),
            "custom_ami": custom_ami,
            "tf_vars": vars_,
        }))
    if provenance_platform:
        prov = d / "provenance"
        prov.mkdir(exist_ok=True)
        (prov / "build_provenance.json").write_text(json.dumps(
            {"tee_platform": provenance_platform, "entries": []}))
    return d


@pytest.fixture(autouse=True)
def _isolate_tf_var_env():
    """Snapshot and restore ``TF_VAR_*`` around every test in this file.

    The command under test mutates ``os.environ`` on purpose — Terraform reads
    ``TF_VAR_*`` from the process environment, so there is nowhere else to put
    them — and ``monkeypatch`` cannot undo a write it did not make.  Without
    this, a ``gpu-cc-aws`` case leaves ``TF_VAR_instance_type=p5.4xlarge``
    behind and the next ``nitro-aws`` case dies on "not a supported instance
    type", which reads like a bug in the code rather than in the test.
    Harmless in production: every CLI invocation is a fresh process.
    """
    before = {k: v for k, v in os.environ.items() if k.startswith("TF_VAR_")}
    try:
        yield
    finally:
        for key in [k for k in os.environ if k.startswith("TF_VAR_")]:
            del os.environ[key]
        os.environ.update(before)


@pytest.fixture
def spy(monkeypatch):
    """Neutralise every boundary that costs money or needs credentials.

    Returns a dict the deployment phase fills in when it is reached.  Nothing
    here stubs the platform dispatch itself, which is the thing under test.
    """
    calls: dict = {}

    monkeypatch.setattr(
        "tee_crafter.cli.cloud_auth.validate_required_creds",
        lambda *a, **kw: None)
    monkeypatch.setattr(
        "tee_crafter.cli.commands.deploy.from_build.verify_build_integrity",
        lambda *a, **kw: None)
    monkeypatch.setattr(
        "tee_crafter.cli.commands.deploy.from_build.get_enclave_hashes",
        lambda path: (True, {"PCR0": "00" * 48, "PCR1": "11" * 48,
                             "PCR2": "22" * 48}, ""))
    monkeypatch.setattr(
        "tee_crafter.cli.deployment.common.siem_sidecar."
        "siem_export_blocked_deploy", lambda audit: None)

    def _fake_phase(**kwargs):
        calls.update(kwargs)
        # Snapshot the environment Terraform would have been handed.
        calls["_tf_env"] = {k: v for k, v in os.environ.items()
                            if k.startswith("TF_VAR_")}
        return True

    # Patch each phase where the dispatch will look it up: at its own module.
    for platform in ALL_PLATFORMS:
        fn, _ = deployment_phase_for(platform)
        module = __import__(fn.__module__, fromlist=["_"])

        def _named(name=fn.__name__):
            def _inner(**kwargs):
                calls["phase"] = name
                return _fake_phase(**kwargs)
            return _inner

        monkeypatch.setattr(module, fn.__name__, _named())
    return calls


def _invoke(build_dir: Path, *extra: str):
    return CliRunner().invoke(_cli(), [
        "deploy-from-build", "--build-dir", str(build_dir), "--auto-approve",
        *extra,
    ])


# --------------------------------------------------------------------------- #
# The dispatch itself
# --------------------------------------------------------------------------- #

class TestPlatformDispatch:

    @pytest.mark.parametrize("platform", ALL_PLATFORMS)
    def test_every_platform_reaches_its_own_phase(self, tmp_path, spy,
                                                  platform):
        r = _invoke(_build_dir(tmp_path, platform))
        assert r.exit_code == 0, r.output
        assert spy["phase"] == _phase_name(platform), (
            f"{platform} ran {spy.get('phase')}")

    def test_cvm_build_dir_no_longer_asks_for_an_eif(self, tmp_path, spy):
        """The exact 2026-08-23 failure: no ``app.eif``, and none needed."""
        build_dir = _build_dir(tmp_path, "tdx-azure")
        assert not (build_dir / "app.eif").exists()
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert "app.eif" not in r.output

    def test_nitro_still_needs_its_eif(self, tmp_path, spy):
        build_dir = _build_dir(tmp_path, "nitro-aws")
        (build_dir / "app.eif").unlink()
        r = _invoke(build_dir)
        assert r.exit_code != 0
        assert "app.eif not found" in r.output

    def test_nitro_measurements_are_recomputed_not_read(self, tmp_path, spy):
        """Nitro PCRs come from the EIF, so a lying manifest cannot set them."""
        build_dir = _build_dir(
            tmp_path, "nitro-aws", measurements={"PCR0": "de" * 48})
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert spy["hashes"]["PCR0"] == "00" * 48

    def test_cvm_measurements_come_from_the_manifest(self, tmp_path, spy):
        build_dir = _build_dir(
            tmp_path, "snp-gcp", measurements={"measurement": "ab" * 48})
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert spy["measurements"] == {"measurement": "ab" * 48}

    @pytest.mark.parametrize("platform", ALL_PLATFORMS)
    def test_an_instance_type_override_sets_the_variable_the_template_declares(
            self, tmp_path, spy, platform, monkeypatch):
        """Terraform ignores an unknown ``TF_VAR_*`` silently.

        The two names differ — ``nitro-aws`` declares ``instance_type`` and
        ``sgx-azure`` declares ``vm_size`` — so a single default would make
        ``--instance-type`` on one of them appear to work and change nothing.
        """
        from tee_crafter.cli.commands.deploy.platform import (
            INSTANCE_TYPE_TF_VAR,
        )

        var, value = _SHAPE_VAR[platform]
        assert INSTANCE_TYPE_TF_VAR[platform] == var
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI", "1")
        r = _invoke(_build_dir(tmp_path, platform), "--instance-type", value)
        assert r.exit_code == 0, r.output
        assert spy["_tf_env"][var] == value

    def test_every_resumable_platform_has_an_instance_variable(self):
        from tee_crafter.cli.commands.deploy.platform import (
            INSTANCE_TYPE_TF_VAR,
        )

        assert set(INSTANCE_TYPE_TF_VAR) >= set(RESUMABLE_PLATFORMS)

    def test_the_measurement_kwarg_matches_each_real_signature(self):
        """Guard the one thing the dispatch table can get wrong on its own.

        ``nitro-aws``'s phase names its measurement parameter ``hashes``; the
        other nine name it ``measurements``.  The table records which, so a
        rename in a phase module would otherwise surface as a ``TypeError``
        during a live deploy.
        """
        import inspect

        for platform in RESUMABLE_PLATFORMS:
            fn, kwarg = deployment_phase_for(platform)
            params = inspect.signature(fn).parameters
            assert kwarg in params, f"{platform}: {fn.__name__} has no {kwarg}"
            for required in ("console", "build_dir", "cpu", "ram",
                            "auto_approve", "teardown", "audit", "custom_ami"):
                assert required in params, f"{platform}: missing {required}"


# --------------------------------------------------------------------------- #
# Refusals — every one of these used to be a silent wrong deploy
# --------------------------------------------------------------------------- #

class TestRefusals:

    def test_no_platform_recorded_is_refused_not_guessed(self, tmp_path, spy):
        build_dir = _build_dir(tmp_path, "tdx-azure", manifest=False)
        r = _invoke(build_dir)
        assert r.exit_code != 0
        assert "Cannot tell which TEE platform" in r.output
        assert "phase" not in spy, "ran a deploy phase without knowing which"

    def test_directory_name_is_never_used_as_the_platform(self, tmp_path):
        """A Nitro build dir is named ``..._container_nitro_...``.

        Close enough to ``nitro-aws`` to look parseable, and the label for the
        other nine platforms is not the platform id either.  ``resolve_platform``
        must ignore the name entirely.
        """
        d = tmp_path / "hello_http_container_tdx-azure_build_20260823_071236_1"
        d.mkdir()
        (d / "main.tf").write_text("# tf\n")
        assert resume_manifest.resolve_platform(str(d)) == ("", "")

    def test_provenance_alone_identifies_but_does_not_authorise_a_cvm(
            self, tmp_path, spy):
        """A CVM needs the manifest's measurements, so provenance is not enough.

        ``build_provenance.json`` records the platform but carries no launch
        measurements — and on ``sgx-azure``, ``snp-gcp`` and ``gpu-cc-azure``
        the measurements are functional, not decorative.  Deploying with ``{}``
        would weaken the attestation check instead of failing it.
        """
        build_dir = _build_dir(tmp_path, "tdx-azure", manifest=False,
                              provenance_platform="tdx-azure")
        r = _invoke(build_dir)
        assert r.exit_code != 0
        assert resume_manifest.MANIFEST_NAME in r.output
        assert "phase" not in spy

    def test_provenance_alone_is_enough_for_nitro(self, tmp_path, spy,
                                                  monkeypatch):
        """Nitro is exempt: its PCRs are recomputed from ``app.eif``.

        Needs the unbaked-image escape hatch, because without a manifest there
        is no recorded image either and the pinned-AMI gate fires first — which
        is the correct order.
        """
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI", "1")
        build_dir = _build_dir(tmp_path, "nitro-aws", manifest=False,
                              provenance_platform="nitro-aws")
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert spy["phase"] == "run_nitro_deployment_phase"

    def test_unknown_platform_is_named_in_the_error(self, tmp_path, spy):
        d = tmp_path / "b"
        d.mkdir()
        (d / "main.tf").write_text("# tf\n")
        (d / resume_manifest.MANIFEST_NAME).write_text(json.dumps(
            {"manifest_version": 1, "tee_platform": "sev-es-oracle",
             "cpu": 2, "ram": 2048, "tf_vars": {}}))
        r = _invoke(d)
        assert r.exit_code != 0
        assert "sev-es-oracle" in r.output
        assert "tdx-azure" in r.output       # lists what it does support

    def test_missing_main_tf_is_refused(self, tmp_path, spy):
        build_dir = _build_dir(tmp_path, "snp-aws")
        (build_dir / "main.tf").unlink()
        r = _invoke(build_dir)
        assert r.exit_code != 0
        assert "main.tf not found" in r.output


# --------------------------------------------------------------------------- #
# TF_VAR_* fidelity — the failure mode Terraform does not report
# --------------------------------------------------------------------------- #

class TestTerraformEnvironment:

    def test_recorded_vars_reach_the_apply(self, tmp_path, spy, monkeypatch):
        monkeypatch.delenv("TF_VAR_attest_maa_egress", raising=False)
        build_dir = _build_dir(tmp_path, "tdx-azure", tf_vars={
            "TF_VAR_attest_maa_egress": "true",
            "TF_VAR_azure_location": "westus",
        })
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert spy["_tf_env"]["TF_VAR_attest_maa_egress"] == "true"
        assert spy["_tf_env"]["TF_VAR_azure_location"] == "westus"

    def test_a_var_absent_at_apply_time_is_cleared(self, tmp_path, spy,
                                                   monkeypatch):
        """Leaving it set would open egress the half-applied plan never had.

        ``TF_VAR_allow_setup_egress`` is the one that matters: it attaches a NAT
        gateway and a default route.  If the operator's shell has it set now but
        the recorded apply did not, honouring the shell would silently change
        the network posture of a resume.
        """
        monkeypatch.setenv("TF_VAR_allow_setup_egress", "true")
        build_dir = _build_dir(tmp_path, "tdx-azure")
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert "TF_VAR_allow_setup_egress" not in spy["_tf_env"]
        assert "TF_VAR_allow_setup_egress" in r.output

    def test_the_manifest_beats_a_disagreeing_environment(self, tmp_path, spy,
                                                          monkeypatch):
        monkeypatch.setenv("TF_VAR_azure_location", "eastus2")
        build_dir = _build_dir(tmp_path, "tdx-azure",
                              tf_vars={"TF_VAR_azure_location": "westus"})
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert spy["_tf_env"]["TF_VAR_azure_location"] == "westus"
        assert "eastus2" in r.output and "westus" in r.output

    def test_recorded_image_is_reused_without_an_ami_flag(self, tmp_path, spy):
        build_dir = _build_dir(tmp_path, "tdx-azure", custom_ami="img-abc123")
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert spy["custom_ami"] == "img-abc123"

    def test_explicit_ami_flag_wins_over_the_recording(self, tmp_path, spy,
                                                      monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI", "1")
        build_dir = _build_dir(tmp_path, "tdx-azure", custom_ami="img-abc123")
        r = _invoke(build_dir, "--ami-id", "img-override")
        assert r.exit_code == 0, r.output
        assert spy["custom_ami"] == "img-override"

    def test_recorded_shape_is_used_when_no_flag_overrides_it(self, tmp_path,
                                                             spy):
        build_dir = _build_dir(tmp_path, "tdx-azure")
        r = _invoke(build_dir)
        assert r.exit_code == 0, r.output
        assert (spy["cpu"], spy["ram"]) == (2, 4096)


# --------------------------------------------------------------------------- #
# The manifest module on its own
# --------------------------------------------------------------------------- #

class TestManifestModule:

    def test_round_trip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TF_VAR_vm_size", "Standard_DC2es_v6")
        monkeypatch.setenv("TEE_CRAFTER_MAA_ENDPOINT", "https://example/")
        path = resume_manifest.write_manifest(
            str(tmp_path), tee_platform="tdx-azure", cpu=2, ram=4096,
            measurements={"MRTD": "ab" * 48}, custom_ami="img-1")
        assert path and Path(path).name == resume_manifest.MANIFEST_NAME
        doc = resume_manifest.read_manifest(str(tmp_path))
        assert doc["tee_platform"] == "tdx-azure"
        assert doc["measurements"] == {"MRTD": "ab" * 48}
        assert doc["tf_vars"]["TF_VAR_vm_size"] == "Standard_DC2es_v6"
        # Only TF_VAR_* is captured: the rest of the environment carries
        # credentials and SIEM API keys.
        assert not any(k.startswith("TEE_CRAFTER_") for k in doc["tf_vars"])

    def test_no_secrets_in_the_captured_vars(self, tmp_path, monkeypatch):
        for name in ("AWS_SECRET_ACCESS_KEY", "TEE_CRAFTER_SIEM_API_KEY",
                     "ARM_CLIENT_SECRET"):
            monkeypatch.setenv(name, "s3cret")
        resume_manifest.write_manifest(
            str(tmp_path), tee_platform="snp-aws", cpu=2, ram=4096)
        assert "s3cret" not in (tmp_path / resume_manifest.MANIFEST_NAME
                                ).read_text()

    def test_unreadable_manifest_reads_as_absent(self, tmp_path):
        (tmp_path / resume_manifest.MANIFEST_NAME).write_text("{not json")
        assert resume_manifest.read_manifest(str(tmp_path)) is None
        assert resume_manifest.resolve_platform(str(tmp_path)) == ("", "")

    def test_a_json_list_reads_as_absent(self, tmp_path):
        (tmp_path / resume_manifest.MANIFEST_NAME).write_text("[]")
        assert resume_manifest.read_manifest(str(tmp_path)) is None

    def test_write_failure_is_reported_not_raised(self, tmp_path):
        assert resume_manifest.write_manifest(
            str(tmp_path / "does-not-exist"), tee_platform="snp-aws",
            cpu=2, ram=4096) is None

    def test_apply_tf_vars_reports_all_three_categories(self):
        env = {"TF_VAR_keep": "old", "TF_VAR_extra": "x", "PATH": "/bin"}
        restored, overridden, cleared = resume_manifest.apply_tf_vars(
            {"tf_vars": {"TF_VAR_keep": "new", "TF_VAR_added": "y"}}, env=env)
        assert restored == ["TF_VAR_added", "TF_VAR_keep"]
        assert overridden == [("TF_VAR_keep", "old", "new")]
        assert cleared == ["TF_VAR_extra"]
        assert env == {"TF_VAR_keep": "new", "TF_VAR_added": "y",
                       "PATH": "/bin"}

    def test_apply_tf_vars_on_a_manifest_without_the_key(self):
        env = {"TF_VAR_x": "1"}
        assert resume_manifest.apply_tf_vars({}, env=env) == ([], [], [])
        assert env == {"TF_VAR_x": "1"}, "must not clear on a bad manifest"


class TestDeployWritesTheManifest:
    """The manifest has to exist before anything can fail, or C5 comes back."""

    def test_helper_writes_on_both_deploy_and_no_deploy_paths(self, tmp_path):
        """Guard the placement, which is the whole point.

        ``_record_resume_manifest`` is called *before* each ``if do_deploy:``
        fork in ``deploy_container``.  Assert that textually: a future edit that
        moves it inside the ``if`` would leave ``--no-deploy`` build directories
        unresumable, and no runtime test of the deploy path would notice.
        """
        import inspect

        from tee_crafter.cli.commands.deploy import deploy_container

        src = inspect.getsource(deploy_container)
        for fn_name in ("_deploy_nitro_container", "_deploy_sgx_container",
                        "_deploy_cvm_container"):
            body = src.split(f"def {fn_name}(", 1)[1]
            body = body.split("\ndef ", 1)[0]
            assert "_record_resume_manifest(" in body, fn_name
            assert body.index("_record_resume_manifest(") < body.index(
                "if do_deploy:"), f"{fn_name}: manifest write is inside the fork"


# --------------------------------------------------------------------------- #
# Stale Terraform state lock
# --------------------------------------------------------------------------- #

class TestStaleStateLock:
    """A lock left by a killed apply must not silently block the resume.

    Terraform releases the lock on SIGINT, so a lock on disk means the apply
    was killed outright.  That is the case this command exists for, and it is
    also the case where an unhandled lock costs money: the resume stops before
    it plans while the half-created Bastion keeps billing.
    """

    LOCK = {
        "ID": "79e1c5fd-75e6-c758-48f4-1495a42350dc",
        "Operation": "OperationTypeApply",
        "Who": "root@docker-desktop",
        "Version": "1.15.9",
        "Created": "2026-08-23T09:36:29.870821631Z",
        "Path": "terraform.tfstate",
    }

    def _lock(self, d: Path, payload=None):
        p = d / resume_manifest.STATE_LOCK_NAME
        p.write_text(json.dumps(self.LOCK if payload is None else payload))
        return p

    def test_refuses_by_default(self, tmp_path, spy):
        d = _build_dir(tmp_path, "snp-azure")
        self._lock(d)
        r = _invoke(d)
        assert r.exit_code != 0
        assert "state lock" in r.output
        assert "phase" not in spy, "must not reach the phase while locked"

    def test_refusal_names_who_and_when(self, tmp_path, spy):
        """An operator has to be able to tell a dead apply from a live one."""
        d = _build_dir(tmp_path, "snp-azure")
        self._lock(d)
        out = _invoke(d).output
        assert "root@docker-desktop" in out
        assert "2026-08-23T09:36:29" in out
        assert "--force-unlock" in out

    def test_force_unlock_clears_it_and_proceeds(self, tmp_path, spy):
        d = _build_dir(tmp_path, "snp-azure")
        lock = self._lock(d)
        r = _invoke(d, "--force-unlock")
        assert r.exit_code == 0, r.output
        assert not lock.exists()
        assert spy["phase"] == _phase_name("snp-azure")

    def test_unlocked_directory_is_untouched(self, tmp_path, spy):
        """No lock file, no mention of locking, no behaviour change."""
        d = _build_dir(tmp_path, "snp-azure")
        r = _invoke(d)
        assert r.exit_code == 0, r.output
        assert "state lock" not in r.output

    def test_malformed_lock_still_refuses(self, tmp_path, spy):
        """Failing to parse the lock is not a reason to ignore it."""
        d = _build_dir(tmp_path, "snp-azure")
        (d / resume_manifest.STATE_LOCK_NAME).write_text("{not json")
        r = _invoke(d)
        assert r.exit_code != 0
        assert "state lock" in r.output

    def test_malformed_lock_can_be_forced(self, tmp_path, spy):
        d = _build_dir(tmp_path, "snp-azure")
        (d / resume_manifest.STATE_LOCK_NAME).write_text("{not json")
        r = _invoke(d, "--force-unlock")
        assert r.exit_code == 0, r.output
        assert not (d / resume_manifest.STATE_LOCK_NAME).exists()

    @pytest.mark.parametrize("platform", ALL_PLATFORMS)
    def test_gate_applies_to_every_platform(self, tmp_path, spy, platform):
        d = _build_dir(tmp_path, platform)
        self._lock(d)
        assert _invoke(d).exit_code != 0


class TestStateLockHelpers:

    def test_read_returns_none_when_absent(self, tmp_path):
        assert resume_manifest.read_state_lock(str(tmp_path)) is None

    def test_read_returns_empty_dict_on_garbage(self, tmp_path):
        (tmp_path / resume_manifest.STATE_LOCK_NAME).write_text("nope")
        assert resume_manifest.read_state_lock(str(tmp_path)) == {}

    def test_absent_is_distinguishable_from_unparseable(self, tmp_path):
        """``None`` and ``{}`` must not collapse: one means no lock at all."""
        assert resume_manifest.read_state_lock(str(tmp_path)) is None
        (tmp_path / resume_manifest.STATE_LOCK_NAME).write_text("nope")
        assert resume_manifest.read_state_lock(str(tmp_path)) is not None

    def test_describe_handles_empty(self):
        assert "unreadable" in resume_manifest.describe_state_lock({})

    def test_clear_is_idempotent(self, tmp_path):
        assert resume_manifest.clear_state_lock(str(tmp_path)) is True
        (tmp_path / resume_manifest.STATE_LOCK_NAME).write_text("{}")
        assert resume_manifest.clear_state_lock(str(tmp_path)) is True
        assert resume_manifest.clear_state_lock(str(tmp_path)) is True
