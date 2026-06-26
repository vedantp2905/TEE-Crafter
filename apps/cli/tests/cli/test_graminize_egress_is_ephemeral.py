"""Graminizing gets internet access for the build, and loses it before the run.

`sgx-azure` is pre-baked-only and its NSG denies all outbound except HTTPS to
`VirtualNetwork`.  Graminizing, though, is a *source build*, and the bake used
to hand the network-dependent half of it to the one machine with no network:
`setup_sgx.sh` wrote GSC's config with `Repository` + `Branch`, i.e. "clone and
compile Gramine from source", and deferred that to `gsc build` at deploy time.
It died at `Step 1/30 : FROM debian:13` with a Docker Hub i/o timeout, roughly
twenty-five minutes into a deploy.  Measured on real hardware 2026-08-22; a
single temporary Outbound 80/443 rule made the identical build succeed.

Two changes, and the split between them is the point:

* **Bake time** now pre-builds a base-Gramine image (`gsc build-gramine`) and
  points `Gramine.Image` at it, so `gsc build` skips the compile stage entirely
  — no `debian:13` pull, no Intel repository, no GitHub clone, no ~8-minute
  compile at deploy.
* **Deploy time** keeps the smallest possible hole for what genuinely cannot be
  pre-baked: GSC's build stage is `FROM <the user's image>` and apt-installs
  Gramine's runtime dependencies into it, and that image is unknown until
  deploy.  That hole is a separately-named NSG rule which the CLI deletes as
  soon as the build finishes — so the *workload* still runs under
  `DenyAllOutbound`.

Failing to close it is fatal, not a warning.
"""
from __future__ import annotations

import inspect
import json
import pathlib


from tee_crafter.cli.commands.deploy import batch as batch_mod

REPO = pathlib.Path(__file__).resolve().parents[4]
SGX_TF = (REPO / "apps" / "cli" / "src" / "tee_crafter" / "templates" / "sgx"
          / "main.template.tf")
SETUP_SH = (REPO / "apps" / "cli" / "src" / "tee_crafter" / "scripts"
            / "sgx_azure" / "setup_sgx.sh")


def _rendered_setup() -> str:
    from tee_crafter.cli.loaders import render_sgx_setup_script
    return render_sgx_setup_script()


class _Console:
    def __init__(self):
        self.text = ""

    def print(self, *a, **k):
        self.text += " ".join(str(x) for x in a) + "\n"


def _state(tmp_path, nsg="nsg1", rg="rg1"):
    (tmp_path / "terraform.tfstate").write_text(json.dumps({
        "resources": [{
            "type": "azurerm_network_security_group",
            "instances": [{"attributes": {
                "name": nsg, "resource_group_name": rg}}],
        }],
    }), encoding="utf-8")
    return str(tmp_path)


class _Az:
    """Stand-in for the `az` CLI, scripted per subcommand."""

    def __init__(self, *, exists_before=True, delete_ok=True,
                 exists_after=False):
        self.exists_before = exists_before
        self.delete_ok = delete_ok
        self.exists_after = exists_after
        self.calls: list[list[str]] = []
        self._shown = 0

    def __call__(self, cmd, capture_output=True, text=True):
        self.calls.append(cmd)

        class _R:
            returncode = 0
            stdout = ""
            stderr = ""

        r = _R()
        if "show" in cmd:
            self._shown += 1
            present = self.exists_before if self._shown == 1 else self.exists_after
            r.returncode = 0 if present else 1
        elif "delete" in cmd:
            r.returncode = 0 if self.delete_ok else 1
            r.stderr = "" if self.delete_ok else "AuthorizationFailed"
        return r


class TestBakeTimePreBuildsGramine:
    """The best fix: do the network work where the network is."""

    def test_the_bake_runs_gsc_build_gramine(self):
        assert "gsc build-gramine" in _rendered_setup()

    def test_it_pins_a_distro_because_auto_is_refused(self):
        """`gsc build-gramine` exits 1 on Distro: auto."""
        rendered = _rendered_setup()
        assert 'GRAMINE_BASE_DISTRO="debian:13"' in rendered
        assert 'Distro: "$GRAMINE_BASE_DISTRO"' in rendered

    def test_the_deploy_config_points_at_the_prebuilt_image(self):
        """This is what makes `gsc build` skip the compile stage."""
        rendered = _rendered_setup()
        assert 'Image:      "$GRAMINE_BASE_IMAGE"' in rendered

    def test_the_deploy_config_keeps_distro_auto(self):
        """Only the Gramine binaries are pinned; the build stage still adapts
        to whatever distro the user's image turns out to be."""
        rendered = _rendered_setup()
        deploy_cfg = rendered.split("DEPLOYCFG", 1)[1]
        assert 'Distro: "auto"' in deploy_cfg

    def test_build_gramine_gets_its_own_config_file(self):
        """GSC refuses `build-gramine` when Gramine.Image is set, so the two
        configs cannot be the same file."""
        rendered = _rendered_setup()
        assert "config.build-gramine.yaml" in rendered
        build_cfg = rendered.split("GRAMINECFG", 1)[1].split("GRAMINECFG", 1)[0]
        assert "Image:" not in build_cfg
        assert "Repository:" in build_cfg and "Branch:" in build_cfg

    def test_it_is_idempotent(self):
        """The bake script re-runs on boot; recompiling Gramine each time is
        many wasted minutes."""
        assert 'docker image inspect "$GRAMINE_BASE_IMAGE"' in _rendered_setup()


class TestTheEphemeralNsgRule:
    def test_the_rule_exists_and_is_separately_named(self):
        """Named separately from allow_setup_egress so it can be deleted
        without disturbing a Terraform-managed rule that must persist."""
        tf = SGX_TF.read_text(encoding="utf-8")
        assert 'name                       = "AllowGraminizeEgress"' in tf
        assert "var.graminize_egress ? [1] : []" in tf

    def test_it_opens_only_80_and_443(self):
        tf = SGX_TF.read_text(encoding="utf-8")
        block = tf.split("AllowGraminizeEgress", 1)[1].split("}", 1)[0]
        assert '["80", "443"]' in block

    def test_it_triggers_the_nat_gateway(self):
        """An NSG Allow with no NAT permits traffic that has nowhere to go."""
        tf = SGX_TF.read_text(encoding="utf-8")
        assert "var.graminize_egress ||" in tf.split("needs_nat", 1)[1][:200]

    def test_the_workload_still_has_deny_all(self):
        tf = SGX_TF.read_text(encoding="utf-8")
        assert 'name                       = "DenyAllOutbound"' in tf


class TestClosingTheRule:
    def test_a_present_rule_is_deleted_and_verified(self, tmp_path, monkeypatch):
        az = _Az(exists_before=True, delete_ok=True, exists_after=False)
        monkeypatch.setattr("subprocess.run", az)
        console = _Console()
        ok, msg = batch_mod.close_graminize_egress(_state(tmp_path), console)
        assert ok and msg == "closed"
        assert any("delete" in c for c in az.calls)
        assert "DenyAllOutbound" in console.text

    def test_an_absent_rule_is_fine(self, tmp_path, monkeypatch):
        """graminize_egress=false, or a re-run — the post-condition holds."""
        az = _Az(exists_before=False)
        monkeypatch.setattr("subprocess.run", az)
        ok, msg = batch_mod.close_graminize_egress(_state(tmp_path), _Console())
        assert ok and msg == "absent"
        assert not any("delete" in c for c in az.calls)

    def test_a_failed_delete_is_not_success(self, tmp_path, monkeypatch):
        az = _Az(exists_before=True, delete_ok=False)
        monkeypatch.setattr("subprocess.run", az)
        ok, msg = batch_mod.close_graminize_egress(_state(tmp_path), _Console())
        assert not ok
        assert "AuthorizationFailed" in msg

    def test_a_rule_that_survives_deletion_is_not_success(self, tmp_path, monkeypatch):
        """`az` exiting 0 is not proof; re-check."""
        az = _Az(exists_before=True, delete_ok=True, exists_after=True)
        monkeypatch.setattr("subprocess.run", az)
        ok, msg = batch_mod.close_graminize_egress(_state(tmp_path), _Console())
        assert not ok
        assert "still present" in msg

    def test_missing_state_is_not_success(self, tmp_path):
        ok, msg = batch_mod.close_graminize_egress(str(tmp_path), _Console())
        assert not ok
        assert "terraform.tfstate" in msg

    def test_an_nsg_absent_from_state_is_not_success(self, tmp_path):
        (tmp_path / "terraform.tfstate").write_text(
            json.dumps({"resources": []}), encoding="utf-8")
        ok, msg = batch_mod.close_graminize_egress(str(tmp_path), _Console())
        assert not ok
        assert "could not find the NSG" in msg


class TestTheDeployRefusesToRunWithBorrowedEgress:
    def test_graminize_closes_egress_before_the_workload(self):
        src = inspect.getsource(batch_mod.run_batch_container_deploy)
        assert "close_graminize_egress" in src
        assert src.index("close_graminize_egress") < src.index(
            "load_container_batch_unit")

    def test_a_failure_to_close_aborts_the_run(self):
        src = inspect.getsource(batch_mod.run_batch_container_deploy)
        tail = src.split("close_graminize_egress", 1)[1]
        assert "BatchResult(" in tail
        assert "Refusing to run the workload" in tail


class TestTheEgressPreflightStillGuardsTheBuild:
    """Belt and braces: if the rule is missing, say so in seconds."""

    def _probe(self, reply):
        calls = []

        def _run(cmd, timeout=60):
            calls.append(cmd)
            return reply
        return batch_mod._check_graminize_egress(_run)

    def test_reachable_registry_passes(self):
        ok, _ = self._probe((True, "401", ""))
        assert ok

    def test_no_answer_fails_with_the_diagnosis(self):
        ok, msg = self._probe((True, "000", ""))
        assert not ok
        assert "no outbound internet" in msg
        assert "TF_VAR_allow_setup_egress=true" in msg
