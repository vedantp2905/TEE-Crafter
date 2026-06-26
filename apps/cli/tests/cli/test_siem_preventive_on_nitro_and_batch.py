"""C8: make continuous-attestation export preventive on nitro-aws and in batch.

Two different gaps closed two different ways, because the two platforms are not
the same shape.

**nitro-aws** ran the exporter as a host-side sidecar.  The health file it wrote
lived on the parent instance; ``siem_health`` inside the EIF read a path in the
enclave's own namespace, and no SIEM variable crossed the boundary at all, so
``is_fail_closed()`` returned False and ``fail_closed_wrap`` passed every
request through.  Export was therefore detective: the SOC saw the stream stop,
nothing stopped the workload.  The fix moves the exporter *inside* the enclave,
where it writes the health file the gate actually reads and delivers over TLS it
terminates itself through a dedicated vsock tunnel.  A compromised parent can
drop that traffic; it cannot read it and cannot forge a collector's acceptance.

**Batch runs** — on *every* platform, not just the two host-side ones — had no
gate at all, and this is the part that was mis-stated rather than merely
missing.  ``fail_closed_wrap`` wraps ``process_request``; a batch container
serves no requests, so there was nothing for it to guard even on the eight CVM
platforms whose gate was described as armed.  Worse, ``--batch`` never installed
the SIEM sidecar in the first place: that happens in the per-platform *phase*
modules and batch returns before them, so ``--siem splunk-hec --batch`` staged a
config, opened egress for a collector, and exported nothing.  On ``sgx-azure``,
which is batch-only, that was the whole story for the platform.

The batch control is the output: an unaudited run does not get to hand over
PHI-derived results and report success.

What these tests do NOT cover: that events actually arrive at a collector from
inside an enclave.  That needs a live SIEM endpoint, which this project does not
have on every platform — see ``docs/pending.md``, which records that the
fail-closed direction has only been exercised on ``snp-aws``.
"""
from __future__ import annotations

import inspect
import json
import os
import pathlib
import time

import pytest

from tee_crafter.cli.deployment.common import siem_sidecar

REPO = pathlib.Path(__file__).resolve().parents[4]
TPL = REPO / "apps" / "cli" / "src" / "tee_crafter" / "templates"
NITRO_APP = TPL / "nitro" / "app_vsock.template.py"
EIF_DOCKERFILE = TPL / "common" / "Dockerfile.container.template"


class _Remote:
    """Scripted ``run_remote`` that records what it was asked to do."""

    def __init__(self, *replies):
        self._replies = list(replies)
        self.commands: list[str] = []

    def __call__(self, cmd, timeout=60):
        self.commands.append(cmd)
        return self._replies.pop(0) if self._replies else (True, "", "")


def _health(status="pass", age=0):
    return json.dumps({
        "ts": int(time.time()) - age,
        "last_seq": 3,
        "last_status": "pass",
        "last_export_status": status,
        "last_export_error": "",
        "last_digest": "ab" * 32,
        "tee_platform": "sgx-azure",
    })


class TestTheBatchDeliveryCheck:
    def test_a_fresh_pass_counts_as_delivered(self):
        ok, reason = siem_sidecar.batch_export_delivered(
            _Remote((True, _health(), "")), "sgx-azure")
        assert ok and reason == ""

    def test_a_missing_health_file_is_not_delivered(self):
        ok, reason = siem_sidecar.batch_export_delivered(
            _Remote((True, "MISSING", "")), "sgx-azure")
        assert not ok
        assert "never ticked" in reason

    def test_a_failed_export_is_not_delivered(self):
        ok, reason = siem_sidecar.batch_export_delivered(
            _Remote((True, _health(status="fail"), "")), "sgx-azure")
        assert not ok
        assert "did not accept" in reason

    def test_a_stale_success_is_not_delivered(self):
        """An old 'pass' describes some earlier run, not this one."""
        ok, reason = siem_sidecar.batch_export_delivered(
            _Remote((True, _health(age=99999), "")), "sgx-azure",
            max_lag_seconds=300)
        assert not ok
        assert "predates this batch run" in reason

    def test_unparseable_health_is_not_delivered(self):
        ok, reason = siem_sidecar.batch_export_delivered(
            _Remote((True, "not json at all", "")), "sgx-azure")
        assert not ok
        assert "not readable JSON" in reason

    def test_it_reads_the_platform_specific_path(self):
        remote = _Remote((True, _health(), ""))
        siem_sidecar.batch_export_delivered(remote, "nitro-aws")
        assert "/run/tee-crafter-nitro-aws/siem.health" in remote.commands[0]


class TestOutputIsWithheldFromAnUnauditedRun:
    """The bundle is deleted, not merely warned about."""

    def _run(self, tmp_path, *, siem_on=True, fail_open=False, delivered=False,
             monkeypatch=None):
        from tee_crafter.cli.commands.deploy import batch as batch_mod

        build = tmp_path / "build"
        (build / "siem").mkdir(parents=True)
        (build / "siem" / "siem.env").write_text(
            f"TEE_CRAFTER_SIEM_ENABLED={'1' if siem_on else '0'}\n"
            f"TEE_CRAFTER_SIEM_FAIL_OPEN={'1' if fail_open else '0'}\n",
            encoding="utf-8")

        bundle = build / "output.tar.gz"
        bundle.write_bytes(b"payload")
        (build / "output.tar.gz.sha256").write_text("deadbeef", encoding="utf-8")
        extracted = build / "output"
        extracted.mkdir()
        (extracted / "results.json").write_text("{}", encoding="utf-8")

        monkeypatch.setattr(
            batch_mod, "_withhold_output_if_unaudited",
            batch_mod._withhold_output_if_unaudited)
        monkeypatch.setattr(
            siem_sidecar, "batch_export_delivered",
            lambda *_a, **_k: (delivered, "" if delivered else "collector dark"))

        class _C:
            def __init__(self): self.text = ""
            def print(self, *a, **k): self.text += " ".join(str(x) for x in a)

        console = _C()
        result = batch_mod._withhold_output_if_unaudited(
            _Remote(), console, build_dir=str(build), tee_platform="sgx-azure",
            local_bundle=str(bundle), extracted_dir=str(extracted), duration=1.0)
        return result, console, bundle, extracted

    def test_an_undelivered_run_fails_and_deletes_the_bundle(self, tmp_path, monkeypatch):
        result, console, bundle, extracted = self._run(
            tmp_path, delivered=False, monkeypatch=monkeypatch)
        assert result is not None and result.success is False
        assert "withheld" in result.message
        assert not bundle.exists()
        assert not extracted.exists()
        assert "not audited" in console.text

    def test_a_delivered_run_keeps_its_output(self, tmp_path, monkeypatch):
        result, _console, bundle, extracted = self._run(
            tmp_path, delivered=True, monkeypatch=monkeypatch)
        assert result is None
        assert bundle.exists() and extracted.exists()

    def test_fail_open_releases_the_output_with_a_warning(self, tmp_path, monkeypatch):
        result, console, bundle, _ = self._run(
            tmp_path, delivered=False, fail_open=True, monkeypatch=monkeypatch)
        assert result is None
        assert bundle.exists()
        assert "no audit trail" in console.text

    def test_siem_off_is_not_gated_at_all(self, tmp_path, monkeypatch):
        result, _console, bundle, _ = self._run(
            tmp_path, siem_on=False, delivered=False, monkeypatch=monkeypatch)
        assert result is None
        assert bundle.exists()


class TestBatchActuallyInstallsTheSidecar:
    """Without this the gate above could never pass: nothing exported."""

    def test_the_batch_collector_installs_it(self):
        from tee_crafter.cli.commands.deploy import batch as batch_mod
        src = inspect.getsource(batch_mod.collect_batch_output)
        assert "_install_siem_for_batch" in src

    def test_it_runs_before_the_workload_starts(self):
        """An exporter started after a batch container exits observes nothing."""
        from tee_crafter.cli.commands.deploy import batch as batch_mod
        src = inspect.getsource(batch_mod.collect_batch_output)
        assert src.index("_install_siem_for_batch") < src.index(
            "_start_oneshot_and_wait")

    def test_it_marks_the_install_as_batch(self):
        from tee_crafter.cli.commands.deploy import batch as batch_mod
        src = inspect.getsource(batch_mod._install_siem_for_batch)
        assert "batch=True" in src

    def test_the_gate_is_never_preventive_in_batch_mode(self):
        """No requests exist to refuse, on any platform."""
        for platform in sorted(siem_sidecar.PREVENTIVE_GATE_PLATFORMS):
            assert siem_sidecar.gate_is_preventive(platform, batch=True) is False


class TestCollectorEndpointDerivation:
    @pytest.mark.parametrize("env,expected", [
        ({"TEE_CRAFTER_SIEM": "syslog-cef",
          "TEE_CRAFTER_SIEM_HOST": "siem.example.com",
          "TEE_CRAFTER_SIEM_PORT": "6514"}, ("siem.example.com", 6514)),
        ({"TEE_CRAFTER_SIEM": "splunk-hec",
          "TEE_CRAFTER_SIEM_ENDPOINT":
              "https://hec.example.com:8088/services/collector"},
         ("hec.example.com", 8088)),
        ({"TEE_CRAFTER_SIEM": "splunk-hec",
          "TEE_CRAFTER_SIEM_ENDPOINT": "https://hec.example.com/x"},
         ("hec.example.com", 443)),
        ({"TEE_CRAFTER_SIEM": "datadog",
          "TEE_CRAFTER_SIEM_SITE": "datadoghq.eu"},
         ("http-intake.logs.datadoghq.eu", 443)),
        ({"TEE_CRAFTER_SIEM": "none"}, ("", 0)),
        ({}, ("", 0)),
    ])
    def test_endpoints(self, env, expected):
        assert siem_sidecar.collector_endpoint(env) == expected

    def test_it_reads_the_same_provider_key_the_exporter_reads(self):
        """``TEE_CRAFTER_SIEM``, not ``TEE_CRAFTER_SIEM_PROVIDER``."""
        exporter = (TPL / "common" / "siem_export.py").read_text(encoding="utf-8")
        assert 'os.environ.get("TEE_CRAFTER_SIEM", "none")' in exporter
        assert siem_sidecar.collector_endpoint(
            {"TEE_CRAFTER_SIEM": "datadog"}) == (
                "http-intake.logs.datadoghq.com", 443)


class TestTheEnclaveEgressTunnel:
    def test_it_is_a_no_op_off_nitro(self):
        ok, detail = siem_sidecar.install_enclave_egress(
            console=None, build_dir="/nonexistent", tee_platform="snp-aws",
            run_remote=_Remote())
        assert ok and detail == ""

    def test_the_vsock_port_matches_the_enclave_side(self):
        """Two files, one number; a mismatch is a silent dead tunnel."""
        app = NITRO_APP.read_text(encoding="utf-8")
        assert f"_VSOCK_PORT_SIEM = {siem_sidecar.NITRO_SIEM_VSOCK_PORT}" in app

    def test_it_does_not_collide_with_the_kms_tunnel(self):
        app = NITRO_APP.read_text(encoding="utf-8")
        assert "_VSOCK_PORT_KMS = 8000" in app
        assert siem_sidecar.NITRO_SIEM_VSOCK_PORT != 8000

    def test_each_destination_gets_its_own_loopback_address(self):
        """Ports would collide when the collector is also on 443."""
        app = NITRO_APP.read_text(encoding="utf-8")
        assert "_LOOPBACK_KMS = '127.0.0.1'" in app
        assert "_LOOPBACK_SIEM = '127.0.0.2'" in app

    def test_the_redirect_rewrites_only_the_host(self):
        """Leaving the port and hostname alone is what keeps TLS verifying."""
        app = NITRO_APP.read_text(encoding="utf-8")
        assert "_orig_getaddrinfo(_LOOPBACK_SIEM, port, *args, **kwargs)" in app


class TestTheEnclaveCarriesTheExporter:
    def test_the_eif_copies_the_exporter(self):
        assert "COPY siem_export.py" in EIF_DOCKERFILE.read_text(encoding="utf-8")

    def test_the_eif_copies_the_public_siem_env(self):
        assert "COPY siem.env.public" in EIF_DOCKERFILE.read_text(encoding="utf-8")

    def test_the_bearer_secret_is_not_baked_into_the_measured_image(self):
        """The token would otherwise land in a published image hash."""
        from tee_crafter.cli.commands.deploy.siem_mode import SECRET_ENV_KEYS
        assert "TEE_CRAFTER_SIEM_TOKEN" in SECRET_ENV_KEYS
        assert "TEE_CRAFTER_SIEM_API_KEY" in SECRET_ENV_KEYS

    def test_the_entrypoint_sources_the_public_env_before_exec(self):
        from tee_crafter.core.packaging.container_wrap import generate_nitro_entrypoint
        script = generate_nitro_entrypoint("echo hi", 8080)
        assert "/tee-crafter-runtime/siem.env.public" in script
        assert script.index("siem.env.public") < script.index(
            "exec python3 /tee-crafter-runtime/app_vsock.py")

    def test_the_enclave_starts_the_exporter(self):
        app = NITRO_APP.read_text(encoding="utf-8")
        assert "start_in_enclave_siem_export()" in app

    def test_the_exporter_start_is_never_fatal(self):
        """A dead exporter must not take the workload down; the gate handles it."""
        app = NITRO_APP.read_text(encoding="utf-8")
        block = app.split("def start_in_enclave_siem_export", 1)[1].split(
            "\ndef ", 1)[0]
        assert "except Exception" in block
        assert "daemon=True" in block

    def test_it_stays_dormant_when_siem_is_off(self):
        app = NITRO_APP.read_text(encoding="utf-8")
        block = app.split("def start_in_enclave_siem_export", 1)[1].split(
            "\ndef ", 1)[0]
        assert "TEE_CRAFTER_SIEM_ENABLED" in block


class TestTheEifAlwaysHasSomethingToCopy:
    """An unconditional COPY of a missing file fails the whole image build."""

    def test_a_placeholder_is_written_when_siem_is_off(self, tmp_path):
        from tee_crafter.cli.commands.deploy.flow_container import (
            _stage_siem_env_public_for_eif,
        )
        dest = _stage_siem_env_public_for_eif(str(tmp_path))
        assert os.path.isfile(dest)
        assert "--siem not enabled" in pathlib.Path(dest).read_text(encoding="utf-8")

    def test_the_real_config_is_hoisted_to_the_build_root(self, tmp_path):
        from tee_crafter.cli.commands.deploy.flow_container import (
            _stage_siem_env_public_for_eif,
        )
        (tmp_path / "siem").mkdir()
        (tmp_path / "siem" / "siem.env.public").write_text(
            "TEE_CRAFTER_SIEM_ENABLED=1\nTEE_CRAFTER_SIEM=datadog\n",
            encoding="utf-8")
        dest = _stage_siem_env_public_for_eif(str(tmp_path))
        body = pathlib.Path(dest).read_text(encoding="utf-8")
        assert "TEE_CRAFTER_SIEM_ENABLED=1" in body
        assert "TEE_CRAFTER_SIEM=datadog" in body
