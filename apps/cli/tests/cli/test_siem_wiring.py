"""Tests for the SIEM end-to-end wiring: staging, sidecar install, providers."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))


class TestSiemExportStaging(unittest.TestCase):
    """`siem_export.py` must be staged into every build's app/ dir so the
    sidecar systemd unit can find it."""

    def test_siem_export_is_in_runtime_modules(self):
        from tee_crafter.core.builder import platforms as p
        self.assertIn("siem_export.py", p._RUNTIME_MODULES)

    def test_siem_export_file_exists_in_templates_common(self):
        from tee_crafter.core.builder import platforms as p
        common = p._common_dir()
        self.assertTrue(
            os.path.isfile(os.path.join(common, "siem_export.py")),
            "siem_export.py missing from templates/common/")

    def test_copy_runtime_modules_includes_siem_export(self):
        from tee_crafter.core.builder.platforms import _copy_runtime_modules
        dest = tempfile.mkdtemp(prefix="tc_test_siem_")
        try:
            _copy_runtime_modules(dest)
            self.assertTrue(
                os.path.isfile(os.path.join(dest, "siem_export.py")),
                "siem_export.py was not copied into staged app/ dir")
        finally:
            shutil.rmtree(dest, ignore_errors=True)


class TestSidecarPlatformLayout(unittest.TestCase):
    """All known TEE platforms must have a layout entry so the sidecar
    install path doesn't silently no-op."""

    def test_all_supported_platforms_have_layout(self):
        from tee_crafter.cli.deployment.common import siem_sidecar as s
        for plat in s.SUPPORTED_PLATFORMS:
            self.assertIn(plat, s._LAYOUT,
                          f"{plat} missing from _LAYOUT — sidecar won't install")

    def test_supported_platforms_match_export_factories(self):
        # The on-VM script's provider factory list and the deploy-side
        # layout list must agree, or installs will fail post-bake.
        from tee_crafter.cli.deployment.common.siem_sidecar import _LAYOUT
        from tee_crafter.templates.common import siem_export as e
        # Every layout-listed platform must have a provider factory.
        for plat in _LAYOUT:
            self.assertIn(plat, e._PROVIDER_FACTORIES,
                          f"{plat} has _LAYOUT but no _PROVIDER_FACTORIES entry")

    def test_render_sidecar_unit_substitutes_paths(self):
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            render_sidecar_unit,
        )
        unit = render_sidecar_unit("snp-aws")
        self.assertIn("/opt/tee-crafter-snp/app", unit)
        self.assertIn("/opt/tee-crafter-snp/venv/bin/python3", unit)
        self.assertIn("TEE_CRAFTER_TEE_PLATFORM=snp-aws", unit)
        # The template's placeholders must have been substituted.
        self.assertNotIn("{remote_app_dir}", unit)
        self.assertNotIn("{remote_venv}", unit)
        self.assertNotIn("{tee_platform}", unit)

    def test_render_sidecar_unit_nitro_uses_system_python(self):
        # Nitro's host has no /opt/tee-crafter/venv — the sidecar must
        # fall back to system Python.
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            render_sidecar_unit,
        )
        unit = render_sidecar_unit("nitro-aws")
        self.assertIn("/usr/bin/python3", unit)
        self.assertIn("TEE_CRAFTER_TEE_PLATFORM=nitro-aws", unit)

    def test_render_sidecar_unit_rejects_unknown_platform(self):
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            render_sidecar_unit,
        )
        with self.assertRaises(ValueError):
            render_sidecar_unit("unknown-platform")


class TestSidecarInstallGate(unittest.TestCase):
    """`install_siem_sidecar` must be a no-op when SIEM is disabled and
    must actually attempt install when SIEM is enabled."""

    def setUp(self):
        self.build_dir = tempfile.mkdtemp(prefix="tc_test_siem_install_")

    def tearDown(self):
        shutil.rmtree(self.build_dir, ignore_errors=True)

    def _write_siem_env(self, enabled: bool):
        with open(os.path.join(self.build_dir, "siem.env"),
                  "w", encoding="utf-8") as f:
            f.write("TEE_CRAFTER_SIEM=splunk-hec\n")
            f.write(f"TEE_CRAFTER_SIEM_ENABLED={'1' if enabled else '0'}\n")

    def test_no_op_when_no_siem_env(self):
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            install_siem_sidecar,
        )
        run_remote = MagicMock()
        console = MagicMock()
        ok = install_siem_sidecar(
            console=console, build_dir=self.build_dir,
            tee_platform="snp-aws", run_remote=run_remote,
        )
        self.assertTrue(ok)
        # No remote command should have run.
        run_remote.assert_not_called()

    def test_no_op_when_siem_explicitly_disabled(self):
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            install_siem_sidecar,
        )
        self._write_siem_env(enabled=False)
        run_remote = MagicMock()
        ok = install_siem_sidecar(
            console=MagicMock(), build_dir=self.build_dir,
            tee_platform="snp-aws", run_remote=run_remote,
        )
        self.assertTrue(ok)
        run_remote.assert_not_called()

    def test_install_runs_when_enabled(self):
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            install_siem_sidecar,
        )
        self._write_siem_env(enabled=True)
        run_remote = MagicMock(return_value=(True, "active\n", ""))
        ok = install_siem_sidecar(
            console=MagicMock(), build_dir=self.build_dir,
            tee_platform="snp-aws", run_remote=run_remote,
        )
        self.assertTrue(ok)
        run_remote.assert_called_once()
        # The install script must reference the daemon-reload step and
        # the resolved app dir.
        script = run_remote.call_args.args[0]
        self.assertIn("daemon-reload", script)
        self.assertIn("tee-crafter-siem.service", script)
        self.assertIn("/opt/tee-crafter-snp/app/siem.env", script)


class TestExporterFactories(unittest.TestCase):
    """Each supported provider in `siem_export._build_exporter` must
    construct cleanly when the env is set."""

    def setUp(self):
        # Snapshot the env so each test can mutate freely.
        self._env_snapshot = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env_snapshot)

    def test_splunk_hec_constructs(self):
        from tee_crafter.templates.common.siem_export import _build_exporter
        os.environ.update({
            "TEE_CRAFTER_SIEM": "splunk-hec",
            "TEE_CRAFTER_SIEM_ENDPOINT": "https://splunk.example.com:8088",
            "TEE_CRAFTER_SIEM_TOKEN": "abcd-1234",
            "TEE_CRAFTER_SIEM_INDEX": "tee_crafter",
        })
        exp = _build_exporter()
        # URL must end at /services/collector/event regardless of how
        # the user supplied the endpoint.
        self.assertTrue(exp.url.endswith("/services/collector/event"))
        self.assertEqual(exp.index, "tee_crafter")

    def test_splunk_hec_handles_trailing_collector_in_endpoint(self):
        from tee_crafter.templates.common.siem_export import _build_exporter
        os.environ.update({
            "TEE_CRAFTER_SIEM": "splunk-hec",
            "TEE_CRAFTER_SIEM_ENDPOINT":
                "https://splunk.example.com/services/collector",
            "TEE_CRAFTER_SIEM_TOKEN": "abcd-1234",
        })
        exp = _build_exporter()
        # Trailing "/services/collector" should NOT be doubled up.
        self.assertEqual(
            exp.url, "https://splunk.example.com/services/collector/event")

    def test_datadog_constructs(self):
        from tee_crafter.templates.common.siem_export import _build_exporter
        os.environ.update({
            "TEE_CRAFTER_SIEM": "datadog",
            "TEE_CRAFTER_SIEM_API_KEY": "ddapi",
            "TEE_CRAFTER_SIEM_SITE": "datadoghq.com",
            "TEE_CRAFTER_SIEM_SERVICE": "tee-crafter",
        })
        exp = _build_exporter()
        self.assertIn("datadoghq.com", exp.url)

    def test_syslog_cef_constructs(self):
        from tee_crafter.templates.common.siem_export import _build_exporter
        os.environ.update({
            "TEE_CRAFTER_SIEM": "syslog-cef",
            "TEE_CRAFTER_SIEM_HOST": "10.0.0.1",
            "TEE_CRAFTER_SIEM_PORT": "514",
        })
        exp = _build_exporter()
        self.assertEqual(exp.host, "10.0.0.1")
        self.assertEqual(exp.port, 514)
        self.assertEqual(exp.protocol, "tcp")


class TestInsecureTlsGate(unittest.TestCase):
    """Regression for SIEM-SEC-1: shipping events over an unauthenticated
    TLS channel must require an explicit `allow_insecure` opt-in."""

    def setUp(self):
        self._snapshot = dict(os.environ)
        # Default sandbox-ish config so main() reaches the gate.
        os.environ.clear()
        os.environ.update({
            "TEE_CRAFTER_SIEM": "splunk-hec",
            "TEE_CRAFTER_SIEM_ENABLED": "1",
            "TEE_CRAFTER_SIEM_ENDPOINT": "https://localhost:8443/services/collector",
            "TEE_CRAFTER_SIEM_TOKEN": "11111111-1111-1111-1111-111111111111",
            "TEE_CRAFTER_TEE_PLATFORM": "snp-aws",
            "TEE_CRAFTER_SIEM_X_VERIFY_SSL": "0",
            # NOTE: TEE_CRAFTER_SIEM_X_ALLOW_INSECURE intentionally not set.
        })

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._snapshot)

    def test_main_refuses_when_verify_ssl_off_and_no_allow_insecure(self):
        from tee_crafter.templates.common import siem_export as e
        # Force the autodetect to fail-fast so we don't try to import
        # a non-existent app_snp module.
        original_build_provider = e._build_provider
        e._build_provider = lambda *_a, **_k: (_ for _ in ()).throw(
            RuntimeError("test stub — should not be reached"))
        try:
            rc = e.main()
        finally:
            e._build_provider = original_build_provider
        # Exit code 5 = SIEM-SEC-1 refuse-to-export.
        self.assertEqual(rc, 5)

    def test_main_proceeds_when_allow_insecure_set(self):
        from tee_crafter.templates.common import siem_export as e
        os.environ["TEE_CRAFTER_SIEM_X_ALLOW_INSECURE"] = "1"
        # Provider factory will succeed (no real app_snp on path → fail at
        # import), so we'll observe exit code 3 not 5.
        rc = e.main()
        self.assertNotEqual(rc, 5,
                            "allow_insecure=1 should bypass the SEC-1 gate")


class TestHeartbeatProvider(unittest.TestCase):
    """The Nitro / SGX heartbeat provider reads measurement from a JSON
    file and emits boot-anchored events."""

    def test_heartbeat_reads_measurement_from_json(self):
        from tee_crafter.templates.common.siem_export import _provider_heartbeat
        d = tempfile.mkdtemp(prefix="tc_test_hb_")
        try:
            p1 = os.path.join(d, "build_provenance.json")
            with open(p1, "w", encoding="utf-8") as f:
                json.dump({"measurement": "DEADBEEF"}, f)
            prov = _provider_heartbeat([p1])
            blob, meas = prov()
            self.assertEqual(blob, b"")
            self.assertEqual(meas, "deadbeef")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_heartbeat_falls_back_to_empty_when_no_file(self):
        from tee_crafter.templates.common.siem_export import _provider_heartbeat
        prov = _provider_heartbeat(["/nonexistent/path/abc.json"])
        blob, meas = prov()
        self.assertEqual(blob, b"")
        self.assertEqual(meas, "")


class TestAttestationEventSchema(unittest.TestCase):
    """The sidecar's AttestationEvent must hash-chain and sign correctly
    so downstream verification (which mirrors the in-tree
    ``tee_crafter.core.audit.continuous.AttestationEvent``) succeeds."""

    def test_canonical_digest_excludes_signature(self):
        from tee_crafter.templates.common.siem_export import AttestationEvent
        ev = AttestationEvent(
            event_id="x", seq=0, event_type="attestation_boot",
            timestamp="2026-05-14T05:00:00Z", pipeline_version="t",
            instance_id="i-test", tee_platform="snp-aws",
            measurement_sha256="0" * 96, attestation_sha256="0" * 64,
            attestation_size_bytes=0, status="pass", prev_digest="",
            signature="not-included",
        )
        payload = ev.canonical_digest_payload()
        self.assertNotIn(b"not-included", payload)
        # `signature` field must be dropped from the digest input.
        self.assertNotIn(b'"signature"', payload)


if __name__ == "__main__":
    unittest.main()
