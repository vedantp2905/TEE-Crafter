"""Two defects found by running `--siem syslog-cef` against a real collector.

**1. The egress port didn't follow the collector's port.** `egress_ports`
defaults to `[443]`, which is right for the HTTPS providers and wrong for
syslog-cef, whose documented default port is 514. Nothing folded the configured
`port` into the egress allowlist, so the generated security group permitted 443
outbound while the exporter dialled 514 — the default syslog-cef configuration
blocked its own traffic.

**2. "events streaming" was claimed without a single delivered event.** The
readiness check only proved the sidecar *process* was alive. syslog-cef connects
lazily, so an unreachable collector leaves the unit `active` forever while every
export times out. Measured on a real `nitro-aws` deploy (2026-08-20) with a
collector on 6514 and an SG allowing only 443:

    syslog TCP socket to 18.117.255.23:6514 died (timeout); reconnecting
    syslog TCP send ... failed after reconnect: timeout
    exporter.emit failed: timeout
    emitted seq=-1 status=pass size=0 platform=nitro-aws export=fail

The collector received **zero bytes**, and the deploy printed
"✓ SIEM sidecar active — events streaming."

The sidecar already publishes the answer: SIEM-SEC-4's health file carries
`last_export_status`, and the in-TEE fail-closed gate reads that same field. The
readiness check now reads it too.
"""

import json

import pytest

from tee_crafter.cli.commands.deploy.siem_mode import build_siem_config
from tee_crafter.cli.deployment.common import siem_sidecar


def _cfg_file(tmp_path, doc):
    p = tmp_path / "siem.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


class TestSyslogEgressPort:
    def test_egress_port_follows_the_collector_port(self, tmp_path):
        cfg = build_siem_config(
            provider="syslog-cef",
            raw_config_path=_cfg_file(tmp_path, {
                "provider": "syslog-cef", "host": "collector.example",
                "port": 6514, "protocol": "tcp", "egress_mode": "public",
            }))
        assert cfg.egress_ports == [6514], (
            "egress SG would allow 443 while the exporter dials 6514")

    def test_default_syslog_port_is_not_left_on_443(self, tmp_path):
        """The out-of-the-box case: no port given, so 514 is used."""
        cfg = build_siem_config(
            provider="syslog-cef",
            raw_config_path=_cfg_file(tmp_path, {
                "provider": "syslog-cef", "host": "collector.example",
                "protocol": "tcp", "egress_mode": "public",
            }))
        assert cfg.port == 514
        assert cfg.egress_ports == [514]

    def test_explicit_egress_ports_win(self, tmp_path):
        """A collector behind a proxy on 443 must stay overridable."""
        cfg = build_siem_config(
            provider="syslog-cef",
            raw_config_path=_cfg_file(tmp_path, {
                "provider": "syslog-cef", "host": "collector.example",
                "port": 6514, "egress_ports": [443], "egress_mode": "public",
            }))
        assert cfg.egress_ports == [443]

    @pytest.mark.parametrize("provider,extra", [
        ("splunk-hec", {"endpoint": "https://x/services/collector", "token": "t"}),
        ("datadog", {"api_key": "k"}),
    ])
    def test_https_providers_keep_443(self, tmp_path, provider, extra):
        """Only syslog-cef changes; the HTTPS providers still default to 443."""
        doc = {"provider": provider, "egress_mode": "public"}
        doc.update(extra)
        cfg = build_siem_config(provider=provider,
                                raw_config_path=_cfg_file(tmp_path, doc))
        assert cfg.egress_ports == [443]


class TestSidecarExportConfirmation:
    def test_install_script_polls_the_health_file(self):
        script = siem_sidecar._install_script("dW5pdA==", "nitro-aws")
        assert "/run/tee-crafter-nitro-aws/siem.health" in script
        assert "last_export_status" in script
        assert "export=" in script

    @pytest.mark.parametrize("marker,expected", [
        ("SIEM-SEC: tee-crafter-siem state=active restarts=0->0 export=pass",
         ("active", "0->0", "pass")),
        ("SIEM-SEC: tee-crafter-siem state=active restarts=0->0 export=fail",
         ("active", "0->0", "fail")),
        ("SIEM-SEC: tee-crafter-siem state=crashlooping restarts=0->4 export=unknown",
         ("crashlooping", "0->4", "unknown")),
        ("no marker at all", ("", "", "")),
    ])
    def test_marker_parser_reads_all_three_fields(self, marker, expected):
        assert siem_sidecar.parse_sidecar_marker(marker) == expected

    def test_later_marker_wins_over_a_journal_echo(self):
        """A journal line quoting the prefix must not shadow the real verdict."""
        text = (
            "SIEM-SEC: tee-crafter-siem state=active restarts=0->0 export=fail\n"
            "some journal noise\n"
            "SIEM-SEC: tee-crafter-siem state=active restarts=0->0 export=pass\n"
        )
        assert siem_sidecar.parse_sidecar_marker(text)[2] == "pass"

    def test_active_but_failing_export_is_not_streaming(self):
        """The exact live failure: process alive, every export timing out.

        Uses the real parser, so this fails if the verdict stops reading the
        export field — unlike an assertion over a locally built string, which
        would pass no matter what the implementation did.
        """
        state, _, export = siem_sidecar.parse_sidecar_marker(
            "SIEM-SEC: tee-crafter-siem state=active restarts=0->0 export=fail")
        streaming = (state == "active" and export == "pass")
        assert not streaming

    def test_active_with_confirmed_export_is_streaming(self):
        state, _, export = siem_sidecar.parse_sidecar_marker(
            "SIEM-SEC: tee-crafter-siem state=active restarts=0->0 export=pass")
        assert (state == "active" and export == "pass")

    def test_success_branch_requires_export_pass_in_source(self):
        """The implementation must gate the green line on export_status.

        A source assertion is deliberate: the alternative is a fake remote host,
        and the defect was a missing conjunct in one `if`.
        """
        import inspect
        src = inspect.getsource(siem_sidecar.install_siem_sidecar)
        assert 'export_status == "pass"' in src, (
            "the streaming claim is no longer conditioned on a confirmed export")
        # And the not-yet-exporting case must be reported, not silently passed.
        assert "has not confirmed an" in src
