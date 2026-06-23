"""Unit tests for continuous attestation refresh + SIEM exporters."""
from __future__ import annotations

import json
import time

import pytest

from tee_crafter.core.audit.continuous import (
    AuditEventExporter, ContinuousAttestor, InMemoryExporter,
)
from tee_crafter.core.audit.exporters.syslog import SyslogCefExporter
from tee_crafter.core.audit.exporters.splunk_hec import SplunkHecExporter
from tee_crafter.core.audit.exporters.datadog import DatadogLogsExporter
from tee_crafter.core.audit.exporters.azure_monitor import AzureMonitorExporter
from tee_crafter.core.audit.exporters.cloudwatch import CloudWatchLogsExporter


# ---------- ContinuousAttestor ----------

def _ok_attest(nonce: bytes) -> bytes:
    return b"FAKE_QUOTE:" + nonce


def _fail_attest(nonce: bytes) -> bytes:
    raise RuntimeError("nsm busy")


class TestContinuousAttestor:
    def test_emit_now_pass(self):
        ex = InMemoryExporter()
        ca = ContinuousAttestor(
            attest=_ok_attest, exporters=[ex], interval_seconds=60,
            instance_id="i-1", tee_platform="snp-aws",
            pipeline_version="0.1.0",
        )
        ev = ca.emit_now(event_type="boot")
        assert ev.status == "pass"
        assert ev.attestation_size_bytes > 0
        assert ev.event_type == "boot"
        assert ev.signature != ""
        assert ev.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert ex.events[0] is ev

    def test_emit_now_failure_records_error(self):
        ex = InMemoryExporter()
        ca = ContinuousAttestor(
            attest=_fail_attest, exporters=[ex], interval_seconds=60,
        )
        ev = ca.emit_now()
        assert ev.status == "fail"
        assert ev.attestation_size_bytes == 0
        assert "nsm busy" in ev.extra.get("error", "")

    def test_chain_links_and_verify_chain(self):
        ex = InMemoryExporter()
        ca = ContinuousAttestor(
            attest=_ok_attest, exporters=[ex], interval_seconds=60,
        )
        for _ in range(5):
            ca.emit_now()
        events = ex.events
        assert len(events) == 5
        for prev_ev, ev in zip(events, events[1:]):
            assert ev.prev_digest == prev_ev.digest
        errs = ContinuousAttestor.verify_chain(events)
        assert errs == []

    def test_chain_detects_tampering(self):
        ex = InMemoryExporter()
        ca = ContinuousAttestor(
            attest=_ok_attest, exporters=[ex], interval_seconds=60)
        ca.emit_now(); ca.emit_now()
        events = list(ex.events)
        events[1].extra["mutated"] = "evil"  # tamper
        errs = ContinuousAttestor.verify_chain(events)
        assert errs and any("digest mismatch" in e for e in errs)

    def test_exporter_failure_does_not_break_chain(self):
        class Bad(AuditEventExporter):
            def emit(self, event):
                raise RuntimeError("downstream gone")
        good = InMemoryExporter()
        ca = ContinuousAttestor(
            attest=_ok_attest, exporters=[Bad(), good],
            interval_seconds=60)
        ca.emit_now(); ca.emit_now()
        # chain still advances even though Bad raised
        assert len(good.events) == 2
        assert good.events[1].prev_digest == good.events[0].digest

    def test_invalid_construction(self):
        with pytest.raises(ValueError):
            ContinuousAttestor(attest=_ok_attest, exporters=[],
                                interval_seconds=60)
        with pytest.raises(ValueError):
            ContinuousAttestor(attest=_ok_attest,
                                exporters=[InMemoryExporter()],
                                interval_seconds=0)

    def test_background_thread_emits(self):
        ex = InMemoryExporter()
        ca = ContinuousAttestor(
            attest=_ok_attest, exporters=[ex], interval_seconds=1,
        )
        ca.start()
        try:
            deadline = time.time() + 4
            while time.time() < deadline and len(ex.events) < 2:
                time.sleep(0.1)
        finally:
            ca.stop()
        assert len(ex.events) >= 2

    def test_signature_is_verifiable(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        ex = InMemoryExporter()
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[ex],
                                  interval_seconds=60)
        ev = ca.emit_now()
        pk = serialization.load_pem_public_key(ev.public_key_pem.encode())
        assert isinstance(pk, Ed25519PublicKey)
        pk.verify(bytes.fromhex(ev.signature), ev.digest.encode("ascii"))


# ---------- Syslog/CEF exporter ----------

class _FakeUDPSocket:
    def __init__(self):
        self.sends = []

    def sendto(self, data, addr):
        self.sends.append((data, addr))

    def sendall(self, data):  # for tcp
        self.sends.append((data, None))

    def connect(self, addr):
        pass

    def close(self):
        pass


class TestSyslogCefExporter:
    def test_udp_emit(self):
        sock = _FakeUDPSocket()
        ex = SyslogCefExporter(host="logserver", port=514, protocol="udp",
                                hostname="enc-01",
                                sock_factory=lambda: sock)
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[ex],
                                  interval_seconds=60,
                                  instance_id="i-abc", tee_platform="tdx-azure")
        ev = ca.emit_now(event_type="attestation_boot")
        assert sock.sends, "exporter sent nothing"
        line, addr = sock.sends[0]
        text = line.decode("utf-8")
        assert "CEF:0|TEE-Crafter|tee-crafter|" in text
        assert "tdx-azure" in text
        assert "rt=" in text
        assert ev.attestation_sha256 in text
        assert addr == ("logserver", 514)

    def test_invalid_protocol(self):
        with pytest.raises(ValueError):
            SyslogCefExporter(protocol="sctp")

    def test_severity_increases_on_failure(self):
        sock = _FakeUDPSocket()
        ex = SyslogCefExporter(sock_factory=lambda: sock, protocol="udp")
        ca = ContinuousAttestor(attest=_fail_attest, exporters=[ex],
                                  interval_seconds=60)
        ca.emit_now()
        line = sock.sends[0][0].decode("utf-8")
        # CEF severity 8 corresponds to a failure
        assert "|8|" in line


# ---------- Splunk HEC ----------

class TestSplunkHecExporter:
    def test_emit_posts_to_collector(self):
        captured = {}

        def fake(method, url, headers, body):
            captured.update({"method": method, "url": url,
                              "headers": headers, "body": body})
            return {"text": "Success", "code": 0}

        ex = SplunkHecExporter(endpoint="https://splunk.example/", token="TOKEN-X",
                                index="security", http=fake)
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[ex],
                                  interval_seconds=60, instance_id="i-1")
        ca.emit_now()
        assert captured["url"].endswith("/services/collector/event")
        assert captured["headers"]["Authorization"] == "Splunk TOKEN-X"
        assert captured["body"]["index"] == "security"
        assert captured["body"]["event"]["instance_id"] == "i-1"
        # Regression: ``time`` must be a numeric epoch, not an ISO string.
        # Splunk HEC rejects ISO-string timestamps with HTTP 400 "Error
        # in handling indexed fields" (code 15) so any non-numeric ``time``
        # would silently drop every event in production.
        assert isinstance(captured["body"]["time"], (int, float))
        assert captured["body"]["time"] > 0

    def test_time_field_is_epoch_seconds(self):
        """Splunk HEC ``time`` must be epoch seconds (float / int)."""
        from tee_crafter.core.audit.exporters.splunk_hec import _iso_to_epoch
        # Known fixed timestamp -> 2024-01-15T12:34:56Z is 1705322096
        assert _iso_to_epoch("2024-01-15T12:34:56Z") == 1705322096.0
        # Malformed input must not crash; fall back to "now" rather than
        # propagating an exception that would break the whole export.
        assert _iso_to_epoch("not-a-date") > 0
        assert _iso_to_epoch("") > 0

    def test_invalid_endpoint(self):
        with pytest.raises(ValueError):
            SplunkHecExporter(endpoint="ftp://x", token="t")

    def test_missing_token(self):
        with pytest.raises(ValueError):
            SplunkHecExporter(endpoint="https://x", token="")


# ---------- Datadog ----------

class TestDatadogLogsExporter:
    def test_emit(self):
        captured = {}

        def fake(method, url, headers, body):
            captured.update({"url": url, "headers": headers, "body": body})
            return {}

        ex = DatadogLogsExporter(api_key="DD-K", site="datadoghq.eu",
                                   env="prod", http=fake)
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[ex],
                                  interval_seconds=60, instance_id="i-7",
                                  tee_platform="snp-azure")
        ca.emit_now()
        assert captured["url"].endswith("logs.datadoghq.eu/api/v2/logs")
        assert captured["headers"]["DD-API-KEY"] == "DD-K"
        body = captured["body"]
        assert body["service"] == "tee-crafter"
        assert "tee_platform:snp-azure" in body["ddtags"]
        assert "status:pass" in body["ddtags"]


# ---------- Azure Monitor ----------

class TestAzureMonitorExporter:
    def test_emit(self):
        captured = {}

        def fake(method, url, headers, body):
            captured.update({"url": url, "headers": headers, "body": body})
            return {}

        ex = AzureMonitorExporter(
            dce_url="https://my-dce.eastus-1.ingest.monitor.azure.com",
            dcr_immutable_id="dcr-abcd",
            stream_name="Custom-TeeCrafterAttestation_CL",
            bearer_token_provider=lambda: "BEARER-T",
            http=fake,
        )
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[ex],
                                  interval_seconds=60)
        ca.emit_now()
        assert "dataCollectionRules/dcr-abcd" in captured["url"]
        assert "Custom-TeeCrafterAttestation_CL" in captured["url"]
        assert captured["headers"]["Authorization"] == "Bearer BEARER-T"
        assert isinstance(captured["body"], list)

    def test_validates_inputs(self):
        with pytest.raises(ValueError):
            AzureMonitorExporter(
                dce_url="http://insecure", dcr_immutable_id="x",
                stream_name="Custom-x", bearer_token_provider=lambda: "")
        with pytest.raises(ValueError):
            AzureMonitorExporter(
                dce_url="https://x", dcr_immutable_id="",
                stream_name="Custom-x", bearer_token_provider=lambda: "")
        with pytest.raises(ValueError):
            AzureMonitorExporter(
                dce_url="https://x", dcr_immutable_id="dcr",
                stream_name="WrongPrefix", bearer_token_provider=lambda: "")


# ---------- CloudWatch ----------

class FakeLogsClient:
    def __init__(self):
        self.create_group_calls = []
        self.create_stream_calls = []
        self.put_calls = []

    def create_log_group(self, logGroupName):
        self.create_group_calls.append(logGroupName)

    def create_log_stream(self, logGroupName, logStreamName):
        self.create_stream_calls.append((logGroupName, logStreamName))

    def put_log_events(self, **kwargs):
        self.put_calls.append(kwargs)
        return {"nextSequenceToken": "seq-1"}


class TestCloudWatchLogsExporter:
    def test_emit_creates_resources_then_logs(self):
        c = FakeLogsClient()
        ex = CloudWatchLogsExporter(log_group="/tee-crafter/audit",
                                      log_stream="i-1",
                                      client=c)
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[ex],
                                  interval_seconds=60, instance_id="i-1")
        ca.emit_now(); ca.emit_now()
        assert c.create_group_calls == ["/tee-crafter/audit"]
        assert c.create_stream_calls == [("/tee-crafter/audit", "i-1")]
        assert len(c.put_calls) == 2
        # Second call should carry the sequenceToken returned by the first.
        assert c.put_calls[1].get("sequenceToken") == "seq-1"
        # Each call carries exactly one log event with JSON body.
        msg = c.put_calls[0]["logEvents"][0]["message"]
        parsed = json.loads(msg)
        assert parsed["instance_id"] == "i-1"

    def test_invalid_args(self):
        with pytest.raises(ValueError):
            CloudWatchLogsExporter(log_group="", log_stream="x")
        with pytest.raises(ValueError):
            CloudWatchLogsExporter(log_group="x", log_stream="")


# ---------- wire-format: one canonicalisation, one genesis ----------

class TestWireFormat:
    """The producer, the sidecar and the verifier must agree byte-for-byte.

    They did not: ``siem_export.AttestationEvent.canonical_digest_payload``
    popped only ``signature`` and so hashed a dict still containing
    ``"digest": ""``, while both verifiers excluded ``digest`` *and*
    ``signature``.  Different JSON, different SHA-256, so no event a
    deployed TEE emitted could verify.
    """

    def test_digest_payload_excludes_digest_and_signature(self):
        from tee_crafter.templates.common.siem_export import (
            canonical_digest_payload,
        )
        payload = json.loads(canonical_digest_payload({
            "seq": 0, "digest": "aa", "signature": "bb", "status": "pass",
        }))
        assert payload == {"seq": 0, "status": "pass"}

    def test_core_and_sidecar_share_the_same_function(self):
        from tee_crafter.core.audit import continuous as core
        from tee_crafter.templates.common import siem_export

        assert core.canonical_digest_payload is siem_export.canonical_digest_payload
        assert core.GENESIS_PREV_DIGEST == siem_export.GENESIS_PREV_DIGEST
        assert core.EVENT_SCHEMA_VERSION == siem_export.EVENT_SCHEMA_VERSION

    def test_digest_recomputes_over_a_real_event(self):
        from dataclasses import asdict
        from tee_crafter.templates.common.siem_export import compute_digest

        exporter = InMemoryExporter()
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[exporter],
                                interval_seconds=60, instance_id="i-1")
        ev = ca.emit_now()
        assert compute_digest(asdict(ev)) == ev.digest

    def test_genesis_prev_digest_is_the_documented_value(self):
        from tee_crafter.templates.common.siem_export import GENESIS_PREV_DIGEST

        exporter = InMemoryExporter()
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[exporter],
                                interval_seconds=60, instance_id="i-1")
        first = ca.emit_now()
        second = ca.emit_now()
        assert first.prev_digest == GENESIS_PREV_DIGEST == "0" * 64
        assert second.prev_digest == first.digest
        assert ContinuousAttestor.verify_chain([first, second]) == []

    def test_unknown_schema_version_is_rejected_not_mis_verified(self):
        exporter = InMemoryExporter()
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[exporter],
                                interval_seconds=60, instance_id="i-1")
        ev = ca.emit_now()
        ev.schema_version = 99
        errs = ContinuousAttestor.verify_chain([ev])
        assert any("unsupported schema_version" in e for e in errs)
        # And it must NOT also report a digest mismatch: we stop at the
        # version gate rather than applying schema-2 rules to it.
        assert not any("digest mismatch" in e for e in errs)

    def test_schema_version_is_covered_by_the_digest(self):
        from dataclasses import asdict
        from tee_crafter.templates.common.siem_export import compute_digest

        exporter = InMemoryExporter()
        ca = ContinuousAttestor(attest=_ok_attest, exporters=[exporter],
                                interval_seconds=60, instance_id="i-1")
        ev = ca.emit_now()
        d = asdict(ev)
        d["schema_version"] = 3
        assert compute_digest(d) != ev.digest
