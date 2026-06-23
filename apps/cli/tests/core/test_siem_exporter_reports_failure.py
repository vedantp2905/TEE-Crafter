"""Exporters must raise on delivery failure, not log and return.

``AttestationLoop.tick`` derives ``last_export_status`` solely from whether
``emit()`` raised.  That design is sound, and it is why an exporter that
swallows its own failures reports ``pass`` forever — which matters because
``last_export_status`` is what the in-TEE fail-closed gate reads
(``siem_health.assert_siem_healthy``) and, under the shipped default
``fail_open = False``, what decides whether the workload may serve at all.

Measured on a live ``nitro-aws`` deploy (2026-08-21) with the collector pointed
at an RFC 2606 ``.invalid`` hostname, so delivery was impossible::

    WARNING HEC POST failed: URLError(gaierror(-2, 'Name or service not known'))
    INFO    emitted seq=0 status=pass size=0 platform=nitro-aws export=pass

``siem.health`` recorded ``"last_export_status":"pass"`` with an empty
``last_export_error``, and the deploy printed "✓ SIEM sidecar active — events
streaming (export confirmed)".  Three separate earlier fixes to this readiness
check all held; the check was correct and was being fed a lie one layer down.

The parametrisation over exporters is the point: ``splunk-hec`` and ``datadog``
had the identical swallowing shape, and syslog's UDP branch had it too while its
TCP branch was correct. A fix applied to one and not the others is how this bug
survived three rounds.
"""

import socket
import urllib.error

import pytest

from tee_crafter.templates.common.siem_export import (
    DatadogLogsExporter,
    SiemExportError,
    SplunkHecExporter,
    SyslogCefExporter,
)


def _splunk(**kw):
    return SplunkHecExporter(
        endpoint="https://collector.invalid:8088", token="tok",
        index="main", sourcetype="st", source="src", **kw)


def _datadog(**kw):
    return DatadogLogsExporter(
        api_key="key", site="datadoghq.com", service="svc",
        source="src", env="test", **kw)


#: The two HTTP exporters share a wire shape, so they share the assertions.
HTTP_EXPORTERS = [
    pytest.param(_splunk, id="splunk-hec"),
    pytest.param(_datadog, id="datadog"),
]


@pytest.fixture
def event():
    """A minimal event; no exporter reads more than the dataclass fields."""
    from tee_crafter.templates.common.siem_export import AttestationEvent
    return AttestationEvent(
        event_id="abcdef0123456789", seq=1, event_type="attestation_boot",
        timestamp="2026-08-21T06:15:48Z", pipeline_version="test",
        instance_id="i-061889b6de6e88d28", tee_platform="nitro-aws",
        measurement_sha256="", attestation_sha256="",
        attestation_size_bytes=0, status="pass", prev_digest="",
    )


class TestHttpExportersRaise:
    @pytest.mark.parametrize("make", HTTP_EXPORTERS)
    def test_unresolvable_host_raises(self, make, event, monkeypatch):
        """The exact live failure: DNS cannot resolve the collector."""
        def _boom(*_a, **_kw):
            raise urllib.error.URLError(
                socket.gaierror(-2, "Name or service not known"))
        monkeypatch.setattr(
            "urllib.request.urlopen", _boom, raising=True)
        with pytest.raises(SiemExportError) as exc:
            make().emit(event)
        assert "Name or service not known" in str(exc.value)

    @pytest.mark.parametrize("make", HTTP_EXPORTERS)
    def test_http_error_raises(self, make, event, monkeypatch):
        """A 403 is a bad token — the collector received nothing."""
        def _boom(*_a, **_kw):
            raise urllib.error.HTTPError(
                "https://collector.invalid", 403, "Forbidden", {},
                __import__("io").BytesIO(b'{"text":"Invalid token","code":4}'))
        monkeypatch.setattr("urllib.request.urlopen", _boom, raising=True)
        with pytest.raises(SiemExportError) as exc:
            make().emit(event)
        assert "403" in str(exc.value)

    @pytest.mark.parametrize("make", HTTP_EXPORTERS)
    def test_3xx_status_raises(self, make, event, monkeypatch):
        """A redirect is not a delivery.

        ``urlopen`` does not raise for 3xx, so this is the one failure mode that
        has to be checked on the response object rather than caught.
        """
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda *_a, **_kw: _FakeResponse(302, b"moved"), raising=True)
        with pytest.raises(SiemExportError) as exc:
            make().emit(event)
        assert "302" in str(exc.value)

    @pytest.mark.parametrize("make", HTTP_EXPORTERS)
    def test_2xx_does_not_raise(self, make, event, monkeypatch):
        """The success path must stay silent — this is the regression guard.

        Making failures raise is only useful if success still returns normally;
        an exporter that raised unconditionally would take every workload down
        under the fail-closed default.
        """
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda *_a, **_kw: _FakeResponse(200, b""), raising=True)
        make().emit(event)  # must not raise


class _FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, *_a):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class TestSyslogUdpRaises:
    def test_udp_send_failure_raises(self, event, monkeypatch):
        """UDP's locally-detectable failures must not be swallowed.

        A successful ``sendto`` proves only that the datagram reached the local
        kernel, and that limit is inherent to UDP.  An unresolvable hostname is
        different: it fails locally, is detectable, and used to be logged and
        forgotten while the tick still reported ``export=pass``.
        """
        class _Sock:
            def sendto(self, *_a):
                raise socket.gaierror(-2, "Name or service not known")

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", lambda *_a, **_kw: _Sock())
        exporter = SyslogCefExporter(host="collector.invalid", port=514,
                                     protocol="udp")
        with pytest.raises(SiemExportError):
            exporter.emit(event)

    def test_udp_success_does_not_raise(self, event, monkeypatch):
        sent = []

        class _Sock:
            def sendto(self, data, addr):
                sent.append((data, addr))

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", lambda *_a, **_kw: _Sock())
        SyslogCefExporter(host="10.0.1.5", port=514,
                          protocol="udp").emit(event)
        assert len(sent) == 1


class TestLoopRecordsTheFailure:
    """End-to-end within the sidecar: a raising exporter -> ``fail`` + reason."""

    def _tick_with(self, exporter, monkeypatch, tmp_path):
        from tee_crafter.templates.common import siem_export as se
        written = {}
        monkeypatch.setattr(
            se, "_write_health_state",
            lambda **kw: written.update(kw), raising=True)
        loop = se.AttestationLoop(
            exporter=exporter,
            interval_seconds=60,
            instance_id="i-061889b6de6e88d28",
            tee_platform="nitro-aws",
            pipeline_version="test",
            attest_provider=lambda: (b"report-bytes", "a" * 64),
        )
        loop.tick()
        return written

    def test_failure_becomes_fail_with_a_reason(self, monkeypatch, tmp_path):
        class _Raising:
            def emit(self, _ev):
                raise SiemExportError(
                    "HEC POST failed: URLError(gaierror(-2, "
                    "'Name or service not known'))")

        written = self._tick_with(_Raising(), monkeypatch, tmp_path)
        assert written["last_export_status"] == "fail"
        # The class name alone cannot distinguish a bad token from a dead host.
        assert "Name or service not known" in written["last_export_error"]

    def test_health_error_field_carries_no_json_metacharacters(
        self, monkeypatch, tmp_path,
    ):
        """The readiness check seds ``last_export_status`` out of this JSON.

        ``last_export_error`` is serialised before it (keys are sorted), and the
        sed pattern is greedy, so an error string containing a quoted
        ``last_export_status`` could shadow the real value.  Strip the
        metacharacters rather than rely on nobody ever echoing them back.
        """
        class _Raising:
            def emit(self, _ev):
                raise SiemExportError(
                    'collector said "last_export_status": "pass" \\ oops')

        written = self._tick_with(_Raising(), monkeypatch, tmp_path)
        assert '"' not in written["last_export_error"]
        assert "\\" not in written["last_export_error"]
        assert written["last_export_status"] == "fail"

    def test_success_still_records_pass(self, monkeypatch, tmp_path):
        class _Ok:
            def emit(self, _ev):
                return None

        written = self._tick_with(_Ok(), monkeypatch, tmp_path)
        assert written["last_export_status"] == "pass"
        assert written["last_export_error"] == ""
