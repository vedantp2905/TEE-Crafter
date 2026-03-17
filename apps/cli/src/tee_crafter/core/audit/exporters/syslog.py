"""Generic syslog (RFC 5424) + CEF-formatted exporter.

Works with any SIEM that ingests syslog: ArcSight, IBM QRadar, Sentinel
Linux agent, Graylog, rsyslog forwarders, etc.  Defaults to **TCP** for
reliable delivery; set ``protocol="udp"`` when your collector only
listens on UDP (legacy ``514/udp``).  Production often terminates TLS on
a forwarder hop before plain syslog to the SIEM.
"""
from __future__ import annotations

import logging
import select
import socket
from typing import Optional

from tee_crafter.core.audit.continuous import AttestationEvent, AuditEventExporter

logger = logging.getLogger("tee_crafter.audit.exporters.syslog")


class SyslogCefExporter(AuditEventExporter):
    """Production-grade RFC 5424 + CEF exporter.

    TCP path includes reconnect-on-failure: any send-side OSError or
    timeout closes the cached socket and the next ``emit()`` re-dials.
    DNS is re-resolved on every re-dial — important for collectors
    behind multi-A-record DNS, ngrok TCP edges, or k8s services whose
    cluster-IP can rotate after a control-plane upgrade.

    Connect / send timeouts (``connect_timeout``/``send_timeout``)
    prevent a black-holed peer from wedging the attestation loop —
    fail-open is only fail-open if the failure is *prompt*.
    """

    def __init__(
        self,
        *,
        host: str = "localhost",
        port: int = 514,
        protocol: str = "tcp",
        facility: int = 13,  # log audit
        severity: int = 5,    # notice
        hostname: str = "",
        device_vendor: str = "TEE-Crafter",
        device_product: str = "tee-crafter",
        device_version: str = "0.1.0",
        connect_timeout: float = 10.0,
        send_timeout: float = 5.0,
        sock_factory=None,
    ):
        if protocol not in ("udp", "tcp"):
            raise ValueError("SyslogCefExporter protocol must be 'udp' or 'tcp'")
        self.host = host
        self.port = port
        self.protocol = protocol
        self.facility = facility
        self.severity = severity
        self.hostname = hostname or socket.gethostname()
        self.device_vendor = device_vendor
        self.device_product = device_product
        self.device_version = device_version
        self.connect_timeout = float(connect_timeout)
        self.send_timeout = float(send_timeout)
        self._sock_factory = sock_factory
        self._sock: Optional[socket.socket] = None

    def _open_socket(self):
        if self._sock_factory is not None:
            return self._sock_factory()
        if self.protocol == "udp":
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.connect_timeout)
        s.connect((self.host, self.port))
        s.settimeout(self.send_timeout)
        # SO_KEEPALIVE + tight knobs so the kernel proactively probes a
        # silent peer (NAT rebind, ngrok edge rotation, docker proxy
        # restart) instead of waiting ~2h for the default keepalive
        # timer.  TCP_KEEPIDLE / _KEEPINTVL / _KEEPCNT are Linux-only;
        # on macOS the kernel uses the default ~2h.  Guard each with
        # hasattr so the same code runs on every supported host.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
            if hasattr(socket, "TCP_KEEPINTVL"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            if hasattr(socket, "TCP_KEEPCNT"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except OSError:
            pass
        return s

    def _get_socket(self):
        if self._sock is None:
            self._sock = self._open_socket()
        return self._sock

    def _drop_socket(self) -> None:
        s = self._sock
        self._sock = None
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    def _peer_closed(self, sock) -> bool:
        """Cheap pre-send liveness probe.

        TCP gives no synchronous "is the peer gone" API.  A naive
        ``sendall`` succeeds (data goes to the kernel buffer) even if
        the peer has already sent FIN; only the *next* send observes
        the RST.  That single-send loss is unacceptable for an
        attestation event stream.

        We use ``select(timeout=0)`` to ask the kernel "is there
        anything to read right now?" — instant, no blocking, no
        interaction with ``settimeout()``.  Only if the socket
        reports readable do we ``recv(MSG_PEEK)`` to disambiguate:

        * readable + ``recv`` returns ``b""``    → peer sent FIN
        * readable + ``recv`` returns data       → unsolicited; weird
        * readable + ``recv`` raises             → broken
        * not readable                            → alive, idle
        """
        try:
            readable, _, _ = select.select([sock], [], [], 0)
        except (OSError, ValueError):
            return True
        if not readable:
            return False
        try:
            data = sock.recv(1, socket.MSG_PEEK)
            return data == b"" or len(data) > 0
        except OSError:
            return True

    def emit(self, event: AttestationEvent) -> None:
        line = self._format(event).encode("utf-8")
        if self.protocol == "udp":
            sock = self._get_socket()
            sock.sendto(line, (self.host, self.port))
            return
        payload = line + b"\n"
        # TCP: probe-then-send, with one retry.  The probe handles the
        # half-closed case (FIN-only) that ``sendall`` would silently
        # absorb; the retry handles the case where the peer dies
        # *between* the probe and the send.
        for attempt in (1, 2):
            try:
                sock = self._get_socket()
                if self._sock_factory is None and self._peer_closed(sock):
                    self._drop_socket()
                    sock = self._get_socket()
                sock.sendall(payload)
                return
            except (OSError, socket.timeout) as e:
                self._drop_socket()
                if attempt == 2:
                    logger.warning(
                        "syslog TCP send to %s:%d failed after reconnect: %r",
                        self.host, self.port, e)
                    raise
                logger.info(
                    "syslog TCP socket to %s:%d died (%r); reconnecting",
                    self.host, self.port, e)

    def close(self) -> None:
        self._drop_socket()

    # ---- formatting ----

    def _format(self, ev: AttestationEvent) -> str:
        # CEF:Version|Vendor|Product|Version|EventID|Name|Severity|Extension
        sev = self._sev_for_event(ev)
        cef_header = (
            f"CEF:0|{_esc(self.device_vendor)}|{_esc(self.device_product)}|"
            f"{_esc(self.device_version)}|{_esc(ev.event_type)}|"
            f"TEE attestation {ev.status}|{sev}|"
        )
        ext = (
            f"rt={ev.timestamp} "
            f"deviceExternalId={ev.instance_id} "
            f"cs1Label=teePlatform cs1={ev.tee_platform} "
            f"cs2Label=measurementSha256 cs2={ev.measurement_sha256} "
            f"cs3Label=attestationSha256 cs3={ev.attestation_sha256} "
            f"cs4Label=chainHead cs4={ev.digest} "
            f"cs5Label=signature cs5={ev.signature} "
            f"cn1Label=seq cn1={ev.seq} "
            f"cn2Label=attestationSizeBytes cn2={ev.attestation_size_bytes} "
            f"outcome={ev.status}"
        )
        body = cef_header + ext
        pri = self.facility * 8 + self.severity
        return f"<{pri}>1 {ev.timestamp} {self.hostname} {self.device_product} - - - {body}"

    @staticmethod
    def _sev_for_event(ev: AttestationEvent) -> int:
        if ev.status == "fail":
            return 8
        if ev.status == "warn":
            return 5
        return 3


def _esc(s: str) -> str:
    """Escape CEF header pipe / backslash characters."""
    return s.replace("\\", "\\\\").replace("|", "\\|")
