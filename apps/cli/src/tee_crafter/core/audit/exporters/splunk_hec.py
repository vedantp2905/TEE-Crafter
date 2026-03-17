"""Splunk HTTP Event Collector exporter."""
from __future__ import annotations

import datetime as _dt
import json
import logging
import time as _time
from dataclasses import asdict
from typing import Callable, Dict, Optional

from tee_crafter.core.audit.continuous import AttestationEvent, AuditEventExporter

logger = logging.getLogger("tee_crafter.audit.exporters.splunk_hec")


def _iso_to_epoch(iso_ts: str) -> float:
    """Convert ``AttestationEvent.timestamp`` (ISO-8601 UTC, suffix Z) to a
    UNIX epoch float.  Splunk HEC rejects ISO-string ``time`` values with
    HTTP 400 ``Error in handling indexed fields`` (code 15) — only numeric
    epoch seconds are accepted.  This wire-format quirk is documented at
    https://docs.splunk.com/Documentation/Splunk/latest/Data/HECExamples.

    Falls back to ``time.time()`` if parsing fails so a malformed timestamp
    never breaks the entire export pipeline.
    """
    if not iso_ts:
        return _time.time()
    try:
        normalised = iso_ts[:-1] + "+00:00" if iso_ts.endswith("Z") else iso_ts
        return _dt.datetime.fromisoformat(normalised).timestamp()
    except (TypeError, ValueError):
        return _time.time()

HttpClient = Callable[[str, str, Dict[str, str], Dict], Dict]


class SplunkHecExporter(AuditEventExporter):
    def __init__(
        self,
        *,
        endpoint: str,
        token: str,
        index: str = "main",
        sourcetype: str = "tee_crafter:attestation",
        source: str = "tee-crafter",
        http: Optional[HttpClient] = None,
        verify_ssl: bool = True,
        timeout: int = 10,
    ):
        if not endpoint.startswith(("http://", "https://")):
            raise ValueError("Splunk HEC endpoint must be http(s)://")
        if not token:
            raise ValueError("Splunk HEC token required")
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.index = index
        self.sourcetype = sourcetype
        self.source = source
        self._http = http
        self._verify = verify_ssl
        self._timeout = timeout

    def _default_http(self) -> HttpClient:
        try:
            import requests  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("requests is required for SplunkHecExporter") from exc

        def _post(method, url, headers, body):
            r = requests.request(method, url, headers=headers,
                                  data=json.dumps(body),
                                  timeout=self._timeout, verify=self._verify)
            r.raise_for_status()
            return r.json() if r.content else {}
        return _post

    def emit(self, event: AttestationEvent) -> None:
        body = {
            "time": _iso_to_epoch(event.timestamp),
            "host": event.instance_id,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": asdict(event),
        }
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        }
        url = f"{self.endpoint}/services/collector/event"
        http = self._http or self._default_http()
        http("POST", url, headers, body)
