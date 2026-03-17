"""Azure Monitor / Microsoft Sentinel exporter (Logs Ingestion API).

Ships events to a Data Collection Endpoint (DCE) that forwards to a
Data Collection Rule (DCR) writing into a Custom Log Analytics table.
The DCE/DCR pair is the modern replacement for the deprecated HTTP
Data Collector API; it works with Sentinel out of the box.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Callable, Dict, List, Optional

from tee_crafter.core.audit.continuous import AttestationEvent, AuditEventExporter

HttpClient = Callable[[str, str, Dict[str, str], List[Dict]], Dict]


class AzureMonitorExporter(AuditEventExporter):
    def __init__(
        self,
        *,
        dce_url: str,
        dcr_immutable_id: str,
        stream_name: str,
        bearer_token_provider: Callable[[], str],
        http: Optional[HttpClient] = None,
        timeout: int = 10,
    ):
        if not dce_url.startswith("https://"):
            raise ValueError("dce_url must be https://")
        if not dcr_immutable_id:
            raise ValueError("dcr_immutable_id required")
        if not stream_name.startswith("Custom-"):
            raise ValueError("stream_name must start with 'Custom-'")
        self.dce_url = dce_url.rstrip("/")
        self.dcr_immutable_id = dcr_immutable_id
        self.stream_name = stream_name
        self._bearer = bearer_token_provider
        self._http = http
        self._timeout = timeout

    def _default_http(self) -> HttpClient:
        try:
            import requests  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("requests is required for AzureMonitorExporter") from exc

        def _post(method, url, headers, body):
            r = requests.request(method, url, headers=headers,
                                  data=json.dumps(body), timeout=self._timeout)
            r.raise_for_status()
            return {}
        return _post

    def emit(self, event: AttestationEvent) -> None:
        url = (f"{self.dce_url}/dataCollectionRules/{self.dcr_immutable_id}/"
               f"streams/{self.stream_name}?api-version=2023-01-01")
        headers = {
            "Authorization": f"Bearer {self._bearer()}",
            "Content-Type": "application/json",
        }
        body = [asdict(event)]
        http = self._http or self._default_http()
        http("POST", url, headers, body)
