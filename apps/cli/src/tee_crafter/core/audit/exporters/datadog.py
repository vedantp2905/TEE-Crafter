"""Datadog Logs API exporter."""
from __future__ import annotations

import json
from typing import Callable, Dict, Optional

from tee_crafter.core.audit.continuous import AttestationEvent, AuditEventExporter

HttpClient = Callable[[str, str, Dict[str, str], Dict], Dict]


class DatadogLogsExporter(AuditEventExporter):
    def __init__(
        self,
        *,
        api_key: str,
        site: str = "datadoghq.com",
        service: str = "tee-crafter",
        ddsource: str = "tee-crafter",
        env: str = "prod",
        http: Optional[HttpClient] = None,
        timeout: int = 10,
    ):
        if not api_key:
            raise ValueError("Datadog api_key required")
        self.api_key = api_key
        self.site = site
        self.service = service
        self.ddsource = ddsource
        self.env = env
        self._http = http
        self._timeout = timeout

    def _default_http(self) -> HttpClient:
        try:
            import requests  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("requests is required for DatadogLogsExporter") from exc

        def _post(method, url, headers, body):
            r = requests.request(method, url, headers=headers,
                                  data=json.dumps(body), timeout=self._timeout)
            r.raise_for_status()
            return {}
        return _post

    def emit(self, event: AttestationEvent) -> None:
        body = {
            "ddsource": self.ddsource,
            "service": self.service,
            "ddtags": (
                f"env:{self.env},tee_platform:{event.tee_platform},"
                f"status:{event.status},event_type:{event.event_type}"
            ),
            "hostname": event.instance_id,
            "message": event.to_json(),
            "level": "error" if event.status == "fail" else "info",
        }
        headers = {
            "DD-API-KEY": self.api_key,
            "Content-Type": "application/json",
        }
        url = f"https://http-intake.logs.{self.site}/api/v2/logs"
        http = self._http or self._default_http()
        http("POST", url, headers, body)
