"""AWS CloudWatch Logs exporter."""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import Optional

from tee_crafter.core.audit.continuous import AttestationEvent, AuditEventExporter


class CloudWatchLogsExporter(AuditEventExporter):
    def __init__(
        self,
        *,
        log_group: str,
        log_stream: str,
        client=None,
        region: str = "",   # empty => let boto3 resolve (env, then IMDS on EC2)
        ensure_resources: bool = True,
    ):
        if not log_group or not log_stream:
            raise ValueError("log_group and log_stream required")
        self.log_group = log_group
        self.log_stream = log_stream
        self._client = client
        self._region = (region or "").strip()
        self._sequence_token: Optional[str] = None
        self._ensured = not ensure_resources

    def _logs(self):
        if self._client is not None:
            return self._client
        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("boto3 is required for CloudWatchLogsExporter") from exc
        self._client = (
            boto3.client("logs", region_name=self._region) if self._region
            else boto3.client("logs"))
        return self._client

    def _ensure(self) -> None:
        if self._ensured:
            return
        c = self._logs()
        try:
            c.create_log_group(logGroupName=self.log_group)
        except Exception:
            pass
        try:
            c.create_log_stream(logGroupName=self.log_group,
                                  logStreamName=self.log_stream)
        except Exception:
            pass
        self._ensured = True

    def emit(self, event: AttestationEvent) -> None:
        self._ensure()
        c = self._logs()
        body = {
            "logGroupName": self.log_group,
            "logStreamName": self.log_stream,
            "logEvents": [{
                "timestamp": int(time.time() * 1000),
                "message": json.dumps(asdict(event), separators=(",", ":")),
            }],
        }
        if self._sequence_token:
            body["sequenceToken"] = self._sequence_token
        resp = c.put_log_events(**body)
        self._sequence_token = resp.get("nextSequenceToken", self._sequence_token)
