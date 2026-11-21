"""Direct Grafana Loki push exporter using stdlib urllib.request (zero Fluent Bit/Logstash)."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from src.events import TopologyEvent

logger = logging.getLogger("ospf_tracker.notifier.loki")


@dataclass
class LokiConfig:
    """Configuration for pushing events to Grafana Loki ``/loki/api/v1/push``."""

    enabled: bool = False
    url: str = ""
    job: str = "ospf-topoviz"
    asn: str = "0"
    watcher_name: str = "ospf-topoviz"
    tenant_id: str = ""
    timeout: float = 10.0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> LokiConfig:
        data = data or {}
        url = str(data.get("url") or os.environ.get("OSPF_MONITOR_LOKI_URL") or "").strip()
        return cls(
            enabled=bool(data.get("enabled", False)),
            url=url,
            job=str(data.get("job") or "ospf-topoviz"),
            asn=str(data.get("asn") or "0"),
            watcher_name=str(data.get("watcher_name") or "ospf-topoviz"),
            tenant_id=str(data.get("tenant_id") or ""),
            timeout=float(data.get("timeout", 10.0)),
        )


class LokiExporter:
    """Push normalized OSPF topology events directly into Grafana Loki."""

    def __init__(self, config: LokiConfig) -> None:
        self.config = config

    @staticmethod
    def _ns_timestamp(iso_ts: str) -> str:
        try:
            dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(UTC)
        return str(int(dt.timestamp() * 1_000_000_000))

    def build_payload(self, events: Sequence[TopologyEvent]) -> dict[str, Any]:
        """Build Loki HTTP push JSON ``{"streams": [...]}`` compatible with ospfwatcher dashboards."""
        grouped: dict[tuple[tuple[str, str], ...], list[list[str]]] = {}
        for ev in events:
            stream_labels = {
                "job": self.config.job,
                "event_name": ev.event_name,
                "event_status": ev.object_status,
                "area_num": ev.area or "0.0.0.0",
                "asn": str(self.config.asn),
                "watcher_name": self.config.watcher_name,
                "severity": ev.severity,
            }
            key = tuple(sorted(stream_labels.items()))
            line = json.dumps(ev.to_dict(), ensure_ascii=False, default=str)
            grouped.setdefault(key, []).append([self._ns_timestamp(ev.timestamp), line])
        return {
            "streams": [
                {"stream": dict(labels), "values": vals}
                for labels, vals in grouped.items()
            ]
        }

    def export_events(self, events: Sequence[TopologyEvent]) -> bool:
        """Push events to Loki; returns True if delivered cleanly."""
        if not self.config.enabled or not self.config.url or not events:
            return False
        payload = self.build_payload(events)
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if self.config.tenant_id:
            headers["X-Scope-OrgID"] = self.config.tenant_id
        req = urllib.request.Request(
            self.config.url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                return 200 <= getattr(resp, "status", 200) < 300
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning("Grafana Loki push failed: %s", exc)
            return False
