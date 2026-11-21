"""Webhook notifier supporting Generic JSON, Slack Block Kit, MS Teams, and Discord."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from src.events import TopologyEvent
from src.notifier.base import BaseNotifier
from src.notifier.telegram import SEVERITY_LEVELS

logger = logging.getLogger("ospf_tracker.notifier.webhook")


@dataclass
class WebhookConfig:
    """Configuration for a webhook alert sink."""

    name: str = "webhook"
    enabled: bool = False
    url: str = ""
    format: str = "generic"  # generic | slack | teams | discord
    min_severity: str = "warning"
    events: list[str] = field(default_factory=list)
    timeout: float = 10.0
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> WebhookConfig:
        """Build from a YAML mapping with optional env fallback."""
        data = data or {}
        url = str(data.get("url") or os.environ.get("OSPF_MONITOR_WEBHOOK_URL") or "").strip()
        fmt = str(data.get("format") or "generic").strip().lower()
        if fmt not in ("generic", "slack", "teams", "discord"):
            fmt = "generic"
        sev = str(data.get("min_severity") or "warning").strip().lower()
        if sev not in SEVERITY_LEVELS:
            sev = "warning"
        return cls(
            name=str(data.get("name") or "webhook"),
            enabled=bool(data.get("enabled", False)),
            url=url,
            format=fmt,
            min_severity=sev,
            events=[str(e) for e in (data.get("events") or ())],
            timeout=float(data.get("timeout", 10.0)),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
        )


class WebhookNotifier(BaseNotifier):
    """HTTP JSON webhook notifier using Python standard library ``urllib.request``."""

    def __init__(self, config: WebhookConfig) -> None:
        self.config = config

    def matches_events(self, events: Sequence[TopologyEvent]) -> bool:
        """True if this webhook subscribes to any of the emitted events (or has no event filter)."""
        if not self.config.events:
            return True
        if not events:
            return False
        wanted = set(self.config.events)
        return any(ev.event_type in wanted for ev in events)

    def format_payload(
        self,
        title: str,
        message: str,
        level: str = "warning",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Format an alert into Slack, Teams, Discord, or generic JSON payload."""
        sev = level.lower()
        tag = level.upper()
        fmt = self.config.format
        if fmt == "slack":
            return {
                "text": f"*{title}* [{tag}]",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{title}* (`{tag}`)\n{message}",
                        },
                    }
                ],
            }
        if fmt == "teams":
            color = (
                "E74C3C"
                if sev == "critical"
                else ("E67E22" if sev == "warning" else "2ECC71")
            )
            return {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": title,
                "themeColor": color,
                "title": f"[{tag}] {title}",
                "text": message,
            }
        if fmt == "discord":
            return {"content": f"**[{tag}] {title}**\n{message}"}
        return {
            "title": title,
            "message": message,
            "level": sev,
            "metadata": metadata or {},
        }

    def send_alert(
        self,
        title: str,
        message: str,
        level: str = "warning",
        attachment_path: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Deliver alert via HTTP POST; returns False if disabled, filtered, or failed."""
        _ = attachment_path
        if not self.config.enabled or not self.config.url:
            return False
        lvl_rank = SEVERITY_LEVELS.get(level.lower(), 1)
        min_rank = SEVERITY_LEVELS.get(self.config.min_severity.lower(), 1)
        if lvl_rank < min_rank:
            return False

        body = json.dumps(
            self.format_payload(title, message, level, metadata), default=str
        ).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8", **self.config.headers}
        req = urllib.request.Request(
            self.config.url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                return 200 <= getattr(resp, "status", 200) < 300
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning("Webhook '%s' delivery failed: %s", self.config.name, exc)
            return False
