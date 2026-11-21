"""Multi-sink alert & event dispatcher coordinating Telegram, webhooks, Loki, Zabbix, and JSONL logs."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from src.events import TopologyEvent
from src.notifier.base import BaseNotifier
from src.notifier.event_log import EventLogConfig, EventLogExporter
from src.notifier.loki import LokiConfig, LokiExporter
from src.notifier.telegram import TelegramConfig, TelegramNotifier
from src.notifier.webhook import WebhookConfig, WebhookNotifier
from src.notifier.zabbix import ZabbixConfig, ZabbixExporter

logger = logging.getLogger("ospf_tracker.notifier.dispatcher")


@dataclass
class NotifierDispatcher:
    """Dispatch alerts and normalized events across all configured sinks with fault isolation."""

    telegram: TelegramNotifier | None = None
    webhooks: list[WebhookNotifier] = field(default_factory=list)
    loki: LokiExporter | None = None
    zabbix: ZabbixExporter | None = None
    event_log: EventLogExporter | None = None

    @classmethod
    def from_settings(
        cls,
        settings: dict[str, Any] | None,
        telegram: TelegramNotifier | None = None,
    ) -> NotifierDispatcher:
        """Build all configured notifiers and exporters from ``settings["alerting"]``."""
        settings = settings or {}
        alerting = settings.get("alerting") or {}
        if not isinstance(alerting, dict):
            alerting = {}

        if telegram is None:
            tg_dict = dict(alerting.get("telegram") or {}) if isinstance(alerting.get("telegram"), dict) else {}
            for key in ("enabled", "min_severity", "cooldown_seconds"):
                if key in alerting and key not in tg_dict:
                    tg_dict[key] = alerting[key]
            telegram = TelegramNotifier(TelegramConfig.from_dict(tg_dict))

        webhooks: list[WebhookNotifier] = []
        raw_wh = alerting.get("webhooks") or ()
        if isinstance(raw_wh, list):
            for entry in raw_wh:
                if isinstance(entry, dict):
                    webhooks.append(WebhookNotifier(WebhookConfig.from_dict(entry)))

        loki = (
            LokiExporter(LokiConfig.from_dict(alerting.get("loki")))
            if isinstance(alerting.get("loki"), dict)
            else None
        )
        zabbix = (
            ZabbixExporter(ZabbixConfig.from_dict(alerting.get("zabbix")))
            if isinstance(alerting.get("zabbix"), dict)
            else None
        )
        event_log = (
            EventLogExporter(EventLogConfig.from_dict(alerting.get("event_log")))
            if isinstance(alerting.get("event_log"), dict)
            else None
        )
        return cls(
            telegram=telegram,
            webhooks=webhooks,
            loki=loki,
            zabbix=zabbix,
            event_log=event_log,
        )

    def has_alert_sinks(self) -> bool:
        """True if Telegram or at least one webhook is enabled."""
        tg_on = bool(self.telegram and self.telegram.config.enabled)
        return tg_on or any(w.config.enabled for w in self.webhooks)

    def dispatch_alert(
        self,
        title: str,
        message: str,
        level: str = "warning",
        attachment_path: str | None = None,
        metadata: dict[str, Any] | None = None,
        events: Sequence[TopologyEvent] = (),
    ) -> None:
        """Send an alert to enabled Telegram and matching Webhook notifiers without raising."""
        sinks: list[BaseNotifier] = []
        if self.telegram is not None and self.telegram.config.enabled:
            sinks.append(self.telegram)
        for wh in self.webhooks:
            if wh.config.enabled and wh.matches_events(events):
                sinks.append(wh)

        for sink in sinks:
            try:
                sink.send_alert(
                    title=title,
                    message=message,
                    level=level,
                    attachment_path=attachment_path,
                    metadata=metadata,
                )
            except Exception as exc:  # noqa: BLE001 - sink failure must never abort sibling sinks
                logger.warning("Notification sink %s failed: %s", type(sink).__name__, exc)

    def export_events(self, events: Sequence[TopologyEvent]) -> None:
        """Push accepted ``TopologyEvent`` items to Loki, Zabbix Trapper, and JSONL logs."""
        if not events:
            return
        for name, exporter in (
            ("loki", self.loki),
            ("zabbix", self.zabbix),
            ("event_log", self.event_log),
        ):
            if exporter is None or not exporter.config.enabled:
                continue
            try:
                exporter.export_events(events)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Exporter %s failed: %s", name, exc)
