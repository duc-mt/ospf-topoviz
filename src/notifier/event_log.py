"""JSON Lines (events.jsonl) file exporter for normalized OSPF topology events."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.events import TopologyEvent

logger = logging.getLogger("ospf_tracker.notifier.event_log")


@dataclass
class EventLogConfig:
    """Configuration for appending events to a JSONL log file."""

    enabled: bool = False
    path: Path = Path("data/events.jsonl")

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> EventLogConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            path=Path(data.get("path") or "data/events.jsonl"),
        )


class EventLogExporter:
    """Append normalized ``TopologyEvent`` entries as JSON lines."""

    def __init__(self, config: EventLogConfig) -> None:
        self.config = config

    def export_events(self, events: Sequence[TopologyEvent]) -> int:
        """Append events to ``self.config.path`` and return the number of lines written."""
        if not self.config.enabled or not events:
            return 0
        try:
            self.config.path.parent.mkdir(parents=True, exist_ok=True)
            with self.config.path.open("a", encoding="utf-8") as fh:
                for ev in events:
                    fh.write(json.dumps(ev.to_dict(), ensure_ascii=False, default=str) + "\n")
            return len(events)
        except OSError as exc:
            logger.warning("Could not write events to %s: %s", self.config.path, exc)
            return 0
