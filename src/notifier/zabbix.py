"""Direct Zabbix Trapper TCP binary protocol (ZBXD\\x01) exporter using Python stdlib."""

from __future__ import annotations

import json
import logging
import socket
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from src.events import TopologyEvent

logger = logging.getLogger("ospf_tracker.notifier.zabbix")

_ZABBIX_KEY_MAP = {
    "link_up": "ospf_neighbor_up_down",
    "link_down": "ospf_neighbor_up_down",
    "node_added": "ospf_neighbor_up_down",
    "node_removed": "ospf_neighbor_up_down",
    "link_cost_changed": "ospf_link_cost_change",
    "network_up": "ospf_network_up_down",
    "network_down": "ospf_network_up_down",
    "network_cost_changed": "ospf_network_up_down",
    "node_flag_changed": "ospf_node_flag_change",
    "te_changed": "ospf_te_change",
    "finding_raised": "ospf_finding",
    "finding_resolved": "ospf_finding",
}


@dataclass
class ZabbixConfig:
    """Configuration for pushing events to a Zabbix Trapper receiver."""

    enabled: bool = False
    server: str = "127.0.0.1"
    port: int = 10051
    host: str = "ospf-topoviz"
    timeout: float = 10.0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ZabbixConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            server=str(data.get("server") or "127.0.0.1"),
            port=int(data.get("port", 10051)),
            host=str(data.get("host") or "ospf-topoviz"),
            timeout=float(data.get("timeout", 10.0)),
        )


class ZabbixExporter:
    """Send OSPF events directly via Zabbix Trapper TCP protocol (``ZBXD\\x01``)."""

    def __init__(self, config: ZabbixConfig) -> None:
        self.config = config

    @staticmethod
    def zabbix_key(event_type: str) -> str:
        """Map normalized event_type to an ospfwatcher-compatible Zabbix item key."""
        return _ZABBIX_KEY_MAP.get(event_type, "ospf_event")

    def export_events(self, events: Sequence[TopologyEvent]) -> bool:
        """Send events to the Zabbix server; returns True if acknowledged as success."""
        if not self.config.enabled or not self.config.server or not events:
            return False
        data_items = [
            {
                "host": self.config.host,
                "key": self.zabbix_key(ev.event_type),
                "value": json.dumps(ev.to_dict(), ensure_ascii=False, default=str),
            }
            for ev in events
        ]
        payload = json.dumps(
            {"request": "sender data", "data": data_items},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        packet = b"ZBXD\x01" + struct.pack("<Q", len(payload)) + payload
        try:
            with socket.create_connection(
                (self.config.server, self.config.port), timeout=self.config.timeout
            ) as sock:
                sock.sendall(packet)
                hdr = self._recv_exact(sock, 13)
                if len(hdr) < 13 or hdr[:5] != b"ZBXD\x01":
                    return False
                (resp_len,) = struct.unpack("<Q", hdr[5:13])
                body = self._recv_exact(sock, min(resp_len, 1024 * 1024))
                parsed = json.loads(body.decode("utf-8"))
                return parsed.get("response") == "success"
        except (OSError, TimeoutError, ValueError) as exc:
            logger.warning(
                "Zabbix Trapper push to %s:%s failed: %s",
                self.config.server,
                self.config.port,
                exc,
            )
            return False

    @staticmethod
    def _recv_exact(sock: socket.socket, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            part = sock.recv(count - len(chunks))
            if not part:
                break
            chunks.extend(part)
        return bytes(chunks)
