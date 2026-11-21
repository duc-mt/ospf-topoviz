"""Unit tests for Grafana Loki, Zabbix Trapper, and JSONL EventLog exporters."""

from __future__ import annotations

import json
import socketserver
import struct
import threading
from unittest.mock import MagicMock, patch

from src.events import TopologyEvent
from src.notifier.event_log import EventLogConfig, EventLogExporter
from src.notifier.loki import LokiConfig, LokiExporter
from src.notifier.zabbix import ZabbixConfig, ZabbixExporter


def _sample_events() -> list[TopologyEvent]:
    return [
        TopologyEvent(
            event_id="run-1:1",
            run_id="run-1",
            timestamp="2026-11-21T12:00:00+00:00",
            event_type="link_down",
            event_name="metric",
            object_status="down",
            severity="warning",
            object_id="10.0.0.2",
            detected_by="10.0.0.1",
            area="0.0.0.0",
            summary="Link down: 10.0.0.1 -> 10.0.0.2",
            details={"old_metric": 10},
        ),
        TopologyEvent(
            event_id="run-1:2",
            run_id="run-1",
            timestamp="2026-11-21T12:00:00+00:00",
            event_type="network_up",
            event_name="network",
            object_status="up",
            severity="info",
            object_id="10.99.0.0/24",
            detected_by="10.0.0.1",
            area="0.0.0.0",
            summary="Prefix advertised: 10.99.0.0/24",
            details={},
        ),
    ]


def test_loki_exporter_posts_valid_streams_json_with_ospfwatcher_labels() -> None:
    cfg = LokiConfig(
        enabled=True,
        url="http://loki.local:3100/loki/api/v1/push",
        job="ospf-topoviz",
        asn="65001",
        watcher_name="lab-watcher",
        tenant_id="tenant-1",
    )
    exporter = LokiExporter(cfg)
    mock_resp = MagicMock()
    mock_resp.status = 204
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        ok = exporter.export_events(_sample_events())
        assert ok is True
        req = mock_open.call_args[0][0]
        assert req.get_header("X-scope-orgid") == "tenant-1"
        body = json.loads(req.data.decode("utf-8"))
        assert "streams" in body and len(body["streams"]) == 2
        labels = body["streams"][0]["stream"]
        assert labels["job"] == "ospf-topoviz"
        assert labels["event_name"] == "metric"
        assert labels["event_status"] == "down"
        assert labels["area_num"] == "0.0.0.0"
        assert labels["asn"] == "65001"
        assert labels["watcher_name"] == "lab-watcher"
        ns_ts, msg = body["streams"][0]["values"][0]
        assert ns_ts.isdigit()
        assert json.loads(msg)["event_id"] == "run-1:1"


def test_zabbix_trapper_encodes_zbxd_header_and_parses_response() -> None:
    received: list[dict] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            hdr = self.request.recv(13)
            assert hdr[:5] == b"ZBXD\x01"
            (length,) = struct.unpack("<Q", hdr[5:13])
            data = b""
            while len(data) < length:
                chunk = self.request.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            received.append(json.loads(data.decode("utf-8")))
            resp = b'{"response":"success","info":"processed: 2; failed: 0; total: 2"}'
            self.request.sendall(b"ZBXD\x01" + struct.pack("<Q", len(resp)) + resp)

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.handle_request, daemon=True)
        t.start()
        cfg = ZabbixConfig(enabled=True, server="127.0.0.1", port=port, host="ospf-core")
        assert ZabbixExporter(cfg).export_events(_sample_events()) is True
        t.join(timeout=2)

    assert len(received) == 1
    assert received[0]["request"] == "sender data"
    keys = [item["key"] for item in received[0]["data"]]
    assert keys == ["ospf_neighbor_up_down", "ospf_network_up_down"]


def test_event_log_exporter_appends_jsonl_without_crashing(tmp_path) -> None:
    log_path = tmp_path / "nested" / "events.jsonl"
    exp = EventLogExporter(EventLogConfig(enabled=True, path=log_path))
    written = exp.export_events(_sample_events())
    assert written == 2
    lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert lines[0]["event_type"] == "link_down"
    assert lines[1]["event_type"] == "network_up"
