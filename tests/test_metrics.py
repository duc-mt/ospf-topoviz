"""Unit tests for Prometheus /metrics exposition endpoint."""

from __future__ import annotations

import networkx as nx

from src.graph_engine import TopologyDiff
from src.web.server import WebApp


def test_metrics_endpoint_renders_valid_prometheus_text_format(tmp_path) -> None:
    app = WebApp(tmp_path / "data", tmp_path / "topology.html")
    g = nx.DiGraph()
    g.add_node("10.0.0.1", type="router", areas=["0.0.0.0"])
    g.add_node("10.0.0.2", type="router", areas=["0.0.0.0"])
    g.add_node("net-10.0.0.0", type="network", areas=["0.0.0.0"])
    g.add_edge("10.0.0.1", "10.0.0.2", metric=10, area="0.0.0.0")
    app.engine.save_graph(g)

    diff = TopologyDiff(
        baseline_available=True,
        added_nodes=[{"id": "10.0.0.2", "type": "router", "areas": ["0.0.0.0"]}],
        findings=[
            {
                "category": "route",
                "kind": "ROUTE_MISSING",
                "severity": "critical",
                "router": "10.0.0.1",
                "subject": "10.9.0.0/24",
                "message": "missing",
            }
        ],
    )
    app.history.record(g, diff, run_id="run-1", timestamp="2026-11-21T12:00:00+00:00")

    resp = app.handle("GET", "/metrics")
    assert resp.status == 200
    assert resp.content_type.startswith("text/plain; version=0.0.4")
    text = resp.body.decode("utf-8")
    assert "# TYPE ospf_topoviz_nodes gauge" in text
    assert 'ospf_topoviz_nodes{type="router"} 2' in text
    assert 'ospf_topoviz_nodes{type="network"} 1' in text
    assert "ospf_topoviz_links 1" in text
    assert 'ospf_topoviz_findings{severity="critical"} 1' in text
    assert 'ospf_topoviz_events_total{event_name="node",status="up"} 1' in text
    assert "ospf_topoviz_poll_running 0" in text
    assert "ospf_topoviz_last_poll_timestamp_seconds " in text
