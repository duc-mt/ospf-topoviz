"""Unit tests for the report table rendering module."""

import networkx as nx

from src.graph_engine import TopologyDiff
from src.poller import RawLSDB
from src.report import (
    render_diff_table,
    render_quality_table,
    render_summary_banner,
    render_table,
    render_topology_summary_table,
)


def test_render_table_basic():
    headers = ["COL1", "COL2"]
    rows = [["val1", "val2"], ["longer_val", "10"]]
    out = render_table(headers, rows, alignments=["left", "right"])
    assert "COL1" in out
    assert "COL2" in out
    assert "val1" in out
    assert "10" in out
    assert "╭" in out and "╯" in out


def test_render_topology_summary_table_first_run():
    graph = nx.DiGraph()
    graph.add_node("10.0.0.1", type="router")
    graph.add_node("net-192.168.1.0/24", type="network")
    graph.add_edge("10.0.0.1", "net-192.168.1.0/24")

    diff = TopologyDiff(baseline_available=False)
    out = render_topology_summary_table(graph, diff)
    assert "Router Nodes" in out
    assert "Transit Networks" in out
    assert "INITIALIZED" in out


def test_render_topology_summary_table_with_diff():
    graph = nx.DiGraph()
    graph.add_node("10.0.0.1", type="router")
    graph.add_edge("10.0.0.1", "10.0.0.2")

    diff = TopologyDiff(
        baseline_available=True,
        added_nodes=[{"label": "10.0.0.1", "type": "router"}],
        removed_nodes=[],
        added_edges=[{"source_label": "10.0.0.1", "target_label": "10.0.0.2", "metric": 10, "link_type": "point-to-point"}],
        removed_edges=[],
        changed_metrics=[],
    )
    out = render_topology_summary_table(graph, diff)
    assert "Router Nodes" in out
    assert "EXPANDED" in out


def test_render_diff_table():
    diff = TopologyDiff(
        baseline_available=True,
        added_nodes=[{"label": "10.0.0.1", "type": "router"}],
        removed_nodes=[{"label": "10.0.0.2", "type": "router"}],
        added_edges=[{"source_label": "10.0.0.1", "target_label": "10.0.0.3", "metric": 10, "link_type": "point-to-point"}],
        removed_edges=[],
        changed_metrics=[{"source_label": "10.0.0.4", "target_label": "10.0.0.5", "old_metric": 10, "new_metric": 20}],
    )
    out = render_diff_table(diff)
    assert out is not None
    assert "✚ ADD NODE" in out
    assert "✖ REM NODE" in out
    assert "➜ METRIC" in out


def test_render_quality_table():
    graph = nx.DiGraph()
    graph.graph["adjacency_issues"] = [
        {"source": "R1", "neighbor": "R2", "interface": "eth0", "state": "Init", "in_lsdb": True}
    ]
    graph.graph["stale_nodes"] = ["R3"]
    graph.add_node("R3", lsa_age=3600)

    out = render_quality_table(graph)
    assert out is not None
    assert "ADJACENCY" in out
    assert "STALE LSA" in out


def test_render_summary_banner():
    graph = nx.DiGraph()
    graph.add_node("10.0.0.1")
    graph.add_edge("10.0.0.1", "10.0.0.2")
    raw = RawLSDB(router="", network="", source="test", collected_at="2026-10-11")
    diff = TopologyDiff(suspect_reasons=[])

    banner = render_summary_banner(raw, graph, diff)
    assert "Stable Topology" in banner
    assert "Nodes: 2" in banner
    assert "Links: 1" in banner
