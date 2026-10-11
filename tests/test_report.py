"""Unit tests for the report table rendering module."""

import networkx as nx

from src.graph_engine import TopologyDiff
from src.poller import RawLSDB, SeedResult
from src.report import (
    render_diff_table,
    render_quality_table,
    render_seed_table,
    render_summary_banner,
    render_table,
    render_topology_summary_table,
    seed_role,
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


# ------------------------------------------------------------ seed health table
def _seed(host, status="SUCCEEDED", duration=2.4, lsas=15, neighbors=4, tags=("Area0", "Core")):
    return SeedResult(name=host, host=host, device_type="vyos", status=status, duration=duration,
                      lsas=lsas, neighbors=neighbors, tags=tuple(tags))


def test_seed_table_uses_rounded_borders_and_the_agreed_columns():
    out = render_seed_table([
        _seed("10.255.255.6"),
        _seed("10.255.255.10", "TIMEOUT", 10.0, 0, 0, ("Area1", "Edge")),
    ])
    lines = out.splitlines()
    assert lines[0].startswith("╭") and lines[0].endswith("╮")
    assert lines[-1].startswith("╰") and lines[-1].endswith("╯")
    for column in ("SEED ROUTER", "PLATFORM", "STATUS", "DURATION", "LSAS / NBRS", "ROLE"):
        assert column in lines[1]
    assert "✔ SUCCEEDED" in out and "✖ TIMEOUT" in out
    assert "2.4s" in out and "10.0s" in out
    assert "15 / 4 nbrs" in out and "0 / 0 nbrs" in out
    assert "Area 0 Core" in out and "Area 1 Edge" in out
    assert len({len(line) for line in lines}) == 1  # every row has the same width


def test_seed_table_shows_dashes_for_a_seed_that_was_never_tried():
    out = render_seed_table([_seed("10.0.0.9", "SKIPPED", 0.0, 0, 0)])
    assert "○ SKIPPED" in out and "0.0s" not in out and "nbrs" not in out


def test_seed_role_prettifies_area_tags():
    assert seed_role(["Area0", "Core"]) == "Area 0 Core"
    assert seed_role(["area12"]) == "Area 12"
    assert seed_role(["Transit"]) == "Transit"
    assert seed_role([]) == "-"


def _banner_graph():
    graph = nx.DiGraph()
    graph.add_edge("10.0.0.1", "10.0.0.2")
    return graph


_RAW = RawLSDB(router="", network="", source="test", collected_at="2026-10-11")


def test_banner_reports_how_many_seeds_passed():
    seeds = [_seed("a"), _seed("b"), _seed("c", "TIMEOUT")]
    banner = render_summary_banner(_RAW, _banner_graph(), TopologyDiff(), seeds)
    assert "Seeds: 2/3 Passed" in banner and "Diffs: 0" in banner and "Nodes: 2" in banner and "Links: 1" in banner
    assert "Stable Topology" not in banner


def test_banner_counts_a_skipped_fallback_seed_neither_way():
    banner = render_summary_banner(_RAW, _banner_graph(), TopologyDiff(), [_seed("a"), _seed("b", "SKIPPED")])
    assert "Seeds: 1/1 Passed" in banner


def test_banner_still_calls_out_a_suspect_run_when_seeds_are_shown():
    diff = TopologyDiff(suspect_reasons=["1 seed router(s) could not be polled"])
    assert "Suspect Run" in render_summary_banner(_RAW, _banner_graph(), diff, [_seed("a")])
