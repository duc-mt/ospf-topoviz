"""Unit tests for node-flag transition diffing and granular prefix/external diffing."""

from __future__ import annotations

import networkx as nx

from src.explorer import build_scene
from src.graph_engine import GraphEngine, TopologyDiff, filter_diff_by_area
from src.report import render_diff_table, render_topology_summary_table


def _base_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(
        "10.0.0.1",
        type="router",
        areas=["0.0.0.0"],
        abr=False,
        asbr=False,
        max_metric=False,
        prefixes=[{"prefix": "10.1.0.0/24", "metric": 10, "area": "0.0.0.0"}],
        externals=[],
    )
    g.add_node(
        "10.0.0.2",
        type="router",
        areas=["0.0.0.0", "0.0.0.1"],
        abr=True,
        asbr=False,
        max_metric=False,
        prefixes=[{"prefix": "10.2.0.0/24", "metric": 5, "area": "0.0.0.1"}],
        externals=[
            {
                "prefix": "192.168.50.0/24",
                "metric": 20,
                "metric_type": "E2",
                "area": "",
            }
        ],
    )
    g.add_node(
        "net-10.12.0.1",
        type="network",
        resolved=True,
        areas=["0.0.0.0"],
        address="10.12.0.1",
        dr="10.0.0.1",
        mask="255.255.255.0",
        prefix="10.12.0.0/24",
    )
    g.add_edge("10.0.0.1", "net-10.12.0.1", metric=10, area="0.0.0.0", link_type="transit")
    g.add_edge("net-10.12.0.1", "10.0.0.1", metric=0, area="0.0.0.0", link_type="attachment")
    return g


def test_first_run_no_baseline_emits_zero_flag_or_prefix_diffs(tmp_path) -> None:
    engine = GraphEngine(data_dir=tmp_path)
    diff = engine.compare(None, _base_graph())
    assert diff.baseline_available is False
    assert diff.changed_node_flags == []
    assert diff.changed_prefixes == []
    assert diff.changed_te == []
    assert diff.has_changes is False


def test_node_flag_transition_detected(tmp_path) -> None:
    engine = GraphEngine(data_dir=tmp_path)
    old = _base_graph()
    new = _base_graph()
    new.nodes["10.0.0.1"]["abr"] = True
    new.nodes["10.0.0.1"]["max_metric"] = True
    new.nodes["10.0.0.2"]["abr"] = False
    new.nodes["10.0.0.2"]["is_asbr"] = True

    diff = engine.compare(old, new)
    assert diff.has_changes is True
    by_key = {(c["id"], c["attribute"]): c for c in diff.changed_node_flags}
    assert by_key[("10.0.0.1", "abr")]["old"] is False
    assert by_key[("10.0.0.1", "abr")]["new"] is True
    assert by_key[("10.0.0.1", "max_metric")]["new"] is True
    assert by_key[("10.0.0.2", "abr")]["old"] is True
    assert by_key[("10.0.0.2", "abr")]["new"] is False
    assert by_key[("10.0.0.2", "asbr")]["old"] is False
    assert by_key[("10.0.0.2", "asbr")]["new"] is True

    table = render_diff_table(diff)
    assert table is not None and "FLAG" in table


def test_stub_transit_and_external_prefix_diffs(tmp_path) -> None:
    engine = GraphEngine(data_dir=tmp_path)
    old = _base_graph()
    new = _base_graph()

    # Stub prefix: cost changed + new stub prefix added
    new.nodes["10.0.0.1"]["prefixes"] = [
        {"prefix": "10.1.0.0/24", "metric": 25, "area": "0.0.0.0"},
        {"prefix": "10.1.99.0/24", "metric": 1, "area": "0.0.0.0"},
    ]
    # Transit network prefix added/withdrawn
    new.nodes["net-10.12.0.1"]["prefix"] = "10.12.1.0/24"
    # External & NSSA prefix: old external removed, NSSA added
    new.nodes["10.0.0.2"]["externals"] = [
        {
            "prefix": "172.16.10.0/24",
            "metric": 50,
            "metric_type": "N1",
            "area": "0.0.0.1",
        }
    ]

    diff = engine.compare(old, new)
    assert diff.has_changes is True
    by_key = {
        (c["action"], c["kind"], c["prefix"]): c for c in diff.changed_prefixes
    }
    assert ("changed", "stub", "10.1.0.0/24") in by_key
    assert by_key[("changed", "stub", "10.1.0.0/24")]["old_metric"] == 10
    assert by_key[("changed", "stub", "10.1.0.0/24")]["new_metric"] == 25
    assert ("added", "stub", "10.1.99.0/24") in by_key
    assert ("removed", "transit", "10.12.0.0/24") in by_key
    assert ("added", "transit", "10.12.1.0/24") in by_key
    assert ("removed", "external", "192.168.50.0/24") in by_key
    assert ("added", "nssa", "172.16.10.0/24") in by_key

    summary = render_topology_summary_table(new, diff)
    assert "Prefix" in summary or "Node Flags" in summary
    table = render_diff_table(diff)
    assert table is not None and "PREFIX" in table

    scene = build_scene(new, diff)
    assert scene["diagnostics"]["changes"]["prefixChanges"] == len(diff.changed_prefixes)


def test_filter_diff_by_area_scopes_flags_and_prefixes() -> None:
    view = nx.DiGraph()
    view.add_node("10.0.0.1", type="router", areas=["0.0.0.0"])
    diff = TopologyDiff(
        baseline_available=True,
        changed_node_flags=[
            {"id": "10.0.0.1", "attribute": "max_metric", "old": False, "new": True, "areas": ["0.0.0.0"]},
            {"id": "10.0.0.3", "attribute": "abr", "old": False, "new": True, "areas": ["0.0.0.1"]},
        ],
        changed_prefixes=[
            {"action": "added", "prefix": "10.1.0.0/24", "router": "10.0.0.1", "kind": "stub", "area": "0.0.0.0"},
            {"action": "added", "prefix": "10.2.0.0/24", "router": "10.0.0.2", "kind": "stub", "area": "0.0.0.1"},
        ],
    )
    scoped = filter_diff_by_area(diff, "0.0.0.0", view)
    assert len(scoped.changed_node_flags) == 1
    assert scoped.changed_node_flags[0]["id"] == "10.0.0.1"
    assert len(scoped.changed_prefixes) == 1
    assert scoped.changed_prefixes[0]["prefix"] == "10.1.0.0/24"
