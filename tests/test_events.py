"""Unit tests for normalized TopologyEvent generation and HistoryStore SQLite event persistence."""

from __future__ import annotations

import json
import sqlite3

import networkx as nx

from src.events import TopologyEvent, diff_to_events
from src.graph_engine import GraphEngine, HistoryConfig, HistoryStore, TopologyDiff


def _sample_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("10.0.0.1", type="router", areas=["0.0.0.0"])
    g.add_node("10.0.0.2", type="router", areas=["0.0.0.0"])
    g.add_edge("10.0.0.1", "10.0.0.2", metric=10, area="0.0.0.0", link_type="point-to-point")
    return g


def test_diff_to_events_maps_links_prefixes_flags_te_and_findings() -> None:
    diff = TopologyDiff(
        baseline_available=True,
        added_nodes=[{"id": "10.0.0.3", "type": "router", "areas": ["0.0.0.0"]}],
        removed_nodes=[{"id": "10.0.0.9", "type": "router", "areas": ["0.0.0.1"]}],
        added_edges=[
            {
                "source": "10.0.0.1",
                "target": "10.0.0.3",
                "metric": 10,
                "area": "0.0.0.0",
                "interface_address": "10.13.0.1",
            }
        ],
        removed_edges=[
            {
                "source": "10.0.0.1",
                "target": "10.0.0.9",
                "metric": 20,
                "area": "0.0.0.1",
            }
        ],
        changed_metrics=[
            {
                "source": "10.0.0.1",
                "target": "10.0.0.2",
                "old_metric": 10,
                "new_metric": 50,
                "area": "0.0.0.0",
            }
        ],
        changed_node_flags=[
            {
                "id": "10.0.0.2",
                "label": "10.0.0.2",
                "attribute": "max_metric",
                "old": False,
                "new": True,
                "areas": ["0.0.0.0"],
            }
        ],
        changed_prefixes=[
            {
                "action": "added",
                "prefix": "10.50.0.0/24",
                "router": "10.0.0.1",
                "kind": "stub",
                "subtype": None,
                "area": "0.0.0.0",
                "old_metric": None,
                "new_metric": 1,
            },
            {
                "action": "removed",
                "prefix": "192.168.1.0/24",
                "router": "10.0.0.2",
                "kind": "external",
                "subtype": "E2",
                "area": "",
                "old_metric": 20,
                "new_metric": None,
            },
        ],
        changed_te=[
            {
                "source": "10.0.0.1",
                "target": "10.0.0.2",
                "area": "0.0.0.0",
                "local_ip": "10.12.0.1",
                "remote_ip": "10.12.0.2",
                "changes": {"srlgs": {"old": [], "new": [100]}},
            }
        ],
        findings=[
            {
                "category": "route",
                "kind": "ROUTE_MISSING",
                "severity": "critical",
                "router": "10.0.0.1",
                "subject": "10.88.0.0/24",
                "message": "10.88.0.0/24 missing from RIB",
            }
        ],
    )
    prev_findings = [
        {
            "category": "neighbor",
            "kind": "ADJ_NOT_FULL",
            "severity": "warning",
            "router": "10.0.0.1",
            "subject": "10.0.0.2",
            "message": "Neighbor 10.0.0.2 stuck",
        }
    ]
    events = diff_to_events(
        diff,
        _sample_graph(),
        run_id="20261121T120000Z-aaaa1111",
        timestamp="2026-11-21T12:00:00+00:00",
        prev_findings=prev_findings,
    )
    assert all(isinstance(ev, TopologyEvent) for ev in events)
    by_type = {ev.event_type: ev for ev in events}

    assert by_type["node_added"].event_name == "node"
    assert by_type["node_removed"].object_status == "down"
    assert by_type["link_up"].event_name == "metric"
    assert by_type["link_down"].event_name == "metric"
    assert by_type["link_cost_changed"].object_status == "changed"
    assert by_type["node_flag_changed"].severity == "warning"
    assert by_type["network_up"].event_name == "network"
    assert by_type["network_up"].object_id == "10.50.0.0/24"
    assert by_type["network_down"].object_id == "192.168.1.0/24"
    assert by_type["te_changed"].event_name == "temetric"
    assert by_type["finding_raised"].severity == "critical"
    assert by_type["finding_resolved"].object_status == "resolved"
    assert len({ev.event_id for ev in events}) == len(events)


def test_history_store_migrates_existing_db_and_queries_events(tmp_path) -> None:
    db_path = tmp_path / "history.db"
    # Seed a legacy v1 history.db containing ONLY `runs` table
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE runs (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            node_count INTEGER NOT NULL,
            link_count INTEGER NOT NULL,
            added_nodes TEXT NOT NULL,
            removed_nodes TEXT NOT NULL,
            added_links TEXT NOT NULL,
            removed_links TEXT NOT NULL,
            metric_changes TEXT NOT NULL,
            is_suspect INTEGER NOT NULL,
            findings TEXT NOT NULL DEFAULT '[]',
            graph_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO runs VALUES (1, 'run-0', '2026-11-21T10:00:00+00:00', 1, 0, '[]', '[]', '[]', '[]', '[]', 0, '[]', '{}')"
    )
    conn.commit()
    conn.close()

    store = HistoryStore(db_path, max_runs=10)
    g = _sample_graph()
    diff = TopologyDiff(
        baseline_available=True,
        changed_metrics=[
            {
                "source": "10.0.0.1",
                "target": "10.0.0.2",
                "old_metric": 10,
                "new_metric": 40,
                "area": "0.0.0.0",
            }
        ],
        changed_prefixes=[
            {
                "action": "added",
                "prefix": "10.77.0.0/24",
                "router": "10.0.0.1",
                "kind": "stub",
                "subtype": None,
                "area": "0.0.0.0",
                "old_metric": None,
                "new_metric": 5,
            }
        ],
    )
    run_id = store.record(g, diff, run_id="run-1", timestamp="2026-11-21T10:15:00+00:00")
    assert run_id == "run-1"

    all_events, total = store.query_events()
    assert total == 2
    assert len(all_events) == 2

    metric_events, m_total = store.query_events(event_type="link_cost_changed")
    assert m_total == 1
    assert metric_events[0]["detected_by"] == "10.0.0.1"
    assert json.loads(json.dumps(metric_events[0]["details"]))["new_metric"] == 40

    pfx_events, p_total = store.query_events(prefix="10.77.0.0/24")
    assert p_total == 1
    assert pfx_events[0]["event_type"] == "network_up"

    q_events, q_total = store.query_events(router="10.0.0.1", q="40")
    assert q_total == 1

    hist = store.event_histogram(bucket="1h")
    assert len(hist) == 1
    assert hist[0]["total"] == 2
    assert hist[0]["up"] == 1
    assert hist[0]["changed"] == 1


def test_suspect_unaccepted_run_never_records_events(tmp_path) -> None:
    engine = GraphEngine(data_dir=tmp_path, history=HistoryConfig(enabled=True, max_runs=100))
    p1 = {
        "metadata": {},
        "nodes": [
            {"id": "10.0.0.1", "type": "router", "areas": ["0.0.0.0"], "resolved": True},
            {"id": "10.0.0.2", "type": "router", "areas": ["0.0.0.0"], "resolved": True},
            {"id": "10.0.0.3", "type": "router", "areas": ["0.0.0.0"], "resolved": True},
        ],
        "edges": [
            {"source": "10.0.0.1", "target": "10.0.0.2", "metric": 10, "area": "0.0.0.0", "link_type": "point-to-point"},
            {"source": "10.0.0.2", "target": "10.0.0.3", "metric": 10, "area": "0.0.0.0", "link_type": "point-to-point"},
        ],
    }
    engine.process(p1)

    # Partial LSDB losing > 50% of nodes triggers guard rejection
    p_suspect = {
        "metadata": {},
        "nodes": [
            {"id": "10.0.0.1", "type": "router", "areas": ["0.0.0.0"], "resolved": True},
        ],
        "edges": [],
    }
    _, diff = engine.process(p_suspect)
    assert diff.baseline_updated is False
    assert engine.last_events == []
    events, total = engine.history.query_events()
    assert total == 0
    assert events == []
