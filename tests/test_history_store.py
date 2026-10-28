"""
==============================================================================
Module Name:   test_history_store.py
Description:   The topology history (time travel): what gets recorded, when, and how it is queried.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-27
Version:       1.0.0
License:       MIT
==============================================================================
"""

from __future__ import annotations

import json
import sqlite3
import threading
from copy import deepcopy

import pytest

from src import atomic_write_text
from src.graph_engine import (
    GraphEngine,
    GraphEngineError,
    HistoryConfig,
    HistoryStore,
    TopologyDiff,
    graph_from_payload,
    graph_to_payload,
)
from tests.test_graph_engine import topology, without


def engine_in(tmp_path, **kw) -> GraphEngine:
    return GraphEngine(tmp_path, **kw)


def test_nothing_is_created_until_the_first_run_is_recorded(tmp_path):
    engine = engine_in(tmp_path)
    assert engine.history is not None
    assert not (tmp_path / "history").exists()
    store = HistoryStore(tmp_path / "nowhere" / "history.db")
    assert (
        store.list_runs(),
        store.count(),
        store.get_run("x"),
        store.get_graph("x"),
    ) == ([], 0, None, None)
    assert not (
        tmp_path / "nowhere"
    ).exists()  # reading a store that is not there creates nothing


def test_an_accepted_run_is_recorded_with_counts_graph_and_findings(tmp_path):
    engine = engine_in(tmp_path)
    graph, _ = engine.process(topology())
    (run,) = engine.history.list_runs()
    assert engine.last_run_id == run["run_id"]
    assert (run["node_count"], run["link_count"]) == (
        graph.number_of_nodes(),
        graph.number_of_edges(),
    )
    assert run["is_suspect"] is False and run["finding_counts"] == {}
    # The first run has no baseline to diff against, so it lists no changes; its graph holds everything.
    assert (
        run["added_nodes"],
        run["removed_nodes"],
        run["added_links"],
        run["removed_links"],
    ) == ([], [], [], [])

    record = engine.history.get_run(run["run_id"])
    assert json.loads(record["graph_json"]) == json.loads(
        engine.current_path.read_text(encoding="utf-8")
    )
    assert record["findings"] == []


def test_the_stored_state_loads_back_into_an_identical_graph(tmp_path):
    engine = engine_in(tmp_path)
    graph, _ = engine.process(topology())
    restored = engine.history.get_graph(engine.last_run_id)
    assert graph_to_payload(restored) == graph_to_payload(graph)
    assert (
        graph_from_payload(graph_to_payload(graph)).number_of_edges()
        == graph.number_of_edges()
    )


def test_a_change_between_runs_is_written_as_nodes_links_and_costs(tmp_path):
    engine = engine_in(tmp_path)
    engine.process(topology())
    changed = topology(extra_routers=1)
    for edge in changed["edges"]:
        if (edge["source"], edge["target"]) == ("10.0.0.1", "10.0.0.2"):
            edge["metric"] = 77
    engine.process(changed)
    newest, first = engine.history.list_runs()
    assert newest["added_nodes"] == ["10.0.0.6"] and newest["removed_nodes"] == []
    assert "10.0.0.5->10.0.0.6" in newest["added_links"]
    assert (
        "10.0.0.5->10.0.0.1" in newest["removed_links"]
    )  # the ring now closes through the new router
    assert {
        "source": "10.0.0.1",
        "target": "10.0.0.2",
        "old_metric": 10,
        "new_metric": 77,
    } in newest["metric_changes"]
    assert first["node_count"] == 5 and newest["node_count"] == 6


def test_runs_come_back_newest_first_and_limit_applies(tmp_path):
    engine = engine_in(tmp_path)
    ids = []
    for extra in range(4):
        engine.process(topology(extra_routers=extra))
        ids.append(engine.last_run_id)
    assert [r["run_id"] for r in engine.history.list_runs()] == ids[::-1]
    assert [r["run_id"] for r in engine.history.list_runs(limit=2)] == ids[:1:-1]
    assert engine.history.count() == 4
    assert (
        engine.history.previous_run_id(ids[2]) == ids[1]
        and engine.history.previous_run_id(ids[0]) is None
    )


def test_a_dry_run_and_a_held_run_are_not_recorded(tmp_path):
    engine = engine_in(tmp_path)
    engine.process(topology(), dry_run=True)
    assert engine.history.count() == 0 and engine.last_run_id is None
    engine.process(topology())
    degraded = without(topology(), {"10.0.0.3", "10.0.0.4", "10.0.0.5"})
    _, diff = engine.process(degraded)
    assert diff.suspect_reasons and not diff.baseline_updated
    assert (
        engine.history.count() == 1
    )  # the guard held the baseline: that run never became history


def test_accepting_a_flagged_run_records_it_as_suspect(tmp_path):
    engine = engine_in(tmp_path)
    engine.process(topology())
    degraded = without(topology(), {"10.0.0.3", "10.0.0.4", "10.0.0.5"})
    engine.process(degraded, accept_changes=True)
    newest = engine.history.list_runs(1)[0]
    assert newest["is_suspect"] is True and len(newest["removed_nodes"]) == 3


def test_history_can_be_switched_off(tmp_path):
    engine = engine_in(tmp_path, history=HistoryConfig(enabled=False))
    engine.process(topology())
    assert engine.history is None and engine.last_run_id is None
    assert not (tmp_path / "history").exists() and engine.current_path.exists()


def test_retention_keeps_only_the_newest_runs(tmp_path):
    engine = engine_in(tmp_path, history=HistoryConfig(max_runs=3))
    ids = []
    for extra in range(5):
        engine.process(topology(extra_routers=extra))
        ids.append(engine.last_run_id)
    assert [r["run_id"] for r in engine.history.list_runs()] == ids[:1:-1]
    assert engine.history.get_run(ids[0]) is None


def test_runs_are_only_ever_inserted(tmp_path):
    store = HistoryStore(tmp_path / "h" / "history.db")
    engine = engine_in(tmp_path)
    graph, diff = engine.process(topology())
    store.record(graph, diff, run_id="fixed-1")
    with pytest.raises(GraphEngineError, match="Could not record"):
        store.record(
            graph, diff, run_id="fixed-1"
        )  # an ID is never reused or overwritten
    assert store.count() == 1


@pytest.mark.parametrize(
    "bad", ["", "a b", "x/y", "../etc", "a;drop table runs", "é", "x" * 65]
)
def test_run_ids_are_validated(tmp_path, bad):
    store = HistoryStore(tmp_path / "history.db")
    graph, diff = engine_in(tmp_path).process(topology())
    with pytest.raises(GraphEngineError, match="Invalid run ID"):
        store.record(graph, diff, run_id=bad or "x y")
    assert (
        store.get_run(bad) is None
        and store.get_graph(bad) is None
        and store.previous_run_id(bad) is None
    )


def test_an_unreadable_stored_state_gives_none_not_a_crash(tmp_path):
    engine = engine_in(tmp_path)
    engine.process(topology())
    run_id = engine.last_run_id
    with sqlite3.connect(engine.history.path) as conn:
        conn.execute(
            "UPDATE runs SET graph_json = ? WHERE run_id = ?", ("{not json", run_id)
        )
    assert engine.history.get_graph(run_id) is None
    assert engine.history.get_run(run_id) is not None  # the row itself is still listed


def test_a_database_file_without_the_table_reads_as_empty(tmp_path):
    path = tmp_path / "history.db"
    sqlite3.connect(path).close()
    store = HistoryStore(path)
    assert store.list_runs() == [] and store.count() == 0


def test_a_file_that_is_not_a_database_is_a_clear_error(tmp_path):
    path = tmp_path / "history.db"
    path.write_text("definitely not sqlite", encoding="utf-8")
    with pytest.raises(GraphEngineError, match="history store"):
        HistoryStore(path).list_runs()


def test_findings_are_stored_and_counted_by_severity(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    graph, _ = engine_in(tmp_path).process(topology())
    diff = TopologyDiff(
        findings=[
            {"severity": "critical", "kind": "ROUTE_MISSING", "router": "10.0.0.1"},
            {"severity": "critical", "kind": "ADJ_NOT_FULL", "router": "10.0.0.2"},
            {"severity": "info", "kind": "NBR_NEW", "router": "10.0.0.3"},
        ]
    )
    run_id = store.record(graph, diff)
    assert store.list_runs()[0]["finding_counts"] == {"critical": 2, "info": 1}
    assert [f["kind"] for f in store.findings(run_id)] == [
        "ROUTE_MISSING",
        "ADJ_NOT_FULL",
        "NBR_NEW",
    ]
    assert store.findings("unknown") == [] and store.findings("a b") == []


def test_threads_can_record_into_one_store_at_the_same_time(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    graph, diff = engine_in(tmp_path / "state").process(topology())
    errors: list[GraphEngineError] = []

    def work():
        try:
            for _ in range(5):
                store.record(graph, diff)
        except GraphEngineError as exc:  # the assertion below reports it
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and store.count() == 30
    assert len({r["run_id"] for r in store.list_runs(100)}) == 30


# ----------------------------------------------------------------- settings
def test_history_settings_defaults_and_validation():
    assert HistoryConfig.from_settings(None) == HistoryConfig(
        enabled=True, max_runs=2000
    )
    assert HistoryConfig.from_settings(
        {"enabled": False, "max_runs": 0}
    ) == HistoryConfig(False, 0)
    for bad in ({"max_runs": -1}, {"max_runs": "many"}, ["x"]):
        with pytest.raises(GraphEngineError):
            HistoryConfig.from_settings(bad)


# ------------------------------------------------------- state compatibility
def test_current_state_json_keeps_its_shape_and_loads_without_the_history(tmp_path):
    engine = engine_in(tmp_path)
    engine.process(topology())
    payload = json.loads(engine.current_path.read_text(encoding="utf-8"))
    assert set(payload) == {"schema_version", "metadata", "nodes", "edges"}
    fresh = engine_in(tmp_path, history=HistoryConfig(enabled=False))
    assert fresh.load_graph(fresh.current_path).number_of_nodes() == 5


def test_atomic_write_leaves_no_temp_file_and_cleans_up_after_a_failure(
    tmp_path, monkeypatch
):
    target = tmp_path / "out" / "page.html"
    atomic_write_text(target, "one")
    atomic_write_text(target, "two")
    assert target.read_text(encoding="utf-8") == "two"
    assert [p.name for p in target.parent.iterdir()] == ["page.html"]

    monkeypatch.setattr(
        "os.replace", lambda *a: (_ for _ in ()).throw(OSError("disk full"))
    )
    with pytest.raises(OSError, match="disk full"):
        atomic_write_text(target, "three")
    assert target.read_text(encoding="utf-8") == "two"  # the old file is intact
    assert [p.name for p in target.parent.iterdir()] == [
        "page.html"
    ]  # and no .tmp is left


def test_the_state_file_is_written_atomically(tmp_path, monkeypatch):
    engine = engine_in(tmp_path)
    graph, _ = engine.process(topology())
    before = engine.current_path.read_text(encoding="utf-8")
    monkeypatch.setattr("os.replace", lambda *a: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(GraphEngineError, match="Could not write state file"):
        engine.save_graph(deepcopy(graph))
    assert engine.current_path.read_text(encoding="utf-8") == before
