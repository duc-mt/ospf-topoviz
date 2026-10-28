"""
==============================================================================
Module Name:   test_history_page_js.py
Description:   The explorer page's history bar (time travel), run in jsdom against a mocked web server.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-27
Version:       1.0.0
License:       MIT
==============================================================================
Needs node and jsdom; skipped when they are not installed (npm install --prefix tests/js).
"""

from __future__ import annotations

import json
import subprocess

import pytest

from src.explorer import build_scene, write_explorer
from src.graph_engine import TopologyDiff
from src.visualizer import VisualOptions
from tests.explorer_fixture import realistic
from tests.test_explorer_js import JS_DIR, NODE

pytestmark = pytest.mark.skipif(
    NODE is None, reason="node + jsdom not available (npm install --prefix tests/js)"
)


def run_summary(run_id: str, nodes: int, links: int) -> dict:
    return {
        "run_id": run_id,
        "timestamp": f"2026-10-27T0{nodes % 10}:00:00+00:00",
        "node_count": nodes,
        "link_count": links,
        "added_nodes": [],
        "removed_nodes": [],
        "added_links": [],
        "removed_links": [],
        "metric_changes": [],
        "is_suspect": False,
        "finding_counts": {},
    }


@pytest.fixture(scope="module")
def observed(tmp_path_factory):
    folder = tmp_path_factory.mktemp("history_page")
    live = realistic()
    page = write_explorer(folder / "live.html", live, TopologyDiff())
    smaller = realistic()
    smaller.remove_node(sorted(smaller.nodes)[-1])
    smallest = realistic()
    for node in sorted(smallest.nodes)[-3:]:
        smallest.remove_node(node)
    ids = [
        "20261027T010000Z-aaaaaaaa",
        "20261027T020000Z-bbbbbbbb",
        "20261027T030000Z-cccccccc",
    ]
    scenes = {
        ids[0]: build_scene(
            smallest, TopologyDiff(), VisualOptions(), history={"run_id": ids[0]}
        ),
        ids[1]: build_scene(
            smaller, TopologyDiff(), VisualOptions(), history={"run_id": ids[1]}
        ),
    }
    runs = [  # newest first, as the API returns them
        run_summary(ids[2], live.number_of_nodes(), live.number_of_edges()),
        run_summary(ids[1], smaller.number_of_nodes(), smaller.number_of_edges()),
        run_summary(ids[0], smallest.number_of_nodes(), smallest.number_of_edges()),
    ]
    fixture = folder / "fixture.json"
    fixture.write_text(json.dumps({"runs": runs, "scenes": scenes}), encoding="utf-8")
    proc = subprocess.run(
        [NODE, str(JS_DIR / "test_history.js"), str(page), str(fixture)],
        cwd=JS_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    out["ids"] = ids
    out["counts"] = {
        "live": live.number_of_nodes(),
        "smaller": smaller.number_of_nodes(),
        "smallest": smallest.number_of_nodes(),
    }
    return out


def test_the_page_opened_from_disk_makes_no_request_and_shows_no_history_bar(observed):
    assert observed["file"]["calls"] == 0 and observed["file"]["barHidden"] is True


def test_a_page_with_no_api_behind_it_shows_no_history_bar(observed):
    assert observed["noApi"]["calls"] == ["api/history?limit=200"]
    assert observed["noApi"]["barHidden"] is True


def test_a_served_page_asks_for_the_history_once_and_shows_the_bar_at_the_latest_run(
    observed,
):
    live = observed["live"]
    assert live["calls"] == ["api/history?limit=200"]
    assert live["barHidden"] is False and live["max"] == "2" and live["value"] == "2"
    assert (
        live["disabled"] is False
        and live["next"] is True
        and live["latest"] is True
        and live["prev"] is False
    )
    assert "Run 3 of 3" in live["label"] and "past state" not in live["label"]
    assert observed["liveNodes"] == observed["counts"]["live"]


def test_scrubbing_to_a_past_run_loads_its_scene_into_the_page(observed):
    assert (
        "Run 1 of 3" in observed["immediateLabel"]
    )  # the label follows the hand at once
    past = observed["past"]
    assert past["requests"] == [f"api/history/{observed['ids'][0]}/scene"]
    assert (
        past["svgNodes"] == observed["counts"]["smallest"] != observed["counts"]["live"]
    )
    assert (
        past["exported"] == past["svgNodes"]
    )  # the objects window.__explorer exposes were updated in place
    assert (
        past["routers"] > 0
        and past["pastClass"] == "past"
        and "past state" in past["label"]
    )
    assert past["next"] is False


def test_stepping_forward_loads_the_next_run_into_the_same_objects(observed):
    stepped = observed["stepped"]
    assert stepped["requests"] == [f"api/history/{observed['ids'][1]}/scene"]
    assert (
        stepped["svgNodes"] == observed["counts"]["smaller"]
        and stepped["sameObject"] is True
    )


def test_latest_brings_back_the_page_s_own_scene_without_asking_the_server(observed):
    latest = observed["latest"]
    assert (
        latest["newRequests"] == 0 and latest["svgNodes"] == observed["counts"]["live"]
    )
    assert latest["pastClass"] == "" and "Run 3 of 3" in latest["label"]


def test_a_scrub_across_several_runs_asks_only_for_the_one_it_stops_on(observed):
    assert observed["debounce"]["requests"] == [
        f"api/history/{observed['ids'][0]}/scene"
    ]


def test_a_simulation_does_not_outlive_the_network_it_was_started_on(observed):
    assert observed["simAfterSwap"] == {"active": False, "selection": None}


def test_a_slow_answer_for_a_run_the_user_already_left_is_ignored(observed):
    stale = observed["stale"]
    assert stale["middleNodes"] == observed["counts"]["smaller"]
    assert (
        stale["afterNodes"] == observed["counts"]["smaller"]
        and "Run 2 of 3" in stale["label"]
    )


def test_a_failed_scene_request_is_reported_and_the_page_keeps_what_it_showed(observed):
    failure = observed["failure"]
    assert "Could not load that run: boom" in failure["toast"]
    assert failure["svgNodes"] == observed["counts"]["live"]


def test_with_a_single_run_the_slider_cannot_move(observed):
    assert (
        observed["single"]["disabled"] is True
        and observed["single"]["barHidden"] is False
    )
    assert "Run 1 of 1" in observed["single"]["label"]


def test_none_of_this_raised_a_javascript_error(observed):
    assert observed["errors"] == []
