"""
==============================================================================
Module Name:   test_area_filter.py
Description:   --area: one OSPF area drawn on its own (graph extraction, diff filtering, diagram, CLI).
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-27
Version:       1.0.0
License:       MIT
==============================================================================
"""

from __future__ import annotations

import shutil

import pytest

import main
from src.graph_engine import (
    GraphEngine,
    GraphEngineError,
    TopologyDiff,
    filter_diff_by_area,
    filter_graph_by_area,
    graph_to_payload,
    parse_area_id,
)
from src.visualizer import TopologyVisualizer
from tests.explorer_fixture import A0, A1, A4, realistic
from tests.test_multi_seed import AREA0, AREA1, R1, R2, R3, R4


def areas_of(graph, node):
    return set(graph.nodes[node]["areas"])


# ------------------------------------------------------------------ area IDs
@pytest.mark.parametrize(
    ("given", "dotted"),
    [
        ("0", "0.0.0.0"),
        ("1", "0.0.0.1"),
        (" 4 ", "0.0.0.4"),
        ("0.0.0.1", "0.0.0.1"),
        ("10.1.2.3", "10.1.2.3"),
        (7, "0.0.0.7"),
    ],
)
def test_area_ids_are_accepted_as_numbers_or_dotted_quads(given, dotted):
    assert parse_area_id(given) == dotted


@pytest.mark.parametrize(
    "bad",
    ["", "abc", "1.2.3", "256.0.0.1", "-1", "4294967296", "0.0.0.0.0", "1;rm", "0x1"],
)
def test_anything_else_is_not_an_area_id(bad):
    with pytest.raises(GraphEngineError, match="not an OSPF area ID"):
        parse_area_id(bad)


# ----------------------------------------------------------- graph extraction
def test_an_area_view_holds_only_the_routers_networks_and_links_of_that_area():
    graph = realistic()
    view = filter_graph_by_area(graph, "0")
    assert (
        view.number_of_nodes() > 0 and view.number_of_nodes() < graph.number_of_nodes()
    )
    for node in view.nodes:
        assert A0 in {a for a in areas_of(graph, node)}, f"{node} is not in area 0"
    for _u, _v, attrs in view.edges(data=True):
        assert attrs["area"] == A0
    # nothing that lives only in another area leaks in
    only_elsewhere = {n for n in graph.nodes if A0 not in areas_of(graph, n)}
    assert only_elsewhere and not only_elsewhere & set(view.nodes)


def test_area_border_routers_stay_as_the_edge_of_the_view_and_name_their_other_areas():
    graph = realistic()
    view = filter_graph_by_area(graph, A0)
    abrs = [
        n for n in view.nodes if len(areas_of(graph, n)) > 1
    ]  # joins area 0 to another area
    assert abrs
    for abr in abrs:
        assert view.nodes[abr]["areas"] == [A0]
        assert set(view.nodes[abr]["border_areas"]) == areas_of(graph, abr) - {A0}
        assert view.nodes[abr]["border_areas"]
    # a router that is in one area only has no border areas
    inner = [n for n in view.nodes if len(areas_of(graph, n)) == 1]
    assert inner and all("border_areas" not in view.nodes[n] for n in inner)


def test_links_of_other_areas_between_the_same_border_routers_are_left_out():
    graph = realistic()
    view = filter_graph_by_area(graph, A1)
    assert view.number_of_edges() > 0
    assert {a["area"] for _u, _v, a in view.edges(data=True)} == {A1}
    full = {a["area"] for _u, _v, a in graph.edges(data=True)}
    assert {A0, A1, A4} <= full  # the whole network does have links in the other areas


@pytest.mark.parametrize("spelling", ["1", "0.0.0.1", " 1 "])
def test_every_spelling_of_an_area_gives_the_same_view(spelling):
    reference = graph_to_payload(filter_graph_by_area(realistic(), "0.0.0.1"))
    assert graph_to_payload(filter_graph_by_area(realistic(), spelling)) == reference


def test_the_input_graph_is_not_modified():
    graph = realistic()
    before = graph_to_payload(graph)
    filter_graph_by_area(graph, "0")
    assert graph_to_payload(graph) == before


def test_the_metadata_is_cut_down_to_the_area():
    graph = realistic()
    graph.graph["stale_nodes"] = [n for n in graph.nodes][:3] + ["10.9.9.9"]
    graph.graph["adjacency_issues"] = [
        {"router": "10.9.9.9"},
        {"router": next(iter(graph.nodes))},
    ]
    graph.graph["areas"] = [A0, A1, A4]
    view = filter_graph_by_area(graph, A0)
    assert view.graph["filtered_area"] == A0 and view.graph["areas"] == [A0]
    assert (
        set(view.graph["stale_nodes"]) <= set(view.nodes)
        and "10.9.9.9" not in view.graph["stale_nodes"]
    )
    assert all(i["router"] in view.nodes for i in view.graph["adjacency_issues"])
    assert "filtered_area" not in graph.graph


def test_one_way_link_counts_are_recounted_for_the_view():
    graph = realistic()
    graph.graph["one_way_links"] = (
        99  # the whole-network count, as the engine records it
    )
    view = filter_graph_by_area(graph, A0)
    assert view.graph["one_way_links"] != 99
    assert view.graph["one_way_links"] == len(
        {
            frozenset((u, v))
            for u, v, a in view.edges(data=True)
            if a.get("link_state") == "one-way"
        }
    )


def test_an_area_with_nothing_in_it_is_an_error_that_lists_the_areas_there_are():
    with pytest.raises(
        GraphEngineError,
        match=r"Area 0\.0\.0\.9 has no routers.*0\.0\.0\.0, 0\.0\.0\.1, 0\.0\.0\.4",
    ):
        filter_graph_by_area(realistic(), "9")


def test_the_engine_exposes_the_same_filters():
    graph = realistic()
    view = GraphEngine.filter_by_area(graph, "4")
    assert set(view.nodes) == set(filter_graph_by_area(graph, "4").nodes)
    diff = TopologyDiff()
    assert GraphEngine.filter_diff_by_area(diff, "4", view) == filter_diff_by_area(
        diff, "4", view
    )


# ---------------------------------------------------------------------- diff
def test_the_diff_is_cut_to_the_area():
    graph = realistic()
    view = filter_graph_by_area(graph, A1)
    inside = next(iter(view.nodes))
    diff = TopologyDiff(
        added_nodes=[
            {"id": "10.1.1.1", "areas": [A1]},
            {"id": "10.1.1.2", "areas": [A0]},
            {"id": "10.1.1.3", "areas": ["1"]},
        ],
        removed_nodes=[{"id": "10.2.2.2", "areas": [A4]}],
        added_edges=[
            {"source": "a", "target": "b", "area": A1},
            {"source": "c", "target": "d", "area": A0},
        ],
        removed_edges=[{"source": "e", "target": "f", "area": "0.0.0.1"}],
        changed_metrics=[{"source": "g", "target": "h", "area": A4}],
        findings=[
            {"router": inside, "kind": "X"},
            {"router": "10.250.250.250", "kind": "Y"},
        ],
        rib_checks=[{"router": inside}, {"router": "10.250.250.250"}],
        suspect_reasons=["keep me"],
    )
    cut = filter_diff_by_area(diff, "1", view)
    assert [r["id"] for r in cut.added_nodes] == [
        "10.1.1.1",
        "10.1.1.3",
    ]  # "1" is area 0.0.0.1 too
    assert cut.removed_nodes == [] and cut.changed_metrics == []
    assert [r["source"] for r in cut.added_edges] == ["a"] and len(
        cut.removed_edges
    ) == 1
    assert [f["kind"] for f in cut.findings] == ["X"] and len(cut.rib_checks) == 1
    assert cut.suspect_reasons == ["keep me"]
    assert len(diff.added_nodes) == 3  # the original is untouched


# ------------------------------------------------------------------- diagram
def dot_of(graph, diff=None) -> str:
    return (
        TopologyVisualizer(output_path="unused.png")
        .build_digraph(graph, diff or TopologyDiff())
        .source
    )


def test_the_diagram_says_which_area_it_shows_and_marks_the_border_routers():
    view = filter_graph_by_area(realistic(), A0)
    source = dot_of(view)
    assert "area 0.0.0.0 only" in source
    assert "links into other areas are not drawn" in source
    assert "also in area" in source
    assert "area 0.0.0.0 only" not in dot_of(realistic())


@pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz is not installed")
def test_the_area_diagram_is_really_rendered_and_leaves_no_scratch_file(tmp_path):
    view = filter_graph_by_area(realistic(), A1)
    image = TopologyVisualizer(output_path=tmp_path / "area1.png").render(
        view, TopologyDiff()
    )
    assert image.exists() and image.stat().st_size > 1000
    assert sorted(p.name for p in tmp_path.iterdir()) == ["area1.png"]


# ------------------------------------------------------------------------ CLI
def full_state(e):
    return e.state()


def test_cli_draws_one_area_and_keeps_the_whole_network_in_the_baseline(
    env, capsys, monkeypatch
):
    monkeypatch.setattr(main, "OUTPUT_HTML", env.tmp / "page.html")
    assert env.run("--area", "1") == main.EXIT_OK
    dot = env.rendered[-1]
    assert "area 0.0.0.1 only" in dot
    assert (
        all(rid in dot for rid in (R2, R3, R4)) and R1 not in dot
    )  # R2 is the ABR on the edge
    out = capsys.readouterr().out
    assert "Area view : 0.0.0.1 (3 router(s)" in out
    state = env.state()  # the saved baseline is the whole network, not the view
    assert sorted(n["id"] for n in state["nodes"] if n["type"] == "router") == [
        R1,
        R2,
        R3,
        R4,
    ]
    assert "filtered_area" not in state["metadata"]
    page = (env.tmp / "page.html").read_text(encoding="utf-8")
    assert R1 in page  # and so is the explorer page


def test_cli_area_0_shows_the_other_side(env, capsys, monkeypatch):
    monkeypatch.setattr(main, "OUTPUT_HTML", env.tmp / "page.html")
    assert env.run("--area", AREA0) == main.EXIT_OK
    dot = env.rendered[-1]
    assert R1 in dot and R2 in dot and R3 not in dot and R4 not in dot
    assert AREA1 in dot  # R2 says it is also in area 1


def test_cli_without_area_is_unchanged(env, capsys, monkeypatch):
    monkeypatch.setattr(main, "OUTPUT_HTML", env.tmp / "page.html")
    assert env.run() == main.EXIT_OK
    assert "only" not in env.rendered[-1].split("label", 1)[1][:120]
    assert "Area view" not in capsys.readouterr().out


def test_cli_rejects_an_area_that_is_not_there_after_saving_the_run(
    env, caplog, monkeypatch
):
    monkeypatch.setattr(main, "OUTPUT_HTML", env.tmp / "page.html")
    assert env.run("--area", "9") == main.EXIT_ERROR
    assert "Area 0.0.0.9 has no routers" in caplog.text
    assert (env.data / "current_state.json").exists()  # polling was not wasted


@pytest.mark.parametrize("bad", ["abc", "1.2.3", "-3"])
def test_cli_rejects_a_malformed_area_before_polling_anything(env, caplog, bad):
    code = env.run(f"--area={bad}")
    assert code == main.EXIT_ERROR and "not an OSPF area ID" in caplog.text
    assert env.network.connected == []  # no SSH session was opened
