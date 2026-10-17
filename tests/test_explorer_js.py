"""Runs the explorer page itself in jsdom (hover, select, drag, save, search, filters, bundles, export ...).

Needs node and jsdom; skipped when they are not installed.  Install once with::

    npm install --prefix tests/js
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from src.correlation import Finding, TraceResult
from src.explorer import write_explorer
from src.graph_engine import TopologyDiff
from tests.explorer_fixture import realistic

JS_DIR = Path(__file__).parent / "js"
P = "10.255.255.19".rsplit(".", 1)[0] + "."


def _node_with_jsdom() -> str | None:
    node = shutil.which("node")
    if not node:
        return None
    probe = subprocess.run(
        [node, "-e", "require('jsdom')"],
        cwd=JS_DIR,
        capture_output=True,
        env=os.environ,
    )
    return node if probe.returncode == 0 else None


NODE = _node_with_jsdom()
pytestmark = pytest.mark.skipif(
    NODE is None, reason="node + jsdom not available (npm install --prefix tests/js)"
)


@pytest.fixture(scope="module")
def observed(tmp_path_factory):
    folder = tmp_path_factory.mktemp("pages")
    plain = write_explorer(folder / "plain.html", realistic(), TopologyDiff())
    findings = [
        Finding(
            "neighbor", "ADJ_NOT_FULL", "critical", P + "1", P + "4", "m1", "h1", {}
        ),
        Finding(
            "route",
            "ROUTE_MISSING",
            "critical",
            P + "6",
            "10.136.4.0/28",
            "m2",
            "h2",
            {"origins": P + "19"},
        ),
        Finding(
            "route", "ROUTE_STALE", "warning", P + "7", "172.31.0.0/24", "m3", "", {}
        ),
        Finding("neighbor", "NBR_NEW", "info", P + "1", P + "4", "m4", "", {}),
    ]
    trace = TraceResult(
        query="10.136.4.9",
        source=P + "6",
        prefix="10.136.4.0/28",
        verdict="RIB and LSDB agree",
        spf_cost=201,
        paths=[[P + "6", "net-10.130.240.1", P + "19", "net-10.136.4.4"]],
    )
    quiet_graph = realistic()
    quiet_graph.graph["flushing_lsas"] = [
        {
            "type": "network",
            "id": "net-10.130.240.9",
            "area": "0.0.0.0",
            "age": 3550,
            "dr": P + "4",
            "prefixes": ["10.130.240.0/24"],
        }
    ]
    rich = write_explorer(
        folder / "rich.html",
        quiet_graph,
        TopologyDiff(
            findings=[f.to_dict() for f in findings],
            suspect_reasons=["1 seed did not answer"],
        ),
        trace=trace,
    )
    run = subprocess.run(
        [NODE, "battery.js", str(plain), str(rich)],
        cwd=JS_DIR,
        capture_output=True,
        text=True,
        timeout=120,
        env=os.environ,
    )
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


def test_the_page_runs_without_script_errors(observed):
    assert observed["errors"] == 0, observed["errorText"]
    assert observed["rich"]["errors"] == 0


def test_the_picture_is_drawn(observed):
    assert (observed["nodes"], observed["links"], observed["areaBoxes"]) == (19, 28, 3)
    assert observed["summary"].startswith(
        "Network View: 14 Routers | 5 Transit | 28 Links | "
    )


def test_the_sidebar_lists_the_diagnostics(observed):
    assert "Topology Split Detected (2 parts)" in observed["cards"][0]
    assert any("One-way Links" in c for c in observed["cards"]) and any(
        "Stale Router" in c for c in observed["cards"]
    )


def test_hovering_a_link_shows_its_details_and_leaving_hides_them(observed):
    assert observed["tipShown"] and observed["tipHidden"]
    for word in ("Interface:", "Cost:", "Status:", "ONE-WAY"):
        assert word in observed["tipText"]


def test_selecting_a_node_dims_the_rest_and_clearing_restores_it(observed):
    assert (
        observed["selVisible"]
        and observed["farDimmed"]
        and observed["selfLit"]
        and observed["selectionCleared"]
    )
    assert "ASBR" in observed["selText"] and observed["linkSelected"]


def test_dragging_moves_a_node_by_the_mouse_distance_and_saves_only_that_node(observed):
    assert (observed["dragDx"], observed["dragDy"]) == (120, 60)
    assert (
        observed["savedKeys"] == ["ospf-explorer:layout:v1:default"]
        and observed["savedOnlyMovedNode"]
    )


def test_a_saved_layout_survives_a_reload_and_a_plain_click_is_not_a_drag(observed):
    assert (
        observed["restoredAfterReload"]
        and observed["otherNodesUntouched"]
        and observed["clickIsNotADrag"]
    )
    assert observed[
        "wobbleSelects"
    ]  # a couple of pixels of hand shake still count as a click


def test_reset_layout_restores_the_computed_positions_and_forgets_the_saved_ones(
    observed,
):
    assert observed["resetRestoresBase"]


def test_search_finds_nodes_by_id_and_prefix_and_can_be_cleared(observed):
    assert observed["searchHits"] == ["10.255.255.19"] and observed[
        "searchByPrefix"
    ] == ["net-10.136.4.4"]
    assert observed["searchByRouterPrefix"] == [
        "10.255.255.8"
    ]  # a router is found by a prefix it advertises
    assert observed["searchNoMatch"] == 0 and observed["searchCleared"]


def test_clicking_a_diagnostic_focuses_the_nodes_it_is_about(observed):
    assert observed["splitFocus"] == ["10.253.0.253", "net-10.253.0.254"]
    assert observed["rings"] == 2 and observed["escapeClears"]


def test_filters_hide_one_way_links_areas_and_area_boxes(observed):
    assert observed["linksWithoutOneWay"] == 17  # 28 - 11 one-way
    assert observed["nodesWithoutArea4"] == 17  # 19 - the area's router and network
    assert observed["areaBoxesHidden"] == 0


def test_bundling_collapses_leaf_routers_and_a_search_or_click_expands_them(observed):
    assert observed["hasBundle"] and "5 routers" in observed["bundleLabel"]
    assert (observed["bundleNodes"], observed["bundleLinks"]) == (
        15,
        19,
    )  # 5 leaves -> 1 bundle, their 10 links -> 1
    assert (
        observed["searchOpensBundle"]
        and observed["bundleBack"]
        and observed["afterExpand"] == 19
    )


def test_toolbar_keyboard_and_panels(observed):
    assert observed["zoomIn"] and observed["fitK"] and observed["slashFocusesSearch"]
    assert (
        observed["sidebarCollapsed"]
        and observed["filterPanelOpen"]
        and observed["morePanelOpensFilterCloses"]
    )


def test_layout_can_be_exported_imported_and_the_picture_downloaded(observed):
    assert (
        observed["exportName"] == "ospf-layout.json" and observed["exportCount"] == 19
    )
    assert observed["importMoved"]
    assert observed["svgName"] == "ospf-topology.svg" and observed["svgOk"]


def test_findings_are_grouped_filterable_and_clicking_one_finds_its_routers(observed):
    rich = observed["rich"]
    assert rich["groups"][0].startswith(
        "LSDB adjacency vs neighbour state"
    )  # critical groups first
    assert rich["groups"][1].startswith("Route missing from RIB (blackhole)")
    assert (
        rich["chips"] == ["2 critical", "1 warning", "1 info"] and rich["suspectCard"]
    )
    assert rich["focusAfterRow"] == [P + "1", P + "4"]
    assert (
        rich["groupsDefault"] == 3
        and rich["infoChipOff"]
        and rich["groupsWithInfo"] == 4
    )  # info on request
    assert rich["groupsWithoutCritical"] == 1


def test_ignored_lsas_are_shown_as_an_information_card(observed):
    [card] = observed["rich"]["flushCard"]
    assert (
        "1 LSA about to age out (ignored)" in card
        and "network 10.130.240.9 (age 3550 s)" in card
    )


def test_the_trace_is_listed_drawn_and_focusable(observed):
    rich = observed["rich"]
    assert (
        "10.136.4.0/28" in rich["traceCard"]
        and "RIB and LSDB agree" in rich["traceCard"]
    )
    assert (
        rich["traceFocusLinks"],
        rich["traceFocusNodes"],
        rich["traceLinksDrawn"],
    ) == (3, 4, 3)


# ---------------------------------------------------------------- theme switch
def test_the_page_starts_in_auto_and_resolves_it_to_dark_when_the_system_says_nothing(
    observed,
):
    first = observed["theme"]["initial"]
    assert (first["pref"], first["attr"], first["saved"]) == ("auto", "dark", None)
    assert first["icon"] == "\u25d0" and "auto" in first["title"]


def test_the_button_cycles_auto_light_dark_auto_and_saves_each_choice(observed):
    light, dark, auto = observed["theme"]["cycle"]
    assert (light["pref"], light["attr"], light["saved"], light["icon"]) == (
        "light",
        "light",
        "light",
        "\u2600\ufe0f",
    )
    assert (dark["pref"], dark["attr"], dark["saved"], dark["icon"]) == (
        "dark",
        "dark",
        "dark",
        "\U0001f319",
    )
    assert (auto["pref"], auto["saved"]) == (
        "auto",
        "auto",
    ) and "follows the system" in auto["title"]
    assert observed["theme"]["drawnWithoutError"] == 19


def test_the_picture_is_recoloured_when_the_theme_changes(observed):
    first, (light, dark, _auto) = (
        observed["theme"]["initial"],
        observed["theme"]["cycle"],
    )
    assert (
        first["areaFill"] == dark["areaFill"] == "#10203a"
        and light["areaFill"] == "#dbeafe"
    )
    assert (
        first["pill"] == "#0b1324" and light["pill"] == "#ffffff"
    )  # cost badges: dark chip / white chip
    assert (
        light["areaLabel"] != dark["areaLabel"]
        and light["linkColor"] != dark["linkColor"]
    )


def test_auto_follows_the_operating_system_live_and_an_explicit_choice_does_not(
    observed,
):
    t = observed["theme"]
    assert (
        t["autoWhenSystemIsLight"]["attr"] == "light"
        and t["autoWhenSystemIsLight"]["pref"] == "auto"
    )
    assert (
        t["afterSystemGoesDark"]["attr"] == "dark"
        and t["afterSystemGoesLight"]["attr"] == "light"
    )
    assert (
        t["explicitIgnoresSystem"]["attr"] == "light"
        and t["explicitIgnoresSystem"]["pref"] == "light"
    )


def test_a_saved_choice_wins_over_the_system_and_junk_in_storage_is_ignored(observed):
    t = observed["theme"]
    assert t["savedDark"]["attr"] == "dark" and t["savedLight"]["attr"] == "light"
    assert (t["junkIgnored"]["pref"], t["junkIgnored"]["attr"]) == ("auto", "dark")


def test_changing_theme_keeps_the_selection_and_the_view(observed):
    assert observed["theme"]["selectionKept"]


def test_the_svg_download_takes_the_current_themes_background(observed):
    assert observed["theme"]["exportBg"] == "#f8fafc"


def test_the_head_script_picks_the_theme_before_the_page_script_runs(observed):
    head = observed["theme"]["head"]
    assert head["scriptWasRemoved"]
    assert (
        head["nothing"] == "dark" and head["autoLight"] == "light"
    )  # "auto": the system decides
    assert head["savedLight"] == "light" and head["savedDarkBeatsSystem"] == "dark"
    assert (
        head["pageDefaultLight"] == "light" and head["pageDefaultDark"] == "dark"
    )  # an explicit page default is not "auto"
