"""The scene builder and the HTML writer of the interactive explorer, and how the CLI reaches them."""

from __future__ import annotations

import json
import re

import pytest

import main
from src.correlation import Finding, TraceResult
from src.explorer import TEMPLATE, build_scene, render_html, write_explorer
from src.graph_engine import TopologyDiff
from src.visualizer import TopologyVisualizer, VisualizationError, VisualOptions
from tests.explorer_fixture import A0, A1, A4, realistic

P = "10.255.255."


def scene(diff=None, **kw):
    return build_scene(realistic(), diff or TopologyDiff(), **kw)


def by_id(items):
    return {i["id"]: i for i in items}


# ------------------------------------------------------------------- scene
def test_scene_counts_match_the_topology():
    s = scene()
    assert (s["meta"]["routers"], s["meta"]["networks"], s["meta"]["links"]) == (
        14,
        5,
        28,
    )
    assert s["meta"]["areas"] == [A0, A1, A4]
    assert [a["id"] for a in s["areas"]] == [A0, A1, A4] and s["areas"][0]["backbone"]


def test_every_node_has_a_position_a_size_and_a_piece_number():
    for n in scene()["nodes"]:
        assert (
            all(isinstance(n[k], (int, float)) for k in ("x", "y", "w", "h"))
            and n["w"] > 0
        )
        assert n["part"] in (0, 1)


def test_node_captions_say_what_a_node_is():
    nodes = by_id(scene()["nodes"])
    assert nodes[P + "5"]["title"] == P + "5" and nodes[P + "5"]["sub"] == ["ASBR"]
    assert nodes[P + "6"]["sub"] == ["ABR/ASBR"] and nodes[P + "6"]["abr"] is True
    hub = nodes["net-10.130.240.1"]
    assert hub["title"] == "net 10.130.240.0/24" and hub["sub"] == [f"DR {P}5"]
    ghost = nodes["net-10.253.0.254"]
    assert (
        ghost["kind"] == "ghost"
        and ghost["title"] == "net 10.253.0.254"
        and ghost["sub"] == ["(no LSA)"]
    )
    stale = nodes["net-10.130.240.2"]
    assert stale["stale"] is True and "stale LSA (60 min)" in stale["sub"]


def test_router_names_replace_the_title_and_keep_the_id_visible():
    s = build_scene(
        realistic(), TopologyDiff(), VisualOptions(names={P + "5": "core-1"})
    )
    node = by_id(s["nodes"])[P + "5"]
    assert (
        node["title"] == "core-1"
        and node["sub"][0] == P + "5"
        and node["name"] == "core-1"
    )


def test_a_networks_box_is_wide_enough_for_its_text():
    nodes = by_id(scene()["nodes"])
    assert (
        nodes["net-10.130.240.2"]["w"] > nodes[P + "5"]["w"] * 1.5
    )  # diamonds are narrow where the text sits


def test_links_carry_everything_the_tooltip_shows():
    link = by_id(scene()["links"])[f"{P}15|net-10.130.240.1"]
    assert link["kind"] == "segment" and link["oneWay"] is False
    [end] = link["ends"]
    assert (end["from"], end["metric"], end["iface"], end["ip"]) == (
        P + "15",
        200,
        "eth0",
        "10.130.240.15",
    )


def test_p2p_links_have_a_end_per_direction():
    link = by_id(scene()["links"])[f"{P}1|{P}4"]
    assert link["kind"] == "p2p" and len(link["ends"]) == 2 and link["metric"] == 1
    assert {e["iface"] for e in link["ends"]} == {"tun0"}


def test_adjacency_state_reaches_the_link():
    link = by_id(scene()["links"])[f"{P}10|net-10.130.240.1"]
    assert link["state"] == "Full" and link["ends"][0]["state"] == "Full"


# -------------------------------------------------------------- diagnostics
def test_a_split_topology_is_reported_with_its_pieces():
    split = scene()["diagnostics"]["split"]
    assert split["parts"] == 2
    assert [len(g) for g in split["groups"]] == [17, 2]
    assert split["groups"][1] == ["10.253.0.253", "net-10.253.0.254"]


def test_a_connected_topology_has_no_split():
    graph = realistic()
    graph.remove_nodes_from(["10.253.0.253", "net-10.253.0.254"])
    assert build_scene(graph, TopologyDiff())["diagnostics"]["split"] is None


def test_one_way_links_and_stale_routers_are_listed():
    d = scene()["diagnostics"]
    assert len(d["oneWay"]) == 11 and d["stale"] == ["net-10.130.240.2"]
    assert all(
        link_id in {link["id"] for link in scene()["links"]} for link_id in d["oneWay"]
    )


def test_changes_since_the_last_run_are_summarised():
    diff = TopologyDiff(
        baseline_available=True,
        added_nodes=[{"id": P + "20", "type": "router"}],
        removed_nodes=[
            {"id": "10.9.9.9", "type": "router", "areas": [A0], "label": "10.9.9.9"}
        ],
        removed_edges=[
            {
                "source": "10.9.9.9",
                "target": P + "5",
                "metric": 4,
                "link_type": "point-to-point",
                "area": A0,
            },
            {
                "source": P + "5",
                "target": "10.9.9.9",
                "metric": 4,
                "link_type": "point-to-point",
                "area": A0,
            },
        ],
    )
    s = scene(diff)
    c = s["diagnostics"]["changes"]
    assert (
        c["baseline"] is True
        and c["addedNodes"] == [P + "20"]
        and c["removedNodes"] == ["10.9.9.9"]
    )
    assert c["removedLinks"] == 1
    removed = by_id(s["nodes"])["10.9.9.9"]
    assert (
        removed["status"] == "removed"
        and by_id(s["nodes"])[P + "20"]["status"] == "added"
    )
    assert by_id(s["links"])[f"10.9.9.9|{P}5"]["status"] == "removed"


def test_a_removed_router_is_still_placed_on_the_page():
    diff = TopologyDiff(
        removed_nodes=[{"id": "10.9.9.9", "type": "router", "areas": [A0]}],
        removed_edges=[
            {
                "source": "10.9.9.9",
                "target": P + "5",
                "metric": 4,
                "link_type": "point-to-point",
                "area": A0,
            }
        ],
    )
    node = by_id(scene(diff)["nodes"])["10.9.9.9"]
    assert isinstance(node["x"], float) and node["areas"] == [A0]


def test_suspect_reasons_travel_to_the_page():
    assert scene(TopologyDiff(suspect_reasons=["2 seed(s) did not answer"]))[
        "diagnostics"
    ]["suspect"] == ["2 seed(s) did not answer"]


# ------------------------------------------------------------------ findings
def finding(**kw):
    base = dict(
        category="route",
        kind="ROUTE_MISSING",
        severity="critical",
        router=P + "6",
        subject="10.136.4.0/28",
        message="m",
        hint="h",
        data={},
    )
    base.update(kw)
    return Finding(**base).to_dict()


def test_a_finding_knows_which_nodes_it_is_about():
    s = scene(TopologyDiff(findings=[finding(data={"origins": P + "19"})]))
    [f] = s["findings"]
    assert f["focus"][0] == P + "6" and P + "19" in f["focus"]
    assert "net-10.136.4.4" in f["focus"]  # the prefix is advertised by that network


def test_a_neighbor_finding_points_at_both_routers():
    f = scene(
        TopologyDiff(
            findings=[
                finding(
                    category="neighbor",
                    kind="ADJ_NOT_FULL",
                    router=P + "1",
                    subject=P + "4",
                )
            ]
        )
    )["findings"][0]
    assert f["focus"] == [P + "1", P + "4"]


def test_next_hop_routers_in_a_findings_data_are_focused_and_unknown_ids_dropped():
    f = scene(
        TopologyDiff(
            findings=[
                finding(
                    data={
                        "next_hop_routers": [P + "7", "10.77.77.77"],
                        "rib": [P + "18"],
                    }
                )
            ]
        )
    )["findings"][0]
    assert (
        P + "7" in f["focus"]
        and P + "18" in f["focus"]
        and "10.77.77.77" not in f["focus"]
    )


def test_adjacency_issues_get_focus_nodes():
    graph = realistic()
    graph.graph["adjacency_issues"] = [
        {
            "router": P + "1",
            "neighbor": P + "4",
            "state": "ExStart",
            "interface": "tun0",
        }
    ]
    d = build_scene(graph, TopologyDiff())["diagnostics"]
    assert d["adjacency"][0]["focus"] == [P + "1", P + "4"]


# --------------------------------------------------------------------- trace
def test_a_trace_is_carried_with_the_links_it_uses():
    trace = TraceResult(
        query="10.136.4.9",
        source=P + "6",
        prefix="10.136.4.0/28",
        verdict="RIB and LSDB agree",
        spf_cost=201,
        paths=[[P + "6", "net-10.130.240.1", P + "19", "net-10.136.4.4"]],
    )
    s = scene(trace=trace)
    assert s["trace"]["links"] == [
        f"{P}6|net-10.130.240.1",
        f"{P}19|net-10.130.240.1",
        f"{P}19|net-10.136.4.4",
    ]
    assert s["trace"]["verdict"] == "RIB and LSDB agree" and s["trace"]["cost"] == 201
    assert scene()["trace"] is None


# --------------------------------------------------------------------- html
def embedded(html):
    return json.loads(
        re.search(
            r'<script type="application/json" id="scene">(.*?)</script>', html, re.S
        ).group(1)
    )


def test_the_page_embeds_the_scene_as_json():
    s = scene(generated="2026-10-12T11:43:30+00:00")
    page = render_html(s)
    assert embedded(page) == json.loads(json.dumps(s))
    assert "__TITLE__" not in page and "/*__SCENE__*/" not in page
    assert "<title>OSPF Topology Explorer - 14 routers</title>" in page


def test_text_that_looks_like_markup_cannot_break_out_of_the_data_block():
    graph = realistic()
    graph.graph["adjacency_issues"] = [
        {
            "router": P + "1",
            "neighbor": P + "4",
            "state": "</script><script>alert(1)</script>",
        }
    ]
    page = render_html(build_scene(graph, TopologyDiff()))
    data_block = re.search(
        r'<script type="application/json" id="scene">(.*?)</script>', page, re.S
    ).group(1)
    assert "</script" not in data_block and "<script" not in data_block
    assert (
        embedded(page)["diagnostics"]["adjacency"][0]["state"]
        == "</script><script>alert(1)</script>"
    )


def test_the_page_needs_no_network():
    page = TEMPLATE.read_text()
    assert (
        not re.search(r'(?:src|href)\s*=\s*["\']https?://', page)
        and "@import" not in page
    )
    assert "fetch(" not in page and "XMLHttpRequest" not in page


def test_write_explorer_creates_the_file_and_its_folder(tmp_path):
    path = write_explorer(
        tmp_path / "deep" / "topology.html", realistic(), TopologyDiff()
    )
    assert path.exists() and path.read_text(encoding="utf-8").startswith(
        "<!DOCTYPE html>"
    )


# --------------------------------------------------------------- visualizer
def test_an_html_output_writes_the_explorer_without_graphviz(tmp_path):
    viz = TopologyVisualizer(output_path=tmp_path / "t.html")
    assert (
        viz.interactive is True
        and TopologyVisualizer(output_path=tmp_path / "t.png").interactive is False
    )
    viz.scope = "10.1.1.1,10.1.1.2"
    out = viz.render(realistic(), TopologyDiff())
    assert (
        out == tmp_path / "t.html"
        and embedded(out.read_text(encoding="utf-8"))["meta"]["scope"]
        == "10.1.1.1,10.1.1.2"
    )


def test_an_unknown_output_format_is_still_rejected():
    with pytest.raises(VisualizationError, match="format"):
        TopologyVisualizer(output_path="output/topology.xyz")


# ----------------------------------------------------------------------- cli
@pytest.fixture
def cli(monkeypatch, tmp_path):
    from tests.test_visibility import HOST, FakeNetwork, sample  # noqa: PLC0415
    import yaml  # noqa: PLC0415

    outputs = {
        "router": sample("router_lsdb.txt"),
        "network": sample("network_lsdb.txt"),
        "neighbors": sample("neighbors.txt"),
        "routes": sample("routes.txt"),
    }
    monkeypatch.setattr(main, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr("src.poller.ConnectHandler", FakeNetwork({HOST: outputs}))
    config = tmp_path / "settings.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "device": {
                    "host": HOST,
                    "username": "u",
                    "password": "p",
                    "device_type": "vyos",
                }
            }
        )
    )
    return lambda *args: main.main(["--config", str(config), *args])


def test_output_html_writes_only_the_explorer(cli, tmp_path, capsys):
    target = tmp_path / "out" / "topology.html"
    assert cli("--output", str(target)) == main.EXIT_OK
    page = embedded(target.read_text(encoding="utf-8"))
    assert page["meta"]["routers"] == 3 and page["meta"]["scope"] == "192.0.2.1"
    assert len(page["findings"]) == 0 and page["trace"] is None
    assert str(target) in capsys.readouterr().out and not list(
        (tmp_path / "out").glob("*.png")
    )



def test_default_run_writes_both_diagram_and_explorer(
    cli, tmp_path, monkeypatch, capsys
):
    """By default (with --output png), both the image and default HTML explorer are produced."""
    real, images = TopologyVisualizer.render, []

    def render(self, graph, diff, highlight=None, **kw):
        if self.interactive:
            return real(self, graph, diff, highlight, **kw)
        images.append(self.output_path)
        return self.output_path

    monkeypatch.setattr(main.TopologyVisualizer, "render", render)
    html_target = tmp_path / "output" / "topology.html"
    png_target = tmp_path / "output" / "topology.png"
    monkeypatch.setattr(main, "OUTPUT_IMAGE", png_target)
    monkeypatch.setattr(main, "OUTPUT_HTML", html_target)

    # CLI called with no --explorer flag
    assert cli("--output", str(png_target)) == main.EXIT_OK
    out = capsys.readouterr().out
    assert "Diagram   :" in out
    assert "Explorer  :" in out
    assert html_target.exists()
    assert images == [png_target]


def test_trace_and_findings_reach_the_explorer(cli, tmp_path):
    target = tmp_path / "t.html"
    assert cli("--output", str(target), "--trace", "10.0.0.3") == main.EXIT_OK
    page = embedded(target.read_text(encoding="utf-8"))
    assert page["trace"]["prefix"] == "10.0.0.3/32" and page["trace"]["links"]
