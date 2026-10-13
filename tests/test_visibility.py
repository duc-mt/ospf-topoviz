"""End-to-end OSPF visibility: stub prefixes and neighbour state in the graph, the engine's cross-checks,
the new report tables, adjacency colours on the diagram, and the whole pipeline through ``main``."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import networkx as nx
import pytest
import yaml

import main
from src.correlation import flap_findings, trace_prefix
from src.graph_engine import GraphEngine, TopologyDiff
from src.parser import OSPFParser
from src.report import (
    render_neighbor_findings_table,
    render_quality_table,
    render_rib_check_table,
    render_route_findings_table,
    render_summary_banner,
    render_trace,
)
from src.poller import RawLSDB
from src.visualizer import (
    COLOR_ADDED,
    COLOR_DOWN,
    COLOR_FULL,
    COLOR_PATH,
    COLOR_STUCK,
    COLOR_TWO_WAY,
    TopologyVisualizer,
    adjacency_color,
)
from tests.test_correlation import (
    A,
    B,
    C,
    D,
    detail_a,
    graph_of,
    healthy_rib,
    nbr,
    square,
)
from tests.test_multi_seed import FakeNetwork, NetmikoTimeoutException

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "vyos"


# ============================================================ graph building
def test_routers_record_the_prefixes_they_advertise():
    graph = graph_of(square())
    prefixes = {e["prefix"]: e["metric"] for e in graph.nodes[D]["prefixes"]}
    assert prefixes == {
        "10.0.0.4/32": 1,
        "10.2.4.0/24": 10,
        "10.3.4.0/24": 10,
        "10.9.0.0/24": 5,
    }
    assert [e["prefix"] for e in graph.nodes[A]["prefixes"]] == sorted(
        e["prefix"] for e in graph.nodes[A]["prefixes"]
    )
    assert all(e["area"] == "0.0.0.0" for e in graph.nodes[A]["prefixes"])


def test_neighbor_state_is_attached_to_the_links_of_the_polled_router():
    graph = graph_of(
        square(),
        [
            detail_a(
                neighbors=[
                    nbr(B, "ExStart", interface="eth1"),
                    nbr(C, "Full", interface="eth2"),
                ]
            )
        ],
    )
    assert (
        graph.edges[A, B]["nbr_state"] == "ExStart"
        and graph.edges[A, C]["nbr_state"] == "Full"
    )
    assert "nbr_state" not in graph.edges[B, A]  # B's own table was not read


def test_neighbor_snapshot_is_kept_in_the_graph_metadata():
    graph = graph_of(
        square(),
        [
            detail_a(
                neighbors=[
                    nbr(B, "Full", "DR", "eth1", "10.1.2.2", priority=1, dead_time=33)
                ]
            )
        ],
    )
    [row] = graph.graph["neighbors"]
    assert row == {
        "router": A,
        "neighbor": B,
        "state": "Full",
        "role": "DR",
        "interface": "eth1",
        "address": "10.1.2.2",
        "priority": 1,
        "dead_time": 33,
        "source": "A",
    }
    assert "neighbors" not in graph_of(square()).graph


def test_on_a_shared_segment_the_worst_neighbor_colours_the_link():
    from src.vendors.base import SourceDetail  # noqa: PLC0415
    from tests.test_correlation import (
        AREA0,
        KIND_TRANSIT,
        LinkRecord,
        Lsdb,
        NetworkLsa,
        router,
    )  # noqa: PLC0415

    def attach(addr):
        return LinkRecord(
            kind=KIND_TRANSIT, link_id="192.168.1.1", link_data=addr, metric=1
        )

    lsdb = Lsdb(
        router_lsas=[
            router(A, [attach("192.168.1.1")]),
            router(B, [attach("192.168.1.2")]),
            router(C, [attach("192.168.1.3")]),
        ],
        network_lsas=[
            NetworkLsa(
                address="192.168.1.1",
                dr=A,
                area=AREA0,
                mask="255.255.255.0",
                attached=[A, B, C],
                seq=-2147483645,
                age=10,
            )
        ],
        process_ids=[],
        router_id=B,
    )
    detail = SourceDetail(
        "B", B, [nbr(A, "Full", "DR"), nbr(C, "Init", "DROther")], None
    )
    graph = graph_of(lsdb, [detail])
    assert (
        graph.edges[B, "net-192.168.1.1"]["nbr_state"] == "Init"
    )  # Full with the DR, Init with C: the worst wins


# =================================================================== engine
def build(details):
    return OSPFParser.build_topology(square(), details=details)


def test_engine_cross_checks_when_given_what_the_routers_reported(tmp_path):
    engine = GraphEngine(tmp_path)
    rib = [r for r in healthy_rib() if r.cidr != "10.9.0.0/24"]
    _graph, diff = engine.process(build([detail_a(rib)]), details=[detail_a(rib)])
    assert [f["kind"] for f in diff.findings] == ["ROUTE_MISSING"]
    assert diff.rib_checks[0]["router"] == A
    assert len(diff.critical_findings) == 1
    assert not diff.has_changes  # findings are not topology changes


def test_engine_without_details_does_not_cross_check(tmp_path):
    _graph, diff = GraphEngine(tmp_path).process(build([]))
    assert (
        diff.findings == [] and diff.rib_checks == [] and diff.critical_findings == []
    )


def test_neighbor_flap_between_two_runs(tmp_path):
    engine = GraphEngine(tmp_path)
    first = detail_a()
    engine.process(build([first]), details=[first])  # baseline: B and C Full
    assert (
        len(json.loads(engine.current_path.read_text())["metadata"]["neighbors"]) == 2
    )

    stuck = detail_a(
        neighbors=[
            nbr(B, "Init", interface="eth1", address="10.1.2.2"),
            nbr(C, interface="eth2", address="10.1.3.3"),
        ]
    )
    _graph, diff = engine.process(build([stuck]), details=[stuck])
    kinds = {f["kind"]: f for f in diff.findings}
    assert kinds["NBR_STATE_CHANGE"]["severity"] == "critical"
    assert "Full -> Init" in kinds["NBR_STATE_CHANGE"]["message"]
    assert "ADJ_NOT_FULL" in kinds


def test_flap_is_measured_against_the_last_accepted_baseline(tmp_path):
    """A suspect run keeps the old baseline, so the next run still compares with the last good one."""
    engine = GraphEngine(tmp_path)
    good = detail_a()
    engine.process(build([good]), details=[good])
    stuck = detail_a(
        neighbors=[nbr(B, "ExStart", interface="eth1"), nbr(C, interface="eth2")]
    )
    engine.process(
        build([stuck]), details=[stuck], partial_sources=["x"]
    )  # suspect: baseline not replaced
    _graph, diff = engine.process(build([stuck]), details=[stuck])
    assert any(f["kind"] == "NBR_STATE_CHANGE" for f in diff.findings)


def test_dry_run_still_cross_checks_but_writes_nothing(tmp_path):
    engine = GraphEngine(tmp_path)
    _graph, diff = engine.process(
        build([detail_a([])]), details=[detail_a([])], dry_run=True
    )
    assert [f["kind"] for f in diff.findings] == ["RIB_EMPTY"]
    assert not tmp_path.exists() or not any(tmp_path.iterdir())


def test_changelog_records_the_finding_counts(tmp_path):
    engine = GraphEngine(tmp_path)
    rib = [r for r in healthy_rib() if r.cidr != "10.9.0.0/24"]
    engine.process(build([detail_a(rib)]), details=[detail_a(rib)])
    entry = json.loads((tmp_path / "changelog.jsonl").read_text().splitlines()[-1])
    assert entry["findings"] == {"critical": 1}


# =================================================================== report
def _diff_with(*findings, checks=()):
    return TopologyDiff(
        findings=[f.to_dict() for f in findings], rib_checks=list(checks)
    )


def _findings(rib=None, neighbors=None):
    from src.correlation import correlate  # noqa: PLC0415

    return correlate(graph_of(square()), [detail_a(rib, neighbors)])


def test_neighbor_table_lists_state_mismatches_with_a_hint():
    report = _findings(
        neighbors=[nbr(B, "ExStart", interface="eth1"), nbr(C, interface="eth2")]
    )
    out = render_neighbor_findings_table(_diff_with(*report.findings))
    assert (
        out.splitlines()[0].startswith("╭")
        and "STATE MISMATCH" in out
        and "✖ CRITICAL" in out
    )
    assert "MTU mismatch" in out  # the troubleshooting hint under the table
    assert render_neighbor_findings_table(TopologyDiff()) is None


def test_flaps_are_labelled_as_such():
    findings = flap_findings(
        [], [{"router": A, "neighbor": B, "state": "Full", "interface": "eth1"}]
    )
    findings += flap_findings(
        [{"router": A, "neighbor": B, "state": "Init", "interface": "eth1"}],
        [{"router": A, "neighbor": B, "state": "Full", "interface": "eth1"}],
    )
    out = render_neighbor_findings_table(_diff_with(*findings))
    assert "FLAP" in out and "Full -> Init" in out


def test_route_table_separates_blackholes_from_suboptimal_routes():
    rib = [r for r in healthy_rib() if r.cidr != "10.0.0.3/32"]
    rib[0].metric = 50
    out = render_route_findings_table(_diff_with(*_findings(rib).findings))
    assert "BLACKHOLE" in out and "SUBOPTIMAL" in out and "10.0.0.3/32" in out
    assert render_route_findings_table(TopologyDiff()) is None


def test_rib_check_table_counts_consistent_and_deviating_routes():
    report = _findings([r for r in healthy_rib() if r.cidr != "10.9.0.0/24"])
    out = render_rib_check_table(_diff_with(checks=report.rib_checks))
    row = next(line for line in out.splitlines() if A in line)
    cells = [c.strip() for c in row.strip("│").split("│")]
    assert cells == [A, "5", "6", "5", "1", "0"]
    assert render_rib_check_table(TopologyDiff()) is None


def test_quality_table_skips_adjacencies_another_table_explains():
    graph = nx.DiGraph()
    graph.graph["adjacency_issues"] = [
        {
            "router": A,
            "neighbor": B,
            "state": "ExStart",
            "interface": "eth1",
            "source": "x",
            "in_lsdb": True,
        },
        {
            "router": A,
            "neighbor": C,
            "state": "Init",
            "interface": "eth2",
            "source": "x",
            "in_lsdb": False,
        },
    ]
    both = render_quality_table(graph)
    assert B in both and C in both
    only = render_quality_table(graph, {(A, B)})
    assert B not in only and C in only


def test_banner_shows_finding_counts():
    raw = RawLSDB(router="", network="", source="s", collected_at="t")
    graph = nx.DiGraph()
    plain = render_summary_banner(raw, graph, TopologyDiff())
    assert "Findings" not in plain
    badge = render_summary_banner(raw, graph, _diff_with(*_findings([]).findings))
    assert "Findings: 1 warning" in badge


def test_trace_report_walks_the_path_hop_by_hop():
    graph = graph_of(square())
    result = trace_prefix(graph, [detail_a()], "10.9.0.7")
    out = render_trace(result, graph)
    assert (
        "10.9.0.0/24" in out
        and "Intra-Area, cost 25" in out
        and "RIB and LSDB agree" in out
    )
    assert "Path 1 of 2" in out and "Path 2 of 2" in out
    assert "(equal cost)" in out and "stub" in out
    first = next(
        line for line in out.splitlines() if line.startswith("│") and "stub" in line
    )
    assert "25" in first  # total cost reaches the prefix's SPF cost


# ============================================================== visualizer
def _viz_graph(state):
    graph = graph_of(
        square(),
        [
            detail_a(
                neighbors=[
                    nbr(B, state, interface="eth1"),
                    nbr(C, "Full", interface="eth2"),
                ]
            )
        ],
    )
    return graph


def dot_of(graph, diff=None, **kw):
    return (
        TopologyVisualizer().build_digraph(graph, diff or TopologyDiff(), **kw).source
    )


def edge_line(src, a, b):
    return next(
        line
        for line in src.splitlines()
        if f'"{a}" -- "{b}"' in line or f'"{b}" -- "{a}"' in line
    )


@pytest.mark.parametrize(
    "state, color",
    [
        ("Full", COLOR_FULL),
        ("2-Way", COLOR_TWO_WAY),
        ("ExStart", COLOR_STUCK),
        ("Exchange", COLOR_STUCK),
        ("Loading", COLOR_STUCK),
        ("Init", COLOR_DOWN),
        ("Down", COLOR_DOWN),
        ("Attempt", COLOR_DOWN),
    ],
)
def test_adjacency_colours(state, color):
    assert adjacency_color(state) == color
    assert color in edge_line(dot_of(_viz_graph(state)), A, B)


def test_a_stuck_adjacency_names_its_state_on_the_link():
    assert "ExStart" in edge_line(dot_of(_viz_graph("ExStart")), A, B)
    assert "Full" not in edge_line(
        dot_of(_viz_graph("Full")), A, B
    )  # a healthy link needs no extra label


def test_links_without_adjacency_data_keep_the_normal_colour():
    src = dot_of(graph_of(square()))
    for color in (COLOR_FULL, COLOR_STUCK, COLOR_DOWN, COLOR_TWO_WAY):
        assert color not in src
    assert "adjacency:" not in src  # no legend either


def test_legend_appears_once_adjacency_data_exists():
    assert "adjacency: green = Full" in dot_of(_viz_graph("Full"))


def _added(a, b):
    """A brand-new link appears in both directions."""
    return TopologyDiff(
        baseline_available=True,
        added_edges=[
            {
                "source": x,
                "target": y,
                "source_label": x,
                "target_label": y,
                "metric": 10,
                "link_type": "point-to-point",
                "area": "0.0.0.0",
            }
            for x, y in ((a, b), (b, a))
        ],
    )


def test_a_stuck_new_link_shows_the_problem_not_the_change():
    line = edge_line(dot_of(_viz_graph("ExStart"), _added(A, B)), A, B)
    assert COLOR_STUCK in line and COLOR_ADDED not in line


def test_a_healthy_new_link_stays_marked_as_new():
    line = edge_line(dot_of(_viz_graph("Full"), _added(A, B)), A, B)
    assert COLOR_ADDED in line


def test_traced_path_is_drawn_in_blue():
    graph = _viz_graph("Full")
    src = dot_of(graph, highlight={frozenset((A, B)), frozenset((B, D))})
    assert COLOR_PATH in edge_line(src, A, B) and COLOR_PATH in edge_line(src, B, D)
    assert COLOR_PATH not in edge_line(src, A, C)


def test_no_extra_dashed_line_for_a_link_that_is_already_coloured():
    graph = _viz_graph("ExStart")
    assert graph.graph["adjacency_issues"]
    src = dot_of(graph)
    assert src.count(f'"{A}" -- "{B}"') + src.count(f'"{B}" -- "{A}"') == 1


# ===================================================== whole pipeline (main)
def sample(name):
    return (SAMPLES / name).read_text()


HOST = "192.0.2.1"


@pytest.fixture
def lab(monkeypatch, tmp_path):
    class Lab:
        pass

    lab = Lab()
    lab.tmp, lab.data = tmp_path, tmp_path / "data"
    lab.outputs = {
        "router": sample("router_lsdb.txt"),
        "network": sample("network_lsdb.txt"),
        "neighbors": sample("neighbors.txt"),
        "routes": sample("routes.txt"),
    }
    lab.network = FakeNetwork({HOST: lab.outputs})
    lab.rendered = []
    monkeypatch.setattr(main, "DATA_DIR", lab.data)
    monkeypatch.setattr("src.poller.ConnectHandler", lab.network)

    def render(self, graph, diff, highlight=None, **_kw):
        lab.rendered.append(
            (self.build_digraph(graph, diff, highlight).source, highlight)
        )
        return tmp_path / "topology.png"

    monkeypatch.setattr(main.TopologyVisualizer, "render", render)
    lab.config = tmp_path / "settings.yaml"
    lab.config.write_text(
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

    def run(*args):
        return main.main(
            ["--config", str(lab.config), "--output", str(tmp_path / "t.png"), *args]
        )

    lab.run = run
    lab.state = lambda: json.loads((lab.data / "current_state.json").read_text())
    return lab


def test_a_consistent_router_passes_every_cross_check(lab, capsys):
    assert lab.run("--fail-on-findings") == main.EXIT_OK
    out = capsys.readouterr().out
    assert "OSPF Routing Table Check" in out
    assert "Neighbor Flap" not in out and "Blackhole" not in out
    assert "Findings" not in out


def test_state_and_prefixes_are_persisted(lab):
    lab.run()
    state = lab.state()
    nodes = {n["id"]: n for n in state["nodes"]}
    assert {e["prefix"] for e in nodes["10.0.0.2"]["prefixes"]} == {"10.0.0.2/32"}
    assert any(
        e["source"] == "10.0.0.1" and e.get("nbr_state") == "Full"
        for e in state["edges"]
    )
    assert {r["neighbor"] for r in state["metadata"]["neighbors"]} == {
        "10.0.0.2",
        "10.0.0.3",
    }


def test_a_stuck_neighbor_is_reported_with_the_likely_cause(lab, capsys):
    lab.outputs["neighbors"] = lab.outputs["neighbors"].replace("Full/-  ", "ExStart/-")
    assert lab.run("--fail-on-findings") == main.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "Neighbor Flap / State Mismatch" in out and "STATE MISMATCH" in out
    assert "MTU mismatch" in out
    assert "Findings: " in out and "critical" in out
    assert (
        "Data Quality" not in out
    )  # the same stuck adjacency is not listed a second time


def test_findings_do_not_change_the_exit_code_unless_asked(lab):
    lab.outputs["neighbors"] = lab.outputs["neighbors"].replace("Full/-  ", "ExStart/-")
    assert lab.run() == main.EXIT_OK


def test_a_prefix_missing_from_the_rib_is_a_blackhole(lab, capsys):
    lab.outputs["routes"] = "\n".join(
        line for line in lab.outputs["routes"].splitlines() if "10.0.0.3/32" not in line
    )
    assert lab.run("--fail-on-findings") == main.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert (
        "Routing Blackhole / Suboptimal Routing" in out
        and "BLACKHOLE" in out
        and "10.0.0.3/32" in out
    )


def test_a_wrong_rib_cost_is_suboptimal(lab, capsys):
    lab.outputs["routes"] = lab.outputs["routes"].replace("[110/11]", "[110/31]")
    assert lab.run() == main.EXIT_OK
    out = capsys.readouterr().out
    assert "SUBOPTIMAL" in out and "cost 31" in out and "gives 11" in out


def test_a_neighbor_flap_between_runs_is_detected(lab, capsys):
    assert lab.run() == main.EXIT_OK  # baseline: both neighbours Full
    capsys.readouterr()
    lab.outputs["neighbors"] = lab.outputs["neighbors"].replace("Full/-  ", "Init/-  ")
    assert lab.run("--fail-on-findings") == main.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "FLAP" in out and "Full -> Init" in out


def test_a_lost_neighbor_between_runs(lab, capsys):
    lab.run()
    capsys.readouterr()
    lab.outputs["neighbors"] = "\n".join(
        row for row in lab.outputs["neighbors"].splitlines() if "10.0.0.3" not in row
    )
    lab.run()
    out = capsys.readouterr().out
    assert "FLAP (LOST)" in out


def test_trace_prints_the_path_and_highlights_it_on_the_diagram(lab, capsys):
    assert lab.run("--trace", "10.0.0.3") == main.EXIT_OK
    out = capsys.readouterr().out
    assert (
        "Prefix Path Trace" in out
        and "10.0.0.3/32" in out
        and "RIB and LSDB agree" in out
    )
    source, highlight = lab.rendered[-1]
    assert highlight and COLOR_PATH in source


def test_trace_from_another_router_uses_the_lsdb_alone(lab, capsys):
    lab.run("--trace", "10.0.0.3", "--trace-from", "10.0.0.2")
    out = capsys.readouterr().out
    assert "from router 10.0.0.2" in out and "no matching OSPF route" in out


def test_a_malformed_trace_fails_before_any_ssh_traffic(lab, capsys):
    assert lab.run("--trace", "banana") == main.EXIT_ERROR
    assert lab.network.connected == []


def test_an_unknown_trace_source_is_a_clean_error(lab):
    assert lab.run("--trace", "10.0.0.3", "--trace-from", "10.9.9.9") == main.EXIT_ERROR


def test_routes_can_be_switched_off_in_the_settings(lab, capsys):
    lab.config.write_text(
        yaml.safe_dump(
            {
                "device": {
                    "host": HOST,
                    "username": "u",
                    "password": "p",
                    "device_type": "vyos",
                },
                "polling": {"routes": False},
            }
        )
    )
    assert lab.run() == main.EXIT_OK
    assert "Routing Table Check" not in capsys.readouterr().out


def test_a_router_that_cannot_list_its_routes_still_gets_the_rest(lab, capsys):
    lab.outputs["routes"] = ""
    assert lab.run("--fail-on-findings") == main.EXIT_OK
    out = capsys.readouterr().out
    assert "Routing Table Check" not in out and "Topology" in out


def test_save_raw_keeps_the_routing_table_for_replay(lab, tmp_path):
    lab.run("--save-raw", str(tmp_path / "raw"))
    assert (tmp_path / "raw" / "routes.txt").read_text() == lab.outputs["routes"]
    assert (tmp_path / "raw" / "neighbors.txt").exists()


def test_replay_runs_the_cross_checks_on_saved_output(lab, capsys):
    assert (
        main.main(
            [
                "--config",
                str(lab.config),
                "--output",
                str(lab.tmp / "t.png"),
                "--replay",
                str(SAMPLES),
                "--device-type",
                "vyos",
                "--dry-run",
            ]
        )
        == main.EXIT_OK
    )
    out = capsys.readouterr().out
    assert "OSPF Routing Table Check" in out and "Seed Routers" not in out


def test_replay_of_a_directory_without_routes_txt_just_skips_the_check(
    lab, capsys, tmp_path
):
    replay = tmp_path / "replay"
    shutil.copytree(SAMPLES, replay)
    (replay / "routes.txt").unlink()
    assert (
        main.main(
            [
                "--config",
                str(lab.config),
                "--output",
                str(tmp_path / "t.png"),
                "--replay",
                str(replay),
                "--device-type",
                "vyos",
                "--dry-run",
            ]
        )
        == main.EXIT_OK
    )
    assert "Routing Table Check" not in capsys.readouterr().out


def test_multi_seed_cross_checks_run_per_polled_router(lab, capsys):
    """Two seeds: each router's own tables are checked against the merged LSDB."""
    lab.network.devices["192.0.2.2"] = NetmikoTimeoutException("t")
    lab.config.write_text(
        yaml.safe_dump(
            {
                "seeds": {
                    "mode": "merge",
                    "username": "u",
                    "password": "p",
                    "devices": [
                        {"host": HOST, "device_type": "vyos"},
                        {"host": "192.0.2.2", "device_type": "vyos"},
                    ],
                }
            }
        )
    )
    lab.run("--dry-run")
    out = capsys.readouterr().out
    assert "OSPF Routing Table Check" in out and "TIMEOUT" in out
