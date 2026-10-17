"""Area coverage audit (correlation), its report block and what the explorer scene carries for the page.

Covers: ``audit_area_coverage`` / ``AREA_UNPOLLED`` (src/correlation.py), ``render_area_coverage`` and the
banner badge (src/report.py), ``area_coverage`` + per-link directional ``spf`` costs in the scene
(src/explorer.py), and the engine hook (src/graph_engine.py).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.correlation import (
    AREA_UNPOLLED,
    INFO,
    WARNING,
    audit_area_coverage,
    correlate,
)
from src.explorer import build_scene, render_html
from src.graph_engine import GraphEngine, TopologyDiff
from src.report import render_area_coverage, render_summary_banner
from src.vendors.base import NeighborRecord, SourceDetail

A0, A1, A2 = "0.0.0.0", "0.0.0.1", "0.0.0.2"


def router(rid, *areas, abr=False, prefixes=()):
    node = {
        "id": rid,
        "type": "router",
        "areas": list(areas),
        "resolved": True,
        "abr": abr,
    }
    if prefixes:
        node["prefixes"] = [
            {"prefix": p, "metric": 1, "area": areas[0]} for p in prefixes
        ]
    return node


def p2p(a, b, ab, ba, area=A0):
    return [
        {
            "source": a,
            "target": b,
            "metric": ab,
            "link_type": "point-to-point",
            "area": area,
        },
        {
            "source": b,
            "target": a,
            "metric": ba,
            "link_type": "point-to-point",
            "area": area,
        },
    ]


def build(nodes, edges, **metadata):
    return GraphEngine(data_dir="/nonexistent").build_graph(
        {"metadata": metadata, "nodes": nodes, "edges": edges}
    )


@pytest.fixture
def backbone_with_hidden_abr():
    """Area 0 only was read; R3 is flagged ABR but only shows area 0 -> something lies behind it."""
    return build(
        [
            router("10.255.255.1", A0),
            router("10.255.255.2", A0),
            router("10.255.255.10", A0, abr=True),
        ],
        p2p("10.255.255.1", "10.255.255.2", 10, 10)
        + p2p("10.255.255.2", "10.255.255.10", 5, 5),
    )


def detail(name, rid, neighbors=()):
    return SourceDetail(name=name, router_id=rid, neighbors=list(neighbors))


# ---------------------------------------------------------------- audit
def test_single_area_without_abr_is_complete():
    g = build(
        [router("1.1.1.1", A0), router("2.2.2.2", A0)], p2p("1.1.1.1", "2.2.2.2", 1, 1)
    )
    cov = audit_area_coverage(g)
    assert cov.complete
    assert list(cov.polled) == [A0]
    assert cov.findings() == []


def test_unknown_area_marker_is_not_an_area():
    """Some platforms print no area at all (``n/a``); that must not count as a polled or missing area."""
    g = build(
        [router("1.1.1.1", "n/a"), router("2.2.2.2", "n/a")],
        p2p("1.1.1.1", "2.2.2.2", 1, 1, area="n/a"),
    )
    cov = audit_area_coverage(g)
    assert cov.polled == {}
    assert cov.complete


def test_abr_with_one_visible_area_means_an_area_is_hidden(
    backbone_with_hidden_abr,
):
    cov = audit_area_coverage(backbone_with_hidden_abr)
    assert not cov.complete
    (miss,) = cov.missing
    assert miss.area is None and not miss.named
    assert miss.candidates == ["10.255.255.10"]
    (finding,) = cov.findings()
    assert finding.kind == AREA_UNPOLLED
    assert finding.category == "area"
    assert finding.severity == INFO  # cannot name the area, so only information
    assert finding.router == "10.255.255.10"
    assert "10.255.255.10" in finding.hint


def test_polling_the_abr_itself_covers_all_its_areas():
    """A seed that *is* the ABR read the LSDB of every area it borders: nothing is hidden."""
    g = build(
        [router("10.255.255.10", A0, A1, abr=True), router("10.255.255.1", A0)],
        p2p("10.255.255.10", "10.255.255.1", 1, 1),
    )
    seed = detail("10.255.255.10", "10.255.255.10")
    cov = audit_area_coverage(g, [seed])
    assert cov.complete
    assert cov.polled[A0] == ["10.255.255.10"]
    assert cov.polled[A1] == ["10.255.255.10"]


def test_seed_labelled_with_an_unread_area_is_a_warning(backbone_with_hidden_abr):
    failed = SimpleNamespace(
        host="10.255.255.20", status="FAILED", tags=["Area2", "Core"]
    )
    cov = audit_area_coverage(backbone_with_hidden_abr, seeds=[failed])
    (miss,) = cov.missing
    assert miss.area == A2  # "Area2" == 0.0.0.2
    assert miss.candidates[0] == "10.255.255.20"  # the seed that should have covered it
    assert "10.255.255.10" in miss.candidates  # the ABR leading there
    assert any("could not be polled" in e for e in miss.evidence)
    (finding,) = cov.findings()
    assert finding.severity == WARNING
    assert finding.subject == A2
    assert finding.data["candidates"] == miss.candidates


def test_skipped_fallback_seed_says_nothing():
    g = build([router("1.1.1.1", A0)], [])
    skipped = SimpleNamespace(host="9.9.9.9", status="SKIPPED", tags=["Area5"])
    # a skipped seed was never needed (fallback mode): its label must not invent a missing area
    cov = audit_area_coverage(g, seeds=[skipped])
    assert [m.area for m in cov.missing] == ["0.0.0.5"]
    # ... but it is not reported as *failed*: the evidence says no LSA was read, not "could not be polled"
    assert "could not be polled" not in " ".join(cov.missing[0].evidence)


def test_neighbour_table_naming_an_unread_area(backbone_with_hidden_abr):
    d = detail(
        "10.255.255.2",
        "10.255.255.2",
        [NeighborRecord(router_id="10.255.255.10", state="Full", area="2")],
    )
    cov = audit_area_coverage(backbone_with_hidden_abr, [d])
    (miss,) = cov.missing
    assert miss.area == A2
    assert miss.candidates[0] == "10.255.255.10"
    assert len(miss.candidates) == len(set(miss.candidates))


def test_polled_area_lists_the_seeds_that_read_it():
    g = build(
        [router("10.255.255.1", A0), router("10.255.255.6", A0, A1, abr=True)],
        p2p("10.255.255.1", "10.255.255.6", 1, 1),
    )
    cov = audit_area_coverage(
        g,
        [detail("S1", "10.255.255.1"), detail("S6", "10.255.255.6")],
    )
    assert cov.polled[A0] == ["S1", "S6"]
    assert cov.polled[A1] == ["S6"]
    assert cov.complete


def test_to_dict_is_json_friendly(backbone_with_hidden_abr):
    data = audit_area_coverage(backbone_with_hidden_abr).to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["complete"] is False
    assert data["missing"][0]["named"] is False


# ---------------------------------------------------------------- correlate / engine
def test_correlate_always_runs_the_area_audit(backbone_with_hidden_abr):
    report = correlate(backbone_with_hidden_abr)  # no neighbour / routing data at all
    assert report.area_coverage is not None
    assert [f.kind for f in report.findings] == [AREA_UNPOLLED]
    assert report.rib_checks == []


def test_process_stores_area_coverage_on_the_diff(backbone_with_hidden_abr, tmp_path):
    parsed = {
        "metadata": {},
        "nodes": [{"id": n, **a} for n, a in backbone_with_hidden_abr.nodes(data=True)],
        "edges": [
            {"source": u, "target": v, **a}
            for u, v, a in backbone_with_hidden_abr.edges(data=True)
        ],
    }
    _graph, diff = GraphEngine(data_dir=tmp_path).process(parsed, dry_run=True)
    assert diff.area_coverage["complete"] is False
    assert [f["kind"] for f in diff.findings] == [AREA_UNPOLLED]
    json.dumps(diff.to_dict())  # the whole diff must stay serialisable


def test_diff_without_audit_has_no_coverage():
    assert TopologyDiff().area_coverage is None


# ---------------------------------------------------------------- report
def multi_area_incomplete():
    return SimpleNamespace(
        area_coverage={
            "complete": False,
            "polled": [
                {"area": A0, "seeds": ["10.255.255.1"]},
                {"area": A1, "seeds": ["10.255.255.6"]},
            ],
            "missing": [
                {
                    "area": A2,
                    "named": True,
                    "evidence": [
                        "10.255.255.2 has neighbour 10.255.255.10 in area 0.0.0.2"
                    ],
                    "candidates": ["10.255.255.10", "10.255.255.11"],
                }
            ],
        }
    )


def test_report_block_for_multi_area_incomplete_coverage(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    text = render_area_coverage(multi_area_incomplete())
    lines = text.splitlines()
    assert lines[0] == "[WARN] INCOMPLETE AREA COVERAGE:"
    assert "- Area 0.0.0.0: OK (polled via seed 10.255.255.1)" in lines
    assert "- Area 0.0.0.1: OK (polled via seed 10.255.255.6)" in lines
    assert "- Area 0.0.0.2: MISSING SEED!" in lines
    action = next(line for line in lines if "Action:" in line)
    assert "Add at least ONE router in Area 0.0.0.2" in action
    assert "10.255.255.10 or 10.255.255.11" in action
    assert action.endswith("to settings.yaml to render this area's full topology.")


def test_report_block_for_single_area_with_hidden_abr(
    backbone_with_hidden_abr, monkeypatch
):
    monkeypatch.setenv("NO_COLOR", "1")
    diff = SimpleNamespace(
        area_coverage=audit_area_coverage(backbone_with_hidden_abr).to_dict()
    )
    text = render_area_coverage(diff)
    assert text.splitlines()[0] == "[WARN] INCOMPLETE AREA COVERAGE:"
    assert "- Area 0.0.0.0: OK (polled)" in text
    assert "- Area (ID not visible): MISSING SEED!" in text
    assert "ABR 10.255.255.10" in text


def test_report_stays_quiet_when_there_is_nothing_to_say():
    one_area = SimpleNamespace(
        area_coverage={
            "complete": True,
            "polled": [{"area": A0, "seeds": []}],
            "missing": [],
        }
    )
    assert render_area_coverage(one_area) is None
    assert render_area_coverage(SimpleNamespace(area_coverage=None)) is None
    assert render_area_coverage(SimpleNamespace()) is None


def test_report_block_for_complete_multi_area(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    diff = SimpleNamespace(
        area_coverage={
            "complete": True,
            "polled": [{"area": A0, "seeds": ["a"]}, {"area": A1, "seeds": ["a", "b"]}],
            "missing": [],
        }
    )
    lines = render_area_coverage(diff).splitlines()
    assert lines[0] == "[ OK ] AREA COVERAGE:"
    assert "- Area 0.0.0.1: OK (polled via seeds a, b)" in lines


def test_banner_shows_the_unpolled_area_badge(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    graph = build([router("1.1.1.1", A0)], [])
    diff = TopologyDiff(baseline_available=False)
    diff.area_coverage = multi_area_incomplete().area_coverage
    assert "Areas: 1 unpolled" in render_summary_banner(None, graph, diff)
    diff.area_coverage = None
    assert "Areas" not in render_summary_banner(None, graph, diff)


# ---------------------------------------------------------------- explorer scene
def scene_for(graph, diff=None):
    return build_scene(graph, diff or TopologyDiff(baseline_available=False))


def test_scene_links_carry_directional_costs():
    g = build(
        [router("1.1.1.1", A0), router("2.2.2.2", A0)],
        p2p("1.1.1.1", "2.2.2.2", 10, 20),
    )
    (link,) = scene_for(g)["links"]
    assert link["a"] == "1.1.1.1"
    assert link["spf"] == {"ab": 10, "ba": 20}  # asymmetric metrics survive


def test_scene_segment_attachment_is_free_and_router_side_pays():
    nodes = [
        router("1.1.1.1", A0),
        router("2.2.2.2", A0),
        {
            "id": "net-10.0.0.1",
            "type": "network",
            "areas": [A0],
            "resolved": True,
            "address": "10.0.0.1",
            "prefix": "10.0.0.0/24",
        },
    ]
    edges = []
    for rid, cost in (("1.1.1.1", 4), ("2.2.2.2", 6)):
        edges.append(
            {
                "source": rid,
                "target": "net-10.0.0.1",
                "metric": cost,
                "link_type": "transit",
                "area": A0,
            }
        )
        edges.append(
            {
                "source": "net-10.0.0.1",
                "target": rid,
                "metric": 0,
                "link_type": "attachment",
                "area": A0,
            }
        )
    links = {
        link["id"]: link["spf"] for link in scene_for(build(nodes, edges))["links"]
    }
    assert links["1.1.1.1|net-10.0.0.1"] == {"ab": 4, "ba": 0}
    assert links["2.2.2.2|net-10.0.0.1"] == {"ab": 6, "ba": 0}


def test_scene_one_way_and_removed_directions_are_not_traversable():
    g = build(
        [router("1.1.1.1", A0), router("2.2.2.2", A0)],
        p2p("1.1.1.1", "2.2.2.2", 10, 10),
    )
    g.edges["1.1.1.1", "2.2.2.2"]["link_state"] = "one-way"
    (link,) = scene_for(g)["links"]
    assert link["spf"] == {"ab": None, "ba": None}

    # a link that vanished since the baseline is still drawn, but SPF must not walk it
    old = build(
        [router("1.1.1.1", A0), router("2.2.2.2", A0), router("3.3.3.3", A0)],
        p2p("1.1.1.1", "2.2.2.2", 1, 1) + p2p("2.2.2.2", "3.3.3.3", 1, 1),
    )
    new = build(
        [router("1.1.1.1", A0), router("2.2.2.2", A0), router("3.3.3.3", A0)],
        p2p("1.1.1.1", "2.2.2.2", 1, 1),
    )
    diff = GraphEngine(data_dir="/nonexistent").compare(old, new)
    spf = {link["id"]: link["spf"] for link in scene_for(new, diff)["links"]}
    assert spf["1.1.1.1|2.2.2.2"] == {"ab": 1, "ba": 1}
    assert spf["2.2.2.2|3.3.3.3"] == {"ab": None, "ba": None}


def test_scene_exposes_area_coverage_and_focuses_the_candidates(
    backbone_with_hidden_abr,
):
    diff = TopologyDiff(baseline_available=False)
    report = correlate(backbone_with_hidden_abr)
    diff.findings = [f.to_dict() for f in report.findings]
    diff.area_coverage = report.area_coverage.to_dict()
    scene = scene_for(backbone_with_hidden_abr, diff)
    assert scene["area_coverage"]["complete"] is False
    (finding,) = scene["findings"]
    assert finding["kind"] == AREA_UNPOLLED
    assert finding["focus"] == [
        "10.255.255.10"
    ]  # click the finding -> the ABR lights up


def test_scene_without_coverage_stays_valid():
    g = build([router("1.1.1.1", A0)], [])
    assert scene_for(g)["area_coverage"] is None


def test_rendered_page_has_the_simulation_engine_and_a_filled_scene(
    backbone_with_hidden_abr,
):
    page = render_html(scene_for(backbone_with_hidden_abr))
    assert "/*__SCENE__*/" not in page
    for marker in ("SIM-ENGINE:BEGIN", "SIM-ENGINE:END", 'id="b-sim"', 'id="sim-bar"'):
        assert marker in page
