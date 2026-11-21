"""Unit tests for RFC 6987 Max-Metric Stub Router detection, correlation, and visualization."""

from __future__ import annotations

from src.correlation import INFO, ROUTER_MAX_METRIC, correlate
from src.explorer import build_scene
from src.graph_engine import GraphEngine, TopologyDiff
from src.parser import OSPFParser
from src.vendors.base import (
    KIND_P2P,
    KIND_STUB,
    KIND_TRANSIT,
    MAX_METRIC_VALUE,
    LinkRecord,
    Lsdb,
    RouterLsa,
    is_max_metric_lsa,
)
from src.visualizer import TopologyVisualizer


def test_rfc6987_max_metric_ignores_stub_links() -> None:
    lsa = RouterLsa(
        router_id="10.0.0.1",
        area="0.0.0.0",
        links=[
            LinkRecord(kind=KIND_P2P, link_id="10.0.0.2", metric=MAX_METRIC_VALUE, link_data="10.1.0.1"),
            LinkRecord(kind=KIND_TRANSIT, link_id="10.1.1.1", metric=65535, link_data="10.1.1.2"),
            LinkRecord(kind=KIND_STUB, link_id="10.99.0.0", metric=1, link_data="255.255.255.0"),
        ],
    )
    assert is_max_metric_lsa(lsa) is True


def test_stub_only_router_is_not_max_metric() -> None:
    lsa = RouterLsa(
        router_id="10.0.0.9",
        area="0.0.0.0",
        links=[
            LinkRecord(kind=KIND_STUB, link_id="10.9.0.0", metric=65535, link_data="255.255.255.0"),
        ],
    )
    assert is_max_metric_lsa(lsa) is False


def test_partial_area_drain_on_abr() -> None:
    lsdb = Lsdb(
        router_lsas=[
            RouterLsa(
                router_id="10.0.0.1",
                area="0.0.0.0",
                abr=True,
                links=[
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.2", metric=10, link_data="10.0.12.1"),
                    LinkRecord(kind=KIND_STUB, link_id="10.0.12.0", metric=10, link_data="255.255.255.252"),
                ],
            ),
            RouterLsa(
                router_id="10.0.0.1",
                area="0.0.0.1",
                abr=True,
                links=[
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.3", metric=65535, link_data="10.1.13.1"),
                    LinkRecord(kind=KIND_STUB, link_id="10.1.13.0", metric=1, link_data="255.255.255.252"),
                ],
            ),
            RouterLsa(
                router_id="10.0.0.2",
                area="0.0.0.0",
                links=[
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.1", metric=10, link_data="10.0.12.2"),
                ],
            ),
            RouterLsa(
                router_id="10.0.0.3",
                area="0.0.0.1",
                links=[
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.1", metric=10, link_data="10.1.13.3"),
                ],
            ),
        ]
    )
    parsed = OSPFParser.build_topology(lsdb)
    nodes = {n["id"]: n for n in parsed["nodes"]}
    assert nodes["10.0.0.1"]["max_metric"] is True
    assert nodes["10.0.0.1"]["max_metric_areas"] == ["0.0.0.1"]
    assert not nodes["10.0.0.2"].get("max_metric")


def test_correlation_emits_router_max_metric_info_finding(tmp_path) -> None:
    lsdb = Lsdb(
        router_lsas=[
            RouterLsa(
                router_id="10.0.0.1",
                area="0.0.0.0",
                links=[
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.2", metric=65535, link_data="10.0.12.1"),
                ],
            ),
            RouterLsa(
                router_id="10.0.0.2",
                area="0.0.0.0",
                links=[
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.1", metric=10, link_data="10.0.12.2"),
                ],
            ),
        ]
    )
    parsed = OSPFParser.build_topology(lsdb)
    graph = GraphEngine(data_dir=tmp_path).build_graph(parsed)
    report = correlate(graph)

    mm_findings = [f for f in report.findings if f.kind == ROUTER_MAX_METRIC]
    assert len(mm_findings) == 1
    finding = mm_findings[0]
    assert finding.severity == INFO
    assert finding.router == "10.0.0.1"
    assert finding.subject == "10.0.0.1"
    assert "max-metric" in finding.message.lower()

    dot = TopologyVisualizer().build_digraph(graph, TopologyDiff()).source
    assert "MAX-METRIC" in dot

    scene = build_scene(graph, TopologyDiff())
    s_nodes = {n["id"]: n for n in scene["nodes"]}
    assert s_nodes["10.0.0.1"]["max_metric"] is True
    assert s_nodes["10.0.0.1"]["max_metric_areas"] == ["0.0.0.0"]
    assert "MAX-METRIC" in s_nodes["10.0.0.1"]["sub"]
