"""
==============================================================================
Module Name:   test_external_lsa.py
Description:   Type 5 / Type 7 (external) LSAs: parsing, merging, ASBR marking, tracing and cross-checks.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-27
Version:       1.0.0
License:       MIT
==============================================================================
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.correlation import (
    ASBR_UNKNOWN,
    ASBR_UNREACHABLE,
    correlate,
    external_origins,
    trace_prefix,
)
from src.graph_engine import GraphEngine
from src.config import ConfigError
from src.parser import OSPFParser, merge_lsdbs
from src.poller import FilePoller, PollingOptions
from src.vendors import PROFILES
from src.vendors.base import ExternalLsa, Lsdb, ParserError, RouterLsa, SourceDetail

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "vyos"

# --- FRR (VyOS): Type 5 has no area; Type 7 sits under "NSSA-external Link States (Area x [NSSA])"
FRR_TYPE5 = """
       OSPF Router with ID (10.0.0.1)

                AS External Link States

  LS age: 1020
  Options: 0x2  : *|-|-|-|-|-|E|-
  LS Flags: 0x6
  LS Type: AS-external-LSA
  Link State ID: 10.99.0.0 (External Network Number)
  Advertising Router: 10.0.0.3
  LS Seq Number: 80000002
  Checksum: 0x1234
  Length: 36
  Network Mask: /24
        Metric Type: 2 (Larger than any link state path)
        TOS: 0
        Metric: 20
        Forward Address: 0.0.0.0
        External Route Tag: 100

  LS age: 30
  LS Type: AS-external-LSA
  Link State ID: 192.0.2.0 (External Network Number)
  Advertising Router: 10.0.0.3
  LS Seq Number: 80000001
  Network Mask: /24
        Metric Type: 1 (Comparable directly to link state metric)
        Metric: 5
        Forward Address: 10.12.0.2
        External Route Tag: 0
"""
FRR_TYPE7 = """
       OSPF Router with ID (10.0.0.1)

                NSSA-external Link States (Area 0.0.0.1 [NSSA])

  LS age: 30
  LS Type: NSSA-external-LSA
  Link State ID: 172.16.5.0 (External Network Number For NSSA)
  Advertising Router: 10.0.0.2
  LS Seq Number: 80000001
  Network Mask: /24
        Metric Type: 1 (Comparable directly to link state metric)
        Metric: 5
        Forward Address: 0.0.0.0
        External Route Tag: 0
"""
# --- IOS / IOS-XE: "Type-5 AS External Link States", "Type-7 AS External Link States (Area 1)", MTID line
IOS_BOTH = """
            OSPF Router with ID (10.1.1.1) (Process ID 1)

                Type-5 AS External Link States

  Routing Bit Set on this LSA in topology Base with MTID 0
  LS age: 612
  Options: (No TOS-capability, DC, Upward)
  LS Type: AS External Link
  Link State ID: 0.0.0.0 (External Network Number )
  Advertising Router: 10.1.1.9
  LS Seq Number: 80000001
  Checksum: 0x2B64
  Length: 36
  Network Mask: /0
        Metric Type: 2 (Larger than any link state path)
        MTID: 0
        Metric: 1
        Forward Address: 0.0.0.0
        External Route Tag: 1

                Type-7 AS External Link States (Area 1)

  LS age: 44
  Options: (No TOS-capability, Type 7/5 translation, DC, Upward)
  LS Type: AS External Link
  Link State ID: 203.0.113.0 (External Network Number )
  Advertising Router: 10.1.1.8
  LS Seq Number: 80000007
  Network Mask: /24
        Metric Type: 2 (Larger than any link state path)
        MTID: 0
        Metric: 100
        Forward Address: 10.1.1.8
        External Route Tag: 0
"""


def frr() -> OSPFParser:
    return OSPFParser("vyos")


# ------------------------------------------------------------------ parsing
def test_frr_type5_lsas_are_parsed_with_type_metric_tag_and_forwarding_address():
    type5, type7 = frr().parse_external(FRR_TYPE5, "")
    assert type7 == []
    first, second = sorted(type5, key=lambda e: e.prefix)
    assert (first.adv_router, first.prefix, first.metric, first.metric_type) == (
        "10.0.0.3",
        "10.99.0.0/24",
        20,
        "E2",
    )
    assert (first.tag, first.area, first.age, first.forwarding_address) == (
        100,
        None,
        1020,
        "0.0.0.0",
    )
    assert (second.prefix, second.metric_type, second.forwarding_address) == (
        "192.0.2.0/24",
        "E1",
        "10.12.0.2",
    )
    assert not first.is_nssa and first.ip_version == 4


def test_frr_nssa_lsas_are_type7_with_the_area_of_their_header():
    type5, type7 = frr().parse_external("", FRR_TYPE7)
    assert type5 == []
    (lsa,) = type7
    assert (lsa.adv_router, lsa.prefix, lsa.metric_type, lsa.area) == (
        "10.0.0.2",
        "172.16.5.0/24",
        "N1",
        "0.0.0.1",
    )
    assert (
        lsa.is_nssa and lsa.seq == -2147483647
    )  # 0x80000001 as a signed 32-bit number


def test_one_text_holding_both_kinds_is_split_by_its_headers_ios_layout():
    type5, type7 = frr().parse_external(IOS_BOTH, "")
    (default,) = type5
    (nssa,) = type7
    assert (default.prefix, default.metric, default.metric_type, default.tag) == (
        "0.0.0.0/0",
        1,
        "E2",
        1,
    )
    assert (nssa.prefix, nssa.metric_type, nssa.area, nssa.forwarding_address) == (
        "203.0.113.0/24",
        "N2",
        "0.0.0.1",
        "10.1.1.8",
    )


def test_an_incomplete_external_lsa_is_skipped_not_fatal():
    broken = FRR_TYPE5.replace("Advertising Router: 10.0.0.3", "", 1)
    type5, _ = frr().parse_external(broken, "")
    assert [e.prefix for e in type5] == ["192.0.2.0/24"]


def test_empty_external_text_yields_nothing_and_unsupported_platforms_ignore_it():
    assert frr().parse_external("", "  \n") == ([], [])
    huawei = OSPFParser("huawei")  # no external-LSA parser for this platform
    assert huawei.parse_external(FRR_TYPE5, FRR_TYPE7) == ([], [])


def test_only_the_platforms_that_print_the_cisco_layout_have_external_commands():
    with_cmds = {k for k, p in PROFILES.items() if p.external and p.nssa}
    assert with_cmds == {"vyos", "cisco_ios", "cisco_xe", "arista_eos", "aruba_aoscx"}
    assert (
        PROFILES["cisco_ios"].command("external", "7")
        == "show ip ospf 7 database external"
    )
    assert (
        PROFILES["vyos"].command("nssa", None) == "show ip ospf database nssa-external"
    )
    with pytest.raises(ConfigError, match="no 'external' command"):
        PROFILES["juniper_junos"].command("external", None)


# ------------------------------------------------------------------ topology
def sample_text(name: str) -> str:
    return (SAMPLE / name).read_text(encoding="utf-8")


def sample_topology(external: str | None = None) -> dict:
    return frr().parse(
        sample_text("router_lsdb.txt"),
        sample_text("network_lsdb.txt"),
        sample_text("external_lsdb.txt") if external is None else external,
    )


def test_a_router_that_originates_external_lsas_becomes_an_asbr_with_its_prefixes():
    topo = sample_topology()
    nodes = {n["id"]: n for n in topo["nodes"]}
    asbr = nodes["10.0.0.3"]
    assert asbr["is_asbr"] is True
    assert [
        (e["prefix"], e["metric_type"], e["metric"]) for e in asbr["externals"]
    ] == [
        ("0.0.0.0/0", "E2", 1),
        ("172.16.50.0/24", "E1", 20),
    ]
    assert not asbr.get("asbr")  # the router LSA's own E bit is a separate fact
    assert "is_asbr" not in nodes["10.0.0.1"] and "externals" not in nodes["10.0.0.1"]
    meta = topo["metadata"]
    assert (meta["external_lsas"], meta["nssa_lsas"], meta["external_unattached"]) == (
        2,
        0,
        [],
    )
    assert meta["ip_version"] == 4


def test_external_lsas_add_no_node_and_no_link_to_the_topology():
    with_ext, without = sample_topology(), sample_topology(external="")
    assert len(with_ext["nodes"]) == len(without["nodes"])
    assert with_ext["edges"] == without["edges"]
    assert "external_lsas" not in without["metadata"]


def test_an_originator_outside_the_topology_is_reported_not_invented():
    stranger = FRR_TYPE5.replace("10.0.0.3", "10.9.9.9")
    topo = sample_topology(external=stranger)
    assert "10.9.9.9" not in {n["id"] for n in topo["nodes"]}
    assert topo["metadata"]["external_unattached"] == ["10.9.9.9"]
    assert topo["metadata"]["external_lsas"] == 2


def test_external_lsas_that_are_about_to_be_flushed_are_ignored():
    flushing = FRR_TYPE5.replace("LS age: 1020", "LS age: MAXAGE(3600)")
    topo = sample_topology(external=flushing)
    asbr = next(n for n in topo["nodes"] if n["id"] == "10.0.0.3")
    assert [e["prefix"] for e in asbr["externals"]] == ["192.0.2.0/24"]


def test_nssa_lsas_are_counted_separately_and_keep_their_area():
    topo = sample_topology(external="")
    lsdb = frr().parse_lsdb(
        sample_text("router_lsdb.txt"), sample_text("network_lsdb.txt"), "", FRR_TYPE7
    )
    topo = OSPFParser.build_topology(lsdb, {"device_type": "vyos"})
    node = next(n for n in topo["nodes"] if n["id"] == "10.0.0.2")
    assert node["is_asbr"] and node["externals"][0]["area"] == "0.0.0.1"
    assert node["externals"][0]["metric_type"] == "N1"
    assert (topo["metadata"]["external_lsas"], topo["metadata"]["nssa_lsas"]) == (0, 1)


def test_unreadable_external_text_never_fails_the_router_and_network_parse():
    topo = sample_topology(external="this is not an LSDB\n")
    assert len(topo["nodes"]) == 4 and "external_lsas" not in topo["metadata"]


# -------------------------------------------------------------------- merge
def ext(adv, prefix, *, seq=1, age=10, metric=20, mtype="E2", area=None):
    return ExternalLsa(adv, prefix, metric, mtype, area=area, age=age, seq=seq)


def lsdb(**kw) -> Lsdb:
    return Lsdb(router_lsas=[RouterLsa("10.0.0.1", "0.0.0.0")], **kw)


def test_merge_unions_external_lsas_and_keeps_the_newer_copy():
    a = lsdb(external_lsas=[ext("10.0.0.3", "10.1.0.0/16", seq=5, metric=10)])
    b = lsdb(
        external_lsas=[
            ext("10.0.0.3", "10.1.0.0/16", seq=9, metric=77),
            ext("10.0.0.4", "10.1.0.0/16"),
        ]
    )
    merged = merge_lsdbs([a, b])
    by_key = {(e.adv_router, e.prefix): e for e in merged.external_lsas}
    assert set(by_key) == {("10.0.0.3", "10.1.0.0/16"), ("10.0.0.4", "10.1.0.0/16")}
    assert (
        by_key[("10.0.0.3", "10.1.0.0/16")].metric == 77
    )  # the higher sequence number won


def test_with_equal_sequence_numbers_the_younger_lsa_wins():
    a = lsdb(external_lsas=[ext("10.0.0.3", "10.1.0.0/16", seq=5, age=900, metric=1)])
    b = lsdb(external_lsas=[ext("10.0.0.3", "10.1.0.0/16", seq=5, age=20, metric=2)])
    (kept,) = merge_lsdbs([a, b]).external_lsas
    assert kept.metric == 2


def test_a_type7_lsa_is_identified_by_its_area_as_well():
    a = lsdb(nssa_lsas=[ext("10.0.0.2", "172.16.0.0/16", mtype="N2", area="0.0.0.1")])
    b = lsdb(
        nssa_lsas=[
            ext(
                "10.0.0.2", "172.16.0.0/16", mtype="N2", area="1"
            ),  # same area, other spelling
            ext("10.0.0.2", "172.16.0.0/16", mtype="N2", area="0.0.0.2"),
        ]
    )
    merged = merge_lsdbs([a, b])
    assert sorted(e.area for e in merged.nssa_lsas) == ["0.0.0.1", "0.0.0.2"]


def test_merge_refuses_to_mix_ospfv2_and_ospfv3_databases():
    with pytest.raises(ParserError, match="OSPFv2"):
        merge_lsdbs([lsdb(), lsdb(ip_version=6)])
    assert merge_lsdbs([lsdb(ip_version=6), lsdb(ip_version=6)]).ip_version == 6


def test_ipv6_prefixes_are_understood_by_the_model_and_the_merge():
    v6 = ext("10.0.0.3", "2001:db8:10::/48")
    assert v6.ip_version == 6
    merged = merge_lsdbs(
        [lsdb(ip_version=6, external_lsas=[v6]), lsdb(ip_version=6, external_lsas=[v6])]
    )
    assert [e.prefix for e in merged.external_lsas] == ["2001:db8:10::/48"]


# ------------------------------------------------------------------- poller
def test_the_file_poller_reads_the_optional_external_files(tmp_path):
    for name in ("router_lsdb.txt", "network_lsdb.txt", "external_lsdb.txt"):
        (tmp_path / name).write_text(sample_text(name), encoding="utf-8")
    (tmp_path / FilePoller.NSSA_FILE).write_text(FRR_TYPE7, encoding="utf-8")
    raw = FilePoller(tmp_path).poll()
    assert "AS External" in raw.external and "NSSA-external" in raw.nssa
    (tmp_path / "external_lsdb.txt").unlink()
    (tmp_path / FilePoller.NSSA_FILE).unlink()
    quiet = FilePoller(tmp_path).poll()
    assert (quiet.external, quiet.nssa) == ("", "")


def test_collecting_external_lsas_is_opt_in():
    assert PollingOptions.from_settings({}).external is False
    assert PollingOptions.from_settings(None).external is False
    assert PollingOptions.from_settings({"external": True}).external is True


# -------------------------------------------------------- tracing and checks
def graph_with_externals():
    return GraphEngine(data_dir="/nonexistent").build_graph(sample_topology())


def test_the_external_index_lists_every_asbr_per_prefix():
    index = external_origins(graph_with_externals())
    assert sorted(index) == ["0.0.0.0/0", "172.16.50.0/24"]
    (origin,) = index["172.16.50.0/24"]
    assert (origin["node"], origin["metric_type"], origin["metric"]) == (
        "10.0.0.3",
        "E1",
        20,
    )


def test_a_type1_external_costs_the_path_to_the_asbr_plus_its_metric():
    result = trace_prefix(graph_with_externals(), [], "172.16.50.9", "10.0.0.1")
    assert result.prefix == "172.16.50.0/24"
    assert result.spf_cost == 1 + 20  # R1 reaches R3 over the shared segment at cost 1
    assert (
        result.paths
        and result.paths[0][0] == "10.0.0.1"
        and result.paths[0][-1] == "10.0.0.3"
    )
    (entry,) = result.externals
    assert (
        entry["asbr"],
        entry["cost_to_asbr"],
        entry["total_cost"],
        entry["selected"],
    ) == (
        "10.0.0.3",
        1,
        21,
        True,
    )
    assert result.verdict == "external route in LSDB"  # no routing table was collected


def test_a_type2_external_costs_only_its_metric_and_a_default_route_catches_the_rest():
    result = trace_prefix(graph_with_externals(), [], "8.8.8.8", "10.0.0.1")
    assert result.prefix == "0.0.0.0/0" and result.spf_cost == 1
    assert result.externals[0]["metric_type"] == "E2"


def test_an_internal_route_of_the_same_length_beats_an_external_one():
    graph = graph_with_externals()
    # 192.168.1.0/24 is a transit network of the topology; advertise it again as an external route.
    graph.nodes["10.0.0.3"]["externals"].append(
        {
            "prefix": "192.168.1.0/24",
            "metric": 1,
            "metric_type": "E1",
            "forwarding_address": "0.0.0.0",
            "tag": 0,
            "area": None,
            "age": 1,
        }
    )
    result = trace_prefix(graph, [], "192.168.1.77", "10.0.0.1")
    assert result.externals == [] and result.prefix == "192.168.1.0/24"


def test_type1_beats_type2_and_equal_total_costs_are_equal_cost_alternatives():
    graph = graph_with_externals()
    graph.nodes["10.0.0.2"]["is_asbr"] = True
    graph.nodes["10.0.0.2"]["externals"] = [
        {
            "prefix": "172.16.50.0/24",
            "metric": 1,
            "metric_type": "E2",
            "forwarding_address": "0.0.0.0",
            "tag": 0,
            "area": None,
            "age": 1,
        }
    ]
    result = trace_prefix(graph, [], "172.16.50.1", "10.0.0.1")
    chosen = {e["asbr"] for e in result.externals if e["selected"]}
    assert chosen == {"10.0.0.3"}  # E1 wins over E2 whatever the cost


def test_an_unreachable_asbr_is_named_in_the_verdict():
    graph = graph_with_externals()
    graph.remove_edges_from([e for e in list(graph.edges) if "10.0.0.3" in e])
    result = trace_prefix(graph, [], "172.16.50.9", "10.0.0.1")
    assert result.verdict == "ASBR unreachable in LSDB" and result.paths == []


def test_a_forwarding_address_is_called_out_in_the_notes():
    graph = GraphEngine(data_dir="/nonexistent").build_graph(
        sample_topology(external=FRR_TYPE5)
    )
    result = trace_prefix(graph, [], "192.0.2.9", "10.0.0.1")
    assert any("forwarding address 10.12.0.2" in note for note in result.notes)


def detail(router: str) -> SourceDetail:
    return SourceDetail(name=router, router_id=router)


def test_an_asbr_no_polled_router_can_reach_is_a_warning():
    graph = graph_with_externals()
    graph.remove_edges_from([e for e in list(graph.edges) if "10.0.0.3" in e])
    report = correlate(graph, [detail("10.0.0.1")])
    hits = [f for f in report.findings if f.kind == ASBR_UNREACHABLE]
    assert [(f.router, f.subject, f.severity) for f in hits] == [
        ("10.0.0.1", "10.0.0.3", "warning")
    ]


def test_an_originator_without_a_router_lsa_is_an_info_finding():
    topo = sample_topology(external=FRR_TYPE5.replace("10.0.0.3", "10.9.9.9"))
    report = correlate(GraphEngine(data_dir="/nonexistent").build_graph(topo), [])
    assert [
        (f.kind, f.subject, f.severity)
        for f in report.findings
        if f.kind == ASBR_UNKNOWN
    ] == [(ASBR_UNKNOWN, "10.9.9.9", "info")]


def test_a_healthy_topology_has_no_asbr_findings():
    report = correlate(graph_with_externals(), [detail("10.0.0.1")])
    assert not [
        f for f in report.findings if f.kind in (ASBR_UNKNOWN, ASBR_UNREACHABLE)
    ]
