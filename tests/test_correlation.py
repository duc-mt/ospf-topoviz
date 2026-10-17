"""Correlation engine: SPF, LSDB vs neighbour table, neighbour flaps, SPF vs routing table, prefix trace."""

from __future__ import annotations

import pytest

from src.correlation import (
    ADJ_MISSING,
    ADJ_NOT_FULL,
    COST_MISMATCH,
    ECMP_MISSING,
    NBR_LOST,
    NBR_NEW,
    NBR_NOT_IN_LSDB,
    NBR_STATE_CHANGE,
    NEXTHOP_DOWN,
    NEXTHOP_MISMATCH,
    RIB_EMPTY,
    ROUTE_MISSING,
    ROUTE_OVERRIDDEN,
    ROUTE_STALE,
    correlate,
    flap_findings,
    neighbor_findings,
    spf,
    trace_prefix,
)
from src.graph_engine import GraphEngine
from src.parser import OSPFParser
from src.vendors.base import (
    KIND_P2P,
    KIND_STUB,
    KIND_TRANSIT,
    LinkRecord,
    Lsdb,
    NeighborRecord,
    NetworkLsa,
    NextHop,
    OSPFRoute,
    RouterLsa,
    SourceDetail,
)

A, B, C, D = "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"
AREA0, AREA1 = "0.0.0.0", "0.0.0.1"


def p2p(neighbor, own_ip, metric):
    return LinkRecord(kind=KIND_P2P, link_id=neighbor, link_data=own_ip, metric=metric)


def stub(prefix, mask, metric):
    return LinkRecord(kind=KIND_STUB, link_id=prefix, link_data=mask, metric=metric)


def router(rid, links, area=AREA0, abr=False):
    return RouterLsa(
        router_id=rid, area=area, links=links, seq=-2147483645, age=10, abr=abr
    )


def square(extra_d_stub=True):
    """A--B, A--C, B--D, C--D (cost 10 each). D also advertises 10.9.0.0/24 (cost 5): two equal paths A->D."""
    d_links = [
        p2p(B, "10.2.4.4", 10),
        p2p(C, "10.3.4.4", 10),
        stub("10.0.0.4", "255.255.255.255", 1),
        stub("10.2.4.0", "255.255.255.0", 10),
        stub("10.3.4.0", "255.255.255.0", 10),
    ]
    if extra_d_stub:
        d_links.append(stub("10.9.0.0", "255.255.255.0", 5))
    return Lsdb(
        router_lsas=[
            router(
                A,
                [
                    p2p(B, "10.1.2.1", 10),
                    p2p(C, "10.1.3.1", 10),
                    stub("10.0.0.1", "255.255.255.255", 1),
                    stub("10.1.2.0", "255.255.255.0", 10),
                    stub("10.1.3.0", "255.255.255.0", 10),
                ],
            ),
            router(
                B,
                [
                    p2p(A, "10.1.2.2", 10),
                    p2p(D, "10.2.4.2", 10),
                    stub("10.0.0.2", "255.255.255.255", 1),
                    stub("10.1.2.0", "255.255.255.0", 10),
                    stub("10.2.4.0", "255.255.255.0", 10),
                ],
            ),
            router(
                C,
                [
                    p2p(A, "10.1.3.3", 10),
                    p2p(D, "10.3.4.3", 10),
                    stub("10.0.0.3", "255.255.255.255", 1),
                    stub("10.1.3.0", "255.255.255.0", 10),
                    stub("10.3.4.0", "255.255.255.0", 10),
                ],
            ),
            router(D, d_links),
        ],
        network_lsas=[],
        process_ids=["1"],
        router_id=A,
    )


def graph_of(lsdb, details=()):
    return GraphEngine.__new__(GraphEngine).build_graph(
        OSPFParser.build_topology(lsdb, details=list(details))
    )


def nbr(rid, state="Full", role=None, interface=None, address=None, **kw):
    return NeighborRecord(
        router_id=rid,
        state=state,
        role=role,
        interface=interface,
        address=address,
        **kw,
    )


def route(cidr, metric, via, rtype="Intra-Area", **kw):
    hops = [NextHop(ip, iface) for ip, iface in via]
    return OSPFRoute.from_cidr(
        cidr, rtype, metric=metric, distance=110, next_hops=hops, **kw
    )


B_HOP = ("10.1.2.2", "eth1")  # A's next hop towards B
C_HOP = ("10.1.3.3", "eth2")  # A's next hop towards C


def healthy_rib():
    """What router A's OSPF routing table should hold for square()."""
    return [
        route("10.0.0.2/32", 11, [B_HOP]),
        route("10.0.0.3/32", 11, [C_HOP]),
        route("10.0.0.4/32", 21, [B_HOP, C_HOP]),
        route("10.2.4.0/24", 20, [B_HOP]),
        route("10.3.4.0/24", 20, [C_HOP]),
        route("10.9.0.0/24", 25, [B_HOP, C_HOP]),
    ]


def detail_a(routes=None, neighbors=None):
    nbrs = (
        [
            nbr(B, interface="eth1", address="10.1.2.2"),
            nbr(C, interface="eth2", address="10.1.3.3"),
        ]
        if neighbors is None
        else neighbors
    )
    return SourceDetail("A", A, nbrs, healthy_rib() if routes is None else routes)


def kinds(findings):
    return sorted(f.kind for f in findings)


# ===================================================================== SPF
def test_spf_costs_and_equal_cost_first_hops():
    g = graph_of(square())
    tree = spf(g, A)
    assert tree.dist == {A: 0, B: 10, C: 10, D: 20}
    assert tree.first_hops[D] == {B, C}  # two equal-cost paths
    assert tree.first_hops[B] == {B}
    paths = tree.paths(D)
    assert sorted(paths) == [[A, B, D], [A, C, D]]


def test_spf_prefers_the_cheaper_path():
    lsdb = square()
    lsdb.router_lsas[0].links[0] = p2p(B, "10.1.2.1", 5)  # A->B now cheap
    lsdb.router_lsas[1].links[0] = p2p(A, "10.1.2.2", 5)
    tree = spf(graph_of(lsdb), A)
    assert tree.dist[D] == 15 and tree.first_hops[D] == {B}


def test_spf_ignores_a_one_way_link():
    lsdb = square()
    lsdb.router_lsas[1].links = [
        lk
        for lk in lsdb.router_lsas[1].links
        if not (lk.kind == KIND_P2P and lk.link_id == A)
    ]
    g = graph_of(lsdb)
    assert g.edges[A, B]["link_state"] == "one-way"
    tree = spf(g, A)
    assert tree.dist[B] == 30  # only reachable round the other way: A -> C -> D -> B
    assert tree.first_hops[B] == {C}


def test_spf_can_be_limited_to_one_area():
    """Intra-area routes are calculated per area: the area-0 walk must not cross into area 1's links."""
    lsdb = Lsdb(
        router_lsas=[
            router(A, [p2p(B, "10.1.2.1", 10)]),
            router(B, [p2p(A, "10.1.2.2", 10)], abr=True),
            router(B, [p2p("10.0.0.5", "10.2.5.2", 10)], area=AREA1, abr=True),
            router("10.0.0.5", [p2p(B, "10.2.5.5", 10)], area=AREA1),
        ],
        network_lsas=[],
        process_ids=[],
        router_id=A,
    )
    g = graph_of(lsdb)
    assert (
        spf(g, A).dist["10.0.0.5"] == 20
    )  # the whole graph reaches it through the ABR
    assert "10.0.0.5" not in spf(g, A, AREA0).dist  # the area-0 walk does not
    assert spf(g, A, AREA0).dist[B] == 10


def test_spf_through_a_transit_network():
    lsdb = Lsdb(
        router_lsas=[
            router(
                A,
                [
                    LinkRecord(
                        kind=KIND_TRANSIT,
                        link_id="192.168.1.2",
                        link_data="192.168.1.1",
                        metric=4,
                    )
                ],
            ),
            router(
                B,
                [
                    LinkRecord(
                        kind=KIND_TRANSIT,
                        link_id="192.168.1.2",
                        link_data="192.168.1.2",
                        metric=6,
                    ),
                    stub("10.0.0.2", "255.255.255.255", 1),
                ],
            ),
        ],
        network_lsas=[
            NetworkLsa(
                address="192.168.1.2",
                dr=B,
                area=AREA0,
                mask="255.255.255.0",
                attached=[A, B],
                seq=-2147483645,
                age=10,
            )
        ],
        process_ids=[],
        router_id=A,
    )
    g = graph_of(lsdb)
    tree = spf(g, A)
    assert tree.dist[B] == 4  # A -> segment (4), segment -> B (0)
    assert tree.first_hops[B] == {
        B
    }  # the segment is looked through: the first hop is router B


# ============================================== neighbour table vs LSDB
def test_matching_neighbor_table_has_no_findings():
    assert neighbor_findings(graph_of(square()), detail_a()) == []


@pytest.mark.parametrize(
    "state, severity, hint",
    [
        ("ExStart", "critical", "MTU"),
        ("Exchange", "critical", "MTU"),
        ("Init", "critical", "one way"),
        ("Down", "critical", "no hellos"),
        ("Loading", "warning", "LSAs"),
    ],
)
def test_lsdb_adjacency_with_a_stuck_neighbor(state, severity, hint):
    detail = detail_a(
        neighbors=[nbr(B, state, interface="eth1"), nbr(C, interface="eth2")]
    )
    [f] = neighbor_findings(graph_of(square()), detail)
    assert (f.kind, f.severity, f.router, f.subject) == (ADJ_NOT_FULL, severity, A, B)
    assert state in f.message and "eth1" in f.message and hint in f.hint


def test_lsdb_adjacency_with_a_neighbor_missing_from_the_table():
    detail = detail_a(neighbors=[nbr(C, interface="eth2")])
    [f] = neighbor_findings(graph_of(square()), detail)
    assert (f.kind, f.subject, f.severity) == (ADJ_MISSING, B, "warning")


def test_full_neighbor_the_lsdb_does_not_know_about():
    detail = detail_a(neighbors=[nbr(B), nbr(C), nbr("10.0.0.99", interface="eth9")])
    [f] = neighbor_findings(graph_of(square()), detail)
    assert (f.kind, f.subject) == (NBR_NOT_IN_LSDB, "10.0.0.99") and "eth9" in f.message


def test_a_neighbor_that_is_down_and_unknown_to_the_lsdb_is_not_reported_twice():
    detail = detail_a(neighbors=[nbr(B), nbr(C), nbr("10.0.0.99", "Init")])
    assert (
        neighbor_findings(graph_of(square()), detail) == []
    )  # the data-quality table already shows stuck non-LSDB neighbours


def test_neighbor_table_not_collected_means_no_judgement():
    detail = SourceDetail("A", A, [], None, neighbors_known=False)
    assert neighbor_findings(graph_of(square()), detail) == []


def shared_segment():
    """A (DR), B and C on one segment: B and C are DROthers."""

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
    return graph_of(lsdb)


def test_two_way_between_two_drothers_is_normal():
    detail = SourceDetail(
        "B", B, [nbr(A, "Full", "DR"), nbr(C, "2-Way", "DROther")], None
    )
    assert neighbor_findings(shared_segment(), detail) == []


def test_two_way_with_the_dr_is_a_problem():
    detail = SourceDetail(
        "B", B, [nbr(A, "2-Way", "DR"), nbr(C, "2-Way", "DROther")], None
    )
    [f] = neighbor_findings(shared_segment(), detail)
    assert (f.kind, f.subject) == (ADJ_NOT_FULL, A)


def test_a_dr_must_be_full_with_everyone():
    detail = SourceDetail("A", A, [nbr(B, "Full"), nbr(C, "2-Way")], None)
    [f] = neighbor_findings(shared_segment(), detail)
    assert (f.kind, f.subject) == (ADJ_NOT_FULL, C)


def test_segment_neighbor_missing_from_the_table():
    detail = SourceDetail("B", B, [nbr(A, "Full", "DR")], None)
    [f] = neighbor_findings(shared_segment(), detail)
    assert (f.kind, f.subject) == (ADJ_MISSING, C)


# ============================================================ flap detection
def row(router_id, neighbor, state, interface="eth1"):
    return {
        "router": router_id,
        "neighbor": neighbor,
        "state": state,
        "interface": interface,
    }


def test_no_previous_snapshot_means_no_flaps():
    assert flap_findings([row(A, B, "Full")], None) == []
    assert flap_findings([row(A, B, "Full")], []) == []


def test_unchanged_neighbors_are_quiet():
    assert flap_findings([row(A, B, "Full")], [row(A, B, "Full")]) == []


def test_full_to_init_is_a_critical_state_change():
    [f] = flap_findings([row(A, B, "Init")], [row(A, B, "Full")])
    assert (f.kind, f.severity) == (NBR_STATE_CHANGE, "critical")
    assert "Full -> Init" in f.message and f.data["previous"] == "Full"


def test_recovery_is_info():
    [f] = flap_findings([row(A, B, "Full")], [row(A, B, "ExStart")])
    assert (f.kind, f.severity, f.hint) == (NBR_STATE_CHANGE, "info", "recovered")


def test_a_lost_full_neighbor_is_critical_and_a_new_one_is_info():
    lost = flap_findings([row(A, C, "Full")], [row(A, B, "Full"), row(A, C, "Full")])
    assert [(f.kind, f.severity, f.subject) for f in lost] == [
        (NBR_LOST, "critical", B)
    ]
    new = flap_findings([row(A, B, "Full"), row(A, C, "Full")], [row(A, B, "Full")])
    assert [(f.kind, f.severity, f.subject) for f in new] == [(NBR_NEW, "info", C)]


def test_only_routers_polled_in_both_runs_are_compared():
    """A seed that was not polled this time must not look like all its neighbours vanished."""
    assert (
        flap_findings([row(A, B, "Full")], [row(A, B, "Full"), row(C, D, "Full")]) == []
    )


def test_parallel_adjacencies_are_told_apart_by_interface():
    now = [row(A, B, "Full", "eth1"), row(A, B, "Init", "eth2")]
    before = [row(A, B, "Full", "eth1"), row(A, B, "Full", "eth2")]
    [f] = flap_findings(now, before)
    assert f.data["interface"] == "eth2"


# ============================================================ SPF vs the RIB
def run(routes=None, neighbors=None, lsdb=None):
    graph = graph_of(lsdb or square())
    report = correlate(graph, [detail_a(routes, neighbors)])
    return report


def test_a_healthy_rib_is_fully_consistent():
    report = run()
    assert report.findings == []
    [check] = report.rib_checks
    assert (
        check["router"],
        check["routes"],
        check["expected"],
        check["verified"],
        check["ok"],
    ) == (A, 6, 6, 6, 6)
    assert check["unverified"] == 0


def test_a_prefix_the_lsdb_advertises_but_the_rib_lacks_is_a_blackhole():
    report = run([r for r in healthy_rib() if r.cidr != "10.9.0.0/24"])
    [f] = report.findings
    assert (f.kind, f.severity, f.subject) == (ROUTE_MISSING, "critical", "10.9.0.0/24")
    assert D in f.message and "25" in f.message and "distribute-list" in f.hint
    [check] = report.rib_checks
    assert check["expected"] - check["verified"] == 1


def test_own_and_attached_prefixes_are_not_expected_in_the_ospf_rib():
    """A's loopback and the subnets it sits on are Connected routes, so they are never 'missing'."""
    assert all(
        f.subject not in ("10.0.0.1/32", "10.1.2.0/24", "10.1.3.0/24")
        for f in run().findings
    )


def test_route_listed_but_not_active_is_overridden():
    rib = healthy_rib()
    rib[5].active = False
    [f] = run(rib).findings
    assert (f.kind, f.subject) == (
        ROUTE_OVERRIDDEN,
        "10.9.0.0/24",
    ) and "distance" in f.hint


def test_a_higher_rib_cost_than_spf_is_flagged():
    rib = healthy_rib()
    rib[5].metric = 35
    [f] = run(rib).findings
    assert (f.kind, f.severity) == (
        COST_MISMATCH,
        "info",
    )  # a longer path than SPF finds still forwards packets
    assert f.data == {"rib_cost": 35, "spf_cost": 25}


def test_cost_is_only_checked_for_internal_route_types():
    rib = healthy_rib()
    rib[5].metric, rib[5].route_type = 99, "E2"
    assert run(rib).findings == []


def test_next_hop_off_the_shortest_path():
    lsdb = square()
    lsdb.router_lsas[0].links[0] = p2p(
        B, "10.1.2.1", 5
    )  # A->B cheap: B is now the only shortest way to D
    lsdb.router_lsas[1].links[0] = p2p(A, "10.1.2.2", 5)
    rib = [
        route("10.0.0.2/32", 6, [B_HOP]),
        route("10.0.0.3/32", 11, [C_HOP]),
        route("10.0.0.4/32", 16, [C_HOP]),  # wrong: goes via C
        route("10.2.4.0/24", 15, [B_HOP]),
        route("10.3.4.0/24", 20, [C_HOP]),
        route("10.9.0.0/24", 20, [B_HOP]),
    ]
    findings = run(rib, lsdb=lsdb).findings
    bad = [f for f in findings if f.kind == NEXTHOP_MISMATCH]
    assert [f.subject for f in bad] == ["10.0.0.4/32"] and B in bad[0].message


def test_equal_cost_path_missing_from_the_rib():
    rib = healthy_rib()
    rib[5] = route("10.9.0.0/24", 25, [B_HOP])  # SPF: via B and via C
    [f] = run(rib).findings
    assert (f.kind, f.subject) == (ECMP_MISSING, "10.9.0.0/24")
    assert f.data == {"rib": [B], "spf": [B, C]} and "maximum-paths" in f.hint


def test_route_via_a_neighbor_that_is_not_full_is_a_blackhole():
    rib = healthy_rib()
    nbrs = [
        nbr(B, "ExStart", interface="eth1", address="10.1.2.2"),
        nbr(C, interface="eth2", address="10.1.3.3"),
    ]
    findings = run(rib, nbrs).findings
    down = {f.subject: f for f in findings if f.kind == NEXTHOP_DOWN}
    # routes whose only next hop is B are blackholed; ECMP routes lose just their share of the traffic
    assert {s for s, f in down.items() if f.severity == "critical"} == {
        "10.0.0.2/32",
        "10.2.4.0/24",
    }
    assert {s for s, f in down.items() if f.severity == "warning"} == {
        "10.0.0.4/32",
        "10.9.0.0/24",
    }
    assert (
        down["10.0.0.2/32"].data["states"] == {B: "ExStart"}
        and "1 of 2" in down["10.9.0.0/24"].message
    )
    assert any(
        f.kind == ADJ_NOT_FULL for f in findings
    )  # and the adjacency itself is reported


def test_an_intra_area_route_no_lsa_advertises_is_stale():
    rib = healthy_rib() + [route("172.31.0.0/24", 10, [B_HOP])]
    [f] = run(rib).findings
    assert (f.kind, f.subject) == (ROUTE_STALE, "172.31.0.0/24")


def test_inter_area_and_external_routes_are_unverified_not_wrong():
    rib = healthy_rib() + [
        route("172.31.0.0/24", 10, [B_HOP], "Inter-Area"),
        route("0.0.0.0/0", 1, [B_HOP], "E2"),
    ]
    report = run(rib)
    assert report.findings == []
    assert report.rib_checks[0]["unverified"] == 2


def test_an_empty_rib_is_one_finding_not_one_per_prefix():
    [f] = run([]).findings
    assert (f.kind, f.severity) == (RIB_EMPTY, "warning") and "6" in f.message


def test_no_routing_table_collected_means_no_route_findings_and_no_check():
    report = correlate(
        graph_of(square()), [SourceDetail("A", A, [nbr(B), nbr(C)], None)]
    )
    assert report.findings == [] and report.rib_checks == []


def test_next_hops_that_cannot_be_matched_to_a_router_are_not_judged():
    rib = healthy_rib()
    rib[5] = route("10.9.0.0/24", 25, [("172.20.0.1", "eth7")])
    assert run(rib).findings == []


def test_prefixes_of_another_area_are_not_expected_from_a_seed_that_is_not_in_it():
    """A (area 0 only) does not have to hold E's area-1 prefix: summarisation or filtering may legitimately hide it."""
    lsdb = Lsdb(
        router_lsas=[
            router(A, [p2p(B, "10.1.2.1", 10), stub("10.0.0.1", "255.255.255.255", 1)]),
            router(
                B,
                [p2p(A, "10.1.2.2", 10), stub("10.0.0.2", "255.255.255.255", 1)],
                abr=True,
            ),
            router(
                B,
                [
                    p2p("10.0.0.5", "10.2.5.2", 10),
                    stub("10.60.0.0", "255.255.255.0", 5),
                ],
                area=AREA1,
                abr=True,
            ),
            router(
                "10.0.0.5",
                [p2p(B, "10.2.5.5", 10), stub("10.50.0.0", "255.255.255.0", 5)],
                area=AREA1,
            ),
        ],
        network_lsas=[],
        process_ids=[],
        router_id=A,
    )
    graph = graph_of(lsdb)
    rib = [route("10.0.0.2/32", 11, [B_HOP])]
    report = correlate(
        graph,
        [SourceDetail("A", A, [nbr(B, interface="eth1", address="10.1.2.2")], rib)],
    )
    assert report.findings == []
    assert (
        report.rib_checks[0]["expected"] == 1
    )  # only B's loopback: not E's prefix, nor the ABR's own area-1 prefix


def test_findings_are_sorted_most_severe_first_and_serialisable():
    rib = [r for r in healthy_rib() if r.cidr != "10.9.0.0/24"]
    rib[0].metric = 50
    report = run(rib, [nbr(B, "ExStart", interface="eth1"), nbr(C, interface="eth2")])
    severities = [f.severity for f in report.findings]
    assert severities == sorted(severities, key=["critical", "warning", "info"].index)
    assert all(isinstance(f.to_dict()["data"], dict) for f in report.findings)


def test_correlate_adds_neighbor_flaps_from_the_baseline():
    base = graph_of(square(), [detail_a()])
    now = graph_of(
        square(),
        [
            detail_a(
                neighbors=[
                    nbr(B, "Init", interface="eth1", address="10.1.2.2"),
                    nbr(C, interface="eth2", address="10.1.3.3"),
                ]
            )
        ],
    )
    report = correlate(
        now,
        [
            detail_a(
                neighbors=[
                    nbr(B, "Init", interface="eth1", address="10.1.2.2"),
                    nbr(C, interface="eth2", address="10.1.3.3"),
                ]
            )
        ],
        base,
    )
    assert NBR_STATE_CHANGE in kinds(report.findings) and ADJ_NOT_FULL in kinds(
        report.findings
    )


def test_nothing_polled_beyond_the_lsdb_means_nothing_to_correlate():
    assert correlate(graph_of(square()), []).findings == []


# ================================================================ prefix trace
def trace(target, **kw):
    graph = graph_of(square())
    return trace_prefix(graph, [detail_a()], target, **kw), graph


def test_trace_follows_the_rib_entry_and_the_lsdb_path():
    t, _ = trace("10.9.0.7")
    assert t.prefix == "10.9.0.0/24" and t.source == A
    assert t.spf_cost == 25 and t.verdict == "RIB and LSDB agree"
    assert [h["router"] for h in t.rib["next_hops"]] == [B, C]
    assert sorted(t.paths) == [[A, B, D], [A, C, D]]
    assert t.origins[0]["node"] == D
    assert t.edges == {
        frozenset((A, B)),
        frozenset((B, D)),
        frozenset((A, C)),
        frozenset((C, D)),
    }


def test_trace_accepts_a_prefix_too():
    t, _ = trace("10.9.0.0/24")
    assert t.prefix == "10.9.0.0/24" and t.verdict == "RIB and LSDB agree"


def test_trace_uses_the_longest_matching_prefix():
    graph = graph_of(square())
    rib = healthy_rib() + [route("10.9.0.0/16", 99, [B_HOP], "Inter-Area")]
    t = trace_prefix(graph, [detail_a(rib)], "10.9.0.1")
    assert t.prefix == "10.9.0.0/24"


def test_trace_of_an_address_nobody_covers():
    t, _ = trace("203.0.113.9")
    assert t.verdict == "no route" and t.prefix is None and t.paths == []


def test_trace_of_a_prefix_missing_from_the_rib():
    graph = graph_of(square())
    rib = [r for r in healthy_rib() if r.cidr != "10.9.0.0/24"]
    t = trace_prefix(graph, [detail_a(rib)], "10.9.0.7")
    assert t.verdict == "in LSDB, not in RIB" and t.spf_cost == 25 and t.rib is None


def test_trace_flags_a_rib_cost_that_differs_from_spf():
    rib = healthy_rib()
    rib[5].metric = 40
    t = trace_prefix(graph_of(square()), [detail_a(rib)], "10.9.0.7")
    assert t.verdict == "RIB cost differs from SPF"


def test_trace_flags_a_next_hop_that_differs_from_spf():
    rib = healthy_rib()
    rib[5] = route("10.9.0.0/24", 25, [("10.1.2.2", "eth1")])  # only via B
    t = trace_prefix(graph_of(square()), [detail_a(rib)], "10.9.0.7")
    assert t.verdict == "RIB next hop differs from SPF"


def test_trace_from_a_chosen_router_uses_only_the_lsdb():
    graph = graph_of(square())
    t = trace_prefix(graph, [detail_a()], "10.9.0.7", source=B)
    assert t.source == B and t.rib is None and t.spf_cost == 15 and t.paths == [[B, D]]


@pytest.mark.parametrize(
    "target, source", [("not-an-ip", None), ("10.9.0.7", "10.9.9.9")]
)
def test_trace_rejects_bad_input(target, source):
    with pytest.raises(ValueError):
        trace_prefix(graph_of(square()), [detail_a()], target, source)
