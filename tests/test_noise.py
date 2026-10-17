"""Noise reduction: LSAs about to be flushed, next hops mapped to routers, and findings graded by impact."""

from __future__ import annotations

import ipaddress
import json

import networkx as nx
import pytest
import yaml

import main
from src.config import ConfigError, maxage_lsa_age
from src.correlation import (
    BLACKHOLE_KINDS,
    COST_MISMATCH,
    ECMP_MISSING,
    NBR_NOT_IN_LSDB,
    NEXTHOP_DOWN,
    NEXTHOP_MISMATCH,
    ROUTE_MISSING,
    ROUTE_OVERRIDDEN,
    ROUTE_STALE,
    IpResolver,
    correlate,
)
from src.graph_engine import GraphEngine, TopologyDiff
from src.parser import (
    DEFAULT_MAXAGE_IGNORE_AGE,
    DEFAULT_STALE_AGE,
    OSPFParser,
    merge_lsdbs,
)
from src.explorer import build_scene
from src.vendors.base import (
    KIND_TRANSIT,
    LinkRecord,
    Lsdb,
    NeighborRecord,
    NetworkLsa,
    SourceDetail,
)
from tests.test_correlation import (
    A,
    AREA0,
    AREA1,
    B,
    C,
    D,
    detail_a,
    graph_of,
    healthy_rib,
    nbr,
    p2p,
    route,
    router,
    square,
    stub,
)

NEW_DR, OLD_DR = (
    "10.130.240.1",
    "10.130.240.2",
)  # interfaces of the DR now, and of the one it replaced


def transit(dr_ip: str, own_ip: str, metric: int = 10) -> LinkRecord:
    return LinkRecord(kind=KIND_TRANSIT, link_id=dr_ip, link_data=own_ip, metric=metric)


def net_lsa(
    address: str, dr: str, age: int, attached=(A, B, C), area: str = AREA0
) -> NetworkLsa:
    return NetworkLsa(
        address=address,
        dr=dr,
        area=area,
        mask="255.255.255.0",
        attached=list(attached),
        seq=-2147483645,
        age=age,
    )


def re_election(old_age: int = 3550, with_old: bool = True) -> Lsdb:
    """Three routers on one segment. A is the DR now; the Network LSA of the previous DR (B) is still in the database."""
    routers = [
        router(
            A, [transit(NEW_DR, "10.130.240.1"), stub("10.0.0.1", "255.255.255.255", 1)]
        ),
        router(
            B, [transit(NEW_DR, "10.130.240.2"), stub("10.0.0.2", "255.255.255.255", 1)]
        ),
        router(
            C, [transit(NEW_DR, "10.130.240.3"), stub("10.0.0.3", "255.255.255.255", 1)]
        ),
    ]
    nets = [net_lsa(NEW_DR, A, 120)] + (
        [net_lsa(OLD_DR, B, old_age)] if with_old else []
    )
    return Lsdb(router_lsas=routers, network_lsas=nets, process_ids=[], router_id=A)


def topo(lsdb: Lsdb, **kw) -> dict:
    return OSPFParser.build_topology(lsdb, **kw)


def graph(parsed: dict) -> nx.DiGraph:
    return GraphEngine.__new__(GraphEngine).build_graph(parsed)


def ids(parsed: dict) -> set[str]:
    return {n["id"] for n in parsed["nodes"]}


# ====================================================== LSAs close to MaxAge
def test_the_default_threshold_is_3500_seconds_just_under_maxage():
    assert DEFAULT_MAXAGE_IGNORE_AGE == 3500 < 3600


def test_a_leftover_network_lsa_from_the_old_dr_is_not_a_node():
    parsed = topo(re_election())
    assert ids(parsed) == {A, B, C, "net-10.130.240.1"}
    assert (
        parsed["metadata"]["one_way_links"] == 0
        and parsed["metadata"]["stale_nodes"] == []
    )
    assert nx.number_weakly_connected_components(graph(parsed)) == 1


def test_without_the_filter_the_same_database_raises_the_false_alarms():
    parsed = topo(re_election(), maxage_age=0)
    assert "net-10.130.240.2" in ids(parsed)
    assert parsed["metadata"]["stale_nodes"] == ["net-10.130.240.2"]
    assert (
        parsed["metadata"]["one_way_links"] == 3
    )  # the old LSA still lists the routers, they no longer list it


@pytest.mark.parametrize("age, ignored", [(3499, False), (3500, True), (3600, True)])
def test_the_boundary_is_inclusive(age, ignored):
    assert ("net-10.130.240.2" not in ids(topo(re_election(old_age=age)))) is ignored


def test_the_threshold_can_be_changed():
    assert "net-10.130.240.2" not in ids(
        topo(re_election(old_age=3100), maxage_age=3000)
    )
    assert "net-10.130.240.2" in ids(topo(re_election(old_age=3100)))


def test_ignored_lsas_are_listed_so_they_can_be_shown_as_information():
    [entry] = topo(re_election())["metadata"]["flushing_lsas"]
    assert entry == {
        "type": "network",
        "id": "net-10.130.240.2",
        "area": AREA0,
        "age": 3550,
        "dr": B,
        "prefixes": ["10.130.240.0/24"],
    }
    assert topo(re_election(with_old=False))["metadata"]["flushing_lsas"] == []
    assert topo(re_election(), maxage_age=0)["metadata"]["flushing_lsas"] == []


def test_a_router_links_to_a_flushing_network_are_ignored_like_spf_does():
    """A router still pointing at the old DR's segment must not create a 'no LSA' ghost network."""
    lsdb = re_election()
    lsdb.router_lsas[1].links[0] = transit(
        OLD_DR, "10.130.240.2"
    )  # B has not re-originated yet
    parsed = topo(lsdb)
    assert not any(n["id"] == "net-10.130.240.2" for n in parsed["nodes"])
    assert not [n for n in parsed["nodes"] if not n["resolved"]]


def test_a_network_that_never_had_an_lsa_is_still_shown_as_no_lsa():
    lsdb = re_election(with_old=False)
    lsdb.router_lsas[1].links.append(transit("10.77.0.1", "10.77.0.2"))
    ghost = next(n for n in topo(lsdb)["nodes"] if n["id"] == "net-10.77.0.1")
    assert ghost["resolved"] is False


def test_a_router_whose_lsa_is_flushing_disappears_with_its_links_and_attachments():
    dead = "10.0.0.9"
    lsdb = re_election(with_old=False)
    lsdb.router_lsas.append(router(dead, [transit(NEW_DR, "10.130.240.9")]))
    lsdb.router_lsas[-1].age = 3600
    lsdb.router_lsas[0].links.append(p2p(dead, "10.9.9.1", 10))
    lsdb.network_lsas[0].attached.append(dead)
    parsed = topo(lsdb)
    assert dead not in ids(parsed)
    assert [e for e in parsed["edges"] if dead in (e["source"], e["target"])] == []
    assert {(e["id"], e["type"]) for e in parsed["metadata"]["flushing_lsas"]} == {
        (dead, "router")
    }


def test_a_router_with_one_flushing_lsa_and_one_live_one_stays():
    lsdb = Lsdb(
        router_lsas=[
            router(A, [p2p(B, "10.1.2.1", 10)]),
            router(B, [p2p(A, "10.1.2.2", 10)], AREA0),
            router(B, [stub("10.8.8.0", "255.255.255.0", 5)], AREA1),
        ],
        network_lsas=[],
        process_ids=[],
    )
    lsdb.router_lsas[2].age = 3600
    parsed = topo(lsdb)
    assert B in ids(parsed) and parsed["metadata"]["flushing_lsas"][0]["area"] == AREA1
    assert "prefixes" not in next(
        n for n in parsed["nodes"] if n["id"] == B
    )  # the flushing LSA's prefix is not advertised


def test_a_live_copy_of_the_same_network_lsa_keeps_the_network():
    lsdb = re_election(with_old=False)
    lsdb.network_lsas.append(
        net_lsa(NEW_DR, A, 3600)
    )  # a flushing duplicate of the live one
    parsed = topo(lsdb)
    assert "net-10.130.240.1" in ids(parsed)
    assert len([e for e in parsed["edges"] if e["source"] == "net-10.130.240.1"]) == 3


def test_when_merging_seeds_a_flush_copy_wins_and_is_then_ignored():
    live = re_election(with_old=False)
    flushed = re_election(with_old=False)
    flushed.network_lsas[0].age = 3600
    parsed = topo(merge_lsdbs([live, flushed]))
    assert "net-10.130.240.1" not in ids(
        parsed
    )  # a withdrawn LSA is gone, whichever seed still has the old copy


def test_the_filter_is_off_with_zero_and_a_stale_age_below_it_still_flags():
    assert DEFAULT_STALE_AGE < DEFAULT_MAXAGE_IGNORE_AGE
    parsed = topo(re_election(old_age=3000))
    assert parsed["metadata"]["stale_nodes"] == [
        "net-10.130.240.2"
    ]  # old but not yet flushing: still reported


# --------------------------------------------------------------- the setting
@pytest.mark.parametrize(
    "value, expected",
    [(None, 3500), (0, 0), (3000, 3000), (3600, 3600), ("3200", 3200)],
)
def test_maxage_setting(value, expected):
    settings = {"data_quality": {} if value is None else {"maxage_lsa_age": value}}
    assert maxage_lsa_age(settings, 3500) == expected


@pytest.mark.parametrize("value", [-1, 3601, "soon"])
def test_bad_maxage_settings_are_rejected(value):
    with pytest.raises(ConfigError, match="maxage_lsa_age"):
        maxage_lsa_age({"data_quality": {"maxage_lsa_age": value}}, 3500)


# ====================================================== next hop -> router
def resolver(lsdb: Lsdb, details=()) -> IpResolver:
    return IpResolver(graph_of(lsdb), list(details))


def test_a_next_hop_is_mapped_through_the_link_data_of_the_router_lsa():
    r = resolver(square())
    assert (
        r.resolve("10.1.2.2") == B and r.resolve("10.1.3.3") == C
    )  # the neighbours' addresses on A's links
    assert r.resolve("10.2.4.4") == D


def test_the_polled_routers_own_neighbour_table_is_trusted_first():
    """The Hello says 10.1.2.2 is C; a stale LSA that says B must not win for that router's next hops."""
    detail = SourceDetail(
        "A", A, [NeighborRecord(router_id=C, state="Full", address="10.1.2.2")], None
    )
    r = resolver(square(), [detail])
    assert r.resolve("10.1.2.2", via=A) == C
    assert (
        r.resolve("10.1.2.2") == B
    )  # without that router's table the LSDB answer stands


def test_the_documented_example_an_interface_ip_resolves_to_its_router_id():
    """Next hop 10.130.240.2 is an interface of router 10.255.255.1, not a router ID."""
    lsdb = re_election()
    lsdb.router_lsas[1] = router("10.255.255.1", [transit(NEW_DR, "10.130.240.2")])
    lsdb.network_lsas[0].attached[1] = "10.255.255.1"
    assert resolver(lsdb).resolve("10.130.240.2") == "10.255.255.1"
    detail = SourceDetail(
        "A",
        A,
        [
            NeighborRecord(
                router_id="10.255.255.1", state="Full", address="10.130.240.2"
            )
        ],
        None,
    )
    assert resolver(lsdb, [detail]).resolve("10.130.240.2", via=A) == "10.255.255.1"


def test_an_address_that_is_also_a_router_id_resolves_to_that_router():
    assert resolver(square()).resolve(D) == D


def test_a_neighbour_in_another_area_is_found_by_the_segment_it_sits_on():
    """Its Router LSA is not in this database, but it is the only other router on the segment."""
    lsdb = Lsdb(
        router_lsas=[router(A, [transit(NEW_DR, "10.130.240.1")])],
        network_lsas=[net_lsa(NEW_DR, A, 10, attached=[A, "10.0.0.9"])],
        process_ids=[],
    )
    assert resolver(lsdb).resolve("10.130.240.77", via=A) == "10.0.0.9"


def test_a_crowded_segment_is_not_guessed_at():
    lsdb = Lsdb(
        router_lsas=[router(A, [transit(NEW_DR, "10.130.240.1")])],
        network_lsas=[net_lsa(NEW_DR, A, 10, attached=[A, "10.0.0.8", "10.0.0.9"])],
        process_ids=[],
    )
    assert resolver(lsdb).resolve("10.130.240.77", via=A) is None


def test_a_point_to_point_subnet_shared_with_one_neighbour_identifies_it():
    lsdb = Lsdb(
        router_lsas=[
            router(
                A, [p2p(B, "10.1.2.1", 10), stub("10.1.2.0", "255.255.255.252", 10)]
            ),
            router(
                B, [p2p(A, "unnumbered", 10), stub("10.1.2.0", "255.255.255.252", 10)]
            ),
        ],
        network_lsas=[],
        process_ids=[],
    )
    assert resolver(lsdb).resolve("10.1.2.2", via=A) == B


def test_an_address_nobody_owns_stays_unresolved():
    assert resolver(square()).resolve("172.31.0.1", via=A) is None


def test_next_hops_that_cannot_be_resolved_raise_no_findings():
    rib = healthy_rib()
    rib[5] = route("10.9.0.0/24", 25, [("172.31.0.1", "eth7")])
    assert correlate(graph_of(square()), [detail_a(rib)]).findings == []


def test_the_neighbour_tables_address_overrides_the_lsdb_for_the_polled_routers_routes():
    """A route via 10.1.2.2 is judged against the router the Hello table says it is."""
    detail = SourceDetail(
        "A",
        A,
        [
            nbr(C, interface="eth1", address="10.1.2.2"),
            nbr(B, interface="eth2", address="10.1.3.3"),
        ],
        healthy_rib(),
    )
    findings = correlate(graph_of(square()), [detail]).findings
    assert {f.kind for f in findings} <= {
        NEXTHOP_MISMATCH,
        ECMP_MISSING,
    }  # swapped tables: wrong next hops, but only noted
    assert all(f.severity == "info" for f in findings)


# =============================================================== severity
def kinds_and_severities(findings):
    return {(f.kind, f.severity) for f in findings}


def run(rib=None, neighbors=None, lsdb=None):
    return correlate(graph_of(lsdb or square()), [detail_a(rib, neighbors)]).findings


def test_a_longer_path_than_spf_is_information_not_a_warning():
    rib = healthy_rib()
    rib[5].metric = 99
    assert kinds_and_severities(run(rib)) == {(COST_MISMATCH, "info")}


def test_a_lost_ecmp_path_is_information():
    rib = healthy_rib()
    rib[5] = route("10.9.0.0/24", 25, [("10.1.2.2", "eth1")])
    assert kinds_and_severities(run(rib)) == {(ECMP_MISSING, "info")}


def test_a_next_hop_off_the_shortest_path_is_information():
    lsdb = square()
    lsdb.router_lsas[0].links[0] = p2p(B, "10.1.2.1", 5)
    lsdb.router_lsas[1].links[0] = p2p(A, "10.1.2.2", 5)
    rib = [
        route("10.0.0.2/32", 6, [("10.1.2.2", "eth1")]),
        route("10.0.0.3/32", 11, [("10.1.3.3", "eth2")]),
        route("10.0.0.4/32", 16, [("10.1.3.3", "eth2")]),
        route("10.2.4.0/24", 15, [("10.1.2.2", "eth1")]),
        route("10.3.4.0/24", 20, [("10.1.3.3", "eth2")]),
        route("10.9.0.0/24", 20, [("10.1.2.2", "eth1")]),
    ]
    assert (NEXTHOP_MISMATCH, "info") in kinds_and_severities(run(rib, lsdb=lsdb))
    assert not [f for f in run(rib, lsdb=lsdb) if f.severity != "info"]


def test_a_route_another_protocol_overrides_is_information():
    rib = healthy_rib()
    rib[5].active = False
    assert kinds_and_severities(run(rib)) == {(ROUTE_OVERRIDDEN, "info")}


def test_a_stale_route_and_a_neighbour_the_lsdb_lags_behind_are_information():
    rib = healthy_rib() + [route("172.31.0.0/24", 10, [("10.1.2.2", "eth1")])]
    assert kinds_and_severities(run(rib)) == {(ROUTE_STALE, "info")}
    detail = detail_a(
        neighbors=[
            nbr(B, interface="eth1"),
            nbr(C, interface="eth2"),
            nbr("10.0.0.99", interface="eth9"),
        ]
    )
    assert (NBR_NOT_IN_LSDB, "info") in kinds_and_severities(
        neighbor_findings_of(detail)
    )


def neighbor_findings_of(detail):
    from src.correlation import neighbor_findings  # noqa: PLC0415

    return neighbor_findings(graph_of(square()), detail)


def test_missing_routes_and_routes_through_a_dead_neighbour_stay_critical():
    rib = [r for r in healthy_rib() if r.cidr != "10.9.0.0/24"]
    assert (ROUTE_MISSING, "critical") in kinds_and_severities(run(rib))
    stuck = [
        nbr(B, "ExStart", interface="eth1", address="10.1.2.2"),
        nbr(C, interface="eth2", address="10.1.3.3"),
    ]
    found = kinds_and_severities(run(healthy_rib(), stuck))
    assert (NEXTHOP_DOWN, "critical") in found and (
        NEXTHOP_DOWN,
        "warning",
    ) in found  # all hops dead / only some
    assert set(BLACKHOLE_KINDS) >= {ROUTE_MISSING, NEXTHOP_DOWN}


def test_a_flood_of_deviations_raises_no_alarm_at_all():
    """Every route a little off, as during reconvergence: plenty of information, no warning, no critical."""
    rib = healthy_rib()
    for r in rib:
        r.metric += 7
    rib[5] = route("10.9.0.0/24", 32, [("10.1.2.2", "eth1")])
    findings = run(rib)
    assert len(findings) >= 6 and {f.severity for f in findings} == {"info"}


def test_a_route_whose_lsa_is_being_flushed_is_not_called_stale():
    lsdb = square()
    lsdb.router_lsas[
        3
    ].age = 3600  # D's LSA is leaving the database (so is its 10.9.0.0/24)
    parsed = topo(lsdb)
    assert D not in ids(parsed)
    rib = [
        route("10.0.0.2/32", 11, [("10.1.2.2", "eth1")]),
        route("10.0.0.3/32", 11, [("10.1.3.3", "eth2")]),
        route("10.9.0.0/24", 25, [("10.1.2.2", "eth1")], "Intra-Area"),
    ]
    report = correlate(graph(parsed), [detail_a(rib)])
    assert ROUTE_STALE not in {f.kind for f in report.findings}
    assert report.rib_checks[0]["unverified"] >= 1


# ================================================== the whole pipeline
def vyos_router_text(router_id, transit_ip, own_ip, area="0.0.0.0", age=100):
    return f"""  LS age: {age}
  Options: 0x2  : *|-|-|-|-|-|E|-
  LS Flags: 0x3
  Flags: 0x0
  LS Type: router-LSA
  Link State ID: {router_id}
  Advertising Router: {router_id}
  LS Seq Number: 80000003
  Checksum: 0x1A2B
  Length: 60

   Number of Links: 2

    Link connected to: Stub Network
     (Link ID) Net: {router_id}
     (Link Data) Network Mask: 255.255.255.255
      Number of TOS metrics: 0
       TOS 0 Metric: 1

    Link connected to: Transit Network
     (Link ID) Designated Router address: {transit_ip}
     (Link Data) Router Interface address: {own_ip}
      Number of TOS metrics: 0
       TOS 0 Metric: 10

"""


def vyos_net_text(address, dr, attached, age):
    rows = "".join(f"        Attached Router: {r}\n" for r in attached)
    return f"""  LS age: {age}
  Options: 0x2  : *|-|-|-|-|-|E|-
  LS Flags: 0x3
  LS Type: network-LSA
  Link State ID: {address} (address of Designated Router)
  Advertising Router: {dr}
  LS Seq Number: 80000002
  Checksum: 0x1234
  Length: 32
  Network Mask: /24
{rows}
"""


@pytest.fixture
def replay(tmp_path, monkeypatch):
    routers = (
        "\n       OSPF Router with ID (10.0.0.1)\n\n\n                Router Link States (Area 0.0.0.0)\n\n"
        + "".join(
            vyos_router_text(f"10.0.0.{i}", "192.168.1.1", f"192.168.1.{i}")
            for i in (1, 2, 3)
        )
    )
    networks = (
        "\n       OSPF Router with ID (10.0.0.1)\n\n\n                Net Link States (Area 0.0.0.0)\n\n"
        + vyos_net_text(
            "192.168.1.1", "10.0.0.1", ["10.0.0.1", "10.0.0.2", "10.0.0.3"], 120
        )
        + vyos_net_text(
            "192.168.1.2", "10.0.0.2", ["10.0.0.1", "10.0.0.2", "10.0.0.3"], 3550
        )
    )
    folder = tmp_path / "raw"
    folder.mkdir()
    (folder / "router_lsdb.txt").write_text(routers)
    (folder / "network_lsdb.txt").write_text(networks)
    (folder / "neighbors.txt").write_text(
        "Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL\n"
        "10.0.0.2          1 Full/Backup     1h02m           33.5s     192.168.1.2     eth0:192.168.1.1                     0     0     0\n"
        "10.0.0.3          1 Full/DROther    1h02m           35.1s     192.168.1.3     eth0:192.168.1.1                     0     0     0\n"
    )
    (folder / "routes.txt").write_text(
        "O>* 10.0.0.2/32 [110/11] via 192.168.1.2, eth0, weight 1, 01:02:03\n"
        "O>* 10.0.0.3/32 [110/11] via 192.168.1.3, eth0, weight 1, 01:02:03\n"
        "O   192.168.1.0/24 [110/10] is directly connected, eth0, weight 1, 01:02:11\n"
    )
    monkeypatch.setattr(main, "DATA_DIR", tmp_path / "data")
    config = tmp_path / "settings.yaml"

    def run(*args, settings=None):
        config.write_text(
            yaml.safe_dump(
                settings
                or {
                    "device": {
                        "host": "x",
                        "username": "u",
                        "password": "p",
                        "device_type": "vyos",
                    }
                }
            )
        )
        page = tmp_path / "topology.html"
        code = main.main(
            [
                "--config",
                str(config),
                "--replay",
                str(folder),
                "--device-type",
                "vyos",
                "--dry-run",
                "--output",
                str(page),
                *args,
            ]
        )
        scene = json.loads(
            page.read_text(encoding="utf-8")
            .split('id="scene">')[1]
            .split("</script>")[0]
        )
        return code, scene

    return run


def test_a_database_with_the_old_drs_leftover_lsa_is_clean(replay, capsys):
    code, scene = replay("--fail-on-findings")
    assert code == main.EXIT_OK
    d = scene["diagnostics"]
    assert (
        d["split"] is None
        and d["oneWay"] == []
        and d["stale"] == []
        and scene["findings"] == []
    )
    assert (scene["meta"]["routers"], scene["meta"]["networks"]) == (3, 1)
    out = capsys.readouterr().out
    assert (
        "Ignored   : 1 LSA(s) at age 3500+ s" in out
        and "network 192.168.1.2 (age 3550 s)" in out
    )
    assert "one-way" not in out.lower() and "SUSPECT" not in out


def test_the_ignored_lsa_is_reported_as_information_in_the_explorer(replay):
    _, scene = replay()
    assert [e["id"] for e in scene["diagnostics"]["flushing"]] == ["net-192.168.1.2"]


def test_switching_the_filter_off_brings_the_old_alarms_back(replay):
    settings = {
        "device": {
            "host": "x",
            "username": "u",
            "password": "p",
            "device_type": "vyos",
        },
        "data_quality": {"maxage_lsa_age": 0},
    }
    _, scene = replay(settings=settings)
    assert len(scene["diagnostics"]["oneWay"]) == 3 and scene["diagnostics"][
        "stale"
    ] == ["net-192.168.1.2"]


def test_scene_marks_nothing_flushing_on_a_clean_database():
    scene = build_scene(graph_of(square()), TopologyDiff())
    assert scene["diagnostics"]["flushing"] == []
    assert ipaddress.ip_address("10.0.0.1")  # keeps the import honest


def info_finding(i: int) -> dict:
    from src.correlation import Finding  # noqa: PLC0415

    return Finding(
        "route",
        COST_MISMATCH,
        "info",
        A,
        f"10.{i}.0.0/24",
        f"cost differs {i}",
        "valid but not ideal",
        {},
    ).to_dict()


def test_the_console_lists_a_few_informational_rows_and_counts_the_rest():
    from src.report import MAX_INFO_ROWS, render_route_findings_table  # noqa: PLC0415

    diff = TopologyDiff(findings=[info_finding(i) for i in range(MAX_INFO_ROWS + 5)])
    table = render_route_findings_table(diff)
    assert table.count("SUBOPTIMAL") == MAX_INFO_ROWS
    assert "5 more informational finding(s) not listed" in table
    assert "valid but not ideal" not in table  # hints are for things that need action


def test_alarms_are_never_hidden_by_the_informational_cap():
    from src.correlation import Finding  # noqa: PLC0415
    from src.report import MAX_INFO_ROWS, render_route_findings_table  # noqa: PLC0415

    critical = Finding(
        "route",
        ROUTE_MISSING,
        "critical",
        A,
        "10.9.9.0/24",
        "gone",
        "check the RIB",
        {},
    ).to_dict()
    diff = TopologyDiff(
        findings=[critical] + [info_finding(i) for i in range(MAX_INFO_ROWS + 3)]
    )
    table = render_route_findings_table(diff)
    assert "BLACKHOLE" in table and "10.9.9.0/24" in table and "check the RIB" in table
