"""Tests for merge_lsdbs and for labelling links from several seeds' neighbour tables."""

from __future__ import annotations

import pytest

from src.parser import MAX_LSA_AGE, OSPFParser, merge_lsdbs
from src.vendors.base import (
    KIND_P2P,
    LinkRecord,
    Lsdb,
    NeighborRecord,
    NetworkLsa,
    ParserError,
    RouterLsa,
    SourceDetail,
)

AREA0, AREA1 = "0.0.0.0", "0.0.0.1"


def _p2p(neighbor: str, metric: int = 10, ip: str | None = None) -> LinkRecord:
    return LinkRecord(kind=KIND_P2P, link_id=neighbor, metric=metric, link_data=ip)


def _router(
    rid, area=AREA0, links=(), seq=0x80000003 - 2**32, age=100, abr=False
) -> RouterLsa:
    return RouterLsa(
        router_id=rid, area=area, links=list(links), seq=seq, age=age, abr=abr
    )


def _lsdb(routers=(), networks=(), router_id=None, pids=("1",)) -> Lsdb:
    return Lsdb(
        router_lsas=list(routers),
        network_lsas=list(networks),
        process_ids=list(pids),
        router_id=router_id,
    )


# ------------------------------------------------------------ deduplication
def test_identical_lsas_from_two_seeds_collapse_to_one():
    a = _lsdb([_router("10.0.0.1", links=[_p2p("10.0.0.2")])], router_id="10.0.0.1")
    b = _lsdb([_router("10.0.0.1", links=[_p2p("10.0.0.2")])], router_id="10.0.0.2")
    merged = merge_lsdbs([a, b])
    assert len(merged.router_lsas) == 1


def test_higher_sequence_number_wins_regardless_of_seed_order():
    old = _router("10.0.0.1", links=[_p2p("10.0.0.2", 10)], seq=0x80000005 - 2**32)
    new = _router("10.0.0.1", links=[_p2p("10.0.0.2", 99)], seq=0x80000009 - 2**32)
    for order in ([old, new], [new, old]):
        merged = merge_lsdbs([_lsdb([order[0]]), _lsdb([order[1]])])
        assert merged.router_lsas[0].links[0].metric == 99


def test_links_of_two_instances_are_not_unioned():
    """A newer LSA that dropped a link must not get that link back from the older copy."""
    old = _router(
        "10.0.0.1", links=[_p2p("10.0.0.2"), _p2p("10.0.0.3")], seq=0x80000005 - 2**32
    )
    new = _router("10.0.0.1", links=[_p2p("10.0.0.2")], seq=0x80000006 - 2**32)
    merged = merge_lsdbs([_lsdb([old]), _lsdb([new])])
    assert [lnk.link_id for lnk in merged.router_lsas[0].links] == ["10.0.0.2"]


def test_equal_sequence_younger_age_wins():
    older = _router("10.0.0.1", age=900, abr=False)
    younger = _router("10.0.0.1", age=30, abr=True)
    merged = merge_lsdbs([_lsdb([older]), _lsdb([younger])])
    assert merged.router_lsas[0].age == 30
    assert merged.router_lsas[0].abr is True


def test_equal_sequence_maxage_copy_beats_a_live_one():
    """A MaxAge copy means the LSA is being withdrawn - the live copy must not resurrect it."""
    live = _router("10.0.0.1", age=40)
    flushed = _router("10.0.0.1", age=MAX_LSA_AGE)
    for order in ([live, flushed], [flushed, live]):
        merged = merge_lsdbs([_lsdb([order[0]]), _lsdb([order[1]])])
        assert merged.router_lsas[0].age == MAX_LSA_AGE


def test_missing_sequence_number_loses_to_a_known_one():
    unknown = _router("10.0.0.1", seq=None, links=[_p2p("10.0.0.9")])
    known = _router("10.0.0.1", links=[_p2p("10.0.0.2")])
    for order in ([unknown, known], [known, unknown]):
        merged = merge_lsdbs([_lsdb([order[0]]), _lsdb([order[1]])])
        assert merged.router_lsas[0].links[0].link_id == "10.0.0.2"


def test_full_tie_keeps_the_first_seed():
    first = _router("10.0.0.1", links=[_p2p("10.0.0.2", 1)], age=50)
    second = _router("10.0.0.1", links=[_p2p("10.0.0.2", 2)], age=50)
    merged = merge_lsdbs([_lsdb([first]), _lsdb([second])])
    assert merged.router_lsas[0].links[0].metric == 1


def test_network_lsas_dedupe_on_address_dr_and_area():
    def net(seq, attached, area=AREA0):
        return NetworkLsa(
            address="192.168.1.1",
            dr="10.0.0.1",
            area=area,
            mask="255.255.255.0",
            attached=attached,
            seq=seq,
            age=10,
        )

    merged = merge_lsdbs(
        [
            _lsdb(networks=[net(0x80000002 - 2**32, ["10.0.0.1", "10.0.0.3"])]),
            _lsdb(
                networks=[net(0x80000004 - 2**32, ["10.0.0.1", "10.0.0.3", "10.0.0.4"])]
            ),
        ]
    )
    assert len(merged.network_lsas) == 1
    assert merged.network_lsas[0].attached == ["10.0.0.1", "10.0.0.3", "10.0.0.4"]


# --------------------------------------------------------------- multi-area
def test_same_router_in_two_areas_keeps_both_lsas():
    """An ABR has one router LSA per area; they are different LSAs, not duplicates."""
    area0 = _lsdb([_router("10.0.0.2", AREA0, [_p2p("10.0.0.1")], abr=True)])
    area1 = _lsdb([_router("10.0.0.2", AREA1, [_p2p("10.0.0.3")], abr=True)])
    merged = merge_lsdbs([area0, area1])
    assert sorted(lsa.area for lsa in merged.router_lsas) == [AREA0, AREA1]


def test_area_written_as_integer_matches_dotted_form():
    """Huawei prints area 0, FRR prints 0.0.0.0: one area, so the LSA is one LSA."""
    merged = merge_lsdbs(
        [_lsdb([_router("10.0.0.1", "0")]), _lsdb([_router("10.0.0.1", AREA0)])]
    )
    assert len(merged.router_lsas) == 1
    assert merged.router_lsas[0].area == AREA0


# ------------------------------------------------------------------- misc
def test_process_ids_are_united_and_router_id_dropped():
    merged = merge_lsdbs(
        [
            _lsdb([_router("10.0.0.1")], router_id="10.0.0.1", pids=("1",)),
            _lsdb([_router("10.0.0.2")], router_id="10.0.0.2", pids=("1", "2")),
        ]
    )
    assert merged.process_ids == ["1", "2"]
    assert merged.router_id is None


def test_single_lsdb_keeps_its_router_id():
    assert (
        merge_lsdbs([_lsdb([_router("10.0.0.1")], router_id="10.0.0.1")]).router_id
        == "10.0.0.1"
    )


def test_inputs_are_not_modified():
    a = _lsdb([_router("10.0.0.1", "0")])
    b = _lsdb([_router("10.0.0.5")])
    merge_lsdbs([a, b])
    assert (
        a.router_lsas[0].area == "0"
        and len(a.router_lsas) == 1
        and len(b.router_lsas) == 1
    )


def test_empty_input_is_an_error():
    with pytest.raises(ParserError):
        merge_lsdbs([])


def test_merged_lsdb_flattens_into_one_graph_across_areas():
    area0 = _lsdb(
        [
            _router("10.0.0.1", AREA0, [_p2p("10.0.0.2")]),
            _router("10.0.0.2", AREA0, [_p2p("10.0.0.1")], abr=True),
        ],
        router_id="10.0.0.1",
    )
    area1 = _lsdb(
        [
            _router("10.0.0.2", AREA1, [_p2p("10.0.0.3")], abr=True),
            _router("10.0.0.3", AREA1, [_p2p("10.0.0.2")]),
        ],
        router_id="10.0.0.3",
    )
    topo = OSPFParser.build_topology(merge_lsdbs([area0, area1]))
    assert [n["id"] for n in topo["nodes"]] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    abr = next(n for n in topo["nodes"] if n["id"] == "10.0.0.2")
    assert abr["areas"] == [AREA0, AREA1] and abr["abr"] is True
    assert topo["metadata"]["areas"] == [AREA0, AREA1]
    assert {(e["source"], e["target"]) for e in topo["edges"]} == {
        ("10.0.0.1", "10.0.0.2"),
        ("10.0.0.2", "10.0.0.1"),
        ("10.0.0.2", "10.0.0.3"),
        ("10.0.0.3", "10.0.0.2"),
    }
    assert topo["metadata"]["one_way_links"] == 0


# ------------------------------------------------ merging neighbour tables
def _neighbor(rid, interface, state="Full") -> NeighborRecord:
    return NeighborRecord(
        router_id=rid, state=state, interface=interface, address="10.99.0.1"
    )


def _edge(topo, source, target):
    return next(
        e for e in topo["edges"] if e["source"] == source and e["target"] == target
    )


def test_neighbour_tables_from_both_ends_label_both_directions():
    lsdb = merge_lsdbs(
        [
            _lsdb(
                [
                    _router("10.0.0.1", links=[_p2p("10.0.0.2")]),
                    _router("10.0.0.2", links=[_p2p("10.0.0.1")]),
                ]
            ),
        ]
    )
    details = [
        SourceDetail("10.0.0.1", "10.0.0.1", [_neighbor("10.0.0.2", "eth1")]),
        SourceDetail("10.0.0.2", "10.0.0.2", [_neighbor("10.0.0.1", "eth7")]),
    ]
    topo = OSPFParser.build_topology(lsdb, details=details)
    assert _edge(topo, "10.0.0.1", "10.0.0.2")["interface"] == "eth1"
    assert _edge(topo, "10.0.0.2", "10.0.0.1")["interface"] == "eth7"


def test_one_seeds_table_does_not_label_the_other_direction():
    lsdb = _lsdb(
        [
            _router("10.0.0.1", links=[_p2p("10.0.0.2")]),
            _router("10.0.0.2", links=[_p2p("10.0.0.1")]),
        ]
    )
    topo = OSPFParser.build_topology(
        lsdb, details=[SourceDetail("a", "10.0.0.1", [_neighbor("10.0.0.2", "eth1")])]
    )
    assert "interface" not in _edge(topo, "10.0.0.2", "10.0.0.1")


def test_adjacency_problem_names_the_reporting_seed():
    lsdb = _lsdb(
        [
            _router("10.0.0.1", links=[_p2p("10.0.0.2")]),
            _router("10.0.0.2", links=[_p2p("10.0.0.1")]),
        ]
    )
    details = [
        SourceDetail(
            "seed-a", "10.0.0.1", [_neighbor("10.0.0.2", "eth1", state="ExStart")]
        ),
        SourceDetail(
            "seed-b", "10.0.0.2", [_neighbor("10.0.0.1", "eth7", state="Full")]
        ),
    ]
    issues = OSPFParser.build_topology(lsdb, details=details)["metadata"][
        "adjacency_issues"
    ]
    assert [(i["source"], i["state"]) for i in issues] == [("seed-a", "ExStart")]
