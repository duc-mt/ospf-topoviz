"""Unit tests for BGP-LS (RFC 7752 / RFC 9552) to OSPF Lsdb translator."""

from __future__ import annotations

import pytest

from src.realtime.bgpls_translator import (
    NLRI_LINK,
    NLRI_NODE,
    NLRI_PREFIX_IPV4,
    PROTOCOL_DIRECT,
    PROTOCOL_ISIS_L1,
    PROTOCOL_OSPFV2,
    BgpLsState,
    translate_bgpls_update,
)
from src.vendors.base import KIND_P2P, KIND_STUB, KIND_TRANSIT


def test_node_nlri_maps_abr_asbr_and_overload_max_metric() -> None:
    state = BgpLsState()
    state.apply_reach(
        {
            "nlri_type": NLRI_NODE,
            "protocol_id": PROTOCOL_OSPFV2,
            "area": "0.0.0.0",
            "router_id": "10.0.0.1",
        },
        {"node_flags": 0x80 | 0x20 | 0x10},  # Overload + ASBR + ABR (RFC 7752)
    )
    lsdb = state.to_lsdb()
    assert len(lsdb.router_lsas) == 1
    r = lsdb.router_lsas[0]
    assert r.router_id == "10.0.0.1"
    assert r.area == "0.0.0.0"
    assert r.max_metric is True
    assert r.asbr is True
    assert r.abr is True


def test_link_nlri_and_pseudonode_translate_to_p2p_and_transit_network_lsas_with_te_and_srlg() -> None:
    state = BgpLsState()
    # Two routers and one broadcast DR pseudonode (10.0.0.2, 192.168.1.2)
    state.apply_reach(
        {"nlri_type": NLRI_NODE, "protocol_id": PROTOCOL_OSPFV2, "area": "0.0.0.0", "router_id": "10.0.0.1"},
        {},
    )
    state.apply_reach(
        {"nlri_type": NLRI_NODE, "protocol_id": PROTOCOL_OSPFV2, "area": "0.0.0.0", "router_id": "10.0.0.2"},
        {},
    )
    state.apply_reach(
        {
            "nlri_type": NLRI_NODE,
            "protocol_id": PROTOCOL_OSPFV2,
            "area": "0.0.0.0",
            "router_id": "10.0.0.2",
            "pseudonode_ip": "192.168.1.2",
        },
        {},
    )
    # P2P link with TE metric, BW, Admin group, and SRLGs
    state.apply_reach(
        {
            "nlri_type": NLRI_LINK,
            "protocol_id": PROTOCOL_OSPFV2,
            "area": "0.0.0.0",
            "local_router_id": "10.0.0.1",
            "remote_router_id": "10.0.0.2",
            "local_ip": "10.12.0.1",
            "remote_ip": "10.12.0.2",
        },
        {
            "igp_metric": 10,
            "te_metric": 25,
            "max_bw_bps": 1_000_000_000.0,
            "max_reservable_bw_bps": 800_000_000.0,
            "admin_groups": 0x3,
            "srlgs": [100, 200],
        },
    )
    # Links into broadcast pseudonode
    state.apply_reach(
        {
            "nlri_type": NLRI_LINK,
            "protocol_id": PROTOCOL_OSPFV2,
            "area": "0.0.0.0",
            "local_router_id": "10.0.0.1",
            "remote_router_id": "10.0.0.2",
            "remote_pseudonode_ip": "192.168.1.2",
            "local_ip": "192.168.1.1",
        },
        {"igp_metric": 5},
    )
    state.apply_reach(
        {
            "nlri_type": NLRI_LINK,
            "protocol_id": PROTOCOL_OSPFV2,
            "area": "0.0.0.0",
            "local_router_id": "10.0.0.2",
            "remote_router_id": "10.0.0.2",
            "remote_pseudonode_ip": "192.168.1.2",
            "local_ip": "192.168.1.2",
        },
        {"igp_metric": 5},
    )

    lsdb = state.to_lsdb()
    r1 = next(r for r in lsdb.router_lsas if r.router_id == "10.0.0.1")
    kinds = {(lk.kind, lk.link_id, lk.metric) for lk in r1.links}
    assert (KIND_P2P, "10.0.0.2", 10) in kinds
    assert (KIND_TRANSIT, "192.168.1.2", 5) in kinds

    assert len(lsdb.network_lsas) == 1
    net = lsdb.network_lsas[0]
    assert net.address == "192.168.1.2"
    assert net.dr == "10.0.0.2"
    assert sorted(net.attached) == ["10.0.0.1", "10.0.0.2"]

    assert len(lsdb.te_lsas) == 1
    te = lsdb.te_lsas[0]
    assert te.te_metric == 25
    assert te.max_bw_bps == pytest.approx(1_000_000_000.0)
    assert te.admin_groups == 0x3
    assert te.srlgs == [100, 200]


def test_prefix_nlri_translates_stub_and_external_lsas_and_withdrawals_remove_them() -> None:
    state = BgpLsState()
    stub_nlri = {
        "nlri_type": NLRI_PREFIX_IPV4,
        "protocol_id": PROTOCOL_OSPFV2,
        "area": "0.0.0.0",
        "router_id": "10.0.0.1",
        "prefix": "10.99.0.0/24",
        "ospf_route_type": 1,  # Intra-Area -> stub link
    }
    ext_nlri = {
        "nlri_type": NLRI_PREFIX_IPV4,
        "protocol_id": PROTOCOL_OSPFV2,
        "area": "0.0.0.0",
        "router_id": "10.0.0.1",
        "prefix": "172.16.0.0/16",
        "ospf_route_type": 4,  # External Type 2 -> ExternalLsa E2
    }
    translate_bgpls_update(
        state,
        reach=[(stub_nlri, {"prefix_metric": 10}), (ext_nlri, {"prefix_metric": 50})],
    )
    lsdb1 = state.to_lsdb()
    r1 = lsdb1.router_lsas[0]
    assert any(lk.kind == KIND_STUB and lk.link_id == "10.99.0.0" and lk.metric == 10 for lk in r1.links)
    assert len(lsdb1.external_lsas) == 1
    assert lsdb1.external_lsas[0].metric_type == "E2"
    assert lsdb1.external_lsas[0].metric == 50

    translate_bgpls_update(state, unreach=[ext_nlri])
    lsdb2 = state.to_lsdb()
    assert lsdb2.external_lsas == []


def test_non_ospf_protocol_ids_are_ignored_cleanly() -> None:
    state = BgpLsState()
    state.apply_reach(
        {"nlri_type": NLRI_NODE, "protocol_id": PROTOCOL_ISIS_L1, "area": "0.0.0.0", "router_id": "10.0.0.1"},
        {},
    )
    state.apply_reach(
        {"nlri_type": NLRI_NODE, "protocol_id": PROTOCOL_DIRECT, "area": "0.0.0.0", "router_id": "10.0.0.2"},
        {},
    )
    lsdb = state.to_lsdb()
    assert lsdb.router_lsas == []
