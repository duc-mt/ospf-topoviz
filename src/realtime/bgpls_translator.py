"""Stateful BGP-LS (RFC 7752 / RFC 9552) NLRI & Attribute translator to OSPF Lsdb."""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.vendors.base import (
    KIND_P2P,
    KIND_STUB,
    KIND_TRANSIT,
    ExternalLsa,
    LinkRecord,
    Lsdb,
    NetworkLsa,
    RouterLsa,
    TeLinkLsa,
    dotted_area,
)

NLRI_NODE = 1
NLRI_LINK = 2
NLRI_PREFIX_IPV4 = 3

PROTOCOL_ISIS_L1 = 1
PROTOCOL_ISIS_L2 = 2
PROTOCOL_OSPFV2 = 3
PROTOCOL_DIRECT = 4
PROTOCOL_STATIC = 5
PROTOCOL_OSPFV3 = 6

# OSPF Route Type TLV 264 values (RFC 7752 Section 3.2.3.1)
_OSPF_ROUTE_INTRA = 1
_OSPF_ROUTE_INTER = 2
_OSPF_ROUTE_EXT1 = 3
_OSPF_ROUTE_EXT2 = 4
_OSPF_ROUTE_NSSA1 = 5
_OSPF_ROUTE_NSSA2 = 6


@dataclass(frozen=True)
class BgplsConfig:
    """Configuration for the passive BGP-LS collector."""

    enabled: bool = False
    mode: str = "native_bgp"
    listen_address: str = "0.0.0.0"
    listen_port: int = 179
    local_as: int = 65001
    router_id: str = "192.0.2.100"
    settle_seconds: float = 2.0
    hold_time: int = 90
    peers: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_settings(cls, section: dict[str, Any] | None) -> BgplsConfig:
        section = section or {}
        return cls(
            enabled=bool(section.get("enabled", False)),
            mode=str(section.get("mode") or "native_bgp"),
            listen_address=str(section.get("listen_address") or "0.0.0.0"),
            listen_port=int(section.get("listen_port", 179)),
            local_as=int(section.get("local_as", 65001)),
            router_id=str(section.get("router_id") or "192.0.2.100"),
            settle_seconds=max(0.0, float(section.get("settle_seconds", 2.0))),
            hold_time=int(section.get("hold_time", 90)),
            peers=[dict(p) for p in (section.get("peers") or ()) if isinstance(p, dict)],
        )


def _iter_tlvs(buf: bytes) -> Iterator[tuple[int, bytes]]:
    pos = 0
    while pos + 4 <= len(buf):
        t, length = struct.unpack_from(">HH", buf, pos)
        pos += 4
        if pos + length > len(buf):
            break
        yield t, buf[pos : pos + length]
        pos += length


def _decode_node_desc(buf: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for t, val in _iter_tlvs(buf):
        if t == 514 and len(val) == 4:
            out["area"] = socket.inet_ntoa(val)
        elif t == 515:
            if len(val) == 4:
                out["router_id"] = socket.inet_ntoa(val)
            elif len(val) == 8:
                out["router_id"] = socket.inet_ntoa(val[:4])
                out["pseudonode_ip"] = socket.inet_ntoa(val[4:8])
    return out


def decode_bgpls_nlris(buf: bytes) -> list[dict[str, Any]]:
    """Decode binary RFC 7752 BGP-LS NLRIs into normalized dictionaries."""
    nlris: list[dict[str, Any]] = []
    pos = 0
    while pos + 4 <= len(buf):
        nlri_type, nlri_len = struct.unpack_from(">HH", buf, pos)
        pos += 4
        if pos + nlri_len > len(buf):
            break
        body = buf[pos : pos + nlri_len]
        pos += nlri_len
        if len(body) < 9:
            continue
        proto_id = body[0]
        item: dict[str, Any] = {
            "nlri_type": nlri_type,
            "protocol_id": proto_id,
            "area": "0.0.0.0",
        }
        tlvs = body[9:]
        for t, val in _iter_tlvs(tlvs):
            if t == 256:
                desc = _decode_node_desc(val)
                if nlri_type == NLRI_LINK:
                    item["local_router_id"] = desc.get("router_id", "")
                    if desc.get("pseudonode_ip"):
                        item["local_pseudonode_ip"] = desc["pseudonode_ip"]
                else:
                    item["router_id"] = desc.get("router_id", "")
                    if desc.get("pseudonode_ip"):
                        item["pseudonode_ip"] = desc["pseudonode_ip"]
                if desc.get("area"):
                    item["area"] = desc["area"]
            elif t == 257:
                desc = _decode_node_desc(val)
                item["remote_router_id"] = desc.get("router_id", "")
                if desc.get("pseudonode_ip"):
                    item["remote_pseudonode_ip"] = desc["pseudonode_ip"]
            elif t == 259 and len(val) == 4:
                item["local_ip"] = socket.inet_ntoa(val)
            elif t == 260 and len(val) == 4:
                item["remote_ip"] = socket.inet_ntoa(val)
            elif t == 264 and len(val) >= 1:
                item["ospf_route_type"] = val[0]
            elif t == 265 and len(val) >= 1:
                plen = val[0]
                padded = (val[1 : 1 + (plen + 7) // 8] + b"\x00\x00\x00\x00")[:4]
                item["prefix"] = f"{socket.inet_ntoa(padded)}/{plen}"
        nlris.append(item)
    return nlris


def decode_bgpls_attr(buf: bytes) -> dict[str, Any]:
    """Decode binary RFC 7752 Path Attribute 29 (BGP-LS Attribute) TLVs."""
    out: dict[str, Any] = {}
    for t, val in _iter_tlvs(buf):
        if t == 1024 and len(val) >= 1:
            out["node_flags"] = val[0]
        elif t == 1088 and len(val) == 4:
            out["admin_groups"] = struct.unpack(">I", val)[0]
        elif t == 1089 and len(val) == 4:
            out["max_bw_bps"] = struct.unpack(">f", val)[0] * 8.0
        elif t == 1090 and len(val) == 4:
            out["max_reservable_bw_bps"] = struct.unpack(">f", val)[0] * 8.0
        elif t == 1091 and len(val) == 32:
            out["unreserved_bw_bps"] = [
                struct.unpack_from(">f", val, i * 4)[0] * 8.0 for i in range(8)
            ]
        elif t == 1092 and len(val) == 4:
            out["te_metric"] = struct.unpack(">I", val)[0]
        elif t == 1095 and 1 <= len(val) <= 3:
            out["igp_metric"] = int.from_bytes(val, "big")
        elif t == 1096 and len(val) >= 4:
            srlgs = [
                struct.unpack_from(">I", val, i)[0]
                for i in range(0, len(val) - 3, 4)
            ]
            out["srlgs"] = sorted(set(srlgs))
        elif t == 1155 and len(val) == 4:
            out["prefix_metric"] = struct.unpack(">I", val)[0]
    return out


class BgpLsState:
    """Stateful BGP-LS RIB-In table producing normalized OSPFv2 ``Lsdb`` snapshots."""

    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.links: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
        self.prefixes: dict[tuple[str, str, str, int], dict[str, Any]] = {}

    @staticmethod
    def _node_key(n: dict[str, Any]) -> tuple[str, str, str]:
        return (
            dotted_area(str(n.get("area") or "0.0.0.0")),
            str(n.get("router_id") or ""),
            str(n.get("pseudonode_ip") or ""),
        )

    @staticmethod
    def _link_key(lk: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
        return (
            dotted_area(str(lk.get("area") or "0.0.0.0")),
            str(lk.get("local_router_id") or ""),
            str(lk.get("remote_router_id") or ""),
            str(lk.get("remote_pseudonode_ip") or ""),
            str(lk.get("local_ip") or ""),
            str(lk.get("remote_ip") or ""),
        )

    @staticmethod
    def _prefix_key(px: dict[str, Any]) -> tuple[str, str, str, int]:
        return (
            dotted_area(str(px.get("area") or "0.0.0.0")),
            str(px.get("router_id") or ""),
            str(px.get("prefix") or ""),
            int(px.get("ospf_route_type") or _OSPF_ROUTE_INTRA),
        )

    def apply_reach(self, nlri: dict[str, Any], attrs: dict[str, Any] | None = None) -> bool:
        """Apply one advertised BGP-LS NLRI + attributes; ignores non-OSPFv2 entries."""
        if int(nlri.get("protocol_id") or 0) != PROTOCOL_OSPFV2:
            return False
        attrs = attrs or {}
        ntype = int(nlri.get("nlri_type") or 0)
        if ntype == NLRI_NODE:
            key = self._node_key(nlri)
            if not key[1]:
                return False
            self.nodes[key] = {**nlri, **attrs}
            return True
        if ntype == NLRI_LINK:
            key = self._link_key(nlri)
            if not key[1] or not key[2]:
                return False
            self.links[key] = {**nlri, **attrs}
            return True
        if ntype == NLRI_PREFIX_IPV4:
            key = self._prefix_key(nlri)
            if not key[1] or not key[2]:
                return False
            self.prefixes[key] = {**nlri, **attrs}
            return True
        return False

    def apply_unreach(self, nlri: dict[str, Any]) -> bool:
        """Remove a withdrawn BGP-LS NLRI; returns True if an entry was present."""
        if int(nlri.get("protocol_id") or 0) != PROTOCOL_OSPFV2:
            return False
        ntype = int(nlri.get("nlri_type") or 0)
        if ntype == NLRI_NODE:
            return self.nodes.pop(self._node_key(nlri), None) is not None
        if ntype == NLRI_LINK:
            return self.links.pop(self._link_key(nlri), None) is not None
        if ntype == NLRI_PREFIX_IPV4:
            return self.prefixes.pop(self._prefix_key(nlri), None) is not None
        return False

    def to_lsdb(self) -> Lsdb:
        """Materialize current OSPFv2 BGP-LS state into a standard neutral ``Lsdb``."""
        lsdb = Lsdb()
        routers_by_key: dict[tuple[str, str], RouterLsa] = {}

        def get_router(rid: str, area: str) -> RouterLsa:
            k = (rid, area)
            if k not in routers_by_key:
                routers_by_key[k] = RouterLsa(router_id=rid, area=area)
            return routers_by_key[k]

        pseudonodes: dict[tuple[str, str, str], NetworkLsa] = {}

        for (area, rid, pnode_ip), rec in self.nodes.items():
            if pnode_ip:
                pseudonodes[(pnode_ip, rid, area)] = NetworkLsa(
                    address=pnode_ip, dr=rid, area=area, mask=None
                )
                continue
            rlsa = get_router(rid, area)
            flags = rec.get("node_flags")
            if isinstance(flags, int):
                rlsa.max_metric = rlsa.max_metric or bool(flags & 0x80)
                rlsa.asbr = rlsa.asbr or bool(flags & 0x20)
                rlsa.abr = rlsa.abr or bool(flags & 0x10)
            rlsa.abr = rlsa.abr or bool(rec.get("abr", False))
            rlsa.asbr = rlsa.asbr or bool(rec.get("asbr", False))
            rlsa.max_metric = rlsa.max_metric or bool(rec.get("overload", False))

        te_keys = ("te_metric", "max_bw_bps", "max_reservable_bw_bps", "unreserved_bw_bps", "admin_groups", "srlgs")
        for (area, lrid, rrid, r_pnode, local_ip, remote_ip), rec in self.links.items():
            rlsa = get_router(lrid, area)
            metric = rec.get("igp_metric")
            if metric is None:
                metric = 10
            if r_pnode:
                rlsa.links.append(
                    LinkRecord(
                        kind=KIND_TRANSIT,
                        link_id=r_pnode,
                        metric=int(metric),
                        link_data=local_ip or None,
                    )
                )
                net = pseudonodes.setdefault(
                    (r_pnode, rrid, area),
                    NetworkLsa(address=r_pnode, dr=rrid, area=area, mask=None),
                )
                if lrid not in net.attached:
                    net.attached.append(lrid)
            else:
                rlsa.links.append(
                    LinkRecord(
                        kind=KIND_P2P,
                        link_id=rrid,
                        metric=int(metric),
                        link_data=local_ip or None,
                    )
                )

            if any(rec.get(k) is not None for k in te_keys):
                lsdb.te_lsas.append(
                    TeLinkLsa(
                        adv_router=lrid,
                        area=area,
                        link_id=r_pnode or rrid,
                        local_ip=local_ip or None,
                        remote_ip=remote_ip or None,
                        te_metric=rec.get("te_metric"),
                        max_bw_bps=rec.get("max_bw_bps"),
                        max_reservable_bw_bps=rec.get("max_reservable_bw_bps"),
                        unreserved_bw_bps=list(rec.get("unreserved_bw_bps") or ()),
                        admin_groups=rec.get("admin_groups"),
                        srlgs=sorted({int(x) for x in (rec.get("srlgs") or ())}),
                    )
                )

        for (area, rid, cidr, rtype), rec in self.prefixes.items():
            metric = int(rec.get("prefix_metric") if rec.get("prefix_metric") is not None else 1)
            if rtype == _OSPF_ROUTE_INTRA:
                try:
                    net = ipaddress.IPv4Network(cidr, strict=False)
                except ValueError:
                    continue
                get_router(rid, area).links.append(
                    LinkRecord(
                        kind=KIND_STUB,
                        link_id=str(net.network_address),
                        metric=metric,
                        link_data=str(net.netmask),
                    )
                )
            elif rtype in (_OSPF_ROUTE_EXT1, _OSPF_ROUTE_EXT2):
                mtype = "E1" if rtype == _OSPF_ROUTE_EXT1 else "E2"
                lsdb.external_lsas.append(
                    ExternalLsa(adv_router=rid, prefix=cidr, metric=metric, metric_type=mtype)
                )
            elif rtype in (_OSPF_ROUTE_NSSA1, _OSPF_ROUTE_NSSA2):
                mtype = "N1" if rtype == _OSPF_ROUTE_NSSA1 else "N2"
                lsdb.nssa_lsas.append(
                    ExternalLsa(adv_router=rid, prefix=cidr, metric=metric, metric_type=mtype, area=area)
                )

        lsdb.router_lsas = list(routers_by_key.values())
        lsdb.network_lsas = list(pseudonodes.values())
        return lsdb


def translate_bgpls_update(
    state: BgpLsState,
    *,
    reach: Sequence[tuple[dict[str, Any], dict[str, Any]]] = (),
    unreach: Sequence[dict[str, Any]] = (),
) -> Lsdb:
    """Apply incremental reach/unreach updates to ``state`` and return an updated ``Lsdb``."""
    for nlri, attrs in reach:
        state.apply_reach(nlri, attrs)
    for nlri in unreach:
        state.apply_unreach(nlri)
    return state.to_lsdb()
