"""
==============================================================================
Module Name:   genie_junos.py
Description:   Source module genie_junos.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 genie_junos.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import importlib
import logging
import re

from src.vendors.base import (
    LinkRecord,
    Lsdb,
    LsdbAdapter,
    NeighborRecord,
    NetworkLsa,
    ParserError,
    RouterLsa,
    TeLinkLsa,
    as_list,
    dotted_area,
    dotted_mask,
    link_kind,
    normalize_state,
    parse_dead_time,
    parse_seq,
    parse_te_bandwidth_bps,
    role_from_dr,
)

logger = logging.getLogger(__name__)

_AREA_BLOCK = re.compile(r"(?m)^(?=[ \t]*OSPF database, Area )")


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bits(lsa: dict) -> int:
    """Router-LSA flag bits (B = 0x01 ABR, E = 0x02 ASBR) as Junos prints them: 'bits 0x2'."""
    try:
        return int(str((lsa.get("ospf-router-lsa") or {}).get("bits", "0")), 16)
    except ValueError:
        return 0


def _clean(value: str | None) -> str:
    """Junos marks our own LSAs with a leading '*' on the ID."""
    return str(value or "").lstrip("*").strip()


class GenieJunosAdapter(LsdbAdapter):
    """Parse Junos router/network LSAs (Genie) into the neutral model."""

    filters_by_process = False

    def __init__(self) -> None:
        try:
            module = importlib.import_module("genie.libs.parser.junos.show_ospf")
            from genie.metaparser.util.exceptions import SchemaEmptyParserError
        except ImportError as exc:
            raise ParserError(
                "Cisco pyATS/Genie is not installed. Run: pip install 'pyats[library]'"
            ) from exc
        self._parser = module.ShowOspfDatabaseExtensive
        self._neighbor_parser = module.ShowOspfNeighbor
        self._neighbor_detail_parser = module.ShowOspfNeighborDetail
        self.route_format = "junos"
        self._empty_exc = SchemaEmptyParserError

    def parse(self, raw_router: str, raw_network: str, process_id: str | None) -> Lsdb:
        if process_id is not None:
            logger.warning(
                "Junos has no numeric OSPF process ID; ignoring '%s'", process_id
            )
        lsdb = Lsdb()
        for area, lsas in self._lsas_by_area(raw_router, "router", required=True):
            lsdb.router_lsas.extend(
                self._router_lsa(area, d) for d in lsas if d.get("lsa-type") == "Router"
            )
            if (
                lsdb.router_id is None
            ):  # Junos marks the router's own LSAs ("*" / our-entry)
                lsdb.router_id = next(
                    (
                        _clean(d.get("advertising-router"))
                        for d in lsas
                        if d.get("our-entry")
                    ),
                    None,
                )
        for area, lsas in self._lsas_by_area(raw_network, "network", required=False):
            lsdb.network_lsas.extend(
                self._network_lsa(area, d)
                for d in lsas
                if d.get("lsa-type") == "Network"
            )
        return lsdb

    # ------------------------------------------------------------------ Genie
    def _lsas_by_area(
        self, raw: str, name: str, required: bool
    ) -> list[tuple[str, list[dict]]]:
        blocks = [b for b in _AREA_BLOCK.split(raw or "") if "OSPF database, Area" in b]
        if not blocks:
            if required:
                raise ParserError(
                    f"No 'OSPF database, Area ...' section found in the {name} LSDB output"
                )
            return []
        result = []
        for block in blocks:
            try:
                info = self._parser(device=None).parse(output=block)[
                    "ospf-database-information"
                ]
            except self._empty_exc:
                continue
            except Exception as exc:
                raise ParserError(
                    f"Genie failed to parse a Junos {name} LSDB block: {exc!r}"
                ) from exc
            area = str((info.get("ospf-area-header") or {}).get("ospf-area", "unknown"))
            result.append((area, as_list(info.get("ospf-database"))))
        return result

    def parse_neighbors(self, raw: str, process_id: str | None) -> list[NeighborRecord]:
        """``show ospf neighbor detail`` (adds the DR/BDR addresses, so each neighbour's role is known) or
        the plain ``show ospf neighbor`` table (no role)."""
        if not raw or not raw.strip():
            return []
        detailed = bool(re.search(r"^\s*Area\s+\S+,\s+opt\s+", raw, re.MULTILINE))
        parser = self._neighbor_detail_parser if detailed else self._neighbor_parser
        try:
            info = parser(device=None).parse(output=raw)["ospf-neighbor-information"]
        except self._empty_exc:
            return []
        except Exception as exc:
            raise ParserError(
                f"Genie failed to parse the Junos neighbour table: {exc!r}"
            ) from exc
        records = []
        for nbr in as_list(info.get("ospf-neighbor")):
            state, role = normalize_state(nbr.get("ospf-neighbor-state", ""))
            address = nbr.get("neighbor-address")
            if role is None and detailed:
                role = role_from_dr(
                    address, nbr.get("dr-address"), nbr.get("bdr-address")
                )
            priority = nbr.get("neighbor-priority")
            records.append(
                NeighborRecord(
                    router_id=_clean(nbr.get("neighbor-id")),
                    state=state,
                    role=role,
                    interface=nbr.get("interface-name"),
                    address=address,
                    area=nbr.get("ospf-area"),
                    priority=int(priority) if str(priority or "").isdigit() else None,
                    dead_time=parse_dead_time(nbr.get("activity-timer")),
                )
            )
        return records

    # ---------------------------------------------------------------- mapping
    def _router_lsa(self, area: str, lsa: dict) -> RouterLsa:
        bits = _bits(lsa)
        router = RouterLsa(
            router_id=_clean(lsa.get("advertising-router")),
            area=area,
            seq=parse_seq(lsa.get("sequence-number")),
            age=_int(lsa.get("age")),
            abr=bool(bits & 0x01),
            asbr=bool(bits & 0x02),
        )
        for link in as_list((lsa.get("ospf-router-lsa") or {}).get("ospf-link")):
            kind = link_kind(str(link.get("link-type-name", "")))
            if kind is None:
                continue
            try:
                metric = int(link.get("metric"))
            except (TypeError, ValueError):
                metric = None
            link_data = (
                _clean(link.get("link-data")) or None
            )  # own address; for a stub its mask
            router.links.append(
                LinkRecord(
                    kind=kind,
                    link_id=_clean(link.get("link-id")),
                    metric=metric,
                    link_data=link_data,
                )
            )
        return router

    def parse_opaque_te(
        self, raw_opaque: str, process_id: str | None
    ) -> list[TeLinkLsa]:
        """Parse Junos ``show ospf database opaque-area extensive`` output."""
        return parse_junos_opaque_te_text(raw_opaque)

    def _network_lsa(self, area: str, lsa: dict) -> NetworkLsa:
        body = lsa.get("ospf-network-lsa") or {}
        return NetworkLsa(
            address=_clean(lsa.get("lsa-id")),
            dr=_clean(lsa.get("advertising-router")),
            area=area,
            mask=dotted_mask(body.get("address-mask")),
            attached=[_clean(r) for r in as_list(body.get("attached-router"))],
            seq=parse_seq(lsa.get("sequence-number")),
            age=_int(lsa.get("age")),
        )


_JUNOS_OPAQ_AREA = re.compile(r"OSPF database,\s+Area\s+(\S+)", re.IGNORECASE)
_JUNOS_OPAQ_ROW = re.compile(
    r"^\s*OpaqArea\s+(\S+)\s+(\S+)\s+(0x[0-9a-fA-F]+|\S+)\s+(\d+)",
    re.IGNORECASE,
)


def parse_junos_opaque_te_text(raw: str) -> list[TeLinkLsa]:
    """Parse Junos ``show ospf database opaque-area extensive`` TE Link TLVs without Genie dependency."""
    results: list[TeLinkLsa] = []
    area = "0.0.0.0"
    cur: dict | None = None

    def flush() -> None:
        nonlocal cur
        if cur is not None and cur.get("adv") and cur.get("link_id"):
            prios = cur.get("unreserved") or {}
            unres = [prios.get(i, 0.0) for i in range(8)] if prios else []
            results.append(
                TeLinkLsa(
                    adv_router=cur["adv"],
                    area=dotted_area(cur["area"]),
                    link_id=cur["link_id"],
                    local_ip=cur.get("local_ip"),
                    remote_ip=cur.get("remote_ip"),
                    te_metric=cur.get("te_metric"),
                    max_bw_bps=cur.get("max_bw_bps"),
                    max_reservable_bw_bps=cur.get("max_res_bw_bps"),
                    unreserved_bw_bps=unres,
                    admin_groups=cur.get("admin_groups"),
                    srlgs=sorted(cur.get("srlgs") or ()),
                    age=cur.get("age"),
                    seq=cur.get("seq"),
                )
            )
        cur = None

    for line in (raw or "").splitlines():
        if m := _JUNOS_OPAQ_AREA.search(line):
            flush()
            area = m.group(1)
            continue
        if m := _JUNOS_OPAQ_ROW.match(line):
            flush()
            cur = {
                "area": area,
                "adv": _clean(m.group(2)),
                "seq": parse_seq(m.group(3)),
                "age": int(m.group(4)),
                "srlgs": set(),
                "unreserved": {},
            }
            continue
        if cur is None:
            continue
        if m := re.search(r"Link ID\s*\(\d+\)[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE):
            cur["link_id"] = m.group(1)
        elif m := re.search(r"Local interface IP address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE):
            cur["local_ip"] = m.group(1)
        elif m := re.search(r"Remote interface IP address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE):
            cur["remote_ip"] = m.group(1)
        elif m := re.search(r"Traffic engineering metric[^:]*:\s*(\d+)", line, re.IGNORECASE):
            cur["te_metric"] = int(m.group(1))
        elif m := re.search(r"Maximum bandwidth[^:]*:\s*(.+)", line, re.IGNORECASE):
            bw = parse_te_bandwidth_bps(m.group(1))
            if bw is not None:
                cur["max_bw_bps"] = bw
        elif m := re.search(r"Maximum reservable bandwidth[^:]*:\s*(.+)", line, re.IGNORECASE):
            bw = parse_te_bandwidth_bps(m.group(1))
            if bw is not None:
                cur["max_res_bw_bps"] = bw
        elif m := re.search(r"Administrative group[^:]*:\s*(0x[0-9a-fA-F]+|\d+)", line, re.IGNORECASE):
            v = m.group(1)
            cur["admin_groups"] = int(v, 16) if v.lower().startswith("0x") else int(v)
        elif m := re.search(r"Shared risk link group[^:]*:\s*(.+)", line, re.IGNORECASE):
            for tok in re.findall(r"\b\d+\b", m.group(1)):
                cur["srlgs"].add(int(tok))
        elif "Priority" in line:
            for pm in re.finditer(r"Priority\s*([0-7])\s*:\s*([^,]+)", line, re.IGNORECASE):
                bw = parse_te_bandwidth_bps(pm.group(2))
                if bw is not None:
                    cur["unreserved"][int(pm.group(1))] = bw
    flush()
    return results
