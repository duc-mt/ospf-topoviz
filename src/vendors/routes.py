"""
==============================================================================
Module Name:   routes.py
Description:   Parsers for a router's OSPF routing table (RIB) - ``show ip route ospf`` and equivalents.
==============================================================================
The layouts below are the documented/typical CLI output of each platform:

* ``ios``  Cisco IOS / IOS-XE:  ``O IA  10.1.1.0/24 [110/30] via 10.12.0.2, 00:05:23, GigabitEthernet0/1``
* ``eos``  Arista EOS:          `` O E2  172.16.0.0/16 [110/20] via 10.12.0.2, Ethernet1``
* ``frr``  VyOS / FRR:          ``O>* 10.1.1.0/24 [110/20] via 10.12.0.2, eth1, weight 1, 00:05:23``
* ``nxos`` Cisco NX-OS:         ``    *via 10.12.0.2, Eth1/1, [110/41], 00:05:23, ospf-1, intra``
* ``junos`` Juniper Junos:      ``10.1.1.0/24  *[OSPF/10] 00:05:23, metric 30`` + ``> to 10.12.0.2 via ge-0/0/0.0``

Real devices vary between software versions; capture a sample with ``--save-raw`` and replay it with
``--replay`` when a platform's output is not parsed as expected.
"""

from __future__ import annotations

import logging
import re

from src.vendors.base import (
    ROUTE_E1,
    ROUTE_E2,
    ROUTE_EXTERNAL,
    ROUTE_INTER,
    ROUTE_INTERNAL,
    ROUTE_INTRA,
    ROUTE_N1,
    ROUTE_N2,
    NextHop,
    OSPFRoute,
    ParserError,
)

logger = logging.getLogger(__name__)

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
_UPTIME = re.compile(r"^(?:\d+[wdhms])+$|^\d+:\d+:\d+$")  # 00:05:23, 1d02h, 3w2d
_NOT_INTERFACE = re.compile(r"^(?:weight|tag|label|metric|onlink)\b")
_CODE_TYPES = {
    "": ROUTE_INTRA,
    "IA": ROUTE_INTER,
    "E1": ROUTE_E1,
    "E2": ROUTE_E2,
    "N1": ROUTE_N1,
    "N2": ROUTE_N2,
}
_NX_TYPES = {
    "intra": ROUTE_INTRA,
    "inter": ROUTE_INTER,
    "type-1": ROUTE_E1,
    "type-2": ROUTE_E2,
    "nssa-type-1": ROUTE_N1,
    "nssa-type-2": ROUTE_N2,
}

# IOS / EOS / FRR: "<codes> <prefix>[/len] [ad/metric] <next-hop text>"
_ROUTE = re.compile(
    rf"^\s*(?P<codes>[A-Za-z][A-Za-z0-9*>+%\s]*?)\s+(?P<prefix>{_IP})(?:/(?P<len>\d{{1,2}}))?"
    r"\s+\[(?P<ad>\d+)/(?P<metric>\d+)\](?P<rest>.*)$"
)
_CONTINUATION = re.compile(r"^\s+\*?\s*(?:\[\d+/\d+\]\s+)?(?P<rest>via\s+.*)$")
_SUBNETTED = re.compile(rf"^\s*{_IP}/(?P<len>\d{{1,2}})\s+is\s+subnetted")
_VARIABLY = re.compile(r"is\s+variably\s+subnetted")


def parse_routes(fmt: str, raw: str, process_id: str | None = None) -> list[OSPFRoute]:
    """Parse the OSPF routes out of a routing-table dump.

    Args:
        fmt: ``"ios"``, ``"eos"``, ``"frr"``, ``"nxos"`` or ``"junos"``.
        raw: The command output.
        process_id: Keep only this OSPF process where the output names it (NX-OS); other platforms list
            the processes together (IOS can filter in the command itself, ``show ip route ospf <pid>``).

    Raises:
        ParserError: For an unknown ``fmt``.
    """
    if not raw or not raw.strip():
        return []
    if fmt in ("ios", "eos", "frr"):
        return _parse_code_style(raw, frr=(fmt == "frr"))
    if fmt == "nxos":
        return _parse_nxos(raw, process_id)
    if fmt == "junos":
        return _parse_junos(raw)
    raise ParserError(f"No routing-table parser for format {fmt!r}")


def _is_multicast(prefix: str) -> bool:
    return 224 <= int(prefix.split(".", maxsplit=1)[0]) <= 239


def _next_hop(text: str) -> NextHop | None:
    """``via 10.12.0.2, 00:05:23, Gi0/1`` / ``via 10.12.0.2, eth1, weight 1`` / ``is directly connected, eth1``."""
    if m := re.search(rf"\bvia\s+({_IP})(.*)", text):
        ip, tail = m.group(1), m.group(2)
    elif "directly connected" in text:
        ip, tail = None, text.split("directly connected", 1)[1]
    else:
        return None
    interface = None
    for token in (t.strip() for t in tail.split(",")):
        if not token or _UPTIME.match(token) or _NOT_INTERFACE.match(token):
            continue
        interface = token.split()[0]
        break
    return NextHop(ip=ip, interface=interface)


def _parse_code_style(raw: str, frr: bool) -> list[OSPFRoute]:
    routes: list[OSPFRoute] = []
    current: OSPFRoute | None = None
    default_len: int | None = (
        None  # "10.0.0.0/24 is subnetted" - the mask of the entries below it
    )
    for line in raw.splitlines():
        if m := _SUBNETTED.match(line):
            default_len = int(m.group("len"))
            continue
        if _VARIABLY.search(line):
            default_len = None
            continue
        if m := _ROUTE.match(line):
            current = None
            codes = m.group("codes").strip()
            if not codes.startswith(
                "O"
            ):  # a non-OSPF route (the command should not print any)
                continue
            kind = re.sub(r"[*>+%\s]", "", codes)[1:]
            if kind not in _CODE_TYPES:
                continue
            length = m.group("len")
            length = int(length) if length is not None else default_len
            if length is None:
                logger.debug(
                    "Route %s has no prefix length and no 'is subnetted' header; skipped",
                    m.group("prefix"),
                )
                continue
            if _is_multicast(m.group("prefix")):
                continue
            route = OSPFRoute.from_cidr(
                f"{m.group('prefix')}/{length}",
                _CODE_TYPES[kind],
                metric=int(m.group("metric")),
                distance=int(m.group("ad")),
                active=(">" in codes)
                if frr
                else True,  # FRR marks the selected route with '>'
            )
            if hop := _next_hop(m.group("rest")):
                route.next_hops.append(hop)
            routes.append(route)
            current = route
        elif current is not None and (m := _CONTINUATION.match(line)):
            if hop := _next_hop(m.group("rest")):
                current.next_hops.append(hop)
    return routes


def _parse_nxos(raw: str, process_id: str | None) -> list[OSPFRoute]:
    routes: dict[str, OSPFRoute] = {}
    prefix: str | None = None
    for line in raw.splitlines():
        if m := re.match(rf"^\s*({_IP}/\d{{1,2}}),\s+ubest/mbest", line):
            prefix = m.group(1)
            continue
        m = re.match(r"^\s*\*?via\s+(?P<body>.+)$", line)
        if not (m and prefix):
            continue
        tokens = [t.strip() for t in m.group("body").split(",")]
        metric_at = next(
            (i for i, t in enumerate(tokens) if re.fullmatch(r"\[\d+/\d+\]", t)), None
        )
        if metric_at is None or len(tokens) <= metric_at + 2:
            continue
        distance, metric = (int(x) for x in tokens[metric_at][1:-1].split("/"))
        source = re.fullmatch(r"ospf-(\S+)", tokens[metric_at + 2])
        if not source or (process_id is not None and source.group(1) != process_id):
            continue
        route_type, tag = ROUTE_INTERNAL, None
        for token in tokens[metric_at + 3 :]:
            if token in _NX_TYPES:
                route_type = _NX_TYPES[token]
            elif t := re.fullmatch(r"tag\s+(\d+)", token):
                tag = int(t.group(1))
        gateway = tokens[0].split("%")[0]
        hop = NextHop(
            ip=gateway if re.fullmatch(_IP, gateway) else None,
            interface=tokens[1] if metric_at > 1 else None,
        )
        if _is_multicast(prefix.split("/")[0]):
            continue
        route = routes.get(prefix)
        if route is None:
            route = routes[prefix] = OSPFRoute.from_cidr(
                prefix,
                route_type,
                metric=metric,
                tag=tag,
                distance=distance,
                process_id=source.group(1),
            )
        route.next_hops.append(hop)
    return list(routes.values())


def _parse_junos(raw: str) -> list[OSPFRoute]:
    routes: list[OSPFRoute] = []
    current: OSPFRoute | None = None
    pending: str | None = (
        None  # a prefix too long for its column: the protocol part is on the next line
    )
    for line in raw.splitlines():
        head = re.match(rf"^({_IP}/\d{{1,2}})\s*(.*)$", line)
        if head:
            pending, rest = head.group(1), head.group(2)
        elif pending and line[:1].isspace() and "[" in line:
            rest = line.strip()
        else:
            rest = None
        if rest is not None and "[" in rest:
            proto = re.match(
                r"^(?P<flag>[*+\-])?\[(?P<name>[A-Za-z-]+)/(?P<pref>\d+)\]\s*(?P<tail>.*)$",
                rest,
            )
            current = None
            if (
                not proto
                or proto.group("name") != "OSPF"
                or _is_multicast(pending.split("/")[0])
            ):
                continue
            tail = proto.group("tail")
            metric = re.search(r"metric\s+(\d+)", tail)
            tag = re.search(r"tag\s+(\d+)", tail)
            preference = int(proto.group("pref"))
            current = OSPFRoute.from_cidr(
                pending,
                # Brief output does not say intra/inter (both are preference 10) or E1/E2 (both 150).
                ROUTE_EXTERNAL if preference >= 150 else ROUTE_INTERNAL,
                metric=int(metric.group(1)) if metric else None,
                tag=int(tag.group(1)) if tag else None,
                distance=preference,
                active=proto.group("flag") in ("*", "+"),
            )
            routes.append(current)
            pending = None
            continue
        if current is None:
            continue
        if m := re.match(rf"^\s+>?\s*to\s+({_IP})\s+via\s+([^\s,]+)", line):
            current.next_hops.append(NextHop(ip=m.group(1), interface=m.group(2)))
        elif m := re.match(r"^\s+>?\s*via\s+([^\s,]+)", line):
            current.next_hops.append(NextHop(ip=None, interface=m.group(1)))
    return routes
