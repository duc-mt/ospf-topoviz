"""
==============================================================================
Module Name:   correlation.py
Description:   Cross-checks the three views of an OSPF network - the LSDB topology, each router's
               neighbour table and its routing table (RIB) - and traces how a prefix is reached.
==============================================================================
What is compared with what:

* LSDB vs neighbour table: an adjacency the LSDB still advertises while the router's own table shows
  the neighbour stuck (Init / ExStart / ...) or gone; a Full neighbour the LSDB has no link for.
* Neighbour table now vs last run: state changes, lost and new neighbours (flaps).
* SPF vs RIB: Dijkstra over the LSDB graph from the polled router gives the cost and the first hops
  every intra-area prefix *should* have; the router's actual ``show ip route ospf`` is held against it.

Limits (by design of the data collected): only Type 1/2 LSAs are read, so inter-area (Type 3) and
external (Type 5/7) routes cannot be recomputed and are reported as "unverified". The RIB command only
lists OSPF routes, so a prefix absent from it can have been beaten by a lower-distance source, filtered, or
never installed - the report says which of these are possible, it cannot tell them apart. FRR and Junos
also print OSPF routes that lost to another source, and those *are* identified as overridden.
"""

from __future__ import annotations

import heapq
import ipaddress
import logging
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

import networkx as nx

from src import node_sort_key
from src.vendors.base import (
    INTERNAL_ROUTE_TYPES,
    ROUTE_INTRA,
    OSPFRoute,
    SourceDetail,
    state_severity,
)

logger = logging.getLogger(__name__)

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEVERITY_RANK = {CRITICAL: 0, WARNING: 1, INFO: 2}

# --- finding kinds -------------------------------------------------------------------------------
ADJ_NOT_FULL = "ADJ_NOT_FULL"  # LSDB advertises the adjacency, the neighbour table says it is not Full
ADJ_MISSING = "ADJ_MISSING"  # LSDB advertises the adjacency, the neighbour table does not list the neighbour
NBR_NOT_IN_LSDB = "NBR_NOT_IN_LSDB"  # neighbour is Full but the LSDB has no link to it
NBR_STATE_CHANGE = "NBR_STATE_CHANGE"  # neighbour state differs from the previous run
NBR_LOST = "NBR_LOST"  # neighbour was there last run, is gone now
NBR_NEW = "NBR_NEW"  # neighbour was not there last run
ROUTE_MISSING = (
    "ROUTE_MISSING"  # LSDB says reachable, the OSPF RIB has no such route (blackhole)
)
NEXTHOP_DOWN = "NEXTHOP_DOWN"  # route goes via a neighbour that is not Full (blackhole)
ROUTE_STALE = (
    "ROUTE_STALE"  # intra-area route in the RIB that no LSA in the LSDB advertises
)
ROUTE_OVERRIDDEN = (
    "ROUTE_OVERRIDDEN"  # OSPF route listed but another source won (lower distance)
)
COST_MISMATCH = (
    "COST_MISMATCH"  # RIB cost differs from the SPF cost (suboptimal routing)
)
NEXTHOP_MISMATCH = (
    "NEXTHOP_MISMATCH"  # RIB next hop is not on any LSDB shortest path (suboptimal)
)
ECMP_MISSING = "ECMP_MISSING"  # LSDB has more equal-cost paths than the RIB installed
RIB_EMPTY = "RIB_EMPTY"  # routing table collected but empty

NEIGHBOR_KINDS = (
    ADJ_NOT_FULL,
    ADJ_MISSING,
    NBR_NOT_IN_LSDB,
    NBR_STATE_CHANGE,
    NBR_LOST,
    NBR_NEW,
)
FLAP_KINDS = (NBR_STATE_CHANGE, NBR_LOST, NBR_NEW)
BLACKHOLE_KINDS = (ROUTE_MISSING, NEXTHOP_DOWN, ROUTE_STALE, RIB_EMPTY)
SUBOPTIMAL_KINDS = (ROUTE_OVERRIDDEN, COST_MISMATCH, NEXTHOP_MISMATCH, ECMP_MISSING)

_STATE_HINTS = {
    "Down": "no hellos seen: link, ACL or authentication problem",
    "Attempt": "no hellos seen from a configured NBMA neighbour: check reachability",
    "Init": "hellos arrive one way only: ACL/authentication, area, timers or packet loss on the return path",
    "ExStart": "stuck negotiating master/slave: typically an MTU mismatch or a duplicate router ID",
    "Exchange": "database exchange not completing: typically an MTU mismatch or packet loss",
    "Loading": "waiting for LSAs: packet loss, MTU, or a corrupt LSA",
    "2-Way": "bidirectional but not adjacent: expected only between two DROthers on a broadcast segment",
}
_STATE_SEVERITY = {
    "Down": CRITICAL,
    "Attempt": CRITICAL,
    "Init": CRITICAL,
    "ExStart": CRITICAL,
    "Exchange": CRITICAL,
    "Loading": WARNING,
    "2-Way": WARNING,
}


@dataclass
class Finding:
    """One thing the cross-check found worth a person's attention (JSON-friendly via ``to_dict``)."""

    category: str  # "neighbor" | "route"
    kind: str
    severity: str
    router: str  # the polled router whose tables were checked
    subject: str  # neighbour ID, or prefix
    message: str
    hint: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationReport:
    findings: list[Finding] = field(default_factory=list)
    #: One entry per polled router whose routing table was checked: counts of routes seen / verified / ok.
    rib_checks: list[dict[str, Any]] = field(default_factory=list)


# ====================================================================== SPF
@dataclass
class SpfResult:
    """Shortest-path tree from one router (equal-cost paths kept)."""

    source: str
    dist: dict[str, int]
    #: node -> the first routers on its shortest paths out of ``source`` (empty for ``source`` itself).
    first_hops: dict[str, set[str]]
    preds: dict[str, set[str]]

    def paths(self, target: str, limit: int = 8) -> list[list[str]]:
        """Up to ``limit`` shortest paths ``source -> ... -> target`` (node IDs, networks included)."""
        if target not in self.dist:
            return []
        found: list[list[str]] = []

        def walk(node: str, tail: list[str]) -> None:
            if len(found) >= limit:
                return
            if node == self.source:
                found.append([node, *tail])
                return
            for pred in sorted(self.preds.get(node, ()), key=node_sort_key):
                walk(pred, [node, *tail])

        walk(target, [])
        return found


def _usable(attrs: dict[str, Any], area: str | None) -> bool:
    if (
        attrs.get("link_state") == "one-way"
    ):  # OSPF's SPF ignores a link the far end does not advertise back
        return False
    if area is not None and attrs.get("area") != area:
        return False
    return isinstance(attrs.get("metric"), int)


def spf(graph: nx.DiGraph, source: str, area: str | None = None) -> SpfResult:
    """Dijkstra over the LSDB graph from ``source``, keeping every equal-cost path.

    Router->router and router->network edges cost their advertised metric; network->router edges cost 0.
    ``area`` restricts the walk to links of one area (intra-area routes are calculated per area).
    The first hop of a path is the first *router* after ``source`` (a shared segment is looked through).
    """
    dist = {source: 0}
    first: dict[str, set[str]] = {source: set()}
    preds: dict[str, set[str]] = {source: set()}
    heap: list[tuple[int, tuple, str]] = [(0, node_sort_key(source), source)]
    while heap:
        d, _key, u = heapq.heappop(heap)
        if d > dist[u]:
            continue
        for v, attrs in graph.adj[u].items():
            if not _usable(attrs, area):
                continue
            nd = d + attrs["metric"]
            if u == source:
                hops = {v}
            elif (
                graph.nodes[u].get("type") == "network" and u in first[u]
            ):  # first[u] == {u}: the segment itself
                hops = {v if x == u else x for x in first[u]}
            else:
                hops = set(first[u])
            if v not in dist or nd < dist[v]:
                dist[v], first[v], preds[v] = nd, hops, {u}
                heapq.heappush(heap, (nd, node_sort_key(v), v))
            elif nd == dist[v]:
                first[v] |= hops
                preds[v].add(u)
    return SpfResult(source, dist, first, preds)


# =============================================================== helpers
def _is_ip(text: Any) -> bool:
    try:
        ipaddress.IPv4Address(str(text))
        return True
    except ValueError:
        return False


def prefix_origins(graph: nx.DiGraph) -> dict[str, list[dict[str, Any]]]:
    """``prefix -> [{node, kind, metric, area}]``: who advertises what in the LSDB (Type 1 stubs, Type 2 networks)."""
    index: dict[str, list[dict[str, Any]]] = {}
    for node, attrs in graph.nodes(data=True):
        if attrs.get("type") == "router":
            for entry in attrs.get("prefixes") or ():
                index.setdefault(entry["prefix"], []).append(
                    {
                        "node": node,
                        "kind": "stub",
                        "metric": entry["metric"],
                        "area": entry["area"],
                    }
                )
        elif attrs.get("type") == "network" and attrs.get("prefix"):
            area = next(iter(attrs.get("areas") or ()), None)
            index.setdefault(attrs["prefix"], []).append(
                {"node": node, "kind": "transit", "metric": 0, "area": area}
            )
    return index


def ip_owners(graph: nx.DiGraph, details: Iterable[SourceDetail]) -> dict[str, str]:
    """Interface address -> router ID, from the LSDB (each router's own address on its links) and neighbour tables."""
    owners: dict[str, str] = {}
    for u, _v, attrs in graph.edges(data=True):
        ip = attrs.get("interface_address")
        if ip and _is_ip(ip) and graph.nodes[u].get("type") == "router":
            owners.setdefault(str(ip), u)
    for detail in details:
        for nbr in detail.neighbors:
            if nbr.address:
                owners.setdefault(nbr.address, nbr.router_id)
    return owners


def _origin_cost(result: SpfResult, origin: dict[str, Any]) -> int | None:
    node = origin["node"]
    if node not in result.dist:
        return None
    return result.dist[node] + (origin["metric"] if origin["kind"] == "stub" else 0)


def _attached(graph: nx.DiGraph, router: str, origin: dict[str, Any]) -> bool:
    """True if ``router`` itself owns the prefix (advertises it, or sits on the transit segment)."""
    if origin["node"] == router:
        return True
    return origin["kind"] == "transit" and graph.has_edge(router, origin["node"])


# ====================================================== neighbour vs LSDB
def _expected_adjacencies(
    graph: nx.DiGraph, router: str
) -> list[tuple[str, bool, str]]:
    """``(neighbour, must_be_full, link kind)`` for every adjacency the LSDB says ``router`` has.

    A point-to-point link needs a Full neighbour. On a shared segment only adjacencies with the DR (or, if
    ``router`` is the DR, with everyone) must be Full; between two DROthers 2-Way is fine.
    """
    wanted: list[tuple[str, bool, str]] = []
    for target, attrs in graph.adj[router].items():
        if attrs.get("link_state") == "one-way":
            continue
        kind = attrs.get("link_type")
        if kind == "point-to-point" and graph.nodes[target].get("type") == "router":
            wanted.append((target, True, "p2p"))
        elif kind == "transit" and graph.nodes[target].get("type") == "network":
            dr = graph.nodes[target].get("dr")
            for other in graph.adj[target]:
                if other != router and graph.nodes[other].get("type") == "router":
                    wanted.append((other, dr in (router, other), "transit"))
    return wanted


def _linked(graph: nx.DiGraph, router: str, neighbor: str) -> bool:
    if graph.has_edge(router, neighbor):
        return True
    return any(
        graph.nodes[seg].get("type") == "network" and graph.has_edge(seg, neighbor)
        for seg in graph.adj[router]
    )


def neighbor_findings(graph: nx.DiGraph, detail: SourceDetail) -> list[Finding]:
    """Hold one router's neighbour table against the adjacencies its LSDB entry advertises."""
    router = detail.router_id
    if not router or router not in graph or not detail.neighbors_known:
        return []
    table: dict[str, list] = {}
    for nbr in detail.neighbors:
        table.setdefault(nbr.router_id, []).append(nbr)

    out: list[Finding] = []
    seen: set[str] = set()
    for neighbor, must_be_full, kind in _expected_adjacencies(graph, router):
        if neighbor in seen:
            continue
        seen.add(neighbor)
        rows = table.get(neighbor)
        if not rows:
            out.append(
                Finding(
                    "neighbor",
                    ADJ_MISSING,
                    WARNING,
                    router,
                    neighbor,
                    f"LSDB shows {router} adjacent to {neighbor} ({kind}) but {neighbor} is not in its neighbour table",
                    "the LSA has not aged out/been re-originated yet, or hellos are no longer received",
                    {"link": kind},
                )
            )
            continue
        best = min(rows, key=lambda r: state_severity(r.state))
        acceptable = best.state == "Full" or (
            not must_be_full and best.state == "2-Way"
        )
        if not acceptable:
            hint = _STATE_HINTS.get(best.state, "")
            out.append(
                Finding(
                    "neighbor",
                    ADJ_NOT_FULL,
                    _STATE_SEVERITY.get(best.state, WARNING),
                    router,
                    neighbor,
                    f"LSDB has {router} -> {neighbor} but the neighbour is {best.state}"
                    + (f" on {best.interface}" if best.interface else ""),
                    hint,
                    {"state": best.state, "interface": best.interface, "link": kind},
                )
            )

    for neighbor, rows in table.items():
        if (
            any(r.state == "Full" for r in rows)
            and neighbor not in seen
            and not _linked(graph, router, neighbor)
        ):
            first = rows[0]
            out.append(
                Finding(
                    "neighbor",
                    NBR_NOT_IN_LSDB,
                    WARNING,
                    router,
                    neighbor,
                    f"{neighbor} is Full with {router}"
                    + (f" on {first.interface}" if first.interface else "")
                    + " but the LSDB has no link between them",
                    "the LSDB is stale or incomplete (another area/process, or this seed's area was not polled)",
                    {"interface": first.interface},
                )
            )
    return out


def flap_findings(
    current: Sequence[dict], previous: Sequence[dict] | None
) -> list[Finding]:
    """Neighbour changes since the previous accepted run (state changes, lost and new neighbours).

    Only routers whose neighbour table was read in *both* runs are compared, so polling a different set
    of seeds does not look like a mass neighbour loss.
    """
    if not previous:
        return []
    common = {r["router"] for r in current} & {r["router"] for r in previous}

    def key(row: dict) -> tuple:
        return (row["router"], row["neighbor"], row.get("interface") or "")

    now = {key(r): r for r in current if r["router"] in common}
    before = {key(r): r for r in previous if r["router"] in common}
    out: list[Finding] = []
    for k in sorted(
        set(now) | set(before),
        key=lambda k: (node_sort_key(k[0]), node_sort_key(k[1]), k[2]),
    ):
        old, new = before.get(k), now.get(k)
        router, neighbor, interface = k
        where = f" on {interface}" if interface else ""
        if old and new and old["state"] != new["state"]:
            worse = state_severity(new["state"]) > state_severity(old["state"])
            sev = _STATE_SEVERITY.get(new["state"], WARNING) if worse else INFO
            out.append(
                Finding(
                    "neighbor",
                    NBR_STATE_CHANGE,
                    sev,
                    router,
                    neighbor,
                    f"{router} <-> {neighbor}{where}: {old['state']} -> {new['state']}",
                    _STATE_HINTS.get(new["state"], "") if worse else "recovered",
                    {
                        "previous": old["state"],
                        "state": new["state"],
                        "interface": interface or None,
                    },
                )
            )
        elif old and not new:
            out.append(
                Finding(
                    "neighbor",
                    NBR_LOST,
                    CRITICAL if old["state"] == "Full" else WARNING,
                    router,
                    neighbor,
                    f"{router} lost neighbour {neighbor}{where} (was {old['state']})",
                    "link down, hellos lost, or the neighbour was shut down",
                    {"previous": old["state"], "interface": interface or None},
                )
            )
        elif new and not old:
            out.append(
                Finding(
                    "neighbor",
                    NBR_NEW,
                    INFO if new["state"] == "Full" else WARNING,
                    router,
                    neighbor,
                    f"{router} has a new neighbour {neighbor}{where} ({new['state']})",
                    "",
                    {"state": new["state"], "interface": interface or None},
                )
            )
    return out


# ===================================================== SPF vs routing table
def _first_hop_routers(graph: nx.DiGraph, hops: Iterable[str]) -> set[str]:
    return {h for h in hops if graph.nodes[h].get("type") == "router"}


def route_findings(
    graph: nx.DiGraph,
    detail: SourceDetail,
    index: dict[str, list[dict[str, Any]]],
    owners: dict[str, str],
) -> tuple[list[Finding], dict[str, Any]]:
    """Check one router's OSPF routing table against what SPF over its LSDB predicts.

    Strictly verified: intra-area prefixes of the areas the router belongs to (that is where Type 1/2
    LSAs are complete). Everything else in the RIB is counted as unverified, not judged.
    """
    router = detail.router_id
    check = {
        "router": router,
        "routes": len(detail.routes or ()),
        "expected": 0,
        "verified": 0,
        "unverified": 0,
        "ok": 0,
    }
    if not router or router not in graph or detail.routes is None:
        return [], check
    areas = sorted(graph.nodes[router].get("areas") or ())
    trees = {area: spf(graph, router, area) for area in areas}

    # What the RIB should hold: prefix -> (cost, first-hop routers, origins)
    expected: dict[str, tuple[int, set[str], list[dict[str, Any]]]] = {}
    for prefix, origins in index.items():
        if any(_attached(graph, router, o) for o in origins):
            continue  # a connected/own prefix: its Connected route beats OSPF, so it is not in the OSPF RIB
        best: int | None = None
        hops: set[str] = set()
        usable = []
        for origin in origins:
            tree = trees.get(origin["area"])
            cost = _origin_cost(tree, origin) if tree else None
            if cost is None:
                continue
            usable.append(origin)
            node_hops = _first_hop_routers(graph, tree.first_hops[origin["node"]])
            if best is None or cost < best:
                best, hops = cost, set(node_hops)
            elif cost == best:
                hops |= node_hops
        if best is not None:
            expected[prefix] = (best, hops, usable)
    check["expected"] = len(expected)

    rib: dict[str, OSPFRoute] = {}
    for route in detail.routes:
        current = rib.get(route.cidr)
        if current is None or (route.active and not current.active):
            rib[route.cidr] = route

    findings: list[Finding] = []
    if not rib:
        if expected:
            findings.append(
                Finding(
                    "route",
                    RIB_EMPTY,
                    WARNING,
                    router,
                    "-",
                    f"the OSPF routing table of {router} is empty but the LSDB advertises {len(expected)} prefix(es)",
                    "the command printed nothing usable, or OSPF routes are not installed; check the raw output "
                    "(--save-raw)",
                )
            )
        return findings, check

    states = {}
    for nbr in detail.neighbors:
        states.setdefault(nbr.router_id, []).append(nbr.state)

    for prefix, (cost, hops, origins) in sorted(
        expected.items(), key=lambda kv: node_sort_key(kv[0].split("/")[0])
    ):
        route = rib.get(prefix)
        who = ", ".join(sorted({o["node"] for o in origins}, key=node_sort_key))
        if route is None:
            findings.append(
                Finding(
                    "route",
                    ROUTE_MISSING,
                    CRITICAL,
                    router,
                    prefix,
                    f"{prefix} is advertised by {who} (SPF cost {cost}) but {router} has no OSPF route for it",
                    "overridden by a lower-distance route (static/BGP), filtered (distribute-list / prefix-list) or "
                    "not installed; `show ip route <prefix>` shows which",
                    {"expected_cost": cost, "origins": who},
                )
            )
            continue
        check["verified"] += 1
        if not route.active and any(h.ip for h in route.next_hops):
            findings.append(
                Finding(
                    "route",
                    ROUTE_OVERRIDDEN,
                    WARNING,
                    router,
                    prefix,
                    f"{prefix}: the OSPF route is listed but not the active one on {router}",
                    "another source with a lower administrative distance (static/BGP/...) is being used instead",
                    {"distance": route.distance},
                )
            )
            continue
        problem = False
        if (
            route.metric is not None
            and route.route_type in INTERNAL_ROUTE_TYPES
            and route.metric != cost
        ):
            problem = True
            findings.append(
                Finding(
                    "route",
                    COST_MISMATCH,
                    WARNING,
                    router,
                    prefix,
                    f"{prefix}: routing table cost {route.metric}, SPF over the LSDB gives {cost}",
                    "the RIB is not following the shortest path (stale route, changed metric not yet flooded, "
                    "or SPF running late)"
                    if route.metric > cost
                    else "the RIB cost is lower than the LSDB allows (stale route, or a metric the LSDB does not show)",
                    {"rib_cost": route.metric, "spf_cost": cost},
                )
            )
        via = {owners.get(h.ip) for h in route.next_hops if h.ip}
        if via and None not in via:  # every next hop identified
            stray = via - hops
            if stray and hops:
                problem = True
                findings.append(
                    Finding(
                        "route",
                        NEXTHOP_MISMATCH,
                        WARNING,
                        router,
                        prefix,
                        f"{prefix}: next hop via {', '.join(sorted(stray, key=node_sort_key))} is not on a shortest path "
                        f"(SPF: via {', '.join(sorted(hops, key=node_sort_key))})",
                        "traffic takes a longer path than the LSDB allows",
                        {"rib": sorted(via), "spf": sorted(hops)},
                    )
                )
            elif hops - via:
                problem = True
                findings.append(
                    Finding(
                        "route",
                        ECMP_MISSING,
                        WARNING,
                        router,
                        prefix,
                        f"{prefix}: SPF has {len(hops)} equal-cost paths, the RIB installs {len(via)} "
                        f"(missing via {', '.join(sorted(hops - via, key=node_sort_key))})",
                        "maximum-paths limit, a filtered path, or a path still being installed",
                        {"rib": sorted(via), "spf": sorted(hops)},
                    )
                )
            broken = {}  # next-hop router -> its non-Full state (a router with any Full adjacency is fine)
            for hop_router in via:
                seen_states = states.get(hop_router, [])
                bad = [st for st in seen_states if st not in ("Full", "2-Way")]
                if bad and "Full" not in seen_states:
                    broken[hop_router] = bad[0]
            if broken:
                problem = True
                everything = set(broken) == via
                names = ", ".join(
                    f"{r} ({st})"
                    for r, st in sorted(
                        broken.items(), key=lambda kv: node_sort_key(kv[0])
                    )
                )
                findings.append(
                    Finding(
                        "route",
                        NEXTHOP_DOWN,
                        CRITICAL if everything else WARNING,
                        router,
                        prefix,
                        f"{prefix} points at {names}, whose adjacency is not Full"
                        + (
                            ""
                            if everything
                            else f" ({len(broken)} of {len(via)} next hops)"
                        ),
                        "traffic to this prefix is blackholed until the adjacency recovers"
                        if everything
                        else "the share of traffic hashed onto the broken path is blackholed until the adjacency recovers",
                        {"next_hop_routers": sorted(broken), "states": dict(broken)},
                    )
                )
        if not problem:
            check["ok"] += 1

    for route in rib.values():
        if route.cidr in expected:
            continue
        if route.cidr not in index and route.route_type == ROUTE_INTRA:
            findings.append(
                Finding(
                    "route",
                    ROUTE_STALE,
                    WARNING,
                    router,
                    route.cidr,
                    f"{route.cidr}: {router} has an intra-area route that no LSA in the LSDB advertises",
                    "a stale route, or the LSDB is missing the area that originates it",
                    {"rib_cost": route.metric},
                )
            )
        else:
            check["unverified"] += (
                1  # inter-area / external / own prefix: not derivable from Type 1/2 LSAs
            )
    return findings, check


# ================================================================ driver
def correlate(
    graph: nx.DiGraph,
    details: Sequence[SourceDetail] = (),
    previous: nx.DiGraph | None = None,
) -> CorrelationReport:
    """Run every cross-check available for the data that was collected.

    Args:
        graph: The current topology (from ``GraphEngine.build_graph``).
        details: What each polled router reported beyond the LSDB (neighbour table, routing table).
        previous: The baseline graph; its saved neighbour snapshot is what flaps are measured against.
    """
    report = CorrelationReport()
    if not details:
        return report
    index = prefix_origins(graph)
    owners = ip_owners(graph, details)
    for detail in details:
        report.findings += neighbor_findings(graph, detail)
        found, check = route_findings(graph, detail, index, owners)
        report.findings += found
        if detail.routes is not None and detail.router_id:
            report.rib_checks.append(check)
    if previous is not None:
        report.findings += flap_findings(
            graph.graph.get("neighbors") or [], previous.graph.get("neighbors")
        )
    report.findings.sort(
        key=lambda f: (
            SEVERITY_RANK.get(f.severity, 3),
            f.category,
            f.router,
            f.subject,
        )
    )
    return report


# ============================================================ prefix trace
@dataclass
class TraceResult:
    """How one router reaches a prefix: RIB next hops, then the LSDB shortest path(s) behind them."""

    query: str
    source: str
    prefix: str | None = None  # the matching (longest) prefix
    rib: dict[str, Any] | None = None  # the router's routing-table entry
    origins: list[dict[str, Any]] = field(
        default_factory=list
    )  # who advertises the prefix in the LSDB
    spf_cost: int | None = None
    paths: list[list[str]] = field(
        default_factory=list
    )  # equal-cost shortest paths, node IDs
    verdict: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def edges(self) -> set[frozenset]:
        """Node pairs along the paths, for highlighting on the diagram."""
        return {frozenset(p) for path in self.paths for p in zip(path, path[1:])}


def trace_prefix(
    graph: nx.DiGraph,
    details: Sequence[SourceDetail],
    target: str,
    source: str | None = None,
) -> TraceResult:
    """Trace how ``source`` (a router ID, or ``details[0]``'s router by default) reaches ``target``.

    ``target`` is an IP address (longest-prefix match, RIB first, then the LSDB) or a prefix.

    Raises:
        ValueError: If ``target`` is not an IP/prefix or ``source`` is not in the topology.
    """
    try:
        query = (
            ipaddress.ip_network(target, strict=False)
            if "/" in target
            else ipaddress.ip_address(target)
        )
    except ValueError as exc:
        raise ValueError(
            f"--trace expects an IP address or a prefix, got {target!r}"
        ) from exc
    detail = (
        next((d for d in details if d.router_id == source), None) if source else None
    )
    if not source:
        detail = next(
            (d for d in details if d.router_id and d.routes is not None), None
        ) or next((d for d in details if d.router_id), None)
        source = detail.router_id if detail else None
    if not source or source not in graph:
        raise ValueError(
            f"source router {source or '(none polled)'} is not in the topology"
        )
    result = TraceResult(query=str(target), source=source)

    def covers(prefix: str) -> bool:
        net = ipaddress.ip_network(prefix, strict=False)
        if isinstance(query, ipaddress.IPv4Address):
            return query in net
        return query.subnet_of(net) if net.version == query.version else False

    rib_best = None
    for route in (detail.routes or ()) if detail else ():
        if covers(route.cidr) and (
            rib_best is None or route.prefix_length > rib_best.prefix_length
        ):
            rib_best = route
    index = prefix_origins(graph)
    lsdb_best = max(
        (p for p in index if covers(p)),
        key=lambda p: ipaddress.ip_network(p).prefixlen,
        default=None,
    )

    if rib_best is not None and (
        lsdb_best is None
        or rib_best.prefix_length >= ipaddress.ip_network(lsdb_best).prefixlen
    ):
        result.prefix = rib_best.cidr
    else:
        result.prefix = lsdb_best
    if rib_best is not None:
        owners = ip_owners(graph, details)
        result.rib = {
            "prefix": rib_best.cidr,
            "route_type": rib_best.route_type,
            "metric": rib_best.metric,
            "active": rib_best.active,
            "next_hops": [
                {
                    "ip": h.ip,
                    "interface": h.interface,
                    "router": owners.get(h.ip) if h.ip else None,
                }
                for h in rib_best.next_hops
            ],
        }
    elif detail is not None and detail.routes is not None:
        result.notes.append(f"{source} has no OSPF route covering {target}")
    if result.prefix is None:
        result.verdict = "no route"
        result.notes.append(
            "no prefix in the OSPF routing table or the LSDB covers this address"
        )
        return result

    result.origins = index.get(result.prefix, [])
    best: int | None = None
    best_paths: list[list[str]] = []
    hops: set[str] = set()
    for origin in result.origins:
        for area in sorted(graph.nodes[source].get("areas") or ()) + [None]:
            tree = spf(graph, source, area)
            cost = _origin_cost(tree, origin)
            if cost is None:
                continue
            if best is None or cost < best:
                best, best_paths, hops = cost, [], set()
            if cost == best:
                best_paths += tree.paths(origin["node"])
                hops |= _first_hop_routers(graph, tree.first_hops[origin["node"]])
            break  # the first area (or the whole graph) that reaches it
    result.spf_cost = best
    result.paths = best_paths[:8]

    if best is None:
        result.verdict = "unreachable in LSDB" if result.origins else "not in LSDB"
        if not result.origins:
            result.notes.append(
                "the prefix is not advertised by any Type 1/2 LSA that was read (inter-area or "
                "external routes are not in the data)"
            )
    elif result.rib is None:
        result.verdict = "in LSDB, not in RIB"
    else:
        via = {h["router"] for h in result.rib["next_hops"] if h["router"]}
        if result.rib["metric"] is not None and result.rib["metric"] != best:
            result.verdict = "RIB cost differs from SPF"
        elif via and hops and via != hops:
            result.verdict = "RIB next hop differs from SPF"
        else:
            result.verdict = "RIB and LSDB agree"
    return result
