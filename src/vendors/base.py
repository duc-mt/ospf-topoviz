"""
==============================================================================
Module Name:   base.py
Description:   Source module base.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 base.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from src import TrackerError

# Link kinds used by the intermediate model.
UNKNOWN_AREA = "n/a"
KIND_P2P = "p2p"
KIND_TRANSIT = "transit"
KIND_STUB = "stub"
KIND_VIRTUAL = "virtual"

# OSPF route types as the neutral model spells them (``OSPFRoute.route_type``).
ROUTE_INTRA = "Intra-Area"
ROUTE_INTER = "Inter-Area"
ROUTE_E1 = "E1"
ROUTE_E2 = "E2"
ROUTE_N1 = "N1"
ROUTE_N2 = "N2"
#: Platforms whose brief route output only distinguishes internal from external routes.
ROUTE_INTERNAL = "Internal"  # intra- or inter-area: the output does not say which
ROUTE_EXTERNAL = "External"  # E1/E2/N1/N2: the output does not say which
INTERNAL_ROUTE_TYPES = (ROUTE_INTRA, ROUTE_INTER, ROUTE_INTERNAL)


class ParserError(TrackerError):
    """Raised when LSDB text cannot be parsed into a usable topology."""


@dataclass
class LinkRecord:
    """One link inside a Type 1 (router) LSA.

    ``link_id`` is the neighbor router-ID for p2p/virtual links and the DR's
    interface address for transit links (same meaning on every platform).
    ``link_data`` is the advertising router's own interface address on that link
    (the "Link Data" field; an ifIndex on unnumbered links). It is what lets the
    diagram label each link end with something a person can find on the box.

    For a *stub* link the same two fields carry the advertised prefix: ``link_id`` is the network
    address, ``link_data`` its mask and ``metric`` the cost to reach it from the advertising router.
    """

    kind: str
    link_id: str
    metric: int | None
    link_data: str | None = None


@dataclass
class RouterLsa:
    """Type 1 LSA: a router and the links it advertises."""

    router_id: str
    area: str
    links: list[LinkRecord] = field(default_factory=list)
    #: LSA sequence number as a signed 32-bit value (larger = newer); ``None`` if the platform omitted it.
    seq: int | None = None
    #: Seconds since the LSA was originated. A live router re-originates its LSA every 30 minutes,
    #: so a very old one means the router is gone.
    age: int | None = None
    #: The router's own B (area border router) and E (AS boundary router) bits.
    abr: bool = False
    asbr: bool = False


@dataclass
class NetworkLsa:
    """Type 2 LSA: a transit network, originated by its Designated Router."""

    address: str  # DR interface address (the LSA's Link State ID)
    dr: str  # DR router-ID (the LSA's advertising router)
    area: str
    mask: str | None
    attached: list[str] = field(default_factory=list)
    seq: int | None = None
    age: int | None = None


@dataclass
class Lsdb:
    """Everything an adapter extracted from one poll."""

    router_lsas: list[RouterLsa] = field(default_factory=list)
    network_lsas: list[NetworkLsa] = field(default_factory=list)
    #: Every OSPF process/instance seen in the output, *before* any filtering.
    process_ids: list[str] = field(default_factory=list)
    #: Router ID of the router that produced this output (``None`` if the output does not say).
    router_id: str | None = None


@dataclass
class NeighborRecord:
    """One row of a router's OSPF neighbour table (its *own* view of its adjacencies)."""

    router_id: str  # the neighbour's router ID
    state: str  # normalised: Full, 2-Way, Init, ExStart, Exchange, Loading, Down, Attempt (else as printed)
    role: str | None = (
        None  # DR | BDR | DROther | None (point-to-point, or not printed)
    )
    interface: str | None = (
        None  # the polled router's own interface towards the neighbour
    )
    address: str | None = None  # the neighbour's interface address
    area: str | None = None
    priority: int | None = None  # the neighbour's router priority (DR election)
    dead_time: int | None = None  # seconds left before the neighbour is declared dead

    # The same record under the names used in the monitoring model.
    @property
    def neighbor_id(self) -> str:
        return self.router_id

    @property
    def ip_address(self) -> str | None:
        return self.address

    @property
    def dr_bdr_role(self) -> str | None:
        return self.role


#: A neighbour-table row. (``NeighborRecord`` is the original name and stays the canonical class.)
OSPFNeighbor = NeighborRecord


@dataclass
class NextHop:
    """One next hop of a route: the gateway and the interface the router sends the traffic out of."""

    ip: str | None = None  # ``None`` for a directly connected network
    interface: str | None = None


@dataclass
class OSPFRoute:
    """One OSPF route of the router's routing table (RIB)."""

    prefix: str  # network address, e.g. "10.1.1.0"
    mask: str  # dotted-quad, e.g. "255.255.255.0"
    route_type: str  # ROUTE_INTRA | ROUTE_INTER | ROUTE_E1 | ... (or ROUTE_INTERNAL / ROUTE_EXTERNAL)
    metric: int | None = None  # the route's cost
    tag: int | None = None  # route tag, where the platform prints it
    distance: int | None = (
        None  # administrative distance / preference (110 for internal OSPF routes)
    )
    next_hops: list[NextHop] = field(
        default_factory=list
    )  # more than one = equal-cost multipath
    process_id: str | None = None
    #: False when the platform lists the OSPF route but another source won (FRR: no ``>``; Junos: no ``*``),
    #: e.g. a static or BGP route with a lower distance. Platforms that only list installed routes are always True.
    active: bool = True

    @property
    def prefix_length(self) -> int:
        return ipaddress.IPv4Network(f"{self.prefix}/{self.mask}", strict=False).prefixlen

    @property
    def cidr(self) -> str:
        return f"{self.prefix}/{self.prefix_length}"

    @classmethod
    def from_cidr(cls, cidr: str, route_type: str, **fields) -> OSPFRoute:
        """Build from ``10.1.1.0/24`` (host bits, if any, are cleared)."""
        net = ipaddress.IPv4Network(cidr, strict=False)
        return cls(
            prefix=str(net.network_address),
            mask=str(net.netmask),
            route_type=route_type,
            **fields,
        )


@dataclass
class SourceDetail:
    """What one polled router told us beyond the LSDB."""

    name: str
    router_id: str | None
    neighbors: list[NeighborRecord] = field(default_factory=list)
    #: The router's OSPF routing table; ``None`` = not collected (or not supported on this platform).
    routes: list[OSPFRoute] | None = None
    #: False when no neighbour table was collected, so an empty ``neighbors`` list means "unknown", not "none".
    neighbors_known: bool = True


class LsdbAdapter(ABC):
    """Turns one platform's raw router/network LSDB text into an ``Lsdb``."""

    #: True if ``process_id`` can be honored when parsing (header or schema carries it).
    filters_by_process: bool = False
    #: Which routing-table layout ``parse_routes`` understands (see ``src.vendors.routes``); ``None`` = none.
    route_format: str | None = None

    @abstractmethod
    def parse(self, raw_router: str, raw_network: str, process_id: str | None) -> Lsdb:
        """Parse raw output. ``process_id`` (if given) selects one OSPF process."""

    def parse_neighbors(
        self, raw: str, process_id: str | None
    ) -> list[NeighborRecord] | None:
        """Parse the neighbour table; ``None`` means this platform has no neighbour parser."""
        return None

    def parse_routes(self, raw: str, process_id: str | None) -> list[OSPFRoute] | None:
        """Parse the OSPF routing table; ``None`` means this platform has no route parser."""
        if self.route_format is None:
            return None
        from src.vendors.routes import parse_routes

        return parse_routes(self.route_format, raw, process_id)


# --------------------------------------------------------------------- helpers
def link_kind(text: str) -> str | None:
    """Map a platform's link-type wording to a kind (``None`` if unrecognized).

    Handles e.g. Cisco "another Router (point-to-point)", Junos "PointToPoint",
    Huawei "P-2-P" / "TransNet" / "StubNet", FRR "Stub Network".
    """
    t = text.lower().replace("-", "").replace(" ", "")
    if "virtual" in t:
        return KIND_VIRTUAL
    if "pointtopoint" in t or "p2p" in t or "point" in t:
        return KIND_P2P
    if "transit" in t or "transnet" in t:
        return KIND_TRANSIT
    if "stub" in t:
        return KIND_STUB
    return None


def dotted_mask(mask: str | None) -> str | None:
    """Normalize ``/24``, ``24`` or ``255.255.255.0`` to dotted-quad form."""
    if not mask:
        return None
    text = str(mask).strip()
    try:
        if text.startswith("/") or text.isdigit():
            return str(ipaddress.ip_network(f"0.0.0.0/{text.lstrip('/')}").netmask)
        ipaddress.ip_address(text)
        return text
    except ValueError:
        return None


def as_list(value) -> list:
    """Genie/XML-style fields are a dict/str when single and a list when repeated."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


_STATES = {
    "DOWN": "Down",
    "ATTEMPT": "Attempt",
    "INIT": "Init",
    "2WAY": "2-Way",
    "2WAYS": "2-Way",
    "TWOWAY": "2-Way",
    "EXSTART": "ExStart",
    "EXCHANGE": "Exchange",
    "LOADING": "Loading",
    "FULL": "Full",
}
_ROLES = {
    "DR": "DR",
    "BDR": "BDR",
    "BACKUP": "BDR",
    "DROTHER": "DROther",
    "OTHER": "DROther",
}


def normalize_state(text: str) -> tuple[str, str | None]:
    """Split a neighbour state as printed (``FULL/DR``, ``Full/Backup``, ``2-Way/DROther``, ``ExStart``)
    into ``(state, role)`` using one vocabulary for every platform."""
    state_part, _, role_part = str(text).strip().partition("/")
    key = "".join(ch for ch in state_part.upper() if ch.isalnum())
    state = _STATES.get(key, state_part.strip() or "unknown")
    role = _ROLES.get("".join(ch for ch in role_part.upper() if ch.isalnum()))
    return state, role


def parse_seq(text) -> int | None:
    """Parse an LSA sequence number ("80000010", "0x8000000f") into a signed 32-bit int.

    Cisco, Junos, FRR and Huawei all print sequence numbers as hexadecimal without a 0x prefix
    ("80000010"); Genie prints "0x8000000f". Returns ``None`` if unparseable.
    """
    if not text:
        return None
    raw = str(text).strip().lower().replace("0x", "")
    try:
        val = int(raw, 16)
        if val >= 0x80000000:
            val -= 0x100000000
        return val
    except ValueError:
        return None


def parse_dead_time(text) -> int | None:
    """Seconds from a dead-timer column: ``00:00:33``, ``33.5s``, ``37`` (Junos). ``None`` if unparseable."""
    if text is None:
        return None
    value = str(text).strip()
    if m := re.fullmatch(r"(\d+):(\d+):(\d+)(?:\.\d+)?", value):
        h, mi, sec = (int(g) for g in m.groups())
        return h * 3600 + mi * 60 + sec
    if m := re.fullmatch(r"(\d+(?:\.\d+)?)s?", value):
        return int(float(m.group(1)))
    return None


def role_from_dr(address: str | None, dr: str | None, bdr: str | None) -> str | None:
    """A neighbour's role on a broadcast segment from the DR / BDR addresses a detail output prints."""
    if not address or not dr or dr in ("0.0.0.0", "-"):
        return None  # point-to-point (no election)
    if address == dr:
        return "DR"
    if address == bdr:
        return "BDR"
    return "DROther"


#: How bad each adjacency state is (higher = worse); anything unknown ranks with Down.
_STATE_SEVERITY = {
    "Full": 0,
    "2-Way": 1,
    "Loading": 2,
    "Exchange": 3,
    "ExStart": 4,
    "Init": 5,
    "Attempt": 6,
    "Down": 7,
}


def state_severity(state: str | None) -> int:
    """Rank an adjacency state for "worst one wins" comparisons (Full < 2-Way < Loading < ... < Down)."""
    return _STATE_SEVERITY.get(str(state), 7)
