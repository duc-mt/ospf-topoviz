"""
==============================================================================
Module Name:   layout.py
Description:   Computes where every node of the OSPF topology goes on the page.
==============================================================================
Why not a generic graph layout: an OSPF topology is mostly *transit networks* (hubs) with routers
hanging off them, grouped into areas. Layered or plain force-directed layouts stack the routers in a
column and send every link across the page. This layout follows the structure instead:

1. **Hub and spoke.** Each transit network is a hub; its routers sit on a ring around it, spaced so
   they never touch. A router's place on the ring follows the direction of its *other* connections, so
   spokes do not cross links that leave the hub (angular barycentre ordering).
2. **Areas are boxes.** Every area gets one box that holds its nodes; the backbone is the root, other
   areas hang below the area they attach to, ordered by where their ABRs are.
3. **ABRs sit on the border.** A router in several areas is drawn straddling the border between the
   boxes, not inside either.
4. **Pieces that are not connected** (the topology is split) are packed apart from the main picture.

The module is pure geometry: it knows nothing about networkx or OSPF records, only node sizes,
areas and links, so it is easy to test. Coordinates are pixels, y grows downwards, positions are node
centres.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

BACKBONE = "0.0.0.0"
ROUTER_SIZE = (140.0, 50.0)
NETWORK_SIZE = (196.0, 78.0)

SPOKE_SPACING = 168.0  # centre-to-centre distance of neighbouring spokes on a ring
RING_MIN = 215.0  # smallest hub-to-spoke distance
RING_STEP = 100.0  # extra radius of the outer ring when a hub has very many spokes
AREA_PAD = 58.0  # space between an area's nodes and its box
AREA_LABEL = 34.0  # extra room on top of the box for the area name
AREA_GAP = (
    150.0  # vertical gap between a parent box and a child box (the ABR sits in it)
)
BLOB_GAP = 90.0  # gap between pieces packed in one box
SIDE_GAP = 110.0  # gap between boxes in a row


@dataclass(frozen=True)
class NodeSpec:
    """What the layout needs to know about a node."""

    kind: str  # "router" | "network" | "ghost" (a network with no LSA of its own)
    areas: tuple[str, ...] = ()
    width: float = 0.0
    height: float = 0.0

    @property
    def size(self) -> tuple[float, float]:
        if self.width and self.height:
            return self.width, self.height
        return ROUTER_SIZE if self.kind == "router" else NETWORK_SIZE

    @property
    def is_hub(self) -> bool:
        return self.kind != "router"


@dataclass
class AreaBox:
    id: str
    x: float  # top-left
    y: float
    w: float
    h: float
    backbone: bool = False
    members: list[str] = field(default_factory=list)


@dataclass
class Layout:
    positions: dict[str, tuple[float, float]]  # node centres
    sizes: dict[str, tuple[float, float]]
    areas: list[AreaBox]
    components: list[list[str]]  # connected pieces, largest first
    borders: dict[str, str] = field(
        default_factory=dict
    )  # ABR id -> the area box whose border it sits on

    def bounds(self, margin: float = 0.0) -> tuple[float, float, float, float]:
        """``(x0, y0, x1, y1)`` of everything drawn (nodes and boxes)."""
        xs0, ys0, xs1, ys1 = [], [], [], []
        for node, (x, y) in self.positions.items():
            w, h = self.sizes[node]
            xs0.append(x - w / 2)
            xs1.append(x + w / 2)
            ys0.append(y - h / 2)
            ys1.append(y + h / 2)
        for box in self.areas:
            xs0.append(box.x)
            xs1.append(box.x + box.w)
            ys0.append(box.y)
            ys1.append(box.y + box.h)
        if not xs0:
            return (0.0, 0.0, 0.0, 0.0)
        return (
            min(xs0) - margin,
            min(ys0) - margin,
            max(xs1) + margin,
            max(ys1) + margin,
        )


# =================================================================== helpers
def _angle(dx: float, dy: float) -> float:
    return math.atan2(dy, dx) % (2 * math.pi)


def _angle_diff(a: float, b: float) -> float:
    d = abs(a - b) % (2 * math.pi)
    return min(d, 2 * math.pi - d)


def _centroid(points: Sequence[tuple[float, float]]) -> tuple[float, float]:
    return (
        sum(p[0] for p in points) / len(points),
        sum(p[1] for p in points) / len(points),
    )


def _components(nodes: Iterable[str], adj: Mapping[str, set[str]]) -> list[list[str]]:
    """Connected pieces of ``nodes`` (edges of ``adj`` leaving the set are ignored), largest first."""
    pool = set(nodes)
    seen: set[str] = set()
    pieces: list[list[str]] = []
    for start in sorted(pool):
        if start in seen:
            continue
        stack, piece = [start], []
        seen.add(start)
        while stack:
            node = stack.pop()
            piece.append(node)
            for other in sorted(adj.get(node, ())):
                if other in pool and other not in seen:
                    seen.add(other)
                    stack.append(other)
        pieces.append(sorted(piece))
    pieces.sort(key=lambda p: (-len(p), p[0]))
    return pieces


def _ring_radius(count: int, hub_size: tuple[float, float]) -> float:
    need = count * SPOKE_SPACING / (2 * math.pi)
    clear = hub_size[0] / 2 + ROUTER_SIZE[0] / 2 + 40
    return max(RING_MIN, need, clear if count > 1 else 0)


def _assign_slots(
    items: Sequence[str],
    desired: Mapping[str, float | None],
    strong: set[str],
    start: float = -math.pi / 2,
) -> dict[str, float]:
    """Spread ``items`` evenly on a circle, turning it so each item lands close to its desired angle.

    Items that have a desired angle keep their cyclic order (so links to the same side stay uncrossed);
    items without one fill the remaining slots. ``strong`` items (ABRs, which must point at the other
    area) count more when choosing the rotation.
    """
    n = len(items)
    if n == 0:
        return {}
    if n == 1:
        only = items[0]
        return {only: desired[only] if desired.get(only) is not None else start}
    step = 2 * math.pi / n
    with_pref = sorted(
        (i for i in items if desired.get(i) is not None), key=lambda i: (desired[i], i)
    )
    without = sorted(i for i in items if desired.get(i) is None)
    order = with_pref + without
    best_cost, best_theta = math.inf, start
    for degrees in range(0, 360, 2):
        theta = math.radians(degrees)
        cost = 0.0
        for k, item in enumerate(order):
            want = desired.get(item)
            if want is None:
                continue
            cost += (5.0 if item in strong else 1.0) * _angle_diff(
                theta + k * step, want
            )
        if cost < best_cost - 1e-9:
            best_cost, best_theta = cost, theta
    return {
        item: (best_theta + k * step) % (2 * math.pi) for k, item in enumerate(order)
    }


def _force_layout(
    ids: Sequence[str], adj: Mapping[str, set[str]], spacing: float = 230.0
) -> dict[str, tuple[float, float]]:
    """Deterministic spring layout for a piece that has no hub (routers linked point to point only)."""
    n = len(ids)
    if n == 1:
        return {ids[0]: (0.0, 0.0)}
    radius = spacing * n / (2 * math.pi) + 60
    pos = {
        node: (
            radius * math.cos(2 * math.pi * k / n),
            radius * math.sin(2 * math.pi * k / n),
        )
        for k, node in enumerate(sorted(ids))
    }
    pool = set(ids)
    order = sorted(ids)
    iterations = 300 if n <= 60 else 120  # big pieces: fewer sweeps (O(n^2) each)
    for step in range(iterations):
        temperature = spacing * (1 - step / iterations) * 0.35 + 1
        force = {node: [0.0, 0.0] for node in ids}
        for i, a in enumerate(order):
            for b in order[i + 1 :]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                dist = math.hypot(dx, dy) or 0.01
                push = (spacing * 0.9) ** 2 / dist
                fx, fy = dx / dist * push, dy / dist * push
                force[a][0] += fx
                force[a][1] += fy
                force[b][0] -= fx
                force[b][1] -= fy
        for a in ids:
            for b in adj.get(a, ()):
                if b in pool and a < b:
                    dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                    dist = math.hypot(dx, dy) or 0.01
                    pull = dist * dist / spacing
                    fx, fy = dx / dist * pull, dy / dist * pull
                    force[a][0] -= fx
                    force[a][1] -= fy
                    force[b][0] += fx
                    force[b][1] += fy
        for node in ids:
            fx, fy = force[node]
            mag = math.hypot(fx, fy) or 0.01
            move = min(mag, temperature)
            pos[node] = (pos[node][0] + fx / mag * move, pos[node][1] + fy / mag * move)
    cx, cy = _centroid(list(pos.values()))
    return {node: (x - cx, y - cy) for node, (x, y) in pos.items()}


def _separate(
    pos: dict[str, tuple[float, float]],
    sizes: Mapping[str, tuple[float, float]],
    fixed: set[str],
    pad: float = 26.0,
    rounds: int = 80,
) -> None:
    """Push overlapping node boxes apart (nodes in ``fixed`` stay where they are)."""
    ids = sorted(pos)
    for _ in range(rounds):
        moved = False
        for i, a in enumerate(ids):
            for b in ids[i + 1 :]:
                (ax, ay), (bx, by) = pos[a], pos[b]
                wa, ha = sizes[a]
                wb, hb = sizes[b]
                ox = (wa + wb) / 2 + pad - abs(ax - bx)
                oy = (ha + hb) / 2 + pad - abs(ay - by)
                if ox <= 0 or oy <= 0:
                    continue
                moved = True
                if ox < oy:
                    shift, dx, dy = ox, (1.0 if ax >= bx else -1.0), 0.0
                else:
                    shift, dx, dy = oy, 0.0, (1.0 if ay >= by else -1.0)
                if a in fixed and b in fixed:
                    continue
                share_a = 0.0 if a in fixed else (1.0 if b in fixed else 0.5)
                share_b = 1.0 - share_a if b not in fixed else 0.0
                pos[a] = (ax + dx * shift * share_a, ay + dy * shift * share_a)
                pos[b] = (bx - dx * shift * share_b, by - dy * shift * share_b)
        if not moved:
            return


# ========================================================== one connected piece
WEAK = 0.5  # links lighter than this (one-way, stale) are drawn but do not decide where a node goes


def _layout_piece(
    ids: Sequence[str],
    specs: Mapping[str, NodeSpec],
    strong: Mapping[str, set[str]],
    everything: Mapping[str, set[str]],
    toward: Mapping[str, float],
) -> dict[str, tuple[float, float]]:
    """Hub-and-spoke positions for one connected piece, centred on (0, 0).

    ``strong`` holds the links that decide placement, ``everything`` also the weak ones (one-way, stale).
    ``toward`` maps a router to the direction (radians) it should face - an ABR faces the other area.
    """
    pool = set(ids)
    hubs_all = sorted(
        (n for n in ids if specs[n].is_hub),
        key=lambda n: (-len(everything[n] & pool), n),
    )
    if not hubs_all:
        return _force_layout(sorted(ids), everything)
    hub_set = set(hubs_all)
    routers = sorted(n for n in ids if n not in hub_set)

    # Which hub(s) is each router attached to? Strong links first; a router whose only links are weak
    # still hangs off the hub it points at (otherwise a hub made of one-way links would float alone).
    attached: dict[str, list[str]] = {}
    for r in routers:
        s_hubs = sorted(strong[r] & hub_set & pool)
        if s_hubs:
            attached[r] = s_hubs
        elif not (strong[r] & pool):
            attached[r] = sorted(everything[r] & hub_set & pool)
        else:
            attached[r] = []
    private: dict[str, list[str]] = {h: [] for h in hubs_all}
    bridges: list[str] = []
    hubless: list[str] = []
    for r in routers:
        if len(attached[r]) == 1:
            private[attached[r][0]].append(r)
        elif len(attached[r]) >= 2:
            bridges.append(r)
        else:
            hubless.append(r)
    used = {h for r in bridges for h in attached[r]} | {
        h for h in hubs_all if private[h]
    }
    hubs = [h for h in hubs_all if h in used]
    satellites = [
        h for h in hubs_all if h not in used
    ]  # hubs reached only by weak links: parked outside
    if not hubs:
        return _force_layout(sorted(ids), everything)

    radius = {h: _ring_radius(len(private[h]), specs[h].size) for h in hubs}

    # --- hubs: spring layout where hubs that share a router want to be one ring-pair apart
    shared: dict[tuple[str, str], int] = defaultdict(int)
    for r in bridges:
        for i, a in enumerate(attached[r]):
            for b in attached[r][i + 1 :]:
                shared[(a, b)] += 1
    hub_pos = _place_hubs(hubs, radius, shared)
    pos: dict[str, tuple[float, float]] = dict(hub_pos)

    # --- routers that join several hubs: between them, fanned out sideways
    by_pair: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for r in bridges:
        by_pair[tuple(attached[r])].append(r)
    for hubs_of, group in sorted(by_pair.items()):
        mid = _centroid([hub_pos[h] for h in hubs_of])
        if len(hubs_of) == 2:
            (ax, ay), (bx, by) = hub_pos[hubs_of[0]], hub_pos[hubs_of[1]]
            norm = math.hypot(bx - ax, by - ay) or 1.0
            px, py = -(by - ay) / norm, (bx - ax) / norm
        else:
            px, py = 1.0, 0.0
        for k, r in enumerate(group):
            offset = (k - (len(group) - 1) / 2) * (ROUTER_SIZE[1] + 46)
            pos[r] = (mid[0] + px * offset, mid[1] + py * offset)

    # --- spokes on a ring around each hub, turned towards what else they connect to
    for h in hubs:
        spokes = private[h]
        if not spokes:
            continue
        hx, hy = hub_pos[h]
        desired: dict[str, float | None] = {}
        for r in spokes:
            if r in toward:
                desired[r] = toward[r]
                continue
            other = [pos[o] for o in strong[r] & pool if o != h and o in pos]
            if other:
                cx, cy = _centroid(other)
                desired[r] = _angle(cx - hx, cy - hy)
            else:
                desired[r] = _outward(h, hub_pos)
        for ring_index, ring in enumerate(_split_rings(spokes)):
            r_here = radius[h] + ring_index * RING_STEP
            slots = _assign_slots(ring, desired, {r for r in ring if r in toward})
            for r, theta in slots.items():
                pos[r] = (hx + r_here * math.cos(theta), hy + r_here * math.sin(theta))

    # --- routers reached only through another router: one step further out
    centre = _centroid(list(hub_pos.values()))
    pending = list(hubless)
    for _ in range(len(pending) + 1):
        progress = False
        for r in list(pending):
            parents = [
                p for p in sorted(everything[r] & pool) if p in pos and p not in hub_set
            ]
            if not parents:
                continue
            parent = parents[0]
            base = _angle(pos[parent][0] - centre[0], pos[parent][1] - centre[1])
            siblings = [x for x in hubless if parent in everything[x] and x in pos]
            theta = base + (len(siblings) % 2 * 2 - 1) * 0.55 * (
                (len(siblings) + 1) // 2
            )
            pos[r] = (
                pos[parent][0] + 190 * math.cos(theta),
                pos[parent][1] + 190 * math.sin(theta),
            )
            pending.remove(r)
            progress = True
        if not progress:
            break
    if pending:  # linked to nothing placed: stack them under the piece
        low = max(y for _, y in pos.values()) + 200
        for k, r in enumerate(pending):
            pos[r] = (k * 190.0, low)

    # --- hubs that only weak links reach: parked outside the rings (left first, then right, then above)
    if satellites:
        reach = max(math.hypot(x - centre[0], y - centre[1]) for x, y in pos.values())
        for k, h in enumerate(satellites):
            theta = (math.pi, 0.0, -math.pi / 2)[k % 3]
            dist = reach + 300 + 150 * (k // 3)
            pos[h] = (
                centre[0] + dist * math.cos(theta),
                centre[1] + dist * math.sin(theta),
            )

    _separate(pos, {n: specs[n].size for n in pos}, fixed=hub_set)
    cx, cy = _centroid(list(pos.values()))
    return {n: (x - cx, y - cy) for n, (x, y) in pos.items()}


def _outward(hub: str, hub_pos: Mapping[str, tuple[float, float]]) -> float | None:
    """Direction away from the other hubs (so free spokes do not point into a neighbouring ring)."""
    others = [p for h, p in hub_pos.items() if h != hub]
    if not others:
        return None
    cx, cy = _centroid(others)
    hx, hy = hub_pos[hub]
    return _angle(hx - cx, hy - cy)


def _split_rings(spokes: Sequence[str]) -> list[list[str]]:
    """One ring up to 14 spokes; beyond that alternate them onto an outer ring so the arcs stay readable."""
    spokes = list(spokes)
    if len(spokes) <= 14:
        return [spokes]
    return [spokes[0::2], spokes[1::2]]


def _place_hubs(
    hubs: Sequence[str],
    radius: Mapping[str, float],
    shared: Mapping[tuple[str, str], int],
) -> dict[str, tuple[float, float]]:
    """Positions for the hubs of a piece (one hub: the origin)."""
    if len(hubs) == 1:
        return {hubs[0]: (0.0, 0.0)}
    n = len(hubs)
    big = max(radius.values()) + 200
    pos = {
        h: (big * math.cos(2 * math.pi * k / n), big * math.sin(2 * math.pi * k / n))
        for k, h in enumerate(hubs)
    }
    for step in range(260):
        cool = 1.0 - step / 260
        force = {h: [0.0, 0.0] for h in hubs}
        for i, a in enumerate(hubs):
            for b in hubs[i + 1 :]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                dist = math.hypot(dx, dy) or 0.01
                key = (a, b) if (a, b) in shared else (b, a)
                want = radius[a] + radius[b] + 230
                if key in shared:
                    pull = (dist - want) * 0.25 * (1 + 0.2 * (shared[key] - 1))
                elif dist < want + 120:
                    pull = (
                        dist - (want + 120)
                    ) * 0.35  # unconnected hubs just keep clear of each other
                else:
                    pull = 0.0
                fx, fy = dx / dist * pull, dy / dist * pull
                force[a][0] -= fx
                force[a][1] -= fy
                force[b][0] += fx
                force[b][1] += fy
        for h in hubs:
            pos[h] = (pos[h][0] + force[h][0] * cool, pos[h][1] + force[h][1] * cool)
    cx, cy = _centroid(list(pos.values()))
    return {h: (x - cx, y - cy) for h, (x, y) in pos.items()}


# =========================================================== areas and the page
def _bbox(
    pos: Mapping[str, tuple[float, float]], sizes: Mapping[str, tuple[float, float]]
) -> tuple[float, float, float, float]:
    x0 = min(p[0] - sizes[n][0] / 2 for n, p in pos.items())
    x1 = max(p[0] + sizes[n][0] / 2 for n, p in pos.items())
    y0 = min(p[1] - sizes[n][1] / 2 for n, p in pos.items())
    y1 = max(p[1] + sizes[n][1] / 2 for n, p in pos.items())
    return x0, y0, x1, y1


def _pack_pieces(
    pieces: list[dict[str, tuple[float, float]]],
    sizes: Mapping[str, tuple[float, float]],
) -> dict[str, tuple[float, float]]:
    """Put an area's connected pieces on one sheet: the biggest on the right, the small ones in a column
    to its left (a second column when the first gets taller than the main piece), all sitting on the same
    bottom edge - the edge the ABRs hang from."""
    boxes = [(_bbox(p, sizes), p) for p in pieces]
    (mx0, my0, _, my1), main = boxes[0]
    main_h = my1 - my0
    columns: list[list[tuple[tuple[float, float, float, float], dict]]] = []
    height = 0.0
    limit = max(main_h, 520.0)
    for item in boxes[1:]:
        (x0, y0, x1, y1), _piece = item
        need = (y1 - y0) + (BLOB_GAP if columns and columns[-1] else 0.0)
        if not columns or height + need > limit:
            columns.append([item])
            height = y1 - y0
        else:
            columns[-1].append(item)
            height += need
    col_widths = [max(b[0][2] - b[0][0] for b in col) for col in columns]
    col_heights = [
        sum(b[0][3] - b[0][1] for b in col) + BLOB_GAP * (len(col) - 1)
        for col in columns
    ]
    total_h = max([main_h, *col_heights])
    placed: dict[str, tuple[float, float]] = {}

    x_cursor = sum(col_widths) + BLOB_GAP * len(columns)
    for node, (x, y) in main.items():
        placed[node] = (x - mx0 + x_cursor, y - my0 + (total_h - main_h))
    right = x_cursor - BLOB_GAP  # the first column ends here, the next one further left
    for col, width, col_h in zip(columns, col_widths, col_heights):
        y_cursor = total_h - col_h
        for (x0, y0, x1, y1), piece in col:
            for node, (x, y) in piece.items():
                placed[node] = (
                    x - x0 + (right - width) + (width - (x1 - x0)) / 2,
                    y - y0 + y_cursor,
                )
            y_cursor += (y1 - y0) + BLOB_GAP
        right -= width + BLOB_GAP
    return placed


def compute_layout(
    nodes: Mapping[str, NodeSpec],
    links: Iterable[tuple],
    backbone: str = BACKBONE,
) -> Layout:
    """Place every node and size every area box.

    Args:
        nodes: ``id -> NodeSpec``.
        links: ``(a, b)`` or ``(a, b, weight)``; direction does not matter, unknown nodes are ignored. A
            weight below 0.5 marks a weak link (one-way, stale): it is drawn but does not decide where
            anything goes.
        backbone: The area drawn as the root; if absent, the largest area is.
    """
    adj: dict[str, set[str]] = {n: set() for n in nodes}  # every link
    strong: dict[str, set[str]] = {
        n: set() for n in nodes
    }  # the ones that decide placement
    for link in links:
        a, b = link[0], link[1]
        weight = link[2] if len(link) > 2 else 1.0
        if a in adj and b in adj and a != b:
            adj[a].add(b)
            adj[b].add(a)
            if weight >= WEAK:
                strong[a].add(b)
                strong[b].add(a)
    sizes = {n: spec.size for n, spec in nodes.items()}
    components = _components(nodes, adj)

    home = _home_areas(nodes, adj)
    borders = {n: spec.areas for n, spec in nodes.items() if len(spec.areas) > 1}
    area_ids = sorted(
        {a for spec in nodes.values() for a in spec.areas}
        | {a for a in home.values() if a}
    )
    root = (
        backbone
        if backbone in area_ids
        else (
            max(area_ids, key=lambda a: sum(1 for h in home.values() if h == a))
            if area_ids
            else None
        )
    )

    # --- the area tree: who hangs below whom (an ABR links two areas)
    neighbours: dict[str, set[str]] = defaultdict(set)
    for areas in borders.values():
        for a in areas:
            neighbours[a].update(x for x in areas if x != a)
    parent: dict[str, str | None] = {}
    level_of: dict[str, int] = {}
    if root is not None:
        parent[root], level_of[root] = None, 0
        queue = [root]
        while queue:
            cur = queue.pop(0)
            for nxt in sorted(neighbours[cur]):
                if nxt not in parent:
                    parent[nxt], level_of[nxt] = cur, level_of[cur] + 1
                    queue.append(nxt)
    loose = [
        a for a in area_ids if a not in parent
    ]  # areas no ABR connects to anything

    # --- lay out the inside of every area
    inside: dict[str, dict[str, tuple[float, float]]] = {}
    facing_down: dict[str, set[str]] = {}
    for area in area_ids:
        members = [n for n in nodes if home.get(n) == area and n not in borders]
        guests = [n for n, areas in borders.items() if area in areas]
        if not members and not guests:
            continue
        toward: dict[str, float] = {}
        kids = sorted(
            a for a, p in parent.items() if p == area
        )  # child areas, left to right
        for g in sorted(guests):
            other = [a for a in borders[g] if a != area]
            below = [a for a in kids if a in other]
            if parent.get(area) in other or not below:
                toward[g] = -math.pi / 2 if parent.get(area) in other else math.pi / 2
            else:  # an ABR to a child area: faces down, fanned out in the order the children sit
                rank = kids.index(below[0])
                mates = sorted(x for x in guests if below[0] in borders[x])
                toward[g] = (
                    math.pi / 2
                    - (rank - (len(kids) - 1) / 2) * 0.5
                    - (mates.index(g) - (len(mates) - 1) / 2) * 0.16
                )
        facing_down[area] = {g for g, t in toward.items() if 0 < t < math.pi}
        pieces = [
            _layout_piece(piece, nodes, strong, adj, toward)
            for piece in _components(members + guests, adj)
        ]
        inside[area] = _pack_pieces(pieces, sizes)

    # --- boxes: sized from the members, plus ABRs that face down (they need room on the ring; the
    #     box edge is where they end up). Up-facing ABRs are drawn on the parent's border instead.
    boxes: dict[str, AreaBox] = {}
    contents: dict[str, dict[str, tuple[float, float]]] = {}
    for area, local in inside.items():
        counted = [n for n in local if n not in borders or n in facing_down[area]]
        measured = {n: local[n] for n in (counted or local)}
        x0, y0, x1, y1 = _bbox(measured, sizes)
        boxes[area] = AreaBox(
            id=area,
            x=0.0,
            y=0.0,
            w=(x1 - x0) + 2 * AREA_PAD,
            h=(y1 - y0) + 2 * AREA_PAD + AREA_LABEL,
            backbone=(area == root),
            members=sorted(n for n in local if n not in borders),
        )
        contents[area] = {
            n: (p[0] - x0 + AREA_PAD, p[1] - y0 + AREA_PAD + AREA_LABEL)
            for n, p in local.items()
        }

    final: dict[str, tuple[float, float]] = {}
    on_border: dict[str, str] = {}

    def put_area(area: str, ox: float, oy: float) -> None:
        box = boxes[area]
        box.x, box.y = ox, oy
        for n, (x, y) in contents[area].items():
            if n not in borders:
                final[n] = (ox + x, oy + y)

    placed_areas: list[str] = []
    if root is not None and root in boxes:
        put_area(root, 0.0, 0.0)
        placed_areas.append(root)
        _hang_children(
            root,
            parent,
            boxes,
            contents,
            borders,
            final,
            on_border,
            put_area,
            placed_areas,
        )
    shelf_x = max(
        (b.x + b.w for a, b in boxes.items() if a in placed_areas), default=-SIDE_GAP
    )
    for area in loose:
        if area in boxes:
            put_area(area, shelf_x + SIDE_GAP, 0.0)
            shelf_x += boxes[area].w + SIDE_GAP

    # --- nodes that belong to no area: their own pieces beside everything
    stray = [n for n in nodes if n not in final and n not in borders]
    if stray:
        pieces = [
            _layout_piece(p, nodes, strong, adj, {}) for p in _components(stray, adj)
        ]
        packed = _pack_pieces(pieces, sizes)
        x_off = max((b.x + b.w for b in boxes.values()), default=-SIDE_GAP) + SIDE_GAP
        for n, (x, y) in packed.items():
            final[n] = (x_off + x, y)

    # ABRs no placed area anchored: fall back to where they were drawn inside the first area that has them
    for n, areas in borders.items():
        if n in final:
            continue
        for area in areas:
            if area in boxes and n in contents[area]:
                final[n] = (
                    boxes[area].x + contents[area][n][0],
                    boxes[area].y + contents[area][n][1],
                )
                break
        else:
            final[n] = (0.0, 0.0)

    return Layout(
        positions=final,
        sizes=sizes,
        areas=sorted(boxes.values(), key=lambda b: (not b.backbone, b.id)),
        components=components,
        borders=on_border,
    )


def _home_areas(
    nodes: Mapping[str, NodeSpec], adj: Mapping[str, set[str]]
) -> dict[str, str | None]:
    """The one area each non-ABR node belongs to; a node with no area takes its neighbours' (majority)."""
    home: dict[str, str | None] = {
        n: (spec.areas[0] if len(spec.areas) == 1 else None)
        for n, spec in nodes.items()
    }
    for _ in range(3):
        for n, spec in sorted(nodes.items()):
            if home[n] is not None or len(spec.areas) > 1:
                continue
            votes: dict[str, int] = defaultdict(int)
            for o in adj[n]:
                if home.get(o):
                    votes[home[o]] += 1
            if votes:
                home[n] = min(votes.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    return home


def _hang_children(
    area: str,
    parent: Mapping[str, str | None],
    boxes: dict[str, AreaBox],
    contents: Mapping[str, dict[str, tuple[float, float]]],
    borders: Mapping[str, tuple[str, ...]],
    final: dict[str, tuple[float, float]],
    on_border: dict[str, str],
    put_area,
    placed: list[str],
) -> None:
    """Place the areas that hang below ``area`` in a row (in the order the ABR ring was fanned out).

    The ABRs that join a child are drawn on the bottom border of ``area``, straight above that child.
    """
    children = sorted(a for a, p in parent.items() if p == area and a in boxes)
    if not children:
        return
    box = boxes[area]
    total = sum(boxes[c].w for c in children) + SIDE_GAP * (len(children) - 1)
    if total > box.w:
        shift = (total - box.w) / 2
        box.w = total
        for m in box.members:
            if m in final:
                final[m] = (final[m][0] + shift, final[m][1])
            if m in contents.get(area, {}):
                contents[area][m] = (contents[area][m][0] + shift, contents[area][m][1])
    cursor = box.x + (box.w - total) / 2
    top = box.y + box.h + AREA_GAP
    for child in children:
        cb = boxes[child]
        put_area(child, cursor, top)
        placed.append(child)
        mine = sorted(
            n
            for n, areas in borders.items()
            if area in areas and child in areas and n not in on_border
        )
        for k, n in enumerate(mine):
            final[n] = (
                cb.x + cb.w / 2 + (k - (len(mine) - 1) / 2) * (ROUTER_SIZE[0] + 40),
                box.y + box.h,
            )
            on_border[n] = area
        cursor += cb.w + SIDE_GAP
        _hang_children(
            child, parent, boxes, contents, borders, final, on_border, put_area, placed
        )
