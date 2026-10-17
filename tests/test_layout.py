"""The layout engine: hub-and-spoke rings, area boxes, ABRs on borders, pieces that are cut off."""

from __future__ import annotations

import math

from src.layout import (
    AREA_GAP,
    RING_MIN,
    SPOKE_SPACING,
    NodeSpec,
    _assign_slots,
    _layout_piece,
    compute_layout,
)
from tests.explorer_fixture import A0, A1, A4, realistic

P = "10.255.255."


def specs_and_links(graph, weak_one_way=True):
    nodes = {}
    for n, a in graph.nodes(data=True):
        kind = (
            "router"
            if a["type"] == "router"
            else ("network" if a.get("resolved", True) else "ghost")
        )
        nodes[n] = NodeSpec(kind, tuple(a.get("areas") or ()))
    links = []
    for pair in {frozenset(e) for e in graph.edges()}:
        a, b = sorted(pair)
        weak = weak_one_way and any(
            graph.has_edge(x, y) and graph[x][y].get("link_state") == "one-way"
            for x, y in ((a, b), (b, a))
        )
        links.append((a, b, 0.2 if weak else 1.0))
    return nodes, links


def realistic_layout():
    return compute_layout(*specs_and_links(realistic()))


def overlap(layout, a, b, pad=0.0):
    (ax, ay), (bx, by) = layout.positions[a], layout.positions[b]
    (wa, ha), (wb, hb) = layout.sizes[a], layout.sizes[b]
    return abs(ax - bx) < (wa + wb) / 2 + pad and abs(ay - by) < (ha + hb) / 2 + pad


def hub_and_spokes(count, area=A0):
    nodes = {"net": NodeSpec("network", (area,))}
    links = []
    for i in range(count):
        nodes[f"r{i}"] = NodeSpec("router", (area,))
        links.append((f"r{i}", "net"))
    return nodes, links


# ------------------------------------------------------------- hub and spoke
def test_routers_sit_on_a_ring_around_their_hub():
    layout = compute_layout(*hub_and_spokes(6))
    hx, hy = layout.positions["net"]
    radii = [
        math.hypot(x - hx, y - hy)
        for n, (x, y) in layout.positions.items()
        if n != "net"
    ]
    assert min(radii) >= RING_MIN - 1
    assert max(radii) - min(radii) < 1.0  # one ring: every spoke the same distance out


def test_spokes_are_spread_evenly_around_the_hub():
    layout = compute_layout(*hub_and_spokes(8))
    hx, hy = layout.positions["net"]
    angles = sorted(
        math.atan2(y - hy, x - hx)
        for n, (x, y) in layout.positions.items()
        if n != "net"
    )
    gaps = [
        (b - a) % (2 * math.pi)
        for a, b in zip(angles, angles[1:] + [angles[0] + 2 * math.pi])
    ]
    assert max(gaps) - min(gaps) < 0.05


def test_a_crowded_hub_gets_a_second_ring_instead_of_overlapping_spokes():
    layout = compute_layout(*hub_and_spokes(24))
    routers = [n for n in layout.positions if n != "net"]
    assert not any(
        overlap(layout, a, b) for i, a in enumerate(routers) for b in routers[i + 1 :]
    )


def test_the_ring_grows_with_the_number_of_spokes():
    def ring(count):
        layout = compute_layout(*hub_and_spokes(count))
        hx, hy = layout.positions["net"]
        return max(
            math.hypot(x - hx, y - hy)
            for n, (x, y) in layout.positions.items()
            if n != "net"
        )

    assert ring(3) < ring(12)


def test_the_layout_is_deterministic():
    assert realistic_layout().positions == realistic_layout().positions
    assert [(a.id, a.x, a.y, a.w, a.h) for a in realistic_layout().areas] == [
        (a.id, a.x, a.y, a.w, a.h) for a in realistic_layout().areas
    ]


def test_no_two_nodes_overlap_in_a_realistic_topology():
    layout = realistic_layout()
    ids = sorted(layout.positions)
    clashes = [
        (a, b) for i, a in enumerate(ids) for b in ids[i + 1 :] if overlap(layout, a, b)
    ]
    assert clashes == []


# ----------------------------------------------------- weak links (one-way)
def two_hubs_with_weak_links():
    """Every router hangs off hub A with a real link, and off a stale hub B with a one-way link only."""
    nodes = {"A": NodeSpec("network", (A0,)), "B": NodeSpec("network", (A0,))}
    links = []
    for i in range(6):
        nodes[f"r{i}"] = NodeSpec("router", (A0,))
        links += [(f"r{i}", "A", 1.0), (f"r{i}", "B", 0.2)]
    return nodes, links


def test_one_way_links_do_not_make_routers_bridges_between_hubs():
    layout = compute_layout(*two_hubs_with_weak_links())
    ax, ay = layout.positions["A"]
    radii = [
        math.hypot(x - ax, y - ay)
        for n, (x, y) in layout.positions.items()
        if n.startswith("r")
    ]
    assert max(radii) - min(radii) < 1.0  # all six on A's ring


def test_a_hub_reached_only_by_weak_links_is_parked_outside_the_rings():
    layout = compute_layout(*two_hubs_with_weak_links())
    (ax, ay), (bx, by) = layout.positions["A"], layout.positions["B"]
    ring = max(
        math.hypot(x - ax, y - ay)
        for n, (x, y) in layout.positions.items()
        if n.startswith("r")
    )
    assert math.hypot(bx - ax, by - ay) > ring + 200
    assert (
        abs(math.hypot(bx - ax, by - ay) - (ring + 300)) < 3 and bx < ax
    )  # parked 300 px beyond the ring, to the left


def test_two_real_hubs_keep_their_shared_router_between_them():
    nodes = {
        "A": NodeSpec("network", (A0,)),
        "B": NodeSpec("network", (A0,)),
        "bridge": NodeSpec("router", (A0,)),
    }
    links = [("bridge", "A"), ("bridge", "B")]
    for i in range(4):
        for hub in "AB":
            nodes[f"{hub}{i}"] = NodeSpec("router", (A0,))
            links.append((f"{hub}{i}", hub))
    layout = compute_layout(nodes, links)
    pa, pb, pm = (
        layout.positions["A"],
        layout.positions["B"],
        layout.positions["bridge"],
    )
    assert math.dist(pm, pa) < math.dist(pa, pb) and math.dist(pm, pb) < math.dist(
        pa, pb
    )


def test_routers_joined_by_point_to_point_links_only_get_a_spring_layout():
    nodes = {f"r{i}": NodeSpec("router", (A0,)) for i in range(6)}
    links = [(f"r{i}", f"r{(i + 1) % 6}") for i in range(6)]
    layout = compute_layout(nodes, links)
    ids = sorted(nodes)
    assert not any(
        overlap(layout, a, b) for i, a in enumerate(ids) for b in ids[i + 1 :]
    )
    assert len({tuple(round(c) for c in p) for p in layout.positions.values()}) == 6


# --------------------------------------------------------------------- areas
def test_every_node_lies_inside_its_area_box_except_abrs_which_sit_on_a_border():
    graph, layout = realistic(), realistic_layout()
    boxes = {b.id: b for b in layout.areas}
    for node, attrs in graph.nodes(data=True):
        x, y = layout.positions[node]
        w, h = layout.sizes[node]
        areas = attrs["areas"]
        if len(areas) == 1:
            b = boxes[areas[0]]
            assert (
                b.x <= x - w / 2
                and x + w / 2 <= b.x + b.w
                and b.y <= y - h / 2
                and y + h / 2 <= b.y + b.h
            ), node


def test_the_backbone_is_the_root_and_other_areas_hang_below_it():
    boxes = {b.id: b for b in realistic_layout().areas}
    assert boxes[A0].backbone and not boxes[A1].backbone
    for child in (A1, A4):
        assert boxes[child].y >= boxes[A0].y + boxes[A0].h + AREA_GAP - 1


def test_sibling_areas_do_not_overlap_and_keep_a_fixed_order():
    boxes = {b.id: b for b in realistic_layout().areas}
    assert boxes[A1].x + boxes[A1].w < boxes[A4].x  # left to right in area order


def test_abrs_sit_on_the_border_straight_above_the_area_they_lead_to():
    layout = realistic_layout()
    boxes = {b.id: b for b in layout.areas}
    for abr, child in ((P + "6", A1), (P + "7", A1), (P + "18", A4), (P + "19", A4)):
        x, y = layout.positions[abr]
        assert (
            abs(y - (boxes[A0].y + boxes[A0].h)) < 0.5
        )  # centred on the backbone's bottom edge
        assert (
            boxes[child].x <= x <= boxes[child].x + boxes[child].w
        )  # and above its child
        assert (
            boxes[A0].x <= x <= boxes[A0].x + boxes[A0].w
        )  # and within the parent's horizontal span
        assert layout.borders[abr] == A0


def test_abrs_of_the_same_border_do_not_sit_on_top_of_each_other():
    layout = realistic_layout()
    on_border = [n for n in layout.borders]
    assert not any(
        overlap(layout, a, b)
        for i, a in enumerate(on_border)
        for b in on_border[i + 1 :]
    )


def test_an_abr_faces_the_area_it_leads_to_on_its_hubs_ring():
    layout = realistic_layout()
    hub = layout.positions["net-10.130.240.1"]
    for abr in (P + "6", P + "7", P + "18", P + "19"):
        assert (
            layout.positions[abr][1] > hub[1] + 100
        )  # below the hub, towards the child areas


def test_without_a_backbone_the_biggest_area_is_the_root():
    nodes, links = hub_and_spokes(5, area="0.0.0.7")
    layout = compute_layout(nodes, links)
    assert [b.id for b in layout.areas] == ["0.0.0.7"] and layout.areas[0].backbone


# ---------------------------------------------------------- split topology
def test_a_piece_cut_off_from_the_rest_is_packed_to_the_left_on_the_same_bottom_edge():
    layout = realistic_layout()
    main_left = min(
        x - layout.sizes[n][0] / 2
        for n, (x, _y) in layout.positions.items()
        if n.startswith("net-10.130") or n.startswith(P)
    )
    for lonely in ("10.253.0.253", "net-10.253.0.254"):
        x, _y = layout.positions[lonely]
        assert x + layout.sizes[lonely][0] / 2 < main_left + 1
    assert [len(c) for c in layout.components] == [17, 2]  # the main piece first


def test_the_cut_off_piece_stays_inside_its_area_box():
    layout = realistic_layout()
    box = next(b for b in layout.areas if b.id == A0)
    for n in ("10.253.0.253", "net-10.253.0.254"):
        x, y = layout.positions[n]
        assert box.x < x < box.x + box.w and box.y < y < box.y + box.h


# ------------------------------------------------------------------- edges
def test_empty_and_tiny_inputs():
    assert compute_layout({}, []).positions == {}
    one = compute_layout({"r": NodeSpec("router", (A0,))}, [])
    assert list(one.positions) == ["r"] and one.areas[0].id == A0


def test_nodes_without_an_area_get_a_place_beside_the_boxes():
    nodes = {"net": NodeSpec("network", ()), "r": NodeSpec("router", ())}
    layout = compute_layout(nodes, [("r", "net")])
    assert set(layout.positions) == {"net", "r"} and layout.areas == []


def test_a_node_with_no_area_takes_its_neighbours_area():
    nodes = {"net": NodeSpec("network", (A0,)), "r": NodeSpec("router", ())}
    layout = compute_layout(nodes, [("r", "net")])
    box = layout.areas[0]
    x, y = layout.positions["r"]
    assert box.x < x < box.x + box.w and box.y < y < box.y + box.h


def test_unknown_link_ends_are_ignored():
    layout = compute_layout({"r": NodeSpec("router", (A0,))}, [("r", "ghost")])
    assert list(layout.positions) == ["r"]


def test_bounds_cover_boxes_and_nodes():
    layout = realistic_layout()
    x0, y0, x1, y1 = layout.bounds()
    for n, (x, y) in layout.positions.items():
        assert x0 <= x <= x1 and y0 <= y <= y1
    assert layout.bounds(10)[0] == x0 - 10


# --------------------------------------------------- ring geometry in detail
def test_a_big_ring_is_sized_so_neighbouring_spokes_are_one_spacing_apart():
    layout = compute_layout(*hub_and_spokes(12))
    hx, hy = layout.positions["net"]
    radii = [
        math.hypot(x - hx, y - hy)
        for n, (x, y) in layout.positions.items()
        if n != "net"
    ]
    assert (
        max(radii) - min(radii) < 6.0
    )  # still one clean ring, not pushed around by overlap removal
    assert abs(sum(radii) / len(radii) - 12 * SPOKE_SPACING / (2 * math.pi)) < 6.0


def test_items_land_near_the_direction_they_want_to_face():
    items = [f"r{i}" for i in range(6)]
    wants = {
        "r0": math.pi / 2 - 0.5,
        "r1": math.pi / 2 + 0.55,
        **{i: None for i in items[2:]},
    }  # one slot (60 deg) apart
    slots = _assign_slots(items, wants, strong={"r0", "r1"})
    for item in ("r0", "r1"):
        assert (
            math.cos(slots[item] - wants[item]) > 0.8
        )  # within ~37 degrees of the wish
    assert len({round(a, 3) for a in slots.values()}) == 6  # and nobody shares a slot


def test_abrs_on_a_ring_face_the_direction_they_were_given():
    nodes, links = hub_and_spokes(8)
    specs = {n: nodes[n] for n in nodes}
    adj = {n: set() for n in nodes}
    for a, b in links:
        adj[a].add(b)
        adj[b].add(a)
    toward = {"r0": math.pi / 2, "r1": math.pi / 2}
    pos = _layout_piece(sorted(nodes), specs, adj, adj, toward)
    hx, hy = pos["net"]
    for abr in ("r0", "r1"):
        assert (
            pos[abr][1] > hy + 150 and abs(pos[abr][0] - hx) < 200
        )  # straight down from the hub


def test_a_few_hundred_nodes_lay_out_quickly_and_without_overlaps():
    import random
    import time

    rng = random.Random(7)
    nodes, links = {}, []
    for a in range(6):
        area = f"0.0.0.{a}"
        hubs = [f"net-{a}-{h}" for h in range(5)]
        for hub in hubs:
            nodes[hub] = NodeSpec("network", (area,))
        for r in range(45):
            rid = f"10.{a}.0.{r}"
            nodes[rid] = NodeSpec("router", (area,))
            links.append((rid, rng.choice(hubs)))
    for a in range(1, 6):
        for k in range(2):
            rid = f"10.255.{a}.{k}"
            nodes[rid] = NodeSpec("router", ("0.0.0.0", f"0.0.0.{a}"))
            links += [(rid, "net-0-0"), (rid, f"net-{a}-0")]
    started = time.time()
    layout = compute_layout(nodes, links)
    assert time.time() - started < 5
    ids = sorted(layout.positions)
    assert len(ids) == len(nodes) == 310
    assert not any(
        overlap(layout, a, b) for i, a in enumerate(ids) for b in ids[i + 1 :]
    )
    assert len(layout.areas) == 6
