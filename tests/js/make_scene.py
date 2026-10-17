"""Print a JSON fixture for ``tests/js/test_simulation.js``: an explorer scene, the rendered page and what the
Python SPF (``correlation.spf``) computes from every router, so the browser's Dijkstra can be held against it.

Run from the project root:  PYTHONPATH=. python3 tests/js/make_scene.py

The network (all area 0.0.0.0, router ``10.0.0.N`` is written ``RN``)::

    primary    R1 -10- R2 -10- R4          R1 -> R4 costs 20 (via R2); the R3 detour costs 40
    secondary  R1 -20- R3 -20- R4
    stub       R4 -5- R7                   R7 hangs off R4 only and advertises two prefixes
    ECMP       R1 -5- R8 -5- R10 and R1 -5- R9 -5- R10     two equal paths, cost 10
    asymmetric R1 -1/100- R11 -1/100- R12 and R1 -10- R12  A->B and B->A pick different routes
    segment    R4 (1), R5 (3), R6 (7) share the transit network 192.168.1.0/24
    one-way    R6 -> R10 is advertised by R6 only: the SPF must ignore it
    ABR        R3 is flagged ABR but only area 0 was read, so an area is hidden behind it
"""

from __future__ import annotations

import json

from src.correlation import correlate, spf
from src.explorer import build_scene, render_html
from src.graph_engine import GraphEngine, TopologyDiff

AREA = "0.0.0.0"
NET = "net-192.168.1.1"


def rid(n: int) -> str:
    return f"10.0.0.{n}"


def build():
    stub_prefixes = ["192.0.2.0/24", "198.51.100.0/24"]
    nodes = []
    for n in range(1, 13):
        node = {
            "id": rid(n),
            "type": "router",
            "areas": [AREA],
            "resolved": True,
            "abr": n == 3,
        }
        if n == 7:
            node["prefixes"] = [
                {"prefix": p, "metric": 1, "area": AREA} for p in stub_prefixes
            ]
        nodes.append(node)
    nodes.append(
        {
            "id": NET,
            "type": "network",
            "areas": [AREA],
            "resolved": True,
            "address": "192.168.1.1",
            "prefix": "192.168.1.0/24",
            "dr": rid(4),
        }
    )
    edges = []

    def p2p(a, b, ab, ba):
        for u, v, m in ((a, b, ab), (b, a, ba)):
            edges.append(
                {
                    "source": rid(u),
                    "target": rid(v),
                    "metric": m,
                    "link_type": "point-to-point",
                    "area": AREA,
                }
            )

    for a, b, ab, ba in (
        (1, 2, 10, 10),
        (2, 4, 10, 10),
        (1, 3, 20, 20),
        (3, 4, 20, 20),
        (4, 7, 5, 5),
        (1, 8, 5, 5),
        (8, 10, 5, 5),
        (1, 9, 5, 5),
        (9, 10, 5, 5),
        (1, 11, 1, 100),
        (11, 12, 1, 100),
        (1, 12, 10, 10),
    ):
        p2p(a, b, ab, ba)
    for n, cost in ((4, 1), (5, 3), (6, 7)):
        edges.append(
            {
                "source": rid(n),
                "target": NET,
                "metric": cost,
                "link_type": "transit",
                "area": AREA,
            }
        )
        edges.append(
            {
                "source": NET,
                "target": rid(n),
                "metric": 0,
                "link_type": "attachment",
                "area": AREA,
            }
        )
    edges.append(
        {
            "source": rid(6),
            "target": rid(10),
            "metric": 1,
            "link_type": "point-to-point",
            "area": AREA,
            "link_state": "one-way",
        }
    )
    return GraphEngine(data_dir="/nonexistent").build_graph(
        {"metadata": {}, "nodes": nodes, "edges": edges}
    )


def main() -> None:
    graph = build()
    report = correlate(graph)
    diff = TopologyDiff(baseline_available=False)
    diff.findings = [f.to_dict() for f in report.findings]
    diff.area_coverage = report.area_coverage.to_dict()
    scene = build_scene(graph, diff)
    expected = {}
    for node, attrs in graph.nodes(data=True):
        if attrs.get("type") == "router":
            expected[node] = spf(graph, node).dist
    print(
        json.dumps(
            {"scene": scene, "html": render_html(scene), "expected": expected},
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
