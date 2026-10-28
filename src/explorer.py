"""
==============================================================================
Module Name:   explorer.py
Description:   Builds the interactive topology explorer: one self-contained HTML file with the
               topology, its diagnostics and the cross-check findings, drawn with the structured
               layout of ``layout.py`` and explored in the browser (pan/zoom, drag nodes, hover
               details, click a warning to find the router, save the layout).
==============================================================================
Python decides *what* is shown and *where* (so the drawing is reproducible and testable); the page only
adds behaviour. No network access and no libraries are needed to open the file.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import networkx as nx

from src import __version__, atomic_write_text, node_sort_key
from src.graph_engine import TopologyDiff
from src.layout import NodeSpec, compute_layout
from src.visualizer import NETWORK_ID_PREFIX, TopologyVisualizer, VisualOptions

TEMPLATE = Path(__file__).with_name("web") / "explorer.html"
WEAK_LINK = 0.2  # layout weight of a one-way / removed link: drawn, but it does not pull nodes around


def _kind(attrs: dict[str, Any]) -> str:
    if attrs.get("type") != "network":
        return "router"
    return "network" if attrs.get("resolved", True) else "ghost"


def _title_and_sub(
    node: str, attrs: dict[str, Any], names: dict[str, str]
) -> tuple[str, list[str]]:
    """The two lines of text on a node: what it is, then what it does."""
    kind = _kind(attrs)
    sub: list[str] = []
    if kind == "router":
        name = names.get(node)
        title = name or node
        if name:
            sub.append(node)
        roles = [
            r
            for r, on in (
                ("ABR", attrs.get("abr")),
                ("ASBR", attrs.get("asbr") or attrs.get("is_asbr")),
            )
            if on
        ]
        if roles:
            sub.append("/".join(roles))
        if attrs.get("externals"):
            count = len(attrs["externals"])
            sub.append(f"{count} external route{'s' if count != 1 else ''}")
    else:
        title = f"net {attrs.get('prefix') or attrs.get('address') or str(node).removeprefix(NETWORK_ID_PREFIX)}"
        if attrs.get("dr"):
            sub.append(f"DR {attrs['dr']}")
        if kind == "ghost":
            sub.append("(no LSA)")
    if attrs.get("stale"):
        sub.append(f"stale LSA ({int(attrs.get('lsa_age') or 0) // 60} min)")
    return title, sub


def _role(kind: str, attrs: dict[str, Any]) -> str:
    """The badge under a router's name: ``ABR``, ``ASBR``, ``ABR/ASBR`` or plain ``Router``."""
    if kind != "router":
        return ""
    flags = [
        r
        for r, on in (
            ("ABR", attrs.get("abr")),
            ("ASBR", attrs.get("asbr") or attrs.get("is_asbr")),
        )
        if on
    ]
    return "/".join(flags) or "Router"


def _parallel_members(*sides: Any) -> list[dict[str, Any]]:
    """Every physical link behind one drawn link: the kept one first, then its parallel twins."""
    for side in sides:
        if side is None or side.attrs.get("link_type") == "attachment":
            continue
        members = [{"metric": side.attrs.get("metric"), "ip": side.attrs.get("interface_address")}]
        members += [
            {"metric": p.get("metric"), "ip": p.get("interface_address")}
            for p in side.attrs.get("parallel_links") or ()
        ]
        if len(members) > 1:
            return members
    return []


def _node_size(kind: str, title: str, sub: list[str]) -> tuple[float, float]:
    """Room for the text (the layout spaces nodes by these sizes). A diamond is narrow where its text
    sits, so a network needs to be much wider than its title."""
    widest = max([len(title), *map(len, sub)])
    lines = 1 + len(sub)
    if kind == "router":
        return max(140.0, 8.4 * widest + 30), 26.0 + 17.0 * lines
    return max(210.0, 1.75 * 7.6 * widest + 34), 52.0 + 17.0 * lines


def _end(side, a: str, b: str) -> dict[str, Any] | None:
    """One direction of a link as shown in the tooltip (``None`` for the cost-less attachment side)."""
    if side is None or side.attrs.get("link_type") == "attachment":
        return None
    out: dict[str, Any] = {
        "from": a,
        "to": b,
        "metric": side.attrs.get("metric"),
        "iface": side.attrs.get("interface"),
        "ip": side.attrs.get("interface_address"),
        "state": side.attrs.get("nbr_state"),
        "status": side.status,
    }
    if side.status == "changed" and side.change:
        out["old"], out["new"] = (
            side.change.get("old_metric"),
            side.change.get("new_metric"),
        )
    return out


def _spf_cost(side, one_way: bool) -> int | None:
    """What the SPF pays to travel one direction of a link; ``None`` when it cannot use that direction.

    Same rules as ``correlation.spf``: a router's outgoing metric as advertised, 0 from a transit network
    back to a router (the attachment), nothing for a one-way link (the far end does not advertise it back),
    a direction that no longer exists, or one that was removed since the baseline (drawn, but not live).
    The page's what-if simulation runs Dijkstra on these numbers, so it never has to guess.
    """
    if side is None or one_way or side.status == "removed":
        return None
    if side.attrs.get("link_type") == "attachment":
        return 0
    metric = side.attrs.get("metric")
    return metric if isinstance(metric, int) else None


def _prefix_index(graph: nx.DiGraph) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for node, attrs in graph.nodes(data=True):
        if attrs.get("prefix"):
            index.setdefault(attrs["prefix"], []).append(node)
        for entry in attrs.get("prefixes") or ():
            index.setdefault(entry["prefix"], []).append(node)
    return index


def _focus(
    finding: dict[str, Any], nodes: set[str], prefixes: dict[str, list[str]]
) -> list[str]:
    """The nodes a finding is about, so clicking it can find them on the drawing."""
    data = finding.get("data") or {}
    wanted: list[str] = [finding.get("router")]
    subject = finding.get("subject")
    wanted.append(subject)
    wanted += prefixes.get(subject, [])
    wanted += [
        o.strip() for o in str(data.get("origins") or "").split(",") if o.strip()
    ]
    for key in ("next_hop_routers", "rib", "spf", "candidates"):
        value = data.get(key)
        if isinstance(value, list):
            wanted += value
    seen: list[str] = []
    for node in wanted:
        if node in nodes and node not in seen:
            seen.append(node)
    return seen


def build_scene(
    graph: nx.DiGraph,
    diff: TopologyDiff,
    options: VisualOptions | None = None,
    *,
    trace: Any = None,
    scope: str = "default",
    generated: str | None = None,
    history: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Turn the graph, the diff and the cross-check findings into the data the page draws.

    Args:
        graph: Current topology.
        diff: What changed against the baseline, plus findings and suspect reasons.
        options: Look-and-feel settings (router names).
        trace: A ``correlation.TraceResult`` whose path should be drawn highlighted.
        scope: Names this network in the browser's saved-layout store (e.g. the seed routers), so layouts
            of different networks do not collide.
        generated: Timestamp shown in the header.
        history: Set when the scene shows a past run (``run_id``, ``timestamp``, ``is_suspect``); the page
            names it in its history bar.
    """
    options = options or VisualOptions()
    removed = {r["id"]: r for r in diff.removed_nodes}
    added = {r["id"] for r in diff.added_nodes}
    links = TopologyVisualizer._collect_links(graph, diff, removed)

    # --- every node: current ones, removed ones (kept in this run's drawing), and link ends nobody described
    entries: dict[str, tuple[dict[str, Any], str | None]] = {}
    for node, attrs in graph.nodes(data=True):
        entries[node] = (attrs, "added" if node in added else None)
    for node, rec in removed.items():
        entries.setdefault(node, (rec, "removed"))
    for link in links:
        for end in (link.a, link.b):
            entries.setdefault(
                end,
                (
                    {
                        "type": "network"
                        if str(end).startswith(NETWORK_ID_PREFIX)
                        else "router",
                        "resolved": False,
                        "areas": [],
                    },
                    None,
                ),
            )

    specs: dict[str, NodeSpec] = {}
    scene_nodes: dict[str, dict[str, Any]] = {}
    for node in sorted(entries, key=node_sort_key):
        attrs, status = entries[node]
        kind = _kind(attrs)
        title, sub = _title_and_sub(node, attrs, options.names)
        width, height = _node_size(kind, title, sub)
        areas = [str(a) for a in attrs.get("areas") or []]
        specs[node] = NodeSpec(kind, tuple(areas), width, height)
        scene_nodes[node] = {
            "id": node,
            "kind": kind,
            "title": title,
            "sub": sub,
            "areas": areas,
            "abr": bool(attrs.get("abr")),
            "asbr": bool(attrs.get("asbr") or attrs.get("is_asbr")),
            "role": _role(kind, attrs),
            "status": status,
            "stale": bool(attrs.get("stale")),
            "age": attrs.get("lsa_age"),
            "dr": attrs.get("dr"),
            "prefix": attrs.get("prefix"),
            "prefixes": [e["prefix"] for e in attrs.get("prefixes") or ()][:40],
            "prefix_count": len(attrs.get("prefixes") or ()),
            # the external routes (Type 5 / Type 7 LSAs) an ASBR injects: the first few, and how many in all
            "externals": [
                {k: e.get(k) for k in ("prefix", "metric", "metric_type")}
                for e in attrs.get("externals") or ()
            ][:40],
            "external_count": len(attrs.get("externals") or ()),
            "border_areas": [str(a) for a in attrs.get("border_areas") or ()],
            "name": options.names.get(node),
        }

    # --- links
    scene_links: list[dict[str, Any]] = []
    layout_links: list[tuple[str, str, float]] = []
    for link in links:
        sides = [s for s in (link.ab, link.ba) if s]
        status = TopologyVisualizer._link_status(link)
        one_way = any(s.attrs.get("link_state") == "one-way" for s in sides)
        unverified = any(s.attrs.get("link_state") == "unverified" for s in sides)
        state = TopologyVisualizer._link_adjacency(link)
        segment = any(specs[n].is_hub for n in (link.a, link.b))
        ends = [
            e
            for e in (_end(link.ab, link.a, link.b), _end(link.ba, link.b, link.a))
            if e
        ]
        members = _parallel_members(link.ab, link.ba)
        scene_links.append(
            {
                "id": f"{link.a}|{link.b}",
                "a": link.a,
                "b": link.b,
                "kind": "segment" if segment else "p2p",
                "parallel": len(members) or 1,
                "members": members,
                "status": status,
                "oneWay": one_way,
                "unverified": unverified,
                "state": state,
                "ends": ends,
                "spf": {
                    "ab": _spf_cost(link.ab, one_way),
                    "ba": _spf_cost(link.ba, one_way),
                },
                "metric": min(
                    (e["metric"] for e in ends if isinstance(e.get("metric"), int)),
                    default=None,
                ),
            }
        )
        layout_links.append(
            (link.a, link.b, WEAK_LINK if (one_way or status == "removed") else 1.0)
        )

    layout = compute_layout(specs, layout_links)
    for node, (x, y) in layout.positions.items():
        scene_nodes[node]["x"], scene_nodes[node]["y"] = round(x, 1), round(y, 1)
        scene_nodes[node]["w"], scene_nodes[node]["h"] = specs[node].size
    component_of = {n: i for i, comp in enumerate(layout.components) for n in comp}
    for node, info in scene_nodes.items():
        info["part"] = component_of.get(node, 0)

    # --- diagnostics
    meta_graph = graph.graph
    groups = (
        sorted(
            (
                sorted(c, key=node_sort_key)
                for c in nx.weakly_connected_components(graph)
            ),
            key=lambda g: (-len(g), g[0]),
        )
        if graph.number_of_nodes()
        else []
    )
    issues = []
    for issue in meta_graph.get("adjacency_issues") or []:
        issues.append(
            {
                **issue,
                "focus": [
                    n
                    for n in (issue.get("router"), issue.get("neighbor"))
                    if n in scene_nodes
                ],
            }
        )
    prefixes = _prefix_index(graph)
    findings = []
    for f in diff.findings:
        findings.append({**f, "focus": _focus(f, set(scene_nodes), prefixes)})
    diagnostics = {
        "split": {"parts": len(groups), "groups": groups} if len(groups) > 1 else None,
        "oneWay": [link["id"] for link in scene_links if link["oneWay"]],
        "unverified": [link["id"] for link in scene_links if link["unverified"]],
        "stale": [n for n, info in scene_nodes.items() if info["stale"]],
        "adjacency": issues,
        "suspect": list(diff.suspect_reasons),
        # LSAs at (or near) MaxAge: left out of the topology on purpose, listed here for information only
        "flushing": [
            {k: e.get(k) for k in ("type", "id", "area", "age", "dr", "prefixes")}
            for e in meta_graph.get("flushing_lsas") or []
        ],
        "changes": {
            "baseline": bool(diff.baseline_available),
            "addedNodes": [n["id"] for n in diff.added_nodes],
            "removedNodes": [n["id"] for n in diff.removed_nodes],
            "addedLinks": len(
                {frozenset((e["source"], e["target"])) for e in diff.added_edges}
            ),
            "removedLinks": len(
                {frozenset((e["source"], e["target"])) for e in diff.removed_edges}
            ),
            "metricChanges": len(diff.changed_metrics),
        },
    }

    trace_scene = None
    if trace is not None:
        pairs = {tuple(sorted(pair)) for pair in trace.edges}
        trace_scene = {
            "query": trace.query,
            "source": trace.source,
            "prefix": trace.prefix,
            "verdict": trace.verdict,
            "cost": trace.spf_cost,
            "notes": list(trace.notes),
            "paths": trace.paths,
            "rib": trace.rib,
            "links": [
                link["id"]
                for link in scene_links
                if tuple(sorted((link["a"], link["b"]))) in pairs
            ],
        }

    routers = sum(1 for n in scene_nodes.values() if n["kind"] == "router")
    return {
        "meta": {
            "version": __version__,
            "generated": generated or datetime.now(UTC).isoformat(timespec="seconds"),
            "scope": scope,
            "theme": options.theme
            if options.theme_explicit
            else "auto",  # starting theme; a saved choice wins
            "routers": routers,
            "networks": len(scene_nodes) - routers,
            "links": len(scene_links),
            "sources": meta_graph.get("sources") or [],
            "areas": sorted({a for n in scene_nodes.values() for a in n["areas"]}),
            "backbone": [b.id for b in layout.areas if b.backbone],
            "device_type": str(meta_graph.get("device_type") or ""),
            "history": history,
        },
        "nodes": list(scene_nodes.values()),
        "links": scene_links,
        "areas": [
            {
                "id": b.id,
                "x": round(b.x, 1),
                "y": round(b.y, 1),
                "w": round(b.w, 1),
                "h": round(b.h, 1),
                "backbone": b.backbone,
            }
            for b in layout.areas
        ],
        "diagnostics": diagnostics,
        "findings": findings,
        "trace": trace_scene,
        "area_coverage": getattr(diff, "area_coverage", None),
    }


def render_html(scene: dict[str, Any]) -> str:
    """Fill the page template with ``scene`` (embedded as JSON, safe inside a ``<script>`` element)."""
    payload = json.dumps(scene, ensure_ascii=False, separators=(",", ":"))
    payload = (
        payload.replace("<", "\\u003c")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    title = html.escape(f"OSPF Topology Explorer - {scene['meta']['routers']} routers")
    page = TEMPLATE.read_text(encoding="utf-8")
    theme = (
        scene["meta"].get("theme")
        if scene["meta"].get("theme") in ("auto", "light", "dark")
        else "auto"
    )
    return (
        page.replace("__TITLE__", title)
        .replace("__THEME__", theme)
        .replace("/*__SCENE__*/null", payload)
    )


def write_explorer(
    path: Path,
    graph: nx.DiGraph,
    diff: TopologyDiff,
    options: VisualOptions | None = None,
    *,
    trace: Any = None,
    scope: str = "default",
) -> Path:
    """Write the explorer page to ``path`` and return it."""
    # Atomic: the web server may be sending this very file to a browser while a poll rewrites it.
    return atomic_write_text(
        path, render_html(build_scene(graph, diff, options, trace=trace, scope=scope))
    )
