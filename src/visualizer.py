"""
==============================================================================
Module Name:   visualizer.py
Description:   Source module visualizer.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 visualizer.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import logging
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import graphviz
import networkx as nx

from src import NETWORK_ID_PREFIX, TrackerError, node_sort_key
from src.graph_engine import TopologyDiff, display_name

logger = logging.getLogger(__name__)

COLOR_NORMAL = "#2C3E50"
COLOR_ADDED = "#27AE60"
COLOR_REMOVED = "#E74C3C"
COLOR_CHANGED = "#E67E22"
COLOR_MUTED = "#95A5A6"
# Adjacency state of a link (from the neighbour tables)
COLOR_FULL = "#1E8449"  # Full
COLOR_TWO_WAY = "#D4AC0D"  # 2-Way (normal between two DROthers on a broadcast segment)
COLOR_STUCK = "#D35400"  # ExStart / Exchange / Loading: negotiating or stuck
COLOR_DOWN = "#C0392B"  # Init / Down / Attempt
COLOR_PATH = "#2471A3"  # the path drawn by --trace
COLOR_WARN = "#8E44AD"  # data the LSDB itself casts doubt on: stale router, one-way link, stuck adjacency

FILL_ROUTER = "#3498DB"
FILL_NETWORK = "#FFF3C4"
FILL_UNRESOLVED = "#ECF0F1"
FILL_REMOVED = "#FDEDEC"


@dataclass(frozen=True)
class Palette:
    """Every colour of the Graphviz picture. ``LIGHT`` is the classic look; ``DARK`` is for dark backgrounds."""

    name: str
    background: str | None  # ``None``: leave the canvas to the viewer (white)
    text: str  # title, notes and legend
    edge: str  # an ordinary link
    edge_text: str  # cost and interface labels
    node_border: str
    muted: str
    added: str
    removed: str
    changed: str
    full: str
    two_way: str
    stuck: str
    down: str
    path: str
    warn: str
    fill_router: str
    router_text: str
    fill_network: str
    network_text: str
    fill_unresolved: str
    unresolved_text: str
    fill_removed: str


LIGHT = Palette(
    name="light",
    background=None,
    text="black",
    edge=COLOR_NORMAL,
    edge_text=COLOR_NORMAL,
    node_border=COLOR_NORMAL,
    muted=COLOR_MUTED,
    added=COLOR_ADDED,
    removed=COLOR_REMOVED,
    changed=COLOR_CHANGED,
    full=COLOR_FULL,
    two_way=COLOR_TWO_WAY,
    stuck=COLOR_STUCK,
    down=COLOR_DOWN,
    path=COLOR_PATH,
    warn=COLOR_WARN,
    fill_router=FILL_ROUTER,
    router_text="white",
    fill_network=FILL_NETWORK,
    network_text="black",
    fill_unresolved=FILL_UNRESOLVED,
    unresolved_text=COLOR_NORMAL,
    fill_removed=FILL_REMOVED,
)
DARK = Palette(
    name="dark",
    background="#0B1324",
    text="#E6EDF7",
    edge="#94A3B8",
    edge_text="#E6EDF7",
    node_border="#94A3B8",
    muted="#94A3B8",
    added="#34D399",
    removed="#F87171",
    changed="#FB923C",
    full="#34D399",
    two_way="#FACC15",
    stuck="#FB923C",
    down="#F87171",
    path="#38BDF8",
    warn="#A78BFA",
    fill_router="#1D4ED8",
    router_text="#E6EDF7",
    fill_network="#5C4A12",
    network_text="#E6EDF7",
    fill_unresolved="#1E293B",
    unresolved_text="#E6EDF7",
    fill_removed="#4B1D22",
)
PALETTES = {"light": LIGHT, "dark": DARK}
THEMES = tuple(PALETTES)

#: Auto layout: a node with at least this many neighbours switches the drawing to left-to-right.
AUTO_LR_DEGREE = 6
#: Line thickness range used when drawing cost-weighted lines.
PEN_MIN, PEN_MAX, PEN_FLAT = 1.0, 2.6, 1.6

#: Display abbreviations for long interface names, longest prefix first (the stored name is never shortened).
_IF_ABBREVIATIONS = (
    ("HundredGigE", "Hu"),
    ("TwentyFiveGigE", "Twe"),
    ("TenGigabitEthernet", "Te"),
    ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"),
    ("Port-channel", "Po"),
    ("Loopback", "Lo"),
    ("Ethernet", "Eth"),
    ("Vlan", "Vl"),
)


def adjacency_color(state: str | None, palette: Palette = LIGHT) -> str | None:
    """Link colour for a neighbour state (``None`` = no adjacency data for the link)."""
    if state is None:
        return None
    return {
        "Full": palette.full,
        "2-Way": palette.two_way,
        "Loading": palette.stuck,
        "Exchange": palette.stuck,
        "ExStart": palette.stuck,
    }.get(state, palette.down)


def short_interface(name: str) -> str:
    """``GigabitEthernet0/0/1`` -> ``Gi0/0/1`` so link labels stay narrow."""
    for long, short in _IF_ABBREVIATIONS:
        if name.startswith(long):
            return short + name[len(long) :]
    return name


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


_RANKDIRS = ("auto", "TB", "LR", "BT", "RL")
_ROUTER_SHAPES = ("box3d", "box", "circle", "ellipse", "oval", "doublecircle")


class VisualizationError(TrackerError):
    """Raised when the diagram cannot be rendered."""


@dataclass(frozen=True)
class VisualOptions:
    """Look-and-feel settings (``visualization:`` in settings.yaml)."""

    rankdir: str = "auto"  # auto | TB | LR | BT | RL
    router_shape: str = "box3d"
    show_interfaces: bool = (
        True  # print the advertising router's interface address next to each cost
    )
    cost_weighted_lines: bool = True
    area_clusters: bool = (
        True  # dashed cluster per OSPF area when there is more than one
    )
    names: dict[str, str] = field(
        default_factory=dict
    )  # router-ID -> hostname, shown above the ID
    theme: str = "light"  # light | dark: colours of the Graphviz picture (the explorer page has its own switch)
    #: True when the user chose the theme (settings or --theme): the explorer then starts in it instead of "auto".
    theme_explicit: bool = False

    @classmethod
    def from_settings(cls, section: dict[str, Any] | None) -> VisualOptions:
        """Build from the ``visualization`` mapping of settings.yaml (missing keys use the defaults).

        Raises:
            VisualizationError: On an unknown rankdir/shape or a malformed ``names`` map.
        """
        section = section or {}
        if not isinstance(section, dict):
            raise VisualizationError(
                "'visualization' in settings.yaml must be a mapping"
            )
        names = section.get("names") or {}
        if not isinstance(names, dict):
            raise VisualizationError(
                "visualization.names must map router IDs to host names"
            )
        options = cls(
            rankdir=str(section.get("rankdir", "auto")),
            router_shape=str(section.get("router_shape", "box3d")),
            show_interfaces=bool(section.get("show_interfaces", True)),
            cost_weighted_lines=bool(section.get("cost_weighted_lines", True)),
            area_clusters=bool(section.get("area_clusters", True)),
            names={str(k): str(v) for k, v in names.items()},
            theme=str(section.get("theme", "light")).strip().lower(),
            theme_explicit="theme" in section,
        )
        if options.theme not in PALETTES:
            raise VisualizationError(
                f"visualization.theme must be one of {', '.join(THEMES)}"
            )
        if options.rankdir not in _RANKDIRS:
            raise VisualizationError(
                f"visualization.rankdir must be one of {', '.join(_RANKDIRS)}"
            )
        if options.router_shape not in _ROUTER_SHAPES:
            raise VisualizationError(
                f"visualization.router_shape must be one of {', '.join(_ROUTER_SHAPES)}"
            )
        return options


@dataclass
class _Side:
    """One direction of a link (a -> b or b -> a)."""

    attrs: dict[str, Any]
    status: str | None = None  # None | "added" | "removed" | "changed"
    change: dict[str, Any] | None = None


@dataclass
class _Link:
    """Both directions of a link merged. ``a`` is the router end (router<->router: the lower ID)."""

    a: str
    b: str
    ab: _Side | None = None
    ba: _Side | None = None

    @property
    def cost_bearing(self) -> list[_Side]:
        return [
            s
            for s in (self.ab, self.ba)
            if s and s.attrs.get("link_type") != "attachment"
        ]


class TopologyVisualizer:
    """Render the topology (and what changed since the last run) with Graphviz."""

    def __init__(
        self,
        output_path: str | os.PathLike = "output/topology.png",
        layout: str = "dot",
        options: VisualOptions | None = None,
    ) -> None:
        """
        Args:
            output_path: Target image; the extension selects the format (png, svg, pdf, ...).
            layout: Graphviz layout engine (``dot``, ``neato``, ``fdp``, ``sfdp``, ...).
            options: Look-and-feel settings (defaults if omitted).
        """
        self.output_path = Path(output_path)
        self.layout = layout
        self.options = options or VisualOptions()
        self.image_format = self.output_path.suffix.lstrip(".").lower() or "png"
        #: Names this network in the explorer page's saved-layout store (set by the caller, e.g. the seeds).
        self.scope = "default"
        self.palette = PALETTES.get(self.options.theme, LIGHT)
        if (
            self.image_format not in ("html", "htm")
            and self.image_format not in graphviz.FORMATS
        ):
            raise VisualizationError(
                f"Unsupported output format '.{self.image_format}'"
            )
        if layout not in graphviz.ENGINES:
            raise VisualizationError(f"Unknown Graphviz layout engine '{layout}'")

    @property
    def interactive(self) -> bool:
        """True when the output is the interactive HTML explorer rather than a Graphviz image."""
        return self.image_format in ("html", "htm")

    # ---------------------------------------------------------------- building
    def build_digraph(
        self,
        graph: nx.DiGraph,
        diff: TopologyDiff,
        highlight: set[frozenset] | None = None,
    ) -> graphviz.Graph:
        """Translate the graph and diff report into a Graphviz graph.

        ``highlight`` is a set of node pairs (``frozenset({a, b})``) to draw as the traced path.

        (The name is historical: the result is undirected, one line per link.)
        """
        removed_nodes = {n["id"]: n for n in diff.removed_nodes}
        links = self._collect_links(graph, diff, removed_nodes)

        dot = graphviz.Graph(
            name="OSPF_Topology", engine=self.layout, format=self.image_format
        )
        pal = self.palette
        dot.attr(
            label=self._title(graph, diff, links),
            labelloc="t",
            fontname="Helvetica",
            fontsize="13",
            fontcolor=pal.removed if diff.suspect_reasons else pal.text,
            rankdir=self._rankdir(links),
            splines="true",
            overlap="false",
            nodesep="0.5",
            ranksep="1.1",
            dpi="150",
        )
        if pal.background:
            dot.attr(bgcolor=pal.background)
        dot.attr("node", fontname="Helvetica", fontsize="11")
        dot.attr("edge", fontname="Helvetica", fontsize="10", labeldistance="2.4")

        drawn = self._draw_nodes(dot, graph, diff, removed_nodes)

        scale = self._cost_scale(links)
        for link in links:
            for end in (
                link.a,
                link.b,
            ):  # an endpoint missing from graph and diff still needs a node
                if end not in drawn:
                    dot.node(
                        end,
                        label=end,
                        style="filled,dashed",
                        fillcolor=pal.fill_unresolved,
                        fontcolor=pal.unresolved_text,
                        color=pal.muted,
                    )
                    drawn.add(end)
            attrs = self._edge_attrs(link, scale)
            if highlight and frozenset((link.a, link.b)) in highlight:
                attrs.update(
                    color=pal.path, fontcolor=pal.path, penwidth="5", style="solid"
                )
            dot.edge(link.a, link.b, **attrs)

        for issue in graph.graph.get("adjacency_issues") or []:
            router, neighbour = issue["router"], issue["neighbor"]
            if router not in drawn or self._state_drawn(graph, router, neighbour):
                continue  # the link itself is coloured by its adjacency state; no extra dashed line needed
            if (
                neighbour not in drawn
            ):  # a router that is trying to join but is not in the LSDB (yet)
                dot.node(
                    neighbour,
                    label=f"{neighbour}\\n(not in LSDB)",
                    style="filled,dashed",
                    fillcolor=pal.fill_unresolved,
                    color=pal.warn,
                    fontcolor=pal.unresolved_text,
                )
                drawn.add(neighbour)
            text = issue["state"] + (
                f"\\n{short_interface(issue['interface'])}"
                if issue.get("interface")
                else ""
            )
            dot.edge(
                router,
                neighbour,
                label=text,
                color=pal.warn,
                fontcolor=pal.warn,
                style="dashed",
                penwidth="1.6",
            )
        return dot

    @staticmethod
    def _state_drawn(graph: nx.DiGraph, router: str, neighbour: str) -> bool:
        """True if the link between ``router`` and ``neighbour`` carries an adjacency state (so it is coloured)."""
        if graph.has_edge(router, neighbour):
            return "nbr_state" in graph.edges[router, neighbour]
        return any(
            "nbr_state" in attrs and graph.has_edge(seg, neighbour)
            for seg, attrs in (
                (s, graph.edges[router, s])
                for s in graph.successors(router)
                if graph.nodes[s].get("type") == "network"
            )
        )

    @staticmethod
    def _link_adjacency(link: _Link) -> str | None:
        """Worst adjacency state over both directions of a link."""
        from src.vendors.base import state_severity

        states = [
            s.attrs["nbr_state"]
            for s in (link.ab, link.ba)
            if s and s.status != "removed" and s.attrs.get("nbr_state")
        ]
        return max(states, key=state_severity) if states else None

    # ------------------------------------------------------------------- links
    @staticmethod
    def _collect_links(
        graph: nx.DiGraph, diff: TopologyDiff, removed_nodes: dict[str, dict]
    ) -> list[_Link]:
        """Merge directed edges (current + removed) into one ``_Link`` per node pair."""
        added = {(e["source"], e["target"]) for e in diff.added_edges}
        changed = {(e["source"], e["target"]): e for e in diff.changed_metrics}
        links: dict[frozenset, _Link] = {}

        def is_network(node: str) -> bool:
            if node in graph:
                return graph.nodes[node].get("type") == "network"
            if node in removed_nodes:
                return removed_nodes[node].get("type") == "network"
            return str(node).startswith(NETWORK_ID_PREFIX)

        def put(u: str, v: str, side: _Side) -> None:
            key = frozenset((u, v))
            if key not in links:
                swap = (is_network(u) and not is_network(v)) or (
                    is_network(u) == is_network(v)
                    and node_sort_key(v) < node_sort_key(u)
                )
                links[key] = _Link(*((v, u) if swap else (u, v)))
            link = links[key]
            if (u, v) == (link.a, link.b):
                link.ab = side
            else:
                link.ba = side

        for u, v, attrs in graph.edges(data=True):
            status = (
                "added" if (u, v) in added else "changed" if (u, v) in changed else None
            )
            put(u, v, _Side(attrs, status, changed.get((u, v))))
        for record in diff.removed_edges:
            if not graph.has_edge(record["source"], record["target"]):
                put(record["source"], record["target"], _Side(record, "removed"))
        return sorted(
            links.values(),
            key=lambda link: (node_sort_key(link.a), node_sort_key(link.b)),
        )

    @staticmethod
    def _link_status(link: _Link) -> str | None:
        """Overall status of a link, judged from the directions that currently exist."""
        sides = [s for s in (link.ab, link.ba) if s]
        live = [s for s in sides if s.status != "removed"]
        if not live:
            return "removed"
        if all(s.status == "added" for s in live):
            return "added"
        if any(s.status == "changed" for s in live):
            return "changed"
        return None

    def _end_text(self, side: _Side | None) -> str:
        """Label for one link end: the cost (``old->new`` if changed) and the interface address."""
        if side is None or side.attrs.get("link_type") == "attachment":
            return ""
        if side.status == "changed" and side.change:
            lines = [f"{side.change['old_metric']}\u2192{side.change['new_metric']}"]
        else:
            lines = [str(side.attrs.get("metric", ""))]
        if self.options.show_interfaces:
            if side.attrs.get("interface"):
                lines.append(short_interface(str(side.attrs["interface"])))
            if side.attrs.get("interface_address"):
                lines.append(str(side.attrs["interface_address"]))
        return "\\n".join(line for line in lines if line)

    def _edge_attrs(self, link: _Link, scale) -> dict[str, str]:
        """Graphviz attributes for one link (labels at the right ends, colour by status)."""
        pal = self.palette
        status = self._link_status(link)
        attrs: dict[str, str] = {"color": pal.edge, "fontcolor": pal.edge_text}

        text_a, text_b = self._end_text(link.ab), self._end_text(link.ba)
        on_segment = any(
            s.attrs.get("link_type") in ("transit", "attachment")
            for s in (link.ab, link.ba)
            if s
        )
        if on_segment:
            # Router <-> transit network: only the router's side carries a cost, so a centred label is
            # unambiguous (and keeps labels clear of busy router boxes).
            if text_a or text_b:
                attrs["label"] = text_a or text_b
        elif link.ab and link.ba and text_a == text_b and text_a:
            attrs["label"] = text_a  # symmetric point-to-point: one centred label
        else:
            # Point-to-point: each router advertises its own cost, shown at its own end of the line.
            if text_a:
                attrs["taillabel"] = text_a
            if text_b:
                attrs["headlabel"] = text_b

        if any(s.attrs.get("link_state") == "one-way" for s in (link.ab, link.ba) if s):
            # Only one end advertises it, so OSPF's own calculation ignores this link.
            for key in ("label", "taillabel", "headlabel"):
                if key in attrs:
                    attrs[key] += "\\none-way"
                    break
            else:
                attrs["label"] = "one-way"
            attrs.update(color=pal.warn, fontcolor=pal.warn, style="dotted")

        costs = [
            s.attrs["metric"]
            for s in link.cost_bearing
            if isinstance(s.attrs.get("metric"), int)
        ]
        attrs["penwidth"] = f"{scale(min(costs)) if costs else PEN_FLAT:.1f}"
        if status == "added":
            attrs.update(color=pal.added, fontcolor=pal.added, penwidth="2.8")
        elif status == "removed":
            attrs.update(
                color=pal.removed,
                fontcolor=pal.removed,
                style="dashed",
                penwidth="2.4",
            )
        elif status == "changed":
            attrs.update(color=pal.changed, fontcolor=pal.changed, penwidth="2.8")

        state = self._link_adjacency(link)
        one_way = attrs.get("style") == "dotted"
        if state and status != "removed" and not one_way:
            color = adjacency_color(state, pal)
            if state == "Full":
                if (
                    status is None
                ):  # an added/changed link keeps its change colour; Full says nothing is wrong
                    attrs.update(color=color, fontcolor=color)
            else:  # anything short of Full is worth seeing, whatever else changed
                attrs.update(color=color, fontcolor=color, penwidth="3.2")
                for key in ("label", "taillabel", "headlabel"):
                    if key in attrs:
                        attrs[key] += f"\\n{state}"
                        break
                else:
                    attrs["label"] = state
        return attrs

    def _cost_scale(self, links: list[_Link]):
        """Return ``cost -> line thickness`` (cheaper = thicker, log scale across the observed range)."""
        costs = [
            s.attrs["metric"]
            for link in links
            for s in link.cost_bearing
            if isinstance(s.attrs.get("metric"), int) and s.attrs["metric"] > 0
        ]
        if (
            not self.options.cost_weighted_lines
            or not costs
            or max(costs) == min(costs)
        ):
            return lambda _cost: PEN_FLAT
        lo, hi = min(costs), max(costs)
        return lambda cost: (
            PEN_MAX
            - (PEN_MAX - PEN_MIN) * math.log(max(cost, lo) / lo) / math.log(hi / lo)
        )

    # ------------------------------------------------------------------- nodes
    def _draw_nodes(
        self,
        dot: graphviz.Graph,
        graph: nx.DiGraph,
        diff: TopologyDiff,
        removed_nodes: dict[str, dict],
    ) -> set[str]:
        """Draw every node (area clusters when there is more than one area); return the IDs drawn."""
        added = {n["id"] for n in diff.added_nodes}
        entries: list[tuple[str, dict, str | None]] = [
            (n, attrs, "added" if n in added else None)
            for n, attrs in graph.nodes(data=True)
        ]
        entries += [
            (n, rec, "removed") for n, rec in removed_nodes.items() if n not in graph
        ]
        entries.sort(key=lambda e: node_sort_key(e[0]))

        every_area = {a for _, attrs, _ in entries for a in attrs.get("areas") or []}
        clustered = self.options.area_clusters and len(every_area) > 1
        by_area: dict[str, list] = {}
        for entry in entries:
            areas = entry[1].get("areas") or []
            if (
                clustered and len(areas) == 1
            ):  # ABRs (several areas) stay outside every cluster
                by_area.setdefault(areas[0], []).append(entry)
            else:
                self._draw_node(dot, *entry)
        for area in sorted(by_area):
            with dot.subgraph(name="cluster_area_" + re.sub(r"\W+", "_", area)) as sub:
                sub.attr(
                    label=f"Area {area}",
                    labeljust="l",
                    style="dashed",
                    color=self.palette.muted,
                    fontcolor=self.palette.muted,
                    fontname="Helvetica",
                    fontsize="12",
                )
                for entry in by_area[area]:
                    self._draw_node(sub, *entry)
        return {e[0] for e in entries}

    def _draw_node(
        self, target: graphviz.Graph, node_id: str, attrs: dict, status: str | None
    ) -> None:
        """Draw one node: shape by role, fill by resolved/unresolved, outline by diff status."""
        pal = self.palette
        if attrs.get("type") == "network":
            label = display_name(node_id, attrs)
            if attrs.get("dr"):
                label += f"\\nDR {attrs['dr']}"
            look = {
                "shape": "diamond",
                "fillcolor": pal.fill_network,
                "fontcolor": pal.network_text,
            }
        else:
            name = self.options.names.get(node_id)
            label = f"{name}\\n{node_id}" if name else node_id
            look = {
                "shape": self.options.router_shape,
                "fillcolor": pal.fill_router,
                "fontcolor": pal.router_text,
            }
            roles = [
                r
                for r, on in (("ABR", attrs.get("abr")), ("ASBR", attrs.get("asbr")))
                if on
            ]
            if roles:
                label += "\\n" + "/".join(roles)
            if attrs.get("abr"):
                look["peripheries"] = (
                    "2"  # a second outline marks the routers that join areas
                )
        look.update(style="filled", color=pal.node_border, penwidth="1.2")

        if not attrs.get(
            "resolved", True
        ):  # referenced by a link, but no LSA of its own in the database
            look.update(
                fillcolor=pal.fill_unresolved,
                fontcolor=pal.unresolved_text,
                color=pal.muted,
                style="filled,dashed",
            )
            label += "\\n(no LSA)"
        if attrs.get(
            "stale"
        ):  # its LSA is no longer being refreshed: the router is probably gone
            look.update(color=pal.warn, style="filled,dashed", penwidth="2")
            label += f"\\nstale LSA ({attrs.get('lsa_age', 0) // 60} min)"
        if status == "added":
            look.update(color=pal.added, penwidth="3")
        elif status == "removed":
            look.update(
                color=pal.removed,
                fontcolor=pal.removed,
                fillcolor=pal.fill_removed,
                style="filled,dashed",
                penwidth="2",
            )
        target.node(node_id, label=label, **look)

    # ------------------------------------------------------------ layout / text
    def _rankdir(self, links: list[_Link]) -> str:
        """Honour an explicit rankdir; otherwise go left-to-right when some node is a hub."""
        if self.options.rankdir != "auto":
            return self.options.rankdir
        neighbours: dict[str, set[str]] = {}
        for link in links:
            neighbours.setdefault(link.a, set()).add(link.b)
            neighbours.setdefault(link.b, set()).add(link.a)
        widest = max((len(n) for n in neighbours.values()), default=0)
        return "LR" if widest >= AUTO_LR_DEGREE else "TB"

    @staticmethod
    def _title(graph: nx.DiGraph, diff: TopologyDiff, links: list[_Link]) -> str:
        stamp = graph.graph.get("generated_at") or graph.graph.get("parsed_at") or ""
        kinds = [attrs.get("type") for _, attrs in graph.nodes(data=True)]
        live_links = sum(
            1 for link in links if TopologyVisualizer._link_status(link) != "removed"
        )
        lines = [
            f"OSPF topology  |  {_plural(kinds.count('router'), 'router')}, "
            f"{_plural(kinds.count('network'), 'transit network')}, {_plural(live_links, 'link')}  |  {stamp}"
        ]
        meta = graph.graph
        flagged = bool(
            meta.get("stale_nodes")
            or meta.get("one_way_links")
            or meta.get("adjacency_issues")
        )
        purple = "   purple = stale / one-way / adjacency problem" if flagged else ""
        if diff.baseline_available:
            lines.append(
                "green = new   red dashed = removed   orange = metric changed"
                + purple
                + "   |   cost shown at each interface"
            )
        else:
            lines.append(
                "first run - no previous state to compare against"
                + purple
                + "   |   cost shown at each interface"
            )
        if any(attrs.get("nbr_state") for _u, _v, attrs in graph.edges(data=True)):
            lines.append(
                "adjacency: green = Full   yellow = 2-Way   orange = ExStart/Exchange/Loading   red = Init/Down"
            )
        if getattr(diff, "findings", None):
            counts = {}
            for f in diff.findings:
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            alarms = [
                f"{counts[sev]} {sev}"
                for sev in ("critical", "warning")
                if counts.get(sev)
            ]
            info = f"{counts['info']} info" if counts.get("info") else ""
            lines.append(
                "CROSS-CHECK: "
                + (
                    ", ".join(alarms) + (f" (+{info})" if info else "")
                    if alarms
                    else f"{info} (no alarm)"
                )
            )
        if meta.get("flushing_lsas"):
            lines.append(
                f"INFO: {_plural(len(meta['flushing_lsas']), 'LSA')} at age {meta.get('maxage_ignore_age') or 0}+ s ignored (being flushed)"
            )
        sources = graph.graph.get("sources") or []
        if len(sources) > 1:
            ok = [s["name"] for s in sources if s.get("status") == "ok"]
            lost = [s["name"] for s in sources if s.get("status") != "ok"]
            line = f"merged from {_plural(len(ok), 'router')}: {', '.join(ok)}"
            lines.append(
                line + (f"   |   NOT POLLED: {', '.join(lost)}" if lost else "")
            )
        found = [
            f"{count} {text}"
            for count, text in (
                (len(meta.get("stale_nodes") or []), "stale router(s)"),
                (meta.get("one_way_links") or 0, "one-way link(s)"),
                (len(meta.get("adjacency_issues") or []), "adjacency problem(s)"),
            )
            if count
        ]
        if found:
            lines.append("DATA QUALITY: " + ", ".join(found))
        parts = (
            nx.number_weakly_connected_components(graph)
            if graph.number_of_nodes()
            else 0
        )
        if parts > 1:
            lines.append(f"WARNING: topology is split into {parts} disconnected parts")
        if diff.suspect_reasons:
            held = (
                "baseline NOT updated"
                if not diff.baseline_updated
                else "baseline updated (--accept-changes)"
            )
            lines.append(f"SUSPECT RUN - possible partial LSDB; {held}")
        return "\\n".join(lines)

    # ---------------------------------------------------------------- rendering
    def render(
        self,
        graph: nx.DiGraph,
        diff: TopologyDiff,
        highlight: set[frozenset] | None = None,
        trace=None,
    ) -> Path:
        """Render the diagram to ``output_path`` and return the path of the image.

        ``highlight`` (node pairs) draws a traced path in blue; see ``correlation.trace_prefix``. With an
        ``.html`` output the interactive explorer is written instead (no Graphviz needed); it takes the whole
        ``trace`` result so it can show the path in its sidebar too.

        On failure to run Graphviz, the DOT source is saved next to the target
        so it can be rendered later with ``dot -Tpng``.

        Raises:
            VisualizationError: If Graphviz is missing or fails.
        """
        if self.interactive:
            # Lazy import: only needed for this output type.
            from src.explorer import write_explorer

            path = write_explorer(
                self.output_path,
                graph,
                diff,
                self.options,
                trace=trace,
                scope=self.scope,
            )
            logger.info("Wrote interactive topology explorer to %s", path)
            return path
        dot = self.build_digraph(graph, diff, highlight)
        out_dir = self.output_path.parent
        stem = self.output_path.stem
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            rendered = dot.render(filename=stem, directory=str(out_dir), cleanup=True)
        except graphviz.ExecutableNotFound as exc:
            source_path = self._save_source(dot, out_dir, stem)
            raise VisualizationError(
                "The Graphviz 'dot' executable was not found (install the system package, e.g. "
                f"'apt install graphviz' or 'brew install graphviz'). DOT source saved to {source_path}"
            ) from exc
        except (graphviz.CalledProcessError, OSError) as exc:
            source_path = self._save_source(dot, out_dir, stem)
            raise VisualizationError(
                f"Graphviz rendering failed ({exc}); DOT source saved to {source_path}"
            ) from exc
        logger.info("Rendered topology diagram to %s", rendered)
        return Path(rendered)

    @staticmethod
    def _save_source(dot: graphviz.Graph, out_dir: Path, stem: str) -> Path:
        path = out_dir / f"{stem}.gv"
        try:
            path.write_text(dot.source, encoding="utf-8")
        except OSError:
            logger.warning("Could not save DOT source to %s", path)
        return path
