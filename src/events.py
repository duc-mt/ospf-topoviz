"""Normalized topology event generation from OSPF diffs and cross-check findings."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

import networkx as nx

if TYPE_CHECKING:
    from src.graph_engine import TopologyDiff


@dataclass(frozen=True)
class TopologyEvent:
    """Normalized OSPF event record stored in SQLite and emitted to exporters and SSE streams."""

    event_id: str
    run_id: str
    timestamp: str
    event_type: str
    event_name: str
    object_status: str
    severity: str
    object_id: str
    detected_by: str
    area: str
    summary: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize this event as a JSON-friendly dictionary."""
        return asdict(self)


def _finding_key(f: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(f.get("kind") or ""),
        str(f.get("router") or ""),
        str(f.get("subject") or ""),
    )


def diff_to_events(
    diff: TopologyDiff,
    graph: nx.DiGraph,
    run_id: str,
    timestamp: str,
    prev_findings: Sequence[dict[str, Any]] = (),
) -> list[TopologyEvent]:
    """Translate an accepted ``TopologyDiff`` and finding delta into ``TopologyEvent`` instances."""
    events: list[TopologyEvent] = []
    seq = 0

    def add(
        event_type: str,
        event_name: str,
        object_status: str,
        severity: str,
        object_id: str,
        detected_by: str,
        area: str,
        summary: str,
        details: dict[str, Any],
    ) -> None:
        nonlocal seq
        seq += 1
        events.append(
            TopologyEvent(
                event_id=f"{run_id}:{seq}",
                run_id=run_id,
                timestamp=timestamp,
                event_type=event_type,
                event_name=event_name,
                object_status=object_status,
                severity=severity,
                object_id=str(object_id),
                detected_by=str(detected_by),
                area=str(area or ""),
                summary=summary,
                details=details,
            )
        )

    for n in diff.added_nodes:
        nid = str(n.get("id") or "")
        area = next(iter(n.get("areas") or ()), "")
        add(
            "node_added",
            "node",
            "up",
            "info",
            nid,
            nid,
            str(area),
            f"Node added: {n.get('label') or nid}",
            {"type": n.get("type", "router"), "areas": list(n.get("areas") or ())},
        )

    for n in diff.removed_nodes:
        nid = str(n.get("id") or "")
        area = next(iter(n.get("areas") or ()), "")
        add(
            "node_removed",
            "node",
            "down",
            "warning",
            nid,
            nid,
            str(area),
            f"Node removed: {n.get('label') or nid}",
            {"type": n.get("type", "router"), "areas": list(n.get("areas") or ())},
        )

    for e in diff.added_edges:
        src = str(e.get("source") or "")
        dst = str(e.get("target") or "")
        add(
            "link_up",
            "metric",
            "up",
            "info",
            dst,
            src,
            str(e.get("area") or ""),
            f"Link up: {src} -> {dst} (metric {e.get('metric', '?')})",
            {
                "source": src,
                "target": dst,
                "metric": e.get("metric"),
                "interface_address": e.get("interface_address"),
                "link_type": e.get("link_type"),
            },
        )

    for e in diff.removed_edges:
        src = str(e.get("source") or "")
        dst = str(e.get("target") or "")
        add(
            "link_down",
            "metric",
            "down",
            "warning",
            dst,
            src,
            str(e.get("area") or ""),
            f"Link down: {src} -> {dst}",
            {
                "source": src,
                "target": dst,
                "old_metric": e.get("metric"),
                "interface_address": e.get("interface_address"),
                "link_type": e.get("link_type"),
            },
        )

    for e in diff.changed_metrics:
        src = str(e.get("source") or "")
        dst = str(e.get("target") or "")
        old_m = e.get("old_metric")
        new_m = e.get("new_metric")
        add(
            "link_cost_changed",
            "metric",
            "changed",
            "warning",
            dst,
            src,
            str(e.get("area") or ""),
            f"Link cost changed: {src} -> {dst} ({old_m} -> {new_m})",
            {
                "source": src,
                "target": dst,
                "old_metric": old_m,
                "new_metric": new_m,
                "interface_address": e.get("interface_address"),
            },
        )

    for p in getattr(diff, "changed_prefixes", []) or ():
        act = str(p.get("action") or "changed")
        prefix = str(p.get("prefix") or "")
        router = str(p.get("router") or "")
        if act == "added":
            etype, status, sev = "network_up", "up", "info"
            msg = f"Prefix advertised: {prefix} ({p.get('kind', 'prefix')}) via {router}"
        elif act == "removed":
            etype, status, sev = "network_down", "down", "warning"
            msg = f"Prefix withdrawn: {prefix} ({p.get('kind', 'prefix')}) from {router}"
        else:
            etype, status, sev = "network_cost_changed", "changed", "info"
            msg = f"Prefix cost changed: {prefix} via {router} ({p.get('old_metric')} -> {p.get('new_metric')})"
        add(
            etype,
            "network",
            status,
            sev,
            prefix,
            router,
            str(p.get("area") or ""),
            msg,
            dict(p),
        )

    for f in getattr(diff, "changed_node_flags", []) or ():
        nid = str(f.get("id") or "")
        attr = str(f.get("attribute") or "")
        new_val = f.get("new")
        sev = "warning" if (attr == "max_metric" and new_val) else "info"
        area = next(iter(f.get("areas") or ()), "")
        add(
            "node_flag_changed",
            "node",
            "changed",
            sev,
            nid,
            nid,
            str(area),
            f"Node flag changed on {nid}: {attr} {f.get('old')} -> {new_val}",
            dict(f),
        )

    for t in getattr(diff, "changed_te", []) or ():
        src = str(t.get("source") or "")
        dst = str(t.get("target") or "")
        changed_fields = ", ".join(sorted((t.get("changes") or {}).keys()))
        add(
            "te_changed",
            "temetric",
            "changed",
            "info",
            dst,
            src,
            str(t.get("area") or ""),
            f"TE attributes changed on {src} -> {dst}: {changed_fields}",
            dict(t),
        )

    prev_map = {_finding_key(f): f for f in prev_findings or ()}
    curr_map = {_finding_key(f): f for f in diff.findings or ()}

    for key, f in curr_map.items():
        if key not in prev_map:
            add(
                "finding_raised",
                "finding",
                "raised",
                str(f.get("severity") or "info"),
                str(f.get("subject") or ""),
                str(f.get("router") or "topology"),
                "",
                str(f.get("message") or f.get("kind") or "Finding raised"),
                dict(f),
            )

    for key, f in prev_map.items():
        if key not in curr_map:
            add(
                "finding_resolved",
                "finding",
                "resolved",
                "info",
                str(f.get("subject") or ""),
                str(f.get("router") or "topology"),
                "",
                f"Resolved: {f.get('message') or f.get('kind')}",
                dict(f),
            )

    _ = graph  # signature kept for enrichment hooks
    return events
