"""Prometheus text exposition v0.0.4 formatter for OSPF TopoViz."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import networkx as nx

from src.graph_engine import HistoryStore


def _esc(val: str) -> str:
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_prometheus_metrics(
    graph: nx.DiGraph | None,
    history: HistoryStore | None,
    poll_snapshot: dict[str, Any] | None = None,
) -> str:
    """Render bounded-cardinality Prometheus metrics from current graph, SQLite store, and poll state."""
    lines: list[str] = []

    router_count = 0
    network_count = 0
    link_count = 0
    last_ts = 0.0
    if graph is not None:
        router_count = sum(
            1 for _, d in graph.nodes(data=True) if d.get("type") == "router"
        )
        network_count = graph.number_of_nodes() - router_count
        link_count = graph.number_of_edges()
        gen_ts = graph.graph.get("generated_at") or graph.graph.get("parsed_at")
        if isinstance(gen_ts, str):
            try:
                last_ts = datetime.fromisoformat(gen_ts.replace("Z", "+00:00")).timestamp()
            except ValueError:
                last_ts = 0.0

    lines.extend(
        [
            "# HELP ospf_topoviz_nodes Number of nodes in the current OSPF baseline topology.",
            "# TYPE ospf_topoviz_nodes gauge",
            f'ospf_topoviz_nodes{{type="router"}} {router_count}',
            f'ospf_topoviz_nodes{{type="network"}} {network_count}',
            "# HELP ospf_topoviz_links Number of directed links in the current OSPF baseline topology.",
            "# TYPE ospf_topoviz_links gauge",
            f"ospf_topoviz_links {link_count}",
        ]
    )

    finding_counts = {"critical": 0, "warning": 0, "info": 0}
    runs_total = 0
    event_totals: dict[tuple[str, str], int] = {}
    if history is not None:
        runs_total = history.count()
        latest = history.list_runs(1)
        if latest:
            for sev, n in (latest[0].get("finding_counts") or {}).items():
                finding_counts[sev] = finding_counts.get(sev, 0) + int(n)
        rows = history._select(
            "SELECT event_name, object_status, COUNT(*) AS n FROM events GROUP BY event_name, object_status"
        )
        for row in rows:
            event_totals[(str(row["event_name"]), str(row["object_status"]))] = int(
                row["n"]
            )

    lines.append(
        "# HELP ospf_topoviz_findings Active findings by severity on the latest accepted run."
    )
    lines.append("# TYPE ospf_topoviz_findings gauge")
    for sev in ("critical", "warning", "info"):
        lines.append(
            f'ospf_topoviz_findings{{severity="{_esc(sev)}"}} {finding_counts.get(sev, 0)}'
        )

    lines.append(
        "# HELP ospf_topoviz_events_total Cumulative recorded topology events grouped by name and status."
    )
    lines.append("# TYPE ospf_topoviz_events_total counter")
    for (ename, estatus), cnt in sorted(event_totals.items()):
        lines.append(
            f'ospf_topoviz_events_total{{event_name="{_esc(ename)}",status="{_esc(estatus)}"}} {cnt}'
        )

    snap = poll_snapshot or {}
    running = 1 if snap.get("running") else 0
    lines.extend(
        [
            "# HELP ospf_topoviz_history_runs_total Total accepted topology runs recorded in history.db.",
            "# TYPE ospf_topoviz_history_runs_total counter",
            f"ospf_topoviz_history_runs_total {runs_total}",
            "# HELP ospf_topoviz_last_poll_timestamp_seconds Unix timestamp of the current baseline topology.",
            "# TYPE ospf_topoviz_last_poll_timestamp_seconds gauge",
            f"ospf_topoviz_last_poll_timestamp_seconds {int(last_ts)}",
            "# HELP ospf_topoviz_poll_running Whether a poll is currently running (1 or 0).",
            "# TYPE ospf_topoviz_poll_running gauge",
            f"ospf_topoviz_poll_running {running}",
        ]
    )
    return "\n".join(lines) + "\n"
