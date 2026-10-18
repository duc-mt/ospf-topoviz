"""Console result table rendering for OSPF TopoViz.

Provides modern Unicode box-drawing tables with rounded corners,
colorized status badges, and aligned metrics -- consistent with
netconfig and netbackup.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap
from collections.abc import Sequence
from itertools import pairwise
from typing import Any

# ANSI escape codes
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"


def is_color_enabled() -> bool:
    """Return True if colored output should be used."""
    if os.environ.get("NO_COLOR", ""):
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def colorize(text: str, color_code: str) -> str:
    """Wrap text in ANSI color code if colors are enabled."""
    if not is_color_enabled() or not color_code:
        return text
    return f"{color_code}{text}{ANSI_RESET}"


def _cell_len(text: str) -> int:
    """Calculate visible character length (ignoring ANSI escape codes)."""
    in_escape = False
    count = 0
    for ch in text:
        if ch == "\033":
            in_escape = True
        elif in_escape:
            if ch == "m":
                in_escape = False
        else:
            count += 1
    return count


def render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    alignments: Sequence[str] | None = None,
    colors: Sequence[Sequence[str | None]] | None = None,
    max_col_widths: Sequence[int | None] | None = None,
) -> str:
    """Render a modern grid table with rounded corners, supporting wrapped multi-line cells.

    Args:
        headers: Column titles.
        rows: 2D matrix of cell strings.
        alignments: Optional list of "left" or "right" per column.
        colors: Optional 2D matrix of ANSI colors per cell.
        max_col_widths: Optional max visible character width per column.
    """
    num_cols = len(headers)
    if num_cols == 0:
        return ""

    if alignments is None:
        alignments = ["left"] * num_cols

    widths = [_cell_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < num_cols:
                for line in str(cell).split("\n"):
                    widths[i] = max(widths[i], _cell_len(line))

    # Auto-wrap the last column to fit terminal width if table exceeds it
    if max_col_widths is None and num_cols > 0:
        term_cols = shutil.get_terminal_size((0, 0)).columns
        overhead = 3 * num_cols + 1
        total_w = sum(widths) + overhead
        if term_cols and total_w > term_cols:
            non_last_sum = sum(widths[:-1]) + overhead
            avail_last = term_cols - non_last_sum
            target_last = max(avail_last, _cell_len(headers[-1]), 20)
            if target_last < widths[-1]:
                max_col_widths = [None] * (num_cols - 1) + [target_last]

    if max_col_widths:
        for i, max_w in enumerate(max_col_widths):
            if max_w is not None and i < num_cols:
                widths[i] = min(widths[i], max(max_w, _cell_len(headers[i])))

    def border(left: str, mid: str, right: str) -> str:
        parts = ["─" * (w + 2) for w in widths]
        return left + mid.join(parts) + right

    lines = []
    # Top border
    lines.append(border("╭", "┬", "╮"))

    # Header row
    hdr_cells = []
    for i, h in enumerate(headers):
        pad_len = widths[i] - _cell_len(h)
        if alignments[i] == "right":
            cell_txt = " " * pad_len + h
        else:
            cell_txt = h + " " * pad_len
        hdr_cells.append(f" {cell_txt} ")
    lines.append("│" + "│".join(hdr_cells) + "│")

    # Header separator
    lines.append(border("├", "┼", "┤"))

    # Data rows (with multi-line cell wrapping support)
    for r_idx, row in enumerate(rows):
        col_lines = []
        for c_idx in range(num_cols):
            cell_val = str(row[c_idx]) if c_idx < len(row) else ""
            target_w = widths[c_idx]
            sublines = []
            for raw_line in cell_val.split("\n"):
                wrapped = textwrap.wrap(raw_line, width=target_w, break_long_words=True)
                sublines.extend(wrapped if wrapped else [""])
            col_lines.append(sublines)

        row_height = max((len(cl) for cl in col_lines), default=1)
        for line_idx in range(row_height):
            row_cells = []
            for c_idx in range(num_cols):
                line_txt = (
                    col_lines[c_idx][line_idx]
                    if line_idx < len(col_lines[c_idx])
                    else ""
                )
                color = (
                    colors[r_idx][c_idx]
                    if colors and r_idx < len(colors) and c_idx < len(colors[r_idx])
                    else None
                )

                pad_len = widths[c_idx] - _cell_len(line_txt)
                if alignments[c_idx] == "right":
                    aligned_txt = " " * pad_len + line_txt
                else:
                    aligned_txt = line_txt + " " * pad_len

                if color and is_color_enabled():
                    aligned_txt = f"{color}{aligned_txt}{ANSI_RESET}"

                row_cells.append(f" {aligned_txt} ")
            lines.append("│" + "│".join(row_cells) + "│")


    # Bottom border
    lines.append(border("╰", "┴", "╯"))
    return "\n".join(lines)


_AREA_TAG = re.compile(r"^area\s*(\d+)$", re.IGNORECASE)


def seed_role(tags: Sequence[str]) -> str:
    """Turn a seed's tags into the ROLE column: ``["Area0", "Core"]`` -> ``Area 0 Core``."""
    words = []
    for tag in tags or ():
        m = _AREA_TAG.match(str(tag).strip())
        words.append(f"Area {m.group(1)}" if m else str(tag))
    return " ".join(words) or "-"


def _seed_status_cell(status: str) -> tuple[str, str]:
    """``(text, color)`` for a seed status, using the same badges as the other tables."""
    if status == "SUCCEEDED":
        return "✔ SUCCEEDED", ANSI_GREEN
    if status == "SKIPPED":
        return "○ SKIPPED", ANSI_DIM
    return f"✖ {status}", ANSI_RED


def render_seed_table(seeds: Sequence[Any]) -> str:
    """Seed Health table: one row per seed router and how its poll went.

    Args:
        seeds: ``SeedResult``-like objects (``host``, ``device_type``, ``status``, ``duration``,
            ``lsas``, ``neighbors``, ``tags``). A skipped seed (fallback mode, never needed) shows dashes.
    """
    headers = ["SEED ROUTER", "PLATFORM", "STATUS", "DURATION", "LSAS / NBRS", "ROLE"]
    alignments = ["left", "left", "left", "right", "left", "left"]
    rows, colors = [], []
    for seed in seeds:
        status_text, status_color = _seed_status_cell(seed.status)
        skipped = seed.status == "SKIPPED"
        duration = "-" if skipped else f"{seed.duration:.1f}s"
        counts = "-" if skipped else f"{seed.lsas} / {seed.neighbors} nbrs"
        rows.append(
            [
                seed.host,
                seed.device_type,
                status_text,
                duration,
                counts,
                seed_role(seed.tags),
            ]
        )
        colors.append([None, None, status_color, None, None, None])
    return render_table(headers, rows, alignments, colors)


def render_topology_summary_table(graph, diff) -> str:
    """Build overview comparison table between baseline and current topology."""
    headers = ["COMPONENT", "BASELINE", "CURRENT", "DELTA", "STATUS"]
    alignments = ["left", "right", "right", "left", "left"]

    # Count nodes by type in current graph
    current_routers = sum(
        1 for _, d in graph.nodes(data=True) if d.get("type") == "router"
    )
    current_networks = sum(
        1 for _, d in graph.nodes(data=True) if d.get("type") == "network"
    )
    current_edges = graph.number_of_edges()

    if not diff.baseline_available:
        # First run (no baseline available)
        rows = [
            [
                "Router Nodes",
                "-",
                str(current_routers),
                f"+{current_routers} nodes",
                "✔ INITIALIZED",
            ],
            [
                "Transit Networks",
                "-",
                str(current_networks),
                f"+{current_networks} nets",
                "✔ INITIALIZED",
            ],
            [
                "Directed Links",
                "-",
                str(current_edges),
                f"+{current_edges} links",
                "✔ INITIALIZED",
            ],
        ]
        colors = [
            [None, None, None, None, ANSI_GREEN],
            [None, None, None, None, ANSI_GREEN],
            [None, None, None, None, ANSI_GREEN],
        ]
        return render_table(headers, rows, alignments, colors)

    # With baseline diff
    added_r = sum(1 for n in diff.added_nodes if n.get("type") == "router")
    removed_r = sum(1 for n in diff.removed_nodes if n.get("type") == "router")
    delta_r = added_r - removed_r
    base_r = current_routers - delta_r

    added_n = sum(1 for n in diff.added_nodes if n.get("type") == "network")
    removed_n = sum(1 for n in diff.removed_nodes if n.get("type") == "network")
    delta_n = added_n - removed_n
    base_n = current_networks - delta_n

    delta_e = len(diff.added_edges) - len(diff.removed_edges)
    base_e = current_edges - delta_e

    def fmt_delta(delta: int, unit: str) -> tuple[str, str, str]:
        if delta == 0:
            return "0 unchanged", "✔ UNCHANGED", ANSI_GREEN
        elif delta > 0:
            return f"+{delta} {unit}", "✚ EXPANDED", ANSI_CYAN
        else:
            return f"{delta} {unit}", "✖ DEGRADED", ANSI_RED

    r_delta_str, r_status, r_color = fmt_delta(delta_r, "routers")
    n_delta_str, n_status, n_color = fmt_delta(delta_n, "networks")
    e_delta_str, e_status, e_color = fmt_delta(delta_e, "links")

    num_metrics = len(diff.changed_metrics)
    if num_metrics == 0:
        m_delta_str, m_status, m_color = "0 unchanged", "✔ UNCHANGED", ANSI_GREEN
    else:
        m_delta_str, m_status, m_color = (
            f"{num_metrics} modified",
            "⚠ MODIFIED",
            ANSI_YELLOW,
        )

    rows = [
        ["Router Nodes", str(base_r), str(current_routers), r_delta_str, r_status],
        ["Transit Networks", str(base_n), str(current_networks), n_delta_str, n_status],
        ["Directed Links", str(base_e), str(current_edges), e_delta_str, e_status],
        ["Metric Changes", "-", str(num_metrics), m_delta_str, m_status],
    ]
    colors = [
        [None, None, None, None, r_color],
        [None, None, None, None, n_color],
        [None, None, None, None, e_color],
        [None, None, None, None, m_color],
    ]
    return render_table(headers, rows, alignments, colors)


def render_diff_table(diff, max_rows: int = 12) -> str | None:
    """Render top changes in added/removed links and nodes as a formatted table."""
    if not diff.has_changes:
        return None

    headers = ["ACTION", "ELEMENT", "DETAILS", "STATUS"]
    alignments = ["left", "left", "left", "left"]
    rows = []
    colors = []

    # Added nodes
    for n in diff.added_nodes:
        rows.append(
            [
                "✚ ADD NODE",
                n.get("label", "?"),
                f"type: {n.get('type', '?')}",
                "✚ ADDED",
            ]
        )
        colors.append([ANSI_CYAN, None, None, ANSI_CYAN])

    # Removed nodes
    for n in diff.removed_nodes:
        rows.append(
            [
                "✖ REM NODE",
                n.get("label", "?"),
                f"type: {n.get('type', '?')}",
                "✖ REMOVED",
            ]
        )
        colors.append([ANSI_RED, None, None, ANSI_RED])

    # Added edges
    for e in diff.added_edges:
        label = f"{e.get('source_label', '?')} -> {e.get('target_label', '?')}"
        detail = f"metric {e.get('metric', '?')}, {e.get('link_type', '?')}"
        rows.append(["✚ ADD LINK", label, detail, "✚ ADDED"])
        colors.append([ANSI_CYAN, None, None, ANSI_CYAN])

    # Removed edges
    for e in diff.removed_edges:
        label = f"{e.get('source_label', '?')} -> {e.get('target_label', '?')}"
        detail = f"metric {e.get('metric', '?')}, {e.get('link_type', '?')}"
        rows.append(["✖ REM LINK", label, detail, "✖ REMOVED"])
        colors.append([ANSI_RED, None, None, ANSI_RED])

    # Changed metrics
    for e in diff.changed_metrics:
        label = f"{e.get('source_label', '?')} -> {e.get('target_label', '?')}"
        detail = f"metric: {e.get('old_metric', '?')} -> {e.get('new_metric', '?')}"
        rows.append(["➜ METRIC", label, detail, "⚠ CHANGED"])
        colors.append([ANSI_YELLOW, None, None, ANSI_YELLOW])

    total_changes = len(rows)
    if total_changes > max_rows:
        overflow = total_changes - max_rows
        rows = rows[:max_rows]
        colors = colors[:max_rows]
        rows.append(
            [
                "...",
                f"+{overflow} more change(s)",
                "see topology.png for diagram",
                "➜ TRUNCATED",
            ]
        )
        colors.append([ANSI_DIM, ANSI_DIM, ANSI_DIM, ANSI_DIM])

    return render_table(headers, rows, alignments, colors)


def render_quality_table(
    graph, skip_adjacency: set[tuple[str, str]] | None = None
) -> str | None:
    """Render adjacency issues and data quality as a table if any problems exist.

    ``skip_adjacency`` holds ``(router, neighbor)`` pairs another table already reports (with more context).
    """
    meta = graph.graph
    stale = meta.get("stale_nodes") or []
    one_way = meta.get("one_way_links") or 0
    issues = [
        i
        for i in (meta.get("adjacency_issues") or [])
        if (i.get("router"), i.get("neighbor")) not in (skip_adjacency or set())
    ]

    if not (stale or one_way or issues):
        return None

    headers = ["SOURCE", "TARGET / NEIGHBOR", "INTERFACE", "STATE", "PROBLEM"]
    alignments = ["left", "left", "left", "left", "left"]
    rows = []
    colors = []

    for issue in issues:
        where = issue.get("interface") or "-"
        in_lsdb = " (not in LSDB)" if not issue.get("in_lsdb") else ""
        state_txt = f"{issue.get('state', '?')}{in_lsdb}"
        rows.append(
            [
                issue.get("source", "?"),
                issue.get("neighbor", "?"),
                where,
                state_txt,
                "✖ ADJACENCY",
            ]
        )
        colors.append([None, None, None, None, ANSI_RED])

    for node in stale:
        minutes = graph.nodes[node].get("lsa_age", 0) // 60
        rows.append([node, "-", "-", f"{minutes}m old", "⏱ STALE LSA"])
        colors.append([None, None, None, None, ANSI_YELLOW])

    if one_way:
        for u, v, attrs in graph.edges(data=True):
            if attrs.get("link_state") == "one-way":
                rows.append([u, v, "-", "one-way", "⚠ UNVERIFIED"])
                colors.append([None, None, None, None, ANSI_YELLOW])

    return render_table(headers, rows, alignments, colors)


# ------------------------------------------------------- cross-check tables
_SEVERITY_CELL = {
    "critical": ("✖ CRITICAL", ANSI_RED),
    "warning": ("⚠ WARNING", ANSI_YELLOW),
    "info": ("ℹ INFO", ANSI_DIM),
}
_NEIGHBOR_LABEL = {
    "ADJ_NOT_FULL": "STATE MISMATCH",
    "ADJ_MISSING": "MISSING NEIGHBOR",
    "NBR_NOT_IN_LSDB": "NOT IN LSDB",
    "NBR_STATE_CHANGE": "FLAP",
    "NBR_LOST": "FLAP (LOST)",
    "NBR_NEW": "NEW NEIGHBOR",
}
_ROUTE_LABEL = {
    "ROUTE_MISSING": "BLACKHOLE",
    "NEXTHOP_DOWN": "BLACKHOLE",
    "ROUTE_STALE": "STALE ROUTE",
    "RIB_EMPTY": "RIB EMPTY",
    "ROUTE_OVERRIDDEN": "OVERRIDDEN",
    "COST_MISMATCH": "SUBOPTIMAL",
    "NEXTHOP_MISMATCH": "SUBOPTIMAL",
    "ECMP_MISSING": "ECMP LOSS",
}


def _clip(text: str, width: int = 78) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


#: Informational findings are listed, but only this many: they are the "valid, just not ideal" kind and
#: can be numerous (after a reconvergence, say). The rest is counted under the table.
MAX_INFO_ROWS = 8


def _findings_table(
    findings: Sequence[dict], labels: dict[str, str], subject_header: str
) -> str:
    headers = ["SEVERITY", "ROUTER", subject_header, "KIND", "DETAIL"]
    rows, colors = [], []
    info_left = [f for f in findings if f["severity"] == "info"][MAX_INFO_ROWS:]
    hidden = {id(f) for f in info_left}
    shown = [f for f in findings if id(f) not in hidden]
    for f in shown:
        text, color = _SEVERITY_CELL.get(f["severity"], (f["severity"].upper(), None))
        rows.append(
            [
                text,
                f["router"],
                f["subject"],
                labels.get(f["kind"], f["kind"]),
                f["message"],
            ]
        )

        colors.append([color, None, None, color, None])
    table = render_table(headers, rows, ["left"] * 5, colors)
    if info_left:
        table += "\n" + colorize(
            f"  ℹ {len(info_left)} more informational finding(s) not listed (see the explorer)",
            ANSI_DIM,
        )
    hints = []
    for f in shown:
        if f["severity"] != "info" and f.get("hint") and f["hint"] not in hints:
            hints.append(f["hint"])
    if hints:
        table += "\n" + "\n".join(f"  • {_clip(h, 160)}" for h in hints[:6])
    return table


def render_neighbor_findings_table(diff) -> str | None:
    """Neighbor Flap / State Mismatch: LSDB adjacencies the neighbour table disagrees with, and changes since last run."""
    findings = [f for f in getattr(diff, "findings", []) if f["category"] == "neighbor"]
    return _findings_table(findings, _NEIGHBOR_LABEL, "NEIGHBOR") if findings else None


def render_route_findings_table(diff) -> str | None:
    """Routing Blackhole / Suboptimal Routing: where the routing table departs from what the LSDB predicts."""
    findings = [f for f in getattr(diff, "findings", []) if f["category"] == "route"]
    return _findings_table(findings, _ROUTE_LABEL, "PREFIX") if findings else None


def render_rib_check_table(diff) -> str | None:
    """How much of each polled router's OSPF routing table could be checked against the LSDB."""
    checks = getattr(diff, "rib_checks", [])
    if not checks:
        return None
    rows, colors = [], []
    for c in checks:
        issues = (
            c["expected"] - c["ok"]
        )  # prefixes with a finding: missing from the RIB or deviating from SPF
        rows.append(
            [
                c["router"],
                str(c["routes"]),
                str(c["expected"]),
                str(c["ok"]),
                str(issues),
                str(c["unverified"]),
            ]
        )
        colors.append(
            [
                None,
                None,
                None,
                ANSI_GREEN if c["ok"] else None,
                ANSI_RED if issues else None,
                ANSI_DIM,
            ]
        )
    return render_table(
        [
            "ROUTER",
            "RIB ROUTES",
            "EXPECTED (SPF)",
            "CONSISTENT",
            "DEVIATING",
            "UNVERIFIED",
        ],
        rows,
        ["left", "right", "right", "right", "right", "right"],
        colors,
    )


def finding_counts(diff) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in getattr(diff, "findings", []):
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def render_area_coverage(diff) -> str | None:
    """Area Coverage Summary: which OSPF areas were polled and which have no seed.

    Reports per *area*, not per router: a missing area is one line plus where to look for a seed (the
    ABR that borders it, the neighbour inside it). Returns ``None`` when there is nothing to say - a
    single area that was read in full - so callers can print the result only if it is not ``None``.
    """
    cov = getattr(diff, "area_coverage", None)
    if not cov:
        return None
    polled = cov.get("polled") or []
    missing = cov.get("missing") or []
    if missing:
        head = colorize("[WARN] INCOMPLETE AREA COVERAGE:", ANSI_YELLOW)
    elif len(polled) > 1:
        head = colorize("[ OK ] AREA COVERAGE:", ANSI_GREEN)
    else:
        return None
    lines = [head]
    for entry in polled:
        seeds = entry.get("seeds") or []
        via = (
            f"polled via seed{'s' if len(seeds) > 1 else ''} {', '.join(seeds)}"
            if seeds
            else "polled"
        )
        lines.append(
            f"- Area {entry['area']}: " + colorize("OK", ANSI_GREEN) + f" ({via})"
        )
    for miss in missing:
        area = miss.get("area")
        label = f"Area {area}" if area else "Area (ID not visible)"
        lines.append(f"- {label}: " + colorize("MISSING SEED!", ANSI_RED))
        lines += [f"  -> {_clip(ev, 150)}" for ev in (miss.get("evidence") or [])[:3]]
        cands = miss.get("candidates") or []
        e_g = f" (e.g. {' or '.join(cands[:2])} or an internal router)" if cands else ""
        where = f"Area {area}" if area else "the area behind that ABR"
        lines.append(
            f"  -> Action: Add at least ONE router in {where}{e_g} to settings.yaml "
            "to render this area's full topology."
        )
    return "\n".join(lines)


def _area_badge(diff) -> str:
    """``│ ⚠ Areas: 1 unpolled`` when some OSPF area has no seed, else nothing."""
    missing = (getattr(diff, "area_coverage", None) or {}).get("missing") or []
    if not missing:
        return ""
    return "  │  " + colorize(f"⚠ Areas: {len(missing)} unpolled", ANSI_YELLOW)


def render_trace(trace, graph) -> str:
    """Prefix path lookup: the router's RIB entry, then the LSDB shortest path hop by hop."""
    from src.graph_engine import display_name

    def name(node: str) -> str:
        return display_name(node, graph.nodes[node]) if node in graph else node

    lines = [
        f" Query     : {trace.query}   from router {trace.source}",
        f" Prefix    : {trace.prefix or '-'}",
    ]
    if trace.rib:
        r = trace.rib
        hops = (
            ", ".join(
                f"{h['ip'] or 'connected'}"
                + (f" via {h['interface']}" if h["interface"] else "")
                + (f" ({h['router']})" if h["router"] else "")
                for h in r["next_hops"]
            )
            or "-"
        )
        lines.append(
            f" RIB       : {r['route_type']}, cost {r['metric'] if r['metric'] is not None else '?'}"
            + ("" if r["active"] else " (not active)")
            + f" -> {hops}"
        )
    else:
        lines.append(" RIB       : no matching OSPF route")
    if trace.origins:
        lines.append(
            " Origin    : "
            + ", ".join(
                f"{name(o['node'])} ({o['kind']}, area {o['area']})"
                for o in trace.origins
            )
        )
    lines.append(
        f" SPF cost  : {trace.spf_cost if trace.spf_cost is not None else '-'}"
    )
    ok = trace.verdict == "RIB and LSDB agree"
    lines.append(
        " Verdict   : "
        + colorize(
            ("✔ " if ok else "⚠ ") + (trace.verdict or "-"),
            ANSI_GREEN if ok else ANSI_YELLOW,
        )
    )
    for note in trace.notes:
        lines.append(f" Note      : {note}")
    out = "\n".join(lines)

    for number, path in enumerate(trace.paths[:4], start=1):
        rows, total = [["0", name(path[0]), "-", "-", "0"]], 0
        for step, (u, v) in enumerate(pairwise(path), start=1):
            edge = graph.edges[u, v]
            cost = edge.get("metric", 0)
            total += cost
            link = (
                edge.get("interface")
                or edge.get("interface_address")
                or ("segment" if v.startswith("net-") else "-")
            )
            rows.append([str(step), name(v), str(link), str(cost), str(total)])
        if trace.origins and trace.origins[0]["kind"] == "stub":
            stub = next((o for o in trace.origins if o["node"] == path[-1]), None)
            if stub:
                total += stub["metric"]
                rows.append(
                    [
                        str(len(path)),
                        trace.prefix or "-",
                        "stub",
                        str(stub["metric"]),
                        str(total),
                    ]
                )
        out += (
            f"\n\n Path {number} of {min(len(trace.paths), 4)}"
            + (" (equal cost)" if len(trace.paths) > 1 else "")
            + ":\n"
        )
        out += render_table(
            ["HOP", "NODE", "LINK (OUT INTERFACE)", "COST", "TOTAL"],
            rows,
            ["right", "left", "left", "right", "right"],
        )
    return out


def _findings_badge(diff) -> str:
    """``│ Findings: 1 critical, 2 warning`` when the cross-checks found anything, else nothing."""
    counts = finding_counts(diff)
    shown = [
        f"{counts[sev]} {sev}" for sev in ("critical", "warning") if counts.get(sev)
    ]
    if not shown:
        return ""
    return "  │  " + colorize(
        "Findings: " + ", ".join(shown),
        ANSI_RED if counts.get("critical") else ANSI_YELLOW,
    )


def render_summary_banner(raw, graph, diff, seeds: Sequence[Any] | None = None) -> str:
    """Render consistent bottom summary banner with badge counts.

    With ``seeds`` (a live multi-seed run) the first badge reports how many seed routers passed,
    ``✔ Seeds: 2/3 Passed``, in place of the topology verdict; a suspect run is still called out at the
    end of the line. Without it (``--replay``) the banner is the plain topology verdict.
    """
    num_nodes = graph.number_of_nodes()
    num_edges = graph.number_of_edges()

    total_diffs = (
        len(diff.added_nodes)
        + len(diff.removed_nodes)
        + len(diff.added_edges)
        + len(diff.removed_edges)
        + len(diff.changed_metrics)
    )
    diff_badge = f"Diffs: {total_diffs}"
    if total_diffs > 0:
        diff_badge = colorize(
            diff_badge, ANSI_YELLOW if not diff.suspect_reasons else ANSI_RED
        )
    else:
        diff_badge = colorize(diff_badge, ANSI_GREEN)

    if seeds is None:
        if diff.suspect_reasons:
            status_badge = colorize("✖ Suspect Run", ANSI_RED)
        elif diff.has_changes:
            status_badge = colorize("⚠ Changes Detected", ANSI_YELLOW)
        else:
            status_badge = colorize("✔ Stable Topology", ANSI_GREEN)
        return (
            f"  {status_badge}  │  {diff_badge}  │  Nodes: {num_nodes}  │  Links: {num_edges}"
            + _area_badge(diff)
            + _findings_badge(diff)
        )

    polled = [
        s for s in seeds if s.status != "SKIPPED"
    ]  # a seed that was never needed is neither pass nor fail
    passed = sum(1 for s in polled if s.status == "SUCCEEDED")
    if passed == len(polled):
        seed_badge = colorize(f"✔ Seeds: {passed}/{len(polled)} Passed", ANSI_GREEN)
    elif passed:
        seed_badge = colorize(f"⚠ Seeds: {passed}/{len(polled)} Passed", ANSI_YELLOW)
    else:
        seed_badge = colorize(f"✖ Seeds: {passed}/{len(polled)} Passed", ANSI_RED)
    line = (
        f"  {seed_badge}  │  {diff_badge}  │  Nodes: {num_nodes}  │  Links: {num_edges}"
    )
    if diff.suspect_reasons:
        line += "  │  " + colorize("✖ Suspect Run", ANSI_RED)
    return line + _area_badge(diff) + _findings_badge(diff)
