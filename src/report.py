"""Console result table rendering for OSPF TopoViz.

Provides modern Unicode box-drawing tables with rounded corners,
colorized status badges, and aligned metrics -- consistent with
netconfig and netbackup.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Sequence

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
) -> str:
    """Render a modern grid table with rounded corners.

    Args:
        headers: Column titles.
        rows: 2D matrix of cell strings.
        alignments: Optional list of "left" or "right" per column.
        colors: Optional 2D matrix of ANSI colors per cell.
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
                widths[i] = max(widths[i], _cell_len(str(cell)))

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

    # Data rows
    for r_idx, row in enumerate(rows):
        row_cells = []
        for c_idx in range(num_cols):
            cell_val = str(row[c_idx]) if c_idx < len(row) else ""
            color = colors[r_idx][c_idx] if colors and r_idx < len(colors) and c_idx < len(colors[r_idx]) else None

            pad_len = widths[c_idx] - _cell_len(cell_val)
            if alignments[c_idx] == "right":
                aligned_txt = " " * pad_len + cell_val
            else:
                aligned_txt = cell_val + " " * pad_len

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
        rows.append([seed.host, seed.device_type, status_text, duration, counts, seed_role(seed.tags)])
        colors.append([None, None, status_color, None, None, None])
    return render_table(headers, rows, alignments, colors)


def render_topology_summary_table(graph, diff) -> str:
    """Build overview comparison table between baseline and current topology."""
    headers = ["COMPONENT", "BASELINE", "CURRENT", "DELTA", "STATUS"]
    alignments = ["left", "right", "right", "left", "left"]

    # Count nodes by type in current graph
    current_routers = sum(1 for _, d in graph.nodes(data=True) if d.get("type") == "router")
    current_networks = sum(1 for _, d in graph.nodes(data=True) if d.get("type") == "network")
    current_edges = graph.number_of_edges()

    if not diff.baseline_available:
        # First run (no baseline available)
        rows = [
            ["Router Nodes", "-", str(current_routers), f"+{current_routers} nodes", "✔ INITIALIZED"],
            ["Transit Networks", "-", str(current_networks), f"+{current_networks} nets", "✔ INITIALIZED"],
            ["Directed Links", "-", str(current_edges), f"+{current_edges} links", "✔ INITIALIZED"],
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
        m_delta_str, m_status, m_color = f"{num_metrics} modified", "⚠ MODIFIED", ANSI_YELLOW

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
        rows.append(["✚ ADD NODE", n.get("label", "?"), f"type: {n.get('type', '?')}", "✚ ADDED"])
        colors.append([ANSI_CYAN, None, None, ANSI_CYAN])

    # Removed nodes
    for n in diff.removed_nodes:
        rows.append(["✖ REM NODE", n.get("label", "?"), f"type: {n.get('type', '?')}", "✖ REMOVED"])
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
        rows.append(["...", f"+{overflow} more change(s)", "see topology.png for diagram", "➜ TRUNCATED"])
        colors.append([ANSI_DIM, ANSI_DIM, ANSI_DIM, ANSI_DIM])

    return render_table(headers, rows, alignments, colors)


def render_quality_table(graph) -> str | None:
    """Render adjacency issues and data quality as a table if any problems exist."""
    meta = graph.graph
    stale = meta.get("stale_nodes") or []
    one_way = meta.get("one_way_links") or 0
    issues = meta.get("adjacency_issues") or []

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
        rows.append([issue.get("source", "?"), issue.get("neighbor", "?"), where, state_txt, "✖ ADJACENCY"])
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


def render_summary_banner(raw, graph, diff, seeds: Sequence[Any] | None = None) -> str:
    """Render consistent bottom summary banner with badge counts.

    With ``seeds`` (a live multi-seed run) the first badge reports how many seed routers passed,
    ``✔ Seeds: 2/3 Passed``, in place of the topology verdict; a suspect run is still called out at the
    end of the line. Without it (``--replay``) the banner is the plain topology verdict.
    """
    num_nodes = graph.number_of_nodes()
    num_edges = graph.number_of_edges()

    total_diffs = len(diff.added_nodes) + len(diff.removed_nodes) + len(diff.added_edges) + len(diff.removed_edges) + len(diff.changed_metrics)
    diff_badge = f"Diffs: {total_diffs}"
    if total_diffs > 0:
        diff_badge = colorize(diff_badge, ANSI_YELLOW if not diff.suspect_reasons else ANSI_RED)
    else:
        diff_badge = colorize(diff_badge, ANSI_GREEN)

    if seeds is None:
        if diff.suspect_reasons:
            status_badge = colorize("✖ Suspect Run", ANSI_RED)
        elif diff.has_changes:
            status_badge = colorize("⚠ Changes Detected", ANSI_YELLOW)
        else:
            status_badge = colorize("✔ Stable Topology", ANSI_GREEN)
        return f"  {status_badge}  │  {diff_badge}  │  Nodes: {num_nodes}  │  Links: {num_edges}"

    polled = [s for s in seeds if s.status != "SKIPPED"]  # a seed that was never needed is neither pass nor fail
    passed = sum(1 for s in polled if s.status == "SUCCEEDED")
    if passed == len(polled):
        seed_badge = colorize(f"✔ Seeds: {passed}/{len(polled)} Passed", ANSI_GREEN)
    elif passed:
        seed_badge = colorize(f"⚠ Seeds: {passed}/{len(polled)} Passed", ANSI_YELLOW)
    else:
        seed_badge = colorize(f"✖ Seeds: {passed}/{len(polled)} Passed", ANSI_RED)
    line = f"  {seed_badge}  │  {diff_badge}  │  Nodes: {num_nodes}  │  Links: {num_edges}"
    if diff.suspect_reasons:
        line += "  │  " + colorize("✖ Suspect Run", ANSI_RED)
    return line
