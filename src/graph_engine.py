"""
==============================================================================
Module Name:   graph_engine.py
Description:   Source module graph_engine.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 graph_engine.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sqlite3
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import networkx as nx

from src import TrackerError, atomic_write_text, node_sort_key
from src.correlation import CRITICAL, area_key, correlate
from src.vendors.base import SourceDetail

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


class GraphEngineError(TrackerError):
    """Raised when the graph cannot be built or its state cannot be saved."""


def display_name(node_id: str, attrs: dict[str, Any]) -> str:
    """Human-friendly node name: the router ID, or ``net <prefix>`` for transit networks."""
    if attrs.get("type") == "network":
        return f"net {attrs.get('prefix') or attrs.get('address') or node_id}"
    return str(node_id)


def graph_to_payload(graph: nx.DiGraph) -> dict[str, Any]:
    """The state-file form of a graph (``current_state.json``): schema version, metadata, nodes and edges."""
    return {
        "schema_version": SCHEMA_VERSION,
        "metadata": dict(graph.graph),
        "nodes": [
            {"id": n, **graph.nodes[n]} for n in sorted(graph.nodes, key=node_sort_key)
        ],
        "edges": [
            {"source": u, "target": v, **graph.edges[u, v]}
            for u, v in sorted(
                graph.edges,
                key=lambda e: (node_sort_key(e[0]), node_sort_key(e[1])),
            )
        ],
    }


def graph_from_payload(payload: dict[str, Any]) -> nx.DiGraph:
    """Rebuild a graph from its state-file form.

    Raises:
        ValueError: If the schema version is not the one this code reads.
        KeyError, TypeError, AttributeError: If the payload is malformed.
    """
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version {payload.get('schema_version')!r}"
        )
    graph = nx.DiGraph(**dict(payload.get("metadata") or {}))
    for node in payload["nodes"]:
        attrs = dict(node)
        graph.add_node(attrs.pop("id"), **attrs)
    for edge in payload["edges"]:
        attrs = dict(edge)
        graph.add_edge(attrs.pop("source"), attrs.pop("target"), **attrs)
    return graph


# ------------------------------------------------------------------ area views
_AREA_ID = re.compile(r"^(?:\d{1,10}|\d{1,3}(?:\.\d{1,3}){3})$")


def parse_area_id(text: Any) -> str:
    """Validate an OSPF area ID (``0``, ``1``, ``0.0.0.1``) and return it in dotted form (``0.0.0.0``).

    Raises:
        GraphEngineError: If it is neither a number nor a dotted quad.
    """
    raw = str(text).strip()
    if _AREA_ID.match(raw):
        try:
            return str(ipaddress.IPv4Address(int(raw) if raw.isdigit() else raw))
        except ValueError:
            pass
    raise GraphEngineError(
        f"{text!r} is not an OSPF area ID: use a number (0, 1) or the dotted form (0.0.0.1)"
    )


def _areas_of(attrs: dict[str, Any]) -> set[str]:
    return {area_key(a) for a in attrs.get("areas") or ()}


def filter_graph_by_area(graph: nx.DiGraph, area: str) -> nx.DiGraph:
    """The part of ``graph`` that lives in one OSPF area, for drawing a single area on its own.

    Kept: every router and transit network that belongs to the area - an area border router (ABR) is in the
    area, so it stays, marked with the other areas it borders in ``border_areas`` - and the links of that
    area between them. Links the ABRs have into other areas are left out, which is the point of the view.
    Each kept node lists only this area in ``areas``. The metadata is cut down to match (stale routers,
    one-way links, adjacency issues and flushing LSAs of the area), and ``filtered_area`` records the view.
    The input graph is not modified.

    Raises:
        GraphEngineError: If ``area`` is not an area ID, or no node of the topology is in it.
    """
    wanted = parse_area_id(area)
    members = {n for n, attrs in graph.nodes(data=True) if wanted in _areas_of(attrs)}
    if not members:
        seen = sorted(
            {a for _n, attrs in graph.nodes(data=True) for a in _areas_of(attrs)},
            key=node_sort_key,
        )
        raise GraphEngineError(
            f"Area {wanted} has no routers or networks in this topology (areas seen: {', '.join(seen) or 'none'})"
        )
    view = nx.DiGraph(**dict(graph.graph))
    for node in sorted(members, key=node_sort_key):
        attrs = dict(graph.nodes[node])
        others = sorted(_areas_of(attrs) - {wanted}, key=node_sort_key)
        attrs["areas"] = [wanted]
        if others:
            attrs["border_areas"] = others
        view.add_node(node, **attrs)
    for u, v, attrs in graph.edges(data=True):
        if u in members and v in members and area_key(attrs.get("area")) == wanted:
            view.add_edge(u, v, **attrs)

    meta = view.graph
    meta["filtered_area"] = wanted
    if "areas" in meta:
        meta["areas"] = [wanted]
    if "stale_nodes" in meta:
        meta["stale_nodes"] = [n for n in meta["stale_nodes"] or () if n in members]
    for key, state in (
        ("one_way_links", "one-way"),
        ("unverified_links", "unverified"),
    ):
        if key in meta:
            meta[key] = len(
                {
                    frozenset((u, v))
                    for u, v, a in view.edges(data=True)
                    if a.get("link_state") == state
                }
            )
    if "adjacency_issues" in meta:
        meta["adjacency_issues"] = [
            i for i in meta["adjacency_issues"] or () if i.get("router") in members
        ]
    if "flushing_lsas" in meta:
        meta["flushing_lsas"] = [
            e for e in meta["flushing_lsas"] or () if area_key(e.get("area")) == wanted
        ]
    return view


def filter_diff_by_area(
    diff: TopologyDiff, area: str, view: nx.DiGraph
) -> TopologyDiff:
    """The part of a diff that belongs to one area, to go with ``filter_graph_by_area``'s ``view``.

    Added / removed nodes are kept when they were in the area, links and metric changes when the link is
    of that area, findings and routing-table checks when the router they are about is in the view.
    """
    wanted = parse_area_id(area)
    nodes = set(view.nodes)
    return replace(
        diff,
        added_nodes=[r for r in diff.added_nodes if wanted in _areas_of(r)],
        removed_nodes=[r for r in diff.removed_nodes if wanted in _areas_of(r)],
        added_edges=[r for r in diff.added_edges if area_key(r.get("area")) == wanted],
        removed_edges=[
            r for r in diff.removed_edges if area_key(r.get("area")) == wanted
        ],
        changed_metrics=[
            r for r in diff.changed_metrics if area_key(r.get("area")) == wanted
        ],
        findings=[f for f in diff.findings if f.get("router") in nodes],
        rib_checks=[c for c in diff.rib_checks if c.get("router") in nodes],
    )


@dataclass(frozen=True)
class GuardConfig:
    """Thresholds for the partial-LSDB safety guard (``guard:`` in settings.yaml)."""

    enabled: bool = True
    #: Fraction of previously known nodes that must still be present (0.7 = at most 30% may vanish).
    min_node_retention: float = 0.7
    #: Flag runs where the graph has more disconnected pieces than the baseline.
    flag_partition: bool = True

    @classmethod
    def from_settings(cls, section: dict[str, Any] | None) -> GuardConfig:
        """Build from the ``guard`` mapping of settings.yaml (missing keys use the defaults)."""
        section = section or {}
        try:
            cfg = cls(
                enabled=bool(section.get("enabled", True)),
                min_node_retention=float(section.get("min_node_retention", 0.7)),
                flag_partition=bool(section.get("flag_partition", True)),
            )
        except (TypeError, ValueError) as exc:
            raise GraphEngineError(f"Invalid 'guard' settings: {exc}") from exc
        if not 0.0 <= cfg.min_node_retention <= 1.0:
            raise GraphEngineError("guard.min_node_retention must be between 0 and 1")
        return cfg


@dataclass(frozen=True)
class HistoryConfig:
    """Settings of the run history (``history:`` in settings.yaml)."""

    enabled: bool = True
    #: Keep at most this many runs (the oldest are dropped); 0 keeps everything.
    max_runs: int = 2000

    @classmethod
    def from_settings(cls, section: dict[str, Any] | None) -> HistoryConfig:
        """Build from the ``history`` mapping of settings.yaml (missing keys use the defaults)."""
        section = section or {}
        if not isinstance(section, dict):
            raise GraphEngineError("'history' in settings.yaml must be a mapping")
        try:
            cfg = cls(
                enabled=bool(section.get("enabled", True)),
                max_runs=int(section.get("max_runs", 2000)),
            )
        except (TypeError, ValueError) as exc:
            raise GraphEngineError(f"Invalid 'history' settings: {exc}") from exc
        if cfg.max_runs < 0:
            raise GraphEngineError(
                "history.max_runs must not be negative (0 = keep every run)"
            )
        return cfg


#: Run IDs are built from letters, digits and ``_ . -`` only, so they are safe in a URL and in SQL alike.
RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class HistoryStore:
    """Append-only history of the topology: one row per accepted run, in a SQLite file.

    Each row keeps what changed in that run (nodes, links, metrics), whether the run was flagged suspect
    and the cross-check findings, plus the complete graph as the JSON text of ``current_state.json`` -
    so any past state can be loaded again (``get_graph``) and the timeline browsed (``list_runs``).
    Rows are only ever inserted; the single exception is the retention limit ``max_runs``, which drops
    the oldest rows once there are more.

    SQLite makes every insert atomic (a transaction: it is all there or not at all, even if the process dies
    in the middle). Nothing is touched at construction: the directory and the database are created by the
    first ``record``, and reading a store that does not exist yields no runs. Every call uses its own
    connection, so one store can be shared between threads.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS runs (
            seq            INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id         TEXT    NOT NULL UNIQUE,
            timestamp      TEXT    NOT NULL,
            node_count     INTEGER NOT NULL,
            link_count     INTEGER NOT NULL,
            added_nodes    TEXT    NOT NULL,
            removed_nodes  TEXT    NOT NULL,
            added_links    TEXT    NOT NULL,
            removed_links  TEXT    NOT NULL,
            metric_changes TEXT    NOT NULL,
            is_suspect     INTEGER NOT NULL,
            findings       TEXT    NOT NULL DEFAULT '[]',
            graph_json     TEXT    NOT NULL
        )
    """
    _SUMMARY_COLUMNS = (
        "run_id, timestamp, node_count, link_count, added_nodes, removed_nodes, "
        "added_links, removed_links, metric_changes, is_suspect, findings"
    )

    def __init__(self, path: str | os.PathLike, max_runs: int = 0) -> None:
        self.path = Path(path)
        self.max_runs = max_runs

    # ------------------------------------------------------------- plumbing
    @contextmanager
    def _connect(self, create: bool = False) -> Iterator[sqlite3.Connection | None]:
        """Open the database (``None`` if it does not exist and ``create`` is False); always closes it."""
        if not create and not self.path.exists():
            yield None
            return
        try:
            if create:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=10)
        except (OSError, sqlite3.Error) as exc:
            raise GraphEngineError(
                f"Could not open the history store {self.path}: {exc}"
            ) from exc
        conn.row_factory = sqlite3.Row
        try:
            if create:
                conn.execute(self._SCHEMA)
            yield conn
        finally:
            conn.close()

    @staticmethod
    def new_run_id() -> str:
        """A sortable, unique run ID: the UTC time and a random suffix (``20261027T031500Z-1a2b3c4d``)."""
        return f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        findings = json.loads(row["findings"])
        counts: dict[str, int] = {}
        for finding in findings:
            sev = str(finding.get("severity"))
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "run_id": row["run_id"],
            "timestamp": row["timestamp"],
            "node_count": row["node_count"],
            "link_count": row["link_count"],
            "added_nodes": json.loads(row["added_nodes"]),
            "removed_nodes": json.loads(row["removed_nodes"]),
            "added_links": json.loads(row["added_links"]),
            "removed_links": json.loads(row["removed_links"]),
            "metric_changes": json.loads(row["metric_changes"]),
            "is_suspect": bool(row["is_suspect"]),
            "finding_counts": counts,
        }

    # --------------------------------------------------------------- writing
    def record(
        self,
        graph: nx.DiGraph,
        diff: TopologyDiff,
        *,
        run_id: str | None = None,
        timestamp: str | None = None,
    ) -> str:
        """Append one run and return its ID.

        ``is_suspect`` is True when the guard flagged the run (it only gets here with ``--accept-changes``).
        Links are written as ``source->target`` (the directed edges of the graph).

        Raises:
            GraphEngineError: If ``run_id`` is not a valid ID, already exists, or the database cannot be written.
        """
        run_id = run_id or self.new_run_id()
        if not RUN_ID.match(run_id):
            raise GraphEngineError(f"Invalid run ID {run_id!r}")
        stamp = timestamp or datetime.now(UTC).isoformat(timespec="seconds")

        def links(records: list[dict]) -> str:
            return json.dumps([f"{r['source']}->{r['target']}" for r in records])

        metric_changes = [
            {
                "source": r["source"],
                "target": r["target"],
                "old_metric": r.get("old_metric"),
                "new_metric": r.get("new_metric"),
            }
            for r in diff.changed_metrics
        ]
        row = (
            run_id,
            stamp,
            graph.number_of_nodes(),
            graph.number_of_edges(),
            json.dumps([r["id"] for r in diff.added_nodes]),
            json.dumps([r["id"] for r in diff.removed_nodes]),
            links(diff.added_edges),
            links(diff.removed_edges),
            json.dumps(metric_changes),
            int(bool(diff.suspect_reasons)),
            json.dumps(diff.findings, default=str),
            json.dumps(graph_to_payload(graph), separators=(",", ":"), default=str),
        )
        try:
            with (
                self._connect(create=True) as conn,
                conn,
            ):  # the inner ``with`` is the transaction
                conn.execute(
                    "INSERT INTO runs (run_id, timestamp, node_count, link_count, added_nodes, removed_nodes, "
                    "added_links, removed_links, metric_changes, is_suspect, findings, graph_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    row,
                )
                if self.max_runs > 0:
                    conn.execute(
                        "DELETE FROM runs WHERE seq <= (SELECT MAX(seq) FROM runs) - ?",
                        (self.max_runs,),
                    )
        except sqlite3.Error as exc:
            raise GraphEngineError(
                f"Could not record run {run_id} in {self.path}: {exc}"
            ) from exc
        return run_id

    # --------------------------------------------------------------- reading
    def _select(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        try:
            with self._connect() as conn:
                return [] if conn is None else conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(
                exc
            ):  # a database file that never got its first run
                return []
            raise GraphEngineError(
                f"Could not read the history store {self.path}: {exc}"
            ) from exc
        except sqlite3.Error as exc:
            raise GraphEngineError(
                f"Could not read the history store {self.path}: {exc}"
            ) from exc

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        """The most recent ``limit`` runs, newest first, without the graph itself (see ``get_run``)."""
        rows = self._select(
            f"SELECT {self._SUMMARY_COLUMNS} FROM runs ORDER BY seq DESC LIMIT ?",
            (max(int(limit), 0),),
        )
        return [self._summary(r) for r in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """One run with its findings and ``graph_json`` (the state-file text); ``None`` if there is no such run."""
        if not RUN_ID.match(str(run_id)):
            return None
        rows = self._select(
            f"SELECT {self._SUMMARY_COLUMNS}, graph_json FROM runs WHERE run_id = ?",
            (run_id,),
        )
        if not rows:
            return None
        record = self._summary(rows[0])
        record["findings"] = json.loads(rows[0]["findings"])
        record["graph_json"] = rows[0]["graph_json"]
        return record

    def findings(self, run_id: str) -> list[dict[str, Any]]:
        """Just the cross-check findings of one run (cheaper than ``get_run``, which also loads the graph)."""
        if not RUN_ID.match(str(run_id)):
            return []
        rows = self._select("SELECT findings FROM runs WHERE run_id = ?", (run_id,))
        return json.loads(rows[0]["findings"]) if rows else []

    def get_graph(self, run_id: str) -> nx.DiGraph | None:
        """The topology as it was in that run; ``None`` if there is no such run or its state is unreadable."""
        record = self.get_run(run_id)
        if record is None:
            return None
        try:
            return graph_from_payload(json.loads(record["graph_json"]))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            logger.warning("Run %s has an unreadable state (%s)", run_id, exc)
            return None

    def previous_run_id(self, run_id: str) -> str | None:
        """The ID of the run recorded just before ``run_id`` (``None`` for the first run or an unknown ID)."""
        if not RUN_ID.match(str(run_id)):
            return None
        rows = self._select(
            "SELECT run_id FROM runs WHERE seq < (SELECT seq FROM runs WHERE run_id = ?) "
            "ORDER BY seq DESC LIMIT 1",
            (run_id,),
        )
        return rows[0]["run_id"] if rows else None

    def count(self) -> int:
        """How many runs are stored."""
        rows = self._select("SELECT COUNT(*) AS n FROM runs")
        return int(rows[0]["n"]) if rows else 0


@dataclass
class TopologyDiff:
    """Difference between the previous and the current topology.

    Every entry is a plain dict (JSON-friendly) carrying the node/edge attributes,
    so downstream consumers - e.g. the visualizer, which must still draw removed
    elements - need nothing but this report.
    """

    baseline_available: bool = False
    added_nodes: list[dict] = field(default_factory=list)
    removed_nodes: list[dict] = field(default_factory=list)
    added_edges: list[dict] = field(default_factory=list)
    removed_edges: list[dict] = field(default_factory=list)
    changed_metrics: list[dict] = field(default_factory=list)
    #: Why the run looks like a partial LSDB (empty = trustworthy).
    suspect_reasons: list[str] = field(default_factory=list)
    #: False when the guard kept the previous baseline instead of saving this run.
    baseline_updated: bool = True
    #: Cross-check results (``correlation.Finding.to_dict()``): LSDB vs neighbour state, neighbour flaps,
    #: SPF vs routing table. Empty when no neighbour/routing data was collected - except the area coverage
    #: findings (``AREA_UNPOLLED``), which need nothing but the topology.
    findings: list[dict] = field(default_factory=list)
    #: Per polled router: how many routing-table entries were seen, checked and found consistent.
    rib_checks: list[dict] = field(default_factory=list)
    #: Which OSPF areas the seeds covered and which nobody read (``correlation.AreaCoverage.to_dict()``);
    #: ``None`` only when the diff was not produced by ``GraphEngine.process``.
    area_coverage: dict[str, Any] | None = None

    @property
    def has_changes(self) -> bool:
        return any(
            (
                self.added_nodes,
                self.removed_nodes,
                self.added_edges,
                self.removed_edges,
                self.changed_metrics,
            )
        )

    @property
    def critical_findings(self) -> list[dict]:
        return [f for f in self.findings if f.get("severity") == CRITICAL]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GraphEngine:
    """Builds, compares and persists the OSPF topology graph."""

    #: Default data directory — resolved from this file so it works regardless of CWD.
    _DEFAULT_DATA_DIR: Path = Path(__file__).resolve().parent.parent / "data"

    def __init__(
        self,
        data_dir: str | os.PathLike | None = None,
        guard: GuardConfig | None = None,
        history: HistoryConfig | None = None,
    ) -> None:
        self.data_dir = (
            Path(data_dir) if data_dir is not None else self._DEFAULT_DATA_DIR
        )
        self.guard = guard or GuardConfig()
        self.current_path = self.data_dir / "current_state.json"
        self.previous_path = self.data_dir / "previous_state.json"
        self.suspect_path = self.data_dir / "suspect_state.json"
        self.changelog_path = self.data_dir / "changelog.jsonl"
        history = history or HistoryConfig()
        #: Every accepted run is appended here (``data/history/history.db``); ``None`` when switched off.
        self.history: HistoryStore | None = (
            HistoryStore(self.data_dir / "history" / "history.db", history.max_runs)
            if history.enabled
            else None
        )
        #: ID of the run ``process`` last recorded in the history (``None`` if it recorded none).
        self.last_run_id: str | None = None

    # ------------------------------------------------------------------- build
    def build_graph(self, parsed: dict[str, Any]) -> nx.DiGraph:
        """Create a directed graph from the parser's standardized dictionary.

        Raises:
            GraphEngineError: If the dictionary is malformed or contains no nodes.
        """
        try:
            graph = nx.DiGraph(**dict(parsed.get("metadata") or {}))
            for node in parsed["nodes"]:
                attrs = dict(node)
                graph.add_node(attrs.pop("id"), **attrs)
            for edge in parsed["edges"]:
                attrs = dict(edge)
                graph.add_edge(attrs.pop("source"), attrs.pop("target"), **attrs)
        except (KeyError, TypeError, AttributeError) as exc:
            raise GraphEngineError(
                f"Parsed topology has an unexpected shape: {exc!r}"
            ) from exc

        if graph.number_of_nodes() == 0:
            raise GraphEngineError(
                "Parsed topology contains no nodes; refusing to use it as a baseline"
            )
        if not nx.is_weakly_connected(graph):
            logger.warning(
                "Topology is split into %d disconnected pieces - the LSDB may be partial "
                "(adjacency down on the seed router, or multiple areas)",
                nx.number_weakly_connected_components(graph),
            )
        return graph

    # ------------------------------------------------------------- persistence
    def load_graph(self, path: str | os.PathLike) -> nx.DiGraph | None:
        """Load a saved state file; return ``None`` if it is missing or unusable."""
        path = Path(path)
        if not path.exists():
            return None
        try:
            return graph_from_payload(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            logger.warning(
                "Ignoring unreadable state file %s (%s); treating this run as a fresh baseline",
                path,
                exc,
            )
            return None

    def save_graph(
        self, graph: nx.DiGraph, path: str | os.PathLike | None = None
    ) -> Path:
        """Write the graph as JSON (nodes + edges + metadata) atomically."""
        path = Path(path) if path else self.current_path
        graph.graph["generated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
        try:
            atomic_write_text(
                path, json.dumps(graph_to_payload(graph), indent=2) + "\n"
            )  # atomic: readers never see a half-written file
        except OSError as exc:
            raise GraphEngineError(f"Could not write state file {path}: {exc}") from exc
        logger.info("Saved topology state to %s", path)
        return path

    def rotate_state(self) -> bool:
        """Move current_state.json to previous_state.json. Returns True if a move happened."""
        if not self.current_path.exists():
            return False
        try:
            os.replace(self.current_path, self.previous_path)
        except OSError as exc:
            raise GraphEngineError(
                f"Could not move {self.current_path} to {self.previous_path}: {exc}"
            ) from exc
        return True

    # ------------------------------------------------------------------- compare
    @staticmethod
    def _node_record(graph: nx.DiGraph, node: str) -> dict[str, Any]:
        attrs = dict(graph.nodes[node])
        return {"id": node, "label": display_name(node, attrs), **attrs}

    @staticmethod
    def _edge_record(graph: nx.DiGraph, source: str, target: str) -> dict[str, Any]:
        return {
            "source": source,
            "target": target,
            "source_label": display_name(source, graph.nodes[source]),
            "target_label": display_name(target, graph.nodes[target]),
            **graph.edges[source, target],
        }

    def compare(self, old: nx.DiGraph | None, new: nx.DiGraph) -> TopologyDiff:
        """Diff two graphs. With no baseline, nothing is reported as changed."""
        if old is None:
            return TopologyDiff(baseline_available=False)

        def by_node(ids) -> list:
            return sorted(ids, key=node_sort_key)

        def by_edge(pairs) -> list:
            return sorted(
                pairs, key=lambda e: (node_sort_key(e[0]), node_sort_key(e[1]))
            )

        old_nodes, new_nodes = set(old.nodes), set(new.nodes)
        old_edges, new_edges = set(old.edges), set(new.edges)

        diff = TopologyDiff(baseline_available=True)
        diff.added_nodes = [
            self._node_record(new, n) for n in by_node(new_nodes - old_nodes)
        ]
        diff.removed_nodes = [
            self._node_record(old, n) for n in by_node(old_nodes - new_nodes)
        ]
        diff.added_edges = [
            self._edge_record(new, u, v) for u, v in by_edge(new_edges - old_edges)
        ]
        diff.removed_edges = [
            self._edge_record(old, u, v) for u, v in by_edge(old_edges - new_edges)
        ]
        for u, v in by_edge(old_edges & new_edges):
            old_metric, new_metric = (
                old.edges[u, v].get("metric"),
                new.edges[u, v].get("metric"),
            )
            if old_metric != new_metric:
                record = self._edge_record(new, u, v)
                record.update(old_metric=old_metric, new_metric=new_metric)
                record.pop("metric", None)
                diff.changed_metrics.append(record)
        return diff

    # ---------------------------------------------------------------- area view
    @staticmethod
    def filter_by_area(graph: nx.DiGraph, area: str) -> nx.DiGraph:
        """One OSPF area of ``graph`` on its own (see ``filter_graph_by_area``). Presentation only: the
        baseline and the history always hold the whole topology."""
        return filter_graph_by_area(graph, area)

    @staticmethod
    def filter_diff_by_area(
        diff: TopologyDiff, area: str, view: nx.DiGraph
    ) -> TopologyDiff:
        """The part of ``diff`` that belongs to the area view ``view`` (see ``filter_diff_by_area``)."""
        return filter_diff_by_area(diff, area, view)

    # --------------------------------------------------------------------- guard
    @staticmethod
    def _described(graph: nx.DiGraph) -> set[str]:
        """Nodes that have an LSA of their own in the database (not just a reference to them)."""
        return {n for n, attrs in graph.nodes(data=True) if attrs.get("resolved", True)}

    def assess(
        self,
        old: nx.DiGraph | None,
        new: nx.DiGraph,
        partial_sources: Sequence[str] = (),
    ) -> list[str]:
        """Return reasons why ``new`` looks like a partial LSDB (empty list = looks fine).

        ``partial_sources`` names seed routers that should have contributed but could not be polled
        (multi-seed merge). Their part of the network is simply absent, which the retention check below
        cannot always tell from a real outage (losing 3 of 16 routers stays above the threshold), so
        any such seed makes the run suspect. It follows the guard's switch and, like every other
        check, needs a baseline to compare with.

        Retention counts only nodes that still have their *own* LSA. In a partial LSDB the
        surviving LSAs keep referring to the missing routers, so those routers stay in the
        graph as placeholders; counting them would hide exactly the failure being detected.
        """
        guard = self.guard
        if not guard.enabled or old is None:
            return []
        reasons = []
        if partial_sources:
            reasons.append(
                f"{len(partial_sources)} seed router(s) could not be polled ({', '.join(partial_sources)}); "
                "the merged view may be missing part of the network"
            )
        known = self._described(old)
        if known:
            kept = len(known & self._described(new))
            retention = kept / len(known)
            if retention < guard.min_node_retention:
                reasons.append(
                    f"only {kept} of {len(known)} previously known nodes still have an LSA in the database "
                    f"({retention:.0%}, minimum {guard.min_node_retention:.0%})"
                )
        if guard.flag_partition:
            before = nx.number_weakly_connected_components(old)
            after = nx.number_weakly_connected_components(new)
            if after > before:
                reasons.append(
                    f"the topology split into {after} disconnected parts (was {before})"
                )
        return reasons

    # ------------------------------------------------------------------ pipeline
    def process(
        self,
        parsed: dict[str, Any],
        accept_changes: bool = False,
        dry_run: bool = False,
        partial_sources: Sequence[str] = (),
        details: Sequence[SourceDetail] = (),
        seeds: Sequence[Any] = (),
    ) -> tuple[nx.DiGraph, TopologyDiff]:
        """Build the graph, diff it against the baseline and (if trustworthy) save it.

        Args:
            parsed: The parser's standardized dictionary.
            accept_changes: Commit this run as the new baseline even if the guard flagged it.
            dry_run: Build and diff without writing any state files.
            partial_sources: Seed routers that failed to answer; see ``assess``.
            details: What each polled router reported besides the LSDB (neighbour table, routing table);
                cross-checked against the topology into ``diff.findings`` (see ``correlation``).
            seeds: ``poller.SeedResult``-like objects (``host``, ``status``, ``tags``); optional, lets the
                area coverage audit name the seed behind each area (see ``correlation.audit_area_coverage``).

        Returns:
            ``(graph, diff)``. ``diff.suspect_reasons`` / ``diff.baseline_updated`` tell
            whether the guard held the baseline back.
        """
        graph = self.build_graph(parsed)
        baseline = self.load_graph(self.current_path)
        if baseline is None:
            baseline = self.load_graph(
                self.previous_path
            )  # crash recovery / first run after rotation
        diff = self.compare(baseline, graph)
        diff.suspect_reasons = self.assess(baseline, graph, partial_sources)
        report = correlate(graph, details, baseline, seeds)
        diff.findings = [f.to_dict() for f in report.findings]
        diff.rib_checks = report.rib_checks
        if report.area_coverage is not None:
            diff.area_coverage = report.area_coverage.to_dict()

        if dry_run:
            diff.baseline_updated = False
            logger.info("Dry run — topology built and diffed; no state files written")
            return graph, diff

        if diff.suspect_reasons and not accept_changes:
            diff.baseline_updated = False
            self.save_graph(graph, self.suspect_path)
            logger.warning(
                "Run looks like a partial LSDB; baseline kept. Observed state saved to %s",
                self.suspect_path,
            )
            self._append_changelog(diff, graph)
            return graph, diff

        if self.rotate_state():
            logger.debug("Rotated %s -> %s", self.current_path, self.previous_path)
        self.save_graph(graph)
        self.suspect_path.unlink(
            missing_ok=True
        )  # any earlier suspect snapshot is now stale
        self._append_changelog(diff, graph)
        self._record_history(graph, diff)
        return graph, diff

    def _record_history(self, graph: nx.DiGraph, diff: TopologyDiff) -> None:
        """Append the accepted run to the history store (never raises: the baseline is already saved)."""
        self.last_run_id = None
        if self.history is None:
            return
        try:
            self.last_run_id = self.history.record(graph, diff)
        except GraphEngineError as exc:
            logger.warning("Run not added to the history: %s", exc)
            return
        logger.info("Recorded run %s in %s", self.last_run_id, self.history.path)

    def _append_changelog(self, diff: TopologyDiff, graph: nx.DiGraph) -> None:
        """Append a one-line JSON entry to ``data/changelog.jsonl`` (never raises)."""
        entry = {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "status": "suspect"
            if (diff.suspect_reasons and not diff.baseline_updated)
            else "ok",
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "added_nodes": len(diff.added_nodes),
            "removed_nodes": len(diff.removed_nodes),
            "added_edges": len(diff.added_edges),
            "removed_edges": len(diff.removed_edges),
            "changed_metrics": len(diff.changed_metrics),
        }
        for key, count in (
            ("stale_nodes", len(graph.graph.get("stale_nodes") or [])),
            ("one_way_links", graph.graph.get("one_way_links") or 0),
            ("adjacency_issues", len(graph.graph.get("adjacency_issues") or [])),
        ):
            if key in graph.graph:
                entry[key] = count
        if diff.findings:
            entry["findings"] = {
                sev: sum(1 for f in diff.findings if f["severity"] == sev)
                for sev in ("critical", "warning", "info")
                if any(f["severity"] == sev for f in diff.findings)
            }
        sources = graph.graph.get("sources")
        if sources:
            entry["sources_ok"] = [
                s["name"] for s in sources if s.get("status") == "ok"
            ]
        try:
            self.changelog_path.parent.mkdir(parents=True, exist_ok=True)
            with self.changelog_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError as exc:
            logger.warning(
                "Could not write to changelog %s: %s", self.changelog_path, exc
            )
