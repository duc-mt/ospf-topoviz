"""
==============================================================================
Module Name:   server.py
Description:   Embedded web server (``main.py --serve``): the latest explorer page, the topology history
               (time travel), on-demand SPF traces and a trigger for a new poll, over plain HTTP.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-27
Version:       1.0.0
License:       MIT
==============================================================================
Endpoints (everything under ``/api`` answers ``{"status": "ok", "data": ...}`` or
``{"status": "error", "error": "..."}``):

    GET  /                          the latest explorer page (output/topology.html)
    GET  /api/status                baseline time, node / link counts, recent findings, poll state
    GET  /api/history?limit=N       the most recent runs, newest first (default 50, at most 500)
    GET  /api/history/<run_id>      one run: what changed, its findings and the complete graph
    GET  /api/history/<run_id>/scene   that run as the explorer page draws it (used by the history slider)
    GET  /api/trace?source=<router_id>&dest=<ip|prefix>   shortest path(s) over the current topology
    POST /api/poll                  start a poll in the background (202; 409 if one is already running)

Only the standard library is used (``http.server``). Nothing here maps a URL to a file path - the one file
served is the configured explorer page - so there is no path to traverse. Router IDs, addresses and prefixes
from the query string are parsed with ``ipaddress`` and run IDs checked against a strict pattern before they
are used for anything. The server has no login: it listens on the loopback address by default.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import queue
import re
import socket
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import networkx as nx

from src import TrackerError, __version__
from src.config import DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT
from src.correlation import trace_prefix
from src.explorer import build_scene
from src.graph_engine import (
    RUN_ID,
    GraphEngine,
    GraphEngineError,
    HistoryStore,
    display_name,
    graph_from_payload,
)
from src.metrics import render_prometheus_metrics
from src.poller import PollBusyError, PollLock
from src.realtime.ingest import IngestCoordinator
from src.visualizer import VisualOptions

logger = logging.getLogger("ospf_tracker.web")

__all__ = [
    "EventBroker",
    "PollCoordinator",
    "PollScheduler",
    "WebApp",
    "create_server",
    "run_server",
]

JSON_TYPE = "application/json; charset=utf-8"
HTML_TYPE = "text/html; charset=utf-8"
DEFAULT_HISTORY_LIMIT = 50
MAX_HISTORY_LIMIT = 500
DEFAULT_EVENT_LIMIT = 100
SSE_KEEPALIVE_SECONDS = 15.0
MAX_INGEST_BYTES = 16 * 1024 * 1024
#: How many findings ``/api/status`` lists.
STATUS_FINDINGS = 20
#: Past scenes kept in memory (a run never changes once recorded, so they can be reused as is).
SCENE_CACHE_SIZE = 24
#: A router ID or a prefix is at most this long (an IPv6 network with a prefix length is 43 characters).
MAX_TEXT = 64


class ApiError(Exception):
    """An error with the HTTP status to answer it with."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Response:
    """What the handler writes back."""

    status: HTTPStatus
    body: bytes
    content_type: str = JSON_TYPE
    headers: dict[str, str] = field(default_factory=dict)


def ok(data: Any, status: HTTPStatus = HTTPStatus.OK) -> Response:
    """A success answer: ``{"status": "ok", "data": data}``."""
    return json_response(status, {"status": "ok", "data": data})


def json_response(
    status: HTTPStatus, payload: dict[str, Any], headers: dict[str, str] | None = None
) -> Response:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
    return Response(status, body.encode("utf-8"), JSON_TYPE, headers or {})


class EventBroker:
    """Thread-safe fan-out hub delivering Server-Sent Events (SSE) to active HTTP clients."""

    def __init__(self, max_queue: int = 128) -> None:
        self._max_queue = max_queue
        self._lock = threading.Lock()
        self._subscribers: set[queue.Queue[str | None]] = set()

    def subscribe(self) -> queue.Queue[str | None]:
        """Register a new subscriber queue."""
        q: queue.Queue[str | None] = queue.Queue(maxsize=self._max_queue)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue[str | None]) -> None:
        """Remove a subscriber queue."""
        with self._lock:
            self._subscribers.discard(q)

    def publish(
        self, event_name: str, data: dict[str, Any], event_id: str | None = None
    ) -> None:
        """Broadcast one SSE event frame to all active subscribers without blocking."""
        payload = json.dumps(
            data, ensure_ascii=False, separators=(",", ":"), default=str
        )
        prefix = f"id: {event_id}\n" if event_id else ""
        frame = f"{prefix}event: {event_name}\ndata: {payload}\n\n"
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(frame)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(frame)
                except (queue.Empty, queue.Full):
                    pass

    def close_all(self) -> None:
        """Signal all open SSE subscribers to close."""
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            with contextlib.suppress(queue.Full):
                q.put_nowait(None)


# ============================================================ polling
class PollCoordinator:
    """Starts polls in the background and remembers how the last one went.

    A poll is whatever ``poll_fn`` does (normally one ``main.run``); it takes the shared poll lock itself, so a
    poll started here, by the CLI or by cron never overlap. ``trigger`` refuses (returns False) while one is
    running - here (a flag) or anywhere else (the lock file) - which the API turns into 409.
    """

    def __init__(
        self,
        poll_fn: Callable[[], int] | None,
        lock_path: str | Path,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        self._poll_fn = poll_fn
        self._lock_path = Path(lock_path)
        self._on_complete = on_complete
        self._guard = threading.Lock()
        self._running = False
        self._last: dict[str, Any] | None = None
        self._thread: threading.Thread | None = None

    @property
    def configured(self) -> bool:
        """False when the server was started without a way to poll."""
        return self._poll_fn is not None

    def snapshot(self) -> dict[str, Any]:
        """``{"configured", "running", "last"}`` for ``/api/status``."""
        with self._guard:
            return {
                "configured": self.configured,
                "running": self._running or PollLock.is_held(self._lock_path),
                "last": dict(self._last) if self._last else None,
            }

    def trigger(self, reason: str = "api") -> bool:
        """Start one poll in a background thread; False if a poll is already running.

        Raises:
            RuntimeError: If the server has no poll function.
        """
        if self._poll_fn is None:
            raise RuntimeError("no poll function configured")
        with self._guard:
            if self._running or PollLock.is_held(self._lock_path):
                return False
            self._running = True
        self._thread = threading.Thread(
            target=self._work, args=(reason,), name="poll", daemon=True
        )
        self._thread.start()
        return True

    def wait(self, timeout: float | None = None) -> None:
        """Block until the poll in progress (if any) ends; for tests and orderly shutdown."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def _work(self, reason: str) -> None:
        outcome: dict[str, Any] = {
            "trigger": reason,
            "started": datetime.now(UTC).isoformat(timespec="seconds"),
            "finished": None,
            "exit_code": None,
            "error": None,
        }
        try:
            outcome["exit_code"] = self._poll_fn()
        except (
            PollBusyError
        ) as exc:  # somebody else polled between the check and the start
            outcome["error"] = str(exc)
            logger.warning("%s", exc)
        except (
            TrackerError
        ) as exc:  # an expected failure (device unreachable, bad config, ...)
            outcome["error"] = str(exc)
            logger.warning("Poll failed: %s", exc)
        except Exception as exc:
            outcome["error"] = f"{type(exc).__name__}: {exc}"
            logger.exception("Poll crashed")
        finally:
            outcome["finished"] = datetime.now(UTC).isoformat(timespec="seconds")
            with self._guard:
                self._running = False
                self._last = outcome
            if self._on_complete is not None:
                try:
                    self._on_complete()
                except Exception:
                    logger.exception("Post-poll callback failed")


class PollScheduler(threading.Thread):
    """Triggers a poll every ``interval`` seconds (the first right away) until stopped.

    A poll that is still running when the next one is due simply makes that one a no-op.
    """

    def __init__(self, coordinator: PollCoordinator, interval: float) -> None:
        super().__init__(name="poll-scheduler", daemon=True)
        self.coordinator = coordinator
        self.interval = interval
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.is_set():
            try:
                if not self.coordinator.trigger("schedule"):
                    logger.info("Scheduled poll skipped: one is already running")
            except Exception:
                logger.exception("Scheduled poll could not be started")
            if self._halt.wait(self.interval):
                break

    def stop(self) -> None:
        self._halt.set()


# ================================================================ app
class WebApp:
    """Everything the endpoints need; ``handle`` turns a request into a ``Response``."""

    def __init__(
        self,
        data_dir: str | Path,
        output_html: str | Path,
        options: VisualOptions | None = None,
        poll_fn: Callable[[], int] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.output_html = Path(output_html)
        self.options = options or VisualOptions()
        self.engine = GraphEngine(self.data_dir)
        self.history = HistoryStore(self.data_dir / "history" / "history.db")
        self.broker = EventBroker()
        self.ingest = IngestCoordinator(self.data_dir, self.engine, self.broker)
        self.coordinator = PollCoordinator(
            poll_fn, self.data_dir / ".poll.lock", on_complete=self._notify_poll_done
        )
        self.scheduler: PollScheduler | None = None
        self._scenes: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._scene_lock = threading.Lock()
        self._last_notified_run_id: str | None = None

    def _notify_poll_done(self) -> None:
        latest = self.history.list_runs(1)
        if latest and latest[0]["run_id"] != self._last_notified_run_id:
            self._last_notified_run_id = latest[0]["run_id"]
            self.broker.publish(
                "topology_updated",
                {
                    "run_id": latest[0]["run_id"],
                    "timestamp": latest[0]["timestamp"],
                },
                event_id=latest[0]["run_id"],
            )

    # ------------------------------------------------------------ routing
    def handle(
        self,
        method: str,
        target: str,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        client_host: str = "127.0.0.1",
    ) -> Response:
        """Answer one request. Never raises: errors become JSON error responses."""
        split = urlsplit(target)
        path, query = split.path, parse_qs(split.query, keep_blank_values=True)
        try:
            if path == "/api/ingest/lsdb":
                if method == "POST":
                    return self._ingest_lsdb(body, headers or {}, client_host)
                response = self._error(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    f"{method} is not allowed here; use POST",
                    path,
                )
                response.headers["Allow"] = "POST"
                return response
            return self._route(method, path, query)
        except ApiError as exc:
            return self._error(exc.status, exc.message, path)
        except GraphEngineError as exc:
            logger.warning("%s %s: %s", method, path, exc)
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc), path)
        except Exception:
            logger.exception("Unhandled error in %s %s", method, path)
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error", path)

    @staticmethod
    def _error(status: HTTPStatus, message: str, path: str) -> Response:
        if path == "/" or not path.startswith("/api"):
            return Response(
                status,
                f"{status.value} {status.phrase}: {message}\n".encode(),
                "text/plain; charset=utf-8",
            )
        return json_response(status, {"status": "error", "error": message})

    def _route(self, method: str, path: str, query: dict[str, list[str]]) -> Response:
        routes: list[tuple[re.Pattern[str], str, Callable[..., Response]]] = [
            (re.compile(r"/"), "GET", self._page),
            (re.compile(r"/api/status"), "GET", self._status),
            (re.compile(r"/api/history"), "GET", self._history_list),
            (re.compile(r"/api/history/([^/]+)"), "GET", self._history_run),
            (re.compile(r"/api/history/([^/]+)/scene"), "GET", self._history_scene),
            (re.compile(r"/api/events"), "GET", self._events_list),
            (re.compile(r"/api/events/histogram"), "GET", self._events_histogram),
            (re.compile(r"/api/trace"), "GET", self._trace),
            (re.compile(r"/api/poll"), "POST", self._poll),
            (re.compile(r"/metrics"), "GET", self._metrics),
        ]
        allowed: set[str] = set()
        for pattern, verb, func in routes:
            match = pattern.fullmatch(path)
            if not match:
                continue
            allowed.add(verb)
            if method == verb or (method == "HEAD" and verb == "GET"):
                return func(query, *match.groups())
        if allowed:
            response = self._error(
                HTTPStatus.METHOD_NOT_ALLOWED,
                f"{method} is not allowed here; use {', '.join(sorted(allowed))}",
                path,
            )
            response.headers["Allow"] = ", ".join(sorted(allowed))
            return response
        raise ApiError(HTTPStatus.NOT_FOUND, f"no such endpoint: {path}")

    # --------------------------------------------------------------- state
    def current_graph(self) -> nx.DiGraph | None:
        """The baseline topology (``data/current_state.json``), or ``None`` before the first accepted run."""
        return self.engine.load_graph(self.engine.current_path)

    @staticmethod
    def _one(query: dict[str, list[str]], name: str) -> str:
        values = query.get(name, [])
        if len(values) != 1 or not values[0].strip():
            raise ApiError(
                HTTPStatus.BAD_REQUEST, f"give exactly one '{name}' parameter"
            )
        value = values[0].strip()
        if len(value) > MAX_TEXT:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"'{name}' is too long")
        return value

    @staticmethod
    def _run_id(text: str) -> str:
        if not RUN_ID.match(text):
            raise ApiError(HTTPStatus.BAD_REQUEST, "malformed run ID")
        return text

    # ----------------------------------------------------------- endpoints
    def _page(self, _query: dict[str, list[str]]) -> Response:
        try:
            body = self.output_html.read_bytes()
        except FileNotFoundError:
            raise ApiError(
                HTTPStatus.NOT_FOUND,
                "no topology has been drawn yet: start a poll (POST /api/poll) or run main.py once",
            ) from None
        except OSError as exc:
            raise ApiError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"cannot read the explorer page: {exc}",
            ) from exc
        return Response(
            HTTPStatus.OK,
            body,
            HTML_TYPE,
            {"Cache-Control": "no-cache"},
        )

    def _status(self, _query: dict[str, list[str]]) -> Response:
        graph = self.current_graph()
        latest = self.history.list_runs(1)
        findings: list[dict[str, Any]] = []
        if latest:
            findings = [
                {
                    k: f.get(k)
                    for k in ("severity", "kind", "router", "subject", "message")
                }
                for f in self.history.findings(latest[0]["run_id"])[:STATUS_FINDINGS]
            ]
        return ok(
            {
                "version": __version__,
                "has_topology": graph is not None,
                "baseline_timestamp": graph.graph.get("generated_at")
                if graph
                else None,
                "node_count": graph.number_of_nodes() if graph else 0,
                "link_count": graph.number_of_edges() if graph else 0,
                "history_runs": self.history.count(),
                "latest_run_id": latest[0]["run_id"] if latest else None,
                "recent_findings": findings,
                "poll": self.coordinator.snapshot(),
            }
        )

    def _history_list(self, query: dict[str, list[str]]) -> Response:
        limit = DEFAULT_HISTORY_LIMIT
        if "limit" in query:
            text = self._one(query, "limit")
            if not text.isdigit() or not 1 <= int(text) <= MAX_HISTORY_LIMIT:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    f"limit must be a whole number from 1 to {MAX_HISTORY_LIMIT}",
                )
            limit = int(text)
        return ok(
            {"runs": self.history.list_runs(limit), "total": self.history.count()}
        )

    def _history_run(self, _query: dict[str, list[str]], run_id: str) -> Response:
        record = self.history.get_run(self._run_id(run_id))
        if record is None:
            raise ApiError(HTTPStatus.NOT_FOUND, f"no run {run_id} in the history")
        try:
            graph = json.loads(record.pop("graph_json"))
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"the stored state of run {run_id} is unreadable",
            ) from exc
        return ok({**record, "graph": graph})

    def _history_scene(self, _query: dict[str, list[str]], run_id: str) -> Response:
        return ok(self.scene_for_run(self._run_id(run_id)))

    def scene_for_run(self, run_id: str) -> dict[str, Any]:
        """The explorer scene of a past run, drawn against the run before it (so what changed shows)."""
        with self._scene_lock:
            cached = self._scenes.get(run_id)
            if cached is not None:
                self._scenes.move_to_end(run_id)
                return cached
        record = self.history.get_run(run_id)
        if record is None:
            raise ApiError(HTTPStatus.NOT_FOUND, f"no run {run_id} in the history")
        try:
            graph = graph_from_payload(json.loads(record["graph_json"]))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ApiError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"the stored state of run {run_id} is unreadable",
            ) from exc
        before_id = self.history.previous_run_id(run_id)
        before = self.history.get_graph(before_id) if before_id else None
        diff = self.engine.compare(before, graph)
        diff.findings = record["findings"]
        if record["is_suspect"]:
            diff.suspect_reasons = [
                "the guard flagged this run as a possible partial LSDB; it was accepted with --accept-changes"
            ]
        scene = build_scene(
            graph,
            diff,
            self.options,
            scope=str(graph.graph.get("scope") or "default"),
            generated=record["timestamp"],
            history={
                "run_id": run_id,
                "timestamp": record["timestamp"],
                "is_suspect": record["is_suspect"],
            },
        )
        with self._scene_lock:
            self._scenes[run_id] = scene
            while len(self._scenes) > SCENE_CACHE_SIZE:
                self._scenes.popitem(last=False)
        return scene

    def _trace(self, query: dict[str, list[str]]) -> Response:
        source, dest = self._one(query, "source"), self._one(query, "dest")
        try:
            ipaddress.ip_address(source)
        except ValueError:
            raise ApiError(
                HTTPStatus.BAD_REQUEST, "source must be a router ID (an IP address)"
            ) from None
        try:
            if "/" in dest:
                ipaddress.ip_network(dest, strict=False)
            else:
                ipaddress.ip_address(dest)
        except ValueError:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "dest must be an IP address or a prefix such as 10.1.0.0/16",
            ) from None
        graph = self.current_graph()
        if graph is None:
            raise ApiError(
                HTTPStatus.NOT_FOUND, "no topology has been saved yet: run a poll first"
            )
        if source not in graph or graph.nodes[source].get("type") != "router":
            raise ApiError(
                HTTPStatus.NOT_FOUND, f"router {source} is not in the topology"
            )
        try:
            result = trace_prefix(graph, [], dest, source)
        except (
            ValueError
        ) as exc:  # cannot happen after the checks above; never a 500 for bad input
            raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc

        def hop(node: str) -> dict[str, Any]:
            attrs = graph.nodes[node] if node in graph else {}
            return {
                "id": node,
                "label": display_name(node, attrs),
                "type": attrs.get("type"),
            }

        paths = [[hop(n) for n in path] for path in result.paths]
        return ok(
            {
                "source": result.source,
                "query": result.query,
                "prefix": result.prefix,
                "verdict": result.verdict,
                "spf_cost": result.spf_cost,
                "origins": result.origins,
                "externals": result.externals,
                "notes": result.notes,
                "paths": paths,
                "hops": paths[0] if paths else [],
            }
        )

    def _events_list(self, query: dict[str, list[str]]) -> Response:
        limit = DEFAULT_EVENT_LIMIT
        if "limit" in query:
            text = self._one(query, "limit")
            if not text.isdigit() or not 1 <= int(text) <= MAX_HISTORY_LIMIT:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    f"limit must be a whole number from 1 to {MAX_HISTORY_LIMIT}",
                )
            limit = int(text)

        def opt(name: str) -> str | None:
            if name not in query:
                return None
            val = self._one(query, name)
            if name in ("since", "until"):
                try:
                    datetime.fromisoformat(val.replace("Z", "+00:00"))
                except ValueError:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        f"'{name}' must be an ISO-8601 timestamp",
                    ) from None
            return val

        events, total = self.history.query_events(
            limit=limit,
            since=opt("since"),
            until=opt("until"),
            event_type=opt("type"),
            status=opt("status"),
            severity=opt("severity"),
            router=opt("router"),
            prefix=opt("prefix"),
            q=opt("q"),
        )
        return ok({"events": events, "total": total})

    def _events_histogram(self, query: dict[str, list[str]]) -> Response:
        bucket = "1h"
        if "bucket" in query:
            bucket = self._one(query, "bucket")
            if bucket not in ("15m", "1h", "1d"):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "bucket must be one of 15m, 1h, 1d",
                )

        def opt_iso(name: str) -> str | None:
            if name not in query:
                return None
            val = self._one(query, name)
            try:
                datetime.fromisoformat(val.replace("Z", "+00:00"))
            except ValueError:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    f"'{name}' must be an ISO-8601 timestamp",
                ) from None
            return val

        series = self.history.event_histogram(
            bucket=bucket,
            since=opt_iso("since"),
            until=opt_iso("until"),
        )
        return ok({"bucket": bucket, "series": series})

    def _metrics(self, _query: dict[str, list[str]]) -> Response:
        text = render_prometheus_metrics(
            self.current_graph(), self.history, self.coordinator.snapshot()
        )
        return Response(
            HTTPStatus.OK,
            text.encode("utf-8"),
            "text/plain; version=0.0.4; charset=utf-8",
        )

    def _ingest_lsdb(
        self, body: bytes, headers: dict[str, str], client_host: str
    ) -> Response:
        auth = None
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth = v
                break
        if not self.ingest.verify_token(auth, remote_host=client_host):
            raise ApiError(
                HTTPStatus.UNAUTHORIZED,
                "unauthorized: valid Bearer token required",
            )
        if not body:
            raise ApiError(HTTPStatus.BAD_REQUEST, "empty JSON body")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"invalid JSON payload: {exc}") from None
        try:
            result = self.ingest.submit(payload)
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from None
        except PollBusyError as exc:
            raise ApiError(HTTPStatus.CONFLICT, str(exc)) from None
        status = HTTPStatus.ACCEPTED if result.get("queued") else HTTPStatus.OK
        return ok(result, status)

    def _poll(self, _query: dict[str, list[str]]) -> Response:
        if not self.coordinator.configured:
            raise ApiError(
                HTTPStatus.NOT_IMPLEMENTED, "this server was started without a poller"
            )
        if not self.coordinator.trigger("api"):
            raise ApiError(HTTPStatus.CONFLICT, "a poll is already running")
        return ok(
            {"started": True, "poll": self.coordinator.snapshot()}, HTTPStatus.ACCEPTED
        )


# ============================================================ HTTP glue
class _Handler(BaseHTTPRequestHandler):
    server_version = f"ospf-topoviz/{__version__}"
    sys_version = ""

    def _serve(self) -> None:
        app: WebApp = self.server.app  # type: ignore[attr-defined]
        split = urlsplit(self.path)
        if self.command == "GET" and split.path == "/api/events/stream":
            self._serve_sse(app, parse_qs(split.query, keep_blank_values=True))
            return
        body = b""
        if self.command == "POST":
            try:
                clen = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                clen = 0
            if clen > MAX_INGEST_BYTES:
                err = json_response(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"status": "error", "error": "request body exceeds 16 MiB limit"},
                )
                self.send_response(err.status)
                self.send_header("Content-Type", err.content_type)
                self.send_header("Content-Length", str(len(err.body)))
                self.end_headers()
                self.wfile.write(err.body)
                return
            if clen > 0:
                body = self.rfile.read(clen)
        headers = dict(self.headers.items())
        client_host = self.client_address[0] if self.client_address else "127.0.0.1"
        response = app.handle(
            self.command,
            self.path,
            body=body,
            headers=headers,
            client_host=client_host,
        )
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header(
            "Cache-Control", response.headers.pop("Cache-Control", "no-store")
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    def _serve_sse(self, app: WebApp, query: dict[str, list[str]]) -> None:
        max_events: int | None = None
        if "max_events" in query and query["max_events"][0].isdigit():
            max_events = max(1, int(query["max_events"][0]))
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        q = app.broker.subscribe()
        sent = 0
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while max_events is None or sent < max_events:
                try:
                    frame = q.get(timeout=SSE_KEEPALIVE_SECONDS)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if frame is None:
                    break
                self.wfile.write(frame.encode("utf-8"))
                self.wfile.flush()
                sent += 1
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            app.broker.unsubscribe(q)

    do_GET = do_HEAD = do_POST = _serve

    def _not_allowed(self) -> None:
        self._serve()

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_allowed

    def log_message(self, format: str, *args: Any) -> None:
        level = logging.INFO if self.command == "POST" else logging.DEBUG
        logger.log(level, "%s %s", self.address_string(), format % args)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    app: WebApp


class _Server6(_Server):
    address_family = socket.AF_INET6


def create_server(
    host: str = DEFAULT_SERVER_HOST,
    port: int = DEFAULT_SERVER_PORT,
    *,
    data_dir: str | Path | None = None,
    output_html: str | Path | None = None,
    options: VisualOptions | None = None,
    poll_fn: Callable[[], int] | None = None,
    poll_interval: float = 0,
) -> ThreadingHTTPServer:
    """Bind the server (``port=0`` picks a free one; see ``server.server_port``) without starting it.

    Args:
        host: Address to listen on (an IPv4 or IPv6 address, or a name). Defaults to the loopback address.
        data_dir: Where ``current_state.json`` and ``history/`` live (default: the project's ``data``).
        output_html: The explorer page ``GET /`` sends (default: ``output/topology.html``).
        options: Look-and-feel of the scenes drawn for past runs.
        poll_fn: What ``POST /api/poll`` runs (it should return an exit code); ``None`` = no polling.
        poll_interval: Seconds between polls the server starts itself (0 = only on request).

    The result carries the application as ``.app``; ``run_server`` starts the schedule and serves.

    Raises:
        OSError: If the address cannot be bound.
    """
    base = GraphEngine._DEFAULT_DATA_DIR
    app = WebApp(
        data_dir if data_dir is not None else base,
        output_html
        if output_html is not None
        else base.parent / "output" / "topology.html",
        options,
        poll_fn,
    )
    try:
        v6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        v6 = False
    server = (_Server6 if v6 else _Server)((host, port), _Handler)
    server.app = app
    if poll_interval and poll_fn is not None:
        app.scheduler = PollScheduler(app.coordinator, poll_interval)
    return server


def run_server(server: ThreadingHTTPServer) -> None:
    """Serve until interrupted (Ctrl-C) or ``server.shutdown()``, then release the port."""
    app: WebApp = server.app  # type: ignore[attr-defined]
    if app.scheduler is not None:
        app.scheduler.start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        logger.info("Interrupted: shutting the web server down")
    finally:
        app.broker.close_all()
        if app.scheduler is not None:
            app.scheduler.stop()
        server.server_close()
