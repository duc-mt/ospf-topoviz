"""
==============================================================================
Module Name:   test_web_server.py
Description:   --serve: the embedded HTTP server, its REST endpoints, error handling and the poll lock.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-27
Version:       1.0.0
License:       MIT
==============================================================================
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from copy import deepcopy
from pathlib import Path

import pytest

import main
from src import TrackerError
from src.config import ConfigError, ServerOptions
from src.graph_engine import GraphEngine, HistoryStore, TopologyDiff
from src.parser import OSPFParser
from src.poller import PollBusyError, PollLock
from src.web.server import (
    PollCoordinator,
    PollScheduler,
    WebApp,
    create_server,
    run_server,
)
from tests.test_graph_engine import topology

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "vyos"
R1, R3 = "10.0.0.1", "10.0.0.3"


def sample_topology() -> dict:
    text = {
        n: (SAMPLE / n).read_text(encoding="utf-8")
        for n in ("router_lsdb.txt", "network_lsdb.txt", "external_lsdb.txt")
    }
    return OSPFParser("vyos").parse(
        text["router_lsdb.txt"], text["network_lsdb.txt"], text["external_lsdb.txt"]
    )


class Site:
    """A WebApp over a temp data directory, with helpers to call it and to feed its history."""

    def __init__(self, tmp_path: Path, poll_fn=None) -> None:
        self.data = tmp_path / "data"
        self.page = tmp_path / "output" / "topology.html"
        self.engine = GraphEngine(self.data)
        self.app = WebApp(self.data, self.page, poll_fn=poll_fn)

    def call(self, method: str, target: str):
        response = self.app.handle(method, target)
        if response.content_type.startswith("application/json"):
            return response.status, json.loads(response.body)
        return response.status, response.body.decode()

    def get(self, target: str):
        return self.call("GET", target)

    def run(self, parsed: dict | None = None, **kw) -> str:
        self.engine.process(parsed or topology(), **kw)
        return self.engine.last_run_id


@pytest.fixture
def site(tmp_path):
    return Site(tmp_path)


def ok(result):
    status, body = result
    assert status == 200, body
    assert body["status"] == "ok"
    return body["data"]


def error(result, status: int):
    got, body = result
    assert (
        got == status and body["status"] == "error" and isinstance(body["error"], str)
    ), (got, body)
    return body["error"]


# ----------------------------------------------------------------- creation
def test_the_server_can_be_created_and_closed_without_any_arguments_but_host_and_port():
    server = create_server(
        "127.0.0.1", 0
    )  # port 0: let the OS pick one, so the test never collides
    try:
        assert server.server_address[0] == "127.0.0.1" and server.server_port > 0
        assert isinstance(server.app, WebApp)
    finally:
        server.server_close()


def test_the_server_binds_an_ipv6_address_when_given_one():
    if not socket.has_ipv6:
        pytest.skip("no IPv6 on this host")
    try:
        server = create_server("::1", 0)
    except OSError:
        pytest.skip("cannot bind ::1 here")
    try:
        assert server.address_family == socket.AF_INET6
    finally:
        server.server_close()


def test_a_port_that_is_taken_is_an_os_error():
    first = create_server("127.0.0.1", 0)
    try:
        with pytest.raises(OSError):
            create_server("127.0.0.1", first.server_port)
    finally:
        first.server_close()


# -------------------------------------------------------------------- page
def test_the_root_serves_the_latest_explorer_page(site):
    status, text = site.get("/")  # the page is plain text on an error, not JSON
    assert status == 404 and "no topology has been drawn yet" in text
    site.page.parent.mkdir(parents=True)
    site.page.write_text("<!DOCTYPE html><title>t</title>", encoding="utf-8")
    response = site.app.handle("GET", "/")
    assert response.status == 200 and response.content_type.startswith("text/html")
    assert response.body == b"<!DOCTYPE html><title>t</title>"
    site.page.write_text("<!DOCTYPE html><title>newer</title>", encoding="utf-8")
    assert (
        b"newer" in site.app.handle("GET", "/").body
    )  # always the latest, never cached in memory


def test_a_query_string_does_not_change_the_page(site):
    site.page.parent.mkdir(parents=True)
    site.page.write_text("<html>x</html>", encoding="utf-8")
    assert (
        site.app.handle("GET", "/?run=1&x=../../etc/passwd").body == b"<html>x</html>"
    )


# ------------------------------------------------------------------- status
def test_status_before_any_run_is_a_healthy_empty_answer(site):
    data = ok(site.get("/api/status"))
    assert data["has_topology"] is False and data["baseline_timestamp"] is None
    assert (data["node_count"], data["link_count"], data["history_runs"]) == (0, 0, 0)
    assert data["recent_findings"] == [] and data["latest_run_id"] is None
    assert data["poll"] == {"configured": False, "running": False, "last": None}


def test_status_reports_the_baseline_counts_and_the_latest_run(site):
    first = site.run()
    second = site.run(topology(extra_routers=1))
    data = ok(site.get("/api/status"))
    assert data["has_topology"] and (data["node_count"], data["link_count"]) == (6, 12)
    assert data["history_runs"] == 2 and data["latest_run_id"] == second != first
    assert (
        data["baseline_timestamp"]
        == json.loads(site.engine.current_path.read_text())["metadata"]["generated_at"]
    )


def test_status_lists_the_recent_findings_of_the_latest_run_trimmed_to_the_useful_fields(
    site,
):
    graph, _ = site.engine.process(topology())
    findings = [
        {
            "severity": "critical",
            "kind": "ROUTE_MISSING",
            "router": R1,
            "subject": "10.9.0.0/24",
            "message": "m",
            "hint": "h",
            "data": {"big": "x" * 50},
        }
    ] * 25
    HistoryStore(site.data / "history" / "history.db").record(
        graph, TopologyDiff(findings=findings)
    )
    shown = ok(site.get("/api/status"))["recent_findings"]
    assert len(shown) == 20
    assert set(shown[0]) == {"severity", "kind", "router", "subject", "message"}


# ------------------------------------------------------------------ history
def test_the_history_lists_runs_newest_first(site):
    ids = [site.run(topology(extra_routers=n)) for n in range(3)]
    data = ok(site.get("/api/history"))
    assert [r["run_id"] for r in data["runs"]] == ids[::-1] and data["total"] == 3
    assert "graph_json" not in data["runs"][0]
    assert [r["run_id"] for r in ok(site.get("/api/history?limit=2"))["runs"]] == ids[
        :0:-1
    ]


def test_the_history_of_a_server_with_no_runs_is_an_empty_list(site):
    assert ok(site.get("/api/history")) == {"runs": [], "total": 0}


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=501",
        "limit=abc",
        "limit=-1",
        "limit=1.5",
        "limit=",
        "limit=1&limit=2",
        "limit=1e3",
    ],
)
def test_a_bad_history_limit_is_a_400(site, query):
    site.run()
    error(site.get(f"/api/history?{query}"), 400)


def test_one_run_comes_back_with_its_graph(site):
    run_id = site.run()
    data = ok(site.get(f"/api/history/{run_id}"))
    assert data["run_id"] == run_id and data["node_count"] == 5
    assert {n["id"] for n in data["graph"]["nodes"]} == {
        f"10.0.0.{i}" for i in range(1, 6)
    }
    assert data["graph"]["schema_version"] and "graph_json" not in data


def test_an_unknown_run_is_a_404_and_a_malformed_id_is_a_400(site):
    site.run()
    error(site.get("/api/history/20990101T000000Z-deadbeef"), 404)
    for bad in ("a%20b", "..%2f..%2fetc", "x;drop", "é", "a" * 65, "%27or%271"):
        error(site.get(f"/api/history/{bad}"), 400)


def test_a_past_run_can_be_drawn_as_a_scene_against_the_run_before_it(site):
    first = site.run()
    second = site.run(topology(extra_routers=1))
    scene_1 = ok(site.get(f"/api/history/{first}/scene"))
    scene_2 = ok(site.get(f"/api/history/{second}/scene"))
    assert len(scene_1["nodes"]) == 5 and len(scene_2["nodes"]) == 6
    assert (
        scene_2["meta"]["history"]["run_id"] == second
        and scene_1["meta"]["history"]["run_id"] == first
    )
    added = [n["id"] for n in scene_2["nodes"] if n.get("status") == "added"]
    assert added == ["10.0.0.6"]  # drawn as what that run changed
    assert not any(
        n.get("status") == "added" for n in scene_1["nodes"]
    )  # the first run has nothing to compare


def test_scenes_are_cached_and_identical_on_a_second_request(site):
    run_id = site.run()
    assert site.app.scene_for_run(run_id) is site.app.scene_for_run(run_id)


def test_a_scene_of_an_unknown_run_is_a_404(site):
    site.run()
    error(site.get("/api/history/20990101T000000Z-deadbeef/scene"), 404)


# -------------------------------------------------------------------- trace
@pytest.fixture
def traced(site):
    site.run(sample_topology())
    return site


def test_a_trace_to_an_address_follows_the_shortest_path(traced):
    data = ok(traced.get(f"/api/trace?source={R1}&dest=192.168.1.3"))
    assert data["source"] == R1 and data["prefix"] == "192.168.1.0/24"
    assert data["hops"] and data["hops"][0]["id"] == R1
    assert data["paths"][0] == data["hops"]
    assert {"id", "label", "type"} <= set(data["hops"][0])


def test_a_trace_to_a_prefix_works_and_so_does_one_to_an_external_route(traced):
    assert (
        ok(traced.get(f"/api/trace?source={R1}&dest=10.0.0.3/32"))["hops"][-1]["id"]
        == R3
    )
    external = ok(traced.get(f"/api/trace?source={R1}&dest=172.16.50.9"))
    assert external["prefix"] == "172.16.50.0/24" and external["spf_cost"] == 21
    assert (
        external["externals"][0]["asbr"] == R3
        and external["externals"][0]["selected"] is True
    )
    assert external["hops"][-1]["id"] == R3


def test_an_address_nothing_covers_is_a_clean_no_route_answer(traced):
    data = ok(traced.get(f"/api/trace?source={R1}&dest=2001:db8::1"))
    assert (
        data["prefix"] is None and data["paths"] == [] and data["verdict"] == "no route"
    )


@pytest.mark.parametrize(
    "query",
    [
        "",
        f"source={R1}",
        "dest=10.0.0.3",
        f"source={R1}&source={R3}&dest=10.0.0.3",
        "source=abc&dest=10.0.0.3",
        f"source={R1}/24&dest=10.0.0.3",
        f"source={R1};rm -rf /&dest=10.0.0.3",
        f"source={R1}&dest=10.0.0.0/33",
        f"source={R1}&dest=not-an-ip",
        f"source={R1}&dest=10.0.0.1/abc",
        f"source={R1}&dest=" + "1" * 70,
        f"source={R1}&dest=%27%20OR%201=1",
        "source=&dest=10.0.0.3",
        "source=%00&dest=10.0.0.3",
    ],
)
def test_a_trace_with_bad_input_is_a_400_never_a_crash(traced, query):
    error(traced.get(f"/api/trace?{query}"), 400)


def test_a_trace_from_a_router_that_is_not_in_the_topology_is_a_404(traced):
    assert "10.7.7.7" in error(
        traced.get("/api/trace?source=10.7.7.7&dest=10.0.0.3"), 404
    )
    network = next(
        n
        for n in traced.engine.load_graph(traced.engine.current_path).nodes
        if n.startswith("net-")
    )
    error(
        traced.get(f"/api/trace?source={network}&dest=10.0.0.3"), 400
    )  # a transit network is not a router ID


def test_a_trace_before_any_run_is_a_404(site):
    assert "no topology" in error(
        site.get(f"/api/trace?source={R1}&dest=10.0.0.3"), 404
    )


# --------------------------------------------------------------------- poll
def test_polling_without_a_poller_is_not_implemented(site):
    error(site.call("POST", "/api/poll"), 501)


def test_a_poll_runs_in_the_background_and_a_second_one_is_refused_meanwhile(tmp_path):
    release, started = threading.Event(), threading.Event()

    def slow_poll() -> int:
        started.set()
        release.wait(5)
        return 0

    site = Site(tmp_path, poll_fn=slow_poll)
    status, body = site.call("POST", "/api/poll")
    assert status == 202 and body["data"]["started"] is True
    assert started.wait(5)
    assert site.app.coordinator.snapshot()["running"] is True
    error(site.call("POST", "/api/poll"), 409)
    assert ok(site.get("/api/status"))["poll"]["running"] is True
    release.set()
    site.app.coordinator.wait(5)
    last = ok(site.get("/api/status"))["poll"]
    assert (
        last["running"] is False
        and last["last"]["exit_code"] == 0
        and last["last"]["error"] is None
    )
    assert last["last"]["trigger"] == "api" and last["last"]["finished"]
    assert (
        site.call("POST", "/api/poll")[0] == 202
    )  # and a new one can start afterwards
    site.app.coordinator.wait(5)


def test_a_poll_that_fails_is_reported_and_the_server_carries_on(tmp_path):
    outcomes = iter(
        [TrackerError("device 192.0.2.1 timed out"), RuntimeError("boom"), 7]
    )

    def poll() -> int:
        result = next(outcomes)
        if isinstance(result, BaseException):
            raise result
        return result

    site = Site(tmp_path, poll_fn=poll)
    seen = []
    for _ in range(3):
        assert site.call("POST", "/api/poll")[0] == 202
        site.app.coordinator.wait(5)
        seen.append(ok(site.get("/api/status"))["poll"]["last"])
    assert (
        seen[0]["error"] == "device 192.0.2.1 timed out"
        and seen[0]["exit_code"] is None
    )
    assert seen[1]["error"] == "RuntimeError: boom"
    assert seen[2]["error"] is None and seen[2]["exit_code"] == 7


def test_a_poll_lock_held_by_the_cli_or_cron_makes_the_api_answer_409(tmp_path):
    site = Site(tmp_path, poll_fn=lambda: 0)
    with PollLock(site.data / ".poll.lock"):
        assert ok(site.get("/api/status"))["poll"]["running"] is True
        error(site.call("POST", "/api/poll"), 409)
    assert site.call("POST", "/api/poll")[0] == 202
    site.app.coordinator.wait(5)


def test_the_coordinator_without_a_poll_function_refuses_to_trigger(tmp_path):
    coordinator = PollCoordinator(None, tmp_path / ".poll.lock")
    assert coordinator.configured is False
    with pytest.raises(RuntimeError):
        coordinator.trigger()


def test_a_poll_that_loses_the_race_for_the_lock_is_recorded_as_skipped(tmp_path):
    def poll() -> int:
        raise PollBusyError("Another poll is already running; this run was skipped")

    coordinator = PollCoordinator(poll, tmp_path / ".poll.lock")
    assert coordinator.trigger("test") is True
    coordinator.wait(5)
    assert "already running" in coordinator.snapshot()["last"]["error"]


# ------------------------------------------------------------- HTTP details
@pytest.fixture
def live(tmp_path):
    """A real server on a free port, serving in a thread."""
    site = Site(tmp_path, poll_fn=lambda: 0)
    server = create_server(
        "127.0.0.1", 0, data_dir=site.data, output_html=site.page, poll_fn=lambda: 0
    )
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    site.server = server
    site.request = lambda method, path, **kw: _request(
        server.server_port, method, path, **kw
    )
    yield site
    server.shutdown()
    server.server_close()
    thread.join(5)


def _request(port: int, method: str, path: str, body: bytes | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def test_real_requests_get_json_with_safe_headers(live):
    status, headers, body = live.request("GET", "/api/status")
    assert (
        status == 200 and headers["Content-Type"] == "application/json; charset=utf-8"
    )
    assert (
        headers["X-Content-Type-Options"] == "nosniff"
        and headers["Cache-Control"] == "no-store"
    )
    assert (
        int(headers["Content-Length"]) == len(body)
        and json.loads(body)["status"] == "ok"
    )
    assert "Python" not in headers.get(
        "Server", ""
    )  # no interpreter version in the banner


def test_the_page_is_served_over_http_and_head_has_no_body(live):
    live.page.parent.mkdir(parents=True)
    live.page.write_text("<html>topology</html>", encoding="utf-8")
    status, headers, body = live.request("GET", "/")
    assert (status, body) == (200, b"<html>topology</html>") and headers[
        "Cache-Control"
    ] == "no-cache"
    status, headers, body = live.request("HEAD", "/")
    assert (
        status == 200
        and body == b""
        and int(headers["Content-Length"]) == len("<html>topology</html>")
    )


def test_unknown_paths_and_traversal_attempts_never_reach_a_file(live):
    secret = live.page.parent.parent / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    for path in (
        "/nope",
        "/api",
        "/api/",
        "/api/nope",
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/api/../secret.txt",
        "/secret.txt",
        "//secret.txt",
        "/api/history/../../secret.txt",
        "/output/topology.html",
    ):
        status, _headers, body = live.request("GET", path)
        assert status in (400, 404) and b"TOP SECRET" not in body, path


def test_wrong_methods_are_a_405_with_an_allow_header(live):
    status, headers, body = live.request("GET", "/api/poll")
    assert (
        status == 405
        and headers["Allow"] == "POST"
        and json.loads(body)["status"] == "error"
    )
    status, headers, _ = live.request("POST", "/api/status")
    assert status == 405 and headers["Allow"] == "GET"
    for verb in ("PUT", "DELETE", "PATCH"):
        status, headers, body = live.request(verb, "/api/history")
        assert (
            status == 405
            and "GET" in headers["Allow"]
            and json.loads(body)["status"] == "error"
        )


def test_a_post_with_a_body_still_works_and_many_clients_can_be_served_at_once(live):
    status, _headers, _body = live.request("POST", "/api/poll", body=b"x" * 5000)
    assert status == 202
    live.server.app.coordinator.wait(5)
    results = []

    def hit():
        results.append(live.request("GET", "/api/status")[0])

    threads = [threading.Thread(target=hit) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert results == [200] * 20


# ----------------------------------------------------------------- scheduler
def test_the_scheduler_polls_at_its_interval_until_stopped(tmp_path):
    calls = []
    server = create_server(
        "127.0.0.1",
        0,
        data_dir=tmp_path / "data",
        output_html=tmp_path / "p.html",
        poll_fn=lambda: calls.append(time.monotonic()) or 0,
        poll_interval=0.05,
    )
    assert isinstance(server.app.scheduler, PollScheduler)
    thread = threading.Thread(target=run_server, args=(server,), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while len(calls) < 3 and time.monotonic() < deadline:
        time.sleep(0.02)
    server.shutdown()
    thread.join(5)
    assert len(calls) >= 3 and not thread.is_alive()
    settled = len(calls)
    time.sleep(0.2)
    assert len(calls) == settled  # stopped with the server


def test_without_an_interval_or_a_poll_function_there_is_no_schedule(tmp_path):
    for kwargs in ({"poll_interval": 30}, {"poll_fn": lambda: 0}):
        server = create_server(
            "127.0.0.1", 0, data_dir=tmp_path, output_html=tmp_path / "p.html", **kwargs
        )
        try:
            assert server.app.scheduler is None
        finally:
            server.server_close()


# ----------------------------------------------------------- settings & CLI
def test_server_options_take_the_flag_then_the_environment_then_the_file(monkeypatch):
    for key in ("OSPF_MONITOR_HOST", "OSPF_MONITOR_PORT", "OSPF_MONITOR_POLL_INTERVAL"):
        monkeypatch.delenv(key, raising=False)
    assert ServerOptions.from_settings({}) == ServerOptions("127.0.0.1", 8080, 0)
    settings = {"server": {"host": "0.0.0.0", "port": 9000, "poll_interval": 300}}
    assert ServerOptions.from_settings(settings) == ServerOptions("0.0.0.0", 9000, 300)
    monkeypatch.setenv("OSPF_MONITOR_PORT", "9100")
    monkeypatch.setenv("OSPF_MONITOR_POLL_INTERVAL", "60")
    assert ServerOptions.from_settings(settings) == ServerOptions("0.0.0.0", 9100, 60)
    assert (
        ServerOptions.from_settings(settings, port=9200).port == 9200
    )  # --port beats the environment


@pytest.mark.parametrize(
    "settings",
    [
        {"server": "x"},
        {"server": {"port": 70000}},
        {"server": {"port": -1}},
        {"server": {"port": "abc"}},
        {"server": {"poll_interval": -5}},
        {"server": {"host": "bad host;rm"}},
        {"server": {"host": "a/b"}},
    ],
)
def test_bad_server_settings_are_config_errors(settings, monkeypatch):
    for key in ("OSPF_MONITOR_HOST", "OSPF_MONITOR_PORT", "OSPF_MONITOR_POLL_INTERVAL"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ConfigError):
        ServerOptions.from_settings(settings)


def test_serve_cannot_be_combined_with_dry_run_or_trace(env, caplog):
    assert env.run("--serve", "--dry-run") == main.EXIT_ERROR
    assert "cannot be combined" in caplog.text
    caplog.clear()
    assert env.run("--serve", "--trace", "10.0.0.3") == main.EXIT_ERROR
    assert env.network.connected == []


def test_serve_starts_the_server_with_the_cli_options_and_a_poll_runs_the_whole_pipeline(
    env, monkeypatch, capsys
):
    monkeypatch.setattr(main, "OUTPUT_HTML", env.tmp / "page.html")
    monkeypatch.delenv("OSPF_MONITOR_PORT", raising=False)
    captured = {}

    def fake_run_server(
        server,
    ):  # stand in for serve_forever: poll once through the real coordinator
        captured["server"] = server
        assert server.app.coordinator.trigger("test") is True
        server.app.coordinator.wait(30)
        captured["status"] = server.app.handle("GET", "/api/status")
        server.server_close()

    monkeypatch.setattr("src.web.server.run_server", fake_run_server)
    assert env.run("--serve", "--port", "0") == main.EXIT_OK
    out = capsys.readouterr().out
    assert "Serving the OSPF topology explorer on http://127.0.0.1:" in out
    last = captured["server"].app.coordinator.snapshot()["last"]
    assert last["exit_code"] == main.EXIT_OK and last["error"] is None
    assert (env.data / "current_state.json").exists() and (
        env.tmp / "page.html"
    ).exists()
    status = json.loads(captured["status"].body)["data"]
    assert status["has_topology"] and status["history_runs"] == 1
    assert status["node_count"] == 4  # the merged two-area fixture: R1..R4


# ------------------------------------------------------------------ the lock
def test_a_cli_run_is_refused_while_another_poll_holds_the_lock(env, caplog, capsys):
    with PollLock(env.data / ".poll.lock"):
        assert env.run() == main.EXIT_ERROR
    assert "Another poll is already running" in caplog.text
    assert (
        env.network.connected == [] and not (env.data / "current_state.json").exists()
    )
    assert "Aborted" not in capsys.readouterr().out
    assert env.run() == main.EXIT_OK  # and it is free again afterwards
    assert not PollLock.is_held(env.data / ".poll.lock")


def test_a_dry_run_does_not_need_the_lock(env):
    with PollLock(env.data / ".poll.lock"):
        assert env.run("--dry-run") == main.EXIT_OK


def test_the_lock_is_released_even_when_the_run_fails(env):
    env.network.devices.clear()  # every seed unreachable
    assert env.run() != main.EXIT_OK
    assert not PollLock.is_held(env.data / ".poll.lock")


def test_a_poll_blocked_by_the_lock_does_not_send_a_failure_alert(env, monkeypatch):
    sent = []
    monkeypatch.setattr(
        "main.TelegramNotifier.send_message",
        lambda self, *a, **k: sent.append(a) or True,
        raising=False,
    )
    with PollLock(env.data / ".poll.lock"):
        env.run()
    assert sent == []


def test_every_page_write_is_atomic_so_the_server_never_serves_half_a_page(
    tmp_path, monkeypatch
):
    from src.explorer import write_explorer
    from tests.explorer_fixture import realistic

    target = tmp_path / "topology.html"
    write_explorer(target, realistic(), TopologyDiff())
    good = target.read_text(encoding="utf-8")
    monkeypatch.setattr(
        "os.replace", lambda *a: (_ for _ in ()).throw(OSError("disk full"))
    )
    with pytest.raises(OSError):
        write_explorer(target, deepcopy(realistic()), TopologyDiff())
    assert target.read_text(encoding="utf-8") == good and [
        p.name for p in tmp_path.iterdir()
    ] == ["topology.html"]
