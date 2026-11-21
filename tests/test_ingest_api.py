"""Unit tests for POST /api/ingest/lsdb and debounced IngestCoordinator."""

from __future__ import annotations

import json
import time

from src.web.server import WebApp


def _sample_ingest_payload(metric: int = 10, rid: str = "10.0.0.2") -> dict:
    return {
        "source": "bgpls-or-sidecar",
        "mode": "snapshot",
        "lsdb": {
            "router_lsas": [
                {
                    "router_id": "10.0.0.1",
                    "area": "0.0.0.0",
                    "links": [
                        {
                            "kind": "p2p",
                            "link_id": rid,
                            "metric": metric,
                            "link_data": "10.12.0.1",
                        }
                    ],
                },
                {
                    "router_id": rid,
                    "area": "0.0.0.0",
                    "links": [
                        {
                            "kind": "p2p",
                            "link_id": "10.0.0.1",
                            "metric": 10,
                            "link_data": "10.12.0.2",
                        }
                    ],
                },
            ],
            "network_lsas": [],
        },
    }


def test_ingest_requires_bearer_token_when_configured_returns_401(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("OSPF_MONITOR_INGEST_TOKEN", "secret-token-123")
    app = WebApp(tmp_path / "data", tmp_path / "topology.html")
    body = json.dumps(_sample_ingest_payload()).encode("utf-8")

    unauth = app.handle("POST", "/api/ingest/lsdb", body=body, headers={})
    assert unauth.status == 401

    wrong = app.handle(
        "POST",
        "/api/ingest/lsdb",
        body=body,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert wrong.status == 401

    ok_resp = app.handle(
        "POST",
        "/api/ingest/lsdb",
        body=body,
        headers={"Authorization": "Bearer secret-token-123"},
    )
    assert ok_resp.status in (200, 202)


def test_ingest_valid_lsdb_updates_baseline_events_and_broadcasts_sse(tmp_path) -> None:
    app = WebApp(tmp_path / "data", tmp_path / "topology.html")
    sub = app.broker.subscribe()
    try:
        # 1. Initial baseline ingest
        r1 = app.handle(
            "POST",
            "/api/ingest/lsdb",
            body=json.dumps(_sample_ingest_payload(metric=10)).encode("utf-8"),
        )
        assert r1.status in (200, 202)
        assert app.current_graph() is not None

        # 2. Metric change ingest produces event + SSE frame
        r2 = app.handle(
            "POST",
            "/api/ingest/lsdb",
            body=json.dumps(_sample_ingest_payload(metric=75)).encode("utf-8"),
        )
        assert r2.status in (200, 202)
        events, total = app.history.query_events(event_type="link_cost_changed")
        assert total == 1
        assert events[0]["details"]["new_metric"] == 75
        assert not sub.empty()
    finally:
        app.broker.unsubscribe(sub)


def test_ingest_burst_is_debounced_into_single_pipeline_run(tmp_path) -> None:
    from src.realtime.ingest import IngestCoordinator

    app = WebApp(tmp_path / "data", tmp_path / "topology.html")
    coord = IngestCoordinator(
        app.data_dir,
        app.engine,
        app.broker,
        debounce_seconds=0.25,
    )
    for m in range(10, 20):
        res = coord.submit(_sample_ingest_payload(metric=m))
        assert res["accepted"] is True
        assert res["queued"] is True
        time.sleep(0.01)

    coord.wait(timeout=3.0)
    assert app.history.count() == 1
    g = app.current_graph()
    assert g is not None
    assert g.edges["10.0.0.1", "10.0.0.2"]["metric"] == 19
