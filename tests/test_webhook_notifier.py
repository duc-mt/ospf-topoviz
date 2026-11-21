"""Unit tests for WebhookNotifier and NotifierDispatcher."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from src.events import TopologyEvent
from src.notifier.dispatcher import NotifierDispatcher
from src.notifier.telegram import TelegramConfig, TelegramNotifier
from src.notifier.webhook import WebhookConfig, WebhookNotifier


def _ev(etype: str = "link_down", severity: str = "warning") -> TopologyEvent:
    return TopologyEvent(
        event_id="run-1:1",
        run_id="run-1",
        timestamp="2026-11-21T12:00:00+00:00",
        event_type=etype,
        event_name="metric",
        object_status="down",
        severity=severity,
        object_id="10.0.0.2",
        detected_by="10.0.0.1",
        area="0.0.0.0",
        summary="Link down: 10.0.0.1 -> 10.0.0.2",
        details={},
    )


def test_webhook_slack_payload_format_and_severity_filter() -> None:
    cfg = WebhookConfig(
        name="slack-noc",
        enabled=True,
        url="https://hooks.example.test/services/123",
        format="slack",
        min_severity="warning",
    )
    notifier = WebhookNotifier(cfg)
    payload = notifier.format_payload("OSPF Changed", "1 link down", "critical", {"target": "OSPF"})
    assert "blocks" in payload
    assert "*OSPF Changed*" in payload["blocks"][0]["text"]["text"]

    # Info below min_severity="warning" should be filtered out without HTTP request
    with patch("urllib.request.urlopen") as mock_open:
        assert notifier.send_alert("Heartbeat", "In Sync", level="info") is False
        assert not mock_open.called

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_open.return_value = mock_resp
        assert notifier.send_alert("Alert", "Link down", level="warning") is True
        assert mock_open.called
        req = mock_open.call_args[0][0]
        sent = json.loads(req.data.decode("utf-8"))
        assert "blocks" in sent


def test_webhook_teams_discord_generic_formats() -> None:
    for fmt, key in (("teams", "@type"), ("discord", "content"), ("generic", "title")):
        n = WebhookNotifier(WebhookConfig(enabled=True, url="https://x.test", format=fmt))
        p = n.format_payload("Title", "Body", "warning")
        assert key in p


def test_webhook_event_type_filter_skips_unsubscribed_events() -> None:
    n = WebhookNotifier(
        WebhookConfig(
            enabled=True,
            url="https://hooks.example.test/1",
            events=["link_down"],
        )
    )
    assert n.matches_events([_ev("link_down")]) is True
    assert n.matches_events([_ev("node_added")]) is False


def test_dispatcher_routes_to_telegram_and_multiple_webhooks_without_raising() -> None:
    tg = MagicMock(spec=TelegramNotifier)
    tg.config = TelegramConfig(enabled=True, bot_token="t", chat_id="1", min_severity="info")
    tg.send_alert.return_value = True

    wh_fail = WebhookNotifier(WebhookConfig(name="bad", enabled=True, url="https://bad.invalid"))
    wh_ok = WebhookNotifier(WebhookConfig(name="good", enabled=True, url="https://good.test"))

    with (
        patch.object(wh_fail, "send_alert", side_effect=RuntimeError("boom")),
        patch.object(wh_ok, "send_alert", return_value=True) as mock_ok,
    ):
        disp = NotifierDispatcher(telegram=tg, webhooks=[wh_fail, wh_ok])
        disp.dispatch_alert(
            title="OSPF Topology Changed",
            message="Link down",
            level="warning",
            events=[_ev("link_down")],
        )
        assert tg.send_alert.called
        assert mock_ok.called
