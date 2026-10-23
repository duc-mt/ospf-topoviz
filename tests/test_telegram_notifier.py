"""Unit tests for TelegramNotifier."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from src.notifier.telegram import TelegramConfig, TelegramNotifier


@pytest.fixture
def base_config() -> TelegramConfig:
    return TelegramConfig(
        enabled=True,
        bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        chat_id="987654321",
        min_severity="warning",
        cooldown_seconds=300,
    )


def test_telegram_config_from_dict_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Test fallback to env vars
    monkeypatch.setenv("TELEGRAM_ENABLED", "true")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "env_token_123")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123456789")
    monkeypatch.setenv("TELEGRAM_MESSAGE_THREAD_ID", "42")
    monkeypatch.setenv("TELEGRAM_MIN_SEVERITY", "critical")
    monkeypatch.setenv("TELEGRAM_COOLDOWN_SECONDS", "60")
    monkeypatch.setenv("TELEGRAM_SILENT", "true")
    monkeypatch.setenv("TELEGRAM_PROXY_URL", "http://proxy.local:8080")

    cfg = TelegramConfig.from_dict({})
    assert cfg.enabled is True
    assert cfg.bot_token == "env_token_123"
    assert cfg.chat_id == "-100123456789"
    assert cfg.thread_id == 42
    assert cfg.min_severity == "critical"
    assert cfg.cooldown_seconds == 60
    assert cfg.silent is True
    assert cfg.proxy == "http://proxy.local:8080"


def test_telegram_notifier_disabled() -> None:
    notifier = TelegramNotifier(TelegramConfig(enabled=False))
    assert notifier.send_alert("Test", "Message", "critical") is False


def test_telegram_notifier_missing_credentials() -> None:
    notifier = TelegramNotifier(TelegramConfig(enabled=True, bot_token="", chat_id=""))
    assert notifier.send_alert("Test", "Message", "critical") is False


def test_telegram_notifier_severity_filtering(base_config: TelegramConfig) -> None:
    base_config.min_severity = "warning"
    notifier = TelegramNotifier(base_config)
    # "info" should be filtered out
    assert notifier.send_alert("Info Title", "Info body", level="info") is False


def test_telegram_notifier_cooldown(base_config: TelegramConfig) -> None:
    notifier = TelegramNotifier(base_config)
    with patch.object(notifier, "_http_request", return_value={"ok": True}):
        # First send succeeds
        assert (
            notifier.send_alert("Flap Event", "Neighbor down", level="critical") is True
        )
        # Second send within cooldown is suppressed
        assert (
            notifier.send_alert("Flap Event", "Neighbor down", level="critical")
            is False
        )
        # Different title is not suppressed
        assert (
            notifier.send_alert(
                "Different Event", "Other neighbor down", level="critical"
            )
            is True
        )


def test_telegram_notifier_send_text_success(base_config: TelegramConfig) -> None:
    notifier = TelegramNotifier(base_config)
    mock_resp = {"ok": True, "result": {"message_id": 100}}

    with patch.object(notifier, "_http_request", return_value=mock_resp) as mock_req:
        ok = notifier.send_alert(
            title="Link Flap <test>",
            message="OSPF dropped & recovered",
            level="warning",
            metadata={"target": "core-router-1", "footer": "Check tun0"},
        )
        assert ok is True
        mock_req.assert_called_once()
        endpoint = mock_req.call_args.args[0]
        data = mock_req.call_args.kwargs.get("data")
        assert endpoint == "sendMessage"
        assert data is not None
        payload = json.loads(data.decode("utf-8"))
        assert payload["chat_id"] == "987654321"
        assert payload["parse_mode"] == "HTML"
        # Verify HTML escaping
        assert "&lt;test&gt;" in payload["text"]
        assert "&amp;" in payload["text"]
        assert "core-router-1" in payload["text"]


def test_telegram_notifier_long_text_overflow(base_config: TelegramConfig) -> None:
    notifier = TelegramNotifier(base_config)
    mock_resp = {"ok": True, "result": {"message_id": 101}}

    with patch.object(notifier, "_http_request", return_value=mock_resp) as mock_req:
        long_message = "A" * 5000
        ok = notifier.send_alert(
            title="Massive Log",
            message=long_message,
            level="critical",
        )
        assert ok is True
        # Exceeds 4096 chars -> should sendDocument
        endpoint = mock_req.call_args[0][0]
        assert endpoint == "sendDocument"


def test_telegram_notifier_send_photo(
    base_config: TelegramConfig, tmp_path: Path
) -> None:
    notifier = TelegramNotifier(base_config)
    img_file = tmp_path / "topology.png"
    img_file.write_bytes(b"\x89PNG\r\n\x1a\nfakeimagecontent")

    mock_resp = {"ok": True, "result": {"message_id": 102}}
    with patch.object(notifier, "_http_request", return_value=mock_resp) as mock_req:
        ok = notifier.send_alert(
            title="Topology Update",
            message="New network topology generated",
            level="warning",
            attachment_path=str(img_file),
        )
        assert ok is True
        endpoint = mock_req.call_args[0][0]
        assert endpoint == "sendPhoto"


def test_telegram_notifier_attachment_not_found_fallback(
    base_config: TelegramConfig,
) -> None:
    notifier = TelegramNotifier(base_config)
    mock_resp = {"ok": True, "result": {"message_id": 103}}

    with patch.object(notifier, "_http_request", return_value=mock_resp) as mock_req:
        ok = notifier.send_alert(
            title="Missing File",
            message="File doesn't exist",
            level="warning",
            attachment_path="/nonexistent/file/path.png",
        )
        assert ok is True
        # Falls back to sendMessage
        endpoint = mock_req.call_args[0][0]
        assert endpoint == "sendMessage"


def test_telegram_notifier_zero_crash_on_network_error(
    base_config: TelegramConfig,
) -> None:
    notifier = TelegramNotifier(base_config)
    # Simulate network timeout/error
    with patch(
        "urllib.request.OpenerDirector.open",
        side_effect=urllib.error.URLError("Connection refused"),
    ):
        # Must return False and not raise
        assert (
            notifier.send_alert("Network Down", "Test message", level="critical")
            is False
        )


def test_telegram_notifier_rate_limit_429_retry(base_config: TelegramConfig) -> None:
    notifier = TelegramNotifier(base_config)

    # First call returns 429, second succeeds
    err_429 = urllib.error.HTTPError(
        url="https://api.telegram.org",
        code=429,
        msg="Too Many Requests",
        hdrs={},
        fp=io.BytesIO(b'{"ok": false, "parameters": {"retry_after": 1}}'),
    )
    success_resp = io.BytesIO(b'{"ok": true, "result": {}}')

    with patch(
        "urllib.request.OpenerDirector.open", side_effect=[err_429, success_resp]
    ), patch("time.sleep") as mock_sleep:
        ok = notifier.send_alert("Retry Test", "429 test", level="critical")
        assert ok is True
        mock_sleep.assert_called_once_with(1)
