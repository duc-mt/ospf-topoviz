"""Unit tests for CLI alerting alignment and --test-telegram flag in ospf-topoviz."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import main as cli
from src import TrackerError
from src.graph_engine import TopologyDiff
from src.notifier import TelegramConfig, TelegramNotifier


def test_test_telegram_flag_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
        min_severity="warning",
    )
    mock_notifier.send_alert.return_value = True

    monkeypatch.setattr(
        cli, "build_telegram_notifier", lambda settings=None: mock_notifier
    )

    code = cli.main(["--test-telegram"])
    assert code == cli.EXIT_OK
    assert mock_notifier.send_alert.called
    out = capsys.readouterr().out
    assert "Test alert successfully delivered" in out


def test_test_telegram_flag_disabled(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=False,
        bot_token="test_tok",
        chat_id="123456",
    )

    monkeypatch.setattr(
        cli, "build_telegram_notifier", lambda settings=None: mock_notifier
    )

    code = cli.main(["--test-telegram"])
    assert code == cli.EXIT_ERROR
    out = capsys.readouterr().out
    assert "Telegram alerting is disabled" in out


def test_test_telegram_flag_missing_creds(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="",
        chat_id="",
    )

    monkeypatch.setattr(
        cli, "build_telegram_notifier", lambda settings=None: mock_notifier
    )

    code = cli.main(["--test-telegram"])
    assert code == cli.EXIT_ERROR
    out = capsys.readouterr().out
    assert "bot_token or chat_id is missing" in out


def test_main_tracker_error_dispatches_critical_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
    )

    monkeypatch.setattr(
        cli, "build_telegram_notifier", lambda settings=None: mock_notifier
    )

    def fail_run(args, notifier=None):
        raise TrackerError("Simulated unrecoverable seed error")

    monkeypatch.setattr(cli, "run", fail_run)

    code = cli.main(["--dry-run"])
    assert code == cli.EXIT_ERROR
    assert mock_notifier.send_alert.called
    call_args = mock_notifier.send_alert.call_args
    assert call_args.kwargs.get("title") == "OSPF Pipeline Aborted"
    assert call_args.kwargs.get("level") == "critical"
    assert "Simulated unrecoverable seed error" in call_args.kwargs.get("message")


def test_main_unexpected_error_dispatches_critical_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
    )

    monkeypatch.setattr(
        cli, "build_telegram_notifier", lambda settings=None: mock_notifier
    )

    def crash_run(args, notifier=None):
        raise RuntimeError("Unexpected pipeline crash")

    monkeypatch.setattr(cli, "run", crash_run)

    code = cli.main(["--dry-run"])
    assert code == cli.EXIT_UNEXPECTED
    assert mock_notifier.send_alert.called
    call_args = mock_notifier.send_alert.call_args
    assert call_args.kwargs.get("title") == "OSPF Pipeline Crash"
    assert call_args.kwargs.get("level") == "critical"


def test_dispatch_alerts_in_sync_sends_info_heartbeat() -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
        min_severity="info",
    )

    diff = TopologyDiff(
        added_nodes=set(),
        removed_nodes=set(),
        added_edges=set(),
        removed_edges=set(),
        findings=[],
        baseline_updated=True,
    )
    graph = {
        "nodes": [{"id": "1.1.1.1"}],
        "edges": [{"source": "1.1.1.1", "target": "2.2.2.2"}],
    }

    cli.dispatch_alerts(
        settings={},
        diff=diff,
        graph=graph,
        notifier=mock_notifier,
    )

    assert mock_notifier.send_alert.called
    call_args = mock_notifier.send_alert.call_args
    assert call_args.kwargs.get("title") == "OSPF Topology In Sync"
    assert call_args.kwargs.get("level") == "info"
    assert "1 router(s)" in call_args.kwargs.get("message")
