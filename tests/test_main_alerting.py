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


def test_dispatch_alerts_info_findings_only_routes_to_heartbeat() -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
        min_severity="warning",
    )

    diff = TopologyDiff(
        added_nodes=set(),
        removed_nodes=set(),
        added_edges=set(),
        removed_edges=set(),
        findings=[
            {
                "category": "route",
                "kind": "STALE ROUTE",
                "severity": "info",
                "router": "10.255.255.10",
                "subject": "10.0.98.32/30",
                "message": "10.0.98.32/30: stale route in RIB",
            }
        ],
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
    assert "0 anomalies" in call_args.kwargs.get("message")


def test_dispatch_alerts_dict_warning_finding() -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
        min_severity="warning",
    )

    diff = TopologyDiff(
        added_nodes=set(),
        removed_nodes=set(),
        added_edges=set(),
        removed_edges=set(),
        findings=[
            {
                "category": "neighbor",
                "kind": "ADJ_LOADING",
                "severity": "warning",
                "router": "10.255.255.1",
                "subject": "10.255.255.2",
                "message": "Neighbor 10.255.255.2 stuck in Loading state",
            }
        ],
        baseline_updated=True,
    )
    graph = {"nodes": [], "edges": []}

    cli.dispatch_alerts(
        settings={},
        diff=diff,
        graph=graph,
        notifier=mock_notifier,
    )

    assert mock_notifier.send_alert.called
    call_args = mock_notifier.send_alert.call_args
    assert call_args.kwargs.get("title") == "OSPF Topology Anomaly Detected"
    assert call_args.kwargs.get("level") == "warning"
    assert "Neighbor 10.255.255.2 stuck in Loading state" in call_args.kwargs.get(
        "message"
    )


def test_dispatch_alerts_dict_critical_finding() -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
        min_severity="warning",
    )

    diff = TopologyDiff(
        added_nodes=set(),
        removed_nodes=set(),
        added_edges=set(),
        removed_edges=set(),
        findings=[
            {
                "category": "neighbor",
                "kind": "ADJ_DOWN",
                "severity": "critical",
                "router": "10.255.255.1",
                "subject": "10.255.255.3",
                "message": "Adjacency down with 10.255.255.3",
            }
        ],
        baseline_updated=True,
    )
    graph = {"nodes": [], "edges": []}

    cli.dispatch_alerts(
        settings={},
        diff=diff,
        graph=graph,
        notifier=mock_notifier,
    )

    assert mock_notifier.send_alert.called
    call_args = mock_notifier.send_alert.call_args
    assert call_args.kwargs.get("title") == "OSPF Topology Anomaly Detected"
    assert call_args.kwargs.get("level") == "critical"
    assert "Adjacency down with 10.255.255.3" in call_args.kwargs.get("message")


def test_dispatch_alerts_in_sync_with_digraph() -> None:
    import networkx as nx

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

    dg = nx.DiGraph()
    dg.add_node("1.1.1.1")
    dg.add_node("2.2.2.2")
    dg.add_edge("1.1.1.1", "2.2.2.2")

    cli.dispatch_alerts(
        settings={},
        diff=diff,
        graph=dg,
        notifier=mock_notifier,
    )

    assert mock_notifier.send_alert.called
    call_args = mock_notifier.send_alert.call_args
    assert call_args.kwargs.get("title") == "OSPF Topology In Sync"
    assert call_args.kwargs.get("level") == "info"
    assert "2 router(s), 1 link(s) active" in call_args.kwargs.get("message")


def test_dispatch_alerts_triggers_on_changed_metrics() -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
        min_severity="warning",
    )

    diff = TopologyDiff(
        baseline_available=True,
        changed_metrics=[
            {
                "source": "1.1.1.1",
                "target": "2.2.2.2",
                "old_metric": 10,
                "new_metric": 100,
                "area": "0.0.0.0",
            }
        ],
        baseline_updated=True,
    )
    graph = {"nodes": [{"id": "1.1.1.1"}, {"id": "2.2.2.2"}], "edges": []}

    cli.dispatch_alerts(
        settings={},
        diff=diff,
        graph=graph,
        notifier=mock_notifier,
    )

    assert mock_notifier.send_alert.called
    call_args = mock_notifier.send_alert.call_args
    assert call_args.kwargs.get("title") == "OSPF Topology Changed"
    assert call_args.kwargs.get("level") == "warning"
    assert "Changed metrics: 1" in call_args.kwargs.get("message")


def test_dispatch_alerts_triggers_on_flag_prefix_and_te_diffs() -> None:
    mock_notifier = MagicMock(spec=TelegramNotifier)
    mock_notifier.config = TelegramConfig(
        enabled=True,
        bot_token="test_tok",
        chat_id="123456",
        min_severity="warning",
    )

    diff = TopologyDiff(
        baseline_available=True,
        changed_node_flags=[
            {
                "id": "1.1.1.1",
                "label": "1.1.1.1",
                "attribute": "max_metric",
                "old": False,
                "new": True,
                "areas": ["0.0.0.0"],
            }
        ],
        changed_prefixes=[
            {
                "action": "added",
                "prefix": "10.99.0.0/24",
                "router": "1.1.1.1",
                "kind": "stub",
                "subtype": None,
                "area": "0.0.0.0",
                "old_metric": None,
                "new_metric": 1,
            }
        ],
        changed_te=[
            {
                "source": "1.1.1.1",
                "target": "2.2.2.2",
                "area": "0.0.0.0",
                "local_ip": "10.0.0.1",
                "remote_ip": "10.0.0.2",
                "changes": {"srlgs": {"old": [], "new": [100]}},
            }
        ],
        baseline_updated=True,
    )
    graph = {"nodes": [{"id": "1.1.1.1"}], "edges": []}

    cli.dispatch_alerts(
        settings={},
        diff=diff,
        graph=graph,
        notifier=mock_notifier,
    )

    assert mock_notifier.send_alert.called
    call_args = mock_notifier.send_alert.call_args
    assert call_args.kwargs.get("title") == "OSPF Topology Changed"
    assert call_args.kwargs.get("level") == "warning"
    msg = call_args.kwargs.get("message")
    assert "Changed flags: 1" in msg
    assert "Changed prefixes: 1" in msg
    assert "Changed TE: 1" in msg


def test_settings_example_parses_cleanly_into_guard_and_visual_options() -> None:
    from pathlib import Path
    import yaml
    from src.graph_engine import GuardConfig
    from src.visualizer import VisualOptions

    raw = yaml.safe_load(
        Path("config/settings.yaml.example").read_text(encoding="utf-8")
    )
    guard_cfg = GuardConfig.from_settings(raw.get("guard"))
    vis_cfg = VisualOptions.from_settings(raw.get("visualization"))

    assert "min_node_retention" in (raw.get("guard") or {})
    assert guard_cfg.min_node_retention == pytest.approx(raw["guard"]["min_node_retention"])
    assert "rankdir" in (raw.get("visualization") or {})
    assert vis_cfg.rankdir == raw["visualization"]["rankdir"]
    assert "show_interfaces" in (raw.get("visualization") or {})
    assert vis_cfg.show_interfaces is raw["visualization"]["show_interfaces"]
    assert "cost_weighted_lines" in (raw.get("visualization") or {})
    assert vis_cfg.cost_weighted_lines is raw["visualization"]["cost_weighted_lines"]


def test_legacy_guard_and_visual_config_aliases_fallback() -> None:
    from src.graph_engine import GuardConfig
    from src.visualizer import VisualOptions

    guard_cfg = GuardConfig.from_settings({"min_known_ratio": 0.65})
    assert guard_cfg.min_node_retention == pytest.approx(0.65)

    vis_cfg = VisualOptions.from_settings({"direction": "LR", "show_addresses": False})
    assert vis_cfg.rankdir == "LR"
    assert vis_cfg.show_interfaces is False
