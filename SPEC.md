# Specification: Alignment of Telegram Alerting & Scheduling with LLDP TopoViz

## 1. Problem Statement & Motivation
In `ospf-topoviz`, Telegram notifications are currently dispatched only when state diffs or anomaly findings are detected during a crawl. Furthermore, the repository lacks:
1. An ad-hoc `--test-telegram` CLI option to verify bot tokens, network connectivity, and chat IDs without waiting for cron or running a network crawl.
2. Top-level crash alerting: if `TrackerError` or unhandled exceptions occur during execution, the poller logs to stderr but cannot notify operators on Telegram.
3. Informational heartbeat reporting on clean runs when `min_severity="info"`.
4. Concurrency-safe cron runner script (`scripts/run_ospf_cron.sh` with `flock`) and systemd unit files (`systemd/ospf-topoviz.service` & `timer`).
5. Complete operations documentation (`docs/TELEGRAM_ALERTING.md`).

Aligning `ospf-topoviz` with `lldp-topoviz` ensures operational consistency, predictable scheduling, and instant manual verifiability across both network visualization tools.

## 2. Requirements & Scope
- **In Scope**:
  - Add `--test-telegram` argument to `main.py` CLI parser to dispatch a test alert using current `.env` and `settings.yaml` parameters and exit.
  - Implement top-level error/crash alerting in `main()` so that any `TrackerError` or unexpected Python crash triggers a `critical` severity Telegram alert.
  - Add clean run heartbeat support in `dispatch_alerts()`: when no changes/findings exist and baseline is intact, dispatch an `info`-level alert (sent when `min_severity="info"`).
  - Create `scripts/run_ospf_cron.sh` with `flock` non-blocking file locking (`/tmp/ospf_topoviz.lock`), automated `.env` sourcing, and proper exit code forwarding.
  - Create `systemd/ospf-topoviz.service` and `systemd/ospf-topoviz.timer` (15-minute cadence, hardened unit configuration).
  - Add comprehensive operations guide in `docs/TELEGRAM_ALERTING.md`.
  - Add unit tests for `--test-telegram` and crash notifications.

- **Out of Scope (Non-Goals)**:
  - Modifying LSDB parsing, Dijkstra graph computation, or vendor poller modules.
  - Adding bidirectional Telegram bot command handlers (polling/webhooks).

## 3. Technical Design & Contracts
- **CLI Interface**:
  - `python main.py --test-telegram` or `./run --test-telegram`:
    - Reads `alerting.telegram` from settings and overlays `TELEGRAM_*` environment variables.
    - Validates bot token and chat ID.
    - Sends a test alert at `warning` severity with operational metadata.
    - Returns `EXIT_OK` (0) on success, `EXIT_ERROR` (1) on failure.
- **Top-Level Alerting Wrapper**:
  - In `main()`:
    - Instantiate `TelegramNotifier` before executing `run(args)`.
    - If `TrackerError` is raised: send `critical` alert titled `"OSPF Pipeline Aborted"`.
    - If unexpected `Exception` is raised: send `critical` alert titled `"OSPF Pipeline Crash"`.
- **Concurrency Locking**:
  - `flock -n 200` on `/tmp/ospf_topoviz.lock` within `scripts/run_ospf_cron.sh`.

## 4. Verification & Acceptance Criteria
- [ ] Criterion 1: `./run --test-telegram` successfully sends a test notification to Telegram and exits `0`.
- [ ] Criterion 2: `./scripts/run_ospf_cron.sh` successfully sources `.env`, respects `flock`, and executes `main.py`.
- [ ] Criterion 3: Unit tests verify `--test-telegram`, disabled state, and crash alerts.
- [ ] Criterion 4: All linters (`ruff check`, `ruff format --check`) and automated pytest tests pass without regression.
