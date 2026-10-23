# Execution Plan: Alignment of Telegram Alerting & Scheduling with LLDP TopoViz

## Prerequisites
- [ ] Requirements specified in `SPEC.md`.
- [ ] Working tree clean in `/home/nms-net/ospf-topoviz`.

## Step-by-Step Implementation

### Step 1: Update CLI Arguments & Handlers in `main.py`
- **Target File(s)**: `/home/nms-net/ospf-topoviz/main.py`
- **Action**:
  - Add `--test-telegram` argument to `parse_args()`.
  - Add `--test-telegram` handler in `run()` that loads configuration, verifies credentials, dispatches a test alert, and exits with appropriate exit codes.
  - Wrap `main()` execution with top-level `notifier.send_alert()` for `TrackerError` and unexpected exceptions.
  - Update `dispatch_alerts()` to dispatch an `info`-level alert on clean/in-sync runs if `min_severity="info"`.
- **Verification**: `python main.py --help` shows `--test-telegram`.

### Step 2: Add Concurrency-Safe Cron Runner Script
- **Target File(s)**: `/home/nms-net/ospf-topoviz/scripts/run_ospf_cron.sh`
- **Action**: Create executable bash script with `flock -n /tmp/ospf_topoviz.lock`, `.env` sourcing, virtual environment python lookup, and trap cleanup.
- **Verification**: `bash -n scripts/run_ospf_cron.sh` passes syntax check and file is executable (`chmod +x`).

### Step 3: Add Systemd Service & Timer Definitions
- **Target File(s)**:
  - `/home/nms-net/ospf-topoviz/systemd/ospf-topoviz.service`
  - `/home/nms-net/ospf-topoviz/systemd/ospf-topoviz.timer`
- **Action**: Define systemd unit files with `nms-net` user, hardened filesystem protections, and 15-minute randomized timer.
- **Verification**: `systemd-analyze verify systemd/*` or syntax inspection.

### Step 4: Add Operations Guide
- **Target File(s)**: `/home/nms-net/ospf-topoviz/docs/TELEGRAM_ALERTING.md`
- **Action**: Create step-by-step setup guide covering BotFather, chat ID, manual test command (`./run --test-telegram`), cronjob configuration, and systemd deployment.
- **Verification**: File exists and links are valid.

### Step 5: Add Unit Tests
- **Target File(s)**: `/home/nms-net/ospf-topoviz/tests/test_main_alerting.py`
- **Action**: Add unit test coverage for `--test-telegram` (success, disabled, missing credentials) and top-level crash alert dispatch.
- **Verification**: `pytest tests/test_main_alerting.py` passes 100%.

## Final Validation & Review
- [ ] Run linter: `ruff check .`
- [ ] Run format check: `ruff format --check .`
- [ ] Run automated test suite: `pytest`
- [ ] Live test: `./run --test-telegram` delivers message to `@nhg_ospf_topoviz_bot`.
- [ ] Review diff (`git diff`).
