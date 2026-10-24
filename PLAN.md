# Execution Plan: Apply OSPF Explorer & Parallel Links Patch

## Prerequisites
- [x] Requirements specified in `SPEC.md`.
- [x] Working tree clean (`git status`).
- [x] Pre-flight patch check (`git apply --check /home/nms-net/ospf-topoviz.patch`) completed cleanly.

## Step-by-Step Implementation

### Step 1: Apply Patch File Cleanly
- **Target File(s)**:
  - `README.md`
  - `src/explorer.py`
  - `src/parser.py`
  - `src/web/explorer.html`
  - `tests/js/battery.js`
  - `tests/js/test_explorer_docs.js`
  - `tests/js/test_simulation.js`
  - `tests/test_explorer.py`
  - `tests/test_parser.py`
- **Action**: Execute `git apply /home/nms-net/ospf-topoviz.patch`.
- **Verification**: `git status` verifies modified and newly created files without patch artifacts or conflicts.

### Step 2: Run Python Linters and Code Quality Checks
- **Target File(s)**: All modified Python source and test files.
- **Action**: Run `./.venv/bin/ruff check .`
- **Verification**: Zero linter errors or warnings.

### Step 3: Run Automated Test Suite
- **Target File(s)**: `tests/`
- **Action**: Run `./.venv/bin/pytest`
- **Verification**: All 558 tests pass with zero failures.

## Final Validation & Review
- [x] Working tree status verified with `git status` and `git diff --stat`.
- [x] Linter check passes (`./.venv/bin/ruff check .`).
- [x] Test suite passes (`./.venv/bin/pytest` -> 558 passed, 39 skipped).
