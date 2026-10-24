# Specification: Apply OSPF Explorer & Parallel Links Patch

## 1. Problem Statement & Motivation
A patch file `~/ospf-topoviz.patch` contains significant feature enhancements for `ospf-topoviz`, including:
1. Parallel link discovery and tracking with interface address differentiation (`_note_parallel`).
2. Router role determination (`ABR`, `ASBR`, `ABR/ASBR`, `Router`) and metadata propagation in explorer scene building.
3. Major interactive Web Explorer upgrades:
   - What-if failure simulation with blast radius calculation.
   - 1-hop and 2-hop focus mode with neighbourhood dimming.
   - Interactive minimap radar.
   - Stub network grouping.
   - Multi-vendor CLI diagnostic generation (Cisco IOS/NX-OS, Arista EOS, Junos, VyOS, Huawei).
   - Documentation bundle export (vector SVG and `TOPOLOGY_SPEC.md`).
4. Automated unit tests covering parallel link tracking, router roles, and explorer JavaScript logic.

Applying this patch cleanly will integrate these improvements into the codebase while maintaining code quality and test compliance.

## 2. Requirements & Scope
- **In Scope**:
  - Cleanly apply `~/ospf-topoviz.patch` to the working directory (`git apply --check` verified).
  - Modify 9 targeted files:
    - `README.md`
    - `src/explorer.py`
    - `src/parser.py`
    - `src/web/explorer.html`
    - `tests/js/battery.js`
    - `tests/js/test_explorer_docs.js`
    - `tests/js/test_simulation.js`
    - `tests/test_explorer.py`
    - `tests/test_parser.py`
  - Ensure all python unit tests pass without regressions using `./.venv/bin/pytest`.
  - Ensure code formatting and linting pass using `./.venv/bin/ruff check .`.

- **Out of Scope (Non-Goals)**:
  - Applying unneeded patches from other repositories (`lldp-topoviz.patch`, `netconfig-*.diff`).
  - Installing Node.js system packages (JS tests run when Node is available, skipped otherwise).

## 3. Technical Design & Contracts
- **Parallel Link Ingestion**:
  - `OSPFParser._note_parallel(kept, other)` records secondary edges with distinct interface addresses into `parallel_links`.
  - `build_scene()` computes `members` and `parallel` count for visual representation with `[2x]` badge.
- **Scene Schema Extension**:
  - Router nodes carry `"role"` (`ABR`, `ASBR`, `ABR/ASBR`, `Router`).
  - Scene links carry `"parallel"` (integer count) and `"members"` (list of metric/IP dictionaries).
  - Scene metadata carries `"backbone"` area IDs and `"device_type"`.

## 4. Verification & Acceptance Criteria
- [x] Criterion 1: Patch `/home/nms-net/ospf-topoviz.patch` applies cleanly with zero reject files.
- [x] Criterion 2: Working directory reflects all changes across the 9 files.
- [x] Criterion 3: `./.venv/bin/pytest` passes 100% of runnable tests (558 passed, 39 skipped).
- [x] Criterion 4: `./.venv/bin/ruff check .` passes without errors.
