# OSPF TopoViz

Poll a seed router over SSH, parse its full OSPF LSDB, build a directed graph, diff it against the previous run, and render a topology diagram — all in one command.

```
python main.py --replay samples/vyos
```

---

## Features

- **Multi-vendor** — Cisco IOS/IOS-XE/IOS-XR/NX-OS, Juniper JunOS, Arista EOS, VyOS/FRR, Huawei VRP
- **Live polling** over SSH (Netmiko) or **offline replay** from saved CLI output
- **Change detection** — added/removed nodes, added/removed links, metric changes
- **Partial-LSDB guard** — detects when the seed router has lost an adjacency and refuses to overwrite a good baseline with a degraded view
- **Readable diagrams** — one line per link with the cost and interface address at each end, area clusters, automatic layout direction, diff highlighting
- **Atomic state rotation** — `current_state.json` → `previous_state.json`, crash-safe
- **Credential-safe** — passwords never have to touch disk; `OSPF_MONITOR_*` env vars override the config file

---

## Requirements

| Dependency | Version |
|---|---|
| Python | ≥ 3.10 |
| Graphviz (`dot`) | system package — see below |
| netmiko | ≥ 4.3, < 5 |
| pyATS / Genie | ≥ 24.1 |
| networkx | ≥ 3.0 |
| graphviz (Python) | ≥ 0.20 |
| PyYAML | ≥ 6.0 |

**Install system Graphviz first:**

```bash
# Debian / Ubuntu
sudo apt install graphviz

# macOS
brew install graphviz
```

> [!NOTE]
> pyATS/Genie is supported on **Linux and macOS** only. Use WSL2 on Windows.

---

## Installation

```bash
git clone https://github.com/duc-mt/ospf-topoviz.git
cd ospf-topoviz

python3 -m venv venv
source venv/bin/activate

# Install exact dependencies
pip install -r requirements.lock
# OR, to install loose dependencies: pip install -r requirements.txt
```

---

## Quick Start

### 1. Offline replay (no router needed)

Try any of the bundled vendor samples:

```bash
# Linux / macOS / WSL
./run.sh --replay samples/vyos
./run.sh --replay samples/cisco_ios

# Windows (CMD / PowerShell)
run.bat --replay samples\vyos

# Or directly with Python
python main.py --replay samples/vyos
```

The topology diagram is written to `output/topology.png`.

### 2. Live polling

Edit `config/settings.yaml` (or set environment variables) and run:

```bash
./run.sh          # Linux / macOS / WSL
run.bat           # Windows
```

---

## Configuration

Edit `config/settings.yaml` (on first run, it is automatically initialized from `config/settings.yaml.example`). `config/settings.yaml` is excluded from version control so credentials are never committed:

```yaml
device:
  host: 10.255.255.6       # seed router management IP or hostname
  username: admin
  password: ""             # or leave blank and use env vars (see below)
  secret: ""               # enable secret — leave empty if already in privileged mode
  device_type: vyos        # see supported types below
  port: 22
  conn_timeout: 15
  auth_timeout: 20
  banner_timeout: 20
  read_timeout: 120        # large LSDBs can be slow

ospf_process_id: 1         # omit for platforms without process IDs (JunOS, VyOS)

guard:
  enabled: true
  min_node_retention: 0.7  # flag run if > 30% of known nodes vanish
  flag_partition: true      # flag run if the graph splits into more pieces than before

visualization:             # every key optional; these are the defaults
  rankdir: auto            # auto = left-to-right when a node has 6+ neighbours, else top-to-bottom (or TB/LR/BT/RL)
  router_shape: box3d      # box3d | box | circle | ellipse | oval | doublecircle
  show_interfaces: true    # interface address printed next to each cost
  cost_weighted_lines: true  # cheaper links are drawn thicker
  area_clusters: true      # dashed box per OSPF area when there are several
  # names:                 # optional host names shown above the router ID
  #   10.255.255.1: core-1
```

### Supported device types

| `device_type` | Platform |
|---|---|
| `cisco_ios` / `cisco_xe` | Cisco IOS / IOS-XE |
| `cisco_xr` | Cisco IOS-XR |
| `cisco_nxos` | Cisco NX-OS |
| `juniper_junos` | Juniper JunOS |
| `arista_eos` | Arista EOS |
| `vyos` | VyOS / FRR |
| `huawei` / `huawei_vrpv8` | Huawei VRP |

### Reading the diagram

| Element | Meaning |
|---|---|
| Blue 3D box | Router (host name above the router ID if configured under `visualization.names`) |
| Yellow diamond | Transit network: prefix and Designated Router |
| Grey dashed node | Referenced by a link but has no LSA of its own in the database (`no LSA`) |
| One line per link | Both directions are merged; a router-to-network line carries the router's cost and interface address in the middle |
| Point-to-point line | Each end shows the cost *advertised by that router* and its interface address; a symmetric link with no addresses gets one centred label |
| Line thickness | Cost: cheaper links are thicker, so preferred paths stand out |
| Dashed cluster | OSPF area (drawn only when the database holds several); area border routers sit outside the boxes |
| Green / red dashed / orange | New / removed (kept in the drawing for this run) / metric changed (`old→new`) |
| Title | Counts of routers, transit networks and links; a warning if the topology is split into disconnected parts |

OSPF does not carry interface names or speeds, so the interface address (the "Link Data" field; an ifIndex on unnumbered links) is the identifier shown.

### Credentials via environment variables

These override anything in `settings.yaml` — use them in CI or to avoid storing passwords on disk:

```bash
export OSPF_MONITOR_USERNAME=admin
export OSPF_MONITOR_PASSWORD=s3cr3t
export OSPF_MONITOR_SECRET=enable_pass   # optional
python main.py
```

---

## CLI Reference

```
python main.py [OPTIONS]

Options:
  --config PATH         Settings file (default: config/settings.yaml)
  --device-type TYPE    Override device.device_type from the settings file
  --replay DIR          Parse saved CLI output instead of connecting via SSH
  --save-raw DIR        Also write the raw CLI output to DIR (replayable later)
  --output PATH         Diagram output path; extension sets format (png, svg, pdf, ...) (default: output/topology.png)
  --layout ENGINE       Graphviz layout engine: dot, neato, fdp, sfdp, circo, ... (default: dot)
  --accept-changes      Commit this run as the new baseline even if the guard flagged it
  --dry-run             Build and diff the topology without saving any state files
  -v, --verbose         Enable debug logging
  --version             Show version and exit
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — baseline updated |
| `1` | Expected failure (config error, SSH failure, parse error, …) |
| `2` | Unexpected error |
| `3` | Run flagged as a possible partial LSDB — baseline kept; use `--accept-changes` to override |

---

## Architecture

```
Poll (SSH / file)
       │
       ▼
Parse (Genie / vendor text adapter)
       │  router-LSAs + network-LSAs → normalised dict
       ▼
Graph Engine (NetworkX)
       │  build DiGraph → diff vs baseline → partial-LSDB guard → atomic save
       ▼
Visualizer (Graphviz)
       │
       ▼
output/topology.png
```

State is kept in `data/`:

| File | Purpose |
|---|---|
| `current_state.json` | Topology from the last accepted run |
| `previous_state.json` | Topology from the run before that (for crash recovery) |
| `suspect_state.json` | Last run the guard rejected (not promoted to baseline) |
| `changelog.jsonl` | Append-only run history (one JSON line per run) |

---

## Capturing New Vendor Samples

Run against a live device and save the raw CLI output for future offline use:

```bash
python main.py --save-raw samples/my_router
# → writes samples/my_router/router_lsdb.txt
# → writes samples/my_router/network_lsdb.txt

# Replay it later (no SSH required):
python main.py --replay samples/my_router --device-type cisco_ios
```

---

## Console Result Tables

Every run displays formatted summary tables with rounded box borders (`╭ ╮ ╰ ╯`), status indicators, and diff breakdowns:

```text
========================================================================
 OSPF Topology Summary
========================================================================
 Source    : samples/vyos   (2026-10-11T02:42:04+00:00)
 Topology  : 4 nodes, 6 directed links

╭──────────────────┬──────────┬─────────┬─────────────┬─────────────╮
│ COMPONENT        │ BASELINE │ CURRENT │ DELTA       │ STATUS      │
├──────────────────┼──────────┼─────────┼─────────────┼─────────────┤
│ Router Nodes     │       12 │       3 │ -9 routers  │ ✖ DEGRADED  │
│ Transit Networks │        3 │       1 │ -2 networks │ ✖ DEGRADED  │
│ Directed Links   │       33 │       6 │ -27 links   │ ✖ DEGRADED  │
│ Metric Changes   │        - │       0 │ 0 unchanged │ ✔ UNCHANGED │
╰──────────────────┴──────────┴─────────┴─────────────┴─────────────╯

 Detailed Topology Changes:
╭────────────┬────────────────────┬──────────────────────────────┬─────────────╮
│ ACTION     │ ELEMENT            │ DETAILS                      │ STATUS      │
├────────────┼────────────────────┼──────────────────────────────┼─────────────┤
│ ✚ ADD NODE │ 10.0.0.1           │ type: router                 │ ✚ ADDED     │
│ ✚ ADD NODE │ net 192.168.1.0/24 │ type: network                │ ✚ ADDED     │
│ ✖ REM NODE │ 10.255.255.1       │ type: router                 │ ✖ REMOVED   │
╰────────────┴────────────────────┴──────────────────────────────┴─────────────╯

  ✖ Suspect Run  │  Diffs: 58  │  Nodes: 4  │  Links: 6
```

---

## Running Tests

```bash
pip install pytest
pytest
```

---

## Project Structure

```
ospf-topoviz/
├── run.sh                    # Universal launcher (Linux/macOS/WSL)
├── run.bat                   # Universal launcher (Windows CMD/PowerShell)
├── main.py                   # CLI entry point & pipeline orchestrator
├── config/
│   ├── settings.yaml.example # Tracked template configuration
│   └── settings.yaml         # User configuration (auto-copied, git-ignored)
├── src/
│   ├── config.py             # Settings loading, validation & auto-initialization
│   ├── poller.py             # SSH (DevicePoller) and file (FilePoller) data sources
│   ├── parser.py             # Dispatches to the right vendor adapter
│   ├── graph_engine.py       # NetworkX graph, diff, guard, state persistence
│   ├── report.py             # Modern box-drawing result table renderer
│   ├── visualizer.py         # Graphviz rendering
│   └── vendors/              # Per-platform LSDB parsers
│       ├── base.py           # VendorProfile base class
│       ├── cisco_style.py    # Cisco IOS/XE/XR/NX-OS + Arista (text)
│       ├── genie_cisco.py    # Cisco via pyATS/Genie
│       ├── genie_junos.py    # Juniper via pyATS/Genie
│       └── huawei.py         # Huawei VRP text parser
├── samples/                  # Bundled offline LSDB captures (one dir per vendor)
├── data/                     # Runtime state (git-ignored)
├── output/                   # Generated diagrams (git-ignored)
└── tests/                    # Unit tests
```

---

## License

MIT — see [LICENSE](LICENSE) if present, or contact the author.

## Author

**Mai Tan Duc** · [ducmai.network@gmail.com](mailto:ducmai.network@gmail.com)
