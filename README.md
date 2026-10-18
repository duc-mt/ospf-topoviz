# OSPF TopoViz

Poll one or more seed routers over SSH, parse their OSPF LSDB, build a directed graph, diff it against the previous run, and render a topology diagram — all in one command.

```
python main.py --replay samples/vyos
```

---

## Features

- **Multi-vendor** — Cisco IOS/IOS-XE/IOS-XR/NX-OS, Juniper JunOS, Arista EOS, VyOS/FRR, Huawei VRP
- **Live polling** over SSH (Netmiko) or **offline replay** from saved CLI output
- **End-to-end visibility** — besides the LSDB, each router's **OSPF neighbour table** and **OSPF routing table (RIB)** are read and cross-checked: LSDB adjacencies vs real neighbour state, neighbour flaps between runs, and an SPF recomputed from the LSDB vs the actual routes (blackholes, suboptimal paths, lost ECMP, routes overridden by static/BGP)
- **Multi-seed polling** — `fallback` uses the first seed that answers (high availability); `merge` polls several seeds in parallel and combines their LSDBs and neighbour tables into one view, across areas
- **Change detection** — added/removed nodes, added/removed links, metric changes
- **Partial-LSDB guard** — detects when the seed router has lost an adjacency (or a merge seed did not answer) and refuses to overwrite a good baseline with a degraded view
- **Readable diagrams** — one line per link with the cost and interface address at each end, area clusters, automatic layout direction, diff highlighting
- **Atomic state rotation** — `current_state.json` → `previous_state.json`, crash-safe
- **Credential-safe** — passwords never have to touch disk; `OSPF_MONITOR_*` env vars override the config file

---

## Standalone Executable (Zero-Dependency & Air-Gapped)

For offline environments on Linux (or Windows WSL2) without needing Python or pip:

1. Download the standalone executable from [GitHub Releases](https://github.com/duc-mt/ospf-lsdb-monitor/releases) under **Latest Build**:
   - `ospf-topoviz-linux-amd64` (Linux 64-bit)
2. Place the executable in an empty directory:
   ```bash
   chmod +x ospf-topoviz-linux-amd64
   ```
3. Generate template configuration:
   ```bash
   ./ospf-topoviz-linux-amd64 --init
   ```
4. Edit the generated `settings.yaml` with your seed router IP, credentials, and settings.
5. Run the poll:
   ```bash
   ./ospf-topoviz-linux-amd64
   ```

---

## Requirements (Source / Developer)

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
# Universal cross-platform launcher (Linux / macOS / WSL / Git Bash):
./run --replay samples/vyos
./run --replay samples/cisco_ios

# Windows CMD (if preferred):
scripts\run.bat --replay samples\vyos

# Or directly with Python
python main.py --replay samples/vyos
```

The topology diagram is written to `output/topology.png`.

### 2. Live polling

Edit `config/settings.yaml` (or set environment variables) and run:

```bash
./run
```

---

## Configuration

Edit `config/settings.yaml` (on first run, it is automatically initialized from `config/settings.yaml.example`). `config/settings.yaml` is excluded from version control so credentials are never committed:

```yaml
seeds:
  mode: merge              # merge | fallback  (see "Multi-seed polling" below)
  concurrency: 5           # merge mode: SSH sessions at the same time
  timeout_per_device: 10   # seconds per connection stage (TCP, banner, login)
  username: admin          # optional: shared by every device that does not set its own
  devices:
    - host: 10.255.255.6   # seed router management IP or hostname
      device_type: vyos    # see supported types below
      password: ""         # or leave blank and use env vars (see below)
      priority: 1          # fallback order, lowest first (default: order written)
      tags: ["Area0", "Core"]   # shown in the ROLE column of the result table
    - host: 10.255.255.10
      device_type: vyos
      password: ""
      priority: 2
      tags: ["Area1", "Edge"]
      # also per device: name, secret, port, conn_timeout, auth_timeout, banner_timeout,
      #                  read_timeout (large LSDBs can be slow), commands

polling:
  neighbors: true          # also read each router's OSPF neighbour table
  routes: true             # also read each router's OSPF routing table (for the SPF-vs-RIB check)

data_quality:
  stale_lsa_age: 2400      # seconds: older than this and still in the database -> flagged stale
  maxage_lsa_age: 3500     # seconds: LSAs this old are being flushed and are ignored (0 = off)

visualization:
  theme: light             # light | dark: the Graphviz picture (the explorer starts in "auto")

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

### Multi-seed polling

| | `fallback` | `merge` |
|---|---|---|
| Use it for | one network view, with spare seeds in case the first is down | seeds in different areas, or several core routers, combined into one diagram |
| Polls | seeds one at a time in `priority` order, stops at the first that works | every seed, up to `concurrency` at once |
| Seeds not needed | shown as `SKIPPED` | – |
| A seed fails | next seed is tried (also if its output cannot be parsed) | the others carry on; the run is flagged as a possible partial LSDB |

**Merging.** LSAs are keyed by originator and area. When two seeds report the same LSA the newer one is kept (higher sequence number; on a tie a MaxAge copy, else the younger one). LSAs of different areas are all kept, so an ABR keeps one router LSA per area. The neighbour tables of all seeds label the interface of every link they cover, in both directions.

**A seed that cannot be polled** (timeout, bad login, SSH error, unparseable output) never stops the run. In `merge` mode it leaves a hole in the picture, so — like any partial LSDB — the run is marked suspect, the baseline is **not** overwritten (`--accept-changes` commits it anyway) and the exit code is `3`. In `fallback` mode a failed seed is expected and does not raise the flag. If *no* seed answers the run fails with exit code `1`; `seeds.require_all: true` makes any failed merge seed fatal.

**Timeouts.** `timeout_per_device` is the wait for each connection stage (TCP connect, SSH banner, login) and fills `conn_timeout` / `auth_timeout` / `banner_timeout` unless a device sets its own. LSDB commands keep `read_timeout`; it is not a cap on the whole poll.

**Credentials.** For each seed: its own non-empty value, then the `OSPF_MONITOR_*` variable, then the shared value under `seeds:`, then the legacy `device:` block. (A device's own password therefore beats the environment — unlike the single `device:` form, below.)

**Existing configs keep working.** Without `seeds.devices` the single `device:` block is polled exactly as before.

### What is not an alarm

A healthy network can look broken for a while after a change. Three rules keep that from turning into noise.

**LSAs about to be flushed are left out.** After a Designated Router is re-elected, the old DR's Type-2 Network LSA stays in the database, ageing, until it reaches MaxAge (3600 s) and is flushed - OSPF's own SPF does not use an LSA at MaxAge. Counting it as a live node produced a "stale" network, a ring of one-way links and a topology "split" that were never there. Router and Network LSAs of age `data_quality.maxage_lsa_age` (default **3500 s**) or more are therefore ignored, together with the links and attachments that point at them, so no ghost "(no LSA)" network appears in their place. What was left out is listed as information (a line in the console summary, the diagram title and an *about to age out* card in the explorer) and the filter can be switched off with `0`. An LSA that is old but below the limit (see `stale_lsa_age`) is still flagged stale.

**A next hop is matched to its router through its interface address.** A routing table names a next hop by the neighbour's IP on the shared link; the topology is made of router IDs. The address is looked up in the polled router's own neighbour table (first-hand: the neighbour's ID and address from its Hellos), then in the link data of the Router LSAs (each router's own interface address on each link), then in the other routers' neighbour tables, then among the router IDs, and finally by the segment it sits on (a transit network, or a point-to-point subnet, with exactly one other router). A next hop that cannot be matched is simply not judged.

**Only what loses packets or cuts the topology is a warning.**

| Level | Findings |
|---|---|
| **critical** | a prefix the LSDB advertises is missing from the routing table; every next hop of a route is through a neighbour that is not Full; a neighbour stuck in Init / ExStart / Exchange / Down; a Full neighbour lost since the last run |
| **warning** | only some next hops of a route are through a broken neighbour; the LSDB advertises an adjacency the neighbour table lacks; a neighbour stuck in Loading / 2-Way where Full is needed; an empty routing table |
| **info** | a path longer than the shortest (cost differs from SPF, next hop off the shortest path), a missing ECMP path, a route another protocol overrides, a stale route nothing advertises, a Full neighbour the LSDB does not show yet, a new neighbour, a recovery |

Information is valid-but-not-ideal. The console lists the first eight informational rows and counts the rest; the explorer hides them until you click the *info* chip; the exit code and the banner badge only ever count critical and warning.

### End-to-end visibility: neighbours and routing table

Next to the LSDB each polled router is asked for its OSPF neighbour table and its OSPF routing table. Both are best effort: a command that fails or is not available on a platform costs nothing but a log warning, and `polling.neighbors: false` / `polling.routes: false` switch them off.

| Platform | Neighbour table | Routing table |
|---|---|---|
| Cisco IOS / IOS-XE | `show ip ospf neighbor` | `show ip route ospf` |
| Cisco NX-OS | `show ip ospf neighbors detail` | `show ip route ospf` |
| Arista EOS | `show ip ospf neighbor` | `show ip route ospf` |
| Juniper Junos | `show ospf neighbor detail` | `show route protocol ospf` |
| VyOS / FRR | `show ip ospf neighbor` | `show ip route ospf` |
| Cisco IOS-XR, Huawei VRP | neighbour table only | not collected |

Each neighbour has an ID, local interface, peer address, state, priority, dead time and DR/BDR role; each route a prefix and mask, type (`Intra-Area`, `Inter-Area`, `E1`, `E2`, `N1`, `N2`), cost, tag (where the platform prints one), distance and next hops (gateway + outgoing interface; several = ECMP). Junos' brief output cannot tell intra- from inter-area or E1 from E2, so those routes are typed `Internal` / `External`.

**What is cross-checked** (`src/correlation.py`):

| Check | Reported when |
|---|---|
| LSDB vs neighbour table | the LSDB still advertises an adjacency but the router's own table shows the neighbour stuck (`Init`, `ExStart`, ...) or absent, or shows a Full neighbour the LSDB has no link for. On a shared segment only adjacencies with the DR must be Full — `2-Way` between two DROthers is normal |
| Neighbour flaps | a neighbour's state changed, was lost or is new compared with the last accepted run (only routers polled in both runs are compared) |
| SPF vs RIB | Dijkstra over the LSDB (equal-cost paths kept) predicts every intra-area prefix's cost and first hops; the routing table is held against it: **blackhole** (prefix missing, or routed via a non-Full neighbour — critical/warning), and, as information only, **suboptimal** (wrong cost, next hop off the shortest path, ECMP path missing), **overridden** (OSPF route listed but not active — FRR and Junos show these) and **stale** (intra-area route no LSA advertises). See *What is not an alarm* |

What it cannot do, and why: only Type 1/2 LSAs are read, so inter-area and external routes cannot be recomputed and are counted as *unverified*, not judged; prefixes in areas the router is not in are not expected in its RIB (summarisation and filtering at the ABR are legitimate). The RIB command only lists OSPF routes, so on Cisco/Arista a prefix that is simply missing may have been beaten by a lower-distance static/BGP route, filtered by a `distribute-list`, or not installed — the report names these as possible causes (`show ip route <prefix>` tells which). A neighbour flap that happens and recovers *between* two runs is not seen.

**Prefix path lookup.** `--trace 10.1.1.5` (an address, longest-prefix match, or a prefix) shows how a router reaches it: its routing-table entry, who advertises the prefix in the LSDB, and the LSDB shortest path hop by hop with interface and cost. The path is drawn in blue on the diagram, and the verdict says whether the RIB and the LSDB agree. `--trace-from ROUTER_ID` picks another router (LSDB side only unless it was polled).

**Alerting.** Findings do not change the exit code by default. `--fail-on-findings` makes a run with a *critical* finding exit with `4` (a suspect run still exits `3`). Counts are added to the bottom banner and to `data/changelog.jsonl`.

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
| Link colour by adjacency | From the polled routers' neighbour tables: dark green = Full, yellow = 2-Way, orange = ExStart/Exchange/Loading, red = Init/Down (the state is also written on the link). A non-Full state wins over the new/changed colour; Full does not |
| Thick blue path | The path of `--trace` |
| Title | Counts of routers, transit networks and links; a warning if the topology is split into disconnected parts |

OSPF does not carry interface names or speeds, so the interface address (the "Link Data" field; an ifIndex on unnumbered links) is the identifier shown.

### Interactive topology explorer

The Graphviz image (`.png` / `.svg` / `.pdf`) is good for a report but hard to read on a busy network: routers are stacked in a column, every link crosses the page, labels collide. The **explorer** is a single self-contained HTML file (no network, no libraries) with its own layout.

By default, every run automatically writes both `output/topology.png` and `output/topology.html`:

```bash
python main.py                                             # writes output/topology.png AND output/topology.html
python main.py --output output/topology.html               # only the explorer, no Graphviz needed
python main.py --trace 10.136.4.9                          # the traced path is drawn in both PNG and HTML
```

**Layout** (`src/layout.py`): a transit network is a *hub* and its routers sit on a ring around it (the ring grows with the number of routers; a very crowded hub gets two rings). A router's place on the ring follows the direction of its other connections, so spokes do not cross links that leave the hub. Each OSPF area is one box; the backbone is the root and the other areas hang below it, left to right. **ABRs sit on the border** between the boxes, straight above the area they lead to. One-way and stale links are drawn but are *weak*: they do not decide where anything goes, so a router that also points at a stale network stays on its real hub's ring and the stale network is parked beside the picture. A part of the topology that is cut off from the rest (the split the title warns about) is packed in its own column on the left of its area, apart from the main picture. The layout is deterministic and takes well under a second for a few hundred nodes.

**In the page**

| What | How |
|---|---|
| Sidebar *Diagnostics & Warnings* | Topology split, one-way links, stale routers, adjacency problems, suspect-run reasons, changes since the last run. **Click an entry and its routers/links are highlighted and centred** |
| Cross-check findings | Neighbour and routing-table findings grouped by kind, severity chips to filter; the hint (likely cause) sits under each message. Click a finding to find its routers on the picture |
| Hover | A link shows both directions: interface, IP, cost, adjacency state (`FULL (Green)`, ...); a node shows areas, LSA age, advertised prefixes, findings about it |
| Click | A node: highlights it and its neighbours and dims the rest; a link: its details. `Esc` clears |
| Labels | Costs are drawn as small pills with collision culling (the text keeps its screen size while you zoom); interface names appear on hover, on selection and when zoomed in |
| Drag a node | Positions are saved **in the browser, per node ID**, and restored on the next run. *Reset Layout* forgets them. *Export / Import layout* moves them between machines (⚙) |
| Search | Router ID, name, prefix (including prefixes a router advertises) or area; `Enter` zooms to the matches; `/` focuses the box |
| Filter | One-way links on/off, cost and interface labels, area boxes, and per-area visibility |
| Bundle | *Bundle leaf routers of a segment, from N*: routers whose only link is to one segment collapse into a single `×N routers` node on a thick link; click it, or search for one of them, to expand |
| View | Wheel zoom, drag the background to pan, `+` `-` `f` (fit), full screen, *Download SVG* of the current picture |
| Theme | The ☀️/🌙/◐ button in the header cycles **auto** (follows the operating system, live), **light** and **dark**; the choice is kept in the browser (`ospf-explorer:theme`) and the whole picture, badges and sidebar are recoloured without losing your selection or zoom. `--theme` sets where a page without a saved choice starts |

The explorer needs a current browser; the layout itself is computed by Python, so the picture is reproducible. The PNG/SVG/PDF output and `--layout` (the Graphviz engine) keep their layout; `--theme dark` redraws them in dark colours (`python main.py --output topo.png --theme dark`).

### Credentials via environment variables

> [!NOTE]
> **Precedence Rules:**
> - In **single-device** mode (`device:` block), `OSPF_MONITOR_*` environment variables **override** the values in `settings.yaml`.
> - In **multi-seed** mode (`seeds.devices`), each device's explicit configuration takes precedence first (`device.password` > `OSPF_MONITOR_*` > shared `seeds.password` > legacy `device:` block).

Use them in CI or to avoid storing passwords on disk:

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
  --device-type TYPE    Override device_type of every seed from the settings file
  --mode {merge,fallback}
                        Override seeds.mode
  --seeds HOST[,HOST...]
                        Poll only these seed routers, in this priority order. A host not in the
                        settings file reuses the shared / legacy credentials and device type
  --trace IP|PREFIX     Show how a router reaches this address/prefix (RIB entry + LSDB path); drawn in blue
  --trace-from ROUTER_ID
                        Router to trace from (default: the first polled router that has a routing table)
  --fail-on-findings    Exit with code 4 when the cross-checks report a critical finding
  --replay DIR          Parse saved CLI output instead of connecting via SSH
  --save-raw DIR        Also write the raw CLI output to DIR (replayable later; one DIR/<host>/ per seed when several are configured)
  --output PATH         Diagram output path; extension sets format (png, svg, pdf, ... or html for the interactive
                        explorer) (default: output/topology.png)
  --theme {light,dark}  Colour theme of the Graphviz picture (default: light, or visualization.theme): dark draws on a
                        dark background with light lines and text. Also the explorer's starting theme
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
| `4` | `--fail-on-findings` and the neighbour / routing-table cross-checks found a critical problem |

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
# → writes samples/my_router/neighbors.txt and routes.txt when the router answered those commands

# Replay it later (no SSH required):
python main.py --replay samples/my_router --device-type cisco_ios
```

---

## Console Result Tables

Every run displays formatted summary tables with rounded box borders (`╭ ╮ ╰ ╯`), status indicators, and diff breakdowns. Live runs start with the **Seed Routers** table — one row per seed with its status (`SUCCEEDED`, `TIMEOUT`, `AUTH FAILED`, `FAILED`, or `SKIPPED` for a fallback seed that was not needed), poll time, LSAs / neighbour rows contributed and role (from `tags`) — and the bottom line counts the seeds that passed:

```text
 Seed Routers:
╭─────────────┬──────────┬─────────────┬──────────┬─────────────┬─────────────╮
│ SEED ROUTER │ PLATFORM │ STATUS      │ DURATION │ LSAS / NBRS │ ROLE        │
├─────────────┼──────────┼─────────────┼──────────┼─────────────┼─────────────┤
│ 192.0.2.1   │ vyos     │ ✔ SUCCEEDED │     2.4s │ 2 / 1 nbrs  │ Area 0 Core │
│ 192.0.2.3   │ vyos     │ ✔ SUCCEEDED │     2.1s │ 3 / 2 nbrs  │ Area 1 Edge │
│ 192.0.2.10  │ vyos     │ ✖ TIMEOUT   │    10.0s │ 0 / 0 nbrs  │ Area 1 Edge │
╰─────────────┴──────────┴─────────────┴──────────┴─────────────┴─────────────╯

  ⚠ Seeds: 2/3 Passed  │  Diffs: 0  │  Nodes: 4  │  Links: 6
```

The rest of a run looks like this (`--replay` runs have no seed table and keep the plain `✔ Stable Topology` verdict at the bottom):

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

With neighbour and routing-table data the run adds the cross-check tables (shown here for a router whose neighbour is stuck in ExStart and whose route to `10.0.0.3/32` has the wrong cost, traced with `--trace 10.0.0.3`):

```text
 Neighbor Flap / State Mismatch:
╭────────────┬──────────┬──────────┬────────────────┬────────────────────────────────────────────────────────────────────╮
│ SEVERITY   │ ROUTER   │ NEIGHBOR │ KIND           │ DETAIL                                                             │
├────────────┼──────────┼──────────┼────────────────┼────────────────────────────────────────────────────────────────────┤
│ ✖ CRITICAL │ 10.0.0.1 │ 10.0.0.2 │ STATE MISMATCH │ LSDB has 10.0.0.1 -> 10.0.0.2 but the neighbour is ExStart on eth1 │
╰────────────┴──────────┴──────────┴────────────────┴────────────────────────────────────────────────────────────────────╯
  • stuck negotiating master/slave: typically an MTU mismatch or a duplicate router ID

 Routing Blackhole / Suboptimal Routing:
╭────────────┬──────────┬─────────────┬────────────┬───────────────────────────────────────────────────────────────────────╮
│ SEVERITY   │ ROUTER   │ PREFIX      │ KIND       │ DETAIL                                                                │
├────────────┼──────────┼─────────────┼────────────┼───────────────────────────────────────────────────────────────────────┤
│ ✖ CRITICAL │ 10.0.0.1 │ 10.0.0.2/32 │ BLACKHOLE  │ 10.0.0.2/32 points at 10.0.0.2 (ExStart), whose adjacency is not Full │
│ ⚠ WARNING  │ 10.0.0.1 │ 10.0.0.3/32 │ SUBOPTIMAL │ 10.0.0.3/32: routing table cost 9, SPF over the LSDB gives 2          │
╰────────────┴──────────┴─────────────┴────────────┴───────────────────────────────────────────────────────────────────────╯
  • traffic to this prefix is blackholed until the adjacency recovers
  • the RIB is not following the shortest path (stale route, changed metric not yet flooded, or SPF running late)

 Prefix Path Trace:
 Query     : 10.0.0.3   from router 10.0.0.1
 Prefix    : 10.0.0.3/32
 RIB       : Intra-Area, cost 9 -> 192.168.1.3 via eth0 (10.0.0.3)
 Origin    : 10.0.0.3 (stub, area 0.0.0.0)
 SPF cost  : 2
 Verdict   : ⚠ RIB cost differs from SPF

 Path 1 of 1:
╭─────┬────────────────────┬──────────────────────┬──────┬───────╮
│ HOP │ NODE               │ LINK (OUT INTERFACE) │ COST │ TOTAL │
├─────┼────────────────────┼──────────────────────┼──────┼───────┤
│   0 │ 10.0.0.1           │ -                    │    - │     0 │
│   1 │ net 192.168.1.0/24 │ eth0                 │    1 │     1 │
│   2 │ 10.0.0.3           │ -                    │    0 │     1 │
│   3 │ 10.0.0.3/32        │ stub                 │    1 │     2 │
╰─────┴────────────────────┴──────────────────────┴──────┴───────╯

  ✔ Stable Topology  │  Diffs: 0  │  Nodes: 4  │  Links: 6  │  Findings: 2 critical, 1 warning
```

---

## Running Tests

```bash
pip install pytest
pytest
```

The explorer page itself (hover, select, drag and save, search, filters, bundles, export) is exercised in jsdom. Those tests are skipped unless node is installed; to run them:

```bash
npm install --prefix tests/js     # once: installs jsdom
pytest tests/test_explorer_js.py
```

---

## Project Structure

```
ospf-topoviz/
├── run                      # Universal cross-platform launcher
├── scripts/
│   ├── run.sh               # Unix bash launcher
│   └── run.bat              # Windows launcher
├── main.py                   # CLI entry point & pipeline orchestrator
├── config/
│   ├── settings.yaml.example # Tracked template configuration
│   └── settings.yaml         # User configuration (auto-copied, git-ignored)
├── src/
│   ├── config.py             # Settings loading, validation & auto-initialization
│   ├── poller.py             # SSH (DevicePoller), file (FilePoller) and multi-seed (MultiDevicePoller) sources
│   ├── parser.py             # Dispatches to the right vendor adapter; merge_lsdbs() combines seeds
│   ├── graph_engine.py       # NetworkX graph, diff, guard, state persistence
│   ├── correlation.py        # SPF, LSDB-vs-neighbour, SPF-vs-RIB checks, neighbour flaps, prefix trace
│   ├── report.py             # Modern box-drawing result table renderer
│   ├── visualizer.py         # Graphviz rendering (and the switch to the explorer for .html output)
│   ├── layout.py             # Hub-and-spoke / area-box layout engine (pure geometry)
│   ├── explorer.py           # Builds the interactive explorer: scene data + self-contained HTML
│   ├── web/explorer.html     # The explorer page (HTML, CSS, JavaScript; no external resources)
│   └── vendors/              # Per-platform LSDB parsers
│       ├── base.py           # Neutral data model (LSAs, OSPFNeighbor, OSPFRoute) and adapter interface
│       ├── routes.py         # Routing-table (RIB) parsers: IOS/EOS/FRR, NX-OS, Junos
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
