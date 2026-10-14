"""
==============================================================================
Module Name:   main.py
Description:   Source module main.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 main.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from src import TrackerError, __version__
from src.correlation import trace_prefix
from src.config import SEED_MODES, load_settings, parse_process_id, parse_seed_hosts, stale_lsa_age
from src.graph_engine import GraphEngine, GuardConfig, TopologyDiff
from src.parser import DEFAULT_STALE_AGE, OSPFParser, merge_lsdbs
from src.poller import (
    FilePoller,
    MultiDevicePoller,
    PollerError,
    PollResult,
    RawLSDB,
    SeedResult,
)
from src.vendors import supported_device_types
from src.vendors.base import Lsdb, SourceDetail
from src.visualizer import TopologyVisualizer, VisualOptions
from src.report import (
    render_diff_table,
    render_neighbor_findings_table,
    render_quality_table,
    render_rib_check_table,
    render_route_findings_table,
    render_seed_table,
    render_summary_banner,
    render_topology_summary_table,
    render_trace,
)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = BASE_DIR / "config" / "settings.yaml"
DATA_DIR = BASE_DIR / "data"
OUTPUT_IMAGE = BASE_DIR / "output" / "topology.png"
OUTPUT_HTML = BASE_DIR / "output" / "topology.html"

EXIT_OK, EXIT_ERROR, EXIT_UNEXPECTED, EXIT_SUSPECT, EXIT_FINDINGS = 0, 1, 2, 3, 4

logger = logging.getLogger("ospf_tracker")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Track OSPF topology changes from the LSDB of one or more seed routers."
    )
    ap.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="settings file (default: %(default)s)",
    )
    ap.add_argument(
        "--device-type",
        metavar="TYPE",
        help=f"Netmiko device type, overrides the settings file ({', '.join(supported_device_types())})",
    )
    ap.add_argument(
        "--mode",
        choices=SEED_MODES,
        help="multi-seed mode, overrides seeds.mode: 'merge' polls every seed and combines their LSDBs, "
        "'fallback' uses the first seed (by priority) that answers",
    )
    ap.add_argument(
        "--seeds",
        metavar="HOST[,HOST...]",
        help="poll only these seed routers, in this priority order (overrides the list in the settings file; "
        "a host not listed there reuses the shared/legacy credentials)",
    )
    ap.add_argument(
        "--trace",
        metavar="IP|PREFIX",
        help="after the run, show how a router reaches this address or prefix: its routing-table entry, then the "
        "LSDB shortest path hop by hop (also drawn in blue on the diagram)",
    )
    ap.add_argument(
        "--trace-from",
        metavar="ROUTER_ID",
        help="router ID to trace from (default: the first polled router that has a routing table)",
    )
    ap.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit with code 4 when the neighbour / routing-table cross-checks report a critical finding",
    )

    ap.add_argument(
        "--replay",
        type=Path,
        metavar="DIR",
        help="read router_lsdb.txt / network_lsdb.txt from DIR instead of connecting to a device",
    )
    ap.add_argument(
        "--save-raw",
        type=Path,
        metavar="DIR",
        help="write the raw CLI output to DIR (router_lsdb.txt, network_lsdb.txt, neighbors.txt); replayable with --replay",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_IMAGE,
        metavar="PATH",
        help="diagram output path; file extension sets the format (png, svg, pdf, ...) (default: %(default)s)",
    )
    ap.add_argument(
        "--layout",
        default="dot",
        metavar="ENGINE",
        help="Graphviz layout engine — dot, neato, fdp, sfdp, circo, ... (default: %(default)s)",
    )
    ap.add_argument(
        "--accept-changes",
        action="store_true",
        help="commit this run as the new baseline even if flagged as a possible partial LSDB",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="build and diff the topology without saving the new baseline or writing state files",
    )
    ap.add_argument("-v", "--verbose", action="action", help="enable debug logging") if False else ap.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap.parse_args(argv)


def print_summary(
    raw: RawLSDB, graph, diff: TopologyDiff, seeds: list[SeedResult] | None = None, trace=None
) -> None:
    """Print a human-readable change report to the console using modern tables.

    ``raw`` only supplies the source and timestamp lines. ``seeds`` (live runs) adds the Seed Health table
    at the top and the seeds count in the bottom banner; replays pass nothing and look as they always did.
    ``trace`` (a ``correlation.TraceResult``) adds the prefix path lookup above the banner.
    """
    print()
    print("=" * 72)
    print(" OSPF Topology Summary")
    print("=" * 72)
    if seeds:
        print("\n Seed Routers:")
        print(render_seed_table(seeds))
        print()
    print(f" Source    : {raw.source}   ({raw.collected_at})")
    print(
        f" Topology  : {graph.number_of_nodes()} nodes, {graph.number_of_edges()} directed links"
    )

    abrs = [n for n, a in graph.nodes(data=True) if a.get("abr")]
    asbrs = [n for n, a in graph.nodes(data=True) if a.get("asbr")]
    if abrs or asbrs:
        print(f" Roles     : {len(abrs)} ABR ({', '.join(abrs) or '-'}), {len(asbrs)} ASBR ({', '.join(asbrs) or '-'})")

    # 1. Topology comparison summary table
    print("\n" + render_topology_summary_table(graph, diff))

    # 2. Quality / Adjacency issues table (if any)
    covered = {(f["router"], f["subject"]) for f in diff.findings if f["kind"] == "ADJ_NOT_FULL"}
    quality_table = render_quality_table(graph, covered)
    if quality_table:
        print("\n Data Quality & Adjacency Issues:")
        print(quality_table)

    # 3. Suspect warning banner
    if diff.suspect_reasons:
        verdict = (
            "baseline NOT updated"
            if not diff.baseline_updated
            else "baseline updated (--accept-changes)"
        )
        print(f"\n !! SUSPECT RUN - possible partial LSDB; {verdict}")
        for reason in diff.suspect_reasons:
            print(f"    - {reason}")
        if not diff.baseline_updated:
            print(
                "    The seed router may have lost an adjacency. Re-run once it has recovered, or use"
            )
            print("    --accept-changes if this change is real.")

    # 4. Topology diff table
    if not diff.baseline_available:
        print(
            "\n First run (or no usable previous state): baseline saved, nothing to compare."
        )
    elif not diff.has_changes:
        print("\n No topology changes detected since the previous run.")
    else:
        diff_table = render_diff_table(diff)
        if diff_table:
            print("\n Detailed Topology Changes:")
            print(diff_table)

    # 5. Cross-checks: neighbour tables and routing tables against the LSDB
    for title, table in (
        ("OSPF Routing Table Check (SPF over the LSDB vs the router's own RIB):", render_rib_check_table(diff)),
        ("Neighbor Flap / State Mismatch:", render_neighbor_findings_table(diff)),
        ("Routing Blackhole / Suboptimal Routing:", render_route_findings_table(diff)),
    ):
        if table:
            print(f"\n {title}")
            print(table)

    # 6. Prefix path lookup (--trace)
    if trace is not None:
        print("\n Prefix Path Trace:")
        print(render_trace(trace, graph))

    # 7. Bottom summary card
    print("\n" + render_summary_banner(raw, graph, diff, seeds))


def save_raw(raw: RawLSDB, directory: Path) -> None:
    """Keep the raw CLI output so a run can be replayed or attached to a bug report."""
    try:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / FilePoller.ROUTER_FILE).write_text(raw.router, encoding="utf-8")
        (directory / FilePoller.NETWORK_FILE).write_text(raw.network, encoding="utf-8")
        if raw.neighbors:
            (directory / FilePoller.NEIGHBORS_FILE).write_text(raw.neighbors, encoding="utf-8")
        if raw.routes:
            (directory / FilePoller.ROUTES_FILE).write_text(raw.routes, encoding="utf-8")
    except OSError as exc:
        raise TrackerError(
            f"Could not write raw capture to {directory}: {exc}"
        ) from exc
    logger.info("Raw CLI output saved to %s", directory)


def save_raw_seeds(result: PollResult, directory: Path) -> None:
    """``--save-raw`` for a poll result.

    One configured seed keeps the flat layout (``DIR/router_lsdb.txt``), replayable as before. With several
    seeds each gets its own folder, ``DIR/<host>/``, so every one can be replayed on its own
    (``--replay DIR/<host> --device-type ...``). The layout depends on how many seeds are configured, not
    on how many answered, so it does not change from one run to the next.
    """
    captured = [(s.host, s.raw) for s in result.seeds if s.raw is not None]
    if len(result.seeds) == 1:
        for _host, raw in captured:
            save_raw(raw, directory)
        return
    for host, raw in captured:
        save_raw(raw, directory / re.sub(r"[^A-Za-z0-9_.-]", "_", host))


@dataclass
class SeedIngest:
    """What parsing one seed's raw output yields: its LSDB and (if it printed one) its neighbour table."""

    lsdb: Lsdb
    detail: SourceDetail | None = None


class ParserPool:
    """One ``OSPFParser`` per (platform, OSPF process), created once and shared by the seeds that need it."""

    def __init__(self) -> None:
        self._parsers: dict[tuple[str, str | None], OSPFParser] = {}

    def get(self, device_type: str, process_id: str | None) -> OSPFParser:
        key = (device_type, process_id)
        if key not in self._parsers:
            self._parsers[key] = OSPFParser(device_type=device_type, process_id=process_id)
        return self._parsers[key]


def make_ingest(parsers: ParserPool):
    """Build the callback that parses one seed's raw output (run by ``MultiDevicePoller`` per seed).

    A ``TrackerError`` from it - e.g. no router LSAs in the output - makes that seed count as failed, so in
    fallback mode the next seed gets its turn.
    """

    def ingest(seed, raw: RawLSDB) -> SeedIngest:
        parser = parsers.get(seed.device_type, seed.process_id)
        lsdb = parser.parse_lsdb(raw.router, raw.network)
        neighbors = routes = None
        if raw.neighbors.strip():
            try:
                neighbors = parser.parse_neighbors(raw.neighbors)
            except TrackerError as exc:
                logger.warning("%s: neighbour table ignored: %s", seed.host, exc)
        if raw.routes.strip():
            try:
                routes = parser.parse_routes(raw.routes)
            except TrackerError as exc:
                logger.warning("%s: routing table ignored: %s", seed.host, exc)
        detail = None
        if neighbors is not None or routes is not None:
            detail = SourceDetail(seed.name, lsdb.router_id, neighbors or [], routes,
                                  neighbors_known=neighbors is not None)
        return SeedIngest(lsdb, detail)

    return ingest


def build_poller(args: argparse.Namespace, settings: dict, ingest) -> MultiDevicePoller:
    """Pick the data source. Swap or extend here to add API polling or another vendor."""
    if args.replay:
        if args.mode or args.seeds:
            logger.warning("--mode and --seeds do nothing with --replay; ignored")
        device = (
            settings.get("device") if isinstance(settings.get("device"), dict) else {}
        )
        replay = FilePoller(
            args.replay,
            device_type=args.device_type or device.get("device_type", "cisco_ios"),
            process_id=parse_process_id(settings.get("ospf_process_id")),
        )
        return MultiDevicePoller([replay], mode="fallback", concurrency=1, ingest=ingest)
    return MultiDevicePoller.from_settings(
        args.config,
        settings=settings,
        mode=args.mode,
        hosts=parse_seed_hosts(args.seeds) or None,
        device_type=args.device_type,
        ingest=ingest,
    )


def combined_source(result: PollResult) -> RawLSDB:
    """A ``RawLSDB`` that stands for the whole poll in the summary (it only supplies source and time).

    One answering seed: that seed's own capture. Several: their hosts joined, stamped with the latest time.
    """
    answered = [s.raw for s in result.succeeded if s.raw is not None]
    if len(answered) == 1:
        return answered[0]
    return RawLSDB(
        router="",
        network="",
        source=", ".join(r.source for r in answered),
        collected_at=max(r.collected_at for r in answered),
    )


def run(args: argparse.Namespace) -> int:
    """Execute the full pipeline once."""
    if args.trace:
        try:  # fail before any SSH traffic
            ipaddress.ip_network(args.trace, strict=False) if "/" in args.trace else ipaddress.ip_address(args.trace)
        except ValueError as exc:
            raise TrackerError(f"--trace expects an IP address or a prefix, got {args.trace!r}") from exc
    settings = load_settings(args.config, required=not args.replay)

    # Build every stage first so configuration/import problems surface before any SSH traffic.
    parsers = ParserPool()
    poller = build_poller(args, settings, make_ingest(parsers))
    for seed in poller.pollers:
        parsers.get(seed.device_type, seed.process_id)  # e.g. Genie missing -> fail now, not after polling
    engine = GraphEngine(
        data_dir=DATA_DIR, guard=GuardConfig.from_settings(settings.get("guard"))
    )
    visualizer = TopologyVisualizer(
        output_path=args.output,
        layout=args.layout,
        options=VisualOptions.from_settings(settings.get("visualization")),
    )

    result = poller.poll()  # 1. Poll (+ parse each seed's output)
    if args.save_raw:
        save_raw_seeds(result, args.save_raw)
    live = not args.replay
    if not result.succeeded or (poller.require_all and poller.mode == "merge" and result.failed):
        if live and len(result.seeds) > 1:  # which seeds failed is the useful part of the answer
            print("\n Seed Routers:\n" + render_seed_table(result.seeds) + "\n")
        if len(result.seeds) == 1:
            raise PollerError(result.seeds[0].error or result.seeds[0].status)
        reason = "No seed router could be polled" if not result.succeeded else "A seed failed and seeds.require_all is set"
        raise PollerError(f"{reason}: {result.failure_report()}")

    answered = result.succeeded
    scope = ",".join(sorted(s.host for s in answered))  # names this network in the explorer's saved layouts
    for seed in answered:
        ingested: SeedIngest = seed.parsed
        seed.lsas = len(ingested.lsdb.router_lsas) + len(ingested.lsdb.network_lsas)
        seed.neighbors = len(ingested.detail.neighbors) if ingested.detail else 0
    lsdbs = [s.parsed.lsdb for s in answered]
    lsdb = merge_lsdbs(lsdbs) if len(lsdbs) > 1 else lsdbs[0]
    details = [s.parsed.detail for s in answered if s.parsed.detail is not None]

    metadata = {"device_type": ", ".join(sorted({s.device_type for s in answered}))}
    if live:
        metadata["seed_mode"] = result.mode
        metadata["sources"] = [
            {"name": s.host, "status": "ok" if s.ok else ("skipped" if s.status == "SKIPPED" else "failed")}
            for s in result.seeds
        ]
    parsed = build_parsed_topology(lsdb, metadata, details, settings)  # 2. Parse / merge
    # In merge mode a seed that did not answer leaves a hole in the picture; in fallback mode it does not.
    partial = [s.host for s in result.failed] if result.mode == "merge" else []
    graph, diff = engine.process(  # 3. Engine
        parsed,
        accept_changes=args.accept_changes,
        dry_run=args.dry_run,
        partial_sources=partial,
        details=details,
    )

    trace = None
    if args.trace:
        try:
            trace = trace_prefix(graph, details, args.trace, args.trace_from)
        except ValueError as exc:
            raise TrackerError(str(exc)) from exc

    print_summary(combined_source(result), graph, diff, result.seeds if live else None, trace)  # shown even if rendering fails
    if args.dry_run:
        print("\n [DRY RUN] Topology diffed — no state files written.\n")
    # 4. Visualize
    visualizer.scope = scope
    if visualizer.interactive:
        image = visualizer.render(graph, diff, trace=trace)
    else:
        image = visualizer.render(graph, diff, highlight=trace.edges) if trace else visualizer.render(graph, diff)
    print(f"\n Diagram   : {image}")
    if not visualizer.interactive:
        page = TopologyVisualizer(output_path=OUTPUT_HTML, options=visualizer.options)
        page.scope = scope
        print(f" Explorer  : {page.render(graph, diff, trace=trace)}")
    print()
    if args.dry_run:
        return EXIT_FINDINGS if args.fail_on_findings and diff.critical_findings else EXIT_OK
    if not diff.baseline_updated:
        return EXIT_SUSPECT
    return EXIT_FINDINGS if args.fail_on_findings and diff.critical_findings else EXIT_OK


def build_parsed_topology(lsdb: Lsdb, metadata: dict, details: list[SourceDetail], settings: dict) -> dict:
    """Flatten the (merged) LSDB plus every seed's neighbour table into the standard topology dict."""
    return OSPFParser.build_topology(
        lsdb,
        metadata,
        details,
        stale_age=stale_lsa_age(settings, DEFAULT_STALE_AGE),
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    try:
        return run(args)
    except TrackerError as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        logger.error("Interrupted")
        return 130
    except (
        Exception
    ):  # last-resort guard: log the traceback, return a clean failure code
        logger.exception("Unexpected error")
        return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
