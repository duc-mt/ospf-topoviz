"""Unit tests for Type 10 Opaque Area TE & SRLG neutral model, vendor parsers, and merging."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from src.parser import OSPFParser, merge_lsdbs
from src.poller import FilePoller, PollingOptions
from src.vendors import get_profile
from src.vendors.base import Lsdb, TeLinkLsa
from src.vendors.cisco_style import CiscoStyleTextAdapter

SAMPLES_VYOS = Path(__file__).resolve().parents[1] / "samples" / "vyos"


def test_polling_options_opaque_te_defaults_false_and_enables() -> None:
    default_opts = PollingOptions.from_settings({})
    assert default_opts.opaque_te is False
    enabled_opts = PollingOptions.from_settings({"opaque_te": True})
    assert enabled_opts.opaque_te is True
    for vendor in (
        "cisco_ios",
        "cisco_xe",
        "cisco_xr",
        "arista_eos",
        "aruba_aoscx",
        "vyos",
        "juniper_junos",
    ):
        assert get_profile(vendor).command("opaque_te", None)


def test_merge_lsdbs_deduplicates_te_lsas_by_newer_seq_and_age() -> None:
    older = TeLinkLsa(
        adv_router="10.0.0.1",
        area="0.0.0.0",
        link_id="10.0.0.2",
        local_ip="10.12.0.1",
        remote_ip="10.12.0.2",
        te_metric=10,
        srlgs=[100],
        seq=0x80000001 - 0x100000000,
        age=200,
    )
    newer = TeLinkLsa(
        adv_router="10.0.0.1",
        area="0",
        link_id="10.0.0.2",
        local_ip="10.12.0.1",
        remote_ip="10.12.0.2",
        te_metric=25,
        srlgs=[100, 200],
        seq=0x80000003 - 0x100000000,
        age=50,
    )
    merged = merge_lsdbs([Lsdb(te_lsas=[older]), Lsdb(te_lsas=[newer])])
    assert len(merged.te_lsas) == 1
    assert merged.te_lsas[0].te_metric == 25
    assert merged.te_lsas[0].area == "0.0.0.0"
    assert merged.te_lsas[0].srlgs == [100, 200]


def test_file_poller_reads_optional_opaque_te_lsdb_txt(tmp_path) -> None:
    shutil.copytree(SAMPLES_VYOS, tmp_path / "vyos")
    raw = FilePoller(tmp_path / "vyos", device_type="vyos").poll()
    assert "Opaque Area Link" in raw.opaque_te
    parser = OSPFParser(device_type="vyos")
    lsdb = parser.parse_lsdb(raw.router, raw.network, raw.external, raw.nssa, raw.opaque_te)
    assert len(lsdb.te_lsas) == 1
    assert lsdb.te_lsas[0].te_metric == 15


def test_parse_frr_opaque_te_with_bandwidth_admin_group_and_srlg() -> None:
    raw = (SAMPLES_VYOS / "opaque_te_lsdb.txt").read_text(encoding="utf-8")
    lsas = CiscoStyleTextAdapter("VyOS/FRR").parse_opaque_te(raw, None)
    assert len(lsas) == 1
    te = lsas[0]
    assert te.adv_router == "10.0.0.1"
    assert te.area == "0.0.0.0"
    assert te.link_id == "10.0.0.2"
    assert te.local_ip == "10.12.0.1"
    assert te.remote_ip == "10.12.0.2"
    assert te.te_metric == 15
    assert te.max_bw_bps == pytest.approx(1_000_000_000.0)
    assert te.max_reservable_bw_bps == pytest.approx(800_000_000.0)
    assert len(te.unreserved_bw_bps) == 8
    assert te.unreserved_bw_bps[0] == pytest.approx(800_000_000.0)
    assert te.unreserved_bw_bps[7] == pytest.approx(400_000_000.0)
    assert te.admin_groups == 0xA
    assert te.srlgs == [100, 200]


def test_parse_cisco_ios_opaque_te_text() -> None:
    cisco_text = """
                OSPF Router with ID (10.0.0.1) (Process ID 1)

                Type-10 Opaque Link Area States (Area 0.0.0.1)

  LS age: 45
  LS Type: Opaque Area Link
  Link State ID: 1.0.0.2
  Opaque Type: 1
  Opaque ID: 2
  Advertising Router: 10.0.0.1
  LS Seq Number: 80000005

    MPLS TE link LSA
      Link Type: Point-to-Point
      Link ID: 10.0.0.4
      Interface Address: 10.14.0.1
      Neighbor Address: 10.14.0.2
      Admin. Group: 0x0000000f
      TE Metric: 50
      Physical Bandwidth: 1000000000 bits/sec
      Res. Global BW: 500000000 bits/sec
      Res. BW Priority 0: 500000000 bits/sec
      Res. BW Priority 1: 400000000 bits/sec
      Shared Risk Link Group: 300
      Shared Risk Link Group: 400, 300
"""
    lsas = CiscoStyleTextAdapter("Cisco IOS / IOS-XE").parse_opaque_te(cisco_text, "1")
    assert len(lsas) == 1
    te = lsas[0]
    assert te.area == "0.0.0.1"
    assert te.link_id == "10.0.0.4"
    assert te.local_ip == "10.14.0.1"
    assert te.remote_ip == "10.14.0.2"
    assert te.te_metric == 50
    assert te.admin_groups == 0xF
    assert te.max_bw_bps == pytest.approx(1_000_000_000.0)
    assert te.srlgs == [300, 400]


def test_parse_junos_opaque_te_text() -> None:
    junos_text = """
    OSPF database, Area 0.0.0.0
 Type       ID               Adv Rtr           Seq      Age  Opt  Cksum  Len
OpaqArea   1.0.0.5          10.0.0.5         0x80000004  120 0x22 0x1234 108
  Link (2), length 96:
    Link type (1), length 1: PointToPoint (1)
    Link ID (2), length 4: 10.0.0.6
    Local interface IP address (3), length 4: 10.56.0.1
    Remote interface IP address (4), length 4: 10.56.0.2
    Traffic engineering metric (5), length 4: 30
    Maximum bandwidth (6), length 4: 10Gbps
    Maximum reservable bandwidth (7), length 4: 8000Mbps
    Unreserved bandwidth (8), length 32:
      Priority 0: 8000Mbps, Priority 1: 7000Mbps
    Administrative group (9), length 4: 0x12
    Shared risk link group (138), length 8: 77 88
"""
    from src.vendors.genie_junos import parse_junos_opaque_te_text

    lsas = parse_junos_opaque_te_text(junos_text)
    assert len(lsas) == 1
    te = lsas[0]
    assert te.adv_router == "10.0.0.5"
    assert te.link_id == "10.0.0.6"
    assert te.local_ip == "10.56.0.1"
    assert te.remote_ip == "10.56.0.2"
    assert te.te_metric == 30
    assert te.max_bw_bps == pytest.approx(10_000_000_000.0)
    assert te.max_reservable_bw_bps == pytest.approx(8_000_000_000.0)
    assert te.admin_groups == 0x12
    assert te.srlgs == [77, 88]


def test_malformed_opaque_te_lsa_is_skipped_without_failing_poll() -> None:
    bad_text = """
                OSPF Router with ID (10.0.0.1)

                Opaque Area-Link States (Area 0.0.0.0)

  LS age: 10
  LS Type: Opaque Area Link
  Link State ID: 4.0.0.0
  Advertising Router: 10.0.0.1
  Opaque Type: Router Information (4)
    Some broken line
    Maximum Bandwidth: not-a-number
    Shared Risk Link Group: abc
"""
    assert CiscoStyleTextAdapter("VyOS/FRR").parse_opaque_te(bad_text, None) == []


def test_te_attaches_to_matching_parallel_link_by_local_ip() -> None:
    from src.vendors.base import KIND_P2P, LinkRecord, RouterLsa

    lsdb = Lsdb(
        router_lsas=[
            RouterLsa(
                router_id="10.0.0.1",
                area="0.0.0.0",
                links=[
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.2", metric=10, link_data="10.12.1.1"),
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.2", metric=20, link_data="10.12.2.1"),
                ],
            ),
            RouterLsa(
                router_id="10.0.0.2",
                area="0.0.0.0",
                links=[
                    LinkRecord(kind=KIND_P2P, link_id="10.0.0.1", metric=10, link_data="10.12.1.2"),
                ],
            ),
        ],
        te_lsas=[
            TeLinkLsa(
                adv_router="10.0.0.1",
                area="0.0.0.0",
                link_id="10.0.0.2",
                local_ip="10.12.2.1",
                remote_ip="10.12.2.2",
                te_metric=55,
                max_bw_bps=1_000_000_000.0,
                srlgs=[42],
            )
        ],
    )
    parsed = OSPFParser.build_topology(lsdb)
    edge = next(
        e for e in parsed["edges"] if e["source"] == "10.0.0.1" and e["target"] == "10.0.0.2"
    )
    assert edge["parallel_links"][0]["te"]["te_metric"] == 55
    assert edge["parallel_links"][0]["te"]["srlgs"] == [42]


def test_compare_detects_te_metric_bandwidth_and_srlg_changes(tmp_path) -> None:
    from src.graph_engine import GraphEngine
    from src.vendors.base import KIND_P2P, LinkRecord, RouterLsa

    def make_graph(te_metric: int, bw: float, srlgs: list[int]):
        lsdb = Lsdb(
            router_lsas=[
                RouterLsa("10.0.0.1", "0.0.0.0", [LinkRecord(KIND_P2P, "10.0.0.2", 10, "10.12.0.1")]),
                RouterLsa("10.0.0.2", "0.0.0.0", [LinkRecord(KIND_P2P, "10.0.0.1", 10, "10.12.0.2")]),
            ],
            te_lsas=[
                TeLinkLsa(
                    adv_router="10.0.0.1",
                    area="0.0.0.0",
                    link_id="10.0.0.2",
                    local_ip="10.12.0.1",
                    te_metric=te_metric,
                    max_bw_bps=bw,
                    srlgs=srlgs,
                )
            ],
        )
        return GraphEngine(data_dir=tmp_path).build_graph(OSPFParser.build_topology(lsdb))

    engine = GraphEngine(data_dir=tmp_path)
    g1 = make_graph(10, 1_000_000_000.0, [100])
    assert engine.compare(None, g1).changed_te == []

    g2 = make_graph(50, 2_000_000_000.0, [100, 200])
    diff = engine.compare(g1, g2)
    assert diff.has_changes is True
    assert len(diff.changed_te) == 1
    chg = diff.changed_te[0]["changes"]
    assert chg["te_metric"] == {"old": 10, "new": 50}
    assert chg["max_bw_bps"] == {"old": 1_000_000_000.0, "new": 2_000_000_000.0}
    assert chg["srlgs"] == {"old": [100], "new": [100, 200]}


def test_correlation_flags_srlg_shared_risk_on_ecmp_paths(tmp_path) -> None:
    from src.correlation import SRLG_SHARED_RISK, WARNING, correlate
    from src.explorer import build_scene
    from src.graph_engine import GraphEngine, TopologyDiff
    from src.vendors.base import KIND_P2P, LinkRecord, RouterLsa

    # Diamond topology: R1 -> R2 -> R4 (cost 20, srlg 100) and R1 -> R3 -> R4 (cost 20, srlg 100)
    lsdb = Lsdb(
        router_lsas=[
            RouterLsa(
                "10.0.0.1",
                "0.0.0.0",
                [
                    LinkRecord(KIND_P2P, "10.0.0.2", 10, "10.12.0.1"),
                    LinkRecord(KIND_P2P, "10.0.0.3", 10, "10.13.0.1"),
                ],
            ),
            RouterLsa(
                "10.0.0.2",
                "0.0.0.0",
                [
                    LinkRecord(KIND_P2P, "10.0.0.1", 10, "10.12.0.2"),
                    LinkRecord(KIND_P2P, "10.0.0.4", 10, "10.24.0.2"),
                ],
            ),
            RouterLsa(
                "10.0.0.3",
                "0.0.0.0",
                [
                    LinkRecord(KIND_P2P, "10.0.0.1", 10, "10.13.0.3"),
                    LinkRecord(KIND_P2P, "10.0.0.4", 10, "10.34.0.3"),
                ],
            ),
            RouterLsa(
                "10.0.0.4",
                "0.0.0.0",
                [
                    LinkRecord(KIND_P2P, "10.0.0.2", 10, "10.24.0.4"),
                    LinkRecord(KIND_P2P, "10.0.0.3", 10, "10.34.0.4"),
                ],
            ),
        ],
        te_lsas=[
            TeLinkLsa("10.0.0.1", "0.0.0.0", "10.0.0.2", "10.12.0.1", srlgs=[100]),
            TeLinkLsa("10.0.0.1", "0.0.0.0", "10.0.0.3", "10.13.0.1", srlgs=[100]),
        ],
    )
    graph = GraphEngine(data_dir=tmp_path).build_graph(OSPFParser.build_topology(lsdb))
    report = correlate(graph)
    srlg_warns = [f for f in report.findings if f.kind == SRLG_SHARED_RISK]
    assert len(srlg_warns) >= 1
    assert any(f.severity == WARNING and 100 in (f.data.get("shared_srlgs") or []) for f in srlg_warns)

    scene = build_scene(graph, TopologyDiff())
    assert 100 in scene["meta"]["srlgs"]
