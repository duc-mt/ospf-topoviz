"""Unit tests for native BGP-LS TCP/179 speaker, startup settle window, and router config CLI."""

from __future__ import annotations

import socket
import struct
import threading

import main
from src.realtime.bgpls_collector import (
    BgpLsCollector,
    encode_bgp_message,
    encode_bgp_open,
    render_bgpls_router_configs,
)
from src.realtime.bgpls_translator import BgplsConfig
from src.vendors.base import Lsdb


def _tlv(t: int, v: bytes) -> bytes:
    return struct.pack(">HH", t, len(v)) + v


def _build_bgpls_wire_update() -> bytes:
    # Node NLRI (type 1, len): proto=3 (OSPFv2), id=0, Local Node Desc TLV 256 (Area 0.0.0.0 + Router-ID 10.0.0.1)
    node_desc = _tlv(514, socket.inet_aton("0.0.0.0")) + _tlv(515, socket.inet_aton("10.0.0.1"))
    node_body = struct.pack(">BQ", 3, 0) + _tlv(256, node_desc)
    node_nlri = struct.pack(">HH", 1, len(node_body)) + node_body

    # Link NLRI (type 2): R1 (10.0.0.1) -> R2 (10.0.0.2)
    r2_desc = _tlv(514, socket.inet_aton("0.0.0.0")) + _tlv(515, socket.inet_aton("10.0.0.2"))
    link_body = (
        struct.pack(">BQ", 3, 0)
        + _tlv(256, node_desc)
        + _tlv(257, r2_desc)
        + _tlv(259, socket.inet_aton("10.12.0.1"))
        + _tlv(260, socket.inet_aton("10.12.0.2"))
    )
    link_nlri = struct.pack(">HH", 2, len(link_body)) + link_body

    # MP_REACH_NLRI (attr 14, extended-length flag 0x90): AFI=16388, SAFI=71, NH len=4 (192.0.2.1), reserved=0
    mp_reach_val = struct.pack(">HBB4sB", 16388, 71, 4, socket.inet_aton("192.0.2.1"), 0) + node_nlri + link_nlri
    mp_reach_attr = struct.pack(">BBH", 0x90, 14, len(mp_reach_val)) + mp_reach_val

    # BGP-LS Attribute (attr 29, optional transitive flag 0xC0): IGP Metric TLV 1095 (cost=15) + SRLG TLV 1096 ([100])
    ls_attr_val = _tlv(1095, struct.pack(">H", 15)) + _tlv(1096, struct.pack(">I", 100))
    ls_attr = struct.pack(">BBB", 0xC0, 29, len(ls_attr_val)) + ls_attr_val

    path_attrs = mp_reach_attr + ls_attr
    update_payload = struct.pack(">HH", 0, len(path_attrs)) + path_attrs
    return encode_bgp_message(2, update_payload)


def test_bgpls_wire_open_keepalive_and_mp_reach_update_decodes_and_emits_lsdb() -> None:
    emitted: list[Lsdb] = []
    done = threading.Event()

    def on_lsdb(lsdb: Lsdb) -> None:
        emitted.append(lsdb)
        done.set()

    cfg = BgplsConfig(
        enabled=True,
        listen_address="127.0.0.1",
        listen_port=0,
        local_as=65001,
        router_id="192.0.2.100",
        settle_seconds=0.05,
    )
    collector = BgpLsCollector(cfg, on_lsdb=on_lsdb)
    collector.start()
    try:
        with socket.create_connection(("127.0.0.1", collector.server_port), timeout=3.0) as sock:
            sock.sendall(encode_bgp_open(asn=65002, hold_time=90, router_id="10.0.0.1"))
            hdr = sock.recv(19)
            assert len(hdr) == 19 and hdr[18] == 1  # OPEN
            open_len = struct.unpack(">H", hdr[16:18])[0] - 19
            if open_len > 0:
                sock.recv(open_len)
            sock.sendall(encode_bgp_message(4, b""))  # KEEPALIVE
            sock.sendall(_build_bgpls_wire_update())
            assert done.wait(timeout=3.0)
    finally:
        collector.stop()

    assert len(emitted) >= 1
    lsdb = emitted[-1]
    r1 = next(r for r in lsdb.router_lsas if r.router_id == "10.0.0.1")
    assert any(lk.link_id == "10.0.0.2" and lk.metric == 15 for lk in r1.links)
    assert any(te.srlgs == [100] for te in lsdb.te_lsas)


def test_startup_settle_window_builds_initial_baseline_without_spurious_events() -> None:
    emitted: list[Lsdb] = []
    done = threading.Event()

    def on_lsdb(lsdb: Lsdb) -> None:
        emitted.append(lsdb)
        done.set()

    collector = BgpLsCollector(
        BgplsConfig(settle_seconds=0.2),
        on_lsdb=on_lsdb,
    )
    # Rapid burst of 5 initial updates during settle window should emit ONE consolidated snapshot
    for rid in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"):
        collector.state.apply_reach(
            {"nlri_type": 1, "protocol_id": 3, "area": "0.0.0.0", "router_id": rid},
            {},
        )
        collector.schedule_emit()

    assert len(emitted) == 0  # still settling
    assert done.wait(timeout=2.0)
    collector.stop()
    assert len(emitted) == 1
    assert len(emitted[0].router_lsas) == 5


def test_show_bgpls_config_prints_iosxr_frr_eos_junos_snippets(capsys) -> None:
    code = main.main(["--show-bgpls-config"])
    assert code == main.EXIT_OK
    out = capsys.readouterr().out
    for kw in ("IOS-XR", "NX-OS", "FRR", "Arista EOS", "Junos", "link-state"):
        assert kw in out
    rendered = render_bgpls_router_configs(local_as=65001, collector_ip="192.0.2.100")
    assert "65001" in rendered
    assert "192.0.2.100" in rendered
