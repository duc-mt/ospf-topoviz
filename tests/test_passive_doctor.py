"""Unit tests for passive OSPF sidecar connection diagnostics (--doctor-passive)."""

from __future__ import annotations

import socket
import struct

import main
from src.realtime.doctor import (
    check_dbd_mtu,
    check_gre_conntrack,
    check_iptables_rules,
    run_passive_doctor,
)


def _ospf_dbd_frame(router_id: str, interface_mtu: int) -> bytes:
    # 20-byte IPv4 header (proto=89 OSPF) + 24-byte OSPF header (type=2 DBD) + 8-byte DBD body
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        52,
        1,
        0,
        64,
        89,
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("10.0.0.2"),
    )
    ospf_hdr = struct.pack(
        "!BBH4s4sHHQ",
        2,  # OSPFv2
        2,  # DBD
        32,
        socket.inet_aton(router_id),
        socket.inet_aton("0.0.0.0"),
        0,
        0,
        0,
    )
    dbd_body = struct.pack("!HBBI", interface_mtu, 0x02, 0x07, 1)
    return ip_hdr + ospf_hdr + dbd_body


def test_doctor_detects_mtu_mismatch_from_ospf_dbd_bytes() -> None:
    frame = _ospf_dbd_frame("10.0.0.1", interface_mtu=1400)
    res = check_dbd_mtu(local_mtu=1500, dbd_packet=frame)
    assert res["ok"] is False
    assert "1400" in res["detail"] and "1500" in res["detail"]
    assert "mtu" in res["remediation"].lower()

    ok_res = check_dbd_mtu(local_mtu=1400, dbd_packet=frame)
    assert ok_res["ok"] is True


def test_doctor_detects_stale_gre_conntrack_and_missing_iptables_rules() -> None:
    conntrack_out = "gre 47 29 src=192.0.2.1 dst=192.0.2.2 [UNREPLIED]\n"
    ct = check_gre_conntrack(conntrack_out, peer_ip="192.0.2.2")
    assert ct["ok"] is False
    assert "conntrack" in ct["remediation"]

    iptables_out = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    ipt = check_iptables_rules(iptables_out, iface="gre1")
    assert ipt["ok"] is False
    assert "47" in ipt["remediation"] or "gre1" in ipt["remediation"]


def test_doctor_macvlan_mode_skips_gre_conntrack_and_iptables_checks(capsys) -> None:
    checks = run_passive_doctor(
        mode="macvlan",
        iface="eth1",
        peer_ip="192.0.2.2",
        local_mtu=1500,
    )
    names = [c["check"] for c in checks]
    assert "gre_conntrack" not in names
    assert "iptables_gre" not in names

    code = main.main(["--doctor-passive", "--passive-mode", "macvlan", "--iface", "eth1"])
    assert code == main.EXIT_OK
    out = capsys.readouterr().out
    assert "macvlan" in out.lower()
