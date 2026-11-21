"""Pure-Python passive OSPF listener diagnostics (DBD MTU, GRE conntrack, iptables)."""

from __future__ import annotations

import ipaddress
import logging
import shutil
import struct
import subprocess
from typing import Any

logger = logging.getLogger("ospf_tracker.realtime.doctor")


def _extract_ip_and_ospf(packet: bytes) -> tuple[int | None, bytes]:
    """Return ``(ospf_type, ospf_body_after_24B_hdr)`` from a raw IPv4 or Ethernet frame."""
    buf = packet
    if len(buf) < 20:
        return None, b""
    # Strip Ethernet 14B header if EtherType 0x0800 appears at offset 12
    if len(buf) >= 34 and buf[12:14] == b"\x08\x00" and (buf[14] >> 4) == 4:
        buf = buf[14:]
    if (buf[0] >> 4) != 4:
        return None, b""
    ihl = (buf[0] & 0x0F) * 4
    proto = buf[9]
    if proto == 47 and len(buf) >= ihl + 24:  # IP-in-GRE encapsulation (4B GRE header)
        gre_off = ihl + 4
        if (buf[gre_off] >> 4) == 4:
            buf = buf[gre_off:]
            ihl = (buf[0] & 0x0F) * 4
            proto = buf[9]
    if proto != 89 or len(buf) < ihl + 24:
        return None, b""
    ospf_type = buf[ihl + 1]
    return ospf_type, buf[ihl + 24 :]


def check_dbd_mtu(
    *, local_mtu: int = 1500, dbd_packet: bytes | None = None
) -> dict[str, Any]:
    """Inspect captured OSPF DBD packet Interface MTU against local interface MTU."""
    if not dbd_packet:
        return {
            "check": "ospf_dbd_mtu",
            "ok": True,
            "detail": f"No DBD packet sample supplied; local interface MTU configured as {local_mtu}.",
            "remediation": "",
        }
    ospf_type, body = _extract_ip_and_ospf(dbd_packet)
    if ospf_type != 2 or len(body) < 2:
        return {
            "check": "ospf_dbd_mtu",
            "ok": False,
            "detail": "Captured packet is not a valid OSPFv2 Database Description (Type 2) packet.",
            "remediation": "Verify OSPF protocol 89 traffic is reaching the passive interface.",
        }
    (peer_mtu,) = struct.unpack_from("!H", body, 0)
    if peer_mtu != local_mtu:
        return {
            "check": "ospf_dbd_mtu",
            "ok": False,
            "detail": f"MTU mismatch: peer advertises {peer_mtu}, local interface MTU is {local_mtu}.",
            "remediation": f"Align interface MTU (`ip link set dev <iface> mtu {peer_mtu}`) or enable `ip ospf mtu-ignore`.",
        }
    return {
        "check": "ospf_dbd_mtu",
        "ok": True,
        "detail": f"Peer DBD MTU {peer_mtu} matches local MTU {local_mtu}.",
        "remediation": "",
    }


def check_gre_conntrack(conntrack_output: str, peer_ip: str | None = None) -> dict[str, Any]:
    """Detect stale [UNREPLIED] or ASSURED-less GRE conntrack entries blocking return OSPF."""
    lines = [
        line.strip()
        for line in (conntrack_output or "").splitlines()
        if "gre" in line.lower() and (not peer_ip or peer_ip in line)
    ]
    unreplied = [ln for ln in lines if "[UNREPLIED]" in ln]
    if unreplied:
        target = f"-d {peer_ip}" if peer_ip else "-p gre"
        return {
            "check": "gre_conntrack",
            "ok": False,
            "detail": f"Found {len(unreplied)} stale [UNREPLIED] GRE conntrack state(s).",
            "remediation": f"Flush stale conntrack states: `sudo conntrack -D -p gre {target}`.",
        }
    return {
        "check": "gre_conntrack",
        "ok": True,
        "detail": "No stale UNREPLIED GRE conntrack entries found.",
        "remediation": "",
    }


def check_iptables_rules(iptables_save_output: str, iface: str = "gre1") -> dict[str, Any]:
    """Verify host firewall allows GRE (proto 47) and OSPF (proto 89) traffic."""
    text = iptables_save_output or ""
    has_gre = ("-p gre" in text) or ("-p 47" in text) or (iface in text)
    has_ospf = ("-p ospf" in text) or ("-p 89" in text) or (iface in text)
    if has_gre or has_ospf:
        return {
            "check": "iptables_gre",
            "ok": True,
            "detail": f"GRE/OSPF firewall match found for {iface}.",
            "remediation": "",
        }
    return {
        "check": "iptables_gre",
        "ok": False,
        "detail": f"No explicit GRE (47) or OSPF (89) rule matched in iptables for {iface}.",
        "remediation": f"Allow GRE & OSPF: `sudo iptables -I INPUT -p 47 -j ACCEPT && sudo iptables -I INPUT -i {iface} -p 89 -j ACCEPT`.",
    }


def _safe_cmd(cmd: list[str]) -> str:
    exe = shutil.which(cmd[0])
    if exe is None:
        return ""
    try:
        return subprocess.check_output(cmd, text=True, timeout=5, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""


def run_passive_doctor(
    *,
    mode: str = "gre",
    iface: str = "gre1",
    peer_ip: str | None = None,
    local_mtu: int = 1500,
    dbd_packet: bytes | None = None,
) -> list[dict[str, Any]]:
    """Run passive OSPF sidecar checks (skips GRE conntrack/iptables checks in ``macvlan`` mode)."""
    if peer_ip:
        ipaddress.ip_address(peer_ip)
    checks: list[dict[str, Any]] = [check_dbd_mtu(local_mtu=local_mtu, dbd_packet=dbd_packet)]
    if mode.lower() == "gre":
        checks.append(check_gre_conntrack(_safe_cmd(["conntrack", "-L", "-p", "gre"]), peer_ip))
        checks.append(check_iptables_rules(_safe_cmd(["iptables-save"]), iface))
    return checks
