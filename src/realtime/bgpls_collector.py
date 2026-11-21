"""Passive RFC 4271 / 4760 / 7752 BGP-LS TCP/179 listener and router config snippet generator."""

from __future__ import annotations

import contextlib
import logging
import socket
import struct
import threading
from collections.abc import Callable
from typing import Any

from src.realtime.bgpls_translator import (
    BgplsConfig,
    BgpLsState,
    decode_bgpls_attr,
    decode_bgpls_nlris,
)
from src.vendors.base import Lsdb

logger = logging.getLogger("ospf_tracker.realtime.bgpls")

_BGP_MARKER = b"\xff" * 16
MSG_OPEN = 1
MSG_UPDATE = 2
MSG_NOTIFICATION = 3
MSG_KEEPALIVE = 4

AFI_BGPLS = 16388
SAFI_BGPLS = 71


def encode_bgp_message(msg_type: int, payload: bytes) -> bytes:
    """Frame a BGP-4 message with the 16-byte marker, length, and type."""
    total_len = 19 + len(payload)
    return _BGP_MARKER + struct.pack(">HB", total_len, msg_type) + payload


def encode_bgp_open(asn: int, hold_time: int, router_id: str) -> bytes:
    """Build a BGP OPEN carrying Multiprotocol Capability (AFI=16388, SAFI=71) & 4-byte ASN."""
    cap_mp = struct.pack(">BBHBB", 1, 4, AFI_BGPLS, 0, SAFI_BGPLS)
    cap_as4 = struct.pack(">BBI", 65, 4, asn)
    caps = cap_mp + cap_as4
    opt_param = struct.pack(">BB", 2, len(caps)) + caps
    asn2 = asn if asn <= 65535 else 23456
    rid_bytes = socket.inet_aton(router_id)
    body = (
        struct.pack(">BHH4sB", 4, asn2, hold_time, rid_bytes, len(opt_param))
        + opt_param
    )
    return encode_bgp_message(MSG_OPEN, body)


def _parse_path_attributes(buf: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    reach_nlris: list[dict[str, Any]] = []
    unreach_nlris: list[dict[str, Any]] = []
    ls_attrs: dict[str, Any] = {}
    pos = 0
    while pos + 2 <= len(buf):
        flags = buf[pos]
        code = buf[pos + 1]
        pos += 2
        ext_len = bool(flags & 0x10)
        if ext_len:
            if pos + 2 > len(buf):
                break
            length = struct.unpack_from(">H", buf, pos)[0]
            pos += 2
        else:
            if pos + 1 > len(buf):
                break
            length = buf[pos]
            pos += 1
        if pos + length > len(buf):
            break
        val = buf[pos : pos + length]
        pos += length

        if code == 14 and len(val) >= 5:  # MP_REACH_NLRI
            afi, safi, nh_len = struct.unpack_from(">HBB", val, 0)
            nlri_off = 4 + nh_len + 1
            if afi == AFI_BGPLS and safi == SAFI_BGPLS and nlri_off <= len(val):
                reach_nlris.extend(decode_bgpls_nlris(val[nlri_off:]))
        elif code == 15 and len(val) >= 3:  # MP_UNREACH_NLRI
            afi, safi = struct.unpack_from(">HB", val, 0)
            if afi == AFI_BGPLS and safi == SAFI_BGPLS:
                unreach_nlris.extend(decode_bgpls_nlris(val[3:]))
        elif code == 29:  # BGP-LS Path Attribute
            ls_attrs.update(decode_bgpls_attr(val))
    return reach_nlris, unreach_nlris, ls_attrs


class BgpLsCollector:
    """Passive RFC 4271 / 7752 BGP-LS TCP collector with startup baseline settle debouncing."""

    def __init__(
        self,
        config: BgplsConfig,
        on_lsdb: Callable[[Lsdb], Any] | None = None,
    ) -> None:
        self.config = config
        self.on_lsdb = on_lsdb
        self.state = BgpLsState()

        self._srv_sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop_ev = threading.Event()
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None

    @property
    def server_port(self) -> int:
        if self._srv_sock is None:
            return self.config.listen_port
        return int(self._srv_sock.getsockname()[1])

    def start(self) -> None:
        """Bind listening TCP socket and accept BGP-LS sessions in daemon threads."""
        if self._srv_sock is not None:
            return
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.config.listen_address, self.config.listen_port))
        srv.listen(8)
        srv.settimeout(0.5)
        self._srv_sock = srv
        self._stop_ev.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="bgpls-accept", daemon=True
        )
        self._accept_thread.start()
        logger.info(
            "Passive BGP-LS listener bound on %s:%s (AS %s)",
            self.config.listen_address,
            self.server_port,
            self.config.local_as,
        )

    def stop(self) -> None:
        """Stop listener socket and cancel pending emit timer."""
        self._stop_ev.set()
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        if self._srv_sock is not None:
            with contextlib.suppress(OSError):
                self._srv_sock.close()
            self._srv_sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None

    def schedule_emit(self) -> None:
        """Coalesce rapid initial or burst BGP-LS UPDATEs inside ``settle_seconds`` before emitting."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            delay = self.config.settle_seconds
            if delay <= 0:
                self._timer = None
                lsdb = self.state.to_lsdb()
            else:
                timer = threading.Timer(delay, self._emit_now)
                timer.daemon = True
                self._timer = timer
                timer.start()
                return
        if self.on_lsdb is not None and lsdb.router_lsas:
            self.on_lsdb(lsdb)

    def _emit_now(self) -> None:
        with self._lock:
            self._timer = None
            lsdb = self.state.to_lsdb()
        if self.on_lsdb is not None and lsdb.router_lsas:
            try:
                self.on_lsdb(lsdb)
            except Exception:
                logger.exception("BGP-LS on_lsdb callback failed")

    def _accept_loop(self) -> None:
        while not self._stop_ev.is_set() and self._srv_sock is not None:
            try:
                conn, addr = self._srv_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_peer, args=(conn, addr), name=f"bgpls-{addr[0]}", daemon=True
            ).start()

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return b""
            buf.extend(chunk)
        return bytes(buf)

    def _handle_peer(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        conn.settimeout(2.0)
        try:
            while not self._stop_ev.is_set():
                try:
                    hdr = self._recv_exact(conn, 19)
                except TimeoutError:
                    continue
                if len(hdr) < 19 or hdr[:16] != _BGP_MARKER:
                    break
                msg_len = struct.unpack_from(">H", hdr, 16)[0]
                msg_type = hdr[18]
                payload_len = msg_len - 19
                if payload_len < 0:
                    break
                payload = self._recv_exact(conn, payload_len) if payload_len else b""
                if len(payload) < payload_len:
                    break

                if msg_type == MSG_OPEN:
                    conn.sendall(
                        encode_bgp_open(
                            self.config.local_as,
                            self.config.hold_time,
                            self.config.router_id,
                        )
                    )
                    conn.sendall(encode_bgp_message(MSG_KEEPALIVE, b""))
                elif msg_type == MSG_KEEPALIVE:
                    conn.sendall(encode_bgp_message(MSG_KEEPALIVE, b""))
                elif msg_type == MSG_UPDATE:
                    self._process_update(payload)
                elif msg_type == MSG_NOTIFICATION:
                    logger.warning("BGP-LS peer %s sent NOTIFICATION", addr[0])
                    break
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _process_update(self, payload: bytes) -> None:
        if len(payload) < 4:
            return
        withdrawn_len = struct.unpack_from(">H", payload, 0)[0]
        attr_pos = 2 + withdrawn_len
        if attr_pos + 2 > len(payload):
            return
        attrs_len = struct.unpack_from(">H", payload, attr_pos)[0]
        attrs_bytes = payload[attr_pos + 2 : attr_pos + 2 + attrs_len]
        reach_nlris, unreach_nlris, ls_attrs = _parse_path_attributes(attrs_bytes)
        changed = False
        with self._lock:
            for nlri in reach_nlris:
                changed = self.state.apply_reach(nlri, ls_attrs) or changed
            for nlri in unreach_nlris:
                changed = self.state.apply_unreach(nlri) or changed
        if changed:
            self.schedule_emit()


def render_bgpls_router_configs(
    *,
    local_as: int = 65001,
    collector_ip: str = "192.0.2.100",
    peer_as: int | None = None,
) -> str:
    """Return copy-paste BGP-LS distribution configuration snippets for major vendors."""
    pas = peer_as or local_as
    return f"""# ======================== OSPF TopoViz BGP-LS Configuration ========================
# Collector: {collector_ip} (TCP/179, AFI 16388 / SAFI 71) | AS {local_as}

# --- Cisco IOS-XR ---
router ospf 1
 distribute link-state
!
router bgp {pas}
 neighbor {collector_ip}
  remote-as {local_as}
  address-family link-state link-state
!

# --- Cisco NX-OS ---
feature bgp
router ospf 1
 ! distribute-ls enabled under process if supported
router bgp {pas}
 neighbor {collector_ip} remote-as {local_as}
  address-family link-state
!

# --- VyOS / FRR (ospfd + bgpd) ---
router ospf
 capability opaque
 ospf router-info area 0.0.0.0
 mpls-te on
router bgp {pas}
 neighbor {collector_ip} remote-as {local_as}
 address-family link-state link-state
  neighbor {collector_ip} activate
!

# --- Arista EOS ---
router ospf 1
 traffic-engineering
router bgp {pas}
 neighbor {collector_ip} remote-as {local_as}
 address-family link-state
  neighbor {collector_ip} activate
!

# --- Juniper Junos ---
set protocols ospf traffic-engineering
set protocols bgp group OSPF-TOPOVIZ type internal
set protocols bgp group OSPF-TOPOVIZ local-as {pas}
set protocols bgp group OSPF-TOPOVIZ family traffic-engineering unicast
set protocols bgp group OSPF-TOPOVIZ neighbor {collector_ip} peer-as {local_as}
"""
