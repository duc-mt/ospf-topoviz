"""Authenticated, debounced LSDB push ingestion coordinator."""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any

from src.parser import OSPFParser
from src.poller import PollBusyError, PollLock
from src.vendors.base import (
    ExternalLsa,
    LinkRecord,
    Lsdb,
    NeighborRecord,
    NetworkLsa,
    NextHop,
    OSPFRoute,
    RouterLsa,
    SourceDetail,
    TeLinkLsa,
    dotted_area,
)

if TYPE_CHECKING:
    from src.graph_engine import GraphEngine
    from src.web.server import EventBroker

logger = logging.getLogger("ospf_tracker.realtime.ingest")


def _is_loopback(host: str) -> bool:
    clean = host.strip().split("%", 1)[0]
    if clean in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(clean).is_loopback
    except ValueError:
        return False


def _opt_int(val: Any) -> int | None:
    if val is None:
        return None
    return int(val)


def _opt_float(val: Any) -> float | None:
    if val is None:
        return None
    return float(val)


def lsdb_from_payload(
    payload: dict[str, Any],
) -> tuple[Lsdb, list[SourceDetail], dict[str, Any]]:
    """Validate and convert an HTTP push JSON dictionary into an ``Lsdb`` + ``SourceDetail`` list.

    Raises:
        ValueError: If the payload structure is malformed or contains zero router LSAs.
    """
    if not isinstance(payload, dict):
        raise ValueError("ingest payload must be a JSON object")

    raw_lsdb = payload["lsdb"] if isinstance(payload.get("lsdb"), dict) else payload
    raw_routers = raw_lsdb.get("router_lsas")
    if not isinstance(raw_routers, list) or not raw_routers:
        raise ValueError("lsdb.router_lsas must be a non-empty list")

    router_lsas: list[RouterLsa] = []
    for item in raw_routers:
        if not isinstance(item, dict) or not item.get("router_id") or "area" not in item:
            raise ValueError("each router_lsa requires 'router_id' and 'area'")
        links = []
        for lk in item.get("links") or ():
            if not isinstance(lk, dict) or not lk.get("kind") or not lk.get("link_id"):
                raise ValueError("each link requires 'kind' and 'link_id'")
            links.append(
                LinkRecord(
                    kind=str(lk["kind"]),
                    link_id=str(lk["link_id"]),
                    metric=_opt_int(lk.get("metric")),
                    link_data=str(lk["link_data"]) if lk.get("link_data") is not None else None,
                )
            )
        router_lsas.append(
            RouterLsa(
                router_id=str(item["router_id"]),
                area=dotted_area(str(item["area"])),
                links=links,
                seq=_opt_int(item.get("seq")),
                age=_opt_int(item.get("age")),
                abr=bool(item.get("abr", False)),
                asbr=bool(item.get("asbr", False)),
                max_metric=bool(item.get("max_metric", False)),
            )
        )

    network_lsas: list[NetworkLsa] = []
    for item in raw_lsdb.get("network_lsas") or ():
        if not isinstance(item, dict) or not item.get("address") or not item.get("dr"):
            raise ValueError("each network_lsa requires 'address' and 'dr'")
        network_lsas.append(
            NetworkLsa(
                address=str(item["address"]),
                dr=str(item["dr"]),
                area=dotted_area(str(item.get("area") or "0.0.0.0")),
                mask=str(item["mask"]) if item.get("mask") is not None else None,
                attached=[str(r) for r in (item.get("attached") or ())],
                seq=_opt_int(item.get("seq")),
                age=_opt_int(item.get("age")),
            )
        )

    def _ext_list(raw_list: Any) -> list[ExternalLsa]:
        out: list[ExternalLsa] = []
        for item in raw_list or ():
            if not isinstance(item, dict):
                raise ValueError("external_lsa item must be an object")
            out.append(
                ExternalLsa(
                    adv_router=str(item["adv_router"]),
                    prefix=str(item["prefix"]),
                    metric=int(item["metric"]),
                    metric_type=str(item.get("metric_type") or "E2"),
                    forwarding_address=str(item.get("forwarding_address") or "0.0.0.0"),
                    tag=int(item.get("tag") or 0),
                    area=dotted_area(str(item["area"])) if item.get("area") else None,
                    age=_opt_int(item.get("age")),
                    seq=_opt_int(item.get("seq")),
                )
            )
        return out

    te_lsas: list[TeLinkLsa] = []
    for item in raw_lsdb.get("te_lsas") or ():
        if not isinstance(item, dict) or not item.get("adv_router") or not item.get("link_id"):
            raise ValueError("each te_lsa requires 'adv_router' and 'link_id'")
        te_lsas.append(
            TeLinkLsa(
                adv_router=str(item["adv_router"]),
                area=dotted_area(str(item.get("area") or "0.0.0.0")),
                link_id=str(item["link_id"]),
                local_ip=str(item["local_ip"]) if item.get("local_ip") is not None else None,
                remote_ip=str(item["remote_ip"]) if item.get("remote_ip") is not None else None,
                te_metric=_opt_int(item.get("te_metric")),
                max_bw_bps=_opt_float(item.get("max_bw_bps")),
                max_reservable_bw_bps=_opt_float(item.get("max_reservable_bw_bps")),
                unreserved_bw_bps=[float(x) for x in (item.get("unreserved_bw_bps") or ())],
                admin_groups=_opt_int(item.get("admin_groups")),
                srlgs=sorted({int(x) for x in (item.get("srlgs") or ())}),
                age=_opt_int(item.get("age")),
                seq=_opt_int(item.get("seq")),
            )
        )

    lsdb = Lsdb(
        router_lsas=router_lsas,
        network_lsas=network_lsas,
        process_ids=[str(p) for p in (raw_lsdb.get("process_ids") or ())],
        router_id=str(raw_lsdb["router_id"]) if raw_lsdb.get("router_id") else None,
        external_lsas=_ext_list(raw_lsdb.get("external_lsas")),
        nssa_lsas=_ext_list(raw_lsdb.get("nssa_lsas")),
        te_lsas=te_lsas,
        ip_version=int(raw_lsdb.get("ip_version", 4)),
    )

    details: list[SourceDetail] = []
    for det in payload.get("details") or ():
        if not isinstance(det, dict):
            continue
        nbrs = [
            NeighborRecord(
                router_id=str(n["router_id"]),
                state=str(n.get("state") or "Full"),
                role=n.get("role"),
                interface=n.get("interface"),
                address=n.get("address"),
                area=n.get("area"),
                priority=_opt_int(n.get("priority")),
                dead_time=_opt_int(n.get("dead_time")),
            )
            for n in (det.get("neighbors") or ())
        ]
        routes = None
        if det.get("routes") is not None:
            routes = [
                OSPFRoute(
                    prefix=str(r["prefix"]),
                    mask=str(r["mask"]),
                    route_type=str(r["route_type"]),
                    metric=_opt_int(r.get("metric")),
                    next_hops=[
                        NextHop(ip=h.get("ip"), interface=h.get("interface"))
                        for h in (r.get("next_hops") or ())
                    ],
                    active=bool(r.get("active", True)),
                )
                for r in det["routes"]
            ]
        details.append(
            SourceDetail(
                name=str(det.get("name") or payload.get("source") or "ingest"),
                router_id=det.get("router_id"),
                neighbors=nbrs,
                routes=routes,
                neighbors_known=bool(det.get("neighbors_known", True)),
            )
        )

    meta = {
        "device_type": str(payload.get("source") or "push_ingest"),
        "scope": str(payload.get("scope") or "default"),
    }
    return lsdb, details, meta


class IngestCoordinator:
    """Thread-safe debounced coordinator feeding pushed ``Lsdb`` snapshots through GraphEngine."""

    def __init__(
        self,
        data_dir: Any,
        engine: GraphEngine,
        broker: EventBroker | None = None,
        *,
        token: str | None = None,
        token_env: str = "OSPF_MONITOR_INGEST_TOKEN",
        debounce_seconds: float = 0.0,
        dispatcher: Any = None,
    ) -> None:
        self.data_dir = data_dir
        self.engine = engine
        self.broker = broker
        self._explicit_token = token
        self._token_env = token_env
        self.debounce_seconds = max(0.0, float(debounce_seconds))
        self.dispatcher = dispatcher

        self._lock = threading.Lock()
        self._pending: tuple[Lsdb, list[SourceDetail], dict[str, Any]] | None = None
        self._timer: threading.Timer | None = None
        self._idle = threading.Event()
        self._idle.set()

    def configured_token(self) -> str:
        """Active Bearer token from explicit config or environment."""
        if self._explicit_token is not None:
            return self._explicit_token
        return str(os.environ.get(self._token_env) or "")

    def verify_token(self, auth_header: str | None, remote_host: str = "127.0.0.1") -> bool:
        """Enforce Bearer token auth whenever configured or exposed beyond loopback."""
        expected = self.configured_token()
        if not expected:
            return _is_loopback(remote_host)
        if not auth_header:
            return False
        scheme, _, candidate = auth_header.strip().partition(" ")
        if scheme.lower() != "bearer" or not candidate:
            return False
        return hmac.compare_digest(candidate, expected)

    def submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Validate and process (or debounce) one pushed LSDB payload."""
        lsdb, details, meta = lsdb_from_payload(payload)
        if self.debounce_seconds <= 0:
            run_id, ev_count = self._execute(lsdb, details, meta)
            return {
                "accepted": True,
                "queued": False,
                "run_id": run_id,
                "events": ev_count,
            }

        with self._lock:
            self._pending = (lsdb, details, meta)
            self._idle.clear()
            if self._timer is not None:
                self._timer.cancel()
            timer = threading.Timer(self.debounce_seconds, self._flush_debounced)
            timer.daemon = True
            self._timer = timer
            timer.start()
        return {"accepted": True, "queued": True}

    def wait(self, timeout: float | None = None) -> bool:
        """Block until any scheduled debounced ingest finishes processing."""
        return self._idle.wait(timeout)

    def _flush_debounced(self) -> None:
        with self._lock:
            item = self._pending
            self._pending = None
            self._timer = None
        try:
            if item is not None:
                lsdb, details, meta = item
                self._execute(lsdb, details, meta)
        except Exception:
            logger.exception("Debounced LSDB ingest failed")
        finally:
            with self._lock:
                if self._pending is None and self._timer is None:
                    self._idle.set()

    def _execute(
        self, lsdb: Lsdb, details: list[SourceDetail], meta: dict[str, Any]
    ) -> tuple[str | None, int]:
        lock = PollLock(self.data_dir / ".poll.lock")
        deadline = time.monotonic() + 5.0
        while not lock.acquire():
            if time.monotonic() >= deadline:
                raise PollBusyError("Another poll holds the lock during ingest")
            time.sleep(0.05)
        try:
            parsed = OSPFParser.build_topology(lsdb, meta, details)
            _graph, diff = self.engine.process(parsed, details=details)
            run_id = self.engine.last_run_id
            events = list(self.engine.last_events)
            if self.broker is not None and diff.baseline_updated:
                self.broker.publish(
                    "topology_updated",
                    {
                        "run_id": run_id,
                        "events": len(events),
                        "source": meta.get("device_type", "ingest"),
                    },
                    event_id=run_id,
                )
            if self.dispatcher is not None and events and diff.baseline_updated:
                self.dispatcher.export_events(events)
            return run_id, len(events)
        finally:
            lock.release()
