"""Poll local FRR OSPF JSON LSDB and push snapshots to OSPF TopoViz POST /api/ingest/lsdb."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

from src.vendors.base import KIND_P2P, KIND_STUB, KIND_TRANSIT, dotted_area

logger = logging.getLogger("ospf_tracker.passive.exporter")


def _link_kind_from_frr(raw_type: str) -> str:
    low = raw_type.lower()
    if "stub" in low:
        return KIND_STUB
    if "transit" in low:
        return KIND_TRANSIT
    return KIND_P2P


def frr_json_to_ingest_payload(
    router_json: dict[str, Any],
    network_json: dict[str, Any] | None = None,
    external_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert FRR ``show ip ospf database ... json`` dicts to ``POST /api/ingest/lsdb`` payload."""
    router_lsas: list[dict[str, Any]] = []
    for area_key, area_body in (router_json.get("areas") or {}).items():
        area = dotted_area(str(area_key))
        for lsa in area_body.get("routerLinkStates") or ():
            links = []
            for lk in lsa.get("links") or ():
                kind = _link_kind_from_frr(str(lk.get("linkType") or "p2p"))
                if kind == KIND_STUB:
                    link_id = str(lk.get("network") or lk.get("linkId") or "")
                    link_data = lk.get("mask") or lk.get("linkData")
                else:
                    link_id = str(
                        lk.get("neighborRouterId")
                        or lk.get("designatedRouterAddress")
                        or lk.get("linkId")
                        or ""
                    )
                    link_data = lk.get("routerInterfaceAddress") or lk.get("linkData")
                if not link_id:
                    continue
                links.append(
                    {
                        "kind": kind,
                        "link_id": link_id,
                        "metric": lk.get("metric"),
                        "link_data": link_data,
                    }
                )
            flags = lsa.get("routerLsaFlags") or {}
            router_lsas.append(
                {
                    "router_id": str(lsa.get("advertisingRouter") or lsa.get("linkStateId") or ""),
                    "area": area,
                    "age": lsa.get("lsaAge"),
                    "abr": bool(flags.get("abr", False)),
                    "asbr": bool(flags.get("asbr", False)),
                    "links": links,
                }
            )

    network_lsas: list[dict[str, Any]] = []
    for area_key, area_body in ((network_json or {}).get("areas") or {}).items():
        area = dotted_area(str(area_key))
        for lsa in area_body.get("networkLinkStates") or ():
            network_lsas.append(
                {
                    "address": str(lsa.get("linkStateId") or ""),
                    "dr": str(lsa.get("advertisingRouter") or ""),
                    "area": area,
                    "mask": lsa.get("networkMask"),
                    "attached": [str(a) for a in (lsa.get("attachedRouters") or ())],
                    "age": lsa.get("lsaAge"),
                }
            )

    external_lsas: list[dict[str, Any]] = []
    for lsa in (external_json or {}).get("asExternalLinkStates") or ():
        external_lsas.append(
            {
                "adv_router": str(lsa.get("advertisingRouter") or ""),
                "prefix": str(lsa.get("network") or lsa.get("linkStateId") or ""),
                "metric": int(lsa.get("metric") or 0),
                "metric_type": str(lsa.get("metricType") or "E2"),
                "forwarding_address": str(lsa.get("forwardAddress") or "0.0.0.0"),
                "tag": int(lsa.get("tag") or 0),
                "age": lsa.get("lsaAge"),
            }
        )

    return {
        "source": "passive_frr",
        "mode": "snapshot",
        "lsdb": {
            "router_id": router_json.get("routerId"),
            "router_lsas": router_lsas,
            "network_lsas": network_lsas,
            "external_lsas": external_lsas,
        },
    }


class PassiveExporter:
    """Pushes changed FRR JSON LSDB snapshots to ``POST /api/ingest/lsdb``."""

    def __init__(
        self,
        ingest_url: str,
        token: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.ingest_url = ingest_url
        self.token = token if token is not None else os.environ.get("OSPF_MONITOR_INGEST_TOKEN", "")
        self.timeout = timeout
        self._last_digest: str | None = None

    def push_if_changed(
        self,
        router_json: dict[str, Any],
        network_json: dict[str, Any] | None = None,
        external_json: dict[str, Any] | None = None,
    ) -> bool:
        """Convert FRR JSON dicts and POST only if the canonical LSDB digest changed."""
        payload = frr_json_to_ingest_payload(router_json, network_json, external_json)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(body).hexdigest()
        if digest == self._last_digest:
            return False

        headers = {"Content-Type": "application/json; charset=utf-8"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.ingest_url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if 200 <= getattr(resp, "status", 200) < 300:
                    self._last_digest = digest
                    return True
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning("Passive FRR ingest push failed: %s", exc)
        return False


def _vtysh_json(cmd: str) -> dict[str, Any]:
    out = subprocess.check_output(["vtysh", "-c", cmd], text=True, timeout=15)
    return json.loads(out or "{}")


def main() -> None:  # pragma: no cover - runtime daemon entry point
    logging.basicConfig(level=logging.INFO)
    url = os.environ.get("OSPF_TOPOVIZ_INGEST_URL", "http://127.0.0.1:8080/api/ingest/lsdb")
    interval = float(os.environ.get("OSPF_PASSIVE_POLL_SECONDS", "2.0"))
    exp = PassiveExporter(ingest_url=url)
    while True:
        try:
            r = _vtysh_json("show ip ospf database router json")
            n = _vtysh_json("show ip ospf database network json")
            exp.push_if_changed(r, n)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            logger.warning("FRR passive poll failed: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
