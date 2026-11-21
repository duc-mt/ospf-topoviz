"""Unit tests for the optional self-hosted passive FRR sidecar exporter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.realtime.ingest import lsdb_from_payload


def test_frr_json_lsdb_converts_to_valid_ingest_payload() -> None:
    from passive.exporter import frr_json_to_ingest_payload

    frr_router_json = {
        "routerId": "10.0.0.99",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaType": "router-LSA",
                        "linkStateId": "10.0.0.1",
                        "advertisingRouter": "10.0.0.1",
                        "lsaAge": 120,
                        "lsaSeqNumber": "0x80000002",
                        "routerLsaFlags": {"abr": True, "asbr": False},
                        "links": [
                            {
                                "linkType": "point-to-point",
                                "neighborRouterId": "10.0.0.2",
                                "routerInterfaceAddress": "10.12.0.1",
                                "metric": 10,
                            },
                            {
                                "linkType": "stub",
                                "network": "10.99.0.0",
                                "mask": "255.255.255.0",
                                "metric": 1,
                            },
                        ],
                    }
                ]
            }
        },
    }
    frr_network_json = {
        "areas": {
            "0.0.0.0": {
                "networkLinkStates": [
                    {
                        "linkStateId": "192.168.1.1",
                        "advertisingRouter": "10.0.0.1",
                        "networkMask": "255.255.255.0",
                        "attachedRouters": ["10.0.0.1", "10.0.0.2"],
                        "lsaAge": 60,
                    }
                ]
            }
        }
    }
    payload = frr_json_to_ingest_payload(frr_router_json, frr_network_json)
    lsdb, _details, _meta = lsdb_from_payload(payload)
    assert len(lsdb.router_lsas) == 1
    assert lsdb.router_lsas[0].abr is True
    assert len(lsdb.network_lsas) == 1
    assert lsdb.network_lsas[0].attached == ["10.0.0.1", "10.0.0.2"]


def test_exporter_skips_post_when_lsdb_unchanged() -> None:
    from passive.exporter import PassiveExporter

    sample_router = {
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "linkStateId": "10.0.0.1",
                        "advertisingRouter": "10.0.0.1",
                        "links": [],
                    }
                ]
            }
        }
    }
    exp = PassiveExporter(ingest_url="http://127.0.0.1:8080/api/ingest/lsdb")
    resp = MagicMock()
    resp.status = 200
    resp.__enter__.return_value = resp

    with patch("urllib.request.urlopen", return_value=resp) as mock_post:
        assert exp.push_if_changed(sample_router, {}) is True
        assert mock_post.call_count == 1
        # Identical LSDB hash -> skip duplicate HTTP push
        assert exp.push_if_changed(sample_router, {}) is False
        assert mock_post.call_count == 1
