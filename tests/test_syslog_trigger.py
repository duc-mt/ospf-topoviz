"""Unit tests for multi-vendor OSPF UDP syslog matcher and debounced fast-poll trigger."""

from __future__ import annotations

import socket
import threading
import time

from src.realtime.syslog_trigger import (
    OspfSyslogMatcher,
    SyslogTriggerConfig,
    SyslogTriggerServer,
)


def test_matcher_identifies_cisco_frr_junos_and_huawei_ospf_events_and_ignores_noise() -> None:
    matcher = OspfSyslogMatcher()
    assert matcher.matches("<189> %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi0/1 from FULL to DOWN")
    assert matcher.matches("<188> %OSPF-4-ERRRCV: Received invalid packet")
    assert matcher.matches("2026-11-21 ospfd[1234]: nsm_change_state(10.0.0.2, Full -> Deleted)")
    assert matcher.matches("RPD_OSPF_NBRDOWN: OSPF neighbor 10.1.1.2 (ge-0/0/0) state changed from Full to Down")
    assert matcher.matches("OSPF/4/NBR_CHG: Neighbor 10.0.0.2 changed state")
    assert not matcher.matches("sshd[221]: Accepted publickey for admin from 10.0.0.50")
    assert not matcher.matches("%SYS-5-CONFIG_I: Configured from console by admin")


def test_syslog_burst_debounces_and_respects_cooldown() -> None:
    triggers: list[str] = []
    ev = threading.Event()

    def on_trigger(reason: str) -> None:
        triggers.append(reason)
        ev.set()

    srv = SyslogTriggerServer(
        SyslogTriggerConfig(
            enabled=True,
            bind="127.0.0.1",
            port=0,
            debounce_seconds=0.15,
            cooldown_seconds=0.5,
        ),
        trigger_callback=on_trigger,
    )
    for _ in range(15):
        srv.handle_message("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 from FULL to DOWN")
    assert ev.wait(timeout=2.0)
    time.sleep(0.1)
    assert len(triggers) == 1

    # Inside cooldown: immediate second burst should be suppressed cleanly
    srv.handle_message("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.3 from FULL to DOWN")
    time.sleep(0.25)
    assert len(triggers) == 1


def test_udp_server_triggers_poll_coordinator_on_ospf_syslog() -> None:
    called = threading.Event()
    reasons: list[str] = []

    def cb(reason: str) -> bool:
        reasons.append(reason)
        called.set()
        return True

    srv = SyslogTriggerServer(
        SyslogTriggerConfig(
            enabled=True,
            bind="127.0.0.1",
            port=0,
            debounce_seconds=0.05,
            cooldown_seconds=0.1,
        ),
        trigger_callback=cb,
    )
    srv.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(
                b"unrelated ssh login message",
                ("127.0.0.1", srv.server_port),
            )
            time.sleep(0.05)
            assert not called.is_set()

            sock.sendto(
                b"<189> %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi0/1 from FULL to DOWN",
                ("127.0.0.1", srv.server_port),
            )
        assert called.wait(timeout=2.0)
        assert reasons == ["syslog"]
    finally:
        srv.stop()
