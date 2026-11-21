"""Lightweight UDP Syslog / OSPF event listener that triggers debounced fast SSH polls."""

from __future__ import annotations

import contextlib
import logging
import re
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("ospf_tracker.realtime.syslog")


@dataclass(frozen=True)
class SyslogTriggerConfig:
    """Settings under ``realtime.syslog_trigger`` in settings.yaml."""

    enabled: bool = False
    bind: str = "127.0.0.1"
    port: int = 5514
    debounce_seconds: float = 2.0
    cooldown_seconds: float = 10.0

    @classmethod
    def from_settings(cls, section: dict[str, Any] | None) -> SyslogTriggerConfig:
        section = section or {}
        return cls(
            enabled=bool(section.get("enabled", False)),
            bind=str(section.get("bind") or "127.0.0.1"),
            port=int(section.get("port", 5514)),
            debounce_seconds=max(0.0, float(section.get("debounce_seconds", 2.0))),
            cooldown_seconds=max(0.0, float(section.get("cooldown_seconds", 10.0))),
        )


class OspfSyslogMatcher:
    """Multi-vendor regex classifier matching OSPF adjacency, interface, and LSA syslogs."""

    _PATTERNS = (
        re.compile(r"%OSPF(?:v3)?-\d+-(?:ADJCHG|ERRRCV|NBR|IF)", re.IGNORECASE),
        re.compile(r"\bospfd\[[^\]]+\]:.*(?:nsm_change_state|Neighbor|Interface|LSA)", re.IGNORECASE),
        re.compile(r"\bRPD_OSPF_(?:NBRUP|NBRDOWN|IFSTATE|LSA)", re.IGNORECASE),
        re.compile(r"\bOSPF/\d+/(?:NBR_CHG|IF_CHG|LSA)", re.IGNORECASE),
    )

    def matches(self, line: str) -> bool:
        """True if ``line`` looks like a relevant OSPF control-plane syslog event."""
        text = str(line or "")
        return any(p.search(text) for p in self._PATTERNS)


class SyslogTriggerServer:
    """UDP listener in a daemon thread that coalesces syslog bursts into fast polls."""

    def __init__(
        self,
        config: SyslogTriggerConfig,
        trigger_callback: Callable[[str], Any],
        matcher: OspfSyslogMatcher | None = None,
    ) -> None:
        self.config = config
        self.trigger_callback = trigger_callback
        self.matcher = matcher or OspfSyslogMatcher()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_ev = threading.Event()
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._last_trigger = 0.0

    @property
    def server_port(self) -> int:
        """Bound UDP port (useful when ``config.port == 0``)."""
        if self._sock is None:
            return self.config.port
        return int(self._sock.getsockname()[1])

    def start(self) -> None:
        """Bind UDP socket and begin serving in a background daemon thread."""
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.bind, self.config.port))
        sock.settimeout(0.5)
        self._sock = sock
        self._stop_ev.clear()
        self._thread = threading.Thread(target=self._serve, name="syslog-trigger", daemon=True)
        self._thread.start()
        logger.info("Listening for OSPF syslog triggers on %s:%s/udp", self.config.bind, self.server_port)

    def stop(self) -> None:
        """Stop UDP listener and cancel any pending debounce timer."""
        self._stop_ev.set()
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _serve(self) -> None:
        while not self._stop_ev.is_set() and self._sock is not None:
            try:
                data, _addr = self._sock.recvfrom(8192)
            except TimeoutError:
                continue
            except OSError:
                break
            text = data.decode("utf-8", errors="replace")
            self.handle_message(text)

    def handle_message(self, text: str) -> bool:
        """Inspect one syslog line; schedule a debounced trigger if it matches an OSPF event."""
        if not self.matcher.matches(text):
            return False
        with self._lock:
            now = time.monotonic()
            if self._last_trigger and (now - self._last_trigger) < self.config.cooldown_seconds:
                return False
            if self._timer is not None:
                return True  # already debouncing a burst
            timer = threading.Timer(self.config.debounce_seconds, self._fire)
            timer.daemon = True
            self._timer = timer
            timer.start()
        return True

    def _fire(self) -> None:
        with self._lock:
            self._timer = None
            now = time.monotonic()
            if self._last_trigger and (now - self._last_trigger) < self.config.cooldown_seconds:
                return
            self._last_trigger = now
        try:
            self.trigger_callback("syslog")
        except Exception:
            logger.exception("Syslog fast-poll trigger callback failed")
