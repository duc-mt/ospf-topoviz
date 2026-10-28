"""
==============================================================================
Module Name:   poller.py
Description:   Source module poller.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 poller.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoBaseException,
    NetmikoTimeoutException,
    ReadTimeout,
)
from paramiko.ssh_exception import SSHException

from src import TrackerError
from src.config import (
    DEFAULT_CONFIG_PATH,
    ENV_OVERRIDES,
    ConfigError,
    SeedsOptions,
    device_entries,
    load_settings,
    parse_process_id,
)
from src.vendors import VendorProfile, get_profile

try:  # POSIX
    import fcntl
except ImportError:  # Windows
    fcntl = None
    import msvcrt

logger = logging.getLogger(__name__)

__all__ = [
    "BasePoller",
    "ConfigError",
    "DevicePoller",
    "FilePoller",
    "MultiDevicePoller",
    "PollBusyError",
    "PollLock",
    "PollResult",
    "PollerAuthError",
    "PollerError",
    "PollerTimeoutError",
    "RawLSDB",
    "SeedResult",
]


def _first_line(exc: BaseException) -> str:
    """Netmiko exceptions carry multi-paragraph help text; keep only the first line."""
    lines = [line.strip() for line in str(exc).splitlines() if line.strip()]
    return lines[0].rstrip(".") if lines else exc.__class__.__name__


class PollerError(TrackerError):
    """Raised when the device cannot be reached or returns unusable output."""


class PollerTimeoutError(PollerError):
    """The device did not answer in time (TCP connect, SSH banner or a command)."""


class PollerAuthError(PollerError):
    """The device refused the credentials."""


class PollBusyError(PollerError):
    """Another poll (the CLI, a cron job or the web server) already holds the poll lock."""


class PollLock:
    """Non-blocking, cross-process lock that keeps two polls from running (and writing state) at once.

    It is an advisory lock on a file (``data/.poll.lock``): ``flock`` on POSIX, ``msvcrt.locking`` on Windows.
    The operating system drops it when the holder exits - even if it crashes - so the file never goes stale.
    The holder's PID is written into the file for whoever wonders who has it.
    """

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self._handle: Any = None

    @property
    def held(self) -> bool:
        """True while this object holds the lock."""
        return self._handle is not None

    def acquire(self) -> bool:
        """Take the lock without waiting; ``False`` if somebody else has it.

        Raises:
            PollerError: If the lock file cannot be opened (e.g. the data directory is not writable).
        """
        if self._handle is not None:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.path.open("a+")
        except OSError as exc:
            raise PollerError(
                f"Could not open the poll lock {self.path}: {exc}"
            ) from exc
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            handle.close()
            return False
        try:
            handle.seek(0)
            handle.truncate()
            handle.write(f"{os.getpid()}\n")
            handle.flush()
        except OSError:  # the PID is a courtesy; the lock itself is held
            logger.debug("Could not record the PID in %s", self.path)
        self._handle = handle
        return True

    def release(self) -> None:
        """Give the lock back (a no-op if it is not held)."""
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            handle.seek(0)
            handle.truncate()  # no stale PID left behind
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            logger.debug("Could not unlock %s cleanly", self.path)
        finally:
            handle.close()

    @classmethod
    def is_held(cls, path: str | os.PathLike) -> bool:
        """True if some other holder has the lock right now (a probe: it takes and drops the lock)."""
        probe = cls(path)
        if probe.acquire():
            probe.release()
            return False
        return True

    def __enter__(self) -> PollLock:
        if not self.acquire():
            raise PollBusyError(
                f"Another poll is already running (lock {self.path}); this run was skipped"
            )
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


@dataclass(frozen=True)
class RawLSDB:
    """Raw, unparsed LSDB text as returned by a poller."""

    router: str  # router-LSA command output
    network: str  # network-LSA command output
    source: str  # host name/IP (or directory when replaying files)
    collected_at: str  # ISO-8601 UTC timestamp
    neighbors: str = ""  # neighbour-table output ("" = not collected or not supported on this platform)
    routes: str = ""  # OSPF routing-table output ("" = not collected or not supported on this platform)
    external: str = ""  # AS-External (Type 5) LSA output ("" = not collected or not supported on this platform)
    nssa: str = ""  # NSSA-External (Type 7) LSA output ("" = not collected or not supported on this platform)


class BasePoller(ABC):
    """Interface every poller implements."""

    #: Netmiko-style device type; the parser uses it to pick the platform adapter.
    device_type: str = "cisco_ios"
    #: OSPF process being tracked (``None`` = every process found in the output).
    process_id: str | None = None

    @abstractmethod
    def poll(self) -> RawLSDB:
        """Collect and return the raw LSDB text."""


class DevicePoller(BasePoller):
    """Collect the OSPF LSDB from a network device over SSH."""

    def __init__(
        self,
        config_path: str | os.PathLike = DEFAULT_CONFIG_PATH,
        device_type: str | None = None,
        settings: dict[str, Any] | None = None,
        *,
        device: dict[str, Any] | None = None,
        collect_neighbors: bool = True,
        apply_env: bool = True,
        collect_routes: bool = True,
        collect_external: bool = False,
    ) -> None:
        """Load and validate the settings.

        Args:
            config_path: Path to the YAML settings file (ignored if ``settings`` is given).
            device_type: Overrides ``device.device_type`` from the file.
            settings: Already-loaded settings, to avoid reading the file twice.
            device: One already-resolved router entry; skips reading settings.
            collect_neighbors: Also run the platform's neighbour-table command (best effort).
            collect_routes: Also run the platform's OSPF routing-table command (best effort).
            collect_external: Also run the platform's AS-External (Type 5) and NSSA-External (Type 7) LSA
                commands (best effort; off by default because they can print very large databases).
            apply_env: Let ``OSPF_MONITOR_*`` override the credentials (the single-device rule). Seed
                entries are resolved by ``device_entries`` - own value, then environment - so it passes False.

        Raises:
            ConfigError: If the settings are missing, unreadable or incomplete.
            UnsupportedVendorError: If the device type has no vendor profile.
        """
        self.config_path = Path(config_path)
        if settings is None:
            settings = load_settings(self.config_path)

        if device is None:
            if not isinstance(settings.get("device"), dict):
                raise ConfigError(f"{self.config_path} must contain a 'device' mapping")
            device = dict(settings["device"])
        else:
            device = dict(device)

        if apply_env:
            for key, env_name in ENV_OVERRIDES.items():
                if os.environ.get(env_name):
                    device[key] = os.environ[env_name]

        missing = [k for k in ("host", "username", "password") if not device.get(k)]
        if missing:
            which = f" for seed {device['host']}" if device.get("host") else ""
            raise ConfigError(
                f"{self.config_path}: missing device setting(s){which}: {', '.join(missing)}"
            )

        try:
            self._port = int(device.get("port", 22))
            self._conn_timeout = int(device.get("conn_timeout", 15))
            self._auth_timeout = int(device.get("auth_timeout", 20))
            self._banner_timeout = int(device.get("banner_timeout", 20))
            self._read_timeout = int(device.get("read_timeout", 120))
        except (TypeError, ValueError) as exc:
            raise ConfigError(
                f"{self.config_path}: numeric device settings must be integers ({exc!r})"
            ) from exc

        self.name = str(device.get("name") or device["host"])
        self.host = str(device["host"])
        try:
            self.priority = int(device.get("priority", 1))
        except (TypeError, ValueError) as exc:
            raise ConfigError(
                f"{self.config_path}: seed {self.host}: priority must be an integer ({exc})"
            ) from exc
        self.tags: tuple[str, ...] = tuple(str(t) for t in (device.get("tags") or ()))
        self.device_type = str(device_type or device.get("device_type", "cisco_ios"))
        self.process_id = parse_process_id(
            device.get("ospf_process_id") or settings.get("ospf_process_id")
        )
        self.profile: VendorProfile = get_profile(self.device_type)
        self._username = str(device["username"])
        self._password = str(device["password"])
        self._secret = str(device.get("secret") or "")

        overrides = device.get("commands") or {}
        if not isinstance(overrides, dict):
            raise ConfigError(
                f"{self.config_path}: device.commands must be a mapping (router/network)"
            )
        self.commands = {
            which: self.profile.command(which, self.process_id, overrides.get(which))
            for which in ("router", "network")
        }
        if collect_neighbors and (
            self.profile.neighbors is not None or overrides.get("neighbors")
        ):
            self.commands["neighbors"] = self.profile.command(
                "neighbors", self.process_id, overrides.get("neighbors")
            )
        if collect_routes and (
            self.profile.routes is not None or overrides.get("routes")
        ):
            self.commands["routes"] = self.profile.command(
                "routes", self.process_id, overrides.get("routes")
            )
        if collect_external:
            for which in ("external", "nssa"):
                if getattr(self.profile, which) is not None or overrides.get(which):
                    self.commands[which] = self.profile.command(
                        which, self.process_id, overrides.get(which)
                    )

    @classmethod
    def from_settings(
        cls,
        config_path: str | os.PathLike = DEFAULT_CONFIG_PATH,
        device_type: str | None = None,
        settings: dict[str, Any] | None = None,
        hosts: Sequence[str] | None = None,
    ) -> list[DevicePoller]:
        """Build one poller per seed router, sorted by priority.

        Routers come from ``seeds.devices``, from the legacy ``device:`` block, or from ``hosts``
        (``--seeds``); see ``config.device_entries`` for how credentials and timeouts are resolved.
        """
        if settings is None:
            settings = load_settings(config_path)
        entries = device_entries(
            settings, str(config_path), hosts=hosts, device_type=device_type
        )
        polling = PollingOptions.from_settings(settings.get("polling"))
        return [
            cls(
                config_path,
                device_type=device_type,
                settings=settings,
                device=entry,
                collect_neighbors=polling.neighbors,
                collect_routes=polling.routes,
                collect_external=polling.external,
                apply_env=bool(entry.get("_legacy")),
            )
            for entry in entries
        ]

    def _connection_params(self) -> dict[str, Any]:
        return {
            "device_type": self.device_type,
            "host": self.host,
            "username": self._username,
            "password": self._password,
            "secret": self._secret,
            "port": self._port,
            "conn_timeout": self._conn_timeout,
            "auth_timeout": self._auth_timeout,
            "banner_timeout": self._banner_timeout,
        }

    # ----------------------------------------------------------------- polling
    def poll(self) -> RawLSDB:
        """Connect to the seed router and return the raw LSDB output.

        Raises:
            PollerError: On authentication failure, timeout, SSH/socket errors,
                or when the device rejects a command or returns nothing useful.
        """
        logger.info("Connecting to %s:%s (%s)", self.host, self._port, self.device_type)
        try:
            with ConnectHandler(**self._connection_params()) as conn:
                if self._secret and not conn.check_enable_mode():
                    conn.enable()
                router = self._run(conn, "router")
                # No Type 2 LSAs is legitimate (e.g. only point-to-point links).
                network = self._run(conn, "network", allow_empty=True)
                # Extra detail only: never let it cost us the LSDB we already have.
                neighbors = self._run_optional(conn, "neighbors", "neighbour table")
                routes = self._run_optional(conn, "routes", "routing table")
                external = self._run_optional(conn, "external", "external LSAs")
                nssa = self._run_optional(conn, "nssa", "NSSA external LSAs")
        except NetmikoAuthenticationException as exc:
            raise PollerAuthError(
                f"Authentication failed for {self.host}: check username, password and enable secret"
            ) from exc
        except (TimeoutError, NetmikoTimeoutException, ReadTimeout) as exc:
            raise PollerTimeoutError(
                f"Timed out talking to {self.host}: {_first_line(exc)}. Check reachability, SSH access "
                f"and the timeout settings in {self.config_path}"
            ) from exc
        except (NetmikoBaseException, SSHException, OSError) as exc:
            raise PollerError(
                f"SSH session to {self.host} failed: {_first_line(exc)}"
            ) from exc

        logger.info(
            "Collected LSDB from %s (%d + %d bytes)",
            self.host,
            len(router),
            len(network),
        )
        return RawLSDB(
            router=router,
            network=network,
            source=self.host,
            collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
            neighbors=neighbors,
            routes=routes,
            external=external,
            nssa=nssa,
        )

    def _run_optional(self, conn: Any, key: str, what: str) -> str:
        """Run a command whose output is a bonus: any failure is logged and gives ``""``."""
        if key not in self.commands:
            return ""
        try:
            return self._run(conn, key, allow_empty=True)
        except (
            PollerError,
            NetmikoBaseException,
            ReadTimeout,
            SSHException,
            OSError,
        ) as exc:
            logger.warning(
                "%s: could not read the %s (%s); continuing without it",
                self.host,
                what,
                _first_line(exc),
            )
            return ""

    def _run(self, conn: Any, key: str, allow_empty: bool = False) -> str:
        """Run one LSDB command and sanity-check its output."""
        command = self.commands[key]
        logger.debug("Running: %s", command)
        output = conn.send_command(command, read_timeout=self._read_timeout)

        if any(marker in output for marker in self.profile.error_markers):
            snippet = output.strip().splitlines()[0] if output.strip() else ""
            raise PollerError(f"Device rejected '{command}': {snippet}")
        if not output.strip() and not allow_empty:
            raise PollerError(
                f"'{command}' returned no output - is OSPF running on {self.host}?"
            )
        return output


class FilePoller(BasePoller):
    """Replay previously saved CLI output (offline testing, demos, regression tests)."""

    ROUTER_FILE = "router_lsdb.txt"
    NETWORK_FILE = "network_lsdb.txt"
    NEIGHBORS_FILE = "neighbors.txt"
    ROUTES_FILE = "routes.txt"
    EXTERNAL_FILE = "external_lsdb.txt"
    NSSA_FILE = "nssa_lsdb.txt"

    def __init__(
        self,
        directory: str | os.PathLike,
        device_type: str = "cisco_ios",
        process_id: str | None = None,
        read_timeout: int = 10,
    ) -> None:
        self.directory = Path(directory)
        self.device_type = device_type
        self.process_id = process_id
        self.read_timeout = read_timeout
        # Lets a replay run through MultiDevicePoller as a single seed.
        self.host = str(self.directory)
        self.name = "replay"
        self.priority = 1
        self.tags: tuple[str, ...] = ()

    def _read_with_timeout(self, path: Path) -> str:
        if not path.exists():
            return ""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(path.read_text, encoding="utf-8")
            try:
                return future.result(timeout=self.read_timeout)
            except concurrent.futures.TimeoutError as exc:
                raise PollerError(
                    f"Timed out reading {path} after {self.read_timeout}s"
                ) from exc
            except OSError as exc:
                raise PollerError(f"Could not read replay file {path}: {exc}") from exc

    def poll(self) -> RawLSDB:
        """Read ``router_lsdb.txt`` (required); the other files (``network_lsdb.txt``, ``neighbors.txt``,
        ``routes.txt``, ``external_lsdb.txt`` and ``nssa_lsdb.txt``) are optional."""
        router_path = self.directory / self.ROUTER_FILE
        network_path = self.directory / self.NETWORK_FILE

        router = self._read_with_timeout(router_path)
        if not router:
            raise PollerError(f"Required file missing or empty: {router_path}")
        network = self._read_with_timeout(network_path)
        neighbors = self._read_with_timeout(self.directory / self.NEIGHBORS_FILE)
        routes = self._read_with_timeout(self.directory / self.ROUTES_FILE)
        external = self._read_with_timeout(self.directory / self.EXTERNAL_FILE)
        nssa = self._read_with_timeout(self.directory / self.NSSA_FILE)

        return RawLSDB(
            router=router,
            network=network,
            source=str(self.directory),
            collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
            neighbors=neighbors,
            routes=routes,
            external=external,
            nssa=nssa,
        )


@dataclass
class PollingOptions:
    """Settings for multi-router polling."""

    concurrency: int = 4  # routers polled at the same time
    require_all: bool = (
        False  # abort the run if ANY router fails (default: carry on with the rest)
    )
    neighbors: bool = True  # also read each router's neighbour table (adjacency state, interface names)
    routes: bool = True  # also read each router's OSPF routing table (to check it against the LSDB)
    external: bool = False  # also read the AS-External (Type 5) / NSSA-External (Type 7) LSAs: off, they can be huge

    @classmethod
    def from_settings(cls, section: dict[str, Any] | None) -> PollingOptions:
        """Read the ``polling:`` mapping from settings.yaml."""
        if section is None:
            return cls()
        if not isinstance(section, dict):
            raise ConfigError("'polling' in settings.yaml must be a mapping")
        try:
            options = cls(
                concurrency=int(section.get("concurrency", 4)),
                require_all=bool(section.get("require_all", False)),
                neighbors=bool(section.get("neighbors", True)),
                routes=bool(section.get("routes", True)),
                external=bool(section.get("external", False)),
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(
                f"polling.concurrency must be an integer ({exc})"
            ) from exc
        if options.concurrency < 1:
            raise ConfigError("polling.concurrency must be 1 or greater")
        return options


# --------------------------------------------------------------- multi-seed polling
STATUS_OK = "SUCCEEDED"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_AUTH = "AUTH FAILED"
STATUS_FAILED = "FAILED"
STATUS_SKIPPED = "SKIPPED"  # fallback mode: an earlier seed already answered, this one was never tried


@dataclass
class SeedResult:
    """What happened to one seed router during a run (a row of the seed health table)."""

    name: str
    host: str
    device_type: str
    priority: int = 1
    tags: tuple[str, ...] = ()
    status: str = STATUS_SKIPPED
    duration: float = 0.0  # seconds spent polling it (0 if it was skipped)
    error: str | None = None
    raw: RawLSDB | None = None
    #: Whatever the ``ingest`` callback made of ``raw`` (the parsed LSDB, ...).
    parsed: Any = None
    lsas: int = 0  # router + network LSAs this seed contributed
    neighbors: int = 0  # neighbour-table rows this seed contributed

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    @property
    def failed(self) -> bool:
        return self.status not in (STATUS_OK, STATUS_SKIPPED)


@dataclass
class PollResult:
    """Outcome of a multi-seed poll: one ``SeedResult`` per configured seed, in priority order."""

    mode: str
    seeds: list[SeedResult] = field(default_factory=list)

    @property
    def succeeded(self) -> list[SeedResult]:
        return [s for s in self.seeds if s.ok]

    @property
    def failed(self) -> list[SeedResult]:
        return [s for s in self.seeds if s.failed]

    @property
    def raws(self) -> list[RawLSDB]:
        """The raw LSDB of every seed that answered (exactly one in fallback mode)."""
        return [s.raw for s in self.succeeded if s.raw is not None]

    def failure_report(self) -> str:
        """One line per failed seed, for error messages."""
        return (
            "; ".join(f"{s.host}: {s.error or s.status}" for s in self.failed)
            or "no seed answered"
        )


class MultiDevicePoller:
    """Poll several seed routers: either the first one that answers, or all of them.

    * ``fallback`` - try the seeds in priority order and stop at the first one that works; the rest are
      reported as ``SKIPPED``. This is plain high availability for a single view of the network.
    * ``merge`` - poll every seed at once (up to ``concurrency`` SSH sessions) so their LSDBs and
      neighbour tables can be combined into one picture, e.g. seeds sitting in different areas.

    A failing seed never stops the others and never raises: ``poll()`` always returns a ``PollResult``
    and the caller decides what an incomplete result means. ``ingest`` (optional) turns each raw LSDB into
    something the caller needs (usually the parsed LSDB). It runs on the calling thread and, if it raises
    a ``TrackerError``, that seed counts as failed - so in fallback mode an unusable answer also moves on
    to the next seed.
    """

    def __init__(
        self,
        pollers: Sequence[Any],
        mode: str = "merge",
        concurrency: int = 5,
        ingest: Callable[[Any, RawLSDB], Any] | None = None,
        require_all: bool = False,
    ) -> None:
        """
        Args:
            pollers: ``DevicePoller``-like objects (``poll()``, ``host``, ``name``, ``device_type``,
                ``priority``, ``tags``).
            mode: ``"merge"`` or ``"fallback"``.
            concurrency: Parallel SSH sessions in merge mode.
            ingest: Optional ``(poller, raw) -> parsed`` callback; its result lands in ``SeedResult.parsed``.
            require_all: Merge mode: the caller should abort if any seed fails (kept here for the caller).

        Raises:
            ConfigError: If there is no seed, the mode is unknown or ``concurrency`` is below 1.
        """
        if not pollers:
            raise ConfigError("No seed routers to poll")
        if mode not in ("merge", "fallback"):
            raise ConfigError(f"Unknown seed mode {mode!r}: use 'merge' or 'fallback'")
        if concurrency < 1:
            raise ConfigError("concurrency must be 1 or greater")
        self.pollers = sorted(
            pollers, key=lambda p: getattr(p, "priority", 0)
        )  # stable for equal priorities
        self.mode = mode
        self.concurrency = concurrency
        self.ingest = ingest
        self.require_all = require_all

    @classmethod
    def from_settings(
        cls,
        config_path: str | os.PathLike = DEFAULT_CONFIG_PATH,
        settings: dict[str, Any] | None = None,
        mode: str | None = None,
        hosts: Sequence[str] | None = None,
        device_type: str | None = None,
        ingest: Callable[[Any, RawLSDB], Any] | None = None,
    ) -> MultiDevicePoller:
        """Build from settings.yaml; ``mode`` / ``hosts`` / ``device_type`` are the CLI overrides."""
        if settings is None:
            settings = load_settings(config_path)
        options = SeedsOptions.from_settings(settings, mode=mode)
        pollers = DevicePoller.from_settings(
            config_path, device_type=device_type, settings=settings, hosts=hosts
        )
        return cls(
            pollers,
            mode=options.mode,
            concurrency=options.concurrency,
            ingest=ingest,
            require_all=options.require_all,
        )

    # ----------------------------------------------------------------- polling
    def poll(self) -> PollResult:
        """Poll according to ``mode`` and report how every seed fared."""
        results = [
            SeedResult(
                name=str(getattr(p, "name", p.host)),
                host=str(p.host),
                device_type=str(getattr(p, "device_type", "")),
                priority=int(getattr(p, "priority", 0)),
                tags=tuple(getattr(p, "tags", ())),
            )
            for p in self.pollers
        ]
        if self.mode == "fallback":
            self._poll_fallback(results)
        else:
            self._poll_merge(results)
        return PollResult(mode=self.mode, seeds=results)

    def _poll_fallback(self, results: list[SeedResult]) -> None:
        for poller, result in zip(self.pollers, results):
            raw, error, duration = self._attempt(poller)
            result.duration = duration
            if error is None and self._accept(poller, result, raw):
                if len(results) > 1:
                    logger.info(
                        "Seed %s answered; the remaining seeds are not needed",
                        result.host,
                    )
                return
            if error is not None:
                self._fail(result, error)

    def _poll_merge(self, results: list[SeedResult]) -> None:
        workers = max(1, min(self.concurrency, len(self.pollers)))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="seed"
        ) as pool:
            futures = [pool.submit(self._attempt, p) for p in self.pollers]
            outcomes = [f.result() for f in futures]  # _attempt never raises
        for poller, result, (raw, error, duration) in zip(
            self.pollers, results, outcomes
        ):
            result.duration = duration
            if error is not None:
                self._fail(result, error)
            else:
                self._accept(poller, result, raw)

    @staticmethod
    def _attempt(poller: Any) -> tuple[RawLSDB | None, Exception | None, float]:
        """Poll one seed, timing it. Any failure is returned, not raised, so one bad seed cannot stop the rest."""
        started = time.monotonic()
        try:
            return poller.poll(), None, time.monotonic() - started
        except Exception as exc:  # noqa: BLE001 - the seed boundary: report it, keep going
            return None, exc, time.monotonic() - started

    def _accept(self, poller: Any, result: SeedResult, raw: RawLSDB | None) -> bool:
        """Record a successful poll and run ``ingest`` on it; returns False (seed failed) if that raises."""
        if raw is None:  # a poller that returned nothing is a failed poller
            self._fail(result, PollerError(f"{result.host} returned no data"))
            return False
        if self.ingest is not None:
            try:
                result.parsed = self.ingest(poller, raw)
            except TrackerError as exc:
                result.raw = raw  # keep it: it is exactly what --save-raw is for when the parser chokes
                self._fail(
                    result,
                    PollerError(f"could not use the output of {result.host}: {exc}"),
                )
                return False
        result.raw = raw
        result.status = STATUS_OK
        return True

    @staticmethod
    def _fail(result: SeedResult, error: Exception) -> None:
        if isinstance(error, PollerTimeoutError):
            result.status = STATUS_TIMEOUT
        elif isinstance(error, PollerAuthError):
            result.status = STATUS_AUTH
        else:
            result.status = STATUS_FAILED
        if isinstance(error, TrackerError):
            result.error = str(error)
            logger.warning("Seed %s failed (%s): %s", result.host, result.status, error)
        else:  # a bug or an exception we do not know: keep the traceback
            result.error = f"unexpected {type(error).__name__}: {error}"
            logger.warning(
                "Seed %s failed (%s): %s",
                result.host,
                result.status,
                result.error,
                exc_info=error,
            )
        result.parsed = None
