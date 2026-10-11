"""
==============================================================================
Module Name:   config.py
Description:   Source module config.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 config.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from src import TrackerError

logger = logging.getLogger("ospf_tracker")

DEFAULT_CONFIG_PATH = Path("config/settings.yaml")

#: Environment variables that override credentials from the YAML file, so the
#: password does not have to live on disk.
ENV_OVERRIDES = {
    "username": "OSPF_MONITOR_USERNAME",
    "password": "OSPF_MONITOR_PASSWORD",
    "secret": "OSPF_MONITOR_SECRET",
}

# The process ID is interpolated into CLI commands, so only a conservative character
# set is accepted (numbers for IOS/Arista/Huawei, names for IOS-XR/NX-OS instance tags).
_PROCESS_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ConfigError(TrackerError):
    """Raised when settings.yaml is missing, malformed or incomplete."""


def load_settings(path: str | os.PathLike, required: bool = True) -> dict[str, Any]:
    """Read the YAML settings file into a dict.

    If path does not exist, automatically copies from path.name + '.example' if available.

    Args:
        path: Settings file.
        required: If False, a missing file yields ``{}`` (used by ``--replay``).

    Raises:
        ConfigError: If the file is unreadable or not a YAML mapping.
    """
    path = Path(path)
    if not path.exists():
        example_path = path.parent / f"{path.name}.example"
        if not example_path.exists():
            example_path = path.parent / "settings.yaml.example"
        if example_path.exists():
            try:
                shutil.copyfile(example_path, path)
                logger.info("Created %s from %s", path, example_path.name)
            except OSError as exc:
                logger.warning("Could not copy %s to %s: %s", example_path.name, path.name, exc)

    try:
        with path.open("r", encoding="utf-8") as handle:
            settings = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        if not required:
            return {}
        raise ConfigError(f"Settings file not found: {path}") from exc
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Could not read settings file {path}: {exc}") from exc
    if settings is None:
        settings = {}
    if not isinstance(settings, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level")
    return settings


def parse_process_id(value: Any) -> str | None:
    """Validate ``ospf_process_id`` (int or name) and return it as a string, or ``None``.

    Raises:
        ConfigError: If the value contains characters unsafe for a CLI command.
    """
    if value is None or value == "":
        return None
    text = str(value).strip()
    if not _PROCESS_ID.match(text):
        raise ConfigError(
            f"ospf_process_id {value!r} is invalid: use 1-64 letters, digits, '.', '_' or '-'"
        )
    return text


def stale_lsa_age(settings: dict[str, Any], default: int) -> int:
    """``data_quality.stale_lsa_age`` in seconds (0 switches the stale-LSA check off).

    Raises:
        ConfigError: If it is not a non-negative integer.
    """
    section = settings.get("data_quality") or {}
    if not isinstance(section, dict):
        raise ConfigError("'data_quality' in settings.yaml must be a mapping")
    try:
        value = int(section.get("stale_lsa_age", default))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"data_quality.stale_lsa_age must be a whole number of seconds ({exc})") from exc
    if value < 0:
        raise ConfigError("data_quality.stale_lsa_age must not be negative")
    return value


# ----------------------------------------------------------------- multi-seed
SEED_MODES = ("merge", "fallback")

#: Per-router settings a ``seeds:`` block may also state once for every device in it.
_SHARED_KEYS = (
    "device_type", "username", "password", "secret", "port", "ospf_process_id",
    "conn_timeout", "auth_timeout", "banner_timeout", "read_timeout", "commands",
)
_TIMEOUT_KEYS = ("conn_timeout", "auth_timeout", "banner_timeout")
_HOST = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")


@dataclass(frozen=True)
class SeedsOptions:
    """Run-wide settings of the ``seeds:`` block (the device list itself is ``device_entries``)."""

    mode: str = "merge"  # merge = poll all seeds and combine; fallback = first seed that answers
    concurrency: int = 5  # SSH sessions at the same time in merge mode
    timeout_per_device: int = 10  # seconds per connection stage (TCP, banner, auth) unless a device sets its own
    require_all: bool = False  # merge mode: abort instead of continuing when any seed fails

    @classmethod
    def from_settings(cls, settings: dict[str, Any], mode: str | None = None) -> SeedsOptions:
        """Read ``seeds:`` (all keys optional); ``mode`` is the ``--mode`` override.

        Raises:
            ConfigError: On an unknown mode or a non-positive number.
        """
        section = settings.get("seeds")
        if section is None:
            section = {}
        if not isinstance(section, dict):
            raise ConfigError("'seeds' in settings.yaml must be a mapping")
        chosen = str(mode or section.get("mode") or cls.mode).strip().lower()
        if chosen not in SEED_MODES:
            raise ConfigError(f"seeds.mode {chosen!r} is invalid: use one of {', '.join(SEED_MODES)}")
        try:
            opts = cls(
                mode=chosen,
                concurrency=int(section.get("concurrency", cls.concurrency)),
                timeout_per_device=int(section.get("timeout_per_device", cls.timeout_per_device)),
                require_all=bool(section.get("require_all", cls.require_all)),
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"seeds.concurrency and seeds.timeout_per_device must be integers ({exc})") from exc
        if opts.concurrency < 1:
            raise ConfigError("seeds.concurrency must be 1 or greater")
        if opts.timeout_per_device < 1:
            raise ConfigError("seeds.timeout_per_device must be 1 or greater")
        return opts


def parse_seed_hosts(text: str | None) -> list[str]:
    """Split a ``--seeds a,b,c`` value into host names, in the order given (duplicates dropped).

    Raises:
        ConfigError: If an entry is not a plausible host name or IP address.
    """
    hosts: list[str] = []
    for item in (text or "").split(","):
        host = item.strip()
        if not host:
            continue
        if not _HOST.match(host):
            raise ConfigError(f"--seeds: {host!r} is not a valid host name or IP address")
        if host not in hosts:
            hosts.append(host)
    return hosts


def _blank(value: Any) -> bool:
    return value is None or value == ""


def _tags(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and all(isinstance(v, (str, int)) for v in value):
        return [str(v) for v in value]
    raise ConfigError(f"{where}: tags must be a list of strings")


def device_entries(
    settings: dict[str, Any],
    source: str = "settings.yaml",
    hosts: Sequence[str] | None = None,
    device_type: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve the routers to poll into plain per-router dicts, sorted by priority.

    Where the routers come from:

    * ``seeds.devices`` - the multi-seed list;
    * the legacy single ``device:`` block - exactly one router, behaves as before;
    * ``hosts`` (``--seeds``) - picks/orders routers by host; a host that is not configured is built from
      the shared settings, so ``--seeds 10.1.1.1,10.1.1.2`` works with nothing but a ``device:`` block.

    A seed's value for each setting is the first one that is set of: its own entry, (username/password/
    secret only) the ``OSPF_MONITOR_*`` environment variable, the shared value written directly under
    ``seeds:``, the legacy ``device:`` block, then the built-in default. The legacy single-device path
    keeps its old rule - there the environment wins over the file - and is applied by ``DevicePoller``.

    Args:
        settings: The loaded settings.yaml.
        source: File name for error messages.
        hosts: ``--seeds`` override; the order given becomes the priority order.
        device_type: ``--device-type`` override, applied to every seed.

    Raises:
        ConfigError: If nothing is configured, an entry is malformed, or a host is listed twice.
    """
    seeds = settings.get("seeds")
    if seeds is not None and not isinstance(seeds, dict):
        raise ConfigError(f"{source}: 'seeds' must be a mapping")
    seeds = seeds or {}
    legacy = settings.get("device")
    if legacy is not None and not isinstance(legacy, dict):
        raise ConfigError(f"{source}: 'device' must be a mapping")
    legacy = dict(legacy or {})
    configured = seeds.get("devices")
    if configured is not None and not isinstance(configured, list):
        raise ConfigError(f"{source}: seeds.devices must be a list")

    # --- legacy single device: one router, unchanged behaviour -----------------------------------
    if not configured and not hosts:
        if not legacy:
            raise ConfigError(f"{source} must contain a 'seeds' block (seeds.devices) or a 'device' mapping")
        entry = dict(legacy)
        entry["_legacy"] = True
        if device_type:
            entry["device_type"] = device_type
        entry.setdefault("priority", 1)
        entry["tags"] = _tags(entry.get("tags"), f"{source}: device")
        return [entry]

    shared = {k: seeds[k] for k in _SHARED_KEYS if not _blank(seeds.get(k))}
    template = {**{k: legacy[k] for k in _SHARED_KEYS if not _blank(legacy.get(k))}, **shared}
    options = SeedsOptions.from_settings(settings)

    own: list[dict[str, Any]] = []
    for position, item in enumerate(configured or [], start=1):
        if not isinstance(item, dict):
            raise ConfigError(f"{source}: seeds.devices[{position}] must be a mapping")
        if _blank(item.get("host")):
            raise ConfigError(f"{source}: seeds.devices[{position}] has no 'host'")
        host = str(item["host"]).strip()
        if not _HOST.match(host):
            raise ConfigError(f"{source}: seeds.devices[{position}]: {host!r} is not a valid host name or IP address")
        entry = {**item, "host": host}
        try:
            entry["priority"] = int(item["priority"]) if not _blank(item.get("priority")) else position
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{source}: seed {host}: priority must be an integer ({exc})") from exc
        entry["tags"] = _tags(item.get("tags"), f"{source}: seed {host}")
        own.append(entry)

    seen: set[str] = set()
    for entry in own:
        if entry["host"] in seen:
            raise ConfigError(f"{source}: seed {entry['host']} is listed more than once")
        seen.add(entry["host"])

    if hosts:  # --seeds: the command line decides which routers run, and in which order
        by_host = {e["host"]: e for e in own}
        own = []
        for rank, host in enumerate(hosts, start=1):
            entry = dict(by_host.get(host) or {"host": host, "tags": []})
            entry["priority"] = rank
            own.append(entry)

    resolved: list[dict[str, Any]] = []
    for entry in own:
        out = dict(entry)
        for key, env_name in ENV_OVERRIDES.items():  # own value > environment > shared > legacy
            if _blank(out.get(key)):
                out[key] = os.environ.get(env_name) or template.get(key)
        for key in _SHARED_KEYS:
            if _blank(out.get(key)) and not _blank(template.get(key)):
                out[key] = template[key]
        for key in _TIMEOUT_KEYS:
            if _blank(out.get(key)):
                out[key] = options.timeout_per_device
        if device_type:
            out["device_type"] = device_type
        resolved.append(out)

    # Stable: equal priorities keep the order they were written in.
    return sorted(resolved, key=lambda e: e["priority"])
