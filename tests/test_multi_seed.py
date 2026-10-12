"""Multi-seed polling: configuration, MultiDevicePoller (fallback / merge) and the end-to-end pipeline."""

from __future__ import annotations

import json
import logging
import threading
import time

import pytest
import yaml
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

import main
from src.config import (
    ConfigError,
    SeedsOptions,
    device_entries,
    parse_seed_hosts,
)
from src.poller import (
    STATUS_AUTH,
    STATUS_FAILED,
    STATUS_OK,
    STATUS_SKIPPED,
    STATUS_TIMEOUT,
    DevicePoller,
    MultiDevicePoller,
    PollerAuthError,
    PollerError,
    PollerTimeoutError,
    RawLSDB,
)
from src.vendors.base import ParserError


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "OSPF_MONITOR_USERNAME",
        "OSPF_MONITOR_PASSWORD",
        "OSPF_MONITOR_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)


# ===================================================================== config
def _seeds_settings(**extra) -> dict:
    return {
        "seeds": {
            "mode": "merge",
            "devices": [
                {
                    "host": "10.255.255.6",
                    "device_type": "vyos",
                    "username": "admin",
                    "password": "pw6",
                    "priority": 1,
                    "tags": ["Area0", "Core"],
                },
                {
                    "host": "10.255.255.4",
                    "device_type": "vyos",
                    "username": "admin",
                    "password": "",
                    "priority": 2,
                    "tags": ["Area0", "Transit"],
                },
                {
                    "host": "10.255.255.10",
                    "device_type": "vyos",
                    "priority": 3,
                    "tags": ["Area1", "Edge"],
                },
            ],
            **extra,
        }
    }


def test_legacy_device_block_is_one_unchanged_entry():
    settings = {
        "device": {
            "host": "10.0.0.1",
            "username": "u",
            "password": "p",
            "device_type": "vyos",
        }
    }
    entries = device_entries(settings)
    assert (
        len(entries) == 1
        and entries[0]["host"] == "10.0.0.1"
        and entries[0]["_legacy"] is True
    )


def test_nothing_configured_is_a_config_error():
    with pytest.raises(ConfigError, match="seeds"):
        device_entries({})


def test_devices_are_sorted_by_priority_and_default_to_written_order(monkeypatch):
    monkeypatch.setenv("OSPF_MONITOR_PASSWORD", "env")
    settings = {
        "seeds": {
            "username": "u",
            "devices": [
                {"host": "c", "priority": 9},
                {"host": "a"},
                {"host": "b"},
            ],
        }
    }
    assert [e["host"] for e in device_entries(settings)] == [
        "a",
        "b",
        "c",
    ]  # a=1, b=2 (position), c=9


def test_credential_precedence_own_then_env_then_shared_then_legacy(monkeypatch):
    monkeypatch.setenv("OSPF_MONITOR_PASSWORD", "from-env")
    settings = _seeds_settings(username="shared-user")
    settings["device"] = {"host": "x", "secret": "legacy-secret"}
    by_host = {e["host"]: e for e in device_entries(settings)}
    assert (
        by_host["10.255.255.6"]["password"] == "pw6"
    )  # its own password beats the environment
    assert (
        by_host["10.255.255.4"]["password"] == "from-env"
    )  # empty own password -> environment
    assert (
        by_host["10.255.255.10"]["password"] == "from-env"
    )  # nothing of its own -> environment
    assert (
        by_host["10.255.255.10"]["username"] == "shared-user"
    )  # shared value under seeds:
    assert (
        by_host["10.255.255.10"]["secret"] == "legacy-secret"
    )  # legacy device: block as last resort


def test_timeout_per_device_fills_connection_timeouts_unless_set():
    settings = _seeds_settings(timeout_per_device=7)
    settings["seeds"]["devices"][0]["conn_timeout"] = 30
    first, *_ = device_entries(settings)
    assert (first["conn_timeout"], first["auth_timeout"], first["banner_timeout"]) == (
        30,
        7,
        7,
    )


@pytest.mark.parametrize(
    "devices, message",
    [
        ([{"host": "a"}, {"host": "a"}], "more than once"),
        ([{"username": "x"}], "no 'host'"),
        ([{"host": "a b"}], "valid host"),
        ([{"host": "a", "priority": "high"}], "priority"),
        (["a"], "mapping"),
    ],
)
def test_bad_seed_entries_are_rejected(devices, message):
    with pytest.raises(ConfigError, match=message):
        device_entries({"seeds": {"devices": devices}})


@pytest.mark.parametrize(
    "section, message",
    [
        ({"mode": "both"}, "seeds.mode"),
        ({"concurrency": 0}, "concurrency"),
        ({"concurrency": "many"}, "integers"),
        ({"timeout_per_device": 0}, "timeout_per_device"),
    ],
)
def test_bad_seed_options_are_rejected(section, message):
    with pytest.raises(ConfigError, match=message):
        SeedsOptions.from_settings({"seeds": section})


def test_mode_override_wins_over_the_file():
    assert (
        SeedsOptions.from_settings({"seeds": {"mode": "merge"}}, mode="fallback").mode
        == "fallback"
    )
    assert SeedsOptions.from_settings({}).mode == "merge"


def test_seeds_flag_selects_and_orders_configured_hosts():
    entries = device_entries(_seeds_settings(), hosts=["10.255.255.10", "10.255.255.6"])
    assert [(e["host"], e["priority"]) for e in entries] == [
        ("10.255.255.10", 1),
        ("10.255.255.6", 2),
    ]
    assert entries[1]["tags"] == [
        "Area0",
        "Core",
    ]  # configured entries keep their own settings


def test_seeds_flag_with_only_a_legacy_device_block_reuses_its_credentials():
    settings = {
        "device": {
            "host": "10.0.0.1",
            "username": "u",
            "password": "p",
            "device_type": "vyos",
        }
    }
    entries = device_entries(settings, hosts=["10.1.1.1", "10.1.1.2"])
    assert [e["host"] for e in entries] == ["10.1.1.1", "10.1.1.2"]
    assert all(
        (e["username"], e["password"], e["device_type"]) == ("u", "p", "vyos")
        for e in entries
    )


def test_parse_seed_hosts():
    assert parse_seed_hosts(" 10.1.1.1, 10.1.1.2 ,,10.1.1.1") == [
        "10.1.1.1",
        "10.1.1.2",
    ]
    assert parse_seed_hosts(None) == []
    with pytest.raises(ConfigError):
        parse_seed_hosts("10.1.1.1;reboot")


def test_device_poller_from_settings_builds_one_poller_per_seed(monkeypatch, tmp_path):
    monkeypatch.setenv("OSPF_MONITOR_PASSWORD", "env")
    pollers = DevicePoller.from_settings(
        tmp_path / "s.yaml", settings=_seeds_settings(username="u")
    )
    assert [(p.host, p.priority, p.tags) for p in pollers] == [
        ("10.255.255.6", 1, ("Area0", "Core")),
        ("10.255.255.4", 2, ("Area0", "Transit")),
        ("10.255.255.10", 3, ("Area1", "Edge")),
    ]
    assert pollers[0]._password == "pw6" and pollers[1]._password == "env"


def test_missing_credentials_name_the_seed(tmp_path):
    """No env password: the first seed that ends up without one is named in the error."""
    with pytest.raises(ConfigError, match=r"seed 10\.255\.255\.4.*password"):
        DevicePoller.from_settings(
            tmp_path / "s.yaml", settings=_seeds_settings(username="u")
        )


# ============================================================ fake pollers
class FakePoller:
    """Duck-typed DevicePoller: returns canned output or raises."""

    def __init__(
        self, host, priority=1, outcome=None, delay=0.0, tags=(), device_type="vyos"
    ):
        self.host, self.name, self.priority, self.tags = host, host, priority, tags
        self.device_type, self.process_id = device_type, None
        self.outcome, self.delay, self.calls = outcome, delay, 0

    def poll(self):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return RawLSDB(
            router=f"router@{self.host}", network="", source=self.host, collected_at="t"
        )


def _statuses(result):
    return [(s.host, s.status) for s in result.seeds]


# ============================================================ fallback mode
def test_fallback_skips_a_dead_seed_and_uses_the_next(caplog):
    pollers = [
        FakePoller("r1", 1, PollerTimeoutError("timed out")),
        FakePoller("r2", 2),
        FakePoller("r3", 3),
    ]
    with caplog.at_level(logging.WARNING, logger="src.poller"):
        result = MultiDevicePoller(pollers, mode="fallback").poll()
    assert _statuses(result) == [
        ("r1", STATUS_TIMEOUT),
        ("r2", STATUS_OK),
        ("r3", STATUS_SKIPPED),
    ]
    assert [r.source for r in result.raws] == ["r2"]
    assert pollers[2].calls == 0  # never contacted once r2 answered
    assert any(
        "r1" in rec.message and rec.levelno == logging.WARNING for rec in caplog.records
    )


def test_fallback_follows_priority_not_the_order_of_the_list():
    pollers = [FakePoller("slow", 5), FakePoller("first", 1)]
    result = MultiDevicePoller(pollers, mode="fallback").poll()
    assert [s.host for s in result.seeds] == ["first", "slow"]
    assert [r.source for r in result.raws] == ["first"]


def test_fallback_with_every_seed_down_returns_a_result_instead_of_raising():
    result = MultiDevicePoller(
        [
            FakePoller("a", 1, PollerAuthError("bad password")),
            FakePoller("b", 2, PollerError("refused")),
        ],
        mode="fallback",
    ).poll()
    assert _statuses(result) == [("a", STATUS_AUTH), ("b", STATUS_FAILED)]
    assert (
        not result.succeeded
        and "bad password" in result.failure_report()
        and "refused" in result.failure_report()
    )


def test_fallback_survives_an_unexpected_exception_in_a_seed():
    result = MultiDevicePoller(
        [FakePoller("a", 1, RuntimeError("boom")), FakePoller("b", 2)], mode="fallback"
    ).poll()
    assert _statuses(result) == [("a", STATUS_FAILED), ("b", STATUS_OK)]
    assert "RuntimeError" in result.seeds[0].error


def test_fallback_moves_on_when_the_answer_cannot_be_parsed():
    def ingest(poller, raw):
        if poller.host == "a":
            raise ParserError("No router (Type 1) LSAs found")
        return f"parsed {poller.host}"

    result = MultiDevicePoller(
        [FakePoller("a", 1), FakePoller("b", 2)], mode="fallback", ingest=ingest
    ).poll()
    assert _statuses(result) == [("a", STATUS_FAILED), ("b", STATUS_OK)]
    assert result.seeds[1].parsed == "parsed b"
    assert (
        result.seeds[0].raw is not None
    )  # the raw capture survives for --save-raw / bug reports


def test_single_seed_fallback_does_not_log_about_remaining_seeds(caplog):
    with caplog.at_level(logging.INFO, logger="src.poller"):
        MultiDevicePoller([FakePoller("only")], mode="fallback").poll()
    assert not any("remaining" in r.message for r in caplog.records)


# ============================================================== merge mode
def test_merge_polls_every_seed_and_keeps_going_past_a_failure():
    pollers = [
        FakePoller("r1", 1),
        FakePoller("r2", 2, PollerTimeoutError("timed out")),
        FakePoller("r3", 3),
    ]
    result = MultiDevicePoller(pollers, mode="merge", concurrency=3).poll()
    assert _statuses(result) == [
        ("r1", STATUS_OK),
        ("r2", STATUS_TIMEOUT),
        ("r3", STATUS_OK),
    ]
    assert [r.source for r in result.raws] == [
        "r1",
        "r3",
    ]  # priority order, failed seed left out
    assert [s.host for s in result.failed] == ["r2"]


def test_merge_classifies_each_failure():
    result = MultiDevicePoller(
        [
            FakePoller("t", 1, PollerTimeoutError("x")),
            FakePoller("a", 2, PollerAuthError("x")),
            FakePoller("f", 3, PollerError("x")),
        ],
        mode="merge",
    ).poll()
    assert [s.status for s in result.seeds] == [
        STATUS_TIMEOUT,
        STATUS_AUTH,
        STATUS_FAILED,
    ]


def test_merge_really_polls_in_parallel():
    barrier = threading.Barrier(
        3, timeout=5
    )  # only opens if all three polls are running at the same time

    class Gate(FakePoller):
        def poll(self):
            barrier.wait()
            return super().poll()

    result = MultiDevicePoller(
        [Gate("a", 1), Gate("b", 2), Gate("c", 3)], mode="merge", concurrency=3
    ).poll()
    assert len(result.succeeded) == 3


def test_merge_never_exceeds_the_concurrency_limit():
    lock, state = threading.Lock(), {"now": 0, "max": 0}

    class Counting(FakePoller):
        def poll(self):
            with lock:
                state["now"] += 1
                state["max"] = max(state["max"], state["now"])
            try:
                time.sleep(0.05)
                return super().poll()
            finally:
                with lock:
                    state["now"] -= 1

    MultiDevicePoller(
        [Counting(f"r{i}", i) for i in range(6)], mode="merge", concurrency=2
    ).poll()
    assert state["max"] == 2


def test_merge_ingest_failure_marks_only_that_seed():
    def ingest(poller, raw):
        if poller.host == "bad":
            raise ParserError("unparseable")
        return poller.host

    result = MultiDevicePoller(
        [FakePoller("ok", 1), FakePoller("bad", 2)], mode="merge", ingest=ingest
    ).poll()
    assert _statuses(result) == [("ok", STATUS_OK), ("bad", STATUS_FAILED)]
    assert [s.parsed for s in result.succeeded] == ["ok"]


def test_duration_is_recorded_per_seed():
    result = MultiDevicePoller(
        [FakePoller("a", 1, delay=0.05), FakePoller("b", 2)], mode="merge"
    ).poll()
    assert (
        result.seeds[0].duration >= 0.04
        and result.seeds[1].duration < result.seeds[0].duration
    )


@pytest.mark.parametrize(
    "pollers, mode, concurrency",
    [([], "merge", 1), ([FakePoller("a")], "both", 1), ([FakePoller("a")], "merge", 0)],
)
def test_constructor_validation(pollers, mode, concurrency):
    with pytest.raises(ConfigError):
        MultiDevicePoller(pollers, mode=mode, concurrency=concurrency)


# ============================================= DevicePoller failure kinds
@pytest.mark.parametrize(
    "raised, expected",
    [
        (
            NetmikoTimeoutException("TCP connection to device failed."),
            PollerTimeoutError,
        ),
        (NetmikoAuthenticationException("Authentication failed."), PollerAuthError),
    ],
)
def test_device_poller_raises_a_specific_error_per_failure_kind(
    monkeypatch, tmp_path, raised, expected
):
    def boom(**params):
        raise raised

    monkeypatch.setattr("src.poller.ConnectHandler", boom)
    poller = DevicePoller(
        tmp_path / "s.yaml",
        settings={"device": {"host": "h", "username": "u", "password": "p"}},
    )
    with pytest.raises(expected):
        poller.poll()


def test_device_poller_socket_error_is_a_plain_poller_error(monkeypatch, tmp_path):
    def boom(**params):
        raise OSError("No route to host")

    monkeypatch.setattr("src.poller.ConnectHandler", boom)
    poller = DevicePoller(
        tmp_path / "s.yaml",
        settings={"device": {"host": "h", "username": "u", "password": "p"}},
    )
    with pytest.raises(PollerError) as caught:
        poller.poll()
    assert not isinstance(caught.value, (PollerTimeoutError, PollerAuthError))


# ====================================================== end to end (main)
#
#   R1 ---- R2 ==== R3 ---- R4        area 0: R1, R2      area 1: R2 (ABR), R3, R4
#   seed "A" = R1 sees area 0 only;   seed "B" = R3 sees area 1 only
AREA0, AREA1 = "0.0.0.0", "0.0.0.1"
R1, R2, R3, R4 = "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"
SEED_A, SEED_B = "192.0.2.1", "192.0.2.3"  # management addresses of R1 and R3


def _lsa(rid, links, abr=False, seq="80000003", age=100):
    lines = [
        f"  LS age: {age}",
        "  Options: 0x2  : *|-|-|-|-|-|E|-",
        "  LS Flags: 0x3",
        f"  Flags: {'0x1' if abr else '0x0'}",
        "  LS Type: router-LSA",
        f"  Link State ID: {rid}",
        f"  Advertising Router: {rid}",
        f"  LS Seq Number: {seq}",
        "  Checksum: 0x1A2B",
        "  Length: 60",
        "",
        f"   Number of Links: {len(links)}",
        "",
    ]
    for neighbor, own_ip, metric in links:
        lines += [
            "    Link connected to: another Router (point-to-point)",
            f"     (Link ID) Neighboring Router ID: {neighbor}",
            f"     (Link Data) Router Interface address: {own_ip}",
            "      Number of TOS metrics: 0",
            f"       TOS 0 Metric: {metric}",
            "",
        ]
    return "\n".join(lines)


def _router_output(local_id, by_area):
    out = [f"\n       OSPF Router with ID ({local_id})\n"]
    for area, lsas in by_area.items():
        out += ["", f"                Router Link States (Area {area})", "", *lsas]
    return "\n".join(out) + "\n"


def _neighbor_output(rows):
    head = "Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL"
    return (
        "\n".join(
            [head]
            + [
                f"{rid:<15} {1:>3} {state:<15} 1h02m           33.5s     {addr:<15} {ifname:<32}   0     0     0"
                for rid, state, addr, ifname in rows
            ]
        )
        + "\n"
    )


OUT_A = {  # what R1 prints: area 0
    "router": _router_output(
        R1,
        {
            AREA0: [
                _lsa(R1, [(R2, "10.12.0.1", 10)]),
                _lsa(R2, [(R1, "10.12.0.2", 10)], abr=True),
            ]
        },
    ),
    "neighbors": _neighbor_output([(R2, "Full/-", "10.12.0.2", "eth1:10.12.0.1")]),
}
OUT_B = {  # what R3 prints: area 1
    "router": _router_output(
        R3,
        {
            AREA1: [
                _lsa(R2, [(R3, "10.23.0.2", 5)], abr=True),
                _lsa(R3, [(R2, "10.23.0.3", 5), (R4, "10.34.0.3", 7)]),
                _lsa(R4, [(R3, "10.34.0.4", 7)]),
            ]
        },
    ),
    "neighbors": _neighbor_output(
        [
            (R2, "Full/-", "10.23.0.2", "eth0:10.23.0.3"),
            (R4, "Full/-", "10.34.0.4", "eth1:10.34.0.3"),
        ]
    ),
}


class FakeConn:
    def __init__(self, outputs):
        self.outputs = outputs

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def check_enable_mode(self):
        return True

    def send_command(self, command, read_timeout=None):
        for key, marker in (
            ("router", "database router"),
            ("network", "database network"),
            ("neighbors", "neighbor"),
            ("routes", "route ospf"),
        ):
            if marker in command:
                return self.outputs.get(key, "")
        raise AssertionError(f"unexpected command {command!r}")


class FakeNetwork:
    """Stands in for netmiko.ConnectHandler: each host maps to canned outputs or an exception to raise."""

    def __init__(self, devices):
        self.devices, self.connected = devices, []

    def __call__(self, **params):
        host = params["host"]
        self.connected.append(host)
        behaviour = self.devices[host]
        if isinstance(behaviour, BaseException):
            raise behaviour
        return FakeConn(behaviour)


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Config file, state directory and fake network wired into main; returns a small helper object."""

    class Env:
        pass

    e = Env()
    e.tmp = tmp_path
    e.data = tmp_path / "data"
    e.config = tmp_path / "settings.yaml"
    e.rendered = []  # DOT source of every diagram "rendered"
    e.network = FakeNetwork({SEED_A: OUT_A, SEED_B: OUT_B})
    monkeypatch.setattr(main, "DATA_DIR", e.data)
    monkeypatch.setattr("src.poller.ConnectHandler", e.network)

    def render(
        self, graph, diff
    ):  # no Graphviz binary needed: keep the DOT source for inspection
        e.rendered.append(self.build_digraph(graph, diff).source)
        return tmp_path / "topology.png"

    monkeypatch.setattr(main.TopologyVisualizer, "render", render)

    def write_config(seeds=None, **top):
        settings = {
            "seeds": {
                "mode": "merge",
                "timeout_per_device": 5,
                "devices": seeds
                or [
                    {
                        "host": SEED_A,
                        "device_type": "vyos",
                        "username": "admin",
                        "password": "pw",
                        "priority": 1,
                        "tags": ["Area0", "Core"],
                    },
                    {
                        "host": SEED_B,
                        "device_type": "vyos",
                        "username": "admin",
                        "password": "pw",
                        "priority": 2,
                        "tags": ["Area1", "Edge"],
                    },
                ],
            },
            **top,
        }
        e.config.write_text(yaml.safe_dump(settings))

    def run(*args):
        return main.main(
            [
                "--config",
                str(e.config),
                "--output",
                str(tmp_path / "topology.png"),
                *args,
            ]
        )

    e.write_config, e.run = write_config, run
    e.state = lambda: json.loads((e.data / "current_state.json").read_text())
    write_config()
    return e


def _router_ids(state):
    return sorted(n["id"] for n in state["nodes"] if n["type"] == "router")


def test_merge_of_two_areas_draws_every_node_of_both(env, capsys):
    assert env.run() == main.EXIT_OK
    state = env.state()
    assert _router_ids(state) == [R1, R2, R3, R4]
    assert len(state["edges"]) == 6
    assert state["metadata"]["areas"] == [AREA0, AREA1]
    dot = env.rendered[-1]
    assert all(rid in dot for rid in (R1, R2, R3, R4))

    out = capsys.readouterr().out
    assert "✔ Seeds: 2/2 Passed" in out
    assert out.count("✔ SUCCEEDED") == 2
    assert "Area 0 Core" in out and "Area 1 Edge" in out
    assert "╭" in out and "╮" in out and "╰" in out and "╯" in out


def test_merge_labels_links_with_interfaces_from_every_seeds_neighbour_table(env):
    env.run()
    interfaces = {
        (e["source"], e["target"]): e.get("interface") for e in env.state()["edges"]
    }
    assert interfaces[(R1, R2)] == "eth1"  # from seed A's table
    assert (
        interfaces[(R3, R2)] == "eth0" and interfaces[(R3, R4)] == "eth1"
    )  # from seed B's table
    assert interfaces[(R2, R1)] is None  # R2 was not polled


def test_seed_health_table_shows_lsas_and_neighbours_per_seed(env, capsys):
    env.run()
    out = capsys.readouterr().out
    assert "1 nbrs" in out and "2 nbrs" in out  # seed A has 1 neighbour, seed B has 2
    assert "2 / 1 nbrs" in out and "3 / 2 nbrs" in out  # LSAs / neighbours


def test_fallback_survives_a_dead_first_seed(env, capsys):
    env.network.devices[SEED_A] = NetmikoTimeoutException(
        "TCP connection to device failed."
    )
    assert env.run("--mode", "fallback") == main.EXIT_OK
    out = capsys.readouterr().out
    assert "✖ TIMEOUT" in out and "✔ SUCCEEDED" in out
    assert _router_ids(env.state()) == [
        R2,
        R3,
        R4,
    ]  # only area 1 is visible through seed B
    assert "⚠ Seeds: 1/2 Passed" in out


def test_fallback_does_not_touch_seeds_it_does_not_need(env, capsys):
    assert env.run("--mode", "fallback") == main.EXIT_OK
    assert env.network.connected == [SEED_A]
    out = capsys.readouterr().out
    assert "○ SKIPPED" in out and "✔ Seeds: 1/1 Passed" in out
    assert _router_ids(env.state()) == [R1, R2]


def test_mode_flag_overrides_the_file_and_the_file_mode_is_used_otherwise(env):
    env.write_config()
    env.run()
    assert sorted(env.network.connected) == [SEED_A, SEED_B]  # file says merge
    env.network.connected.clear()
    env.run("--mode", "fallback")
    assert env.network.connected == [SEED_A]


def test_every_seed_down_is_a_clean_error_not_a_crash(env, capsys):
    env.network.devices[SEED_A] = NetmikoTimeoutException("t")
    env.network.devices[SEED_B] = NetmikoAuthenticationException("a")
    assert env.run() == main.EXIT_ERROR
    out = capsys.readouterr().out
    assert "✖ TIMEOUT" in out and "✖ AUTH FAILED" in out
    assert not (env.data / "current_state.json").exists()


def test_merge_with_a_dead_seed_does_not_overwrite_the_baseline(env, capsys):
    assert env.run() == main.EXIT_OK
    before = (env.data / "current_state.json").read_text()

    env.network.devices[SEED_B] = NetmikoTimeoutException("t")
    assert env.run() == main.EXIT_SUSPECT
    out = capsys.readouterr().out
    assert "SUSPECT RUN" in out and SEED_B in out and "⚠ Seeds: 1/2 Passed" in out
    assert (env.data / "current_state.json").read_text() == before  # baseline untouched
    assert (env.data / "suspect_state.json").exists()

    assert (
        env.run("--accept-changes") == main.EXIT_OK
    )  # the user can still commit it explicitly
    assert _router_ids(env.state()) == [R1, R2]


def test_dead_merge_seed_is_suspect_even_when_the_retention_check_would_pass(
    env, capsys
):
    """Only the unreachable seed can raise the alarm here: the retention threshold is set so low that the
    vanished area-1 routers alone would not (this is the 'small area behind one seed' case)."""
    cfg = yaml.safe_load(env.config.read_text())
    cfg["guard"] = {"min_node_retention": 0.1, "flag_partition": False}
    env.config.write_text(yaml.safe_dump(cfg))
    assert env.run() == main.EXIT_OK
    before = (env.data / "current_state.json").read_text()

    env.network.devices[SEED_B] = NetmikoTimeoutException("t")
    assert env.run() == main.EXIT_SUSPECT
    out = capsys.readouterr().out
    assert f"could not be polled ({SEED_B})" in out
    assert (
        "only" not in out.split("SUSPECT RUN")[1].split("Detailed")[0]
    )  # no retention reason alongside
    assert (env.data / "current_state.json").read_text() == before


def test_fallback_after_a_dead_seed_is_not_suspect(env):
    """In fallback mode a failed seed is expected; the seed that answered gives the full picture."""
    env.run("--mode", "fallback")
    env.network.devices[SEED_A] = NetmikoTimeoutException("t")
    env.network.devices[SEED_B] = OUT_A  # a second seed with the same area-0 view
    assert env.run("--mode", "fallback") == main.EXIT_OK


def test_dry_run_writes_no_state_files(env):
    assert env.run("--dry-run") == main.EXIT_OK
    assert not env.data.exists() or not any(env.data.iterdir())


def test_require_all_aborts_when_a_merge_seed_fails(env, caplog):
    cfg = yaml.safe_load(env.config.read_text())
    cfg["seeds"]["require_all"] = True
    env.config.write_text(yaml.safe_dump(cfg))
    env.network.devices[SEED_B] = NetmikoTimeoutException("t")
    with caplog.at_level(logging.ERROR, logger="ospf_tracker"):
        assert env.run() == main.EXIT_ERROR
    assert any(
        "require_all" in r.message and SEED_B in r.message for r in caplog.records
    )
    assert not (env.data / "current_state.json").exists()


def test_require_all_is_satisfied_when_every_seed_answers(env):
    cfg = yaml.safe_load(env.config.read_text())
    cfg["seeds"]["require_all"] = True
    env.config.write_text(yaml.safe_dump(cfg))
    assert env.run() == main.EXIT_OK


def test_seeds_flag_polls_only_the_given_hosts(env):
    assert env.run("--seeds", SEED_B) == main.EXIT_OK
    assert env.network.connected == [SEED_B]
    assert _router_ids(env.state()) == [R2, R3, R4]


def test_seeds_flag_accepts_hosts_missing_from_the_file(env):
    other = "192.0.2.99"
    env.network.devices[other] = OUT_A
    cfg = {
        "device": {
            "host": "x",
            "username": "admin",
            "password": "pw",
            "device_type": "vyos",
        }
    }
    env.config.write_text(yaml.safe_dump(cfg))
    assert env.run("--seeds", f"{other},{SEED_B}") == main.EXIT_OK
    assert sorted(env.network.connected) == sorted([other, SEED_B])
    assert _router_ids(env.state()) == [R1, R2, R3, R4]


def test_legacy_single_device_config_still_works(env, capsys):
    cfg = {
        "device": {
            "host": SEED_A,
            "username": "admin",
            "password": "pw",
            "device_type": "vyos",
        }
    }
    env.config.write_text(yaml.safe_dump(cfg))
    assert env.run() == main.EXIT_OK
    assert env.network.connected == [SEED_A]
    assert _router_ids(env.state()) == [R1, R2]
    assert "✔ Seeds: 1/1 Passed" in capsys.readouterr().out


def test_legacy_env_credentials_still_win_over_the_file(env, monkeypatch):
    cfg = {
        "device": {
            "host": SEED_A,
            "username": "admin",
            "password": "file-pw",
            "device_type": "vyos",
        }
    }
    env.config.write_text(yaml.safe_dump(cfg))
    seen = {}

    def spy(**params):
        seen.update(params)
        return FakeConn(OUT_A)

    monkeypatch.setenv("OSPF_MONITOR_PASSWORD", "env-pw")
    monkeypatch.setattr("src.poller.ConnectHandler", spy)
    assert env.run() == main.EXIT_OK
    assert seen["password"] == "env-pw"


def test_changelog_records_which_seeds_answered(env):
    env.network.devices[SEED_B] = NetmikoTimeoutException("t")
    env.run()
    entry = json.loads((env.data / "changelog.jsonl").read_text().splitlines()[-1])
    assert entry["sources_ok"] == [SEED_A]


def test_save_raw_uses_one_folder_per_seed_when_several_are_configured(env, tmp_path):
    raw_dir = tmp_path / "raw"
    env.run("--save-raw", str(raw_dir))
    assert (raw_dir / SEED_A / "router_lsdb.txt").read_text() == OUT_A["router"]
    assert (raw_dir / SEED_B / "neighbors.txt").exists()
    assert not (raw_dir / "router_lsdb.txt").exists()


def test_save_raw_keeps_the_flat_layout_for_a_single_seed(env, tmp_path):
    cfg = {
        "device": {
            "host": SEED_A,
            "username": "admin",
            "password": "pw",
            "device_type": "vyos",
        }
    }
    env.config.write_text(yaml.safe_dump(cfg))
    raw_dir = tmp_path / "raw"
    env.run("--save-raw", str(raw_dir))
    assert (raw_dir / "router_lsdb.txt").read_text() == OUT_A["router"]


def test_replay_output_has_no_seed_table(env, capsys):
    replay = env.tmp / "replay"
    replay.mkdir()
    (replay / "router_lsdb.txt").write_text(OUT_A["router"])
    assert env.run("--replay", str(replay), "--device-type", "vyos") == main.EXIT_OK
    out = capsys.readouterr().out
    assert "Seed Routers" not in out and "✔ Stable Topology" in out


def test_parse_args_accepts_the_new_flags():
    args = main.parse_args(["--mode", "fallback", "--seeds", "10.1.1.1,10.1.1.2"])
    assert (args.mode, args.seeds) == ("fallback", "10.1.1.1,10.1.1.2")
    with pytest.raises(SystemExit):
        main.parse_args(["--mode", "round-robin"])
