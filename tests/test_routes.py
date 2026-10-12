"""OSPF routing-table (RIB) parsers, the extended neighbour parsers, platform commands and RIB polling."""

from __future__ import annotations

import pytest

from src.config import ConfigError
from src.parser import OSPFParser
from src.poller import DevicePoller, FilePoller, PollerError
from src.vendors import get_profile
from src.vendors.base import (
    ROUTE_E1,
    ROUTE_E2,
    ROUTE_EXTERNAL,
    ROUTE_INTER,
    ROUTE_INTERNAL,
    ROUTE_INTRA,
    ROUTE_N1,
    ROUTE_N2,
    NeighborRecord,
    NextHop,
    OSPFNeighbor,
    OSPFRoute,
    ParserError,
    parse_dead_time,
    role_from_dr,
    state_severity,
)
from src.vendors.routes import parse_routes


def _hops(route):
    return [(h.ip, h.interface) for h in route.next_hops]


def _by_cidr(routes):
    return {r.cidr: r for r in routes}


# ----------------------------------------------------------------- model
def test_route_from_cidr_normalises_prefix_and_mask():
    r = OSPFRoute.from_cidr(
        "10.1.1.7/24", ROUTE_INTRA, metric=20, next_hops=[NextHop("10.0.0.2", "eth1")]
    )
    assert (r.prefix, r.mask, r.prefix_length, r.cidr) == (
        "10.1.1.0",
        "255.255.255.0",
        24,
        "10.1.1.0/24",
    )
    assert r.active is True and r.tag is None


def test_neighbor_record_is_also_the_ospf_neighbor_model():
    n = NeighborRecord(
        "10.0.0.2",
        "Full",
        role="DR",
        interface="eth1",
        address="10.12.0.2",
        priority=1,
        dead_time=33,
    )
    assert OSPFNeighbor is NeighborRecord
    assert (n.neighbor_id, n.ip_address, n.dr_bdr_role) == (
        "10.0.0.2",
        "10.12.0.2",
        "DR",
    )


@pytest.mark.parametrize(
    "text, seconds",
    [
        ("00:00:33", 33),
        ("01:02:03", 3723),
        ("33.5s", 33),
        ("37", 37),
        ("-", None),
        (None, None),
    ],
)
def test_parse_dead_time(text, seconds):
    assert parse_dead_time(text) == seconds


def test_role_from_dr_and_state_severity():
    assert role_from_dr("10.0.0.2", "10.0.0.2", "10.0.0.1") == "DR"
    assert role_from_dr("10.0.0.1", "10.0.0.2", "10.0.0.1") == "BDR"
    assert role_from_dr("10.0.0.9", "10.0.0.2", "10.0.0.1") == "DROther"
    assert (
        role_from_dr("10.0.0.9", "0.0.0.0", "0.0.0.0") is None
    )  # point-to-point: no election
    assert (
        state_severity("Full")
        < state_severity("2-Way")
        < state_severity("ExStart")
        < state_severity("Down")
    )
    assert state_severity("weird") == state_severity("Down")


# ------------------------------------------------------------- Cisco IOS
IOS = """Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       O - OSPF, IA - OSPF inter area, E1 - OSPF external type 1, E2 - OSPF external type 2

Gateway of last resort is not set

      10.0.0.0/8 is variably subnetted, 8 subnets, 2 masks
O        10.0.0.2/32 [110/2] via 10.12.0.2, 00:05:23, GigabitEthernet0/1
O IA     10.1.1.0/24 [110/3] via 10.12.0.2, 00:05:23, GigabitEthernet0/1
                     [110/3] via 10.13.0.3, 00:05:23, GigabitEthernet0/2
O E2     172.16.0.0/16 [110/20] via 10.12.0.2, 1d02h, GigabitEthernet0/1
O*E2  0.0.0.0/0 [110/1] via 10.12.0.2, 00:05:23, GigabitEthernet0/1
      192.168.1.0/24 is subnetted, 1 subnets
O        192.168.1.0 [110/2] via 10.12.0.2, 00:05:23, GigabitEthernet0/1
C        10.99.0.0/24 is directly connected, Loopback0
"""


def test_ios_routes():
    routes = _by_cidr(parse_routes("ios", IOS))
    assert set(routes) == {
        "10.0.0.2/32",
        "10.1.1.0/24",
        "172.16.0.0/16",
        "0.0.0.0/0",
        "192.168.1.0/24",
    }
    assert (
        routes["10.0.0.2/32"].route_type == ROUTE_INTRA
        and routes["10.0.0.2/32"].metric == 2
    )
    assert routes["10.0.0.2/32"].distance == 110
    assert routes["10.1.1.0/24"].route_type == ROUTE_INTER
    assert _hops(routes["10.1.1.0/24"]) == [
        ("10.12.0.2", "GigabitEthernet0/1"),
        ("10.13.0.3", "GigabitEthernet0/2"),
    ]
    assert (
        routes["172.16.0.0/16"].route_type == ROUTE_E2
        and routes["172.16.0.0/16"].metric == 20
    )
    assert routes["0.0.0.0/0"].route_type == ROUTE_E2
    assert (
        routes["192.168.1.0/24"].mask == "255.255.255.0"
    )  # mask taken from the "is subnetted" header


def test_ios_ignores_non_ospf_routes_and_junk():
    assert (
        parse_routes(
            "ios",
            "C   10.9.9.0/24 is directly connected, Vlan9\nS   10.8.0.0/16 [1/0] via 10.1.1.1\n",
        )
        == []
    )
    assert parse_routes("ios", "") == [] and parse_routes("ios", "   \n") == []


@pytest.mark.parametrize(
    "codes, expected",
    [
        ("O", ROUTE_INTRA),
        ("O IA", ROUTE_INTER),
        ("O E1", ROUTE_E1),
        ("O E2", ROUTE_E2),
        ("O N1", ROUTE_N1),
        ("O N2", ROUTE_N2),
    ],
)
def test_route_type_codes(codes, expected):
    [route] = parse_routes(
        "ios", f"{codes}   10.5.0.0/24 [110/10] via 10.12.0.2, 00:00:10, Gi0/1\n"
    )
    assert route.route_type == expected


# ---------------------------------------------------------------- Arista
EOS = """VRF: default
Codes: C - connected, S - static, K - kernel,
       O - OSPF, IA - OSPF inter area, E1 - OSPF external type 1,
       E2 - OSPF external type 2, N1 - OSPF NSSA external type 1,
       N2 - OSPF NSSA external type2, B - Other BGP Routes

Gateway of last resort is not set

 O        10.0.0.2/32 [110/20] via 10.12.0.2, Ethernet1
 O IA     10.1.1.0/24 [110/30] via 10.12.0.2, Ethernet1
                               via 10.13.0.3, Ethernet2
 O E2     172.16.0.0/16 [110/20] via 10.12.0.2, Ethernet1
"""


def test_eos_routes_with_ecmp():
    routes = _by_cidr(parse_routes("eos", EOS))
    assert len(routes) == 3
    assert (
        routes["10.1.1.0/24"].route_type == ROUTE_INTER
        and routes["10.1.1.0/24"].metric == 30
    )
    assert _hops(routes["10.1.1.0/24"]) == [
        ("10.12.0.2", "Ethernet1"),
        ("10.13.0.3", "Ethernet2"),
    ]
    assert routes["172.16.0.0/16"].route_type == ROUTE_E2


# ------------------------------------------------------------------- FRR
FRR = """Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, > - selected route, * - FIB route

O   10.12.0.0/24 [110/10] is directly connected, eth1, weight 1, 00:05:23
O>* 10.0.0.2/32 [110/20] via 10.12.0.2, eth1, weight 1, 00:05:23
O>* 10.1.1.0/24 [110/30] via 10.12.0.2, eth1, weight 1, 00:05:23
  *                      via 10.13.0.3, eth2, weight 1, 00:05:23
O IA 10.2.0.0/24 [110/40] via 10.12.0.2, eth1, weight 1, 00:05:23
O   10.7.0.0/24 [110/25] via 10.12.0.2, eth1, weight 1, 00:05:23
"""


def test_frr_routes_selected_flag_ecmp_and_connected():
    routes = _by_cidr(parse_routes("frr", FRR))
    assert routes["10.0.0.2/32"].active is True
    assert routes["10.12.0.0/24"].active is False and _hops(routes["10.12.0.0/24"]) == [
        (None, "eth1")
    ]
    assert _hops(routes["10.1.1.0/24"]) == [
        ("10.12.0.2", "eth1"),
        ("10.13.0.3", "eth2"),
    ]
    assert routes["10.2.0.0/24"].route_type == ROUTE_INTER
    # listed without '>' = another source (static/BGP) was selected instead
    assert (
        routes["10.7.0.0/24"].active is False
        and routes["10.7.0.0/24"].next_hops[0].ip == "10.12.0.2"
    )


# ----------------------------------------------------------------- NX-OS
NXOS = """IP Route Table for VRF "default"
'*' denotes best ucast next-hop
'**' denotes best mcast next-hop
'[x/y]' denotes [preference/metric]
'%<string>' in via output denotes VRF <string>

10.0.0.2/32, ubest/mbest: 1/0
    *via 10.12.0.2, Eth1/1, [110/41], 00:05:23, ospf-1, intra
10.1.1.0/24, ubest/mbest: 2/0
    *via 10.12.0.2, Eth1/1, [110/60], 00:05:23, ospf-1, inter
    *via 10.13.0.3, Eth1/2, [110/60], 00:05:23, ospf-1, inter
172.16.0.0/16, ubest/mbest: 1/0
    *via 10.12.0.2, Eth1/1, [110/20], 00:05:23, ospf-1, type-2, tag 100
172.17.0.0/16, ubest/mbest: 1/0
    *via 10.12.0.2, Eth1/1, [110/20], 00:05:23, ospf-2, type-1
"""


def test_nxos_routes():
    routes = _by_cidr(parse_routes("nxos", NXOS))
    assert (
        routes["10.0.0.2/32"].route_type == ROUTE_INTRA
        and routes["10.0.0.2/32"].metric == 41
    )
    assert (
        routes["10.1.1.0/24"].route_type == ROUTE_INTER
        and len(routes["10.1.1.0/24"].next_hops) == 2
    )
    assert (
        routes["172.16.0.0/16"].route_type == ROUTE_E2
        and routes["172.16.0.0/16"].tag == 100
    )
    assert (
        routes["172.17.0.0/16"].route_type == ROUTE_E1
        and routes["172.17.0.0/16"].process_id == "2"
    )


def test_nxos_filters_by_process():
    assert set(_by_cidr(parse_routes("nxos", NXOS, "2"))) == {"172.17.0.0/16"}
    assert "172.17.0.0/16" not in _by_cidr(parse_routes("nxos", NXOS, "1"))


# ----------------------------------------------------------------- Junos
JUNOS = """inet.0: 12 destinations, 12 routes (12 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

10.0.0.2/32        *[OSPF/10] 00:05:23, metric 1
                    >  to 10.12.0.2 via ge-0/0/0.0
10.1.1.0/24        *[OSPF/10] 00:05:23, metric 30
                    >  to 10.12.0.2 via ge-0/0/0.0
                       to 10.13.0.3 via ge-0/0/1.0
172.16.0.0/16      [OSPF/150] 00:05:23, metric 20, tag 7
                    >  to 10.12.0.2 via ge-0/0/0.0
10.200.200.200.0/24
                   *[OSPF/10] 2d 03:04:05, metric 5
                    >  to 10.12.0.2 via ge-0/0/0.0
224.0.0.5/32       *[OSPF/10] 1w2d 03:04:05, metric 1
                       MultiRecv
"""


def test_junos_routes():
    routes = _by_cidr(parse_routes("junos", JUNOS))
    assert set(routes) == {
        "10.0.0.2/32",
        "10.1.1.0/24",
        "172.16.0.0/16",
    }  # multicast skipped
    assert (
        routes["10.0.0.2/32"].route_type == ROUTE_INTERNAL
        and routes["10.0.0.2/32"].metric == 1
    )
    assert routes["10.0.0.2/32"].distance == 10 and routes["10.0.0.2/32"].active is True
    assert _hops(routes["10.1.1.0/24"]) == [
        ("10.12.0.2", "ge-0/0/0.0"),
        ("10.13.0.3", "ge-0/0/1.0"),
    ]
    ext = routes["172.16.0.0/16"]
    assert ext.route_type == ROUTE_EXTERNAL and ext.tag == 7 and ext.distance == 150
    assert (
        ext.active is False
    )  # no '*' / '+': another protocol's route is the active one


def test_junos_prefix_wrapped_onto_its_own_line():
    text = (
        "10.50.60.0/24\n                   *[OSPF/10] 2d 03:04:05, metric 5\n"
        "                    >  to 10.12.0.2 via ge-0/0/0.0\n"
    )
    [route] = parse_routes("junos", text)
    assert (route.cidr, route.metric, route.active) == ("10.50.60.0/24", 5, True)


def test_junos_ignores_other_protocols():
    text = "10.9.0.0/24        *[Direct/0] 1d 00:00:01\n                    >  via ge-0/0/3.0\n"
    assert parse_routes("junos", text) == []


def test_unknown_route_format_is_an_error():
    with pytest.raises(ParserError):
        parse_routes("cobol", "O 10.0.0.0/8 [110/1] via 1.1.1.1")


# --------------------------------------------- through the platform adapters
def test_parser_dispatches_routes_per_platform():
    assert len(OSPFParser("cisco_ios").parse_routes(IOS)) == 5
    assert len(OSPFParser("arista_eos").parse_routes(EOS)) == 3
    assert len(OSPFParser("vyos").parse_routes(FRR)) == 5
    assert len(OSPFParser("cisco_nxos").parse_routes(NXOS)) == 4
    assert len(OSPFParser("juniper_junos").parse_routes(JUNOS)) == 3


def test_platforms_without_a_route_parser_say_so():
    assert OSPFParser("huawei").parse_routes("anything") is None
    assert OSPFParser("cisco_xr").parse_routes("anything") is None


# ----------------------------------------------------- extended neighbours
def test_ios_neighbors_carry_priority_dead_time_and_role():
    text = """Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.2          1   FULL/DR         00:00:33    10.12.0.2       GigabitEthernet0/1
10.0.0.3          0   2WAY/DROTHER    00:00:38    10.13.0.3       GigabitEthernet0/2
10.0.0.4          1   EXSTART/-       00:00:35    10.14.0.4       GigabitEthernet0/3
"""
    a, b, c = OSPFParser("cisco_ios").parse_neighbors(text)
    assert (a.state, a.role, a.priority, a.dead_time, a.interface, a.address) == (
        "Full",
        "DR",
        1,
        33,
        "GigabitEthernet0/1",
        "10.12.0.2",
    )
    assert (b.state, b.role, b.priority) == (
        "2-Way",
        "DROther",
        0,
    )  # priority 0 is a value, not "missing"
    assert (c.state, c.role) == ("ExStart", None)


def test_arista_neighbors():
    text = """Neighbor ID     Instance VRF      Pri State                  Dead Time   Address         Interface
10.0.0.2        1        default  1   FULL/DR                00:00:33    10.12.0.2       Ethernet1
10.0.0.3        1        default  100 2-WAY/DROTHER          00:00:38    10.13.0.3       Ethernet2
"""
    a, b = OSPFParser("arista_eos").parse_neighbors(text)
    assert (a.state, a.role, a.priority, a.dead_time, a.interface) == (
        "Full",
        "DR",
        1,
        33,
        "Ethernet1",
    )
    assert (b.state, b.role, b.priority) == ("2-Way", "DROther", 100)


JUNOS_DETAIL = """Address          Interface              State           ID               Pri  Dead
10.12.0.2        ge-0/0/0.0             Full            10.0.0.2         128    37
  Area 0.0.0.0, opt 0x52, DR 10.12.0.2, BDR 10.12.0.1
  Up 00:05:21, adjacent 00:05:21
10.13.0.3        ge-0/0/1.0             ExStart         10.0.0.3         1      35
  Area 0.0.0.0, opt 0x52, DR 10.13.0.1, BDR 10.13.0.5
  Up 00:00:12, adjacent 00:00:12
10.14.0.4        ge-0/0/2.0             Full            10.0.0.4         128    38
  Area 0.0.0.0, opt 0x52, DR 0.0.0.0, BDR 0.0.0.0
  Up 00:05:21, adjacent 00:05:21
"""


def test_junos_neighbor_detail_gives_roles_priority_and_dead_time():
    a, b, c = OSPFParser("juniper_junos").parse_neighbors(JUNOS_DETAIL)
    assert (a.state, a.role, a.priority, a.dead_time, a.area) == (
        "Full",
        "DR",
        128,
        37,
        "0.0.0.0",
    )
    assert (b.state, b.role) == ("ExStart", "DROther")
    assert c.role is None  # DR 0.0.0.0 = point-to-point


def test_junos_plain_neighbor_table_still_parses():
    text = (
        "Address          Interface              State           ID               Pri  Dead\n"
        "10.12.0.2        ge-0/0/0.0             Full            10.0.0.2         128    37\n"
    )
    [n] = OSPFParser("juniper_junos").parse_neighbors(text)
    assert (n.router_id, n.state, n.role, n.priority, n.dead_time) == (
        "10.0.0.2",
        "Full",
        None,
        128,
        37,
    )


NXOS_DETAIL = """ Neighbor 10.0.0.2, interface address 10.12.0.2
    Process ID 1 VRF default, in area 0.0.0.0 via interface Ethernet1/1
    State is FULL, 5 state changes, last change 08:38:40
    Neighbor priority is 1
    DR is 10.12.0.2 BDR is 10.12.0.1
    Hello options 0x12, dbd options 0x52
    Last non-hello packet received never
    Dead timer due in 00:00:33
 Neighbor 10.0.0.3, interface address 10.13.0.3
    Process ID 1 VRF default, in area 0.0.0.0 via interface Ethernet1/2
    State is EXSTART, 1 state changes, last change 00:00:12
    Neighbor priority is 0
    DR is 0.0.0.0 BDR is 0.0.0.0
    Hello options 0x12, dbd options 0x52
    Last non-hello packet received never
    Dead timer due in 00:00:35
"""


def test_nxos_neighbors():
    a, b = OSPFParser("cisco_nxos").parse_neighbors(NXOS_DETAIL)
    assert (
        a.router_id,
        a.state,
        a.role,
        a.priority,
        a.dead_time,
        a.interface,
        a.area,
    ) == ("10.0.0.2", "Full", "DR", 1, 33, "Ethernet1/1", "0.0.0.0")
    assert (b.state, b.role, b.priority) == ("ExStart", None, 0)
    assert (
        OSPFParser("cisco_nxos", 2).parse_neighbors(NXOS_DETAIL) == []
    )  # another OSPF process


def test_frr_neighbors_have_priority_and_dead_time():
    text = (
        "Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL\n"
        "10.0.0.2          1 Full/Backup     1h02m           33.5s     10.12.0.2       eth1:10.12.0.1                       0     0     0\n"
    )
    [n] = OSPFParser("vyos").parse_neighbors(text)
    assert (n.role, n.priority, n.dead_time, n.interface) == ("BDR", 1, 33, "eth1")


# --------------------------------------------------- platform command table
@pytest.mark.parametrize(
    "device_type, routes, neighbors",
    [
        ("cisco_ios", "show ip route ospf", "show ip ospf neighbor"),
        ("cisco_nxos", "show ip route ospf", "show ip ospf neighbors detail"),
        ("arista_eos", "show ip route ospf", "show ip ospf neighbor"),
        ("juniper_junos", "show route protocol ospf", "show ospf neighbor detail"),
        ("vyos", "show ip route ospf", "show ip ospf neighbor"),
    ],
)
def test_platform_commands(device_type, routes, neighbors):
    profile = get_profile(device_type)
    assert profile.command("routes", None) == routes
    assert profile.command("neighbors", None) == neighbors


def test_ios_route_command_takes_the_process_id():
    assert get_profile("cisco_ios").command("routes", "7") == "show ip route ospf 7"
    assert (
        get_profile("cisco_nxos").command("neighbors", "7")
        == "show ip ospf 7 neighbors detail"
    )


def test_platform_without_a_route_command_refuses_politely():
    with pytest.raises(ConfigError):
        get_profile("huawei").command("routes", None)
    assert get_profile("huawei").routes is None


# ------------------------------------------------------------ polling RIB
class _Conn:
    def __init__(self, outputs, boom=None):
        self.outputs, self.boom, self.sent = outputs, boom, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def check_enable_mode(self):
        return True

    def send_command(self, command, read_timeout=None):
        self.sent.append(command)
        if self.boom and self.boom in command:
            raise OSError("socket closed")
        for key, marker in (
            ("router", "database router"),
            ("network", "database network"),
            ("neighbors", "neighbor"),
            ("routes", "route ospf"),
        ):
            if marker in command:
                return self.outputs.get(key, "")
        raise AssertionError(command)


def _poller(tmp_path, monkeypatch, conn, polling=None):
    monkeypatch.setattr("src.poller.ConnectHandler", lambda **params: conn)
    settings = {
        "device": {"host": "h", "username": "u", "password": "p", "device_type": "vyos"}
    }
    if polling is not None:
        settings["polling"] = polling
    return DevicePoller.from_settings(tmp_path / "s.yaml", settings=settings)[0]


def test_poller_collects_the_routing_table(tmp_path, monkeypatch):
    conn = _Conn({"router": "R", "network": "N", "neighbors": "NB", "routes": FRR})
    raw = _poller(tmp_path, monkeypatch, conn).poll()
    assert raw.routes == FRR and raw.neighbors == "NB"
    assert "show ip route ospf" in conn.sent


def test_polling_routes_can_be_switched_off(tmp_path, monkeypatch):
    conn = _Conn({"router": "R", "network": "N", "routes": FRR})
    raw = _poller(tmp_path, monkeypatch, conn, {"routes": False}).poll()
    assert raw.routes == "" and "show ip route ospf" not in conn.sent


def test_a_failing_routing_table_command_never_costs_the_lsdb(tmp_path, monkeypatch):
    conn = _Conn({"router": "R", "network": "N", "neighbors": "NB"}, boom="route ospf")
    raw = _poller(tmp_path, monkeypatch, conn).poll()
    assert raw.router == "R" and raw.neighbors == "NB" and raw.routes == ""


def test_a_rejected_routing_table_command_is_not_fatal(tmp_path, monkeypatch):
    conn = _Conn({"router": "R", "network": "N", "routes": "Invalid command"})
    assert _poller(tmp_path, monkeypatch, conn).poll().routes == ""


def test_file_poller_reads_routes_txt(tmp_path):
    (tmp_path / "router_lsdb.txt").write_text("R")
    (tmp_path / "routes.txt").write_text(FRR)
    assert FilePoller(tmp_path, device_type="vyos").poll().routes == FRR
    (tmp_path / "routes.txt").unlink()
    assert FilePoller(tmp_path, device_type="vyos").poll().routes == ""


def test_router_lsdb_failure_is_still_fatal(tmp_path, monkeypatch):
    conn = _Conn({"router": ""})
    with pytest.raises(PollerError):
        _poller(tmp_path, monkeypatch, conn).poll()
