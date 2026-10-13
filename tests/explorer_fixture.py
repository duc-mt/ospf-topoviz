"""A topology shaped like a real one: 14 routers, 5 transit networks, areas 0/1/4, one stale network,
ten one-way links and a piece that is cut off from the rest (a router and a network with no LSA).

Used by the layout, scene and explorer tests.
"""

import networkx as nx

A0, A1, A4 = "0.0.0.0", "0.0.0.1", "0.0.0.4"


def realistic() -> nx.DiGraph:
    """The topology described in the module docstring (node/edge attributes as the parser makes them)."""
    g = nx.DiGraph()

    def router(i, areas, abr=False, asbr=True, **kw):
        g.add_node(
            i,
            type="router",
            areas=list(areas),
            abr=abr,
            asbr=asbr,
            resolved=True,
            lsa_age=300,
            **kw,
        )

    def net(i, area, dr, prefix, resolved=True, **kw):
        g.add_node(
            i,
            type="network",
            areas=[area] if area else [],
            resolved=resolved,
            dr=dr,
            prefix=prefix,
            **({"lsa_age": 300} | kw),
        )

    def attach(r, n, metric, area, iface=None, ip=None, oneway=False, state=None):
        a = {"metric": metric, "link_type": "transit", "area": area}
        if iface:
            a["interface"] = iface
        if ip:
            a["interface_address"] = ip
        if state:
            a["nbr_state"] = state
        g.add_edge(r, n, **a)
        if not oneway:
            g.add_edge(n, r, metric=0, link_type="attachment", area=area)
        else:
            g[r][n]["link_state"] = "one-way"

    P = "10.255.255."
    for i in (1, 6, 7, 10, 11, 14, 15, 18, 19):
        router(
            P + str(i),
            [A0]
            if i in (1, 10, 11, 14, 15)
            else ([A0, A1] if i in (6, 7) else [A0, A4]),
            abr=True,
        )
    router(P + "4", [A0])
    router(P + "5", [A0])
    router("10.253.0.253", [A0], asbr=False)
    router(
        P + "8", [A1], prefixes=[{"prefix": "10.80.0.0/24", "metric": 1, "area": A1}]
    )
    router(P + "20", [A4])
    net("net-10.130.240.1", A0, P + "5", "10.130.240.0/24")
    net("net-10.130.240.2", A0, P + "4", "10.130.240.0/24", stale=True, lsa_age=3600)
    net("net-10.253.0.254", A0, None, None, resolved=False)
    net("net-172.16.4.4", A1, P + "7", "172.16.4.0/28")
    net("net-10.136.4.4", A4, P + "19", "10.136.4.0/28")
    hub = "net-10.130.240.1"
    stale = "net-10.130.240.2"
    for i, m in (
        (15, 200),
        (11, 200),
        (5, 200),
        (10, 1),
        (14, 1),
        (4, 1),
        (6, 1),
        (7, 200),
        (18, 1),
        (19, 200),
    ):
        attach(
            P + str(i),
            hub,
            m,
            A0,
            iface=f"eth{i % 3}",
            ip=f"10.130.240.{i}",
            state="Full" if i in (4, 10, 14) else None,
        )
    for i in (15, 11, 5, 10, 14, 4, 6, 7, 18, 19):
        attach(P + str(i), stale, 200, A0, ip=f"10.130.240.{i + 20}", oneway=True)
    g.add_edge(
        P + "1",
        P + "4",
        metric=1,
        link_type="point-to-point",
        area=A0,
        interface="tun0",
        interface_address="10.253.0.253",
    )
    g.add_edge(
        P + "4",
        P + "1",
        metric=1,
        link_type="point-to-point",
        area=A0,
        interface="tun0",
        interface_address="10.253.0.254",
    )
    attach("10.253.0.253", "net-10.253.0.254", 1, A0, ip="10.253.0.253", oneway=True)
    for r, m in ((P + "6", 1), (P + "7", 200), (P + "8", 10)):
        attach(
            r, "net-172.16.4.4", m, A1, iface="eth1", ip="172.16.4." + r.split(".")[-1]
        )
    for r, m in ((P + "18", 1), (P + "19", 200), (P + "20", 10)):
        attach(
            r, "net-10.136.4.4", m, A4, iface="eth1", ip="10.136.4." + r.split(".")[-1]
        )
    return g
