# Optional Self-Hosted Passive OSPF Sidecar (Linux)

For legacy routers that do not support **BGP-LS**, this optional Linux-only profile runs FRRouting (`ospfd`) in an isolated container namespace (`gre` or `macvlan`), installs `route-map TO_KERNEL deny 200` so zero OSPF routes ever enter the kernel RIB, attaches an MIT-licensed `tc-bpf` listen-only egress filter, and pushes changed LSDB snapshots to `POST /api/ingest/lsdb`.

## Quick Start

1. Export an ingest secret token and launch `ospf-topoviz` with `docker compose --profile passive -f docker-compose.passive.yml up -d`.
2. Attach the listen-only BPF filter if required: `passive/filter/attach_filter.sh gre1`.
3. Diagnose GRE/MTU/firewall connectivity issues:
   ```bash
   python main.py --doctor-passive --passive-mode gre --iface gre1 --peer 192.0.2.2
   ```
