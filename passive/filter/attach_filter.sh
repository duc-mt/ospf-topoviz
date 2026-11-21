#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-gre1}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBJ="${SRC_DIR}/announcement_filter.o"

clang -O2 -g -target bpf -c "${SRC_DIR}/announcement_filter.c" -o "${OBJ}"
tc qdisc replace dev "${IFACE}" clsact
tc filter replace dev "${IFACE}" egress bpf da obj "${OBJ}" sec classifier
echo "Attached MIT listen-only OSPF eBPF filter on egress of ${IFACE}."
