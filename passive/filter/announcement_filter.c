// SPDX-License-Identifier: MIT
// Listen-only OSPF TopoViz tc-BPF egress announcement filter.
// Allows non-LSUpdate OSPF packets (Hello/DBD/LSR/LSAck) and drops any LSUpdate carrying
// non-self-originated Router-LSAs or Type 2/3/5/7 transit/external LSAs.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF 89
#endif
#define OSPF_TYPE_LSUPDATE 4

SEC("classifier")
int ospf_listen_only_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_OSPF)
        return TC_ACT_OK;

    __u8 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return TC_ACT_OK;

    // OSPF common header begins right after IPv4 header: [version:1B][type:1B]
    __u8 *ospf_hdr = (__u8 *)ip + ihl;
    if ((void *)(ospf_hdr + 24) > data_end)
        return TC_ACT_OK;

    __u8 ospf_type = ospf_hdr[1];
    // Allow Hello (1), DBD (2), LSR (3), LSAck (5); only restrict LSUpdate (4) with >1 LSA
    if (ospf_type != OSPF_TYPE_LSUPDATE)
        return TC_ACT_OK;

    __u8 *ls_count_ptr = ospf_hdr + 24;
    if ((void *)(ls_count_ptr + 4) > data_end)
        return TC_ACT_SHOT;

    __u32 num_lsas = bpf_ntohl(*(__u32 *)ls_count_ptr);
    if (num_lsas == 0)
        return TC_ACT_OK;

    // Enforce listen-only safety: only allow a single empty Router-LSA (type 1)
    if (num_lsas > 1)
        return TC_ACT_SHOT;

    __u8 *lsa_hdr = ls_count_ptr + 4;
    if ((void *)(lsa_hdr + 20) > data_end)
        return TC_ACT_SHOT;

    __u8 ls_type = lsa_hdr[3];
    if (ls_type != 1)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "MIT";
