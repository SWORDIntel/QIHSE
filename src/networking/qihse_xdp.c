#include "qihse_platform.h"

#ifndef _WIN32
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define QIHSE_RESP_PORT 6380
#define QIHSE_PG_PORT 5433

/* AF_XDP socket map */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} xsks_map SEC(".maps");

/* Blacklisted IPs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} blacklist_map SEC(".maps");

SEC("xdp")
int qihse_xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Check blacklist */
    __u32 src_ip = ip->saddr;
    __u32 *blacklisted = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (blacklisted) {
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Parse TCP/UDP header to get port */
    struct tcphdr *tcp = (void *)(ip + 1);
    struct udphdr *udp = (void *)(ip + 1);

    __u16 dest_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dest_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dest_port = bpf_ntohs(udp->dest);
    }

    /* Redirect QIHSE traffic to AF_XDP socket */
    if (dest_port == QIHSE_RESP_PORT || dest_port == QIHSE_PG_PORT) {
        /* Redirect to the AF_XDP socket bound to this RX queue */
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
#endif

