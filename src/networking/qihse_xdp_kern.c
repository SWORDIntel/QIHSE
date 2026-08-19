/*
 * qihse_xdp_kern.c — QIHSE eBPF/XDP kernel program
 *
 * Compiled with: clang -target bpf -O2 (see Makefile: make xdp-kern)
 * Loaded by:     qihse_af_xdp_init() via libxdp
 *
 * Packet classification:
 *   TCP dst port 5432  (PostgreSQL wire)  → XDP_REDIRECT to AF_XDP socket
 *   TCP dst port 7432  (UWP default)      → XDP_REDIRECT to AF_XDP socket
 *   TCP dst port 6379  (RESP / Redis)     → XDP_REDIRECT to AF_XDP socket
 *   UDP dst port 16379 (Cluster Bus)      → XDP_REDIRECT to AF_XDP socket
 *   TCP/UDP payload bytes 0-4 == "QIHSE"  → XDP_REDIRECT (UWP / Cluster on any port)
 *   Packet too short to parse headers     → XDP_DROP (malformed, DDoS mitigation)
 *   Anything else                         → XDP_PASS  (kernel TCP/IP stack)
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ── Maps ────────────────────────────────────────────────────────────────── */

/*
 * XSKMAP: AF_XDP sockets registered by userspace via qihse_af_xdp_init().
 * Key = queue index (0 for single-queue NICs), value = xsk fd.
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key,   __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

/*
 * qihse_ports: configurable port list set by userspace.
 * Index 0 = PG wire port   (default 5432)
 * Index 1 = UWP port       (default 7432)
 * Index 2 = RESP wire port (default 6379)
 * Index 3 = Cluster bus    (default 16379)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} qihse_ports SEC(".maps");

/* ── Constants ───────────────────────────────────────────────────────────── */

#define QIHSE_DEFAULT_PG_PORT    5432
#define QIHSE_DEFAULT_UWP_PORT   7432
#define QIHSE_DEFAULT_RESP_PORT  6379
#define QIHSE_DEFAULT_BUS_PORT   16379

/* Minimum packet size: Ethernet (14) + IPv4 (20) + UDP (8) = 42 bytes */
#define QIHSE_MIN_PKT_LEN 42

/* UWP / Cluster magic: 'Q','I','H','S','E' */
#define UWP_MAGIC_0 'Q'
#define UWP_MAGIC_1 'I'
#define UWP_MAGIC_2 'H'
#define UWP_MAGIC_3 'S'
#define UWP_MAGIC_4 'E'

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline __u32 get_port(__u32 idx, __u32 fallback) {
    __u32 *val = bpf_map_lookup_elem(&qihse_ports, &idx);
    return (val && *val) ? *val : fallback;
}

/* ── XDP program ─────────────────────────────────────────────────────────── */

SEC("xdp")
int qihse_xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* Drop anything too short to contain valid headers */
    if (data + QIHSE_MIN_PKT_LEN > data_end)
        return XDP_DROP;

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS; /* Not IPv4 — let kernel handle */

    /* Parse IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return XDP_DROP;

    /* Retrieve configured ports */
    __u32 pg_port   = get_port(0, QIHSE_DEFAULT_PG_PORT);
    __u32 uwp_port  = get_port(1, QIHSE_DEFAULT_UWP_PORT);
    __u32 resp_port = get_port(2, QIHSE_DEFAULT_RESP_PORT);
    __u32 bus_port  = get_port(3, QIHSE_DEFAULT_BUS_PORT);

    /* 1. Handle TCP traffic (PG, UWP, RESP) */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        __u16 dst_port = bpf_ntohs(tcp->dest);
        int is_qihse_port = (dst_port == pg_port || dst_port == uwp_port || dst_port == resp_port);

        /* Check payload for UWP magic or RESP array prefix */
        __u32 tcp_hdr_len = tcp->doff * 4;
        if (tcp_hdr_len < 20)
            return XDP_DROP;

        __u8 *payload = (void *)tcp + tcp_hdr_len;
        int has_qihse_magic = 0;
        if ((void *)(payload + 5) <= data_end) {
            has_qihse_magic = (payload[0] == UWP_MAGIC_0 &&
                               payload[1] == UWP_MAGIC_1 &&
                               payload[2] == UWP_MAGIC_2 &&
                               payload[3] == UWP_MAGIC_3 &&
                               payload[4] == UWP_MAGIC_4);
        }

        if (is_qihse_port || has_qihse_magic) {
            __u32 queue_idx = ctx->rx_queue_index;
            return bpf_redirect_map(&xsks_map, queue_idx, XDP_PASS);
        }
    }

    /* 2. Handle UDP traffic (Cluster Bus Gossip) */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        __u16 dst_port = bpf_ntohs(udp->dest);
        if (dst_port == bus_port) {
            __u32 queue_idx = ctx->rx_queue_index;
            return bpf_redirect_map(&xsks_map, queue_idx, XDP_PASS);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
