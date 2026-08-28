/*
 * qihse_xdp_kern.c — QIHSE eBPF/XDP kernel program (hardened)
 *
 * Compiled with: clang -target bpf -O2 (see Makefile: make xdp-kern)
 * Loaded by:     qihse_af_xdp_init() via libxdp
 *
 * Packet classification:
 *   TCP dst port 5432  (PostgreSQL wire)  → XDP_REDIRECT to AF_XDP socket (established + payload)
 *   TCP dst port 7432  (UWP default)      → XDP_REDIRECT to AF_XDP socket (established + payload)
 *   TCP dst port 6379  (RESP / Redis)     → XDP_REDIRECT to AF_XDP socket (established + payload)
 *   UDP dst port 16379 (Cluster Bus)      → XDP_REDIRECT to AF_XDP socket
 *   TCP payload bytes 0-3 == 0x51,49,48,53 → XDP_REDIRECT ONLY if qihse_magic_enabled[0] == 1
 *   Rate limit exceeded                   → XDP_DROP (100 redirects/sec per src IP)
 *   Redirect map lookup failure           → XDP_DROP (prevent double-processing)
 *   Packet too short to parse headers     → XDP_DROP (malformed, DDoS mitigation)
 *   TCP handshake / teardown / pure ACK   → XDP_PASS (kernel TCP/IP stack)
 *   Anything else                         → XDP_PASS (kernel TCP/IP stack)
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

/*
 * qihse_magic_enabled: opt-in flag for magic-on-any-port payload matching.
 * Key 0: 0 = disabled (default), 1 = enabled (cluster gossip mode).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} qihse_magic_enabled SEC(".maps");

/*
 * qihse_redirect_rl: per-source-IP token bucket rate limiter.
 * Allow at most 100 redirects per second per source IP.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32); /* src ip */
    __type(value, __u64); /* last_allowed_ns */
    __uint(max_entries, 10000);
} qihse_redirect_rl SEC(".maps");

/*
 * qihse_xdp_stats: drop and redirect statistics.
 * Index 0 = redirect_ok
 * Index 1 = redirect_fail_drop
 * Index 2 = rate_limited_drop
 * Index 3 = short_drop
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} qihse_xdp_stats SEC(".maps");

/* ── Constants ───────────────────────────────────────────────────────────── */

#define QIHSE_DEFAULT_PG_PORT    5432
#define QIHSE_DEFAULT_UWP_PORT   7432
#define QIHSE_DEFAULT_RESP_PORT  6379
#define QIHSE_DEFAULT_BUS_PORT   16379

/* Minimum packet size: Ethernet (14) + IPv4 (20) + UDP (8) = 42 bytes */
#define QIHSE_MIN_PKT_LEN 42

/* UWP magic: 0x51, 0x49, 0x48, 0x53. */
#define UWP_MAGIC_0 0x51
#define UWP_MAGIC_1 0x49
#define UWP_MAGIC_2 0x48
#define UWP_MAGIC_3 0x53

/* Rate limit: 100 redirects / sec -> 10ms (10,000,000 ns) per token */
#define QIHSE_RL_INTERVAL_NS 10000000ULL

/* Stats map indices */
#define STATS_REDIRECT_OK        0
#define STATS_REDIRECT_FAIL_DROP 1
#define STATS_RATE_LIMITED_DROP  2
#define STATS_SHORT_DROP         3

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&qihse_xdp_stats, &idx);
    if (val) {
        *val += 1;
    }
}

static __always_inline __u32 get_port(__u32 idx, __u32 fallback) {
    __u32 *val = bpf_map_lookup_elem(&qihse_ports, &idx);
    return (val && *val) ? *val : fallback;
}

static __always_inline int is_magic_enabled(void) {
    __u32 key = 0;
    __u8 *val = bpf_map_lookup_elem(&qihse_magic_enabled, &key);
    return (val && *val == 1) ? 1 : 0;
}

static __always_inline int check_rate_limit(__u32 src_ip) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ns = bpf_map_lookup_elem(&qihse_redirect_rl, &src_ip);
    if (last_ns) {
        if (now >= *last_ns && (now - *last_ns) < QIHSE_RL_INTERVAL_NS) {
            return 0; /* Rate limit exceeded */
        }
    }
    bpf_map_update_elem(&qihse_redirect_rl, &src_ip, &now, BPF_ANY);
    return 1; /* Allowed */
}

static __always_inline int redirect_to_xsk(struct xdp_md *ctx) {
    __u32 queue_idx = ctx->rx_queue_index;
    long ret = bpf_redirect_map(&xsks_map, queue_idx, XDP_DROP);
    if (ret == XDP_REDIRECT) {
        inc_stat(STATS_REDIRECT_OK);
        return XDP_REDIRECT;
    }
    inc_stat(STATS_REDIRECT_FAIL_DROP);
    return XDP_DROP;
}

/* ── XDP program ─────────────────────────────────────────────────────────── */

SEC("xdp")
int qihse_xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* Drop anything too short to contain valid headers */
    if (data + QIHSE_MIN_PKT_LEN > data_end) {
        inc_stat(STATS_SHORT_DROP);
        return XDP_DROP;
    }

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STATS_SHORT_DROP);
        return XDP_DROP;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS; /* Not IPv4 — let kernel handle */

    /* Parse IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_stat(STATS_SHORT_DROP);
        return XDP_DROP;
    }

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || (void *)ip + ip_hdr_len > data_end) {
        inc_stat(STATS_SHORT_DROP);
        return XDP_DROP;
    }

    /* Retrieve configured ports */
    __u32 pg_port   = get_port(0, QIHSE_DEFAULT_PG_PORT);
    __u32 uwp_port  = get_port(1, QIHSE_DEFAULT_UWP_PORT);
    __u32 resp_port = get_port(2, QIHSE_DEFAULT_RESP_PORT);
    __u32 bus_port  = get_port(3, QIHSE_DEFAULT_BUS_PORT);

    /* 1. Handle TCP traffic (PG, UWP, RESP) */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end) {
            inc_stat(STATS_SHORT_DROP);
            return XDP_DROP;
        }

        /*
         * Require established TCP state: ACK=1, SYN=0, FIN=0, RST=0.
         * SYN/FIN/RST segments get XDP_PASS so the kernel TCP stack handles
         * connection lifecycle (handshake, teardown, resets).
         */
        if (!(tcp->ack == 1 && tcp->syn == 0 && tcp->fin == 0 && tcp->rst == 0))
            return XDP_PASS;

        __u32 tcp_hdr_len = tcp->doff * 4;
        if (tcp_hdr_len < 20 || (void *)tcp + tcp_hdr_len > data_end) {
            inc_stat(STATS_SHORT_DROP);
            return XDP_DROP;
        }

        __u8 *payload = (void *)tcp + tcp_hdr_len;

        /* Only redirect if there is non-zero payload (payload < data_end) */
        if ((void *)payload >= data_end)
            return XDP_PASS;

        __u16 dst_port = bpf_ntohs(tcp->dest);
        int is_qihse_port = (dst_port == pg_port || dst_port == uwp_port || dst_port == resp_port);

        int has_qihse_magic = 0;
        /* Only check payload magic if opt-in map qihse_magic_enabled[0] == 1 */
        if (is_magic_enabled()) {
            if ((void *)(payload + 4) <= data_end) {
                has_qihse_magic = (payload[0] == UWP_MAGIC_0 &&
                                   payload[1] == UWP_MAGIC_1 &&
                                   payload[2] == UWP_MAGIC_2 &&
                                   payload[3] == UWP_MAGIC_3);
            }
        }

        if (is_qihse_port || has_qihse_magic) {
            /* Per-source-IP rate limiter (100 pkts/sec) */
            if (!check_rate_limit(ip->saddr)) {
                inc_stat(STATS_RATE_LIMITED_DROP);
                return XDP_DROP;
            }
            return redirect_to_xsk(ctx);
        }
    }

    /* 2. Handle UDP traffic (Cluster Bus Gossip) */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end) {
            inc_stat(STATS_SHORT_DROP);
            return XDP_DROP;
        }

        __u16 dst_port = bpf_ntohs(udp->dest);
        if (dst_port == bus_port) {
            /* Per-source-IP rate limiter (100 pkts/sec) */
            if (!check_rate_limit(ip->saddr)) {
                inc_stat(STATS_RATE_LIMITED_DROP);
                return XDP_DROP;
            }
            return redirect_to_xsk(ctx);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
