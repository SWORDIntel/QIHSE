#include "qihse_platform.h"
#include "qihse_af_xdp.h"

#ifndef _WIN32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <linux/if_link.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048

struct qihse_af_xdp_ctx {
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons comp_ring;
    struct xsk_ring_prod tx_ring;
    struct xsk_ring_cons rx_ring;
    void *buffer;
    struct xdp_program *prog;
};

struct qihse_af_xdp_ctx *qihse_af_xdp_init(const char *ifname) {
    if (!ifname || strlen(ifname) == 0) return NULL;
    struct qihse_af_xdp_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    /* 1. Load XDP program */
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        free(ctx);
        return NULL;
    }

    const char *xdp_obj = getenv("QIHSE_XDP_OBJ");
    if (xdp_obj) {
        if (strstr(xdp_obj, "..") != NULL) {
            fprintf(stderr, "[QIHSE] Rejected QIHSE_XDP_OBJ containing path traversal: %s\n", xdp_obj);
            xdp_obj = NULL;
        }
    }
    if (!xdp_obj) xdp_obj = "/usr/local/lib/qihse/qihse_xdp.o";
    ctx->prog = xdp_program__open_file(xdp_obj, "xdp", NULL);
    if (!ctx->prog || libxdp_get_error(ctx->prog)) {
        // Non-fatal if XDP object file is not installed on system; allow graceful fallback
        free(ctx);
        return NULL;
    }

    if (xdp_program__attach(ctx->prog, ifindex, XDP_MODE_SKB, 0)) {
        xdp_program__close(ctx->prog);
        free(ctx);
        return NULL;
    }

    /* 2. Setup UMEM */
    if (posix_memalign(&ctx->buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        goto cleanup;
    }

    struct xsk_umem_config umem_cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    if (xsk_umem__create(&ctx->umem, ctx->buffer, NUM_FRAMES * FRAME_SIZE, 
                         &ctx->fill_ring, &ctx->comp_ring, &umem_cfg)) {
        goto cleanup;
    }

    /* 3. Setup AF_XDP socket */
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = 0,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_USE_NEED_WAKEUP,
    };

    if (xsk_socket__create(&ctx->xsk, ifname, 0, ctx->umem,
                           &ctx->rx_ring, &ctx->tx_ring, &xsk_cfg)) {
        xsk_umem__delete(ctx->umem);
        goto cleanup;
    }

    /* Populate fill ring */
    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&ctx->fill_ring, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx) ==
        XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
            *xsk_ring_prod__fill_addr(&ctx->fill_ring, idx++) = i * FRAME_SIZE;
        }
        xsk_ring_prod__submit(&ctx->fill_ring, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    }

    /* Register AF_XDP socket in the kernel XSKMAP so XDP_REDIRECT works */
    struct bpf_object *bpf_obj = xdp_program__bpf_obj(ctx->prog);
    struct bpf_map *xsk_map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    if (xsk_map) {
        int xsk_map_fd = bpf_map__fd(xsk_map);
        int sock_fd    = xsk_socket__fd(ctx->xsk);
        uint32_t key   = 0; /* queue index 0 */
        bpf_map_update_elem(xsk_map_fd, &key, &sock_fd, BPF_ANY);
    }

    return ctx;

cleanup:
    if (ctx->buffer) free(ctx->buffer);
    xdp_program__detach(ctx->prog, ifindex, XDP_MODE_SKB, 0);
    xdp_program__close(ctx->prog);
    free(ctx);
    return NULL;
}

void qihse_af_xdp_teardown(struct qihse_af_xdp_ctx *ctx, const char *ifname) {
    if (!ctx) return;
    int ifindex = ifname ? if_nametoindex(ifname) : 0;
    if (ctx->xsk) xsk_socket__delete(ctx->xsk);
    if (ctx->umem) xsk_umem__delete(ctx->umem);
    if (ctx->buffer) free(ctx->buffer);
    if (ctx->prog && ifindex) xdp_program__detach(ctx->prog, ifindex, XDP_MODE_SKB, 0);
    if (ctx->prog) xdp_program__close(ctx->prog);
    free(ctx);
}

int qihse_af_xdp_get_fd(struct qihse_af_xdp_ctx *ctx) {
    if (!ctx || !ctx->xsk) return -1;
    return xsk_socket__fd(ctx->xsk);
}

void qihse_af_xdp_set_port(struct qihse_af_xdp_ctx *ctx, uint32_t idx, uint32_t port) {
    if (!ctx || !ctx->prog) return;
    struct bpf_object *bpf_obj = xdp_program__bpf_obj(ctx->prog);
    if (!bpf_obj) return;
    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "qihse_ports");
    if (!map) return;
    int fd = bpf_map__fd(map);
    bpf_map_update_elem(fd, &idx, &port, BPF_ANY);
}

bool qihse_af_xdp_send(struct qihse_af_xdp_ctx *ctx, const void *pkt, uint32_t len) {
    if (!ctx || !ctx->xsk || !pkt || len == 0 || len > FRAME_SIZE) return false;

    uint32_t idx_tx = 0;
    if (xsk_ring_prod__reserve(&ctx->tx_ring, 1, &idx_tx) != 1) {
        return false;
    }

    struct xdp_desc *desc = xsk_ring_prod__tx_desc(&ctx->tx_ring, idx_tx);
    uint64_t addr = (uint64_t)idx_tx * FRAME_SIZE;
    char *dest = xsk_umem__get_data(ctx->buffer, addr);
    memcpy(dest, pkt, len);

    desc->addr = addr;
    desc->len = len;

    xsk_ring_prod__submit(&ctx->tx_ring, 1);
    sendto(xsk_socket__fd(ctx->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    return true;
}

void qihse_af_xdp_poll(struct qihse_af_xdp_ctx *ctx, qihse_af_xdp_cb_t cb, void *arg) {
    if (!ctx || !ctx->xsk) return;
    
    uint32_t idx_rx = 0;
    unsigned int rcvd = xsk_ring_cons__peek(&ctx->rx_ring, 64, &idx_rx);
    if (!rcvd) return;

    uint32_t idx_fq = 0;
    unsigned int ret = xsk_ring_prod__reserve(&ctx->fill_ring, rcvd, &idx_fq);
    if (ret < rcvd) {
        xsk_ring_cons__release(&ctx->rx_ring, rcvd);
        return;
    }

    for (unsigned int i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&ctx->rx_ring, idx_rx++);
        uint64_t addr = desc->addr;
        uint32_t len = desc->len;
        
        if (cb) {
            char *pkt = xsk_umem__get_data(ctx->buffer, addr);
            cb(pkt, len, arg);
        }
        
        *xsk_ring_prod__fill_addr(&ctx->fill_ring, idx_fq++) = addr;
    }

    xsk_ring_prod__submit(&ctx->fill_ring, rcvd);
    xsk_ring_cons__release(&ctx->rx_ring, rcvd);
}

bool qihse_af_xdp_extract_tcp_payload(
    const void *raw_pkt, uint32_t raw_len,
    const char **out_payload, uint32_t *out_payload_len,
    uint32_t *out_src_ip, uint16_t *out_src_port, uint16_t *out_dst_port) {
    if (!raw_pkt || raw_len < 54) return false;

    const uint8_t *p = (const uint8_t *)raw_pkt;
    const struct ether_header *eth = (const struct ether_header *)p;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return false;

    const struct ip *iph = (const struct ip *)(p + sizeof(struct ether_header));
    uint32_t ip_hl = (uint32_t)iph->ip_hl * 4;
    if (ip_hl < 20 || sizeof(struct ether_header) + ip_hl > raw_len) return false;
    if (iph->ip_p != IPPROTO_TCP) return false;

    const struct tcphdr *tcph = (const struct tcphdr *)(p + sizeof(struct ether_header) + ip_hl);
    uint32_t tcp_hl = (uint32_t)tcph->doff * 4;
    uint32_t hdr_total = sizeof(struct ether_header) + ip_hl + tcp_hl;
    if (tcp_hl < 20 || hdr_total > raw_len) return false;

    if (out_src_ip) *out_src_ip = ntohl(iph->ip_src.s_addr);
    if (out_src_port) *out_src_port = ntohs(tcph->source);
    if (out_dst_port) *out_dst_port = ntohs(tcph->dest);

    if (out_payload) *out_payload = (const char *)(p + hdr_total);
    if (out_payload_len) *out_payload_len = raw_len - hdr_total;

    return true;
}

bool qihse_af_xdp_extract_udp_payload(
    const void *raw_pkt, uint32_t raw_len,
    const void **out_payload, uint32_t *out_payload_len,
    uint32_t *out_src_ip, uint16_t *out_src_port, uint16_t *out_dst_port) {
    if (!raw_pkt || raw_len < 42) return false;

    const uint8_t *p = (const uint8_t *)raw_pkt;
    const struct ether_header *eth = (const struct ether_header *)p;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return false;

    const struct ip *iph = (const struct ip *)(p + sizeof(struct ether_header));
    uint32_t ip_hl = (uint32_t)iph->ip_hl * 4;
    if (ip_hl < 20 || sizeof(struct ether_header) + ip_hl > raw_len) return false;
    if (iph->ip_p != IPPROTO_UDP) return false;

    const struct udphdr *udph = (const struct udphdr *)(p + sizeof(struct ether_header) + ip_hl);
    uint32_t hdr_total = sizeof(struct ether_header) + ip_hl + sizeof(struct udphdr);
    if (hdr_total > raw_len) return false;

    if (out_src_ip) *out_src_ip = ntohl(iph->ip_src.s_addr);
    if (out_src_port) *out_src_port = ntohs(udph->source);
    if (out_dst_port) *out_dst_port = ntohs(udph->dest);

    if (out_payload) *out_payload = (const void *)(p + hdr_total);
    if (out_payload_len) *out_payload_len = raw_len - hdr_total;

    return true;
}

#endif /* _WIN32 */
