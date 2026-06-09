#include "qihse_platform.h"
#include "qihse_af_xdp.h"

#ifndef _WIN32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <net/if.h>
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
    struct qihse_af_xdp_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    /* 1. Load XDP program */
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        free(ctx);
        return NULL;
    }

    ctx->prog = xdp_program__open_file("src/networking/qihse_xdp.o", "xdp", NULL);
    if (libxdp_get_error(ctx->prog)) {
        fprintf(stderr, "Failed to open XDP program\n");
        free(ctx);
        return NULL;
    }

    if (xdp_program__attach(ctx->prog, ifindex, XDP_MODE_SKB, 0)) {
        fprintf(stderr, "Failed to attach XDP program\n");
        xdp_program__close(ctx->prog);
        free(ctx);
        return NULL;
    }

    /* 2. Setup UMEM */
    if (posix_memalign(&ctx->buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        fprintf(stderr, "Failed to allocate buffer\n");
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
        fprintf(stderr, "Failed to create UMEM\n");
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
        fprintf(stderr, "Failed to create AF_XDP socket\n");
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

    printf("[QIHSE eBPF] XDP Program attached to %s. AF_XDP socket bound.\n", ifname);
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
    int ifindex = if_nametoindex(ifname);
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

void qihse_af_xdp_poll(struct qihse_af_xdp_ctx *ctx, qihse_af_xdp_cb_t cb, void *arg) {
    if (!ctx || !ctx->xsk) return;
    
    uint32_t idx_rx = 0;
    unsigned int rcvd = xsk_ring_cons__peek(&ctx->rx_ring, 64, &idx_rx);
    if (!rcvd) return;

    uint32_t idx_fq = 0;
    unsigned int ret = xsk_ring_prod__reserve(&ctx->fill_ring, rcvd, &idx_fq);
    if (ret < rcvd) {
        // Drop logic if fill queue is full
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
#endif

