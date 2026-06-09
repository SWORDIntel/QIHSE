#ifndef QIHSE_AF_XDP_H
#define QIHSE_AF_XDP_H

#include "qihse_platform.h"

#ifndef _WIN32
struct qihse_af_xdp_ctx;

struct qihse_af_xdp_ctx *qihse_af_xdp_init(const char *ifname);
void qihse_af_xdp_teardown(struct qihse_af_xdp_ctx *ctx, const char *ifname);
int qihse_af_xdp_get_fd(struct qihse_af_xdp_ctx *ctx);

typedef void (*qihse_af_xdp_cb_t)(char *pkt, uint32_t len, void *arg);
void qihse_af_xdp_poll(struct qihse_af_xdp_ctx *ctx, qihse_af_xdp_cb_t cb, void *arg);
#endif

#endif // QIHSE_AF_XDP_H
