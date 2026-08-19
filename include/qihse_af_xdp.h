#ifndef QIHSE_AF_XDP_H
#define QIHSE_AF_XDP_H

#include "qihse_platform.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef _WIN32
struct qihse_af_xdp_ctx;

struct qihse_af_xdp_ctx *qihse_af_xdp_init(const char *ifname);
void qihse_af_xdp_teardown(struct qihse_af_xdp_ctx *ctx, const char *ifname);
int qihse_af_xdp_get_fd(struct qihse_af_xdp_ctx *ctx);

/* Port index definitions */
#define QIHSE_XDP_PORT_PG    0
#define QIHSE_XDP_PORT_UWP   1
#define QIHSE_XDP_PORT_RESP  2
#define QIHSE_XDP_PORT_BUS   3

void qihse_af_xdp_set_port(struct qihse_af_xdp_ctx *ctx, uint32_t idx, uint32_t port);
bool qihse_af_xdp_send(struct qihse_af_xdp_ctx *ctx, const void *pkt, uint32_t len);

typedef void (*qihse_af_xdp_cb_t)(char *pkt, uint32_t len, void *arg);
void qihse_af_xdp_poll(struct qihse_af_xdp_ctx *ctx, qihse_af_xdp_cb_t cb, void *arg);

/**
 * @brief Zero-copy parser extracting TCP payload and endpoints from a raw Ethernet frame.
 */
bool qihse_af_xdp_extract_tcp_payload(
    const void *raw_pkt, uint32_t raw_len,
    const char **out_payload, uint32_t *out_payload_len,
    uint32_t *out_src_ip, uint16_t *out_src_port, uint16_t *out_dst_port);

/**
 * @brief Zero-copy parser extracting UDP payload and endpoints from a raw Ethernet frame.
 */
bool qihse_af_xdp_extract_udp_payload(
    const void *raw_pkt, uint32_t raw_len,
    const void **out_payload, uint32_t *out_payload_len,
    uint32_t *out_src_ip, uint16_t *out_src_port, uint16_t *out_dst_port);

#endif /* _WIN32 */

#endif /* QIHSE_AF_XDP_H */
