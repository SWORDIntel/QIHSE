#ifndef QIHSE_AF_XDP_H
#define QIHSE_AF_XDP_H

#include "qihse_platform.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_kv_store.h"
#include "qihse_cluster_slot.h"
#include "qihse_keystone.h"

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

/**
 * @brief Zero-copy ingestion of a single raw Ethernet frame directly into the
 *        Keystone dirty-log pipeline.
 *
 * The TCP/UDP payload pointer returned by the zero-copy parsers stays inside the
 * caller's buffer (e.g. the AF_XDP UMEM region) -- no userspace copy is performed.
 * The payload is handed directly to qihse_keystone_ingest_dirty_logs(), which
 * scans it in place and routes extracted artifacts across the 16,384 CRC16
 * cluster hash slots.
 *
 * @param raw_pkt   Pointer to the raw Ethernet frame (may live inside a UMEM frame).
 * @param raw_len   Length of the raw frame in bytes.
 * @param kv        Black Hole KV store handle that will receive the artifacts.
 * @param topo      Optional cluster topology for sharding (may be NULL).
 * @param clearance Default SCI clearance level stamped on ingested records.
 * @param compartment Default SCI compartment mask stamped on ingested records.
 * @return Number of artifacts extracted and indexed from this frame.
 */
size_t qihse_af_xdp_ingest_frame_zero_copy(
    const void *raw_pkt, uint32_t raw_len,
    qihse_kv_store_t *kv,
    qihse_cluster_topology_t *topo,
    uint16_t clearance,
    uint16_t compartment);

/**
 * @brief Polls the AF_XDP RX ring and ingests every received UMEM frame directly
 *        into the Keystone dirty-log pipeline with zero userspace copies.
 *
 * For each received descriptor the on-UMEM payload pointer is extracted by the
 * zero-copy TCP/UDP parsers and forwarded in place to
 * qihse_keystone_ingest_dirty_logs(). Extracted artifacts are distributed across
 * the 16,384 CRC16 cluster hash slots. After ingestion the UMEM frame is
 * recycled back onto the fill ring for immediate reuse by the kernel.
 *
 * @param ctx         AF_XDP context returned by qihse_af_xdp_init().
 * @param kv          Black Hole KV store handle that will receive the artifacts.
 * @param topo        Optional cluster topology for sharding (may be NULL).
 * @param clearance   Default SCI clearance level stamped on ingested records.
 * @param compartment Default SCI compartment mask stamped on ingested records.
 * @return Total number of artifacts extracted and indexed across all polled frames.
 */
size_t qihse_af_xdp_ingest_keystone(struct qihse_af_xdp_ctx *ctx,
                                    qihse_kv_store_t *kv,
                                    qihse_cluster_topology_t *topo,
                                    uint16_t clearance,
                                    uint16_t compartment);

#endif /* _WIN32 */

#endif /* QIHSE_AF_XDP_H */
