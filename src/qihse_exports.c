#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include "qihse.h"
#include "qihse_kv_store.h"
#include "qihse_timeseries.h"
#ifndef _WIN32
#include "qihse_af_xdp.h"
#include "qihse_keystone.h"
#endif

// Define missing symbols that Python's ctypes wrapper expects
// These are exported symbols that are NOT defined in other core files

int qihse_amplify_internal(void* d, size_t n, const void* q, qihse_data_type_t t, void* c) { (void)d; (void)n; (void)q; (void)t; (void)c; errno = ENOTSUP; return -1; }


double qihse_tsdb_average_range(qihse_tsdb_t* tsdb, uint64_t start_ts, uint64_t end_ts, qihse_user_t* user) {
    return qihse_tsdb_average_range_user(tsdb, start_ts, end_ts, user);
}

#ifndef _WIN32
/*
 * Principal-aware AF_XDP -> Keystone adapters.
 *
 * These deliberately live above the raw AF_XDP transport.  The legacy
 * context-free AF_XDP functions remain ABI-compatible but, because Keystone's
 * context-free ingest entry point is unclassified-only, cannot ingest
 * classified/SCI data.  Callers that need classified zero-copy ingestion must
 * use these *_user functions and supply an authenticated QIHSE principal.
 */
size_t qihse_af_xdp_ingest_frame_zero_copy_user(
    const void *raw_pkt, uint32_t raw_len,
    qihse_kv_store_t *kv,
    qihse_cluster_topology_t *topo,
    uint16_t clearance,
    uint16_t compartment,
    qihse_user_t *user)
{
    if (!raw_pkt || raw_len == 0u || !kv) return 0u;
    if (!qihse_auth_can_access(user, clearance, compartment)) {
        /* W5.2: a refusal is a security event, so it is counted separately
         * from a malformed frame. */
        qihse_af_xdp_stats_record_denied(1u);
        return 0u;
    }

    const char *tcp_payload = NULL;
    uint32_t tcp_len = 0u;
    if (qihse_af_xdp_extract_tcp_payload(raw_pkt, raw_len,
                                         &tcp_payload, &tcp_len,
                                         NULL, NULL, NULL)) {
        if (tcp_len == 0u) {
            qihse_af_xdp_stats_record_dropped(1u);
            return 0u;
        }
        size_t added = qihse_keystone_ingest_dirty_logs_user(
            kv, topo, tcp_payload, (size_t)tcp_len,
            clearance, compartment, user);
        if (added > 0u) {
            qihse_af_xdp_stats_record_ingested(added);
        } else {
            qihse_af_xdp_stats_record_dropped(1u);
        }
        return added;
    }

    const void *udp_payload = NULL;
    uint32_t udp_len = 0u;
    if (qihse_af_xdp_extract_udp_payload(raw_pkt, raw_len,
                                         &udp_payload, &udp_len,
                                         NULL, NULL, NULL)) {
        if (udp_len == 0u) {
            qihse_af_xdp_stats_record_dropped(1u);
            return 0u;
        }
        size_t added = qihse_keystone_ingest_dirty_logs_user(
            kv, topo, (const char *)udp_payload, (size_t)udp_len,
            clearance, compartment, user);
        if (added > 0u) {
            qihse_af_xdp_stats_record_ingested(added);
        } else {
            qihse_af_xdp_stats_record_dropped(1u);
        }
        return added;
    }

    qihse_af_xdp_stats_record_dropped(1u);
    return 0u;
}

typedef struct {
    qihse_kv_store_t *kv;
    qihse_cluster_topology_t *topo;
    uint16_t clearance;
    uint16_t compartment;
    qihse_user_t *user;
    size_t artifacts;
} qihse_af_xdp_keystone_user_ctx_t;

static void qihse_af_xdp_keystone_user_cb(char *pkt, uint32_t len, void *arg)
{
    qihse_af_xdp_keystone_user_ctx_t *ctx =
        (qihse_af_xdp_keystone_user_ctx_t *)arg;
    if (!ctx || !pkt || len == 0u) return;
    size_t added = qihse_af_xdp_ingest_frame_zero_copy_user(
        pkt, len, ctx->kv, ctx->topo,
        ctx->clearance, ctx->compartment, ctx->user);
    if (SIZE_MAX - ctx->artifacts < added) {
        ctx->artifacts = SIZE_MAX;
    } else {
        ctx->artifacts += added;
    }
}

size_t qihse_af_xdp_ingest_keystone_user(
    struct qihse_af_xdp_ctx *ctx,
    qihse_kv_store_t *kv,
    qihse_cluster_topology_t *topo,
    uint16_t clearance,
    uint16_t compartment,
    qihse_user_t *user)
{
    if (!ctx || !kv) return 0u;
    if (!qihse_auth_can_access(user, clearance, compartment)) {
        qihse_af_xdp_stats_record_denied(1u);
        return 0u;
    }

    qihse_af_xdp_keystone_user_ctx_t ingest = {
        .kv = kv,
        .topo = topo,
        .clearance = clearance,
        .compartment = compartment,
        .user = user,
        .artifacts = 0u
    };
    qihse_af_xdp_poll(ctx, qihse_af_xdp_keystone_user_cb, &ingest);
    /* The per-frame adapter already counted each frame's artifacts, so the
     * ring total is deliberately not counted a second time here. */
    return ingest.artifacts;
}
#endif

/* Preserve the legacy four-argument raw-float ABI. Typed complex states use
 * qihse_superposition_state_fidelity instead. */
int qihse_superposition_fidelity(const void* a, const void* b, size_t n, double* fidelity) {
    if (fidelity) *fidelity = 0.0;
    if (!a || !b || !n || !fidelity || n > SIZE_MAX / sizeof(float)) { errno = EINVAL; return -1; }
    const float* fa = a;
    const float* fb = b;
    long double dot = 0.0L, an = 0.0L, bn = 0.0L;
    for (size_t i = 0; i < n; ++i) {
        if (!isfinite(fa[i]) || !isfinite(fb[i])) { errno = EDOM; return -1; }
        dot += (long double)fa[i] * fb[i];
        an += (long double)fa[i] * fa[i];
        bn += (long double)fb[i] * fb[i];
    }
    if (!(an > 0.0L) || !(bn > 0.0L)) { errno = EDOM; return -1; }
    *fidelity = (double)fminl(1.0L, (dot / an) * (dot / bn));
    return 0;
}

/* These historical untyped interfaces never had an implemented data/operator
 * contract. Keep their symbols, but do not report an operation that did not run. */
int qihse_superposition_destroy(void* s) { (void)s; errno = ENOTSUP; return -1; }
int qihse_superposition_create(const void* d, size_t n, void** s) {
    (void)d; (void)n; if (s) *s = NULL; errno = ENOTSUP; return -1;
}
int qihse_superposition_apply_operator(void* s, int op, void* p) {
    (void)s; (void)op; (void)p; errno = ENOTSUP; return -1;
}
int qihse_rff_config_init(void* c) { (void)c; errno = ENOTSUP; return -1; }
int qihse_superposition_config_init(void* c) { (void)c; errno = ENOTSUP; return -1; }

size_t qihse_rff_get_input_dims(const qihse_rff_kernel_t* k) { return k ? k->input_dims : 0; }
size_t qihse_rff_get_output_dims(const qihse_rff_kernel_t* k) { return k ? k->output_dims : 0; }
double qihse_rff_get_gamma(const qihse_rff_kernel_t* k) { return k ? k->gamma : 0.0; }
uint64_t qihse_rff_get_seed(const qihse_rff_kernel_t* k) { return k ? k->seed : 0; }
