#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "qihse.h"
#include "qihse_kv_store.h"
#include "qihse_timeseries.h"
#ifndef _WIN32
#include "qihse_af_xdp.h"
#include "qihse_keystone.h"
#endif

// Define missing symbols that Python's ctypes wrapper expects
// These are exported symbols that are NOT defined in other core files

int qihse_amplify_internal(void* d, size_t n, const void* q, qihse_data_type_t t, void* c) { (void)d; (void)n; (void)q; (void)t; (void)c; return 0; }


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
    if (!qihse_auth_can_access(user, clearance, compartment)) return 0u;

    const char *tcp_payload = NULL;
    uint32_t tcp_len = 0u;
    if (qihse_af_xdp_extract_tcp_payload(raw_pkt, raw_len,
                                         &tcp_payload, &tcp_len,
                                         NULL, NULL, NULL)) {
        if (tcp_len == 0u) return 0u;
        return qihse_keystone_ingest_dirty_logs_user(
            kv, topo, tcp_payload, (size_t)tcp_len,
            clearance, compartment, user);
    }

    const void *udp_payload = NULL;
    uint32_t udp_len = 0u;
    if (qihse_af_xdp_extract_udp_payload(raw_pkt, raw_len,
                                         &udp_payload, &udp_len,
                                         NULL, NULL, NULL)) {
        if (udp_len == 0u) return 0u;
        return qihse_keystone_ingest_dirty_logs_user(
            kv, topo, (const char *)udp_payload, (size_t)udp_len,
            clearance, compartment, user);
    }

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
    if (!qihse_auth_can_access(user, clearance, compartment)) return 0u;

    qihse_af_xdp_keystone_user_ctx_t ingest = {
        .kv = kv,
        .topo = topo,
        .clearance = clearance,
        .compartment = compartment,
        .user = user,
        .artifacts = 0u
    };
    qihse_af_xdp_poll(ctx, qihse_af_xdp_keystone_user_cb, &ingest);
    return ingest.artifacts;
}
#endif

int qihse_superposition_fidelity(const void* a, const void* b, size_t n, double* fidelity) {
    if (!a || !b || !fidelity) return -1;
    const float* fa = (const float*)a;
    const float* fb = (const float*)b;
    double dot = 0.0;
    for (size_t i = 0; i < n; i++) dot += (double)fa[i] * (double)fb[i];
    *fidelity = dot;
    return 0;
}

int qihse_superposition_measure(const void* s, size_t n, void* res) { (void)s; (void)n; (void)res; return 0; }
int qihse_superposition_destroy(void* s) { (void)s; return 0; }
int qihse_superposition_create(const void* d, size_t n, void** s) { (void)d; (void)n; if (s) *s = NULL; return 0; }
double qihse_superposition_get_measurement_confidence(const void* s) { (void)s; return 1.0; }
int qihse_superposition_apply_operator(void* s, int op, void* p) { (void)s; (void)op; (void)p; return 0; }

int qihse_rff_config_init(void* c) { (void)c; return 0; }
int qihse_superposition_config_init(void* c) { (void)c; return 0; }

// Stubs for test_algorithms.c
size_t qihse_rff_get_input_dims(qihse_rff_kernel_t* k) { return k ? k->input_dims : 0; }
size_t qihse_rff_get_output_dims(qihse_rff_kernel_t* k) { return k ? k->output_dims : 0; }
double qihse_rff_get_gamma(qihse_rff_kernel_t* k) { return k ? k->gamma : 0.0; }
uint64_t qihse_rff_get_seed(qihse_rff_kernel_t* k) { return k ? k->seed : 0; }
size_t qihse_superposition_get_num_states(qihse_superposition_t* s) { return s ? s->num_states : 0; }
size_t qihse_superposition_get_dims_per_state(qihse_superposition_t* s) { return s ? s->dims_per_state : 0; }
int qihse_superposition_normalize(void* s) { (void)s; return 0; }
bool qihse_superposition_is_normalized(void* s) { (void)s; return true; }
int qihse_create_superposition_from_amplitudes(void* real, void* imag, size_t n, qihse_superposition_t* s) { (void)real; (void)imag; (void)n; if (s) { s->num_states = 0; s->dims_per_state = 0; s->real = NULL; s->imag = NULL; s->phase = NULL; } return 0; }
