#ifndef QIHSE_UWP_METRICS_H
#define QIHSE_UWP_METRICS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_uwp_metrics {
    /* Connection counters */
    uint64_t connections_total;
    uint64_t connections_active;
    uint64_t connections_rejected;

    /* Frame counters */
    uint64_t frames_received;
    uint64_t frames_valid;
    uint64_t frames_invalid_magic;
    uint64_t frames_invalid_version;
    uint64_t frames_oversized;
    uint64_t frames_partial;

    /* Auth counters */
    uint64_t auth_attempts;
    uint64_t auth_successes;
    uint64_t auth_failures;
    uint64_t auth_rate_limited;

    /* Dispatch counters (per target) */
    uint64_t dispatch_ok[16];      /* indexed by target_engine 0x00-0x0F */
    uint64_t dispatch_error[16];

    /* TLS counters */
    uint64_t tls_connections;
    uint64_t tls_decrypt_failures;

    /* Rate limiting */
    uint64_t rate_limited_ips;
} qihse_uwp_metrics_t;

qihse_uwp_metrics_t* qihse_uwp_metrics_create(void);
void qihse_uwp_metrics_destroy(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_reset(qihse_uwp_metrics_t* m);

/* Atomic increment helpers (thread-safe via __atomic_fetch_add) */
void qihse_uwp_metrics_inc_connections_total(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_connections_active(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_dec_connections_active(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_connections_rejected(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_frames_received(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_frames_valid(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_frames_invalid_magic(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_frames_invalid_version(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_frames_oversized(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_frames_partial(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_auth_attempts(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_auth_successes(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_auth_failures(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_auth_rate_limited(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_dispatch_ok(qihse_uwp_metrics_t* m, uint8_t target);
void qihse_uwp_metrics_inc_dispatch_error(qihse_uwp_metrics_t* m, uint8_t target);
void qihse_uwp_metrics_inc_tls_connections(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_tls_decrypt_failures(qihse_uwp_metrics_t* m);
void qihse_uwp_metrics_inc_rate_limited_ips(qihse_uwp_metrics_t* m);

/* Snapshot to JSON string (caller frees) */
char* qihse_uwp_metrics_to_json(const qihse_uwp_metrics_t* m);

/* Snapshot to Prometheus text format (caller frees) */
char* qihse_uwp_metrics_to_prometheus(const qihse_uwp_metrics_t* m);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_UWP_METRICS_H */
