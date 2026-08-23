#include "qihse_uwp_metrics.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

qihse_uwp_metrics_t* qihse_uwp_metrics_create(void) {
    return (qihse_uwp_metrics_t*)calloc(1, sizeof(qihse_uwp_metrics_t));
}

void qihse_uwp_metrics_destroy(qihse_uwp_metrics_t* m) {
    if (!m) return;
    free(m);
}

void qihse_uwp_metrics_reset(qihse_uwp_metrics_t* m) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
}

void qihse_uwp_metrics_inc_connections_total(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->connections_total, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_connections_active(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->connections_active, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_dec_connections_active(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_sub(&m->connections_active, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_connections_rejected(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->connections_rejected, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_frames_received(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->frames_received, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_frames_valid(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->frames_valid, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_frames_invalid_magic(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->frames_invalid_magic, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_frames_invalid_version(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->frames_invalid_version, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_frames_oversized(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->frames_oversized, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_frames_partial(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->frames_partial, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_auth_attempts(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->auth_attempts, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_auth_successes(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->auth_successes, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_auth_failures(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->auth_failures, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_auth_rate_limited(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->auth_rate_limited, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_dispatch_ok(qihse_uwp_metrics_t* m, uint8_t target) {
    if (!m) return;
    if (target >= 16) return;
    __atomic_fetch_add(&m->dispatch_ok[target], 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_dispatch_error(qihse_uwp_metrics_t* m, uint8_t target) {
    if (!m) return;
    if (target >= 16) return;
    __atomic_fetch_add(&m->dispatch_error[target], 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_tls_connections(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->tls_connections, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_tls_decrypt_failures(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->tls_decrypt_failures, 1, __ATOMIC_RELAXED);
}

void qihse_uwp_metrics_inc_rate_limited_ips(qihse_uwp_metrics_t* m) {
    if (m) __atomic_fetch_add(&m->rate_limited_ips, 1, __ATOMIC_RELAXED);
}

char* qihse_uwp_metrics_to_json(const qihse_uwp_metrics_t* m) {
    if (!m) return NULL;

    /* Build a dynamic buffer for the JSON object. */
    size_t cap = 4096;
    char* buf = (char*)malloc(cap);
    if (!buf) return NULL;
    size_t len = 0;

#define APPEND(fmt, ...) do { \
        char _line[256]; \
        int _n = snprintf(_line, sizeof(_line), fmt, ##__VA_ARGS__); \
        if (_n < 0) break; \
        if (len + (size_t)_n + 1 > cap) { \
            cap = (len + (size_t)_n + 1) * 2; \
            char* _nb = (char*)realloc(buf, cap); \
            if (!_nb) { free(buf); return NULL; } \
            buf = _nb; \
        } \
        memcpy(buf + len, _line, (size_t)_n); \
        len += (size_t)_n; \
    } while (0)

    APPEND("{");
    APPEND("\"connections_total\":%llu,", (unsigned long long)m->connections_total);
    APPEND("\"connections_active\":%llu,", (unsigned long long)m->connections_active);
    APPEND("\"connections_rejected\":%llu,", (unsigned long long)m->connections_rejected);
    APPEND("\"frames_received\":%llu,", (unsigned long long)m->frames_received);
    APPEND("\"frames_valid\":%llu,", (unsigned long long)m->frames_valid);
    APPEND("\"frames_invalid_magic\":%llu,", (unsigned long long)m->frames_invalid_magic);
    APPEND("\"frames_invalid_version\":%llu,", (unsigned long long)m->frames_invalid_version);
    APPEND("\"frames_oversized\":%llu,", (unsigned long long)m->frames_oversized);
    APPEND("\"frames_partial\":%llu,", (unsigned long long)m->frames_partial);
    APPEND("\"auth_attempts\":%llu,", (unsigned long long)m->auth_attempts);
    APPEND("\"auth_successes\":%llu,", (unsigned long long)m->auth_successes);
    APPEND("\"auth_failures\":%llu,", (unsigned long long)m->auth_failures);
    APPEND("\"auth_rate_limited\":%llu,", (unsigned long long)m->auth_rate_limited);

    /* dispatch_ok array */
    APPEND("\"dispatch_ok\":[");
    for (int i = 0; i < 16; i++) {
        APPEND("%llu%s", (unsigned long long)m->dispatch_ok[i], (i < 15) ? "," : "");
    }
    APPEND("],");

    /* dispatch_error array */
    APPEND("\"dispatch_error\":[");
    for (int i = 0; i < 16; i++) {
        APPEND("%llu%s", (unsigned long long)m->dispatch_error[i], (i < 15) ? "," : "");
    }
    APPEND("],");

    APPEND("\"tls_connections\":%llu,", (unsigned long long)m->tls_connections);
    APPEND("\"tls_decrypt_failures\":%llu,", (unsigned long long)m->tls_decrypt_failures);
    APPEND("\"rate_limited_ips\":%llu", (unsigned long long)m->rate_limited_ips);
    APPEND("}");

#undef APPEND

    buf[len] = '\0';
    return buf;
}

char* qihse_uwp_metrics_to_prometheus(const qihse_uwp_metrics_t* m) {
    if (!m) return NULL;

    size_t cap = 8192;
    char* buf = (char*)malloc(cap);
    if (!buf) return NULL;
    size_t len = 0;

#define APPEND(fmt, ...) do { \
        char _line[512]; \
        int _n = snprintf(_line, sizeof(_line), fmt, ##__VA_ARGS__); \
        if (_n < 0) break; \
        if (len + (size_t)_n + 1 > cap) { \
            cap = (len + (size_t)_n + 1) * 2; \
            char* _nb = (char*)realloc(buf, cap); \
            if (!_nb) { free(buf); return NULL; } \
            buf = _nb; \
        } \
        memcpy(buf + len, _line, (size_t)_n); \
        len += (size_t)_n; \
    } while (0)

#define COUNTER(name, help, field) do { \
        APPEND("# HELP qihse_uwp_%s %s\n", name, help); \
        APPEND("# TYPE qihse_uwp_%s counter\n", name); \
        APPEND("qihse_uwp_%s %llu\n", name, (unsigned long long)m->field); \
    } while (0)

#define GAUGE(name, help, field) do { \
        APPEND("# HELP qihse_uwp_%s %s\n", name, help); \
        APPEND("# TYPE qihse_uwp_%s gauge\n", name); \
        APPEND("qihse_uwp_%s %llu\n", name, (unsigned long long)m->field); \
    } while (0)

    COUNTER("connections_total", "Total connections accepted", connections_total);
    GAUGE("connections_active", "Currently active connections", connections_active);
    COUNTER("connections_rejected", "Connections rejected", connections_rejected);
    COUNTER("frames_received", "Total frames received", frames_received);
    COUNTER("frames_valid", "Frames that passed validation", frames_valid);
    COUNTER("frames_invalid_magic", "Frames with invalid magic bytes", frames_invalid_magic);
    COUNTER("frames_invalid_version", "Frames with unsupported version", frames_invalid_version);
    COUNTER("frames_oversized", "Frames exceeding maximum payload", frames_oversized);
    COUNTER("frames_partial", "Incomplete/partial frames", frames_partial);
    COUNTER("auth_attempts", "Authentication attempts", auth_attempts);
    COUNTER("auth_successes", "Successful authentications", auth_successes);
    COUNTER("auth_failures", "Failed authentications", auth_failures);
    COUNTER("auth_rate_limited", "Auth attempts rejected by rate limiter", auth_rate_limited);
    COUNTER("tls_connections", "TLS connections established", tls_connections);
    COUNTER("tls_decrypt_failures", "TLS decryption failures", tls_decrypt_failures);
    COUNTER("rate_limited_ips", "IPs blocked by rate limiting", rate_limited_ips);

    /* Per-target dispatch counters with label */
    APPEND("# HELP qihse_uwp_dispatch_ok Total successful dispatches per target engine\n");
    APPEND("# TYPE qihse_uwp_dispatch_ok counter\n");
    for (int i = 0; i < 16; i++) {
        APPEND("qihse_uwp_dispatch_ok{target=\"%d\"} %llu\n",
               i, (unsigned long long)m->dispatch_ok[i]);
    }

    APPEND("# HELP qihse_uwp_dispatch_error Total dispatch errors per target engine\n");
    APPEND("# TYPE qihse_uwp_dispatch_error counter\n");
    for (int i = 0; i < 16; i++) {
        APPEND("qihse_uwp_dispatch_error{target=\"%d\"} %llu\n",
               i, (unsigned long long)m->dispatch_error[i]);
    }

#undef COUNTER
#undef GAUGE
#undef APPEND

    buf[len] = '\0';
    return buf;
}
