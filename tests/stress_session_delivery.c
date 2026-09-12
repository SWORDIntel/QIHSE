/* Session-delivery stress harness.
 *
 * Phase 1 (measured): create QIHSE_STRESS_TENANTS tenant principals (operator
 * minted) — this deliberately surfaces the serialized PBKDF2 verifier cost of
 * tenant onboarding.
 *
 * Phase 2: one thread per tenant performing continuous cycles until the time
 * budget expires. Each cycle: upload a random 1–5 MB blob, download it back
 * in 64 KiB range reads (BUNDLE.CHUNK semantics) with byte verification, three
 * random-slice reads, and one schema-valid telemetry KV write. Records
 * latency (µs), bytes, and errors; prints 30 s progress and a final report
 * with percentiles.
 *
 * Environment overrides:
 *   QIHSE_STRESS_TENANTS   (default 100)
 *   QIHSE_STRESS_SECONDS   (default 300)
 *   QIHSE_STRESS_MIN_MB    (default 1)
 *   QIHSE_STRESS_MAX_MB    (default 5)
 *   QIHSE_STRESS_CYCLE_MS  (default 30000; target period per tenant cycle)
 */
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_blob.h"
#include "qihse_kv_store.h"
#include "qihse_quota.h"
#include "qihse_pqc_crypto.h"

#define MAX_SAMPLES 8192u

typedef struct {
    uint32_t* samples;
    size_t count;
    uint64_t total_us;
    uint32_t max_us;
    uint64_t errors;
} op_stats_t;

static void op_record(op_stats_t* s, uint64_t us) {
    if (!s->samples) s->samples = malloc(MAX_SAMPLES * sizeof(uint32_t));
    if (s->samples && s->count < MAX_SAMPLES) s->samples[s->count++] = (uint32_t)(us > 0xFFFFFFFFu ? 0xFFFFFFFFu : us);
    s->total_us += us;
    if (us > s->max_us) s->max_us = (uint32_t)us;
}

static void op_fail(op_stats_t* s, const char* what, int tenant, int err) {
    s->errors++;
    fprintf(stderr, "[stress] tenant %d %s failed: %s\n", tenant, what, strerror(err));
}

static int u32_cmp(const void* a, const void* b) {
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static double op_percentile(const op_stats_t* s, double p) {
    if (!s->count || !s->samples) return 0.0;
    size_t idx = (size_t)(p * (double)(s->count - 1u));
    uint32_t* copy = malloc(s->count * sizeof(uint32_t));
    assert(copy != NULL);
    memcpy(copy, s->samples, s->count * sizeof(uint32_t));
    qsort(copy, s->count, sizeof(uint32_t), u32_cmp);
    double v = (double)copy[idx];
    free(copy);
    return v;
}

static uint32_t QIHSE_STRESS_MIN_MB = 1, QIHSE_STRESS_MAX_MB = 5, QIHSE_STRESS_CYCLE_MS = 30000;

typedef struct {
    int tenant_index;          /* 0-based */
    uint32_t tenant_id;
    qihse_user_t* user;
    qihse_blob_store_t* blobs;
    qihse_kv_store_t* kv;
    struct timespec deadline;
    unsigned int seed;
    op_stats_t put;
    op_stats_t get;            /* 64 KiB range reads */
    op_stats_t telemetry;
    uint64_t bytes_up;
    uint64_t bytes_down;
    uint64_t cycles;
} tenant_worker_t;

/* Aggregates (accessed with __atomic builtins). */
static uint64_t g_bytes_up, g_bytes_down, g_cycles, g_puts, g_gets, g_telemetry, g_errors;
static uint64_t g_blob_unique; /* distinct hashes uploaded */

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static uint64_t now_ms_wall(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void sleep_us(uint64_t us) {
    struct timespec ts = { (time_t)(us / 1000000u), (long)((us % 1000000u) * 1000u) };
    nanosleep(&ts, NULL);
}

static void* tenant_main(void* argument) {
    tenant_worker_t* w = (tenant_worker_t*)argument;
    uint8_t* chunk = malloc(64u * 1024u); /* BUNDLE.CHUNK-sized read buffer */
    if (!chunk) return NULL;

    char key[128], value[64];
    struct timespec deadline = w->deadline;

    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) break;

        uint64_t cycle_start = now_us();
        size_t mb = (size_t)(QIHSE_STRESS_MIN_MB +
                             rand_r(&w->seed) % (QIHSE_STRESS_MAX_MB - QIHSE_STRESS_MIN_MB + 1));
        size_t size = mb * 1024u * 1024u;
        uint8_t* payload = malloc(size);
        if (!payload) { w->put.errors++; continue; }
        for (size_t i = 0; i < size; i += 4096u) payload[i] = (uint8_t)rand_r(&w->seed);
        size_t marker = size > 4096u ? 4096u : (size ? size - 1u : 0);
        payload[marker] = (uint8_t)(w->tenant_id & 0xFF);

        /* Upload */
        uint64_t t0 = now_us();
        uint8_t hash[QIHSE_BLOB_HASH_BYTES];
        if (!qihse_blob_put_buffer_user(w->blobs, w->tenant_id, QIHSE_BLOB_TAG_SCRIPT_SET,
                                        0, 0, w->user, payload, size, hash)) {
            op_fail(&w->put, "blob put", w->tenant_index, errno);
            __atomic_add_fetch(&g_errors, 1u, __ATOMIC_RELAXED);
            free(payload);
            continue;
        }
        op_record(&w->put, now_us() - t0);
        w->bytes_up += size;
        __atomic_add_fetch(&g_bytes_up, (unsigned long long)size, __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_puts, 1u, __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_blob_unique, 1u, __ATOMIC_RELAXED);

        /* Download: sequential 64 KiB range reads (BUNDLE.CHUNK semantics). */
        size_t offset = 0;
        bool download_ok = true;
        while (offset < size) {
            size_t want = size - offset > 64u * 1024u ? 64u * 1024u : size - offset;
            uint64_t r0 = now_us();
            size_t nread = 0;
            if (!qihse_blob_get_user(w->blobs, hash, offset, chunk, 64u * 1024u, &nread, w->user) ||
                nread != want) {
                op_fail(&w->get, "blob range read", w->tenant_index, errno);
                download_ok = false;
                break;
            }
            op_record(&w->get, now_us() - r0);
            if (memcmp(chunk, payload + offset, want) != 0) {
                op_fail(&w->get, "byte mismatch", w->tenant_index, 0);
                download_ok = false;
                break;
            }
            offset += want;
            w->bytes_down += want;
            __atomic_add_fetch(&g_bytes_down, (unsigned long long)want, __ATOMIC_RELAXED);
            __atomic_add_fetch(&g_gets, 1u, __ATOMIC_RELAXED);
        }
        if (!download_ok) {
            __atomic_add_fetch(&g_errors, 1u, __ATOMIC_RELAXED);
            free(payload);
            continue;
        }

        /* Random slices (resume semantics). */
        for (int s = 0; s < 3; s++) {
            size_t slice_off = ((size_t)rand_r(&w->seed) * 977u) % size;
            size_t want = size - slice_off > 64u * 1024u ? 64u * 1024u : size - slice_off;
            size_t nread = 0;
            uint64_t r0 = now_us();
            bool ok = qihse_blob_get_user(w->blobs, hash, slice_off, chunk, 64u * 1024u, &nread, w->user);
            op_record(&w->get, now_us() - r0);
            if (!ok || nread != want || memcmp(chunk, payload + slice_off, want) != 0) {
                op_fail(&w->get, "slice read", w->tenant_index, 0);
                __atomic_add_fetch(&g_errors, 1u, __ATOMIC_RELAXED);
                download_ok = false;
                break;
            }
            __atomic_add_fetch(&g_gets, 1u, __ATOMIC_RELAXED);
        }

        /* One schema-valid telemetry write per cycle (ingest gate + quota path). */
        {
            snprintf(key, sizeof(key), "t:%u/tlm/census/stress", w->tenant_id);
            uint64_t t1 = now_us();
            snprintf(value, sizeof(value), "census|%zu|1000", size);
            if (qihse_kv_set_user(w->kv, key, value, 0, 0, w->user)) {
                op_record(&w->telemetry, now_us() - t1);
                __atomic_add_fetch(&g_telemetry, 1u, __ATOMIC_RELAXED);
            } else {
                op_fail(&w->telemetry, "telemetry set", w->tenant_index, errno);
                __atomic_add_fetch(&g_errors, 1u, __ATOMIC_RELAXED);
            }
        }

        free(payload);
        if (download_ok) {
            w->cycles++;
            __atomic_add_fetch(&g_cycles, 1u, __ATOMIC_RELAXED);
        }

        /* Keep the per-tenant cycle period near QIHSE_STRESS_CYCLE_MS. */
        uint64_t elapsed = now_us() - cycle_start;
        if (elapsed < QIHSE_STRESS_CYCLE_MS * 1000u) sleep_us(QIHSE_STRESS_CYCLE_MS * 1000u - elapsed);
    }
    free(chunk);
    return NULL;
}

static uint32_t env_u32(const char* name, uint32_t fallback) {
    const char* v = getenv(name);
    return v && *v ? (uint32_t)strtoul(v, NULL, 10) : fallback;
}

int main(void) {
    uint32_t tenants = env_u32("QIHSE_STRESS_TENANTS", 100);
    uint32_t seconds = env_u32("QIHSE_STRESS_SECONDS", 300);
    QIHSE_STRESS_MIN_MB = env_u32("QIHSE_STRESS_MIN_MB", 1);
    QIHSE_STRESS_MAX_MB = env_u32("QIHSE_STRESS_MAX_MB", 5);
    QIHSE_STRESS_CYCLE_MS = env_u32("QIHSE_STRESS_CYCLE_MS", 30000);
    if (QIHSE_STRESS_MIN_MB == 0) QIHSE_STRESS_MIN_MB = 1;
    if (QIHSE_STRESS_MAX_MB < QIHSE_STRESS_MIN_MB) QIHSE_STRESS_MAX_MB = QIHSE_STRESS_MIN_MB;

    char data_dir[] = "/tmp/qihse-stress-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    setenv("QIHSE_DATA_DIR", data_dir, 1);
    setenv("QIHSE_FIPS_MODE", "disabled", 1);

    printf("[stress] %u tenants, %us, %u-%u MB payloads, cycle target %u ms\n",
           tenants, seconds, QIHSE_STRESS_MIN_MB, QIHSE_STRESS_MAX_MB, QIHSE_STRESS_CYCLE_MS);
    printf("[stress] data dir: %s\n", data_dir);

    qihse_pqc_init_providers();
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorStressPa1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);

    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv != NULL);
    char blob_dir[512];
    snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", data_dir);
    qihse_blob_store_t* blobs = qihse_blob_store_create(blob_dir);
    assert(blobs != NULL);
    qihse_quota_table_t* quotas = qihse_quota_table_create(256);
    assert(quotas != NULL);

    /* ---- Phase 1: tenant onboarding (measured; PBKDF2 is serialized) ---- */
    printf("[stress] phase 1: creating %u tenant principals...\n", tenants);
    uint64_t create_start = now_ms_wall();
    tenant_worker_t* workers = calloc(tenants, sizeof(tenant_worker_t));
    assert(workers != NULL);
    for (uint32_t i = 0; i < tenants; i++) {
        uint32_t tenant_id = 100u + i;
        /* MAX_USERS is 65536 (operator is 0): natural mapping 1000+i. */
        uint32_t user_id = 1000u + i;
        char password[64];
        snprintf(password, sizeof(password), "StressTenant%uPass!", i);
        qihse_user_t* user = qihse_auth_create_tenant_user(op, tenant_id, user_id,
                                                           QIHSE_ROLE_GUEST, 91, 0,
                                                           password, false);
        if (!user) {
            fprintf(stderr, "[stress] FAILED to create tenant %u\n", tenant_id);
            return 1;
        }
        workers[i].tenant_index = (int)i;
        workers[i].tenant_id = tenant_id;
        workers[i].user = user;
        workers[i].blobs = blobs;
        workers[i].kv = kv;
        workers[i].seed = 0x5eedu + i * 7919u;
    }
    uint64_t create_ms = now_ms_wall() - create_start;
    printf("[stress] phase 1 done: %u tenants in %.1f s (%.0f ms/tenant, serialized PBKDF2)\n",
           tenants, (double)create_ms / 1000.0, (double)create_ms / (double)tenants);

    /* Generous quotas: exercise the path without throttling the measurement. */
    for (uint32_t i = 0; i < tenants; i++) {
        uint32_t tenant_id = 100u + i;
        assert(qihse_quota_configure(quotas, tenant_id, QIHSE_QUOTA_TELEMETRY_INGEST, 100000, 60));
        assert(qihse_quota_configure(quotas, tenant_id, QIHSE_QUOTA_BUNDLE_PULL, 100000, 60));
        assert(qihse_quota_configure(quotas, tenant_id, QIHSE_QUOTA_KV_WRITE, 100000, 60));
    }

    /* ---- Phase 2: concurrent up/down traffic ---- */
    printf("[stress] phase 2: traffic for %u s...\n", seconds);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += (time_t)seconds;

    uint64_t traffic_start = now_ms_wall();
    pthread_t* threads = calloc(tenants, sizeof(pthread_t));
    for (uint32_t i = 0; i < tenants; i++) {
        workers[i].deadline = deadline;
        int rc = pthread_create(&threads[i], NULL, tenant_main, &workers[i]);
        assert(rc == 0);
    }

    uint64_t last_print = now_ms_wall();
    uint64_t last_up = 0, last_down = 0;
    for (;;) {
        sleep_us(30u * 1000u * 1000u);
        uint64_t now = now_ms_wall();
        uint64_t up = __atomic_load_n(&g_bytes_up, __ATOMIC_RELAXED);
        uint64_t down = __atomic_load_n(&g_bytes_down, __ATOMIC_RELAXED);
        double dt = (double)(now - last_print) / 1000.0;
        printf("[stress %3us] cycles=%llu  up=%.1f MB/s  down=%.1f MB/s  (totals: up %.2f GB, down %.2f GB, errors=%llu)\n",
               (unsigned)((now - traffic_start) / 1000u),
               (unsigned long long)__atomic_load_n(&g_cycles, __ATOMIC_RELAXED),
               (double)(up - last_up) / 1048576.0 / dt,
               (double)(down - last_down) / 1048576.0 / dt,
               (double)up / 1073741824.0, (double)down / 1073741824.0,
               (unsigned long long)__atomic_load_n(&g_errors, __ATOMIC_RELAXED));
        fflush(stdout);
        last_print = now;
        last_up = up;
        last_down = down;
        struct timespec now_ts;
        clock_gettime(CLOCK_REALTIME, &now_ts);
        if (now_ts.tv_sec >= deadline.tv_sec) break;
    }

    for (uint32_t i = 0; i < tenants; i++) pthread_join(threads[i], NULL);

    /* ---- Summary ---- */
    op_stats_t put = {0}, get = {0}, telemetry = {0};
    /* Aggregate per-thread samples. */
    for (uint32_t i = 0; i < tenants; i++) {
        put.total_us += workers[i].put.total_us; put.count += workers[i].put.count;
        put.max_us = workers[i].put.max_us > put.max_us ? workers[i].put.max_us : put.max_us;
        put.errors += workers[i].put.errors;
        get.total_us += workers[i].get.total_us; get.count += workers[i].get.count;
        get.max_us = workers[i].get.max_us > get.max_us ? workers[i].get.max_us : get.max_us;
        get.errors += workers[i].get.errors;
        telemetry.total_us += workers[i].telemetry.total_us; telemetry.count += workers[i].telemetry.count;
        telemetry.max_us = workers[i].telemetry.max_us > telemetry.max_us ? workers[i].telemetry.max_us : telemetry.max_us;
        telemetry.errors += workers[i].telemetry.errors;
    }
    /* Merge samples for percentile reporting. */
    op_stats_t put_all = {0}, get_all = {0}, tlm_all = {0};
    size_t cap = tenants * MAX_SAMPLES;
    put_all.samples = malloc(cap * sizeof(uint32_t));
    get_all.samples = malloc(cap * sizeof(uint32_t));
    tlm_all.samples = malloc(cap * sizeof(uint32_t));
    for (uint32_t i = 0; i < tenants; i++) {
        if (workers[i].put.samples) memcpy(put_all.samples + put_all.count, workers[i].put.samples, workers[i].put.count * sizeof(uint32_t));
        put_all.count += workers[i].put.count;
        if (workers[i].get.samples) memcpy(get_all.samples + get_all.count, workers[i].get.samples, workers[i].get.count * sizeof(uint32_t));
        get_all.count += workers[i].get.count;
        if (workers[i].telemetry.samples) memcpy(tlm_all.samples + tlm_all.count, workers[i].telemetry.samples, workers[i].telemetry.count * sizeof(uint32_t));
        tlm_all.count += workers[i].telemetry.count;
    }
    put_all.total_us = put.total_us; get_all.total_us = get.total_us; tlm_all.total_us = telemetry.total_us;

    uint64_t up = __atomic_load_n(&g_bytes_up, __ATOMIC_RELAXED);
    uint64_t down = __atomic_load_n(&g_bytes_down, __ATOMIC_RELAXED);

    printf("\n================ STRESS SUMMARY ================\n");
    printf("tenants:                %u (created in %.1f s, %.0f ms/tenant)\n",
           tenants, (double)create_ms / 1000.0, (double)create_ms / (double)tenants);
    printf("duration:               %u s (traffic phase)\n", seconds);
    printf("cycles completed:       %llu\n", (unsigned long long)__atomic_load_n(&g_cycles, __ATOMIC_RELAXED));
    printf("bytes uploaded:         %.2f GB (%.2f MB/s avg)\n", (double)up / 1073741824.0, (double)up / 1048576.0 / (double)seconds);
    printf("bytes downloaded:       %.2f GB (%.2f MB/s avg)\n", (double)down / 1073741824.0, (double)down / 1048576.0 / (double)seconds);
    printf("blob puts:              %llu  err=%llu  avg %.0f us  p50 %.0f  p95 %.0f  p99 %.0f  max %.0f us\n",
           (unsigned long long)__atomic_load_n(&g_puts, __ATOMIC_RELAXED), (unsigned long long)put.errors,
           put.count ? (double)put.total_us / (double)put.count : 0.0,
           op_percentile(&put_all, 0.50), op_percentile(&put_all, 0.95), op_percentile(&put_all, 0.99), (double)put.max_us);
    printf("blob 64KiB reads:       %llu  err=%llu  avg %.0f us  p50 %.0f  p95 %.0f  p99 %.0f  max %.0f us\n",
           (unsigned long long)__atomic_load_n(&g_gets, __ATOMIC_RELAXED), (unsigned long long)get.errors,
           get.count ? (double)get.total_us / (double)get.count : 0.0,
           op_percentile(&get_all, 0.50), op_percentile(&get_all, 0.95), op_percentile(&get_all, 0.99), (double)get.max_us);
    printf("telemetry writes:       %llu  err=%llu  avg %.0f us  p50 %.0f  p95 %.0f  p99 %.0f  max %.0f us\n",
           (unsigned long long)__atomic_load_n(&g_telemetry, __ATOMIC_RELAXED), (unsigned long long)telemetry.errors,
           telemetry.count ? (double)telemetry.total_us / (double)telemetry.count : 0.0,
           op_percentile(&tlm_all, 0.50), op_percentile(&tlm_all, 0.95), op_percentile(&tlm_all, 0.99), (double)telemetry.max_us);
    printf("errors total:           %llu\n", (unsigned long long)__atomic_load_n(&g_errors, __ATOMIC_RELAXED));
    printf("================================================\n");

    return __atomic_load_n(&g_errors, __ATOMIC_RELAXED) == 0 ? 0 : 1;
}
