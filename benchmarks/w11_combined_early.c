#define _GNU_SOURCE
#include "qihse_auth.h"
#include "qihse_kv_store.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* Early W11.6 contention probe. All data access uses authenticated public KV
 * APIs. This does not implement a cross-model application transaction. */
typedef enum { INVENTORY, FINDINGS, MEMORY } lane_t;
typedef struct {
    qihse_kv_store_t* store;
    qihse_user_t* user;
    lane_t lane;
    unsigned worker;
    unsigned ops;
    uint64_t seed;
    uint64_t* lat_us;
    unsigned samples;
    unsigned success;
    unsigned expected_reject;
    unsigned errors;
    pthread_barrier_t* start;
} worker_t;

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) abort();
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t next_random(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *state = x;
}

static void record(worker_t* w, uint64_t start) {
    w->lat_us[w->samples++] = (now_ns() - start + 999u) / 1000u;
}

static void* run_worker(void* opaque) {
    worker_t* w = opaque;
    pthread_barrier_wait(w->start);
    for (unsigned i = 0; i < w->ops; ++i) {
        char key[96], value[64];
        uint64_t start = now_ns();
        if (w->lane == INVENTORY) {
            /* One-key CAS protects the stock count; order/outbox are absent. */
            unsigned retries = 0;
            for (;;) {
                char* old = qihse_kv_get_user(w->store, "w11/stock", w->user);
                if (!old) { w->errors++; break; }
                char* end = NULL;
                errno = 0;
                unsigned long stock = strtoul(old, &end, 10);
                if (errno || !end || *end || stock > 100000000u) {
                    w->errors++; free(old); break;
                }
                if (stock == 0) {
                    w->expected_reject++; free(old); break;
                }
                snprintf(value, sizeof value, "%lu", stock - 1);
                qihse_kv_cas_result_t rc = qihse_kv_compare_set_user(
                    w->store, "w11/stock", old, value, 0, 0, w->user);
                free(old);
                if (rc == QIHSE_KV_CAS_UPDATED) { w->success++; break; }
                if (rc == QIHSE_KV_CAS_FAILED) { w->errors++; break; }
                /* MISMATCH is a concurrent reservation; retry the logical op. */
                if (++retries > 1024u) { w->errors++; break; }
            }
        } else if (w->lane == FINDINGS) {
            snprintf(key, sizeof key, "w11/finding/%08u", i);
            snprintf(value, sizeof value, "finding-v1-%08u", i);
            if (qihse_kv_set_user(w->store, key, value, 5, 0, w->user))
                w->success++;
            else
                w->errors++;
        } else {
            snprintf(key, sizeof key, "w11/memory/%08u", i);
            snprintf(value, sizeof value, "memory-v1-%08u", i);
            if (!qihse_kv_set_user(w->store, key, value, 5, 0, w->user)) {
                w->errors++;
            } else {
                unsigned selected = (unsigned)(next_random(&w->seed) % (i + 1u));
                snprintf(key, sizeof key, "w11/memory/%08u", selected);
                snprintf(value, sizeof value, "memory-v1-%08u", selected);
                char* got = qihse_kv_get_user(w->store, key, w->user);
                if (got && strcmp(got, value) == 0) w->success++;
                else w->errors++;
                free(got);
            }
        }
        record(w, start);
    }
    return NULL;
}

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

static uint64_t percentile(uint64_t* v, size_t n, unsigned pct) {
    if (!n) return 0;
    size_t index = ((size_t)pct * n + 99u) / 100u;
    return v[index ? index - 1u : 0u];
}

static void metric(const char* name, const worker_t* a, const worker_t* b,
                   double elapsed_s) {
    size_t n = a->samples + (b ? b->samples : 0u);
    uint64_t* lat = malloc(n * sizeof *lat);
    if (!lat) abort();
    memcpy(lat, a->lat_us, a->samples * sizeof *lat);
    if (b) memcpy(lat + a->samples, b->lat_us, b->samples * sizeof *lat);
    qsort(lat, n, sizeof *lat, cmp_u64);
    unsigned success = a->success + (b ? b->success : 0u);
    unsigned rejected = a->expected_reject + (b ? b->expected_reject : 0u);
    unsigned errors = a->errors + (b ? b->errors : 0u);
    printf("  \"%s\":{\"attempts\":%zu,\"success\":%u,\"expected_reject\":%u,"
           "\"errors\":%u,\"ops_per_s\":%.3f,\"p50_us\":%" PRIu64
           ",\"p95_us\":%" PRIu64 ",\"p99_us\":%" PRIu64 "}",
           name, n, success, rejected, errors, success / elapsed_s,
           percentile(lat, n, 50), percentile(lat, n, 95), percentile(lat, n, 99));
    free(lat);
}

int main(int argc, char** argv) {
    unsigned ops = 64u;
    uint64_t seed = UINT64_C(20261106);
    if (argc > 3) return 2;
    if (argc > 1) {
        char* end = NULL;
        unsigned long x = strtoul(argv[1], &end, 10);
        if (!end || *end || x == 0 || x > 100000) return 2;
        ops = (unsigned)x;
    }
    if (argc > 2) {
        char* end = NULL;
        seed = strtoull(argv[2], &end, 10);
        if (!end || *end || seed == 0) return 2;
    }
    if (!qihse_auth_init() ||
        !qihse_auth_bootstrap_operator("W11CombinedEarlyOperator1!")) return 1;
    qihse_user_t* op = qihse_auth_get_user(0);
    qihse_user_t* low = qihse_auth_create_user(op, 47471, QIHSE_ROLE_GUEST,
        0, 0, "W11CombinedEarlyGuest1!", false);
    if (!op || !low) return 1;
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    if (!store) return 1;
    char initial[64];
    snprintf(initial, sizeof initial, "%u", ops);
    if (!qihse_kv_set_user(store, "w11/stock", initial, 0, 0, op)) return 1;

    pthread_barrier_t start;
    if (pthread_barrier_init(&start, NULL, 5) != 0) return 1;
    worker_t w[4] = {
        {.store=store, .user=op, .lane=INVENTORY, .worker=0, .ops=ops, .seed=seed},
        {.store=store, .user=op, .lane=INVENTORY, .worker=1, .ops=ops, .seed=seed+1},
        {.store=store, .user=op, .lane=FINDINGS, .worker=2, .ops=ops, .seed=seed+2},
        {.store=store, .user=op, .lane=MEMORY, .worker=3, .ops=ops, .seed=seed+3},
    };
    pthread_t threads[4];
    for (size_t i = 0; i < 4; ++i) {
        w[i].start = &start;
        w[i].lat_us = calloc(ops, sizeof(uint64_t));
        if (!w[i].lat_us || pthread_create(&threads[i], NULL, run_worker, &w[i])) return 1;
    }
    uint64_t started = now_ns();
    pthread_barrier_wait(&start);
    for (size_t i = 0; i < 4; ++i) pthread_join(threads[i], NULL);
    double elapsed_s = (now_ns() - started) / 1e9;
    pthread_barrier_destroy(&start);

    char* final_stock = qihse_kv_get_user(store, "w11/stock", op);
    unsigned stock = final_stock ? (unsigned)strtoul(final_stock, NULL, 10) : UINT32_MAX;
    free(final_stock);
    unsigned inventory_success = w[0].success + w[1].success;
    bool stock_ok = stock <= ops && inventory_success + stock == ops &&
        inventory_success + w[0].expected_reject + w[1].expected_reject == 2u * ops;
    bool findings_ok = true;
    for (unsigned i = 0; i < ops; ++i) {
        char key[96], expected[64];
        snprintf(key, sizeof key, "w11/finding/%08u", i);
        snprintf(expected, sizeof expected, "finding-v1-%08u", i);
        char* got = qihse_kv_get_user(store, key, op);
        if (!got || strcmp(got, expected)) findings_ok = false;
        free(got);
    }
    bool denied = qihse_kv_get_user(store, "w11/finding/00000000", low) == NULL &&
                  qihse_kv_get_user(store, "w11/memory/00000000", low) == NULL;
    struct utsname machine;
    if (uname(&machine) != 0) return 1;
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    long pages = sysconf(_SC_PHYS_PAGES), page_bytes = sysconf(_SC_PAGESIZE);
    printf("{\"schema\":\"w11-combined-early-v1\",\"seed\":%" PRIu64
           ",\"ops_per_worker\":%u,\"hardware\":{\"machine\":\"%s\","
           "\"cores_online\":%ld,\"ram_bytes\":%llu},\"elapsed_s\":%.6f,\n",
           seed, ops, machine.machine, cores,
           (unsigned long long)((uint64_t)pages * (uint64_t)page_bytes), elapsed_s);
    metric("inventory_stock_cas", &w[0], &w[1], elapsed_s); puts(",");
    metric("finding_record_ingest", &w[2], NULL, elapsed_s); puts(",");
    metric("memory_exact_key", &w[3], NULL, elapsed_s); puts(",");
    printf("  \"invariants\":{\"stock_nonnegative_and_accounted\":%s,"
           "\"finding_records_read_back\":%s,\"low_clearance_denied\":%s},\n"
           "  \"coverage\":{\"order_outbox_atomicity\":false,"
           "\"finding_blobs_provenance\":false,\"semantic_memory_recall\":false,"
           "\"node_faults_partitions_restore\":false,\"w11_scale_gate\":false}}\n",
           stock_ok ? "true" : "false", findings_ok ? "true" : "false",
           denied ? "true" : "false");
    unsigned errors = w[0].errors + w[1].errors + w[2].errors + w[3].errors;
    for (size_t i = 0; i < 4; ++i) free(w[i].lat_us);
    qihse_kv_store_destroy(store);
    return stock_ok && findings_ok && denied && errors == 0 ? 0 : 1;
}
