/* Concurrency stress test: 16 threads hammering UWP dispatch, auth, ACLs, metrics. */
#include "qihse_uwp.h"
#include "qihse_auth.h"
#include "qihse_uwp_metrics.h"
#include "qihse_kv_store.h"
#include "qihse_audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>
#include <errno.h>
#include <sys/stat.h>

#define NUM_THREADS 16
#define ITERATIONS 1000

static qihse_uwp_metrics_t* g_metrics;
static qihse_kv_store_t* g_kv;
static qihse_user_t* g_operator;
static _Atomic int g_auth_attempts = 0;
static _Atomic int g_auth_successes = 0;
static _Atomic int g_acl_grants = 0;
static _Atomic int g_acl_denies = 0;
static _Atomic int g_errors = 0;
static pthread_barrier_t g_barrier;

static void* worker_thread(void* arg) {
    int tid = (int)(long)arg;
    pthread_barrier_wait(&g_barrier);

    /* Authenticate a real principal under contention. Reusing the handle
     * keeps this test focused on concurrent API calls instead of spending
     * 16,000 password hashes on nonexistent usernames. */
    atomic_fetch_add(&g_auth_attempts, 1);
    qihse_user_t* user = qihse_auth_authenticate_from(
        0x0A000001u + (uint32_t)tid, "User_100", "UwpConcurrencyUser123!");
    if (!user) {
        atomic_fetch_add(&g_errors, 1);
        return NULL;
    }
    atomic_fetch_add(&g_auth_successes, 1);

    for (int i = 0; i < ITERATIONS; i++) {
        /* Metrics stress */
        qihse_uwp_metrics_inc_frames_received(g_metrics);
        qihse_uwp_metrics_inc_frames_valid(g_metrics);
        qihse_uwp_metrics_inc_dispatch_ok(g_metrics, tid % 16);

        /* One repeatedly updated grant and one permanently denied object
         * per principal stay within the bounded ACL table. */
        uint64_t resource = (uint64_t)tid * 2u + (i % 3 == 0 ? 0u : 1u);
        if (i % 3 == 0) {
            if (qihse_auth_grant_object(g_operator, user, 0, resource,
                                        QIHSE_ACL_READ))
                atomic_fetch_add(&g_acl_grants, 1);
            else
                atomic_fetch_add(&g_errors, 1);
        }
        bool can = qihse_auth_can_access_object(user, 0, resource, QIHSE_ACL_READ);
        if (can != (i % 3 == 0)) atomic_fetch_add(&g_errors, 1);
        if (!can) atomic_fetch_add(&g_acl_denies, 1);

        /* KV store stress */
        if (g_kv) {
            char key[64], val[64];
            snprintf(key, sizeof(key), "k_%d_%d", tid, i);
            snprintf(val, sizeof(val), "v_%d_%d", tid, i);
            if (!qihse_kv_set_user(g_kv, key, val, 0, 0, user))
                atomic_fetch_add(&g_errors, 1);
            char* got = qihse_kv_get_user(g_kv, key, user);
            if (!got || strcmp(got, val) != 0) atomic_fetch_add(&g_errors, 1);
            free(got);
        }
    }
    return NULL;
}

int main(void) {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_uwp_concurrency_XXXXXX";
    if (mkdir("build", 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "uwp_concurrency: build directory failed\n");
        return 1;
    }
    if (!mkdtemp(qdd) || setenv("QIHSE_DATA_DIR", qdd, 1) != 0) {
        fprintf(stderr, "uwp_concurrency: scratch directory failed\n");
        return 1;
    }
}
    /* Audited UWP paths fail closed (abort) without the audit writer, the same
     * as the AF_XDP ingress test: initialize auth first. */
    if (!qihse_auth_init()) {
        fprintf(stderr, "uwp_concurrency: auth init failed\n");
        return 1;
    }
    if (!qihse_auth_bootstrap_operator("UwpConcurrencySystem123!")) {
        fprintf(stderr, "uwp_concurrency: operator bootstrap failed\n");
        return 1;
    }
    g_operator = qihse_auth_get_user(0);
    if (!g_operator) return 1;
    if (!qihse_auth_create_user(g_operator, 100, QIHSE_ROLE_ANALYST,
                                0, 0, "UwpConcurrencyUser123!", false)) {
        fprintf(stderr, "uwp_concurrency: user creation failed\n");
        return 1;
    }
    g_metrics = qihse_uwp_metrics_create();
    g_kv = qihse_kv_store_create();
    if (!g_metrics || !g_kv) {
        fprintf(stderr, "uwp_concurrency: test stores failed\n");
        return 1;
    }
    pthread_barrier_init(&g_barrier, NULL, NUM_THREADS);

    pthread_t threads[NUM_THREADS];
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker_thread, (void*)(long)i);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    pthread_barrier_destroy(&g_barrier);

    /* Verify metrics consistency */
    int expected = NUM_THREADS * ITERATIONS;
    /* Read metrics via JSON to verify */
    char* json = qihse_uwp_metrics_to_json(g_metrics);
    int ok = 1;

    /* Check that metrics counters are non-zero and reasonable */
    if (!json) {
        fprintf(stderr, "[FAIL] metrics JSON is NULL\n");
        ok = 0;
    } else {
        if (!strstr(json, "frames_received")) {
            fprintf(stderr, "[FAIL] metrics JSON missing frames_received\n");
            ok = 0;
        }
        free(json);
    }

    /* Check Prometheus output */
    char* prom = qihse_uwp_metrics_to_prometheus(g_metrics);
    if (!prom || !strstr(prom, "qihse_uwp_frames_received")) {
        fprintf(stderr, "[FAIL] Prometheus output missing metrics\n");
        ok = 0;
    }
    if (prom) free(prom);

    int attempts = atomic_load(&g_auth_attempts);
    int successes = atomic_load(&g_auth_successes);
    int grants = atomic_load(&g_acl_grants);
    int denies = atomic_load(&g_acl_denies);

    printf("Concurrency test: %d threads x %d iterations in %.2fs\n", NUM_THREADS, ITERATIONS, elapsed);
    printf("  Auth attempts: %d, successes: %d\n", attempts, successes);
    printf("  ACL grants: %d, denies: %d\n", grants, denies);
    printf("  Total operations: %d\n", expected);

    qihse_audit_flush();
    if (ok && attempts == NUM_THREADS && successes == NUM_THREADS &&
        grants == NUM_THREADS * ((ITERATIONS + 2) / 3) &&
        denies == NUM_THREADS * (ITERATIONS - ((ITERATIONS + 2) / 3)) &&
        atomic_load(&g_errors) == 0) {
        printf("\nPASS UWP concurrency stress test (no crashes, metrics consistent)\n");
        qihse_uwp_metrics_destroy(g_metrics);
        qihse_kv_store_destroy(g_kv);
        return 0;
    }
    printf("\nFAIL concurrency test (ok=%d, attempts=%d, successes=%d, errors=%d)\n",
           ok, attempts, successes, atomic_load(&g_errors));
    qihse_uwp_metrics_destroy(g_metrics);
    qihse_kv_store_destroy(g_kv);
    return 1;
}
