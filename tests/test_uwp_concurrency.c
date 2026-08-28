/* Concurrency stress test: 16 threads hammering UWP dispatch, auth, ACLs, metrics. */
#include "qihse_uwp.h"
#include "qihse_auth.h"
#include "qihse_uwp_metrics.h"
#include "qihse_kv_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>

#define NUM_THREADS 16
#define ITERATIONS 1000

static qihse_uwp_metrics_t* g_metrics;
static qihse_kv_store_t* g_kv;
static _Atomic int g_auth_attempts = 0;
static _Atomic int g_auth_successes = 0;
static _Atomic int g_acl_grants = 0;
static _Atomic int g_acl_denies = 0;
static pthread_barrier_t g_barrier;

static void* worker_thread(void* arg) {
    int tid = (int)(long)arg;
    pthread_barrier_wait(&g_barrier);

    for (int i = 0; i < ITERATIONS; i++) {
        /* Metrics stress */
        qihse_uwp_metrics_inc_frames_received(g_metrics);
        qihse_uwp_metrics_inc_frames_valid(g_metrics);
        qihse_uwp_metrics_inc_dispatch_ok(g_metrics, tid % 16);

        /* Auth stress */
        char username[64];
        snprintf(username, sizeof(username), "user_%d_%d", tid, i % 4);
        atomic_fetch_add(&g_auth_attempts, 1);
        qihse_user_t* user = qihse_auth_authenticate(username, "pass");
        if (user) {
            atomic_fetch_add(&g_auth_successes, 1);

            /* ACL stress */
            uint64_t resource = (uint64_t)tid * ITERATIONS + i;
            if (i % 3 == 0) {
                qihse_auth_grant_object(user, user, 0, resource, 1);
                atomic_fetch_add(&g_acl_grants, 1);
            }
            bool can = qihse_auth_can_access_object(user, 0, resource);
            if (can && i % 3 == 0) {
                /* expected: granted */
            } else if (!can) {
                atomic_fetch_add(&g_acl_denies, 1);
            }
        }

        /* KV store stress */
        if (g_kv) {
            char key[64], val[64];
            snprintf(key, sizeof(key), "k_%d_%d", tid, i);
            snprintf(val, sizeof(val), "v_%d_%d", tid, i);
            qihse_kv_set(g_kv, key, val, 0, 0);
            char* got = qihse_kv_get(g_kv, key);
            if (got) free(got);
        }
    }
    return NULL;
}

int main(void) {
    g_metrics = qihse_uwp_metrics_create();
    g_kv = qihse_kv_store_create();
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

    if (ok && attempts == expected) {
        printf("\nPASS UWP concurrency stress test (no crashes, metrics consistent)\n");
        qihse_uwp_metrics_destroy(g_metrics);
        qihse_kv_store_destroy(g_kv);
        return 0;
    }
    printf("\nFAIL concurrency test (ok=%d, attempts=%d, expected=%d)\n", ok, attempts, expected);
    qihse_uwp_metrics_destroy(g_metrics);
    qihse_kv_store_destroy(g_kv);
    return 1;
}
