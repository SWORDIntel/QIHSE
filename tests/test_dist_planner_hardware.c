/*
 * QIHSE — Idea 4: Adaptive Hardware Backend Dispatcher tests.
 *
 * Verifies that the distributed query planner:
 *   1. Profiles the host CPU/cache topology at runtime.
 *   2. Selects a runtime kernel backend per shard task based on payload size
 *      and cache residency, gated on the profiled feature mask.
 *   3. Falls back gracefully (BLAS -> AVX512 -> AVX2 -> SSE4.2 -> scalar)
 *      when a preferred backend is unavailable.
 *   4. Records the selected backend on every task produced by qihse_dist_plan_query.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "qihse_dist_planner.h"
#include "qihse_cpu_detect.h"
#include "qihse_cluster_slot.h"

static void add_helper_node(qihse_cluster_topology_t* topo, const char* name,
                            const char* host, uint16_t port, bool is_local) {
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    qihse_cluster_node_id_from_seed(name, strlen(name), node.id);
    strncpy(node.host, host, sizeof(node.host) - 1);
    node.port = port;
    node.bus_port = port + 10000;
    node.healthy = true;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    uint16_t idx = 0;
    qihse_cluster_topology_upsert_node(topo, &node, &idx);
    if (is_local) qihse_cluster_topology_set_local_node(topo, idx);
}

/* ------------------------------------------------------------------ */
/*  Test 1: host auto-profile sanity                                   */
/* ------------------------------------------------------------------ */
static void test_host_profile_autodetect(void) {
    printf("Testing host hardware profile auto-detection...\n");
    qihse_hw_profile_t* p = qihse_hw_profile_create();
    assert(p != NULL);

    assert(p->cache.cache_line_size > 0);
    assert(p->cache.l1_data_size > 0);
    assert(p->cache.l2_size > 0);
    assert(p->cache.numa_nodes >= 1);

    /* preferred must be one of the valid enum values and consistent with the
     * availability flags. */
    assert(p->preferred >= QIHSE_HW_BACKEND_SCALAR);
    assert(p->preferred <= QIHSE_HW_BACKEND_BLAS);

    if (p->blas_available)        assert(p->preferred == QIHSE_HW_BACKEND_BLAS);
    else if (p->avx512_available) assert(p->preferred == QIHSE_HW_BACKEND_AVX512);
    else if (p->avx2_available)   assert(p->preferred == QIHSE_HW_BACKEND_AVX2);
    else if (p->avx_available)    assert(p->preferred == QIHSE_HW_BACKEND_AVX);
    else if (p->sse42_available)  assert(p->preferred == QIHSE_HW_BACKEND_SSE42);
    else                          assert(p->preferred == QIHSE_HW_BACKEND_SCALAR);

    printf("  -> cache_line=%d L1d=%zu L2=%zu L3=%zu numa=%d "
           "avx=%d avx2=%d avx512=%d sse42=%d blas=%d preferred=%s OK\n",
           p->cache.cache_line_size, p->cache.l1_data_size, p->cache.l2_size,
           p->cache.l3_size, p->cache.numa_nodes,
           p->avx_available, p->avx2_available, p->avx512_available, p->sse42_available,
           p->blas_available, qihse_hw_backend_name(p->preferred));

    qihse_hw_profile_destroy(p);
}

/* ------------------------------------------------------------------ */
/*  Test 2: payload-size-driven backend selection                      */
/* ------------------------------------------------------------------ */
static void test_payload_size_dispatch(void) {
    printf("Testing payload-size-driven backend dispatch...\n");

    /* Synthetic profile: AVX2 + SSE4.2 available, BLAS off, small caches. */
    qihse_cache_topology_t cache = {
        .cache_line_size = 64,
        .l1_data_size    = 32 * 1024,
        .l2_size         = 256 * 1024,
        .l3_size         = 2 * 1024 * 1024,
        .numa_nodes      = 1
    };
    uint64_t feats = QIHSE_CPU_FEATURE_SSE4_2 | QIHSE_CPU_FEATURE_AVX2;
    qihse_hw_profile_t* p = qihse_hw_profile_create_from(feats, &cache, false);
    assert(p != NULL);
    assert(p->avx2_available);
    assert(p->sse42_available);
    assert(!p->avx512_available);
    assert(!p->blas_available);

    /* Tiny payload (< L1/4): scalar. */
    assert(qihse_hw_select_backend(p, 64, 128) == QIHSE_HW_BACKEND_SCALAR);
    /* L1-resident: SSE4.2. */
    assert(qihse_hw_select_backend(p, cache.l1_data_size / 2, 128) == QIHSE_HW_BACKEND_SSE42);
    /* L2-resident: AVX2. */
    assert(qihse_hw_select_backend(p, cache.l1_data_size * 2, 128) == QIHSE_HW_BACKEND_AVX2);
    /* >= L2 (no BLAS): still AVX2 (widest available). */
    assert(qihse_hw_select_backend(p, cache.l2_size * 4, 128) == QIHSE_HW_BACKEND_AVX2);

    /* Enable BLAS: bulk payloads (>= L3) should now dispatch to BLAS. */
    qihse_hw_profile_set_blas_available(p, true);
    assert(p->blas_available);
    assert(qihse_hw_select_backend(p, cache.l3_size, 128) == QIHSE_HW_BACKEND_BLAS);
    /* Sub-L3 bulk still uses AVX2. */
    assert(qihse_hw_select_backend(p, cache.l2_size * 2, 128) == QIHSE_HW_BACKEND_AVX2);

    printf("  -> scalar/sse4.2/avx2/blas thresholds honoured OK\n");
    qihse_hw_profile_destroy(p);
}

/* ------------------------------------------------------------------ */
/*  Test 3: graceful fallback when only scalar is available            */
/* ------------------------------------------------------------------ */
static void test_scalar_only_fallback(void) {
    printf("Testing scalar-only fallback...\n");
    qihse_cache_topology_t cache = {
        .cache_line_size = 64,
        .l1_data_size    = 32 * 1024,
        .l2_size         = 256 * 1024,
        .l3_size         = 2 * 1024 * 1024,
        .numa_nodes      = 1
    };
    qihse_hw_profile_t* p = qihse_hw_profile_create_from(0, &cache, false);
    assert(p != NULL);
    assert(!p->sse42_available);
    assert(!p->avx2_available);
    assert(!p->avx512_available);
    assert(!p->blas_available);
    assert(p->preferred == QIHSE_HW_BACKEND_SCALAR);

    for (size_t sz = 64; sz < 16 * 1024 * 1024; sz *= 8) {
        assert(qihse_hw_select_backend(p, sz, 128) == QIHSE_HW_BACKEND_SCALAR);
    }
    printf("  -> all payload sizes dispatch to scalar OK\n");
    qihse_hw_profile_destroy(p);
}

/* ------------------------------------------------------------------ */
/*  Test 4: AVX-512 preferred for bulk payloads when available         */
/* ------------------------------------------------------------------ */
static void test_avx512_bulk_preference(void) {
    printf("Testing AVX-512 bulk preference...\n");
    qihse_cache_topology_t cache = {
        .cache_line_size = 64,
        .l1_data_size    = 32 * 1024,
        .l2_size         = 1024 * 1024,
        .l3_size         = 32 * 1024 * 1024,
        .numa_nodes      = 1
    };
    uint64_t feats = QIHSE_CPU_FEATURE_SSE4_2 | QIHSE_CPU_FEATURE_AVX2 |
                     QIHSE_CPU_FEATURE_AVX512F | QIHSE_CPU_FEATURE_AVX512BW;
    qihse_hw_profile_t* p = qihse_hw_profile_create_from(feats, &cache, false);
    assert(p->avx512_available);
    /* Bulk (>= L2) without BLAS -> AVX-512. */
    assert(qihse_hw_select_backend(p, cache.l2_size * 2, 256) == QIHSE_HW_BACKEND_AVX512);
    /* L1-resident still prefers SSE4.2. */
    assert(qihse_hw_select_backend(p, cache.l1_data_size / 2, 256) == QIHSE_HW_BACKEND_SSE42);
    printf("  -> avx512 selected for bulk, sse4.2 for L1-resident OK\n");
    qihse_hw_profile_destroy(p);
}

/* ------------------------------------------------------------------ */
/*  Test 5: planner attaches profile and dispatches per task           */
/* ------------------------------------------------------------------ */
static void test_planner_attaches_profile_and_dispatches(void) {
    printf("Testing planner profile attach + per-task dispatch...\n");

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    add_helper_node(topo, "alpha", "10.0.0.1", 7000, true);
    add_helper_node(topo, "beta",  "10.0.0.2", 7001, false);
    qihse_dist_planner_t* planner = qihse_dist_planner_create(topo);
    assert(planner != NULL);

    /* No profile attached yet: get returns NULL. */
    assert(qihse_dist_planner_get_hw_profile(planner) == NULL);

    /* Attach a synthetic profile with AVX2 + SSE4.2. */
    qihse_cache_topology_t cache = {
        .cache_line_size = 64,
        .l1_data_size    = 32 * 1024,
        .l2_size         = 256 * 1024,
        .l3_size         = 2 * 1024 * 1024,
        .numa_nodes      = 1
    };
    uint64_t feats = QIHSE_CPU_FEATURE_SSE4_2 | QIHSE_CPU_FEATURE_AVX2;
    qihse_hw_profile_t* p = qihse_hw_profile_create_from(feats, &cache, false);
    qihse_dist_planner_set_hw_profile(planner, p);
    assert(qihse_dist_planner_get_hw_profile(planner) == p);

    /* Vector scatter-gather: each task should get a backend assigned. */
    const char* qql = "MATCH (n:Sensor) WHERE vector_search(embedding, top_k=10) RETURN n";
    qihse_dist_plan_t* plan = qihse_dist_plan_query(planner, qql, NULL);
    assert(plan != NULL);
    assert(plan->num_tasks > 0);

    bool all_assigned = true;
    for (size_t i = 0; i < plan->num_tasks; i++) {
        qihse_hw_backend_t b = plan->tasks[i].selected_backend;
        if (b < QIHSE_HW_BACKEND_SCALAR || b > QIHSE_HW_BACKEND_BLAS) {
            all_assigned = false;
        }
        assert(plan->tasks[i].estimated_payload_bytes > 0);
        printf("  -> task %zu: type=%d backend=%s payload=%zu bytes\n",
               i, plan->tasks[i].task_type, qihse_hw_backend_name(b),
               plan->tasks[i].estimated_payload_bytes);
    }
    assert(all_assigned);

    qihse_dist_plan_free(plan);
    qihse_dist_planner_destroy(planner);
    qihse_cluster_topology_destroy(topo);
}

/* ------------------------------------------------------------------ */
/*  Test 6: explicit dispatch_backend API records payload + backend    */
/* ------------------------------------------------------------------ */
static void test_explicit_dispatch_backend_api(void) {
    printf("Testing explicit qihse_dist_planner_dispatch_backend API...\n");

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    add_helper_node(topo, "alpha", "10.0.0.1", 7000, true);
    qihse_dist_planner_t* planner = qihse_dist_planner_create(topo);

    qihse_cache_topology_t cache = {
        .cache_line_size = 64,
        .l1_data_size    = 32 * 1024,
        .l2_size         = 256 * 1024,
        .l3_size         = 2 * 1024 * 1024,
        .numa_nodes      = 1
    };
    qihse_hw_profile_t* p = qihse_hw_profile_create_from(
        QIHSE_CPU_FEATURE_SSE4_2 | QIHSE_CPU_FEATURE_AVX2, &cache, false);
    qihse_dist_planner_set_hw_profile(planner, p);

    /* KV point lookup: tiny payload -> scalar. */
    qihse_shard_task_t kv_task;
    memset(&kv_task, 0, sizeof(kv_task));
    kv_task.task_type = QIHSE_TASK_KV_POINT;
    assert(qihse_dist_planner_dispatch_backend(planner, &kv_task) == QIHSE_HW_BACKEND_SCALAR);
    assert(kv_task.selected_backend == QIHSE_HW_BACKEND_SCALAR);
    assert(kv_task.estimated_payload_bytes > 0);

    /* Vector search: top_k=32, dims=128 -> 32*128*4 = 16384 bytes
     * (>= L1/4=8192 and < L1=32768 -> L1-resident -> SSE4.2). */
    qihse_shard_task_t vec_task;
    memset(&vec_task, 0, sizeof(vec_task));
    vec_task.task_type = QIHSE_TASK_VECTOR_SEARCH;
    vec_task.vector_dims = 128;
    vec_task.top_k = 32;
    qihse_hw_backend_t vb = qihse_dist_planner_dispatch_backend(planner, &vec_task);
    assert(vb == QIHSE_HW_BACKEND_SSE42);
    assert(vec_task.estimated_payload_bytes == 32 * 128 * sizeof(float));

    /* Large vector search: top_k=4096, dims=512 -> 4096*512*4 = 8 MiB (>= L2 -> AVX2). */
    qihse_shard_task_t bulk_task;
    memset(&bulk_task, 0, sizeof(bulk_task));
    bulk_task.task_type = QIHSE_TASK_VECTOR_SEARCH;
    bulk_task.vector_dims = 512;
    bulk_task.top_k = 4096;
    assert(qihse_dist_planner_dispatch_backend(planner, &bulk_task) == QIHSE_HW_BACKEND_AVX2);

    /* Explicit payload hint overrides the heuristic. */
    qihse_shard_task_t hinted;
    memset(&hinted, 0, sizeof(hinted));
    hinted.task_type = QIHSE_TASK_COL_SCAN;
    hinted.estimated_payload_bytes = 64; /* tiny -> scalar */
    assert(qihse_dist_planner_dispatch_backend(planner, &hinted) == QIHSE_HW_BACKEND_SCALAR);

    printf("  -> KV=scalar, vec(L1)=sse4.2, vec(bulk)=avx2, hint honoured OK\n");

    qihse_dist_planner_destroy(planner);
    qihse_cluster_topology_destroy(topo);
}

/* ------------------------------------------------------------------ */
/*  Test 7: NULL-safe dispatch (no profile, no planner)                */
/* ------------------------------------------------------------------ */
static void test_null_safety(void) {
    printf("Testing NULL-safety of dispatcher...\n");
    assert(qihse_hw_select_backend(NULL, 1024, 128) == QIHSE_HW_BACKEND_SCALAR);
    assert(qihse_dist_planner_dispatch_backend(NULL, NULL) == QIHSE_HW_BACKEND_SCALAR);

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    add_helper_node(topo, "alpha", "10.0.0.1", 7000, true);
    qihse_dist_planner_t* planner = qihse_dist_planner_create(topo);

    /* No profile attached: dispatch must still succeed via auto-detect. */
    qihse_shard_task_t task;
    memset(&task, 0, sizeof(task));
    task.task_type = QIHSE_TASK_KV_POINT;
    qihse_hw_backend_t b = qihse_dist_planner_dispatch_backend(planner, &task);
    assert(b >= QIHSE_HW_BACKEND_SCALAR && b <= QIHSE_HW_BACKEND_BLAS);
    assert(task.selected_backend == b);

    printf("  -> NULL profile auto-detected, backend=%s OK\n", qihse_hw_backend_name(b));

    qihse_dist_planner_destroy(planner);
    qihse_cluster_topology_destroy(topo);
}

/* ------------------------------------------------------------------ */
/*  Test 8: backend name coverage                                      */
/* ------------------------------------------------------------------ */
static void test_backend_name_coverage(void) {
    printf("Testing backend name coverage...\n");
    assert(strcmp(qihse_hw_backend_name(QIHSE_HW_BACKEND_SCALAR), "scalar") == 0);
    assert(strcmp(qihse_hw_backend_name(QIHSE_HW_BACKEND_SSE42),  "sse4.2") == 0);
    assert(strcmp(qihse_hw_backend_name(QIHSE_HW_BACKEND_AVX),    "avx")    == 0);
    assert(strcmp(qihse_hw_backend_name(QIHSE_HW_BACKEND_AVX2),   "avx2")   == 0);
    assert(strcmp(qihse_hw_backend_name(QIHSE_HW_BACKEND_AVX512), "avx512") == 0);
    assert(strcmp(qihse_hw_backend_name(QIHSE_HW_BACKEND_BLAS),   "blas")   == 0);
    printf("  -> all backend names resolved OK\n");
}

/* ------------------------------------------------------------------ */
/*  Test 9: existing dist planner still works (regression)             */
/* ------------------------------------------------------------------ */
static void test_existing_planner_regression(void) {
    printf("Testing existing planner behaviour regression...\n");
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    add_helper_node(topo, "alpha", "10.0.0.1", 7000, true);

    qihse_dist_planner_t* planner = qihse_dist_planner_create(topo);
    const char* sql = "SELECT * FROM {device_4096} WHERE vector_search(embedding, top_k=10)";
    qihse_dist_plan_t* plan = qihse_dist_plan_query(planner, sql, NULL);
    assert(plan != NULL);
    assert(!plan->is_scatter_gather);
    assert(plan->num_tasks == 1);
    assert(plan->tasks[0].task_type == QIHSE_TASK_VECTOR_SEARCH);
    assert(strcmp(plan->tasks[0].target_entity, "{device_4096}") == 0);
    assert(plan->merge_strategy == QIHSE_MERGE_RRF);
    /* New field must be populated even without an explicit profile. */
    assert(plan->tasks[0].selected_backend >= QIHSE_HW_BACKEND_SCALAR);
    assert(plan->tasks[0].selected_backend <= QIHSE_HW_BACKEND_BLAS);

    printf("  -> regression OK (backend=%s)\n",
           qihse_hw_backend_name(plan->tasks[0].selected_backend));

    qihse_dist_plan_free(plan);
    qihse_dist_planner_destroy(planner);
    qihse_cluster_topology_destroy(topo);
}

int main(void) {
    printf("============================================================\n");
    printf("  QIHSE Idea 4 — Adaptive Hardware Backend Dispatcher Tests \n");
    printf("============================================================\n");

    test_host_profile_autodetect();
    test_payload_size_dispatch();
    test_scalar_only_fallback();
    test_avx512_bulk_preference();
    test_planner_attaches_profile_and_dispatches();
    test_explicit_dispatch_backend_api();
    test_null_safety();
    test_backend_name_coverage();
    test_existing_planner_regression();

    printf("\nAll Adaptive Hardware Backend Dispatcher Tests PASSED!\n");
    return 0;
}
