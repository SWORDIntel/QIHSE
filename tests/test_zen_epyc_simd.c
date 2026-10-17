/*
 * QIHSE - Zen 4 & Zen 2 SIMD / Hardware Instruction Set Verification Test
 *
 * Verifies:
 * 1. Runtime CPU feature detection & helper functions (SHANI, VPOPCNTDQ, CLZERO, CLWB, RDPID, etc.)
 * 2. Signal safety of safe_execute_test() across all 13 new instruction sets
 * 3. Hardware cache utilities (qihse_cache_zero_64, qihse_cache_writeback, qihse_get_cpu_id)
 * 4. Hardware SHA-NI block transform acceleration
 * 5. Vector DB AVX512 VPOPCNTDQ Hamming distance & VNNI INT8 dot product
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>

#include "backends/cpu/qihse_cpu_detect.h"
#include "include/backends/cpu/qihse_cpu_cache.h"
#include "include/qihse_sha256_shani.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
        exit(1); \
    } \
} while(0)

static void test_feature_detection_and_names(void) {
    printf("[1/5] Testing CPU feature detection, bitmasks, names and descriptions...\n");
    qihse_cpu_info_t info = qihse_cpu_detect();
    qihse_cpu_feature_t feats = qihse_cpu_detect_features();
    TEST_ASSERT(info.features == feats, "info.features must match qihse_cpu_detect_features()");

    qihse_cpu_feature_t new_features[] = {
        QIHSE_CPU_FEATURE_SHANI,
        QIHSE_CPU_FEATURE_AVX512VPOPCNTDQ,
        QIHSE_CPU_FEATURE_VPCLMUL,
        QIHSE_CPU_FEATURE_VAES,
        QIHSE_CPU_FEATURE_AVX512BITALG,
        QIHSE_CPU_FEATURE_AVX512VBMI,
        QIHSE_CPU_FEATURE_AVX512VBMI2,
        QIHSE_CPU_FEATURE_AVX512IFMA,
        QIHSE_CPU_FEATURE_GFNI,
        QIHSE_CPU_FEATURE_CLZERO,
        QIHSE_CPU_FEATURE_CLWB,
        QIHSE_CPU_FEATURE_RDPID,
        QIHSE_CPU_FEATURE_CX16
    };

    size_t count = sizeof(new_features) / sizeof(new_features[0]);
    for (size_t i = 0; i < count; i++) {
        const char* name = qihse_cpu_feature_name(new_features[i]);
        const char* desc = qihse_cpu_feature_description(new_features[i]);
        TEST_ASSERT(name != NULL && strcmp(name, "UNKNOWN") != 0, "Feature name must not be UNKNOWN");
        TEST_ASSERT(desc != NULL && strcmp(desc, "Unknown CPU feature") != 0, "Feature description must be valid");
        printf("    Feature 0x%012llx: %-18s -> %s\n", (unsigned long long)new_features[i], name, desc);
    }

    /* Test helper functions */
    TEST_ASSERT(qihse_cpu_has_shani(&info) == ((info.features & QIHSE_CPU_FEATURE_SHANI) != 0), "qihse_cpu_has_shani parity");
    TEST_ASSERT(qihse_cpu_has_clzero(&info) == ((info.features & QIHSE_CPU_FEATURE_CLZERO) != 0), "qihse_cpu_has_clzero parity");
    TEST_ASSERT(qihse_cpu_has_clwb(&info) == ((info.features & QIHSE_CPU_FEATURE_CLWB) != 0), "qihse_cpu_has_clwb parity");
    TEST_ASSERT(qihse_cpu_has_rdpid(&info) == ((info.features & QIHSE_CPU_FEATURE_RDPID) != 0), "qihse_cpu_has_rdpid parity");
    TEST_ASSERT(qihse_cpu_has_cx16(&info) == ((info.features & QIHSE_CPU_FEATURE_CX16) != 0), "qihse_cpu_has_cx16 parity");
    TEST_ASSERT(qihse_cpu_has_gfni(&info) == ((info.features & QIHSE_CPU_FEATURE_GFNI) != 0), "qihse_cpu_has_gfni parity");

    printf("  -> Feature detection and helper functions OK\n");
}

static void test_signal_safe_tests(void) {
    printf("[2/5] Testing execution safety of all 13 instruction test functions...\n");

    /* None of these test functions may crash when invoked, even on older host CPU */
    bool ok_shani = qihse_cpu_safe_execute_test(qihse_cpu_test_shani);
    bool ok_vpopcnt = qihse_cpu_safe_execute_test(qihse_cpu_test_avx512vpopcntdq);
    bool ok_vpclmul = qihse_cpu_safe_execute_test(qihse_cpu_test_vpclmul);
    bool ok_vaes = qihse_cpu_safe_execute_test(qihse_cpu_test_vaes);
    bool ok_bitalg = qihse_cpu_safe_execute_test(qihse_cpu_test_avx512bitalg);
    bool ok_vbmi = qihse_cpu_safe_execute_test(qihse_cpu_test_avx512vbmi);
    bool ok_vbmi2 = qihse_cpu_safe_execute_test(qihse_cpu_test_avx512vbmi2);
    bool ok_ifma = qihse_cpu_safe_execute_test(qihse_cpu_test_avx512ifma);
    bool ok_gfni = qihse_cpu_safe_execute_test(qihse_cpu_test_gfni);
    bool ok_clzero = qihse_cpu_safe_execute_test(qihse_cpu_test_clzero);
    bool ok_clwb = qihse_cpu_safe_execute_test(qihse_cpu_test_clwb);
    bool ok_rdpid = qihse_cpu_safe_execute_test(qihse_cpu_test_rdpid);
    bool ok_cx16 = qihse_cpu_safe_execute_test(qihse_cpu_test_cx16);

    printf("    Instruction test results (host execution): \n"
           "      SHANI: %d, AVX512VPOPCNTDQ: %d, VPCLMUL: %d, VAES: %d\n"
           "      BITALG: %d, VBMI: %d, VBMI2: %d, IFMA: %d, GFNI: %d\n"
           "      CLZERO: %d, CLWB: %d, RDPID: %d, CX16: %d\n",
           ok_shani, ok_vpopcnt, ok_vpclmul, ok_vaes,
           ok_bitalg, ok_vbmi, ok_vbmi2, ok_ifma, ok_gfni,
           ok_clzero, ok_clwb, ok_rdpid, ok_cx16);

    printf("  -> Signal safe execution tests passed without crashes\n");
}

static void test_hardware_cache_utilities(void) {
    printf("[3/5] Testing hardware cache and core identification utilities...\n");

    /* 1. qihse_cache_zero_64 */
    uint8_t buffer[128] __attribute__((aligned(64)));
    memset(buffer, 0xAA, sizeof(buffer));
    qihse_cache_zero_64(buffer);
    for (int i = 0; i < 64; i++) {
        TEST_ASSERT(buffer[i] == 0x00, "qihse_cache_zero_64 must zero first 64 bytes");
    }
    for (int i = 64; i < 128; i++) {
        TEST_ASSERT(buffer[i] == 0xAA, "qihse_cache_zero_64 must not overwrite beyond 64 bytes");
    }
    printf("    qihse_cache_zero_64: 64 bytes successfully zeroed\n");

    /* 2. qihse_cache_writeback */
    qihse_cache_writeback(buffer);
    printf("    qihse_cache_writeback: executed cleanly\n");

    /* 3. qihse_get_cpu_id */
    uint32_t node_id = 0xFFFF;
    int cpu_id = qihse_get_cpu_id(&node_id);
    TEST_ASSERT(cpu_id >= 0, "qihse_get_cpu_id must return non-negative CPU id");
    printf("    qihse_get_cpu_id: cpu=%d, node=%u\n", cpu_id, node_id);

    printf("  -> Cache and sync utilities OK\n");
}

static void test_sha256_shani(void) {
    printf("[4/5] Testing SHA-NI transform verification...\n");
    qihse_cpu_info_t info = qihse_cpu_detect();
    if (qihse_cpu_has_shani(&info)) {
        printf("    Host CPU supports SHA-NI! Running hardware accelerated transform...\n");
        uint8_t block[64];
        memset(block, 0x00, sizeof(block));
        block[0] = 0x80;

        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        qihse_sha256_shani_transform(state, block);
        uint8_t b0 = (uint8_t)(state[0] >> 24);
        uint8_t b1 = (uint8_t)(state[0] >> 16);
        uint8_t b2 = (uint8_t)(state[0] >> 8);
        uint8_t b3 = (uint8_t)(state[0] >> 0);

        TEST_ASSERT(b0 == 0xE3 && b1 == 0xB0 && b2 == 0xC4 && b3 == 0x42, "SHA-256 state output must match standard");
        printf("    SHA-NI empty message hash matched expected 0xE3B0C442!\n");
    } else {
        printf("    Host CPU lacks SHA-NI; verified clean runtime gating (no SIGILL triggered)\n");
    }
    printf("  -> SHA-NI transform verification OK\n");
}

static void test_vector_db_simd(void) {
    printf("[5/5] Testing Vector DB SIMD distance and dot product dispatch...\n");

    /* Per-test audit/chain isolation */
    char qdd[] = "/tmp/qihse_zen_simd_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);

    const char* password = "ZenSimdTestAuthPassword123!";
    TEST_ASSERT(qihse_auth_init(), "qihse_auth_init failed");
    qihse_auth_bootstrap_operator(password);
    qihse_user_t* user = qihse_auth_authenticate_id(0, password);
    TEST_ASSERT(user != NULL, "Operator authentication failed");

    const char* test_path = "/tmp/qihse_simd_test.vdb";
    qihse_vector_db_t db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, test_path,
                                                QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_TRUNCATE);
    TEST_ASSERT(db != NULL, "qihse_vector_db_open failed");

    float vectors[2 * 128];
    uint64_t ids[2] = {1001u, 1002u};
    for (int i = 0; i < 128; i++) {
        vectors[i] = (float)(i % 10 - 5);
        vectors[128 + i] = (float)(i % 7 - 3);
    }

    TEST_ASSERT(qihse_vector_db_add_vectors(db, vectors, 2u, 128u, ids, NULL, NULL), "add_vectors failed");

    /* Search query vector */
    qihse_vector_query_t query;
    memset(&query, 0, sizeof(query));
    query.query_vector = vectors;
    query.vector_dims = 128u;
    query.top_k = 2;
    query.distance_metric = QIHSE_DISTANCE_EUCLIDEAN;
    query.similarity_threshold = -1e9f;
    query.user = user;

    qihse_vector_result_t results[2];
    int count = qihse_vector_db_search(db, &query, results, 2);
    TEST_ASSERT(count > 0, "qihse_vector_db_search returned no results");
    TEST_ASSERT(results[0].id == 1001u, "Top match must be vector 1001");

    /* Test INT8 sidecar acceleration (exercises qihse_vdb_int8_dot_product) */
    TEST_ASSERT(qihse_vector_db_build_int8(db), "build_int8 failed");
    query.query_mode = QIHSE_VDB_QUERY_INT8;
    int int8_count = qihse_vector_db_search(db, &query, results, 2);
    TEST_ASSERT(int8_count > 0, "INT8 search returned no results");
    TEST_ASSERT(results[0].id == 1001u, "Top INT8 match must be vector 1001");
    printf("    INT8 sidecar & dot product dispatch: PASS\n");

    /* Test Binary sidecar acceleration (exercises qihse_vdb_hamming_distance) */
    TEST_ASSERT(qihse_vector_db_build_binary(db), "build_binary failed");
    int bin_count = qihse_vector_db_search_binary_candidates(db, &query, 2, results, 2);
    TEST_ASSERT(bin_count > 0, "binary candidate search returned no results");
    TEST_ASSERT(results[0].id == 1001u, "Top binary candidate match must be vector 1001");
    printf("    Binary sidecar & Hamming distance dispatch: PASS\n");

    qihse_vector_db_close(db);
    unlink(test_path);
    printf("  -> Vector DB SIMD distance dispatch OK\n");
}

int main(void) {
    printf("============================================================\n");
    printf("  QIHSE Zen 4 (Ryzen 9 7950X) & Zen 2 (EPYC 7662) SIMD Tests \n");
    printf("============================================================\n");

    test_feature_detection_and_names();
    test_signal_safe_tests();
    test_hardware_cache_utilities();
    test_sha256_shani();
    test_vector_db_simd();

    printf("============================================================\n");
    printf("  All Zen 4 & Zen 2 SIMD / Instruction Set Tests PASSED!     \n");
    printf("============================================================\n");
    return 0;
}
