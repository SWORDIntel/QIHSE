#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../core/qihse_abi.h"
#include "../memory/include/qihse_memory.h"
#include "../qihse_vector_db.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Forward declarations for the PR-1 persistence API. The declarations are
 * intentionally repeated here while the test lands separately from the header
 * update; they must match qihse_vector_db.h when the implementation is wired.
 */
qihse_vector_db_t qihse_vector_db_open(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path,
    uint32_t flags
);
bool qihse_vector_db_flush(qihse_vector_db_t vdb);
bool qihse_vector_db_checkpoint(qihse_vector_db_t vdb);
bool qihse_vector_db_compact(qihse_vector_db_t vdb);
bool qihse_vector_db_close(qihse_vector_db_t vdb);

#define QIHSE_TEST_OPEN_CREATE      (1u << 0)
#define QIHSE_TEST_OPEN_READ_ONLY   (1u << 1)
#define QIHSE_TEST_OPEN_TRUNCATE    (1u << 2)
#define QIHSE_TEST_OPEN_FILE_BACKED (1u << 3)
#define QIHSE_TEST_OPEN_MMAP        (1u << 4)

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            return false; \
        } \
    } while (0)

typedef struct test_env_s {
    qihse_context_t ctx;
    qihse_memory_manager_t memory;
    qihse_uma_manager_t uma;
} test_env_t;

typedef struct test_case_s {
    const char* name;
    bool (*fn)(void);
} test_case_t;

static bool env_init(test_env_t* env);
static void env_destroy(test_env_t* env);
static char* make_temp_db_path(const char* name);
static void remove_tree(const char* path);
static void free_results(qihse_vector_result_t* results, size_t count);
static bool add_one(qihse_vector_db_t vdb,
                    const float* vector,
                    size_t dims,
                    uint64_t id,
                    const void* metadata,
                    size_t metadata_size);
static int search_one(qihse_vector_db_t vdb,
                      const float* query_vector,
                      size_t dims,
                      bool include_vector,
                      bool include_metadata,
                      qihse_vector_result_t* result);
static bool close_db(qihse_vector_db_t vdb);
static bool float_eq(float a, float b);
static bool vector_eq(const float* a, const float* b, size_t dims);
static bool corrupt_file_byte(const char* dir, const char* name, off_t offset, uint8_t value);
static bool truncate_file_to(const char* dir, const char* name, off_t size);
static bool file_size_of(const char* dir, const char* name, off_t* out_size);
static bool write_file_u64le_at(const char* dir, const char* name, off_t offset, uint64_t value);
static bool write_file_payload(const char* dir,
                               const char* name,
                               const uint8_t* payload,
                               size_t payload_size);
static bool read_file_payload(const char* dir,
                              const char* name,
                              uint8_t** out_payload,
                              size_t* out_payload_size);
static bool write_qtri_payload(const char* dir, const uint8_t* payload, size_t payload_size);

static bool test_create_insert_close_reopen_search(void);
static bool test_sparse_ids_hydrate_vector_and_metadata(void);
static bool test_binary_metadata_survives_restart(void);
static bool test_null_db_path_ephemeral_searchable(void);
static bool test_wal_replays_unflushed_add(void);
static bool test_wal_replays_unflushed_delete_update_upsert(void);
static bool test_torn_wal_tail_ignored_and_truncated(void);
static bool test_checkpoint_publishes_snapshot_and_clears_wal(void);
static bool test_checkpoint_ignores_stale_complete_wal(void);
static bool test_read_only_mmap_reopen_searches(void);
static bool test_corrupt_vectors_qvec_magic_rejected(void);
static bool test_truncated_vectors_qvec_payload_rejected(void);
static bool test_corrupt_metadata_qmeta_rejected(void);
static bool test_truncated_metadata_qmeta_payload_rejected(void);
static bool test_corrupt_index_qidx_magic_rejected(void);
static bool test_corrupt_index_qidx_count_mismatch_rejected(void);
static bool test_corrupt_index_qidx_row_bytes_rejected(void);
static bool test_legacy_manifest_index_row_mismatch_rejected(void);
static bool test_manifest_index_checksum_mismatch_rejected(void);
static bool test_partial_compaction_tmp_fallback_on_restart(void);
static bool test_truncated_index_qidx_rejected(void);
static bool test_truncated_manifest_rejected(void);
static bool test_stale_manifest_tmp_ignored_after_checkpoint(void);
static bool test_stale_snapshot_tmp_files_ignored_after_checkpoint(void);
static bool test_manifest_rejects_impossible_qmag_shape(void);
static bool test_read_only_open_searches_and_rejects_add(void);
static bool test_duplicate_vector_id_rejected(void);
static bool test_corrupt_idmap_rebuilds_high_ids(void);
static bool test_invalid_idmap_row_index_rebuilds_on_reopen(void);
static bool test_missing_vectors_qtri_accepted(void);
static bool test_corrupt_vectors_qtri_accepted_and_reported(void);
static bool test_trinary_candidate_search_matches_float32_top_ids(void);
static bool test_trinary_rerank_hydrates_requested_payloads(void);
static bool test_default_search_ignores_missing_or_corrupt_qtri(void);
static bool test_trinary_candidate_search_rejects_missing_or_corrupt_qtri(void);
static bool test_trinary_candidate_search_validates_counts(void);
static bool test_explicit_scalar_default_candidate_pool_searches(void);
static bool test_tombstone_heavy_small_qtri_pool_skips_deleted_rows(void);
static bool test_scalar_default_pool_handles_positive_sign_collapse(void);
static bool test_qmag_sidecar_persists_and_magnitude_query_matches_float32(void);
static bool test_qmag_default_candidate_pool_searches(void);
static bool test_qmag_sparse_default_policy_matches_float32(void);
static bool test_qmag_dense_default_policy_matches_float32(void);
static bool test_qmag_adaptive_pool_top_k_boundaries(void);
static bool test_qmag_100_case_small_row_default_falls_back_to_float32(void);
static bool test_qmag_100_case_dense_high_active_default_falls_back_to_float32(void);
static bool test_qmag_100_case_sparse_low_pressure_default_matches_float32(void);
static bool test_qmag_100_case_explicit_pool_runs_when_default_falls_back(void);
static bool test_qmag_low_active_low_top_k_default_policy_matches_float32(void);
static bool test_qmag_high_top_k_default_policy_falls_back_to_float32(void);
static bool test_explicit_qmag_pool_bypasses_default_performance_gate(void);
static bool test_default_search_ignores_missing_or_corrupt_qmag(void);
static bool test_qmag_stale_reported_and_opt_in_rejected(void);
static bool test_qmag_mutations_compact_and_reopen_refresh_candidates(void);
static bool test_tombstone_heavy_small_qmag_pool_skips_deleted_and_old_rows(void);
static bool test_old_128_byte_manifest_opens_with_qmag_absent(void);
static bool test_delete_by_id_persists_across_reopen(void);
static bool test_update_by_id_replaces_vector_and_metadata(void);
static bool test_upsert_by_ids_reports_insert_and_update_counts(void);
static bool test_read_only_open_rejects_mutations(void);
static bool test_compact_preserves_live_rows_after_mutations(void);
static bool test_compact_counts_after_delete_update_current_snapshot(void);
static bool test_compact_rebuilds_high_id_idmap_consistency(void);
static bool test_compact_rewrites_qtri_sidecar_valid(void);
static bool test_compact_rebuilds_corrupt_derived_sidecars(void);
static bool test_compact_ignores_stale_tmp_files(void);
static bool test_wal_mutations_compact_clear_wal_and_prune(void);

int main(void) {
    const test_case_t tests[] = {
        {"create -> insert -> close -> reopen -> search",
         test_create_insert_close_reopen_search},
        {"sparse IDs hydrate correct vector and metadata",
         test_sparse_ids_hydrate_vector_and_metadata},
        {"binary metadata survives restart byte-for-byte",
         test_binary_metadata_survives_restart},
        {"db_path == NULL remains ephemeral and searchable in-process",
         test_null_db_path_ephemeral_searchable},
        {"WAL replays an accepted add before snapshot flush",
         test_wal_replays_unflushed_add},
        {"WAL replays unflushed delete/update/upsert mutations",
         test_wal_replays_unflushed_delete_update_upsert},
        {"torn WAL tail is ignored and truncated on writable open",
         test_torn_wal_tail_ignored_and_truncated},
        {"checkpoint publishes snapshot and clears WAL",
         test_checkpoint_publishes_snapshot_and_clears_wal},
        {"checkpointed snapshot ignores stale complete WAL",
         test_checkpoint_ignores_stale_complete_wal},
        {"read-only mmap reopen searches mapped vector file",
         test_read_only_mmap_reopen_searches},
        {"corrupt vectors.qvec magic fails open cleanly",
         test_corrupt_vectors_qvec_magic_rejected},
        {"truncated vectors.qvec payload fails open cleanly",
         test_truncated_vectors_qvec_payload_rejected},
        {"corrupt metadata.qmeta fails open cleanly",
         test_corrupt_metadata_qmeta_rejected},
        {"truncated metadata.qmeta payload fails open cleanly",
         test_truncated_metadata_qmeta_payload_rejected},
        {"corrupt index.qidx magic fails open cleanly",
         test_corrupt_index_qidx_magic_rejected},
        {"index.qidx row-count mismatch rejects open",
         test_corrupt_index_qidx_count_mismatch_rejected},
        {"index.qidx row-bytes mismatch rejects open",
         test_corrupt_index_qidx_row_bytes_rejected},
        {"legacy (128-byte) MANIFEST rejects mismatched index row metadata",
         test_legacy_manifest_index_row_mismatch_rejected},
        {"manifest/index checksum mismatch rejects open",
         test_manifest_index_checksum_mismatch_rejected},
        {"partial compaction write.tmp artifacts fall back to last valid snapshot",
         test_partial_compaction_tmp_fallback_on_restart},
        {"truncated index.qidx fails open cleanly",
         test_truncated_index_qidx_rejected},
        {"truncated manifest fails open cleanly",
         test_truncated_manifest_rejected},
        {"stale MANIFEST.tmp is ignored after checkpoint",
         test_stale_manifest_tmp_ignored_after_checkpoint},
        {"stale snapshot tmp files are ignored after checkpoint",
         test_stale_snapshot_tmp_files_ignored_after_checkpoint},
        {"manifest rejects impossible qmag metadata",
         test_manifest_rejects_impossible_qmag_shape},
        {"read-only open can search but rejects add_vectors",
         test_read_only_open_searches_and_rejects_add},
        {"duplicate vector_id rejected",
         test_duplicate_vector_id_rejected},
        {"corrupt idmap.qid rebuilds and high IDs survive",
         test_corrupt_idmap_rebuilds_high_ids},
        {"invalid idmap row index rebuilds on reopen",
         test_invalid_idmap_row_index_rebuilds_on_reopen},
        {"missing vectors.qtri accepted for FLOAT32 DB",
         test_missing_vectors_qtri_accepted},
        {"corrupt vectors.qtri is accepted but reported unavailable",
         test_corrupt_vectors_qtri_accepted_and_reported},
        {"PR-5 qtri candidate search matches FLOAT32 top IDs",
         test_trinary_candidate_search_matches_float32_top_ids},
        {"PR-5 trinary rerank hydrates requested vectors and metadata",
         test_trinary_rerank_hydrates_requested_payloads},
        {"PR-5 default search ignores missing/corrupt qtri",
         test_default_search_ignores_missing_or_corrupt_qtri},
        {"PR-5 opt-in qtri search rejects missing/corrupt qtri",
         test_trinary_candidate_search_rejects_missing_or_corrupt_qtri},
        {"PR-5 qtri candidate search validates candidate_count/top_k",
         test_trinary_candidate_search_validates_counts},
        {"explicit scalar default candidate pool searches",
         test_explicit_scalar_default_candidate_pool_searches},
        {"tombstone-heavy rows with explicit small qtri pool search live row",
         test_tombstone_heavy_small_qtri_pool_skips_deleted_rows},
        {"scalar default pool handles positive sign collapse",
         test_scalar_default_pool_handles_positive_sign_collapse},
        {"PR-6 qmag sidecar persists and magnitude query matches FLOAT32",
         test_qmag_sidecar_persists_and_magnitude_query_matches_float32},
        {"qmag default candidate pool searches",
         test_qmag_default_candidate_pool_searches},
        {"qmag sparse default policy preserves FLOAT32 results",
         test_qmag_sparse_default_policy_matches_float32},
        {"qmag dense default policy falls back safely or preserves FLOAT32 results",
         test_qmag_dense_default_policy_matches_float32},
        {"qmag adaptive default pool handles top_k boundaries",
         test_qmag_adaptive_pool_top_k_boundaries},
        {"qmag 100-case small-row default falls back to FLOAT32-equivalent results",
         test_qmag_100_case_small_row_default_falls_back_to_float32},
        {"qmag 100-case dense/high-active default falls back to FLOAT32-equivalent results",
         test_qmag_100_case_dense_high_active_default_falls_back_to_float32},
        {"qmag 100-case sparse low-pressure default remains FLOAT32-equivalent",
         test_qmag_100_case_sparse_low_pressure_default_matches_float32},
        {"qmag 100-case explicit pool runs when default policy would fall back",
         test_qmag_100_case_explicit_pool_runs_when_default_falls_back},
        {"qmag low-active low-top_k default policy preserves FLOAT32 results",
         test_qmag_low_active_low_top_k_default_policy_matches_float32},
        {"qmag high-top_k default policy falls back to FLOAT32 results",
         test_qmag_high_top_k_default_policy_falls_back_to_float32},
        {"explicit qmag pool bypasses default performance gate",
         test_explicit_qmag_pool_bypasses_default_performance_gate},
        {"PR-6 default search ignores missing/corrupt qmag",
         test_default_search_ignores_missing_or_corrupt_qmag},
        {"PR-6 qmag stale sidecar is reported and rejected for opt-in search",
         test_qmag_stale_reported_and_opt_in_rejected},
        {"PR-6 qmag mutations compact and reopen refresh candidate cache",
         test_qmag_mutations_compact_and_reopen_refresh_candidates},
        {"explicit small qmag pool does not return tombstoned rows",
         test_tombstone_heavy_small_qmag_pool_skips_deleted_and_old_rows},
        {"PR-6 old 128-byte manifest opens with qmag absent",
         test_old_128_byte_manifest_opens_with_qmag_absent},
        {"delete_by_id persists across reopen",
         test_delete_by_id_persists_across_reopen},
        {"update_by_id replaces vector and metadata",
         test_update_by_id_replaces_vector_and_metadata},
        {"upsert_by_ids reports insert/update counts",
         test_upsert_by_ids_reports_insert_and_update_counts},
        {"read-only open rejects mutation APIs",
         test_read_only_open_rejects_mutations},
        {"compact preserves live rows after mutations",
         test_compact_preserves_live_rows_after_mutations},
        {"compact reports delete/update row and index counts",
         test_compact_counts_after_delete_update_current_snapshot},
        {"compact rebuilds idmap consistently with high IDs",
         test_compact_rebuilds_high_id_idmap_consistency},
        {"compact rewrites a valid vectors.qtri sidecar",
         test_compact_rewrites_qtri_sidecar_valid},
        {"compact rebuilds stale/corrupt derived sidecars",
         test_compact_rebuilds_corrupt_derived_sidecars},
        {"compact ignores stale tmp files on reopen",
         test_compact_ignores_stale_tmp_files},
        {"WAL mutations compact clears WAL and prunes rows",
         test_wal_mutations_compact_clear_wal_and_prune},
    };

    for (size_t i = 0; i < ARRAY_LEN(tests); i++) {
        printf("RUN  %s\n", tests[i].name);
        if (!tests[i].fn()) {
            printf("FAIL %s\n", tests[i].name);
            return 1;
        }
        printf("PASS %s\n", tests[i].name);
    }

    printf("PASS all qihse vector DB persistence tests\n");
    return 0;
}

static bool env_init(test_env_t* env) {
    memset(env, 0, sizeof(*env));

    if (qihse_context_create(NULL, &env->ctx) != QIHSE_OK) {
        return false;
    }

    env->memory = qihse_memory_manager_create(env->ctx, "uma");
    if (!env->memory) {
        env_destroy(env);
        return false;
    }

    env->uma = qihse_uma_create(env->memory, QIHSE_UMA_MIGRATE_ON_ACCESS);
    if (!env->uma) {
        env_destroy(env);
        return false;
    }

    return true;
}

static void env_destroy(test_env_t* env) {
    if (!env) {
        return;
    }
    if (env->uma) {
        qihse_uma_destroy(env->uma);
    }
    if (env->memory) {
        qihse_memory_manager_destroy(env->memory);
    }
    if (env->ctx) {
        qihse_context_destroy(env->ctx);
    }
    memset(env, 0, sizeof(*env));
}

static char* make_temp_db_path(const char* name) {
    char template_path[256];
    snprintf(template_path, sizeof(template_path), "/tmp/qihse_%s_XXXXXX", name);

    char* path = strdup(template_path);
    if (!path) {
        return NULL;
    }
    if (!mkdtemp(path)) {
        free(path);
        return NULL;
    }

    remove_tree(path);
    return path;
}

static void remove_tree(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) {
        return;
    }

    struct dirent* entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char child[512];
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(child, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            remove_tree(child);
        } else {
            unlink(child);
        }
    }

    closedir(dir);
    rmdir(path);
}

static void free_results(qihse_vector_result_t* results, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(results[i].vector);
        free(results[i].metadata);
        results[i].vector = NULL;
        results[i].metadata = NULL;
    }
}

static bool add_one(qihse_vector_db_t vdb,
                    const float* vector,
                    size_t dims,
                    uint64_t id,
                    const void* metadata,
                    size_t metadata_size) {
    const uint64_t ids[] = {id};
    const void* metadata_items[] = {metadata};
    const size_t metadata_sizes[] = {metadata_size};

    return qihse_vector_db_add_vectors(
        vdb,
        vector,
        1,
        dims,
        ids,
        metadata ? metadata_items : NULL,
        metadata ? metadata_sizes : NULL
    );
}

static int search_one(qihse_vector_db_t vdb,
                      const float* query_vector,
                      size_t dims,
                      bool include_vector,
                      bool include_metadata,
                      qihse_vector_result_t* result) {
    memset(result, 0, sizeof(*result));

    qihse_vector_query_t query = {
        .query_vector = query_vector,
        .vector_dims = dims,
        .top_k = 1,
        .similarity_threshold = 0.999f,
        .include_vectors = include_vector,
        .include_metadata = include_metadata,
    };

    return qihse_vector_db_search(vdb, &query, result, 1);
}

static bool close_db(qihse_vector_db_t vdb) {
    if (!vdb) {
        return true;
    }
    TEST_ASSERT(qihse_vector_db_flush(vdb), "flush should succeed");
    TEST_ASSERT(qihse_vector_db_close(vdb), "close should succeed");
    return true;
}

static bool float_eq(float a, float b) {
    return fabsf(a - b) <= 0.00001f;
}

static bool vector_eq(const float* a, const float* b, size_t dims) {
    if (!a || !b) {
        return false;
    }
    for (size_t i = 0; i < dims; i++) {
        if (!float_eq(a[i], b[i])) {
            return false;
        }
    }
    return true;
}

static uint64_t test_fnv1a64(const void* data, size_t size) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void test_write_u32le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void test_write_u64le(uint8_t* p, uint64_t v) {
    for (size_t i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (i * 8)) & 0xffu);
    }
}

static bool test_join_path(const char* dir, const char* name, char* out, size_t out_size) {
    int written = snprintf(out, out_size, "%s/%s", dir, name);
    return written > 0 && (size_t)written < out_size;
}

static bool corrupt_file_byte(const char* dir, const char* name, off_t offset, uint8_t value) {
    char path[512];
    if (!test_join_path(dir, name, path, sizeof(path))) {
        return false;
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return false;
    }
    bool ok = pwrite(fd, &value, 1, offset) == 1;
    if (ok) ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool truncate_file_to(const char* dir, const char* name, off_t size) {
    char path[512];
    if (!test_join_path(dir, name, path, sizeof(path))) {
        return false;
    }
    return truncate(path, size) == 0;
}

static bool file_size_of(const char* dir, const char* name, off_t* out_size) {
    char path[512];
    struct stat st;

    if (!out_size || !test_join_path(dir, name, path, sizeof(path))) {
        return false;
    }
    if (stat(path, &st) != 0 || st.st_size < 0) {
        return false;
    }
    *out_size = st.st_size;
    return true;
}

static bool write_file_u64le_at(const char* dir, const char* name, off_t offset, uint64_t value) {
    char path[512];
    uint8_t bytes[8];

    if (!test_join_path(dir, name, path, sizeof(path))) {
        return false;
    }
    test_write_u64le(bytes, value);

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return false;
    }
    bool ok = pwrite(fd, bytes, sizeof(bytes), offset) == (ssize_t)sizeof(bytes);
    if (ok) ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool write_file_payload(const char* dir,
                               const char* name,
                               const uint8_t* payload,
                               size_t payload_size) {
    char path[512];

    if (!test_join_path(dir, name, path, sizeof(path)) ||
        (!payload && payload_size != 0u)) {
        return false;
    }

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        return false;
    }
    bool ok = true;
    if (payload_size != 0u) {
        ok = pwrite(fd, payload, payload_size, 0) == (ssize_t)payload_size;
    }
    if (ok) ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool read_file_payload(const char* dir,
                              const char* name,
                              uint8_t** out_payload,
                              size_t* out_payload_size) {
    char path[512];
    struct stat st;
    uint8_t* data = NULL;
    int fd = -1;
    bool ok = false;

    if (!out_payload || !out_payload_size ||
        !test_join_path(dir, name, path, sizeof(path))) {
        return false;
    }
    *out_payload = NULL;
    *out_payload_size = 0u;
    if (stat(path, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > (uint64_t)SIZE_MAX) {
        return false;
    }
    data = (uint8_t*)malloc((size_t)st.st_size ? (size_t)st.st_size : 1u);
    if (!data) {
        return false;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        free(data);
        return false;
    }
    ok = true;
    if (st.st_size != 0) {
        ok = read(fd, data, (size_t)st.st_size) == st.st_size;
    }
    if (close(fd) != 0) {
        ok = false;
    }
    if (!ok) {
        free(data);
        return false;
    }
    *out_payload = data;
    *out_payload_size = (size_t)st.st_size;
    return true;
}

static bool write_qtri_payload(const char* dir, const uint8_t* payload, size_t payload_size) {
    char path[512];
    if (!test_join_path(dir, "vectors.qtri", path, sizeof(path))) {
        return false;
    }

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        return false;
    }

    uint8_t header[64];
    memset(header, 0, sizeof(header));
    const uint8_t magic[8] = {'Q','H','T','R','I','0','1','\0'};
    memcpy(header, magic, sizeof(magic));
    test_write_u32le(header + 8, 1u);
    test_write_u32le(header + 12, 64u);
    test_write_u64le(header + 16, 7u);
    test_write_u64le(header + 24, (uint64_t)payload_size);
    test_write_u64le(header + 32, test_fnv1a64(payload, payload_size));

    bool ok = pwrite(fd, header, sizeof(header), 0) == (ssize_t)sizeof(header);
    if (ok && payload_size > 0) {
        ok = pwrite(fd, payload, payload_size, (off_t)sizeof(header)) == (ssize_t)payload_size;
    }
    if (ok) ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool test_create_insert_close_reopen_search(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("create_reopen");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {1.0f, 0.0f, 0.0f};
    const char metadata[] = "first";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 101, metadata, sizeof(metadata)),
                "insert before close should succeed");
    TEST_ASSERT(close_db(db), "created database should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), true, true, &result);
    TEST_ASSERT(count == 1, "reopened search should find one result");
    TEST_ASSERT(result.id == 101, "reopened search should preserve vector id");
    TEST_ASSERT(vector_eq(result.vector, vector, ARRAY_LEN(vector)),
                "reopened search should hydrate vector");
    TEST_ASSERT(result.metadata_size == sizeof(metadata), "metadata size should persist");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "metadata bytes should persist");
    free_results(&result, 1);

    TEST_ASSERT(close_db(db), "reopened database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_sparse_ids_hydrate_vector_and_metadata(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("sparse_ids");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vectors[][3] = {
        {1.0f, 0.0f, 0.0f},
        {0.0f, 1.0f, 0.0f},
        {0.0f, 0.0f, 1.0f},
    };
    const uint64_t ids[] = {1001, 42, 987654321};
    const char meta0[] = "row-zero";
    const char meta1[] = "row-one";
    const char meta2[] = "row-two";
    const void* metas[] = {meta0, meta1, meta2};
    const size_t meta_sizes[] = {sizeof(meta0), sizeof(meta1), sizeof(meta2)};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, &vectors[0][0], ARRAY_LEN(vectors),
                                            ARRAY_LEN(vectors[0]), ids, metas, meta_sizes),
                "sparse-id insert should succeed");
    TEST_ASSERT(close_db(db), "database should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database");

    qihse_vector_result_t result;
    int count = search_one(db, vectors[1], ARRAY_LEN(vectors[1]), true, true, &result);
    TEST_ASSERT(count == 1, "sparse-id query should find one result");
    TEST_ASSERT(result.id == ids[1], "sparse-id query should return external id");
    TEST_ASSERT(vector_eq(result.vector, vectors[1], ARRAY_LEN(vectors[1])),
                "sparse-id query should hydrate the matching vector row");
    TEST_ASSERT(result.metadata_size == meta_sizes[1], "sparse-id metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, meta1, meta_sizes[1]) == 0,
                "sparse-id query should hydrate matching metadata row");
    free_results(&result, 1);

    TEST_ASSERT(close_db(db), "database should close after sparse-id check");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_binary_metadata_survives_restart(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("binary_meta");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.0f, 1.0f, 0.0f, 0.0f};
    const uint8_t metadata[] = {
        0x00, 0xff, 0x7f, 0x80, 0x41, 0x00, 0x42, 0x13,
        0x37, 0xc0, 0xde, 0x00, 0xfa, 0xce, 0x5a, 0xa5
    };

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 555, metadata, sizeof(metadata)),
                "binary metadata insert should succeed");
    TEST_ASSERT(close_db(db), "database should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), false, true, &result);
    TEST_ASSERT(count == 1, "binary metadata search should find one result");
    TEST_ASSERT(result.id == 555, "binary metadata id should persist");
    TEST_ASSERT(result.metadata_size == sizeof(metadata),
                "binary metadata size should survive restart");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "binary metadata bytes should survive restart exactly");
    free_results(&result, 1);

    TEST_ASSERT(close_db(db), "database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_null_db_path_ephemeral_searchable(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    const float vector[] = {0.0f, 0.0f, 1.0f};
    const char metadata[] = "ephemeral";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, NULL);
    TEST_ASSERT(db != NULL, "NULL path create should return an ephemeral database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 707, metadata, sizeof(metadata)),
                "ephemeral insert should succeed");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), true, true, &result);
    TEST_ASSERT(count == 1, "ephemeral search should find one result");
    TEST_ASSERT(result.id == 707, "ephemeral search should preserve vector id");
    TEST_ASSERT(vector_eq(result.vector, vector, ARRAY_LEN(vector)),
                "ephemeral search should hydrate vector in-process");
    TEST_ASSERT(result.metadata_size == sizeof(metadata), "ephemeral metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "ephemeral metadata should hydrate in-process");
    free_results(&result, 1);

    qihse_vector_db_destroy(db);
    env_destroy(&env);
    return true;
}

static bool test_wal_replays_unflushed_add(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("wal_replay");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.25f, 0.50f, 0.75f};
    const char metadata[] = "wal-durable";

    qihse_vector_db_t writer =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(writer != NULL, "writer create should return a database");
    TEST_ASSERT(add_one(writer, vector, ARRAY_LEN(vector), 424242, metadata, sizeof(metadata)),
                "add should succeed and append WAL before flush");

    qihse_vector_db_persistence_stats_t writer_stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(writer, &writer_stats),
                "writer persistence stats should be available");
    TEST_ASSERT(writer_stats.needs_flush, "unflushed writer should report pending durable snapshot");
    TEST_ASSERT(writer_stats.wal_bytes_pending > 0, "unflushed writer should have WAL bytes pending");

    qihse_vector_db_t recovered = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(recovered != NULL, "read-only open should recover from WAL without a snapshot");

    qihse_vector_db_persistence_stats_t recovered_stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(recovered, &recovered_stats),
                "recovered persistence stats should be available");
    TEST_ASSERT(recovered_stats.wal_records_replayed == 1,
                "recovered database should report one replayed WAL record");
    TEST_ASSERT(recovered_stats.live_vectors == 1,
                "recovered database should expose the WAL-added row");

    qihse_vector_result_t result;
    int count = search_one(recovered, vector, ARRAY_LEN(vector), true, true, &result);
    TEST_ASSERT(count == 1, "recovered WAL row should be searchable");
    TEST_ASSERT(result.id == 424242, "recovered WAL row should preserve vector id");
    TEST_ASSERT(vector_eq(result.vector, vector, ARRAY_LEN(vector)),
                "recovered WAL row should hydrate vector bytes");
    TEST_ASSERT(result.metadata_size == sizeof(metadata), "recovered WAL metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "recovered WAL metadata bytes should match");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(recovered), "read-only recovered database should close");
    TEST_ASSERT(qihse_vector_db_close(writer), "writer close should checkpoint WAL into snapshot");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_wal_replays_unflushed_delete_update_upsert(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("wal_mutation_replay");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float deleted[] = {1.0f, 0.0f, 0.0f, 0.0f};
    const float updated_old[] = {0.0f, 1.0f, 0.0f, 0.0f};
    const float upsert_old[] = {0.0f, 0.0f, 1.0f, 0.0f};
    const float updated_new[] = {0.0f, 0.0f, 0.0f, 1.0f};
    const float upsert_vectors[][4] = {
        {0.5f, 0.5f, 0.0f, 0.0f},
        {0.0f, 0.5f, 0.5f, 0.0f},
    };
    const uint64_t upsert_ids[] = {9603, 9604};
    const char updated_meta[] = "wal-updated";
    const char upsert_update_meta[] = "wal-upsert-updated";
    const char upsert_insert_meta[] = "wal-upsert-inserted";
    const void* upsert_metas[] = {upsert_update_meta, upsert_insert_meta};
    const size_t upsert_meta_sizes[] = {
        sizeof(upsert_update_meta),
        sizeof(upsert_insert_meta)
    };

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, deleted, ARRAY_LEN(deleted), 9601, NULL, 0),
                "delete target insert should succeed");
    TEST_ASSERT(add_one(db, updated_old, ARRAY_LEN(updated_old), 9602, NULL, 0),
                "update target insert should succeed");
    TEST_ASSERT(add_one(db, upsert_old, ARRAY_LEN(upsert_old), 9603, NULL, 0),
                "upsert target insert should succeed");
    TEST_ASSERT(close_db(db), "base snapshot should close before WAL mutations");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "writer reopen should return a database");
    TEST_ASSERT(qihse_vector_db_delete_by_id(db, 9601),
                "delete mutation should append WAL");
    TEST_ASSERT(qihse_vector_db_update_by_id(db, 9602, updated_new,
                                             ARRAY_LEN(updated_new),
                                             updated_meta, sizeof(updated_meta)),
                "update mutation should append WAL");
    size_t inserted_count = 0;
    size_t updated_count = 0;
    TEST_ASSERT(qihse_vector_db_upsert_by_ids(db, upsert_ids, &upsert_vectors[0][0],
                                              ARRAY_LEN(upsert_ids),
                                              ARRAY_LEN(upsert_vectors[0]),
                                              upsert_metas, upsert_meta_sizes,
                                              &inserted_count, &updated_count),
                "upsert mutation should append WAL");
    TEST_ASSERT(inserted_count == 1 && updated_count == 1,
                "upsert should report one insert and one update");
    qihse_vector_db_destroy(db);

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "read-only open should replay mutation WAL");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "replayed mutation stats should be available");
    TEST_ASSERT(stats.wal_records_replayed == 3,
                "delete/update/upsert WAL records should replay");
    TEST_ASSERT(stats.live_vectors == 3,
                "mutation replay should expose three live rows");

    qihse_vector_result_t result;
    int count = search_one(db, deleted, ARRAY_LEN(deleted), false, false, &result);
    TEST_ASSERT(count == 0, "WAL-deleted row should not be searchable");

    count = search_one(db, updated_old, ARRAY_LEN(updated_old), false, false, &result);
    TEST_ASSERT(count == 0, "WAL-updated old vector should not be searchable");

    count = search_one(db, updated_new, ARRAY_LEN(updated_new), true, true, &result);
    TEST_ASSERT(count == 1, "WAL-updated new vector should be searchable");
    TEST_ASSERT(result.id == 9602, "WAL update should preserve id");
    TEST_ASSERT(vector_eq(result.vector, updated_new, ARRAY_LEN(updated_new)),
                "WAL update should hydrate replacement vector");
    TEST_ASSERT(result.metadata_size == sizeof(updated_meta),
                "WAL update should hydrate replacement metadata size");
    TEST_ASSERT(memcmp(result.metadata, updated_meta, sizeof(updated_meta)) == 0,
                "WAL update should hydrate replacement metadata bytes");
    free_results(&result, 1);

    count = search_one(db, upsert_vectors[0], ARRAY_LEN(upsert_vectors[0]),
                       true, true, &result);
    TEST_ASSERT(count == 1, "WAL-upsert updated vector should be searchable");
    TEST_ASSERT(result.id == 9603, "WAL upsert update should preserve id");
    TEST_ASSERT(result.metadata_size == sizeof(upsert_update_meta),
                "WAL upsert update metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, upsert_update_meta,
                       sizeof(upsert_update_meta)) == 0,
                "WAL upsert update metadata bytes should match");
    free_results(&result, 1);

    count = search_one(db, upsert_vectors[1], ARRAY_LEN(upsert_vectors[1]),
                       true, true, &result);
    TEST_ASSERT(count == 1, "WAL-upsert inserted vector should be searchable");
    TEST_ASSERT(result.id == 9604, "WAL upsert insert should preserve id");
    TEST_ASSERT(result.metadata_size == sizeof(upsert_insert_meta),
                "WAL upsert insert metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, upsert_insert_meta,
                       sizeof(upsert_insert_meta)) == 0,
                "WAL upsert insert metadata bytes should match");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only replayed database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_torn_wal_tail_ignored_and_truncated(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("wal_torn_tail");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float stable[] = {1.0f, 0.0f, 0.0f};
    const float torn[] = {0.0f, 1.0f, 0.0f};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, stable, ARRAY_LEN(stable), 5150, NULL, 0),
                "stable vector insert should succeed");
    TEST_ASSERT(close_db(db), "stable snapshot should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "writer reopen should return a database");
    TEST_ASSERT(add_one(db, torn, ARRAY_LEN(torn), 5151, NULL, 0),
                "uncheckpointed vector should append WAL");
    qihse_vector_db_destroy(db);

    off_t wal_size = 0;
    TEST_ASSERT(file_size_of(path, "wal.qwal", &wal_size), "WAL should exist before truncation");
    TEST_ASSERT(wal_size > 1, "WAL should contain enough bytes to truncate");
    TEST_ASSERT(truncate_file_to(path, "wal.qwal", wal_size - 1),
                "test should create a torn WAL tail");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "writable open should recover by truncating torn WAL tail");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after torn WAL recovery");
    TEST_ASSERT(stats.wal_records_replayed == 0,
                "torn add should not be replayed without its complete commit record");
    TEST_ASSERT(stats.wal_bytes_pending == 0,
                "writable recovery should truncate the torn WAL tail");

    qihse_vector_result_t result;
    int count = search_one(db, stable, ARRAY_LEN(stable), false, false, &result);
    TEST_ASSERT(count == 1, "stable snapshot row should remain searchable");
    TEST_ASSERT(result.id == 5150, "stable snapshot row should preserve id");
    free_results(&result, 1);

    count = search_one(db, torn, ARRAY_LEN(torn), false, false, &result);
    TEST_ASSERT(count == 0, "torn WAL row should not be visible after recovery");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "recovered database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_checkpoint_publishes_snapshot_and_clears_wal(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("checkpoint_clears_wal");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.125f, 0.250f, 0.500f, 1.000f};
    const char metadata[] = "checkpoint-published";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 6161, metadata, sizeof(metadata)),
                "checkpoint fixture insert should append WAL");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available before checkpoint");
    TEST_ASSERT(stats.needs_flush, "uncheckpointed insert should need flush");
    TEST_ASSERT(stats.wal_bytes_pending > 0u,
                "uncheckpointed insert should have pending WAL bytes");

    TEST_ASSERT(qihse_vector_db_checkpoint(db), "checkpoint should publish snapshot");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after checkpoint");
    TEST_ASSERT(!stats.needs_flush, "checkpoint should clear dirty snapshot state");
    TEST_ASSERT(stats.wal_bytes_pending == 0u, "checkpoint should clear pending WAL bytes");
    TEST_ASSERT(stats.index_rows == 1u, "checkpoint should publish one index row");
    TEST_ASSERT(stats.live_vectors == 1u, "checkpoint should publish one live row");

    off_t wal_size = -1;
    TEST_ASSERT(file_size_of(path, "wal.qwal", &wal_size),
                "WAL file should exist after checkpoint truncation");
    TEST_ASSERT(wal_size == 0, "checkpoint should truncate WAL file to zero bytes");
    TEST_ASSERT(qihse_vector_db_close(db), "checkpointed database should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "read-only reopen should accept checkpointed snapshot");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after checkpointed reopen");
    TEST_ASSERT(stats.wal_records_replayed == 0u,
                "checkpointed reopen should not replay old WAL records");
    TEST_ASSERT(stats.wal_bytes_pending == 0u,
                "checkpointed reopen should see an empty WAL");
    TEST_ASSERT(stats.index_rows == 1u && stats.live_vectors == 1u,
                "checkpointed snapshot should preserve row counts");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), true, true, &result);
    TEST_ASSERT(count == 1, "checkpointed row should be searchable");
    TEST_ASSERT(result.id == 6161, "checkpointed row should preserve vector id");
    TEST_ASSERT(vector_eq(result.vector, vector, ARRAY_LEN(vector)),
                "checkpointed row should hydrate vector bytes");
    TEST_ASSERT(result.metadata_size == sizeof(metadata),
                "checkpointed metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "checkpointed metadata bytes should match");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only checkpointed database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_checkpoint_ignores_stale_complete_wal(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("checkpoint_stale_wal");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.875f, 0.500f, 0.250f, 0.125f};
    const char metadata[] = "checkpoint-stale-wal";
    uint8_t* stale_wal = NULL;
    size_t stale_wal_size = 0u;

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 6171, metadata, sizeof(metadata)),
                "checkpoint stale WAL fixture insert should append WAL");
    TEST_ASSERT(read_file_payload(path, "wal.qwal", &stale_wal, &stale_wal_size),
                "test should capture complete pre-checkpoint WAL");
    TEST_ASSERT(stale_wal_size > 0u, "captured WAL should contain the insert record");

    TEST_ASSERT(qihse_vector_db_checkpoint(db), "checkpoint should publish snapshot");
    TEST_ASSERT(qihse_vector_db_close(db), "checkpointed database should close");
    TEST_ASSERT(write_file_payload(path, "wal.qwal", stale_wal, stale_wal_size),
                "test should restore stale complete WAL after checkpoint");
    free(stale_wal);
    stale_wal = NULL;

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "writable reopen should accept checkpoint plus stale WAL");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after stale WAL reopen");
    TEST_ASSERT(stats.wal_records_replayed == 0u,
                "stale complete WAL generation should not replay over checkpoint");
    TEST_ASSERT(stats.index_rows == 1u, "stale WAL should not duplicate index rows");
    TEST_ASSERT(stats.live_vectors == 1u, "stale WAL should not duplicate live rows");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), true, true, &result);
    TEST_ASSERT(count == 1, "checkpointed row should search despite stale WAL");
    TEST_ASSERT(result.id == 6171, "checkpointed row id should survive stale WAL");
    TEST_ASSERT(vector_eq(result.vector, vector, ARRAY_LEN(vector)),
                "checkpointed vector should survive stale WAL");
    TEST_ASSERT(result.metadata_size == sizeof(metadata),
                "checkpointed metadata size should survive stale WAL");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "checkpointed metadata should survive stale WAL");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "stale-WAL database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_read_only_mmap_reopen_searches(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("mmap_reopen");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.10f, 0.20f, 0.30f, 0.40f};
    const char metadata[] = "mmap";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 909090, metadata, sizeof(metadata)),
                "insert before mmap reopen should succeed");
    TEST_ASSERT(close_db(db), "database should close before mmap reopen");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "read-only mmap open should return a database");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "mmap persistence stats should be available");
    TEST_ASSERT(stats.storage_mode == QIHSE_VDB_STORAGE_FILE_MMAP,
                "mmap open should report FILE_MMAP storage mode");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), true, true, &result);
    TEST_ASSERT(count == 1, "mmap search should find one result");
    TEST_ASSERT(result.id == 909090, "mmap search should preserve vector id");
    TEST_ASSERT(vector_eq(result.vector, vector, ARRAY_LEN(vector)),
                "mmap search should hydrate vector from mapped qvec");
    TEST_ASSERT(result.metadata_size == sizeof(metadata), "mmap metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "mmap metadata bytes should hydrate from metadata store");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "mmap database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_corrupt_vectors_qvec_magic_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("corrupt_qvec");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {1.0f, 0.0f, 0.0f};
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9001, NULL, 0),
                "insert before corrupting qvec should succeed");
    TEST_ASSERT(close_db(db), "database should close before qvec corruption");

    TEST_ASSERT(corrupt_file_byte(path, "vectors.qvec", 0, (uint8_t)'X'),
                "test should corrupt vectors.qvec magic");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "corrupt vectors.qvec magic should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_truncated_vectors_qvec_payload_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("truncated_qvec_payload");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vectors[][4] = {
        {1.0f, 0.0f, 0.0f, 0.0f},
        {0.0f, 1.0f, 0.0f, 0.0f},
    };
    const uint64_t ids[] = {9011, 9012};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, &vectors[0][0], ARRAY_LEN(vectors),
                                            ARRAY_LEN(vectors[0]), ids, NULL, NULL),
                "insert before truncating qvec payload should succeed");
    TEST_ASSERT(close_db(db), "database should close before qvec payload truncation");

    off_t qvec_size = 0;
    TEST_ASSERT(file_size_of(path, "vectors.qvec", &qvec_size),
                "vectors.qvec size should be readable before truncation");
    TEST_ASSERT(qvec_size > 1, "vectors.qvec should contain enough bytes to truncate");
    TEST_ASSERT(truncate_file_to(path, "vectors.qvec", qvec_size - 1),
                "test should truncate vectors.qvec payload");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "truncated vectors.qvec payload should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_corrupt_metadata_qmeta_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("corrupt_qmeta");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.25f, 0.50f, 0.75f};
    const char metadata[] = "authoritative-metadata";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9005, metadata, sizeof(metadata)),
                "insert before corrupting metadata should succeed");
    TEST_ASSERT(close_db(db), "database should close before metadata corruption");

    TEST_ASSERT(corrupt_file_byte(path, "metadata.qmeta", 0, (uint8_t)'X'),
                "test should corrupt metadata.qmeta payload");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "corrupt metadata.qmeta payload should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_truncated_metadata_qmeta_payload_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("truncated_qmeta_payload");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.75f, 0.50f, 0.25f};
    const char metadata[] = "authoritative-metadata-truncated";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9013, metadata, sizeof(metadata)),
                "insert before truncating metadata payload should succeed");
    TEST_ASSERT(close_db(db), "database should close before metadata payload truncation");

    off_t qmeta_size = 0;
    TEST_ASSERT(file_size_of(path, "metadata.qmeta", &qmeta_size),
                "metadata.qmeta size should be readable before truncation");
    TEST_ASSERT(qmeta_size > 1, "metadata.qmeta should contain enough bytes to truncate");
    TEST_ASSERT(truncate_file_to(path, "metadata.qmeta", qmeta_size - 1),
                "test should truncate metadata.qmeta payload");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "truncated metadata.qmeta payload should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_corrupt_index_qidx_magic_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("corrupt_qidx");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.20f, 0.70f, 0.10f};
    const char metadata[] = "index-corruption";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9014, metadata, sizeof(metadata)),
                "insert before corrupting qidx should succeed");
    TEST_ASSERT(close_db(db), "database should close before qidx corruption");

    TEST_ASSERT(corrupt_file_byte(path, "index.qidx", 0, (uint8_t)'X'),
                "test should corrupt index.qidx magic");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "corrupt index.qidx magic should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_corrupt_index_qidx_count_mismatch_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("index_qidx_count_mismatch");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.7f, 0.1f, 0.2f};
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9015, NULL, 0),
                "insert before index count mutation should succeed");
    TEST_ASSERT(close_db(db), "database should close before index count corruption");

    TEST_ASSERT(write_file_u64le_at(path, "index.qidx", 16, 2u),
                "test should mutate index.qidx row-count");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "index.qidx row-count mismatch should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_corrupt_index_qidx_row_bytes_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("index_qidx_row_bytes");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.3f, 0.6f, 0.9f};
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9016, NULL, 0),
                "insert before index row-bytes mutation should succeed");
    TEST_ASSERT(close_db(db), "database should close before index row-bytes corruption");

    TEST_ASSERT(corrupt_file_byte(path, "index.qidx", 12, 0xffu),
                "test should corrupt index.qidx row-bytes field");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "index.qidx impossible row-bytes should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_legacy_manifest_index_row_mismatch_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("legacy_manifest_index_row_mismatch");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vectors[][3] = {
        {0.12f, 0.34f, 0.56f},
        {0.78f, 0.90f, 0.11f},
    };
    const uint64_t ids[] = {9201, 9202};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, &vectors[0][0], ARRAY_LEN(vectors),
                                            ARRAY_LEN(vectors[0]), ids, NULL, NULL),
                "legacy manifest index-row fixture insert should succeed");
    TEST_ASSERT(close_db(db), "database should close before legacy migration mutation");

    TEST_ASSERT(truncate_file_to(path, "MANIFEST", 128),
                "test should convert snapshot to legacy 128-byte manifest");

    uint8_t* index_payload = NULL;
    size_t index_size = 0u;
    TEST_ASSERT(read_file_payload(path, "index.qidx", &index_payload, &index_size),
                "test should cache index payload before mutation");

    TEST_ASSERT(write_file_u64le_at(path, "index.qidx", 16, 3u),
                "test should mutate index.qidx row-count under legacy manifest");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "legacy manifest should reject index row-count mismatch");

    TEST_ASSERT(write_file_payload(path, "index.qidx", index_payload, index_size),
                "test should restore index payload after mismatch check");
    free(index_payload);
    index_payload = NULL;

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "restored legacy manifest snapshot should reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after legacy manifest restore");
    TEST_ASSERT(stats.index_rows == 2u, "legacy snapshot should preserve row count");
    TEST_ASSERT(stats.storage_mode == QIHSE_VDB_STORAGE_FILE_COPY,
                "legacy reopen should use file-copy storage");

    qihse_vector_result_t result;
    int count = search_one(db, vectors[0], ARRAY_LEN(vectors[0]), false, false, &result);
    TEST_ASSERT(count == 1, "legacy snapshot should remain searchable after restore");
    TEST_ASSERT(result.id == 9201, "legacy snapshot search should return restored row");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "legacy restore database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_manifest_index_checksum_mismatch_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("manifest_index_checksum_mismatch");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.5f, 0.4f, 0.1f};
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9017, NULL, 0),
                "insert before manifest checksum mutation should succeed");
    TEST_ASSERT(close_db(db), "database should close before manifest checksum mutation");

    TEST_ASSERT(write_file_u64le_at(path, "MANIFEST", 56, 0u),
                "test should mutate manifest index CRC64");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "manifest index checksum mismatch should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_partial_compaction_tmp_fallback_on_restart(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("partial_compaction_tmp_fallback");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vectors[][4] = {
        {1.0f, 0.0f, 0.0f, 0.0f},
        {0.0f, 1.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 1.0f, 0.0f},
    };
    const uint64_t ids[] = {9301, 9302, 9303};
    const char metadata[] = "compaction-tmp-fallback";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vectors[0], ARRAY_LEN(vectors[0]), ids[0], metadata, sizeof(metadata)),
                "partial-compaction row insert should succeed");
    TEST_ASSERT(add_one(db, vectors[1], ARRAY_LEN(vectors[1]), ids[1], metadata, sizeof(metadata)),
                "second partial-compaction row insert should succeed");
    TEST_ASSERT(add_one(db, vectors[2], ARRAY_LEN(vectors[2]), ids[2], metadata, sizeof(metadata)),
                "third partial-compaction row insert should succeed");
    TEST_ASSERT(qihse_vector_db_delete_by_id(db, ids[1]),
                "delete before compact should create compaction opportunity");

    TEST_ASSERT(qihse_vector_db_compact(db), "compact should complete before tmp fallback simulation");
    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available before partial tmp injection");
    TEST_ASSERT(stats.index_rows == 2u,
                "compacted partial fixture should preserve two live rows");
    TEST_ASSERT(stats.live_vectors == 2u, "compacted partial fixture should keep two live rows");
    TEST_ASSERT(close_db(db), "database should close before partial compaction tmp injection");

    uint8_t* manifest_payload = NULL;
    size_t manifest_size = 0u;
    uint8_t* index_payload = NULL;
    size_t index_size = 0u;
    TEST_ASSERT(read_file_payload(path, "MANIFEST", &manifest_payload, &manifest_size),
                "should read manifest for partial-compaction tmp fixture");
    TEST_ASSERT(read_file_payload(path, "index.qidx", &index_payload, &index_size),
                "should read index for partial-compaction tmp fixture");
    TEST_ASSERT(write_file_payload(path, "MANIFEST.tmp", manifest_payload, manifest_size),
                "test should write partial MANIFEST.tmp");
    TEST_ASSERT(write_file_payload(path, "index.qidx.tmp", index_payload, index_size),
                "test should write partial index.qidx.tmp");
    TEST_ASSERT(manifest_size > 16u, "manifest should be long enough to truncate");
    TEST_ASSERT(truncate_file_to(path, "MANIFEST.tmp", (off_t)(manifest_size / 2u)),
                "test should create partial MANIFEST.tmp");
    TEST_ASSERT(index_size > 16u, "index snapshot should be long enough to truncate");
    TEST_ASSERT(truncate_file_to(path, "index.qidx.tmp", (off_t)(index_size / 2u)),
                "test should create partial index.qidx.tmp");
    free(manifest_payload);
    free(index_payload);
    manifest_payload = NULL;
    index_payload = NULL;

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "partial compaction tmp files should not block reopen");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after partial tmp fallback reopen");
    TEST_ASSERT(stats.index_rows == 2u, "fallback should keep compacted row count");
    TEST_ASSERT(stats.live_vectors == 2u, "fallback should keep compacted live count");

    qihse_vector_result_t result;
    int count = search_one(db, vectors[0], ARRAY_LEN(vectors[0]), true, true, &result);
    TEST_ASSERT(count == 1, "fallback should preserve compacted first row");
    TEST_ASSERT(result.id == 9301, "fallback should preserve first live row id");
    free_results(&result, 1);

    count = search_one(db, vectors[1], ARRAY_LEN(vectors[1]), true, true, &result);
    TEST_ASSERT(count == 0, "deleted row should remain deleted after compaction fallback");
    free_results(&result, 1);

    count = search_one(db, vectors[2], ARRAY_LEN(vectors[2]), true, true, &result);
    TEST_ASSERT(count == 1, "fallback should preserve third live row");
    TEST_ASSERT(result.id == 9303, "fallback should preserve third live row id");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only partial-compaction fallback database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_truncated_index_qidx_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("truncated_qidx");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.0f, 1.0f, 0.0f};
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9002, NULL, 0),
                "insert before truncating qidx should succeed");
    TEST_ASSERT(close_db(db), "database should close before qidx truncation");

    TEST_ASSERT(truncate_file_to(path, "index.qidx", 64 + 24),
                "test should truncate index.qidx mid-row");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "truncated index.qidx should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_truncated_manifest_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("truncated_manifest");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.0f, 1.0f, 0.0f};
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9003, NULL, 0),
                "insert before truncating manifest should succeed");
    TEST_ASSERT(close_db(db), "database should close before manifest truncation");

    TEST_ASSERT(truncate_file_to(path, "MANIFEST", 64),
                "test should truncate manifest to an unsupported size");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "truncated manifest should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_stale_manifest_tmp_ignored_after_checkpoint(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("stale_manifest_tmp");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.40f, 0.30f, 0.20f, 0.10f};
    const char metadata[] = "manifest-tmp-ignored";
    const uint8_t stale_manifest[] = {
        'Q', 'I', 'H', 'S', 'E', 'M', 'A', 'N',
        0xff, 0xff, 0xff, 0xff, 0xde, 0xad, 0xbe, 0xef
    };

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9006, metadata, sizeof(metadata)),
                "insert before checkpoint should succeed");
    TEST_ASSERT(qihse_vector_db_checkpoint(db), "checkpoint should publish valid manifest");
    TEST_ASSERT(qihse_vector_db_close(db), "checkpointed database should close");

    TEST_ASSERT(write_file_payload(path, "MANIFEST.tmp", stale_manifest, sizeof(stale_manifest)),
                "test should write interrupted manifest publication tmp file");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "stale MANIFEST.tmp should not block read-only reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after stale manifest tmp reopen");
    TEST_ASSERT(stats.index_rows == 1u, "stale manifest tmp should not change index rows");
    TEST_ASSERT(stats.live_vectors == 1u, "stale manifest tmp should not change live rows");
    TEST_ASSERT(stats.wal_records_replayed == 0u,
                "stale manifest tmp should not force WAL replay");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), true, true, &result);
    TEST_ASSERT(count == 1, "checkpointed row should search despite stale manifest tmp");
    TEST_ASSERT(result.id == 9006, "checkpointed row id should survive stale manifest tmp");
    TEST_ASSERT(vector_eq(result.vector, vector, ARRAY_LEN(vector)),
                "checkpointed vector should survive stale manifest tmp");
    TEST_ASSERT(result.metadata_size == sizeof(metadata),
                "checkpointed metadata size should survive stale manifest tmp");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "checkpointed metadata should survive stale manifest tmp");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only stale manifest tmp database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_stale_snapshot_tmp_files_ignored_after_checkpoint(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("stale_snapshot_tmps");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float first[] = {0.60f, 0.20f, 0.10f, 0.10f};
    const float second[] = {0.10f, 0.20f, 0.60f, 0.10f};
    const char first_metadata[] = "published-first";
    const char second_metadata[] = "published-second";
    const uint8_t stale_payload[] = {
        'Q', 'I', 'H', 'S', 'E', '-', 'T', 'M', 'P',
        0xde, 0xad, 0xbe, 0xef
    };

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, first, ARRAY_LEN(first), 9011,
                        first_metadata, sizeof(first_metadata)),
                "first checkpoint tmp fixture insert should succeed");
    TEST_ASSERT(add_one(db, second, ARRAY_LEN(second), 9012,
                        second_metadata, sizeof(second_metadata)),
                "second checkpoint tmp fixture insert should succeed");
    TEST_ASSERT(qihse_vector_db_checkpoint(db),
                "checkpoint should publish authoritative snapshot files");
    TEST_ASSERT(qihse_vector_db_close(db), "checkpointed database should close");

    TEST_ASSERT(write_file_payload(path, "vectors.qvec.tmp",
                                   stale_payload, sizeof(stale_payload)),
                "test should write stale vectors.qvec tmp");
    TEST_ASSERT(write_file_payload(path, "metadata.qmeta.tmp",
                                   stale_payload, sizeof(stale_payload)),
                "test should write stale metadata.qmeta tmp");
    TEST_ASSERT(write_file_payload(path, "index.qidx.tmp",
                                   stale_payload, sizeof(stale_payload)),
                "test should write stale index.qidx tmp");
    TEST_ASSERT(write_file_payload(path, "idmap.qid.tmp",
                                   stale_payload, sizeof(stale_payload)),
                "test should write stale idmap.qid tmp");
    TEST_ASSERT(write_file_payload(path, "vectors.qtri.tmp",
                                   stale_payload, sizeof(stale_payload)),
                "test should write stale vectors.qtri tmp");
    TEST_ASSERT(write_file_payload(path, "vectors.qmag.tmp",
                                   stale_payload, sizeof(stale_payload)),
                "test should write stale vectors.qmag tmp");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "stale snapshot tmp files should not block reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after stale snapshot tmp reopen");
    TEST_ASSERT(stats.index_rows == 2u,
                "stale snapshot tmp files should not change index rows");
    TEST_ASSERT(stats.live_vectors == 2u,
                "stale snapshot tmp files should not change live rows");
    TEST_ASSERT(stats.idmap_valid,
                "stale snapshot tmp files should not invalidate idmap");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "stale snapshot tmp files should not invalidate qtri");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "stale snapshot tmp files should not invalidate qmag");
    TEST_ASSERT(stats.wal_records_replayed == 0u,
                "stale snapshot tmp files should not force WAL replay");

    qihse_vector_result_t result;
    int count = search_one(db, second, ARRAY_LEN(second), true, true, &result);
    TEST_ASSERT(count == 1, "published row should search despite stale tmp files");
    TEST_ASSERT(result.id == 9012, "published row id should ignore stale tmp files");
    TEST_ASSERT(vector_eq(result.vector, second, ARRAY_LEN(second)),
                "published vector should ignore stale tmp files");
    TEST_ASSERT(result.metadata_size == sizeof(second_metadata),
                "published metadata size should ignore stale tmp files");
    TEST_ASSERT(memcmp(result.metadata, second_metadata, sizeof(second_metadata)) == 0,
                "published metadata should ignore stale tmp files");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db),
                "read-only stale snapshot tmp database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_manifest_rejects_impossible_qmag_shape(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("impossible_qmag_manifest");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {1.0f, -1.0f, 0.5f};
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 9004, NULL, 0),
                "insert before corrupting qmag manifest metadata should succeed");
    TEST_ASSERT(close_db(db), "database should close before qmag manifest corruption");

    TEST_ASSERT(write_file_u64le_at(path, "MANIFEST", 136, 2u),
                "test should make qmag row bytes disagree with vector dimensions");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db == NULL, "impossible qmag manifest metadata should fail open");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_read_only_open_searches_and_rejects_add(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("readonly");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {1.0f, 0.0f};
    const float other[] = {0.0f, 1.0f};
    const char metadata[] = "readonly";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 11, metadata, sizeof(metadata)),
                "initial insert should succeed");
    TEST_ASSERT(close_db(db), "database should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "read-only open should return a database");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), false, false, &result);
    TEST_ASSERT(count == 1, "read-only search should find existing result");
    TEST_ASSERT(result.id == 11, "read-only search should preserve vector id");
    free_results(&result, 1);

    TEST_ASSERT(!add_one(db, other, ARRAY_LEN(other), 12, NULL, 0),
                "read-only add_vectors should be rejected");

    TEST_ASSERT(close_db(db), "read-only database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_duplicate_vector_id_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("duplicate_id");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float first[] = {1.0f, 0.0f, 0.0f};
    const float second[] = {0.0f, 1.0f, 0.0f};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, first, ARRAY_LEN(first), 31337, NULL, 0),
                "first insert for id should succeed");
    TEST_ASSERT(!add_one(db, second, ARRAY_LEN(second), 31337, NULL, 0),
                "duplicate vector_id should be rejected");

    qihse_vector_db_destroy(db);
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_corrupt_idmap_rebuilds_high_ids(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("corrupt_idmap_high_ids");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vectors[][4] = {
        {1.0f, 0.0f, 0.0f, 0.0f},
        {0.0f, 1.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 1.0f, 0.0f},
    };
    const uint64_t ids[] = {
        17u,
        UINT64_C(0x8000000000000005),
        UINT64_MAX
    };

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, &vectors[0][0], ARRAY_LEN(vectors),
                                            ARRAY_LEN(vectors[0]), ids, NULL, NULL),
                "high-ID insert should succeed");
    TEST_ASSERT(close_db(db), "database should close before idmap corruption");

    TEST_ASSERT(corrupt_file_byte(path, "idmap.qid", 0, (uint8_t)'Z'),
                "test should corrupt idmap.qid magic");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "corrupt idmap.qid should rebuild from index.qidx");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "persistence stats should be available");
    TEST_ASSERT(stats.idmap_valid, "rebuilt idmap should be valid");
    TEST_ASSERT(stats.idmap_dirty, "rebuilt idmap should be marked dirty until flushed");
    TEST_ASSERT(stats.idmap_rows == ARRAY_LEN(ids), "rebuilt idmap row count should match live rows");

    qihse_vector_result_t result;
    int count = search_one(db, vectors[1], ARRAY_LEN(vectors[1]), true, false, &result);
    TEST_ASSERT(count == 1, "high-ID vector should search after idmap rebuild");
    TEST_ASSERT(result.id == ids[1], "ID above INT64_MAX should survive idmap rebuild");
    TEST_ASSERT(vector_eq(result.vector, vectors[1], ARRAY_LEN(vectors[1])),
                "high-ID search should hydrate the correct vector");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_flush(db), "flush should rewrite rebuilt idmap sidecar");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "persistence stats should be available after flush");
    TEST_ASSERT(!stats.idmap_dirty, "idmap should be clean after flush");
    TEST_ASSERT(qihse_vector_db_close(db), "database should close after idmap rebuild");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_invalid_idmap_row_index_rebuilds_on_reopen(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("invalid_idmap_row_index");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.0f, 1.0f, 0.0f};
    const uint64_t id = 8123u;

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), id, NULL, 0),
                "idmap row index fixture insert should succeed");
    TEST_ASSERT(close_db(db), "database should close before idmap corruption");

    uint8_t idmap_bytes[32u + 16u];
    memset(idmap_bytes, 0, sizeof(idmap_bytes));
    memcpy(idmap_bytes, "QIHSEQID", 8u);
    test_write_u32le(idmap_bytes + 8u, 1u);
    test_write_u32le(idmap_bytes + 12u, 16u);
    test_write_u64le(idmap_bytes + 16u, 1u);
    test_write_u64le(idmap_bytes + 32u, (uint64_t)(id ^ UINT64_C(0x8000000000000000)));
    test_write_u64le(idmap_bytes + 40u, 1u);
    test_write_u64le(idmap_bytes + 24u, test_fnv1a64(idmap_bytes + 32u, 16u));

    TEST_ASSERT(write_file_payload(path, "idmap.qid", idmap_bytes, sizeof(idmap_bytes)),
                "test should write an idmap.qid entry with an out-of-range row index");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "invalid idmap.qid should rebuild on reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after invalid idmap reopen");
    TEST_ASSERT(stats.idmap_valid, "invalid idmap should rebuild in memory");
    TEST_ASSERT(!stats.idmap_dirty, "read-only invalid idmap reopen should stay clean");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), false, false, &result);
    TEST_ASSERT(count == 1, "row should remain searchable after invalid idmap reopen");
    TEST_ASSERT(result.id == id, "row id should survive invalid idmap reopen");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only invalid-idmap database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_missing_vectors_qtri_accepted(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("missing_qtri");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.0f, 1.0f, 0.0f};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 8080, NULL, 0),
                "FLOAT32 insert should succeed");
    TEST_ASSERT(close_db(db), "database should close");

    char qtri_path[512];
    snprintf(qtri_path, sizeof(qtri_path), "%s/vectors.qtri", path);
    if (unlink(qtri_path) != 0 && errno != ENOENT) {
        fprintf(stderr, "FAIL: unable to remove %s: %s\n", qtri_path, strerror(errno));
        remove_tree(path);
        free(path);
        env_destroy(&env);
        return false;
    }

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "missing vectors.qtri should not block FLOAT32 reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "persistence stats should be available for missing qtri");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_ABSENT,
                "missing vectors.qtri should be reported as absent");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), false, false, &result);
    TEST_ASSERT(count == 1, "FLOAT32 DB should search after missing qtri reopen");
    TEST_ASSERT(result.id == 8080, "FLOAT32 DB should preserve id without qtri");
    free_results(&result, 1);

    TEST_ASSERT(close_db(db), "database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_corrupt_vectors_qtri_accepted_and_reported(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("corrupt_qtri");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vector[] = {0.0f, 0.0f, 1.0f};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vector, ARRAY_LEN(vector), 8081, NULL, 0),
                "FLOAT32 insert should succeed before qtri corruption");
    TEST_ASSERT(close_db(db), "database should close before qtri corruption");

    const uint8_t invalid_tryte[] = {243u};
    TEST_ASSERT(write_qtri_payload(path, invalid_tryte, sizeof(invalid_tryte)),
                "test should write a qtri payload containing an invalid tryte");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "corrupt vectors.qtri should not block FLOAT32 reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "persistence stats should be available for corrupt qtri");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_CORRUPT,
                "invalid tryte bytes 243..255 should mark qtri corrupt");

    qihse_vector_result_t result;
    int count = search_one(db, vector, ARRAY_LEN(vector), false, false, &result);
    TEST_ASSERT(count == 1, "FLOAT32 DB should search despite corrupt qtri");
    TEST_ASSERT(result.id == 8081, "FLOAT32 DB should preserve id despite corrupt qtri");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only database should close after corrupt qtri check");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

#if defined(QIHSE_VECTOR_DB_PR5_TRINARY_SEARCH_API)
static int search_many(qihse_vector_db_t vdb,
                       const float* query_vector,
                       size_t dims,
                       size_t top_k,
                       qihse_vector_result_t* results,
                       size_t max_results) {
    qihse_vector_query_t query = {
        .query_vector = query_vector,
        .vector_dims = dims,
        .top_k = top_k,
        .similarity_threshold = -1.0f,
        .include_vectors = false,
        .include_metadata = false,
        .use_trinary_candidates = false,
        .candidate_count = 0u,
    };

    return qihse_vector_db_search(vdb, &query, results, max_results);
}

static int search_many_qtri(qihse_vector_db_t vdb,
                            const float* query_vector,
                            size_t dims,
                            size_t top_k,
                            size_t candidate_count,
                            qihse_vector_result_t* results,
                            size_t max_results) {
    qihse_vector_query_t query = {
        .query_vector = query_vector,
        .vector_dims = dims,
        .top_k = top_k,
        .similarity_threshold = -1.0f,
        .include_vectors = false,
        .include_metadata = false,
        .use_trinary_candidates = true,
        .candidate_count = candidate_count,
    };

    return qihse_vector_db_search(vdb, &query, results, max_results);
}

static int search_many_qtri_scalar(qihse_vector_db_t vdb,
                                   const float* query_vector,
                                   size_t dims,
                                   size_t top_k,
                                   size_t candidate_pool_size,
                                   size_t candidate_count,
                                   qihse_vector_result_t* results,
                                   size_t max_results) {
    qihse_vector_query_t query = {
        .query_vector = query_vector,
        .vector_dims = dims,
        .top_k = top_k,
        .similarity_threshold = -1.0f,
        .include_vectors = false,
        .include_metadata = false,
        .candidate_count = candidate_count,
        .query_mode = QIHSE_VDB_QUERY_TRINARY_SCALAR,
        .candidate_pool_size = candidate_pool_size,
    };

    return qihse_vector_db_search(vdb, &query, results, max_results);
}

static int search_many_qmag(qihse_vector_db_t vdb,
                            const float* query_vector,
                            size_t dims,
                            size_t top_k,
                            size_t candidate_count,
                            qihse_vector_result_t* results,
                            size_t max_results) {
    qihse_vector_query_t query = {
        .query_vector = query_vector,
        .vector_dims = dims,
        .top_k = top_k,
        .similarity_threshold = -1.0f,
        .include_vectors = false,
        .include_metadata = false,
        .query_mode = QIHSE_VDB_QUERY_TRINARY_MAGNITUDE,
        .candidate_pool_size = candidate_count,
    };

    return qihse_vector_db_search(vdb, &query, results, max_results);
}

static bool expect_same_result_ids(const qihse_vector_result_t* expected,
                                   const qihse_vector_result_t* actual,
                                   size_t count,
                                   const char* message) {
    for (size_t i = 0; i < count; i++) {
        TEST_ASSERT(actual[i].id == expected[i].id, message);
    }
    return true;
}

static bool create_sign_friendly_qtri_db(test_env_t* env, char** out_path) {
    const float vectors[][6] = {
        { 3.0f,  2.0f,  1.0f, -1.0f, -2.0f, -3.0f},
        { 2.0f,  1.0f,  3.0f, -1.0f, -3.0f, -2.0f},
        {-3.0f, -2.0f, -1.0f,  1.0f,  2.0f,  3.0f},
        { 1.0f,  3.0f,  2.0f, -2.0f, -1.0f, -3.0f},
        {-2.0f, -1.0f, -3.0f,  3.0f,  1.0f,  2.0f},
    };
    const uint64_t ids[] = {9101, 9102, 9103, 9104, 9105};

    char* path = make_temp_db_path("pr5_qtri_search");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env->uma, path);
    TEST_ASSERT(db != NULL, "create should return a database for qtri search");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, &vectors[0][0], ARRAY_LEN(vectors),
                                            ARRAY_LEN(vectors[0]), ids, NULL, NULL),
                "sign-friendly fixture insert should succeed");
    TEST_ASSERT(close_db(db), "database should close and write qtri sidecar");

    *out_path = path;
    return true;
}

static bool create_qmag_policy_db(test_env_t* env, char** out_path) {
    const float vectors[][8] = {
        { 10.0f,  0.0f,  0.0f,  0.0f,  0.0f,  0.0f,  0.0f,  0.0f},
        {  8.0f,  2.0f,  0.0f,  0.0f,  0.0f,  0.0f,  0.0f,  0.0f},
        {  0.0f, 10.0f,  0.0f,  0.0f,  0.0f,  0.0f,  0.0f,  0.0f},
        {  0.0f,  0.0f, 10.0f,  0.0f,  0.0f,  0.0f,  0.0f,  0.0f},
        {  2.0f,  2.0f,  2.0f,  2.0f,  2.0f,  2.0f,  2.0f,  2.0f},
        {  1.0f,  2.0f,  3.0f,  4.0f,  5.0f,  6.0f,  7.0f,  8.0f},
        { -1.0f, -2.0f, -3.0f, -4.0f, -5.0f, -6.0f, -7.0f, -8.0f},
        {  8.0f,  8.0f,  8.0f,  8.0f,  8.0f,  8.0f,  8.0f,  8.0f},
    };
    const uint64_t ids[] = {
        9401u, 9402u, 9403u, 9404u, 9405u, 9406u, 9407u, 9408u
    };

    char* path = make_temp_db_path("qmag_policy");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env->uma, path);
    TEST_ASSERT(db != NULL, "create should return a database for qmag policy tests");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, &vectors[0][0], ARRAY_LEN(vectors),
                                            ARRAY_LEN(vectors[0]), ids, NULL, NULL),
                "qmag policy fixture insert should succeed");
    TEST_ASSERT(close_db(db), "database should close and write qmag policy sidecars");

    *out_path = path;
    return true;
}

static bool create_low_active_qmag_policy_db(test_env_t* env, char** out_path) {
    enum { ROWS = 512, DIMS = 64 };
    float vectors[ROWS * DIMS];
    uint64_t ids[ROWS];

    memset(vectors, 0, sizeof(vectors));
    for (size_t row = 0u; row < ROWS; row++) {
        vectors[(row * DIMS) + 0u] = 2.55f - ((float)row * 0.003f);
        for (size_t dim = 1u; dim < DIMS; dim++) {
            vectors[(row * DIMS) + dim] = 0.1f;
        }
        ids[row] = 95000u + (uint64_t)row;
    }

    char* path = make_temp_db_path("qmag_low_active_default_policy");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env->uma, path);
    TEST_ASSERT(db != NULL, "create should return a low-active qmag policy database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, vectors, ROWS, DIMS, ids, NULL, NULL),
                "low-active qmag policy fixture insert should succeed");
    TEST_ASSERT(close_db(db), "database should close and write low-active qmag sidecars");

    *out_path = path;
    return true;
}

static bool create_high_top_k_qmag_policy_db(test_env_t* env, char** out_path) {
    enum { ROWS = 512, DIMS = 64, DECOYS = 300 };
    float vectors[ROWS * DIMS];
    uint64_t ids[ROWS];

    memset(vectors, 0, sizeof(vectors));
    for (size_t row = 0u; row < ROWS; row++) {
        vectors[(row * DIMS) + 0u] = 10.0f;
        ids[row] = 96000u + (uint64_t)row;
        if (row < DECOYS) {
            for (size_t dim = 1u; dim < DIMS; dim++) {
                vectors[(row * DIMS) + dim] = 10.0f;
            }
        } else if (row >= DECOYS + 64u) {
            vectors[(row * DIMS) + 1u] = 20.0f;
        }
    }

    char* path = make_temp_db_path("qmag_high_top_k_default_policy");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env->uma, path);
    TEST_ASSERT(db != NULL, "create should return a high-top_k qmag policy database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, vectors, ROWS, DIMS, ids, NULL, NULL),
                "high-top_k qmag policy fixture insert should succeed");
    TEST_ASSERT(close_db(db), "database should close and write high-top_k qmag sidecars");

    *out_path = path;
    return true;
}

static bool create_dense_high_active_qmag_policy_db(test_env_t* env, char** out_path) {
    enum { ROWS = 512, DIMS = 64 };
    float vectors[ROWS * DIMS];
    uint64_t ids[ROWS];

    for (size_t row = 0u; row < ROWS; row++) {
        ids[row] = 97000u + (uint64_t)row;
        for (size_t dim = 0u; dim < DIMS; dim++) {
            const float row_bias = (float)(row % 29u) * 0.003f;
            const float dim_bias = (float)(dim % 7u) * 0.002f;
            vectors[(row * DIMS) + dim] = 1.0f + row_bias + dim_bias;
        }
    }

    char* path = make_temp_db_path("qmag_dense_high_active_default_policy");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env->uma, path);
    TEST_ASSERT(db != NULL, "create should return a dense high-active qmag policy database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, vectors, ROWS, DIMS, ids, NULL, NULL),
                "dense high-active qmag policy fixture insert should succeed");
    TEST_ASSERT(close_db(db),
                "database should close and write dense high-active qmag sidecars");

    *out_path = path;
    return true;
}

static bool create_positive_sign_collapse_qtri_db(test_env_t* env, char** out_path) {
    enum { ROWS = 40, DIMS = 2 };
    float vectors[ROWS * DIMS];
    uint64_t ids[ROWS];

    for (size_t row = 0; row < ROWS; row++) {
        vectors[(row * DIMS) + 0u] = 1.0f + ((float)row * 0.02f);
        vectors[(row * DIMS) + 1u] = 2.0f - ((float)row * 0.01f);
        ids[row] = 9200u + (uint64_t)row;
    }

    char* path = make_temp_db_path("pr5_qtri_positive_collapse");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env->uma, path);
    TEST_ASSERT(db != NULL, "create should return a database for positive qtri search");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, vectors, ROWS, DIMS, ids, NULL, NULL),
                "positive-only fixture insert should succeed");
    TEST_ASSERT(close_db(db), "database should close and write positive qtri sidecar");

    *out_path = path;
    return true;
}

static bool test_trinary_rerank_hydrates_requested_payloads(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("trinary_rerank_payloads");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vectors[][4] = {
        { 1.00f, -0.50f,  0.25f, -0.125f},
        {-0.25f,  0.75f, -1.00f,  0.500f},
        { 0.50f,  0.25f, -0.75f, -1.000f},
    };
    const uint64_t ids[] = {93001u, 93002u, 93003u};
    const uint8_t meta0[] = {0x70, 0x30, 0x00, 0xff};
    const uint8_t meta1[] = {0x70, 0x31, 0x13, 0x37, 0x00};
    const uint8_t meta2[] = {0x70, 0x32, 0x5a};
    const void* metas[] = {meta0, meta1, meta2};
    const size_t meta_sizes[] = {sizeof(meta0), sizeof(meta1), sizeof(meta2)};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, &vectors[0][0], ARRAY_LEN(vectors),
                                            ARRAY_LEN(vectors[0]), ids,
                                            metas, meta_sizes),
                "payload hydration fixture insert should succeed");
    TEST_ASSERT(close_db(db), "database should close and write trinary sidecars");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "payload hydration fixture should reopen read-only");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for payload hydration fixture");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "payload hydration fixture should have valid qtri");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "payload hydration fixture should have valid qmag");

    qihse_vector_result_t scalar_results[2];
    memset(scalar_results, 0, sizeof(scalar_results));
    qihse_vector_query_t scalar_query = {
        .query_vector = vectors[1],
        .vector_dims = ARRAY_LEN(vectors[1]),
        .top_k = 2u,
        .similarity_threshold = -1.0f,
        .include_vectors = true,
        .include_metadata = true,
        .query_mode = QIHSE_VDB_QUERY_TRINARY_SCALAR,
        .candidate_pool_size = ARRAY_LEN(vectors),
    };
    int count = qihse_vector_db_search(db, &scalar_query, scalar_results,
                                       ARRAY_LEN(scalar_results));
    TEST_ASSERT(count == 2, "scalar trinary rerank should return two results");
    TEST_ASSERT(scalar_results[0].id == ids[1],
                "scalar trinary rerank should return exact match first");
    TEST_ASSERT(vector_eq(scalar_results[0].vector, vectors[1], ARRAY_LEN(vectors[1])),
                "scalar trinary rerank should hydrate requested vector");
    TEST_ASSERT(scalar_results[0].metadata_size == sizeof(meta1),
                "scalar trinary rerank should hydrate requested metadata size");
    TEST_ASSERT(memcmp(scalar_results[0].metadata, meta1, sizeof(meta1)) == 0,
                "scalar trinary rerank should hydrate requested metadata bytes");
    free_results(scalar_results, ARRAY_LEN(scalar_results));

    qihse_vector_result_t omitted_result;
    memset(&omitted_result, 0, sizeof(omitted_result));
    qihse_vector_query_t omitted_query = {
        .query_vector = vectors[1],
        .vector_dims = ARRAY_LEN(vectors[1]),
        .top_k = 1u,
        .similarity_threshold = -1.0f,
        .include_vectors = false,
        .include_metadata = false,
        .query_mode = QIHSE_VDB_QUERY_TRINARY_SCALAR,
        .candidate_pool_size = ARRAY_LEN(vectors),
    };
    count = qihse_vector_db_search(db, &omitted_query, &omitted_result, 1u);
    TEST_ASSERT(count == 1, "scalar trinary rerank should return one omitted-payload result");
    TEST_ASSERT(omitted_result.id == ids[1],
                "scalar trinary rerank should still return the exact match");
    TEST_ASSERT(omitted_result.vector == NULL,
                "scalar trinary rerank should omit vector when not requested");
    TEST_ASSERT(omitted_result.metadata == NULL && omitted_result.metadata_size == 0u,
                "scalar trinary rerank should omit metadata when not requested");
    free_results(&omitted_result, 1u);

    qihse_vector_result_t qmag_result;
    memset(&qmag_result, 0, sizeof(qmag_result));
    qihse_vector_query_t qmag_query = {
        .query_vector = vectors[1],
        .vector_dims = ARRAY_LEN(vectors[1]),
        .top_k = 1u,
        .similarity_threshold = -1.0f,
        .include_vectors = true,
        .include_metadata = true,
        .query_mode = QIHSE_VDB_QUERY_TRINARY_MAGNITUDE,
        .candidate_pool_size = ARRAY_LEN(vectors),
    };
    count = qihse_vector_db_search(db, &qmag_query, &qmag_result, 1u);
    TEST_ASSERT(count == 1, "qmag trinary rerank should return one result");
    TEST_ASSERT(qmag_result.id == ids[1],
                "qmag trinary rerank should return exact match");
    TEST_ASSERT(vector_eq(qmag_result.vector, vectors[1], ARRAY_LEN(vectors[1])),
                "qmag trinary rerank should hydrate requested vector");
    TEST_ASSERT(qmag_result.metadata_size == sizeof(meta1),
                "qmag trinary rerank should hydrate requested metadata size");
    TEST_ASSERT(memcmp(qmag_result.metadata, meta1, sizeof(meta1)) == 0,
                "qmag trinary rerank should hydrate requested metadata bytes");
    free_results(&qmag_result, 1u);

    TEST_ASSERT(qihse_vector_db_close(db), "payload hydration fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_trinary_candidate_search_matches_float32_top_ids(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "sign-friendly qtri DB fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "qtri fixture should reopen read-only");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for qtri fixture");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "qtri fixture should have a valid sidecar");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t float32_results[3];
    qihse_vector_result_t qtri_results[3];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qtri_results, 0, sizeof(qtri_results));

    int float32_count = search_many(db, query, ARRAY_LEN(query), 3u,
                                    float32_results, ARRAY_LEN(float32_results));
    int qtri_count = search_many_qtri(db, query, ARRAY_LEN(query), 3u, 5u,
                                      qtri_results, ARRAY_LEN(qtri_results));
    TEST_ASSERT(float32_count == 3, "FLOAT32 search should return top 3");
    TEST_ASSERT(qtri_count == 3, "qtri candidate search should return top 3");
    for (size_t i = 0; i < ARRAY_LEN(float32_results); i++) {
        TEST_ASSERT(qtri_results[i].id == float32_results[i].id,
                    "qtri candidate search should preserve FLOAT32 top ID order");
    }

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qtri_results, ARRAY_LEN(qtri_results));
    TEST_ASSERT(qihse_vector_db_close(db), "read-only qtri fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_default_search_ignores_missing_or_corrupt_qtri(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "default-search missing/corrupt fixture should be created");

    char qtri_path[512];
    snprintf(qtri_path, sizeof(qtri_path), "%s/vectors.qtri", path);
    TEST_ASSERT(unlink(qtri_path) == 0, "test should remove vectors.qtri");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "missing qtri should not block default open");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t result;
    int count = search_many(db, query, ARRAY_LEN(query), 1u, &result, 1u);
    TEST_ASSERT(count == 1, "default FLOAT32 search should work with missing qtri");
    TEST_ASSERT(result.id == 9101, "default FLOAT32 search should return expected ID");
    free_results(&result, 1u);
    TEST_ASSERT(qihse_vector_db_close(db), "missing-qtri database should close");

    const uint8_t invalid_tryte[] = {0xff, 0x00};
    TEST_ASSERT(write_qtri_payload(path, invalid_tryte, sizeof(invalid_tryte)),
                "test should write corrupt qtri sidecar");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "corrupt qtri should not block default open");
    count = search_many(db, query, ARRAY_LEN(query), 1u, &result, 1u);
    TEST_ASSERT(count == 1, "default FLOAT32 search should work with corrupt qtri");
    TEST_ASSERT(result.id == 9101, "default FLOAT32 search should ignore corrupt qtri");
    free_results(&result, 1u);

    TEST_ASSERT(qihse_vector_db_close(db), "corrupt-qtri database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_trinary_candidate_search_rejects_missing_or_corrupt_qtri(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "opt-in rejection fixture should be created");

    char qtri_path[512];
    snprintf(qtri_path, sizeof(qtri_path), "%s/vectors.qtri", path);
    TEST_ASSERT(unlink(qtri_path) == 0, "test should remove vectors.qtri");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "missing qtri fixture should reopen");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t result;
    int count = search_many_qtri(db, query, ARRAY_LEN(query), 1u, 3u, &result, 1u);
    TEST_ASSERT(count < 0, "opt-in qtri search should reject missing qtri");
    TEST_ASSERT(qihse_vector_db_close(db), "missing-qtri opt-in fixture should close");

    const uint8_t invalid_tryte[] = {0xff, 0x00};
    TEST_ASSERT(write_qtri_payload(path, invalid_tryte, sizeof(invalid_tryte)),
                "test should write corrupt qtri sidecar");
    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "corrupt qtri fixture should reopen");
    count = search_many_qtri(db, query, ARRAY_LEN(query), 1u, 3u, &result, 1u);
    TEST_ASSERT(count < 0, "opt-in qtri search should reject corrupt qtri");

    TEST_ASSERT(qihse_vector_db_close(db), "corrupt-qtri opt-in fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_trinary_candidate_search_validates_counts(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "count-validation fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "count-validation fixture should reopen");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t results[3];
    TEST_ASSERT(search_many_qtri(db, query, ARRAY_LEN(query), 0u, 3u,
                                 results, ARRAY_LEN(results)) < 0,
                "opt-in qtri search should reject top_k == 0");
    TEST_ASSERT(search_many_qtri(db, query, ARRAY_LEN(query), 2u, 0u,
                                 results, ARRAY_LEN(results)) < 0,
                "opt-in qtri search should reject candidate_count == 0");
    TEST_ASSERT(search_many_qtri(db, query, ARRAY_LEN(query), 3u, 2u,
                                 results, ARRAY_LEN(results)) < 0,
                "opt-in qtri search should reject candidate_count < top_k");
    TEST_ASSERT(search_many_qtri(db, query, ARRAY_LEN(query), 3u, 5u,
                                 results, 2u) < 0,
                "opt-in qtri search should reject max_results < top_k");

    TEST_ASSERT(qihse_vector_db_close(db), "count-validation fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_explicit_scalar_default_candidate_pool_searches(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "scalar-default fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "scalar-default fixture should reopen");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t float32_results[3];
    qihse_vector_result_t qtri_results[3];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qtri_results, 0, sizeof(qtri_results));

    int float32_count = search_many(db, query, ARRAY_LEN(query), 3u,
                                    float32_results, ARRAY_LEN(float32_results));
    int qtri_count = search_many_qtri_scalar(db, query, ARRAY_LEN(query), 3u,
                                             0u, 0u, qtri_results,
                                             ARRAY_LEN(qtri_results));
    TEST_ASSERT(float32_count == 3, "FLOAT32 search should return top 3");
    TEST_ASSERT(qtri_count == 3,
                "explicit scalar mode should default candidate_pool_size == 0");
    for (size_t i = 0; i < ARRAY_LEN(float32_results); i++) {
        TEST_ASSERT(qtri_results[i].id == float32_results[i].id,
                    "default scalar candidate pool should preserve top ID order");
    }

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qtri_results, ARRAY_LEN(qtri_results));
    TEST_ASSERT(qihse_vector_db_close(db), "scalar-default fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_tombstone_heavy_small_qtri_pool_skips_deleted_rows(void) {
    enum { ROWS = 24, DIMS = 4 };
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("qtri_tombstone_heavy_small_pool");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    float vectors[ROWS * DIMS];
    uint64_t ids[ROWS];
    for (size_t row = 0; row < ROWS; row++) {
        vectors[(row * DIMS) + 0u] = 1.0f + ((float)row * 0.001f);
        vectors[(row * DIMS) + 1u] = 2.0f + ((float)row * 0.001f);
        vectors[(row * DIMS) + 2u] = -3.0f - ((float)row * 0.001f);
        vectors[(row * DIMS) + 3u] = -4.0f - ((float)row * 0.001f);
        ids[row] = 94000u + (uint64_t)row;
    }

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, vectors, ROWS, DIMS, ids, NULL, NULL),
                "tombstone-heavy fixture insert should succeed");
    for (size_t row = 0; row + 1u < ROWS; row++) {
        TEST_ASSERT(qihse_vector_db_delete_by_id(db, ids[row]),
                    "tombstone-heavy fixture delete should succeed");
    }
    TEST_ASSERT(qihse_vector_db_checkpoint(db),
                "checkpoint should publish tombstone-heavy physical rows");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after tombstone-heavy checkpoint");
    TEST_ASSERT(stats.live_vectors == 1u,
                "tombstone-heavy fixture should leave one live row");
    TEST_ASSERT(stats.index_rows > stats.live_vectors,
                "tombstone-heavy fixture should keep deleted physical rows before compact");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "checkpointed tombstone-heavy fixture should have valid qtri");
    TEST_ASSERT(close_db(db), "tombstone-heavy fixture should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "tombstone-heavy fixture should reopen read-only");

    const float* query = &vectors[(ROWS - 1u) * DIMS];
    qihse_vector_result_t result;
    memset(&result, 0, sizeof(result));
    int count = search_many_qtri_scalar(db, query, DIMS, 1u, 1u, 0u, &result, 1u);
    TEST_ASSERT(count == 1,
                "explicit one-row qtri pool should skip deleted physical rows");
    TEST_ASSERT(result.id == ids[ROWS - 1u],
                "explicit one-row qtri pool should return the remaining live row");
    free_results(&result, 1u);

    TEST_ASSERT(qihse_vector_db_close(db), "tombstone-heavy fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_scalar_default_pool_handles_positive_sign_collapse(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_positive_sign_collapse_qtri_db(&env, &path),
                "positive sign-collapse fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "positive sign-collapse fixture should reopen");

    const float query[] = {1.78f, 1.61f};
    qihse_vector_result_t float32_results[3];
    qihse_vector_result_t qtri_results[3];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qtri_results, 0, sizeof(qtri_results));

    int float32_count = search_many(db, query, ARRAY_LEN(query), 3u,
                                    float32_results, ARRAY_LEN(float32_results));
    int qtri_count = search_many_qtri_scalar(db, query, ARRAY_LEN(query), 3u,
                                             0u, 0u, qtri_results,
                                             ARRAY_LEN(qtri_results));
    TEST_ASSERT(float32_count == 3, "FLOAT32 search should return top 3");
    TEST_ASSERT(qtri_count == 3,
                "default scalar qtri should return top 3 after full-row rerank");
    for (size_t i = 0; i < ARRAY_LEN(float32_results); i++) {
        TEST_ASSERT(qtri_results[i].id == float32_results[i].id,
                    "positive-only scalar qtri should preserve FLOAT32 top IDs");
    }

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qtri_results, ARRAY_LEN(qtri_results));
    TEST_ASSERT(qihse_vector_db_close(db), "positive sign-collapse fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_sidecar_persists_and_magnitude_query_matches_float32(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "qmag fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "qmag fixture should reopen read-only");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for qmag fixture");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "qmag fixture should also have a valid qtri sidecar");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "qmag fixture should have a valid magnitude sidecar");
    TEST_ASSERT(stats.magnitude_row_bytes == 6u,
                "six-dimensional qmag rows should use six bytes");
    TEST_ASSERT(stats.magnitude_rows == 5u,
                "qmag should contain all physical rows");

    off_t qmag_size = 0;
    TEST_ASSERT(file_size_of(path, "vectors.qmag", &qmag_size),
                "vectors.qmag size should be readable");
    TEST_ASSERT(qmag_size == (off_t)(stats.magnitude_row_bytes * stats.magnitude_rows),
                "vectors.qmag size should match raw magnitude rows");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t float32_results[3];
    qihse_vector_result_t qmag_results[3];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, query, ARRAY_LEN(query), 3u,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, query, ARRAY_LEN(query), 3u, 5u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == 3, "FLOAT32 search should return top 3 for qmag fixture");
    TEST_ASSERT(qmag_count == 3, "qmag candidate search should return top 3");
    for (size_t i = 0; i < ARRAY_LEN(float32_results); i++) {
        TEST_ASSERT(qmag_results[i].id == float32_results[i].id,
                    "qmag candidate search should preserve FLOAT32 top ID order");
    }

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "read-only qmag fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_default_candidate_pool_searches(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "qmag-default fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "qmag-default fixture should reopen");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t float32_results[3];
    qihse_vector_result_t qmag_results[3];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, query, ARRAY_LEN(query), 3u,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, query, ARRAY_LEN(query), 3u, 0u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == 3, "FLOAT32 search should return top 3");
    TEST_ASSERT(qmag_count == 3,
                "qmag mode should default candidate_pool_size == 0");
    for (size_t i = 0; i < ARRAY_LEN(float32_results); i++) {
        TEST_ASSERT(qmag_results[i].id == float32_results[i].id,
                    "default qmag candidate pool should preserve top ID order");
    }

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "qmag-default fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_sparse_default_policy_matches_float32(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_qmag_policy_db(&env, &path),
                "qmag sparse policy fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "qmag sparse policy fixture should reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for qmag sparse policy fixture");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "qmag sparse policy fixture should have valid qtri");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "qmag sparse policy fixture should have valid qmag");

    const float sparse_query[] = {10.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    qihse_vector_result_t float32_results[4];
    qihse_vector_result_t qmag_results[4];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, sparse_query, ARRAY_LEN(sparse_query), 4u,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, sparse_query, ARRAY_LEN(sparse_query), 4u, 0u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == 4, "FLOAT32 sparse policy search should return top 4");
    TEST_ASSERT(qmag_count == 4,
                "qmag sparse default policy should return top 4 or fall back safely");
    TEST_ASSERT(expect_same_result_ids(float32_results, qmag_results, 4u,
                                       "qmag sparse default policy should preserve IDs"),
                "qmag sparse default policy result IDs should match FLOAT32");

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "qmag sparse policy fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_dense_default_policy_matches_float32(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_qmag_policy_db(&env, &path),
                "qmag dense policy fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "qmag dense policy fixture should reopen");

    const float dense_query[] = {8.0f, 8.0f, 8.0f, 8.0f, 8.0f, 8.0f, 8.0f, 8.0f};
    qihse_vector_result_t float32_results[6];
    qihse_vector_result_t qmag_results[6];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, dense_query, ARRAY_LEN(dense_query), 6u,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, dense_query, ARRAY_LEN(dense_query), 6u, 0u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == 6, "FLOAT32 dense policy search should return top 6");
    TEST_ASSERT(qmag_count == 6,
                "qmag dense default policy should return top 6 or fall back safely");
    TEST_ASSERT(expect_same_result_ids(float32_results, qmag_results, 6u,
                                       "qmag dense default policy should preserve IDs"),
                "qmag dense default policy result IDs should match FLOAT32");

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "qmag dense policy fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_adaptive_pool_top_k_boundaries(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_qmag_policy_db(&env, &path),
                "qmag adaptive pool fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "qmag adaptive pool fixture should reopen");

    const float query[] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    qihse_vector_result_t float32_one[1];
    qihse_vector_result_t qmag_one[1];
    qihse_vector_result_t float32_many[6];
    qihse_vector_result_t qmag_many[6];
    memset(float32_one, 0, sizeof(float32_one));
    memset(qmag_one, 0, sizeof(qmag_one));
    memset(float32_many, 0, sizeof(float32_many));
    memset(qmag_many, 0, sizeof(qmag_many));

    int float32_count = search_many(db, query, ARRAY_LEN(query), 1u,
                                    float32_one, ARRAY_LEN(float32_one));
    int qmag_count = search_many_qmag(db, query, ARRAY_LEN(query), 1u, 0u,
                                      qmag_one, ARRAY_LEN(qmag_one));
    TEST_ASSERT(float32_count == 1, "FLOAT32 adaptive boundary search should return top 1");
    TEST_ASSERT(qmag_count == 1, "qmag adaptive default pool should handle top_k=1");
    TEST_ASSERT(qmag_one[0].id == float32_one[0].id,
                "qmag adaptive top_k=1 result should match FLOAT32");

    float32_count = search_many(db, query, ARRAY_LEN(query), 6u,
                                float32_many, ARRAY_LEN(float32_many));
    qmag_count = search_many_qmag(db, query, ARRAY_LEN(query), 6u, 0u,
                                  qmag_many, ARRAY_LEN(qmag_many));
    TEST_ASSERT(float32_count == 6, "FLOAT32 adaptive boundary search should return top 6");
    TEST_ASSERT(qmag_count == 6, "qmag adaptive default pool should handle larger top_k");
    TEST_ASSERT(expect_same_result_ids(float32_many, qmag_many, 6u,
                                       "qmag adaptive larger top_k should preserve IDs"),
                "qmag adaptive larger top_k IDs should match FLOAT32");

    free_results(float32_one, ARRAY_LEN(float32_one));
    free_results(qmag_one, ARRAY_LEN(qmag_one));
    free_results(float32_many, ARRAY_LEN(float32_many));
    free_results(qmag_many, ARRAY_LEN(qmag_many));
    TEST_ASSERT(qihse_vector_db_close(db), "qmag adaptive pool fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_100_case_small_row_default_falls_back_to_float32(void) {
    enum { TOP_K = 6 };
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_qmag_policy_db(&env, &path),
                "small-row qmag policy fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "small-row qmag policy fixture should reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for small-row qmag fixture");
    TEST_ASSERT(stats.live_vectors == 8u,
                "small-row fixture should stay below the default qmag row floor");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "small-row qmag fixture should have valid qmag");

    const float query[] = {8.0f, 8.0f, 8.0f, 8.0f, 8.0f, 8.0f, 8.0f, 8.0f};
    qihse_vector_result_t float32_results[TOP_K];
    qihse_vector_result_t qmag_results[TOP_K];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, query, ARRAY_LEN(query), TOP_K,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, query, ARRAY_LEN(query), TOP_K, 0u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == TOP_K,
                "FLOAT32 small-row policy search should return top results");
    TEST_ASSERT(qmag_count == TOP_K,
                "default qmag small-row fallback should return top results");
    TEST_ASSERT(expect_same_result_ids(float32_results, qmag_results, TOP_K,
                                       "default qmag small-row fallback should preserve IDs"),
                "default qmag small-row fallback IDs should match FLOAT32");

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "small-row qmag fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_100_case_dense_high_active_default_falls_back_to_float32(void) {
    enum { DIMS = 64, TOP_K = 16 };
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_dense_high_active_qmag_policy_db(&env, &path),
                "dense high-active qmag policy fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "dense high-active qmag policy fixture should reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for dense high-active qmag fixture");
    TEST_ASSERT(stats.live_vectors == 512u,
                "dense high-active fixture should meet qmag policy live-row floor");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "dense high-active qmag fixture should have valid qmag");

    float query[DIMS];
    for (size_t dim = 0u; dim < DIMS; dim++) {
        query[dim] = 1.0f + ((float)(dim % 7u) * 0.002f);
    }

    qihse_vector_result_t float32_results[TOP_K];
    qihse_vector_result_t qmag_results[TOP_K];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, query, DIMS, TOP_K,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, query, DIMS, TOP_K, 0u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == TOP_K,
                "FLOAT32 dense high-active policy search should return top results");
    TEST_ASSERT(qmag_count == TOP_K,
                "default qmag dense high-active fallback should return top results");
    TEST_ASSERT(expect_same_result_ids(float32_results, qmag_results, TOP_K,
                                       "default qmag dense high-active fallback should preserve IDs"),
                "default qmag dense high-active fallback IDs should match FLOAT32");

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "dense high-active qmag fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_100_case_sparse_low_pressure_default_matches_float32(void) {
    enum { DIMS = 64, TOP_K = 4 };
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_low_active_qmag_policy_db(&env, &path),
                "sparse low-pressure qmag policy fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "sparse low-pressure qmag policy fixture should reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for sparse low-pressure qmag fixture");
    TEST_ASSERT(stats.live_vectors == 512u,
                "sparse low-pressure fixture should meet qmag policy live-row floor");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "sparse low-pressure qmag fixture should have valid qmag");

    const float query[DIMS] = {10.0f};
    qihse_vector_result_t float32_results[TOP_K];
    qihse_vector_result_t qmag_results[TOP_K];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, query, DIMS, TOP_K,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, query, DIMS, TOP_K, 0u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == TOP_K,
                "FLOAT32 sparse low-pressure policy search should return top results");
    TEST_ASSERT(qmag_count == TOP_K,
                "default qmag sparse low-pressure policy search should return top results");
    TEST_ASSERT(expect_same_result_ids(float32_results, qmag_results, TOP_K,
                                       "default qmag sparse low-pressure should preserve IDs"),
                "default qmag sparse low-pressure IDs should match FLOAT32");

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "sparse low-pressure qmag fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_100_case_explicit_pool_runs_when_default_falls_back(void) {
    enum { DIMS = 64, TOP_K = 32 };
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_high_top_k_qmag_policy_db(&env, &path),
                "explicit qmag 100-case fallback fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "explicit qmag 100-case fallback fixture should reopen");

    const float query[DIMS] = {10.0f};
    qihse_vector_result_t default_results[TOP_K];
    qihse_vector_result_t explicit_results[TOP_K];
    memset(default_results, 0, sizeof(default_results));
    memset(explicit_results, 0, sizeof(explicit_results));

    int default_count = search_many_qmag(db, query, DIMS, TOP_K, 0u,
                                         default_results, ARRAY_LEN(default_results));
    int explicit_count = search_many_qmag(db, query, DIMS, TOP_K, TOP_K,
                                          explicit_results, ARRAY_LEN(explicit_results));
    TEST_ASSERT(default_count == TOP_K,
                "default qmag high-pressure fallback should return top results");
    TEST_ASSERT(explicit_count == TOP_K,
                "explicit qmag pool should still execute under fallback-shaped pressure");

    bool differs = false;
    for (size_t i = 0u; i < TOP_K; i++) {
        if (explicit_results[i].id != default_results[i].id) {
            differs = true;
            break;
        }
    }
    TEST_ASSERT(differs,
                "explicit qmag pool should use caller-selected shortlist, not default fallback");

    free_results(default_results, ARRAY_LEN(default_results));
    free_results(explicit_results, ARRAY_LEN(explicit_results));
    TEST_ASSERT(qihse_vector_db_close(db), "explicit qmag 100-case fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_low_active_low_top_k_default_policy_matches_float32(void) {
    enum { DIMS = 64, TOP_K = 4 };
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_low_active_qmag_policy_db(&env, &path),
                "low-active qmag default policy fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "low-active qmag default policy fixture should reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for low-active qmag policy fixture");
    TEST_ASSERT(stats.live_vectors == 512u,
                "low-active qmag policy fixture should meet qmag policy live-row floor");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "low-active qmag policy fixture should have valid qmag");

    const float query[DIMS] = {10.0f};
    qihse_vector_result_t float32_results[TOP_K];
    qihse_vector_result_t qmag_results[TOP_K];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, query, DIMS, TOP_K,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, query, DIMS, TOP_K, 0u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == TOP_K,
                "FLOAT32 low-active low-top_k policy search should return top results");
    TEST_ASSERT(qmag_count == TOP_K,
                "default qmag low-active low-top_k policy search should return top results");
    TEST_ASSERT(expect_same_result_ids(float32_results, qmag_results, TOP_K,
                                       "default qmag low-active low-top_k should preserve IDs"),
                "default qmag low-active low-top_k IDs should match FLOAT32");

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "low-active qmag policy fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_high_top_k_default_policy_falls_back_to_float32(void) {
    enum { DIMS = 64, TOP_K = 32 };
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_high_top_k_qmag_policy_db(&env, &path),
                "high-top_k qmag default policy fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "high-top_k qmag default policy fixture should reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for high-top_k qmag policy fixture");
    TEST_ASSERT(stats.live_vectors == 512u,
                "high-top_k qmag policy fixture should meet qmag policy live-row floor");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "high-top_k qmag policy fixture should have valid qmag");

    const float query[DIMS] = {10.0f};
    qihse_vector_result_t float32_results[TOP_K];
    qihse_vector_result_t qmag_results[TOP_K];
    memset(float32_results, 0, sizeof(float32_results));
    memset(qmag_results, 0, sizeof(qmag_results));

    int float32_count = search_many(db, query, DIMS, TOP_K,
                                    float32_results, ARRAY_LEN(float32_results));
    int qmag_count = search_many_qmag(db, query, DIMS, TOP_K, 0u,
                                      qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(float32_count == TOP_K,
                "FLOAT32 high-top_k policy search should return top results");
    TEST_ASSERT(qmag_count == TOP_K,
                "default qmag high-top_k policy search should return top results");
    TEST_ASSERT(expect_same_result_ids(float32_results, qmag_results, TOP_K,
                                       "default qmag high-top_k fallback should preserve IDs"),
                "default qmag high-top_k fallback IDs should match FLOAT32");

    free_results(float32_results, ARRAY_LEN(float32_results));
    free_results(qmag_results, ARRAY_LEN(qmag_results));
    TEST_ASSERT(qihse_vector_db_close(db), "high-top_k qmag policy fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_explicit_qmag_pool_bypasses_default_performance_gate(void) {
    enum { DIMS = 64, TOP_K = 32 };
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_high_top_k_qmag_policy_db(&env, &path),
                "explicit qmag gate-bypass fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "explicit qmag gate-bypass fixture should reopen");

    const float query[DIMS] = {10.0f};
    qihse_vector_result_t default_results[TOP_K];
    qihse_vector_result_t explicit_results[TOP_K];
    memset(default_results, 0, sizeof(default_results));
    memset(explicit_results, 0, sizeof(explicit_results));

    int default_count = search_many_qmag(db, query, DIMS, TOP_K, 0u,
                                         default_results, ARRAY_LEN(default_results));
    int explicit_count = search_many_qmag(db, query, DIMS, TOP_K, TOP_K,
                                          explicit_results, ARRAY_LEN(explicit_results));
    TEST_ASSERT(default_count == TOP_K,
                "default qmag high-top_k gate-bypass fixture should return top results");
    TEST_ASSERT(explicit_count == TOP_K,
                "explicit qmag pool should return top results");

    bool differs = false;
    for (size_t i = 0u; i < TOP_K; i++) {
        if (explicit_results[i].id != default_results[i].id) {
            differs = true;
            break;
        }
    }
    TEST_ASSERT(differs,
                "explicit qmag pool should use caller-selected qmag shortlist, not default fallback");

    free_results(default_results, ARRAY_LEN(default_results));
    free_results(explicit_results, ARRAY_LEN(explicit_results));
    TEST_ASSERT(qihse_vector_db_close(db), "explicit qmag gate-bypass fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_default_search_ignores_missing_or_corrupt_qmag(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "default-search qmag fixture should be created");

    char qmag_path[512];
    snprintf(qmag_path, sizeof(qmag_path), "%s/vectors.qmag", path);
    TEST_ASSERT(unlink(qmag_path) == 0, "test should remove vectors.qmag");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "missing qmag should not block default open");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for missing qmag");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_ABSENT,
                "missing qmag should be reported absent");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t result;
    int count = search_many(db, query, ARRAY_LEN(query), 1u, &result, 1u);
    TEST_ASSERT(count == 1, "default FLOAT32 search should work with missing qmag");
    TEST_ASSERT(result.id == 9101, "default FLOAT32 search should return expected ID");
    free_results(&result, 1u);
    count = search_many_qmag(db, query, ARRAY_LEN(query), 1u, 5u, &result, 1u);
    TEST_ASSERT(count < 0, "opt-in qmag search should reject missing qmag");
    TEST_ASSERT(qihse_vector_db_close(db), "missing-qmag database should close");

    const uint8_t corrupt_qmag[] = {0xff, 0x00};
    TEST_ASSERT(write_file_payload(path, "vectors.qmag", corrupt_qmag, sizeof(corrupt_qmag)),
                "test should write corrupt qmag sidecar");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "corrupt qmag should not block default open");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for corrupt qmag");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_CORRUPT,
                "corrupt qmag should be reported corrupt");
    count = search_many(db, query, ARRAY_LEN(query), 1u, &result, 1u);
    TEST_ASSERT(count == 1, "default FLOAT32 search should work with corrupt qmag");
    TEST_ASSERT(result.id == 9101, "default FLOAT32 search should ignore corrupt qmag");
    free_results(&result, 1u);
    count = search_many_qmag(db, query, ARRAY_LEN(query), 1u, 5u, &result, 1u);
    TEST_ASSERT(count < 0, "opt-in qmag search should reject corrupt qmag");

    TEST_ASSERT(qihse_vector_db_close(db), "corrupt-qmag database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_stale_reported_and_opt_in_rejected(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "qmag stale fixture should be created");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "qmag stale fixture should reopen writable");

    const float replacement[] = {-2.0f, -1.0f, -3.0f, 1.0f, 3.0f, 2.0f};
    TEST_ASSERT(qihse_vector_db_update_by_id(db, 9102u, replacement,
                                             ARRAY_LEN(replacement), NULL, 0),
                "qmag stale fixture update should succeed");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after qmag stale update");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_STALE,
                "updated fixture should report qmag stale distinctly");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_STALE,
                "updated fixture should also report qtri stale distinctly");

    qihse_vector_result_t result;
    memset(&result, 0, sizeof(result));
    int count = search_many(db, replacement, ARRAY_LEN(replacement), 1u, &result, 1u);
    TEST_ASSERT(count == 1, "default FLOAT32 search should work with stale qmag");
    TEST_ASSERT(result.id == 9102u, "default search should return updated row");
    free_results(&result, 1u);

    memset(&result, 0, sizeof(result));
    count = search_many_qmag(db, replacement, ARRAY_LEN(replacement), 1u, 5u,
                             &result, 1u);
    TEST_ASSERT(count < 0, "opt-in qmag search should reject stale qmag");

    TEST_ASSERT(qihse_vector_db_close(db), "qmag stale fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_qmag_mutations_compact_and_reopen_refresh_candidates(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("qmag_mutation_compact_reopen");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float deleted[] = {8.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    const float updated_old[] = {0.0f, 8.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    const float upsert_old[] = {0.0f, 0.0f, 8.0f, 0.0f, 0.0f, 0.0f};
    const float stable[] = {0.0f, 0.0f, 0.0f, 8.0f, 0.0f, 0.0f};
    const float updated_new[] = {0.0f, 0.0f, 0.0f, 0.0f, 9.0f, 0.0f};
    const float upsert_vectors[][6] = {
        {0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 9.0f},
        {4.0f, 4.0f, 0.0f, 0.0f, 0.0f, 0.0f},
    };
    const uint64_t upsert_ids[] = {92003u, 92005u};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, deleted, ARRAY_LEN(deleted), 92001u, NULL, 0),
                "qmag delete target insert should succeed");
    TEST_ASSERT(add_one(db, updated_old, ARRAY_LEN(updated_old), 92002u, NULL, 0),
                "qmag update target insert should succeed");
    TEST_ASSERT(add_one(db, upsert_old, ARRAY_LEN(upsert_old), 92003u, NULL, 0),
                "qmag upsert target insert should succeed");
    TEST_ASSERT(add_one(db, stable, ARRAY_LEN(stable), 92004u, NULL, 0),
                "qmag stable row insert should succeed");
    TEST_ASSERT(close_db(db), "database should close and write initial qmag sidecar");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "qmag mutation fixture should reopen writable");

    TEST_ASSERT(qihse_vector_db_delete_by_id(db, 92001u),
                "qmag delete mutation should succeed");
    TEST_ASSERT(qihse_vector_db_update_by_id(db, 92002u, updated_new,
                                             ARRAY_LEN(updated_new), NULL, 0),
                "qmag update mutation should succeed");
    size_t inserted_count = 0;
    size_t updated_count = 0;
    TEST_ASSERT(qihse_vector_db_upsert_by_ids(db, upsert_ids, &upsert_vectors[0][0],
                                              ARRAY_LEN(upsert_ids),
                                              ARRAY_LEN(upsert_vectors[0]),
                                              NULL, NULL,
                                              &inserted_count, &updated_count),
                "qmag upsert mutations should succeed");
    TEST_ASSERT(inserted_count == 1u && updated_count == 1u,
                "qmag upsert should report one insert and one update");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after qmag mutations");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_STALE,
                "delete/update/upsert should mark qmag stale");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_STALE,
                "delete/update/upsert should mark qtri stale");

    qihse_vector_result_t result;
    memset(&result, 0, sizeof(result));
    int count = search_many_qmag(db, updated_new, ARRAY_LEN(updated_new), 1u, 1u,
                                 &result, 1u);
    TEST_ASSERT(count < 0, "opt-in qmag search should reject stale mutation cache");

    count = search_one(db, deleted, ARRAY_LEN(deleted), false, false, &result);
    TEST_ASSERT(count == 0, "default search should not find deleted qmag row");
    count = search_one(db, updated_new, ARRAY_LEN(updated_new), false, false, &result);
    TEST_ASSERT(count == 1, "default search should find updated qmag row");
    TEST_ASSERT(result.id == 92002u, "default search should return updated qmag row id");
    free_results(&result, 1u);

    TEST_ASSERT(qihse_vector_db_compact(db), "compact should rebuild qmag after mutations");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after qmag mutation compact");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "compact should make qmag valid after mutations");
    TEST_ASSERT(stats.magnitude_row_bytes == ARRAY_LEN(updated_new),
                "compacted qmag row width should match vector dimensions");
    TEST_ASSERT(stats.magnitude_rows == stats.live_vectors,
                "compacted qmag rows should mirror live rows");
    TEST_ASSERT(stats.live_vectors == 4u,
                "compact should preserve four live qmag rows");
    TEST_ASSERT(close_db(db), "compacted qmag mutation fixture should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "compacted qmag mutation fixture should reopen read-only");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after qmag mutation reopen");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "reopened compacted qmag should remain valid");
    TEST_ASSERT(stats.magnitude_rows == 4u,
                "reopened compacted qmag should contain only live rows");

    memset(&result, 0, sizeof(result));
    count = search_many_qmag(db, updated_new, ARRAY_LEN(updated_new), 1u, 1u,
                             &result, 1u);
    TEST_ASSERT(count == 1, "qmag search after reopen should find updated row");
    TEST_ASSERT(result.id == 92002u, "qmag search after reopen should return updated id");
    free_results(&result, 1u);

    memset(&result, 0, sizeof(result));
    count = search_many_qmag(db, upsert_vectors[0], ARRAY_LEN(upsert_vectors[0]),
                             1u, 1u, &result, 1u);
    TEST_ASSERT(count == 1, "qmag search after reopen should find upsert-updated row");
    TEST_ASSERT(result.id == 92003u,
                "qmag search after reopen should return upsert-updated id");
    free_results(&result, 1u);

    memset(&result, 0, sizeof(result));
    count = search_many_qmag(db, upsert_vectors[1], ARRAY_LEN(upsert_vectors[1]),
                             1u, 1u, &result, 1u);
    TEST_ASSERT(count == 1, "qmag search after reopen should find upsert-inserted row");
    TEST_ASSERT(result.id == 92005u,
                "qmag search after reopen should return upsert-inserted id");
    free_results(&result, 1u);

    count = search_one(db, deleted, ARRAY_LEN(deleted), false, false, &result);
    TEST_ASSERT(count == 0, "deleted qmag row should stay absent after compact reopen");

    TEST_ASSERT(qihse_vector_db_close(db), "read-only compacted qmag fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_tombstone_heavy_small_qmag_pool_skips_deleted_and_old_rows(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("qmag_live_row_small_pool");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float deleted_hot[] = {12.0f, 0.0f, 0.0f, 0.0f};
    const float updated_old_hot[] = {0.0f, 12.0f, 0.0f, 0.0f};
    const float deleted_live_fallback[] = {11.0f, 0.0f, 0.0f, 0.0f};
    const float updated_old_live_fallback[] = {0.0f, 11.0f, 0.0f, 0.0f};
    const float updated_new[] = {0.0f, 0.0f, 12.0f, 0.0f};
    const float stable[] = {0.0f, 0.0f, 0.0f, 12.0f};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, deleted_hot, ARRAY_LEN(deleted_hot), 92101u, NULL, 0),
                "qmag deleted-hot row insert should succeed");
    TEST_ASSERT(add_one(db, updated_old_hot, ARRAY_LEN(updated_old_hot), 92102u, NULL, 0),
                "qmag old-update row insert should succeed");
    TEST_ASSERT(add_one(db, deleted_live_fallback, ARRAY_LEN(deleted_live_fallback),
                        92103u, NULL, 0),
                "qmag deleted-query live fallback insert should succeed");
    TEST_ASSERT(add_one(db, updated_old_live_fallback,
                        ARRAY_LEN(updated_old_live_fallback), 92104u, NULL, 0),
                "qmag old-query live fallback insert should succeed");
    TEST_ASSERT(add_one(db, stable, ARRAY_LEN(stable), 92105u, NULL, 0),
                "qmag stable row insert should succeed");
    TEST_ASSERT(close_db(db), "database should close and write qmag sidecar");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "qmag live-row fixture should reopen writable");
    TEST_ASSERT(qihse_vector_db_delete_by_id(db, 92101u),
                "qmag hot delete should succeed");
    TEST_ASSERT(qihse_vector_db_update_by_id(db, 92102u, updated_new,
                                             ARRAY_LEN(updated_new), NULL, 0),
                "qmag hot update should succeed");
    TEST_ASSERT(qihse_vector_db_compact(db),
                "compact should rebuild qmag with only live rows");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after qmag live-row compact");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "qmag should be valid after live-row compact");
    TEST_ASSERT(stats.magnitude_rows == stats.live_vectors,
                "qmag compact should mirror live rows");
    TEST_ASSERT(stats.live_vectors == 4u,
                "qmag live-row compact should prune one delete and one old update");
    TEST_ASSERT(close_db(db), "qmag live-row compact fixture should close");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY | QIHSE_TEST_OPEN_MMAP
    );
    TEST_ASSERT(db != NULL, "qmag live-row fixture should reopen read-only");

    qihse_vector_result_t result;
    memset(&result, 0, sizeof(result));
    int count = search_many_qmag(db, deleted_hot, ARRAY_LEN(deleted_hot), 1u, 1u,
                                 &result, 1u);
    TEST_ASSERT(count == 1,
                "small qmag pool should continue past deleted hot row to live row");
    TEST_ASSERT(result.id == 92103u,
                "small qmag pool should not return deleted hot row");
    free_results(&result, 1u);

    memset(&result, 0, sizeof(result));
    count = search_many_qmag(db, updated_old_hot, ARRAY_LEN(updated_old_hot), 1u, 1u,
                             &result, 1u);
    TEST_ASSERT(count == 1,
                "small qmag pool should continue past old updated row to live row");
    TEST_ASSERT(result.id == 92104u,
                "small qmag pool should not return old updated row");
    free_results(&result, 1u);

    memset(&result, 0, sizeof(result));
    count = search_many_qmag(db, updated_new, ARRAY_LEN(updated_new), 1u, 1u,
                             &result, 1u);
    TEST_ASSERT(count == 1,
                "small qmag pool should still find replacement updated row");
    TEST_ASSERT(result.id == 92102u,
                "small qmag pool should return replacement updated id");
    free_results(&result, 1u);

    TEST_ASSERT(qihse_vector_db_close(db), "qmag live-row read-only fixture should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_old_128_byte_manifest_opens_with_qmag_absent(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = NULL;
    TEST_ASSERT(create_sign_friendly_qtri_db(&env, &path),
                "old manifest qmag fixture should be created");

    char qmag_path[512];
    snprintf(qmag_path, sizeof(qmag_path), "%s/vectors.qmag", path);
    TEST_ASSERT(unlink(qmag_path) == 0, "test should remove vectors.qmag");
    TEST_ASSERT(truncate_file_to(path, "MANIFEST", 128),
                "test should truncate manifest to old 128-byte size");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "old 128-byte manifest should reopen read-only");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available for old manifest");
    TEST_ASSERT(stats.index_rows == 5u, "old manifest should preserve index row count");
    TEST_ASSERT(stats.live_vectors == 5u, "old manifest should preserve live row count");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "old manifest should preserve valid qtri stats");
    TEST_ASSERT(stats.trinary_row_bytes == 2u,
                "old manifest should preserve qtri row width");
    TEST_ASSERT(stats.trinary_rows == 5u,
                "old manifest should preserve qtri row count");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_ABSENT,
                "old manifest should report qmag absent");
    TEST_ASSERT(stats.magnitude_row_bytes == 0u,
                "old manifest should not invent qmag row width");
    TEST_ASSERT(stats.magnitude_rows == 0u,
                "old manifest should not invent qmag rows");

    const float query[] = {3.0f, 2.0f, 1.0f, -1.0f, -2.0f, -3.0f};
    qihse_vector_result_t result;
    int count = search_many(db, query, ARRAY_LEN(query), 1u, &result, 1u);
    TEST_ASSERT(count == 1, "FLOAT32 search should work with old manifest and no qmag");
    TEST_ASSERT(result.id == 9101, "old manifest search should return expected ID");
    free_results(&result, 1u);

    TEST_ASSERT(qihse_vector_db_close(db), "old-manifest database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}
#else
static bool pr5_trinary_search_api_unavailable(const char* test_name) {
    printf("SKIP %s: QIHSE_VECTOR_DB_PR5_TRINARY_SEARCH_API is not available in this branch\n",
           test_name);
    return true;
}

static bool test_trinary_candidate_search_matches_float32_top_ids(void) {
    return pr5_trinary_search_api_unavailable("qtri candidate search parity");
}

static bool test_trinary_rerank_hydrates_requested_payloads(void) {
    return pr5_trinary_search_api_unavailable("trinary rerank payload hydration");
}

static bool test_default_search_ignores_missing_or_corrupt_qtri(void) {
    return pr5_trinary_search_api_unavailable("default search missing/corrupt qtri tolerance");
}

static bool test_trinary_candidate_search_rejects_missing_or_corrupt_qtri(void) {
    return pr5_trinary_search_api_unavailable("opt-in qtri missing/corrupt rejection");
}

static bool test_trinary_candidate_search_validates_counts(void) {
    return pr5_trinary_search_api_unavailable("candidate_count/top_k validation");
}

static bool test_explicit_scalar_default_candidate_pool_searches(void) {
    return pr5_trinary_search_api_unavailable("explicit scalar default candidate pool");
}

static bool test_tombstone_heavy_small_qtri_pool_skips_deleted_rows(void) {
    return pr5_trinary_search_api_unavailable("tombstone-heavy small qtri pool");
}

static bool test_qmag_sidecar_persists_and_magnitude_query_matches_float32(void) {
    return pr5_trinary_search_api_unavailable("qmag persistence and candidate search parity");
}

static bool test_qmag_default_candidate_pool_searches(void) {
    return pr5_trinary_search_api_unavailable("qmag default candidate pool");
}

static bool test_qmag_sparse_default_policy_matches_float32(void) {
    return pr5_trinary_search_api_unavailable("qmag sparse default policy");
}

static bool test_qmag_dense_default_policy_matches_float32(void) {
    return pr5_trinary_search_api_unavailable("qmag dense default policy");
}

static bool test_qmag_adaptive_pool_top_k_boundaries(void) {
    return pr5_trinary_search_api_unavailable("qmag adaptive pool top_k boundaries");
}

static bool test_qmag_100_case_small_row_default_falls_back_to_float32(void) {
    return pr5_trinary_search_api_unavailable("qmag 100-case small-row default fallback");
}

static bool test_qmag_100_case_dense_high_active_default_falls_back_to_float32(void) {
    return pr5_trinary_search_api_unavailable("qmag 100-case dense/high-active fallback");
}

static bool test_qmag_100_case_sparse_low_pressure_default_matches_float32(void) {
    return pr5_trinary_search_api_unavailable("qmag 100-case sparse low-pressure parity");
}

static bool test_qmag_100_case_explicit_pool_runs_when_default_falls_back(void) {
    return pr5_trinary_search_api_unavailable("qmag 100-case explicit pool fallback bypass");
}

static bool test_default_search_ignores_missing_or_corrupt_qmag(void) {
    return pr5_trinary_search_api_unavailable("default search missing/corrupt qmag tolerance");
}

static bool test_qmag_stale_reported_and_opt_in_rejected(void) {
    return pr5_trinary_search_api_unavailable("qmag stale status and opt-in rejection");
}

static bool test_qmag_mutations_compact_and_reopen_refresh_candidates(void) {
    return pr5_trinary_search_api_unavailable("qmag mutation compact/reopen cache refresh");
}

static bool test_tombstone_heavy_small_qmag_pool_skips_deleted_and_old_rows(void) {
    return pr5_trinary_search_api_unavailable("tombstone-heavy small qmag pool");
}

static bool test_old_128_byte_manifest_opens_with_qmag_absent(void) {
    return pr5_trinary_search_api_unavailable("old manifest qmag compatibility");
}
#endif

static bool test_delete_by_id_persists_across_reopen(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("delete_persists");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float deleted[] = {1.0f, 0.0f, 0.0f};
    const float live[] = {0.0f, 1.0f, 0.0f};
    const char deleted_meta[] = "deleted";
    const char live_meta[] = "live";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, deleted, ARRAY_LEN(deleted), 9001,
                        deleted_meta, sizeof(deleted_meta)),
                "deleted-row insert should succeed");
    TEST_ASSERT(add_one(db, live, ARRAY_LEN(live), 9002, live_meta, sizeof(live_meta)),
                "live-row insert should succeed");
    TEST_ASSERT(qihse_vector_db_delete_by_id(db, 9001), "delete_by_id should delete live row");
    TEST_ASSERT(!qihse_vector_db_delete_by_id(db, 9001),
                "delete_by_id should reject already deleted row");
    TEST_ASSERT(close_db(db), "database should close after delete");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database after delete");

    qihse_vector_result_t result;
    int count = search_one(db, deleted, ARRAY_LEN(deleted), true, true, &result);
    TEST_ASSERT(count == 0, "deleted row should not be searchable after reopen");

    count = search_one(db, live, ARRAY_LEN(live), true, true, &result);
    TEST_ASSERT(count == 1, "live row should remain searchable after delete");
    TEST_ASSERT(result.id == 9002, "live row id should survive delete");
    TEST_ASSERT(vector_eq(result.vector, live, ARRAY_LEN(live)),
                "live row vector should survive delete");
    TEST_ASSERT(result.metadata_size == sizeof(live_meta), "live metadata size should survive");
    TEST_ASSERT(memcmp(result.metadata, live_meta, sizeof(live_meta)) == 0,
                "live metadata should survive delete");
    free_results(&result, 1);

    TEST_ASSERT(close_db(db), "database should close after delete verification");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_update_by_id_replaces_vector_and_metadata(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("update_replaces");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float original[] = {1.0f, 0.0f, 0.0f, 0.0f};
    const float replacement[] = {0.0f, 0.0f, 1.0f, 0.0f};
    const char original_meta[] = "original";
    const uint8_t replacement_meta[] = {0x75, 0x70, 0x64, 0x00, 0xff, 0x42};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, original, ARRAY_LEN(original), 9101,
                        original_meta, sizeof(original_meta)),
                "original row insert should succeed");
    TEST_ASSERT(qihse_vector_db_update_by_id(db, 9101, replacement,
                                             ARRAY_LEN(replacement),
                                             replacement_meta,
                                             sizeof(replacement_meta)),
                "update_by_id should replace existing row");
    TEST_ASSERT(!qihse_vector_db_update_by_id(db, 999999, replacement,
                                              ARRAY_LEN(replacement),
                                              replacement_meta,
                                              sizeof(replacement_meta)),
                "update_by_id should reject missing row");
    TEST_ASSERT(close_db(db), "database should close after update");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database after update");

    qihse_vector_result_t result;
    int count = search_one(db, original, ARRAY_LEN(original), false, false, &result);
    TEST_ASSERT(count == 0, "original vector should not remain searchable after update");

    count = search_one(db, replacement, ARRAY_LEN(replacement), true, true, &result);
    TEST_ASSERT(count == 1, "replacement vector should be searchable after reopen");
    TEST_ASSERT(result.id == 9101, "update should preserve external id");
    TEST_ASSERT(vector_eq(result.vector, replacement, ARRAY_LEN(replacement)),
                "update should hydrate replacement vector");
    TEST_ASSERT(result.metadata_size == sizeof(replacement_meta),
                "update should replace metadata size");
    TEST_ASSERT(memcmp(result.metadata, replacement_meta, sizeof(replacement_meta)) == 0,
                "update should replace metadata bytes");
    free_results(&result, 1);

    TEST_ASSERT(close_db(db), "database should close after update verification");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_upsert_by_ids_reports_insert_and_update_counts(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("upsert_counts");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float original[] = {1.0f, 0.0f, 0.0f};
    const float upsert_vectors[][3] = {
        {0.0f, 1.0f, 0.0f},
        {0.0f, 0.0f, 1.0f},
    };
    const uint64_t ids[] = {9201, 9202};
    const char updated_meta[] = "updated";
    const char inserted_meta[] = "inserted";
    const void* metas[] = {updated_meta, inserted_meta};
    const size_t meta_sizes[] = {sizeof(updated_meta), sizeof(inserted_meta)};
    size_t inserted_count = 777;
    size_t updated_count = 777;

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, original, ARRAY_LEN(original), ids[0], NULL, 0),
                "initial upsert target insert should succeed");

    TEST_ASSERT(qihse_vector_db_upsert_by_ids(db, ids, &upsert_vectors[0][0],
                                              ARRAY_LEN(ids),
                                              ARRAY_LEN(upsert_vectors[0]),
                                              metas, meta_sizes,
                                              &inserted_count, &updated_count),
                "upsert_by_ids should complete");
    TEST_ASSERT(inserted_count == 1, "upsert should report one inserted row");
    TEST_ASSERT(updated_count == 1, "upsert should report one updated row");
    TEST_ASSERT(close_db(db), "database should close after upsert");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database after upsert");

    qihse_vector_result_t result;
    int count = search_one(db, upsert_vectors[0], ARRAY_LEN(upsert_vectors[0]),
                           true, true, &result);
    TEST_ASSERT(count == 1, "updated upsert row should be searchable");
    TEST_ASSERT(result.id == ids[0], "updated upsert row should preserve id");
    TEST_ASSERT(vector_eq(result.vector, upsert_vectors[0], ARRAY_LEN(upsert_vectors[0])),
                "updated upsert row should hydrate replacement vector");
    TEST_ASSERT(result.metadata_size == sizeof(updated_meta),
                "updated upsert metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, updated_meta, sizeof(updated_meta)) == 0,
                "updated upsert metadata should match");
    free_results(&result, 1);

    count = search_one(db, upsert_vectors[1], ARRAY_LEN(upsert_vectors[1]),
                       true, true, &result);
    TEST_ASSERT(count == 1, "inserted upsert row should be searchable");
    TEST_ASSERT(result.id == ids[1], "inserted upsert row should preserve id");
    TEST_ASSERT(vector_eq(result.vector, upsert_vectors[1], ARRAY_LEN(upsert_vectors[1])),
                "inserted upsert row should hydrate vector");
    TEST_ASSERT(result.metadata_size == sizeof(inserted_meta),
                "inserted upsert metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, inserted_meta, sizeof(inserted_meta)) == 0,
                "inserted upsert metadata should match");
    free_results(&result, 1);

    count = search_one(db, original, ARRAY_LEN(original), false, false, &result);
    TEST_ASSERT(count == 0, "original row should not remain searchable after upsert update");

    TEST_ASSERT(close_db(db), "database should close after upsert verification");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_read_only_open_rejects_mutations(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("readonly_mutations");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float existing[] = {1.0f, 0.0f, 0.0f};
    const float replacement[] = {0.0f, 1.0f, 0.0f};
    const float upsert_vectors[][3] = {
        {0.0f, 0.0f, 1.0f},
        {0.5f, 0.5f, 0.0f},
    };
    const uint64_t upsert_ids[] = {9301, 9302};
    const char metadata[] = "readonly-mutation";
    size_t inserted_count = 123;
    size_t updated_count = 456;

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, existing, ARRAY_LEN(existing), 9301, metadata, sizeof(metadata)),
                "initial readonly mutation row insert should succeed");
    TEST_ASSERT(close_db(db), "database should close before read-only mutation checks");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "read-only open should return a database");

    TEST_ASSERT(!qihse_vector_db_delete_by_id(db, 9301),
                "read-only delete_by_id should be rejected");
    TEST_ASSERT(!qihse_vector_db_update_by_id(db, 9301, replacement,
                                              ARRAY_LEN(replacement),
                                              metadata, sizeof(metadata)),
                "read-only update_by_id should be rejected");
    TEST_ASSERT(!qihse_vector_db_upsert_by_ids(db, upsert_ids, &upsert_vectors[0][0],
                                               ARRAY_LEN(upsert_ids),
                                               ARRAY_LEN(upsert_vectors[0]),
                                               NULL, NULL,
                                               &inserted_count, &updated_count),
                "read-only upsert_by_ids should be rejected");
    TEST_ASSERT(!qihse_vector_db_compact(db), "read-only compact should be rejected");

    qihse_vector_result_t result;
    int count = search_one(db, existing, ARRAY_LEN(existing), true, true, &result);
    TEST_ASSERT(count == 1, "read-only rejected mutations should leave row searchable");
    TEST_ASSERT(result.id == 9301, "read-only rejected mutations should preserve id");
    TEST_ASSERT(vector_eq(result.vector, existing, ARRAY_LEN(existing)),
                "read-only rejected mutations should preserve vector");
    TEST_ASSERT(result.metadata_size == sizeof(metadata),
                "read-only rejected mutations should preserve metadata size");
    TEST_ASSERT(memcmp(result.metadata, metadata, sizeof(metadata)) == 0,
                "read-only rejected mutations should preserve metadata bytes");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_compact_preserves_live_rows_after_mutations(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("compact_live_rows");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float deleted[] = {1.0f, 0.0f, 0.0f, 0.0f};
    const float updated_original[] = {0.0f, 1.0f, 0.0f, 0.0f};
    const float updated_replacement[] = {0.0f, 0.0f, 1.0f, 0.0f};
    const float untouched[] = {0.0f, 0.0f, 0.0f, 1.0f};
    const char updated_meta[] = "updated-after-compact";
    const char untouched_meta[] = "untouched-after-compact";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, deleted, ARRAY_LEN(deleted), 9401, NULL, 0),
                "deleted compact row insert should succeed");
    TEST_ASSERT(add_one(db, updated_original, ARRAY_LEN(updated_original), 9402, NULL, 0),
                "updated compact row insert should succeed");
    TEST_ASSERT(add_one(db, untouched, ARRAY_LEN(untouched), 9403,
                        untouched_meta, sizeof(untouched_meta)),
                "untouched compact row insert should succeed");

    TEST_ASSERT(qihse_vector_db_delete_by_id(db, 9401),
                "delete before compact should succeed");
    TEST_ASSERT(qihse_vector_db_update_by_id(db, 9402, updated_replacement,
                                             ARRAY_LEN(updated_replacement),
                                             updated_meta, sizeof(updated_meta)),
                "update before compact should succeed");
    TEST_ASSERT(qihse_vector_db_compact(db), "compact should succeed after mutations");
    TEST_ASSERT(close_db(db), "database should close after compact");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database after compact");

    qihse_vector_result_t result;
    int count = search_one(db, deleted, ARRAY_LEN(deleted), false, false, &result);
    TEST_ASSERT(count == 0, "deleted row should remain absent after compact");

    count = search_one(db, updated_original, ARRAY_LEN(updated_original), false, false, &result);
    TEST_ASSERT(count == 0, "superseded row should remain absent after compact");

    count = search_one(db, updated_replacement, ARRAY_LEN(updated_replacement),
                       true, true, &result);
    TEST_ASSERT(count == 1, "updated live row should survive compact");
    TEST_ASSERT(result.id == 9402, "updated live row id should survive compact");
    TEST_ASSERT(vector_eq(result.vector, updated_replacement,
                          ARRAY_LEN(updated_replacement)),
                "updated live row vector should survive compact");
    TEST_ASSERT(result.metadata_size == sizeof(updated_meta),
                "updated live row metadata size should survive compact");
    TEST_ASSERT(memcmp(result.metadata, updated_meta, sizeof(updated_meta)) == 0,
                "updated live row metadata should survive compact");
    free_results(&result, 1);

    count = search_one(db, untouched, ARRAY_LEN(untouched), true, true, &result);
    TEST_ASSERT(count == 1, "untouched live row should survive compact");
    TEST_ASSERT(result.id == 9403, "untouched live row id should survive compact");
    TEST_ASSERT(vector_eq(result.vector, untouched, ARRAY_LEN(untouched)),
                "untouched live row vector should survive compact");
    TEST_ASSERT(result.metadata_size == sizeof(untouched_meta),
                "untouched live row metadata size should survive compact");
    TEST_ASSERT(memcmp(result.metadata, untouched_meta, sizeof(untouched_meta)) == 0,
                "untouched live row metadata should survive compact");
    free_results(&result, 1);

    TEST_ASSERT(close_db(db), "database should close after compact verification");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_compact_counts_after_delete_update_current_snapshot(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("compact_counts");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float deleted[] = {1.0f, 0.0f, 0.0f};
    const float updated_original[] = {0.0f, 1.0f, 0.0f};
    const float updated_replacement[] = {0.0f, 0.0f, 1.0f};
    const float untouched[] = {0.5f, 0.5f, 0.0f};
    const char updated_meta[] = "compact-counts-updated";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, deleted, ARRAY_LEN(deleted), 9501, NULL, 0),
                "deleted count row insert should succeed");
    TEST_ASSERT(add_one(db, updated_original, ARRAY_LEN(updated_original), 9502, NULL, 0),
                "updated count row insert should succeed");
    TEST_ASSERT(add_one(db, untouched, ARRAY_LEN(untouched), 9503, NULL, 0),
                "untouched count row insert should succeed");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available before count mutations");
    TEST_ASSERT(stats.live_vectors == 3u, "initial live count should include all rows");
    TEST_ASSERT(stats.index_rows == 3u, "initial index row count should include all rows");

    TEST_ASSERT(qihse_vector_db_delete_by_id(db, 9501),
                "delete before count compact should succeed");
    TEST_ASSERT(qihse_vector_db_update_by_id(db, 9502, updated_replacement,
                                             ARRAY_LEN(updated_replacement),
                                             updated_meta, sizeof(updated_meta)),
                "update before count compact should succeed");

    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after count mutations");
    TEST_ASSERT(stats.live_vectors == 2u,
                "delete/update should leave two live logical rows");
    TEST_ASSERT(stats.index_rows == 4u,
                "current snapshot keeps tombstoned and replacement rows before compact");
    TEST_ASSERT(stats.idmap_dirty, "idmap should be dirty after delete/update");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_STALE,
                "qtri should be stale after delete/update");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_STALE,
                "qmag should be stale after delete/update");

    TEST_ASSERT(qihse_vector_db_compact(db), "compact should succeed for count snapshot");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after count compact");
    TEST_ASSERT(stats.live_vectors == 2u,
                "compact should preserve two live logical rows");
    TEST_ASSERT(stats.index_rows == stats.live_vectors,
                "physical compact should prune tombstoned and superseded index rows");
    TEST_ASSERT(stats.idmap_valid, "compact should leave idmap valid");
    TEST_ASSERT(!stats.idmap_dirty, "compact should leave idmap clean");
    TEST_ASSERT(stats.idmap_rows == 2u,
                "compact should rebuild idmap with live rows only");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "compact should rebuild qtri as valid");
    TEST_ASSERT(stats.trinary_rows == stats.live_vectors,
                "physical compact should rebuild qtri for live rows only");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "compact should rebuild qmag as valid");
    TEST_ASSERT(stats.magnitude_rows == stats.live_vectors,
                "physical compact should rebuild qmag for live rows only");

    TEST_ASSERT(close_db(db), "database should close after count compact");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_compact_rebuilds_high_id_idmap_consistency(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("compact_high_ids");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vectors[][4] = {
        {1.0f, 0.0f, 0.0f, 0.0f},
        {0.0f, 1.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 1.0f, 0.0f},
    };
    const float high_replacement[] = {0.0f, 0.0f, 0.0f, 1.0f};
    const uint64_t ids[] = {
        9601u,
        UINT64_C(0x8000000000000101),
        UINT64_MAX
    };
    const char high_meta[] = "high-id-compact";

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(qihse_vector_db_add_vectors(db, &vectors[0][0], ARRAY_LEN(vectors),
                                            ARRAY_LEN(vectors[0]), ids, NULL, NULL),
                "high-ID compact fixture insert should succeed");

    TEST_ASSERT(qihse_vector_db_delete_by_id(db, ids[0]),
                "low-ID delete before compact should succeed");
    TEST_ASSERT(qihse_vector_db_update_by_id(db, ids[1], high_replacement,
                                             ARRAY_LEN(high_replacement),
                                             high_meta, sizeof(high_meta)),
                "high-ID update before compact should succeed");
    TEST_ASSERT(qihse_vector_db_compact(db), "compact should rebuild high-ID idmap");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after high-ID compact");
    TEST_ASSERT(stats.idmap_valid, "high-ID idmap should be valid after compact");
    TEST_ASSERT(!stats.idmap_dirty, "high-ID idmap should be clean after compact");
    TEST_ASSERT(stats.idmap_rows == 2u, "high-ID idmap should contain live rows only");

    TEST_ASSERT(close_db(db), "database should close after high-ID compact");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database after high-ID compact");

    qihse_vector_result_t result;
    int count = search_one(db, vectors[0], ARRAY_LEN(vectors[0]), false, false, &result);
    TEST_ASSERT(count == 0, "deleted low-ID row should stay absent after compact");

    count = search_one(db, high_replacement, ARRAY_LEN(high_replacement),
                       true, true, &result);
    TEST_ASSERT(count == 1, "updated high-ID row should search after compact");
    TEST_ASSERT(result.id == ids[1], "updated ID above INT64_MAX should survive compact");
    TEST_ASSERT(vector_eq(result.vector, high_replacement, ARRAY_LEN(high_replacement)),
                "updated high-ID vector should hydrate after compact");
    TEST_ASSERT(result.metadata_size == sizeof(high_meta),
                "updated high-ID metadata size should survive compact");
    TEST_ASSERT(memcmp(result.metadata, high_meta, sizeof(high_meta)) == 0,
                "updated high-ID metadata should survive compact");
    free_results(&result, 1);

    count = search_one(db, vectors[2], ARRAY_LEN(vectors[2]), true, false, &result);
    TEST_ASSERT(count == 1, "UINT64_MAX row should search after compact");
    TEST_ASSERT(result.id == ids[2], "UINT64_MAX id should survive compact");
    TEST_ASSERT(vector_eq(result.vector, vectors[2], ARRAY_LEN(vectors[2])),
                "UINT64_MAX vector should hydrate after compact");
    free_results(&result, 1);

    TEST_ASSERT(close_db(db), "database should close after high-ID compact verification");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_compact_rewrites_qtri_sidecar_valid(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("compact_qtri_valid");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float original[] = {1.0f, -1.0f, 0.0f, 1.0f, -1.0f, 0.0f};
    const float replacement[] = {-1.0f, 1.0f, 0.0f, -1.0f, 1.0f, 0.0f};
    const float untouched[] = {0.0f, 0.0f, 1.0f, 1.0f, -1.0f, -1.0f};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, original, ARRAY_LEN(original), 9701, NULL, 0),
                "qtri original row insert should succeed");
    TEST_ASSERT(add_one(db, untouched, ARRAY_LEN(untouched), 9702, NULL, 0),
                "qtri untouched row insert should succeed");
    TEST_ASSERT(close_db(db), "database should close before qtri compact fixture");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "reopen should return a database for qtri compact");

    TEST_ASSERT(qihse_vector_db_update_by_id(db, 9701, replacement,
                                             ARRAY_LEN(replacement), NULL, 0),
                "qtri update before compact should succeed");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available before qtri compact");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_STALE,
                "qtri should be stale after update");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_STALE,
                "qmag should be stale after update");

    TEST_ASSERT(qihse_vector_db_compact(db), "compact should rewrite qtri/qmag sidecars");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after qtri compact");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "qtri should be valid after compact");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "qmag should be valid after compact");
    TEST_ASSERT(stats.trinary_row_bytes == 2u,
                "six-dimensional qtri rows should use two tryte bytes");
    TEST_ASSERT(stats.magnitude_row_bytes == 6u,
                "six-dimensional qmag rows should use six bytes");
    TEST_ASSERT(stats.trinary_rows == stats.live_vectors,
                "compacted qtri rows should mirror live rows");
    TEST_ASSERT(stats.magnitude_rows == stats.live_vectors,
                "compacted qmag rows should mirror live rows");

    off_t qtri_size = 0;
    TEST_ASSERT(file_size_of(path, "vectors.qtri", &qtri_size),
                "vectors.qtri size should be readable after compact");
    TEST_ASSERT(qtri_size == (off_t)(stats.trinary_row_bytes * stats.trinary_rows),
                "vectors.qtri size should match raw tryte rows");
    off_t qmag_size = 0;
    TEST_ASSERT(file_size_of(path, "vectors.qmag", &qmag_size),
                "vectors.qmag size should be readable after compact");
    TEST_ASSERT(qmag_size == (off_t)(stats.magnitude_row_bytes * stats.magnitude_rows),
                "vectors.qmag size should match raw magnitude rows");

    TEST_ASSERT(close_db(db), "database should close after qtri compact");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "read-only reopen should accept compacted qtri");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after qtri read-only reopen");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "compacted qtri should remain valid across reopen");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "compacted qmag should remain valid across reopen");
    TEST_ASSERT(qihse_vector_db_close(db), "read-only qtri database should close");

    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_compact_rebuilds_corrupt_derived_sidecars(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("compact_corrupt_sidecars");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float vectors[][5] = {
        {1.0f, 0.0f, -1.0f, 1.0f, 0.0f},
        {-1.0f, 1.0f, 0.0f, -1.0f, 1.0f},
    };
    const uint8_t invalid_tryte[] = {0xff, 0x00, 0x01};
    const uint8_t corrupt_qmag[] = {0xde, 0xad, 0xbe, 0xef};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, vectors[0], ARRAY_LEN(vectors[0]), 9801, NULL, 0),
                "first corrupt-sidecar fixture row insert should succeed");
    TEST_ASSERT(add_one(db, vectors[1], ARRAY_LEN(vectors[1]), 9802, NULL, 0),
                "second corrupt-sidecar fixture row insert should succeed");
    TEST_ASSERT(close_db(db), "database should close before sidecar corruption");

    TEST_ASSERT(corrupt_file_byte(path, "idmap.qid", 0, (uint8_t)'Z'),
                "test should corrupt derived idmap sidecar");
    TEST_ASSERT(write_qtri_payload(path, invalid_tryte, sizeof(invalid_tryte)),
                "test should corrupt derived qtri sidecar");
    TEST_ASSERT(write_file_payload(path, "vectors.qmag", corrupt_qmag, sizeof(corrupt_qmag)),
                "test should corrupt derived qmag sidecar");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "corrupt derived sidecars should reopen writable");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after corrupt sidecar reopen");
    TEST_ASSERT(stats.idmap_valid, "corrupt idmap should rebuild in memory");
    TEST_ASSERT(stats.idmap_dirty, "rebuilt idmap should be dirty before compact");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_CORRUPT,
                "corrupt qtri should be reported before compact");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_CORRUPT,
                "corrupt qmag should be reported before compact");

    TEST_ASSERT(qihse_vector_db_compact(db), "compact should rebuild corrupt sidecars");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after corrupt sidecar compact");
    TEST_ASSERT(stats.idmap_valid, "compacted idmap should be valid");
    TEST_ASSERT(!stats.idmap_dirty, "compacted idmap should be clean");
    TEST_ASSERT(stats.idmap_rows == 2u, "compacted idmap should contain live rows");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "compacted qtri should be valid");
    TEST_ASSERT(stats.trinary_row_bytes == 1u,
                "five-dimensional qtri rows should use one tryte byte");
    TEST_ASSERT(stats.trinary_rows == 2u,
                "compacted qtri should contain both physical rows");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "compacted qmag should be valid");
    TEST_ASSERT(stats.magnitude_row_bytes == 5u,
                "five-dimensional qmag rows should use five bytes");
    TEST_ASSERT(stats.magnitude_rows == 2u,
                "compacted qmag should contain both physical rows");

    TEST_ASSERT(close_db(db), "database should close after corrupt sidecar compact");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "read-only reopen should accept rebuilt sidecars");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after rebuilt sidecar reopen");
    TEST_ASSERT(stats.idmap_valid, "rebuilt idmap should persist");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "rebuilt qtri should persist");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "rebuilt qmag should persist");

    qihse_vector_result_t result;
    int count = search_one(db, vectors[1], ARRAY_LEN(vectors[1]), true, false, &result);
    TEST_ASSERT(count == 1, "row should search after derived sidecar rebuild");
    TEST_ASSERT(result.id == 9802, "row id should survive derived sidecar rebuild");
    TEST_ASSERT(vector_eq(result.vector, vectors[1], ARRAY_LEN(vectors[1])),
                "row vector should survive derived sidecar rebuild");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only rebuilt-sidecar database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_compact_ignores_stale_tmp_files(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("compact_stale_tmp");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float first[] = {1.0f, 0.0f, 0.0f};
    const float second[] = {0.0f, 1.0f, 0.0f};
    const uint8_t junk[] = {0xde, 0xad, 0xbe, 0xef};

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, first, ARRAY_LEN(first), 9901, NULL, 0),
                "first stale-tmp row insert should succeed");
    TEST_ASSERT(add_one(db, second, ARRAY_LEN(second), 9902, NULL, 0),
                "second stale-tmp row insert should succeed");
    TEST_ASSERT(qihse_vector_db_compact(db), "initial compact should publish snapshot");
    TEST_ASSERT(close_db(db), "database should close before stale tmp injection");

    TEST_ASSERT(write_file_payload(path, "MANIFEST.tmp", junk, sizeof(junk)),
                "test should write stale manifest tmp");
    TEST_ASSERT(write_file_payload(path, "index.qidx.tmp", junk, sizeof(junk)),
                "test should write stale index tmp");
    TEST_ASSERT(write_file_payload(path, "vectors.qvec.tmp", junk, sizeof(junk)),
                "test should write stale vector tmp");
    TEST_ASSERT(write_file_payload(path, "metadata.qmeta.tmp", junk, sizeof(junk)),
                "test should write stale metadata tmp");
    TEST_ASSERT(write_file_payload(path, "idmap.qid.tmp", junk, sizeof(junk)),
                "test should write stale idmap tmp");
    TEST_ASSERT(write_file_payload(path, "vectors.qtri.tmp", junk, sizeof(junk)),
                "test should write stale qtri tmp");
    TEST_ASSERT(write_file_payload(path, "vectors.qmag.tmp", junk, sizeof(junk)),
                "test should write stale qmag tmp");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "stale tmp files should not block read-only reopen");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after stale tmp reopen");
    TEST_ASSERT(stats.index_rows == 2u, "stale tmp files should not change index rows");
    TEST_ASSERT(stats.live_vectors == 2u, "stale tmp files should not change live rows");
    TEST_ASSERT(stats.idmap_valid, "stale tmp files should not invalidate idmap");
    TEST_ASSERT(stats.trinary_status == QIHSE_VDB_TRINARY_VALID,
                "stale tmp files should not invalidate qtri");
    TEST_ASSERT(stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID,
                "stale tmp files should not invalidate qmag");

    qihse_vector_result_t result;
    int count = search_one(db, second, ARRAY_LEN(second), true, false, &result);
    TEST_ASSERT(count == 1, "row should search despite stale tmp files");
    TEST_ASSERT(result.id == 9902, "row id should survive stale tmp files");
    TEST_ASSERT(vector_eq(result.vector, second, ARRAY_LEN(second)),
                "row vector should survive stale tmp files");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only stale-tmp database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}

static bool test_wal_mutations_compact_clear_wal_and_prune(void) {
    test_env_t env;
    TEST_ASSERT(env_init(&env), "environment should initialize");

    char* path = make_temp_db_path("wal_compact");
    TEST_ASSERT(path != NULL, "temp db path should be created");

    const float deleted[] = {1.0f, 0.0f, 0.0f, 0.0f};
    const float updated_old[] = {0.0f, 1.0f, 0.0f, 0.0f};
    const float upsert_old[] = {0.0f, 0.0f, 1.0f, 0.0f};
    const float updated_new[] = {0.0f, 0.0f, 0.0f, 1.0f};
    const float upsert_vectors[][4] = {
        {0.5f, 0.5f, 0.0f, 0.0f},
        {0.0f, 0.5f, 0.5f, 0.0f},
    };
    const uint64_t upsert_ids[] = {9913, 9914};
    const char updated_meta[] = "wal-compact-updated";
    const char upsert_update_meta[] = "wal-compact-upsert-updated";
    const char upsert_insert_meta[] = "wal-compact-upsert-inserted";
    const void* upsert_metas[] = {upsert_update_meta, upsert_insert_meta};
    const size_t upsert_meta_sizes[] = {
        sizeof(upsert_update_meta),
        sizeof(upsert_insert_meta)
    };

    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env.uma, path);
    TEST_ASSERT(db != NULL, "create should return a database");
    TEST_ASSERT(add_one(db, deleted, ARRAY_LEN(deleted), 9911, NULL, 0),
                "delete target insert should succeed");
    TEST_ASSERT(add_one(db, updated_old, ARRAY_LEN(updated_old), 9912, NULL, 0),
                "update target insert should succeed");
    TEST_ASSERT(add_one(db, upsert_old, ARRAY_LEN(upsert_old), 9913, NULL, 0),
                "upsert target insert should succeed");
    TEST_ASSERT(close_db(db), "base snapshot should close before WAL compact mutations");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED
    );
    TEST_ASSERT(db != NULL, "writer reopen should return a database");
    TEST_ASSERT(qihse_vector_db_delete_by_id(db, 9911),
                "delete before compact should append WAL");
    TEST_ASSERT(qihse_vector_db_update_by_id(db, 9912, updated_new,
                                             ARRAY_LEN(updated_new),
                                             updated_meta, sizeof(updated_meta)),
                "update before compact should append WAL");
    size_t inserted_count = 0;
    size_t updated_count = 0;
    TEST_ASSERT(qihse_vector_db_upsert_by_ids(db, upsert_ids, &upsert_vectors[0][0],
                                              ARRAY_LEN(upsert_ids),
                                              ARRAY_LEN(upsert_vectors[0]),
                                              upsert_metas, upsert_meta_sizes,
                                              &inserted_count, &updated_count),
                "upsert before compact should append WAL");
    TEST_ASSERT(inserted_count == 1 && updated_count == 1,
                "upsert before compact should report one insert and one update");

    qihse_vector_db_persistence_stats_t stats;
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available before WAL compact");
    TEST_ASSERT(stats.wal_bytes_pending > 0u,
                "uncompacted mutations should have WAL bytes pending");
    TEST_ASSERT(stats.index_rows > stats.live_vectors,
                "uncompacted mutation rows should include tombstones");

    TEST_ASSERT(qihse_vector_db_compact(db), "compact should publish WAL mutations");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after WAL compact");
    TEST_ASSERT(stats.wal_bytes_pending == 0u, "compact should clear checkpointed WAL");
    TEST_ASSERT(stats.index_rows == 3u, "compact should prune to three live rows");
    TEST_ASSERT(stats.live_vectors == 3u, "compact should preserve three live rows");
    TEST_ASSERT(stats.idmap_rows == 3u, "compact should rebuild idmap for live rows");
    TEST_ASSERT(stats.trinary_rows == 3u, "compact should rebuild qtri for live rows");

    off_t wal_size = -1;
    TEST_ASSERT(file_size_of(path, "wal.qwal", &wal_size),
                "WAL file should exist after compact truncation");
    TEST_ASSERT(wal_size == 0, "compact should truncate WAL file to zero bytes");
    TEST_ASSERT(close_db(db), "database should close after WAL compact");

    db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        env.uma,
        path,
        QIHSE_TEST_OPEN_FILE_BACKED | QIHSE_TEST_OPEN_READ_ONLY
    );
    TEST_ASSERT(db != NULL, "read-only reopen should accept compacted WAL snapshot");
    TEST_ASSERT(qihse_vector_db_get_persistence_stats(db, &stats),
                "stats should be available after compacted WAL reopen");
    TEST_ASSERT(stats.wal_records_replayed == 0u,
                "compacted WAL snapshot should not replay old mutations");
    TEST_ASSERT(stats.index_rows == 3u && stats.live_vectors == 3u,
                "compacted WAL snapshot should reopen with only live rows");

    qihse_vector_result_t result;
    int count = search_one(db, deleted, ARRAY_LEN(deleted), false, false, &result);
    TEST_ASSERT(count == 0, "compacted WAL delete should not resurrect row");

    count = search_one(db, updated_old, ARRAY_LEN(updated_old), false, false, &result);
    TEST_ASSERT(count == 0, "compacted WAL update should not resurrect old vector");

    count = search_one(db, updated_new, ARRAY_LEN(updated_new), true, true, &result);
    TEST_ASSERT(count == 1, "compacted WAL update should preserve replacement");
    TEST_ASSERT(result.id == 9912, "compacted WAL update should preserve id");
    TEST_ASSERT(result.metadata_size == sizeof(updated_meta),
                "compacted WAL update metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, updated_meta, sizeof(updated_meta)) == 0,
                "compacted WAL update metadata should match");
    free_results(&result, 1);

    count = search_one(db, upsert_vectors[1], ARRAY_LEN(upsert_vectors[1]),
                       true, true, &result);
    TEST_ASSERT(count == 1, "compacted WAL upsert insert should survive");
    TEST_ASSERT(result.id == 9914, "compacted WAL upsert insert should preserve id");
    TEST_ASSERT(result.metadata_size == sizeof(upsert_insert_meta),
                "compacted WAL upsert insert metadata size should match");
    TEST_ASSERT(memcmp(result.metadata, upsert_insert_meta,
                       sizeof(upsert_insert_meta)) == 0,
                "compacted WAL upsert insert metadata should match");
    free_results(&result, 1);

    TEST_ASSERT(qihse_vector_db_close(db), "read-only WAL compact database should close");
    remove_tree(path);
    free(path);
    env_destroy(&env);
    return true;
}
