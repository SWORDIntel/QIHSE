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
static bool write_qtri_payload(const char* dir, const uint8_t* payload, size_t payload_size);

static bool test_create_insert_close_reopen_search(void);
static bool test_sparse_ids_hydrate_vector_and_metadata(void);
static bool test_binary_metadata_survives_restart(void);
static bool test_null_db_path_ephemeral_searchable(void);
static bool test_wal_replays_unflushed_add(void);
static bool test_torn_wal_tail_ignored_and_truncated(void);
static bool test_read_only_mmap_reopen_searches(void);
static bool test_corrupt_vectors_qvec_magic_rejected(void);
static bool test_truncated_index_qidx_rejected(void);
static bool test_read_only_open_searches_and_rejects_add(void);
static bool test_duplicate_vector_id_rejected(void);
static bool test_corrupt_idmap_rebuilds_high_ids(void);
static bool test_missing_vectors_qtri_accepted(void);
static bool test_corrupt_vectors_qtri_accepted_and_reported(void);
static bool test_delete_by_id_persists_across_reopen(void);
static bool test_update_by_id_replaces_vector_and_metadata(void);
static bool test_upsert_by_ids_reports_insert_and_update_counts(void);
static bool test_read_only_open_rejects_mutations(void);
static bool test_compact_preserves_live_rows_after_mutations(void);

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
        {"torn WAL tail is ignored and truncated on writable open",
         test_torn_wal_tail_ignored_and_truncated},
        {"read-only mmap reopen searches mapped vector file",
         test_read_only_mmap_reopen_searches},
        {"corrupt vectors.qvec magic fails open cleanly",
         test_corrupt_vectors_qvec_magic_rejected},
        {"truncated index.qidx fails open cleanly",
         test_truncated_index_qidx_rejected},
        {"read-only open can search but rejects add_vectors",
         test_read_only_open_searches_and_rejects_add},
        {"duplicate vector_id rejected",
         test_duplicate_vector_id_rejected},
        {"corrupt idmap.qid rebuilds and high IDs survive",
         test_corrupt_idmap_rebuilds_high_ids},
        {"missing vectors.qtri accepted for FLOAT32 DB",
         test_missing_vectors_qtri_accepted},
        {"corrupt vectors.qtri is accepted but reported unavailable",
         test_corrupt_vectors_qtri_accepted_and_reported},
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
