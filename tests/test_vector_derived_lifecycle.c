#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_user_t* operator_user;

static void query_mode(qihse_vector_db_t db, qihse_vector_db_query_mode_t mode,
                       const float* needle, uint64_t expected_id) {
    qihse_vector_query_t query;
    qihse_vector_result_t result[2];
    memset(&query, 0, sizeof(query));
    query.query_vector = needle;
    query.vector_dims = 2u;
    query.top_k = 1u;
    query.query_mode = mode;
    query.user = operator_user;
    int n = qihse_vector_db_search(db, &query, result, 2u);
    if (n != 1 || result[0].id != expected_id)
        fprintf(stderr, "mode=%d expected=%llu got_count=%d got_id=%llu errno=%d\n",
                (int)mode, (unsigned long long)expected_id, n,
                (unsigned long long)(n > 0 ? result[0].id : 0u), errno);
    assert(n == 1 && result[0].id == expected_id);
}

static qihse_vector_db_t seed(const char* path) {
    const float vectors[] = {1.0f, 0.0f, 0.0f, 1.0f};
    const uint64_t ids[] = {1u, 2u};
    qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, path);
    assert(db);
    if (!qihse_vector_db_add_vectors(db, vectors, 2u, 2u, ids, NULL, NULL)) {
        perror("add_vectors");
        abort();
    }
    assert(qihse_vector_db_flush(db));
    assert(qihse_vector_db_build_graph(db, 2u, 8u));
    assert(qihse_vector_db_build_int8(db));
    assert(qihse_vector_db_build_binary(db));
    return db;
}

static void test_mutation_invalidates_candidate_indexes(const char* path) {
    const float nearest[] = {0.8f, 0.6f};
    const float updated[] = {0.8f, 0.6f};
    const uint64_t id = 3u;
    qihse_vector_db_t db = seed(path);
    assert(qihse_vector_db_add_vectors(db, nearest, 1u, 2u, &id, NULL, NULL));
    query_mode(db, QIHSE_VDB_QUERY_GRAPH, nearest, id);
    query_mode(db, QIHSE_VDB_QUERY_INT8, nearest, id);
    query_mode(db, QIHSE_VDB_QUERY_BINARY, nearest, id);
    assert(qihse_vector_db_delete_by_id_user(db, operator_user, id));
    assert(qihse_vector_db_update_by_id_user(db, operator_user, 1u, updated,
                                              2u, NULL, 0u));
    query_mode(db, QIHSE_VDB_QUERY_GRAPH, updated, 1u);
    query_mode(db, QIHSE_VDB_QUERY_INT8, updated, 1u);
    query_mode(db, QIHSE_VDB_QUERY_BINARY, updated, 1u);
    qihse_vector_db_destroy(db); /* leave committed mutation in WAL */

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, path,
                              QIHSE_VDB_OPEN_FILE_BACKED);
    assert(db);
    query_mode(db, QIHSE_VDB_QUERY_GRAPH, updated, 1u);
    query_mode(db, QIHSE_VDB_QUERY_INT8, updated, 1u);
    float loaded[2];
    size_t loaded_dims = 0;
    assert(!qihse_vector_db_get_vector_by_id_user(db, operator_user, id,
                                                  loaded, &loaded_dims));
    assert(qihse_vector_db_flush(db));
    qihse_vector_db_destroy(db);
}

static void test_read_only_build_is_ephemeral(const char* path) {
    struct stat before, after;
    assert(stat(path, &before) == 0);
    qihse_vector_db_t db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, path,
        QIHSE_VDB_OPEN_FILE_BACKED | QIHSE_VDB_OPEN_READ_ONLY | QIHSE_VDB_OPEN_MMAP);
    assert(db);
    assert(qihse_vector_db_build_graph(db, 2u, 8u));
    assert(qihse_vector_db_build_int8(db));
    assert(stat(path, &after) == 0);
    assert(before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
    qihse_vector_db_destroy(db);
    assert(stat(path, &after) == 0);
    assert(before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
}

static int remove_entry(const char* path, const struct stat* info, int type,
                        struct FTW* walk) {
    (void)info; (void)type; (void)walk;
    return remove(path);
}

int main(void) {
    char root[] = "tests/vector-derived-lifecycle-XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("VectorDerivedLifecycle123!"));
    operator_user = qihse_auth_get_user(0u);
    assert(operator_user);
    char path[256];
    assert(snprintf(path, sizeof(path), "%s/vector.qdb", root) < (int)sizeof(path));
    test_mutation_invalidates_candidate_indexes(path);
    test_read_only_build_is_ephemeral(path);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("PASS derived vector index invalidation, WAL freshness, and readonly builds");
    return 0;
}
