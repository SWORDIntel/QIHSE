#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "qihse_audit.h"

#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int __real_posix_memalign(void **memptr, size_t alignment, size_t size);

static int fail_aligned_after = -1;

int __wrap_posix_memalign(void **memptr, size_t alignment, size_t size) {
    if (fail_aligned_after == 0) {
        fail_aligned_after = -1;
        return ENOMEM;
    }
    if (fail_aligned_after > 0) --fail_aligned_after;
    return __real_posix_memalign(memptr, alignment, size);
}

static int remove_entry(const char *path, const struct stat *info, int type,
                        struct FTW *walk) {
    (void)info;
    (void)type;
    (void)walk;
    return remove(path);
}

int main(void) {
    char root[] = "tests/vector-graph-oom-XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("VectorGraphOomTest123!"));
    qihse_user_t *operator_user = qihse_auth_get_user(0u);
    assert(operator_user);

    char path[256];
    assert(snprintf(path, sizeof(path), "%s/vector.qdb", root) <
           (int)sizeof(path));
    qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,
                                                   NULL, path);
    assert(db);
    const float vector[] = {1.0f, 0.0f};
    const uint64_t id = 7u;
    assert(qihse_vector_db_add_vectors(db, vector, 1u, 2u, &id, NULL, NULL));
    assert(qihse_vector_db_flush(db));

    /* hnsw_create's aligned allocation succeeds; fail the next one, which is
     * the first layer allocation during insertion. The DB must reject the
     * build and discard its incomplete HNSW state. */
    fail_aligned_after = 1;
    assert(!qihse_vector_db_build_graph(db, 2u, 8u));
    assert(errno == ENOMEM);

    qihse_vector_query_t query;
    qihse_vector_result_t result;
    memset(&query, 0, sizeof(query));
    query.query_vector = vector;
    query.vector_dims = 2u;
    query.top_k = 1u;
    query.query_mode = QIHSE_VDB_QUERY_GRAPH;
    query.user = operator_user;
    assert(qihse_vector_db_search(db, &query, &result, 1u) < 0);
    assert(errno == ENOENT);

    assert(qihse_vector_db_build_graph(db, 2u, 8u));
    assert(qihse_vector_db_search(db, &query, &result, 1u) == 1);
    assert(result.id == id);

    qihse_vector_db_destroy(db);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("PASS vector graph build rejects allocation-failed HNSW");
    return 0;
}
