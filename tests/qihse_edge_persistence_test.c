#include "qihse_vector_db.h"
#include "persistence/qihse_container.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s (errno=%d)\n", \
                __FILE__, __LINE__, #expr, errno); \
        return 1; \
    } \
} while (0)

static int write_uncheckpointed_edges(const char* path) {
    qihse_vector_db_t db;
    const float vectors[] = {1.0f, 0.0f, 0.0f, 1.0f, 0.5f, 0.5f};
    const uint64_t ids[] = {101u, 102u, 103u};
    const char metadata[] = "callsite=alpha";

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, path,
                              QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED |
                              QIHSE_VDB_OPEN_TRUNCATE);
    CHECK(db != NULL);
    CHECK(qihse_vector_db_add_vectors(db, vectors, 3u, 2u, ids, NULL, NULL));
    CHECK(qihse_vector_db_add_edge(db, 101u, 102u, "CALLS",
                                   metadata, sizeof(metadata) - 1u));
    CHECK(qihse_vector_db_add_edge(db, 101u, 103u, "TESTED_BY", NULL, 0u));
    CHECK(!qihse_vector_db_delete_by_id(db, 102u));
    CHECK(errno == EBUSY);
    _exit(0);
}

static int verify_replay_and_checkpoint(const char* path) {
    qihse_vector_db_t db;
    uint64_t neighbors[4] = {0u};
    qihse_edge_result_t records[2];
    qihse_edge_input_t batch[2];
    size_t changed = 0u;
    int count;
    const char replacement[] = "callsite=beta";

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, path,
                              QIHSE_VDB_OPEN_FILE_BACKED);
    CHECK(db != NULL);
    count = qihse_vector_db_get_edges(db, 101u, NULL, neighbors, 4u);
    CHECK(count == 2);
    CHECK(neighbors[0] == 102u && neighbors[1] == 103u);

    CHECK(qihse_vector_db_add_edge(db, 101u, 102u, "CALLS", "ignored", 7u));
    memset(records, 0, sizeof(records));
    count = qihse_vector_db_get_edge_records(db, 101u, "CALLS",
                                              QIHSE_EDGE_OUTGOING, records, 2u);
    CHECK(count == 1);
    CHECK(records[0].metadata_size == strlen("callsite=alpha"));
    CHECK(memcmp(records[0].metadata, "callsite=alpha", records[0].metadata_size) == 0);
    qihse_vector_db_free_edge_records(records, 1u);

    CHECK(qihse_vector_db_replace_edge(db, 101u, 102u, "CALLS",
                                       replacement, sizeof(replacement) - 1u));
    batch[0] = (qihse_edge_input_t){102u, 103u, "CALLS", NULL, 0u};
    batch[1] = (qihse_edge_input_t){103u, 101u, "IMPLEMENTS", "iface", 5u};
    CHECK(qihse_vector_db_add_edges(db, batch, 2u, &changed));
    CHECK(changed == 2u);
    count = qihse_vector_db_get_typed_neighbors(db, 103u, NULL,
                                                 QIHSE_EDGE_INCOMING,
                                                 neighbors, 4u);
    CHECK(count == 2);
    CHECK(neighbors[0] == 102u || neighbors[1] == 102u);
    CHECK(qihse_vector_db_checkpoint(db));
    CHECK(qihse_vector_db_close(db));

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, path,
                              QIHSE_VDB_OPEN_FILE_BACKED | QIHSE_VDB_OPEN_READ_ONLY);
    CHECK(db != NULL);
    memset(records, 0, sizeof(records));
    count = qihse_vector_db_get_edge_records(db, 101u, "CALLS",
                                              QIHSE_EDGE_OUTGOING, records, 2u);
    CHECK(count == 1);
    CHECK(records[0].metadata_size == sizeof(replacement) - 1u);
    CHECK(memcmp(records[0].metadata, replacement, sizeof(replacement) - 1u) == 0);
    qihse_vector_db_free_edge_records(records, 1u);
    CHECK(!qihse_vector_db_remove_edge(db, 101u, 102u, "CALLS"));
    CHECK(errno == EROFS);
    qihse_vector_db_destroy(db);
    return 0;
}

static int verify_remove_and_old_container(const char* path) {
    qihse_vector_db_t db;
    qihse_container_t ctr;
    qihse_ctr_section_buf_t remove_edges = {QIHSE_CTR_SEC_EDGES, NULL, 0u};
    uint64_t neighbors[2] = {0u};

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, path,
                              QIHSE_VDB_OPEN_FILE_BACKED);
    CHECK(db != NULL);
    CHECK(qihse_vector_db_remove_edge(db, 101u, 102u, "CALLS"));
    CHECK(qihse_vector_db_remove_edge(db, 101u, 102u, "CALLS"));
    CHECK(qihse_vector_db_checkpoint(db));
    CHECK(qihse_vector_db_close(db));

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, path,
                              QIHSE_VDB_OPEN_FILE_BACKED);
    CHECK(db != NULL);
    CHECK(qihse_vector_db_get_edges(db, 101u, "CALLS", neighbors, 2u) == 0);
    CHECK(!qihse_vector_db_add_edge(db, 101u, 999u, "CALLS", NULL, 0u));
    CHECK(errno == ENOENT);
    CHECK(qihse_vector_db_close(db));

    CHECK(qihse_ctr_open_write(path, false, &ctr));
    CHECK(qihse_ctr_flush(&ctr, &remove_edges, 1u));
    qihse_ctr_close(&ctr);
    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL, path,
                              QIHSE_VDB_OPEN_FILE_BACKED | QIHSE_VDB_OPEN_READ_ONLY);
    CHECK(db != NULL);
    CHECK(qihse_vector_db_get_edges(db, 101u, NULL, neighbors, 2u) == 0);
    qihse_vector_db_destroy(db);
    return 0;
}

int main(void) {
    const char* path = "/tmp/qihse_edge_persistence_test.qdb";
    pid_t child;
    int status = 0;
    unlink(path);

    child = fork();
    CHECK(child >= 0);
    if (child == 0) return write_uncheckpointed_edges(path);
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(verify_replay_and_checkpoint(path) == 0);
    CHECK(verify_remove_and_old_container(path) == 0);
    unlink(path);
    puts("qihse explicit edge persistence tests passed");
    return 0;
}
