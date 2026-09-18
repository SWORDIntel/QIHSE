/*
 * gold_security_null_context.c — gold workload (area: security-regressions).
 *
 * Regression probe for AGENTS.md security invariant 1:
 *
 *   "NULL MUST NOT accidentally become an authorization bypass.  If QIHSE
 *    supports an explicitly security-disabled operating mode, that mode must be
 *    represented deliberately in configuration/context state rather than
 *    inferred from a forgotten user argument."
 *
 * The defect this probe was written for: qihse_vector_db_search() substituted
 * qihse_auth_get_user(0) — the operator, the highest-privilege principal — when
 * query.user was NULL (src/broad_oak/qihse_vector_db.c:5841-5845).  The
 * substitution is removed; a NULL context now fails closed with EACCES and
 * materialises nothing.
 *
 *   GOLD: OK        <workload-id> <check>: <detail>   (defect absent)
 *   GOLD: KNOWN-BUG <workload-id> <check>: <detail>   (defect present)
 *
 * The check asserts absence, not merely an error return: the search must report
 * no rows AND leave the caller's result slot byte-for-byte untouched, so a
 * regression that returns rows — or writes a result and then reports an error —
 * is caught.  The control is the same search with an explicit authenticated
 * user; if the control fails the probe is broken and exits non-zero.
 *
 * Impact statement (kept honest): every vector row is written with
 * QIHSE_CLASS_UNCLASSIFIED today (src/broad_oak/qihse_vector_db.c:3927), so the
 * old fallback disclosed no classified payload yet.  The defect was that a
 * forgotten argument selected the operator identity rather than failing closed,
 * which is what invariant 1 forbids for a classified-capable read primitive.
 * The same fallback is why the shipped persistence regression test — which
 * never initialises auth and passes user = NULL — fails today
 * (tests/qihse_vector_db_persistence_test.c:423-441).
 *
 * Exit status: 0 when the probe ran and reported; non-zero when the control
 * failed.
 */
#include "qihse_abi.h"
#include "qihse_memory.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOLD_ID       "gold_security_null_context"
#define GOLD_DIMS     3u
#define GOLD_PASSWORD "gold-suite-test-password"

typedef struct {
    int  count;        /* qihse_vector_db_search() return value */
    int  err;          /* errno observed after the call */
    bool bytes_absent; /* the result slot was not written at all */
} gold_search_outcome_t;

static gold_search_outcome_t search_with(qihse_vector_db_t db, const float* vector,
                                         qihse_user_t* user) {
    qihse_vector_query_t query;
    memset(&query, 0, sizeof(query));
    query.query_vector = vector;
    query.vector_dims = GOLD_DIMS;
    query.top_k = 1;
    query.similarity_threshold = 0.999f;
    query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
    query.distance_metric = QIHSE_DISTANCE_COSINE;
    query.user = user;

    qihse_vector_result_t result;
    qihse_vector_result_t untouched;
    memset(&result, 0, sizeof(result));
    memset(&untouched, 0, sizeof(untouched));

    gold_search_outcome_t out;
    memset(&out, 0, sizeof(out));
    errno = 0;
    out.count = qihse_vector_db_search(db, &query, &result, 1);
    out.err = errno;
    /* Byte absence: a fail-closed search must not have written id, score,
     * vector or metadata into the caller's result slot. */
    out.bytes_absent = memcmp(&result, &untouched, sizeof(untouched)) == 0;
    free(result.vector);
    free(result.metadata);
    return out;
}

int main(void) {
    if (!qihse_auth_init()) {
        fprintf(stderr, "%s: probe control failed: qihse_auth_init\n", GOLD_ID);
        return 1;
    }
    const char* env_pw = getenv("QIHSE_OPERATOR_PASSWORD");
    qihse_user_t* operator_user = NULL;
    if (env_pw && *env_pw) operator_user = qihse_auth_authenticate_id(0, env_pw);
    if (!operator_user) {
        if (!qihse_auth_bootstrap_operator(GOLD_PASSWORD)) {
            fprintf(stderr, "%s: probe control failed: operator bootstrap\n", GOLD_ID);
            return 1;
        }
        operator_user = qihse_auth_authenticate_id(0, GOLD_PASSWORD);
    }
    if (!operator_user) {
        fprintf(stderr, "%s: probe control failed: no authenticated operator\n",
                GOLD_ID);
        return 1;
    }
    qihse_user_t* user_zero = qihse_auth_get_user(0);
    if (!user_zero) {
        fprintf(stderr,
                "%s: probe control failed: qihse_auth_get_user(0) is NULL, so "
                "the fallback the probe tests cannot be reached\n", GOLD_ID);
        return 1;
    }

    qihse_context_t ctx;
    if (qihse_context_create(NULL, &ctx) != QIHSE_OK) return 1;
    qihse_memory_manager_t memory = qihse_memory_manager_create(ctx, "uma");
    if (!memory) return 1;
    qihse_uma_manager_t uma = qihse_uma_create(memory, QIHSE_UMA_MIGRATE_ON_ACCESS);
    if (!uma) return 1;
    qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, NULL);
    if (!db) {
        fprintf(stderr, "%s: probe control failed: vector db create\n", GOLD_ID);
        return 1;
    }

    const float vector[GOLD_DIMS] = {1.0f, 0.0f, 0.0f};
    const uint64_t ids[1] = {1u};
    if (!qihse_vector_db_add_vectors(db, vector, 1, GOLD_DIMS, ids, NULL, NULL)) {
        fprintf(stderr, "%s: probe control failed: add_vectors\n", GOLD_ID);
        return 1;
    }

    /* Control: an explicit authenticated identity can read the row. */
    gold_search_outcome_t control = search_with(db, vector, operator_user);
    if (control.count != 1) {
        fprintf(stderr,
                "%s: probe control failed: an explicit operator search returned "
                "%d (errno=%d); the NULL-user check below cannot be interpreted\n",
                GOLD_ID, control.count, control.err);
        return 1;
    }

    /* The check: a NULL security context must not become an identity, and must
     * return no rows and no result bytes. */
    gold_search_outcome_t null_out = search_with(db, vector, NULL);
    if (null_out.count > 0 || !null_out.bytes_absent || null_out.err != EACCES) {
        char detail[1100];
        snprintf(detail, sizeof(detail),
                 "a search with query.user == NULL did not fail closed with no "
                 "result bytes (count=%d, errno=%d, result_bytes_absent=%s). If "
                 "it returned rows, the caller's missing argument was replaced by "
                 "qihse_auth_get_user(0), the active operator principal "
                 "(role=%d, clearance=0x%X, user_id=%u) — "
                 "src/broad_oak/qihse_vector_db.c:5831, AGENTS.md invariant 1.  "
                 "Impact today: vector rows are written as "
                 "QIHSE_CLASS_UNCLASSIFIED (src/broad_oak/qihse_vector_db.c:3927), "
                 "so no classified payload is disclosed yet; the same fallback is "
                 "why tests/qihse_vector_db_persistence_test.c:423-441 fails "
                 "(it passes user = NULL without initialising auth)",
                 null_out.count, null_out.err,
                 null_out.bytes_absent ? "yes" : "no",
                 (int)qihse_user_get_role(user_zero),
                 (unsigned)qihse_user_get_classification(user_zero),
                 (unsigned)qihse_user_get_id(user_zero));
        printf("GOLD: KNOWN-BUG %s null-user-fails-closed: %s\n", GOLD_ID, detail);
    } else {
        printf("GOLD: OK %s null-user-fails-closed: a search with query.user == "
               "NULL returned no rows (count=%d errno=%d) and wrote no result "
               "bytes; no principal was substituted — "
               "src/broad_oak/qihse_vector_db.c:5831, AGENTS.md invariant 1\n",
               GOLD_ID, null_out.count, null_out.err);
    }

    qihse_vector_db_destroy(db);
    qihse_uma_destroy(uma);
    qihse_memory_manager_destroy(memory);
    qihse_context_destroy(ctx);
    return 0;
}
