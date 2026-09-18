/*
 * gold_security_null_context.c — gold workload (area: security-regressions).
 *
 * A KNOWN-DEFECT probe for AGENTS.md security invariant 1:
 *
 *   "NULL MUST NOT accidentally become an authorization bypass.  If QIHSE
 *    supports an explicitly security-disabled operating mode, that mode must be
 *    represented deliberately in configuration/context state rather than
 *    inferred from a forgotten user argument."
 *
 * qihse_vector_db_search() substitutes qihse_auth_get_user(0) — the operator,
 * the highest-privilege principal — when query.user is NULL
 * (src/broad_oak/qihse_vector_db.c:5841-5845) instead of failing closed.  This
 * probe observes the behaviour on a real search:
 *
 *   GOLD: KNOWN-BUG <workload-id> <check>: <detail>
 *   GOLD: OK        <workload-id> <check>: <detail>
 *
 * The control is the same search with an explicit authenticated user; if the
 * control fails the probe is broken and exits non-zero.
 *
 * Impact statement (kept honest): every vector row is written with
 * QIHSE_CLASS_UNCLASSIFIED today (src/broad_oak/qihse_vector_db.c:3927), so no
 * classified payload is disclosed by this path yet.  The defect is that a
 * forgotten argument selects the operator identity rather than failing closed,
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOLD_ID       "gold_security_null_context"
#define GOLD_DIMS     3u
#define GOLD_PASSWORD "gold-suite-test-password"

static int search_with(qihse_vector_db_t db, const float* vector,
                       qihse_user_t* user, int* out_errno) {
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
    memset(&result, 0, sizeof(result));
    errno = 0;
    int count = qihse_vector_db_search(db, &query, &result, 1);
    if (out_errno) *out_errno = errno;
    free(result.vector);
    free(result.metadata);
    return count;
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
    int control_errno = 0;
    int control_count = search_with(db, vector, operator_user, &control_errno);
    if (control_count != 1) {
        fprintf(stderr,
                "%s: probe control failed: an explicit operator search returned "
                "%d (errno=%d); the NULL-user check below cannot be interpreted\n",
                GOLD_ID, control_count, control_errno);
        return 1;
    }

    /* The check: a NULL security context must not become an identity. */
    int null_errno = 0;
    int null_count = search_with(db, vector, NULL, &null_errno);
    if (null_count > 0) {
        char detail[900];
        snprintf(detail, sizeof(detail),
                 "a search with query.user == NULL was accepted (returned %d row) "
                 "instead of failing closed with EACCES; the caller's missing "
                 "argument was replaced by qihse_auth_get_user(0), which is the "
                 "active operator principal (role=%d, clearance=0x%X, "
                 "user_id=%u) — src/broad_oak/qihse_vector_db.c:5841-5845, "
                 "AGENTS.md invariant 1.  Impact today: vector rows are written "
                 "as QIHSE_CLASS_UNCLASSIFIED (src/broad_oak/qihse_vector_db.c:3927), "
                 "so no classified payload is disclosed yet; the same fallback is "
                 "why tests/qihse_vector_db_persistence_test.c:423-441 fails "
                 "(it passes user = NULL without initialising auth)",
                 null_count, (int)qihse_user_get_role(user_zero),
                 (unsigned)qihse_user_get_classification(user_zero),
                 (unsigned)qihse_user_get_id(user_zero));
        printf("GOLD: KNOWN-BUG %s null-user-fails-closed: %s\n", GOLD_ID, detail);
    } else {
        printf("GOLD: OK %s null-user-fails-closed: a search with query.user == "
               "NULL was refused (count=%d errno=%d), not silently run as the "
               "operator\n", GOLD_ID, null_count, null_errno);
    }

    qihse_vector_db_destroy(db);
    qihse_uma_destroy(uma);
    qihse_memory_manager_destroy(memory);
    qihse_context_destroy(ctx);
    return 0;
}
