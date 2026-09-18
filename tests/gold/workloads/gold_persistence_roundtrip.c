/*
 * gold_persistence_roundtrip.c — gold workload (area: persistence-recovery).
 *
 * Verifies the durability claims of the native vector store through the public
 * API only, on paths relative to the repository root:
 *
 *   1. a durable add survives close + reopen, byte-for-byte (id, vector,
 *      metadata), and the reopened container answers a search;
 *   2. a durable add survives a process that exits WITHOUT close/checkpoint
 *      (WAL replay).  The write is performed in a forked child that calls
 *      _exit(), so no in-process teardown, flush or checkpoint can run;
 *   3. a committed delete_by_id stays deleted across reopen.
 *
 * Every check is a real call into the shipped library; there is no assertion
 * that would hold for a broken build (for example, check 2 fails if the WAL
 * is ignored on reopen).
 *
 * Auth note: qihse_vector_db_search() requires an authenticated user.  This
 * workload bootstraps an operator (or authenticates with the environment
 * password when one is already configured) so the search path is exercised
 * with a real identity, not with the NULL-context fallback.
 *
 * Exit status: 0 = every check held; non-zero = the claimed behaviour is
 * absent.  The runner additionally requires the final PASS line.
 */
#include "qihse_abi.h"
#include "qihse_memory.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GOLD_TMP_DIR  "tests/gold/.tmp"
#define GOLD_DB_PATH  GOLD_TMP_DIR "/persistence-roundtrip.qdb"
#define GOLD_WAL_PATH GOLD_TMP_DIR "/persistence-wal-replay.qdb"
#define GOLD_DIMS     4u
#define GOLD_PASSWORD "gold-suite-test-password"

typedef struct gold_env_s {
    qihse_context_t ctx;
    qihse_memory_manager_t memory;
    qihse_uma_manager_t uma;
    qihse_user_t* user;
} gold_env_t;

static int fail(const char* what) {
    fprintf(stderr, "gold_persistence_roundtrip: FAIL: %s (errno=%d %s)\n",
            what, errno, strerror(errno));
    return 1;
}

static void env_destroy(gold_env_t* env) {
    if (!env) return;
    if (env->uma) qihse_uma_destroy(env->uma);
    if (env->memory) qihse_memory_manager_destroy(env->memory);
    if (env->ctx) qihse_context_destroy(env->ctx);
    memset(env, 0, sizeof(*env));
}

static int env_init(gold_env_t* env) {
    memset(env, 0, sizeof(*env));
    if (qihse_context_create(NULL, &env->ctx) != QIHSE_OK) return -1;
    env->memory = qihse_memory_manager_create(env->ctx, "uma");
    if (!env->memory) return -1;
    env->uma = qihse_uma_create(env->memory, QIHSE_UMA_MIGRATE_ON_ACCESS);
    if (!env->uma) return -1;

    if (!qihse_auth_init()) return -1;
    const char* env_pw = getenv("QIHSE_OPERATOR_PASSWORD");
    if (env_pw && *env_pw) env->user = qihse_auth_authenticate_id(0, env_pw);
    if (!env->user) {
        if (!qihse_auth_bootstrap_operator(GOLD_PASSWORD)) return -1;
        env->user = qihse_auth_authenticate_id(0, GOLD_PASSWORD);
    }
    if (!env->user) return -1;
    return 0;
}

static void remove_db(const char* path) {
    char tmp[256];
    unlink(path);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    unlink(tmp);
}

static int add_one(qihse_vector_db_t db, const float* vector, uint64_t id,
                   const char* metadata, size_t metadata_size) {
    const uint64_t ids[1] = {id};
    const void* metas[1] = {metadata};
    const size_t sizes[1] = {metadata_size};
    return qihse_vector_db_add_vectors(db, vector, 1, GOLD_DIMS, ids, metas,
                                       sizes) ? 0 : -1;
}

/* Search for one exact row; returns the result count, or a negative error. */
static int search_one(qihse_vector_db_t db, const float* vector,
                      qihse_user_t* user, qihse_vector_result_t* result) {
    qihse_vector_query_t query;
    memset(&query, 0, sizeof(query));
    query.query_vector = vector;
    query.vector_dims = GOLD_DIMS;
    query.top_k = 1;
    query.similarity_threshold = 0.999f;
    query.include_vectors = true;
    query.include_metadata = true;
    query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
    query.distance_metric = QIHSE_DISTANCE_COSINE;
    query.user = user;
    memset(result, 0, sizeof(*result));
    return qihse_vector_db_search(db, &query, result, 1);
}

static void free_result(qihse_vector_result_t* result) {
    free(result->vector);
    free(result->metadata);
    result->vector = NULL;
    result->metadata = NULL;
}

/* ── Check 1: durable add survives close + reopen ───────────────────────── */
static int check_close_reopen(gold_env_t* env) {
    const float vector[GOLD_DIMS] = {1.0f, 0.0f, 0.0f, 0.0f};
    const char metadata[] = "roundtrip";

    remove_db(GOLD_DB_PATH);
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env->uma, GOLD_DB_PATH);
    if (!db) return fail("create (close/reopen) returned NULL");
    if (add_one(db, vector, 101, metadata, sizeof(metadata)) != 0)
        return fail("add before close failed");
    if (!qihse_vector_db_flush(db)) return fail("flush before close failed");
    if (!qihse_vector_db_close(db)) return fail("close failed");

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, env->uma, GOLD_DB_PATH,
                              QIHSE_VDB_OPEN_FILE_BACKED);
    if (!db) return fail("reopen returned NULL");

    qihse_vector_result_t result;
    int count = search_one(db, vector, env->user, &result);
    if (count != 1) {
        fprintf(stderr,
                "gold_persistence_roundtrip: FAIL: reopened search returned %d "
                "(expected 1); the durable row is not searchable after reopen\n",
                count);
        qihse_vector_db_close(db);
        return 1;
    }
    if (result.id != 101) return fail("reopened row has the wrong id");
    if (!result.vector ||
        memcmp(result.vector, vector, sizeof(vector)) != 0)
        return fail("reopened row lost its vector bytes");
    if (!result.metadata || result.metadata_size != sizeof(metadata) ||
        memcmp(result.metadata, metadata, sizeof(metadata)) != 0)
        return fail("reopened row lost its metadata bytes");
    free_result(&result);

    if (!qihse_vector_db_close(db)) return fail("close after reopen failed");
    remove_db(GOLD_DB_PATH);
    printf("  check 1: durable add survived close + reopen (id, vector, metadata)\n");
    return 0;
}

/* ── Check 2: WAL replay after a process exits without close ────────────── */
static int check_wal_replay(gold_env_t* env) {
    const float vector[GOLD_DIMS] = {0.0f, 1.0f, 0.0f, 0.0f};
    const char metadata[] = "wal-replay";

    remove_db(GOLD_WAL_PATH);
    pid_t pid = fork();
    if (pid < 0) return fail("fork failed");
    if (pid == 0) {
        /* Child: accepted write, durable WAL flush, then _exit() so that no
         * close/checkpoint/atexit path can publish a snapshot. */
        qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,
                                                      env->uma, GOLD_WAL_PATH);
        if (!db) _exit(11);
        if (add_one(db, vector, 202, metadata, sizeof(metadata)) != 0) _exit(12);
        if (!qihse_vector_db_flush(db)) _exit(13);
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid failed");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr,
                "gold_persistence_roundtrip: FAIL: writer child exited "
                "status=%d (expected a clean WAL flush then _exit)\n", status);
        return 1;
    }

    qihse_vector_db_t db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,
                                                env->uma, GOLD_WAL_PATH,
                                                QIHSE_VDB_OPEN_FILE_BACKED);
    if (!db) return fail("reopen after simulated crash returned NULL");

    qihse_vector_result_t result;
    int count = search_one(db, vector, env->user, &result);
    if (count != 1) {
        fprintf(stderr,
                "gold_persistence_roundtrip: FAIL: after a writer that exited "
                "without close, the WAL-replayed row is not searchable "
                "(search returned %d)\n", count);
        qihse_vector_db_close(db);
        return 1;
    }
    if (result.id != 202) return fail("WAL-replayed row has the wrong id");
    free_result(&result);
    if (!qihse_vector_db_close(db)) return fail("close after WAL replay failed");
    remove_db(GOLD_WAL_PATH);
    printf("  check 2: unflushed-but-durable add replayed from the WAL\n");
    return 0;
}

/* ── Check 3: a committed delete stays deleted across reopen ────────────── */
static int check_delete_persists(gold_env_t* env) {
    const float vector[GOLD_DIMS] = {0.0f, 0.0f, 1.0f, 0.0f};
    const char metadata[] = "deleted";

    remove_db(GOLD_DB_PATH);
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, env->uma, GOLD_DB_PATH);
    if (!db) return fail("create (delete) returned NULL");
    if (add_one(db, vector, 303, metadata, sizeof(metadata)) != 0)
        return fail("add before delete failed");
    if (!qihse_vector_db_delete_by_id(db, 303))
        return fail("delete_by_id failed");
    if (!qihse_vector_db_flush(db)) return fail("flush after delete failed");
    if (!qihse_vector_db_close(db)) return fail("close after delete failed");

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, env->uma, GOLD_DB_PATH,
                              QIHSE_VDB_OPEN_FILE_BACKED);
    if (!db) return fail("reopen after delete returned NULL");
    qihse_vector_result_t result;
    int count = search_one(db, vector, env->user, &result);
    if (count != 0) {
        fprintf(stderr,
                "gold_persistence_roundtrip: FAIL: deleted row is visible "
                "after reopen (search returned %d)\n", count);
        free_result(&result);
        qihse_vector_db_close(db);
        return 1;
    }
    if (!qihse_vector_db_close(db)) return fail("close after delete reopen failed");
    remove_db(GOLD_DB_PATH);
    printf("  check 3: committed delete stayed deleted across reopen\n");
    return 0;
}

int main(void) {
    if (mkdir(GOLD_TMP_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "gold_persistence_roundtrip: cannot create %s: %s\n",
                GOLD_TMP_DIR, strerror(errno));
        return 1;
    }

    gold_env_t env;
    if (env_init(&env) != 0) {
        fprintf(stderr, "gold_persistence_roundtrip: environment/auth setup failed\n");
        env_destroy(&env);
        return 1;
    }

    int rc = 0;
    rc |= check_close_reopen(&env);
    rc |= check_wal_replay(&env);
    rc |= check_delete_persists(&env);

    env_destroy(&env);
    rmdir(GOLD_TMP_DIR);

    if (rc != 0) return 1;
    printf("gold_persistence_roundtrip: PASS (durable add across close/reopen, "
           "WAL replay after a writer exits without close, delete durability)\n");
    return 0;
}
