#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_uwp.h"
#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_schema.h"
#include "qihse_table_store.h"
#include "qihse_txn.h"
#include "qihse_blob.h"
#include "qihse_auth.h"
#include "qihse_audit.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>

#define SQL_ENGINE_ID 81u
#define BLOB_ENGINE_ID 82u

static const uint8_t payload[] = "durable sql plus blob transaction";
static const char* journal_path;
static const char* sql_path;
static const char* blob_path;
static int sql_engine_placeholder;
static int crash_before_blob_publish;
static bool receipt_case;
static unsigned receipt_blob_calls, receipt_blob_abort_calls;
static bool receipt_commit_decision = true;
static __thread struct {
    bool armed, file_synced;
    unsigned fired;
    char destination[PATH_MAX];
    dev_t parent_dev, file_dev;
    ino_t parent_ino, file_ino;
} receipt_fault;

typedef struct {
    qihse_blob_store_t* store;
    qihse_user_t* user;
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
} blob_resource_t;

static int64_t memory_read(void* opaque, uint8_t* buffer, size_t capacity) {
    size_t* offset = opaque;
    size_t remaining = sizeof(payload) - 1u - *offset;
    if (!remaining) return 0;
    size_t n = remaining < capacity ? remaining : capacity;
    memcpy(buffer, payload + *offset, n);
    *offset += n;
    return (int64_t)n;
}

static int blob_prepare(void* opaque, uint64_t txn_id) {
    (void)opaque; (void)txn_id;
    return 0;
}

static int blob_prepare_resource(void* opaque, uint64_t txn_id, void* resource) {
    (void)opaque;
    blob_resource_t* blob = resource;
    size_t offset = 0;
    bool ok = blob && qihse_blob_prepare_expected_user(blob->store, txn_id,
        qihse_user_get_tenant_id(blob->user), QIHSE_BLOB_TAG_SCRIPT_SET,
        0, 0, blob->user, memory_read, &offset, blob->hash, sizeof(payload) - 1u);
    free(blob);
    return ok ? 0 : -1;
}

static void blob_resource_rollback(void* resource) { free(resource); }

static int blob_commit(void* opaque, uint64_t txn_id) {
    if (receipt_case) ++receipt_blob_calls;
    if (crash_before_blob_publish) _exit(77);
    return qihse_blob_resolve_prepared(opaque, txn_id, true) ? 0 : -1;
}

static int blob_abort(void* opaque, uint64_t txn_id) {
    if (receipt_case) ++receipt_blob_abort_calls;
    return qihse_blob_resolve_prepared(opaque, txn_id, false) ? 0 : -1;
}

static ssize_t reply_write(void* opaque, const void* data, size_t len) {
    (void)opaque; (void)data;
    return (ssize_t)len;
}

static uwp_sts_result_t sql(qihse_uwp_context_t* ctx, qihse_user_t* user,
                            const char* statement, qihse_txn_t** txn) {
    return uwp_dispatch_sql(ctx, 0x02, (const uint8_t*)statement,
        strlen(statement) + 1u, txn, user, -1, reply_write, NULL);
}

static void open_context_unrecovered(qihse_uwp_context_t* ctx, qihse_user_t* user,
                                     qihse_blob_store_t** blob_out) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->sql_engine = &sql_engine_placeholder;
    ctx->schema = NULL; /* Adopt the durable catalog during fresh-process recovery. */
    ctx->txn_manager = qihse_txn_manager_create_durable(journal_path);
    assert(ctx->txn_manager);
    assert(qihse_uwp_sql_open_durable(ctx, sql_path) == 0 && ctx->schema);
    *blob_out = qihse_blob_store_create(blob_path);
    assert(*blob_out);
    assert(qihse_uwp_sql_txn_register_durable_participant(ctx->txn_manager,
                                                          SQL_ENGINE_ID) == 0);
    qihse_txn_participant_t bp = { .engine_id = BLOB_ENGINE_ID,
        .engine_ctx = *blob_out, .prepare = blob_prepare,
        .commit = blob_commit, .abort = blob_abort };
    assert(qihse_txn_register_resource_participant(ctx->txn_manager, bp,
                                                    blob_prepare_resource) == 0);
    uint64_t next_id = 0;
    assert(qihse_blob_decision_next_id(*blob_out, &next_id));
    assert(qihse_txn_advance_next_id(ctx->txn_manager, next_id) == 0);
    (void)user;
}

static void open_context(qihse_uwp_context_t* ctx, qihse_user_t* user,
                         qihse_blob_store_t** blob_out) {
    open_context_unrecovered(ctx, user, blob_out);
    assert(qihse_txn_manager_recover(ctx->txn_manager) == 0);
}

static void close_context(qihse_uwp_context_t* ctx, qihse_blob_store_t* blob) {
    qihse_blob_store_destroy(blob);
    qihse_uwp_sql_close_durable(ctx);
    qihse_schema_registry_destroy(ctx->schema);
    qihse_txn_manager_destroy(ctx->txn_manager);
}

static void stage_transaction(qihse_uwp_context_t* ctx, qihse_user_t* user,
                              qihse_blob_store_t* blob, uint8_t hash[48],
                              qihse_txn_t** out_txn, bool expect_blob_visible) {
    size_t prior_rows = qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "artifacts"));
    qihse_txn_t* txn = NULL;
    assert(sql(ctx, user, "BEGIN", &txn) == UWP_STS_OK && txn);
    assert(sql(ctx, user, "INSERT INTO artifacts VALUES (1, 'pending')", &txn) == UWP_STS_OK);
    blob_resource_t* resource = calloc(1, sizeof(*resource));
    assert(resource);
    resource->store = blob;
    resource->user = user;
    size_t offset = 0;
    /* Compute the expected digest using the same SHA-384 contract as the blob tier. */
    EVP_MD_CTX* digest = EVP_MD_CTX_new();
    unsigned int length = 0;
    assert(digest && EVP_DigestInit_ex(digest, EVP_sha384(), NULL) == 1 &&
           EVP_DigestUpdate(digest, payload, sizeof(payload) - 1u) == 1 &&
           EVP_DigestFinal_ex(digest, hash, &length) == 1 && length == 48);
    EVP_MD_CTX_free(digest);
    (void)offset;
    memcpy(resource->hash, hash, 48);
    assert(qihse_uwp_sql_txn_enlist_durable(ctx->txn_manager, txn, SQL_ENGINE_ID) == 0);
    assert(qihse_txn_attach_participant_resource(ctx->txn_manager, txn,
        BLOB_ENGINE_ID, resource, blob_resource_rollback) == 0);
    assert(qihse_txn_prepare(ctx->txn_manager, txn) == 0);
    assert(qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "artifacts")) == prior_rows);
    qihse_blob_info_t info;
    if (expect_blob_visible) {
        assert(qihse_blob_info_user(blob, hash, &info, user));
    } else {
        assert(!qihse_blob_info_user(blob, hash, &info, user));
    }
    *out_txn = txn;
}

static void crash_after_common_commit(qihse_user_t* user, uint8_t hash[48]) {
    qihse_uwp_context_t ctx;
    qihse_blob_store_t* blob;
    open_context(&ctx, user, &blob);
    qihse_txn_t* txn;
    stage_transaction(&ctx, user, blob, hash, &txn, false);
    crash_before_blob_publish = 1;
    (void)qihse_txn_commit_prepared(ctx.txn_manager, txn);
    _exit(3);
}

static void crash_after_prepare(qihse_user_t* user, uint8_t hash[48]) {
    qihse_uwp_context_t ctx;
    qihse_blob_store_t* blob;
    open_context(&ctx, user, &blob);
    qihse_txn_t* txn;
    stage_transaction(&ctx, user, blob, hash, &txn, true);
    assert(txn->id == 3u);
    _exit(78); /* no common decision: recovery must durably choose ABORT */
}

static void prepare_blob_receipt(qihse_blob_store_t* blob, qihse_user_t* user,
                                  const uint8_t hash[48], uint64_t txn_id) {
    size_t offset = 0;
    assert(qihse_blob_prepare_expected_user(blob, txn_id,
        qihse_user_get_tenant_id(user), QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
        user, memory_read, &offset, hash, sizeof(payload) - 1u));
}

static void test_blob_decision_high_water(const char* root, qihse_user_t* user,
                                          uint8_t hash[48]) {
    const char* saved_journal = journal_path;
    char terminal_journal[512], prepared_journal[512];
    snprintf(terminal_journal, sizeof(terminal_journal), "%s/terminal.journal", root);
    snprintf(prepared_journal, sizeof(prepared_journal), "%s/prepared.journal", root);
    qihse_uwp_context_t ctx;
    qihse_blob_store_t* blob;
    open_context(&ctx, user, &blob);
    uint64_t sql_next = 0, next = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sql_next));
    assert(sql_next == 4u);
    prepare_blob_receipt(blob, user, hash, 41u);
    assert(qihse_blob_decision_next_id(blob, &next) && next == 42u);
    assert(qihse_blob_resolve_prepared(blob, 41u, true));
    assert(qihse_blob_decision_next_id(blob, &next) && next == 42u);
    prepare_blob_receipt(blob, user, hash, 73u);
    assert(qihse_blob_resolve_prepared(blob, 73u, false));
    assert(qihse_blob_decision_next_id(blob, &next) && next == 74u);
    close_context(&ctx, blob);

    /* No coordinator journal contains 41 or 73; SQL still only fences at 4. */
    journal_path = terminal_journal;
    open_context(&ctx, user, &blob);
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sql_next));
    assert(sql_next == 4u);
    assert(qihse_blob_decision_next_id(blob, &next) && next == 74u);
    assert(qihse_blob_resolve_prepared(blob, 41u, true));
    assert(!qihse_blob_resolve_prepared(blob, 41u, false));
    assert(qihse_blob_resolve_prepared(blob, 73u, false));
    assert(!qihse_blob_resolve_prepared(blob, 73u, true));
    qihse_blob_info_t info;
    assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 2u);
    qihse_txn_t* txn = NULL;
    assert(sql(&ctx, user, "BEGIN", &txn) == UWP_STS_OK && txn && txn->id == 74u);
    assert(sql(&ctx, user, "ROLLBACK", &txn) == UWP_STS_OK && !txn);
    prepare_blob_receipt(blob, user, hash, 97u);
    assert(qihse_blob_decision_next_id(blob, &next) && next == 98u);
    assert(!qihse_blob_ref_user(blob, hash, user));
    close_context(&ctx, blob);

    /* An orphan PREPARE also fences a fresh coordinator, but does not authorize
     * recovery to publish or abort it without the missing common journal. */
    journal_path = prepared_journal;
    open_context(&ctx, user, &blob);
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sql_next));
    assert(sql_next == 4u);
    assert(qihse_blob_decision_next_id(blob, &next) && next == 98u);
    assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 2u);
    assert(!qihse_blob_ref_user(blob, hash, user));
    assert(sql(&ctx, user, "BEGIN", &txn) == UWP_STS_OK && txn && txn->id == 98u);
    assert(sql(&ctx, user, "ROLLBACK", &txn) == UWP_STS_OK && !txn);
    /* This fixture explicitly owns the orphan; the high-water query does not. */
    assert(qihse_blob_resolve_prepared(blob, 97u, false));
    stage_transaction(&ctx, user, blob, hash, &txn, true);
    assert(txn->id == 99u);
    assert(qihse_txn_commit_prepared(ctx.txn_manager, txn) == 0);
    assert(qihse_blob_decision_next_id(blob, &next) && next == 100u);
    assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 3u);
    assert(qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "artifacts")) == 2u);
    close_context(&ctx, blob);

    /* Nonfresh same-journal replay must neither double-apply nor lower IDs. */
    open_context(&ctx, user, &blob);
    assert(qihse_txn_manager_recover(ctx.txn_manager) == 0);
    assert(qihse_blob_resolve_prepared(blob, 99u, true));
    assert(!qihse_blob_resolve_prepared(blob, 99u, false));
    assert(qihse_blob_resolve_prepared(blob, 97u, false));
    assert(qihse_blob_decision_next_id(blob, &next) && next == 100u);
    assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 3u);
    assert(qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "artifacts")) == 2u);
    txn = NULL;
    assert(sql(&ctx, user, "BEGIN", &txn) == UWP_STS_OK && txn && txn->id == 100u);
    assert(sql(&ctx, user, "ROLLBACK", &txn) == UWP_STS_OK && !txn);
    close_context(&ctx, blob);

    /* The older nonfresh journal's IDs 1..3 cannot lower participant fences. */
    journal_path = saved_journal;
    open_context(&ctx, user, &blob);
    assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 3u);
    assert(qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "artifacts")) == 2u);
    assert(sql(&ctx, user, "BEGIN", &txn) == UWP_STS_OK && txn && txn->id == 100u);
    assert(sql(&ctx, user, "ROLLBACK", &txn) == UWP_STS_OK && !txn);
    close_context(&ctx, blob);
}

static void test_blob_absent_abort(const char* root, qihse_user_t* user,
                                    const uint8_t hash[48]) {
    char path[512];
    snprintf(path, sizeof(path), "%s/blob-absent-abort", root);
    qihse_blob_store_t* blob = qihse_blob_store_create(path);
    assert(blob);
    prepare_blob_receipt(blob, user, hash, 11u);
    assert(qihse_blob_resolve_prepared(blob, 11u, true));
    prepare_blob_receipt(blob, user, hash, 12u);
    assert(qihse_blob_resolve_prepared(blob, 12u, false));
    uint64_t baseline = 0;
    assert(qihse_blob_snapshot_epoch_user(blob, user, &baseline));

    for (unsigned reopen = 0; reopen < 2u; ++reopen) {
        uint64_t next = 0, epoch = 0;
        assert(qihse_blob_decision_next_id(blob, &next) && next == 13u);
        if (!reopen) {
            /* Both failures precede durable T: recovery has nothing to undo. */
            uint8_t wrong_hash[48];
            memcpy(wrong_hash, hash, sizeof(wrong_hash));
            wrong_hash[0] ^= 1u;
            size_t offset = 0;
            assert(!qihse_blob_prepare_expected_user(blob, 1001u,
                qihse_user_get_tenant_id(user), QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                user, memory_read, &offset, wrong_hash, sizeof(payload) - 1u));
            offset = 0;
            assert(!qihse_blob_prepare_expected_user(blob, 1002u,
                qihse_user_get_tenant_id(user), QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                user, memory_read, &offset, hash, sizeof(payload)));
        }
        for (uint64_t id = 1000u; id <= 1002u; ++id) {
            assert(!qihse_blob_resolve_prepared(blob, id, true));
            assert(qihse_blob_resolve_prepared(blob, id, false));
            assert(qihse_blob_resolve_prepared(blob, id, false));
            assert(!qihse_blob_resolve_prepared(blob, id, true));
        }
        assert(!qihse_blob_resolve_prepared(NULL, 1000u, false));
        assert(!qihse_blob_resolve_prepared(blob, 0u, false));
        assert(qihse_blob_resolve_prepared(blob, 11u, true));
        assert(!qihse_blob_resolve_prepared(blob, 11u, false));
        assert(qihse_blob_resolve_prepared(blob, 12u, false));
        assert(!qihse_blob_resolve_prepared(blob, 12u, true));
        assert(qihse_blob_decision_next_id(blob, &next) && next == 13u);
        assert(qihse_blob_snapshot_epoch_user(blob, user, &epoch) && epoch == baseline);
        qihse_blob_info_t info;
        assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 1u);
        if (!reopen) {
            /* The child must use only the pre-lock owner-PID rejection path. */
            qihse_audit_shutdown();
            pid_t child = fork();
            assert(child >= 0);
            if (!child) {
                alarm(5u);
                _exit(qihse_blob_resolve_prepared(blob, 1000u, false) ||
                    qihse_blob_resolve_prepared(blob, 1000u, true) ||
                    qihse_blob_resolve_prepared(blob, 11u, true) ||
                    qihse_blob_resolve_prepared(blob, 12u, false) ? 1 : 0);
            }
            int status = 0;
            pid_t waited;
            do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
            qihse_audit_init();
            assert(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
        qihse_blob_store_destroy(blob);
        if (!reopen) {
            blob = qihse_blob_store_create(path);
            assert(blob);
        }
    }
}

static bool fail_blob_index_sync;
static dev_t poisoned_dev;
static ino_t poisoned_ino;
static unsigned poisoned_syncs;

int fsync(int fd) {
    struct stat st;
    if (receipt_fault.armed && fstat(fd, &st) == 0) {
        if (S_ISREG(st.st_mode) && st.st_size == 32) {
            char proc[64], target[PATH_MAX];
            int n = snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
            assert(n > 0 && (size_t)n < sizeof(proc));
            ssize_t length = readlink(proc, target, sizeof(target));
            size_t base = strlen(receipt_fault.destination);
            if (length > 0 && (size_t)length == base + 11u &&
                !memcmp(target, receipt_fault.destination, base) &&
                !memcmp(target + base, ".tmp.", 5u)) {
                int rc = (int)syscall(SYS_fsync, fd);
                if (rc == 0) {
                    assert(!receipt_fault.file_synced);
                    receipt_fault.file_synced = true;
                    receipt_fault.file_dev = st.st_dev;
                    receipt_fault.file_ino = st.st_ino;
                }
                return rc;
            }
        } else if (S_ISDIR(st.st_mode) && receipt_fault.file_synced &&
                   st.st_dev == receipt_fault.parent_dev && st.st_ino == receipt_fault.parent_ino) {
            struct stat published;
            if (lstat(receipt_fault.destination, &published) == 0 &&
                S_ISREG(published.st_mode) && published.st_nlink == 1 &&
                published.st_dev == receipt_fault.file_dev && published.st_ino == receipt_fault.file_ino) {
                receipt_fault.armed = false; ++receipt_fault.fired;
                errno = EIO; return -1;
            }
        }
    }
    if (fail_blob_index_sync && fstat(fd, &st) == 0 &&
        st.st_dev == poisoned_dev && st.st_ino == poisoned_ino) {
        ++poisoned_syncs; errno = EIO; return -1;
    }
    return (int)syscall(SYS_fsync, fd);
}

static void test_blob_poisoned_abort(const char* root, qihse_user_t* user,
                                     const uint8_t hash[48]) {
    char path[512], index[600];
    snprintf(path, sizeof(path), "%s/blob-abort-poisoned", root);
    qihse_blob_store_t* blob = qihse_blob_store_create(path); assert(blob);
    size_t offset = 0;
    assert(qihse_blob_put_expected_user(blob, qihse_user_get_tenant_id(user),
        QIHSE_BLOB_TAG_SCRIPT_SET, 12, 0,
        user, memory_read, &offset, hash, sizeof(payload) - 1u));
    snprintf(index, sizeof(index), "%s/index.log", path);
    struct stat st; assert(stat(index, &st) == 0 && S_ISREG(st.st_mode));
    poisoned_dev = st.st_dev; poisoned_ino = st.st_ino;
    poisoned_syncs = 0; fail_blob_index_sync = true;
    bool changed = qihse_blob_ref_user(blob, hash, user);
    fail_blob_index_sync = false;
    assert(!changed && poisoned_syncs >= 2u);
    assert(!qihse_blob_resolve_prepared(blob, 1000u, false));
    assert(!qihse_blob_resolve_prepared(blob, 1000u, true));
    uint64_t value = 123u;
    assert(!qihse_blob_decision_next_id(blob, &value) && value == 123u);
    assert(!qihse_blob_snapshot_epoch_user(blob, user, &value) && value == 123u);
    qihse_blob_store_destroy(blob);
    blob = qihse_blob_store_create(path); assert(blob);
    qihse_blob_info_t info;
    assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 1u);
    assert(qihse_blob_verify_user(blob, hash, user));
    assert(qihse_blob_resolve_prepared(blob, 1000u, false));
    assert(!qihse_blob_resolve_prepared(blob, 1000u, true));
    assert(qihse_blob_decision_next_id(blob, &value) && value == 1u);
    qihse_blob_store_destroy(blob);
    puts("PASS blob ABORT no-op remains fenced after uncertain index sync until reopen");
}

static void test_blob_decision_overflow(const char* root, qihse_user_t* user,
                                        const uint8_t hash[48]) {
    char path[512];
    snprintf(path, sizeof(path), "%s/blob-overflow", root);
    qihse_blob_store_t* blob = qihse_blob_store_create(path);
    assert(blob);
    uint64_t next = 123u;
    assert(!qihse_blob_decision_next_id(NULL, &next) && next == 123u);
    assert(!qihse_blob_decision_next_id(blob, NULL));
    assert(qihse_blob_decision_next_id(blob, &next) && next == 1u);
    prepare_blob_receipt(blob, user, hash, UINT64_MAX - 1u);
    assert(qihse_blob_resolve_prepared(blob, UINT64_MAX - 1u, false));
    assert(qihse_blob_decision_next_id(blob, &next) && next == UINT64_MAX);
    prepare_blob_receipt(blob, user, hash, UINT64_MAX);
    next = 123u;
    assert(!qihse_blob_decision_next_id(blob, &next) && next == 123u);
    qihse_blob_store_destroy(blob);
    blob = qihse_blob_store_create(path);
    assert(blob);
    assert(!qihse_blob_decision_next_id(blob, &next) && next == 123u);
    assert(!qihse_blob_info_user(blob, hash, &(qihse_blob_info_t){0}, user));
    assert(qihse_blob_resolve_prepared(blob, UINT64_MAX, true));
    assert(!qihse_blob_decision_next_id(blob, &next) && next == 123u);
    qihse_blob_store_destroy(blob);
    blob = qihse_blob_store_create(path);
    assert(blob);
    assert(qihse_blob_resolve_prepared(blob, UINT64_MAX, true));
    assert(!qihse_blob_resolve_prepared(blob, UINT64_MAX, false));
    assert(!qihse_blob_decision_next_id(blob, &next) && next == 123u);
    qihse_blob_store_destroy(blob);
}

#define RECEIPT_PATH_CAP 512u

static void receipt_path(char* out, size_t capacity, const char* root, const char* leaf) {
    int n = snprintf(out, capacity, "%s/%s", root, leaf);
    assert(n > 0 && (size_t)n < capacity);
}
static void receipt_io(int fd, void* data, size_t length, bool writing) {
    uint8_t* p = data;
    while (length) {
        ssize_t n = writing ? write(fd, p, length) : read(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0); p += (size_t)n; length -= (size_t)n;
    }
}
static size_t receipt_read(const char* path, void* data, size_t capacity) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    assert(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && !(st.st_mode & 077) && st.st_nlink == 1 &&
        st.st_size >= 0 && (uint64_t)st.st_size <= capacity);
    size_t length = (size_t)st.st_size;
    receipt_io(fd, data, length, false);
    uint8_t extra;
    assert(read(fd, &extra, 1u) == 0 && close(fd) == 0);
    return length;
}
static void receipt_save(const char* root, const char* leaf, void* data, size_t length) {
    char path[RECEIPT_PATH_CAP]; receipt_path(path, sizeof path, root, leaf);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    assert(fd >= 0); receipt_io(fd, data, length, true);
    assert(fsync(fd) == 0 && close(fd) == 0);
    fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && fsync(fd) == 0 && close(fd) == 0);
}
static uint64_t receipt_le64(const uint8_t* p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8u; ++i) v |= (uint64_t)p[i] << (8u * i);
    return v;
}
static uint64_t receipt_hash(const uint8_t* p, size_t n) {
    uint64_t v = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < n; ++i) { v ^= p[i]; v *= UINT64_C(1099511628211); }
    return v;
}
static void receipt_digest(const void* data, size_t n, uint8_t digest[48]) {
    unsigned length = 0;
    assert(EVP_Digest(data, n, digest, &length, EVP_sha384(), NULL) == 1 && length == 48u);
}
static void receipt_journal(uint64_t id, bool commit, uint8_t bytes[72]) {
    assert(receipt_read(journal_path, bytes, 72u) == 72u);
    for (unsigned r = 0; r < 2u; ++r) {
        const uint8_t* p = bytes + r * 36u;
        assert(!memcmp(p, "QT2P\1", 5u) && p[5] == (r ? (commit ? 2u : 3u) : 1u) &&
            p[6] == (r ? 0u : 2u) && p[7] == 0u);
        uint64_t found = 0;
        for (unsigned i = 0; i < 8u; ++i) found = (found << 8) | p[8u + i];
        assert(found == id);
    }
    assert(bytes[16] == SQL_ENGINE_ID && bytes[17] == BLOB_ENGINE_ID);
    /* The native manager additionally validates both record CRCs. */
}
static __attribute__((noinline)) void receipt_native_files(const char* root, uint64_t id, bool pending) {
    char path[RECEIPT_PATH_CAP];
    int n = snprintf(path, sizeof path, "%s.decision.%016llx", sql_path, (unsigned long long)id);
    assert(n > 0 && (size_t)n < sizeof path);
    uint8_t decision[32], image[4096], prepared[4096];
    assert(receipt_read(path, decision, sizeof decision) == sizeof decision);
    assert(!memcmp(decision, "QTSDEC\1\0", 8u) && receipt_le64(decision + 8) == id &&
        receipt_le64(decision + 16) == (receipt_commit_decision ? 1u : 0u) && receipt_le64(decision + 24) == receipt_hash(decision, 24u));
    n = snprintf(path, sizeof path, "%s.prepared", sql_path);
    assert(n > 0 && (size_t)n < sizeof path);
    if (pending) {
        size_t size = receipt_read(path, prepared, sizeof prepared);
        assert(size >= 32u && !memcmp(prepared, "QTSPREP\1", 8u) &&
            receipt_le64(prepared + 8) == id && receipt_le64(prepared + 16) == size - 32u &&
            receipt_le64(prepared + 24) == receipt_hash(prepared + 32, size - 32u));
        size_t image_size = receipt_read(sql_path, image, sizeof image);
        if (receipt_commit_decision) {
            assert(image_size == size - 32u && !memcmp(image, prepared + 32, image_size));
        } else {
            assert(image_size != size - 32u || memcmp(image, prepared + 32, image_size));
        }
    } else {
        struct stat st; assert(lstat(path, &st) == -1 && errno == ENOENT);
    }
    if (!receipt_commit_decision) {
        uint8_t baseline[4096];
        receipt_path(path, sizeof path, root, "sql-baseline");
        size_t expected = receipt_read(path, baseline, sizeof baseline);
        assert(receipt_read(sql_path, image, sizeof image) == expected && !memcmp(image, baseline, expected));
    }
}
static void receipt_blob_log(qihse_blob_store_t* blob, qihse_user_t* user,
    const uint8_t hash[48], uint64_t id) {
    char path[RECEIPT_PATH_CAP]; receipt_path(path, sizeof path, blob_path, "index.log");
    uint8_t bytes[22u + sizeof(qihse_blob_info_t)];
    size_t prepared = 11u + sizeof(qihse_blob_info_t);
    assert(receipt_read(path, bytes, sizeof bytes) == prepared + 11u);
    uint64_t found; memcpy(&found, bytes + 3, sizeof found);
    assert(bytes[0] == 'Q' && bytes[1] == 2u && bytes[2] == 'T' && found == id);
    qihse_blob_info_t info; memcpy(&info, bytes + 11u, sizeof info);
    assert(!memcmp(info.hash, hash, 48u) && info.refcount == 1u && info.size == sizeof(payload) - 1u &&
        info.classification == 0u && info.sci_compartment == 0u && info.tag == QIHSE_BLOB_TAG_SCRIPT_SET &&
        info.tenant_id == qihse_user_get_tenant_id(user));
    memcpy(&found, bytes + prepared + 3u, sizeof found);
    assert(bytes[prepared] == 'Q' && bytes[prepared + 1u] == 2u && bytes[prepared + 2u] == (receipt_commit_decision ? 'C' : 'A') && found == id);
    if (!receipt_commit_decision) {
        assert(!qihse_blob_info_user(blob, hash, &info, user));
        uint8_t hidden[sizeof payload], sentinel[sizeof payload];
        memset(hidden, 0xa5, sizeof hidden); memcpy(sentinel, hidden, sizeof sentinel);
        size_t got = 123u;
        assert(!qihse_blob_get_user(blob, hash, 0u, hidden, sizeof hidden, &got, user) &&
            !memcmp(hidden, sentinel, sizeof hidden));
        return;
    }
    assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 1u &&
        info.size == sizeof(payload) - 1u && qihse_blob_verify_user(blob, hash, user));
    uint8_t actual[sizeof payload]; size_t got = 0;
    assert(qihse_blob_get_user(blob, hash, 0u, actual, sizeof actual, &got, user) &&
        got == sizeof(payload) - 1u && !memcmp(actual, payload, got));
}
static bool receipt_row(const qihse_col_value_t* row, size_t count, void* opaque) {
    unsigned* rows = opaque;
    assert(count == 2u && !row[0].is_null && row[0].type == QIHSE_TS_INT32 && row[0].v.i32 == 1 &&
        !row[1].is_null && row[1].type == QIHSE_TS_STRING && !strcmp(row[1].v.str, "pending"));
    ++*rows; return true;
}
static void receipt_rows(qihse_user_t* user) {
    qihse_table_t* table = qihse_table_store_find_table(qihse_uwp_sql_table_store(), "artifacts");
    unsigned rows = 0;
    size_t expected = receipt_commit_decision ? 1u : 0u;
    assert(table && qihse_table_row_count(table) == expected &&
        qihse_table_scan_user(table, user, receipt_row, &rows) && rows == expected);
}
static void receipt_refused(qihse_uwp_context_t* ctx, qihse_user_t* user,
    const char* root, uint64_t id, bool sql_pending) {
    qihse_txn_backup_checkpoint_t out = {123u, 123u, 123u};
    assert(!qihse_txn_is_committed(ctx->txn_manager, id) && !qihse_txn_is_aborted(ctx->txn_manager, id) &&
        !qihse_txn_backup_checkpoint_user(ctx->txn_manager, user, &out) &&
        out.epoch == 123u && out.next_txn_id == 123u && out.journal_bytes == 123u);
    if (sql_pending) {
        char path[RECEIPT_PATH_CAP]; uint64_t epoch = 123u;
        receipt_path(path, sizeof path, root, "refused-sql-backup");
        assert(!qihse_table_store_snapshot_epoch_user(qihse_uwp_sql_table_store(), user, &epoch) && epoch == 123u &&
            !qihse_table_store_backup(qihse_uwp_sql_table_store(), user, path));
        struct stat st; assert(lstat(path, &st) == -1 && errno == ENOENT);
    }
}
static __attribute__((noinline)) int receipt_process(const char* mode, const char* root, int witness_fd) {
    alarm(120u); receipt_case = true;
    receipt_commit_decision = strstr(mode, "--receipt-abort-") == NULL;
    char native[RECEIPT_PATH_CAP]; receipt_path(native, sizeof native, root, "native");
    static char journal[RECEIPT_PATH_CAP], sql_file[RECEIPT_PATH_CAP], blob_dir[RECEIPT_PATH_CAP];
    receipt_path(journal, sizeof journal, native, "coordinator.journal"); journal_path = journal;
    receipt_path(sql_file, sizeof sql_file, native, "sql"); sql_path = sql_file;
    receipt_path(blob_dir, sizeof blob_dir, native, "blob"); blob_path = blob_dir;
    /* Fresh synthetic auth per exec, separate from the receipt parent. */
    char auth[RECEIPT_PATH_CAP]; receipt_path(auth, sizeof auth, root, "auth-XXXXXX");
    assert(mkdtemp(auth) && setenv("QIHSE_DATA_DIR", auth, 1) == 0 &&
        setenv("QIHSE_LOG_DIR", auth, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0 && qihse_auth_init() &&
        qihse_auth_bootstrap_operator("SqlBlob2pcPass1!"));
    qihse_user_t* user = qihse_auth_authenticate_id(0u, "SqlBlob2pcPass1!"); assert(user);
    uint8_t hash[48]; receipt_digest(payload, sizeof(payload) - 1u, hash);
    qihse_uwp_context_t ctx; qihse_blob_store_t* blob;
    if (!strcmp(mode, "--receipt-crash") || !strcmp(mode, "--receipt-abort-crash")) {
        memset(&ctx, 0, sizeof ctx); ctx.sql_engine = &sql_engine_placeholder;
        ctx.schema = qihse_schema_registry_create();
        ctx.txn_manager = qihse_txn_manager_create_durable(journal_path);
        assert(ctx.schema && ctx.txn_manager && qihse_uwp_sql_open_durable(&ctx, sql_path) == 0);
        blob = qihse_blob_store_create(blob_path); assert(blob);
        assert(sql(&ctx, user, "CREATE TABLE artifacts (id INT, note TEXT)", NULL) == UWP_STS_OK);
        close_context(&ctx, blob); open_context(&ctx, user, &blob);
        uint8_t before[4096], after[4096];
        size_t prior = receipt_read(sql_path, before, sizeof before);
        receipt_save(root, "sql-baseline", before, prior);
        qihse_txn_t* txn; stage_transaction(&ctx, user, blob, hash, &txn, false);
        assert(txn->id && txn->id < UINT64_MAX && txn->state == QIHSE_TXN_PREPARED);
        char* absolute = realpath(sql_path, NULL); assert(absolute);
        int n = snprintf(receipt_fault.destination, sizeof receipt_fault.destination,
            "%s.decision.%016llx", absolute, (unsigned long long)txn->id);
        free(absolute); assert(n > 0 && (size_t)n < sizeof receipt_fault.destination);
        struct stat parent, absent;
        assert(stat(native, &parent) == 0 && S_ISDIR(parent.st_mode) && parent.st_uid == geteuid() &&
            !(parent.st_mode & 077) && lstat(receipt_fault.destination, &absent) == -1 && errno == ENOENT);
        receipt_fault.parent_dev = parent.st_dev; receipt_fault.parent_ino = parent.st_ino;
        receipt_fault.armed = true; errno = 0;
        int result = receipt_commit_decision ? qihse_txn_commit_prepared(ctx.txn_manager, txn) :
            qihse_txn_abort_prepared(ctx.txn_manager, txn);
        qihse_txn_state_t pending_state = receipt_commit_decision ? QIHSE_TXN_COMMITTING : QIHSE_TXN_ABORTING;
        assert(result == -1 && errno == EAGAIN && txn->state == pending_state && receipt_fault.fired == 1u &&
            receipt_fault.file_synced && !receipt_fault.armed &&
            receipt_blob_calls == (receipt_commit_decision ? 1u : 0u) &&
            receipt_blob_abort_calls == (receipt_commit_decision ? 0u : 1u));
        result = receipt_commit_decision ? qihse_txn_abort_prepared(ctx.txn_manager, txn) :
            qihse_txn_commit_prepared(ctx.txn_manager, txn);
        assert(result == -1 && txn->state == pending_state);
        uint64_t next = 123u;
        assert(!qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &next) && next == 123u);
        receipt_refused(&ctx, user, root, txn->id, true); receipt_rows(user);
        receipt_native_files(root, txn->id, true);
        /* Later decision callbacks run normally despite the SQL error. */
        receipt_blob_log(blob, user, hash, txn->id);
        size_t current = receipt_read(sql_path, after, sizeof after);
        if (receipt_commit_decision) assert(current != prior || memcmp(before, after, prior));
        else assert(current == prior && !memcmp(before, after, prior));
        uint8_t journal_bytes[72]; receipt_journal(txn->id, receipt_commit_decision, journal_bytes);
        uint8_t witness[9] = {receipt_commit_decision ? 'S' : 'A'};
        for (unsigned i = 0; i < 8u; ++i) witness[i + 1u] = (uint8_t)(txn->id >> (8u * i));
        receipt_io(witness_fd, witness, sizeof witness, true); assert(close(witness_fd) == 0);
        assert(kill(getpid(), SIGKILL) == 0); _exit(99);
    }
    bool pending = !strcmp(mode, "--receipt-recover") || !strcmp(mode, "--receipt-abort-recover");
    assert(pending || !strcmp(mode, "--receipt-reopen") || !strcmp(mode, "--receipt-abort-reopen"));
    char path[RECEIPT_PATH_CAP]; uint8_t witness[9], baseline[120], journal_bytes[72], digest[48];
    receipt_path(path, sizeof path, root, "witness");
    assert(receipt_read(path, witness, sizeof witness) == sizeof witness && witness[0] == (receipt_commit_decision ? 'S' : 'A'));
    uint64_t id = receipt_le64(witness + 1); assert(id && id < UINT64_MAX);
    receipt_path(path, sizeof path, root, "journal-baseline");
    assert(receipt_read(path, baseline, sizeof baseline) == sizeof baseline);
    open_context_unrecovered(&ctx, user, &blob);
    uint64_t next = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &next) && next == id + 1u);
    assert(qihse_blob_decision_next_id(blob, &next) && next == id + 1u);
    receipt_refused(&ctx, user, root, id, pending); receipt_rows(user);
    receipt_native_files(root, id, pending); receipt_blob_log(blob, user, hash, id);
    assert(!receipt_blob_calls && !receipt_blob_abort_calls);
    receipt_journal(id, receipt_commit_decision, journal_bytes);
    assert(!memcmp(journal_bytes, baseline, sizeof journal_bytes));
    /* Inspect native effects BEFORE direct replay can mask a missed callback. */
    assert(qihse_txn_manager_recover(ctx.txn_manager) == 0 &&
        receipt_blob_calls == (receipt_commit_decision ? 1u : 0u) &&
        receipt_blob_abort_calls == (receipt_commit_decision ? 0u : 1u) &&
        qihse_txn_is_committed(ctx.txn_manager, id) == receipt_commit_decision &&
        qihse_txn_is_aborted(ctx.txn_manager, id) == !receipt_commit_decision);
    receipt_rows(user); receipt_native_files(root, id, false); receipt_blob_log(blob, user, hash, id);
    uint64_t epoch_before = 0u, epoch_after = 0u;
    assert(qihse_table_store_snapshot_epoch_user(qihse_uwp_sql_table_store(), user, &epoch_before));
    for (unsigned replay = 0; replay < 2u; ++replay) {
        assert(qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), id, receipt_commit_decision) &&
            !qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), id, !receipt_commit_decision) &&
            qihse_blob_resolve_prepared(blob, id, receipt_commit_decision) &&
            !qihse_blob_resolve_prepared(blob, id, !receipt_commit_decision));
    }
    assert(qihse_table_store_snapshot_epoch_user(qihse_uwp_sql_table_store(), user, &epoch_after) &&
        epoch_before == epoch_after);
    receipt_rows(user); receipt_native_files(root, id, false); receipt_blob_log(blob, user, hash, id);
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &next) && next == id + 1u);
    assert(qihse_blob_decision_next_id(blob, &next) && next == id + 1u);
    qihse_txn_backup_checkpoint_t cp;
    assert(qihse_txn_backup_checkpoint_user(ctx.txn_manager, user, &cp) &&
        cp.next_txn_id == id + 1u && cp.journal_bytes == sizeof journal_bytes);
    receipt_path(path, sizeof path, root, pending ? "resumed-sql-backup" : "reopened-sql-backup");
    struct stat absent; assert(lstat(path, &absent) == -1 && errno == ENOENT);
    assert(qihse_table_store_backup(qihse_uwp_sql_table_store(), user, path));
    receipt_journal(id, receipt_commit_decision, journal_bytes); receipt_digest(journal_bytes, sizeof journal_bytes, digest);
    assert(!memcmp(journal_bytes, baseline, sizeof journal_bytes) && !memcmp(digest, baseline + 72u, sizeof digest));
    close_context(&ctx, blob); qihse_auth_release_principal_scoped(user); qihse_audit_shutdown();
    qihse_auth_shutdown_rate_limiter(); qihse_auth_shutdown_volume_limiter();
    return 0;
}
static pid_t receipt_exec(const char* self, const char* mode, const char* root, int read_fd, int write_fd) {
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        alarm(120u); if (read_fd >= 0) assert(close(read_fd) == 0);
        char fd[32]; int n = snprintf(fd, sizeof fd, "%d", write_fd);
        assert(n > 0 && (size_t)n < sizeof fd);
        execl(self, self, mode, root, fd, (char*)NULL); _exit(127);
    }
    return child;
}
static void receipt_wait(pid_t child, bool killed) {
    int status; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    assert(waited == child);
    if (killed) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static int receipt_suite_decision(const char* self, bool commit) {
    alarm(360u); char root[] = "build/sql-receipt-recovery-XXXXXX";
    assert(mkdtemp(root));
    fprintf(stderr, "SQL receipt recovery fixture: %s (preserved)\n", root);
    char native[RECEIPT_PATH_CAP]; receipt_path(native, sizeof native, root, "native");
    assert(mkdir(native, 0700) == 0);
    int pipefd[2]; assert(pipe(pipefd) == 0);
    pid_t child = receipt_exec(self, commit ? "--receipt-crash" : "--receipt-abort-crash",
        root, pipefd[0], pipefd[1]);
    assert(close(pipefd[1]) == 0); uint8_t witness[9], extra;
    receipt_io(pipefd[0], witness, sizeof witness, false);
    assert(read(pipefd[0], &extra, 1u) == 0 && close(pipefd[0]) == 0); receipt_wait(child, true);
    assert(witness[0] == (commit ? 'S' : 'A') && receipt_le64(witness + 1) && receipt_le64(witness + 1) < UINT64_MAX);
    receipt_save(root, "witness", witness, sizeof witness);
    char journal[RECEIPT_PATH_CAP]; uint8_t baseline[120];
    const char* previous_journal = journal_path;
    receipt_path(journal, sizeof journal, native, "coordinator.journal"); journal_path = journal;
    receipt_journal(receipt_le64(witness + 1), commit, baseline);
    receipt_digest(baseline, 72u, baseline + 72u); receipt_save(root, "journal-baseline", baseline, sizeof baseline);
    receipt_wait(receipt_exec(self, commit ? "--receipt-recover" : "--receipt-abort-recover", root, -1, -1), false);
    receipt_wait(receipt_exec(self, commit ? "--receipt-reopen" : "--receipt-abort-reopen", root, -1, -1), false);
    journal_path = previous_journal;
    alarm(0);
    printf("PASS native SQL %s receipt parent-fsync EIO, witnessed SIGKILL, common replay/reopen: %s\n",
        commit ? "COMMIT" : "ABORT", root);
    return 0;
}
static int receipt_suite(const char* self) {
    assert(receipt_suite_decision(self, true) == 0);
    assert(receipt_suite_decision(self, false) == 0);
    return 0;
}

static int original_main(void) {
    char root[] = "build/sql-blob-2pc-XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("SqlBlob2pcPass1!"));
    qihse_user_t* user = qihse_auth_get_user(0);
    assert(user);
    char path[512];
    snprintf(path, sizeof(path), "%s/sql", root); sql_path = strdup(path);
    snprintf(path, sizeof(path), "%s/blob", root); blob_path = strdup(path);
    snprintf(path, sizeof(path), "%s/coordinator.journal", root); journal_path = strdup(path);
    assert(sql_path && blob_path && journal_path);

    qihse_uwp_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.sql_engine = &sql_engine_placeholder;
    ctx.schema = qihse_schema_registry_create();
    ctx.txn_manager = qihse_txn_manager_create_durable(journal_path);
    assert(ctx.schema && ctx.txn_manager && qihse_uwp_sql_open_durable(&ctx, sql_path) == 0);
    qihse_blob_store_t* blob = qihse_blob_store_create(blob_path);
    assert(blob);
    assert(sql(&ctx, user, "CREATE TABLE artifacts (id INT, note TEXT)", NULL) == UWP_STS_OK);
    close_context(&ctx, blob);

    /* COMMIT reaches the SQL participant and durably records the common decision,
     * then the process dies before the blob participant publishes. */
    uint8_t hash[48];
    unsigned int hash_len = 0;
    assert(EVP_Digest(payload, sizeof(payload) - 1u, hash, &hash_len,
                      EVP_sha384(), NULL) == 1 && hash_len == sizeof(hash));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) crash_after_common_commit(user, hash);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 77);

    open_context(&ctx, user, &blob);
    qihse_table_t* table = qihse_table_store_find_table(qihse_uwp_sql_table_store(), "artifacts");
    assert(table && qihse_table_row_count(table) == 1);
    assert(qihse_blob_info_user(blob, hash, &(qihse_blob_info_t){0}, user));
    qihse_blob_info_t info;
    assert(qihse_blob_info_user(blob, hash, &info, user));
    assert(info.size == sizeof(payload) - 1u && info.refcount == 1 &&
           info.tenant_id == qihse_user_get_tenant_id(user) &&
           info.tag == QIHSE_BLOB_TAG_SCRIPT_SET && info.classification == 0 &&
           info.sci_compartment == 0 && qihse_blob_verify_user(blob, hash, user));
    uint8_t bytes[sizeof(payload)]; size_t got = 0;
    assert(qihse_blob_get_user(blob, hash, 0, bytes, sizeof(bytes), &got, user));
    assert(got == sizeof(payload) - 1u && !memcmp(bytes, payload, got));
    assert(qihse_blob_resolve_prepared(blob, 1, true)); /* exact replay is idempotent */
    close_context(&ctx, blob);

    /* Aborting a duplicate CAS reference leaves the already committed object
     * visible with its original refcount. */
    open_context(&ctx, user, &blob);
    qihse_txn_t* txn = NULL;
    uint8_t aborted_hash[48];
    memcpy(aborted_hash, hash, sizeof(aborted_hash));
    qihse_blob_info_t before_abort;
    assert(qihse_blob_info_user(blob, aborted_hash, &before_abort, user));
    stage_transaction(&ctx, user, blob, aborted_hash, &txn, true);
    assert(!qihse_blob_ref_user(blob, aborted_hash, user));
    assert(!qihse_blob_unref_user(blob, aborted_hash, user));
    size_t concurrent_put_offset = 0u;
    assert(!qihse_blob_put_expected_user(blob, qihse_user_get_tenant_id(user),
        QIHSE_BLOB_TAG_SCRIPT_SET, 0u, 0u, user, memory_read,
        &concurrent_put_offset, aborted_hash, sizeof(payload) - 1u));
    assert(qihse_txn_abort_prepared(ctx.txn_manager, txn) == 0);
    assert(qihse_blob_info_user(blob, aborted_hash, &info, user));
    assert(info.refcount == before_abort.refcount);
    assert(!qihse_blob_resolve_prepared(blob, txn->id, true));
    close_context(&ctx, blob);

    pid_t abort_child = fork();
    assert(abort_child >= 0);
    if (!abort_child) crash_after_prepare(user, hash);
    int abort_status = 0;
    assert(waitpid(abort_child, &abort_status, 0) == abort_child &&
           WIFEXITED(abort_status) && WEXITSTATUS(abort_status) == 78);
    open_context(&ctx, user, &blob);
    table = qihse_table_store_find_table(qihse_uwp_sql_table_store(), "artifacts");
    assert(table && qihse_table_row_count(table) == 1);
    assert(qihse_blob_info_user(blob, hash, &info, user) && info.refcount == 1);
    assert(qihse_blob_resolve_prepared(blob, 3u, false));
    assert(!qihse_blob_resolve_prepared(blob, 3u, true));
    close_context(&ctx, blob);

    test_blob_decision_high_water(root, user, hash);
    test_blob_decision_overflow(root, user, hash);
    test_blob_absent_abort(root, user, hash);
    test_blob_poisoned_abort(root, user, hash);
    puts("PASS SQL/blob common-manager 2PC crash/restart, commit/abort replay, visibility and decision ID fences");
    return 0;
}

int main(int argc, char** argv) {
    umask(0077);
    if (argc == 2 && !strcmp(argv[1], "--receipt-suite")) return receipt_suite(argv[0]);
    if (argc == 4 && (!strcmp(argv[1], "--receipt-crash") ||
        !strcmp(argv[1], "--receipt-recover") || !strcmp(argv[1], "--receipt-reopen") ||
        !strcmp(argv[1], "--receipt-abort-crash") || !strcmp(argv[1], "--receipt-abort-recover") ||
        !strcmp(argv[1], "--receipt-abort-reopen"))) {
        char* end = NULL; errno = 0;
        long fd = strtol(argv[3], &end, 10);
        assert(!errno && end && !*end && fd >= -1 && fd <= INT_MAX);
        assert((strcmp(argv[1], "--receipt-crash") && strcmp(argv[1], "--receipt-abort-crash")) || fd >= 0);
        return receipt_process(argv[1], argv[2], (int)fd);
    }
    assert(argc == 1);
    assert(receipt_suite(argv[0]) == 0); /* Before original auth/global DATA_DIR. */
    return original_main();
}
