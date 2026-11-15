/* Focused native shared-backup regression. Keep failed fixture trees in build/. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "qihse_shared_backup.h"
#include "qihse_uwp.h"
#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_schema.h"
#include "qihse_auth.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <linux/magic.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define SQL_ID 81u
#define BLOB_ID 82u
#define PATH_CAP 1024u
#define FIXTURE_CAP (1024u * 1024u)
#define MANIFEST_CAP 65536u
#define HIGH_CLASS 7u
#define HIGH_SCI 0x0004u

static uint8_t key[QIHSE_SHARED_BACKUP_KEY_BYTES];
static uint8_t payload[196621]; /* More than one copy/hash chunk. */
static const uint8_t abort_payload[] = "must never become visible";
static const uint8_t deleted_payload[] = "committed then deliberately deleted";
static int sql_placeholder;

typedef struct {
    qihse_uwp_context_t sql;
    qihse_blob_store_t* blob;
    qihse_kv_store_t* kv;
    qihse_user_t* user;
    qihse_shared_backup_sources_t sources;
} fixture_t;

typedef struct {
    const uint8_t* bytes;
    size_t length, offset;
} memory_t;

typedef struct {
    qihse_blob_store_t* blob;
    qihse_user_t* user;
    const uint8_t* bytes;
    size_t length;
    uint8_t hash[48];
} blob_resource_t;

static void path_join(char out[PATH_CAP], const char* root, const char* leaf) {
    int n = snprintf(out, PATH_CAP, "%s/%s", root, leaf);
    assert(n > 0 && (size_t)n < PATH_CAP);
}

static void absent(const char* path) {
    struct stat st;
    assert(lstat(path, &st) == -1 && errno == ENOENT);
}

static void digest(const uint8_t* bytes, size_t length, uint8_t hash[48]) {
    unsigned n = 0;
    assert(EVP_Digest(bytes, length, hash, &n, EVP_sha384(), NULL) == 1 && n == 48u);
}

static int64_t memory_read(void* opaque, uint8_t* bytes, size_t capacity) {
    memory_t* m = opaque;
    size_t n = m->length - m->offset;
    if (n > capacity) n = capacity;
    memcpy(bytes, m->bytes + m->offset, n);
    m->offset += n;
    return (int64_t)n;
}

static int64_t file_read(void* opaque, uint8_t* bytes, size_t capacity) {
    int fd = *(int*)opaque;
    ssize_t n;
    do { n = read(fd, bytes, capacity); } while (n < 0 && errno == EINTR);
    return n;
}

static int blob_prepare(void* opaque, uint64_t id) {
    (void)opaque; (void)id;
    return 0;
}

static int blob_prepare_resource(void* opaque, uint64_t id, void* resource) {
    (void)opaque;
    blob_resource_t* r = resource;
    memory_t m = {r->bytes, r->length, 0};
    bool ok = qihse_blob_prepare_expected_user(r->blob, id, 0,
        QIHSE_BLOB_TAG_SCRIPT_SET, HIGH_CLASS, HIGH_SCI, r->user,
        memory_read, &m, r->hash, r->length);
    free(r);
    return ok ? 0 : -1;
}

static void blob_rollback_resource(void* resource) { free(resource); }
static int blob_commit(void* opaque, uint64_t id) {
    return qihse_blob_resolve_prepared(opaque, id, true) ? 0 : -1;
}
static int blob_abort(void* opaque, uint64_t id) {
    return qihse_blob_resolve_prepared(opaque, id, false) ? 0 : -1;
}

typedef struct { char bytes[1024]; size_t length; } sql_reply_t;
static ssize_t discard_reply(void* opaque, const void* bytes, size_t length) {
    sql_reply_t* reply = opaque;
    if (reply) {
        size_t n = length < sizeof(reply->bytes) - 1u - reply->length ? length :
            sizeof(reply->bytes) - 1u - reply->length;
        memcpy(reply->bytes + reply->length, bytes, n);
        reply->length += n;
        reply->bytes[reply->length] = '\0';
    }
    return (ssize_t)length;
}

static void sql(fixture_t* f, const char* statement, qihse_txn_t** txn) {
    sql_reply_t reply = {0};
    int status = uwp_dispatch_sql(&f->sql, 0x02, (const uint8_t*)statement,
        strlen(statement) + 1u, txn, f->user, -1, discard_reply, &reply);
    if (status != UWP_STS_OK) fprintf(stderr, "SQL failed: %s => %s\n", statement, reply.bytes);
    assert(status == UWP_STS_OK);
}

static void register_participants(fixture_t* f, uint8_t sql_id, uint8_t blob_id,
                                  uint64_t manifest_floor) {
    assert(qihse_uwp_sql_txn_register_durable_participant(f->sql.txn_manager, sql_id) == 0);
    qihse_txn_participant_t bp = {.engine_id = blob_id, .engine_ctx = f->blob,
        .prepare = blob_prepare, .commit = blob_commit, .abort = blob_abort};
    assert(qihse_txn_register_resource_participant(f->sql.txn_manager, bp,
                                                  blob_prepare_resource) == 0);
    uint64_t sql_floor = 0, blob_floor = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sql_floor));
    assert(qihse_blob_decision_next_id(f->blob, &blob_floor));
    if (manifest_floor < sql_floor) manifest_floor = sql_floor;
    if (manifest_floor < blob_floor) manifest_floor = blob_floor;
    assert(qihse_txn_advance_next_id(f->sql.txn_manager, manifest_floor) == 0);
    assert(qihse_txn_manager_recover(f->sql.txn_manager) == 0);
    f->sources = (qihse_shared_backup_sources_t){f->kv, qihse_uwp_sql_table_store(),
        f->blob, f->sql.txn_manager, sql_id, blob_id};
}

static void attach_blob(fixture_t* f, qihse_txn_t* txn,
                         const uint8_t* bytes, size_t length) {
    blob_resource_t* r = calloc(1, sizeof(*r));
    assert(r);
    r->blob = f->blob; r->user = f->user; r->bytes = bytes; r->length = length;
    digest(bytes, length, r->hash);
    assert(qihse_txn_attach_participant_resource(f->sql.txn_manager, txn,
        BLOB_ID, r, blob_rollback_resource) == 0);
}

static uint64_t common_decision(fixture_t* f, const char* statement,
                                const uint8_t* bytes, size_t length, bool commit) {
    qihse_txn_t* txn = NULL;
    sql(f, "BEGIN", &txn);
    assert(txn);
    uint64_t id = txn->id;
    sql(f, statement, &txn);
    assert(qihse_uwp_sql_txn_enlist_durable(f->sql.txn_manager, txn, SQL_ID) == 0);
    attach_blob(f, txn, bytes, length);
    assert(qihse_txn_prepare(f->sql.txn_manager, txn) == 0);
    assert((commit ? qihse_txn_commit_prepared(f->sql.txn_manager, txn) :
                     qihse_txn_abort_prepared(f->sql.txn_manager, txn)) == 0);
    assert(qihse_txn_release(f->sql.txn_manager, txn) == 0);
    return id;
}

static void init_auth(const char* data_dir) {
    assert(mkdir(data_dir, 0700) == 0);
    assert(unsetenv("QIHSE_OPERATOR_PASSWORD") == 0);
    assert(setenv("QIHSE_AUTH_PEPPER", "shared-backup-synthetic-local-pepper", 1) == 0);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("SharedBackupSynthetic1!"));
    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(0x31u + 7u * i);
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(i * 13u + i / 251u);
}

static void open_source(fixture_t* f, const char* root) {
    memset(f, 0, sizeof(*f));
    f->user = qihse_auth_get_user(0);
    assert(f->user);
    f->kv = qihse_kv_store_create_user(f->user);
    assert(f->kv);
    f->sql.sql_engine = &sql_placeholder;
    f->sql.schema = qihse_schema_registry_create();
    char path[PATH_CAP];
    path_join(path, root, "source.qts");
    assert(f->sql.schema && qihse_uwp_sql_open_durable(&f->sql, path) == 0);
    path_join(path, root, "source.qtj");
    f->sql.txn_manager = qihse_txn_manager_create_durable(path);
    path_join(path, root, "source-blob");
    f->blob = qihse_blob_store_create(path);
    assert(f->sql.txn_manager && f->blob);
    register_participants(f, SQL_ID, BLOB_ID, 1u);
    sql(f, "CREATE TABLE artifacts (id INT, note TEXT)", NULL);
    assert(qihse_kv_set_user(f->kv, "protected/shared-backup", "classified SCI value",
                              HIGH_CLASS, HIGH_SCI, f->user));
    assert(common_decision(f, "INSERT INTO artifacts VALUES (1, 'committed')",
                           payload, sizeof(payload), true) == 1u);
    assert(common_decision(f, "INSERT INTO artifacts VALUES (2, 'aborted')",
                           abort_payload, sizeof(abort_payload) - 1u, false) == 2u);
    qihse_txn_t* txn = qihse_txn_begin(f->sql.txn_manager, QIHSE_ISO_READ_COMMITTED);
    assert(txn && txn->id == 3u);
    attach_blob(f, txn, deleted_payload, sizeof(deleted_payload) - 1u);
    assert(qihse_txn_prepare(f->sql.txn_manager, txn) == 0);
    assert(qihse_txn_commit_prepared(f->sql.txn_manager, txn) == 0);
    assert(qihse_txn_release(f->sql.txn_manager, txn) == 0);
    uint8_t hash[48];
    digest(deleted_payload, sizeof(deleted_payload) - 1u, hash);
    assert(qihse_blob_delete_user(f->blob, hash, f->user));
    assert(!qihse_blob_info_user(f->blob, hash, &(qihse_blob_info_t){0}, f->user));
    digest(payload, sizeof(payload), hash);
    assert(qihse_blob_ref_user(f->blob, hash, f->user));
    assert(qihse_blob_ref_user(f->blob, hash, f->user));
    assert(qihse_blob_pin_user(f->blob, hash, f->user));
    assert(qihse_blob_pin_user(f->blob, hash, f->user));
    /* This ID is not in any decision journal or participant receipt. */
    txn = qihse_txn_begin(f->sql.txn_manager, QIHSE_ISO_READ_COMMITTED);
    assert(txn && txn->id == 4u);
    assert(qihse_txn_rollback(f->sql.txn_manager, txn) == 0);
    assert(qihse_txn_release(f->sql.txn_manager, txn) == 0);
}

static void close_fixture(fixture_t* f) {
    qihse_blob_store_destroy(f->blob);
    qihse_uwp_sql_close_durable(&f->sql);
    qihse_schema_registry_destroy(f->sql.schema);
    qihse_txn_manager_destroy(f->sql.txn_manager);
    qihse_kv_store_destroy(f->kv);
}

static bool check_row(const qihse_col_value_t* values, size_t n, void* opaque) {
    unsigned* count = opaque;
    assert(n == 2u && !values[0].is_null && !values[1].is_null);
    assert(values[0].type == QIHSE_TS_INT32 && values[0].v.i32 == 1);
    assert(values[1].type == QIHSE_TS_STRING && !strcmp(values[1].v.str, "committed"));
    ++*count;
    return true;
}

static size_t load_file(const char* path, uint8_t* out, size_t capacity);
static void save_file(const char* path, const void* bytes, size_t length);

static int restore_process(const char* root, const char* package, uint64_t expected_floor) {
    alarm(120u);
    char path[PATH_CAP], target[PATH_CAP];
    path_join(path, root, "fresh-data");
    init_auth(path);
    fixture_t f = {0};
    f.user = qihse_auth_get_user(0);
    assert(f.user);
    qihse_shared_backup_info_t info;
    assert(qihse_shared_backup_verify_user(package, f.user, key, sizeof(key), &info));
    assert(info.sql_engine_id == SQL_ID && info.blob_engine_id == BLOB_ID);
    assert(info.coordinator.next_txn_id == expected_floor);
    /* Native SQL restore creates an input lock sidecar. Keep that operational
     * artifact in a disposable unpack, never in the authenticated package. */
    char restore_input[PATH_CAP];
    path_join(restore_input, root, "restore-input");
    assert(qihse_shared_backup_unpack_user(package, restore_input, f.user,
        key, sizeof(key), NULL) == QIHSE_SHARED_BACKUP_OK);
    package = restore_input;
    path_join(path, package, QIHSE_SHARED_BACKUP_SQL_FILE);
    path_join(target, root, "restored.qts");
    assert(qihse_table_store_restore(f.user, path, target));
    f.sql.sql_engine = &sql_placeholder;
    assert(qihse_uwp_sql_open_durable(&f.sql, target) == 0 && f.sql.schema);
    path_join(path, package, QIHSE_SHARED_BACKUP_BLOB_FILE);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    path_join(target, root, "restored-blob");
    assert(qihse_blob_archive_restore_user(target, f.user, key, sizeof(key),
                                          file_read, &fd) == QIHSE_BLOB_ARCHIVE_OK);
    assert(close(fd) == 0);
    f.blob = qihse_blob_store_create(target);
    assert(f.blob);
    f.kv = qihse_kv_store_create_user(f.user);
    assert(f.kv);
    path_join(path, package, QIHSE_SHARED_BACKUP_KV_FILE);
    assert(qihse_restore_user(f.kv, f.user, path) == QIHSE_BACKUP_EXPORT_OK);
    path_join(path, package, QIHSE_SHARED_BACKUP_JOURNAL_FILE);
    uint8_t* journal = malloc(FIXTURE_CAP);
    assert(journal);
    size_t journal_length = load_file(path, journal, FIXTURE_CAP);
    assert(journal_length == info.coordinator.journal_bytes);
    path_join(target, root, "restored-coordinator.qtj");
    save_file(target, journal, journal_length);
    free(journal);
    f.sql.txn_manager = qihse_txn_manager_create_durable(target);
    assert(f.sql.txn_manager);
    register_participants(&f, info.sql_engine_id, info.blob_engine_id,
                           info.coordinator.next_txn_id);
    assert(qihse_txn_manager_recover(f.sql.txn_manager) == 0);
    uint8_t* bytes = malloc(sizeof(payload));
    assert(bytes);
    for (unsigned pass = 0; pass < 2; ++pass) {
        assert(qihse_txn_manager_recover(f.sql.txn_manager) == 0);
        if (expected_floor == 6u) {
            assert(qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), 5u, false));
            assert(!qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), 5u, true));
            assert(qihse_blob_resolve_prepared(f.blob, 5u, false));
            assert(!qihse_blob_resolve_prepared(f.blob, 5u, true));
            uint64_t blob_floor = 0;
            assert(qihse_blob_decision_next_id(f.blob, &blob_floor) && blob_floor == 4u);
        }
        assert(qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), 1u, true));
        assert(qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), 2u, false));
        assert(qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), 3u, true));
        assert(qihse_blob_resolve_prepared(f.blob, 1u, true));
        assert(qihse_blob_resolve_prepared(f.blob, 2u, false));
        assert(qihse_blob_resolve_prepared(f.blob, 3u, true));
        unsigned rows = 0;
        qihse_table_t* table = qihse_table_store_find_table(qihse_uwp_sql_table_store(), "artifacts");
        assert(table && qihse_table_row_count(table) == 1u);
        assert(qihse_table_scan_user(table, f.user, check_row, &rows) && rows == 1u);
        char* value = qihse_kv_get_user(f.kv, "protected/shared-backup", f.user);
        assert(value && !strcmp(value, "classified SCI value"));
        free(value);
        uint8_t hash[48];
        digest(payload, sizeof(payload), hash);
        qihse_blob_info_t bi;
        assert(qihse_blob_info_user(f.blob, hash, &bi, f.user));
        assert(bi.size == sizeof(payload) && bi.refcount == 3u && bi.tenant_id == 0u &&
               bi.tag == QIHSE_BLOB_TAG_SCRIPT_SET && bi.classification == HIGH_CLASS &&
               bi.sci_compartment == HIGH_SCI);
        uint32_t pins = 0;
        assert(qihse_blob_pin_count_user(f.blob, hash, f.user, &pins) && pins == 2u);
        size_t got = 0;
        assert(qihse_blob_get_user(f.blob, hash, 0, bytes, sizeof(payload), &got, f.user));
        assert(got == sizeof(payload) && !memcmp(bytes, payload, got));
        digest(abort_payload, sizeof(abort_payload) - 1u, hash);
        assert(!qihse_blob_info_user(f.blob, hash, &bi, f.user));
        digest(deleted_payload, sizeof(deleted_payload) - 1u, hash);
        assert(!qihse_blob_info_user(f.blob, hash, &bi, f.user));
    }
    free(bytes);
    qihse_user_t* low = qihse_auth_create_user(f.user, 104, QIHSE_ROLE_ANALYST,
        0, 0, "FreshSyntheticLow1!", false);
    qihse_user_t* no_sci = qihse_auth_create_user(f.user, 105, QIHSE_ROLE_ANALYST,
        HIGH_CLASS, 0, "FreshSyntheticNoSci1!", false);
    assert(low && no_sci);
    assert(!qihse_kv_get_user(f.kv, "protected/shared-backup", low));
    assert(!qihse_kv_get_user(f.kv, "protected/shared-backup", no_sci));
    uint64_t floor = info.coordinator.next_txn_id, participant_floor = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &participant_floor));
    if (floor < participant_floor) floor = participant_floor;
    assert(qihse_blob_decision_next_id(f.blob, &participant_floor));
    if (floor < participant_floor) floor = participant_floor;
    qihse_txn_t* txn = qihse_txn_begin(f.sql.txn_manager, QIHSE_ISO_READ_COMMITTED);
    assert(txn && txn->id == floor && txn->id > 4u);
    sql(&f, "INSERT INTO artifacts VALUES (5, 'after restore commit')", &txn);
    assert(qihse_uwp_sql_txn_enlist_durable(f.sql.txn_manager, txn, info.sql_engine_id) == 0);
    attach_blob(&f, txn, payload, sizeof(payload));
    assert(qihse_txn_prepare(f.sql.txn_manager, txn) == 0);
    assert(qihse_txn_commit_prepared(f.sql.txn_manager, txn) == 0);
    assert(qihse_txn_release(f.sql.txn_manager, txn) == 0);
    qihse_table_t* table = qihse_table_store_find_table(qihse_uwp_sql_table_store(), "artifacts");
    assert(table && qihse_table_row_count(table) == 2u);
    uint8_t live_hash[48]; digest(payload, sizeof(payload), live_hash);
    qihse_blob_info_t live_info;
    assert(qihse_blob_info_user(f.blob, live_hash, &live_info, f.user) && live_info.refcount == 4u);
    uint32_t live_pins = 0u;
    assert(qihse_blob_pin_count_user(f.blob, live_hash, f.user, &live_pins) && live_pins == 2u);
    close_fixture(&f);
    puts("PASS shared backup fresh-exec native restore and exact terminal replay");
    return 0;
}

/* These wrappers affect only this executable. Candidate inode/name guards keep
 * injected failures away from native source journals, snapshots and receipts. */
typedef enum {
    HOOK_NONE, FAIL_WRITE, FAIL_NO_SPACE, FAIL_FILE_SYNC, FAIL_RENAME, FAIL_PARENT_SYNC,
    KILL_BEFORE_RENAME, KILL_AFTER_RENAME, OBSERVE_CAPACITY,
    MUTATE_KV, MUTATE_SQL, MUTATE_BLOB, MUTATE_COORD, SQL_ABA, COMMON_COMMIT,
    MUTATE_PRINCIPAL, MUTATE_PRINCIPAL_SYNC, MUTATE_UNPACK
} hook_t;
static hook_t hook;
static fixture_t* hook_fixture;
static dev_t candidate_dev, parent_dev;
static ino_t candidate_ino, parent_ino;
static bool candidate_known, published, no_space_partial;
static int interruption_fd = -1;
static unsigned hook_hits;
static size_t first_write_size;
static char final_name[PATH_CAP], unpack_source[PATH_CAP];

static void mutate_source(hook_t action);

static int capacity_evidence = -1;
static dev_t capacity_dev;
static size_t capacity_written, capacity_short_writes;
static unsigned capacity_errors;
static struct stat capacity_partial;
static struct statvfs capacity_exhausted;

/* Read the actual still-open partial member before unpack removes its stage.
 * The evidence FD was opened on the backing filesystem, not the full tmpfs. */
static void capacity_capture(int fd) {
    assert(capacity_evidence >= 0 && capacity_errors == 1u);
    assert(fstat(fd, &capacity_partial) == 0 && S_ISREG(capacity_partial.st_mode) &&
           capacity_partial.st_dev == capacity_dev && capacity_partial.st_nlink == 1 &&
           (capacity_partial.st_mode & 0777) == 0600 && capacity_partial.st_size > 0 &&
           (uint64_t)capacity_partial.st_size == capacity_written &&
           capacity_written < sizeof(payload));
    assert(fstatvfs(fd, &capacity_exhausted) == 0 && capacity_exhausted.f_bavail == 0 &&
           capacity_exhausted.f_favail > 0);
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    assert(n > 0 && (size_t)n < sizeof(path));
    int input = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    assert(input >= 0 && fstat(input, &st) == 0 && st.st_dev == capacity_partial.st_dev &&
           st.st_ino == capacity_partial.st_ino);
    uint8_t bytes[4096];
    size_t at = 0;
    while (at < capacity_written) {
        ssize_t got = read(input, bytes, sizeof(bytes));
        assert(got > 0 && (size_t)got <= capacity_written - at);
        size_t copied = 0;
        while (copied < (size_t)got) {
            ssize_t put = (ssize_t)syscall(SYS_write, capacity_evidence,
                bytes + copied, (size_t)got - copied);
            assert(put > 0); copied += (size_t)put;
        }
        at += (size_t)got;
    }
    assert(close(input) == 0 && fsync(capacity_evidence) == 0);
}

int openat(int dirfd, const char* path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int fd = (int)syscall(SYS_openat, dirfd, path, flags, mode);
    if (fd >= 0 && hook != HOOK_NONE && (flags & O_ACCMODE) != O_RDONLY &&
        !strcmp(path, QIHSE_SHARED_BACKUP_BLOB_FILE)) {
        struct stat st;
        assert(fstat(fd, &st) == 0);
        candidate_dev = st.st_dev; candidate_ino = st.st_ino; candidate_known = true;
    }
    return fd;
}

static bool is_candidate(int fd) {
    struct stat st;
    return candidate_known && fstat(fd, &st) == 0 &&
        st.st_dev == candidate_dev && st.st_ino == candidate_ino;
}

ssize_t write(int fd, const void* bytes, size_t length) {
    bool candidate = hook != HOOK_NONE && is_candidate(fd);
    if (candidate && hook == FAIL_NO_SPACE) {
        if (!no_space_partial && length > 1u) {
            ssize_t partial = (ssize_t)syscall(SYS_write, fd, bytes, length / 2u);
            if (partial > 0) no_space_partial = true;
            return partial;
        }
        hook = HOOK_NONE; ++hook_hits; errno = ENOSPC; return -1;
    }
    if (candidate && hook == FAIL_WRITE) {
        hook = HOOK_NONE; ++hook_hits; errno = EIO; return -1;
    }
    ssize_t n = (ssize_t)syscall(SYS_write, fd, bytes, length);
    int saved_errno = errno;
    if (candidate && hook == OBSERVE_CAPACITY) {
        if (n > 0) {
            capacity_written += (size_t)n;
            if ((size_t)n < length) ++capacity_short_writes;
        } else if (n < 0 && saved_errno == ENOSPC) {
            ++capacity_errors;
            capacity_capture(fd);
        }
        errno = saved_errno;
        return n; /* Observation only: preserve the kernel result exactly. */
    }
    if (candidate && n > 0 && hook >= MUTATE_KV && hook != MUTATE_PRINCIPAL_SYNC) {
        hook_t action = hook;
        hook = HOOK_NONE; ++hook_hits; first_write_size = (size_t)n;
        mutate_source(action);
    }
    return n;
}

int fsync(int fd) {
    struct stat st, manifest;
    if (hook == MUTATE_PRINCIPAL_SYNC && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
        fstatat(fd, QIHSE_SHARED_BACKUP_MANIFEST_FILE, &manifest, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(manifest.st_mode)) {
        hook = HOOK_NONE; ++hook_hits;
        mutate_source(MUTATE_PRINCIPAL_SYNC);
    }
    bool fail = (hook == FAIL_FILE_SYNC && is_candidate(fd)) ||
        (hook == FAIL_PARENT_SYNC && published && fstat(fd, &st) == 0 &&
         st.st_dev == parent_dev && st.st_ino == parent_ino);
    if (fail) { hook = HOOK_NONE; ++hook_hits; errno = EIO; return -1; }
    return (int)syscall(SYS_fsync, fd);
}

static void interrupt_at_rename(char boundary) {
    assert(interruption_fd >= 0);
    assert(syscall(SYS_write, interruption_fd, &boundary, 1u) == 1);
    kill(getpid(), SIGKILL);
    _exit(126);
}

int renameat2(int oldfd, const char* oldpath, int newfd, const char* newpath,
              unsigned flags) {
    const char* base = strrchr(newpath, '/');
    struct stat parent;
    bool final = hook != HOOK_NONE && !strcmp(base ? base + 1 : newpath, final_name) &&
        fstat(newfd, &parent) == 0 && parent.st_dev == parent_dev && parent.st_ino == parent_ino;
    if (final && hook == FAIL_RENAME) {
        hook = HOOK_NONE; ++hook_hits; errno = ENOSYS; return -1;
    }
    if (final && hook == KILL_BEFORE_RENAME) interrupt_at_rename('B');
    int rc = (int)syscall(SYS_renameat2, oldfd, oldpath, newfd, newpath, flags);
    if (final && rc == 0) {
        published = true;
        if (hook == KILL_AFTER_RENAME) interrupt_at_rename('A');
    }
    return rc;
}

static void arm(hook_t action, fixture_t* f, const char* root, const char* destination) {
    assert(hook == HOOK_NONE);
    hook = action; hook_fixture = f; hook_hits = 0; candidate_known = false;
    published = false; no_space_partial = false; first_write_size = 0;
    struct stat st;
    assert(stat(root, &st) == 0);
    parent_dev = st.st_dev; parent_ino = st.st_ino;
    const char* base = strrchr(destination, '/');
    int n = snprintf(final_name, sizeof(final_name), "%s", base ? base + 1 : destination);
    assert(n > 0 && (size_t)n < sizeof(final_name));
}

static void flip_last_byte(const char* path, size_t already_written) {
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && st.st_size > (off_t)already_written);
    uint8_t byte;
    assert(pread(fd, &byte, 1, st.st_size - 1) == 1);
    byte ^= 0x80u;
    assert(pwrite(fd, &byte, 1, st.st_size - 1) == 1);
    assert(close(fd) == 0);
}

static void mutate_source(hook_t action) {
    fixture_t* f = hook_fixture;
    uint8_t hash[48];
    switch (action) {
    case MUTATE_KV:
        assert(qihse_kv_set_user(f->kv, "protected/mutated", "retained mutation",
                                  HIGH_CLASS, HIGH_SCI, f->user));
        break;
    case MUTATE_SQL: {
        qihse_table_t* table = qihse_table_store_find_table(qihse_uwp_sql_table_store(), "artifacts");
        qihse_table_txn_t* txn = qihse_table_txn_begin_user(table, f->user);
        qihse_col_value_t values[] = {
            {.type = QIHSE_TS_INT32, .v.i32 = 10},
            {.type = QIHSE_TS_STRING, .v.str = "retained SQL mutation"}
        };
        assert(txn && qihse_table_txn_insert(txn, values, 2u) >= 0);
        assert(qihse_table_txn_commit(txn));
        break;
    }
    case MUTATE_BLOB:
        digest(payload, sizeof(payload), hash);
        assert(qihse_blob_ref_user(f->blob, hash, f->user));
        break;
    case MUTATE_COORD: {
        qihse_txn_t* txn = qihse_txn_begin(f->sql.txn_manager, QIHSE_ISO_READ_COMMITTED);
        assert(txn && qihse_txn_rollback(f->sql.txn_manager, txn) == 0);
        assert(qihse_txn_release(f->sql.txn_manager, txn) == 0);
        break;
    }
    case SQL_ABA: {
        qihse_txn_t* txn = NULL;
        sql(f, "BEGIN", &txn);
        sql(f, "INSERT INTO artifacts VALUES (11, 'ABA must not publish')", &txn);
        assert(qihse_uwp_sql_txn_enlist_durable(f->sql.txn_manager, txn, SQL_ID) == 0);
        /* Membership includes every registered engine. Give the blob participant
         * a real abortable prepare as well, not a fake vote. */
        attach_blob(f, txn, abort_payload, sizeof(abort_payload) - 1u);
        assert(qihse_txn_prepare(f->sql.txn_manager, txn) == 0);
        assert(qihse_txn_abort_prepared(f->sql.txn_manager, txn) == 0);
        assert(qihse_txn_release(f->sql.txn_manager, txn) == 0);
        break;
    }
    case COMMON_COMMIT:
        (void)common_decision(f, "INSERT INTO artifacts VALUES (12, 'retained common decision')",
                              payload, sizeof(payload), true);
        break;
    case MUTATE_PRINCIPAL:
    case MUTATE_PRINCIPAL_SYNC:
        assert(qihse_auth_modify_user(f->user, 0,
            action == MUTATE_PRINCIPAL_SYNC ? "stage-sync-generation-changed" : "shared-backup-generation",
            NULL, -1, -1, -1, -1));
        break;
    case MUTATE_UNPACK:
        flip_last_byte(unpack_source, first_write_size);
        break;
    default:
        assert(!"unexpected mutation");
    }
}

static size_t load_file(const char* path, uint8_t* out, size_t capacity) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 &&
           (uint64_t)st.st_size < capacity);
    size_t at = 0;
    while (at < (size_t)st.st_size) {
        ssize_t n = read(fd, out + at, (size_t)st.st_size - at);
        assert(n > 0); at += (size_t)n;
    }
    assert(close(fd) == 0);
    out[at] = 0;
    return at;
}

static void save_file(const char* path, const void* bytes, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    assert(fd >= 0);
    const uint8_t* p = bytes;
    while (length) {
        ssize_t n = write(fd, p, length);
        assert(n > 0); p += n; length -= (size_t)n;
    }
    assert(fsync(fd) == 0 && close(fd) == 0);
}

static void clone_package(const char* source, const char* destination) {
    assert(mkdir(destination, 0700) == 0);
    DIR* dir = opendir(source);
    assert(dir);
    uint8_t* bytes = malloc(FIXTURE_CAP);
    assert(bytes);
    unsigned count = 0;
    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        assert(++count <= 16u);
        char from[PATH_CAP], to[PATH_CAP];
        path_join(from, source, entry->d_name);
        path_join(to, destination, entry->d_name);
        save_file(to, bytes, load_file(from, bytes, FIXTURE_CAP));
    }
    free(bytes);
    assert(closedir(dir) == 0);
}

static void unchanged(const qihse_shared_backup_info_t* info) {
    const unsigned char* bytes = (const unsigned char*)info;
    for (size_t i = 0; i < sizeof(*info); ++i) assert(bytes[i] == 0xa5u);
}

static void reject_package(const char* bundle, const char* destination,
                            qihse_user_t* user, const uint8_t* signing_key) {
    qihse_shared_backup_info_t info;
    memset(&info, 0xa5, sizeof(info));
    assert(!qihse_shared_backup_verify_user(bundle, user, signing_key, sizeof(key), &info));
    unchanged(&info);
    assert(qihse_shared_backup_unpack_user(bundle, destination, user, signing_key,
        sizeof(key), &info) == QIHSE_SHARED_BACKUP_ERROR);
    unchanged(&info);
    absent(destination);
}

static void authorization_tests(fixture_t* f, const char* root, const char* bundle) {
    qihse_user_t* low = qihse_auth_create_user(f->user, 101, QIHSE_ROLE_ANALYST,
        0, 0, "SyntheticLow1!", false);
    qihse_user_t* no_sci = qihse_auth_create_user(f->user, 102, QIHSE_ROLE_ANALYST,
        HIGH_CLASS, 0, "SyntheticNoSci1!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(f->user, 99, 103,
        QIHSE_ROLE_OPERATOR, 0xffff, 0xffff, "SyntheticForeign1!", false);
    assert(low && no_sci && foreign);
    uint8_t hash[48]; digest(payload, sizeof(payload), hash);
    assert(!qihse_kv_get_user(f->kv, "protected/shared-backup", low));
    assert(!qihse_kv_get_user(f->kv, "protected/shared-backup", no_sci));
    assert(!qihse_blob_info_user(f->blob, hash, &(qihse_blob_info_t){0}, low));
    assert(!qihse_blob_info_user(f->blob, hash, &(qihse_blob_info_t){0}, no_sci));
    qihse_user_t* users[] = {NULL, low, no_sci, foreign};
    for (size_t i = 0; i < sizeof(users) / sizeof(users[0]); ++i) {
        char leaf[64], destination[PATH_CAP];
        assert(snprintf(leaf, sizeof(leaf), "denied-%zu", i) > 0);
        path_join(destination, root, leaf);
        qihse_shared_backup_info_t info;
        memset(&info, 0xa5, sizeof(info));
        assert(qihse_shared_backup_export_user(destination, &f->sources, users[i],
            key, sizeof(key), &info) == QIHSE_SHARED_BACKUP_ERROR);
        unchanged(&info); absent(destination);
        reject_package(bundle, destination, users[i], key);
    }
}

static void sign_manifest(char* text, size_t capacity) {
    char* mac = strstr(text, "MAC ");
    assert(mac && mac > text && mac[-1] == '\n');
    size_t prefix = (size_t)(mac - text);
    uint8_t signature[48]; unsigned n = 0;
    assert(HMAC(EVP_sha384(), key, sizeof(key), (const uint8_t*)text, prefix, signature, &n));
    assert(n == sizeof(signature) && prefix + 102u < capacity);
    memcpy(mac, "MAC ", 4);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(signature); ++i) {
        mac[4 + 2 * i] = hex[signature[i] >> 4];
        mac[5 + 2 * i] = hex[signature[i] & 15u];
    }
    mac[100] = '\n'; mac[101] = 0;
}

static void replace_text(char* text, size_t capacity, const char* old, const char* replacement) {
    char* p = strstr(text, old);
    assert(p);
    size_t a = strlen(old), b = strlen(replacement), tail = strlen(p + a);
    assert(strlen(text) - a + b < capacity);
    memmove(p + b, p + a, tail + 1u);
    memcpy(p, replacement, b);
}

static __attribute__((noinline)) void structural_tests(fixture_t* f, const char* root, const char* bundle) {
    uint8_t wrong_key[sizeof(key)]; memcpy(wrong_key, key, sizeof(key)); wrong_key[0] ^= 1;
    char destination[PATH_CAP]; path_join(destination, root, "wrong-key");
    reject_package(bundle, destination, f->user, wrong_key);
    const char* cases[] = {"bad-mac", "bad-member", "bad-syntax", "duplicate", "traversal",
        "extra", "missing", "symlink", "hardlink", "bad-count", "bad-size", "bad-total",
        "fifo-member", "fifo-manifest", "bad-bindings", "manifest-trailing"};
    char* manifest = malloc(MANIFEST_CAP);
    assert(manifest);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char copy[PATH_CAP], path[PATH_CAP], other[PATH_CAP], leaf[80];
        path_join(copy, root, cases[i]); clone_package(bundle, copy);
        assert(snprintf(leaf, sizeof(leaf), "reject-%s", cases[i]) > 0);
        path_join(destination, root, leaf);
        path_join(path, copy, QIHSE_SHARED_BACKUP_MANIFEST_FILE);
        load_file(path, (uint8_t*)manifest, MANIFEST_CAP);
        if (i == 0) {
            char* p = strstr(manifest, "MAC "); assert(p); p[4] = p[4] == '0' ? '1' : '0';
        } else if (i == 1) {
            path_join(other, copy, QIHSE_SHARED_BACKUP_BLOB_FILE); flip_last_byte(other, 0);
        } else if (i == 2) {
            replace_text(manifest, MANIFEST_CAP, "SQL ", "SQL  ");
        } else if (i == 3) {
            /* Duplicate an existing FILE line and authenticate coherent totals. */
            char* file = strstr(manifest, "FILE "); assert(file);
            char* end = strchr(file, '\n'); assert(end);
            char line[512]; size_t len = (size_t)(end + 1 - file);
            assert(len < sizeof(line)); memcpy(line, file, len); line[len] = 0;
            char name[128]; unsigned long long length = 0;
            assert(sscanf(line, "FILE %127s %16llx", name, &length) == 2);
            char* total = strstr(manifest, "TOTAL "); assert(total);
            unsigned count = 0; unsigned long long bytes = 0;
            assert(sscanf(total, "TOTAL %8x %16llx", &count, &bytes) == 2);
            char old[80], replacement[80];
            assert(snprintf(old, sizeof(old), "TOTAL %08x %016llx", count, bytes) > 0);
            assert(snprintf(replacement, sizeof(replacement), "TOTAL %08x %016llx",
                            count + 1u, bytes + length) > 0);
            replace_text(manifest, MANIFEST_CAP, old, replacement);
            char* mac = strstr(manifest, "MAC "); assert(mac);
            assert(strlen(manifest) + len < MANIFEST_CAP);
            memmove(mac + len, mac, strlen(mac) + 1u); memcpy(mac, line, len);
        } else if (i == 4) {
            replace_text(manifest, MANIFEST_CAP, "FILE kv.qbp ", "FILE ../kv.qbp ");
        } else if (i == 5) {
            path_join(other, copy, "unlisted"); save_file(other, "x", 1);
        } else if (i == 6) {
            char* file = strstr(manifest, "FILE kv.qbp "); assert(file);
            char* end = strchr(file, '\n'); assert(end);
            unsigned long long length = 0;
            assert(sscanf(file, "FILE kv.qbp %16llx", &length) == 1);
            memmove(file, end + 1, strlen(end + 1) + 1u);
            char* total = strstr(manifest, "TOTAL "); assert(total);
            unsigned count = 0; unsigned long long bytes = 0;
            assert(sscanf(total, "TOTAL %8x %16llx", &count, &bytes) == 2 && bytes >= length);
            char old[80], replacement[80];
            assert(snprintf(old, sizeof(old), "TOTAL %08x %016llx", count, bytes) > 0);
            assert(snprintf(replacement, sizeof(replacement), "TOTAL %08x %016llx",
                            count - 1u, bytes - length) > 0);
            replace_text(manifest, MANIFEST_CAP, old, replacement);
            path_join(other, copy, QIHSE_SHARED_BACKUP_KV_FILE); assert(unlink(other) == 0);
        } else if (i == 7) {
            path_join(other, copy, QIHSE_SHARED_BACKUP_KV_FILE); assert(unlink(other) == 0);
            assert(symlink("../not-a-member", other) == 0);
        } else if (i == 8) {
            char outside[PATH_CAP]; path_join(outside, root, "hardlink-target");
            path_join(other, copy, QIHSE_SHARED_BACKUP_KV_FILE);
            assert(link(other, outside) == 0);
        } else if (i == 9) {
            char* total = strstr(manifest, "TOTAL "); assert(total); memcpy(total + 6, "00001001", 8);
        } else if (i == 10) {
            char* file = strstr(manifest, "FILE kv.qbp "); assert(file);
            memcpy(file + strlen("FILE kv.qbp "), "ffffffffffffffff", 16);
        } else if (i == 11) {
            char* total = strstr(manifest, "TOTAL "); assert(total);
            memcpy(total + 15, "00000000c0000001", 16);
        } else if (i == 12) {
            path_join(other, copy, QIHSE_SHARED_BACKUP_BLOB_FILE);
            assert(unlink(other) == 0 && mkfifo(other, 0600) == 0);
        } else if (i == 14) {
            char* engines = strstr(manifest, "ENGINES "); assert(engines);
            memcpy(engines + 8, "01 02", 5u);
        }
        if (i != 0 && i != 1) sign_manifest(manifest, MANIFEST_CAP);
        save_file(path, manifest, strlen(manifest));
        if (i == 13) assert(unlink(path) == 0 && mkfifo(path, 0600) == 0);
        if (i == 15) {
            int fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
            assert(fd >= 0 && write(fd, "x", 1u) == 1 && close(fd) == 0);
        }
        /* A blocking-open regression must fail this test, not hang the suite. */
        if (i == 12 || i == 13) alarm(5u);
        reject_package(copy, destination, f->user, key);
        if (i == 12 || i == 13) alarm(0u);
    }
    free(manifest);
}

static void publication_tests(fixture_t* f, const char* root, const char* bundle) {
    char existing[PATH_CAP], marker[PATH_CAP];
    path_join(existing, root, "already-present"); assert(mkdir(existing, 0700) == 0);
    path_join(marker, existing, "keep"); save_file(marker, "do not replace", 14);
    qihse_shared_backup_info_t info;
    memset(&info, 0xa5, sizeof(info));
    assert(qihse_shared_backup_export_user(existing, &f->sources, f->user, key,
        sizeof(key), &info) == QIHSE_SHARED_BACKUP_ERROR); unchanged(&info);
    assert(qihse_shared_backup_unpack_user(bundle, existing, f->user, key,
        sizeof(key), &info) == QIHSE_SHARED_BACKUP_ERROR); unchanged(&info);
    uint8_t kept[64]; assert(load_file(marker, kept, sizeof(kept)) == 14u);
    assert(!memcmp(kept, "do not replace", 14));
    hook_t actions[] = {FAIL_WRITE, FAIL_NO_SPACE, FAIL_FILE_SYNC, FAIL_RENAME, FAIL_PARENT_SYNC};
    for (unsigned unpack = 0; unpack < 2u; ++unpack) {
        for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); ++i) {
            char leaf[64], destination[PATH_CAP];
            assert(snprintf(leaf, sizeof(leaf), "fault-%u-%zu", unpack, i) > 0);
            path_join(destination, root, leaf);
            arm(actions[i], f, root, destination);
            memset(&info, 0xa5, sizeof(info));
            qihse_shared_backup_result_t result = unpack ?
                qihse_shared_backup_unpack_user(bundle, destination, f->user, key, sizeof(key), &info) :
                qihse_shared_backup_export_user(destination, &f->sources, f->user, key, sizeof(key), &info);
            assert(hook_hits == 1u && hook == HOOK_NONE);
            if (actions[i] == FAIL_NO_SPACE) assert(no_space_partial);
            if (actions[i] == FAIL_PARENT_SYNC) {
                assert(result == QIHSE_SHARED_BACKUP_PUBLISHED_UNSYNCED);
                assert(info.sql_engine_id == SQL_ID && info.blob_engine_id == BLOB_ID);
                assert(qihse_shared_backup_verify_user(destination, f->user, key, sizeof(key), NULL));
            } else {
                assert(result == QIHSE_SHARED_BACKUP_ERROR); unchanged(&info); absent(destination);
            }
        }
    }
}

static int interruption_process(const char* root, const char* bundle,
    const char* boundary, const char* operation, const char* witness) {
    alarm(30u);
    char* end = NULL;
    long fd = strtol(witness, &end, 10);
    assert(*witness && end && !*end && fd >= 0 && fd <= INT_MAX);
    interruption_fd = (int)fd;
    assert(fcntl(interruption_fd, F_GETFD) >= 0);
    char path[PATH_CAP], destination[PATH_CAP];
    path_join(path, root, "source-data");
    init_auth(path);
    fixture_t f = {0};
    f.user = qihse_auth_get_user(0);
    assert(f.user);
    bool unpack = !strcmp(operation, "unpack");
    assert(unpack || !strcmp(operation, "export"));
    if (!unpack) open_source(&f, root);
    path_join(destination, root, "candidate");
    bool after = !strcmp(boundary, "after");
    assert(after || !strcmp(boundary, "before"));
    arm(after ? KILL_AFTER_RENAME : KILL_BEFORE_RENAME, &f, root, destination);
    if (unpack)
        (void)qihse_shared_backup_unpack_user(bundle, destination, f.user,
                                             key, sizeof(key), NULL);
    else
        (void)qihse_shared_backup_export_user(destination, &f.sources, f.user,
                                             key, sizeof(key), NULL);
    assert(!"publication interruption hook was not reached");
    return 1;
}

static __attribute__((noinline)) void interruption_tests(const char* executable,
    fixture_t* f, const char* root, const char* bundle) {
    for (unsigned unpack = 0; unpack < 2u; ++unpack) {
        for (unsigned after = 0; after < 2u; ++after) {
            char leaf[64], run[PATH_CAP], destination[PATH_CAP];
            assert(snprintf(leaf, sizeof(leaf), "interrupt-%u-%u", unpack, after) > 0);
            path_join(run, root, leaf);
            assert(mkdir(run, 0700) == 0);
            path_join(destination, run, "candidate");
            int witness[2];
            assert(pipe2(witness, O_CLOEXEC) == 0);
            char fd_text[32];
            assert(snprintf(fd_text, sizeof(fd_text), "%d", witness[1]) > 0);
            pid_t child = fork(); assert(child >= 0);
            if (!child) {
                close(witness[0]);
                assert(fcntl(witness[1], F_SETFD, 0) == 0);
                execl(executable, executable, "--interrupt", run, bundle,
                      after ? "after" : "before", unpack ? "unpack" : "export", fd_text, (char*)NULL);
                _exit(127);
            }
            assert(close(witness[1]) == 0);
            int status = 0;
            assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                   WTERMSIG(status) == SIGKILL);
            char boundary = 0;
            assert(read(witness[0], &boundary, 1u) == 1 && boundary == (after ? 'A' : 'B'));
            assert(read(witness[0], &boundary, 1u) == 0 && close(witness[0]) == 0);
            assert(qihse_shared_backup_verify_user(bundle, f->user, key, sizeof(key), NULL));
            if (!after) {
                absent(destination);
                /* Preserve the killed attempt's orphan stage; a new attempt must
                 * neither reuse it nor require manual deletion to publish. */
                qihse_shared_backup_result_t retry = unpack ?
                    qihse_shared_backup_unpack_user(bundle, destination, f->user,
                        key, sizeof(key), NULL) :
                    qihse_shared_backup_export_user(destination, &f->sources, f->user,
                        key, sizeof(key), NULL);
                assert(retry == QIHSE_SHARED_BACKUP_OK);
            }
            assert(qihse_shared_backup_verify_user(destination, f->user, key, sizeof(key), NULL));
            child = fork(); assert(child >= 0);
            if (!child) {
                execl(executable, executable, "--restore", run, destination, (char*)NULL);
                _exit(127);
            }
            assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
            assert(qihse_shared_backup_verify_user(destination, f->user, key, sizeof(key), NULL));
        }
    }
    puts("PASS shared backup SIGKILL before/after export and unpack publication with fresh native restore");
}

static void mutation_tests(fixture_t* f, const char* root, const char* bundle) {
    char copy[PATH_CAP], destination[PATH_CAP];
    path_join(copy, root, "unpack-race-source"); clone_package(bundle, copy);
    path_join(destination, root, "unpack-race-destination");
    path_join(unpack_source, copy, QIHSE_SHARED_BACKUP_BLOB_FILE);
    arm(MUTATE_UNPACK, f, root, destination);
    qihse_shared_backup_info_t info;
    memset(&info, 0xa5, sizeof(info));
    assert(qihse_shared_backup_unpack_user(copy, destination, f->user, key,
        sizeof(key), &info) == QIHSE_SHARED_BACKUP_ERROR);
    assert(hook_hits == 1u && hook == HOOK_NONE); unchanged(&info); absent(destination);
    hook_t actions[] = {MUTATE_KV, MUTATE_SQL, MUTATE_BLOB, MUTATE_COORD,
                        SQL_ABA, COMMON_COMMIT, MUTATE_PRINCIPAL, MUTATE_PRINCIPAL_SYNC};
    for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); ++i) {
        char leaf[64]; assert(snprintf(leaf, sizeof(leaf), "export-mutation-%zu", i) > 0);
        path_join(destination, root, leaf);
        size_t rows_before = qihse_table_row_count(qihse_table_store_find_table(
            qihse_uwp_sql_table_store(), "artifacts"));
        uint64_t epoch_before = 0, epoch_after = 0;
        qihse_txn_backup_checkpoint_t coord_before, coord_after;
        assert(qihse_txn_backup_checkpoint_user(f->sql.txn_manager, f->user, &coord_before));
        assert(qihse_table_store_snapshot_epoch_user(qihse_uwp_sql_table_store(), f->user, &epoch_before));
        arm(actions[i], f, root, destination);
        memset(&info, 0xa5, sizeof(info));
        assert(qihse_shared_backup_export_user(destination, &f->sources, f->user,
            key, sizeof(key), &info) == QIHSE_SHARED_BACKUP_ERROR);
        assert(hook_hits == 1u && hook == HOOK_NONE); unchanged(&info); absent(destination);
        if (actions[i] == MUTATE_KV) {
            char* value = qihse_kv_get_user(f->kv, "protected/mutated", f->user);
            assert(value && !strcmp(value, "retained mutation")); free(value);
        }
        size_t rows_after = qihse_table_row_count(qihse_table_store_find_table(
            qihse_uwp_sql_table_store(), "artifacts"));
        assert(rows_after == rows_before +
            ((actions[i] == MUTATE_SQL || actions[i] == COMMON_COMMIT) ? 1u : 0u));
        if (actions[i] == MUTATE_COORD || actions[i] == SQL_ABA || actions[i] == COMMON_COMMIT) {
            assert(qihse_txn_backup_checkpoint_user(f->sql.txn_manager, f->user, &coord_after));
            assert(coord_after.next_txn_id > coord_before.next_txn_id &&
                   coord_after.epoch > coord_before.epoch);
        }
        if (actions[i] == SQL_ABA) {
            assert(qihse_table_store_snapshot_epoch_user(qihse_uwp_sql_table_store(), f->user, &epoch_after));
            assert(epoch_after > epoch_before && rows_before == rows_after);
        }
        if (actions[i] == MUTATE_BLOB || actions[i] == COMMON_COMMIT) {
            uint8_t hash[48]; digest(payload, sizeof(payload), hash);
            qihse_blob_info_t bi;
            assert(qihse_blob_info_user(f->blob, hash, &bi, f->user));
            assert(bi.refcount == (actions[i] == MUTATE_BLOB ? 4u : 5u));
        }
    }
}

static __attribute__((noinline)) int early_abort_process(const char* executable, const char* root) {
    alarm(120u);
    char path[PATH_CAP], bundle[PATH_CAP];
    path_join(path, root, "source-data");
    init_auth(path);
    fixture_t f;
    open_source(&f, root);
    qihse_txn_t* txn = NULL;
    sql(&f, "BEGIN", &txn);
    assert(txn && txn->id == 5u);
    sql(&f, "INSERT INTO artifacts VALUES (6, 'must abort before blob prepare')", &txn);
    assert(qihse_uwp_sql_txn_enlist_durable(f.sql.txn_manager, txn, SQL_ID) == 0);
    blob_resource_t* bad = calloc(1u, sizeof(*bad));
    assert(bad);
    bad->blob = f.blob; bad->user = f.user;
    bad->bytes = abort_payload; bad->length = sizeof(abort_payload) - 1u;
    digest(abort_payload, sizeof(abort_payload) - 1u, bad->hash);
    bad->hash[0] ^= 1u;
    assert(qihse_txn_attach_participant_resource(f.sql.txn_manager, txn, BLOB_ID,
        bad, blob_rollback_resource) == 0);
    assert(qihse_txn_prepare(f.sql.txn_manager, txn) != 0 && txn->state == QIHSE_TXN_ABORTED);
    assert(qihse_txn_release(f.sql.txn_manager, txn) == 0);
    uint64_t sql_floor = 0, blob_floor = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sql_floor) && sql_floor == 6u);
    assert(qihse_blob_decision_next_id(f.blob, &blob_floor) && blob_floor == 4u);
    assert(qihse_txn_manager_recover(f.sql.txn_manager) == 0);
    path_join(bundle, root, "bundle");
    qihse_shared_backup_info_t info;
    assert(qihse_shared_backup_export_user(bundle, &f.sources, f.user, key,
        sizeof(key), &info) == QIHSE_SHARED_BACKUP_OK && info.coordinator.next_txn_id == 6u);
    close_fixture(&f);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        execl(executable, executable, "--restore-early-abort", root, bundle, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(qihse_shared_backup_verify_user(bundle, qihse_auth_get_user(0), key, sizeof(key), NULL));
    puts("PASS shared backup restores common ABORT with no local blob PREPARE receipt");
    return 0;
}

static __attribute__((noinline)) void early_abort_test(const char* executable, const char* root) {
    char run[PATH_CAP];
    path_join(run, root, "early-abort");
    assert(mkdir(run, 0700) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        execl(executable, executable, "--early-abort", run, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static __attribute__((noinline)) int capacity_process(const char* executable,
    const char* root, const char* limited, bool exporting) {
    alarm(120u);
    char path[PATH_CAP], bundle[PATH_CAP], target[PATH_CAP], sentinel[PATH_CAP],
        restore[PATH_CAP];
    struct stat mount_st, backing_st, sentinel_before, sentinel_after, st;
    struct statfs fs;
    struct statvfs space;
    assert(stat(limited, &mount_st) == 0 && stat(root, &backing_st) == 0 &&
           mount_st.st_dev != backing_st.st_dev && statfs(limited, &fs) == 0 &&
           fs.f_type == TMPFS_MAGIC && statvfs(limited, &space) == 0 &&
           space.f_frsize > 0 && space.f_blocks <= (8u * 1024u * 1024u) / space.f_frsize &&
           space.f_files > 16u && space.f_files <= 128u);
    capacity_dev = mount_st.st_dev;
    path_join(path, root, "source-data");
    init_auth(path);
    fixture_t f;
    open_source(&f, root);
    path_join(bundle, root, "bundle");
    qihse_shared_backup_info_t info;
    assert(qihse_shared_backup_export_user(bundle, &f.sources, f.user, key,
        sizeof(key), &info) == QIHSE_SHARED_BACKUP_OK && info.coordinator.next_txn_id == 5u);
    qihse_shared_backup_info_t baseline = info;
    assert(qihse_shared_backup_verify_user(bundle, f.user, key, sizeof(key), NULL));
    path_join(sentinel, limited, "unrelated-sentinel");
    static const char sentinel_bytes[] = "unrelated fixture data must survive capacity failure";
    save_file(sentinel, sentinel_bytes, sizeof(sentinel_bytes));
    assert(lstat(sentinel, &sentinel_before) == 0);
    path_join(path, root, "evidence/partial-blob.qba");
    capacity_evidence = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    assert(capacity_evidence >= 0 && fstat(capacity_evidence, &st) == 0 &&
           st.st_dev == backing_st.st_dev && st.st_dev != capacity_dev);
    path_join(path, limited, "owned-filler");
    int filler = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    assert(filler >= 0);
    uint8_t* bytes = malloc(FIXTURE_CAP);
    uint8_t* canonical = malloc(FIXTURE_CAP);
    assert(bytes && canonical);
    memset(bytes, 0x69, 65536u);
    size_t filled = 0;
    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_write, filler, bytes, 65536u);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { assert(errno == ENOSPC); break; }
        assert(n > 0); filled += (size_t)n;
        assert(filled <= 8u * 1024u * 1024u);
    }
    size_t released = exporting ? 65536u : 32768u;
    assert(fstat(filler, &st) == 0 && st.st_dev == capacity_dev &&
           (uint64_t)st.st_size == filled && filled > released);
    assert(fstatvfs(filler, &space) == 0 && space.f_bavail == 0 && space.f_favail > 16u);
    assert(ftruncate(filler, st.st_size - (off_t)released) == 0 && fsync(filler) == 0);
    assert(fstatvfs(filler, &space) == 0 && space.f_bavail * space.f_frsize == released);
    path_join(target, limited, "attempt");
    arm(OBSERVE_CAPACITY, &f, limited, target);
    memset(&info, 0xa5, sizeof(info));
    qihse_shared_backup_result_t result = exporting
        ? qihse_shared_backup_export_user(target, &f.sources, f.user, key, sizeof(key), &info)
        : qihse_shared_backup_unpack_user(bundle, target, f.user, key, sizeof(key), &info);
    hook = HOOK_NONE;
    assert(close(capacity_evidence) == 0); capacity_evidence = -1;
    path_join(path, root, "evidence/capacity.txt");
    int report = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    assert(report >= 0);
    assert(dprintf(report, "operation=%s tmpfs_dev=%llu mount_inode=%llu blocks=%llu block_bytes=%llu "
        "inodes=%llu filler_bytes=%zu released_bytes=%zu result=%d\n"
        "blob_inode=%llu positive_bytes=%zu short_writes=%zu kernel_enospc=%u "
        "at_error_available_blocks=%llu at_error_available_inodes=%llu\n",
        exporting ? "export" : "unpack", (unsigned long long)capacity_dev,
        (unsigned long long)mount_st.st_ino, (unsigned long long)space.f_blocks,
        (unsigned long long)space.f_frsize, (unsigned long long)space.f_files,
        filled, released, (int)result,
        (unsigned long long)capacity_partial.st_ino, capacity_written, capacity_short_writes,
        capacity_errors, (unsigned long long)capacity_exhausted.f_bavail,
        (unsigned long long)capacity_exhausted.f_favail) > 0);
    assert(fsync(report) == 0 && close(report) == 0);
    assert(result == QIHSE_SHARED_BACKUP_ERROR && candidate_known &&
           candidate_dev == capacity_dev && capacity_errors == 1u &&
           capacity_written > 0 && capacity_short_writes > 0);
    unchanged(&info);
    absent(target);
    DIR* directory = opendir(limited);
    assert(directory);
    unsigned remaining = 0;
    struct dirent* entry;
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        assert(!strcmp(entry->d_name, "owned-filler") ||
               !strcmp(entry->d_name, "unrelated-sentinel"));
        ++remaining;
    }
    assert(remaining == 2u && closedir(directory) == 0);
    assert(lstat(sentinel, &sentinel_after) == 0 &&
           sentinel_after.st_dev == sentinel_before.st_dev &&
           sentinel_after.st_ino == sentinel_before.st_ino &&
           sentinel_after.st_mode == sentinel_before.st_mode &&
           load_file(sentinel, bytes, FIXTURE_CAP) == sizeof(sentinel_bytes) &&
           !memcmp(bytes, sentinel_bytes, sizeof(sentinel_bytes)));
    path_join(path, root, "evidence/partial-blob.qba");
    assert(load_file(path, bytes, FIXTURE_CAP) == capacity_written);
    path_join(path, bundle, QIHSE_SHARED_BACKUP_BLOB_FILE);
    size_t full_length = load_file(path, canonical, FIXTURE_CAP);
    assert(full_length > capacity_written && !memcmp(bytes, canonical, capacity_written));
    assert(qihse_shared_backup_verify_user(bundle, f.user, key, sizeof(key), NULL));
    qihse_kv_snapshot_checkpoint_t kv_checkpoint;
    qihse_txn_backup_checkpoint_t coordinator_checkpoint;
    uint64_t sql_epoch = 0, blob_epoch = 0;
    assert(qihse_kv_snapshot_checkpoint_user(f.kv, f.user, &kv_checkpoint) &&
        !memcmp(&kv_checkpoint, &baseline.kv, sizeof kv_checkpoint));
    assert(qihse_table_store_snapshot_epoch_user(f.sources.sql, f.user, &sql_epoch) &&
        sql_epoch == baseline.sql_epoch);
    assert(qihse_blob_snapshot_epoch_user(f.blob, f.user, &blob_epoch) &&
        blob_epoch == baseline.blob_epoch);
    assert(qihse_txn_backup_checkpoint_user(f.sql.txn_manager, f.user, &coordinator_checkpoint) &&
        !memcmp(&coordinator_checkpoint, &baseline.coordinator, sizeof coordinator_checkpoint));
    /* Only release this fixture's filler. Retry the same absent destination. */
    assert(ftruncate(filler, 0) == 0 && fsync(filler) == 0 && close(filler) == 0);
    result = exporting
        ? qihse_shared_backup_export_user(target, &f.sources, f.user, key, sizeof(key), &info)
        : qihse_shared_backup_unpack_user(bundle, target, f.user, key, sizeof(key), &info);
    assert(result == QIHSE_SHARED_BACKUP_OK);
    assert(info.coordinator.next_txn_id == 5u &&
           qihse_shared_backup_verify_user(target, f.user, key, sizeof(key), NULL));
    close_fixture(&f);
    path_join(restore, root, "native-restore");
    assert(mkdir(restore, 0700) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        execl(executable, executable, "--restore", restore, target, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(qihse_shared_backup_verify_user(bundle, qihse_auth_get_user(0), key, sizeof(key), NULL));
    assert(qihse_shared_backup_verify_user(target, qihse_auth_get_user(0), key, sizeof(key), NULL));
    assert(lstat(sentinel, &sentinel_after) == 0 &&
           sentinel_after.st_dev == sentinel_before.st_dev &&
           sentinel_after.st_ino == sentinel_before.st_ino &&
           sentinel_after.st_mode == sentinel_before.st_mode &&
           load_file(sentinel, bytes, FIXTURE_CAP) == sizeof(sentinel_bytes) &&
           !memcmp(bytes, sentinel_bytes, sizeof(sentinel_bytes)));
    free(canonical); free(bytes);
    printf("PASS real tmpfs %s partial-write ENOSPC, preserved evidence, unchanged sources, same-path retry and fresh native restore\n",
        exporting ? "native-export" : "unpack");
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 4 && !strcmp(argv[1], "--capacity"))
        return capacity_process(argv[0], argv[2], argv[3], false);
    if (argc == 4 && !strcmp(argv[1], "--capacity-export"))
        return capacity_process(argv[0], argv[2], argv[3], true);
    if (argc == 4 && !strcmp(argv[1], "--restore")) return restore_process(argv[2], argv[3], 5u);
    if (argc == 4 && !strcmp(argv[1], "--restore-early-abort")) return restore_process(argv[2], argv[3], 6u);
    if (argc == 3 && !strcmp(argv[1], "--early-abort")) return early_abort_process(argv[0], argv[2]);
    if (argc == 7 && !strcmp(argv[1], "--interrupt"))
        return interruption_process(argv[2], argv[3], argv[4], argv[5], argv[6]);
    assert(argc == 1);
    char root[] = "build/shared-backup-XXXXXX";
    assert(mkdtemp(root));
    fprintf(stderr, "shared backup artifacts: %s (preserved)\n", root);
    char path[PATH_CAP]; path_join(path, root, "source-data");
    init_auth(path);
    fixture_t f;
    open_source(&f, root);
    char bundle[PATH_CAP], unpacked[PATH_CAP];
    path_join(bundle, root, "bundle"); path_join(unpacked, root, "unpacked");
    qihse_shared_backup_info_t exported, verified, unpack_info;
    assert(qihse_shared_backup_export_user(bundle, &f.sources, f.user, key,
        sizeof(key), &exported) == QIHSE_SHARED_BACKUP_OK);
    assert(exported.coordinator.next_txn_id == 5u && exported.member_count >= 4u);
    assert(qihse_shared_backup_verify_user(bundle, f.user, key, sizeof(key), &verified));
    assert(verified.coordinator.next_txn_id == exported.coordinator.next_txn_id &&
           verified.member_count == exported.member_count && verified.payload_bytes == exported.payload_bytes);
    assert(qihse_shared_backup_unpack_user(bundle, unpacked, f.user, key,
        sizeof(key), &unpack_info) == QIHSE_SHARED_BACKUP_OK);
    assert(unpack_info.coordinator.next_txn_id == exported.coordinator.next_txn_id);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        execl(argv[0], argv[0], "--restore", root, unpacked, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    authorization_tests(&f, root, bundle);
    structural_tests(&f, root, bundle);
    publication_tests(&f, root, bundle);
    interruption_tests(argv[0], &f, root, bundle);
    mutation_tests(&f, root, bundle);
    close_fixture(&f);
    early_abort_test(argv[0], root);
    puts("PASS shared backup authorization, authenticated structure, publication faults and source mutation");
    return 0;
}
