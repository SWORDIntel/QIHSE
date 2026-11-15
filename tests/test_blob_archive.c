/* W11.6 authenticated archive and fresh-store publication regression. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_blob.h"
#include "qihse_txn.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/hmac.h>

/* Interpose only in this test process; exercise real failure boundaries in
 * the shared library without adding production hooks or weakening checks. */
static bool fail_next_fsync, fail_parent_fsync, fail_rename;
static dev_t parent_device;
static ino_t parent_inode;
static unsigned injected_failures;

int fsync(int fd) {
    struct stat st;
    if (fail_next_fsync || (fail_parent_fsync && fstat(fd, &st) == 0 &&
            st.st_dev == parent_device && st.st_ino == parent_inode)) {
        fail_next_fsync = false;
        fail_parent_fsync = false;
        injected_failures++;
        errno = EIO;
        return -1;
    }
    return (int)syscall(SYS_fsync, fd);
}

int renameat2(int oldfd, const char* oldpath, int newfd, const char* newpath, unsigned flags) {
    if (fail_rename) {
        fail_rename = false;
        injected_failures++;
        errno = ENOSYS;
        return -1;
    }
    return (int)syscall(SYS_renameat2, oldfd, oldpath, newfd, newpath, flags);
}

typedef struct {
    uint8_t* data;
    size_t length, capacity, offset, limit;
    const char* destination;
    bool race_destination, abort_at_end, overreport, fail_sync_at_end;
    void (*mutate_fn)(void* opaque);
    void* mutate_opaque;
    size_t mutate_at;
} stream_t;

static void absent(const char* path) {
    struct stat st;
    assert(lstat(path, &st) == -1 && errno == ENOENT);
}

static bool stream_write(void* opaque, const uint8_t* data, size_t length) {
    stream_t* s = opaque;
    assert(length <= QIHSE_BLOB_CHUNK_SIZE);
    if (s->limit && s->length + length > s->limit) return false;
    if (s->length + length > s->capacity) {
        s->capacity = (s->length + length) * 2u;
        s->data = realloc(s->data, s->capacity);
        assert(s->data);
    }
    memcpy(s->data + s->length, data, length);
    s->length += length;
    if (s->mutate_fn && s->length >= s->mutate_at) {
        void (*mutate_fn)(void*) = s->mutate_fn;
        s->mutate_fn = NULL;
        mutate_fn(s->mutate_opaque);
    }
    return true;
}

static int64_t stream_read(void* opaque, uint8_t* buffer, size_t capacity) {
    stream_t* s = opaque;
    if (s->destination) absent(s->destination); /* Never visible during I/O. */
    if (s->overreport) return (int64_t)capacity + 1;
    if (s->offset == s->length) {
        if (s->fail_sync_at_end) fail_next_fsync = true;
        if (s->race_destination) {
            assert(mkdir(s->destination, 0700) == 0);
            s->destination = NULL;
        }
        return s->abort_at_end ? -1 : 0;
    }
    if (s->limit && s->offset >= s->limit) return -1;
    size_t n = s->length - s->offset;
    if (n > capacity) n = capacity;
    if (n > 4093) n = 4093; /* Deliberate short reads, including content. */
    if (s->limit && n > s->limit - s->offset) n = s->limit - s->offset;
    memcpy(buffer, s->data + s->offset, n);
    s->offset += n;
    return (int64_t)n;
}

typedef struct { uint64_t at, length; } generated_t;
static int64_t generated_read(void* opaque, uint8_t* data, size_t capacity) {
    generated_t* g = opaque;
    size_t n = capacity;
    if (g->length - g->at < n) n = (size_t)(g->length - g->at);
    for (size_t i = 0; i < n; i++) data[i] = (uint8_t)((g->at + i) * 7u);
    g->at += n;
    return (int64_t)n;
}

static uint64_t decode(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}

static void sign_archive(stream_t* s, const uint8_t* key) {
    unsigned int n = 0;
    assert(HMAC(EVP_sha384(), key, QIHSE_BLOB_ARCHIVE_KEY_BYTES,
                s->data, s->length - 48, s->data + s->length - 48, &n));
    assert(n == 48);
}

static void no_stage(const char* root) {
    DIR* dir = opendir(root);
    assert(dir);
    struct dirent* e;
    while ((e = readdir(dir))) assert(strncmp(e->d_name, ".qihse-archive-", 15));
    assert(closedir(dir) == 0);
}

static qihse_blob_archive_result_t restore(stream_t* archive, const char* destination,
                                          qihse_user_t* user, const uint8_t* key) {
    archive->offset = 0;
    archive->destination = destination;
    return qihse_blob_archive_restore_user(destination, user, key,
            QIHSE_BLOB_ARCHIVE_KEY_BYTES, stream_read, archive);
}

static void reject(stream_t* archive, const char* destination, const char* root,
                    qihse_user_t* user, const uint8_t* key) {
    assert(restore(archive, destination, user, key) == QIHSE_BLOB_ARCHIVE_ERROR);
    absent(destination);
    no_stage(root);
}

static void compare_store(qihse_blob_store_t* source, qihse_blob_store_t* restored,
                           qihse_user_t* user, const uint8_t hashes[][48], size_t count) {
    uint8_t* a = malloc(8192);
    uint8_t* b = malloc(8192);
    assert(a && b);
    for (size_t i = 0; i < count; i++) {
        qihse_blob_info_t x, y;
        uint32_t xp, yp;
        assert(qihse_blob_info_user(source, hashes[i], &x, user));
        assert(qihse_blob_info_user(restored, hashes[i], &y, user));
        assert(!memcmp(x.hash, y.hash, 48) && x.size == y.size &&
            x.tenant_id == y.tenant_id && x.tag == y.tag &&
            x.classification == y.classification && x.sci_compartment == y.sci_compartment &&
            x.refcount == y.refcount);
        assert(qihse_blob_pin_count_user(source, hashes[i], user, &xp));
        assert(qihse_blob_pin_count_user(restored, hashes[i], user, &yp) && xp == yp);
        assert(qihse_blob_verify_user(restored, hashes[i], user));
        for (uint64_t at = 0; at < x.size; at += 8192) {
            size_t an, bn;
            assert(qihse_blob_get_user(source, hashes[i], at, a, 8192, &an, user));
            assert(qihse_blob_get_user(restored, hashes[i], at, b, 8192, &bn, user));
            assert(an == bn && !memcmp(a, b, an));
        }
    }
    free(a);
    free(b);
}

static void prepare_receipt(qihse_blob_store_t* store, qihse_user_t* user,
                            uint64_t txn_id, const char* text, uint8_t hash[48]) {
    unsigned int length = 0u;
    assert(EVP_Digest(text, strlen(text), hash, &length, EVP_sha384(), NULL) == 1 && length == 48u);
    stream_t content = { .data = (uint8_t*)text, .length = strlen(text) };
    assert(qihse_blob_prepare_expected_user(store, txn_id, 7u, QIHSE_BLOB_TAG_SCRIPT_SET,
        95u, 1u, user, stream_read, &content, hash, strlen(text)));
}

typedef struct {
    qihse_blob_store_t* store;
    qihse_user_t* user;
    uint8_t hash[48];
} receipt_mutation_t;

static void add_receipt_during_export(void* opaque) {
    receipt_mutation_t* mutation = opaque;
    prepare_receipt(mutation->store, mutation->user, 201u,
        "callback object", mutation->hash);
    assert(qihse_blob_resolve_prepared(mutation->store, 201u, true));
}

typedef struct {
    qihse_user_t* actor;
    uint32_t user_id;
} clearance_change_t;

static void lower_export_clearance(void* opaque) {
    clearance_change_t* change = opaque;
    assert(qihse_auth_modify_user(change->actor, change->user_id,
        NULL, NULL, -1, -1, 91, -1));
}

static void test_receipt_archive(const char* root, qihse_user_t* op,
                                 qihse_user_t* low, qihse_user_t* foreign,
                                 const uint8_t key[48]) {
    char source_path[256], destination[256], frozen_path[256], rejected[256];
    snprintf(source_path, sizeof source_path, "%s/receipt-source", root);
    snprintf(destination, sizeof destination, "%s/receipt-restored", root);
    snprintf(frozen_path, sizeof frozen_path, "%s/receipt-frozen", root);
    snprintf(rejected, sizeof rejected, "%s/receipt-rejected", root);
    qihse_blob_store_t* source = qihse_blob_store_create(source_path);
    assert(source);
    uint64_t epoch = UINT64_MAX, unchanged = UINT64_MAX;
    assert(qihse_blob_snapshot_epoch_user(source, op, &epoch) && epoch == 0u);
    assert(!qihse_blob_snapshot_epoch_user(NULL, op, &unchanged) && unchanged == UINT64_MAX);
    assert(!qihse_blob_snapshot_epoch_user(source, NULL, &unchanged) && unchanged == UINT64_MAX);
    uint8_t live[48], aborted[48], deleted[48], orphan[48];
    prepare_receipt(source, op, 41u, "receipt live", live);
    assert(!qihse_blob_snapshot_epoch_user(source, op, &unchanged) && unchanged == UINT64_MAX);
    assert(qihse_blob_resolve_prepared(source, 41u, true));
    assert(qihse_blob_ref_user(source, live, op));
    assert(qihse_blob_pin_user(source, live, op));
    assert(qihse_blob_pin_user(source, live, op));
    prepare_receipt(source, op, 73u, "receipt aborted", aborted);
    assert(qihse_blob_resolve_prepared(source, 73u, false));
    prepare_receipt(source, op, 97u, "receipt deleted", deleted);
    assert(qihse_blob_resolve_prepared(source, 97u, true));
    assert(qihse_blob_delete_user(source, deleted, op));
    stream_t archive = {0}, denied = {0};
    assert(qihse_blob_snapshot_epoch_user(source, op, &epoch) && epoch > 0u);
    uint64_t stable = epoch;
    assert(qihse_blob_archive_export_user(source, op, key, 48u, stream_write, &archive));
    assert(qihse_blob_snapshot_epoch_user(source, op, &epoch) && epoch == stable);
    assert(decode(archive.data + 8u, 4u) == 2u);
    qihse_user_t* downgraded = qihse_auth_create_tenant_user(op, 7u, 191u,
        QIHSE_ROLE_GUEST, 95u, 1u, "ArchiveDowngradePass1!", false);
    assert(downgraded);
    clearance_change_t clearance = { .actor = op, .user_id = 191u };
    stream_t revoked = { .mutate_fn = lower_export_clearance,
        .mutate_opaque = &clearance, .mutate_at = archive.length };
    assert(!qihse_blob_archive_export_user(source, downgraded, key, 48u, stream_write, &revoked));
    assert(revoked.length == archive.length && !revoked.mutate_fn);
    free(revoked.data);
    assert(restore(&archive, destination, op, key) == QIHSE_BLOB_ARCHIVE_OK);
    qihse_blob_store_t* restored = qihse_blob_store_create(destination);
    assert(restored);
    qihse_blob_info_t info;
    uint32_t pins = 0u;
    uint64_t next = 0u;
    assert(qihse_blob_decision_next_id(restored, &next) && next == 98u);
    uint64_t restored_epoch = 0u;
    assert(qihse_blob_snapshot_epoch_user(restored, op, &restored_epoch));
    assert(qihse_blob_resolve_prepared(restored, 41u, true));
    assert(!qihse_blob_resolve_prepared(restored, 41u, false));
    assert(qihse_blob_resolve_prepared(restored, 73u, false));
    assert(!qihse_blob_resolve_prepared(restored, 73u, true));
    assert(qihse_blob_resolve_prepared(restored, 97u, true));
    assert(!qihse_blob_info_user(restored, aborted, &info, op));
    assert(!qihse_blob_info_user(restored, deleted, &info, op));
    assert(qihse_blob_info_user(restored, live, &info, op) && info.refcount == 2u);
    assert(qihse_blob_pin_count_user(restored, live, op, &pins) && pins == 2u);
    assert(qihse_blob_snapshot_epoch_user(restored, op, &epoch) && epoch == restored_epoch);
    qihse_blob_store_destroy(restored);
    restored = qihse_blob_store_create(destination);
    assert(restored && qihse_blob_resolve_prepared(restored, 97u, true));
    assert(qihse_blob_decision_next_id(restored, &next) && next == 98u);
    assert(qihse_blob_info_user(restored, live, &info, op) && info.refcount == 2u);
    assert(!qihse_blob_info_user(restored, deleted, &info, op));
    char journal[256];
    snprintf(journal, sizeof journal, "%s/receipt-fresh-coordinator.log", root);
    qihse_txn_manager_t* manager = qihse_txn_manager_create_durable(journal);
    assert(manager && qihse_txn_advance_next_id(manager, next) == 0 &&
        qihse_txn_manager_recover(manager) == 0);
    qihse_txn_t* fresh = qihse_txn_begin(manager, QIHSE_ISO_REPEATABLE_READ);
    assert(fresh && fresh->id == next);
    assert(qihse_txn_rollback(manager, fresh) == 0);
    qihse_txn_manager_destroy(manager);
    uint8_t next_hash[48];
    prepare_receipt(restored, op, next, "receipt live", next_hash);
    assert(qihse_blob_resolve_prepared(restored, next, true));
    assert(qihse_blob_info_user(restored, live, &info, op) && info.refcount == 3u);
    qihse_blob_store_destroy(restored);

    /* Correct MACs must not make malformed or duplicate receipts acceptable. */
    size_t receipt = 16u + 96u + strlen("receipt live");
    assert(decode(archive.data + receipt, 8u) == 2u);
    stream_t corrupt = {0};
    assert(stream_write(&corrupt, archive.data, archive.length));
    const size_t bad_offsets[] = {receipt + 103u, receipt + 104u,
        receipt + 105u, receipt + 88u, 11u};
    const uint8_t bad_values[] = {0u, 'P', 1u, 1u, 1u};
    for (size_t i = 0u; i < sizeof bad_offsets / sizeof bad_offsets[0]; ++i) {
        memcpy(corrupt.data, archive.data, archive.length);
        corrupt.data[bad_offsets[i]] = bad_values[i];
        sign_archive(&corrupt, key);
        reject(&corrupt, rejected, root, op, key);
    }
    memcpy(corrupt.data, archive.data, archive.length);
    memcpy(corrupt.data + receipt + 112u + 96u, archive.data + receipt + 96u, 8u);
    sign_archive(&corrupt, key);
    reject(&corrupt, rejected, root, op, key);

    /* The callback creates a later receipt, but neither it nor its new live
     * object may be appended to the captured older archive. */
    receipt_mutation_t mutation = { .store = source, .user = op };
    stream_t frozen = { .mutate_fn = add_receipt_during_export, .mutate_opaque = &mutation };
    assert(qihse_blob_archive_export_user(source, op, key, 48u, stream_write, &frozen));
    assert(qihse_blob_decision_next_id(source, &next) && next == 202u);
    assert(qihse_blob_snapshot_epoch_user(source, op, &epoch) && epoch > stable);
    stable = epoch;
    assert(restore(&frozen, frozen_path, op, key) == QIHSE_BLOB_ARCHIVE_OK);
    restored = qihse_blob_store_create(frozen_path);
    assert(restored && qihse_blob_decision_next_id(restored, &next) && next == 98u);
    assert(!qihse_blob_resolve_prepared(restored, 201u, true));
    assert(!qihse_blob_info_user(restored, mutation.hash, &info, op));
    qihse_blob_store_destroy(restored);
    prepare_receipt(source, op, 211u, "unresolved receipt", orphan);
    assert(!qihse_blob_archive_export_user(source, op, key, 48u, stream_write, &denied));
    assert(denied.length == 0u && qihse_blob_resolve_prepared(source, 211u, false));
    assert(qihse_blob_snapshot_epoch_user(source, op, &epoch) && epoch > stable);

    /* Even with no live rows, classified deleted-object receipts require full
     * authorization before a single archive byte is emitted. */
    assert(qihse_blob_unpin_user(source, live, op));
    assert(qihse_blob_unpin_user(source, live, op));
    assert(qihse_blob_unref_user(source, live, op));
    assert(qihse_blob_delete_user(source, live, op));
    assert(qihse_blob_delete_user(source, mutation.hash, op));
    assert(!qihse_blob_archive_export_user(source, low, key, 48u, stream_write, &denied));
    assert(!qihse_blob_archive_export_user(source, foreign, key, 48u, stream_write, &denied));
    assert(denied.length == 0u);
    assert(!qihse_blob_snapshot_epoch_user(source, low, &unchanged) && unchanged == UINT64_MAX);
    assert(!qihse_blob_snapshot_epoch_user(source, foreign, &unchanged) && unchanged == UINT64_MAX);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) _exit(qihse_blob_snapshot_epoch_user(source, op, &unchanged) ||
        unchanged != UINT64_MAX ? 1 : 0);
    int child_status = 0;
    assert(waitpid(child, &child_status, 0) == child && WIFEXITED(child_status) &&
        WEXITSTATUS(child_status) == 0);
    stream_t receipts_only = {0};
    char only_path[256];
    snprintf(only_path, sizeof only_path, "%s/receipt-only-restored", root);
    assert(qihse_blob_archive_export_user(source, op, key, 48u, stream_write, &receipts_only));
    assert(decode(receipts_only.data + 16u, 8u) == 2u);
    assert(restore(&receipts_only, only_path, op, key) == QIHSE_BLOB_ARCHIVE_OK);
    restored = qihse_blob_store_create(only_path);
    assert(restored && qihse_blob_decision_next_id(restored, &next) && next == 212u);
    assert(qihse_blob_resolve_prepared(restored, 41u, true));
    assert(qihse_blob_resolve_prepared(restored, 211u, false));
    assert(!qihse_blob_info_user(restored, live, &info, op));
    assert(!qihse_blob_info_user(restored, mutation.hash, &info, op));
    qihse_blob_store_destroy(restored);
    qihse_blob_store_destroy(source);
    free(receipts_only.data);
    free(archive.data); free(corrupt.data); free(frozen.data); free(denied.data);
}

int main(void) {
    char root[] = "build/qihse-blob-archive-XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ArchiveOperator1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    qihse_user_t* low = qihse_auth_create_tenant_user(op, 7, 71,
        QIHSE_ROLE_GUEST, 91, 0, "ArchiveTenant7Pass1!", false);
    assert(low);
    qihse_user_t* no_sci = qihse_auth_create_tenant_user(op, 7, 72,
        QIHSE_ROLE_GUEST, 95, 0, "ArchiveNoSciPass1!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(op, 8, 73,
        QIHSE_ROLE_GUEST, 95, 0xffff, "ArchiveForeignPass1!", false);
    assert(no_sci && foreign);
    char source_path[256], destination[256], failed[256], empty_path[256];
    snprintf(source_path, sizeof(source_path), "%s/source", root);
    snprintf(destination, sizeof(destination), "%s/restored", root);
    snprintf(failed, sizeof(failed), "%s/rejected", root);
    snprintf(empty_path, sizeof(empty_path), "%s/empty", root);
    qihse_blob_store_t* source = qihse_blob_store_create(source_path);
    assert(source);
    uint8_t key[48], wrong_key[48], hashes[3][48];
    for (size_t i = 0; i < sizeof(key); i++) { key[i] = (uint8_t)i; wrong_key[i] = (uint8_t)(i + 1); }
    generated_t g = { .length = 2u * QIHSE_BLOB_CHUNK_SIZE + 17u };
    assert(qihse_blob_put_user(source, 7, QIHSE_BLOB_TAG_DUMP_ARTIFACT, 95, 1,
        op, generated_read, &g, hashes[0], NULL));
    assert(qihse_blob_put_buffer_user(source, 7, QIHSE_BLOB_TAG_SCRIPT_SET,
        91, 0, op, (const uint8_t*)"hello", 5, hashes[1]));
    assert(qihse_blob_put_buffer_user(source, 7, QIHSE_BLOB_TAG_PATTERN_BUNDLE,
        91, 0, op, NULL, 0, hashes[2]));
    assert(qihse_blob_ref_user(source, hashes[0], op));
    assert(qihse_blob_ref_user(source, hashes[0], op));
    assert(qihse_blob_pin_user(source, hashes[0], op));
    assert(qihse_blob_pin_user(source, hashes[0], op));
    assert(qihse_blob_pin_user(source, hashes[1], op));

    stream_t archive = {0}, denied = {0};
    assert(!qihse_blob_archive_export_user(source, low, key, sizeof(key), stream_write, &denied));
    assert(denied.length == 0); /* Same tenant, but above clearance: no header/payload. */
    assert(!qihse_blob_archive_export_user(source, no_sci, key, sizeof(key), stream_write, &denied));
    assert(!qihse_blob_archive_export_user(source, foreign, key, sizeof(key), stream_write, &denied));
    assert(denied.length == 0);
    assert(!qihse_blob_archive_export_user(source, NULL, key, sizeof(key), stream_write, &denied));
    assert(!qihse_blob_archive_export_user(source, op, key, 47, stream_write, &denied));
    assert(denied.length == 0);
    assert(qihse_blob_archive_export_user(source, op, key, sizeof(key), stream_write, &archive));
    assert(archive.length == 16 + 3 * 96 + (size_t)g.length + 5 + 16 + 48);
    /* Deterministic encoding and independent HMAC verification. */
    stream_t second = {0};
    assert(qihse_blob_archive_export_user(source, op, key, sizeof(key), stream_write, &second));
    assert(second.length == archive.length && !memcmp(second.data, archive.data, archive.length));
    uint8_t saved_mac[48];
    memcpy(saved_mac, second.data + second.length - 48, 48);
    sign_archive(&second, key);
    assert(!memcmp(saved_mac, second.data + second.length - 48, 48));
    assert(restore(&archive, destination, op, key) == QIHSE_BLOB_ARCHIVE_OK);
    no_stage(root);
    qihse_blob_store_t* restored = qihse_blob_store_create(destination);
    assert(restored);
    compare_store(source, restored, op, hashes, 3);
    qihse_blob_store_destroy(restored);
    restored = qihse_blob_store_create(destination);
    assert(restored);
    compare_store(source, restored, op, hashes, 3); /* Exact replay, including pins. */
    assert(qihse_blob_delete_user(restored, hashes[0], op));
    assert(qihse_blob_delete_user(restored, hashes[0], op));
    assert(!qihse_blob_delete_user(restored, hashes[0], op)); /* Pins protect the final ref. */
    assert(qihse_blob_unpin_user(restored, hashes[0], op));
    uint32_t pins;
    assert(qihse_blob_pin_count_user(restored, hashes[0], op, &pins) && pins == 1);
    assert(qihse_blob_unpin_user(restored, hashes[0], op));
    assert(qihse_blob_delete_user(restored, hashes[0], op));
    qihse_blob_store_destroy(restored);

    /* Existing directory/file/symlink and a destination created during final EOF
     * must never be replaced, including an empty competing directory. */
    archive.offset = 0;
    archive.destination = NULL;
    assert(qihse_blob_archive_restore_user(destination, op, key, sizeof(key),
        stream_read, &archive) == QIHSE_BLOB_ARCHIVE_ERROR && archive.offset == 0);
    assert(symlink("missing", failed) == 0);
    assert(qihse_blob_archive_restore_user(failed, op, key, sizeof(key),
        stream_read, &archive) == QIHSE_BLOB_ARCHIVE_ERROR && archive.offset == 0);
    assert(unlink(failed) == 0);
    FILE* existing = fopen(failed, "wb");
    assert(existing && fputs("sentinel", existing) >= 0 && fclose(existing) == 0);
    assert(qihse_blob_archive_restore_user(failed, op, key, sizeof(key),
        stream_read, &archive) == QIHSE_BLOB_ARCHIVE_ERROR && archive.offset == 0);
    struct stat st;
    assert(stat(failed, &st) == 0 && st.st_size == 8);
    assert(unlink(failed) == 0);
    archive.race_destination = true;
    assert(restore(&archive, failed, op, key) == QIHSE_BLOB_ARCHIVE_ERROR);
    assert(stat(failed, &st) == 0 && S_ISDIR(st.st_mode));
    assert(rmdir(failed) == 0);
    archive.race_destination = false;
    no_stage(root);

    reject(&archive, failed, root, op, wrong_key);
    reject(&archive, failed, root, low, key);
    reject(&archive, failed, root, no_sci, key);
    reject(&archive, failed, root, foreign, key);
    reject(&archive, failed, root, NULL, key);
    archive.limit = 123;
    reject(&archive, failed, root, op, key); /* Aborted input. */
    archive.limit = 0;
    archive.abort_at_end = true;
    reject(&archive, failed, root, op, key); /* EOF is required, not just a valid MAC. */
    archive.abort_at_end = false;
    archive.overreport = true;
    reject(&archive, failed, root, op, key);
    archive.overreport = false;
    stream_t aborted = { .limit = 130 };
    assert(!qihse_blob_archive_export_user(source, op, key, sizeof(key), stream_write, &aborted));
    reject(&aborted, failed, root, op, key); /* Partial export is never a valid archive. */
    free(aborted.data);

    /* Mutate every field category plus content/footer/MAC without resigning. */
    const size_t fields[] = {0, 11, 15, 23, 31, 32, 87, 91, 93, 95, 97, 99, 103, 107, 111, 112};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        memcpy(second.data, archive.data, archive.length);
        second.data[fields[i]] ^= 1;
        reject(&second, failed, root, op, key);
    }
    for (size_t i = archive.length - 64; i < archive.length; i += 7) {
        memcpy(second.data, archive.data, archive.length);
        second.data[i] ^= 1;
        reject(&second, failed, root, op, key);
    }
    /* Truncated header, record, content, footer, MAC; extra bytes. */
    const size_t cuts[] = {0, 15, 17, 111, 120, archive.length - 64, archive.length - 1};
    for (size_t i = 0; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
        stream_t cut = archive;
        cut.length = cuts[i];
        reject(&cut, failed, root, op, key);
    }
    memcpy(second.data, archive.data, archive.length);
    second.data[second.length++] = 0;
    reject(&second, failed, root, op, key);
    second.length--;

    /* Even a correctly keyed encoder cannot emit noncanonical/invalid records. */
    const size_t invalid[] = {11, 15, 23, 31, 99, 111};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        memcpy(second.data, archive.data, archive.length);
        second.data[invalid[i]] ^= 1;
        sign_archive(&second, key);
        reject(&second, failed, root, op, key);
    }
    memcpy(second.data, archive.data, archive.length);
    memset(second.data + 16 + 64, 0xff, 8); /* Length beyond blob size limit. */
    sign_archive(&second, key);
    reject(&second, failed, root, op, key);
    memcpy(second.data, archive.data, archive.length);
    memset(second.data + 16 + 84, 0, 4); /* Zero refcount. */
    sign_archive(&second, key);
    reject(&second, failed, root, op, key);
    memcpy(second.data, archive.data, archive.length);
    /* Find real nonempty content, rather than assuming the first object is nonempty. */
    size_t content = 16;
    while (!decode(archive.data + content + 64, 8)) content += 96;
    content += 96;
    second.data[content] ^= 1; /* Valid HMAC, invalid object digest. */
    sign_archive(&second, key);
    reject(&second, failed, root, op, key);

    size_t blocks[3], positions[3], at = 16;
    for (size_t i = 0; i < 3; i++) {
        positions[i] = at;
        blocks[i] = 96 + (size_t)decode(archive.data + at + 64, 8);
        if (i) assert(memcmp(archive.data + positions[i - 1] + 16, archive.data + at + 16, 48) < 0);
        at += blocks[i];
    }
    assert(at + 64 == archive.length);
    /* Swap complete entries, fixing ordinals and HMAC: reject ordering itself. */
    memcpy(second.data, archive.data, archive.length);
    memcpy(second.data + 16, archive.data + positions[1], blocks[1]);
    memcpy(second.data + 16 + blocks[1], archive.data + positions[0], blocks[0]);
    second.data[16 + 15] = 0;
    second.data[16 + blocks[1] + 15] = 1;
    sign_archive(&second, key);
    reject(&second, failed, root, op, key);
    /* Duplicate entry with valid ordinal/footer/MAC. */
    stream_t duplicate = {0};
    assert(stream_write(&duplicate, archive.data, 16));
    for (size_t i = 0; i < 2; i++) {
        /* stream_write has a chunk bound, so copy record and content separately. */
        size_t start = duplicate.length;
        for (size_t off = 0; off < blocks[0]; ) {
            size_t n = blocks[0] - off;
            if (n > QIHSE_BLOB_CHUNK_SIZE) n = QIHSE_BLOB_CHUNK_SIZE;
            assert(stream_write(&duplicate, archive.data + 16 + off, n));
            off += n;
        }
        duplicate.data[start + 15] = (uint8_t)i;
    }
    uint8_t footer_mac[64] = {0};
    footer_mac[15] = 2;
    assert(stream_write(&duplicate, footer_mac, sizeof(footer_mac)));
    sign_archive(&duplicate, key);
    reject(&duplicate, failed, root, op, key);
    free(duplicate.data);

    /* No-replace unsupported and a final staging fsync failure fail closed.
     * A parent fsync failure AFTER rename is reported distinctly, not rolled
     * back: a complete authenticated store is visible but durability uncertain. */
    archive.fail_sync_at_end = true;
    reject(&archive, failed, root, op, key);
    archive.fail_sync_at_end = false;
    assert(injected_failures == 1);
    fail_rename = true;
    reject(&archive, failed, root, op, key);
    assert(injected_failures == 2);
    assert(stat(root, &st) == 0);
    parent_device = st.st_dev;
    parent_inode = st.st_ino;
    fail_parent_fsync = true;
    char unsynced[256];
    snprintf(unsynced, sizeof(unsynced), "%s/published-unsynced", root);
    assert(restore(&archive, unsynced, op, key) == QIHSE_BLOB_ARCHIVE_PUBLISHED_UNSYNCED);
    assert(injected_failures == 3);
    restored = qihse_blob_store_create(unsynced);
    assert(restored);
    compare_store(source, restored, op, hashes, 3);
    qihse_blob_store_destroy(restored);
    no_stage(root);

    /* Full-width multiplicities must not produce count-sized loops/logs. */
    memcpy(second.data, archive.data, archive.length);
    memset(second.data + 16 + 84, 0xff, 8);
    sign_archive(&second, key);
    assert(restore(&second, failed, op, key) == QIHSE_BLOB_ARCHIVE_OK);
    restored = qihse_blob_store_create(failed);
    assert(restored);
    qihse_blob_info_t full;
    assert(qihse_blob_info_user(restored, second.data + 32, &full, op) && full.refcount == UINT32_MAX);
    assert(qihse_blob_pin_count_user(restored, second.data + 32, op, &pins) && pins == UINT32_MAX);
    assert(!qihse_blob_ref_user(restored, second.data + 32, op));
    assert(!qihse_blob_pin_user(restored, second.data + 32, op));
    qihse_blob_store_destroy(restored);

    /* Empty store still needs a valid key, authenticated footer and active user. */
    qihse_blob_store_t* empty = qihse_blob_store_create(empty_path);
    assert(empty);
    stream_t empty_archive = {0};
    assert(qihse_blob_archive_export_user(empty, op, key, sizeof(key), stream_write, &empty_archive));
    assert(empty_archive.length == 80);
    char empty_destination[256];
    snprintf(empty_destination, sizeof(empty_destination), "%s/empty-restored", root);
    assert(restore(&empty_archive, empty_destination, op, key) == QIHSE_BLOB_ARCHIVE_OK);
    qihse_blob_store_destroy(empty);

    test_receipt_archive(root, op, low, foreign, key);

    /* A damaged source cannot produce a successful authenticated export. */
    char hex[QIHSE_BLOB_HASH_HEX], object[512];
    qihse_blob_hash_to_hex(hashes[0], hex);
    snprintf(object, sizeof(object), "%s/objects/%.2s/%s", source_path, hex, hex + 2);
    int fd = open(object, O_WRONLY);
    uint8_t corrupt = 0xff;
    assert(fd >= 0 && pwrite(fd, &corrupt, 1, 0) == 1 && close(fd) == 0);
    stream_t damaged = {0};
    assert(!qihse_blob_archive_export_user(source, op, key, sizeof(key), stream_write, &damaged));
    char damaged_path[256];
    snprintf(damaged_path, sizeof(damaged_path), "%s/damaged-restore", root);
    reject(&damaged, damaged_path, root, op, key);
    free(damaged.data);
    qihse_blob_store_destroy(source);
    free(empty_archive.data);
    free(second.data);
    free(archive.data);
    no_stage(root);
    puts("test_blob_archive: all assertions passed");
    return 0;
}
