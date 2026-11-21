#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_recovery_manifest.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define TRAILER (QIHSE_CT1_RECOVERY_WIRE_SIZE - 32u)
static const char* const source_b[] = {"ct-baseline.qfs", "ct-state.bin",
    "restore-highwater.bin", "slot-ownership.journal",
    "slot-ownership.journal.lock", "sstable_11321.db", "sstable_11322.db",
    "wal.log"};
static const char* const target_b[] = {"ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_6.db", "sstable_7.db", "wal.log"};

static void roster(qihse_ct1_recovery_file_t* files, const char* const* names,
    size_t count, unsigned seed) {
    for (size_t i = 0; i < count; ++i) {
        strcpy(files[i].filename, names[i]);
        const char* s = names[i];
        files[i].kind = !strcmp(s, "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(s, "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(s, "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(s, "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(s, "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(s, "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
        files[i].size = files[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ?
            0 : 100 + seed * 10 + i;
        if (files[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK)
            assert(SHA256((const unsigned char*)"", 0, files[i].sha256));
        else memset(files[i].sha256, (int)(seed + i + 1), 32);
    }
}
static qihse_ct1_recovery_manifest_t sample(bool alternative) {
    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "configured-operator");
    strcpy(m.source_qkp_id, "source");
    strcpy(m.target_qkp_id, "target");
    strcpy(m.generation, "generation-1");
    strcpy(m.source_store_id, "source-store-uuid");
    strcpy(m.target_store_id, "target-store-uuid");
    strcpy(m.replication_principal_id, "active-replication-service");
    strcpy(m.row_key, "tenant-key-11");
    strcpy(m.source_peer_qkp_id, "source-successor");
    strcpy(m.target_peer_qkp_id, "target-successor");
    unsigned char* hashes[] = {m.issuer_operator_pin, m.source_peer_pin,
        m.target_peer_pin, m.frame_sha256, m.baseline_sha256, m.nonce};
    for (size_t i = 0; i < 6; ++i) memset(hashes[i], (int)(i + 1), 32);
    roster(m.source_files, source_b, QIHSE_CT1_RECOVERY_SOURCE_FILES,
        alternative ? 20 : 1);
    roster(m.target_files, target_b, QIHSE_CT1_RECOVERY_TARGET_FILES,
        alternative ? 40 : 10);
    m.epoch = 9; m.issued_ms = 1000; m.expires_ms = 2000;
    m.frame_offset = 101; m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 11111; m.baseline_row_seq = 17;
    m.target_cursor = 11110; m.target_high_water = 5729457;
    m.source_high_water = 5729448; m.row_change_seq = 5729448;
    m.tombstone_position = 11103; m.tombstone_row_seq = 5729450;
    m.row_tenant_id = 42; m.principal_tenant_id = 42;
    m.classification = 4; m.sci = 2;
    m.principal_classification = 4; m.principal_sci = 2;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    return m;
}
static void resign(unsigned char* data) {
    assert(SHA256(data, TRAILER, data + TRAILER));
}
static void rejected(const qihse_ct1_recovery_manifest_t* m) {
    unsigned char data[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    assert(!qihse_ct1_recovery_encode(m, true, false, data));
}
static void changed(const qihse_ct1_recovery_manifest_t* original,
    const qihse_ct1_recovery_manifest_t* changed_m) {
    unsigned char data[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    qihse_ct1_recovery_manifest_t decoded;
    assert(qihse_ct1_recovery_encode(changed_m, true, false, data));
    assert(qihse_ct1_recovery_decode(data, sizeof(data), true, &decoded, NULL));
    assert(!qihse_ct1_recovery_matches(&decoded, original, 1500, false));
    assert(!qihse_ct1_recovery_issuer_authorized());
}
static void check_wire(void) {
    qihse_ct1_recovery_manifest_t m = sample(false), alt = sample(true), actual, wrong;
    unsigned char data[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    bool spent = true;
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    assert(qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    assert(!spent && actual.tombstone_row_seq == m.tombstone_row_seq &&
        qihse_ct1_recovery_matches(&actual, &m, 1000, false));
    assert(!qihse_ct1_recovery_matches(&actual, &m, 999, false));
    assert(!qihse_ct1_recovery_matches(&actual, &m, 2000, false));
    assert(!qihse_ct1_recovery_matches(&actual, &m, 1500, true));
    assert(!qihse_ct1_recovery_decode(data, sizeof(data) - 1, true, &actual, &spent));
    assert(!qihse_ct1_recovery_decode(data, sizeof(data), false, &actual, &spent));
    assert(qihse_ct1_recovery_encode(&alt, true, false, data));
    assert(qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    assert(qihse_ct1_recovery_matches(&actual, &alt, 1500, false));
    assert(!qihse_ct1_recovery_matches(&actual, &m, 1500, false));
    assert(!qihse_ct1_recovery_issuer_authorized());
    data[TRAILER] ^= 1;
    assert(!qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    data[10] = 1; resign(data);
    assert(!qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    data[TRAILER - 1] = 1; resign(data);
    assert(!qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    data[9] = 2; resign(data);
    assert(!qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    /* An old 12-value record with a fresh checksum cannot omit the sequence. */
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    size_t seq_offset = 12 + 10 * 65 + 6 * 32 + 12 * 8;
    size_t first = seq_offset + 8 + 2 * 4 + 5 * 2;
    size_t used = first + (QIHSE_CT1_RECOVERY_SOURCE_FILES +
        QIHSE_CT1_RECOVERY_TARGET_FILES) * (1 + 65 + 8 + 32);
    memmove(data + seq_offset, data + seq_offset + 8, used - seq_offset - 8);
    memset(data + used - 8, 0, 8);
    resign(data);
    assert(!qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    /* A changed nonzero sequence is structurally valid but not matching evidence. */
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    data[seq_offset + 7] ^= 1; resign(data);
    assert(qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    assert(actual.tombstone_row_seq != m.tombstone_row_seq);
    assert(!qihse_ct1_recovery_matches(&actual, &m, 1500, false));
    /* Fresh checksums can validate changed evidence, never issuer authority. */
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    data[12 + 10 * 65 + 3 * 32] ^= 1; resign(data);
    assert(qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    assert(!qihse_ct1_recovery_matches(&actual, &m, 1500, false));
    assert(!qihse_ct1_recovery_issuer_authorized());
    assert(QIHSE_CT1_RECOVERY_MAX_AGE_MS == 900000u);
    wrong = m; wrong.expires_ms = wrong.issued_ms + QIHSE_CT1_RECOVERY_MAX_AGE_MS;
    assert(qihse_ct1_recovery_encode(&wrong, true, false, data));
    assert(qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, &spent));
    assert(qihse_ct1_recovery_matches(&actual, &wrong, wrong.expires_ms - 1, false));
    assert(!qihse_ct1_recovery_matches(&actual, &wrong, wrong.expires_ms, false));
    wrong.expires_ms++;
    rejected(&wrong);
    wrong = m; wrong.expires_ms = wrong.issued_ms; rejected(&wrong);
    wrong = m; wrong.frame_offset = UINT64_MAX; rejected(&wrong);
    wrong = m; wrong.frame_length--; rejected(&wrong);
    wrong = m; wrong.frame_length++; rejected(&wrong);
    wrong = m; wrong.tombstone_row_seq = 0; rejected(&wrong);
    wrong = m; wrong.operation = 2; rejected(&wrong);
    wrong = m; memset(wrong.nonce, 0, 32); rejected(&wrong);
    wrong = m; wrong.generation[0] = '/'; rejected(&wrong);
    wrong = m; wrong.source_files[0].size = UINT64_MAX; rejected(&wrong);
    wrong = m; wrong.source_files[0].size = 0; rejected(&wrong);
    wrong = m; wrong.target_files[2].size = 0; rejected(&wrong);
    wrong = m; wrong.source_files[4].size = 1; rejected(&wrong);
    wrong = m; wrong.target_files[3].size = 1; rejected(&wrong);
    wrong = m; wrong.source_files[4].sha256[0] ^= 1; rejected(&wrong);
    wrong = m; memset(wrong.target_files[3].sha256, 0, 32); rejected(&wrong);
    wrong = m; memset(wrong.target_files[2].sha256, 0, 32); rejected(&wrong);
    wrong = m; wrong.source_files[3] = wrong.source_files[2]; rejected(&wrong);
    wrong = m; wrong.target_files[6] = wrong.target_files[5]; rejected(&wrong);
    wrong = m; wrong.source_files[7].filename[0] = 0; rejected(&wrong);
    wrong = m; strcpy(wrong.source_files[0].filename, "ct-baseline.qfs.bak"); rejected(&wrong);
    wrong = m; strcpy(wrong.source_files[3].filename, "slot-ownership.journal.bak"); rejected(&wrong);
    wrong = m; strcpy(wrong.target_files[3].filename, "slot-ownership.journal.link"); rejected(&wrong);
    wrong = m; strcpy(wrong.source_files[5].filename, "sstable_00.db"); rejected(&wrong);
    wrong = m; strcpy(wrong.target_files[4].filename, "../sstable_6.db"); rejected(&wrong);
    wrong = m; wrong.source_files[3].kind = QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK; rejected(&wrong);
    wrong = m; wrong.target_files[3].kind = QIHSE_CT1_FILE_SLOT_JOURNAL; rejected(&wrong);
    wrong = m; wrong.target_files[0].kind = QIHSE_CT1_FILE_WAL; rejected(&wrong);
    wrong = m; strcpy(wrong.target_files[1].filename, "replica-cursors.bin");
    wrong.target_files[1].kind = QIHSE_CT1_FILE_REPLICA_CURSORS; rejected(&wrong);
    wrong = m; strcpy(wrong.target_files[0].filename, "ct-baseline.qfs");
    wrong.target_files[0].kind = QIHSE_CT1_FILE_BASELINE; rejected(&wrong);
    wrong = m; qihse_ct1_recovery_file_t swap = wrong.source_files[3];
    wrong.source_files[3] = wrong.source_files[4]; wrong.source_files[4] = swap;
    rejected(&wrong);
    /* Re-signed invalid on-wire filename/sidecar and duplicate slot fail parse. */
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    first = 12 + 10 * 65 + 6 * 32 + 13 * 8 + 2 * 4 + 5 * 2;
    data[first + 1] = '/'; resign(data);
    assert(!qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, NULL));
    assert(qihse_ct1_recovery_encode(&m, true, false, data));
    memcpy(data + first + 3 * (1 + 65 + 8 + 32),
        data + first + 2 * (1 + 65 + 8 + 32), 1 + 65 + 8 + 32);
    resign(data);
    assert(!qihse_ct1_recovery_decode(data, sizeof(data), true, &actual, NULL));
    /* Mutations to every individual file and all bound metadata must mismatch. */
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_SOURCE_FILES; ++i) {
        if (i != 4) {
            wrong = m; wrong.source_files[i].size++; changed(&m, &wrong);
        }
        wrong = m; wrong.source_files[i].sha256[0] ^= 1;
        if (i == 4) rejected(&wrong);
        else changed(&m, &wrong);
    }
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_TARGET_FILES; ++i) {
        if (i != 3) {
            wrong = m; wrong.target_files[i].size++; changed(&m, &wrong);
        }
        wrong = m; wrong.target_files[i].sha256[0] ^= 1;
        if (i == 3) rejected(&wrong);
        else changed(&m, &wrong);
    }
#define CHECK_CHANGE(expr) do { wrong = m; expr; changed(&m, &wrong); } while (0)
    CHECK_CHANGE(wrong.issuer_operator_pin[0] ^= 1);
    CHECK_CHANGE(wrong.source_peer_pin[0] ^= 1);
    CHECK_CHANGE(wrong.target_peer_pin[0] ^= 1);
    CHECK_CHANGE(wrong.frame_sha256[0] ^= 1);
    CHECK_CHANGE(wrong.baseline_sha256[0] ^= 1);
    CHECK_CHANGE(wrong.issuer_qkp_id[0] ^= 1);
    CHECK_CHANGE(wrong.replication_principal_id[1] ^= 1);
    CHECK_CHANGE(wrong.source_store_id[0] ^= 1);
    CHECK_CHANGE(wrong.target_store_id[0] ^= 1);
    CHECK_CHANGE(wrong.row_key[0] ^= 1);
    CHECK_CHANGE(wrong.target_cursor++);
    CHECK_CHANGE(wrong.target_high_water++);
    CHECK_CHANGE(wrong.source_high_water++);
    CHECK_CHANGE(wrong.row_change_seq++);
    CHECK_CHANGE(wrong.tombstone_position++);
    CHECK_CHANGE(wrong.tombstone_row_seq++);
    CHECK_CHANGE(wrong.frame_position++);
    CHECK_CHANGE(wrong.frame_offset++);
    CHECK_CHANGE(wrong.baseline_row_seq++);
    CHECK_CHANGE(wrong.classification++);
    CHECK_CHANGE(wrong.sci++);
    CHECK_CHANGE(wrong.principal_classification++);
    CHECK_CHANGE(wrong.principal_sci++);
    CHECK_CHANGE(wrong.row_tenant_id++);
    CHECK_CHANGE(wrong.principal_tenant_id++);
    CHECK_CHANGE(wrong.epoch++);
    CHECK_CHANGE(wrong.nonce[0] ^= 1);
#undef CHECK_CHANGE
}
static void check_receipt(const char* path, const char* torn, const char* link) {
    qihse_ct1_recovery_manifest_t m = sample(false), actual, wrong;
    bool spent = true;
    assert(qihse_ct1_recovery_create(path, &m, true));
    assert(!qihse_ct1_recovery_create(path, &m, true));
    assert(symlink("receipt", link) == 0);
    assert(!qihse_ct1_recovery_create(link, &m, true));
    assert(!qihse_ct1_recovery_load(link, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(link, &m, 1500));
    assert(unlink(link) == 0);
    assert(qihse_ct1_recovery_load(path, true, &actual, &spent) && !spent);
    char other[256];
    assert(snprintf(other, sizeof(other), "%s-hard", path) > 0);
    assert(linkat(AT_FDCWD, path, AT_FDCWD, other, 0) == 0);
    assert(!qihse_ct1_recovery_load(path, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(path, &m, 1500));
    assert(unlink(other) == 0);
    assert(chmod(path, 0644) == 0);
    assert(!qihse_ct1_recovery_load(path, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(path, &m, 1500));
    assert(chmod(path, 0600) == 0);
    wrong = m; wrong.target_files[4].sha256[0] ^= 1;
    assert(!qihse_ct1_recovery_spend(path, &wrong, 1500));
    assert(!qihse_ct1_recovery_spend(path, &m, 2000));
    assert(qihse_ct1_recovery_spend(path, &m, 1500));
    assert(qihse_ct1_recovery_load(path, true, &actual, &spent) && spent);
    assert(!qihse_ct1_recovery_spend(path, &m, 1500));
    assert(!qihse_ct1_recovery_matches(&actual, &m, 1500, spent));
    /* Simulated crash/torn rewrite: exact size and checksum both fail closed. */
    assert(qihse_ct1_recovery_create(torn, &m, true));
    int fd = open(torn, O_WRONLY);
    assert(fd >= 0);
    unsigned char damaged = 0xff;
    assert(pwrite(fd, &damaged, 1, 900) == 1 && fsync(fd) == 0);
    assert(!qihse_ct1_recovery_load(torn, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(torn, &m, 1500));
    assert(ftruncate(fd, QIHSE_CT1_RECOVERY_WIRE_SIZE - 1) == 0);
    assert(fsync(fd) == 0 && close(fd) == 0);
    assert(!qihse_ct1_recovery_load(torn, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(torn, &m, 1500));
}
static void check_receipt_negatives(const char* dir) {
    qihse_ct1_recovery_manifest_t m = sample(false), actual;
    char receipt[256], fifo[256], ancestor[256], via[256], crash[256],
        concurrent[256], lockpath[266];
    bool spent;
    snprintf(receipt, sizeof(receipt), "%s/normal", dir);
    snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
    snprintf(ancestor, sizeof(ancestor), "%s/ancestor", dir);
    snprintf(via, sizeof(via), "%s/ancestor/normal", dir);
    snprintf(crash, sizeof(crash), "%s/crash", dir);
    snprintf(concurrent, sizeof(concurrent), "%s/concurrent", dir);
    assert(qihse_ct1_recovery_create(receipt, &m, true));
    assert(symlink(".", ancestor) == 0);
    assert(!qihse_ct1_recovery_create(via, &m, true));
    assert(!qihse_ct1_recovery_load(via, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(via, &m, 1500));
    assert(unlink(ancestor) == 0);
    assert(chmod(dir, 0770) == 0);
    assert(!qihse_ct1_recovery_load(receipt, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(receipt, &m, 1500));
    assert(chmod(dir, 0700) == 0);
    assert(unlink(receipt) == 0 && mkfifo(receipt, 0600) == 0);
    alarm(3);
    assert(!qihse_ct1_recovery_load(receipt, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(receipt, &m, 1500));
    alarm(0);
    assert(unlink(receipt) == 0);
    assert(mkfifo(fifo, 0600) == 0);
    assert(!qihse_ct1_recovery_create(fifo, &m, true));
    assert(unlink(fifo) == 0);
    assert(qihse_ct1_recovery_create(crash, &m, true));
    snprintf(lockpath, sizeof(lockpath), "%s.lock", crash);
    int fd = open(lockpath, O_RDWR);
    assert(fd >= 0);
    /* Crash after durable spend intent but before rename: unspent is denied. */
    assert(pwrite(fd, "1", 1, 0) == 1 && fsync(fd) == 0);
    char pending[266];
    snprintf(pending, sizeof(pending), "%s/.crash.pending", dir);
    int torn_fd = open(pending, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(torn_fd >= 0 && write(torn_fd, "torn", 4) == 4);
    assert(fsync(torn_fd) == 0 && close(torn_fd) == 0);
    assert(!qihse_ct1_recovery_load(crash, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(crash, &m, 1500));
    assert(pwrite(fd, "X", 1, 0) == 1 && fsync(fd) == 0 && close(fd) == 0);
    assert(!qihse_ct1_recovery_load(crash, true, &actual, &spent));
    assert(!qihse_ct1_recovery_spend(crash, &m, 1500));
    assert(unlink(pending) == 0);
    assert(qihse_ct1_recovery_create(concurrent, &m, true));
    int barrier[2]; assert(pipe(barrier) == 0);
    pid_t children[2];
    for (int i = 0; i < 2; ++i) {
        children[i] = fork(); assert(children[i] >= 0);
        if (!children[i]) {
            char ready;
            close(barrier[1]);
            if (read(barrier[0], &ready, 1) != 1) _exit(2);
            _exit(qihse_ct1_recovery_spend(concurrent, &m, 1500) ? 0 : 1);
        }
    }
    close(barrier[0]);
    assert(write(barrier[1], "xx", 2) == 2 && close(barrier[1]) == 0);
    int successes = 0;
    for (int i = 0; i < 2; ++i) {
        int status;
        assert(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status));
        assert(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 1);
        successes += WEXITSTATUS(status) == 0;
    }
    assert(successes == 1);
    assert(qihse_ct1_recovery_load(concurrent, true, &actual, &spent) && spent);
    assert(!qihse_ct1_recovery_spend(concurrent, &m, 1500));
    const char* paths[] = {receipt, crash, concurrent};
    for (size_t i = 0; i < 3; ++i) {
        if (i) assert(unlink(paths[i]) == 0);
        snprintf(lockpath, sizeof(lockpath), "%s.lock", paths[i]);
        assert(unlink(lockpath) == 0);
    }
}
static void fixture_file(char* out, size_t capacity, const char* dir,
    const char* name) {
    int n = snprintf(out, capacity, "%s/%s", dir, name);
    assert(n > 0 && (size_t)n < capacity);
}
static void fixture_roster(const char* dir, qihse_ct1_recovery_file_t* files,
    size_t count) {
    for (size_t i = 0; i < count; ++i) {
        char path[256];
        fixture_file(path, sizeof(path), dir, files[i].filename);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0);
        unsigned char bytes[128];
        memset(bytes, (int)(i + 1), sizeof(bytes));
        size_t len = files[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ?
            0 : 80 + i;
        assert(write(fd, bytes, len) == (ssize_t)len);
        assert(close(fd) == 0);
        files[i].size = len;
        assert(SHA256(bytes, len, files[i].sha256));
    }
}
static int frozen_hook_mode, frozen_hook_count, frozen_reads_after_revocation;
static void revoke_frozen_fixture(void) {
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op && (frozen_hook_mode == 1 ?
        qihse_auth_destroy_user(op, 62010) :
        qihse_auth_modify_user(op, 62010, NULL, NULL, -1, -1, 0, -1)));
}
void qihse_ct1_frozen_test_before_block(const char* name, uint64_t total) {
    if (frozen_hook_mode == 1 && !strcmp(name, "wal.log") &&
        total >= 16384 && !qihse_auth_get_user(62010))
        ++frozen_reads_after_revocation;
}
void qihse_ct1_frozen_test_after_block(const char* name, uint64_t total) {
    if (frozen_hook_mode != 1 || strcmp(name, "wal.log") ||
        total < 16384) return;
    if (++frozen_hook_count == 1) revoke_frozen_fixture();
}
void qihse_ct1_frozen_test_after_entry(void) {
    if (frozen_hook_mode != 2) return;
    if (++frozen_hook_count == 1) revoke_frozen_fixture();
}
static void check_frozen(const char* root, const qihse_user_t* principal,
    const qihse_user_t* low, const qihse_user_t* tenant) {
    qihse_ct1_recovery_manifest_t m = sample(false), wrong;
    char source[256], target[256], link_dir[256], path[256], other[256];
    fixture_file(source, sizeof(source), root, "frozen-source");
    fixture_file(target, sizeof(target), root, "frozen-target");
    fixture_file(link_dir, sizeof(link_dir), root, "frozen-link");
    assert(mkdir(source, 0700) == 0 && mkdir(target, 0700) == 0);
    fixture_roster(source, m.source_files, QIHSE_CT1_RECOVERY_SOURCE_FILES);
    fixture_roster(target, m.target_files, QIHSE_CT1_RECOVERY_TARGET_FILES);
#define VERIFY_BOTH() do { \
    assert(qihse_ct1_recovery_verify_frozen(principal, source, &m, true)); \
    assert(qihse_ct1_recovery_verify_frozen(principal, target, &m, false)); \
    assert(!qihse_ct1_recovery_issuer_authorized()); \
} while (0)
    VERIFY_BOTH();
    /* The single-row B label is deliberately low; WAL/SSTables may hold
     * higher-label rows in another tenant. Deny before any frozen file opens. */
    assert(!qihse_ct1_recovery_verify_frozen(NULL, source, &m, true));
    assert(!qihse_ct1_recovery_verify_frozen(low, source, &m, true));
    assert(!qihse_ct1_recovery_verify_frozen(tenant, source, &m, true));
    wrong = m; wrong.classification = 0; wrong.sci = 0;
    wrong.row_tenant_id = 0; wrong.principal_tenant_id = 0;
    assert(!qihse_ct1_recovery_verify_frozen(low, source, &wrong, true));
    assert(!qihse_ct1_recovery_verify_frozen(principal, source, NULL, true));
    assert(!qihse_ct1_recovery_verify_frozen(principal, NULL, &m, true));
    wrong = m; wrong.target_files[0].sha256[0] ^= 1;
    assert(!qihse_ct1_recovery_verify_frozen(principal, target, &wrong, false));
    fixture_file(path, sizeof(path), source, m.source_files[0].filename);
    assert(unlink(path) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, source, &m, true));
    /* Restore identical bytes, then mutate without changing the file length. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    unsigned char bytes[128]; memset(bytes, 1, sizeof(bytes));
    assert(write(fd, bytes, m.source_files[0].size) ==
        (ssize_t)m.source_files[0].size && close(fd) == 0);
    VERIFY_BOTH();
    fd = open(path, O_WRONLY);
    assert(fd >= 0);
    unsigned char changed_byte = 42;
    assert(pwrite(fd, &changed_byte, 1, 0) == 1 && close(fd) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, source, &m, true));
    fd = open(path, O_WRONLY);
    assert(fd >= 0 && pwrite(fd, bytes, 1, 0) == 1 && close(fd) == 0);
    VERIFY_BOTH();
    fixture_file(other, sizeof(other), target, "unexpected.sidecar");
    fd = open(other, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && close(fd) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, target, &m, false));
    assert(unlink(other) == 0);
    fixture_file(path, sizeof(path), target, m.target_files[1].filename);
    assert(unlink(path) == 0 && symlink("wal.log", path) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, target, &m, false));
    assert(unlink(path) == 0 && mkfifo(path, 0600) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, target, &m, false));
    assert(unlink(path) == 0);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    memset(bytes, 2, sizeof(bytes));
    assert(write(fd, bytes, m.target_files[1].size) ==
        (ssize_t)m.target_files[1].size && close(fd) == 0);
    VERIFY_BOTH();
    fixture_file(other, sizeof(other), root, "hardlink");
    assert(link(path, other) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, target, &m, false));
    assert(unlink(other) == 0);
    assert(chmod(path, 0644) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, target, &m, false));
    assert(chmod(path, 0600) == 0);
    VERIFY_BOTH();
    assert(symlink("frozen-source", link_dir) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, link_dir, &m, true));
    fixture_file(path, sizeof(path), link_dir, m.source_files[0].filename);
    assert(!qihse_ct1_recovery_verify_frozen(principal, path, &m, true));
    assert(!qihse_ct1_recovery_verify_frozen(principal, "../frozen-source", &m, true));
    assert(!qihse_ct1_recovery_verify_frozen(principal, "././frozen-source", &m, true));
    assert(unlink(link_dir) == 0);
    /* This link is an intermediate component, not the final directory. */
    int n = snprintf(link_dir, sizeof(link_dir), "%s-link", root);
    assert(n > 0 && (size_t)n < sizeof(link_dir));
    assert(symlink(root, link_dir) == 0);
    fixture_file(path, sizeof(path), link_dir, "frozen-source");
    assert(!qihse_ct1_recovery_verify_frozen(principal, path, &m, true));
    assert(unlink(link_dir) == 0);
    assert(chmod(source, 0750) == 0);
    assert(!qihse_ct1_recovery_verify_frozen(principal, source, &m, true));
    assert(chmod(source, 0700) == 0);
    VERIFY_BOTH();
    /* Force two distinct WAL reads; revoke after the first block and prove
     * that the second cannot be materialized despite the low B row label. */
    fixture_file(path, sizeof(path), source, "wal.log");
    unsigned char* large = calloc(1, 32769);
    assert(large);
    memset(large, 8, m.source_files[7].size);
    fd = open(path, O_WRONLY); assert(fd >= 0);
    assert(pwrite(fd, large, 32769, 0) == 32769 && close(fd) == 0);
    m.source_files[7].size = 32769;
    assert(SHA256(large, 32769, m.source_files[7].sha256));
    free(large);
    frozen_hook_mode = 2; frozen_hook_count = 0;
    assert(!qihse_ct1_recovery_verify_frozen(principal, source, &m, true));
    assert(frozen_hook_count == 1 &&
        qihse_user_get_classification(principal) == 0);
    frozen_hook_mode = 0;
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op && qihse_auth_modify_user(op, 62010, NULL, NULL,
        -1, -1, UINT16_MAX, -1));
    frozen_hook_mode = 1; frozen_hook_count = 0;
    frozen_reads_after_revocation = 0;
    assert(!qihse_ct1_recovery_verify_frozen(principal, source, &m, true));
    assert(frozen_hook_count == 1 && frozen_reads_after_revocation == 0 &&
        !qihse_auth_user_is_active(principal));
    frozen_hook_mode = 0;
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_SOURCE_FILES; ++i) {
        fixture_file(path, sizeof(path), source, m.source_files[i].filename);
        assert(unlink(path) == 0);
    }
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_TARGET_FILES; ++i) {
        fixture_file(path, sizeof(path), target, m.target_files[i].filename);
        assert(unlink(path) == 0);
    }
    assert(rmdir(source) == 0 && rmdir(target) == 0);
#undef VERIFY_BOTH
}
static void ledger_remove(const char* path) {
    char lock[256];
    assert(snprintf(lock, sizeof(lock), "%s.lock", path) > 0);
    assert(unlink(path) == 0 && unlink(lock) == 0);
}
static void check_ledger(const char* dir) {
    qihse_ct1_recovery_manifest_t m = sample(false), next = m, wrong;
    char path[256], lock[266], other[256], via[256];
    fixture_file(path, sizeof(path), dir, "ledger");
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    assert(qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    assert(!qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    assert(!qihse_ct1_recovery_ledger_consume(path, "wrong-node", &m, 1500));
    assert(!qihse_ct1_recovery_ledger_consume(path, "target", &m, 1500));
    wrong = m; strcpy(wrong.generation, "generation-2");
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &wrong, 1500));
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 2000));
    assert(qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE], digest[32], recorded[32];
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    assert(SHA256(wire, sizeof(wire), digest));
    int ledger_fd = open(path, O_RDONLY); assert(ledger_fd >= 0);
    assert(pread(ledger_fd, recorded, sizeof(recorded), 300 + 8 + 32) ==
        (ssize_t)sizeof(recorded));
    assert(close(ledger_fd) == 0 && memcmp(recorded, digest, sizeof(digest)) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    fixture_file(other, sizeof(other), dir, "target-ledger");
    assert(qihse_ct1_recovery_ledger_bootstrap(other, "target", &m));
    assert(qihse_ct1_recovery_ledger_consume(other, "target", &m, 1500));
    assert(!qihse_ct1_recovery_ledger_consume(other, "target", &m, 1500));
    assert(!qihse_ct1_recovery_ledger_consume(other, "source", &m, 1500));
    ledger_remove(other);
    next.epoch++; next.nonce[0]++;
    wrong = next; wrong.epoch = m.epoch;
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &wrong, 1500));
    wrong = next; wrong.nonce[0] = m.nonce[0];
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &wrong, 1500));
    wrong = m; wrong.frame_sha256[0] ^= 1;
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &wrong, 1500));
    assert(qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
    /* Reopen via separate process: historical nonce and high-water persist. */
    pid_t pid = fork(); assert(pid >= 0);
    if (!pid) _exit(qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500) ? 1 : 0);
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    snprintf(lock, sizeof(lock), "%s.lock", path);
    fixture_file(other, sizeof(other), dir, "alias");
    assert(link(path, other) == 0);
    next.epoch++; next.nonce[0]++;
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
    assert(unlink(other) == 0);
    assert(chmod(path, 0644) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
    assert(chmod(path, 0600) == 0);
    assert(chmod(lock, 0644) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
    assert(chmod(lock, 0600) == 0);
    if (geteuid() == 0) {
        assert(chown(path, 65534, (gid_t)-1) == 0);
        assert(!qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
        assert(chown(path, 0, (gid_t)-1) == 0);
    }
    assert(qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
    /* Intent cut: an uncertain append cannot admit another epoch after reopen. */
    int fd = open(lock, O_RDWR); assert(fd >= 0);
    assert(pwrite(fd, "1", 1, 0) == 1 && fsync(fd) == 0 && close(fd) == 0);
    next.epoch++; next.nonce[0]++;
    pid = fork(); assert(pid >= 0);
    if (!pid) _exit(qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500) ? 1 : 0);
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    ledger_remove(path);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
    /* Re-bootstrap is explicitly non-authoritative and cannot detect rollback. */
    assert(qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    fd = open(path, O_RDWR); assert(fd >= 0);
    assert(pwrite(fd, "X", 1, 0) == 1 && fsync(fd) == 0 && close(fd) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    ledger_remove(path);
    assert(qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    assert(qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    fd = open(path, O_RDWR); assert(fd >= 0);
    assert(pwrite(fd, "X", 1, 300 + 40) == 1 && fsync(fd) == 0 && close(fd) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
    fd = open(path, O_RDWR); assert(fd >= 0);
    assert(ftruncate(fd, 300 + 104 - 1) == 0 && fsync(fd) == 0 && close(fd) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &next, 1500));
    ledger_remove(path);
    assert(qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    fd = open(path, O_RDWR); assert(fd >= 0);
    assert(ftruncate(fd, 299) == 0 && fsync(fd) == 0 && close(fd) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    ledger_remove(path);
    assert(qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    assert(snprintf(other, sizeof(other), "%s/ancestor", dir) > 0);
    assert(symlink(".", other) == 0);
    assert(snprintf(via, sizeof(via), "%s/ancestor/ledger", dir) > 0);
    assert(!qihse_ct1_recovery_ledger_consume(via, "source", &m, 1500));
    assert(unlink(other) == 0);
    assert(chmod(dir, 0770) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    assert(chmod(dir, 0700) == 0);
    fixture_file(other, sizeof(other), dir, "lock-alias");
    assert(link(lock, other) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    assert(unlink(other) == 0);
    assert(unlink(lock) == 0 && symlink("ledger", lock) == 0);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    assert(unlink(lock) == 0 && mkfifo(lock, 0600) == 0);
    alarm(3);
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    alarm(0);
    assert(unlink(lock) == 0 && unlink(path) == 0);
    assert(symlink("missing", path) == 0);
    assert(!qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    assert(unlink(path) == 0);
    assert(mkfifo(path, 0600) == 0);
    alarm(3);
    assert(!qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    assert(!qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500));
    alarm(0);
    assert(unlink(path) == 0);
    /* Two competing processes can at most commit one identical epoch. */
    assert(qihse_ct1_recovery_ledger_bootstrap(path, "source", &m));
    int barrier[2]; assert(pipe(barrier) == 0);
    pid_t children[2];
    for (int i = 0; i < 2; ++i) {
        children[i] = fork(); assert(children[i] >= 0);
        if (!children[i]) {
            char ready;
            close(barrier[1]);
            if (read(barrier[0], &ready, 1) != 1) _exit(2);
            _exit(qihse_ct1_recovery_ledger_consume(path, "source", &m, 1500) ? 0 : 1);
        }
    }
    close(barrier[0]);
    assert(write(barrier[1], "xx", 2) == 2 && close(barrier[1]) == 0);
    int successes = 0;
    for (int i = 0; i < 2; ++i) {
        assert(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status));
        assert(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 1);
        successes += WEXITSTATUS(status) == 0;
    }
    assert(successes == 1);
    ledger_remove(path);
}
static void check_archive(const char* root) {
    qihse_ct1_recovery_manifest_t m = sample(false), wrong;
    unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    for (size_t i = 0; i < sizeof(frame); ++i) frame[i] = (unsigned char)i;
    assert(SHA256(frame, sizeof(frame), m.frame_sha256));
    char dir[256], path[256], other[256], moved[256], via[256];
    fixture_file(dir, sizeof(dir), root, "archive-dir");
    assert(mkdir(dir, 0700) == 0);
    fixture_file(path, sizeof(path), dir, "exact-frame");
    fixture_file(other, sizeof(other), dir, "alias");
    fixture_file(moved, sizeof(moved), root, "archive-moved");
    fixture_file(via, sizeof(via), root, "archive-symlink");
    assert(!qihse_ct1_recovery_archive_create(path, &m, frame, sizeof(frame)-1));
    assert(!qihse_ct1_recovery_archive_create(path, &m, frame, sizeof(frame)+1));
    assert(!qihse_ct1_recovery_archive_create(path, &m, NULL, sizeof(frame)));
    unsigned char tampered[sizeof(frame)];
    memcpy(tampered, frame, sizeof(frame)); tampered[17] ^= 1;
    assert(!qihse_ct1_recovery_archive_create(path, &m, tampered, sizeof(tampered)));
    assert(qihse_ct1_recovery_archive_create(path, &m, frame, sizeof(frame)));
    assert(!qihse_ct1_recovery_archive_create(path, &m, frame, sizeof(frame)));
    struct stat st;
    assert(stat(path, &st) == 0 && st.st_size == QIHSE_CT1_RECOVERY_ARCHIVE_BYTES);
    /* Even complete, spent bookkeeping plus a durable archive is no grant. */
    char receipt[256], ledger[256], receipt_lock[266];
    fixture_file(receipt, sizeof(receipt), dir, "source-receipt");
    fixture_file(ledger, sizeof(ledger), dir, "source-ledger");
    assert(qihse_ct1_recovery_create(receipt, &m, true));
    assert(qihse_ct1_recovery_ledger_bootstrap(ledger, "source", &m));
    assert(qihse_ct1_recovery_ledger_consume(ledger, "source", &m, 1500));
    assert(qihse_ct1_recovery_spend(receipt, &m, 1500));
    assert(!qihse_ct1_recovery_issuer_authorized());
    /* Reopen after durable evidence publication without sharing artifact fds. */
    pid_t child = fork(); assert(child >= 0);
    if (!child) _exit(qihse_ct1_recovery_archive_verify(path, &m) &&
        !qihse_ct1_recovery_ledger_consume(ledger, "source", &m, 1500) &&
        !qihse_ct1_recovery_spend(receipt, &m, 1500) &&
        !qihse_ct1_recovery_issuer_authorized() ? 0 : 1);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    ledger_remove(ledger);
    assert(snprintf(receipt_lock, sizeof(receipt_lock), "%s.lock", receipt) > 0);
    assert(unlink(receipt) == 0 && unlink(receipt_lock) == 0);
    wrong = m; wrong.epoch++;
    assert(!qihse_ct1_recovery_archive_verify(path, &wrong));
    wrong = m; strcpy(wrong.generation, "generation-2");
    assert(!qihse_ct1_recovery_archive_verify(path, &wrong));
    wrong = m; wrong.frame_sha256[0] ^= 1;
    assert(!qihse_ct1_recovery_archive_verify(path, &wrong));
    wrong = m; wrong.frame_length--;
    assert(!qihse_ct1_recovery_archive_verify(path, &wrong));
    assert(symlink("exact-frame", other) == 0);
    assert(!qihse_ct1_recovery_archive_verify(other, &m));
    assert(!qihse_ct1_recovery_archive_create(other, &m, frame, sizeof(frame)));
    assert(unlink(other) == 0 && link(path, other) == 0);
    assert(!qihse_ct1_recovery_archive_verify(path, &m));
    assert(unlink(other) == 0 && chmod(path, 0644) == 0);
    assert(!qihse_ct1_recovery_archive_verify(path, &m));
    assert(chmod(path, 0600) == 0);
    assert(chmod(dir, 0770) == 0);
    assert(!qihse_ct1_recovery_archive_verify(path, &m));
    assert(chmod(dir, 0700) == 0);
    assert(symlink(dir, via) == 0);
    char through[256]; fixture_file(through, sizeof(through), via, "exact-frame");
    assert(!qihse_ct1_recovery_archive_verify(through, &m));
    assert(unlink(via) == 0);
    assert(rename(dir, moved) == 0 && mkdir(dir, 0700) == 0);
    assert(!qihse_ct1_recovery_archive_verify(path, &m));
    assert(rmdir(dir) == 0 && rename(moved, dir) == 0);
    assert(qihse_ct1_recovery_archive_verify(path, &m));
    int fd = open(path, O_RDWR); assert(fd >= 0);
    assert(pwrite(fd, tampered, sizeof(tampered), QIHSE_CT1_RECOVERY_WIRE_SIZE) ==
        (ssize_t)sizeof(tampered) && fsync(fd) == 0);
    assert(!qihse_ct1_recovery_archive_verify(path, &m));
    assert(pwrite(fd, frame, sizeof(frame), QIHSE_CT1_RECOVERY_WIRE_SIZE) ==
        (ssize_t)sizeof(frame) && fsync(fd) == 0);
    assert(qihse_ct1_recovery_archive_verify(path, &m));
    assert(ftruncate(fd, QIHSE_CT1_RECOVERY_ARCHIVE_BYTES - 1) == 0 && fsync(fd) == 0);
    assert(!qihse_ct1_recovery_archive_verify(path, &m));
    assert(close(fd) == 0 && unlink(path) == 0);
    /* Creation completes in the child; parent has no inherited archive fd. */
    child = fork(); assert(child >= 0);
    if (!child) _exit(qihse_ct1_recovery_archive_create(path, &m,
        frame, sizeof(frame)) ? 0 : 1);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(qihse_ct1_recovery_archive_verify(path, &m));
    assert(unlink(path) == 0);
    /* Simulated crash leaves a partial exclusive file, never replaced. */
    child = fork(); assert(child >= 0);
    if (!child) {
        int partial = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (partial < 0 || write(partial, frame, 21) != 21 || fsync(partial)) _exit(1);
        _exit(0);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!qihse_ct1_recovery_archive_verify(path, &m));
    assert(!qihse_ct1_recovery_archive_create(path, &m, frame, sizeof(frame)));
    assert(stat(path, &st) == 0 && st.st_size == 21);
    assert(unlink(path) == 0 && rmdir(dir) == 0);
    assert(!qihse_ct1_recovery_issuer_authorized());
}
static char auth_fixture_dir[] = "./ct1-recovery-test-XXXXXX";
static void cleanup_auth_fixture(void) {
    DIR* audit = opendir(auth_fixture_dir);
    if (!audit) return;
    struct dirent* entry;
    while ((entry = readdir(audit))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char file[256];
        fixture_file(file, sizeof(file), auth_fixture_dir, entry->d_name);
        assert(unlink(file) == 0);
    }
    assert(closedir(audit) == 0 && rmdir(auth_fixture_dir) == 0);
}
int main(void) {
    char* dir = auth_fixture_dir;
    assert(mkdtemp(dir) && atexit(cleanup_auth_fixture) == 0);
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    char receipt[128], torn[128], link[128];
    assert(snprintf(receipt, sizeof(receipt), "%s/receipt", dir) > 0);
    assert(snprintf(torn, sizeof(torn), "%s/torn", dir) > 0);
    assert(snprintf(link, sizeof(link), "%s/link", dir) > 0);
    check_wire(); check_receipt(receipt, torn, link);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("Ct1FrozenFixtureOperator1!"));
    qihse_user_t* operator = qihse_auth_get_user(0);
    assert(operator);
    qihse_user_t* service = qihse_auth_create_user(operator, 62010,
        QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX,
        "Ct1FrozenFixtureService1!", false);
    qihse_user_t* low = qihse_auth_create_user(operator, 62011,
        QIHSE_ROLE_ANALYST, 0, 0, "Ct1FrozenFixtureLow1!", false);
    qihse_user_t* tenant = qihse_auth_create_tenant_user(operator, 42, 62012,
        QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX,
        "Ct1FrozenFixtureTenant1!", false);
    assert(service && low && tenant);
    check_receipt_negatives(dir); check_frozen(dir, service, low, tenant);
    check_ledger(dir);
    check_archive(dir);
    assert(unlink(receipt) == 0 && unlink(torn) == 0);
    char lockpath[256];
    snprintf(lockpath, sizeof(lockpath), "%s.lock", receipt);
    assert(unlink(lockpath) == 0);
    snprintf(lockpath, sizeof(lockpath), "%s.lock", torn);
    assert(unlink(lockpath) == 0);
    puts("CT1 B structural receipt checks passed (issuer binding remains denied)");
    return 0;
}
