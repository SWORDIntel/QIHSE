#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_authority_witness.h"
#include <assert.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *const source_names[] = {"ct-baseline.qfs", "ct-state.bin",
    "restore-highwater.bin", "slot-ownership.journal",
    "slot-ownership.journal.lock", "sstable_1.db", "sstable_2.db", "wal.log"};
static const char *const target_names[] = {"ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock", "sstable_1.db",
    "sstable_2.db", "wal.log"};
static void files(qihse_ct1_recovery_file_t *out, const char *const *names,
    size_t count) {
    for (size_t i = 0; i < count; i++) {
        strcpy(out[i].filename, names[i]);
        const char *n = names[i];
        out[i].kind = !strcmp(n, "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(n, "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(n, "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(n, "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(n, "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(n, "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
        out[i].size = out[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ? 0 : 100;
        memset(out[i].sha256, (int)i + 1, 32);
        if (!out[i].size) assert(SHA256((const unsigned char *)"", 0, out[i].sha256));
    }
}
static qihse_ct1_recovery_manifest_t sample(void) {
    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator");
    strcpy(m.source_qkp_id, "source");
    strcpy(m.target_qkp_id, "target");
    strcpy(m.generation, "generation-1");
    strcpy(m.source_store_id, "source-store");
    strcpy(m.target_store_id, "target-store");
    strcpy(m.replication_principal_id, "service");
    strcpy(m.row_key, "sample-row");
    strcpy(m.source_peer_qkp_id, "source-peer");
    strcpy(m.target_peer_qkp_id, "target-peer");
    memset(m.issuer_operator_pin, 1, 32);
    memset(m.source_peer_pin, 2, 32);
    memset(m.target_peer_pin, 3, 32);
    memset(m.frame_sha256, 4, 32);
    memset(m.baseline_sha256, 5, 32);
    memset(m.nonce, 6, 32);
    files(m.source_files, source_names, 8);
    files(m.target_files, target_names, 7);
    m.epoch = 1; m.issued_ms = 1000; m.expires_ms = 901000;
    m.frame_offset = 1; m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 11111; m.baseline_row_seq = 2;
    m.target_cursor = 11110; m.target_high_water = 4;
    m.source_high_water = 3; m.row_change_seq = 3;
    m.tombstone_position = 11103; m.tombstone_row_seq = 4;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    return m;
}
static void name(char out[256], const char *dir, const char *base) {
    int n = snprintf(out, 256, "%s/%s", dir, base);
    assert(n > 0 && n < 256);
}
static void remove_fixture(const char *dir) {
    char path[256];
    name(path, dir, "ct1-witness.log"); assert(unlink(path) == 0);
    name(path, dir, "ct1-witness.lock"); assert(unlink(path) == 0);
    assert(rmdir(dir) == 0);
}
static void test_replay_expiry(void) {
    char dir[] = "./ct1-witness-test-XXXXXX";
    assert(mkdtemp(dir));
    unsigned char head[32], next[32], third[32];
    qihse_ct1_recovery_manifest_t m = sample(), other;
    assert(!qihse_ct1_witness_bootstrap(NULL, head));
    assert(qihse_ct1_witness_bootstrap(dir, head));
    assert(!qihse_ct1_witness_bootstrap(dir, next));
    assert(!qihse_ct1_witness_consume(NULL, &m, 1000, head, next));
    assert(!qihse_ct1_witness_consume(dir, &m, 999, head, next));
    assert(!qihse_ct1_witness_consume(dir, &m, 901000, head, next));
    assert(qihse_ct1_witness_consume(dir, &m, 900999, head, next));
    char log[256]; name(log, dir, "ct1-witness.log");
    int fd = open(log, O_RDONLY); assert(fd >= 0);
    unsigned char pins[96], principal[65], digest[32], wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    assert(pread(fd, principal, sizeof(principal), 40 + 40) == 65);
    assert(!strcmp((const char *)principal, m.replication_principal_id));
    assert(pread(fd, digest, 32, 40 + 105) == 32);
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    unsigned char expected[32]; assert(SHA256(wire, sizeof(wire), expected));
    assert(!memcmp(digest, expected, 32));
    assert(pread(fd, pins, sizeof(pins), 40 + 137) == 96 && close(fd) == 0);
    assert(!memcmp(pins, m.issuer_operator_pin, 32) &&
        !memcmp(pins + 32, m.source_peer_pin, 32) &&
        !memcmp(pins + 64, m.target_peer_pin, 32));
    assert(!qihse_ct1_witness_consume(dir, &m, 1001, head, third));
    assert(!qihse_ct1_witness_consume(dir, &m, 1001, next, third));
    other = m; other.epoch = 2;
    assert(!qihse_ct1_witness_consume(dir, &other, 1001, next, third));
    other.nonce[0] ^= 1;
    assert(qihse_ct1_witness_consume(dir, &other, 1001, next, third));
    other.epoch = 2; other.nonce[1] ^= 1;
    assert(!qihse_ct1_witness_consume(dir, &other, 1001, third, next));
    remove_fixture(dir);
}
static void test_crash_concurrent(void) {
    char dir[] = "./ct1-witness-test-XXXXXX";
    assert(mkdtemp(dir));
    unsigned char head[32], out[32];
    qihse_ct1_recovery_manifest_t m = sample();
    assert(qihse_ct1_witness_bootstrap(dir, head));
    int gate[2]; assert(pipe(gate) == 0);
    pid_t children[2];
    for (int i = 0; i < 2; i++) {
        children[i] = fork(); assert(children[i] >= 0);
        if (!children[i]) {
            char token;
            close(gate[1]);
            if (read(gate[0], &token, 1) != 1) _exit(2);
            bool ok = qihse_ct1_witness_consume(dir, &m, 1001, head, out);
            _exit(ok ? 0 : 1); /* No close/cleanup: crash-like cold reopen. */
        }
    }
    close(gate[0]); assert(write(gate[1], "xx", 2) == 2); close(gate[1]);
    int successes = 0;
    for (int i = 0; i < 2; i++) {
        int status;
        assert(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status));
        assert(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 1);
        successes += WEXITSTATUS(status) == 0;
    }
    assert(successes == 1);
    assert(!qihse_ct1_witness_consume(dir, &m, 1001, head, out));
    remove_fixture(dir);
}
static void test_cold_reopen_rollback(void) {
    char dir[] = "./ct1-witness-test-XXXXXX", log[256];
    assert(mkdtemp(dir)); name(log, dir, "ct1-witness.log");
    unsigned char head[32], next[32], later[32];
    qihse_ct1_recovery_manifest_t m = sample();
    assert(qihse_ct1_witness_bootstrap(dir, head));
    int pair[2]; assert(pipe(pair) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(pair[0]);
        if (!qihse_ct1_witness_consume(dir, &m, 1000, head, next) ||
            write(pair[1], next, 32) != 32) _exit(1);
        _exit(0);
    }
    close(pair[1]);
    assert(read(pair[0], next, 32) == 32 && close(pair[0]) == 0);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    m.epoch++; m.nonce[0]++;
    assert(qihse_ct1_witness_consume(dir, &m, 1001, next, later));
    /* A full, locally valid earlier generation is still stale against a
     * checkpoint held outside the ledger; no implicit bootstrap on loss. */
    int fd = open(log, O_RDWR); assert(fd >= 0);
    assert(ftruncate(fd, 40 + 297) == 0 && fsync(fd) == 0 && close(fd) == 0);
    m.epoch++; m.nonce[0]++;
    assert(!qihse_ct1_witness_consume(dir, &m, 1001, later, head));
    remove_fixture(dir);
}
static void test_corruption(void) {
    char dir[] = "./ct1-witness-test-XXXXXX", log[256], lock[256], alias[256];
    assert(mkdtemp(dir));
    name(log, dir, "ct1-witness.log"); name(lock, dir, "ct1-witness.lock");
    name(alias, dir, "extra");
    unsigned char head[32], next[32];
    qihse_ct1_recovery_manifest_t m = sample();
    assert(qihse_ct1_witness_bootstrap(dir, head));
    assert(symlink("ct1-witness.log", alias) == 0);
    assert(!qihse_ct1_witness_bootstrap(alias, next));
    assert(unlink(alias) == 0);
    assert(link(log, alias) == 0);
    assert(!qihse_ct1_witness_consume(dir, &m, 1000, head, next));
    assert(unlink(alias) == 0);
    assert(rename(log, alias) == 0 && symlink("extra", log) == 0);
    assert(!qihse_ct1_witness_consume(dir, &m, 1000, head, next));
    assert(unlink(log) == 0 && rename(alias, log) == 0);
    assert(chmod(log, 0644) == 0);
    assert(!qihse_ct1_witness_consume(dir, &m, 1000, head, next));
    assert(chmod(log, 0600) == 0);
    assert(chmod(dir, 0770) == 0);
    assert(!qihse_ct1_witness_consume(dir, &m, 1000, head, next));
    assert(chmod(dir, 0700) == 0);
    int fd = open(log, O_RDWR); assert(fd >= 0);
    assert(pwrite(fd, "x", 1, 8) == 1 && fsync(fd) == 0);
    assert(close(fd) == 0);
    assert(!qihse_ct1_witness_consume(dir, &m, 1000, head, next));
    remove_fixture(dir);
    assert(mkdtemp(strcpy(dir, "./ct1-witness-test-XXXXXX")));
    name(log, dir, "ct1-witness.log"); name(lock, dir, "ct1-witness.lock");
    assert(qihse_ct1_witness_bootstrap(dir, head));
    fd = open(log, O_WRONLY | O_APPEND); assert(fd >= 0);
    assert(write(fd, "torn", 4) == 4 && fsync(fd) == 0 && close(fd) == 0);
    assert(!qihse_ct1_witness_consume(dir, &m, 1000, head, next));
    remove_fixture(dir);
    assert(mkdtemp(strcpy(dir, "./ct1-witness-test-XXXXXX")));
    name(log, dir, "ct1-witness.log"); name(lock, dir, "ct1-witness.lock");
    assert(qihse_ct1_witness_bootstrap(dir, head));
    fd = open(lock, O_WRONLY); assert(fd >= 0);
    assert(write(fd, "1", 1) == 1 && fsync(fd) == 0 && close(fd) == 0);
    assert(!qihse_ct1_witness_consume(dir, &m, 1000, head, next));
    remove_fixture(dir);
}
int main(void) {
    test_replay_expiry(); test_crash_concurrent(); test_cold_reopen_rollback();
    test_corruption();
    return 0;
}
