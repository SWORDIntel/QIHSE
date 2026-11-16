#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_recovery_manifest.h"
#include <assert.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    m.tombstone_position = 11103;
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
    assert(!spent && qihse_ct1_recovery_matches(&actual, &m, 1000, false));
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
    size_t first = 12 + 10 * 65 + 6 * 32 + 12 * 8 + 2 * 4 + 5 * 2;
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
int main(void) {
    char dir[] = "./ct1-recovery-test-XXXXXX";
    assert(mkdtemp(dir));
    char receipt[128], torn[128], link[128];
    assert(snprintf(receipt, sizeof(receipt), "%s/receipt", dir) > 0);
    assert(snprintf(torn, sizeof(torn), "%s/torn", dir) > 0);
    assert(snprintf(link, sizeof(link), "%s/link", dir) > 0);
    check_wire(); check_receipt(receipt, torn, link);
    assert(unlink(receipt) == 0 && unlink(torn) == 0 && rmdir(dir) == 0);
    puts("CT1 B structural receipt checks passed (issuer binding remains denied)");
    return 0;
}
