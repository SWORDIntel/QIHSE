#include "qihse_ct1_disposition.h"
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

/* Deterministic active-principal fixture; no daemon, filesystem or authority. */
struct qihse_user_s { uint32_t tenant; uint16_t clearance, sci; bool active; };
bool qihse_auth_user_is_active(const qihse_user_t *u) { return u && u->active; }
uint32_t qihse_user_get_tenant_id(const qihse_user_t *u) { return u->tenant; }
bool qihse_auth_can_access(const qihse_user_t *u, uint16_t c, uint16_t s) {
    return u && u->active && u->clearance >= c && (u->sci & s) == s;
}
static const char *const source_names[] = {"ct-baseline.qfs", "ct-state.bin",
    "restore-highwater.bin", "slot-ownership.journal",
    "slot-ownership.journal.lock", "sstable_11321.db", "sstable_11322.db", "wal.log"};
static const char *const target_names[] = {"ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_6.db", "sstable_7.db", "wal.log"};

static void roster(qihse_ct1_recovery_file_t *files, const char *const *names,
    size_t count) {
    for (size_t i = 0; i < count; ++i) {
        strcpy(files[i].filename, names[i]);
        const char *s = names[i];
        files[i].kind = !strcmp(s, "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(s, "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(s, "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(s, "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(s, "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(s, "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
        files[i].size = files[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ? 0 : 100 + i;
        if (!files[i].size) assert(SHA256((const unsigned char *)"", 0, files[i].sha256));
        else memset(files[i].sha256, (int)(i + 1), 32);
    }
}
static qihse_ct1_recovery_manifest_t fixture(const unsigned char frame[1644]) {
    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator");
    strcpy(m.source_qkp_id, "source"); strcpy(m.target_qkp_id, "target");
    strcpy(m.generation, "gen-11111");
    strcpy(m.source_store_id, "source-store");
    strcpy(m.target_store_id, "target-store");
    strcpy(m.replication_principal_id, "replication-service");
    strcpy(m.row_key, "classified-row");
    strcpy(m.source_peer_qkp_id, "source-next");
    strcpy(m.target_peer_qkp_id, "target-next");
    memset(m.issuer_operator_pin, 1, 32);
    memset(m.source_peer_pin, 2, 32); memset(m.target_peer_pin, 3, 32);
    assert(SHA256(frame, QIHSE_CT1_RECOVERY_FRAME_BYTES, m.frame_sha256));
    memset(m.baseline_sha256, 5, 32); memset(m.nonce, 6, 32);
    roster(m.source_files, source_names, QIHSE_CT1_RECOVERY_SOURCE_FILES);
    roster(m.target_files, target_names, QIHSE_CT1_RECOVERY_TARGET_FILES);
    m.epoch = 9; m.issued_ms = 1000; m.expires_ms = 901000;
    m.frame_offset = 400; m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 11111; m.target_cursor = 11110;
    m.target_high_water = 5729457; m.source_high_water = 5729448;
    m.row_change_seq = 5729448; m.tombstone_position = 11103;
    m.tombstone_row_seq = 5729450;
    m.row_tenant_id = 42; m.principal_tenant_id = 42;
    m.classification = 4; m.sci = 2;
    m.principal_classification = 4; m.principal_sci = 2;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    return m;
}
static void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char)v;
}
static void put64(unsigned char *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (56 - i * 8));
}
static void refused(const qihse_user_t *u, const qihse_ct1_recovery_manifest_t *m,
    const unsigned char *data, size_t length) {
    qihse_ct1_disposition_view_t v = {(const unsigned char *)1, 1};
    assert(!qihse_ct1_disposition_decode(u, m, data, length, &v));
    assert(!v.original_frame && !v.original_length);
}
int main(void) {
    enum { FRAME = 16 + QIHSE_CT1_RECOVERY_WIRE_SIZE,
        CHECK = QIHSE_CT1_DISPOSITION_SIZE - 32 };
    struct qihse_user_s principal = {42, 4, 2, true}, denied = {42, 3, 2, true};
    struct qihse_user_s missing_sci = {42, 4, 0, true};
    unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES], record[QIHSE_CT1_DISPOSITION_SIZE];
    unsigned char changed[sizeof(record) + 1], other_frame[sizeof(frame)];
    qihse_ct1_disposition_view_t view = {0};
    memset(frame, 0, sizeof(frame));
    memcpy(frame, "QKV6CT01", 8);
    frame[8] = 1; /* SOURCE, never a receiver frame */
    put32(frame + 12, sizeof(frame)); put64(frame + 32, 11111);
    /* Disposable one-row B-shaped QKV6 SOURCE frame, including its checksum.
     * Neither this fixture nor the codec claims historical source authorship. */
    const char *key = "t:42/classified-row";
    const size_t source_len = strlen("source-store"), gen_len = strlen("gen-11111");
    const size_t body = sizeof(frame) - 96 - source_len - gen_len - 48;
    frame[9] = 1; put32(frame + 16, 48); put32(frame + 20, body);
    put32(frame + 24, 1); put32(frame + 28, 42);
    put64(frame + 40, 5729448); put64(frame + 48, 5729448);
    frame[56] = (unsigned char)source_len; frame[57] = (unsigned char)gen_len;
    memcpy(frame + 96, "source-store", source_len);
    memcpy(frame + 96 + source_len, "gen-11111", gen_len);
    unsigned char *row = frame + 96 + source_len + gen_len;
    put32(row + 4, 42); put32(row + 8, 42);
    row[13] = 4; row[15] = 2; row[16] = 1;
    put64(row + 20, 5729448); put32(row + 36, strlen(key));
    put32(row + 40, body - strlen(key));
    memcpy(row + 48, key, strlen(key));
    for (size_t i = strlen(key); i < body; ++i)
        row[48 + i] = (unsigned char)('A' + i % 26);
    assert(SHA256(frame, sizeof(frame), frame + 64));
    qihse_ct1_recovery_manifest_t m = fixture(frame), wrong;
    assert(qihse_ct1_disposition_encode(&principal, &m, frame, sizeof(frame), record));
    assert(qihse_ct1_disposition_decode(&principal, &m, record, sizeof(record), &view));
    assert(view.original_length == 1644 && view.original_frame == record + FRAME);
    assert(!memcmp(view.original_frame, frame, sizeof(frame)));
    /* The encoder also accepts input at the start of its output buffer. */
    memcpy(changed, frame, sizeof(frame));
    assert(qihse_ct1_disposition_encode(&principal, &m, changed,
        sizeof(frame), changed));
    assert(!memcmp(changed, record, sizeof(record)));
    /* The QKV6 checksum is genuine; forging a lower manifest and every outer
     * hash must not launder its high-class/SCI row to a lower principal. */
    wrong = m;
    wrong.classification = 1; wrong.sci = 0;
    wrong.principal_classification = 1; wrong.principal_sci = 0;
    memset(changed, 0xa5, sizeof(changed));
    assert(!qihse_ct1_disposition_encode(&denied, &wrong, frame,
        sizeof(frame), changed));
    for (size_t i = 0; i < sizeof(record); ++i) assert(changed[i] == 0xa5);
    memcpy(changed, record, sizeof(record));
    assert(qihse_ct1_recovery_encode(&wrong, false, false, changed + 16));
    assert(SHA256(changed, CHECK, changed + CHECK));
    refused(&denied, &wrong, changed, sizeof(record));
    refused(&missing_sci, &wrong, changed, sizeof(record));
    memset(changed, 0xa5, sizeof(changed));
    assert(!qihse_ct1_disposition_encode(&missing_sci, &wrong, frame,
        sizeof(frame), changed));
    for (size_t i = 0; i < sizeof(record); ++i) assert(changed[i] == 0xa5);
    wrong = m; wrong.classification = 1; wrong.sci = 0;
    memset(changed, 0xa5, sizeof(changed));
    assert(!qihse_ct1_disposition_encode(&principal, &wrong, frame,
        sizeof(frame), changed)); /* actual row must match the expected label */
    for (size_t i = 0; i < sizeof(record); ++i) assert(changed[i] == 0xa5);
    memcpy(changed, record, sizeof(record));
    assert(qihse_ct1_recovery_encode(&wrong, false, false, changed + 16));
    assert(SHA256(changed, CHECK, changed + CHECK));
    refused(&principal, &wrong, changed, sizeof(record));
    wrong = m; strcpy(wrong.row_key, "other-row");
    assert(!qihse_ct1_disposition_encode(&principal, &wrong, frame,
        sizeof(frame), changed));
    wrong = m; wrong.row_change_seq++;
    assert(!qihse_ct1_disposition_encode(&principal, &wrong, frame,
        sizeof(frame), changed));
    wrong = m; strcpy(wrong.source_store_id, "other-source");
    assert(!qihse_ct1_disposition_encode(&principal, &wrong, frame,
        sizeof(frame), changed));
    memcpy(other_frame, frame, sizeof(frame));
    other_frame[64] ^= 1; /* manifest frame hash can be forged, QKV6 cannot */
    wrong = fixture(other_frame);
    assert(!qihse_ct1_disposition_encode(&principal, &wrong, other_frame,
        sizeof(other_frame), changed));
    refused(&principal, &m, frame, sizeof(frame)); /* old SOURCE is not a disposition */
    for (size_t cut = 0; cut < sizeof(record); ++cut)
        refused(&principal, &m, record, cut); /* every crash-tail prefix */
    memcpy(changed, record, sizeof(record)); changed[sizeof(record)] = 0;
    refused(&principal, &m, changed, sizeof(changed));
    refused(&principal, &m, record, SIZE_MAX); /* overflow-length denial */
    refused(NULL, &m, record, sizeof(record));
    refused(&denied, &m, record, sizeof(record)); /* low clearance */
    refused(&missing_sci, &m, record, sizeof(record));
    denied = principal; denied.tenant = 43;
    refused(&denied, &m, record, sizeof(record));
    denied = principal; denied.active = false;
    refused(&denied, &m, record, sizeof(record));
    assert(!qihse_ct1_disposition_encode(&denied, &m, frame, sizeof(frame), changed));
    assert(!qihse_ct1_disposition_encode(&principal, &m, frame, SIZE_MAX, changed));
    assert(!qihse_ct1_disposition_encode(&principal, &m, frame, sizeof(frame) - 1, changed));
    wrong = m; wrong.target_cursor++;
    refused(&principal, &wrong, record, sizeof(record));
    wrong = m; wrong.target_high_water++;
    refused(&principal, &wrong, record, sizeof(record));
    wrong = m; wrong.tombstone_row_seq++;
    refused(&principal, &wrong, record, sizeof(record));
    wrong = m; wrong.frame_position++;
    refused(&principal, &wrong, record, sizeof(record));
    wrong = m; strcpy(wrong.generation, "gen-11112");
    refused(&principal, &wrong, record, sizeof(record));
    wrong = m; strcpy(wrong.target_store_id, "other-store");
    refused(&principal, &wrong, record, sizeof(record));
    wrong = m; wrong.nonce[0] ^= 1;
    refused(&principal, &wrong, record, sizeof(record));
    memcpy(changed, record, sizeof(record));
    assert(qihse_ct1_recovery_encode(&wrong, false, false, changed + 16));
    assert(SHA256(changed, CHECK, changed + CHECK));
    refused(&principal, &m, changed, sizeof(record)); /* self-consistent foreign binding */
    for (size_t i = 0; i < sizeof(record); ++i) {
        memcpy(changed, record, sizeof(record)); changed[i] ^= 1;
        refused(&principal, &m, changed, sizeof(record));
    }
    memcpy(changed, record, sizeof(record)); put32(changed + 8, UINT32_MAX);
    assert(SHA256(changed, CHECK, changed + CHECK));
    refused(&principal, &m, changed, sizeof(record));
    memcpy(changed, record, sizeof(record)); put32(changed + 12, 1643);
    assert(SHA256(changed, CHECK, changed + CHECK));
    refused(&principal, &m, changed, sizeof(record));
    memcpy(changed, record, sizeof(record)); changed[FRAME + 128] ^= 1;
    assert(SHA256(changed, CHECK, changed + CHECK));
    refused(&principal, &m, changed, sizeof(record)); /* recomputed outer hash */
    memcpy(other_frame, frame, sizeof(frame)); other_frame[8] = 2;
    wrong = fixture(other_frame);
    assert(!qihse_ct1_disposition_encode(&principal, &wrong, other_frame,
        sizeof(other_frame), changed)); /* receiver-mode substitution */
    puts("ct1 disposition inert codec checks passed");
    return 0;
}
