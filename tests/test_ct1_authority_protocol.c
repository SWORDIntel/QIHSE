#include "qihse_ct1_authority_protocol.h"
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

static const char *const source_names[] = {"ct-baseline.qfs", "ct-state.bin",
    "restore-highwater.bin", "slot-ownership.journal",
    "slot-ownership.journal.lock", "sstable_11321.db", "sstable_11322.db", "wal.log"};
static const char *const target_names[] = {"ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_6.db", "sstable_7.db", "wal.log"};

static void roster(qihse_ct1_recovery_file_t *files, const char *const *names,
    size_t count) {
    for (size_t i = 0; i < count; i++) {
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

static qihse_ct1_recovery_manifest_t sample(void) {
    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator");
    strcpy(m.source_qkp_id, "source"); strcpy(m.target_qkp_id, "target");
    strcpy(m.generation, "gen-1");
    strcpy(m.source_store_id, "source-store");
    strcpy(m.target_store_id, "target-store");
    strcpy(m.replication_principal_id, "replication-service");
    strcpy(m.row_key, "row");
    strcpy(m.source_peer_qkp_id, "source-next");
    strcpy(m.target_peer_qkp_id, "target-next");
    memset(m.issuer_operator_pin, 1, 32);
    memset(m.source_peer_pin, 2, 32); memset(m.target_peer_pin, 3, 32);
    memset(m.frame_sha256, 4, 32); memset(m.baseline_sha256, 5, 32);
    memset(m.nonce, 6, 32);
    roster(m.source_files, source_names, QIHSE_CT1_RECOVERY_SOURCE_FILES);
    roster(m.target_files, target_names, QIHSE_CT1_RECOVERY_TARGET_FILES);
    m.epoch = 9; m.issued_ms = 1000; m.expires_ms = 901000;
    m.frame_offset = 1; m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 2; m.target_cursor = 1;
    m.target_high_water = 1; m.source_high_water = 1;
    m.row_change_seq = 1; m.tombstone_position = 1; m.tombstone_row_seq = 2;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    return m;
}

static qihse_ct1_authority_statement_t statement(const qihse_ct1_recovery_manifest_t *m,
    bool source) {
    qihse_ct1_authority_statement_t s = {0};
    strcpy(s.qkp_id, source ? m->source_peer_qkp_id : m->target_peer_qkp_id);
    strcpy(s.service_principal_id, m->replication_principal_id);
    memcpy(s.current_pin, source ? m->source_peer_pin : m->target_peer_pin, 32);
    return s;
}

int main(void) {
    qihse_ct1_recovery_manifest_t m = sample(), parsed, altered;
    qihse_ct1_authority_statement_t source = statement(&m, true),
        target = statement(&m, false), a, b, wrong;
    unsigned char challenge[QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE];
    unsigned char response[QIHSE_CT1_AUTHORITY_RESPONSE_SIZE], scratch[sizeof(response)];
    assert(sizeof(response) <= QIHSE_QKP_MAX_PAYLOAD);
    assert(qihse_ct1_authority_challenge_encode(&m, challenge));
    assert(qihse_ct1_authority_response_encode(&m, &source, &target, response));
    assert(qihse_ct1_authority_challenge_decode(challenge, sizeof(challenge), &parsed));
    assert(qihse_ct1_authority_response_decode(response, sizeof(response), &parsed, &a, &b));
    assert(!memcmp(&a, &source, sizeof(a)) && !memcmp(&b, &target, sizeof(b)));
    assert(qihse_ct1_authority_response_matches(challenge, sizeof(challenge),
        response, sizeof(response)));
    assert(!qihse_ct1_authority_approve(NULL, NULL, challenge, sizeof(challenge),
        response, sizeof(response)));
    assert(!qihse_ct1_authority_challenge_decode(challenge, sizeof(challenge) - 1, &parsed));
    assert(!qihse_ct1_authority_response_decode(response, sizeof(response) + 1,
        &parsed, &a, &b));
    assert(!qihse_ct1_authority_response_matches(challenge, sizeof(challenge),
        response, sizeof(response) - 1));
    memcpy(scratch, challenge, sizeof(challenge)); scratch[4]++;
    assert(!qihse_ct1_authority_challenge_decode(scratch, sizeof(challenge), &parsed));
    memcpy(scratch, challenge, sizeof(challenge)); scratch[5] = 2;
    assert(!qihse_ct1_authority_challenge_decode(scratch, sizeof(challenge), &parsed));
    memcpy(scratch, challenge, sizeof(challenge)); scratch[6] = 1;
    assert(!qihse_ct1_authority_challenge_decode(scratch, sizeof(challenge), &parsed));
    memcpy(scratch, challenge, sizeof(challenge)); scratch[11]++;
    assert(!qihse_ct1_authority_challenge_decode(scratch, sizeof(challenge), &parsed));
    memcpy(scratch, response, sizeof(response)); scratch[0] ^= 1;
    assert(!qihse_ct1_authority_response_decode(scratch, sizeof(response), &parsed, &a, &b));
    memcpy(scratch, response, sizeof(response));
    scratch[QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE + 130] ^= 1;
    assert(!qihse_ct1_authority_response_decode(scratch, sizeof(response), &parsed, &a, &b));
    memcpy(scratch, response, sizeof(response));
    scratch[QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE + QIHSE_CT1_AUTHORITY_STATEMENT_SIZE + 65] ^= 1;
    assert(!qihse_ct1_authority_response_decode(scratch, sizeof(response), &parsed, &a, &b));
    wrong = source; wrong.qkp_id[0] ^= 1;
    assert(!qihse_ct1_authority_response_encode(&m, &wrong, &target, scratch));
    wrong = target; wrong.current_pin[0] ^= 1;
    assert(!qihse_ct1_authority_response_encode(&m, &source, &wrong, scratch));
    altered = m; altered.nonce[0] ^= 1;
    a = statement(&altered, true); b = statement(&altered, false);
    assert(qihse_ct1_authority_response_encode(&altered, &a, &b, scratch));
    assert(!qihse_ct1_authority_response_matches(challenge, sizeof(challenge),
        scratch, sizeof(response)));
    /* Every byte of the canonical manifest, including its checksum, binds the pair. */
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_WIRE_SIZE; i++) {
        memcpy(scratch, response, sizeof(response));
        scratch[QIHSE_CT1_AUTHORITY_HEADER_SIZE + i] ^= 1;
        assert(!qihse_ct1_authority_response_matches(challenge, sizeof(challenge),
            scratch, sizeof(response)));
    }
    altered = m; altered.expires_ms++;
    assert(!qihse_ct1_authority_challenge_encode(&altered, challenge));
    assert(!qihse_ct1_authority_approve(NULL, NULL, NULL, 0, NULL, 0));
    puts("ct1 authority protocol structural checks passed (approval disabled)");
    return 0;
}
