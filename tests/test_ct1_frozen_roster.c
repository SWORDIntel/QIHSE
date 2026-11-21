/* Disposable CT1 fixture only: structural evidence, never recovery authority. */
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_ct1_node_quote.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_ct_codec.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include <assert.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char roster_auth_dir[] = "./ct1-roster-auth-XXXXXX";
static void cleanup_roster_auth(void) {
    DIR* dir = opendir(roster_auth_dir);
    if (!dir) return;
    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char path[256];
        int n = snprintf(path, sizeof(path), "%s/%s", roster_auth_dir,
            entry->d_name);
        assert(n > 0 && (size_t)n < sizeof(path) && unlink(path) == 0);
    }
    assert(closedir(dir) == 0 && rmdir(roster_auth_dir) == 0);
}

static void observed(const qihse_cluster_ownership_entry_t *entry, void *ctx) {
    const char *owner = ctx;
    assert(entry->start == 0 && entry->end == 16383 &&
           entry->config_epoch == 0 && strcmp(entry->owner_id, owner) == 0);
    puts("native ownership journal replay: observed assigned owner");
}

static int kind(const char *name) {
    if (!strcmp(name, "ct-baseline.qfs")) return QIHSE_CT1_FILE_BASELINE;
    if (!strcmp(name, "ct-state.bin")) return QIHSE_CT1_FILE_CT_STATE;
    if (!strcmp(name, "restore-highwater.bin")) return QIHSE_CT1_FILE_RESTORE_HIGHWATER;
    if (!strcmp(name, "slot-ownership.journal")) return QIHSE_CT1_FILE_SLOT_JOURNAL;
    if (!strcmp(name, "slot-ownership.journal.lock")) return QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK;
    if (!strcmp(name, "wal.log")) return QIHSE_CT1_FILE_WAL;
    return QIHSE_CT1_FILE_SSTABLE;
}

static void measure(const char *dir, qihse_ct1_recovery_file_t *file,
                    const char *name) {
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/%s", dir, name);
    assert(length > 0 && (size_t)length < sizeof(path));
    struct stat st;
    assert(lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           (st.st_mode & 07777) == 0600 && st.st_nlink == 1 && st.st_size >= 0);
    assert(strlen(name) < sizeof(file->filename));
    strcpy(file->filename, name);
    file->kind = (uint8_t)kind(name);
    file->size = (uint64_t)st.st_size;
    FILE *in = fopen(path, "rb");
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    assert(in && hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1);
    unsigned char block[16384];
    size_t n;
    while ((n = fread(block, 1, sizeof(block), in)))
        assert(EVP_DigestUpdate(hash, block, n) == 1);
    unsigned digest_length = 0;
    assert(!ferror(in) && fclose(in) == 0 &&
           EVP_DigestFinal_ex(hash, file->sha256, &digest_length) == 1 &&
           digest_length == 32);
    EVP_MD_CTX_free(hash);
}

static void roster(const char *dir, qihse_ct1_recovery_file_t *files,
                   const char *first, const char *second, bool source) {
    const char *names[8] = {"ct-state.bin", "restore-highwater.bin",
        "slot-ownership.journal", "slot-ownership.journal.lock",
        first, second, "wal.log"};
    if (source) {
        names[0] = "ct-baseline.qfs";
        names[1] = "ct-state.bin";
        names[2] = "restore-highwater.bin";
        names[3] = "slot-ownership.journal";
        names[4] = "slot-ownership.journal.lock";
        names[5] = first;
        names[6] = second;
        names[7] = "wal.log";
    }
    size_t count = source ? 8 : 7;
    for (size_t i = 0; i < count; i++) measure(dir, &files[i], names[i]);
}

static void hex32(const char *text, unsigned char out[32]) {
    assert(strlen(text) == 64);
    for (size_t i = 0; i < 32; ++i) {
        unsigned a, b;
        assert(sscanf(text + 2 * i, "%1x%1x", &a, &b) == 2);
        out[i] = (unsigned char)((a << 4) | b);
    }
}

static void pin(const char *path, unsigned char out[32]) {
    FILE *in = fopen(path, "rb");
    assert(in);
    EVP_PKEY *key = PEM_read_PUBKEY(in, NULL, NULL, NULL);
    assert(fclose(in) == 0 && key);
    int length = i2d_PUBKEY(key, NULL);
    assert(length > 0 && length < 8192);
    unsigned char *der = OPENSSL_malloc((size_t)length), *cursor = der;
    assert(der && i2d_PUBKEY(key, &cursor) == length);
    unsigned int digest_length = 0;
    assert(EVP_Digest(der, (size_t)length, out, &digest_length,
                      EVP_sha256(), NULL) == 1 && digest_length == 32);
    OPENSSL_clear_free(der, (size_t)length);
    EVP_PKEY_free(key);
}

static uint64_t decimal(const char *s) {
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);
    assert(end && *s && !*end);
    return (uint64_t)value;
}

static void manifest_source(qihse_ct1_recovery_manifest_t *m, char **argv) {
    const char *operator_password = getenv("QIHSE_OPERATOR_PASSWORD");
    assert(operator_password && qihse_auth_init());
    qihse_user_t *operator = qihse_auth_authenticate_id(0u, operator_password);
    assert(operator && qihse_auth_user_is_active(operator) &&
           qihse_user_get_role(operator) == QIHSE_ROLE_OPERATOR);
    /* The standalone fixture has its own in-process auth registry; provision
     * the same bounded service identity as the disposable daemon. */
    qihse_user_t *service = qihse_auth_create_user(operator, 65535u,
        QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX,
        "Ct1FrozenFixtureService28!", false);
    assert(service && qihse_auth_user_is_active(service) &&
           qihse_user_get_tenant_id(service) == QIHSE_TENANT_SYSTEM);
    strcpy(m->issuer_qkp_id, "ct-test-client");
    strcpy(m->source_store_id, m->source_qkp_id);
    strcpy(m->target_store_id, m->target_qkp_id);
    strcpy(m->row_key, "ct1:freeze:pending");
    pin(argv[9], m->target_peer_pin);
    pin(argv[10], m->source_peer_pin);
    pin(argv[11], m->issuer_operator_pin);
    m->baseline_row_seq = decimal(argv[12]);
    hex32(argv[13], m->baseline_sha256);
    uint64_t acknowledged = decimal(argv[14]);
    uint64_t durable = decimal(argv[15]);
    m->target_cursor = decimal(argv[16]);
    hex32(argv[17], m->nonce);
    assert(durable > acknowledged && m->target_cursor > 0);
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/wal.log", argv[2]);
    assert(n > 0 && (size_t)n < sizeof(path));
    FILE *wal = fopen(path, "rb");
    assert(wal);
    for (uint64_t position = acknowledged + 1; position <= durable; ++position) {
        off_t offset = ftello(wal);
        qihse_kv_ct_group_t group = {0};
        uint8_t mode = 0;
        size_t length = 0;
        assert(offset >= 0 && qihse_ct_codec_read(wal, service,
            QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, QIHSE_CT_CODEC_MAX_FRAME,
            &group, &mode, &length) == 1);
        assert(mode == QIHSE_CT_CODEC_MODE_SOURCE &&
               group.stream_position == position && group.count == 1 &&
               !strcmp(group.source_id, m->source_qkp_id) &&
               !strcmp(group.generation, m->generation));
        if (position == durable) {
            assert(length == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
                   !strcmp(group.records[0].key, m->row_key) &&
                   !group.records[0].tombstone);
            m->frame_offset = (uint64_t)offset;
            m->frame_length = length;
            m->frame_position = position;
            m->row_change_seq = group.records[0].change_seq;
            m->row_tenant_id = group.records[0].resource_tenant_id;
            m->classification = group.records[0].classification;
            m->sci = group.records[0].sci_compartment;
            m->source_high_water = group.last_seq;
            unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
            assert(fseeko(wal, offset, SEEK_SET) == 0 &&
                   fread(frame, 1, sizeof(frame), wal) == sizeof(frame) &&
                   EVP_Digest(frame, sizeof(frame), m->frame_sha256,
                       NULL, EVP_sha256(), NULL) == 1);
        }
        qihse_ct_codec_clear(&group);
    }
    assert(fgetc(wal) == EOF && !ferror(wal) && fclose(wal) == 0);
    m->principal_tenant_id = qihse_user_get_tenant_id(service);
    m->principal_classification = qihse_user_get_classification(service);
    m->principal_sci = qihse_user_get_sci(service);
    /* Decode the actual persisted receiver WAL, never synthesize target state
     * from the B manifest. The quote snapshot rechecks this under its lock. */
    n = snprintf(path, sizeof(path), "%s/wal.log", argv[3]);
    assert(n > 0 && (size_t)n < sizeof(path));
    wal = fopen(path, "rb");
    assert(wal);
    m->tombstone_position = 0;
    m->tombstone_row_seq = 0;
    m->target_high_water = 0;
    for (uint64_t position = 1; position <= m->target_cursor; ++position) {
        qihse_kv_ct_group_t group = {0};
        uint8_t mode = 0;
        size_t length = 0;
        assert(qihse_ct_codec_read(wal, service, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
            0u, QIHSE_CT_CODEC_MAX_FRAME, &group, &mode, &length) == 1);
        assert(mode == QIHSE_CT_CODEC_MODE_RECEIVER &&
               group.stream_position == position &&
               !strcmp(group.source_id, m->source_qkp_id) &&
               !strcmp(group.generation, m->generation));
        m->target_high_water = group.last_seq;
        for (size_t i = 0; i < group.count; ++i) {
            const qihse_kv_ct_record_t *row = &group.records[i];
            if (strcmp(row->key, m->row_key)) continue;
            m->tombstone_position = 0;
            m->tombstone_row_seq = 0;
            if (row->tombstone &&
                row->actor_kind != QIHSE_KV_CT_ACTOR_REPLICA &&
                row->resource_tenant_id == m->row_tenant_id &&
                row->classification == m->classification &&
                row->sci_compartment == m->sci && row->change_seq) {
                m->tombstone_position = position;
                m->tombstone_row_seq = row->change_seq;
            }
        }
        qihse_ct_codec_clear(&group);
    }
    assert(m->tombstone_position > 0 && m->tombstone_row_seq > 0 &&
           m->target_high_water > 0 &&
           fgetc(wal) == EOF && !ferror(wal) && fclose(wal) == 0);
    time_t now = time(NULL);
    assert(now > 0);
    m->epoch = 1; /* host commitment, not measured on source */
    m->issued_ms = (uint64_t)now * 1000u;
    m->expires_ms = m->issued_ms + QIHSE_CT1_RECOVERY_MAX_AGE_MS;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "seed")) {
        const char *password = getenv("QIHSE_OPERATOR_PASSWORD");
        assert(password && qihse_auth_init());
        (void)qihse_auth_bootstrap_operator(password);
        qihse_user_t *operator = qihse_auth_authenticate_id(0u, password);
        assert(operator);
        qihse_kv_store_t *store = qihse_kv_store_create_user(operator);
        assert(store && qihse_kv_set_user(store, "ct1:freeze:baseline",
            "protected-fixture-baseline", 5u, 1u, operator) &&
            qihse_kv_set_user(store, "ct1:freeze:pending",
                "before-tombstone", 0u, 0u, operator) &&
            qihse_kv_sync_store(store));
        qihse_kv_store_destroy(store);
        return 0;
    }
    if (argc == 7 && (!strcmp(argv[1], "quote") ||
                      !strcmp(argv[1], "quote-target"))) {
        unsigned char manifest[QIHSE_CT1_RECOVERY_WIRE_SIZE];
        unsigned char quote[QIHSE_CT1_NODE_QUOTE_SIZE], nonce[32];
        unsigned char source_pin[32], target_pin[32];
        FILE *in = fopen(argv[2], "rb");
        assert(in && fread(manifest, 1, sizeof(manifest), in) == sizeof(manifest) &&
               fgetc(in) == EOF && fclose(in) == 0);
        in = fopen(argv[3], "rb");
        assert(in && fread(quote, 1, sizeof(quote), in) == sizeof(quote) &&
               fgetc(in) == EOF && fclose(in) == 0);
        hex32(argv[6], nonce);
        pin(argv[4], source_pin);
        pin(argv[5], target_pin);
        if (!strcmp(argv[1], "quote-target")) {
            qihse_ct1_recovery_manifest_t m = {0};
            qihse_ct1_node_quote_expected_t expected = {0};
            assert(qihse_ct1_recovery_decode(manifest, sizeof(manifest),
                false, &m, NULL));
            strcpy(expected.source_qkp_id, "ct-primary");
            strcpy(expected.target_qkp_id, "ct-successor");
            strcpy(expected.source_peer_qkp_id, "ct-successor");
            strcpy(expected.target_peer_qkp_id, "ct-primary");
            strcpy(expected.replication_principal_id, "65535");
            strcpy(expected.generation, m.generation);
            memcpy(expected.source_signer_pin, source_pin, 32);
            memcpy(expected.target_signer_pin, target_pin, 32);
            memcpy(expected.source_peer_pin, target_pin, 32);
            memcpy(expected.target_peer_pin, source_pin, 32);
            memcpy(expected.baseline_sha256, m.baseline_sha256, 32);
            expected.target_cursor = m.target_cursor;
            expected.source_high_water = m.source_high_water;
            expected.target_high_water = m.target_high_water;
            assert(qihse_ct1_node_quote_verify_strict(quote, sizeof(quote),
                manifest, sizeof(manifest), QIHSE_CT1_NODE_QUOTE_TARGET,
                nonce, argv[5], &expected));
            assert(!qihse_ct1_node_quote_verify_strict(quote, sizeof(quote),
                manifest, sizeof(manifest), QIHSE_CT1_NODE_QUOTE_TARGET,
                nonce, argv[4], &expected));
            expected.target_high_water++;
            assert(!qihse_ct1_node_quote_verify_strict(quote, sizeof(quote),
                manifest, sizeof(manifest), QIHSE_CT1_NODE_QUOTE_TARGET,
                nonce, argv[5], &expected));
            puts("target quote strict signature verified");
        } else {
            assert(qihse_ct1_node_quote_verify(quote, sizeof(quote), manifest,
                sizeof(manifest), QIHSE_CT1_NODE_QUOTE_SOURCE, nonce, argv[4],
                source_pin, target_pin, "65535"));
            nonce[0] ^= 1;
            assert(!qihse_ct1_node_quote_verify(quote, sizeof(quote), manifest,
                sizeof(manifest), QIHSE_CT1_NODE_QUOTE_SOURCE, nonce, argv[4],
                source_pin, target_pin, "65535"));
            puts("source quote signature verified");
        }
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "tamper")) {
        unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
        qihse_ct1_recovery_manifest_t m = {0};
        FILE *in = fopen(argv[2], "rb");
        assert(in && fread(wire, 1, sizeof(wire), in) == sizeof(wire) &&
               fgetc(in) == EOF && fclose(in) == 0 &&
               qihse_ct1_recovery_decode(wire, sizeof(wire), false, &m, NULL));
        if (!strcmp(argv[4], "generation"))
            m.generation[0] = m.generation[0] == 'f' ? 'e' : 'f';
        else if (!strcmp(argv[4], "cursor")) m.target_cursor++;
        else if (!strcmp(argv[4], "highwater")) m.target_high_water++;
        else if (!strcmp(argv[4], "tombstone")) m.tombstone_position++;
        else if (!strcmp(argv[4], "tombstone-row-seq")) m.tombstone_row_seq++;
        else return 2;
        assert(qihse_ct1_recovery_encode(&m, false, false, wire));
        FILE *out = fopen(argv[3], "wb");
        assert(out && fwrite(wire, 1, sizeof(wire), out) == sizeof(wire) &&
               fclose(out) == 0);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "journal")) {
        /* The static topology already assigns this range to this owner. A
         * zero-epoch record does not claim promotion or new authority. */
        assert(qihse_cluster_ownership_journal_append(argv[2], 0, 16383,
                                                      argv[3], 0) == 0);
        assert(qihse_cluster_ownership_journal_replay(argv[2], observed,
                                                       argv[3]) == 1);
        return 0;
    }
    if ((argc != 9 && argc != 19) ||
        (strcmp(argv[1], "verify") && strcmp(argv[1], "manifest")) ||
        (argc == 19 && strcmp(argv[1], "manifest")) ||
        strlen(argv[8]) >= QIHSE_CT1_RECOVERY_ID_MAX) return 2;
    qihse_ct1_recovery_manifest_t m = {0}, decoded = {0};
    strcpy(m.issuer_qkp_id, "fixture-not-authority");
    strcpy(m.source_qkp_id, "ct-primary");
    strcpy(m.target_qkp_id, "ct-successor");
    strcpy(m.source_peer_qkp_id, "ct-successor");
    strcpy(m.target_peer_qkp_id, "ct-primary");
    strcpy(m.source_store_id, "fixture-source");
    strcpy(m.target_store_id, "fixture-target");
    strcpy(m.generation, argv[8]);
    strcpy(m.replication_principal_id, "65535");
    strcpy(m.row_key, "fixture-row");
    memset(m.issuer_operator_pin, 1, 32);
    memset(m.source_peer_pin, 2, 32);
    memset(m.target_peer_pin, 3, 32);
    memset(m.frame_sha256, 4, 32);
    memset(m.baseline_sha256, 5, 32);
    memset(m.nonce, 6, 32);
    m.epoch = m.issued_ms = m.frame_position = m.target_cursor = 1;
    m.expires_ms = 2;
    m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.source_high_water = m.target_high_water = m.row_change_seq =
        m.tombstone_position = m.tombstone_row_seq = 1;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    roster(argv[2], m.source_files, argv[4], argv[5], true);
    roster(argv[3], m.target_files, argv[6], argv[7], false);
    if (argc == 19) manifest_source(&m, argv);
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE], again[sizeof(wire)];
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    assert(qihse_ct1_recovery_decode(wire, sizeof(wire), false, &decoded, NULL));
    assert(qihse_ct1_recovery_encode(&decoded, false, false, again) &&
           memcmp(wire, again, sizeof(wire)) == 0);
    qihse_user_t* service;
    if (argc == 19) {
        /* manifest_source already initialized the disposable auth registry. */
        service = qihse_auth_get_user(65535u);
    } else {
        assert(mkdtemp(roster_auth_dir) &&
            atexit(cleanup_roster_auth) == 0 &&
            setenv("QIHSE_DATA_DIR", roster_auth_dir, 1) == 0 &&
            setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
        assert(qihse_auth_init());
        if (qihse_auth_is_operator_password_default())
            assert(qihse_auth_bootstrap_operator("Ct1FrozenRosterFixture1!"));
        const qihse_user_t* operator = qihse_auth_get_user(0);
        assert(operator);
        service = qihse_auth_create_user(operator, 62013,
            QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX,
            "Ct1FrozenRosterService1!", false);
    }
    assert(service);
    assert(qihse_ct1_recovery_verify_frozen(service, argv[2], &decoded, true));
    assert(qihse_ct1_recovery_verify_frozen(service, argv[3], &decoded, false));
    if (argc == 19) {
        FILE *out = fopen(argv[18], "wb");
        assert(out && fwrite(wire, 1, sizeof(wire), out) == sizeof(wire) &&
               fclose(out) == 0);
    }
    /* Never print wire or pins: the filler fields do not attest identity. */
    puts("native structural verifier: source 8/8, target 7/7 (no authority)");
    return 0;
}
