/* test_ct1_source_hold_resp.c - REPL.CT1 SOURCE HOLD-V1 RESP-level fixture.
 * A real QKP recovery peer installs the durable V2 custody hold on a
 * disposable CT1 source built through the public store API only (no
 * floor-test helpers). The retained frame is calibrated to the exact
 * QIHSE_CT1_RECOVERY_FRAME_BYTES so a shape-valid manifest can carry the
 * real quote facts. Every denial path is exercised before the single
 * admitted hold; the exact wire is then replayed and refused.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "qihse_auth.h"
#include "core/qihse_audit.h"
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_kv_store.h"
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"
#include "qihse_resp_wire.h"

#define GEN        "0123456789abcdef0123456789abcdef"
#define SOURCE_ID  "hold-primary"
#define TARGET_ID  "hold-successor"
#define ADMIN_ID   "hold-admin"
#define RECOVERY_ID "hold-recovery"
#define ROW_KEY    "ct1.hold-pending"

typedef struct { char dir[PATH_MAX], dsa[PATH_MAX], pub[PATH_MAX],
    kem[PATH_MAX], kem_pub[PATH_MAX]; } identity_t;

static int remove_entry(const char* path, const struct stat* st, int flag,
    struct FTW* buffer) {
    (void)st; (void)flag; (void)buffer;
    return remove(path);
}

static void make_identity(identity_t* id, const char* root, const char* name) {
    assert(snprintf(id->dir, sizeof(id->dir), "%s/%s", root, name) > 0);
    assert(mkdir(id->dir, 0700) == 0);
    assert(qihse_pqc_keygen(id->dir));
    assert(snprintf(id->dsa, sizeof(id->dsa), "%s/qihse_dsa_key.pem", id->dir) > 0);
    assert(snprintf(id->pub, sizeof(id->pub), "%s/qihse_dsa_pub.pem", id->dir) > 0);
    assert(snprintf(id->kem, sizeof(id->kem), "%s/qihse_kem_key.pem", id->dir) > 0);
    assert(snprintf(id->kem_pub, sizeof(id->kem_pub),
        "%s/qihse_kem_pub.pem", id->dir) > 0);
}

/* Mirrors the static qihse_resp_ct1_public_pin: ML-DSA-87 DER -> SHA-256. */
static bool public_pin(const char* path, unsigned char pin[32]) {
    if (!path || !*path) return false;
    FILE* file = fopen(path, "rb");
    if (!file) return false;
    EVP_PKEY* key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    if (!key) return false;
    int length = EVP_PKEY_is_a(key, "ML-DSA-87") ? i2d_PUBKEY(key, NULL) : -1;
    unsigned char* der = length > 0 && length <= 8192 ?
        OPENSSL_malloc((size_t)length) : NULL;
    unsigned char* cursor = der;
    bool ok = der && i2d_PUBKEY(key, &cursor) == length &&
        SHA256(der, (size_t)length, pin) != NULL;
    OPENSSL_clear_free(der, der ? (size_t)length : 0u);
    EVP_PKEY_free(key);
    return ok;
}

static uint64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
}

static void frozen_file(const char* root, const char* name, size_t size) {
    char path[PATH_MAX];
    assert(snprintf(path, sizeof(path), "%s/%s", root, name) > 0);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    for (size_t i = 0u; i < size; ++i) {
        unsigned char byte = (unsigned char)(i * 31u + 7u);
        assert(write(fd, &byte, 1u) == 1);
    }
    assert(fsync(fd) == 0 && close(fd) == 0);
}

static char* hold_wire_command(qihse_qkp_admin_client_t* client,
    const unsigned char* wire, char* error, size_t error_cap) {
    const char* argv[4] = {"REPL.CT1", "SOURCE", "HOLD-V1", (const char*)wire};
    const size_t lengths[4] = {8u, 6u, 7u, QIHSE_CT1_RECOVERY_WIRE_SIZE};
    char* reply = NULL;
    size_t reply_len = 0u;
    assert(qihse_qkp_admin_command(client, 4u, argv, lengths, &reply,
        &reply_len, error, error_cap) == 0 && reply && reply_len >= 2u);
    return reply;
}

static void expect_denied(qihse_qkp_admin_client_t* client,
    const unsigned char* wire, const char* label) {
    char error[256];
    char* reply = hold_wire_command(client, wire, error, sizeof(error));
    assert(reply[0] == '-' && !strstr(reply, "+OK"));
    qihse_qkp_admin_free(reply);
    printf("  denied: %s\n", label);
}

int main(void) {
    char root[] = "build/ct1-source-hold-XXXXXX";
    assert(mkdtemp(root));
    char data[PATH_MAX], frozen[PATH_MAX], frozen_abs[PATH_MAX];
    assert(snprintf(data, sizeof(data), "%s/data", root) > 0 &&
        snprintf(frozen, sizeof(frozen), "%s/frozen", root) > 0);
    assert(mkdir(data, 0700) == 0 && mkdir(frozen, 0700) == 0);
    assert(realpath(frozen, frozen_abs) == frozen_abs);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
    identity_t primary_id, admin_id, successor_id, recovery_id;
    make_identity(&primary_id, root, "primary-identity");
    make_identity(&admin_id, root, "admin-identity");
    make_identity(&successor_id, root, "successor-identity");
    make_identity(&recovery_id, root, "recovery-identity");

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("HoldRespOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "HoldRespOperator1!");
    assert(op && qihse_user_get_role(op) == QIHSE_ROLE_OPERATOR);
    qihse_user_t* service = qihse_auth_create_user(op, 8302u,
        QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX, "HoldRespService1!", false);
    assert(service && qihse_user_get_tenant_id(service) == QIHSE_TENANT_SYSTEM &&
        qihse_user_get_classification(service) == UINT16_MAX &&
        qihse_user_get_sci(service) == UINT16_MAX &&
        qihse_user_get_role(service) != QIHSE_ROLE_OPERATOR);

    qihse_kv_store_t* source = qihse_kv_store_create_user(op);
    assert(source);
    /* Preexisting history predating the CT binding, so the sealed baseline
     * carries a nonzero row sequence like the production source. */
    assert(qihse_kv_set_user(source, "ct1.preexisting", "baseline-history",
        2u, 1u, op));
    assert(qihse_kv_ct_source_enable(source, op, SOURCE_ID, TARGET_ID, GEN,
        NULL, 128u * 1024u * 1024u));
    qihse_kv_store_set_replication_principal_id(source,
        qihse_user_get_id(service));
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], baseline_digest[32];
    assert(qihse_kv_ct_owner_token_get(source, op, token));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t baseline_seq = 0u;
    assert(qihse_kv_ct_source_baseline_snapshot_create(source, op, &snapshot,
        &baseline_seq, baseline_digest) == 0 && snapshot && baseline_seq > 0u);
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(qihse_kv_ct_source_reconcile_peer(source, op, service, TARGET_ID,
        GEN, baseline_digest, 0u));

    /* Calibrate the retained frame to the exact production frame size by
     * sizing the pending row value. Every completed position is ACKed so the
     * final pending group keeps acknowledged == durable - 1. */
    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter(source, op, token, &scope));
    unsigned char* value = malloc(QIHSE_CT1_RECOVERY_FRAME_BYTES + 256u);
    assert(value);
    size_t value_len = 96u;
    uint64_t position = 0u, highwater = 0u, row_change_seq = 0u;
    uint32_t row_tenant = 0u;
    uint16_t row_class = 0u, row_sci = 0u;
    qihse_kv_ct_source_quote_snapshot_t quote = {0};
    for (unsigned attempt = 0u; attempt < 8u; ++attempt) {
        for (size_t i = 0u; i < value_len; ++i)
            value[i] = (unsigned char)('a' + (i * 7u) % 26u);
        value[value_len] = '\0';
        assert(qihse_kv_set_user(source, ROW_KEY, (const char*)value, 2u, 1u, op));
        ++position;
        if (position > 1u)
            assert(qihse_kv_ct_source_ack(source, service, TARGET_ID, GEN,
                position - 1u));
        qihse_kv_ct_group_t* groups = NULL;
        size_t count = 0u;
        uint64_t cursor = 0u;
        assert(qihse_kv_ct_source_read(source, op, GEN, position - 1u, 1u,
            65536u, &groups, &count, &cursor) && count == 1u &&
            cursor == position && groups[0].count == 1u &&
            strcmp(groups[0].records[0].key, ROW_KEY) == 0);
        qihse_kv_ct_record_t* row = &groups[0].records[0];
        qihse_kv_ct_source_retained_frame_request_t request = {
            .version = QIHSE_KV_CT_SOURCE_RETAINED_FRAME_V1,
            .size = sizeof(request), .source_id = SOURCE_ID,
            .successor_id = TARGET_ID, .generation = GEN,
            .baseline_row_seq = baseline_seq,
            .acknowledged_position = position - 1u,
            .durable_position = position, .stream_position = position,
            .key = row->key,
            .resource_tenant_id = row->resource_tenant_id,
            .classification = row->classification,
            .sci_compartment = row->sci_compartment,
            .row_change_seq = row->change_seq };
        memcpy(request.baseline_digest, baseline_digest, sizeof(baseline_digest));
        highwater = qihse_kv_change_seq(source);
        qihse_kv_ct_source_quote_snapshot_t next = {0};
        assert(qihse_kv_ct_source_quote_snapshot_v1(source, op, service,
            &request, highwater, &next) &&
            next.row_seq_high_water == highwater &&
            next.retained.frame_length >= 4u);
        bool done = next.retained.frame_length == QIHSE_CT1_RECOVERY_FRAME_BYTES;
        if (done) {
            quote = next;
            row_change_seq = row->change_seq;
            row_tenant = row->resource_tenant_id;
            row_class = row->classification;
            row_sci = row->sci_compartment;
        } else {
            long delta = (long)QIHSE_CT1_RECOVERY_FRAME_BYTES -
                (long)next.retained.frame_length;
            assert((long)value_len + delta > 0L &&
                (size_t)((long)value_len + delta) <=
                    QIHSE_CT1_RECOVERY_FRAME_BYTES + 128u);
            value_len = (size_t)((long)value_len + delta);
            free(next.retained.frame);
            free(next.retained.key);
        }
        qihse_kv_ct_groups_free(groups, count);
        if (done) break;
    }
    free(value);
    assert(quote.retained.frame_length == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        position >= 1u && row_change_seq > 0u && highwater > 0u);
    printf("  fixture: frame %zu bytes at position %llu offset %llu\n",
        quote.retained.frame_length, (unsigned long long)position,
        (unsigned long long)quote.frame_offset);

    unsigned char own_pin[32], peer_pin[32], issuer_pin[32];
    assert(public_pin(primary_id.pub, own_pin) &&
        public_pin(successor_id.pub, peer_pin) &&
        public_pin(admin_id.pub, issuer_pin) &&
        memcmp(own_pin, peer_pin, 32u) != 0);

    /* Frozen source roster: eight exact private files, name-sorted. */
    static const struct { const char* name; size_t size; } roster[] = {
        {"ct-baseline.qfs", 512u}, {"ct-state.bin", 256u},
        {"restore-highwater.bin", 64u}, {"slot-ownership.journal", 128u},
        {"slot-ownership.journal.lock", 0u}, {"sstable_1.db", 1024u},
        {"sstable_2.db", 1024u}, {"wal.log", 1644u}};
    unsigned char empty_sha[32], file_sha[8][32];
    assert(SHA256((const unsigned char*)"", 0u, empty_sha));
    for (size_t i = 0u; i < 8u; ++i) {
        frozen_file(frozen_abs, roster[i].name, roster[i].size);
        char path[PATH_MAX];
        assert(snprintf(path, sizeof(path), "%s/%s", frozen_abs,
            roster[i].name) > 0);
        if (roster[i].size == 0u) {
            memcpy(file_sha[i], empty_sha, 32u);
            continue;
        }
        FILE* file = fopen(path, "rb");
        assert(file);
        unsigned char body[2048];
        assert(fread(body, 1u, roster[i].size, file) == roster[i].size);
        fclose(file);
        assert(SHA256(body, roster[i].size, file_sha[i]));
    }

    qihse_ct1_recovery_manifest_t m;
    memset(&m, 0, sizeof(m));
    strcpy(m.issuer_qkp_id, ADMIN_ID);
    strcpy(m.source_qkp_id, SOURCE_ID);
    strcpy(m.target_qkp_id, TARGET_ID);
    strcpy(m.generation, GEN);
    strcpy(m.source_store_id, SOURCE_ID);
    strcpy(m.target_store_id, TARGET_ID);
    assert(snprintf(m.replication_principal_id,
        sizeof(m.replication_principal_id), "%u",
        qihse_user_get_id(service)) > 0);
    strcpy(m.row_key, ROW_KEY);
    strcpy(m.source_peer_qkp_id, TARGET_ID);
    strcpy(m.target_peer_qkp_id, SOURCE_ID);
    memcpy(m.issuer_operator_pin, issuer_pin, 32u);
    memcpy(m.source_peer_pin, peer_pin, 32u);
    memcpy(m.target_peer_pin, own_pin, 32u);
    memcpy(m.frame_sha256, quote.retained.frame_sha256, 32u);
    memcpy(m.baseline_sha256, baseline_digest, 32u);
    for (size_t i = 0u; i < 32u; ++i) m.nonce[i] = (unsigned char)(i + 1u);
    m.epoch = 1u;
    uint64_t now = now_ms();
    m.issued_ms = now - 1000u;
    m.expires_ms = now + 599000u;
    m.frame_offset = quote.frame_offset;
    m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = position;
    m.baseline_row_seq = baseline_seq;
    m.target_cursor = 1u;
    m.target_high_water = 1u;
    m.source_high_water = highwater;
    m.row_change_seq = row_change_seq;
    m.tombstone_position = 1u;
    m.tombstone_row_seq = 1u;
    m.row_tenant_id = row_tenant;
    m.principal_tenant_id = qihse_user_get_tenant_id(service);
    m.classification = row_class;
    m.sci = row_sci;
    m.principal_classification = UINT16_MAX;
    m.principal_sci = UINT16_MAX;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    static const uint8_t kinds[8] = {
        QIHSE_CT1_FILE_BASELINE, QIHSE_CT1_FILE_CT_STATE,
        QIHSE_CT1_FILE_RESTORE_HIGHWATER, QIHSE_CT1_FILE_SLOT_JOURNAL,
        QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK, QIHSE_CT1_FILE_SSTABLE,
        QIHSE_CT1_FILE_SSTABLE, QIHSE_CT1_FILE_WAL};
    for (size_t i = 0u; i < 8u; ++i) {
        m.source_files[i].kind = kinds[i];
        strcpy(m.source_files[i].filename, roster[i].name);
        m.source_files[i].size = roster[i].size;
        memcpy(m.source_files[i].sha256, file_sha[i], 32u);
    }
    for (size_t i = 0u, t = 0u; i < 8u; ++i) {
        if (kinds[i] == QIHSE_CT1_FILE_BASELINE) continue;
        m.target_files[t++] = m.source_files[i];
    }
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = source;
    config.port = 0u;
    config.auth_required = true;
    config.replication_service_principal = service;
    config.ct_role = "primary";
    config.ct_peer_host = "127.0.0.1";
    config.ct_peer_port = 6390u;
    config.ct_generation_hex = GEN;
    config.ct_log_limit_bytes = 128u * 1024u * 1024u;
    config.ct_ack_timeout_ms = 1000u;
    config.ct_owner_token = token;
    config.ct_control_principal = op;
    config.ct1_recovery_frozen_root = frozen_abs;
    config.ct1_recovery_replication_principal_id = qihse_user_get_id(service);
    config.pqc.require = true;
    config.pqc.node_id = SOURCE_ID;
    config.pqc.dsa_key_path = primary_id.dsa;
    config.pqc.kem_key_path = primary_id.kem;
    config.pqc.kem_pub_path = primary_id.kem_pub;
    config.pqc.admin_peer_node_id = ADMIN_ID;
    config.pqc.admin_peer_dsa_pub_path = admin_id.pub;
    config.pqc.replication_peer_node_id = TARGET_ID;
    config.pqc.replication_peer_dsa_pub_path = successor_id.pub;
    config.pqc.recovery_peer_node_id = RECOVERY_ID;
    config.pqc.recovery_peer_dsa_pub_path = recovery_id.pub;
    const char* trusted[] = {successor_id.pub, admin_id.pub, recovery_id.pub};
    config.pqc.trusted_pubs = trusted;
    config.pqc.trusted_count = 3u;
    assert(qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server && qihse_resp_server_start(server));
    uint16_t port = qihse_resp_server_port(server);

    char error[256];
    qihse_qkp_admin_client_t* recovery = NULL;
    assert(qihse_qkp_admin_open("127.0.0.1", port, RECOVERY_ID, recovery_id.dir,
        primary_id.pub, 30000u, &recovery, error, sizeof(error)) == 0);

    /* Denial battery: each variant is independently refused and leaves no
     * hold installed. */
    {
        const char* ping[] = {"PING"};
        char* reply = NULL;
        size_t reply_len = 0u;
        assert(qihse_qkp_admin_command(recovery, 1u, ping, NULL, &reply,
            &reply_len, error, sizeof(error)) == 0);
        assert(reply && strstr(reply, "NOPERM"));
        qihse_qkp_admin_free(reply);
        printf("  denied: PING outside the single HOLD exception\n");
    }
    {
        unsigned char bad[QIHSE_CT1_RECOVERY_WIRE_SIZE];
        memcpy(bad, wire, sizeof(bad));
        bad[1500] ^= 1u; /* breaks the integral trailer on re-decode */
        expect_denied(recovery, bad, "tampered wire (trailer integrity)");
        qihse_ct1_recovery_manifest_t v = m;
        v.issued_ms = now - 800000u;
        v.expires_ms = now - 200000u;
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        expect_denied(recovery, bad, "expired manifest window");
        v = m;
        strcpy(v.generation, "ffffffffffffffffffffffffffffffff");
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        expect_denied(recovery, bad, "wrong generation");
        v = m;
        v.issuer_operator_pin[0] ^= 1u;
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        expect_denied(recovery, bad, "wrong issuer operator pin");
        v = m;
        v.frame_sha256[0] ^= 1u;
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        expect_denied(recovery, bad, "wrong pinned frame digest");
        v = m;
        v.source_high_water = highwater + 1u;
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        expect_denied(recovery, bad, "wrong source high-water");
        v = m;
        v.row_change_seq = row_change_seq + 1u;
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        expect_denied(recovery, bad, "wrong row change sequence");
    }
    {   /* Frozen roster no longer matches the pinned digest roster. */
        char path[PATH_MAX];
        assert(snprintf(path, sizeof(path), "%s/ct-state.bin", frozen_abs) > 0);
        int fd = open(path, O_RDWR | O_CLOEXEC);
        unsigned char byte;
        assert(fd >= 0 && pread(fd, &byte, 1u, 0u) == 1);
        unsigned char changed = byte ^ 1u;
        assert(pwrite(fd, &changed, 1u, 0u) == 1 && fsync(fd) == 0);
        expect_denied(recovery, wire, "frozen roster digest mismatch");
        assert(pwrite(fd, &byte, 1u, 0u) == 1 && fsync(fd) == 0 && close(fd) == 0);
    }
    {   /* The data-plane successor peer is not the recovery identity. */
        qihse_qkp_admin_client_t* successor = NULL;
        assert(qihse_qkp_admin_open("127.0.0.1", port, TARGET_ID,
            successor_id.dir, primary_id.pub, 30000u, &successor, error,
            sizeof(error)) == 0);
        char* reply = hold_wire_command(successor, wire, error, sizeof(error));
        assert(reply[0] == '-' && !strstr(reply, "+OK"));
        qihse_qkp_admin_free(reply);
        qihse_qkp_admin_close(successor);
        printf("  denied: successor peer outside recovery identity\n");
    }

    /* The single admitted hold. */
    {
        char* reply = hold_wire_command(recovery, wire, error, sizeof(error));
        assert(reply[0] == '+' && strstr(reply, "OK"));
        qihse_qkp_admin_free(reply);
        printf("  admitted: exact tuple installed the durable V2 hold\n");
    }
    /* Replay of the identical admitted wire must be refused. */
    expect_denied(recovery, wire, "replay of the admitted hold");

    qihse_qkp_admin_close(recovery);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    free(quote.retained.frame);
    free(quote.retained.key);
    qihse_kv_store_destroy(source);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CT1 SOURCE HOLD-V1 RESP-level fixture: OK");
    return 0;
}
