/* test_ct1_target_disposition_resp.c - REPL.CT1 TARGET DISPOSITION-V1.
 * A real QKP recovery peer commits the archived, epoch-fenced suppression
 * on a disposable successor built through the public API only. Every
 * admission mismatch is refused before persistence, the one admitted
 * commit advances the cursor without applying the old SET, and the exact
 * wire replayed is refused.
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
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "qihse_auth.h"
#include "core/qihse_audit.h"
#include "qihse_cluster_failover.h"
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_ct_codec.h"
#include "qihse_kv_store.h"
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"
#include "qihse_resp_wire.h"

#define GEN        "0123456789abcdef0123456789abcdef"
#define SOURCE_ID  "hold-primary"
#define TARGET_ID  "hold-successor"
#define ADMIN_ID   "hold-admin"
#define RECOVERY_ID "hold-recovery"
#define FULL_KEY   "commons/ct1.hold-pending"
#define ROW_KEY    "ct1.hold-pending"
#define CURSOR     7u
#define PENDING    8u

typedef struct { char dir[PATH_MAX], dsa[PATH_MAX], pub[PATH_MAX],
    kem[PATH_MAX], kem_pub[PATH_MAX]; } identity_t;

static int remove_entry(const char* path, const struct stat* st, int flag,
    struct FTW* buffer) {
    (void)st; (void)flag; (void)buffer;
    return remove(path);
}

static void make_identity(identity_t* id, const char* root, const char* name) {
    assert(snprintf(id->dir, sizeof(id->dir), "%s/%s", root, name) > 0);
    assert(mkdir(id->dir, 0700) == 0 && qihse_pqc_keygen(id->dir));
    assert(snprintf(id->dsa, sizeof(id->dsa), "%s/qihse_dsa_key.pem", id->dir) > 0);
    assert(snprintf(id->pub, sizeof(id->pub), "%s/qihse_dsa_pub.pem", id->dir) > 0);
    assert(snprintf(id->kem, sizeof(id->kem), "%s/qihse_kem_key.pem", id->dir) > 0);
    assert(snprintf(id->kem_pub, sizeof(id->kem_pub),
        "%s/qihse_kem_pub.pem", id->dir) > 0);
}

static bool public_pin(const char* path, unsigned char pin[32]) {
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

static bool topo_qkp_id(void* context, const char* topology_id,
    char out[QIHSE_QKP_NODE_ID_LEN + 1u]) {
    (void)context;
    if (!topology_id || !*topology_id) return false;
    snprintf(out, QIHSE_QKP_NODE_ID_LEN + 1u, "%s", topology_id);
    return true;
}

static int mint_baseline_process(const char* src_dir) {
    char data_dir[PATH_MAX];
    assert(snprintf(data_dir, PATH_MAX, "%s/data", src_dir) > 0);
    assert(mkdir(src_dir, 0700) == 0 && mkdir(data_dir, 0700) == 0 &&
        setenv("QIHSE_DATA_DIR", data_dir, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("DispRespOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "DispRespOperator1!");
    assert(op);
    qihse_kv_store_t* source = qihse_kv_store_create_user(op);
    assert(source && qihse_kv_set_user(source, "ct1.preexisting",
        "baseline-history", 2u, 1u, op) && qihse_kv_sync_store(source));
    assert(qihse_kv_ct_source_enable(source, op, SOURCE_ID, TARGET_ID, GEN,
        NULL, 128u * 1024u * 1024u));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t seq = 0u;
    unsigned char digest[32];
    assert(qihse_kv_ct_source_baseline_snapshot_create(source, op, &snapshot,
        &seq, digest) == 0 && snapshot && seq > 0u);
    qihse_kv_replica_snapshot_destroy(snapshot);
    qihse_kv_store_destroy(source);
    char baseline_path[PATH_MAX], meta_path[PATH_MAX];
    assert(snprintf(baseline_path, PATH_MAX, "%s/ct-baseline.qfs",
        data_dir) > 0 && snprintf(meta_path, PATH_MAX, "%s/baseline.meta",
        data_dir) > 0);
    unsigned char meta[40];
    for (unsigned i = 0u; i < 8u; ++i)
        meta[i] = (unsigned char)(seq >> (8u * i));
    memcpy(meta + 8u, digest, 32u);
    int fd = open(meta_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, meta, sizeof(meta)) == (ssize_t)sizeof(meta) &&
        fsync(fd) == 0 && close(fd) == 0);
    qihse_audit_shutdown();
    return 0;
}

static void frozen_roster(const char* frozen) {
    static const struct { const char* name; size_t size; } roster[] = {
        {"ct-baseline.qfs", 512u}, {"ct-state.bin", 256u},
        {"restore-highwater.bin", 64u}, {"slot-ownership.journal", 128u},
        {"slot-ownership.journal.lock", 0u}, {"sstable_11321.db", 1024u},
        {"sstable_11322.db", 1024u}, {"wal.log", 1644u}};
    for (size_t i = 0u; i < 8u; ++i) {
        char path[PATH_MAX];
        assert(snprintf(path, PATH_MAX, "%s/%s", frozen, roster[i].name) > 0);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(fd >= 0);
        for (size_t b = 0u; b < roster[i].size; ++b) {
            unsigned char byte = (unsigned char)(b * 31u + 7u);
            assert(write(fd, &byte, 1u) == 1);
        }
        assert(fsync(fd) == 0 && close(fd) == 0);
    }
}

static char* disposition_command(qihse_qkp_admin_client_t* client,
    const unsigned char* wire, const unsigned char* frame, size_t frame_len,
    char* error, size_t error_cap) {
    const char* argv[5] = {"REPL.CT1", "TARGET", "DISPOSITION-V1",
        (const char*)wire, (const char*)frame};
    const size_t lengths[5] = {8u, 6u, 14u, QIHSE_CT1_RECOVERY_WIRE_SIZE,
        frame_len};
    char* reply = NULL;
    size_t reply_len = 0u;
    assert(qihse_qkp_admin_command(client, 5u, argv, lengths, &reply,
        &reply_len, error, error_cap) == 0 && reply && reply_len >= 2u);
    return reply;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3 && strcmp(argv[1], "mint") == 0)
        return mint_baseline_process(argv[2]);
    assert(argc == 1);
    char root[] = "build/ct1-target-disposition-resp-XXXXXX";
    assert(mkdtemp(root));
    char rx[PATH_MAX], frozen[PATH_MAX], frozen_abs[PATH_MAX];
    assert(snprintf(rx, PATH_MAX, "%s/rx", root) > 0 &&
        snprintf(frozen, PATH_MAX, "%s/frozen", root) > 0);
    assert(mkdir(rx, 0700) == 0 && mkdir(frozen, 0700) == 0 &&
        realpath(frozen, frozen_abs) == frozen_abs);
    assert(setenv("QIHSE_DATA_DIR", rx, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
    identity_t successor_id, admin_id, source_id, recovery_id;
    make_identity(&successor_id, root, "successor-identity");
    make_identity(&admin_id, root, "admin-identity");
    make_identity(&source_id, root, "source-identity");
    make_identity(&recovery_id, root, "recovery-identity");

    char mint_dir[PATH_MAX];
    assert(snprintf(mint_dir, PATH_MAX, "%s/src", root) > 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        execl(argv[0], argv[0], "mint", mint_dir, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("DispRespOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "DispRespOperator1!");
    assert(op);
    qihse_user_t* service = qihse_auth_create_user(op, 8302u,
        QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX, "DispRespService1!", false);
    assert(service && qihse_user_get_tenant_id(service) == QIHSE_TENANT_SYSTEM);

    /* Receiver at cursor CURSOR with the retained same-key tombstone. */
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, 8302u);
    char baseline_path[PATH_MAX], meta_path[PATH_MAX];
    assert(snprintf(baseline_path, PATH_MAX, "%s/src/data/ct-baseline.qfs",
        root) > 0 && snprintf(meta_path, PATH_MAX, "%s/src/data/baseline.meta",
        root) > 0);
    unsigned char meta[40];
    int fd = open(meta_path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && read(fd, meta, sizeof(meta)) == (ssize_t)sizeof(meta));
    close(fd);
    uint64_t seq = 0u;
    for (unsigned i = 0u; i < 8u; ++i)
        seq |= (uint64_t)meta[i] << (8u * i);
    unsigned char digest[32];
    memcpy(digest, meta + 8u, 32u);
    assert(qihse_kv_ct_receiver_bind(store, op, SOURCE_ID, TARGET_ID, GEN,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, seq, NULL));
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_owner_token_get(store, op, token) &&
        qihse_kv_ct_receiver_install_baseline(store, op, service, SOURCE_ID,
            GEN, baseline_path, seq, digest, token));
    uint64_t cursor = 0u, tombstone_seq = 0u;
    for (unsigned pos = 1u; pos <= CURSOR; ++pos) {
        bool tomb = pos == 3u;
        const char* key = (pos == 1u || tomb) ? FULL_KEY : "commons/unrelated";
        qihse_kv_ct_record_t row = {
            .key = (char*)key, .value = tomb ? NULL : "fixture-value",
            .change_seq = seq + pos, .resource_tenant_id = 0u,
            .classification = 4u, .sci_compartment = 2u,
            .actor_kind = QIHSE_KV_CT_ACTOR_USER, .tombstone = tomb};
        qihse_kv_ct_group_t group = {
            .stream_position = pos, .first_seq = row.change_seq,
            .last_seq = row.change_seq, .records = &row, .count = 1u};
        strcpy(group.source_id, SOURCE_ID);
        strcpy(group.generation, GEN);
        assert(qihse_kv_ct_receiver_apply(store, service, &group, &cursor) &&
            cursor == pos);
        if (tomb) tombstone_seq = row.change_seq;
    }
    uint64_t high_water = qihse_kv_change_seq(store);

    /* Exact 1644-byte SOURCE frame for the pending position. */
    unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    char* padded = malloc(2000);
    assert(padded);
    memset(padded, 'x', 1999);
    padded[1999] = 0;
    padded[1] = 0;
    qihse_kv_ct_record_t frame_row = {
        .key = (char*)FULL_KEY, .value = padded, .change_seq = seq + 1u,
        .resource_tenant_id = 0u, .classification = 4u,
        .sci_compartment = 2u, .actor_kind = QIHSE_KV_CT_ACTOR_USER};
    qihse_kv_ct_group_t frame_group = {
        .stream_position = PENDING, .first_seq = frame_row.change_seq,
        .last_seq = frame_row.change_seq, .records = &frame_row, .count = 1u};
    strcpy(frame_group.source_id, SOURCE_ID);
    strcpy(frame_group.generation, GEN);
    size_t encoded = 0u;
    assert(qihse_ct_codec_encoded_size(op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
        QIHSE_CT_CODEC_MODE_SOURCE, &frame_group, 65536u, &encoded));
    size_t payload = QIHSE_CT1_RECOVERY_FRAME_BYTES - encoded + 1u;
    padded[1] = 'x';
    padded[payload] = 0;
    FILE* tmp = tmpfile();
    size_t written = 0u;
    assert(tmp && qihse_ct_codec_write(tmp, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0u, QIHSE_CT_CODEC_MODE_SOURCE, &frame_group, 65536u, &written) &&
        written == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        fseek(tmp, 0, SEEK_SET) == 0 &&
        fread(frame, 1u, sizeof(frame), tmp) == sizeof(frame));
    fclose(tmp);
    free(padded);
    unsigned char frame_sha[32], wire_sha[32];
    assert(SHA256(frame, sizeof(frame), frame_sha) &&
        frame[9] == QIHSE_KV_CT_TENANT_SYSTEM_ALL);

    /* Manifest with the target-side identity directions. */
    qihse_ct1_recovery_manifest_t m;
    memset(&m, 0, sizeof(m));
    unsigned char own_pin[32], peer_pin[32], issuer_pin[32];
    assert(public_pin(successor_id.pub, own_pin) &&
        public_pin(source_id.pub, peer_pin) &&
        public_pin(admin_id.pub, issuer_pin));
    strcpy(m.issuer_qkp_id, ADMIN_ID);
    strcpy(m.target_qkp_id, TARGET_ID);
    strcpy(m.source_qkp_id, SOURCE_ID);
    strcpy(m.target_store_id, TARGET_ID);
    strcpy(m.source_store_id, SOURCE_ID);
    strcpy(m.generation, GEN);
    strcpy(m.replication_principal_id, "8302");
    strcpy(m.row_key, ROW_KEY);
    strcpy(m.target_peer_qkp_id, SOURCE_ID);
    strcpy(m.source_peer_qkp_id, TARGET_ID);
    memcpy(m.issuer_operator_pin, issuer_pin, 32u);
    memcpy(m.target_peer_pin, peer_pin, 32u);
    memcpy(m.source_peer_pin, own_pin, 32u);
    memcpy(m.frame_sha256, frame_sha, 32u);
    memcpy(m.baseline_sha256, digest, 32u);
    for (size_t i = 0u; i < 32u; ++i) m.nonce[i] = (unsigned char)(i + 1u);
    static const char* const src_files[] = {"ct-baseline.qfs", "ct-state.bin",
        "restore-highwater.bin", "slot-ownership.journal",
        "slot-ownership.journal.lock", "sstable_11321.db",
        "sstable_11322.db", "wal.log"};
    for (size_t i = 0u; i < 8u; ++i) {
        m.source_files[i].kind =
            strstr(src_files[i], "baseline") ? QIHSE_CT1_FILE_BASELINE :
            strstr(src_files[i], "ct-state") ? QIHSE_CT1_FILE_CT_STATE :
            strstr(src_files[i], "restore") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            strstr(src_files[i], "journal.lock") ?
                QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            strstr(src_files[i], "journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            strstr(src_files[i], "sstable") ? QIHSE_CT1_FILE_SSTABLE :
            QIHSE_CT1_FILE_WAL;
        strcpy(m.source_files[i].filename, src_files[i]);
        if (m.source_files[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK) {
            m.source_files[i].size = 0u;
            assert(SHA256((const unsigned char*)"", 0u,
                m.source_files[i].sha256));
        } else {
            m.source_files[i].size = 64u + i * 16u;
            memset(m.source_files[i].sha256, (int)(i + 1u), 32u);
        }
    }
    for (size_t i = 0u, t = 0u; i < 8u; ++i) {
        if (m.source_files[i].kind == QIHSE_CT1_FILE_BASELINE) continue;
        m.target_files[t++] = m.source_files[i];
    }
    uint64_t now = now_ms();
    m.epoch = 9u;
    m.issued_ms = now - 1000u;
    m.expires_ms = now + 599000u;
    m.frame_offset = 400u;
    m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = PENDING;
    m.target_cursor = CURSOR;
    m.target_high_water = high_water;
    m.source_high_water = seq + 1u;
    m.row_change_seq = seq + 1u;
    m.tombstone_position = 3u;
    m.tombstone_row_seq = tombstone_seq;
    m.baseline_row_seq = seq;
    m.row_tenant_id = 0u;
    m.principal_tenant_id = 0u;
    m.classification = 4u;
    m.sci = 2u;
    m.principal_classification = UINT16_MAX;
    m.principal_sci = UINT16_MAX;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    assert(qihse_ct1_recovery_encode(&m, false, false, wire) &&
        SHA256(wire, sizeof(wire), wire_sha));

    /* Store-level epoch fence binding the same facts. */
    qihse_kv_ct_target_epoch_fence_request_t fence_request;
    memset(&fence_request, 0, sizeof(fence_request));
    fence_request.version = QIHSE_KV_CT_TARGET_EPOCH_FENCE_V1;
    fence_request.size = sizeof(fence_request);
    fence_request.key = FULL_KEY;
    strcpy(fence_request.source_id, SOURCE_ID);
    strcpy(fence_request.target_id, TARGET_ID);
    strcpy(fence_request.generation, GEN);
    memcpy(fence_request.baseline_digest, digest, 32u);
    memcpy(fence_request.manifest_sha256, wire_sha, 32u);
    memcpy(fence_request.frame_sha256, frame_sha, 32u);
    fence_request.baseline_row_seq = seq;
    fence_request.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    fence_request.pending_position = PENDING;
    fence_request.durable_cursor = CURSOR;
    fence_request.target_high_water = high_water;
    fence_request.tombstone_row_seq = tombstone_seq;
    fence_request.tombstone_position = 3u;
    fence_request.resource_tenant_id = 0u;
    fence_request.classification = 4u;
    fence_request.sci_compartment = 2u;
    uint64_t epoch = 0u;
    assert(qihse_kv_ct_target_epoch_fence_install_pinned_v1(store, op,
        service, &fence_request, &epoch) && epoch == 1u);
    frozen_roster(frozen_abs);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0u;
    config.auth_required = true;
    config.replication_service_principal = service;
    config.ct_role = "successor";
    config.ct_peer_host = "127.0.0.1";
    config.ct_peer_port = 6390u;
    config.ct_generation_hex = GEN;
    config.ct_log_limit_bytes = 128u * 1024u * 1024u;
    config.ct_ack_timeout_ms = 1000u;
    config.ct_control_principal = op;
    config.ct_topology_qkp_id = topo_qkp_id;
    config.ct1_recovery_frozen_root = frozen_abs;
    config.ct1_recovery_replication_principal_id = qihse_user_get_id(service);
    config.pqc.require = true;
    config.pqc.node_id = TARGET_ID;
    config.pqc.dsa_key_path = successor_id.dsa;
    config.pqc.kem_key_path = successor_id.kem;
    config.pqc.kem_pub_path = successor_id.kem_pub;
    config.pqc.admin_peer_node_id = ADMIN_ID;
    config.pqc.admin_peer_dsa_pub_path = admin_id.pub;
    config.pqc.replication_peer_node_id = SOURCE_ID;
    config.pqc.replication_peer_dsa_pub_path = source_id.pub;
    config.pqc.recovery_peer_node_id = RECOVERY_ID;
    config.pqc.recovery_peer_dsa_pub_path = recovery_id.pub;
    const char* trusted[] = {source_id.pub, admin_id.pub, recovery_id.pub};
    config.pqc.trusted_pubs = trusted;
    config.pqc.trusted_count = 3u;
    assert(qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server && qihse_resp_server_start(server));
    uint16_t port = qihse_resp_server_port(server);

    char error[256];
    qihse_qkp_admin_client_t* recovery = NULL;
    assert(qihse_qkp_admin_open("127.0.0.1", port, RECOVERY_ID, recovery_id.dir,
        successor_id.pub, 30000u, &recovery, error, sizeof(error)) == 0);

    /* Denial battery: nothing persists before the single admitted commit. */
    {
        const char* ping[] = {"PING"};
        char* reply = NULL;
        size_t reply_len = 0u;
        assert(qihse_qkp_admin_command(recovery, 1u, ping, NULL, &reply,
            &reply_len, error, sizeof(error)) == 0);
        assert(reply && strstr(reply, "NOPERM"));
        qihse_qkp_admin_free(reply);
        printf("  denied: PING outside the two recovery commands\n");
    }
    {   /* The primary-side hold command has no place on a successor. */
        const char* argv[4] = {"REPL.CT1", "SOURCE", "HOLD-V1",
            (const char*)wire};
        const size_t lengths[4] = {8u, 6u, 7u, QIHSE_CT1_RECOVERY_WIRE_SIZE};
        char* reply = NULL;
        size_t reply_len = 0u;
        assert(qihse_qkp_admin_command(recovery, 4u, argv, lengths, &reply,
            &reply_len, error, sizeof(error)) == 0);
        assert(reply && reply[0] == '-' && !strstr(reply, "+OK"));
        qihse_qkp_admin_free(reply);
        printf("  denied: SOURCE HOLD-V1 on a successor role\n");
    }
    {
        unsigned char bad[QIHSE_CT1_RECOVERY_FRAME_BYTES];
        memcpy(bad, frame, sizeof(bad));
        bad[100] ^= 1u;
        char* reply = disposition_command(recovery, wire, bad, sizeof(bad),
            error, sizeof(error));
        assert(reply[0] == '-');
        qihse_qkp_admin_free(reply);
        printf("  denied: frame bytes disagree with the pinned digest\n");
    }
    {
        unsigned char bad[QIHSE_CT1_RECOVERY_WIRE_SIZE];
        qihse_ct1_recovery_manifest_t v = m;
        v.target_high_water = high_water + 1u;
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        char* reply = disposition_command(recovery, bad, frame,
            sizeof(frame), error, sizeof(error));
        assert(reply[0] == '-');
        qihse_qkp_admin_free(reply);
        printf("  denied: wrong target high-water\n");
        v = m;
        strcpy(v.generation, "ffffffffffffffffffffffffffffffff");
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        reply = disposition_command(recovery, bad, frame, sizeof(frame),
            error, sizeof(error));
        assert(reply[0] == '-');
        qihse_qkp_admin_free(reply);
        printf("  denied: wrong generation\n");
        v = m;
        v.issuer_operator_pin[0] ^= 1u;
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        reply = disposition_command(recovery, bad, frame, sizeof(frame),
            error, sizeof(error));
        assert(reply[0] == '-');
        qihse_qkp_admin_free(reply);
        printf("  denied: wrong issuer operator pin\n");
        v = m;
        v.issued_ms = now_ms() - 800000u;
        v.expires_ms = now_ms() - 200000u;
        assert(qihse_ct1_recovery_encode(&v, false, false, bad));
        reply = disposition_command(recovery, bad, frame, sizeof(frame),
            error, sizeof(error));
        assert(reply[0] == '-');
        qihse_qkp_admin_free(reply);
        printf("  denied: expired manifest window\n");
        memcpy(bad, wire, sizeof(bad));
        bad[1500] ^= 1u;
        reply = disposition_command(recovery, bad, frame, sizeof(frame),
            error, sizeof(error));
        assert(reply[0] == '-');
        qihse_qkp_admin_free(reply);
        printf("  denied: tampered wire (trailer integrity)\n");
    }
    {   /* The data-plane source peer is not the recovery identity. */
        qihse_qkp_admin_client_t* source_peer = NULL;
        assert(qihse_qkp_admin_open("127.0.0.1", port, SOURCE_ID,
            source_id.dir, successor_id.pub, 30000u, &source_peer, error,
            sizeof(error)) == 0);
        char* reply = disposition_command(source_peer, wire, frame,
            sizeof(frame), error, sizeof(error));
        assert(reply[0] == '-' && !strstr(reply, "+OK"));
        qihse_qkp_admin_free(reply);
        qihse_qkp_admin_close(source_peer);
        printf("  denied: source peer outside the recovery identity\n");
    }
    {   /* Nothing persisted: cursor still at the fence. */
        qihse_kv_ct_receiver_status_t status = {0};
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == CURSOR);
    }

    /* The single admitted commit. */
    {
        char* reply = disposition_command(recovery, wire, frame,
            sizeof(frame), error, sizeof(error));
        assert(reply[0] == '+' && strstr(reply, "OK"));
        qihse_qkp_admin_free(reply);
        printf("  admitted: archived suppression committed at cursor %u\n",
            PENDING);
    }
    {   /* The old SET is absent; the exact replay is an idempotent +OK
         * (crash-retry semantics), never a second application. */
        qihse_kv_ct_receiver_status_t status = {0};
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == PENDING &&
            qihse_kv_get_user(store, FULL_KEY, op) == NULL);
        char* reply = disposition_command(recovery, wire, frame,
            sizeof(frame), error, sizeof(error));
        assert(reply[0] == '+' && strstr(reply, "OK"));
        qihse_qkp_admin_free(reply);
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == PENDING);
        printf("  idempotent: exact replay re-admitted, cursor unchanged\n");
    }

    qihse_qkp_admin_close(recovery);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CT1 TARGET DISPOSITION-V1 RESP-level fixture: OK");
    return 0;
}
