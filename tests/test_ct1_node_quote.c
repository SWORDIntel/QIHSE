#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_node_quote.h"
#include "qihse_pqc_crypto.h"
#include <assert.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef QIHSE_CT1_SOURCE_SNAPSHOT_TEST
#include <sys/file.h>
#include "qihse_auth.h"
#include "qihse_kv_store.h"

/* Run only in a fresh disposable process/data directory. */
int main(void) {
    assert(getenv("QIHSE_DATA_DIR") && qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtQuoteOperator1!"));
    qihse_user_t *op = qihse_auth_authenticate_id(0u, "CtQuoteOperator1!");
    assert(op);
    qihse_user_t *service = qihse_auth_create_user(op, 8302u, QIHSE_ROLE_ANALYST,
        5u, 1u, "CtQuoteService1!", false);
    qihse_user_t *low = qihse_auth_create_user(op, 8301u, QIHSE_ROLE_ANALYST,
        0u, 0u, "CtQuoteAnalyst1!", false);
    assert(service && low);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store && qihse_kv_ct_source_enable(store, op, "source", "target",
        "generation", NULL, 128u * 1024u * 1024u));
    qihse_kv_store_set_replication_principal_id(store, 8302u);
    qihse_kv_replica_snapshot_t *baseline = NULL;
    uint64_t baseline_seq = 0;
    unsigned char digest[32], token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_source_baseline_snapshot_create(store, op, &baseline,
        &baseline_seq, digest) == 0);
    qihse_kv_replica_snapshot_destroy(baseline);
    assert(qihse_kv_ct_source_reconcile_peer(store, op, service, "target",
        "generation", digest, 0u));
    assert(qihse_kv_ct_owner_token_get(store, op, token));
    qihse_kv_ct_writer_scope_t *scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
    assert(qihse_kv_set_user(store, "commons/quote", "CT1-QUOTE-PROTECTED", 5u, 1u, op));
    qihse_kv_ct_writer_scope_leave(scope);
    qihse_kv_ct_group_t *groups = NULL;
    size_t count = 0;
    uint64_t resume = 0;
    assert(qihse_kv_ct_source_read(store, service, "generation", 0u, 1u, 65536u,
        &groups, &count, &resume) && count == 1u && groups[0].count == 1u);
    qihse_kv_ct_source_retained_frame_request_t req = {
        .version = QIHSE_KV_CT_SOURCE_RETAINED_FRAME_V1, .size = sizeof(req),
        .source_id = "source", .successor_id = "target", .generation = "generation",
        .baseline_row_seq = baseline_seq, .durable_position = 1u,
        .stream_position = 1u, .key = groups[0].records[0].key,
        .resource_tenant_id = groups[0].records[0].resource_tenant_id,
        .classification = 5u, .sci_compartment = 1u,
        .row_change_seq = groups[0].records[0].change_seq};
    memcpy(req.baseline_digest, digest, 32);
    uint64_t high_water = groups[0].last_seq;
    qihse_kv_ct_source_quote_snapshot_t snap = {0}, empty = {0};
    assert(qihse_kv_ct_source_quote_snapshot_v1(store, op, service, &req, high_water, &snap));
    assert(snap.row_seq_high_water == high_water && snap.frame_offset == 0u &&
        snap.retained.frame_length > 4u && !memcmp(snap.retained.frame, "QKV6", 4u));
    char path[4096];
    assert(snprintf(path, sizeof(path), "%s/wal.log", getenv("QIHSE_DATA_DIR")) > 0);
    FILE *wal = fopen(path, "rb");
    unsigned char *original = malloc(snap.retained.frame_length);
    assert(wal && original && fread(original, 1, snap.retained.frame_length, wal) ==
        snap.retained.frame_length && fgetc(wal) == EOF && fclose(wal) == 0);
    assert(!memcmp(original, snap.retained.frame, snap.retained.frame_length));
    size_t frame_len = snap.retained.frame_length;
    assert(SHA256(original, frame_len, digest));
    assert(!memcmp(digest, snap.retained.frame_sha256, 32));
    free(snap.retained.frame); free(snap.retained.key);
    free(original);
    assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
    assert(qihse_kv_set_user(store, "commons/quote-second", "CT1-QUOTE-SECOND", 5u, 1u, op));
    qihse_kv_ct_writer_scope_leave(scope);
    qihse_kv_ct_groups_free(groups, count);
    groups = NULL;
    assert(qihse_kv_ct_source_read(store, service, "generation", 1u, 1u, 65536u,
        &groups, &count, &resume) && count == 1u && groups[0].count == 1u);
    req.durable_position = req.stream_position = 2u;
    req.key = groups[0].records[0].key;
    req.resource_tenant_id = groups[0].records[0].resource_tenant_id;
    req.row_change_seq = groups[0].records[0].change_seq;
    high_water = groups[0].last_seq;
    assert(qihse_kv_ct_source_quote_snapshot_v1(store, op, service, &req, high_water, &snap));
    assert(snap.row_seq_high_water == high_water && snap.frame_offset == frame_len &&
        snap.frame_offset > 0u && snap.retained.frame_length > 4u &&
        !memcmp(snap.retained.frame, "QKV6", 4u));
    size_t first_frame_len = frame_len;
    frame_len = snap.retained.frame_length;
    wal = fopen(path, "rb");
    original = malloc(frame_len);
    assert(wal && original && fseek(wal, 0, SEEK_END) == 0 &&
        ftell(wal) == (long)(snap.frame_offset + frame_len) &&
        fseek(wal, (long)snap.frame_offset, SEEK_SET) == 0 &&
        fread(original, 1, frame_len, wal) == frame_len &&
        fgetc(wal) == EOF && fclose(wal) == 0);
    assert(!memcmp(original, snap.retained.frame, frame_len));
    assert(SHA256(original, frame_len, digest));
    assert(!memcmp(digest, snap.retained.frame_sha256, 32));
    free(snap.retained.frame); free(snap.retained.key);
#define DENIED(operator_user, data_user, high) do { \
    memset(&snap, 0xa5, sizeof(snap)); \
    assert(!qihse_kv_ct_source_quote_snapshot_v1(store, (operator_user), (data_user), \
        &req, (high), &snap)); \
    assert(!memcmp(&snap, &empty, sizeof(snap))); \
} while (0)
    int directory = open(getenv("QIHSE_DATA_DIR"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(directory >= 0 && flock(directory, LOCK_EX | LOCK_NB) == 0);
    DENIED(op, service, high_water);
    assert(flock(directory, LOCK_UN) == 0 && close(directory) == 0);
    DENIED(NULL, service, high_water);
    DENIED(low, service, high_water);
    DENIED(op, NULL, high_water);
    DENIED(op, op, high_water); /* Operator cannot substitute for the service. */
    DENIED(op, low, high_water);
    DENIED(op, service, high_water + 1u);
    req.generation = "wrong-generation"; DENIED(op, service, high_water);
    req.generation = "generation";
    req.baseline_digest[0] ^= 1u; DENIED(op, service, high_water);
    req.baseline_digest[0] ^= 1u;
    req.durable_position++; DENIED(op, service, high_water); req.durable_position--;
    qihse_kv_store_set_replication_principal_id(store, 8301u);
    DENIED(op, service, high_water); /* Former configured service. */
    DENIED(op, low, high_water); /* Current service cannot read class5/SCI1. */
    req.classification = req.sci_compartment = 0u;
    DENIED(op, low, high_water); /* Stored labels, not caller claims. */
    req.classification = 5u; req.sci_compartment = 1u;
    qihse_kv_store_set_replication_principal_id(store, 8302u);
    assert(qihse_kv_ct_source_quote_snapshot_v1(store, op, service, &req, high_water, &snap));
    assert(snap.row_seq_high_water == high_water &&
        snap.frame_offset == first_frame_len && snap.retained.frame_length == frame_len &&
        !memcmp(snap.retained.frame, original, frame_len) &&
        !memcmp(snap.retained.frame_sha256, digest, 32));
    free(original); free(snap.retained.frame); free(snap.retained.key);
    /* No writer runs between file replacement and restoration in this disposable store. */
    char state_path[4096], moved[4096];
    assert(snprintf(state_path, sizeof(state_path), "%s/ct-state.bin",
        getenv("QIHSE_DATA_DIR")) > 0);
    assert(snprintf(moved, sizeof(moved), "%s/ct-state.bin.replaced",
        getenv("QIHSE_DATA_DIR")) > 0);
    assert(rename(state_path, moved) == 0 &&
        symlink("ct-state.bin.replaced", state_path) == 0);
    DENIED(op, service, high_water);
    assert(unlink(state_path) == 0 && rename(moved, state_path) == 0);
    assert(snprintf(moved, sizeof(moved), "%s/wal.log.replaced",
        getenv("QIHSE_DATA_DIR")) > 0);
    assert(rename(path, moved) == 0 && symlink("wal.log.replaced", path) == 0);
    DENIED(op, service, high_water);
    assert(unlink(path) == 0 && rename(moved, path) == 0);
    assert(qihse_kv_ct_source_quote_snapshot_v1(store, op, service, &req, high_water, &snap));
    free(snap.retained.frame); free(snap.retained.key);
    qihse_kv_ct_groups_free(groups, count);
    qihse_kv_store_destroy(store);
    puts("ct1 source quote snapshot: locked original bytes and denial checks passed");
    return 0;
}
#else

static const char *const source_names[] = {"ct-baseline.qfs", "ct-state.bin",
    "restore-highwater.bin", "slot-ownership.journal",
    "slot-ownership.journal.lock", "sstable_11321.db", "sstable_11322.db", "wal.log"};
static const char *const target_names[] = {"ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock", "sstable_6.db",
    "sstable_7.db", "wal.log"};

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
        else memset(files[i].sha256, (int)i + 1, 32);
    }
}

static qihse_ct1_recovery_manifest_t sample(void) {
    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator");
    strcpy(m.source_qkp_id, "source"); strcpy(m.target_qkp_id, "target");
    strcpy(m.source_peer_qkp_id, "source-node");
    strcpy(m.target_peer_qkp_id, "target-node");
    strcpy(m.source_store_id, "source-store");
    strcpy(m.target_store_id, "target-store");
    strcpy(m.generation, "generation-1");
    strcpy(m.replication_principal_id, "replication-service");
    strcpy(m.row_key, "row");
    memset(m.issuer_operator_pin, 1, 32);
    memset(m.frame_sha256, 4, 32); memset(m.baseline_sha256, 5, 32);
    memset(m.nonce, 6, 32);
    roster(m.source_files, source_names, QIHSE_CT1_RECOVERY_SOURCE_FILES);
    roster(m.target_files, target_names, QIHSE_CT1_RECOVERY_TARGET_FILES);
    m.epoch = 9; m.issued_ms = 1000; m.expires_ms = 901000;
    m.frame_offset = 1; m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 2; m.target_cursor = 21;
    m.source_high_water = 33; m.target_high_water = 44;
    m.row_change_seq = 3; m.tombstone_position = 1; m.tombstone_row_seq = 2;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    return m;
}

static void keypair(const char *private_path, const char *public_path,
    unsigned char pin[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    EVP_PKEY *key = NULL;
    assert(ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1);
    int fd = open(private_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f && PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1);
    assert(fclose(f) == 0);
    f = fopen(public_path, "wb");
    assert(f && PEM_write_PUBKEY(f, key) == 1);
    assert(fclose(f) == 0);
    int length = i2d_PUBKEY(key, NULL);
    assert(length > 0 && length < 8192);
    unsigned char *der = OPENSSL_malloc((size_t)length), *cursor = der;
    assert(der && i2d_PUBKEY(key, &cursor) == length);
    assert(SHA256(der, (size_t)length, pin));
    OPENSSL_free(der);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
}

/* Fixture-only signing of a fixed CT1Q record, not an exported signer. */
static void put64(unsigned char *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (56u - i * 8u));
}
static void label(unsigned char *p, const char *s) { memcpy(p, s, strlen(s)); }
static void quote(unsigned char out[QIHSE_CT1_NODE_QUOTE_SIZE],
    const unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE],
    const qihse_ct1_recovery_manifest_t *m, unsigned role,
    const unsigned char nonce[32], const unsigned char signer_pin[32],
    const char *private_path) {
    memset(out, 0, QIHSE_CT1_NODE_QUOTE_SIZE);
    size_t n = 0;
    memcpy(out + n, "CT1Q", 4); n += 4;
    out[n++] = 2; out[n++] = (unsigned char)role; n += 2;
    memcpy(out + n, nonce, 32); n += 32;
    assert(SHA256(wire, QIHSE_CT1_RECOVERY_WIRE_SIZE, out + n)); n += 32;
    label(out + n, role == 1 ? m->source_qkp_id : m->target_qkp_id); n += 65;
    label(out + n, m->source_qkp_id); n += 65;
    label(out + n, m->target_qkp_id); n += 65;
    memcpy(out + n, signer_pin, 32); n += 32;
    label(out + n, role == 1 ? m->source_peer_qkp_id : m->target_peer_qkp_id); n += 65;
    memcpy(out + n, role == 1 ? m->source_peer_pin : m->target_peer_pin, 32); n += 32;
    label(out + n, m->replication_principal_id); n += 65;
    label(out + n, m->generation); n += 65;
    memcpy(out + n, m->baseline_sha256, 32); n += 32;
    put64(out + n, m->target_cursor); n += 8;
    put64(out + n, role == 1 ? m->source_high_water : m->target_high_water); n += 8;
    assert(n == QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE);
    assert(qihse_pqc_sign_path(out, n, out + n, private_path));
}

int main(void) {
    char tmp[] = "./ct1-quote-XXXXXX";
    assert(mkdtemp(tmp));
    char source_priv[128], source_pub[128], target_priv[128], target_pub[128];
    char peer_priv[128], peer_pub[128], other_peer_priv[128], other_peer_pub[128];
    unsigned char source_pin[32], target_pin[32];
    assert(snprintf(source_priv, sizeof(source_priv), "%s/source-key.pem", tmp) > 0);
    assert(snprintf(source_pub, sizeof(source_pub), "%s/source-pub.pem", tmp) > 0);
    assert(snprintf(target_priv, sizeof(target_priv), "%s/target-key.pem", tmp) > 0);
    assert(snprintf(target_pub, sizeof(target_pub), "%s/target-pub.pem", tmp) > 0);
    assert(snprintf(peer_priv, sizeof(peer_priv), "%s/peer-key.pem", tmp) > 0);
    assert(snprintf(peer_pub, sizeof(peer_pub), "%s/peer-pub.pem", tmp) > 0);
    assert(snprintf(other_peer_priv, sizeof(other_peer_priv), "%s/other-peer-key.pem", tmp) > 0);
    assert(snprintf(other_peer_pub, sizeof(other_peer_pub), "%s/other-peer-pub.pem", tmp) > 0);
    qihse_ct1_recovery_manifest_t m = sample(), changed;
    keypair(source_priv, source_pub, source_pin);
    keypair(target_priv, target_pub, target_pin);
    keypair(peer_priv, peer_pub, m.source_peer_pin);
    keypair(other_peer_priv, other_peer_pub, m.target_peer_pin);
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE], other[sizeof(wire)];
    unsigned char nonce[32], bad_nonce[32];
    memset(nonce, 0x74, sizeof(nonce));
    memcpy(bad_nonce, nonce, sizeof(nonce)); bad_nonce[0] ^= 1;
    memcpy(m.nonce, nonce, sizeof(nonce));
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    unsigned char source[QIHSE_CT1_NODE_QUOTE_SIZE], target[sizeof(source)],
        scratch[sizeof(source)];
    quote(source, wire, &m, 1, nonce, source_pin, source_priv);
    quote(target, wire, &m, 2, nonce, target_pin, target_priv);
    qihse_ct1_node_quote_expected_t trusted = {0}, stale;
    strcpy(trusted.source_qkp_id, "source");
    strcpy(trusted.target_qkp_id, "target");
    strcpy(trusted.source_peer_qkp_id, "source-node");
    strcpy(trusted.target_peer_qkp_id, "target-node");
    strcpy(trusted.replication_principal_id, "replication-service");
    strcpy(trusted.generation, "generation-1");
    memcpy(trusted.source_signer_pin, source_pin, 32);
    memcpy(trusted.target_signer_pin, target_pin, 32);
    memcpy(trusted.source_peer_pin, m.source_peer_pin, 32);
    memcpy(trusted.target_peer_pin, m.target_peer_pin, 32);
    memset(trusted.baseline_sha256, 5, 32);
    trusted.target_cursor = 21;
    trusted.source_high_water = 33;
    trusted.target_high_water = 44;
    /* Real disposable node keys; signing accepts only a canonical B equal to
     * independently supplied evidence and the current trusted identities. */
    qihse_ct1_recovery_manifest_t verified = m, stale_manifest;
    memcpy(verified.nonce, nonce, sizeof(nonce));
    unsigned char signed_wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    unsigned char signed_quote[QIHSE_CT1_NODE_QUOTE_SIZE];
    unsigned char zero_quote[sizeof(signed_quote)] = {0};
    assert(qihse_ct1_recovery_encode(&verified, false, false, signed_wire));
    qihse_ct1_node_quote_signing_evidence_t evidence = {
        .manifest_wire = signed_wire, .manifest_len = sizeof(signed_wire),
        .verified_manifest = &verified, .expected = &trusted,
        .role = QIHSE_CT1_NODE_QUOTE_SOURCE, .now_ms = verified.issued_ms,
        .host_nonce = nonce, .own_private_key_path = source_priv,
        .own_public_key_path = source_pub};
    assert(qihse_ct1_node_quote_sign_verified(&evidence, signed_quote));
    assert(qihse_ct1_node_quote_verify_strict(signed_quote, sizeof(signed_quote),
        signed_wire, sizeof(signed_wire), evidence.role, nonce, source_pub, &trusted));
    /* Source signing binds but does not independently measure the target sequence. */
    qihse_ct1_recovery_manifest_t remote = verified;
    unsigned char remote_wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    remote.tombstone_row_seq++;
    assert(qihse_ct1_recovery_encode(&remote, false, false, remote_wire));
    evidence.verified_manifest = &remote;
    evidence.manifest_wire = remote_wire;
    assert(qihse_ct1_node_quote_sign_verified(&evidence, signed_quote));
    assert(qihse_ct1_node_quote_verify_strict(signed_quote, sizeof(signed_quote),
        remote_wire, sizeof(remote_wire), evidence.role, nonce, source_pub, &trusted));
    assert(!qihse_ct1_node_quote_verify_strict(signed_quote, sizeof(signed_quote),
        signed_wire, sizeof(signed_wire), evidence.role, nonce, source_pub, &trusted));
    evidence.verified_manifest = &verified;
    evidence.manifest_wire = signed_wire;
    evidence.role = QIHSE_CT1_NODE_QUOTE_TARGET;
    evidence.own_private_key_path = target_priv;
    evidence.own_public_key_path = target_pub;
    assert(qihse_ct1_node_quote_sign_verified(&evidence, signed_quote));
    assert(qihse_ct1_node_quote_verify_strict(signed_quote, sizeof(signed_quote),
        signed_wire, sizeof(signed_wire), evidence.role, nonce, target_pub, &trusted));
#define SIGN_DENIED() do { \
    memset(signed_quote, 0x5a, sizeof(signed_quote)); \
    assert(!qihse_ct1_node_quote_sign_verified(&evidence, signed_quote)); \
    assert(!memcmp(signed_quote, zero_quote, sizeof(signed_quote))); \
} while (0)
    evidence.role = QIHSE_CT1_NODE_QUOTE_SOURCE;
    evidence.own_private_key_path = source_priv;
    evidence.own_public_key_path = source_pub;
    evidence.host_nonce = bad_nonce; SIGN_DENIED(); evidence.host_nonce = nonce;
    evidence.host_nonce = zero_quote; SIGN_DENIED(); evidence.host_nonce = nonce;
    evidence.now_ms = verified.issued_ms - 1u; SIGN_DENIED();
    evidence.now_ms = verified.expires_ms; SIGN_DENIED();
    evidence.now_ms = verified.issued_ms;
    evidence.role = 3u; SIGN_DENIED(); evidence.role = QIHSE_CT1_NODE_QUOTE_SOURCE;
    evidence.own_private_key_path = target_priv; SIGN_DENIED();
    evidence.own_private_key_path = source_priv;
    evidence.own_public_key_path = target_pub; SIGN_DENIED();
    evidence.own_public_key_path = source_pub;
    evidence.manifest_len--; SIGN_DENIED(); evidence.manifest_len++;
    signed_wire[0] ^= 1u; SIGN_DENIED(); signed_wire[0] ^= 1u;
    stale_manifest = verified;
    strcpy(stale_manifest.source_qkp_id, "wrong-source");
    evidence.verified_manifest = &stale_manifest; SIGN_DENIED();
    stale_manifest = verified; stale_manifest.target_cursor++;
    evidence.verified_manifest = &stale_manifest; SIGN_DENIED();
    stale_manifest = verified; stale_manifest.source_files[0].sha256[0] ^= 1u;
    evidence.verified_manifest = &stale_manifest; SIGN_DENIED();
    stale_manifest = verified; stale_manifest.frame_sha256[0] ^= 1u;
    evidence.verified_manifest = &stale_manifest; SIGN_DENIED();
    stale_manifest = verified; stale_manifest.classification++;
    evidence.verified_manifest = &stale_manifest; SIGN_DENIED();
    stale_manifest = verified; stale_manifest.principal_sci++;
    evidence.verified_manifest = &stale_manifest; SIGN_DENIED();
    stale_manifest = verified; stale_manifest.expires_ms =
        stale_manifest.issued_ms + QIHSE_CT1_RECOVERY_MAX_AGE_MS + 1u;
    evidence.verified_manifest = &stale_manifest; SIGN_DENIED();
    evidence.verified_manifest = &verified;
    stale = trusted; strcpy(stale.generation, "wrong-generation");
    evidence.expected = &stale; SIGN_DENIED();
    stale = trusted; stale.source_signer_pin[0] ^= 1u;
    evidence.expected = &stale; SIGN_DENIED();
    stale = trusted; stale.source_peer_pin[0] ^= 1u;
    evidence.expected = &stale; SIGN_DENIED();
    evidence.expected = &trusted;
    assert(qihse_ct1_node_quote_sign_verified(&evidence, signed_quote));
#undef SIGN_DENIED
#define STRICT(q, r, pub, ctx) \
    qihse_ct1_node_quote_verify_strict((q), sizeof(source), wire, sizeof(wire), \
        (r), nonce, (pub), (ctx))
    assert(STRICT(source, 1, source_pub, &trusted));
    assert(STRICT(target, 2, target_pub, &trusted));
    /* Even a correctly signed quote cannot bind a different manifest nonce. */
    changed = m;
    memcpy(changed.nonce, bad_nonce, sizeof(bad_nonce));
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    assert(!qihse_ct1_node_quote_verify_strict(scratch, sizeof(scratch),
        other, sizeof(other), 1, nonce, source_pub, &trusted));
    /* Standalone role verification remains valid for nonstale ordering. */
    assert(!qihse_ct1_node_quote_verify_paired_stale(source, sizeof(source),
        target, sizeof(target), wire, sizeof(wire), nonce, source_pub, target_pub,
        &trusted, &trusted));

    changed = m;
    changed.frame_position = 11111; changed.target_cursor = 11110;
    changed.tombstone_position = 11103;
    changed.row_change_seq = 5729448; changed.tombstone_row_seq = 5729450;
    changed.source_high_water = 5729448; changed.target_high_water = 5729457;
    stale = trusted;
    stale.target_cursor = changed.target_cursor;
    stale.source_high_water = changed.source_high_water;
    stale.target_high_water = changed.target_high_water;
    qihse_ct1_node_quote_expected_t stale_target = stale;
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    quote(signed_quote, other, &changed, 2, nonce, target_pin, target_priv);
#define PAIRED(src, dst, b, n, sp, tp, se, te) \
    qihse_ct1_node_quote_verify_paired_stale((src), sizeof(source), (dst), \
        sizeof(target), (b), sizeof(other), (n), (sp), (tp), (se), (te))
    /* Individually valid role quotes must not pair unrelated configured peers. */
    assert(qihse_ct1_node_quote_verify_strict(scratch, sizeof(scratch), other,
        sizeof(other), 1, nonce, source_pub, &stale));
    assert(qihse_ct1_node_quote_verify_strict(signed_quote, sizeof(signed_quote), other,
        sizeof(other), 2, nonce, target_pub, &stale_target));
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        &stale, &stale_target));
    strcpy(changed.source_peer_qkp_id, changed.target_qkp_id);
    strcpy(changed.target_peer_qkp_id, changed.source_qkp_id);
    memcpy(changed.source_peer_pin, target_pin, 32);
    memcpy(changed.target_peer_pin, source_pin, 32);
    strcpy(stale.source_peer_qkp_id, changed.source_peer_qkp_id);
    strcpy(stale.target_peer_qkp_id, changed.target_peer_qkp_id);
    memcpy(stale.source_peer_pin, target_pin, 32);
    memcpy(stale.target_peer_pin, source_pin, 32);
    stale_target = stale;
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    quote(signed_quote, other, &changed, 2, nonce, target_pin, target_priv);
    assert(PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        &stale, &stale_target));
    stale_target.source_signer_pin[0] ^= 1u;
    assert(qihse_ct1_node_quote_verify_strict(signed_quote, sizeof(signed_quote),
        other, sizeof(other), 2, nonce, target_pub, &stale_target));
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        &stale, &stale_target));
    stale_target.source_signer_pin[0] ^= 1u;
    strcpy(changed.row_key, "different-row");
    assert(qihse_ct1_recovery_encode(&changed, false, false, wire));
    quote(signed_quote, wire, &changed, 2, nonce, target_pin, target_priv);
    assert(qihse_ct1_node_quote_verify_strict(signed_quote, sizeof(signed_quote),
        wire, sizeof(wire), 2, nonce, target_pub, &stale_target));
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        &stale, &stale_target));
    strcpy(changed.row_key, m.row_key);
    quote(signed_quote, other, &changed, 2, nonce, target_pin, target_priv);
    assert(!PAIRED(signed_quote, scratch, other, nonce, source_pub, target_pub,
        &stale, &stale_target));
    assert(!PAIRED(scratch, signed_quote, other, bad_nonce, source_pub, target_pub,
        &stale, &stale_target));
    assert(!PAIRED(scratch, signed_quote, other, nonce, target_pub, target_pub,
        &stale, &stale_target));
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, source_pub,
        &stale, &stale_target));
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        NULL, &stale));
    trusted.target_cursor = 21;
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        &stale, &trusted));
    scratch[sizeof(scratch) - 1] ^= 1;
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        &stale, &stale_target));
    scratch[sizeof(scratch) - 1] ^= 1;
    signed_quote[sizeof(signed_quote) - 1] ^= 1;
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        &stale, &stale_target));
    signed_quote[sizeof(signed_quote) - 1] ^= 1;
    memcpy(wire, other, sizeof(wire)); wire[1600] ^= 1;
    assert(!PAIRED(scratch, signed_quote, wire, nonce, source_pub, target_pub,
        &stale, &stale_target));
    assert(!qihse_ct1_node_quote_verify_paired_stale(scratch, sizeof(scratch),
        signed_quote, sizeof(signed_quote), other, sizeof(other) - 1u, nonce,
        source_pub, target_pub, &stale, &stale_target));
    assert(PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub,
        &stale, &stale_target));
#define ORDER_DENIED() do { \
    stale.target_cursor = changed.target_cursor; \
    stale.source_high_water = changed.source_high_water; \
    stale.target_high_water = changed.target_high_water; \
    stale_target = stale; \
    assert(qihse_ct1_recovery_encode(&changed, false, false, other)); \
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv); \
    quote(signed_quote, other, &changed, 2, nonce, target_pin, target_priv); \
    assert(qihse_ct1_node_quote_verify_strict(scratch, sizeof(scratch), other, \
        sizeof(other), 1, nonce, source_pub, &stale)); \
    assert(qihse_ct1_node_quote_verify_strict(signed_quote, sizeof(signed_quote), other, \
        sizeof(other), 2, nonce, target_pub, &stale)); \
    assert(!PAIRED(scratch, signed_quote, other, nonce, source_pub, target_pub, \
        &stale, &stale_target)); \
} while (0)
    changed.row_change_seq = changed.tombstone_row_seq; ORDER_DENIED();
    changed.row_change_seq++; ORDER_DENIED();
    changed.row_change_seq = 5729448;
    changed.source_high_water = changed.row_change_seq - 1u; ORDER_DENIED();
    changed.source_high_water = changed.row_change_seq;
    changed.target_high_water = changed.tombstone_row_seq - 1u; ORDER_DENIED();
    changed.target_high_water = 5729457;
    changed.tombstone_position = changed.target_cursor + 1u; ORDER_DENIED();
    changed.tombstone_position = 11103;
    changed.frame_position = changed.target_cursor; ORDER_DENIED();
    changed.target_cursor = UINT64_MAX;
    changed.frame_position = 1u; ORDER_DENIED();
#undef ORDER_DENIED
#undef PAIRED
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    assert(!STRICT(source, 2, source_pub, &trusted));
    assert(!STRICT(target, 1, target_pub, &trusted));
    assert(!STRICT(source, 1, target_pub, &trusted));
    assert(!STRICT(source, 1, source_pub, NULL));
    stale = trusted; strcpy(stale.source_qkp_id, "wrong-source");
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; strcpy(stale.target_qkp_id, "wrong-target");
    assert(!STRICT(target, 2, target_pub, &stale));
    stale = trusted; stale.source_signer_pin[0] ^= 1;
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; stale.target_signer_pin[0] ^= 1;
    assert(!STRICT(target, 2, target_pub, &stale));
    stale = trusted; strcpy(stale.source_peer_qkp_id, "wrong-peer");
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; strcpy(stale.target_peer_qkp_id, "wrong-peer");
    assert(!STRICT(target, 2, target_pub, &stale));
    stale = trusted; stale.source_peer_pin[0] ^= 1;
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; stale.target_peer_pin[0] ^= 1;
    assert(!STRICT(target, 2, target_pub, &stale));
    stale = trusted; strcpy(stale.replication_principal_id, "other-service");
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; strcpy(stale.generation, "generation-2");
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; stale.baseline_sha256[0] ^= 1;
    assert(!STRICT(target, 2, target_pub, &stale));
    stale = trusted; stale.target_cursor++;
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; stale.source_high_water++;
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; stale.target_high_water++;
    assert(!STRICT(target, 2, target_pub, &stale));
    stale = trusted; strcpy(stale.source_qkp_id, stale.target_qkp_id);
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; memcpy(stale.target_peer_pin, stale.source_signer_pin, 32);
    assert(!STRICT(source, 1, source_pub, &stale));
    stale = trusted; stale.target_peer_qkp_id[0] = '\0';
    assert(!STRICT(target, 2, target_pub, &stale));
    assert(!qihse_ct1_node_quote_verify_strict(source, sizeof(source), wire,
        sizeof(wire), 1, bad_nonce, source_pub, &trusted));
    /* A node's configured peer can be the other role's own signer. */
    changed = m;
    strcpy(changed.source_peer_qkp_id, changed.target_qkp_id);
    strcpy(changed.target_peer_qkp_id, changed.source_qkp_id);
    memcpy(changed.source_peer_pin, target_pin, 32);
    memcpy(changed.target_peer_pin, source_pin, 32);
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    stale = trusted;
    strcpy(stale.source_peer_qkp_id, changed.source_peer_qkp_id);
    strcpy(stale.target_peer_qkp_id, changed.target_peer_qkp_id);
    memcpy(stale.source_peer_pin, changed.source_peer_pin, 32);
    memcpy(stale.target_peer_pin, changed.target_peer_pin, 32);
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    assert(qihse_ct1_node_quote_verify_strict(scratch, sizeof(scratch), other,
        sizeof(other), 1, nonce, source_pub, &stale));
    quote(scratch, other, &changed, 2, nonce, target_pin, target_priv);
    assert(qihse_ct1_node_quote_verify_strict(scratch, sizeof(scratch), other,
        sizeof(other), 2, nonce, target_pub, &stale));
#define VERIFY(q, r, pub, source_trust, target_trust, principal) \
    qihse_ct1_node_quote_verify((q), sizeof(source), wire, sizeof(wire), \
        (r), nonce, (pub), (source_trust), (target_trust), (principal))
    assert(VERIFY(source, 1, source_pub, source_pin, target_pin, m.replication_principal_id));
    assert(VERIFY(target, 2, target_pub, source_pin, target_pin, m.replication_principal_id));
    assert(!VERIFY(source, 2, source_pub, source_pin, target_pin, m.replication_principal_id));
    assert(!VERIFY(target, 1, target_pub, source_pin, target_pin, m.replication_principal_id));
    assert(!VERIFY(source, 1, target_pub, source_pin, target_pin, m.replication_principal_id));
    assert(!VERIFY(source, 1, source_pub, m.target_peer_pin, target_pin, m.replication_principal_id));
    assert(!VERIFY(source, 1, source_pub, source_pin, target_pin, "other-service"));
    assert(!VERIFY(source, 1, source_pub, source_pin, source_pin,
        m.replication_principal_id));
    assert(!VERIFY(target, 2, target_pub, target_pin, target_pin,
        m.replication_principal_id));
    /* A valid own-key signature cannot turn the configured peer into self. */
    changed = m; memcpy(changed.source_peer_pin, source_pin, 32);
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    assert(!qihse_ct1_node_quote_verify(scratch, sizeof(scratch), other, sizeof(other),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    changed = m; memcpy(changed.target_peer_pin, target_pin, 32);
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 2, nonce, target_pin, target_priv);
    assert(!qihse_ct1_node_quote_verify(scratch, sizeof(scratch), other, sizeof(other),
        2, nonce, target_pub, source_pin, target_pin, m.replication_principal_id));
    /* The configured peer key is not a signer even when its pin is in B. */
    quote(scratch, wire, &m, 1, nonce, m.source_peer_pin, peer_priv);
    assert(!VERIFY(scratch, 1, peer_pub, source_pin, target_pin,
        m.replication_principal_id));
    quote(scratch, wire, &m, 2, nonce, m.target_peer_pin, other_peer_priv);
    assert(!VERIFY(scratch, 2, other_peer_pub, source_pin, target_pin,
        m.replication_principal_id));
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source), wire, sizeof(wire),
        1, bad_nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source), wire, sizeof(wire),
        1, (unsigned char[32]){0}, source_pub, source_pin, target_pin, m.replication_principal_id));
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source) - 1, wire, sizeof(wire),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source), wire, sizeof(wire) - 1,
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    changed = m; changed.target_cursor++;
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source), other, sizeof(other),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    changed = m; strcpy(changed.generation, "generation-2");
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source), other, sizeof(other),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    memcpy(other, wire, sizeof(other)); other[1600] ^= 1;
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source), other, sizeof(other),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    /* Sign again after each mutation: structural checks cannot rely on signature failure. */
    const size_t bad_fields[] = {0, 4, 5, 6, 8, 40, 72, 90, 137, 202, 267,
        299, 364, 396, 461, 526, 558, 566};
    for (size_t i = 0; i < sizeof(bad_fields) / sizeof(bad_fields[0]); ++i) {
        memcpy(scratch, source, sizeof(source));
        scratch[bad_fields[i]] ^= 1;
        assert(qihse_pqc_sign_path(scratch, QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE,
            scratch + QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE, source_priv));
        assert(!VERIFY(scratch, 1, source_pub, source_pin, target_pin, m.replication_principal_id));
    }
    const size_t target_fields[] = {72, 267, 299, 364, 566};
    for (size_t i = 0; i < sizeof(target_fields) / sizeof(target_fields[0]); ++i) {
        memcpy(scratch, target, sizeof(target));
        scratch[target_fields[i]] ^= 1;
        assert(qihse_pqc_sign_path(scratch, QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE,
            scratch + QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE, target_priv));
        assert(!VERIFY(scratch, 2, target_pub, source_pin, target_pin,
            m.replication_principal_id));
    }
    memcpy(scratch, source, sizeof(source)); scratch[sizeof(source) - 1] ^= 1;
    assert(!VERIFY(scratch, 1, source_pub, source_pin, target_pin, m.replication_principal_id));
    /* Even a valid signature under the other node key cannot impersonate source. */
    memcpy(scratch, source, sizeof(source));
    assert(qihse_pqc_sign_path(scratch, QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE,
        scratch + QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE, target_priv));
    assert(!VERIFY(scratch, 1, source_pub, source_pin, target_pin, m.replication_principal_id));
    /* A key from the other role cannot become the signer by relabeling. */
    quote(scratch, wire, &m, 2, nonce, source_pin, source_priv);
    assert(!VERIFY(scratch, 2, source_pub, source_pin, target_pin,
        m.replication_principal_id));
    changed = m; strcpy(changed.target_qkp_id, changed.source_qkp_id);
    assert(!qihse_ct1_recovery_encode(&changed, false, false, other));
    /* A freshly signed, canonical but stale B cannot supply its own expectations. */
    changed = m; changed.target_cursor++;
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    assert(!qihse_ct1_node_quote_verify_strict(scratch, sizeof(scratch), other,
        sizeof(other), 1, nonce, source_pub, &trusted));
    changed = m; strcpy(changed.source_peer_qkp_id, "new-peer");
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    assert(!qihse_ct1_node_quote_verify_strict(scratch, sizeof(scratch), other,
        sizeof(other), 1, nonce, source_pub, &trusted));
    changed = m; strcpy(changed.target_peer_qkp_id, changed.source_peer_qkp_id);
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    assert(!qihse_ct1_node_quote_verify(scratch, sizeof(scratch), other, sizeof(other),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    changed = m; strcpy(changed.source_peer_qkp_id, "different-peer");
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source), other, sizeof(other),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    changed = m; memcpy(changed.source_peer_pin, changed.target_peer_pin, 32);
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    assert(!qihse_ct1_node_quote_verify(source, sizeof(source), other, sizeof(other),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    changed = m; memcpy(changed.target_peer_pin, changed.source_peer_pin, 32);
    assert(qihse_ct1_recovery_encode(&changed, false, false, other));
    quote(scratch, other, &changed, 1, nonce, source_pin, source_priv);
    assert(!qihse_ct1_node_quote_verify(scratch, sizeof(scratch), other, sizeof(other),
        1, nonce, source_pub, source_pin, target_pin, m.replication_principal_id));
    /* Denials must not consume or modify either signed record. */
    assert(STRICT(source, 1, source_pub, &trusted));
    assert(STRICT(target, 2, target_pub, &trusted));
    assert(unlink(peer_priv) == 0 && unlink(peer_pub) == 0);
    assert(unlink(other_peer_priv) == 0 && unlink(other_peer_pub) == 0);
    assert(unlink(source_priv) == 0 && unlink(source_pub) == 0);
    assert(unlink(target_priv) == 0 && unlink(target_pub) == 0);
    assert(rmdir(tmp) == 0);
    puts("ct1 node quote helper: real ML-DSA-87 signing, verification and denial checks passed");
    return 0;
}
#endif
