#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_node_quote.h"
#include "qihse_pqc_crypto.h"
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

/* Mirror QKP's SHA256(DER SubjectPublicKeyInfo) fingerprint, not PEM bytes. */
static EVP_PKEY *public_pin(const char *path, unsigned char pin[32]) {
    if (!path || !*path || strnlen(path, 4096) >= 4096) return NULL;
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    EVP_PKEY *key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    if (!key) return NULL;
    int len = i2d_PUBKEY(key, NULL);
    unsigned char *der = len > 0 && len <= 8192 ? OPENSSL_malloc((size_t)len) : NULL;
    unsigned char *cursor = der;
    bool ok = der && i2d_PUBKEY(key, &cursor) == len &&
        SHA256(der, (size_t)len, pin) != NULL;
    OPENSSL_clear_free(der, der ? (size_t)len : 0);
    if (!ok) { EVP_PKEY_free(key); return NULL; }
    return key;
}

static void put_id(unsigned char *out, const char *id) {
    memcpy(out, id, strlen(id));
}

static void put64(unsigned char *out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        out[i] = (unsigned char)(value >> (56u - 8u * i));
}

static bool valid_label(const char *label) {
    size_t n = strnlen(label, QIHSE_CT1_RECOVERY_ID_MAX + 1u);
    return n > 0 && n <= QIHSE_CT1_RECOVERY_ID_MAX;
}

static bool valid_pin(const unsigned char pin[32]) {
    unsigned char bits = 0;
    for (size_t i = 0; i < 32; ++i) bits |= pin[i];
    return bits != 0;
}

static bool matches_expected(const qihse_ct1_recovery_manifest_t *m,
    const qihse_ct1_node_quote_expected_t *e) {
    if (!e || !valid_label(e->source_qkp_id) || !valid_label(e->target_qkp_id) ||
        !valid_label(e->source_peer_qkp_id) || !valid_label(e->target_peer_qkp_id) ||
        !valid_label(e->replication_principal_id) || !valid_label(e->generation) ||
        !valid_pin(e->source_signer_pin) || !valid_pin(e->target_signer_pin) ||
        !valid_pin(e->source_peer_pin) || !valid_pin(e->target_peer_pin) ||
        !strcmp(e->source_qkp_id, e->target_qkp_id) ||
        !strcmp(e->source_peer_qkp_id, e->target_peer_qkp_id) ||
        !strcmp(e->source_qkp_id, e->source_peer_qkp_id) ||
        !strcmp(e->target_qkp_id, e->target_peer_qkp_id) ||
        !CRYPTO_memcmp(e->source_signer_pin, e->target_signer_pin, 32) ||
        !CRYPTO_memcmp(e->source_peer_pin, e->target_peer_pin, 32) ||
        !CRYPTO_memcmp(e->source_signer_pin, e->source_peer_pin, 32) ||
        !CRYPTO_memcmp(e->target_signer_pin, e->target_peer_pin, 32)) return false;
    return !strcmp(m->source_qkp_id, e->source_qkp_id) &&
        !strcmp(m->target_qkp_id, e->target_qkp_id) &&
        !strcmp(m->source_peer_qkp_id, e->source_peer_qkp_id) &&
        !strcmp(m->target_peer_qkp_id, e->target_peer_qkp_id) &&
        !strcmp(m->replication_principal_id, e->replication_principal_id) &&
        !strcmp(m->generation, e->generation) &&
        !CRYPTO_memcmp(m->source_peer_pin, e->source_peer_pin, 32) &&
        !CRYPTO_memcmp(m->target_peer_pin, e->target_peer_pin, 32) &&
        !CRYPTO_memcmp(m->baseline_sha256, e->baseline_sha256, 32) &&
        m->target_cursor == e->target_cursor &&
        m->source_high_water == e->source_high_water &&
        m->target_high_water == e->target_high_water;
}

static bool quote_prefix(unsigned char out[QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE],
    const unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE],
    const qihse_ct1_recovery_manifest_t *manifest, unsigned role,
    const unsigned char host_nonce[32], const unsigned char signer_pin[32]) {
    memset(out, 0, QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE);
    const char *signer = role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        manifest->source_qkp_id : manifest->target_qkp_id;
    const char *peer = role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        manifest->source_peer_qkp_id : manifest->target_peer_qkp_id;
    const unsigned char *peer_pin = role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        manifest->source_peer_pin : manifest->target_peer_pin;
    uint64_t high_water = role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        manifest->source_high_water : manifest->target_high_water;
    size_t n = 0;
    memcpy(out + n, "CT1Q", 4); n += 4;
    out[n++] = 2; out[n++] = (unsigned char)role;
    n += 2; /* reserved zero */
    memcpy(out + n, host_nonce, 32); n += 32;
    if (!SHA256(wire, QIHSE_CT1_RECOVERY_WIRE_SIZE, out + n)) return false;
    n += 32;
    put_id(out + n, signer); n += 65;
    put_id(out + n, manifest->source_qkp_id); n += 65;
    put_id(out + n, manifest->target_qkp_id); n += 65;
    memcpy(out + n, signer_pin, 32); n += 32;
    put_id(out + n, peer); n += 65;
    memcpy(out + n, peer_pin, 32); n += 32;
    put_id(out + n, manifest->replication_principal_id); n += 65;
    put_id(out + n, manifest->generation); n += 65;
    memcpy(out + n, manifest->baseline_sha256, 32); n += 32;
    put64(out + n, manifest->target_cursor); n += 8;
    put64(out + n, high_water); n += 8;
    return n == QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE;
}

static bool verify_quote(const unsigned char *quote, size_t quote_len,
    const unsigned char *manifest_wire, size_t manifest_len, unsigned role,
    const unsigned char host_nonce[QIHSE_CT1_NODE_QUOTE_NONCE_SIZE],
    const char *current_node_pub_path,
    const unsigned char current_source_signer_pin[32],
    const unsigned char current_target_signer_pin[32],
    const char *current_replication_principal,
    const qihse_ct1_node_quote_expected_t *expected) {
    typedef char sig_size_matches[(QIHSE_CT1_NODE_QUOTE_SIGNATURE_SIZE ==
        QIHSE_MLDSA_SIGNATURE_SIZE) ? 1 : -1];
    (void)sizeof(sig_size_matches);
    if (!quote || quote_len != QIHSE_CT1_NODE_QUOTE_SIZE || !manifest_wire ||
        manifest_len != QIHSE_CT1_RECOVERY_WIRE_SIZE || !host_nonce ||
        !current_source_signer_pin || !current_target_signer_pin ||
        !current_replication_principal ||
        (role != QIHSE_CT1_NODE_QUOTE_SOURCE &&
         role != QIHSE_CT1_NODE_QUOTE_TARGET)) return false;
    size_t principal_len = strnlen(current_replication_principal,
        QIHSE_CT1_RECOVERY_ID_MAX + 1u);
    if (!principal_len || principal_len > QIHSE_CT1_RECOVERY_ID_MAX) return false;
    unsigned char nonzero = 0;
    for (size_t i = 0; i < QIHSE_CT1_NODE_QUOTE_NONCE_SIZE; ++i)
        nonzero |= host_nonce[i];
    if (!nonzero) return false;

    qihse_ct1_recovery_manifest_t manifest;
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    if (!qihse_ct1_recovery_decode(manifest_wire, manifest_len, false,
            &manifest, NULL) ||
        !qihse_ct1_recovery_encode(&manifest, false, false, canonical) ||
        memcmp(canonical, manifest_wire, sizeof(canonical)) ||
        CRYPTO_memcmp(manifest.nonce, host_nonce, 32) ||
        strcmp(manifest.source_qkp_id, manifest.target_qkp_id) == 0 ||
        CRYPTO_memcmp(current_source_signer_pin,
            current_target_signer_pin, 32) == 0 ||
        strcmp(manifest.source_peer_qkp_id, manifest.target_peer_qkp_id) == 0 ||
        CRYPTO_memcmp(manifest.source_peer_pin, manifest.target_peer_pin, 32) == 0 ||
        strcmp(manifest.replication_principal_id,
            current_replication_principal) != 0 ||
        (expected && (!matches_expected(&manifest, expected) ||
            CRYPTO_memcmp(current_source_signer_pin, expected->source_signer_pin, 32) ||
            CRYPTO_memcmp(current_target_signer_pin, expected->target_signer_pin, 32))))
        return false;

    const unsigned char *signer_pin = role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        current_source_signer_pin : current_target_signer_pin;
    const unsigned char *peer_pin = role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        manifest.source_peer_pin : manifest.target_peer_pin;
    unsigned char pin[32];
    EVP_PKEY *key = public_pin(current_node_pub_path, pin);
    if (!key) return false;
    if (CRYPTO_memcmp(pin, signer_pin, sizeof(pin)) ||
        CRYPTO_memcmp(pin, peer_pin, sizeof(pin)) == 0) {
        EVP_PKEY_free(key);
        return false;
    }

    unsigned char signed_expected[QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE];
    bool valid = quote_prefix(signed_expected, canonical, &manifest, role,
            host_nonce, pin) &&
        CRYPTO_memcmp(signed_expected, quote, sizeof(signed_expected)) == 0 &&
        qihse_pqc_verify_with_key(quote, sizeof(signed_expected),
            quote + sizeof(signed_expected), key);
    EVP_PKEY_free(key);
    return valid;
}

bool qihse_ct1_node_quote_verify(const unsigned char *quote, size_t quote_len,
    const unsigned char *manifest_wire, size_t manifest_len, unsigned role,
    const unsigned char host_nonce[QIHSE_CT1_NODE_QUOTE_NONCE_SIZE],
    const char *current_node_pub_path,
    const unsigned char current_source_signer_pin[32],
    const unsigned char current_target_signer_pin[32],
    const char *current_replication_principal) {
    return verify_quote(quote, quote_len, manifest_wire, manifest_len, role,
        host_nonce, current_node_pub_path, current_source_signer_pin,
        current_target_signer_pin, current_replication_principal, NULL);
}

bool qihse_ct1_node_quote_verify_strict(const unsigned char *quote, size_t quote_len,
    const unsigned char *manifest_wire, size_t manifest_len, unsigned role,
    const unsigned char host_nonce[QIHSE_CT1_NODE_QUOTE_NONCE_SIZE],
    const char *current_node_pub_path,
    const qihse_ct1_node_quote_expected_t *expected) {
    if (!expected) return false;
    return verify_quote(quote, quote_len, manifest_wire, manifest_len, role,
        host_nonce, current_node_pub_path, expected->source_signer_pin,
        expected->target_signer_pin, expected->replication_principal_id, expected);
}

bool qihse_ct1_node_quote_verify_paired_stale(
    const unsigned char *source_quote, size_t source_quote_len,
    const unsigned char *target_quote, size_t target_quote_len,
    const unsigned char *manifest_wire, size_t manifest_len,
    const unsigned char host_nonce[QIHSE_CT1_NODE_QUOTE_NONCE_SIZE],
    const char *trusted_source_pub_path, const char *trusted_target_pub_path,
    const qihse_ct1_node_quote_expected_t *trusted_source_expected,
    const qihse_ct1_node_quote_expected_t *trusted_target_expected) {
    if (!trusted_source_expected || !trusted_target_expected ||
        strncmp(trusted_source_expected->source_qkp_id,
            trusted_target_expected->source_qkp_id, QIHSE_CT1_RECOVERY_ID_MAX + 1u) ||
        strncmp(trusted_source_expected->target_qkp_id,
            trusted_target_expected->target_qkp_id, QIHSE_CT1_RECOVERY_ID_MAX + 1u) ||
        strncmp(trusted_source_expected->source_peer_qkp_id,
            trusted_source_expected->target_qkp_id, QIHSE_CT1_RECOVERY_ID_MAX + 1u) ||
        strncmp(trusted_target_expected->target_peer_qkp_id,
            trusted_target_expected->source_qkp_id, QIHSE_CT1_RECOVERY_ID_MAX + 1u) ||
        CRYPTO_memcmp(trusted_source_expected->source_signer_pin,
            trusted_target_expected->source_signer_pin, 32) ||
        CRYPTO_memcmp(trusted_source_expected->target_signer_pin,
            trusted_target_expected->target_signer_pin, 32) ||
        CRYPTO_memcmp(trusted_source_expected->source_peer_pin,
            trusted_target_expected->target_signer_pin, 32) ||
        CRYPTO_memcmp(trusted_target_expected->target_peer_pin,
            trusted_source_expected->source_signer_pin, 32)) return false;
    if (!qihse_ct1_node_quote_verify_strict(source_quote, source_quote_len,
            manifest_wire, manifest_len, QIHSE_CT1_NODE_QUOTE_SOURCE,
            host_nonce, trusted_source_pub_path, trusted_source_expected) ||
        !qihse_ct1_node_quote_verify_strict(target_quote, target_quote_len,
            manifest_wire, manifest_len, QIHSE_CT1_NODE_QUOTE_TARGET,
            host_nonce, trusted_target_pub_path, trusted_target_expected)) return false;

    qihse_ct1_recovery_manifest_t manifest;
    if (!qihse_ct1_recovery_decode(manifest_wire, manifest_len, false,
            &manifest, NULL)) return false;
    return manifest.row_change_seq < manifest.tombstone_row_seq &&
        manifest.row_change_seq <= manifest.source_high_water &&
        manifest.tombstone_row_seq <= manifest.target_high_water &&
        manifest.tombstone_position <= manifest.target_cursor &&
        manifest.target_cursor < UINT64_MAX &&
        manifest.frame_position == manifest.target_cursor + 1u;
}

bool qihse_ct1_node_quote_sign_verified(
    const qihse_ct1_node_quote_signing_evidence_t *e,
    unsigned char out[QIHSE_CT1_NODE_QUOTE_SIZE]) {
    if (!out) return false;
    memset(out, 0, QIHSE_CT1_NODE_QUOTE_SIZE);
    if (!e || !e->manifest_wire || e->manifest_len != QIHSE_CT1_RECOVERY_WIRE_SIZE ||
        !e->verified_manifest || !e->expected || !e->host_nonce ||
        !e->own_private_key_path || !*e->own_private_key_path ||
        !e->own_public_key_path || !*e->own_public_key_path ||
        (e->role != QIHSE_CT1_NODE_QUOTE_SOURCE &&
         e->role != QIHSE_CT1_NODE_QUOTE_TARGET)) return false;
    unsigned char nonzero = 0;
    for (size_t i = 0; i < QIHSE_CT1_NODE_QUOTE_NONCE_SIZE; ++i)
        nonzero |= e->host_nonce[i];
    if (!nonzero) return false;
    qihse_ct1_recovery_manifest_t manifest;
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    if (!qihse_ct1_recovery_decode(e->manifest_wire, e->manifest_len, false,
            &manifest, NULL) ||
        !qihse_ct1_recovery_encode(&manifest, false, false, canonical) ||
        CRYPTO_memcmp(canonical, e->manifest_wire, sizeof(canonical)) ||
        !qihse_ct1_recovery_matches(&manifest, e->verified_manifest, e->now_ms, false) ||
        CRYPTO_memcmp(manifest.nonce, e->host_nonce, 32) ||
        !matches_expected(&manifest, e->expected)) return false;
    const unsigned char *signer_pin = e->role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        e->expected->source_signer_pin : e->expected->target_signer_pin;
    const unsigned char *peer_pin = e->role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        e->expected->source_peer_pin : e->expected->target_peer_pin;
    unsigned char pin[32];
    EVP_PKEY *key = public_pin(e->own_public_key_path, pin);
    if (!key) return false;
    bool ok = !CRYPTO_memcmp(pin, signer_pin, 32) &&
        CRYPTO_memcmp(pin, peer_pin, 32) &&
        quote_prefix(out, canonical, &manifest, e->role, e->host_nonce, pin) &&
        qihse_pqc_sign_path(out, QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE,
            out + QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE, e->own_private_key_path) &&
        qihse_pqc_verify_with_key(out, QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE,
            out + QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE, key);
    EVP_PKEY_free(key);
    if (!ok) memset(out, 0, QIHSE_CT1_NODE_QUOTE_SIZE);
    return ok;
}
