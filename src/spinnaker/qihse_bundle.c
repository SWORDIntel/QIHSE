#include "qihse_bundle.h"
#include "qihse_audit.h"
#include "qihse_pqc_crypto.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

struct qihse_bundle_composer {
    qihse_blob_store_t* blobs;
    qihse_kv_store_t* kv;
    char keys_dir[480];
    char dsa_key_path[576];
};

qihse_bundle_composer_t* qihse_bundle_composer_create(qihse_blob_store_t* blobs,
                                                      qihse_kv_store_t* kv,
                                                      const char* keys_dir,
                                                      const char* dsa_private_key_path) {
    if (!blobs || !kv || !keys_dir || !*keys_dir) return NULL;
    if (strlen(keys_dir) >= sizeof(((qihse_bundle_composer_t*)0)->keys_dir)) return NULL;
    qihse_bundle_composer_t* composer = calloc(1, sizeof(*composer));
    if (!composer) return NULL;
    composer->blobs = blobs;
    composer->kv = kv;
    snprintf(composer->keys_dir, sizeof(composer->keys_dir), "%s", keys_dir);
    if (dsa_private_key_path && *dsa_private_key_path) {
        snprintf(composer->dsa_key_path, sizeof(composer->dsa_key_path), "%s", dsa_private_key_path);
    }
    /* Route ML-KEM/ML-DSA through the FIPS module when available. */
    qihse_pqc_init_providers();
    return composer;
}

void qihse_bundle_composer_destroy(qihse_bundle_composer_t* composer) {
    free(composer);
}

/* --------------------------------------------------------------------------
 * Manifest buffer
 * -------------------------------------------------------------------------- */
typedef struct {
    char* data;
    size_t len;
    size_t cap;
    bool ok;
} manifest_buf_t;

static void manifest_append(manifest_buf_t* buf, const char* text) {
    if (!buf->ok) return;
    size_t add = strlen(text);
    if (buf->len + add + 1u > buf->cap) {
        size_t next = buf->cap ? buf->cap * 2u : 4096u;
        while (next < buf->len + add + 1u) next *= 2u;
        char* grown = realloc(buf->data, next);
        if (!grown) {
            free(buf->data);
            buf->data = NULL;
            buf->ok = false;
            return;
        }
        buf->data = grown;
        buf->cap = next;
    }
    memcpy(buf->data + buf->len, text, add);
    buf->len += add;
    buf->data[buf->len] = '\0';
}

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */
static bool valid_fingerprint(const char* s) {
    if (!s || strlen(s) != 16u) return false;
    for (size_t i = 0; i < 16u; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return true;
}

static void tenant_key_path(const qihse_bundle_composer_t* composer,
                            uint32_t tenant_id, char* path, size_t cap) {
    snprintf(path, cap, "%s/tenant-%u-kem_pub.pem", composer->keys_dir, tenant_id);
}

/* Reads an authorization-checked KV pointer ("t:<tid>/bundle/...") holding a
 * blob hash in hex. Returns false when absent. */
static bool kv_blob_pointer(qihse_bundle_composer_t* composer, qihse_user_t* user,
                            uint32_t tenant_id, const char* kind,
                            const char* fingerprint, char hex[QIHSE_BLOB_HASH_HEX]) {
    char key[256];
    if (fingerprint) {
        snprintf(key, sizeof(key), "t:%u/bundle/%s/%s", tenant_id, kind, fingerprint);
    } else {
        snprintf(key, sizeof(key), "t:%u/bundle/%s", tenant_id, kind);
    }
    char* value = qihse_kv_get_user(composer->kv, key, user);
    if (!value) return false;
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    bool ok = strlen(value) == QIHSE_BLOB_HASH_BYTES * 2u &&
              qihse_blob_hash_from_hex(value, hash);
    if (ok) memcpy(hex, value, QIHSE_BLOB_HASH_HEX);
    free(value);
    return ok;
}

bool qihse_bundle_compose(qihse_bundle_composer_t* composer, qihse_user_t* user,
                          uint32_t tenant_id, const char* fingerprint_hex,
                          const char** have_hexes, size_t have_count,
                          char** out_manifest, size_t* out_len,
                          char* err, size_t err_cap) {
    if (err && err_cap > 0) err[0] = '\0';
    if (!composer || !user || !fingerprint_hex || !out_manifest || !out_len) {
        return false;
    }
    if (!qihse_auth_user_is_active(user)) {
        snprintf(err, err_cap, "principal is not active");
        return false;
    }
    uint32_t user_tenant = qihse_user_get_tenant_id(user);
    if (user_tenant != QIHSE_TENANT_SYSTEM && user_tenant != tenant_id) {
        snprintf(err, err_cap, "bundle requested for a foreign tenant");
        return false;
    }
    if (!valid_fingerprint(fingerprint_hex)) {
        snprintf(err, err_cap, "malformed build fingerprint");
        return false;
    }

    /* 1. Fresh per-session entitlement key-seed: encapsulate under the
     *    tenant client's KEM public key. Never persisted. */
    char peer_pub_path[512];
    tenant_key_path(composer, tenant_id, peer_pub_path, sizeof(peer_pub_path));
    qihse_pqc_ctx_t session_ctx;
    memset(&session_ctx, 0, sizeof(session_ctx));
    uint8_t ciphertext[QIHSE_MLKEM_CIPHERTEXT_SIZE];
    if (!qihse_pqc_encapsulate_peer(&session_ctx, peer_pub_path, ciphertext)) {
        snprintf(err, err_cap, "session-key encapsulation failed (tenant KEM key missing or invalid)");
        return false;
    }
    qihse_pqc_destroy(&session_ctx); /* compose-time only; wiped immediately */

    /* 2. Pattern bundle for this build — the sanity gate (poison defense). */
    char pattern_hex[QIHSE_BLOB_HASH_HEX];
    if (!kv_blob_pointer(composer, user, tenant_id, "pattern", fingerprint_hex, pattern_hex)) {
        snprintf(err, err_cap, "no pattern bundle recorded for this build");
        return false;
    }
    uint8_t pattern_hash[QIHSE_BLOB_HASH_BYTES];
    qihse_blob_hash_from_hex(pattern_hex, pattern_hash);
    qihse_blob_info_t pattern_info;
    if (!qihse_blob_info_user(composer->blobs, pattern_hash, &pattern_info, user)) {
        snprintf(err, err_cap, "sanity gate rejected: pattern blob unreadable");
        return false;
    }
    if (pattern_info.tenant_id != tenant_id ||
        pattern_info.tag != (uint16_t)QIHSE_BLOB_TAG_PATTERN_BUNDLE) {
        qihse_audit_log("BUNDLE_SANITY_GATE_REJECTED", user_tenant, tenant_id,
                        pattern_info.classification, pattern_info.sci_compartment);
        snprintf(err, err_cap, "sanity gate rejected: pattern blob binding does not match tenant/build");
        return false;
    }

    /* 3. Optional tenant script set. */
    char script_hex[QIHSE_BLOB_HASH_HEX] = {0};
    bool have_script = kv_blob_pointer(composer, user, tenant_id, "scripts", NULL, script_hex);

    /* 4. Delta: drop blobs the client already holds. */
    bool skip_pattern = false;
    bool skip_script = false;
    for (size_t i = 0; i < have_count; i++) {
        size_t hex_len = QIHSE_BLOB_HASH_HEX - 1u;
        if (have_hexes[i] && strncmp(have_hexes[i], pattern_hex, hex_len) == 0) skip_pattern = true;
        if (have_hexes[i] && strncmp(have_hexes[i], script_hex, hex_len) == 0) skip_script = true;
    }

    /* 5. Assemble the manifest. */
    manifest_buf_t buf = { NULL, 0, 0, true };
    char line[3400];
    manifest_append(&buf, "QHSE-BUNDLE 1\n");
    snprintf(line, sizeof(line), "tenant:%u\n", tenant_id);
    manifest_append(&buf, line);
    snprintf(line, sizeof(line), "build:%s\n", fingerprint_hex);
    manifest_append(&buf, line);
    manifest_append(&buf, "session-key:MLKEM1024 ");
    {
        char hex_ct[QIHSE_MLKEM_CIPHERTEXT_SIZE * 2u + 1u];
        for (size_t i = 0; i < QIHSE_MLKEM_CIPHERTEXT_SIZE; i++) {
            snprintf(hex_ct + i * 2u, 3u, "%02x", ciphertext[i]);
        }
        manifest_append(&buf, hex_ct);
    }
    manifest_append(&buf, "\n");
    if (!skip_pattern) {
        uint64_t size = 0;
        qihse_blob_size_user(composer->blobs, pattern_hash, &size, user);
        snprintf(line, sizeof(line), "blob:%s %llu pattern_bundle\n", pattern_hex, (unsigned long long)size);
        manifest_append(&buf, line);
    }
    if (have_script && !skip_script) {
        uint8_t script_hash[QIHSE_BLOB_HASH_BYTES];
        qihse_blob_hash_from_hex(script_hex, script_hash);
        uint64_t size = 0;
        if (qihse_blob_size_user(composer->blobs, script_hash, &size, user)) {
            snprintf(line, sizeof(line), "blob:%s %llu script_set\n", script_hex, (unsigned long long)size);
            manifest_append(&buf, line);
        }
    }

    /* 6. Server authenticity: sign the manifest body with ML-DSA-87. */
    if (buf.ok && composer->dsa_key_path[0]) {
        uint8_t signature[QIHSE_MLDSA_SIGNATURE_SIZE];
        if (qihse_pqc_sign_path((const uint8_t*)buf.data, buf.len, signature, composer->dsa_key_path)) {
            manifest_append(&buf, "sig:MLDSA87 ");
            char hex_sig[QIHSE_MLDSA_SIGNATURE_SIZE * 2u + 1u];
            for (size_t i = 0; i < QIHSE_MLDSA_SIGNATURE_SIZE; i++) {
                snprintf(hex_sig + i * 2u, 3u, "%02x", signature[i]);
            }
            manifest_append(&buf, hex_sig);
            manifest_append(&buf, "\n");
        }
    }

    if (!buf.ok || !buf.data) {
        free(buf.data);
        OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
        snprintf(err, err_cap, "manifest allocation failed");
        return false;
    }
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    *out_manifest = buf.data;
    *out_len = buf.len;
    return true;
}
