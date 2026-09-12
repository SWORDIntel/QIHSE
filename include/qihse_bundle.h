#ifndef QIHSE_BUNDLE_H
#define QIHSE_BUNDLE_H

/* U3 — session-bundle composer + RESP delivery (SESSION_DELIVERY_UPGRADES.md).
 *
 * Composes one session bundle for a tenant client:
 *   - a FRESH entitlement key-seed per session: an ML-KEM-1024 encapsulation
 *     under the tenant client's public key (the shared secret is the session
 *     key; it lives in server memory only and is never persisted),
 *   - the pattern bundle recorded for the client's build fingerprint,
 *   - the tenant's script-set blob,
 *   minus any blob hashes the client already holds (delta pull).
 *
 * Sanity gate (commons-poisoning defense): a pattern blob only enters the
 * bundle when it is bound to the requesting tenant AND tagged
 * pattern_bundle — verified against the blob store's authoritative index.
 *
 * The manifest is signed with the server's ML-DSA-87 key so clients can
 * detect tampered or forged manifests.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qihse_auth.h"
#include "qihse_blob.h"
#include "qihse_kv_store.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_BUNDLE_MAX_BLOBS     256u
#define QIHSE_BUNDLE_CHUNK_SIZE    (64u * 1024u)

typedef struct qihse_bundle_composer qihse_bundle_composer_t;

/* blobs + kv are borrowed. keys_dir holds per-tenant client KEM public keys
 * named "tenant-<tenant_id>-kem_pub.pem" (uploaded out-of-band by the
 * operator). dsa_private_key_path signs manifests (NULL = skip signing). */
qihse_bundle_composer_t* qihse_bundle_composer_create(qihse_blob_store_t* blobs,
                                                      qihse_kv_store_t* kv,
                                                      const char* keys_dir,
                                                      const char* dsa_private_key_path);
void qihse_bundle_composer_destroy(qihse_bundle_composer_t* composer);

/* Compose a manifest for the tenant of `user` (system-domain callers must
 * pass the tenant via the BUNDLE.PREPARE argument instead; see the RESP
 * handler). fingerprint is hex16. have_hexes are 64-char blob-hash hex
 * strings the client already holds (delta). Returns a malloc'd manifest
 * buffer the caller frees. Every internal read goes through the
 * authorization-checked KV/blob APIs with the caller's user context. */
bool qihse_bundle_compose(qihse_bundle_composer_t* composer, qihse_user_t* user,
                          uint32_t tenant_id, const char* fingerprint_hex,
                          const char** have_hexes, size_t have_count,
                          char** out_manifest, size_t* out_len,
                          char* err, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_BUNDLE_H */
