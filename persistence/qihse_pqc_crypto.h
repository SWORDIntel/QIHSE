#ifndef QIHSE_PQC_CRYPTO_H
#define QIHSE_PQC_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ── Algorithm constants ──────────────────────────────────────────────── */

#define QIHSE_AES_256_KEY_SIZE      32   /* AES-256 key */
#define QIHSE_AES_GCM_IV_SIZE       12   /* 96-bit IV for AES-256-GCM */
#define QIHSE_AES_GCM_TAG_SIZE      16   /* 128-bit GCM authentication tag */

#define QIHSE_MLKEM_CIPHERTEXT_SIZE 1568 /* ML-KEM-1024 ciphertext */
#define QIHSE_MLKEM_SHARED_SIZE       32 /* ML-KEM-1024 shared secret (= AES-256 key) */
#define QIHSE_MLDSA_SIGNATURE_SIZE  4627 /* ML-DSA-87 signature */

/* ── Key file locations ───────────────────────────────────────────────── */

/* ML-KEM-1024: used for key encapsulation (at-rest AES key wrapping).
 * Generate with: scripts/qihse_keygen.sh  */
#define QIHSE_KEM_PRIVATE_KEY_FILE  "qihse_kem_key.pem"
#define QIHSE_KEM_PUBLIC_KEY_FILE   "qihse_kem_pub.pem"

/* ML-DSA-87: used for signing container manifests and audit log entries.
 * Generate with: scripts/qihse_keygen.sh  */
#define QIHSE_DSA_PRIVATE_KEY_FILE  "qihse_dsa_key.pem"
#define QIHSE_DSA_PUBLIC_KEY_FILE   "qihse_dsa_pub.pem"

/* ── Context ──────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t aes_key[QIHSE_AES_256_KEY_SIZE]; /* AES-256 session key (zeroed on destroy) */
    bool initialized;
} qihse_pqc_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * qihse_pqc_init_providers - Load the best available OpenSSL provider.
 *
 * Call once at application startup before any PQC operations.
 * Returns 1 if the FIPS 140-3 validated module is active, 0 if using
 * the standard default provider.
 */
int qihse_pqc_init_providers(void);

/*
 * qihse_pqc_init - Establish a session key via ML-KEM-1024.
 *
 * Encapsulate path (encapsulated_key_in == NULL):
 *   Reads qihse_kem_pub.pem, runs EVP_PKEY_encapsulate() to generate a fresh
 *   ML-KEM ciphertext and 32-byte shared secret. The shared secret IS the AES-256
 *   session key. Writes the ciphertext to encapsulated_key_out
 *   (must be QIHSE_MLKEM_CIPHERTEXT_SIZE bytes).
 *
 * Decapsulate path (encapsulated_key_in != NULL):
 *   Reads qihse_kem_key.pem, runs EVP_PKEY_decapsulate() on the provided
 *   ciphertext to recover the 32-byte shared secret, which becomes the AES-256
 *   session key.
 *
 * Returns false and leaves ctx uninitialized on any failure. No silent
 * fallback to plaintext.
 */
bool qihse_pqc_init(qihse_pqc_ctx_t* ctx,
                    const uint8_t* encapsulated_key_in,
                    uint8_t* encapsulated_key_out);

/* Zero and release the session key. Always call when done. */
void qihse_pqc_destroy(qihse_pqc_ctx_t* ctx);

/*
 * qihse_pqc_encrypt - Encrypt with AES-256-GCM.
 * Output layout: [12-byte IV][ciphertext][16-byte GCM tag]
 * out_buffer must be at least (in_len + QIHSE_AES_GCM_IV_SIZE + QIHSE_AES_GCM_TAG_SIZE).
 * Returns total bytes written, or 0 on failure.
 */
size_t qihse_pqc_encrypt(qihse_pqc_ctx_t* ctx,
                         const uint8_t* in_data, size_t in_len,
                         uint8_t* out_buffer);

/*
 * qihse_pqc_decrypt - Decrypt AES-256-GCM ciphertext produced by qihse_pqc_encrypt.
 * Returns plaintext bytes written, or 0 on failure (including authentication failure).
 */
size_t qihse_pqc_decrypt(qihse_pqc_ctx_t* ctx,
                         const uint8_t* in_data, size_t in_len,
                         uint8_t* out_buffer);

/*
 * qihse_pqc_sign - Sign data with ML-DSA-87 (reads qihse_dsa_key.pem).
 * out_sig must be QIHSE_MLDSA_SIGNATURE_SIZE bytes.
 */
bool qihse_pqc_sign(const uint8_t* data, size_t len, uint8_t* out_sig);

/*
 * qihse_pqc_verify - Verify an ML-DSA-87 signature (reads qihse_dsa_pub.pem).
 */
bool qihse_pqc_verify(const uint8_t* data, size_t len, const uint8_t* sig);

/*
 * qihse_pqc_keygen - Generate CNSA 2.0 keypairs natively in C.
 *
 * Writes four PEM files into out_dir (pass NULL or "." for the current
 * directory):
 *   qihse_kem_key.pem / qihse_kem_pub.pem  — ML-KEM-1024
 *   qihse_dsa_key.pem / qihse_dsa_pub.pem  — ML-DSA-87
 *
 * Private keys are chmod 600'd automatically.
 * A round-trip self-test is run on each pair; returns false on any failure.
 *
 * Call qihse_pqc_init_providers() first to route generation through the
 * FIPS 140-3 validated module when available.
 */
bool qihse_pqc_keygen(const char* out_dir);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_PQC_CRYPTO_H */
