#ifndef QIHSE_PQC_CRYPTO_H
#define QIHSE_PQC_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define QIHSE_AES_256_KEY_SIZE 32
#define QIHSE_AES_GCM_IV_SIZE  12
#define QIHSE_AES_GCM_TAG_SIZE 16

#define QIHSE_MLKEM_CIPHERTEXT_SIZE 1568  /* ML-KEM-1024 ciphertext size */
#define QIHSE_MLDSA_SIGNATURE_SIZE  4627  /* ML-DSA-87 signature size */

typedef struct {
    uint8_t aes_key[QIHSE_AES_256_KEY_SIZE];
    bool initialized;
} qihse_pqc_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the PQC context by either generating and encapsulating a new AES key,
   or decapsulating an existing one.
   If encapsulated_key_in is NULL, it generates a new AES key and writes the ML-KEM 
   ciphertext to encapsulated_key_out (must be QIHSE_MLKEM_CIPHERTEXT_SIZE).
   If encapsulated_key_in is provided, it uses the server's private key to decapsulate. */
bool qihse_pqc_init(qihse_pqc_ctx_t* ctx, 
                    const uint8_t* encapsulated_key_in, 
                    uint8_t* encapsulated_key_out);

/* Encrypt a payload using AES-256-GCM. 
   out_buffer must be at least (in_len + QIHSE_AES_GCM_IV_SIZE + QIHSE_AES_GCM_TAG_SIZE).
   Returns the total bytes written, or 0 on failure. */
size_t qihse_pqc_encrypt(qihse_pqc_ctx_t* ctx, 
                         const uint8_t* in_data, size_t in_len,
                         uint8_t* out_buffer);

/* Decrypt a payload using AES-256-GCM. 
   out_buffer must be at least (in_len - QIHSE_AES_GCM_IV_SIZE - QIHSE_AES_GCM_TAG_SIZE).
   Returns the decrypted payload size, or 0 on failure. */
size_t qihse_pqc_decrypt(qihse_pqc_ctx_t* ctx,
                         const uint8_t* in_data, size_t in_len,
                         uint8_t* out_buffer);

/* Sign the manifest or payload using ML-DSA-87.
   out_sig must be QIHSE_MLDSA_SIGNATURE_SIZE bytes. */
bool qihse_pqc_sign(const uint8_t* data, size_t len, uint8_t* out_sig);

/* Verify an ML-DSA-87 signature. */
bool qihse_pqc_verify(const uint8_t* data, size_t len, const uint8_t* sig);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_PQC_CRYPTO_H */
