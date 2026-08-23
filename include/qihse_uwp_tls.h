#ifndef QIHSE_UWP_TLS_H
#define QIHSE_UWP_TLS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque server-side TLS context (holds the long-lived ChaCha20 key pair). */
typedef struct qihse_uwp_tls_ctx qihse_uwp_tls_ctx_t;

/* Opaque per-connection TLS session (holds derived session key + nonces). */
typedef struct qihse_uwp_tls_session qihse_uwp_tls_session_t;

/**
 * @brief Create a server-side TLS context.
 *
 * Generates a fresh 32-byte ChaCha20 server key via RAND_bytes. The key is
 * held for the lifetime of the context and used to derive per-connection
 * session keys.
 *
 * @return Newly allocated context, or NULL on allocation/RNG failure.
 *         Caller must destroy with qihse_uwp_tls_ctx_destroy().
 */
qihse_uwp_tls_ctx_t* qihse_uwp_tls_ctx_create(void);

/**
 * @brief Destroy a server-side TLS context and zeroise its key material.
 */
void qihse_uwp_tls_ctx_destroy(qihse_uwp_tls_ctx_t* ctx);

/**
 * @brief Create a per-connection TLS session.
 *
 * Derives a session key from the server key and a fresh random connection
 * nonce (HKDF-SHA256 when available, otherwise a simple XOR-mix fallback).
 * Each session owns its own key material and an atomic nonce counter so it
 * is safe to use from a single connection thread.
 *
 * @param ctx Server context to derive from. Must be non-NULL.
 * @return Newly allocated session, or NULL on failure.
 *         Caller must destroy with qihse_uwp_tls_session_destroy().
 */
qihse_uwp_tls_session_t* qihse_uwp_tls_session_create(qihse_uwp_tls_ctx_t* ctx);

/**
 * @brief Destroy a per-connection TLS session and zeroise its key material.
 */
void qihse_uwp_tls_session_destroy(qihse_uwp_tls_session_t* session);

/**
 * @brief Encrypt plaintext using ChaCha20-Poly1305 AEAD.
 *
 * The output layout is: [12-byte nonce][ciphertext][16-byte Poly1305 tag].
 * Therefore @p cap must be at least @p len + 28 bytes.
 *
 * @param session  Session with a derived key.
 * @param plaintext Input plaintext buffer.
 * @param len      Length of plaintext.
 * @param ciphertext Output buffer (must hold len + 28 bytes).
 * @param cap      Capacity of the output buffer.
 * @param out_len  Set to the number of bytes written on success.
 * @return 0 on success, non-zero on error (e.g. insufficient capacity,
 *         missing key, or OpenSSL unavailable at compile time).
 */
int qihse_uwp_tls_encrypt(qihse_uwp_tls_session_t* session,
                          const uint8_t* plaintext, size_t len,
                          uint8_t* ciphertext, size_t cap, size_t* out_len);

/**
 * @brief Decrypt and authenticate a ChaCha20-Poly1305 AEAD record.
 *
 * Expected input layout: [12-byte nonce][ciphertext][16-byte Poly1305 tag].
 *
 * @param session   Session with a derived key.
 * @param ciphertext Input ciphertext buffer (nonce + ciphertext + tag).
 * @param len       Total length of the input (must be >= 28).
 * @param plaintext  Output buffer (must hold len - 28 bytes).
 * @param cap       Capacity of the output buffer.
 * @param out_len   Set to the number of plaintext bytes on success.
 * @return 0 on success, -1 on authentication failure (tag mismatch or
 *         malformed input), other non-zero on operational error.
 */
int qihse_uwp_tls_decrypt(qihse_uwp_tls_session_t* session,
                          const uint8_t* ciphertext, size_t len,
                          uint8_t* plaintext, size_t cap, size_t* out_len);

/**
 * @brief Report whether a session has an active key (TLS enabled).
 * @return true if the session holds a derived key, false otherwise.
 */
bool qihse_uwp_tls_enabled(qihse_uwp_tls_session_t* session);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_UWP_TLS_H */
