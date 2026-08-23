#ifndef QIHSE_UWP_TLS_H
#define QIHSE_UWP_TLS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque server-side TLS context.
 *
 * Two flavours are supported:
 *   - Symmetric-key context (random 32-byte ChaCha20 key): the legacy
 *     AEAD-only path. Suitable for environments without certificate
 *     infrastructure but NOT recommended for production.
 *   - Certificate-based context (real X.509 certificate + private key
 *     backed by an OpenSSL SSL_CTX): provides genuine TLS 1.3 on the wire
 *     via SSL_accept/SSL_connect. This is the production-grade path.
 */
typedef struct qihse_uwp_tls_ctx qihse_uwp_tls_ctx_t;

/* Opaque per-connection TLS session.
 *
 * For certificate-based contexts the session wraps an OpenSSL SSL* object
 * and performs real TLS 1.3 record-layer encryption/decryption through
 * SSL_write/SSL_read. For symmetric-key contexts the session uses the
 * ChaCha20-Poly1305 AEAD record format:
 *
 *     [ 12-byte nonce ][ ciphertext ][ 16-byte Poly1305 tag ]
 */
typedef struct qihse_uwp_tls_session qihse_uwp_tls_session_t;

/**
 * @brief Create a server-side TLS context using a random symmetric key.
 *
 * Generates a fresh 32-byte ChaCha20 server key via RAND_bytes. The key is
 * held for the lifetime of the context and used to derive per-connection
 * session keys.
 *
 * @note This is the legacy AEAD-only path. It is NOT recommended for
 *       production deployments that have access to certificate infrastructure;
 *       prefer qihse_uwp_tls_ctx_create_with_cert() or
 *       qihse_uwp_tls_ctx_create_selfsigned() for real TLS 1.3.
 *
 * @return Newly allocated context, or NULL on allocation/RNG failure.
 *         Caller must destroy with qihse_uwp_tls_ctx_destroy().
 */
qihse_uwp_tls_ctx_t* qihse_uwp_tls_ctx_create(void);

/**
 * @brief Create a server-side TLS context from an X.509 certificate and
 *        private key (PEM-encoded).
 *
 * This is the production-grade path: it builds a real OpenSSL SSL_CTX
 * configured for TLS 1.3, loads the supplied certificate chain and private
 * key via SSL_CTX_use_certificate_chain_file() /
 * SSL_CTX_use_PrivateKey_file(), and validates that the key matches the
 * certificate. Sessions created from this context perform genuine TLS 1.3
 * handshakes on the wire.
 *
 * @param cert_pem PEM-encoded certificate chain (NUL-terminated string).
 * @param key_pem  PEM-encoded private key matching @p cert_pem.
 * @return Newly allocated context, or NULL on failure.
 *         Caller must destroy with qihse_uwp_tls_ctx_destroy().
 */
qihse_uwp_tls_ctx_t* qihse_uwp_tls_ctx_create_with_cert(const char* cert_pem,
                                                        const char* key_pem);

/**
 * @brief Create a server-side TLS context with a freshly generated
 *        self-signed X.509 certificate and EC (P-256) key.
 *
 * Generates an ephemeral self-signed certificate (valid for one year) using
 * OpenSSL's X509 APIs (X509_new, X509_set_version, X509_set_subject_name,
 * X509_set_pubkey, X509_sign, ...) and an EC key of the requested size,
 * then wraps it in a TLS 1.3 SSL_CTX ready for use. Useful for development,
 * testing, and closed environments where a full PKI is unavailable.
 *
 * @param common_name Common Name (CN) for the certificate subject. May be
 *                    NULL, in which case "qihse-uwp-tls" is used.
 * @param key_bits    Requested key size in bits. Supported: 256 (P-256,
 *                    default), 384 (P-384), 521 (P-521). Any other value
 *                    defaults to 256.
 * @return Newly allocated context, or NULL on failure.
 *         Caller must destroy with qihse_uwp_tls_ctx_destroy().
 */
qihse_uwp_tls_ctx_t* qihse_uwp_tls_ctx_create_selfsigned(const char* common_name,
                                                         size_t key_bits);

/**
 * @brief Destroy a server-side TLS context and zeroise its key material.
 */
void qihse_uwp_tls_ctx_destroy(qihse_uwp_tls_ctx_t* ctx);

/**
 * @brief Rotate the server key material of a TLS context.
 *
 * For symmetric-key contexts: generates a fresh 32-byte server key. Existing
 * sessions continue to use their already-derived session keys until they
 * reconnect, at which point they pick up the new server key.
 *
 * For certificate-based contexts: regenerates a new self-signed certificate
 * and private key (preserving the original common name / key size) and
 * rebuilds the SSL_CTX. Existing SSL sessions are unaffected until they
 * re-handshake.
 *
 * @param ctx Context to rotate. Must be non-NULL.
 * @return 0 on success, non-zero on error.
 */
int qihse_uwp_tls_ctx_rotate_key(qihse_uwp_tls_ctx_t* ctx);

/**
 * @brief Create a per-connection TLS session (symmetric-key / AEAD path).
 *
 * Derives a session key from the server key and a fresh random connection
 * nonce (HKDF-SHA256 when available, otherwise a simple XOR-mix fallback).
 * Each session owns its own key material and a monotonic nonce counter so it
 * is safe to use from a single connection thread.
 *
 * @note This entry point is for the symmetric-key AEAD path only. For
 *       certificate-based contexts use
 *       qihse_uwp_tls_session_create_with_fd() which performs a real TLS
 *       1.3 handshake.
 *
 * @param ctx Server context to derive from. Must be non-NULL and symmetric.
 * @return Newly allocated session, or NULL on failure.
 *         Caller must destroy with qihse_uwp_tls_session_destroy().
 */
qihse_uwp_tls_session_t* qihse_uwp_tls_session_create(qihse_uwp_tls_ctx_t* ctx);

/**
 * @brief Create a per-connection TLS session bound to a connected socket
 *        and perform the server-side TLS 1.3 handshake.
 *
 * For certificate-based contexts this creates an OpenSSL SSL* object,
 * associates it with @p fd via SSL_set_fd(), and performs SSL_accept() to
 * complete the TLS 1.3 handshake. Subsequent encrypt/decrypt calls operate
 * through SSL_write/SSL_read.
 *
 * @param ctx Certificate-based server context. Must be non-NULL.
 * @param fd  Connected TCP socket file descriptor (server side).
 * @return Newly allocated session with an established TLS channel, or NULL
 *         on handshake failure. Caller must destroy with
 *         qihse_uwp_tls_session_destroy().
 */
qihse_uwp_tls_session_t* qihse_uwp_tls_session_create_with_fd(
    qihse_uwp_tls_ctx_t* ctx, int fd);

/**
 * @brief Destroy a per-connection TLS session and zeroise its key material.
 */
void qihse_uwp_tls_session_destroy(qihse_uwp_tls_session_t* session);

/**
 * @brief Renegotiate / re-key an established session.
 *
 * For TLS (SSL*) sessions: invokes SSL_renegotiate() to drive a handshake
 * re-key on the existing channel.
 *
 * For AEAD sessions: re-derives the session key from the context's current
 * server key and a fresh random connection nonce, and resets the nonce
 * counter.
 *
 * @param session Session to renegotiate. Must be non-NULL.
 * @return 0 on success, non-zero on error.
 */
int qihse_uwp_tls_session_renegotiate(qihse_uwp_tls_session_t* session);

/**
 * @brief Encrypt plaintext.
 *
 * For AEAD sessions the output layout is:
 *     [12-byte nonce][ciphertext][16-byte Poly1305 tag]
 * so @p cap must be at least @p len + 28 bytes.
 *
 * For TLS (SSL*) sessions the ciphertext buffer is not used; the plaintext
 * is written directly to the socket via SSL_write() (the TLS record layer
 * performs the encryption). @p ciphertext may be NULL and @p cap may be 0
 * in this case. @p out_len is set to @p len on success.
 *
 * @param session    Session with an established key/channel.
 * @param plaintext  Input plaintext buffer.
 * @param len        Length of plaintext.
 * @param ciphertext Output buffer (AEAD) or unused (TLS).
 * @param cap        Capacity of the output buffer.
 * @param out_len    Set to the number of bytes written on success.
 * @return 0 on success, non-zero on error.
 */
int qihse_uwp_tls_encrypt(qihse_uwp_tls_session_t* session,
                          const uint8_t* plaintext, size_t len,
                          uint8_t* ciphertext, size_t cap, size_t* out_len);

/**
 * @brief Decrypt and authenticate a record.
 *
 * For AEAD sessions the expected input layout is:
 *     [12-byte nonce][ciphertext][16-byte Poly1305 tag]
 *
 * For TLS (SSL*) sessions the ciphertext buffer is not used; plaintext is
 * read directly from the socket via SSL_read() (the TLS record layer
 * performs the decryption/authentication). @p ciphertext may be NULL and
 * @p len may be 0 in this case.
 *
 * @param session    Session with an established key/channel.
 * @param ciphertext Input ciphertext buffer (AEAD) or unused (TLS).
 * @param len        Total length of the input (AEAD) or unused (TLS).
 * @param plaintext  Output buffer.
 * @param cap        Capacity of the output buffer.
 * @param out_len    Set to the number of plaintext bytes on success.
 * @return 0 on success, -1 on authentication failure (AEAD tag mismatch),
 *         other non-zero on operational error.
 */
int qihse_uwp_tls_decrypt(qihse_uwp_tls_session_t* session,
                          const uint8_t* ciphertext, size_t len,
                          uint8_t* plaintext, size_t cap, size_t* out_len);

/**
 * @brief Report whether a session has an active key / established channel.
 * @return true if the session holds a derived key or an SSL* channel,
 *         false otherwise.
 */
bool qihse_uwp_tls_enabled(qihse_uwp_tls_session_t* session);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_UWP_TLS_H */
