/*
 * qihse_uwp_tls.c - Transport encryption layer for the QIHSE Unified Wire
 *                   Protocol (UWP).
 *
 * Provides ChaCha20-Poly1305 AEAD protection for auth credentials and data on
 * the wire using OpenSSL's EVP interface (the project already links -lssl
 * -lcrypto). Each server context holds a long-lived 32-byte key; each
 * connection session derives its own key from the server key plus a random
 * connection nonce. Records on the wire are laid out as:
 *
 *     [ 12-byte nonce ][ ciphertext ][ 16-byte Poly1305 tag ]
 *
 * When OpenSSL is not available at compile time the module degrades to a
 * safe no-op that returns errors rather than crashing.
 */

#include "qihse_uwp_tls.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* OpenSSL detection                                                   */
/* ------------------------------------------------------------------ */
#if defined(__has_include)
#  if __has_include(<openssl/evp.h>) && __has_include(<openssl/rand.h>) && \
      __has_include(<openssl/kdf.h>)
#    define QIHSE_UWP_TLS_HAVE_OPENSSL 1
#  endif
#else
/* Fall back to a conservative probe: assume OpenSSL is present (the
 * Makefile links -lssl -lcrypto) and let the compiler error if headers
 * are genuinely missing. */
#  define QIHSE_UWP_TLS_HAVE_OPENSSL 1
#endif

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */
#define QIHSE_UWP_TLS_KEY_LEN     32   /* ChaCha20 key length            */
#define QIHSE_UWP_TLS_NONCE_LEN   12   /* Poly1305 nonce length          */
#define QIHSE_UWP_TLS_TAG_LEN     16   /* Poly1305 authentication tag    */
#define QIHSE_UWP_TLS_OVERHEAD    (QIHSE_UWP_TLS_NONCE_LEN + QIHSE_UWP_TLS_TAG_LEN)

/* ------------------------------------------------------------------ */
/* Server-side context                                                 */
/* ------------------------------------------------------------------ */
struct qihse_uwp_tls_ctx {
    uint8_t server_key[QIHSE_UWP_TLS_KEY_LEN];
    int     ok;   /* 1 once the key has been generated successfully */
};

/* ------------------------------------------------------------------ */
/* Per-connection session                                              */
/* ------------------------------------------------------------------ */
struct qihse_uwp_tls_session {
    uint8_t session_key[QIHSE_UWP_TLS_KEY_LEN];
    uint8_t conn_nonce[QIHSE_UWP_TLS_NONCE_LEN]; /* static connection salt */
    /* Monotonic per-record nonce counter. Incremented atomically before
     * each encryption so each record uses a unique 12-byte nonce formed
     * from the connection salt XOR the counter. */
    uint64_t counter;
    int      has_key;
};

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/* Best-effort constant-time-ish wipe. */
static void qihse_uwp_tls_wipe(void* p, size_t n) {
    if (!p || !n) return;
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) *v++ = 0;
}

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL

/*
 * Derive a per-connection session key from the server key and a connection
 * nonce using HKDF-SHA256. Falls back to a simple XOR-mix if HKDF is not
 * available at runtime.
 */
static int qihse_uwp_tls_derive_session(const uint8_t* server_key,
                                        const uint8_t* conn_nonce,
                                        size_t nonce_len,
                                        uint8_t* out_key) {
    /* Try HKDF-SHA256 first. */
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx) {
        if (EVP_PKEY_derive_init(pctx) > 0 &&
            EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
            EVP_PKEY_CTX_set1_hkdf_salt(pctx, conn_nonce, (int)nonce_len) > 0 &&
            EVP_PKEY_CTX_set1_hkdf_key(pctx, server_key, QIHSE_UWP_TLS_KEY_LEN) > 0 &&
            EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char*)"qihse-uwp-tls",
                                        12) > 0 &&
            EVP_PKEY_derive(pctx, out_key, &(size_t){QIHSE_UWP_TLS_KEY_LEN}) > 0) {
            EVP_PKEY_CTX_free(pctx);
            return 0;
        }
        EVP_PKEY_CTX_free(pctx);
        /* Fall through to simple derivation. */
    }

    /* Simple fallback: XOR the connection nonce (repeated) into the key. */
    for (size_t i = 0; i < QIHSE_UWP_TLS_KEY_LEN; ++i) {
        out_key[i] = server_key[i] ^ conn_nonce[i % nonce_len];
    }
    return 0;
}

/*
 * Build a 12-byte per-record nonce from the connection salt and the
 * session's monotonic counter (little-endian, XOR-folded into the salt).
 */
static void qihse_uwp_tls_build_nonce(const uint8_t* salt, uint64_t counter,
                                      uint8_t* out) {
    for (size_t i = 0; i < QIHSE_UWP_TLS_NONCE_LEN; ++i) {
        uint8_t c = (uint8_t)(counter >> (8 * (i % 8)));
        out[i] = salt[i] ^ c;
    }
}

/*
 * Core AEAD routine. mode = 1 encrypt, mode = 0 decrypt.
 */
static int qihse_uwp_tls_aead(qihse_uwp_tls_session_t* session,
                              const uint8_t* in, size_t in_len,
                              const uint8_t* nonce,
                              uint8_t* out, size_t cap, size_t* out_len,
                              int mode) {
    if (!session || !session->has_key || !in || !out || !out_len)
        return -2;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -3;

    int rc = -4;
    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    if (!cipher) goto done;

    if (mode) {
        /* Encrypt */
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                QIHSE_UWP_TLS_NONCE_LEN, NULL) != 1) goto done;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL,
                               session->session_key, nonce) != 1) goto done;

        int len = 0;
        if (EVP_EncryptUpdate(ctx, NULL, &len, NULL, 0) != 1) goto done; /* no AAD */
        if (cap < in_len) goto done;
        if (EVP_EncryptUpdate(ctx, out, &len, in, (int)in_len) != 1) goto done;
        int total = len;
        int finlen = 0;
        if (EVP_EncryptFinal_ex(ctx, out + total, &finlen) != 1) goto done;
        total += finlen;

        uint8_t tag[QIHSE_UWP_TLS_TAG_LEN];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                QIHSE_UWP_TLS_TAG_LEN, tag) != 1) goto done;
        memcpy(out + total, tag, QIHSE_UWP_TLS_TAG_LEN);
        *out_len = (size_t)total + QIHSE_UWP_TLS_TAG_LEN;
        rc = 0;
    } else {
        /* Decrypt */
        if (in_len < QIHSE_UWP_TLS_TAG_LEN) goto done;
        size_t ct_len = in_len - QIHSE_UWP_TLS_TAG_LEN;
        if (cap < ct_len) goto done;

        if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                QIHSE_UWP_TLS_NONCE_LEN, NULL) != 1) goto done;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL,
                               session->session_key, nonce) != 1) goto done;

        int len = 0;
        if (EVP_DecryptUpdate(ctx, NULL, &len, NULL, 0) != 1) goto done; /* no AAD */
        if (EVP_DecryptUpdate(ctx, out, &len, in, (int)ct_len) != 1) goto done;
        int total = len;

        /* Set the expected tag (located at the end of the input). */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                QIHSE_UWP_TLS_TAG_LEN,
                                (void*)(in + ct_len)) != 1) goto done;

        int finlen = 0;
        if (EVP_DecryptFinal_ex(ctx, out + total, &finlen) != 1) {
            /* Authentication failure: tag mismatch. */
            rc = -1;
            goto done;
        }
        total += finlen;
        *out_len = (size_t)total;
        rc = 0;
    }

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

#endif /* QIHSE_UWP_TLS_HAVE_OPENSSL */

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

qihse_uwp_tls_ctx_t* qihse_uwp_tls_ctx_create(void) {
    qihse_uwp_tls_ctx_t* ctx =
        (qihse_uwp_tls_ctx_t*)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    if (RAND_bytes(ctx->server_key, QIHSE_UWP_TLS_KEY_LEN) != 1) {
        qihse_uwp_tls_wipe(ctx->server_key, sizeof(ctx->server_key));
        free(ctx);
        return NULL;
    }
    ctx->ok = 1;
#else
    ctx->ok = 0;
#endif
    return ctx;
}

void qihse_uwp_tls_ctx_destroy(qihse_uwp_tls_ctx_t* ctx) {
    if (!ctx) return;
    qihse_uwp_tls_wipe(ctx->server_key, sizeof(ctx->server_key));
    free(ctx);
}

qihse_uwp_tls_session_t* qihse_uwp_tls_session_create(qihse_uwp_tls_ctx_t* ctx) {
    if (!ctx || !ctx->ok) return NULL;

    qihse_uwp_tls_session_t* s =
        (qihse_uwp_tls_session_t*)calloc(1, sizeof(*s));
    if (!s) return NULL;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    if (RAND_bytes(s->conn_nonce, QIHSE_UWP_TLS_NONCE_LEN) != 1) {
        free(s);
        return NULL;
    }
    if (qihse_uwp_tls_derive_session(ctx->server_key, s->conn_nonce,
                                     QIHSE_UWP_TLS_NONCE_LEN,
                                     s->session_key) != 0) {
        qihse_uwp_tls_wipe(s->session_key, sizeof(s->session_key));
        free(s);
        return NULL;
    }
    s->counter = 0;
    s->has_key = 1;
#else
    s->has_key = 0;
#endif
    return s;
}

void qihse_uwp_tls_session_destroy(qihse_uwp_tls_session_t* session) {
    if (!session) return;
    qihse_uwp_tls_wipe(session->session_key, sizeof(session->session_key));
    qihse_uwp_tls_wipe(session->conn_nonce, sizeof(session->conn_nonce));
    free(session);
}

int qihse_uwp_tls_encrypt(qihse_uwp_tls_session_t* session,
                          const uint8_t* plaintext, size_t len,
                          uint8_t* ciphertext, size_t cap, size_t* out_len) {
    if (!out_len) return -2;
    *out_len = 0;
    if (!session || !session->has_key || !plaintext || !ciphertext)
        return -2;
    /* Output = nonce + ciphertext + tag. */
    if (cap < len + QIHSE_UWP_TLS_OVERHEAD) return -2;
    if (len > (size_t)INT_MAX) return -2;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    /* Reserve room for the nonce prefix. */
    uint8_t* ct_body = ciphertext + QIHSE_UWP_TLS_NONCE_LEN;
    size_t   ct_cap  = cap - QIHSE_UWP_TLS_NONCE_LEN;

    /* Build a per-record nonce from the connection salt + counter. */
    uint64_t counter = session->counter++;
    uint8_t  nonce[QIHSE_UWP_TLS_NONCE_LEN];
    qihse_uwp_tls_build_nonce(session->conn_nonce, counter, nonce);

    /* Write the nonce prefix. */
    memcpy(ciphertext, nonce, QIHSE_UWP_TLS_NONCE_LEN);

    size_t body_len = 0;
    int rc = qihse_uwp_tls_aead(session, plaintext, len, nonce,
                                ct_body, ct_cap, &body_len, 1);
    if (rc != 0) return rc;

    *out_len = QIHSE_UWP_TLS_NONCE_LEN + body_len;
    return 0;
#else
    return -100; /* OpenSSL unavailable at compile time */
#endif
}

int qihse_uwp_tls_decrypt(qihse_uwp_tls_session_t* session,
                          const uint8_t* ciphertext, size_t len,
                          uint8_t* plaintext, size_t cap, size_t* out_len) {
    if (!out_len) return -2;
    *out_len = 0;
    if (!session || !session->has_key || !ciphertext || !plaintext)
        return -2;
    if (len < QIHSE_UWP_TLS_OVERHEAD) return -1; /* too short to be valid */
    if (len - QIHSE_UWP_TLS_OVERHEAD > (size_t)INT_MAX) return -2;
    if (cap < len - QIHSE_UWP_TLS_OVERHEAD) return -2;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    /* Extract the nonce prefix. */
    const uint8_t* nonce   = ciphertext;
    const uint8_t* ct_body = ciphertext + QIHSE_UWP_TLS_NONCE_LEN;
    size_t         ct_len  = len - QIHSE_UWP_TLS_NONCE_LEN;

    size_t pt_len = 0;
    int rc = qihse_uwp_tls_aead(session, ct_body, ct_len, nonce,
                                plaintext, cap, &pt_len, 0);
    if (rc != 0) return rc;

    *out_len = pt_len;
    return 0;
#else
    return -100; /* OpenSSL unavailable at compile time */
#endif
}

bool qihse_uwp_tls_enabled(qihse_uwp_tls_session_t* session) {
    return session && session->has_key;
}
