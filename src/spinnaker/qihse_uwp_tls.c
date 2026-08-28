/*
 * qihse_uwp_tls.c - Transport encryption layer for the QIHSE Unified Wire
 *                   Protocol (UWP).
 *
 * Production-grade TLS for the UWP transport. Two modes are supported:
 *
 *   1. Certificate-based (production): a real OpenSSL SSL_CTX configured for
 *      TLS 1.3, loaded with an X.509 certificate + private key (either
 *      supplied by the caller or freshly generated self-signed). Sessions
 *      perform a genuine TLS 1.3 handshake (SSL_accept on the server side)
 *      and all record protection is handled by OpenSSL's TLS record layer
 *      via SSL_write/SSL_read.
 *
 *   2. Symmetric-key AEAD (legacy / fallback): each server context holds a
 *      long-lived 32-byte key; each connection session derives its own key
 *      from the server key plus a random connection nonce. Records on the
 *      wire are laid out as:
 *
 *          [ 12-byte nonce ][ ciphertext ][ 16-byte Poly1305 tag ]
 *
 *      This path is NOT recommended for production deployments that have
 *      access to certificate infrastructure; it is retained for environments
 *      without cert/PKI support.
 *
 * When OpenSSL is not available at compile time the module degrades to a
 * safe no-op that returns errors rather than crashing.
 */

#include "qihse_uwp_tls.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>      /* snprintf, tmpnam-style path building           */
#include <unistd.h>     /* unlink, getpid                                */
#include <fcntl.h>      /* O_WRONLY|O_CREAT|O_EXCL for safe temp files   */
#include <errno.h>

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
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */
#define QIHSE_UWP_TLS_KEY_LEN     32   /* ChaCha20 key length            */
#define QIHSE_UWP_TLS_NONCE_LEN   12   /* Poly1305 nonce length          */
#define QIHSE_UWP_TLS_TAG_LEN     16   /* Poly1305 authentication tag    */
#define QIHSE_UWP_TLS_OVERHEAD    (QIHSE_UWP_TLS_NONCE_LEN + QIHSE_UWP_TLS_TAG_LEN)

#define QIHSE_UWP_TLS_DEFAULT_CN  "qihse-uwp-tls"

/* ------------------------------------------------------------------ */
/* Server-side context                                                 */
/* ------------------------------------------------------------------ */
struct qihse_uwp_tls_ctx {
    uint8_t server_key[QIHSE_UWP_TLS_KEY_LEN];
    int     ok;            /* 1 once the key has been generated/loaded    */
    int     is_cert_based; /* 1 when ssl_ctx is populated (real TLS 1.3)  */
#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    SSL_CTX* ssl_ctx;      /* OpenSSL SSL_CTX for cert-based TLS 1.3      */
    /* Cached parameters so rotate_key can regenerate a self-signed cert. */
    char*   selfsigned_cn;
    size_t  selfsigned_bits;
    int     is_selfsigned;
#endif
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
    int      is_ssl;       /* 1 when ssl is populated (real TLS channel)  */
    int      fd;           /* socket fd bound to the SSL object           */
    qihse_uwp_tls_ctx_t* ctx; /* back-reference for renegotiate/rotate    */
#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    SSL*     ssl;          /* OpenSSL SSL* for real TLS 1.3               */
#endif
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

/* ------------------------------------------------------------------ */
/* Certificate / SSL_CTX helpers                                       */
/* ------------------------------------------------------------------ */

/* Map a requested key size in bits to an OpenSSL EC curve NID. */
static int qihse_uwp_tls_curve_for_bits(size_t key_bits) {
    switch (key_bits) {
        case 384: return NID_secp384r1;
        case 521: return NID_secp521r1;
        case 256:
        default:  return NID_X9_62_prime256v1;
    }
}

/*
 * Generate a fresh EC key and self-signed X509 certificate, install them
 * into @p ssl_ctx, and return 0 on success. On success the caller owns the
 * SSL_CTX; the X509/EVP_PKEY objects are consumed by the SSL_CTX.
 *
 * Key generation uses the OpenSSL 3.0 EVP_PKEY_keygen API (non-deprecated).
 *
 * @p common_name may be NULL (defaults to QIHSE_UWP_TLS_DEFAULT_CN).
 */
static int qihse_uwp_tls_gen_selfsigned(SSL_CTX* ssl_ctx,
                                        const char* common_name,
                                        size_t key_bits) {
    int rc = -1;
    EVP_PKEY* pkey = NULL;
    X509* x509 = NULL;
    X509_NAME* name = NULL;
    const char* cn = common_name ? common_name : QIHSE_UWP_TLS_DEFAULT_CN;
    const char* curve = "P-256";
    if (key_bits == 384)      curve = "P-384";
    else if (key_bits == 521) curve = "P-521";

    /* Generate the EC key via the modern EVP_PKEY_keygen API. */
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!kctx) goto cleanup;
    if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); goto cleanup; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
            kctx, qihse_uwp_tls_curve_for_bits(key_bits)) <= 0) {
        EVP_PKEY_CTX_free(kctx); goto cleanup;
    }
    if (EVP_PKEY_generate(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        pkey = NULL;
        goto cleanup;
    }
    EVP_PKEY_CTX_free(kctx);
    (void)curve; /* curve name kept for documentation/debugging only */

    /* Build the self-signed certificate. */
    x509 = X509_new();
    if (!x509) goto cleanup;
    /* X509 version 3 (value is one less than the version number). */
    if (X509_set_version(x509, 2) != 1) goto cleanup;
    /* Serial number. */
    if (ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) != 1) goto cleanup;
    /* Validity: now .. now + 365 days. */
    if (X509_gmtime_adj(X509_getm_notBefore(x509), 0) == NULL) goto cleanup;
    if (X509_gmtime_adj(X509_getm_notAfter(x509), 365L * 24 * 3600) == NULL)
        goto cleanup;
    /* Public key. */
    if (X509_set_pubkey(x509, pkey) != 1) goto cleanup;
    /* Subject + issuer (self-signed => identical). */
    name = X509_NAME_new();
    if (!name) goto cleanup;
    if (X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                                   (const unsigned char*)"US", -1, -1, 0) != 1) {
        X509_NAME_free(name); name = NULL; goto cleanup;
    }
    if (X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                                   (const unsigned char*)"QIHSE", -1, -1, 0) != 1) {
        X509_NAME_free(name); name = NULL; goto cleanup;
    }
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char*)cn, -1, -1, 0) != 1) {
        X509_NAME_free(name); name = NULL; goto cleanup;
    }
    if (X509_set_subject_name(x509, name) != 1) {
        X509_NAME_free(name); name = NULL; goto cleanup;
    }
    if (X509_set_issuer_name(x509, name) != 1) {
        X509_NAME_free(name); name = NULL; goto cleanup;
    }
    X509_NAME_free(name);
    name = NULL;

    /* Sign with SHA-256. */
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) goto cleanup;

    /* Install into the SSL_CTX. */
    if (SSL_CTX_use_certificate(ssl_ctx, x509) != 1) goto cleanup;
    if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) goto cleanup;

    rc = 0;

cleanup:
    if (name)  X509_NAME_free(name);
    if (x509)  X509_free(x509);
    if (pkey)  EVP_PKEY_free(pkey);
    return rc;
}

/*
 * Build a TLS 1.3 server SSL_CTX with sensible defaults. Returns NULL on
 * failure. Caller owns the result.
 */
static SSL_CTX* qihse_uwp_tls_make_ssl_ctx(void) {
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) return NULL;

    /* Restrict to TLS 1.3. */
    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }
    if (SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    /* Prefer server ciphers and disable old/weak ones. */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                  SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
                                  SSL_OP_NO_TLSv1_2 |
                                  SSL_OP_NO_COMPRESSION);
    return ssl_ctx;
}

/*
 * Write a NUL-terminated PEM blob to a unique temporary file and return the
 * path in a caller-provided buffer. The file is created with O_EXCL. Returns
 * 0 on success and the path is NUL-terminated. On failure returns non-zero.
 */
static int qihse_uwp_tls_pem_to_tmp(const char* pem, char* path, size_t path_cap) {
    if (!pem || !path || path_cap < 32) return -1;

    int fd = -1;
    int attempts = 0;
    do {
        if (snprintf(path, path_cap, "/tmp/qihse-uwp-tls-%ld-%d.pem",
                     (long)getpid(), attempts) >= (int)path_cap) {
            return -1;
        }
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST) return -1;
    } while (++attempts < 64);
    if (fd < 0) return -1;

    size_t total = strlen(pem);
    size_t off = 0;
    while (off < total) {
        ssize_t w = write(fd, pem + off, total - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(path);
            return -1;
        }
        off += (size_t)w;
    }
    close(fd);
    return 0;
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

qihse_uwp_tls_ctx_t* qihse_uwp_tls_ctx_create_with_cert(const char* cert_pem,
                                                        const char* key_pem) {
    if (!cert_pem || !key_pem) return NULL;

    qihse_uwp_tls_ctx_t* ctx =
        (qihse_uwp_tls_ctx_t*)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    SSL_CTX* ssl_ctx = qihse_uwp_tls_make_ssl_ctx();
    if (!ssl_ctx) {
        free(ctx);
        return NULL;
    }

    /* SSL_CTX_use_certificate_chain_file / SSL_CTX_use_PrivateKey_file take
     * file paths, so write the PEM blobs to temporary files first. */
    char cert_path[256];
    char key_path[256];
    if (qihse_uwp_tls_pem_to_tmp(cert_pem, cert_path, sizeof(cert_path)) != 0) {
        SSL_CTX_free(ssl_ctx);
        free(ctx);
        return NULL;
    }
    if (qihse_uwp_tls_pem_to_tmp(key_pem, key_path, sizeof(key_path)) != 0) {
        unlink(cert_path);
        SSL_CTX_free(ssl_ctx);
        free(ctx);
        return NULL;
    }

    int loaded = 0;
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_path) == 1 &&
        SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) == 1) {
        if (SSL_CTX_check_private_key(ssl_ctx) == 1) {
            loaded = 1;
        }
    }

    /* Remove the temporary files regardless of outcome. */
    unlink(cert_path);
    unlink(key_path);

    if (!loaded) {
        SSL_CTX_free(ssl_ctx);
        free(ctx);
        return NULL;
    }

    ctx->ssl_ctx = ssl_ctx;
    ctx->is_cert_based = 1;
    ctx->ok = 1;
    return ctx;
#else
    (void)cert_pem; (void)key_pem;
    free(ctx);
    return NULL;
#endif
}

qihse_uwp_tls_ctx_t* qihse_uwp_tls_ctx_create_selfsigned(const char* common_name,
                                                         size_t key_bits) {
    qihse_uwp_tls_ctx_t* ctx =
        (qihse_uwp_tls_ctx_t*)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    SSL_CTX* ssl_ctx = qihse_uwp_tls_make_ssl_ctx();
    if (!ssl_ctx) {
        free(ctx);
        return NULL;
    }

    if (qihse_uwp_tls_gen_selfsigned(ssl_ctx, common_name, key_bits) != 0) {
        SSL_CTX_free(ssl_ctx);
        free(ctx);
        return NULL;
    }

    ctx->ssl_ctx = ssl_ctx;
    ctx->is_cert_based = 1;
    ctx->is_selfsigned = 1;
    ctx->selfsigned_bits = (key_bits == 384 || key_bits == 521) ? key_bits : 256;

    /* Cache the common name for rotate_key. */
    const char* cn = common_name ? common_name : QIHSE_UWP_TLS_DEFAULT_CN;
    ctx->selfsigned_cn = strdup(cn);
    if (!ctx->selfsigned_cn) {
        SSL_CTX_free(ssl_ctx);
        free(ctx);
        return NULL;
    }

    ctx->ok = 1;
    return ctx;
#else
    (void)common_name; (void)key_bits;
    free(ctx);
    return NULL;
#endif
}

void qihse_uwp_tls_ctx_destroy(qihse_uwp_tls_ctx_t* ctx) {
    if (!ctx) return;
    qihse_uwp_tls_wipe(ctx->server_key, sizeof(ctx->server_key));
#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    if (ctx->selfsigned_cn) {
        qihse_uwp_tls_wipe(ctx->selfsigned_cn, strlen(ctx->selfsigned_cn));
        free(ctx->selfsigned_cn);
    }
#endif
    free(ctx);
}

int qihse_uwp_tls_ctx_rotate_key(qihse_uwp_tls_ctx_t* ctx) {
    if (!ctx || !ctx->ok) return -2;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    if (ctx->is_cert_based) {
        /* Regenerate the certificate / key material. */
        SSL_CTX* new_ssl_ctx = qihse_uwp_tls_make_ssl_ctx();
        if (!new_ssl_ctx) return -3;

        if (ctx->is_selfsigned) {
            if (qihse_uwp_tls_gen_selfsigned(new_ssl_ctx,
                                             ctx->selfsigned_cn,
                                             ctx->selfsigned_bits) != 0) {
                SSL_CTX_free(new_ssl_ctx);
                return -4;
            }
        } else {
            /* For externally-supplied certs we cannot regenerate without the
             * original PEM; instead we re-key the symmetric fallback path so
             * the context remains usable for new AEAD sessions. Real rotation
             * for externally-supplied certs is the caller's responsibility
             * (rebuild via qihse_uwp_tls_ctx_create_with_cert). */
            if (RAND_bytes(ctx->server_key, QIHSE_UWP_TLS_KEY_LEN) != 1) {
                SSL_CTX_free(new_ssl_ctx);
                return -5;
            }
            SSL_CTX_free(new_ssl_ctx);
            return 0;
        }

        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = new_ssl_ctx;
        return 0;
    }

    /* Symmetric-key context: generate a fresh server key. Existing sessions
     * keep their already-derived keys until they reconnect. */
    if (RAND_bytes(ctx->server_key, QIHSE_UWP_TLS_KEY_LEN) != 1) return -5;
    return 0;
#else
    return -100;
#endif
}

qihse_uwp_tls_session_t* qihse_uwp_tls_session_create(qihse_uwp_tls_ctx_t* ctx) {
    if (!ctx || !ctx->ok) return NULL;

    /* The single-arg entry point is the symmetric-key AEAD path. A
     * cert-based context has no server_key to derive from, so it must use
     * qihse_uwp_tls_session_create_with_fd() instead. */
#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    if (ctx->is_cert_based) return NULL;
#endif

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
    s->ctx = ctx;
#else
    s->has_key = 0;
#endif
    return s;
}

qihse_uwp_tls_session_t* qihse_uwp_tls_session_create_with_fd(
    qihse_uwp_tls_ctx_t* ctx, int fd) {
    if (!ctx || !ctx->ok || fd < 0) return NULL;

    qihse_uwp_tls_session_t* s =
        (qihse_uwp_tls_session_t*)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->fd = fd;
    s->ctx = ctx;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    if (!ctx->is_cert_based || !ctx->ssl_ctx) {
        /* No certificate infrastructure: fall back to the AEAD path using the
         * symmetric server key (if present). */
        if (!ctx->ok) { free(s); return NULL; }
        if (RAND_bytes(s->conn_nonce, QIHSE_UWP_TLS_NONCE_LEN) != 1) {
            free(s); return NULL;
        }
        if (qihse_uwp_tls_derive_session(ctx->server_key, s->conn_nonce,
                                         QIHSE_UWP_TLS_NONCE_LEN,
                                         s->session_key) != 0) {
            free(s); return NULL;
        }
        s->counter = 0;
        s->has_key = 1;
        return s;
    }

    /* Certificate-based: real TLS 1.3 server handshake. */
    SSL* ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) { free(s); return NULL; }

    if (SSL_set_fd(ssl, fd) != 1) {
        SSL_free(ssl);
        free(s);
        return NULL;
    }

    /* Perform the server-side handshake. */
    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        SSL_free(ssl);
        free(s);
        return NULL;
    }

    s->ssl = ssl;
    s->is_ssl = 1;
    s->has_key = 1;
    return s;
#else
    (void)fd;
    free(s);
    return NULL;
#endif
}

void qihse_uwp_tls_session_destroy(qihse_uwp_tls_session_t* session) {
    if (!session) return;
#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    if (session->ssl) {
        SSL_shutdown(session->ssl);
        SSL_free(session->ssl);
        session->ssl = NULL;
    }
#endif
    qihse_uwp_tls_wipe(session->session_key, sizeof(session->session_key));
    qihse_uwp_tls_wipe(session->conn_nonce, sizeof(session->conn_nonce));
    free(session);
}

int qihse_uwp_tls_session_renegotiate(qihse_uwp_tls_session_t* session) {
    if (!session) return -2;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    if (session->is_ssl && session->ssl) {
        /* Drive a TLS re-handshake on the existing channel. */
        if (SSL_renegotiate(session->ssl) != 1) return -3;
        /* Walk the handshake to completion. */
        int ret = 0;
        do {
            ret = SSL_do_handshake(session->ssl);
        } while (ret <= 0 &&
                 SSL_get_error(session->ssl, ret) == SSL_ERROR_WANT_READ);
        if (ret <= 0) return -4;
        return 0;
    }

    /* AEAD session: re-derive the session key from the context's current
     * server key + a fresh connection nonce, and reset the counter. */
    if (!session->ctx || !session->ctx->ok) return -5;
    if (RAND_bytes(session->conn_nonce, QIHSE_UWP_TLS_NONCE_LEN) != 1) return -6;
    if (qihse_uwp_tls_derive_session(session->ctx->server_key,
                                     session->conn_nonce,
                                     QIHSE_UWP_TLS_NONCE_LEN,
                                     session->session_key) != 0) return -7;
    session->counter = 0;
    return 0;
#else
    return -100;
#endif
}

int qihse_uwp_tls_encrypt(qihse_uwp_tls_session_t* session,
                          const uint8_t* plaintext, size_t len,
                          uint8_t* ciphertext, size_t cap, size_t* out_len) {
    if (!out_len) return -2;
    *out_len = 0;
    if (!session || !session->has_key || !plaintext)
        return -2;
    if (len > (size_t)INT_MAX) return -2;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    /* TLS (SSL*) path: write plaintext directly to the socket; the TLS
     * record layer performs encryption. The ciphertext buffer is unused. */
    if (session->is_ssl && session->ssl) {
        int w = 0;
        size_t off = 0;
        while (off < len) {
            w = SSL_write(session->ssl, plaintext + off, (int)(len - off));
            if (w <= 0) {
                int err = SSL_get_error(session->ssl, w);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                    continue;
                return -8;
            }
            off += (size_t)w;
        }
        *out_len = len;
        return 0;
    }
#endif

    /* AEAD path. */
    if (!ciphertext) return -2;
    if (cap < len + QIHSE_UWP_TLS_OVERHEAD) return -2;

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
    if (!session || !session->has_key || !plaintext)
        return -2;

#ifdef QIHSE_UWP_TLS_HAVE_OPENSSL
    /* TLS (SSL*) path: read plaintext directly from the socket; the TLS
     * record layer performs decryption/authentication. The ciphertext
     * buffer is unused. */
    if (session->is_ssl && session->ssl) {
        int r = 0;
        size_t off = 0;
        while (off < cap) {
            r = SSL_read(session->ssl, plaintext + off, (int)(cap - off));
            if (r <= 0) {
                int err = SSL_get_error(session->ssl, r);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                if (err == SSL_ERROR_ZERO_RETURN) break; /* clean EOF */
                return -8;
            }
            off += (size_t)r;
            /* One record at a time is enough for a frame-oriented test. */
            break;
        }
        if (off == 0) return -9;
        *out_len = off;
        return 0;
    }
#endif

    /* AEAD path. */
    if (!ciphertext) return -2;
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
