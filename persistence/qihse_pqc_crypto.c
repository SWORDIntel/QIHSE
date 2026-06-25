/*
 * qihse_pqc_crypto.c — CNSA 2.0 cryptographic primitives
 *
 * Algorithms used (all via OpenSSL 3.5+):
 *   Key encapsulation : ML-KEM-1024  (NIST FIPS 203)
 *   Digital signatures: ML-DSA-87    (NIST FIPS 204)
 *   Symmetric cipher  : AES-256-GCM
 *   Hash              : SHA-384      (NIST FIPS 180-4)
 *
 * Provider selection:
 *   If the OpenSSL FIPS provider is installed (openssl-provider-fips),
 *   qihse_pqc_init_providers() loads it and all crypto operations run
 *   through the FIPS 140-3 validated module. If the FIPS module is not
 *   present, the standard default provider is used and a notice is printed.
 *   Call qihse_pqc_init_providers() once at application startup.
 *
 * Key files (generate with scripts/qihse_keygen.sh):
 *   qihse_kem_key.pem / qihse_kem_pub.pem  — ML-KEM-1024
 *   qihse_dsa_key.pem / qihse_dsa_pub.pem  — ML-DSA-87
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "qihse_pqc_crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

/* ── Provider initialisation ─────────────────────────────────────────── */

static OSSL_PROVIDER *fips_provider    = NULL;
static OSSL_PROVIDER *default_provider = NULL;

/*
 * qihse_pqc_init_providers - Load the best available OpenSSL provider.
 *
 * Call once at application startup before any PQC operations.
 * Returns 1 if the FIPS 140-3 validated module is active, 0 if falling
 * back to the standard default provider.
 */
int qihse_pqc_init_providers(void) {
    fips_provider = OSSL_PROVIDER_load(NULL, "fips");
    if (fips_provider) {
        /* Also load default so non-FIPS ops (e.g. rand seeding) still work */
        default_provider = OSSL_PROVIDER_load(NULL, "default");
        fprintf(stderr,
            "[QIHSE PQC] FIPS 140-3 validated provider active "
            "(OpenSSL FIPS %s).\n",
            OSSL_PROVIDER_get0_name(fips_provider));
        return 1;
    }
    /* FIPS module not installed — fall back to standard provider */
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    fprintf(stderr,
        "[QIHSE PQC] FIPS provider not found; using standard OpenSSL provider.\n"
        "            Install openssl-provider-fips for FIPS 140-3 validated operations.\n");
    return 0;
}

/* ── Internal key helpers ────────────────────────────────────────────── */

static EVP_PKEY *load_private_key(const char *path) {
#ifndef _WIN32
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "[QIHSE PQC] Cannot open private key: %s\n", path);
        return NULL;
    }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return NULL; }
#else
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[QIHSE PQC] Cannot open private key: %s\n", path);
        return NULL;
#endif
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        fprintf(stderr, "[QIHSE PQC] Failed to parse private key: %s\n", path);
        ERR_print_errors_fp(stderr);
    }
    return pkey;
}

static EVP_PKEY *load_public_key(const char *path) {
#ifndef _WIN32
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "[QIHSE PQC] Cannot open public key: %s\n", path);
        return NULL;
    }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return NULL; }
#else
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[QIHSE PQC] Cannot open public key: %s\n", path);
        return NULL;
#endif
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        fprintf(stderr, "[QIHSE PQC] Failed to parse public key: %s\n", path);
        ERR_print_errors_fp(stderr);
    }
    return pkey;
}

/* ── ML-KEM-1024 key encapsulation ───────────────────────────────────── */

bool qihse_pqc_init(qihse_pqc_ctx_t *ctx,
                    const uint8_t *encapsulated_key_in,
                    uint8_t *encapsulated_key_out) {
    if (!ctx) return false;
    ctx->initialized = false;

    if (encapsulated_key_in == NULL && encapsulated_key_out != NULL) {
        /*
         * Encapsulate path: generate a fresh session key.
         *
         * EVP_PKEY_encapsulate() generates:
         *   - a random 32-byte shared secret  → we use this directly as AES-256 key
         *   - a 1568-byte ML-KEM-1024 ciphertext → stored in the container header
         *
         * The private key holder can later recover the same shared secret by
         * running EVP_PKEY_decapsulate() on the stored ciphertext.
         */
        EVP_PKEY *pub_key = load_public_key(QIHSE_KEM_PUBLIC_KEY_FILE);
        if (!pub_key) return false;

        bool ok = false;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pub_key, NULL);
        if (pctx && EVP_PKEY_encapsulate_init(pctx, NULL) > 0) {
            uint8_t shared_secret[QIHSE_MLKEM_SHARED_SIZE];
            size_t ct_len  = QIHSE_MLKEM_CIPHERTEXT_SIZE;
            size_t ss_len  = sizeof(shared_secret);

            if (EVP_PKEY_encapsulate(pctx,
                                     encapsulated_key_out, &ct_len,
                                     shared_secret, &ss_len) > 0
                && ct_len == QIHSE_MLKEM_CIPHERTEXT_SIZE
                && ss_len == QIHSE_MLKEM_SHARED_SIZE) {
                memcpy(ctx->aes_key, shared_secret, QIHSE_AES_256_KEY_SIZE);
                OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
                ctx->initialized = true;
                ok = true;
            } else {
                ERR_print_errors_fp(stderr);
            }
            EVP_PKEY_CTX_free(pctx);
        }
        EVP_PKEY_free(pub_key);
        return ok;

    } else if (encapsulated_key_in != NULL) {
        /*
         * Decapsulate path: recover the session key from a stored ciphertext.
         *
         * EVP_PKEY_decapsulate() uses the ML-KEM-1024 private key to recover
         * the same 32-byte shared secret that was generated during encapsulation.
         */
        EVP_PKEY *priv_key = load_private_key(QIHSE_KEM_PRIVATE_KEY_FILE);
        if (!priv_key) return false;

        bool ok = false;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv_key, NULL);
        if (pctx && EVP_PKEY_decapsulate_init(pctx, NULL) > 0) {
            uint8_t shared_secret[QIHSE_MLKEM_SHARED_SIZE];
            size_t ss_len = sizeof(shared_secret);

            if (EVP_PKEY_decapsulate(pctx,
                                     shared_secret, &ss_len,
                                     encapsulated_key_in,
                                     QIHSE_MLKEM_CIPHERTEXT_SIZE) > 0
                && ss_len == QIHSE_MLKEM_SHARED_SIZE) {
                memcpy(ctx->aes_key, shared_secret, QIHSE_AES_256_KEY_SIZE);
                OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
                ctx->initialized = true;
                ok = true;
            } else {
                ERR_print_errors_fp(stderr);
            }
            EVP_PKEY_CTX_free(pctx);
        }
        EVP_PKEY_free(priv_key);
        return ok;
    }

    return false;
}

void qihse_pqc_destroy(qihse_pqc_ctx_t *ctx) {
    if (!ctx) return;
    OPENSSL_cleanse(ctx->aes_key, sizeof(ctx->aes_key));
    ctx->initialized = false;
}

/* ── AES-256-GCM encrypt/decrypt ─────────────────────────────────────── */

size_t qihse_pqc_encrypt(qihse_pqc_ctx_t *ctx,
                         const uint8_t *in_data, size_t in_len,
                         uint8_t *out_buffer) {
    if (!ctx || !ctx->initialized || !in_data || !out_buffer) return 0;

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx) return 0;

    /* Fresh random 96-bit IV per encryption */
    uint8_t iv[QIHSE_AES_GCM_IV_SIZE];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        EVP_CIPHER_CTX_free(cctx);
        return 0;
    }

    int len;
    size_t ciphertext_len = 0;

    if (EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1) goto err;
    if (EVP_EncryptInit_ex(cctx, NULL, NULL, ctx->aes_key, iv) != 1) goto err;

    /* Output layout: [IV][ciphertext][tag] */
    memcpy(out_buffer, iv, sizeof(iv));
    uint8_t *out_ct = out_buffer + sizeof(iv);

    if (EVP_EncryptUpdate(cctx, out_ct, &len, in_data, (int)(in_len > INT_MAX ? INT_MAX : in_len)) != 1) goto err;
    ciphertext_len = (size_t)len;

    if (EVP_EncryptFinal_ex(cctx, out_ct + len, &len) != 1) goto err;
    ciphertext_len += (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, QIHSE_AES_GCM_TAG_SIZE,
                             out_ct + ciphertext_len) != 1) goto err;

    EVP_CIPHER_CTX_free(cctx);
    return QIHSE_AES_GCM_IV_SIZE + ciphertext_len + QIHSE_AES_GCM_TAG_SIZE;

err:
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(cctx);
    return 0;
}

size_t qihse_pqc_decrypt(qihse_pqc_ctx_t *ctx,
                         const uint8_t *in_data, size_t in_len,
                         uint8_t *out_buffer) {
    if (!ctx || !ctx->initialized || !in_data || !out_buffer) return 0;
    if (in_len <= QIHSE_AES_GCM_IV_SIZE + QIHSE_AES_GCM_TAG_SIZE) return 0;
    if (in_len > (size_t)INT_MAX + QIHSE_AES_GCM_IV_SIZE + QIHSE_AES_GCM_TAG_SIZE) return 0;

    const uint8_t *iv         = in_data;
    const uint8_t *ciphertext = in_data + QIHSE_AES_GCM_IV_SIZE;
    size_t ct_len             = in_len - QIHSE_AES_GCM_IV_SIZE - QIHSE_AES_GCM_TAG_SIZE;
    const uint8_t *tag        = ciphertext + ct_len;

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx) return 0;

    int len;
    size_t plaintext_len = 0;

    if (EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, QIHSE_AES_GCM_IV_SIZE, NULL) != 1) goto err;
    if (EVP_DecryptInit_ex(cctx, NULL, NULL, ctx->aes_key, iv) != 1) goto err;

    if (EVP_DecryptUpdate(cctx, out_buffer, &len, ciphertext, (int)ct_len) != 1) goto err;
    plaintext_len = (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, QIHSE_AES_GCM_TAG_SIZE,
                             (void *)tag) != 1) goto err;

    if (EVP_DecryptFinal_ex(cctx, out_buffer + len, &len) <= 0) {
        /* GCM authentication tag mismatch — data integrity failure */
        fprintf(stderr, "[QIHSE PQC] AES-256-GCM authentication failure.\n");
        goto err;
    }
    plaintext_len += (size_t)len;

    EVP_CIPHER_CTX_free(cctx);
    return plaintext_len;

err:
    EVP_CIPHER_CTX_free(cctx);
    return 0;
}

/* ── ML-DSA-87 sign/verify ───────────────────────────────────────────── */

bool qihse_pqc_sign(const uint8_t *data, size_t len, uint8_t *out_sig) {
    EVP_PKEY *priv_key = load_private_key(QIHSE_DSA_PRIVATE_KEY_FILE);
    if (!priv_key) return false;

    bool ok = false;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (mctx) {
        if (EVP_DigestSignInit(mctx, NULL, NULL, NULL, priv_key) > 0) {
            size_t siglen = QIHSE_MLDSA_SIGNATURE_SIZE;
            if (EVP_DigestSign(mctx, out_sig, &siglen, data, len) > 0) {
                ok = true;
            } else {
                ERR_print_errors_fp(stderr);
            }
        }
        EVP_MD_CTX_free(mctx);
    }
    EVP_PKEY_free(priv_key);
    return ok;
}

bool qihse_pqc_verify(const uint8_t *data, size_t len, const uint8_t *sig) {
    EVP_PKEY *pub_key = load_public_key(QIHSE_DSA_PUBLIC_KEY_FILE);
    if (!pub_key) return false;

    bool ok = false;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (mctx) {
        if (EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pub_key) > 0) {
            if (EVP_DigestVerify(mctx, sig, QIHSE_MLDSA_SIGNATURE_SIZE, data, len) == 1) {
                ok = true;
            }
        }
        EVP_MD_CTX_free(mctx);
    }
    EVP_PKEY_free(pub_key);
    return ok;
}

/* ── Native key generation ───────────────────────────────────────────── */

/*
 * write_keypair - Generate a keypair for the given algorithm and write
 * private + public PEM files into out_dir.
 * Returns true on success.
 */
static bool write_keypair(const char *algorithm,
                          const char *priv_path,
                          const char *pub_path) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, algorithm);
    if (!pkey) {
        fprintf(stderr, "[QIHSE keygen] Failed to generate %s keypair.\n", algorithm);
        ERR_print_errors_fp(stderr);
        return false;
    }

    /* Private key */
    FILE *f = fopen(priv_path, "w");
    if (!f) {
        fprintf(stderr, "[QIHSE keygen] Cannot write %s\n", priv_path);
        EVP_PKEY_free(pkey);
        return false;
    }
    bool ok = (PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(f);
    if (!ok) {
        fprintf(stderr, "[QIHSE keygen] Failed to write private key %s\n", priv_path);
        EVP_PKEY_free(pkey);
        return false;
    }
    /* chmod 600 on the private key */
    chmod(priv_path, 0600);

    /* Public key */
    f = fopen(pub_path, "w");
    if (!f) {
        fprintf(stderr, "[QIHSE keygen] Cannot write %s\n", pub_path);
        EVP_PKEY_free(pkey);
        return false;
    }
    ok = (PEM_write_PUBKEY(f, pkey) == 1);
    fclose(f);
    if (!ok) {
        fprintf(stderr, "[QIHSE keygen] Failed to write public key %s\n", pub_path);
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_PKEY_free(pkey);
    return true;
}

/* Verify ML-KEM-1024 encapsulate→decapsulate round-trip. */
static bool verify_kem_roundtrip(const char *priv_path, const char *pub_path) {
    EVP_PKEY *pub  = load_public_key(pub_path);
    EVP_PKEY *priv = load_private_key(priv_path);
    if (!pub || !priv) { EVP_PKEY_free(pub); EVP_PKEY_free(priv); return false; }

    bool ok = false;

    /* Encapsulate */
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    if (!ectx || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) goto kem_done;

    size_t ct_len = 0, ss_enc_len = 0;
    EVP_PKEY_encapsulate(ectx, NULL, &ct_len, NULL, &ss_enc_len);

    uint8_t *ct     = malloc(ct_len);
    uint8_t *ss_enc = malloc(ss_enc_len);
    uint8_t *ss_dec = malloc(ss_enc_len);
    if (!ct || !ss_enc || !ss_dec) goto kem_mem;

    if (EVP_PKEY_encapsulate(ectx, ct, &ct_len, ss_enc, &ss_enc_len) <= 0) goto kem_mem;

    /* Decapsulate */
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
    size_t ss_dec_len = ss_enc_len;
    if (!dctx || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) { EVP_PKEY_CTX_free(dctx); goto kem_mem; }
    if (EVP_PKEY_decapsulate(dctx, ss_dec, &ss_dec_len, ct, ct_len) <= 0) { EVP_PKEY_CTX_free(dctx); goto kem_mem; }
    EVP_PKEY_CTX_free(dctx);

    ok = (ss_enc_len == ss_dec_len &&
          CRYPTO_memcmp(ss_enc, ss_dec, ss_enc_len) == 0);

kem_mem:
    OPENSSL_cleanse(ss_enc, ss_enc_len);
    OPENSSL_cleanse(ss_dec, ss_dec_len);
    free(ct); free(ss_enc); free(ss_dec);
kem_done:
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_free(pub); EVP_PKEY_free(priv);
    return ok;
}

/* Verify ML-DSA-87 sign→verify round-trip. */
static bool verify_dsa_roundtrip(const char *priv_path, const char *pub_path) {
    EVP_PKEY *priv = load_private_key(priv_path);
    EVP_PKEY *pub  = load_public_key(pub_path);
    if (!priv || !pub) { EVP_PKEY_free(priv); EVP_PKEY_free(pub); return false; }

    const uint8_t test_msg[] = "qihse-cnsa-2.0-selftest";
    uint8_t sig[QIHSE_MLDSA_SIGNATURE_SIZE];
    bool ok = false;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (mctx && EVP_DigestSignInit(mctx, NULL, NULL, NULL, priv) > 0) {
        size_t siglen = sizeof(sig);
        if (EVP_DigestSign(mctx, sig, &siglen, test_msg, sizeof(test_msg) - 1) > 0) {
            EVP_MD_CTX_reset(mctx);
            if (EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pub) > 0) {
                ok = (EVP_DigestVerify(mctx, sig, siglen,
                                       test_msg, sizeof(test_msg) - 1) == 1);
            }
        }
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(priv); EVP_PKEY_free(pub);
    return ok;
}

/*
 * qihse_pqc_keygen - Generate CNSA 2.0 key pairs natively in C.
 *
 * Generates:
 *   <out_dir>/qihse_kem_key.pem   ML-KEM-1024 private key  (chmod 600)
 *   <out_dir>/qihse_kem_pub.pem   ML-KEM-1024 public key
 *   <out_dir>/qihse_dsa_key.pem   ML-DSA-87   private key  (chmod 600)
 *   <out_dir>/qihse_dsa_pub.pem   ML-DSA-87   public key
 *
 * Runs a round-trip self-test on each pair before returning.
 * Returns true if all four files were written and both self-tests passed.
 *
 * Call qihse_pqc_init_providers() first so that if the FIPS module is
 * available the keys are generated through the validated module.
 */
bool qihse_pqc_keygen(const char *out_dir) {
    if (!out_dir) out_dir = ".";

    /* Build file paths — key file macros may be absolute paths */
    char kem_priv[512], kem_pub[512], dsa_priv[512], dsa_pub[512];
    if (QIHSE_KEM_PRIVATE_KEY_FILE[0] == '/') {
        snprintf(kem_priv, sizeof(kem_priv), "%s", QIHSE_KEM_PRIVATE_KEY_FILE);
        snprintf(kem_pub,  sizeof(kem_pub),  "%s", QIHSE_KEM_PUBLIC_KEY_FILE);
        snprintf(dsa_priv, sizeof(dsa_priv), "%s", QIHSE_DSA_PRIVATE_KEY_FILE);
        snprintf(dsa_pub,  sizeof(dsa_pub),  "%s", QIHSE_DSA_PUBLIC_KEY_FILE);
    } else {
        snprintf(kem_priv, sizeof(kem_priv), "%s/%s", out_dir, QIHSE_KEM_PRIVATE_KEY_FILE);
        snprintf(kem_pub,  sizeof(kem_pub),  "%s/%s", out_dir, QIHSE_KEM_PUBLIC_KEY_FILE);
        snprintf(dsa_priv, sizeof(dsa_priv), "%s/%s", out_dir, QIHSE_DSA_PRIVATE_KEY_FILE);
        snprintf(dsa_pub,  sizeof(dsa_pub),  "%s/%s", out_dir, QIHSE_DSA_PUBLIC_KEY_FILE);
    }

    fprintf(stderr, "[QIHSE keygen] Output directory : %s\n", out_dir);

    /* 1. ML-KEM-1024 */
    fprintf(stderr, "[QIHSE keygen] [1/4] Generating ML-KEM-1024 private key...\n");
    if (!write_keypair("ML-KEM-1024", kem_priv, kem_pub)) return false;
    fprintf(stderr, "[QIHSE keygen]       Written: %s\n", kem_priv);
    fprintf(stderr, "[QIHSE keygen] [2/4] Deriving ML-KEM-1024 public key...\n");
    fprintf(stderr, "[QIHSE keygen]       Written: %s\n", kem_pub);

    /* 2. ML-DSA-87 */
    fprintf(stderr, "[QIHSE keygen] [3/4] Generating ML-DSA-87 private key...\n");
    if (!write_keypair("ML-DSA-87", dsa_priv, dsa_pub)) return false;
    fprintf(stderr, "[QIHSE keygen]       Written: %s\n", dsa_priv);
    fprintf(stderr, "[QIHSE keygen] [4/4] Deriving ML-DSA-87 public key...\n");
    fprintf(stderr, "[QIHSE keygen]       Written: %s\n", dsa_pub);

    /* 3. Round-trip verification */
    fprintf(stderr, "[QIHSE keygen] Verifying ML-KEM-1024 round-trip...\n");
    if (!verify_kem_roundtrip(kem_priv, kem_pub)) {
        fprintf(stderr, "[QIHSE keygen] FAIL: ML-KEM-1024 round-trip mismatch.\n");
        return false;
    }
    fprintf(stderr, "[QIHSE keygen]       ML-KEM-1024 round-trip: PASS\n");

    fprintf(stderr, "[QIHSE keygen] Verifying ML-DSA-87 round-trip...\n");
    if (!verify_dsa_roundtrip(dsa_priv, dsa_pub)) {
        fprintf(stderr, "[QIHSE keygen] FAIL: ML-DSA-87 round-trip mismatch.\n");
        return false;
    }
    fprintf(stderr, "[QIHSE keygen]       ML-DSA-87 round-trip:   PASS\n");

    return true;
}
