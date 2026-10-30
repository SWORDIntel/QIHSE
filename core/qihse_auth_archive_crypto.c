#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth_archive_crypto.h"
#include "../persistence/qihse_pqc_crypto.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARCHIVE_HEADER_SIZE 356u
#define ARCHIVE_AAD_SIZE (ARCHIVE_HEADER_SIZE + QIHSE_MLKEM_CIPHERTEXT_SIZE)
#define ARCHIVE_OVERHEAD (ARCHIVE_AAD_SIZE + QIHSE_AES_GCM_TAG_SIZE + QIHSE_MLDSA_SIGNATURE_SIZE)
#define KEY_FILE_MAX 65536u

struct qihse_auth_sealed {
    size_t length;
    uint8_t *data;
};

static void store_be(uint8_t *p, uint64_t value, size_t bytes) {
    for (size_t i = 0; i < bytes; ++i) {
        p[bytes - i - 1u] = (uint8_t)value;
        value >>= 8;
    }
}

static uint64_t load_be(const uint8_t *p, size_t bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < bytes; ++i) value = (value << 8) | p[i];
    return value;
}

static bool nonzero(const uint8_t *p, size_t length) {
    uint8_t value = 0;
    for (size_t i = 0; i < length; ++i) value |= p[i];
    return value != 0;
}

static bool valid_binding(const qihse_auth_archive_config_t *config) {
    if (!config) return false;
    const qihse_auth_archive_binding_t *b = &config->binding;
    if (b->version != QIHSE_AUTH_ARCHIVE_VERSION ||
        (b->purpose != QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE &&
         b->purpose != QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER) ||
        b->mode != QIHSE_AUTH_AUTHORITY_STANDALONE ||
        !nonzero(b->source_authority, 16u) ||
        !nonzero(b->source.history, 16u) || !nonzero(b->source.node, 16u) ||
        !nonzero(b->target.node, 16u) || !nonzero(b->archive_id, 16u) ||
        !b->source.epoch || !b->target.epoch ||
        memcmp(b->source_authority, b->target_authority, 16u) ||
        memcmp(b->source.history, b->target.history, 16u) ||
        b->source.epoch != b->target.epoch ||
        (!b->allow_node_relocation && memcmp(b->source.node, b->target.node, 16u)) ||
        !nonzero(config->keys.recipient_pin, 48u) ||
        !nonzero(config->keys.signer_pin, 48u)) return false;
    /* Durable reopen is the same node and exact state, not a transfer. */
    return b->purpose != QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE ||
        (!b->allow_node_relocation &&
         b->source.generation == b->target.generation &&
         !memcmp(b->source.node, b->target.node, 16u));
}

static void position_encode(uint8_t *p, const qihse_auth_position_t *position) {
    memcpy(p, position->history, 16u);
    memcpy(p + 16u, position->node, 16u);
    store_be(p + 32u, position->epoch, 8u);
    store_be(p + 40u, position->generation, 8u);
}

static void header_encode(uint8_t *h, const qihse_auth_archive_config_t *config,
                          size_t length, uint64_t count, uint64_t retries,
                          const uint8_t digest[48], const uint8_t iv[12]) {
    const qihse_auth_archive_binding_t *b = &config->binding;
    memcpy(h, "QASEAL01", 8u);
    store_be(h + 8u, b->version, 4u);
    store_be(h + 12u, b->purpose, 4u);
    store_be(h + 16u, b->mode, 4u);
    store_be(h + 20u, b->allow_node_relocation ? 1u : 0u, 4u);
    memcpy(h + 24u, b->source_authority, 16u);
    position_encode(h + 40u, &b->source);
    memcpy(h + 88u, b->target_authority, 16u);
    position_encode(h + 104u, &b->target);
    memcpy(h + 152u, b->archive_id, 16u);
    memcpy(h + 168u, config->keys.recipient_pin, 48u);
    memcpy(h + 216u, config->keys.signer_pin, 48u);
    memcpy(h + 264u, digest, 48u);
    store_be(h + 312u, length, 8u);
    store_be(h + 320u, count, 8u);
    store_be(h + 328u, retries, 8u);
    store_be(h + 336u, QIHSE_MLKEM_CIPHERTEXT_SIZE, 4u);
    store_be(h + 340u, QIHSE_MLDSA_SIGNATURE_SIZE, 4u);
    memcpy(h + 344u, iv, 12u);
}

static int no_password(char *buf, int size, int rwflag, void *arg) {
    (void)buf; (void)size; (void)rwflag; (void)arg;
    return 0;
}

/* Read once through an owner-controlled fd (private keys unreadable to peers;
 * public keys may be readable, but never writable, by peers). Reopening a
 * pinned pathname for sign/decapsulation would introduce key substitution. */
static EVP_PKEY *load_pinned(const char *path, bool private_key, bool kem,
                             const uint8_t pin[48]) {
    EVP_PKEY *key = NULL;
    uint8_t *pem = NULL, *der = NULL;
    BIO *bio = NULL;
    struct stat st;
    size_t length = 0, used = 0;
    int fd = -1, der_length = 0;
    unsigned int digest_length = 0;
    uint8_t digest[48] = {0};
    if (!path || !*path || !pin) goto done;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || st.st_nlink != 1 ||
        (st.st_mode & (private_key ? 077u : 022u)) || st.st_size <= 0 ||
        (uint64_t)st.st_size > KEY_FILE_MAX) goto done;
    length = (size_t)st.st_size;
    pem = OPENSSL_malloc(length);
    if (!pem) goto done;
    while (used < length) {
        ssize_t n = read(fd, pem + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    uint8_t extra;
    ssize_t n;
    do { n = read(fd, &extra, 1u); } while (n < 0 && errno == EINTR);
    if (n != 0) goto done;
    bio = BIO_new_mem_buf(pem, (int)length);
    if (!bio) goto done;
    key = private_key ? PEM_read_bio_PrivateKey(bio, NULL, no_password, NULL) :
                        PEM_read_bio_PUBKEY(bio, NULL, no_password, NULL);
    if (!key) goto done;
    if (kem ? !(EVP_PKEY_is_a(key, "ML-KEM-1024") || EVP_PKEY_is_a(key, "mlkem1024")) :
              !(EVP_PKEY_is_a(key, "ML-DSA-87") || EVP_PKEY_is_a(key, "mldsa87")))
        goto invalid;
    der_length = i2d_PUBKEY(key, &der);
    if (der_length <= 0 ||
        EVP_Digest(der, (size_t)der_length, digest, &digest_length, EVP_sha384(), NULL) != 1 ||
        digest_length != 48u || CRYPTO_memcmp(digest, pin, 48u)) goto invalid;
    goto done;
invalid:
    EVP_PKEY_free(key);
    key = NULL;
done:
    if (fd >= 0) close(fd);
    BIO_free(bio);
    OPENSSL_clear_free(pem, length);
    OPENSSL_free(der);
    OPENSSL_cleanse(digest, sizeof(digest));
    return key;
}

/* Existing PQC path APIs reopen filenames and AES helpers have no AAD. Use
 * the same fixed algorithms/constants and verified in-memory key interface,
 * but retain the validated key handles throughout this transaction. */
static bool kem_key(EVP_PKEY *key, bool encrypt, uint8_t *ciphertext,
                     qihse_pqc_ctx_t *session) {
    bool ok = false;
    size_t secret_length = sizeof(session->aes_key);
    size_t ciphertext_length = QIHSE_MLKEM_CIPHERTEXT_SIZE;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!ctx) goto done;
    if (encrypt) {
        ok = EVP_PKEY_encapsulate_init(ctx, NULL) > 0 &&
             EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_length,
                                   session->aes_key, &secret_length) > 0 &&
             ciphertext_length == QIHSE_MLKEM_CIPHERTEXT_SIZE &&
             secret_length == QIHSE_MLKEM_SHARED_SIZE;
    } else {
        ok = EVP_PKEY_decapsulate_init(ctx, NULL) > 0 &&
             EVP_PKEY_decapsulate(ctx, session->aes_key, &secret_length,
                                   ciphertext, ciphertext_length) > 0 &&
             secret_length == QIHSE_MLKEM_SHARED_SIZE;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    session->initialized = ok;
    if (!ok) qihse_pqc_destroy(session);
    return ok;
}

static bool sign_envelope(EVP_PKEY *key, const uint8_t *data, size_t length,
                           uint8_t *signature) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t signature_length = QIHSE_MLDSA_SIGNATURE_SIZE;
    bool ok = ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) > 0 &&
        EVP_DigestSign(ctx, signature, &signature_length, data, length) > 0 &&
        signature_length == QIHSE_MLDSA_SIGNATURE_SIZE;
    EVP_MD_CTX_free(ctx);
    return ok;
}

qihse_auth_maintenance_status_t qihse_auth_archive_encrypt(
    const qihse_auth_image_context_t *context,
    const qihse_auth_archive_config_t *config,
    const uint8_t *plaintext, size_t length, uint64_t count,
    uint64_t retry_count, qihse_auth_sealed_t **out) {
    qihse_auth_maintenance_status_t status = QIHSE_AUTH_MAINT_CORRUPT;
    qihse_auth_sealed_t *sealed = NULL;
    EVP_PKEY *recipient = NULL, *signer = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    qihse_pqc_ctx_t session = {0};
    uint8_t digest[48] = {0}, iv[12] = {0};
    unsigned int digest_length = 0;
    int n = 0, final_length = 0;
    if (out) *out = NULL;
    if (!out || !plaintext || !length || !valid_binding(config)) return QIHSE_AUTH_MAINT_INVALID;
    if (!qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
    if (length > QIHSE_AUTH_ARCHIVE_MAX_BYTES - ARCHIVE_OVERHEAD || length > INT_MAX ||
        count > QIHSE_AUTH_IMAGE_MAX_PRINCIPALS || retry_count > QIHSE_AUTH_RETRY_MAX)
        return QIHSE_AUTH_MAINT_LIMIT;
    recipient = load_pinned(config->keys.recipient_public_file, false, true, config->keys.recipient_pin);
    signer = load_pinned(config->keys.signer_private_file, true, false, config->keys.signer_pin);
    if (!recipient || !signer) { status = QIHSE_AUTH_MAINT_IO; goto done; }
    sealed = calloc(1u, sizeof(*sealed));
    if (!sealed) { status = QIHSE_AUTH_MAINT_LIMIT; goto done; }
    sealed->length = length + ARCHIVE_OVERHEAD;
    sealed->data = calloc(1u, sealed->length);
    cipher = EVP_CIPHER_CTX_new();
    if (!sealed->data || !cipher) { status = QIHSE_AUTH_MAINT_LIMIT; goto done; }
    if (EVP_Digest(plaintext, length, digest, &digest_length, EVP_sha384(), NULL) != 1 ||
        digest_length != sizeof(digest) || RAND_bytes(iv, sizeof(iv)) != 1) goto done;
    header_encode(sealed->data, config, length, count, retry_count, digest, iv);
    if (!kem_key(recipient, true, sealed->data + ARCHIVE_HEADER_SIZE, &session)) goto done;
    uint8_t *encrypted = sealed->data + ARCHIVE_AAD_SIZE;
    if (EVP_EncryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, session.aes_key, iv) != 1 ||
        EVP_EncryptUpdate(cipher, NULL, &n, sealed->data, ARCHIVE_AAD_SIZE) != 1 ||
        EVP_EncryptUpdate(cipher, encrypted, &n, plaintext, (int)length) != 1 ||
        n != (int)length || EVP_EncryptFinal_ex(cipher, encrypted + length, &final_length) != 1 ||
        final_length != 0 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, QIHSE_AES_GCM_TAG_SIZE, encrypted + length) != 1 ||
        !sign_envelope(signer, sealed->data, sealed->length - QIHSE_MLDSA_SIGNATURE_SIZE,
                       sealed->data + sealed->length - QIHSE_MLDSA_SIGNATURE_SIZE)) goto done;
    *out = sealed;
    sealed = NULL;
    status = QIHSE_AUTH_MAINT_OK;
done:
    qihse_auth_sealed_free(sealed);
    EVP_CIPHER_CTX_free(cipher);
    EVP_PKEY_free(recipient);
    EVP_PKEY_free(signer);
    qihse_pqc_destroy(&session);
    OPENSSL_cleanse(digest, sizeof(digest));
    return status;
}

qihse_auth_maintenance_status_t qihse_auth_archive_decrypt(
    const qihse_auth_image_context_t *context,
    const qihse_auth_archive_config_t *config,
    const uint8_t *sealed, size_t length, uint8_t **plaintext,
    size_t *plaintext_length, uint64_t *count, uint64_t *retry_count) {
    qihse_auth_maintenance_status_t status = QIHSE_AUTH_MAINT_CORRUPT;
    EVP_PKEY *recipient = NULL, *signer = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    qihse_pqc_ctx_t session = {0};
    uint8_t header[ARCHIVE_HEADER_SIZE] = {0}, digest[48] = {0};
    uint8_t *staging = NULL;
    unsigned int digest_length = 0;
    size_t size = 0;
    int n = 0, final_length = 0;
    if (plaintext) *plaintext = NULL;
    if (plaintext_length) *plaintext_length = 0;
    if (count) *count = 0;
    if (retry_count) *retry_count = 0;
    if (!plaintext || !plaintext_length || !count || !retry_count || !sealed ||
        !valid_binding(config)) return QIHSE_AUTH_MAINT_INVALID;
    if (!qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
    if (length <= ARCHIVE_OVERHEAD || length > QIHSE_AUTH_ARCHIVE_MAX_BYTES)
        return QIHSE_AUTH_MAINT_CORRUPT;
    uint64_t declared = load_be(sealed + 312u, 8u);
    uint64_t rows = load_be(sealed + 320u, 8u), retries = load_be(sealed + 328u, 8u);
    if (declared != length - ARCHIVE_OVERHEAD || declared > INT_MAX ||
        rows > QIHSE_AUTH_IMAGE_MAX_PRINCIPALS || retries > QIHSE_AUTH_RETRY_MAX) goto done;
    size = (size_t)declared;
    header_encode(header, config, size, rows, retries, sealed + 264u, sealed + 344u);
    if (CRYPTO_memcmp(header, sealed, sizeof(header))) goto done;
    signer = load_pinned(config->keys.signer_public_file, false, false, config->keys.signer_pin);
    if (!signer) { status = QIHSE_AUTH_MAINT_IO; goto done; }
    if (!qihse_pqc_verify_with_key(sealed, length - QIHSE_MLDSA_SIGNATURE_SIZE,
                                  sealed + length - QIHSE_MLDSA_SIGNATURE_SIZE, signer)) goto done;
    /* Nothing below runs for unauthenticated input. No plaintext is released
     * until both the signature and GCM tag and digest have been checked. */
    recipient = load_pinned(config->keys.recipient_private_file, true, true, config->keys.recipient_pin);
    if (!recipient) { status = QIHSE_AUTH_MAINT_IO; goto done; }
    if (!kem_key(recipient, false, (uint8_t *)sealed + ARCHIVE_HEADER_SIZE, &session)) goto done;
    staging = OPENSSL_zalloc(size + EVP_MAX_BLOCK_LENGTH);
    cipher = EVP_CIPHER_CTX_new();
    if (!staging || !cipher) { status = QIHSE_AUTH_MAINT_LIMIT; goto done; }
    const uint8_t *encrypted = sealed + ARCHIVE_AAD_SIZE;
    if (EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, session.aes_key, sealed + 344u) != 1 ||
        EVP_DecryptUpdate(cipher, NULL, &n, sealed, ARCHIVE_AAD_SIZE) != 1 ||
        EVP_DecryptUpdate(cipher, staging, &n, encrypted, (int)size) != 1 || n != (int)size ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, QIHSE_AES_GCM_TAG_SIZE,
                             (void *)(encrypted + size)) != 1 ||
        EVP_DecryptFinal_ex(cipher, staging + size, &final_length) != 1 || final_length != 0 ||
        EVP_Digest(staging, size, digest, &digest_length, EVP_sha384(), NULL) != 1 ||
        digest_length != sizeof(digest) || CRYPTO_memcmp(digest, sealed + 264u, sizeof(digest))) goto done;
    *plaintext = staging;
    *plaintext_length = size;
    *count = rows;
    *retry_count = retries;
    staging = NULL;
    status = QIHSE_AUTH_MAINT_OK;
done:
    OPENSSL_clear_free(staging, size + EVP_MAX_BLOCK_LENGTH);
    EVP_CIPHER_CTX_free(cipher);
    EVP_PKEY_free(recipient);
    EVP_PKEY_free(signer);
    qihse_pqc_destroy(&session);
    OPENSSL_cleanse(digest, sizeof(digest));
    return status;
}

const uint8_t *qihse_auth_sealed_data(const qihse_auth_sealed_t *sealed) {
    return sealed ? sealed->data : NULL;
}

size_t qihse_auth_sealed_size(const qihse_auth_sealed_t *sealed) {
    return sealed ? sealed->length : 0;
}

void qihse_auth_sealed_free(qihse_auth_sealed_t *sealed) {
    if (!sealed) return;
    if (sealed->data) { OPENSSL_cleanse(sealed->data, sealed->length); free(sealed->data); }
    OPENSSL_cleanse(sealed, sizeof(*sealed));
    free(sealed);
}
