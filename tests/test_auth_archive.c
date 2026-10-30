#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth_archive_crypto.h"
#include "qihse_audit.h"
#include "qihse_pqc_crypto.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(e) do { if (!(e)) { fprintf(stderr, "archive assertion %s:%d: %s\n", __FILE__, __LINE__, #e); exit(EXIT_FAILURE); } } while (0)
#define OK(e) CHECK((e) == QIHSE_AUTH_MAINT_OK)

/* A fresh private authority: no configured host keys or production principals. */
static const char password[] = "Archive-Synthetic-Only!72";
static char directory[] = "./build/test-auth-archive-XXXXXX";
static char paths[10][256];
static qihse_auth_archive_keys_t keys, other_keys;

static void key_pair(const char *algorithm, size_t priv, size_t pub, uint8_t pin[48]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    EVP_PKEY *key = NULL;
    CHECK(ctx && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_generate(ctx, &key) > 0);
    int fd = open(paths[priv], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    FILE *file = fdopen(fd, "w");
    CHECK(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    CHECK(fclose(file) == 0);
    fd = open(paths[pub], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    file = fdopen(fd, "w");
    CHECK(file && PEM_write_PUBKEY(file, key) == 1);
    CHECK(fclose(file) == 0);
    unsigned char *der = NULL;
    int length = i2d_PUBKEY(key, &der);
    unsigned int n = 0;
    CHECK(length > 0 && EVP_Digest(der, (size_t)length, pin, &n, EVP_sha384(), NULL) == 1 && n == 48);
    OPENSSL_free(der); EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx);
}

static void setup_keys(void) {
    CHECK(mkdir("./build", 0700) == 0 || errno == EEXIST);
    CHECK(mkdtemp(directory));
    CHECK(setenv("QIHSE_DATA_DIR", directory, 1) == 0);
    const char *names[] = {"kem.pem", "kem.pub", "dsa.pem", "dsa.pub",
        "other-kem.pem", "other-kem.pub", "other-dsa.pem", "other-dsa.pub", "bootstrap", "state"};
    for (size_t i = 0; i < 10; ++i) {
        int n = snprintf(paths[i], sizeof(paths[i]), "%s/%s", directory, names[i]);
        CHECK(n > 0 && (size_t)n < sizeof(paths[i]));
    }
    CHECK(mkdir(paths[9], 0700) == 0);
    qihse_pqc_init_providers();
    keys.recipient_private_file = paths[0]; keys.recipient_public_file = paths[1];
    keys.signer_private_file = paths[2]; keys.signer_public_file = paths[3];
    other_keys.recipient_private_file = paths[4]; other_keys.recipient_public_file = paths[5];
    other_keys.signer_private_file = paths[6]; other_keys.signer_public_file = paths[7];
    key_pair("ML-KEM-1024", 0, 1, keys.recipient_pin);
    key_pair("ML-DSA-87", 2, 3, keys.signer_pin);
    key_pair("ML-KEM-1024", 4, 5, other_keys.recipient_pin);
    key_pair("ML-DSA-87", 6, 7, other_keys.signer_pin);
}

static void position_equal(const qihse_auth_position_t *a, const qihse_auth_position_t *b) {
    CHECK(memcmp(a->history, b->history, 16) == 0 && memcmp(a->node, b->node, 16) == 0);
    CHECK(a->epoch == b->epoch && a->generation == b->generation);
}

static qihse_auth_archive_config_t config_for(const qihse_auth_position_t *position) {
    qihse_auth_archive_config_t c = {0};
    c.keys = keys; c.binding.version = QIHSE_AUTH_ARCHIVE_VERSION;
    c.binding.purpose = QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER;
    c.binding.mode = QIHSE_AUTH_AUTHORITY_STANDALONE;
    memset(c.binding.source_authority, 0x31, 16);
    memcpy(c.binding.target_authority, c.binding.source_authority, 16);
    c.binding.source = c.binding.target = *position;
    memset(c.binding.archive_id, 0x73, 16);
    return c;
}

static void principal_equal(const qihse_user_t *a, const qihse_user_t *b) {
    CHECK(a->user_id == b->user_id && a->tenant_id == b->tenant_id);
    CHECK(a->role == b->role && a->classification_level == b->classification_level);
    CHECK(a->sci_compartments == b->sci_compartments);
    CHECK(a->can_create_users == b->can_create_users);
    CHECK(a->requires_hardware_token == b->requires_hardware_token);
    CHECK(!b->hardware_token_present && b->password_set);
    CHECK(strcmp(a->username, b->username) == 0);
    CHECK(strcmp(a->fido2_credential_id, b->fido2_credential_id) == 0);
    CHECK(a->verifier.version == b->verifier.version && a->verifier.algorithm == b->verifier.algorithm);
    CHECK(a->verifier.iterations == b->verifier.iterations);
    CHECK(memcmp(a->verifier.salt, b->verifier.salt, QIHSE_PW_SALT_BYTES) == 0);
    CHECK(memcmp(a->verifier.verifier, b->verifier.verifier, QIHSE_PW_HASH_BYTES) == 0);
    CHECK(a->object_acl_count == b->object_acl_count);
    for (uint8_t i = 0; i < a->object_acl_count; ++i) {
        CHECK(a->object_acl[i].namespace_id == b->object_acl[i].namespace_id);
        CHECK(a->object_acl[i].resource_id == b->object_acl[i].resource_id);
        CHECK(a->object_acl[i].access_flags == b->object_acl[i].access_flags);
    }
}

static void image_equal(const qihse_auth_image_t *a, const qihse_auth_image_t *b) {
    position_equal(&a->position, &b->position);
    CHECK(a->root_generation == b->root_generation && a->root_failed_count == b->root_failed_count);
    CHECK(a->root_lockout_until == b->root_lockout_until);
    CHECK(a->count == b->count && a->retry_count == b->retry_count && a->has_local_root == b->has_local_root);
    if (a->has_local_root) {
        principal_equal(&a->local_root, &b->local_root);
        CHECK(memcmp(a->bootstrap_binding, b->bootstrap_binding, 48) == 0);
    }
    for (size_t i = 0; i < a->count; ++i) {
        const qihse_auth_image_row_t *x = &a->rows[i], *y = &b->rows[i];
        CHECK(x->user_id == y->user_id && x->active == y->active);
        CHECK(x->generation == y->generation && x->failed_count == y->failed_count);
        CHECK(x->lockout_until == y->lockout_until);
        if (x->active) principal_equal(&x->principal, &y->principal);
        else { qihse_user_t zero = {0}; CHECK(memcmp(&y->principal, &zero, sizeof(zero)) == 0); }
    }
    for (size_t i = 0; i < a->retry_count; ++i) {
        CHECK(memcmp(a->retries[i].request_id, b->retries[i].request_id, 16) == 0);
        CHECK(memcmp(a->retries[i].digest, b->retries[i].digest, 48) == 0);
        CHECK(a->retries[i].actor_id == b->retries[i].actor_id);
        CHECK(a->retries[i].actor_generation == b->retries[i].actor_generation);
        position_equal(&a->retries[i].result, &b->retries[i].result);
    }
}

static void external_only(const qihse_auth_image_t *image) {
    uint8_t zero[48] = {0}; qihse_user_t root = {0};
    CHECK(!image->has_local_root && memcmp(image->bootstrap_binding, zero, 48) == 0);
    CHECK(memcmp(&image->local_root, &root, sizeof(root)) == 0);
}

static qihse_auth_image_t *synthetic_image(void) {
    qihse_auth_image_t *im = calloc(1, sizeof(*im)); CHECK(im);
    memset(im->position.history, 0x11, 16); memset(im->position.node, 0x22, 16);
    im->position.epoch = UINT64_C(0x0102030405060708); im->position.generation = 19;
    memset(im->bootstrap_binding, 0xee, 48);
    im->root_generation = 9; im->root_failed_count = 3;
    im->root_lockout_until = UINT64_C(0x11223344556677);
    im->count = 2; im->rows = calloc(im->count, sizeof(*im->rows)); CHECK(im->rows);
    qihse_auth_image_row_t *row = &im->rows[0];
    row->user_id = 7; row->active = true; row->generation = 11;
    row->failed_count = 4; row->lockout_until = INT64_MAX;
    qihse_user_t *p = &row->principal;
    p->user_id = 7; p->tenant_id = 23; p->role = QIHSE_ROLE_ANALYST;
    p->classification_level = 0x1234; p->sci_compartments = 0x5678;
    p->can_create_users = true; p->requires_hardware_token = true;
    strcpy(p->username, "archive-synthetic"); strcpy(p->fido2_credential_id, "synthetic-credential");
    p->password_set = true; p->verifier.version = QIHSE_PW_VERIFIER_VERSION_1;
    p->verifier.algorithm = QIHSE_PW_ALG_PBKDF2_HMAC_SHA384;
    p->verifier.iterations = QIHSE_PW_MIN_ITERATIONS;
    for (size_t i = 0; i < sizeof(p->verifier.salt); ++i) p->verifier.salt[i] = (uint8_t)(i + 1);
    for (size_t i = 0; i < sizeof(p->verifier.verifier); ++i) p->verifier.verifier[i] = (uint8_t)(i + 33);
    p->object_acl_count = 2;
    p->object_acl[0] = (qihse_acl_entry_t){17, UINT64_C(0x1020304050607080), QIHSE_ACL_READ | QIHSE_ACL_WRITE};
    p->object_acl[1] = (qihse_acl_entry_t){UINT32_MAX, UINT64_MAX, QIHSE_ACL_ADMIN};
    im->rows[1].user_id = 99; im->rows[1].generation = 5;
    im->rows[1].failed_count = 2; im->rows[1].lockout_until = 77;
    /* Deliberate retired secret: tombstones must serialize metadata only. */
    memset(&im->rows[1].principal, 0xab, sizeof(im->rows[1].principal));
    im->retry_count = 2;
    for (size_t i = 0; i < im->retry_count; ++i) {
        qihse_auth_retry_t *r = &im->retries[i];
        memset(r->request_id, (int)i + 1, 16); memset(r->digest, (int)i + 3, 48);
        r->actor_id = i ? UINT32_MAX : 7; r->actor_generation = i ? 0 : 11;
        r->result = im->position; r->result.generation -= i;
    }
    return im;
}

static void decode_reject(const qihse_auth_image_context_t *ctx, const uint8_t *bytes, size_t length) {
    qihse_auth_image_t *out = (void *)1;
    CHECK(qihse_auth_image_decode(ctx, bytes, length, &out) == QIHSE_AUTH_MAINT_CORRUPT);
    CHECK(out == NULL);
}

static void encode_reject(const qihse_auth_image_context_t *ctx, const qihse_auth_image_t *im) {
    uint8_t *out = (void *)1; size_t length = 123;
    CHECK(qihse_auth_image_encode(ctx, im, &out, &length) == QIHSE_AUTH_MAINT_INVALID);
    CHECK(out == NULL && length == 0);
}

static void codec_tests(const qihse_auth_image_context_t *ctx, qihse_auth_image_t *im) {
    /* Explicit v1 empty-image golden bytes, independent of native struct layout. */
    qihse_auth_image_t empty = {0};
    empty.position = im->position; empty.root_generation = 1;
    uint8_t golden[141] = {0};
    memcpy(golden, "QAIMAGE1", 8); golden[11] = 1; golden[15] = 2;
    memset(golden + 16, 0x11, 16); memset(golden + 32, 0x22, 16);
    const uint8_t epoch[] = {1,2,3,4,5,6,7,8};
    memcpy(golden + 48, epoch, 8); golden[63] = 19; golden[119] = 1;
    uint8_t *bytes = NULL; size_t length = 0;
    OK(qihse_auth_image_encode(ctx, &empty, &bytes, &length));
    CHECK(length == sizeof(golden) && memcmp(bytes, golden, sizeof(golden)) == 0);
    OPENSSL_cleanse(bytes, length); free(bytes);
    qihse_auth_image_t *decoded = NULL;
    OK(qihse_auth_image_decode(ctx, golden, sizeof(golden), &decoded));
    image_equal(&empty, decoded); external_only(decoded); qihse_auth_image_free(decoded);

    OK(qihse_auth_image_encode(ctx, im, &bytes, &length));
    /* 141 header + 25 row + 216 principal + 26 ACL + 25 tombstone + 248 retries. */
    CHECK(length == 681);
    const uint8_t row_prefix[] = {0,0,0,7,1,0,0,0,0,0,0,0,11,0,0,0,4,
                                 0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    CHECK(memcmp(bytes + 141, row_prefix, sizeof(row_prefix)) == 0);
    const uint8_t principal_prefix[] = {0,0,0,7,0,0,0,23,0,1,0x12,0x34,0x56,0x78,3};
    CHECK(memcmp(bytes + 166, principal_prefix, sizeof(principal_prefix)) == 0);
    const uint8_t verifier_prefix[] = {0,1,0,1,0,9,0x27,0xc0};
    CHECK(memcmp(bytes + 309, verifier_prefix, sizeof(verifier_prefix)) == 0);
    const uint8_t acl_bytes[] = {0,0,0,17,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,3,
                                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,4};
    CHECK(memcmp(bytes + 382, acl_bytes, sizeof(acl_bytes)) == 0);
    OK(qihse_auth_image_decode(ctx, bytes, length, &decoded));
    image_equal(im, decoded); external_only(decoded);
    uint8_t *again = NULL; size_t again_length = 0;
    OK(qihse_auth_image_encode(ctx, decoded, &again, &again_length));
    CHECK(length == again_length && memcmp(bytes, again, length) == 0);
    OPENSSL_cleanse(again, again_length); free(again); qihse_auth_image_free(decoded);
    qihse_auth_image_row_t swap = im->rows[0]; im->rows[0] = im->rows[1]; im->rows[1] = swap;
    OK(qihse_auth_image_encode(ctx, im, &again, &again_length));
    CHECK(length == again_length && memcmp(bytes, again, length) == 0);
    OPENSSL_cleanse(again, again_length); free(again);
    swap = im->rows[0]; im->rows[0] = im->rows[1]; im->rows[1] = swap;
    for (size_t n = 0; n < length; ++n) decode_reject(ctx, bytes, n);
    decode_reject(ctx, bytes, QIHSE_AUTH_ARCHIVE_MAX_BYTES + (size_t)1);
    uint8_t *bad = malloc(length + 1); CHECK(bad);
    /* Version/purpose, root leakage, counts, booleans, verifier and ACL bounds. */
    const size_t offsets[] = {0,11,15,64,132,136,140,145,175,180,309,311,381};
    for (size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); ++i) {
        memcpy(bad, bytes, length); bad[offsets[i]] = 0xff; decode_reject(ctx, bad, length);
    }
    memcpy(bad, bytes, length); bad[length] = 0; decode_reject(ctx, bad, length + 1);
    memcpy(bad, bytes, length); bad[181 + 63] = 1; decode_reject(ctx, bad, length);
    memcpy(bad, bytes, length); memset(bad + 181, 'x', 64); decode_reject(ctx, bad, length);
    memcpy(bad, bytes, length); memset(bad + 141, 0, 4); decode_reject(ctx, bad, length);
    memcpy(bad, bytes, length); memcpy(bad + 408, bad + 141, 4); decode_reject(ctx, bad, length);
    memcpy(bad, bytes, length); bad[394] = 0x80; decode_reject(ctx, bad, length);
    /* Retry IDs must be unique; malformed retry provenance is not a QPR1 record. */
    memcpy(bad, bytes, length); memcpy(bad + 557, bad + 433, 16); decode_reject(ctx, bad, length);
    memcpy(bad, bytes, length); memset(bad + 433, 0, 16); decode_reject(ctx, bad, length);
    OPENSSL_cleanse(bad, length + 1); free(bad);
    OPENSSL_cleanse(bytes, length); free(bytes);

    im->has_local_root = true; encode_reject(ctx, im); im->has_local_root = false;
    qihse_user_t *p = &im->rows[0].principal;
    p->hardware_token_present = true; encode_reject(ctx, im); p->hardware_token_present = false;
    p->verifier.version++; encode_reject(ctx, im); p->verifier.version--;
    p->verifier.algorithm++; encode_reject(ctx, im); p->verifier.algorithm--;
    p->verifier.iterations--; encode_reject(ctx, im); p->verifier.iterations++;
    p->verifier.iterations = (uint32_t)INT_MAX + 1u; encode_reject(ctx, im);
    p->verifier.iterations = QIHSE_PW_MIN_ITERATIONS;
    p->object_acl_count = QIHSE_OBJECT_ACL_MAX_ENTRIES + 1;
    encode_reject(ctx, im); p->object_acl_count = 2;
    im->count = QIHSE_AUTH_IMAGE_MAX_PRINCIPALS + (size_t)1; encode_reject(ctx, im); im->count = 2;
    im->retry_count = QIHSE_AUTH_RETRY_MAX + (size_t)1; encode_reject(ctx, im); im->retry_count = 2;
    im->rows[1].user_id = 7; encode_reject(ctx, im); im->rows[1].user_id = 99;
    im->rows[0].lockout_until = UINT64_MAX; encode_reject(ctx, im); im->rows[0].lockout_until = INT64_MAX;
    /* Inclusive supported string/ACL/verifier boundaries must remain accepted. */
    qihse_user_t saved = *p;
    memset(p->username, 'u', 63); p->username[63] = 0;
    memset(p->fido2_credential_id, 'c', 63); p->fido2_credential_id[63] = 0;
    p->verifier.iterations = INT_MAX; p->object_acl_count = QIHSE_OBJECT_ACL_MAX_ENTRIES;
    for (size_t i = 0; i < QIHSE_OBJECT_ACL_MAX_ENTRIES; ++i)
        p->object_acl[i] = (qihse_acl_entry_t){(uint32_t)i, UINT64_MAX - i, QIHSE_ACL_ADMIN};
    OK(qihse_auth_image_encode(ctx, im, &bytes, &length));
    OK(qihse_auth_image_decode(ctx, bytes, length, &decoded));
    image_equal(im, decoded); qihse_auth_image_free(decoded);
    OPENSSL_cleanse(bytes, length); free(bytes); *p = saved; OPENSSL_cleanse(&saved, sizeof(saved));
}

static void open_reject(const qihse_auth_image_context_t *ctx,
                        const qihse_auth_archive_config_t *config, const uint8_t *bytes, size_t length) {
    qihse_auth_image_t *out = (void *)1;
    CHECK(qihse_auth_archive_open(ctx, bytes, length, config, &out) != QIHSE_AUTH_MAINT_OK);
    CHECK(out == NULL);
    uint8_t *plain = (void *)1; size_t plain_length = 99;
    uint64_t count = 99, retries = 99;
    CHECK(qihse_auth_archive_decrypt(ctx, config, bytes, length,
          &plain, &plain_length, &count, &retries) != QIHSE_AUTH_MAINT_OK);
    CHECK(plain == NULL && plain_length == 0 && count == 0 && retries == 0);
}

static void resign(uint8_t *bytes, size_t length) {
    FILE *file = fopen(keys.signer_private_file, "r"); CHECK(file);
    EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    CHECK(fclose(file) == 0 && key);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); size_t n = QIHSE_MLDSA_SIGNATURE_SIZE;
    CHECK(ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) > 0);
    CHECK(EVP_DigestSign(ctx, bytes + length - QIHSE_MLDSA_SIGNATURE_SIZE, &n,
                        bytes, length - QIHSE_MLDSA_SIGNATURE_SIZE) > 0);
    CHECK(n == QIHSE_MLDSA_SIGNATURE_SIZE);
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
}

static void crypto_tests(const qihse_auth_image_context_t *ctx,
                         qihse_auth_image_t *im, const qihse_user_t *root) {
    qihse_auth_archive_config_t config = config_for(&im->position);
    qihse_auth_sealed_t *sealed = NULL;
    OK(qihse_auth_archive_seal(ctx, im, &config, &sealed));
    const uint8_t *bytes = qihse_auth_sealed_data(sealed);
    size_t length = qihse_auth_sealed_size(sealed);
    CHECK(length > 681 && memcmp(bytes, "QASEAL01", 8) == 0);
    qihse_auth_image_t *out = NULL;
    OK(qihse_auth_archive_open(ctx, bytes, length, &config, &out));
    image_equal(im, out); external_only(out); qihse_auth_image_free(out);
    qihse_auth_archive_config_t bad;
#define WRONG(statement) do { bad = config; statement; open_reject(ctx, &bad, bytes, length); } while (0)
    WRONG(bad.keys.recipient_pin[0] ^= 1);
    WRONG(bad.keys.signer_pin[0] ^= 1);
    WRONG(bad.keys.recipient_private_file = other_keys.recipient_private_file);
    WRONG(bad.keys.signer_public_file = other_keys.signer_public_file);
    WRONG(bad.binding.source.history[0] ^= 1; bad.binding.target.history[0] ^= 1);
    WRONG(bad.binding.source.node[0] ^= 1; bad.binding.target.node[0] ^= 1);
    WRONG(bad.binding.source_authority[0] ^= 1; bad.binding.target_authority[0] ^= 1);
    WRONG(bad.binding.target_authority[0] ^= 1);
    WRONG(bad.binding.target.generation++);
    WRONG(bad.binding.source.generation++);
    WRONG(bad.binding.target.epoch++; bad.binding.source.epoch++);
    WRONG(bad.binding.archive_id[0] ^= 1);
    WRONG(bad.binding.purpose = QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE);
    WRONG(bad.binding.version++);
    WRONG(bad.binding.mode = QIHSE_AUTH_AUTHORITY_CONSENSUS);
#undef WRONG
    uint8_t *tampered = malloc(length + 1); CHECK(tampered);
    const size_t offsets[] = {0,11,15,20,24,40,88,104,152,168,216,264,312,320,328,336,340,344,356};
    for (size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); ++i) {
        memcpy(tampered, bytes, length); tampered[offsets[i]] ^= 1;
        open_reject(ctx, &config, tampered, length);
    }
    size_t aad = 356 + QIHSE_MLKEM_CIPHERTEXT_SIZE;
    const size_t encrypted_offsets[] = {264,344,356,aad,aad + 681,length - 1};
    for (size_t i = 0; i < sizeof(encrypted_offsets)/sizeof(encrypted_offsets[0]); ++i) {
        memcpy(tampered, bytes, length); tampered[encrypted_offsets[i]] ^= 1;
        open_reject(ctx, &config, tampered, length);
        /* Valid signatures exercise post-verification KEM/GCM/digest failures. */
        if (encrypted_offsets[i] != length - 1) {
            resign(tampered, length); open_reject(ctx, &config, tampered, length);
        }
    }
    const size_t cuts[] = {0,1,355,356,357,1024};
    for (size_t i = 0; i < sizeof(cuts)/sizeof(cuts[0]); ++i) open_reject(ctx, &config, bytes, cuts[i]);
    open_reject(ctx, &config, bytes, length - 1);
    memcpy(tampered, bytes, length); tampered[length] = 0;
    open_reject(ctx, &config, tampered, length + 1);
    open_reject(ctx, &config, bytes, QIHSE_AUTH_ARCHIVE_MAX_BYTES + (size_t)1);
    OPENSSL_cleanse(tampered, length + 1); free(tampered); qihse_auth_sealed_free(sealed);

    uint8_t *plain = NULL; size_t plain_length = 0;
    OK(qihse_auth_image_encode(ctx, im, &plain, &plain_length));
    OK(qihse_auth_archive_encrypt(ctx, &config, plain, plain_length, im->count + 1, im->retry_count, &sealed));
    out = (void *)1;
    CHECK(qihse_auth_archive_open(ctx, qihse_auth_sealed_data(sealed),
          qihse_auth_sealed_size(sealed), &config, &out) == QIHSE_AUTH_MAINT_CORRUPT && out == NULL);
    qihse_auth_sealed_free(sealed);
    plain[11] = 2;
    OK(qihse_auth_archive_encrypt(ctx, &config, plain, plain_length, im->count, im->retry_count, &sealed));
    out = (void *)1;
    CHECK(qihse_auth_archive_open(ctx, qihse_auth_sealed_data(sealed),
          qihse_auth_sealed_size(sealed), &config, &out) == QIHSE_AUTH_MAINT_CORRUPT && out == NULL);
    qihse_auth_sealed_free(sealed); OPENSSL_cleanse(plain, plain_length); free(plain);

    bad = config; bad.keys.signer_private_file = other_keys.signer_private_file;
    sealed = (void *)1;
    CHECK(qihse_auth_archive_seal(ctx, im, &bad, &sealed) == QIHSE_AUTH_MAINT_IO && sealed == NULL);
    CHECK(chmod(keys.signer_private_file, 0644) == 0);
    sealed = (void *)1;
    CHECK(qihse_auth_archive_seal(ctx, im, &config, &sealed) == QIHSE_AUTH_MAINT_IO && sealed == NULL);
    CHECK(chmod(keys.signer_private_file, 0600) == 0);
    bad = config; bad.binding.allow_node_relocation = true; bad.binding.target.node[0] ^= 1;
    OK(qihse_auth_archive_seal(ctx, im, &bad, &sealed));
    OK(qihse_auth_archive_open(ctx, qihse_auth_sealed_data(sealed), qihse_auth_sealed_size(sealed), &bad, &out));
    image_equal(im, out); external_only(out); qihse_auth_image_free(out);
    bad.binding.allow_node_relocation = false;
    open_reject(ctx, &bad, qihse_auth_sealed_data(sealed), qihse_auth_sealed_size(sealed));
    qihse_auth_sealed_free(sealed);

    im->has_local_root = true; im->local_root = *root; im->local_root.hardware_token_present = false;
    encode_reject(ctx, im);
    sealed = (void *)1;
    CHECK(qihse_auth_archive_seal(ctx, im, &config, &sealed) == QIHSE_AUTH_MAINT_INVALID && sealed == NULL);
    config.binding.purpose = QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE;
    OK(qihse_auth_archive_seal(ctx, im, &config, &sealed));
    OK(qihse_auth_archive_open(ctx, qihse_auth_sealed_data(sealed), qihse_auth_sealed_size(sealed), &config, &out));
    image_equal(im, out); qihse_auth_image_free(out);
    config.binding.purpose = QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER;
    open_reject(ctx, &config, qihse_auth_sealed_data(sealed), qihse_auth_sealed_size(sealed));
    qihse_auth_sealed_free(sealed);
    im->has_local_root = false; OPENSSL_cleanse(&im->local_root, sizeof(im->local_root));
}

static qihse_auth_image_t *capture(const qihse_auth_image_context_t *ctx) {
    qihse_auth_image_t *im = NULL;
    qihse_auth_lifecycle_enter(); OK(qihse_auth_image_capture(ctx, &im)); qihse_auth_lifecycle_leave();
    return im;
}

static void denied(const qihse_user_t *actor, const qihse_auth_image_t *im,
                   const qihse_auth_archive_config_t *config, const qihse_auth_sealed_t *sealed) {
    qihse_auth_image_context_t ctx = {actor, NULL};
    uint8_t *bytes = (void *)1; size_t length = 9;
    qihse_auth_image_t *out = (void *)1; qihse_auth_sealed_t *cipher = (void *)1;
    qihse_auth_lifecycle_enter();
    CHECK(qihse_auth_image_encode(&ctx, im, &bytes, &length) == QIHSE_AUTH_MAINT_DENIED);
    CHECK(bytes == NULL && length == 0);
    CHECK(qihse_auth_image_decode(&ctx, (const uint8_t *)"x", 1, &out) == QIHSE_AUTH_MAINT_DENIED && out == NULL);
    out = (void *)1;
    CHECK(qihse_auth_image_capture(&ctx, &out) == QIHSE_AUTH_MAINT_DENIED && out == NULL);
    CHECK(qihse_auth_archive_seal(&ctx, im, config, &cipher) == QIHSE_AUTH_MAINT_DENIED && cipher == NULL);
    out = (void *)1;
    CHECK(qihse_auth_archive_open(&ctx, qihse_auth_sealed_data(sealed),
          qihse_auth_sealed_size(sealed), config, &out) == QIHSE_AUTH_MAINT_DENIED && out == NULL);
    uint64_t rows = 1, retries = 1; bytes = (void *)1; length = 9;
    CHECK(qihse_auth_archive_decrypt(&ctx, config, qihse_auth_sealed_data(sealed),
          qihse_auth_sealed_size(sealed), &bytes, &length, &rows, &retries) == QIHSE_AUTH_MAINT_DENIED);
    CHECK(bytes == NULL && length == 0 && rows == 0 && retries == 0);
    qihse_auth_lifecycle_leave();
    cipher = (void *)1;
    CHECK(qihse_auth_maintenance_export(actor, &im->position, config, &cipher) == QIHSE_AUTH_MAINT_DENIED && cipher == NULL);
    qihse_auth_position_t result, zero = {0}; memset(&result, 0xaa, sizeof(result));
    uint8_t request[16] = {9};
    CHECK(qihse_auth_maintenance_import(actor, &im->position, request, config,
          qihse_auth_sealed_data(sealed), qihse_auth_sealed_size(sealed), &result) == QIHSE_AUTH_MAINT_DENIED);
    CHECK(memcmp(&result, &zero, sizeof(result)) == 0);
}

static void maintenance_tests(qihse_user_t *root) {
    qihse_auth_image_context_t ctx = {root, NULL};
    qihse_user_t *guest = qihse_auth_create_user(root, 101, QIHSE_ROLE_GUEST, 0, 0, password, false);
    qihse_user_t *low = qihse_auth_create_user(root, 102, QIHSE_ROLE_ANALYST, 1, 0, password, false);
    qihse_user_t *tenant = qihse_auth_create_tenant_user(root, 42, 103, QIHSE_ROLE_OPERATOR,
                                                      UINT16_MAX, UINT16_MAX, password, false);
    qihse_user_t *revoked = qihse_auth_create_user(root, 104, QIHSE_ROLE_OPERATOR,
                                                UINT16_MAX, UINT16_MAX, password, false);
    qihse_user_t *stale = qihse_auth_create_user(root, 105, QIHSE_ROLE_OPERATOR,
                                              UINT16_MAX, UINT16_MAX, password, false);
    CHECK(guest && low && tenant && revoked && stale);
    qihse_user_t retired = *revoked; retired.hardware_token_present = false;
    CHECK(qihse_auth_destroy_user(root, 104));
    qihse_auth_image_t *before = capture(&ctx);
    qihse_auth_archive_config_t config = config_for(&before->position);
    qihse_auth_sealed_t *sealed = NULL;
    OK(qihse_auth_maintenance_export(root, &before->position, &config, &sealed));
    qihse_auth_image_t *exported = NULL;
    qihse_auth_lifecycle_enter();
    OK(qihse_auth_archive_open(&ctx, qihse_auth_sealed_data(sealed), qihse_auth_sealed_size(sealed), &config, &exported));
    qihse_auth_lifecycle_leave();
    image_equal(before, exported); external_only(exported); qihse_auth_image_free(exported);
    const qihse_user_t *actors[] = {NULL, guest, low, tenant, revoked};
    for (size_t i = 0; i < sizeof(actors)/sizeof(actors[0]); ++i) denied(actors[i], before, &config, sealed);
    qihse_auth_position_t result, zero = {0}; uint8_t request[16] = {0x91};
    size_t sealed_length = qihse_auth_sealed_size(sealed);
    uint8_t *tampered = malloc(sealed_length); CHECK(tampered);
    memcpy(tampered, qihse_auth_sealed_data(sealed), sealed_length); tampered[sealed_length - 1] ^= 1;
    memset(&result, 0xaa, sizeof(result));
    CHECK(qihse_auth_maintenance_import(root, &before->position, request, &config,
          tampered, sealed_length, &result) == QIHSE_AUTH_MAINT_CORRUPT);
    CHECK(memcmp(&result, &zero, sizeof(result)) == 0);
    qihse_auth_image_t *after = capture(&ctx); image_equal(before, after); qihse_auth_image_free(after);

    /* A correctly signed image still cannot resurrect a local tombstone. */
    size_t tombstone = 0;
    while (tombstone < before->count && before->rows[tombstone].user_id != 104) tombstone++;
    CHECK(tombstone < before->count && !before->rows[tombstone].active);
    before->rows[tombstone].active = true; before->rows[tombstone].principal = retired;
    qihse_auth_sealed_t *resurrection = NULL;
    qihse_auth_lifecycle_enter();
    OK(qihse_auth_archive_seal(&ctx, before, &config, &resurrection));
    qihse_auth_lifecycle_leave();
    memset(&result, 0xaa, sizeof(result));
    CHECK(qihse_auth_maintenance_import(root, &before->position, request, &config,
          qihse_auth_sealed_data(resurrection), qihse_auth_sealed_size(resurrection),
          &result) == QIHSE_AUTH_MAINT_CONFLICT);
    CHECK(memcmp(&result, &zero, sizeof(result)) == 0);
    before->rows[tombstone].active = false;
    OPENSSL_cleanse(&before->rows[tombstone].principal, sizeof(retired));
    OPENSSL_cleanse(&retired, sizeof(retired)); qihse_auth_sealed_free(resurrection);
    after = capture(&ctx); image_equal(before, after); qihse_auth_image_free(after);

    OK(qihse_auth_maintenance_import(root, &before->position, request, &config,
          qihse_auth_sealed_data(sealed), sealed_length, &result));
    CHECK(result.generation == before->position.generation + 1);
    qihse_auth_position_t committed = result;
    after = capture(&ctx); position_equal(&after->position, &committed);
    CHECK(after->retry_count == before->retry_count + 1 && after->count == before->count);
    for (size_t i = 0; i < before->count; ++i) {
        CHECK(after->rows[i].user_id == before->rows[i].user_id);
        CHECK(after->rows[i].generation == before->rows[i].generation + 1);
        CHECK(after->rows[i].active == before->rows[i].active);
        if (after->rows[i].active) principal_equal(&before->rows[i].principal, &after->rows[i].principal);
    }
    CHECK(qihse_auth_get_user(104) == NULL);
    OK(qihse_auth_maintenance_import(root, &before->position, request, &config,
          qihse_auth_sealed_data(sealed), sealed_length, &result));
    position_equal(&result, &committed);
    qihse_auth_image_t *retry_image = capture(&ctx);
    image_equal(after, retry_image); qihse_auth_image_free(retry_image);
    qihse_auth_archive_config_t conflicting = config; conflicting.binding.archive_id[0] ^= 1;
    memset(&result, 0xaa, sizeof(result));
    CHECK(qihse_auth_maintenance_import(root, &before->position, request, &conflicting,
          qihse_auth_sealed_data(sealed), sealed_length, &result) == QIHSE_AUTH_MAINT_CONFLICT);
    CHECK(memcmp(&result, &zero, sizeof(result)) == 0);
    memset(&result, 0xaa, sizeof(result));
    CHECK(qihse_auth_maintenance_import(root, &before->position, request, &config,
          tampered, sealed_length, &result) == QIHSE_AUTH_MAINT_CONFLICT);
    CHECK(memcmp(&result, &zero, sizeof(result)) == 0);
    retry_image = capture(&ctx); image_equal(after, retry_image); qihse_auth_image_free(retry_image);
    denied(stale, before, &config, sealed);
    uint8_t fresh_request[16] = {0x92};
    CHECK(qihse_auth_maintenance_import(root, &before->position, fresh_request, &config,
          qihse_auth_sealed_data(sealed), sealed_length, &result) == QIHSE_AUTH_MAINT_CONFLICT);
    qihse_auth_sealed_t *empty_output = (void *)1;
    CHECK(qihse_auth_maintenance_export(root, &before->position, &config,
                                      &empty_output) == QIHSE_AUTH_MAINT_CONFLICT && empty_output == NULL);
    OPENSSL_cleanse(tampered, sealed_length); free(tampered);
    qihse_auth_image_free(before); qihse_auth_image_free(after); qihse_auth_sealed_free(sealed);
}

int main(void) {
    setup_keys();
    OK(qihse_auth_bootstrap_provision(paths[8], "archive-root", password, false, "", true));
    qihse_auth_startup_config_t startup = {0};
    startup.mode = QIHSE_AUTH_AUTHORITY_STANDALONE; startup.action = QIHSE_AUTH_START_PROVISION;
    startup.state_directory = paths[9]; startup.bootstrap_file = paths[8];
    startup.archive_keys = startup.transfer_keys = keys;
    memset(startup.authority_id, 0x31, 16); memset(startup.node, 0x42, 16); startup.epoch = 7;
    qihse_auth_recovery_t *recovery = NULL;
    OK(qihse_auth_maintenance_start(&startup, &recovery)); CHECK(recovery);
    qihse_user_t *root = qihse_auth_authenticate("archive-root", password); CHECK(root);
    qihse_auth_image_context_t ctx = {root, NULL};
    qihse_auth_image_t *im = synthetic_image();
    qihse_auth_lifecycle_enter();
    CHECK(qihse_auth_image_context_valid(&ctx));
    codec_tests(&ctx, im); crypto_tests(&ctx, im, root);
    qihse_auth_image_t *out = (void *)1;
    CHECK(qihse_auth_image_capture(NULL, &out) == QIHSE_AUTH_MAINT_DENIED && out == NULL);
    qihse_auth_image_context_t ambiguous = {root, recovery};
    CHECK(!qihse_auth_image_context_valid(&ambiguous));
    qihse_auth_lifecycle_leave(); qihse_auth_image_free(im);
    maintenance_tests(root);
    qihse_auth_maintenance_recovery_release(recovery);
    qihse_auth_image_context_t released = {NULL, recovery};
    qihse_auth_lifecycle_enter(); out = (void *)1;
    CHECK(qihse_auth_image_capture(&released, &out) == QIHSE_AUTH_MAINT_DENIED && out == NULL);
    qihse_auth_lifecycle_leave();
    qihse_audit_shutdown();
    const char *audit_files[] = {"qihse_audit.log", "qihse_integrity.chain", "qihse_audit.writer.lock"};
    char audit_path[300];
    for (size_t i = 0; i < sizeof(audit_files)/sizeof(audit_files[0]); ++i) {
        CHECK(snprintf(audit_path, sizeof(audit_path), "%s/%s", directory, audit_files[i]) > 0);
        CHECK(unlink(audit_path) == 0);
    }
    for (size_t i = 0; i < 9; ++i) CHECK(unlink(paths[i]) == 0);
    char state_file[300];
    CHECK(snprintf(state_file, sizeof(state_file), "%s/authority.state", paths[9]) > 0);
    CHECK(unlink(state_file) == 0);
    CHECK(snprintf(state_file, sizeof(state_file), "%s/authority.lock", paths[9]) > 0);
    CHECK(unlink(state_file) == 0 && rmdir(paths[9]) == 0 && rmdir(directory) == 0);
    puts("auth archive: codec, real PQ crypto, authorization and atomic maintenance passed");
    return 0;
}
