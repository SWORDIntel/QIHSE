#include "qihse_auth_archive_crypto.h"
#include "qihse_principal_record.h"
#include <limits.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

#define IMAGE_VERSION 1u
#define IMAGE_MIN_BYTES 141u
#define IMAGE_ROW_MIN_BYTES 25u
#define IMAGE_RETRY_BYTES 124u

typedef struct {
    uint8_t *data;
    size_t capacity, used;
    bool good;
} image_writer_t;

typedef struct {
    const uint8_t *data;
    size_t length, used;
    bool good;
} image_reader_t;

static void write_bytes(image_writer_t *w, const void *data, size_t length) {
    if (!w->good || length > w->capacity - w->used) { w->good = false; return; }
    if (w->data && length) memcpy(w->data + w->used, data, length);
    w->used += length;
}

static void write_number(image_writer_t *w, uint64_t value, size_t width) {
    uint8_t bytes[8];
    for (size_t i = 0; i < width; ++i) {
        bytes[width - 1u - i] = (uint8_t)value;
        value >>= 8;
    }
    write_bytes(w, bytes, width);
}

static void read_bytes(image_reader_t *r, void *data, size_t length) {
    if (!r->good || length > r->length - r->used) { r->good = false; return; }
    if (length) memcpy(data, r->data + r->used, length);
    r->used += length;
}

static uint64_t read_number(image_reader_t *r, size_t width) {
    uint8_t bytes[8] = {0};
    uint64_t value = 0;
    read_bytes(r, bytes, width);
    for (size_t i = 0; i < width; ++i) value = (value << 8) | bytes[i];
    return value;
}

static bool bytes_nonzero(const uint8_t *p, size_t size) {
    uint8_t bits = 0;
    for (size_t i = 0; i < size; ++i) bits |= p[i];
    return bits != 0;
}

static bool position_valid(const qihse_auth_position_t *p) {
    return bytes_nonzero(p->history, 16u) && bytes_nonzero(p->node, 16u) && p->epoch;
}

static bool position_equal(const qihse_auth_position_t *a, const qihse_auth_position_t *b) {
    return !memcmp(a->history, b->history, 16u) && !memcmp(a->node, b->node, 16u) &&
           a->epoch == b->epoch && a->generation == b->generation;
}

static void write_position(image_writer_t *w, const qihse_auth_position_t *p) {
    write_bytes(w, p->history, 16u);
    write_bytes(w, p->node, 16u);
    write_number(w, p->epoch, 8u);
    write_number(w, p->generation, 8u);
}

static void read_position(image_reader_t *r, qihse_auth_position_t *p) {
    read_bytes(r, p->history, 16u);
    read_bytes(r, p->node, 16u);
    p->epoch = read_number(r, 8u);
    p->generation = read_number(r, 8u);
}

static void write_string(image_writer_t *w, const char value[64]) {
    uint8_t padded[64] = {0};
    const char *end = memchr(value, 0, 64u);
    if (!end) { w->good = false; return; }
    memcpy(padded, value, (size_t)(end - value));
    write_bytes(w, padded, sizeof(padded));
}

static void read_string(image_reader_t *r, char value[64]) {
    read_bytes(r, value, 64u);
    const char *end = memchr(value, 0, 64u);
    if (!end) { r->good = false; return; }
    for (size_t i = (size_t)(end - value) + 1u; i < 64u; ++i)
        if (value[i]) r->good = false;
}

static void write_principal(image_writer_t *w, const qihse_user_t *p) {
    write_number(w, p->user_id, 4u);
    write_number(w, p->tenant_id, 4u);
    write_number(w, p->role, 2u);
    write_number(w, p->classification_level, 2u);
    write_number(w, p->sci_compartments, 2u);
    write_number(w, (p->can_create_users ? 1u : 0u) |
                    (p->requires_hardware_token ? 2u : 0u), 1u);
    write_string(w, p->username);
    write_string(w, p->fido2_credential_id);
    write_number(w, p->verifier.version, 2u);
    write_number(w, p->verifier.algorithm, 2u);
    write_number(w, p->verifier.iterations, 4u);
    write_bytes(w, p->verifier.salt, sizeof(p->verifier.salt));
    write_bytes(w, p->verifier.verifier, sizeof(p->verifier.verifier));
    write_number(w, p->object_acl_count, 1u);
    for (uint8_t i = 0; i < p->object_acl_count; ++i) {
        write_number(w, p->object_acl[i].namespace_id, 4u);
        write_number(w, p->object_acl[i].resource_id, 8u);
        write_number(w, p->object_acl[i].access_flags, 1u);
    }
}

static void read_principal(image_reader_t *r, qihse_user_t *p, bool root) {
    p->user_id = (uint32_t)read_number(r, 4u);
    p->tenant_id = (uint32_t)read_number(r, 4u);
    p->role = (uint16_t)read_number(r, 2u);
    p->classification_level = (uint16_t)read_number(r, 2u);
    p->sci_compartments = (uint16_t)read_number(r, 2u);
    uint8_t flags = (uint8_t)read_number(r, 1u);
    if (flags & ~3u) r->good = false;
    p->can_create_users = (flags & 1u) != 0;
    p->requires_hardware_token = (flags & 2u) != 0;
    p->hardware_token_present = false;
    p->password_set = true;
    read_string(r, p->username);
    read_string(r, p->fido2_credential_id);
    p->verifier.version = (uint16_t)read_number(r, 2u);
    p->verifier.algorithm = (uint16_t)read_number(r, 2u);
    p->verifier.iterations = (uint32_t)read_number(r, 4u);
    read_bytes(r, p->verifier.salt, sizeof(p->verifier.salt));
    read_bytes(r, p->verifier.verifier, sizeof(p->verifier.verifier));
    p->object_acl_count = (uint8_t)read_number(r, 1u);
    if (p->object_acl_count > QIHSE_OBJECT_ACL_MAX_ENTRIES) { r->good = false; return; }
    for (uint8_t i = 0; i < p->object_acl_count; ++i) {
        p->object_acl[i].namespace_id = (uint32_t)read_number(r, 4u);
        p->object_acl[i].resource_id = read_number(r, 8u);
        p->object_acl[i].access_flags = (uint8_t)read_number(r, 1u);
    }
    if (!qihse_principal_fields_valid(p, root)) r->good = false;
}

static int row_id_compare(const void *a, const void *b) {
    const qihse_auth_image_row_t *x = *(const qihse_auth_image_row_t * const *)a;
    const qihse_auth_image_row_t *y = *(const qihse_auth_image_row_t * const *)b;
    return (x->user_id > y->user_id) - (x->user_id < y->user_id);
}

static int row_name_compare(const void *a, const void *b) {
    const qihse_auth_image_row_t *x = *(const qihse_auth_image_row_t * const *)a;
    const qihse_auth_image_row_t *y = *(const qihse_auth_image_row_t * const *)b;
    if (x->active != y->active) return x->active ? -1 : 1;
    return x->active ? strcmp(x->principal.username, y->principal.username) : 0;
}

/* Validate actual principal fields, never manufacture a log record with fake
 * actor/request provenance merely to borrow the QPR1 decoder. */
static qihse_auth_maintenance_status_t image_validate(const qihse_auth_image_t *image,
    bool local, const qihse_auth_image_row_t ***ordered) {
    const qihse_auth_image_row_t **rows = NULL;
    if (ordered) *ordered = NULL;
    if (!image || !ordered || !position_valid(&image->position) || !image->root_generation ||
        image->count > QIHSE_AUTH_IMAGE_MAX_PRINCIPALS ||
        image->retry_count > QIHSE_AUTH_RETRY_MAX || (image->count && !image->rows) ||
        (!local && image->has_local_root) ||
        (local && (!image->has_local_root || image->local_root.user_id != 0u ||
                   !qihse_principal_fields_valid(&image->local_root, true))) ||
        image->root_lockout_until > INT64_MAX) return QIHSE_AUTH_MAINT_INVALID;
    if (image->count) {
        rows = malloc(image->count * sizeof(*rows));
        if (!rows) return QIHSE_AUTH_MAINT_LIMIT;
    }
    for (size_t i = 0; i < image->count; ++i) {
        const qihse_auth_image_row_t *row = &image->rows[i];
        if (!row->user_id || row->user_id > QIHSE_AUTH_IMAGE_MAX_PRINCIPALS ||
            !row->generation || row->lockout_until > INT64_MAX ||
            (row->active && (row->principal.user_id != row->user_id ||
                             !qihse_principal_fields_valid(&row->principal, false)))) goto invalid;
        rows[i] = row;
    }
    if (image->count) {
        qsort(rows, image->count, sizeof(*rows), row_name_compare);
        for (size_t i = 1; i < image->count; ++i)
            if (rows[i - 1u]->active && rows[i]->active &&
                !strcmp(rows[i - 1u]->principal.username, rows[i]->principal.username)) goto invalid;
        if (local) for (size_t i = 0; i < image->count; ++i)
            if (rows[i]->active && !strcmp(rows[i]->principal.username, image->local_root.username)) goto invalid;
        qsort(rows, image->count, sizeof(*rows), row_id_compare);
        for (size_t i = 1; i < image->count; ++i)
            if (rows[i - 1u]->user_id == rows[i]->user_id) goto invalid;
    }
    for (size_t i = 0; i < image->retry_count; ++i) {
        const qihse_auth_retry_t *retry = &image->retries[i];
        if (!bytes_nonzero(retry->request_id, 16u) || !bytes_nonzero(retry->digest, 48u) ||
            (retry->actor_id == UINT32_MAX ? retry->actor_generation != 0u :
             (retry->actor_id > QIHSE_AUTH_IMAGE_MAX_PRINCIPALS || !retry->actor_generation)) ||
            !position_valid(&retry->result) ||
            memcmp(retry->result.history, image->position.history, 16u) ||
            memcmp(retry->result.node, image->position.node, 16u) ||
            retry->result.epoch != image->position.epoch ||
            retry->result.generation > image->position.generation) goto invalid;
        for (size_t j = 0; j < i; ++j)
            if (!memcmp(image->retries[j].request_id, retry->request_id, 16u)) goto invalid;
    }
    *ordered = rows;
    return QIHSE_AUTH_MAINT_OK;
invalid:
    free(rows);
    return QIHSE_AUTH_MAINT_INVALID;
}

static void image_write(image_writer_t *w, const qihse_auth_image_t *image,
                         const qihse_auth_image_row_t * const *rows, bool local) {
    static const uint8_t zero_binding[48] = {0};
    write_bytes(w, "QAIMAGE1", 8u);
    write_number(w, IMAGE_VERSION, 4u);
    write_number(w, local ? QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE : QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER, 4u);
    write_position(w, &image->position);
    write_bytes(w, local ? image->bootstrap_binding : zero_binding, 48u);
    write_number(w, image->root_generation, 8u);
    write_number(w, image->root_failed_count, 4u);
    write_number(w, image->root_lockout_until, 8u);
    write_number(w, image->count, 4u);
    write_number(w, image->retry_count, 4u);
    write_number(w, local ? 1u : 0u, 1u);
    if (local) write_principal(w, &image->local_root);
    for (size_t i = 0; i < image->count; ++i) {
        const qihse_auth_image_row_t *row = rows[i];
        write_number(w, row->user_id, 4u);
        write_number(w, row->active ? 1u : 0u, 1u);
        write_number(w, row->generation, 8u);
        write_number(w, row->failed_count, 4u);
        write_number(w, row->lockout_until, 8u);
        if (row->active) write_principal(w, &row->principal);
    }
    for (size_t i = 0; i < image->retry_count; ++i) {
        const qihse_auth_retry_t *retry = &image->retries[i];
        write_bytes(w, retry->request_id, 16u);
        write_bytes(w, retry->digest, 48u);
        write_number(w, retry->actor_id, 4u);
        write_number(w, retry->actor_generation, 8u);
        write_position(w, &retry->result);
    }
}

static qihse_auth_maintenance_status_t image_encode_purpose(
    const qihse_auth_image_context_t *context, const qihse_auth_image_t *image,
    bool local, uint8_t **out, size_t *length) {
    const qihse_auth_image_row_t **rows = NULL;
    uint8_t *bytes = NULL;
    if (out) *out = NULL;
    if (length) *length = 0;
    if (!out || !length) return QIHSE_AUTH_MAINT_INVALID;
    if (!qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
    qihse_auth_maintenance_status_t status = image_validate(image, local, &rows);
    if (status != QIHSE_AUTH_MAINT_OK) return status;
    image_writer_t w = {NULL, QIHSE_AUTH_ARCHIVE_MAX_BYTES, 0, true};
    image_write(&w, image, rows, local);
    if (!w.good) { status = QIHSE_AUTH_MAINT_LIMIT; goto done; }
    bytes = malloc(w.used);
    if (!bytes) { status = QIHSE_AUTH_MAINT_LIMIT; goto done; }
    w.data = bytes;
    w.capacity = w.used;
    w.used = 0;
    image_write(&w, image, rows, local);
    if (!w.good || w.used != w.capacity) { status = QIHSE_AUTH_MAINT_INVALID; goto done; }
    *out = bytes;
    *length = w.used;
    bytes = NULL;
done:
    if (bytes) { OPENSSL_cleanse(bytes, w.capacity); free(bytes); }
    free(rows);
    return status;
}

static qihse_auth_maintenance_status_t image_decode_purpose(
    const qihse_auth_image_context_t *context, const uint8_t *data, size_t length,
    bool local, qihse_auth_image_t **out) {
    qihse_auth_image_t *image = NULL;
    const qihse_auth_image_row_t **ordered = NULL;
    qihse_auth_maintenance_status_t status = QIHSE_AUTH_MAINT_CORRUPT;
    uint8_t magic[8] = {0};
    if (out) *out = NULL;
    if (!data || !out) return QIHSE_AUTH_MAINT_INVALID;
    if (!qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
    if (length < IMAGE_MIN_BYTES || length > QIHSE_AUTH_ARCHIVE_MAX_BYTES) return QIHSE_AUTH_MAINT_CORRUPT;
    image = calloc(1u, sizeof(*image));
    if (!image) return QIHSE_AUTH_MAINT_LIMIT;
    image_reader_t r = {data, length, 0, true};
    read_bytes(&r, magic, sizeof(magic));
    if (memcmp(magic, "QAIMAGE1", sizeof(magic)) || read_number(&r, 4u) != IMAGE_VERSION ||
        read_number(&r, 4u) != (local ? QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE : QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER)) goto done;
    read_position(&r, &image->position);
    read_bytes(&r, image->bootstrap_binding, 48u);
    image->root_generation = read_number(&r, 8u);
    image->root_failed_count = (uint32_t)read_number(&r, 4u);
    image->root_lockout_until = read_number(&r, 8u);
    image->count = (size_t)read_number(&r, 4u);
    image->retry_count = (size_t)read_number(&r, 4u);
    uint8_t has_root = (uint8_t)read_number(&r, 1u);
    if (!r.good || has_root != (local ? 1u : 0u) ||
        (!local && bytes_nonzero(image->bootstrap_binding, 48u)) ||
        image->count > QIHSE_AUTH_IMAGE_MAX_PRINCIPALS || image->retry_count > QIHSE_AUTH_RETRY_MAX ||
        image->count > (length - r.used) / IMAGE_ROW_MIN_BYTES ||
        image->retry_count > (length - r.used) / IMAGE_RETRY_BYTES) goto done;
    image->has_local_root = local;
    if (local) read_principal(&r, &image->local_root, true);
    if (image->count) {
        image->rows = calloc(image->count, sizeof(*image->rows));
        if (!image->rows) { status = QIHSE_AUTH_MAINT_LIMIT; goto done; }
    }
    for (size_t i = 0; i < image->count; ++i) {
        qihse_auth_image_row_t *row = &image->rows[i];
        row->user_id = (uint32_t)read_number(&r, 4u);
        uint8_t active = (uint8_t)read_number(&r, 1u);
        if (active > 1u) r.good = false;
        row->active = active != 0;
        row->generation = read_number(&r, 8u);
        row->failed_count = (uint32_t)read_number(&r, 4u);
        row->lockout_until = read_number(&r, 8u);
        if (row->active) read_principal(&r, &row->principal, false);
        if (!r.good || (i && image->rows[i - 1u].user_id >= row->user_id)) goto done;
    }
    for (size_t i = 0; i < image->retry_count; ++i) {
        qihse_auth_retry_t *retry = &image->retries[i];
        read_bytes(&r, retry->request_id, 16u);
        read_bytes(&r, retry->digest, 48u);
        retry->actor_id = (uint32_t)read_number(&r, 4u);
        retry->actor_generation = read_number(&r, 8u);
        read_position(&r, &retry->result);
    }
    if (!r.good || r.used != length) goto done;
    status = image_validate(image, local, &ordered);
    if (status != QIHSE_AUTH_MAINT_OK) {
        if (status == QIHSE_AUTH_MAINT_INVALID) status = QIHSE_AUTH_MAINT_CORRUPT;
        goto done;
    }
    *out = image;
    image = NULL;
done:
    free(ordered);
    qihse_auth_image_free(image);
    return status;
}

qihse_auth_maintenance_status_t qihse_auth_image_encode(
    const qihse_auth_image_context_t *context, const qihse_auth_image_t *image,
    uint8_t **out, size_t *length) {
    return image_encode_purpose(context, image, false, out, length);
}

qihse_auth_maintenance_status_t qihse_auth_image_decode(
    const qihse_auth_image_context_t *context, const uint8_t *data, size_t length,
    qihse_auth_image_t **out) {
    return image_decode_purpose(context, data, length, false, out);
}

void qihse_auth_image_free(qihse_auth_image_t *image) {
    if (!image) return;
    if (image->rows) {
        OPENSSL_cleanse(image->rows, image->count * sizeof(*image->rows));
        free(image->rows);
    }
    OPENSSL_cleanse(image, sizeof(*image));
    free(image);
}

qihse_auth_maintenance_status_t qihse_auth_archive_seal(
    const qihse_auth_image_context_t *context, const qihse_auth_image_t *image,
    const qihse_auth_archive_config_t *config, qihse_auth_sealed_t **out) {
    uint8_t *plaintext = NULL;
    size_t length = 0;
    if (out) *out = NULL;
    if (!out || !config) return QIHSE_AUTH_MAINT_INVALID;
    if (!qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
    if (!image || !position_equal(&config->binding.source, &image->position)) return QIHSE_AUTH_MAINT_CONFLICT;
    if (config->binding.purpose != QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE &&
        config->binding.purpose != QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER) return QIHSE_AUTH_MAINT_INVALID;
    qihse_auth_maintenance_status_t status = image_encode_purpose(context, image,
        config->binding.purpose == QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE, &plaintext, &length);
    if (status == QIHSE_AUTH_MAINT_OK)
        status = qihse_auth_archive_encrypt(context, config, plaintext, length,
                                            image->count, image->retry_count, out);
    if (plaintext) { OPENSSL_cleanse(plaintext, length); free(plaintext); }
    return status;
}

qihse_auth_maintenance_status_t qihse_auth_archive_open(
    const qihse_auth_image_context_t *context, const uint8_t *sealed, size_t length,
    const qihse_auth_archive_config_t *config, qihse_auth_image_t **out) {
    uint8_t *plaintext = NULL;
    size_t plaintext_length = 0;
    uint64_t count = 0, retries = 0;
    qihse_auth_image_t *image = NULL;
    if (out) *out = NULL;
    if (!out || !config) return QIHSE_AUTH_MAINT_INVALID;
    if (!qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
    qihse_auth_maintenance_status_t status = qihse_auth_archive_decrypt(context, config,
        sealed, length, &plaintext, &plaintext_length, &count, &retries);
    if (status != QIHSE_AUTH_MAINT_OK) return status;
    status = image_decode_purpose(context, plaintext, plaintext_length,
        config->binding.purpose == QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE, &image);
    if (status == QIHSE_AUTH_MAINT_OK) {
        if (!position_equal(&config->binding.source, &image->position) ||
            image->count != count || image->retry_count != retries) status = QIHSE_AUTH_MAINT_CORRUPT;
        else { *out = image; image = NULL; }
    }
    qihse_auth_image_free(image);
    OPENSSL_clear_free(plaintext, plaintext_length);
    return status;
}
