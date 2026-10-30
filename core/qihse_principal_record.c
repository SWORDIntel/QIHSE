#include "qihse_principal_record.h"
#include <openssl/crypto.h>
#include <limits.h>
#include <string.h>

#define RECORD_MAGIC "QPR1"

typedef struct {
    uint8_t* data;
    size_t length;
    size_t position;
    bool valid;
} writer_t;

typedef struct {
    const uint8_t* data;
    size_t length;
    size_t position;
    bool valid;
} reader_t;

static void put_bytes(writer_t* w, const void* source, size_t length) {
    if (!w->valid || length > w->length - w->position) {
        w->valid = false;
        return;
    }
    memcpy(w->data + w->position, source, length);
    w->position += length;
}

static void put_u8(writer_t* w, uint8_t value) { put_bytes(w, &value, 1u); }

static void put_u16(writer_t* w, uint16_t value) {
    put_u8(w, (uint8_t)value);
    put_u8(w, (uint8_t)(value >> 8));
}

static void put_u32(writer_t* w, uint32_t value) {
    for (unsigned int i = 0; i < 4u; i++) put_u8(w, (uint8_t)(value >> (i * 8u)));
}

static void put_u64(writer_t* w, uint64_t value) {
    for (unsigned int i = 0; i < 8u; i++) put_u8(w, (uint8_t)(value >> (i * 8u)));
}

static void get_bytes(reader_t* r, void* destination, size_t length) {
    if (!r->valid || length > r->length - r->position) {
        r->valid = false;
        return;
    }
    memcpy(destination, r->data + r->position, length);
    r->position += length;
}

static uint8_t get_u8(reader_t* r) {
    uint8_t value = 0;
    get_bytes(r, &value, 1u);
    return value;
}

static uint16_t get_u16(reader_t* r) {
    uint16_t value = 0;
    for (unsigned int i = 0; i < 2u; i++) value |= (uint16_t)get_u8(r) << (i * 8u);
    return value;
}

static uint32_t get_u32(reader_t* r) {
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4u; i++) value |= (uint32_t)get_u8(r) << (i * 8u);
    return value;
}

static uint64_t get_u64(reader_t* r) {
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8u; i++) value |= (uint64_t)get_u8(r) << (i * 8u);
    return value;
}

static bool bounded_string(const char* value, size_t size, bool nonempty,
                           bool require_zero_padding) {
    const char* end = memchr(value, 0, size);
    if (!end || (nonempty && end == value)) return false;
    size_t used = (size_t)(end - value) + 1u;
    if (require_zero_padding) {
        for (size_t i = used; i < size; i++) {
            if (value[i] != 0) return false;
        }
    }
    return true;
}

bool qihse_principal_fields_valid(const qihse_user_t* user, bool allow_root) {
    if (!user || user->user_id >= 65536u ||
        (user->user_id == 0u && (!allow_root ||
         user->role != QIHSE_ROLE_OPERATOR ||
         user->tenant_id != QIHSE_TENANT_SYSTEM ||
         user->classification_level != UINT16_MAX ||
         user->sci_compartments != UINT16_MAX)) ||
        user->tenant_id == QIHSE_TENANT_INVALID ||
        user->role > QIHSE_ROLE_GUEST ||
        !bounded_string(user->username, sizeof(user->username), true, false) ||
        !bounded_string(user->fido2_credential_id,
                        sizeof(user->fido2_credential_id), false, false) ||
        user->object_acl_count > QIHSE_OBJECT_ACL_MAX_ENTRIES ||
        !user->password_set ||
        user->verifier.version != QIHSE_PW_VERIFIER_VERSION_1 ||
        user->verifier.algorithm != QIHSE_PW_ALG_PBKDF2_HMAC_SHA384 ||
        user->verifier.iterations < QIHSE_PW_MIN_ITERATIONS ||
        user->verifier.iterations > (uint32_t)INT_MAX ||
        /* Physical token presence is session state, never a durable grant. */
        user->hardware_token_present) {
        return false;
    }
    if (user->role == QIHSE_ROLE_OPERATOR &&
        (user->classification_level != UINT16_MAX ||
         user->sci_compartments != UINT16_MAX)) return false;
    for (uint8_t i = 0; i < user->object_acl_count; i++) {
        const qihse_acl_entry_t* acl = &user->object_acl[i];
        if (acl->access_flags == 0u ||
            (acl->access_flags & ~(QIHSE_ACL_READ | QIHSE_ACL_WRITE |
                                   QIHSE_ACL_ADMIN)) != 0u) return false;
        for (uint8_t j = 0; j < i; j++) {
            if (user->object_acl[j].namespace_id == acl->namespace_id &&
                user->object_acl[j].resource_id == acl->resource_id) return false;
        }
    }
    return true;
}

static bool valid_put(const qihse_principal_record_t* record) {
    return record->target_id != 0u &&
           record->principal.user_id == record->target_id &&
           qihse_principal_fields_valid(&record->principal, false);
}

static bool valid_record(const qihse_principal_record_t* record) {
    if (!record || record->target_id == 0u ||
        record->target_id >= 65536u || record->actor_id >= 65536u ||
        record->principal_generation == 0u ||
        record->actor_generation == 0u) return false;
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof(record->request_id); i++)
        nonzero |= record->request_id[i];
    if (nonzero == 0u) return false;
    return record->kind == QIHSE_PRINCIPAL_DELETE ||
           (record->kind == QIHSE_PRINCIPAL_PUT && valid_put(record));
}

bool qihse_principal_record_encode(const qihse_principal_record_t* record,
                                   uint8_t* out, size_t out_cap,
                                   size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!out || !out_len || !valid_record(record)) return false;
    writer_t w = {out, out_cap < QIHSE_PRINCIPAL_RECORD_MAX_BYTES ?
                      out_cap : QIHSE_PRINCIPAL_RECORD_MAX_BYTES, 0u, true};
    put_bytes(&w, RECORD_MAGIC, 4u);
    put_u16(&w, QIHSE_PRINCIPAL_RECORD_VERSION);
    put_u8(&w, (uint8_t)record->kind);
    put_u8(&w, 0u);
    put_bytes(&w, record->request_id, sizeof(record->request_id));
    put_u64(&w, record->expected_registry_generation);
    put_u32(&w, record->actor_id);
    put_u64(&w, record->actor_generation);
    put_u64(&w, record->principal_generation);
    put_u32(&w, record->target_id);
    if (record->kind == QIHSE_PRINCIPAL_PUT) {
        const qihse_user_t* user = &record->principal;
        put_u32(&w, user->tenant_id);
        put_u16(&w, user->role);
        put_u16(&w, user->classification_level);
        put_u16(&w, user->sci_compartments);
        put_u8(&w, user->can_create_users ? 1u : 0u);
        put_u8(&w, user->requires_hardware_token ? 1u : 0u);
        put_u8(&w, user->hardware_token_present ? 1u : 0u);
        char padded[sizeof(user->username)] = {0};
        size_t name_len = strlen(user->username);
        memcpy(padded, user->username, name_len);
        put_bytes(&w, padded, sizeof(padded));
        memset(padded, 0, sizeof(padded));
        size_t credential_len = strlen(user->fido2_credential_id);
        memcpy(padded, user->fido2_credential_id, credential_len);
        put_bytes(&w, padded, sizeof(padded));
        put_u16(&w, user->verifier.version);
        put_u16(&w, user->verifier.algorithm);
        put_u32(&w, user->verifier.iterations);
        put_bytes(&w, user->verifier.salt, sizeof(user->verifier.salt));
        put_bytes(&w, user->verifier.verifier, sizeof(user->verifier.verifier));
        put_u8(&w, user->object_acl_count);
        for (uint8_t i = 0; i < user->object_acl_count; i++) {
            put_u32(&w, user->object_acl[i].namespace_id);
            put_u64(&w, user->object_acl[i].resource_id);
            put_u8(&w, user->object_acl[i].access_flags);
        }
    }
    if (!w.valid) {
        OPENSSL_cleanse(out, w.length);
        return false;
    }
    *out_len = w.position;
    return true;
}

bool qihse_principal_record_decode(const uint8_t* data, size_t data_len,
                                   qihse_principal_record_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!data || data_len > QIHSE_PRINCIPAL_RECORD_MAX_BYTES) return false;
    reader_t r = {data, data_len, 0u, true};
    uint8_t magic[4];
    get_bytes(&r, magic, sizeof(magic));
    uint16_t version = get_u16(&r);
    out->kind = (qihse_principal_record_kind_t)get_u8(&r);
    uint8_t reserved = get_u8(&r);
    get_bytes(&r, out->request_id, sizeof(out->request_id));
    out->expected_registry_generation = get_u64(&r);
    out->actor_id = get_u32(&r);
    out->actor_generation = get_u64(&r);
    out->principal_generation = get_u64(&r);
    out->target_id = get_u32(&r);
    if (out->kind == QIHSE_PRINCIPAL_PUT) {
        qihse_user_t* user = &out->principal;
        user->user_id = out->target_id;
        user->tenant_id = get_u32(&r);
        user->role = get_u16(&r);
        user->classification_level = get_u16(&r);
        user->sci_compartments = get_u16(&r);
        uint8_t delegated = get_u8(&r);
        uint8_t token_required = get_u8(&r);
        uint8_t token_present = get_u8(&r);
        user->can_create_users = delegated == 1u;
        user->requires_hardware_token = token_required == 1u;
        user->hardware_token_present = token_present == 1u;
        get_bytes(&r, user->username, sizeof(user->username));
        get_bytes(&r, user->fido2_credential_id,
                  sizeof(user->fido2_credential_id));
        user->verifier.version = get_u16(&r);
        user->verifier.algorithm = get_u16(&r);
        user->verifier.iterations = get_u32(&r);
        get_bytes(&r, user->verifier.salt, sizeof(user->verifier.salt));
        get_bytes(&r, user->verifier.verifier, sizeof(user->verifier.verifier));
        user->object_acl_count = get_u8(&r);
        if (user->object_acl_count > QIHSE_OBJECT_ACL_MAX_ENTRIES)
            r.valid = false;
        for (uint8_t i = 0; r.valid && i < user->object_acl_count; i++) {
            user->object_acl[i].namespace_id = get_u32(&r);
            user->object_acl[i].resource_id = get_u64(&r);
            user->object_acl[i].access_flags = get_u8(&r);
        }
        user->password_set = true;
        if (delegated > 1u || token_required > 1u || token_present > 1u)
            r.valid = false;
    }
    if (!r.valid || r.position != data_len ||
        memcmp(magic, RECORD_MAGIC, sizeof(magic)) != 0 ||
        version != QIHSE_PRINCIPAL_RECORD_VERSION || reserved != 0u ||
        !valid_record(out) ||
        (out->kind == QIHSE_PRINCIPAL_PUT &&
         (!bounded_string(out->principal.username,
                          sizeof(out->principal.username), true, true) ||
          !bounded_string(out->principal.fido2_credential_id,
                          sizeof(out->principal.fido2_credential_id), false,
                          true)))) {
        OPENSSL_cleanse(out, sizeof(*out));
        return false;
    }
    return true;
}

bool qihse_principal_record_authorize_transition(
    const qihse_principal_record_t* record,
    uint64_t registry_generation,
    const qihse_user_t* actor, uint64_t actor_generation,
    const qihse_user_t* target, uint64_t target_generation) {
    if (!valid_record(record) || !actor ||
        actor->role > QIHSE_ROLE_GUEST ||
        actor->tenant_id == QIHSE_TENANT_INVALID ||
        record->expected_registry_generation != registry_generation ||
        registry_generation == UINT64_MAX ||
        record->actor_id != actor->user_id ||
        record->actor_generation != actor_generation ||
        actor_generation == 0u ||
        (target && target->user_id != record->target_id) ||
        (target && target_generation == 0u) ||
        (!target && target_generation != 0u) ||
        target_generation == UINT64_MAX ||
        record->principal_generation != target_generation + 1u) return false;

    /* An actor that was revoked between proposal and ordered apply is not
     * supplied by the registry service. A stale actor generation also fails
     * above. Delegation permits creation, never modification or deletion. */
    if (record->kind == QIHSE_PRINCIPAL_DELETE) {
        if (!target || actor->role != QIHSE_ROLE_OPERATOR) return false;
        return actor->tenant_id == QIHSE_TENANT_SYSTEM ||
               (actor->tenant_id == target->tenant_id &&
                target->tenant_id != QIHSE_TENANT_SYSTEM);
    }

    const qihse_user_t* proposed = &record->principal;
    if (target) {
        if (actor->role != QIHSE_ROLE_OPERATOR ||
            target->role != proposed->role ||
            target->tenant_id != proposed->tenant_id) return false;
        if (actor->tenant_id != QIHSE_TENANT_SYSTEM &&
            (target->tenant_id != actor->tenant_id ||
             target->tenant_id == QIHSE_TENANT_SYSTEM)) return false;
    } else {
        if (actor->role != QIHSE_ROLE_OPERATOR &&
            !actor->can_create_users) return false;
        if (actor->tenant_id != QIHSE_TENANT_SYSTEM &&
            proposed->tenant_id != actor->tenant_id) return false;
        if (actor->role != QIHSE_ROLE_OPERATOR &&
            (proposed->role != QIHSE_ROLE_GUEST ||
             proposed->classification_level != 0u ||
             proposed->sci_compartments != 0u ||
             proposed->can_create_users ||
             proposed->object_acl_count != 0u)) return false;
    }

    /* These bounds apply again at ordered apply, after all prior committed
     * mutations. can_create_users does not elevate an actor's own authority. */
    if (proposed->role < actor->role ||
        proposed->classification_level > actor->classification_level ||
        (proposed->sci_compartments & actor->sci_compartments) !=
            proposed->sci_compartments ||
        (proposed->can_create_users &&
         actor->role != QIHSE_ROLE_OPERATOR && !actor->can_create_users) ||
        (actor->requires_hardware_token &&
         !proposed->requires_hardware_token)) return false;
    return true;
}
