#include "qihse_ingest_guard.h"

#include <stdio.h>
#include <string.h>

/* Telemetry record types (closed whitelist, SESSION_DELIVERY_UPGRADES.md U4).
 * Value schema: "<type>|<field>|<field>..." — positional, typed fields.
 *   build_record        hex16 build_hash | hex16 hw_hash | u64 duration_ms | enum{ok,fail}
 *   symbol_context      hex16 symbol_hash | u64 kind | u64 frequency
 *   census              u64 count | u64 window_ms
 *   survival_observation u64 session_ms | enum{0,1,2,3}
 *   burn_edge           hex16 src | hex16 dst | u64 weight
 * The first value field must repeat the record type from the key, so a
 * record cannot be relabeled after the fact. */

typedef enum {
    FIELD_HEX16 = 1,
    FIELD_U64,
    FIELD_U8_0_3,
    FIELD_ENUM_OK_FAIL
} field_kind_t;

typedef struct {
    const char* type;
    field_kind_t fields[4];
    size_t field_count;
} record_schema_t;

static const record_schema_t g_schemas[] = {
    { "build_record",         { FIELD_HEX16, FIELD_HEX16, FIELD_U64, FIELD_ENUM_OK_FAIL }, 4 },
    { "symbol_context",       { FIELD_HEX16, FIELD_U64, FIELD_U64 },                       3 },
    { "census",               { FIELD_U64, FIELD_U64 },                                    2 },
    { "survival_observation", { FIELD_U64, FIELD_U8_0_3 },                                 2 },
    { "burn_edge",            { FIELD_HEX16, FIELD_HEX16, FIELD_U64 },                     3 }
};

#define SCHEMA_COUNT (sizeof(g_schemas) / sizeof(g_schemas[0]))

static const record_schema_t* schema_for(const char* type, size_t len) {
    for (size_t i = 0; i < SCHEMA_COUNT; i++) {
        if (strlen(g_schemas[i].type) == len && memcmp(g_schemas[i].type, type, len) == 0) {
            return &g_schemas[i];
        }
    }
    return NULL;
}

static bool all_digits(const char* s, size_t len) {
    if (len == 0) return false;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
    return true;
}

static bool valid_u64(const char* s, size_t len) {
    if (!all_digits(s, len) || len > 20) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < len; i++) {
        uint64_t digit = (uint64_t)(s[i] - '0');
        if (value > (UINT64_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    return true;
}

static bool valid_hex(const char* s, size_t len, size_t exact) {
    if (len != exact) return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

static bool valid_u8_0_3(const char* s, size_t len) {
    return len == 1 && s[0] >= '0' && s[0] <= '3';
}

static bool valid_ok_fail(const char* s, size_t len) {
    return (len == 2 && memcmp(s, "ok", 2) == 0) || (len == 4 && memcmp(s, "fail", 4) == 0);
}

static bool valid_field(field_kind_t kind, const char* s, size_t len) {
    switch (kind) {
        case FIELD_HEX16: return valid_hex(s, len, 16);
        case FIELD_U64: return valid_u64(s, len);
        case FIELD_U8_0_3: return valid_u8_0_3(s, len);
        case FIELD_ENUM_OK_FAIL: return valid_ok_fail(s, len);
        default: return false;
    }
}

bool qihse_ingest_is_telemetry_key(const uint8_t* key, size_t key_len) {
    /* "t:" prefix + "tlm/" path segment anywhere after the tenant id. */
    if (key_len < 8 || key[0] != 't' || key[1] != ':') return false;
    for (size_t i = 2; i + 4u <= key_len; i++) {
        if (key[i] == '/' && key[i + 1u] == 't' && key[i + 2u] == 'l' &&
            key[i + 3u] == 'm' && key[i + 4u] == '/') {
            return true;
        }
    }
    return false;
}

static void set_err(char* err, size_t err_cap, const char* reason) {
    if (err && err_cap > 0) snprintf(err, err_cap, "%s", reason);
}

bool qihse_ingest_guard_validate(const uint8_t* key, size_t key_len,
                                 const uint8_t* value, size_t value_len,
                                 char* err, size_t err_cap) {
    if (err && err_cap > 0) err[0] = '\0';
    if (!key || key_len == 0 || !value || value_len == 0) {
        set_err(err, err_cap, "empty telemetry record");
        return false;
    }
    if (value_len > QIHSE_INGEST_MAX_VALUE) {
        set_err(err, err_cap, "telemetry record too large");
        return false;
    }
    /* Closed value charset: no spaces, no quotes, no separators that could
     * carry free text or injection — only the schema alphabet survives. */
    for (size_t i = 0; i < value_len; i++) {
        uint8_t c = value[i];
        bool allowed = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                       (c >= 'A' && c <= 'Z') || c == '|' || c == '_' || c == '.';
        if (!allowed) {
            set_err(err, err_cap, "telemetry value contains characters outside the closed schema alphabet");
            return false;
        }
    }

    /* Extract the record type from the key: "t:<tid>/tlm/<type>/<label>". */
    const char* tlm = memmem(key, key_len, "/tlm/", 5);
    if (!tlm) {
        set_err(err, err_cap, "malformed telemetry key");
        return false;
    }
    const char* type_start = tlm + 5;
    size_t type_avail = key_len - (size_t)(type_start - (const char*)key);
    const char* slash = memchr(type_start, '/', type_avail);
    size_t type_len = slash ? (size_t)(slash - type_start) : type_avail;
    const record_schema_t* schema = schema_for(type_start, type_len);
    if (!schema) {
        set_err(err, err_cap, "telemetry record type is not whitelisted");
        return false;
    }

    /* Split the value on '|' and validate positionally. */
    const char* fields[8];
    size_t lens[8];
    size_t field_count = 0;
    const char* p = (const char*)value;
    size_t remaining = value_len;
    while (field_count < 8) {
        const char* pipe = memchr(p, '|', remaining);
        if (pipe) {
            fields[field_count] = p;
            lens[field_count] = (size_t)(pipe - p);
            remaining -= (size_t)(pipe - p) + 1u;
            p = pipe + 1;
            field_count++;
        } else {
            fields[field_count] = p;
            lens[field_count] = remaining;
            field_count++;
            break;
        }
    }
    if (memchr(p, '|', remaining) != NULL || field_count >= 8) {
        set_err(err, err_cap, "telemetry record has too many fields");
        return false;
    }
    if (field_count != schema->field_count + 1u) {
        set_err(err, err_cap, "telemetry record field count does not match the schema");
        return false;
    }
    if (!schema_for(fields[0], lens[0]) || schema_for(fields[0], lens[0]) != schema) {
        set_err(err, err_cap, "telemetry value type tag does not match the key");
        return false;
    }
    for (size_t i = 0; i < schema->field_count; i++) {
        if (!valid_field(schema->fields[i], fields[i + 1u], lens[i + 1u])) {
            set_err(err, err_cap, "telemetry field violates the closed schema for its record type");
            return false;
        }
    }
    return true;
}
