#include "qihse_codegraph_packed.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Versioned prototype frame:
 * magic[8], record_count:u32, frame_length:u64, reserved:u32,
 * records..., SHA256[32] over everything before the digest. All integers BE.
 * Record: key_tag:u8 (1=node digest, 2=edge digest, 3=literal),
 * key:[32 digest bytes | u16 length + bytes], classification:u16, sci:u16,
 * flags:u8, expiry:u64, sequence:u64, value_length:u32, value:bytes.
 * The tag is a two-entry fixed dictionary for the repeated "n:"/"e:" key
 * prefixes. Values are opaque: preserving labels, evidence and unknown JSON
 * bytes takes priority over parsing them inside this format experiment. */
static const unsigned char magic[8] = {'Q', 'C', 'G', 'P', '0', '0', '0', '1'};
enum { HEADER_SIZE = 24, TRAILER_SIZE = 32, RECORD_FIXED = 26,
       KEY_NODE = 1, KEY_EDGE = 2, KEY_LITERAL = 3, TOMBSTONE = 1 };

static bool authorized(qihse_user_t *principal, uint16_t classification,
                       uint16_t sci) {
    return principal && qihse_auth_user_is_active(principal) &&
           qihse_user_get_role(principal) == QIHSE_ROLE_OPERATOR &&
           qihse_auth_can_access(principal, classification, sci);
}
static uint16_t get16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t get32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t get64(const unsigned char *p) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}
static void put16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v;
}
static void put32(unsigned char *p, uint32_t v) {
    for (size_t i = 0; i < 4; i++) p[i] = (unsigned char)(v >> (24 - i * 8));
}
static void put64(unsigned char *p, uint64_t v) {
    for (size_t i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (56 - i * 8));
}
static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static unsigned char hex_char(unsigned char value) {
    return (unsigned char)(value < 10 ? '0' + value : 'a' + value - 10);
}
static uint8_t key_tag(const char *key, size_t length) {
    if (length != 66 || key[1] != ':' || (key[0] != 'n' && key[0] != 'e'))
        return KEY_LITERAL;
    for (size_t i = 2; i < 66; i++)
        if (hex_digit((unsigned char)key[i]) < 0) return KEY_LITERAL;
    return key[0] == 'n' ? KEY_NODE : KEY_EDGE;
}
static bool digest(const unsigned char *data, size_t length,
                   unsigned char out[TRAILER_SIZE]) {
    unsigned int n = 0;
    return EVP_Digest(data, length, out, &n, EVP_sha256(), NULL) == 1 &&
           n == TRAILER_SIZE;
}
static bool add_size(size_t *size, size_t amount) {
    if (amount > SIZE_MAX - *size || *size + amount > CG_PACKED_MAX_BYTES)
        return false;
    *size += amount;
    return true;
}
static bool valid_record(const cg_packed_record *record,
                         qihse_user_t *principal, size_t *key_len,
                         uint8_t *tag) {
    if (!record || !record->key || !authorized(principal,
            record->meta.classification, record->meta.sci_compartment) ||
        (record->meta.flags & (uint8_t)~TOMBSTONE) ||
        record->value_len > CG_PACKED_MAX_VALUE ||
        (record->value_len && !record->value) ||
        ((record->meta.flags & TOMBSTONE) &&
         (record->value_len || record->meta.expire_time_ms))) return false;
    if (!record->key_len || record->key_len > UINT16_MAX ||
        memchr(record->key, 0, record->key_len)) return false;
    *key_len = record->key_len;
    *tag = key_tag(record->key, *key_len);
    return true;
}
static bool all_authorized(const cg_packed_record *records, size_t count,
                           qihse_user_t *principal) {
    if (!authorized(principal, 0, 0)) return false;
    for (size_t i = 0; i < count; i++)
        if (!authorized(principal, records[i].meta.classification,
                        records[i].meta.sci_compartment)) return false;
    return true;
}

bool cg_packed_encode(const cg_packed_record *records, size_t count,
                      qihse_user_t *principal, unsigned char **out,
                      size_t *out_len) {
    if (!out || !out_len) return false;
    *out = NULL; *out_len = 0;
    if (!authorized(principal, 0, 0) || (count && !records) ||
        count > CG_PACKED_MAX_RECORDS || count > UINT32_MAX) return false;
    size_t size = HEADER_SIZE;
    for (size_t i = 0; i < count; i++) {
        size_t key_len = 0; uint8_t tag = 0;
        if (!valid_record(&records[i], principal, &key_len, &tag) ||
            !add_size(&size, RECORD_FIXED) ||
            !add_size(&size, tag == KEY_LITERAL ? 2 + key_len : 32) ||
            !add_size(&size, records[i].value_len)) return false;
    }
    if (!add_size(&size, TRAILER_SIZE)) return false;
    unsigned char *frame = malloc(size);
    if (!frame) return false;
    memcpy(frame, magic, sizeof(magic));
    put32(frame + 8, (uint32_t)count);
    put64(frame + 12, size);
    put32(frame + 20, 0);
    size_t offset = HEADER_SIZE;
    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        const cg_packed_record *r = &records[i];
        size_t key_len = 0; uint8_t tag = 0;
        if (!valid_record(r, principal, &key_len, &tag)) { ok = false; break; }
        frame[offset++] = tag;
        if (tag == KEY_LITERAL) {
            put16(frame + offset, (uint16_t)key_len); offset += 2;
            memcpy(frame + offset, r->key, key_len); offset += key_len;
        } else {
            for (size_t j = 0; j < 32; j++) {
                int high = hex_digit((unsigned char)r->key[2 + j * 2]);
                int low = hex_digit((unsigned char)r->key[3 + j * 2]);
                frame[offset++] = (unsigned char)((high << 4) | low);
            }
        }
        put16(frame + offset, r->meta.classification); offset += 2;
        put16(frame + offset, r->meta.sci_compartment); offset += 2;
        frame[offset++] = r->meta.flags;
        put64(frame + offset, r->meta.expire_time_ms); offset += 8;
        put64(frame + offset, r->meta.change_seq); offset += 8;
        put32(frame + offset, (uint32_t)r->value_len); offset += 4;
        if (r->value_len) {
            memcpy(frame + offset, r->value, r->value_len);
            offset += r->value_len;
        }
    }
    if (ok && offset == size - TRAILER_SIZE &&
        all_authorized(records, count, principal)) {
        ok = digest(frame, offset, frame + offset);
    } else ok = false;
    if (!ok) {
        OPENSSL_cleanse(frame, size); free(frame); return false;
    }
    *out = frame; *out_len = size;
    return true;
}

void cg_packed_records_free(cg_packed_record *records, size_t count) {
    if (!records) return;
    for (size_t i = 0; i < count; i++) {
        if (records[i].key) OPENSSL_cleanse(records[i].key, records[i].key_len);
        free(records[i].key);
        if (records[i].value) {
            OPENSSL_cleanse(records[i].value, records[i].value_len);
            free(records[i].value);
        }
    }
    free(records);
}

bool cg_packed_decode(const unsigned char *data, size_t length,
                      qihse_user_t *principal, cg_packed_record **out,
                      size_t *out_count) {
    if (!out || !out_count) return false;
    *out = NULL; *out_count = 0;
    if (!authorized(principal, 0, 0) || !data ||
        length < HEADER_SIZE + TRAILER_SIZE || length > CG_PACKED_MAX_BYTES ||
        memcmp(data, magic, sizeof(magic)) || get64(data + 12) != length ||
        get32(data + 20) != 0) return false;
    size_t count = get32(data + 8);
    if (count > CG_PACKED_MAX_RECORDS ||
        count > (length - HEADER_SIZE - TRAILER_SIZE) / (RECORD_FIXED + 3))
        return false;
    unsigned char hash[TRAILER_SIZE];
    if (!digest(data, length - TRAILER_SIZE, hash) ||
        memcmp(hash, data + length - TRAILER_SIZE, TRAILER_SIZE)) return false;
    cg_packed_record *records = calloc(count ? count : 1, sizeof(*records));
    if (!records) return false;
    size_t offset = HEADER_SIZE, end = length - TRAILER_SIZE;
    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        if (end - offset < 1) { ok = false; break; }
        uint8_t tag = data[offset++];
        size_t key_len;
        const unsigned char *key_bytes;
        if (tag == KEY_NODE || tag == KEY_EDGE) {
            if (end - offset < 32) { ok = false; break; }
            key_len = 66;
            key_bytes = data + offset; offset += 32;
        } else if (tag == KEY_LITERAL) {
            if (end - offset < 2) { ok = false; break; }
            key_len = get16(data + offset); offset += 2;
            if (!key_len || end - offset < key_len) { ok = false; break; }
            key_bytes = data + offset; offset += key_len;
        } else { ok = false; break; }
        if (end - offset < RECORD_FIXED - 1) { ok = false; break; }
        cg_packed_record *r = &records[i];
        r->meta.classification = get16(data + offset); offset += 2;
        r->meta.sci_compartment = get16(data + offset); offset += 2;
        r->meta.flags = data[offset++];
        r->meta.expire_time_ms = get64(data + offset); offset += 8;
        r->meta.change_seq = get64(data + offset); offset += 8;
        r->value_len = get32(data + offset); offset += 4;
        if (!authorized(principal, r->meta.classification, r->meta.sci_compartment) ||
            (r->meta.flags & (uint8_t)~TOMBSTONE) ||
            r->value_len > CG_PACKED_MAX_VALUE ||
            ((r->meta.flags & TOMBSTONE) &&
             (r->value_len || r->meta.expire_time_ms)) ||
            end - offset < r->value_len) { ok = false; break; }
        /* The label is checked before any identifier or payload is built. */
        if (tag == KEY_LITERAL && memchr(key_bytes, 0, key_len)) { ok = false; break; }
        r->key = malloc(key_len + 1);
        if (!r->key) { ok = false; break; }
        r->key_len = key_len;
        if (tag == KEY_LITERAL) {
            memcpy(r->key, key_bytes, key_len);
        } else {
            r->key[0] = tag == KEY_NODE ? 'n' : 'e';
            r->key[1] = ':';
            for (size_t j = 0; j < 32; j++) {
                r->key[2 + j * 2] = (char)hex_char(key_bytes[j] >> 4);
                r->key[3 + j * 2] = (char)hex_char(key_bytes[j] & 15);
            }
        }
        r->key[key_len] = 0;
        if (r->value_len) {
            r->value = malloc(r->value_len);
            if (!r->value) { ok = false; break; }
            memcpy(r->value, data + offset, r->value_len);
            offset += r->value_len;
        }
    }
    if (offset != end || !all_authorized(records, count, principal)) ok = false;
    if (!ok) { cg_packed_records_free(records, count); return false; }
    *out = records; *out_count = count;
    return true;
}
