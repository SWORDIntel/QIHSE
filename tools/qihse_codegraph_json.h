/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CODEGRAPH_JSON_H
#define QIHSE_CODEGRAPH_JSON_H

#include <errno.h>
#include <json-c/json.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CG_JSON_MAX_BYTES (256u * 1024u)
#define CG_JSON_MAX_DEPTH 32u

/* Pure bounded input parser, not a data-retrieval or authorization primitive.
 * Its caller must retain the authenticated context around source/store access.
 * Reject duplicate TOP-LEVEL decoded keys, including escaped spellings. Nested
 * unknown objects retain json-c's existing interpretation; this wrapper does
 * not silently impose a recursive duplicate-key policy on unknown payloads.
 * The input is borrowed; returned object has one reference, owned by caller. */
typedef struct {
    const unsigned char *bytes;
    size_t length, offset, members;
} cg_json_scan;

static inline bool cg_json_utf8_valid(const unsigned char *p, size_t size) {
    for (size_t i = 0; i < size;) {
        unsigned c = p[i++];
        if (c < 0x80)
            continue;
        unsigned need, minimum, value;
        if (c >= 0xc2 && c <= 0xdf) {
            need = 1;
            minimum = 0x80;
            value = c & 0x1f;
        } else if (c >= 0xe0 && c <= 0xef) {
            need = 2;
            minimum = 0x800;
            value = c & 0x0f;
        } else if (c >= 0xf0 && c <= 0xf4) {
            need = 3;
            minimum = 0x10000;
            value = c & 7;
        } else
            return false;
        if (need > size - i)
            return false;
        for (unsigned j = 0; j < need; j++) {
            c = p[i++];
            if ((c & 0xc0) != 0x80)
                return false;
            value = (value << 6) | (c & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
            return false;
    }
    return true;
}

static inline void cg_json_space(cg_json_scan *s) {
    while (s->offset < s->length) {
        unsigned c = s->bytes[s->offset];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            break;
        s->offset++;
    }
}

static inline bool cg_json_hex4(cg_json_scan *s, unsigned *out) {
    if (s->length - s->offset < 4)
        return false;
    unsigned result = 0;
    for (unsigned i = 0; i < 4; i++) {
        unsigned c = s->bytes[s->offset++], value;
        if (c >= '0' && c <= '9')
            value = c - '0';
        else if (c >= 'a' && c <= 'f')
            value = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            value = c - 'A' + 10;
        else
            return false;
        result = (result << 4) | value;
    }
    *out = result;
    return true;
}

static inline bool cg_json_string(cg_json_scan *s, bool top_key) {
    if (s->offset == s->length || s->bytes[s->offset++] != '"')
        return false;
    while (s->offset < s->length) {
        unsigned c = s->bytes[s->offset++];
        if (c == '"')
            return true;
        if (c < 0x20)
            return false;
        if (c != '\\')
            continue;
        if (s->offset == s->length)
            return false;
        c = s->bytes[s->offset++];
        if (c == '"' || c == '\\' || c == '/' || c == 'b' || c == 'f' || c == 'n' || c == 'r' ||
            c == 't')
            continue;
        if (c != 'u')
            return false;
        unsigned code;
        if (!cg_json_hex4(s, &code) || (top_key && code == 0))
            return false;
        /* Retain json-c's established treatment of escaped surrogate code
         * units in unknown values. Their syntax is four hex digits; decoded
         * top-level key aliases are still detected by the member-count check. */
    }
    return false;
}

static inline bool cg_json_scan_value(cg_json_scan *s, unsigned depth);

static inline bool cg_json_container(cg_json_scan *s, unsigned depth, bool object) {
    if (depth >= CG_JSON_MAX_DEPTH)
        return false;
    s->offset++;
    cg_json_space(s);
    unsigned close = object ? '}' : ']';
    if (s->offset < s->length && s->bytes[s->offset] == close) {
        s->offset++;
        return true;
    }
    for (;;) {
        if (object) {
            if (!cg_json_string(s, depth == 0))
                return false;
            if (depth == 0)
                s->members++;
            cg_json_space(s);
            if (s->offset == s->length || s->bytes[s->offset++] != ':')
                return false;
        }
        if (!cg_json_scan_value(s, depth + 1))
            return false;
        cg_json_space(s);
        if (s->offset == s->length)
            return false;
        unsigned separator = s->bytes[s->offset++];
        if (separator == close)
            return true;
        if (separator != ',')
            return false;
        cg_json_space(s);
    }
}

static inline bool cg_json_number(cg_json_scan *s) {
    if (s->bytes[s->offset] == '-')
        s->offset++;
    if (s->offset == s->length)
        return false;
    if (s->bytes[s->offset] == '0')
        s->offset++;
    else {
        if (s->bytes[s->offset] < '1' || s->bytes[s->offset] > '9')
            return false;
        do
            s->offset++;
        while (s->offset < s->length && s->bytes[s->offset] >= '0' && s->bytes[s->offset] <= '9');
    }
    if (s->offset < s->length && s->bytes[s->offset] == '.') {
        size_t start = ++s->offset;
        while (s->offset < s->length && s->bytes[s->offset] >= '0' && s->bytes[s->offset] <= '9')
            s->offset++;
        if (s->offset == start)
            return false;
    }
    if (s->offset < s->length && (s->bytes[s->offset] == 'e' || s->bytes[s->offset] == 'E')) {
        s->offset++;
        if (s->offset < s->length && (s->bytes[s->offset] == '+' || s->bytes[s->offset] == '-'))
            s->offset++;
        size_t start = s->offset;
        while (s->offset < s->length && s->bytes[s->offset] >= '0' && s->bytes[s->offset] <= '9')
            s->offset++;
        if (s->offset == start)
            return false;
    }
    return true;
}

static inline bool cg_json_scan_value(cg_json_scan *s, unsigned depth) {
    cg_json_space(s);
    if (s->offset == s->length)
        return false;
    unsigned c = s->bytes[s->offset];
    if (c == '{' || c == '[')
        return cg_json_container(s, depth, c == '{');
    if (c == '"')
        return cg_json_string(s, false);
    if (c == '-' || (c >= '0' && c <= '9'))
        return cg_json_number(s);
    const char *literal = c == 't' ? "true" : c == 'f' ? "false" : c == 'n' ? "null" : NULL;
    if (!literal)
        return false;
    size_t n = strlen(literal);
    if (n > s->length - s->offset || memcmp(s->bytes + s->offset, literal, n))
        return false;
    s->offset += n;
    return true;
}

static inline struct json_object *cg_json_parse_object(const char *bytes, size_t length) {
    if (!bytes || !length) {
        errno = EINVAL;
        return NULL;
    }
    if (length > CG_JSON_MAX_BYTES) {
        errno = EFBIG;
        return NULL;
    }
    if (memchr(bytes, 0, length) || !cg_json_utf8_valid((const unsigned char *)bytes, length)) {
        errno = EINVAL;
        return NULL;
    }
    cg_json_scan scan = {.bytes = (const unsigned char *)bytes, .length = length};
    cg_json_space(&scan);
    if (scan.offset == length || scan.bytes[scan.offset] != '{' || !cg_json_scan_value(&scan, 0)) {
        errno = EINVAL;
        return NULL;
    }
    cg_json_space(&scan);
    if (scan.offset != length) {
        errno = EINVAL;
        return NULL;
    }
    struct json_tokener *tok = json_tokener_new_ex(CG_JSON_MAX_DEPTH);
    if (!tok) {
        errno = ENOMEM;
        return NULL;
    }
    /* Host json-c strict/UTF-8 flags reject some valid non-ASCII strings.
     * The independent bounded lexer above already enforces standard syntax. */
    struct json_object *obj = json_tokener_parse_ex(tok, bytes, (int)length);
    size_t consumed = json_tokener_get_parse_end(tok);
    bool valid = obj && json_tokener_get_error(tok) == json_tokener_success &&
                 json_object_is_type(obj, json_type_object) && consumed <= length &&
                 (size_t)json_object_object_length(obj) == scan.members;
    for (size_t i = consumed; valid && i < length; i++)
        valid = bytes[i] == ' ' || bytes[i] == '\t' || bytes[i] == '\r' || bytes[i] == '\n';
    json_tokener_free(tok);
    if (!valid) {
        if (obj)
            json_object_put(obj);
        errno = EINVAL;
        return NULL;
    }
    return obj;
}
#endif
