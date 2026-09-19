#include "qihse_mongo_wire.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <regex.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

/* ---- BSON implementation ---- */

bson_t* bson_create(void) {
    bson_t* b = (bson_t*)calloc(1, sizeof(bson_t));
    if (!b) return NULL;
    b->cap = 256;
    b->data = (uint8_t*)calloc(b->cap, 1);
    b->len = 4; /* reserve for document size */
    return b;
}

void bson_destroy(bson_t* b) {
    if (!b) return;
    free(b->data);
    free(b);
}

static int bson_ensure(bson_t* b, size_t need) {
    if (b->len + need > b->cap) {
        while (b->len + need > b->cap) b->cap *= 2;
        b->data = (uint8_t*)realloc(b->data, b->cap);
    }
    return 0;
}

static int bson_append_type_and_key(bson_t* b, uint8_t type, const char* key) {
    size_t klen = strlen(key) + 1;
    bson_ensure(b, 1 + klen);
    b->data[b->len++] = type;
    memcpy(b->data + b->len, key, klen);
    b->len += klen;
    return 0;
}

/* Embed sub as a spec-conformant nested document/array:
 * [int32 total_size][elements][0x00], total_size counting all of it.
 *
 * A bson_t has two lifetimes.  A builder (bson_create()) counts the 4-byte
 * length prefix plus the elements in len; its trailing NUL is not stored.  A
 * serialized view (bson_copy()/a view over wire bytes) has len equal to the
 * full serialized size, trailing NUL included, and its own length prefix
 * describes that buffer exactly.  The prefix therefore identifies which one
 * this is, and both are emitted in the conformant form.  Emitting a builder
 * sub-document with its len (the previous behaviour) produced a nested
 * document that declared one byte less than it occupied and carried no
 * terminator, which a stock BSON parser rejects whenever the last element of
 * the nested document does not itself end in a 0x00 byte. */
static int bson_embed(bson_t* b, const char* key, uint8_t type, const bson_t* sub) {
    if (!b || !key || !sub || !sub->data || sub->len < 4) return -1;
    int32_t declared = 0;
    memcpy(&declared, sub->data, 4);
    int serialized = (declared == (int32_t)sub->len);
    size_t content = sub->len - 4;                 /* elements, prefix excluded */
    size_t total = content + 4u + (serialized ? 0u : 1u);
    if (total > MONGO_MAX_BSON_SIZE) return -1;
    bson_append_type_and_key(b, type, key);
    bson_ensure(b, total);
    int32_t sz = (int32_t)total;
    memcpy(b->data + b->len, &sz, 4);
    b->len += 4;
    memcpy(b->data + b->len, sub->data + 4, content);
    b->len += content;
    if (!serialized) b->data[b->len++] = 0x00;
    return 0;
}

int bson_append_int32(bson_t* b, const char* key, int32_t val) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_INT32, key);
    bson_ensure(b, 4);
    memcpy(b->data + b->len, &val, 4);
    b->len += 4;
    return 0;
}

int bson_append_int64(bson_t* b, const char* key, int64_t val) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_INT64, key);
    bson_ensure(b, 8);
    memcpy(b->data + b->len, &val, 8);
    b->len += 8;
    return 0;
}

int bson_append_double(bson_t* b, const char* key, double val) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_DOUBLE, key);
    bson_ensure(b, 8);
    memcpy(b->data + b->len, &val, 8);
    b->len += 8;
    return 0;
}

int bson_append_string(bson_t* b, const char* key, const char* val) {
    if (!b || !key || !val) return -1;
    bson_append_type_and_key(b, BSON_STRING, key);
    int32_t slen = (int32_t)(strlen(val) + 1);
    bson_ensure(b, 4 + slen);
    memcpy(b->data + b->len, &slen, 4);
    b->len += 4;
    memcpy(b->data + b->len, val, slen);
    b->len += slen;
    return 0;
}

int bson_append_bool(bson_t* b, const char* key, int val) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_BOOL, key);
    bson_ensure(b, 1);
    b->data[b->len++] = val ? 1 : 0;
    return 0;
}

int bson_append_null(bson_t* b, const char* key) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_NULL, key);
    return 0;
}

int bson_append_document(bson_t* b, const char* key, const bson_t* sub) {
    return bson_embed(b, key, BSON_DOCUMENT, sub);
}

int bson_append_array(bson_t* b, const char* key, const bson_t* sub) {
    return bson_embed(b, key, BSON_ARRAY, sub);
}

int bson_append_binary(bson_t* b, const char* key, const uint8_t* data, size_t len) {
    if (!b || !key || !data) return -1;
    bson_append_type_and_key(b, BSON_BINARY, key);
    int32_t slen = (int32_t)len;
    bson_ensure(b, 5 + len);
    memcpy(b->data + b->len, &slen, 4);
    b->len += 4;
    b->data[b->len++] = 0x00;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

int bson_append_datetime(bson_t* b, const char* key, int64_t ms) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_DATETIME, key);
    bson_ensure(b, 8);
    memcpy(b->data + b->len, &ms, 8);
    b->len += 8;
    return 0;
}

int bson_append_objectid(bson_t* b, const char* key, const uint8_t oid[12]) {
    if (!b || !key || !oid) return -1;
    bson_append_type_and_key(b, BSON_OBJECTID, key);
    bson_ensure(b, 12);
    memcpy(b->data + b->len, oid, 12);
    b->len += 12;
    return 0;
}

int bson_append_regex(bson_t* b, const char* key, const char* pattern, const char* options) {
    if (!b || !key || !pattern) return -1;
    if (!options) options = "";
    bson_append_type_and_key(b, BSON_REGEX, key);
    size_t plen = strlen(pattern) + 1;
    size_t olen = strlen(options) + 1;
    bson_ensure(b, plen + olen);
    memcpy(b->data + b->len, pattern, plen);
    b->len += plen;
    memcpy(b->data + b->len, options, olen);
    b->len += olen;
    return 0;
}

int bson_append_timestamp(bson_t* b, const char* key, int32_t incr, int32_t ts) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_TIMESTAMP, key);
    bson_ensure(b, 8);
    memcpy(b->data + b->len, &incr, 4);
    b->len += 4;
    memcpy(b->data + b->len, &ts, 4);
    b->len += 4;
    return 0;
}

int bson_append_minkey(bson_t* b, const char* key) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_MINKEY, key);
    return 0;
}

int bson_append_maxkey(bson_t* b, const char* key) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_MAXKEY, key);
    return 0;
}

size_t bson_size(const bson_t* b) {
    if (!b) return 0;
    int32_t sz = (int32_t)(b->len + 1);
    memcpy(b->data, &sz, 4);
    return b->len + 1;
}

const uint8_t* bson_data(const bson_t* b) {
    if (!b) return NULL;
    int32_t sz = (int32_t)(b->len + 1);
    memcpy(b->data, &sz, 4);
    if (b->len < b->cap) b->data[b->len] = 0;
    return b->data;
}

/* ---- Raw element iterator (internal) ---- */
typedef struct {
    bson_type_t type;
    const char* key;
    const uint8_t* value_ptr;
    size_t value_len;
    size_t elem_start;
    size_t elem_end;
} raw_elem_t;

/* Bounded reader helpers.  Every length in a BSON document is attacker
 * controlled once the document arrives over the wire, so each field is checked
 * against the bytes actually present before it is used.  A malformed element
 * is refused (return -1) rather than walked past. */
static int raw_need(const bson_t* b, size_t offset, size_t need) {
    return (offset <= b->len && need <= b->len - offset) ? 0 : -1;
}

/* Bounded strlen over the document's own bytes.  Returns the length of the
 * NUL-terminated string at offset, or -1 when no NUL is present inside the
 * buffer. */
static long raw_cstr_len(const bson_t* b, size_t offset) {
    if (offset >= b->len) return -1;
    const void* nul = memchr(b->data + offset, 0, b->len - offset);
    if (!nul) return -1;
    return (long)((const uint8_t*)nul - (b->data + offset));
}

static int bson_raw_iter(const bson_t* b, size_t* offset, raw_elem_t* e) {
    if (!b || !offset || !e || !b->data) return -1;
    if (*offset == 0) *offset = 4;
    if (*offset >= b->len) return -1;
    uint8_t type = b->data[*offset];
    if (type == 0) return -1;
    e->type = (bson_type_t)type;
    e->elem_start = *offset;
    (*offset)++;
    e->key = (const char*)(b->data + *offset);
    long klen = raw_cstr_len(b, *offset);
    if (klen < 0) return -1;
    *offset += (size_t)klen + 1u;
    e->value_ptr = b->data + *offset;
    switch (type) {
        case BSON_INT32:
            if (raw_need(b, *offset, 4) != 0) return -1;
            e->value_len = 4; *offset += 4; break;
        case BSON_INT64:
        case BSON_DATETIME:
        case BSON_TIMESTAMP:
        case BSON_DOUBLE:
        case BSON_DECIMAL128:
            if (raw_need(b, *offset, 8) != 0) return -1;
            e->value_len = 8; *offset += 8; break;
        case BSON_STRING: {
            if (raw_need(b, *offset, 4) != 0) return -1;
            int32_t slen; memcpy(&slen, b->data + *offset, 4);
            /* A BSON string declares its own length including the trailing
             * NUL, which must be present inside the buffer. */
            if (slen < 1 || raw_need(b, *offset + 4u, (size_t)slen) != 0) return -1;
            if (b->data[*offset + 4u + (size_t)slen - 1u] != 0x00) return -1;
            e->value_len = 4 + (size_t)slen; *offset += 4 + (size_t)slen; break;
        }
        case BSON_BOOL:
            if (raw_need(b, *offset, 1) != 0) return -1;
            e->value_len = 1; *offset += 1; break;
        case BSON_NULL: e->value_len = 0; break;
        case BSON_BINARY: {
            if (raw_need(b, *offset, 5) != 0) return -1;
            int32_t blen; memcpy(&blen, b->data + *offset, 4);
            if (blen < 0 || raw_need(b, *offset + 4u, (size_t)blen + 1u) != 0) return -1;
            e->value_len = 5 + (size_t)blen; *offset += 5 + (size_t)blen; break;
        }
        case BSON_DOCUMENT:
        case BSON_ARRAY: {
            if (raw_need(b, *offset, 5) != 0) return -1;
            int32_t dlen; memcpy(&dlen, b->data + *offset, 4);
            /* A nested document must declare at least its prefix and a
             * terminator, must fit in the bytes present, and must actually end
             * with the terminator. */
            if (dlen < 5 || raw_need(b, *offset, (size_t)dlen) != 0) return -1;
            if (b->data[*offset + (size_t)dlen - 1u] != 0x00) return -1;
            e->value_len = (size_t)dlen; *offset += (size_t)dlen; break;
        }
        case BSON_OBJECTID:
            if (raw_need(b, *offset, 12) != 0) return -1;
            e->value_len = 12; *offset += 12; break;
        case BSON_REGEX: {
            long pl = raw_cstr_len(b, *offset);
            if (pl < 0) return -1;
            size_t poff = *offset + (size_t)pl + 1u;
            long ol = raw_cstr_len(b, poff);
            if (ol < 0) return -1;
            *offset = poff + (size_t)ol + 1u;
            e->value_len = (size_t)pl + 1u + (size_t)ol + 1u; break;
        }
        case BSON_MINKEY:
        case BSON_MAXKEY: e->value_len = 0; break;
        default: *offset = b->len; return -1;
    }
    e->elem_end = *offset;
    return 0;
}

/* BSON iteration (public) */
int bson_iter(const bson_t* b, size_t* offset, bson_element_t* out_elem) {
    if (!b || !offset || !out_elem) return -1;
    raw_elem_t re;
    if (bson_raw_iter(b, offset, &re) != 0) return -1;
    memset(out_elem, 0, sizeof(*out_elem));
    out_elem->type = re.type;
    out_elem->key = re.key;
    switch (re.type) {
        case BSON_INT32: memcpy(&out_elem->v.i32, re.value_ptr, 4); break;
        case BSON_INT64:
        case BSON_DATETIME:
        case BSON_TIMESTAMP: memcpy(&out_elem->v.i64, re.value_ptr, 8); break;
        case BSON_DOUBLE: memcpy(&out_elem->v.d, re.value_ptr, 8); break;
        case BSON_STRING: out_elem->v.str = (const char*)(re.value_ptr + 4); break;
        case BSON_BOOL: out_elem->v.b = re.value_ptr[0]; break;
        case BSON_NULL: break;
        case BSON_BINARY: {
            int32_t blen; memcpy(&blen, re.value_ptr, 4);
            out_elem->v.bin.data = re.value_ptr + 5;
            out_elem->v.bin.len = blen; break;
        }
        case BSON_DOCUMENT:
        case BSON_ARRAY: {
            int32_t dlen; memcpy(&dlen, re.value_ptr, 4);
            out_elem->v.doc.data = re.value_ptr;
            out_elem->v.doc.len = dlen; break;
        }
        case BSON_OBJECTID: out_elem->v.oid.data = re.value_ptr; break;
        case BSON_REGEX: {
            out_elem->v.regex.pattern = (const char*)re.value_ptr;
            size_t pl = strlen(out_elem->v.regex.pattern) + 1;
            out_elem->v.regex.options = (const char*)(re.value_ptr + pl); break;
        }
        default: break;
    }
    return 0;
}

int bson_append_element(bson_t* b, const char* key, const bson_element_t* e, const uint8_t* raw) {
    if (!b || !key || !e) return -1;
    (void)raw;
    switch (e->type) {
        case BSON_INT32: bson_append_int32(b, key, e->v.i32); break;
        case BSON_INT64: bson_append_int64(b, key, e->v.i64); break;
        case BSON_DATETIME: bson_append_datetime(b, key, e->v.i64); break;
        case BSON_TIMESTAMP: bson_append_timestamp(b, key, 0, 0); break;
        case BSON_DOUBLE: bson_append_double(b, key, e->v.d); break;
        case BSON_STRING: bson_append_string(b, key, e->v.str); break;
        case BSON_BOOL: bson_append_bool(b, key, e->v.b); break;
        case BSON_NULL: bson_append_null(b, key); break;
        case BSON_BINARY: bson_append_binary(b, key, e->v.bin.data, e->v.bin.len); break;
        case BSON_DOCUMENT:
        case BSON_ARRAY: {
            bson_t view; view.data = (uint8_t*)e->v.doc.data; view.len = e->v.doc.len; view.cap = e->v.doc.len;
            if (e->type == BSON_ARRAY) bson_append_array(b, key, &view);
            else bson_append_document(b, key, &view);
            break;
        }
        case BSON_OBJECTID: bson_append_objectid(b, key, e->v.oid.data); break;
        case BSON_REGEX: bson_append_regex(b, key, e->v.regex.pattern, e->v.regex.options); break;
        case BSON_MINKEY: bson_append_minkey(b, key); break;
        case BSON_MAXKEY: bson_append_maxkey(b, key); break;
        default: break;
    }
    return 0;
}

bson_t* bson_copy(const bson_t* src) {
    if (!src) return NULL;
    bson_t* b = (bson_t*)calloc(1, sizeof(bson_t));
    b->cap = src->len;
    b->len = src->len;
    b->data = (uint8_t*)malloc(src->len);
    memcpy(b->data, src->data, src->len);
    return b;
}

int bson_find_element(const bson_t* b, const char* key, bson_element_t* out) {
    if (!b || !key || !out) return -1;
    size_t off = 0;
    bson_element_t e;
    while (bson_iter(b, &off, &e) == 0) {
        if (strcmp(e.key, key) == 0) { *out = e; return 0; }
    }
    return -1;
}

static bson_t bson_view(const uint8_t* data, int32_t len) {
    bson_t v;
    v.data = (uint8_t*)data;
    v.len = len;
    v.cap = len;
    return v;
}

int bson_find_path(const bson_t* b, const char* dotted, bson_element_t* out) {
    if (!b || !dotted || !out) return -1;
    char path[256];
    strncpy(path, dotted, sizeof(path) - 1);
    path[sizeof(path) - 1] = 0;
    char* save = NULL;
    char* tok = strtok_r(path, ".", &save);
    const bson_t* cur = b;
    bson_t view_storage;
    bson_element_t e;
    while (tok) {
        char* next = strtok_r(NULL, ".", &save);
        if (bson_find_element(cur, tok, &e) != 0) return -1;
        if (next) {
            if (e.type != BSON_DOCUMENT && e.type != BSON_ARRAY) return -1;
            view_storage = bson_view(e.v.doc.data, e.v.doc.len);
            cur = &view_storage;
            tok = next;
        } else {
            *out = e;
            return 0;
        }
    }
    return -1;
}

/* ---- JSON serialization ---- */
/* Bound on nesting depth for both the matcher and the JSON writer.  A filter
 * document arrives from the wire, so its nesting is attacker controlled and
 * recursion must not be able to exhaust the stack. */
#define MONGO_MAX_FILTER_DEPTH 32
#define MONGO_MAX_JSON_DEPTH   64

static void bson_to_json_rec(const bson_t* b, char* buf, size_t cap, size_t* len, int is_array, int depth);

static void json_escape(const char* s, char* buf, size_t cap, size_t* len) {
    for (const char* p = s; *p && *len + 2 < cap; p++) {
        if (*p == '"' || *p == '\\') { buf[(*len)++] = '\\'; buf[(*len)++] = *p; }
        else if (*p == '\n') { buf[(*len)++] = '\\'; buf[(*len)++] = 'n'; }
        else buf[(*len)++] = *p;
    }
}

static void json_num(double v, char* buf, size_t cap, size_t* len) {
    char tmp[64];
    if (v == floor(v) && !isinf(v)) snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
    else snprintf(tmp, sizeof(tmp), "%g", v);
    size_t tl = strlen(tmp);
    if (*len + tl < cap) { memcpy(buf + *len, tmp, tl); *len += tl; }
}

static void bson_elem_to_json(const bson_element_t* e, char* buf, size_t cap, size_t* len, int depth) {
    if (depth > MONGO_MAX_JSON_DEPTH) {
        const char* s = "null"; size_t l = 4;
        if (*len + l < cap) { memcpy(buf + *len, s, l); *len += l; }
        return;
    }
    switch (e->type) {
        case BSON_INT32: json_num((double)e->v.i32, buf, cap, len); break;
        case BSON_INT64: json_num((double)e->v.i64, buf, cap, len); break;
        case BSON_DOUBLE: json_num(e->v.d, buf, cap, len); break;
        case BSON_BOOL: { const char* s = e->v.b ? "true" : "false"; size_t l = strlen(s); if (*len + l < cap) { memcpy(buf + *len, s, l); *len += l; } } break;
        case BSON_STRING: if (*len < cap) buf[(*len)++] = '"'; json_escape(e->v.str, buf, cap, len); if (*len < cap) buf[(*len)++] = '"'; break;
        case BSON_NULL: { const char* s = "null"; size_t l = 4; if (*len + l < cap) { memcpy(buf + *len, s, l); *len += l; } } break;
        case BSON_DOCUMENT: { bson_t v = bson_view(e->v.doc.data, e->v.doc.len); bson_to_json_rec(&v, buf, cap, len, 0, depth + 1); } break;
        case BSON_ARRAY: { bson_t v = bson_view(e->v.doc.data, e->v.doc.len); bson_to_json_rec(&v, buf, cap, len, 1, depth + 1); } break;
        default: { const char* s = "null"; size_t l = 4; if (*len + l < cap) { memcpy(buf + *len, s, l); *len += l; } } break;
    }
}

static void bson_to_json_rec(const bson_t* b, char* buf, size_t cap, size_t* len, int is_array, int depth) {
    if (!b || depth > MONGO_MAX_JSON_DEPTH) {
        const char* s = "null"; size_t l = 4;
        if (*len + l < cap) { memcpy(buf + *len, s, l); *len += l; }
        return;
    }
    if (*len < cap) buf[(*len)++] = is_array ? '[' : '{';
    size_t off = 0;
    bson_element_t e;
    int first = 1;
    while (bson_iter(b, &off, &e) == 0) {
        if (!first) { if (*len < cap) buf[(*len)++] = ','; }
        first = 0;
        if (!is_array) {
            if (*len < cap) buf[(*len)++] = '"';
            json_escape(e.key, buf, cap, len);
            if (*len + 2 < cap) { buf[(*len)++] = '"'; buf[(*len)++] = ':'; }
        }
        bson_elem_to_json(&e, buf, cap, len, depth);
    }
    if (*len < cap) buf[(*len)++] = is_array ? ']' : '}';
}

char* bson_to_json(const bson_t* b) {
    if (!b) return NULL;
    char* buf = (char*)malloc(65536);
    if (!buf) return NULL;
    size_t len = 0;
    bson_to_json_rec(b, buf, 65536, &len, 0, 0);
    buf[len] = 0;
    return buf;
}

void bson_remove_key(bson_t* b, const char* key) {
    if (!b || !key) return;
    bson_t* nb = bson_create();
    size_t off = 0;
    raw_elem_t re;
    while (bson_raw_iter(b, &off, &re) == 0) {
        if (strcmp(re.key, key) == 0) continue;
        bson_append_type_and_key(nb, (uint8_t)re.type, re.key);
        bson_ensure(nb, re.value_len);
        memcpy(nb->data + nb->len, re.value_ptr, re.value_len);
        nb->len += re.value_len;
    }
    free(b->data);
    b->data = nb->data;
    b->len = nb->len;
    b->cap = nb->cap;
    free(nb);
}

int bson_set_field(bson_t* b, const char* key, const bson_element_t* e, const uint8_t* raw) {
    if (!b || !key || !e) return -1;
    (void)raw;
    bson_t* nb = bson_create();
    int found = 0;
    size_t off = 0;
    raw_elem_t re;
    while (bson_raw_iter(b, &off, &re) == 0) {
        if (strcmp(re.key, key) == 0) {
            bson_append_element(nb, key, e, NULL);
            found = 1;
        } else {
            bson_append_type_and_key(nb, (uint8_t)re.type, re.key);
            bson_ensure(nb, re.value_len);
            memcpy(nb->data + nb->len, re.value_ptr, re.value_len);
            nb->len += re.value_len;
        }
    }
    if (!found) bson_append_element(nb, key, e, NULL);
    free(b->data);
    b->data = nb->data;
    b->len = nb->len;
    b->cap = nb->cap;
    free(nb);
    return 0;
}

/* ---- Value comparison helpers ---- */
static double elem_as_num(const bson_element_t* e) {
    if (!e) return 0;
    switch (e->type) {
        case BSON_INT32: return (double)e->v.i32;
        case BSON_INT64:
        case BSON_DATETIME:
        case BSON_TIMESTAMP: return (double)e->v.i64;
        case BSON_DOUBLE: return e->v.d;
        case BSON_BOOL: return e->v.b ? 1.0 : 0.0;
        default: return 0;
    }
}

static int elem_is_numeric(const bson_element_t* e) {
    return e && (e->type == BSON_INT32 || e->type == BSON_INT64 ||
                 e->type == BSON_DOUBLE || e->type == BSON_DATETIME ||
                 e->type == BSON_TIMESTAMP);
}

static int elem_equal(const bson_element_t* a, const bson_element_t* b) {
    if (!a || !b) return 0;
    if (elem_is_numeric(a) && elem_is_numeric(b)) return elem_as_num(a) == elem_as_num(b);
    if (a->type != b->type) return 0;
    switch (a->type) {
        case BSON_STRING: return strcmp(a->v.str, b->v.str) == 0;
        case BSON_BOOL: return a->v.b == b->v.b;
        case BSON_NULL: return 1;
        case BSON_OBJECTID: return memcmp(a->v.oid.data, b->v.oid.data, 12) == 0;
        case BSON_DOCUMENT:
        case BSON_ARRAY: return a->v.doc.len == b->v.doc.len && memcmp(a->v.doc.data, b->v.doc.data, a->v.doc.len) == 0;
        default: return 0;
    }
}

static int elem_cmp(const bson_element_t* a, const bson_element_t* b) {
    if (elem_is_numeric(a) && elem_is_numeric(b)) {
        double da = elem_as_num(a), db = elem_as_num(b);
        return (da < db) ? -1 : (da > db) ? 1 : 0;
    }
    if (a->type == BSON_STRING && b->type == BSON_STRING) return strcmp(a->v.str, b->v.str);
    if (a->type == BSON_BOOL && b->type == BSON_BOOL) return (a->v.b < b->v.b) ? -1 : (a->v.b > b->v.b) ? 1 : 0;
    return 0;
}

/* ---- Query operators ---- */
static int op_regex(const char* pattern, const char* options, const char* text) {
    char rx[256];
    int flags = REG_EXTENDED | REG_NOSUB;
    if (options && strchr(options, 'i')) flags |= REG_ICASE;
    snprintf(rx, sizeof(rx), "%s", pattern);
    regex_t re;
    if (regcomp(&re, rx, flags) != 0) return 0;
    int rc = regexec(&re, text, 0, NULL, 0);
    regfree(&re);
    return rc == 0;
}

/* Matcher recursion is bounded: a filter document arrives from the wire, so
 * its nesting is attacker controlled.  A depth overflow returns -1, which the
 * callers treat as "no match" (fail closed: the query returns nothing) and
 * which $not/$nor/$pull must not invert into a match. */
static int match_subfilter_d(const bson_t* doc, const bson_t* filter, int depth);

static int array_count(const bson_element_t* arr) {
    if (!arr || (arr->type != BSON_ARRAY && arr->type != BSON_DOCUMENT)) return -1;
    bson_t v = bson_view(arr->v.doc.data, arr->v.doc.len);
    size_t off = 0; bson_element_t e; int n = 0;
    while (bson_iter(&v, &off, &e) == 0) n++;
    return n;
}

static int match_operator_d(const bson_t* doc, const char* key, const bson_element_t* field,
                            const char* op, const bson_element_t* opval, const uint8_t* raw,
                            int depth) {
    (void)raw;
    if (depth > MONGO_MAX_FILTER_DEPTH) return -1;
    if (strcmp(op, "$eq") == 0) {
        return field && elem_equal(field, opval);
    } else if (strcmp(op, "$ne") == 0) {
        return !field || !elem_equal(field, opval);
    } else if (strcmp(op, "$gt") == 0) {
        return field && elem_is_numeric(field) && elem_is_numeric(opval) && elem_cmp(field, opval) > 0;
    } else if (strcmp(op, "$gte") == 0) {
        return field && elem_is_numeric(field) && elem_is_numeric(opval) && elem_cmp(field, opval) >= 0;
    } else if (strcmp(op, "$lt") == 0) {
        return field && elem_is_numeric(field) && elem_is_numeric(opval) && elem_cmp(field, opval) < 0;
    } else if (strcmp(op, "$lte") == 0) {
        return field && elem_is_numeric(field) && elem_is_numeric(opval) && elem_cmp(field, opval) <= 0;
    } else if (strcmp(op, "$in") == 0) {
        if (!opval || opval->type != BSON_ARRAY) return 0;
        bson_t arr = bson_view(opval->v.doc.data, opval->v.doc.len);
        size_t off = 0; bson_element_t item;
        while (bson_iter(&arr, &off, &item) == 0) {
            if (field && elem_equal(field, &item)) return 1;
        }
        return 0;
    } else if (strcmp(op, "$nin") == 0) {
        if (!opval || opval->type != BSON_ARRAY) return 1;
        bson_t arr = bson_view(opval->v.doc.data, opval->v.doc.len);
        size_t off = 0; bson_element_t item;
        while (bson_iter(&arr, &off, &item) == 0) {
            if (field && elem_equal(field, &item)) return 0;
        }
        return 1;
    } else if (strcmp(op, "$exists") == 0) {
        int want = opval && (opval->type == BSON_BOOL ? opval->v.b : (int)elem_as_num(opval));
        return want ? (field != NULL) : (field == NULL);
    } else if (strcmp(op, "$type") == 0) {
        if (!field) return 0;
        int want = (int)elem_as_num(opval);
        return (int)field->type == want;
    } else if (strcmp(op, "$regex") == 0) {
        if (!field || field->type != BSON_STRING) return 0;
        const char* pat = opval->type == BSON_STRING ? opval->v.str : NULL;
        const char* opts = "";
        if (opval->type == BSON_REGEX) { pat = opval->v.regex.pattern; opts = opval->v.regex.options; }
        if (!pat) return 0;
        return op_regex(pat, opts, field->v.str);
    } else if (strcmp(op, "$mod") == 0) {
        if (!field || !elem_is_numeric(field) || !opval || opval->type != BSON_ARRAY) return 0;
        bson_t arr = bson_view(opval->v.doc.data, opval->v.doc.len);
        size_t off = 0; bson_element_t d, r;
        if (bson_iter(&arr, &off, &d) != 0 || bson_iter(&arr, &off, &r) != 0) return 0;
        double dv = elem_as_num(&d), rv = elem_as_num(&r);
        if (dv == 0) return 0;
        return fmod(elem_as_num(field), dv) == rv;
    } else if (strcmp(op, "$all") == 0) {
        if (!field || field->type != BSON_ARRAY || !opval || opval->type != BSON_ARRAY) return 0;
        bson_t want = bson_view(opval->v.doc.data, opval->v.doc.len);
        bson_t have = bson_view(field->v.doc.data, field->v.doc.len);
        size_t woff = 0; bson_element_t w;
        while (bson_iter(&want, &woff, &w) == 0) {
            size_t hoff = 0; bson_element_t h; int found = 0;
            while (bson_iter(&have, &hoff, &h) == 0) { if (elem_equal(&w, &h)) { found = 1; break; } }
            if (!found) return 0;
        }
        return 1;
    } else if (strcmp(op, "$elemMatch") == 0) {
        if (!field || field->type != BSON_ARRAY || !opval) return 0;
        bson_t arr = bson_view(field->v.doc.data, field->v.doc.len);
        size_t off = 0; bson_element_t item;
        while (bson_iter(&arr, &off, &item) == 0) {
            if (opval->type == BSON_DOCUMENT) {
                bson_t sub = bson_view(opval->v.doc.data, opval->v.doc.len);
                if (item.type == BSON_DOCUMENT) {
                    bson_t iv = bson_view(item.v.doc.data, item.v.doc.len);
                    int r = match_subfilter_d(&iv, &sub, depth + 1);
                    if (r < 0) return -1;
                    if (r) return 1;
                }
            } else {
                if (elem_equal(&item, opval)) return 1;
            }
        }
        return 0;
    } else if (strcmp(op, "$size") == 0) {
        if (!field || field->type != BSON_ARRAY) return 0;
        int want = (int)elem_as_num(opval);
        return array_count(field) == want;
    } else if (strcmp(op, "$not") == 0) {
        if (!opval || opval->type != BSON_DOCUMENT) return 1;
        bson_t sub = bson_view(opval->v.doc.data, opval->v.doc.len);
        size_t off = 0; bson_element_t inner;
        while (bson_iter(&sub, &off, &inner) == 0) {
            if (inner.key[0] == '$') {
                int r = match_operator_d(doc, key, field, inner.key, &inner, NULL, depth + 1);
                if (r < 0) return -1;
                if (r) return 0;
            }
        }
        return 1;
    } else if (strcmp(op, "$where") == 0) {
        (void)doc; (void)key; (void)field; (void)opval;
        return 1;
    }
    return 0;
}

int bson_match_operator(const bson_t* doc, const char* key, const bson_element_t* field,
                        const char* op, const bson_element_t* opval, const uint8_t* raw) {
    return match_operator_d(doc, key, field, op, opval, raw, 0);
}

static int match_subfilter_d(const bson_t* doc, const bson_t* filter, int depth) {
    if (!doc || !filter || !filter->data) return -1;
    if (depth > MONGO_MAX_FILTER_DEPTH) return -1;
    size_t off = 0;
    bson_element_t fe;
    while (bson_iter(filter, &off, &fe) == 0) {
        if (fe.key[0] == '$') {
            if (strcmp(fe.key, "$and") == 0) {
                if (fe.type != BSON_ARRAY) return -1;
                bson_t arr = bson_view(fe.v.doc.data, fe.v.doc.len);
                size_t aoff = 0; bson_element_t sub;
                while (bson_iter(&arr, &aoff, &sub) == 0) {
                    if (sub.type != BSON_DOCUMENT) return -1;
                    bson_t sv = bson_view(sub.v.doc.data, sub.v.doc.len);
                    int r = match_subfilter_d(doc, &sv, depth + 1);
                    if (r < 0) return -1;
                    if (!r) return 0;
                }
            } else if (strcmp(fe.key, "$or") == 0) {
                if (fe.type != BSON_ARRAY) return -1;
                bson_t arr = bson_view(fe.v.doc.data, fe.v.doc.len);
                size_t aoff = 0; bson_element_t sub; int matched = 0;
                while (bson_iter(&arr, &aoff, &sub) == 0) {
                    if (sub.type == BSON_DOCUMENT) {
                        bson_t sv = bson_view(sub.v.doc.data, sub.v.doc.len);
                        int r = match_subfilter_d(doc, &sv, depth + 1);
                        if (r < 0) return -1;
                        if (r) { matched = 1; break; }
                    }
                }
                if (!matched) return 0;
            } else if (strcmp(fe.key, "$nor") == 0) {
                if (fe.type != BSON_ARRAY) return -1;
                bson_t arr = bson_view(fe.v.doc.data, fe.v.doc.len);
                size_t aoff = 0; bson_element_t sub;
                while (bson_iter(&arr, &aoff, &sub) == 0) {
                    if (sub.type == BSON_DOCUMENT) {
                        bson_t sv = bson_view(sub.v.doc.data, sub.v.doc.len);
                        int r = match_subfilter_d(doc, &sv, depth + 1);
                        if (r < 0) return -1;
                        if (r) return 0;
                    }
                }
            } else if (strcmp(fe.key, "$not") == 0) {
                if (fe.type == BSON_DOCUMENT) {
                    bson_t sv = bson_view(fe.v.doc.data, fe.v.doc.len);
                    int r = match_subfilter_d(doc, &sv, depth + 1);
                    if (r < 0) return -1;
                    if (r) return 0;
                }
            } else if (strcmp(fe.key, "$where") == 0) {
                /* $where is not evaluated (no server-side JavaScript): the
                 * stage is refused rather than silently matching everything. */
                return -1;
            } else {
                return -1;
            }
            continue;
        }
        bson_element_t field;
        int present = (bson_find_path(doc, fe.key, &field) == 0);
        if (fe.type == BSON_DOCUMENT) {
            bson_t sub = bson_view(fe.v.doc.data, fe.v.doc.len);
            size_t soff = 0; bson_element_t op;
            int has_op = 0, all_ok = 1;
            while (bson_iter(&sub, &soff, &op) == 0) {
                if (op.key[0] == '$') {
                    has_op = 1;
                    int r = match_operator_d(doc, fe.key, present ? &field : NULL, op.key, &op, NULL, depth + 1);
                    if (r < 0) return -1;
                    if (!r) { all_ok = 0; break; }
                }
            }
            if (has_op) { if (!all_ok) return 0; }
            else {
                if (!present || !elem_equal(&field, &fe)) return 0;
            }
        } else {
            if (!present || !elem_equal(&field, &fe)) return 0;
        }
    }
    return 1;
}

int bson_match(const bson_t* doc, const bson_t* filter) {
    if (!filter || filter->len <= 5) return 1;
    /* A malformed or too-deeply-nested filter matches nothing rather than
     * everything: a filter that cannot be evaluated must not widen the result
     * set. */
    return match_subfilter_d(doc, filter, 0) == 1;
}

/* ---- Update operators ---- */
static void array_to_elems(const bson_element_t* arr, bson_element_t** out, size_t* n) {
    *out = NULL; *n = 0;
    if (!arr || (arr->type != BSON_ARRAY && arr->type != BSON_DOCUMENT)) return;
    bson_t v = bson_view(arr->v.doc.data, arr->v.doc.len);
    size_t cap = 8, off = 0; bson_element_t e; size_t cnt = 0;
    bson_element_t* tmp = (bson_element_t*)calloc(cap, sizeof(bson_element_t));
    while (bson_iter(&v, &off, &e) == 0) {
        if (cnt == cap) { cap *= 2; tmp = (bson_element_t*)realloc(tmp, cap * sizeof(bson_element_t)); }
        tmp[cnt++] = e;
    }
    *out = tmp; *n = cnt;
}

static bson_t* elems_to_array(const bson_element_t* elems, size_t n) {
    bson_t* arr = bson_create();
    char k[16];
    for (size_t i = 0; i < n; i++) {
        snprintf(k, sizeof(k), "%zu", i);
        bson_append_element(arr, k, &elems[i], NULL);
    }
    return arr;
}

static void set_array_field(bson_t* doc, const char* key, const bson_element_t* items, size_t nitems) {
    bson_t* narr = elems_to_array(items, nitems);
    bson_element_t narr_elem; narr_elem.type = BSON_ARRAY; narr_elem.v.doc.data = narr->data; narr_elem.v.doc.len = (int32_t)narr->len;
    bson_set_field(doc, key, &narr_elem, NULL);
    free(narr->data); free(narr);
}

static void apply_array_push(bson_t* doc, const char* key, const bson_element_t* val, const bson_element_t* modifiers) {
    bson_element_t existing;
    int has = (bson_find_path(doc, key, &existing) == 0 && existing.type == BSON_ARRAY);
    bson_element_t* items; size_t nitems;
    if (has) array_to_elems(&existing, &items, &nitems);
    else { items = NULL; nitems = 0; }

    bson_element_t* add = NULL; size_t nadd = 0;
    if (val->type == BSON_ARRAY) {
        bson_element_t* each; size_t neach;
        array_to_elems(val, &each, &neach);
        add = (bson_element_t*)calloc(neach ? neach : 1, sizeof(bson_element_t));
        for (size_t i = 0; i < neach; i++) add[nadd++] = each[i];
        free(each);
    } else {
        add = (bson_element_t*)calloc(1, sizeof(bson_element_t));
        add[nadd++] = *val;
    }

    int position = -1;
    int slice = -1000000;
    int do_sort = 0; int sort_dir = 1;
    if (modifiers && modifiers->type == BSON_DOCUMENT) {
        bson_t mv = bson_view(modifiers->v.doc.data, modifiers->v.doc.len);
        size_t off = 0; bson_element_t m;
        while (bson_iter(&mv, &off, &m) == 0) {
            if (strcmp(m.key, "$each") == 0 && m.type == BSON_ARRAY) {
                bson_element_t* each; size_t neach;
                array_to_elems(&m, &each, &neach);
                add = (bson_element_t*)realloc(add, (nadd + neach) * sizeof(bson_element_t));
                for (size_t i = 0; i < neach; i++) add[nadd++] = each[i];
                free(each);
            } else if (strcmp(m.key, "$position") == 0) {
                position = (int)elem_as_num(&m);
            } else if (strcmp(m.key, "$slice") == 0) {
                slice = (int)elem_as_num(&m);
            } else if (strcmp(m.key, "$sort") == 0) {
                do_sort = 1;
                if (m.type == BSON_INT32) sort_dir = (int)m.v.i32;
            }
        }
    }

    bson_element_t* combined; size_t ncomb;
    if (position >= 0 && (size_t)position <= nitems) {
        ncomb = nitems + nadd;
        combined = (bson_element_t*)calloc(ncomb ? ncomb : 1, sizeof(bson_element_t));
        size_t j = 0;
        for (size_t i = 0; i < (size_t)position; i++) combined[j++] = items[i];
        for (size_t i = 0; i < nadd; i++) combined[j++] = add[i];
        for (size_t i = (size_t)position; i < nitems; i++) combined[j++] = items[i];
    } else {
        ncomb = nitems + nadd;
        combined = (bson_element_t*)calloc(ncomb ? ncomb : 1, sizeof(bson_element_t));
        for (size_t i = 0; i < nitems; i++) combined[i] = items[i];
        for (size_t i = 0; i < nadd; i++) combined[nitems + i] = add[i];
    }

    if (do_sort) {
        for (size_t i = 1; i < ncomb; i++) {
            bson_element_t cur = combined[i]; size_t j = i;
            while (j > 0) {
                int c = elem_cmp(&combined[j - 1], &cur);
                if ((sort_dir >= 0 && c > 0) || (sort_dir < 0 && c < 0)) {
                    combined[j] = combined[j - 1]; j--;
                } else break;
            }
            combined[j] = cur;
        }
    }

    if (slice != -1000000) {
        if (slice >= 0 && ncomb > (size_t)slice) ncomb = (size_t)slice;
        else if (slice < 0) {
            size_t keep = (size_t)(-slice);
            if (ncomb > keep) {
                memmove(combined, combined + (ncomb - keep), keep * sizeof(bson_element_t));
                ncomb = keep;
            }
        }
    }

    set_array_field(doc, key, combined, ncomb);
    free(combined); free(items); free(add);
}

static void apply_array_addtoset(bson_t* doc, const char* key, const bson_element_t* val, const bson_element_t* modifiers) {
    bson_element_t existing;
    int has = (bson_find_path(doc, key, &existing) == 0 && existing.type == BSON_ARRAY);
    bson_element_t* items; size_t nitems;
    if (has) array_to_elems(&existing, &items, &nitems);
    else { items = NULL; nitems = 0; }

    bson_element_t* add = NULL; size_t nadd = 0;
    if (modifiers && modifiers->type == BSON_DOCUMENT) {
        bson_t mv = bson_view(modifiers->v.doc.data, modifiers->v.doc.len);
        bson_element_t each_e;
        if (bson_find_element(&mv, "$each", &each_e) == 0 && each_e.type == BSON_ARRAY) {
            array_to_elems(&each_e, &add, &nadd);
        }
    }
    if (nadd == 0) { add = (bson_element_t*)calloc(1, sizeof(bson_element_t)); add[0] = *val; nadd = 1; }

    for (size_t i = 0; i < nadd; i++) {
        int present = 0;
        for (size_t j = 0; j < nitems; j++) if (elem_equal(&items[j], &add[i])) { present = 1; break; }
        if (!present) {
            items = (bson_element_t*)realloc(items, (nitems + 1) * sizeof(bson_element_t));
            items[nitems++] = add[i];
        }
    }
    set_array_field(doc, key, items, nitems);
    free(items); free(add);
}

static void apply_array_pull(bson_t* doc, const char* key, const bson_element_t* val) {
    bson_element_t existing;
    if (bson_find_path(doc, key, &existing) != 0 || existing.type != BSON_ARRAY) return;
    bson_element_t* items; size_t nitems;
    array_to_elems(&existing, &items, &nitems);
    bson_element_t* kept = (bson_element_t*)calloc(nitems ? nitems : 1, sizeof(bson_element_t));
    size_t nkept = 0;
    for (size_t i = 0; i < nitems; i++) {
        if (val->type == BSON_DOCUMENT) {
            if (items[i].type == BSON_DOCUMENT) {
                bson_t sub = bson_view(val->v.doc.data, val->v.doc.len);
                bson_t iv = bson_view(items[i].v.doc.data, items[i].v.doc.len);
                /* Only an evaluated, positive match pulls the element: a
                 * filter that could not be evaluated (depth overflow) must not
                 * be read as a match. */
                if (match_subfilter_d(&iv, &sub, 0) == 1) continue;
            }
        }
        if (elem_equal(&items[i], val)) continue;
        kept[nkept++] = items[i];
    }
    set_array_field(doc, key, kept, nkept);
    free(kept); free(items);
}

int bson_apply_update(bson_t* doc, const bson_t* update, int is_insert) {
    if (!doc || !update) return -1;
    size_t off = 0;
    bson_element_t op;
    while (bson_iter(update, &off, &op) == 0) {
        if (op.key[0] != '$') {
            bson_t* repl = bson_copy(update);
            free(doc->data);
            doc->data = repl->data; doc->len = repl->len; doc->cap = repl->cap;
            free(repl);
            return 0;
        }
        if (op.type != BSON_DOCUMENT) continue;
        bson_t opdoc = bson_view(op.v.doc.data, op.v.doc.len);
        size_t ooff = 0; bson_element_t fe;
        while (bson_iter(&opdoc, &ooff, &fe) == 0) {
            const char* key = fe.key;
            if (strcmp(op.key, "$set") == 0) {
                bson_set_field(doc, key, &fe, NULL);
            } else if (strcmp(op.key, "$unset") == 0) {
                bson_remove_key(doc, key);
            } else if (strcmp(op.key, "$setOnInsert") == 0) {
                if (is_insert) bson_set_field(doc, key, &fe, NULL);
            } else if (strcmp(op.key, "$inc") == 0) {
                bson_element_t cur;
                if (bson_find_path(doc, key, &cur) == 0 && elem_is_numeric(&cur)) {
                    double nv = elem_as_num(&cur) + elem_as_num(&fe);
                    bson_element_t ne;
                    if (cur.type == BSON_INT64 || fe.type == BSON_INT64) { ne.type = BSON_INT64; ne.v.i64 = (int64_t)nv; }
                    else if (cur.type == BSON_DOUBLE || fe.type == BSON_DOUBLE) { ne.type = BSON_DOUBLE; ne.v.d = nv; }
                    else { ne.type = BSON_INT32; ne.v.i32 = (int32_t)nv; }
                    bson_set_field(doc, key, &ne, NULL);
                } else {
                    bson_element_t ne;
                    if (fe.type == BSON_INT64) { ne.type = BSON_INT64; ne.v.i64 = fe.v.i64; }
                    else if (fe.type == BSON_DOUBLE) { ne.type = BSON_DOUBLE; ne.v.d = fe.v.d; }
                    else { ne.type = BSON_INT32; ne.v.i32 = fe.v.i32; }
                    bson_set_field(doc, key, &ne, NULL);
                }
            } else if (strcmp(op.key, "$mul") == 0) {
                bson_element_t cur;
                if (bson_find_path(doc, key, &cur) == 0 && elem_is_numeric(&cur)) {
                    double nv = elem_as_num(&cur) * elem_as_num(&fe);
                    bson_element_t ne;
                    if (cur.type == BSON_INT64) { ne.type = BSON_INT64; ne.v.i64 = (int64_t)nv; }
                    else if (cur.type == BSON_DOUBLE) { ne.type = BSON_DOUBLE; ne.v.d = nv; }
                    else { ne.type = BSON_INT32; ne.v.i32 = (int32_t)nv; }
                    bson_set_field(doc, key, &ne, NULL);
                } else {
                    bson_element_t z; z.type = BSON_INT32; z.v.i32 = 0;
                    bson_set_field(doc, key, &z, NULL);
                }
            } else if (strcmp(op.key, "$rename") == 0) {
                bson_element_t cur;
                if (bson_find_path(doc, key, &cur) == 0) {
                    bson_remove_key(doc, key);
                    bson_set_field(doc, fe.v.str, &cur, NULL);
                }
            } else if (strcmp(op.key, "$min") == 0) {
                bson_element_t cur;
                if (bson_find_path(doc, key, &cur) == 0 && elem_is_numeric(&cur) && elem_is_numeric(&fe)) {
                    if (elem_as_num(&fe) < elem_as_num(&cur)) bson_set_field(doc, key, &fe, NULL);
                } else bson_set_field(doc, key, &fe, NULL);
            } else if (strcmp(op.key, "$max") == 0) {
                bson_element_t cur;
                if (bson_find_path(doc, key, &cur) == 0 && elem_is_numeric(&cur) && elem_is_numeric(&fe)) {
                    if (elem_as_num(&fe) > elem_as_num(&cur)) bson_set_field(doc, key, &fe, NULL);
                } else bson_set_field(doc, key, &fe, NULL);
            } else if (strcmp(op.key, "$currentDate") == 0) {
                struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
                int64_t ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
                bson_element_t ne; ne.type = BSON_DATETIME; ne.v.i64 = ms;
                bson_set_field(doc, key, &ne, NULL);
            } else if (strcmp(op.key, "$push") == 0) {
                apply_array_push(doc, key, &fe, fe.type == BSON_DOCUMENT ? &fe : NULL);
            } else if (strcmp(op.key, "$addToSet") == 0) {
                apply_array_addtoset(doc, key, &fe, fe.type == BSON_DOCUMENT ? &fe : NULL);
            } else if (strcmp(op.key, "$pop") == 0) {
                bson_element_t existing;
                if (bson_find_path(doc, key, &existing) == 0 && existing.type == BSON_ARRAY) {
                    bson_element_t* items; size_t nitems;
                    array_to_elems(&existing, &items, &nitems);
                    int dir = (int)elem_as_num(&fe);
                    size_t newn = nitems;
                    if (nitems > 0) {
                        if (dir == 1) { newn = nitems - 1; }
                        else { memmove(items, items + 1, (nitems - 1) * sizeof(bson_element_t)); newn = nitems - 1; }
                    }
                    set_array_field(doc, key, items, newn);
                    free(items);
                }
            } else if (strcmp(op.key, "$pull") == 0) {
                apply_array_pull(doc, key, &fe);
            } else if (strcmp(op.key, "$pullAll") == 0) {
                if (fe.type == BSON_ARRAY) {
                    bson_element_t* pullitems; size_t npull;
                    array_to_elems(&fe, &pullitems, &npull);
                    bson_element_t existing;
                    if (bson_find_path(doc, key, &existing) == 0 && existing.type == BSON_ARRAY) {
                        bson_element_t* items; size_t nitems;
                        array_to_elems(&existing, &items, &nitems);
                        bson_element_t* kept = (bson_element_t*)calloc(nitems ? nitems : 1, sizeof(bson_element_t));
                        size_t nkept = 0;
                        for (size_t i = 0; i < nitems; i++) {
                            int rem = 0;
                            for (size_t j = 0; j < npull; j++) if (elem_equal(&items[i], &pullitems[j])) { rem = 1; break; }
                            if (!rem) kept[nkept++] = items[i];
                        }
                        set_array_field(doc, key, kept, nkept);
                        free(kept); free(items);
                    }
                    free(pullitems);
                }
            }
        }
    }
    return 0;
}

/* ===========================================================================
 * MongoDB wire protocol: catalog, framing, aggregation, dispatch, server
 * ---------------------------------------------------------------------------
 * Everything below implements the surface declared in
 * include/qihse_mongo_wire.h.  Authorization is a single chokepoint: no stored
 * document reaches a reply buffer except through mongo_reply_doc(), which
 * refuses a document that carries no label and a document outside the
 * principal's clearance/SCI.  Every entry point refuses a NULL principal
 * before it touches a document.
 * =========================================================================== */

/* Internal per-document labels.  A client cannot set them: every write path
 * overwrites them from the writer's authenticated clearance. */
#define MONGO_META_CLASSIF "__qihse_classif"
#define MONGO_META_SCI     "__qihse_sci"

/* MongoDB error codes used by this adapter. */
#define MONGO_ERR_BAD_VALUE       2
#define MONGO_ERR_UNAUTHORIZED    13
#define MONGO_ERR_NO_SUCH_CMD     59
#define MONGO_ERR_INVALID_NS      73
#define MONGO_ERR_NOT_IMPLEMENTED 303

/* ---- little-endian wire helpers ---- */
static int32_t mongo_rd_i32(const uint8_t* p) {
    int32_t v = 0;
    memcpy(&v, p, 4);
    return v;
}

static int64_t mongo_rd_i64(const uint8_t* p) __attribute__((unused));
static int64_t mongo_rd_i64(const uint8_t* p) {
    int64_t v = 0;
    memcpy(&v, p, 8);
    return v;
}

static void mongo_wr_i32(uint8_t* p, int32_t v) __attribute__((unused));
static void mongo_wr_i32(uint8_t* p, int32_t v) { memcpy(p, &v, 4); }
static void mongo_wr_i64(uint8_t* p, int64_t v) __attribute__((unused));
static void mongo_wr_i64(uint8_t* p, int64_t v) { memcpy(p, &v, 8); }

/* ---- reply builders ---- */
static bson_t* mongo_reply_ok(void) {
    bson_t* r = bson_create();
    if (!r) return NULL;
    bson_append_int32(r, "ok", 1);
    return r;
}

static bson_t* mongo_reply_error(int code, const char* msg) {
    bson_t* r = bson_create();
    if (!r) return NULL;
    bson_append_int32(r, "ok", 0);
    bson_append_int32(r, "code", code);
    bson_append_string(r, "errmsg", msg ? msg : "error");
    return r;
}

static void mongo_array_append(bson_t* arr, size_t idx, const bson_t* doc) {
    char key[24];
    snprintf(key, sizeof(key), "%zu", idx);
    bson_append_document(arr, key, doc);
}

/* ---- per-document labels ---- */
/* Read a document's classification.  Returns 0 only when both internal fields
 * are present and in range; an unlabelled document is refused (fail closed)
 * rather than treated as unclassified. */
static int mongo_doc_label(const bson_t* doc, uint16_t* out_classif, uint16_t* out_sci) {
    if (!doc || !out_classif || !out_sci) return -1;
    bson_element_t c, s;
    if (bson_find_element(doc, MONGO_META_CLASSIF, &c) != 0) return -1;
    if (bson_find_element(doc, MONGO_META_SCI, &s) != 0) return -1;
    if (c.type != BSON_INT32 || s.type != BSON_INT32) return -1;
    if (c.v.i32 < 0 || c.v.i32 > 0xFFFF || s.v.i32 < 0 || s.v.i32 > 0xFFFF) return -1;
    *out_classif = (uint16_t)c.v.i32;
    *out_sci = (uint16_t)s.v.i32;
    return 0;
}

/* The single authorization decision for one stored document.
 *
 * A NULL principal is refused here on purpose: qihse_auth_can_access(NULL, 0, 0)
 * returns TRUE (unclassified data is open to unauthenticated callers by design
 * in core/qihse_auth.c), so relying on the clearance check alone would make a
 * NULL context an authorization bypass for every unlabelled or unclassified
 * document. */
static int mongo_doc_visible(const bson_t* doc, const qihse_user_t* user) {
    uint16_t classif = 0, sci = 0;
    if (!user) return 0;
    if (mongo_doc_label(doc, &classif, &sci) != 0) return 0;
    return qihse_auth_can_access(user, classif, sci) ? 1 : 0;
}

/* Label a document at its writer's clearance.  Any client-supplied value for
 * the internal fields is discarded first, so a client can neither raise nor
 * lower the label of the data it writes. */
static void mongo_doc_label_for_write(bson_t* doc, const qihse_user_t* user) {
    bson_remove_key(doc, MONGO_META_CLASSIF);
    bson_remove_key(doc, MONGO_META_SCI);
    bson_append_int32(doc, MONGO_META_CLASSIF, (int32_t)qihse_user_get_classification(user));
    bson_append_int32(doc, MONGO_META_SCI, (int32_t)qihse_user_get_sci(user));
}

/* The single reply-materialisation path.  Returns a heap copy the caller owns
 * with the internal labels stripped, or NULL when the document must not be
 * disclosed. */
static bson_t* mongo_reply_doc(const bson_t* doc, const qihse_user_t* user) {
    if (!mongo_doc_visible(doc, user)) return NULL;
    bson_t* out = bson_copy(doc);
    if (!out) return NULL;
    bson_remove_key(out, MONGO_META_CLASSIF);
    bson_remove_key(out, MONGO_META_SCI);
    return out;
}

/* ---- catalog ---- */
/* A database/collection name must be non-empty and fit the fixed name field
 * (mongo_database_t.name / mongo_collection_t.name are 128 bytes). */
static int mongo_name_ok(const char* name) {
    if (!name || !name[0]) return 0;
    if (strlen(name) >= 128) return 0;
    return 1;
}

static mongo_collection_t* mongo_coll_new(const char* name) {
    mongo_collection_t* coll = (mongo_collection_t*)calloc(1, sizeof(*coll));
    if (!coll) return NULL;
    snprintf(coll->name, sizeof(coll->name), "%s", name);
    return coll;
}

static void mongo_coll_free(mongo_collection_t* coll) {
    if (!coll) return;
    for (size_t i = 0; i < coll->count; i++) bson_destroy(coll->docs[i]);
    free(coll->docs);
    free(coll);
}

static mongo_database_t* mongo_db_new(const char* name, mongo_catalog_t* owner) {
    mongo_database_t* db = (mongo_database_t*)calloc(1, sizeof(*db));
    if (!db) return NULL;
    snprintf(db->name, sizeof(db->name), "%s", name);
    db->owner = owner;
    return db;
}

static void mongo_db_free(mongo_database_t* db) {
    if (!db) return;
    for (size_t i = 0; i < db->count; i++) mongo_coll_free(db->colls[i]);
    free(db->colls);
    free(db);
}

static mongo_database_t* mongo_cat_find_db_locked(mongo_catalog_t* cat, const char* db) {
    for (size_t i = 0; i < cat->count; i++) {
        if (strcmp(cat->dbs[i]->name, db) == 0) return cat->dbs[i];
    }
    return NULL;
}

static mongo_database_t* mongo_cat_get_db_locked(mongo_catalog_t* cat, const char* db) {
    mongo_database_t* found = mongo_cat_find_db_locked(cat, db);
    if (found) return found;
    if (!mongo_name_ok(db)) return NULL;
    found = mongo_db_new(db, cat);
    if (!found) return NULL;
    if (cat->count == cat->cap) {
        size_t ncap = cat->cap ? cat->cap * 2 : 4;
        mongo_database_t** nd = (mongo_database_t**)realloc(cat->dbs, ncap * sizeof(*nd));
        if (!nd) { mongo_db_free(found); return NULL; }
        cat->dbs = nd;
        cat->cap = ncap;
    }
    cat->dbs[cat->count++] = found;
    return found;
}

static mongo_collection_t* mongo_db_find_coll_locked(mongo_database_t* db, const char* name) {
    for (size_t i = 0; i < db->count; i++) {
        if (strcmp(db->colls[i]->name, name) == 0) return db->colls[i];
    }
    return NULL;
}

static mongo_collection_t* mongo_db_get_coll_locked(mongo_database_t* db, const char* name) {
    mongo_collection_t* found = mongo_db_find_coll_locked(db, name);
    if (found) return found;
    if (!mongo_name_ok(name)) return NULL;
    found = mongo_coll_new(name);
    if (!found) return NULL;
    if (db->count == db->cap) {
        size_t ncap = db->cap ? db->cap * 2 : 4;
        mongo_collection_t** nc = (mongo_collection_t**)realloc(db->colls, ncap * sizeof(*nc));
        if (!nc) { mongo_coll_free(found); return NULL; }
        db->colls = nc;
        db->cap = ncap;
    }
    db->colls[db->count++] = found;
    return found;
}

/* Remove a collection from its database.  Returns 0 when it was present. */
static int mongo_db_remove_coll_locked(mongo_database_t* db, mongo_collection_t* coll) {
    for (size_t i = 0; i < db->count; i++) {
        if (db->colls[i] != coll) continue;
        for (size_t j = i; j + 1u < db->count; j++) db->colls[j] = db->colls[j + 1u];
        db->count--;
        mongo_coll_free(coll);
        return 0;
    }
    return -1;
}

static int mongo_cat_remove_db_locked(mongo_catalog_t* cat, mongo_database_t* db) {
    for (size_t i = 0; i < cat->count; i++) {
        if (cat->dbs[i] != db) continue;
        for (size_t j = i; j + 1u < cat->count; j++) cat->dbs[j] = cat->dbs[j + 1u];
        cat->count--;
        mongo_db_free(db);
        return 0;
    }
    return -1;
}

/* A collection handle is handed out only when the principal may read every
 * document in it: mongo_collection_t exposes its raw docs array, so a handle
 * for a collection with rows above the principal's clearance would be a read
 * primitive that bypasses the per-document check.  An empty collection has
 * nothing to disclose. */
static int mongo_coll_fully_readable(mongo_collection_t* coll, const qihse_user_t* user) {
    if (!user) return 0;
    for (size_t i = 0; i < coll->count; i++) {
        if (!mongo_doc_visible(coll->docs[i], user)) return 0;
    }
    return 1;
}

mongo_catalog_t* mongo_catalog_create(qihse_document_store_t* ds) {
    return mongo_catalog_create_auth(ds, NULL);
}

mongo_catalog_t* mongo_catalog_create_auth(qihse_document_store_t* ds, qihse_user_t* user) {
    mongo_catalog_t* cat = (mongo_catalog_t*)calloc(1, sizeof(*cat));
    if (!cat) return NULL;
    cat->doc_store = ds;
    cat->auth_user = user;
    if (pthread_mutex_init(&cat->lock, NULL) != 0) { free(cat); return NULL; }
    return cat;
}

int mongo_catalog_bind_user(mongo_catalog_t* cat, qihse_user_t* user) {
    if (!cat) return -1;
    pthread_mutex_lock(&cat->lock);
    cat->auth_user = user;
    pthread_mutex_unlock(&cat->lock);
    return 0;
}

qihse_user_t* mongo_catalog_get_user(const mongo_catalog_t* cat) {
    if (!cat) return NULL;
    pthread_mutex_lock(&((mongo_catalog_t*)cat)->lock);
    qihse_user_t* user = cat->auth_user;
    pthread_mutex_unlock(&((mongo_catalog_t*)cat)->lock);
    return user;
}

void mongo_catalog_destroy(mongo_catalog_t* cat) {
    if (!cat) return;
    for (size_t i = 0; i < cat->count; i++) mongo_db_free(cat->dbs[i]);
    free(cat->dbs);
    pthread_mutex_destroy(&cat->lock);
    free(cat);
}

mongo_database_t* mongo_catalog_get_db(mongo_catalog_t* cat, const char* db) {
    if (!cat || !db) return NULL;
    pthread_mutex_lock(&cat->lock);
    qihse_user_t* user = cat->auth_user;
    mongo_database_t* found = user ? mongo_cat_find_db_locked(cat, db) : NULL;
    if (found) {
        for (size_t i = 0; i < found->count; i++) {
            if (!mongo_coll_fully_readable(found->colls[i], user)) { found = NULL; break; }
        }
    }
    pthread_mutex_unlock(&cat->lock);
    return found;
}

mongo_collection_t* mongo_db_get_collection(mongo_database_t* db, const char* name) {
    if (!db || !name) return NULL;
    mongo_catalog_t* cat = (mongo_catalog_t*)db->owner;
    if (!cat) return NULL;   /* detached database: no authenticated context */
    pthread_mutex_lock(&cat->lock);
    qihse_user_t* user = cat->auth_user;
    mongo_collection_t* found = user ? mongo_db_find_coll_locked(db, name) : NULL;
    if (found && !mongo_coll_fully_readable(found, user)) found = NULL;
    pthread_mutex_unlock(&cat->lock);
    return found;
}

mongo_collection_t* mongo_catalog_get_collection(mongo_catalog_t* cat, const char* db, const char* coll) {
    if (!cat || !db || !coll) return NULL;
    pthread_mutex_lock(&cat->lock);
    qihse_user_t* user = cat->auth_user;
    mongo_collection_t* found = NULL;
    if (user) {
        mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
        if (d) {
            found = mongo_db_find_coll_locked(d, coll);
            if (found && !mongo_coll_fully_readable(found, user)) found = NULL;
        }
    }
    pthread_mutex_unlock(&cat->lock);
    return found;
}

int mongo_catalog_drop_collection(mongo_catalog_t* cat, const char* db, const char* coll) {
    if (!cat || !db || !coll) return -1;
    pthread_mutex_lock(&cat->lock);
    qihse_user_t* user = cat->auth_user;
    int rc = -1;
    if (user) {
        mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
        mongo_collection_t* c = d ? mongo_db_find_coll_locked(d, coll) : NULL;
        /* Dropping is destructive and unobservable afterwards, so it requires
         * the same "every document is readable" rule as handing out a handle:
         * a principal cannot destroy data it is not cleared to read. */
        if (c && mongo_coll_fully_readable(c, user)) rc = mongo_db_remove_coll_locked(d, c);
    }
    pthread_mutex_unlock(&cat->lock);
    return rc;
}

/* ---- message framing ---- */
static int mongo_op_supported(int32_t opcode) {
    switch (opcode) {
        case MONGO_OP_REPLY:
        case MONGO_OP_MSG_LEGACY:
        case MONGO_OP_UPDATE:
        case MONGO_OP_INSERT:
        case MONGO_OP_QUERY:
        case MONGO_OP_GET_MORE:
        case MONGO_OP_DELETE:
        case MONGO_OP_KILL_CURSORS:
        case MONGO_OP_MSG:
            return 1;
        default:
            /* OP_COMPRESSED (2012) included: compression is not implemented,
             * so the frame is refused rather than guessed at. */
            return 0;
    }
}

/* Length of the NUL-terminated string at buf[off], or -1 when no NUL is
 * present before limit. */
static long mongo_cstr_len(const uint8_t* buf, size_t limit, size_t off) {
    if (off >= limit) return -1;
    const void* nul = memchr(buf + off, 0, limit - off);
    if (!nul) return -1;
    return (long)((const uint8_t*)nul - (buf + off));
}

/* Validate one BSON document at buf[off]: it must declare a size that fits in
 * the bytes present, be NUL-terminated, and walk cleanly (every inner length
 * checked against the document's own bytes).  Returns the document's size or
 * -1. */
static long mongo_doc_size(const uint8_t* buf, size_t limit, size_t off) {
    if (off + 5u > limit) return -1;
    int32_t dlen = mongo_rd_i32(buf + off);
    if (dlen < 5) return -1;
    if ((uint32_t)dlen > MONGO_MAX_BSON_SIZE) return -1;
    if ((size_t)dlen > limit - off) return -1;
    if (buf[off + (size_t)dlen - 1u] != 0x00) return -1;
    bson_t view;
    view.data = (uint8_t*)(uintptr_t)(const void*)(buf + off);
    view.len = (size_t)dlen;
    view.cap = (size_t)dlen;
    size_t walk = 0;
    bson_element_t e;
    while (bson_iter(&view, &walk, &e) == 0) { }
    /* A clean walk stops on the terminator, which is the last byte. */
    if (walk != (size_t)dlen - 1u) return -1;
    return dlen;
}

/* Body offset of the first document, per opcode. */
static long mongo_first_doc_offset(const mongo_msg_t* msg) {
    const uint8_t* b = msg->body;
    size_t n = msg->body_len;
    size_t off = 4;
    switch (msg->opcode) {
        case MONGO_OP_MSG:
            return 5;   /* flags(4) + section kind(1) */
        case MONGO_OP_MSG_LEGACY:
            return 4;   /* flags(4) */
        case MONGO_OP_REPLY:
            /* responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) */
            return 20;
        case MONGO_OP_INSERT:
            if (mongo_cstr_len(b, n, 4) < 0) return -1;
            off = 4u + (size_t)mongo_cstr_len(b, n, 4) + 1u;
            return (long)off;
        case MONGO_OP_UPDATE:
        case MONGO_OP_DELETE:
            if (mongo_cstr_len(b, n, 4) < 0) return -1;
            off = 4u + (size_t)mongo_cstr_len(b, n, 4) + 1u;
            return (long)off;
        case MONGO_OP_QUERY:
            if (mongo_cstr_len(b, n, 4) < 0) return -1;
            off = 4u + (size_t)mongo_cstr_len(b, n, 4) + 1u;
            if (off + 8u > n) return -1;
            return (long)(off + 8u);
        case MONGO_OP_GET_MORE:
            if (mongo_cstr_len(b, n, 4) < 0) return -1;
            off = 4u + (size_t)mongo_cstr_len(b, n, 4) + 1u;
            if (off + 4u > n) return -1;
            return (long)(off + 4u);
        default:
            return -1;
    }
}

int mongo_msg_parse(const uint8_t* data, size_t len, mongo_msg_t* out) {
    if (!data || !out) return -1;
    if (len < 16u) return -1;
    int32_t msg_len = mongo_rd_i32(data);
    /* The declared length is attacker controlled: it must fit in the bytes
     * actually present, and it must be at least the header. */
    if (msg_len < 16) return -1;
    if ((uint32_t)msg_len > MONGO_MAX_MESSAGE_SIZE) return -1;
    if ((size_t)msg_len > len) return -1;
    int32_t opcode = mongo_rd_i32(data + 12);
    if (!mongo_op_supported(opcode)) return -1;

    mongo_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.message_length = msg_len;
    msg.request_id = mongo_rd_i32(data + 4);
    msg.response_to = mongo_rd_i32(data + 8);
    msg.opcode = opcode;
    msg.body = data + 16;
    msg.body_len = (size_t)msg_len - 16u;

    /* Per-opcode structure, validated before the body is exposed to a caller. */
    if (opcode == MONGO_OP_MSG) {
        if (msg.body_len < 5u) return -1;
        int32_t flags = mongo_rd_i32(msg.body);
        if ((flags & 0x1) != 0) return -1;        /* checksumPresent: no CRC32C */
        if ((flags & 0xFFFF) != 0) return -1;     /* unknown required flags */
        if (msg.body[4] != 0) return -1;          /* only kind-0 sections */
        if (mongo_doc_size(msg.body, msg.body_len, 5) < 0) return -1;
    } else if (opcode == MONGO_OP_QUERY) {
        if (msg.body_len < 4u) return -1;
        long off = mongo_first_doc_offset(&msg);
        if (off < 0) return -1;
        if (mongo_doc_size(msg.body, msg.body_len, (size_t)off) < 0) return -1;
    } else if (opcode == MONGO_OP_INSERT || opcode == MONGO_OP_UPDATE ||
               opcode == MONGO_OP_DELETE) {
        if (msg.body_len < 4u) return -1;
        long off = mongo_first_doc_offset(&msg);
        if (off < 0) return -1;
        if (mongo_doc_size(msg.body, msg.body_len, (size_t)off) < 0) return -1;
    } else if (opcode == MONGO_OP_GET_MORE) {
        if (msg.body_len < 4u) return -1;
        long off = mongo_first_doc_offset(&msg);
        if (off < 0) return -1;
    } else if (opcode == MONGO_OP_KILL_CURSORS) {
        if (msg.body_len < 8u) return -1;
    } else if (opcode == MONGO_OP_REPLY) {
        /* responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) */
        if (msg.body_len < 20u) return -1;
    } else if (opcode == MONGO_OP_MSG_LEGACY) {
        if (msg.body_len < 4u) return -1;
    }
    *out = msg;
    return 0;
}

bson_t* mongo_msg_get_document(const mongo_msg_t* msg, size_t* offset) {
    if (!msg || !offset || !msg->body) return NULL;
    size_t off = *offset;
    if (off == 0) {
        long first = mongo_first_doc_offset(msg);
        if (first < 0) return NULL;
        off = (size_t)first;
    }
    long dlen = mongo_doc_size(msg->body, msg->body_len, off);
    if (dlen < 0) return NULL;
    bson_t view;
    view.data = (uint8_t*)(uintptr_t)(const void*)(msg->body + off);
    view.len = (size_t)dlen;
    view.cap = (size_t)dlen;
    bson_t* out = bson_copy(&view);
    if (!out) return NULL;
    *offset = off + (size_t)dlen;
    return out;
}

/* ===========================================================================
 * Query helpers: candidate selection, sort, projection
 * =========================================================================== */

/* Copy one element verbatim (type byte, key, value bytes).  Used instead of
 * bson_append_element(), which loses DECIMAL128 and TIMESTAMP values, on every
 * path that must not alter a document's bytes. */
static void mongo_raw_copy_elem_key(bson_t* dst, const char* key, const raw_elem_t* re) {
    bson_append_type_and_key(dst, (uint8_t)re->type, key);
    bson_ensure(dst, re->value_len);
    memcpy(dst->data + dst->len, re->value_ptr, re->value_len);
    dst->len += re->value_len;
}

static void mongo_raw_copy_elem(bson_t* dst, const raw_elem_t* re) {
    mongo_raw_copy_elem_key(dst, re->key, re);
}

/* Append one value (not a document) to an array under its index key.  A
 * non-dotted path is copied verbatim; a dotted path falls back to
 * bson_append_element(). */
static void mongo_array_append_value(bson_t* arr, size_t idx, const bson_t* doc,
                                     const char* path, const bson_element_t* fallback) {
    char key[24];
    snprintf(key, sizeof(key), "%zu", idx);
    if (path && !strchr(path, '.')) {
        size_t off = 0;
        raw_elem_t re;
        while (bson_raw_iter(doc, &off, &re) == 0) {
            if (strcmp(re.key, path) == 0) {
                mongo_raw_copy_elem_key(arr, key, &re);
                return;
            }
        }
    }
    bson_append_element(arr, key, fallback, NULL);
}

/* Documents of coll that the principal may read and that match filter, in
 * storage order.  Returns a heap array of borrowed pointers (the collection
 * keeps ownership) and sets *out_count; NULL with *out_count == 0 on
 * allocation failure.
 *
 * The clearance check runs BEFORE the filter, so a filter can never be used to
 * probe for the existence of a document outside the principal's clearance. */
static bson_t** mongo_coll_query_locked(mongo_collection_t* coll, const qihse_user_t* user,
                                        const bson_t* filter, size_t* out_count) {
    bson_t** hits = NULL;
    size_t n = 0, cap = 0;
    if (out_count) *out_count = 0;
    if (!coll || !user) return NULL;
    for (size_t i = 0; i < coll->count; i++) {
        bson_t* doc = coll->docs[i];
        if (!mongo_doc_visible(doc, user)) continue;
        if (filter && !bson_match(doc, filter)) continue;
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            bson_t** nh = (bson_t**)realloc(hits, ncap * sizeof(*nh));
            if (!nh) { free(hits); return NULL; }
            hits = nh;
            cap = ncap;
        }
        hits[n++] = doc;
    }
    if (out_count) *out_count = n;
    return hits;
}

/* Stable sort of a borrowed document array by a sort document
 * ({field: 1|-1, ...}).  qsort_r's context carries the sort document, so no
 * global state is involved and the sort is safe for concurrent connections. */
static int mongo_sort_cmp(const void* pa, const void* pb, void* arg) {
    const bson_t* sort = (const bson_t*)arg;
    const bson_t* da = *(const bson_t* const*)pa;
    const bson_t* db = *(const bson_t* const*)pb;
    size_t off = 0;
    bson_element_t k;
    while (bson_iter(sort, &off, &k) == 0) {
        int dir = (int)elem_as_num(&k);
        bson_element_t ea, eb;
        int ha = (bson_find_path(da, k.key, &ea) == 0);
        int hb = (bson_find_path(db, k.key, &eb) == 0);
        int c;
        if (!ha && !hb) continue;
        if (!ha) c = -1;
        else if (!hb) c = 1;
        else c = elem_cmp(&ea, &eb);
        if (c != 0) return (dir < 0) ? -c : c;
    }
    return 0;
}

static void mongo_apply_sort(bson_t** docs, size_t n, const bson_t* sort) {
    if (!sort || n < 2) return;
    size_t off = 0;
    bson_element_t k;
    if (bson_iter(sort, &off, &k) != 0) return;
    qsort_r(docs, n, sizeof(*docs), mongo_sort_cmp, (void*)sort);
}

/* Projection.  proj is the client's projection document; NULL/empty means "the
 * whole document".  Returns a new document with the internal labels stripped,
 * or NULL when the projection is not one this adapter implements (a computed
 * projection, or a mixture of inclusion and exclusion). */
static bson_t* mongo_project_raw(const bson_t* doc, const bson_t* proj) {
    if (!doc) return NULL;
    if (!proj) {
        bson_t* out = bson_copy(doc);
        if (!out) return NULL;
        bson_remove_key(out, MONGO_META_CLASSIF);
        bson_remove_key(out, MONGO_META_SCI);
        return out;
    }
    int inclusion = 0, exclusion = 0;
    int id_excluded = 0;
    size_t off = 0;
    bson_element_t p;
    while (bson_iter(proj, &off, &p) == 0) {
        int on = (p.type == BSON_BOOL) ? p.v.b : ((int)elem_as_num(&p) != 0);
        if (p.type != BSON_BOOL && !elem_is_numeric(&p)) return NULL;  /* computed */
        if (strcmp(p.key, "_id") == 0) { if (!on) id_excluded = 1; }
        else if (on) inclusion = 1;
        else exclusion = 1;
    }
    if (inclusion && exclusion) return NULL;
    bson_t* out = bson_create();
    if (!out) return NULL;
    if (inclusion) {
        int want_id = !id_excluded;
        size_t ioff = 0;
        raw_elem_t re;
        if (want_id) {
            bson_element_t id;
            if (bson_find_element(doc, "_id", &id) == 0) {
                /* raw copy of _id */
                while (bson_raw_iter(doc, &ioff, &re) == 0) {
                    if (strcmp(re.key, "_id") == 0) { mongo_raw_copy_elem(out, &re); break; }
                }
            }
        }
        off = 0;
        while (bson_iter(proj, &off, &p) == 0) {
            if (strcmp(p.key, "_id") == 0) continue;
            int on = (p.type == BSON_BOOL) ? p.v.b : ((int)elem_as_num(&p) != 0);
            if (!on) continue;
            ioff = 0;
            while (bson_raw_iter(doc, &ioff, &re) == 0) {
                if (strcmp(re.key, p.key) == 0) { mongo_raw_copy_elem(out, &re); break; }
            }
        }
    } else {
        size_t doff = 0;
        raw_elem_t re;
        while (bson_raw_iter(doc, &doff, &re) == 0) {
            if (strcmp(re.key, MONGO_META_CLASSIF) == 0) continue;
            if (strcmp(re.key, MONGO_META_SCI) == 0) continue;
            int drop = 0;
            off = 0;
            while (bson_iter(proj, &off, &p) == 0) {
                if (strcmp(p.key, re.key) == 0) { drop = 1; break; }
            }
            if (drop) continue;
            mongo_raw_copy_elem(out, &re);
        }
    }
    return out;
}

/* ===========================================================================
 * Aggregation pipeline
 * =========================================================================== */
static void mongo_docs_free(bson_t** docs, size_t n) {
    if (!docs) return;
    for (size_t i = 0; i < n; i++) bson_destroy(docs[i]);
    free(docs);
}

static bson_t** mongo_docs_push(bson_t** docs, size_t* n, size_t* cap, bson_t* doc) {
    if (*n == *cap) {
        size_t ncap = *cap ? *cap * 2 : 8;
        bson_t** nd = (bson_t**)realloc(docs, ncap * sizeof(*nd));
        if (!nd) return NULL;
        docs = nd;
        *cap = ncap;
    }
    docs[(*n)++] = doc;
    return docs;
}

/* Evaluate a $group / $project style value expression.  Only a "$path"
 * reference and a literal are supported; anything else is refused. */
static int mongo_expr_value(const bson_t* doc, const bson_element_t* expr, bson_element_t* out) {
    if (expr->type == BSON_STRING && expr->v.str[0] == '$') {
        if (bson_find_path(doc, expr->v.str + 1, out) != 0) return -1;
        return 0;
    }
    *out = *expr;
    return 0;
}

/* Build the group key document for a $group _id expression, plus an owned
 * document holding the key value to emit as "_id" (under the key "v"). */
static int mongo_group_key(const bson_t* doc, const bson_element_t* id_expr,
                           bson_t** out_key, bson_t** out_id) {
    bson_t* key = bson_create();
    bson_t* idv = bson_create();
    if (!key || !idv) { bson_destroy(key); bson_destroy(idv); return -1; }
    if (id_expr->type == BSON_DOCUMENT) {
        bson_t spec = bson_view(id_expr->v.doc.data, id_expr->v.doc.len);
        bson_t* id_doc = bson_create();
        if (!id_doc) { bson_destroy(key); bson_destroy(idv); return -1; }
        size_t off = 0;
        bson_element_t f;
        while (bson_iter(&spec, &off, &f) == 0) {
            bson_element_t v;
            if (mongo_expr_value(doc, &f, &v) != 0) {
                bson_destroy(key); bson_destroy(idv); bson_destroy(id_doc);
                return -1;
            }
            bson_append_element(key, f.key, &v, NULL);
            bson_append_element(id_doc, f.key, &v, NULL);
        }
        bson_element_t id_el;
        memset(&id_el, 0, sizeof(id_el));
        id_el.type = BSON_DOCUMENT;
        id_el.v.doc.data = id_doc->data;
        id_el.v.doc.len = (int32_t)id_doc->len;
        bson_append_element(idv, "v", &id_el, NULL);
        bson_destroy(id_doc);
        *out_id = idv;
        *out_key = key;
        return 0;
    }
    bson_element_t v;
    if (mongo_expr_value(doc, id_expr, &v) != 0) {
        bson_destroy(key); bson_destroy(idv);
        return -1;
    }
    bson_append_element(key, "k", &v, NULL);
    bson_append_element(idv, "v", &v, NULL);
    *out_id = idv;
    *out_key = key;
    return 0;
}

/* Accumulate one $group field for one input document. */
static int mongo_group_accumulate(bson_t* acc, const char* field, const bson_element_t* spec,
                                  const bson_t* doc) {
    if (spec->type != BSON_DOCUMENT) return -1;
    bson_t s = bson_view(spec->v.doc.data, spec->v.doc.len);
    size_t off = 0;
    bson_element_t op;
    if (bson_iter(&s, &off, &op) != 0) return -1;
    bson_element_t v;
    if (mongo_expr_value(doc, &op, &v) != 0) return -1;
    bson_element_t cur;
    int have = (bson_find_element(acc, field, &cur) == 0);
    if (strcmp(op.key, "$sum") == 0) {
        double sum = have ? elem_as_num(&cur) : 0.0;
        sum += elem_as_num(&v);
        bson_element_t ne;
        ne.type = BSON_DOUBLE; ne.v.d = sum;
        if (have) bson_set_field(acc, field, &ne, NULL);
        else bson_append_double(acc, field, sum);
    } else if (strcmp(op.key, "$avg") == 0) {
        double sum = have ? elem_as_num(&cur) : 0.0;
        bson_element_t cnt;
        double count = 0.0;
        char ckey[160];
        snprintf(ckey, sizeof(ckey), "%s__n", field);
        if (bson_find_element(acc, ckey, &cnt) == 0) count = elem_as_num(&cnt);
        sum += elem_as_num(&v);
        count += 1.0;
        bson_element_t ne;
        ne.type = BSON_DOUBLE; ne.v.d = sum;
        if (have) bson_set_field(acc, field, &ne, NULL);
        else bson_append_double(acc, field, sum);
        ne.v.d = count;
        bson_element_t have_cnt;
        if (bson_find_element(acc, ckey, &have_cnt) == 0) bson_set_field(acc, ckey, &ne, NULL);
        else bson_append_double(acc, ckey, count);
    } else if (strcmp(op.key, "$min") == 0) {
        if (!have) bson_append_element(acc, field, &v, NULL);
        else if (elem_cmp(&v, &cur) < 0) bson_set_field(acc, field, &v, NULL);
    } else if (strcmp(op.key, "$max") == 0) {
        if (!have) bson_append_element(acc, field, &v, NULL);
        else if (elem_cmp(&v, &cur) > 0) bson_set_field(acc, field, &v, NULL);
    } else if (strcmp(op.key, "$first") == 0) {
        if (!have) bson_append_element(acc, field, &v, NULL);
    } else if (strcmp(op.key, "$last") == 0) {
        if (have) bson_set_field(acc, field, &v, NULL);
        else bson_append_element(acc, field, &v, NULL);
    } else if (strcmp(op.key, "$push") == 0) {
        bson_t* arr = bson_create();
        if (!arr) return -1;
        if (have && cur.type == BSON_ARRAY) {
            bson_t prev = bson_view(cur.v.doc.data, cur.v.doc.len);
            size_t poff = 0;
            raw_elem_t re;
            while (bson_raw_iter(&prev, &poff, &re) == 0) mongo_raw_copy_elem(arr, &re);
        }
        bson_element_t item = v;
        bson_append_element(arr, "0", &item, NULL);
        bson_element_t arr_el;
        memset(&arr_el, 0, sizeof(arr_el));
        arr_el.type = BSON_ARRAY;
        arr_el.v.doc.data = arr->data;
        arr_el.v.doc.len = (int32_t)arr->len;
        if (have) bson_set_field(acc, field, &arr_el, NULL);
        else bson_append_element(acc, field, &arr_el, NULL);
        bson_destroy(arr);
    } else {
        return -1;   /* accumulator not implemented: refuse the whole stage */
    }
    return 0;
}

/* One aggregation stage over an owned document array.  On success the out
 * parameters are the next stage's input and the previous array is freed; on
 * failure the stage returns -1 and the caller frees both arrays. */
static int mongo_stage_run(bson_t** in, size_t n_in, const bson_t* stage,
                           bson_t*** out, size_t* out_n) {
    *out = NULL;
    *out_n = 0;
    size_t soff = 0;
    bson_element_t s;
    if (bson_iter(stage, &soff, &s) != 0) return -1;
    if (strcmp(s.key, "$match") == 0) {
        if (s.type != BSON_DOCUMENT) return -1;
        bson_t f = bson_view(s.v.doc.data, s.v.doc.len);
        bson_t** res = NULL;
        size_t n = 0, cap = 0;
        for (size_t i = 0; i < n_in; i++) {
            if (bson_match(in[i], &f) != 1) { bson_destroy(in[i]); continue; }
            res = mongo_docs_push(res, &n, &cap, in[i]);
            if (!res) return -1;
        }
        free(in);
        *out = res;
        *out_n = n;
        return 0;
    }
    if (strcmp(s.key, "$limit") == 0) {
        size_t lim = (size_t)((int)elem_as_num(&s));
        for (size_t i = lim; i < n_in; i++) bson_destroy(in[i]);
        if (lim < n_in) n_in = lim;
        *out = in;
        *out_n = n_in;
        return 0;
    }
    if (strcmp(s.key, "$skip") == 0) {
        size_t skip = (size_t)((int)elem_as_num(&s));
        if (skip > n_in) skip = n_in;
        for (size_t i = 0; i < skip; i++) bson_destroy(in[i]);
        bson_t** res = (bson_t**)malloc((n_in - skip ? n_in - skip : 1) * sizeof(*res));
        if (!res) return -1;
        for (size_t i = skip; i < n_in; i++) res[i - skip] = in[i];
        free(in);
        *out = res;
        *out_n = n_in - skip;
        return 0;
    }
    if (strcmp(s.key, "$sort") == 0) {
        if (s.type != BSON_DOCUMENT) return -1;
        bson_t sort = bson_view(s.v.doc.data, s.v.doc.len);
        mongo_apply_sort(in, n_in, &sort);
        *out = in;
        *out_n = n_in;
        return 0;
    }
    if (strcmp(s.key, "$count") == 0) {
        if (s.type != BSON_STRING) return -1;
        bson_t* one = bson_create();
        if (!one) return -1;
        bson_append_int32(one, s.v.str, (int32_t)n_in);
        for (size_t i = 0; i < n_in; i++) bson_destroy(in[i]);
        free(in);
        bson_t** res = (bson_t**)malloc(sizeof(*res));
        if (!res) { bson_destroy(one); return -1; }
        res[0] = one;
        *out = res;
        *out_n = 1;
        return 0;
    }
    if (strcmp(s.key, "$project") == 0) {
        if (s.type != BSON_DOCUMENT) return -1;
        bson_t proj = bson_view(s.v.doc.data, s.v.doc.len);
        bson_t** res = NULL;
        size_t n = 0, cap = 0;
        for (size_t i = 0; i < n_in; i++) {
            bson_t* p = mongo_project_raw(in[i], &proj);
            bson_destroy(in[i]);
            if (!p) { mongo_docs_free(res, n); free(in); return -1; }
            res = mongo_docs_push(res, &n, &cap, p);
            if (!res) { bson_destroy(p); free(in); return -1; }
        }
        free(in);
        *out = res;
        *out_n = n;
        return 0;
    }
    if (strcmp(s.key, "$unwind") == 0) {
        const char* path = NULL;
        int preserve = 0;
        if (s.type == BSON_STRING) path = s.v.str;
        else if (s.type == BSON_DOCUMENT) {
            bson_t spec = bson_view(s.v.doc.data, s.v.doc.len);
            bson_element_t pe, pr;
            if (bson_find_element(&spec, "path", &pe) == 0 && pe.type == BSON_STRING) path = pe.v.str;
            if (bson_find_element(&spec, "preserveNullAndEmptyArrays", &pr) == 0) preserve = (pr.type == BSON_BOOL) ? pr.v.b : 0;
        }
        if (!path || path[0] != '$') return -1;
        bson_t** res = NULL;
        size_t n = 0, cap = 0;
        for (size_t i = 0; i < n_in; i++) {
            bson_element_t f;
            if (bson_find_path(in[i], path + 1, &f) != 0 || f.type != BSON_ARRAY) {
                if (preserve) { res = mongo_docs_push(res, &n, &cap, in[i]); if (!res) { free(in); return -1; } }
                else bson_destroy(in[i]);
                continue;
            }
            bson_t arr = bson_view(f.v.doc.data, f.v.doc.len);
            size_t aoff = 0;
            bson_element_t item;
            int emitted = 0;
            while (bson_iter(&arr, &aoff, &item) == 0) {
                bson_t* copy = bson_copy(in[i]);
                if (!copy) { mongo_docs_free(res, n); free(in); return -1; }
                bson_set_field(copy, path + 1, &item, NULL);
                res = mongo_docs_push(res, &n, &cap, copy);
                if (!res) { bson_destroy(copy); free(in); return -1; }
                emitted = 1;
            }
            if (!emitted && preserve) { res = mongo_docs_push(res, &n, &cap, in[i]); if (!res) { free(in); return -1; } }
            else bson_destroy(in[i]);
        }
        free(in);
        *out = res;
        *out_n = n;
        return 0;
    }
    if (strcmp(s.key, "$group") == 0) {
        if (s.type != BSON_DOCUMENT) return -1;
        bson_t spec = bson_view(s.v.doc.data, s.v.doc.len);
        bson_element_t id_expr;
        if (bson_find_element(&spec, "_id", &id_expr) != 0) return -1;
        /* group key documents, accumulated values, and the key value to emit */
        bson_t** keys = NULL;
        bson_t** accs = NULL;
        bson_t** ids = NULL;
        size_t n_groups = 0, cap_groups = 0;
        int rc = 0;
        for (size_t i = 0; i < n_in && rc == 0; i++) {
            bson_t* key = NULL;
            bson_t* idv = NULL;
            if (mongo_group_key(in[i], &id_expr, &key, &idv) != 0) { rc = -1; break; }
            size_t g = 0;
            for (; g < n_groups; g++) {
                if (keys[g]->len == key->len && memcmp(keys[g]->data, key->data, key->len) == 0) break;
            }
            if (g == n_groups) {
                if (n_groups == cap_groups) {
                    size_t ncap = cap_groups ? cap_groups * 2 : 8;
                    bson_t** nk = (bson_t**)realloc(keys, ncap * sizeof(*nk));
                    bson_t** na = (bson_t**)realloc(accs, ncap * sizeof(*na));
                    bson_t** ni = (bson_t**)realloc(ids, ncap * sizeof(*ni));
                    if (!nk || !na || !ni) {
                        if (nk) keys = nk;
                        if (na) accs = na;
                        if (ni) ids = ni;
                        bson_destroy(key); bson_destroy(idv);
                        rc = -1;
                        break;
                    }
                    keys = nk; accs = na; ids = ni; cap_groups = ncap;
                }
                bson_t* acc = bson_create();
                if (!acc) { bson_destroy(key); bson_destroy(idv); rc = -1; break; }
                keys[n_groups] = key;
                accs[n_groups] = acc;
                ids[n_groups] = idv;
                n_groups++;
            } else {
                bson_destroy(key);
                bson_destroy(idv);
            }
            /* accumulate every non-_id field */
            size_t goff = 0;
            bson_element_t gs;
            while (rc == 0 && bson_iter(&spec, &goff, &gs) == 0) {
                if (strcmp(gs.key, "_id") == 0) continue;
                if (mongo_group_accumulate(accs[g], gs.key, &gs, in[i]) != 0) rc = -1;
            }
        }
        for (size_t i = 0; i < n_in; i++) bson_destroy(in[i]);
        free(in);
        if (rc != 0) {
            mongo_docs_free(keys, n_groups);
            mongo_docs_free(accs, n_groups);
            mongo_docs_free(ids, n_groups);
            return -1;
        }
        bson_t** res = (bson_t**)malloc((n_groups ? n_groups : 1) * sizeof(*res));
        if (!res) {
            mongo_docs_free(keys, n_groups);
            mongo_docs_free(accs, n_groups);
            mongo_docs_free(ids, n_groups);
            return -1;
        }
        size_t n = 0;
        for (size_t g = 0; g < n_groups; g++) {
            bson_t* outdoc = bson_create();
            if (!outdoc) { mongo_docs_free(res, n); rc = -1; break; }
            bson_element_t idval;
            if (bson_find_element(ids[g], "v", &idval) == 0) {
                bson_append_element(outdoc, "_id", &idval, NULL);
            }
            /* The $avg accumulator keeps the running sum in <field> and the
             * running count in <field>__n; the counter is private and the sum
             * is turned into the average below. */
            size_t aoff = 0;
            raw_elem_t re;
            while (bson_raw_iter(accs[g], &aoff, &re) == 0) {
                size_t l = strlen(re.key);
                if (l > 3u && strcmp(re.key + l - 3u, "__n") == 0) continue;
                mongo_raw_copy_elem(outdoc, &re);
            }
            aoff = 0;
            while (bson_raw_iter(accs[g], &aoff, &re) == 0) {
                size_t l = strlen(re.key);
                if (l <= 3u || strcmp(re.key + l - 3u, "__n") != 0) continue;
                if (l - 3u >= 128u) continue;
                char base[128];
                memcpy(base, re.key, l - 3u);
                base[l - 3u] = '\0';
                bson_element_t sum_el;
                if (bson_find_element(accs[g], base, &sum_el) != 0) continue;
                double count = 0.0;
                memcpy(&count, re.value_ptr, sizeof(count));
                bson_element_t ne;
                ne.type = BSON_DOUBLE;
                ne.v.d = (count != 0.0) ? (elem_as_num(&sum_el) / count) : 0.0;
                bson_set_field(outdoc, base, &ne, NULL);
            }
            res[n++] = outdoc;
        }
        mongo_docs_free(keys, n_groups);
        mongo_docs_free(accs, n_groups);
        mongo_docs_free(ids, n_groups);
        if (rc != 0) { mongo_docs_free(res, n); return -1; }
        *out = res;
        *out_n = n;
        return 0;
    }
    /* $lookup, $facet, $graphLookup, $out, ... are not implemented: refuse the
     * stage instead of silently dropping it and returning a wrong answer. */
    return -1;
}

/* ===========================================================================
 * Command dispatch
 * =========================================================================== */
static const char* mongo_arg_str(const bson_t* cmd, const char* key) {
    bson_element_t e;
    if (!cmd || !key) return NULL;
    if (bson_find_element(cmd, key, &e) != 0) return NULL;
    return (e.type == BSON_STRING) ? e.v.str : NULL;
}

/* A document-valued argument.  Returns 0 and fills *view on success. */
static int mongo_arg_doc(const bson_t* cmd, const char* key, bson_t* view) {
    bson_element_t e;
    if (!cmd || !key || !view) return -1;
    if (bson_find_element(cmd, key, &e) != 0) return -1;
    if (e.type != BSON_DOCUMENT) return -1;
    *view = bson_view(e.v.doc.data, e.v.doc.len);
    return 0;
}

static int mongo_arg_i64(const bson_t* cmd, const char* key, int64_t* out) {
    bson_element_t e;
    if (!cmd || !key || !out) return -1;
    if (bson_find_element(cmd, key, &e) != 0) return -1;
    if (!elem_is_numeric(&e)) return -1;
    *out = (int64_t)elem_as_num(&e);
    return 0;
}

static int mongo_coll_add_locked(mongo_collection_t* coll, bson_t* doc) {
    if (!coll || !doc) return -1;
    if (coll->count == coll->cap) {
        size_t ncap = coll->cap ? coll->cap * 2 : 4;
        bson_t** nd = (bson_t**)realloc(coll->docs, ncap * sizeof(*nd));
        if (!nd) return -1;
        coll->docs = nd;
        coll->cap = ncap;
    }
    coll->docs[coll->count++] = doc;
    return 0;
}

static void mongo_coll_remove_at_locked(mongo_collection_t* coll, size_t idx) {
    if (!coll || idx >= coll->count) return;
    bson_destroy(coll->docs[idx]);
    for (size_t j = idx; j + 1u < coll->count; j++) coll->docs[j] = coll->docs[j + 1u];
    coll->count--;
}

/* Indices of the documents of coll that the principal may read and that match
 * filter.  Indices (not pointers) are returned so an update or a delete can
 * mutate the collection without invalidating the result. */
static size_t* mongo_coll_match_indices_locked(mongo_collection_t* coll, const qihse_user_t* user,
                                               const bson_t* filter, size_t* out_n) {
    size_t* hits = NULL;
    size_t n = 0, cap = 0;
    if (out_n) *out_n = 0;
    if (!coll || !user) return NULL;
    for (size_t i = 0; i < coll->count; i++) {
        if (!mongo_doc_visible(coll->docs[i], user)) continue;
        if (filter && !bson_match(coll->docs[i], filter)) continue;
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            size_t* nh = (size_t*)realloc(hits, ncap * sizeof(*nh));
            if (!nh) { free(hits); return NULL; }
            hits = nh;
            cap = ncap;
        }
        hits[n++] = i;
    }
    if (out_n) *out_n = n;
    return hits;
}

/* ---- read commands ---- */
static bson_t* mongo_cmd_find(mongo_catalog_t* cat, qihse_user_t* user, const char* db,
                              const bson_t* cmd, const char* coll_name) {
    char ns[300];
    snprintf(ns, sizeof(ns), "%s.%s", db, coll_name);
    /* A read never creates a database or a collection: a missing namespace is
     * an empty result, not a mutation. */
    mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
    mongo_collection_t* coll = d ? mongo_db_find_coll_locked(d, coll_name) : NULL;

    bson_t filter;
    int have_filter = (mongo_arg_doc(cmd, "filter", &filter) == 0);
    size_t n_hits = 0;
    bson_t** hits = mongo_coll_query_locked(coll, user, have_filter ? &filter : NULL, &n_hits);
    if (!hits && n_hits == 0) hits = NULL;   /* empty result set is not an error */

    bson_t sort;
    if (mongo_arg_doc(cmd, "sort", &sort) == 0) mongo_apply_sort(hits, n_hits, &sort);

    int64_t skip = 0, limit = 0;
    (void)mongo_arg_i64(cmd, "skip", &skip);
    (void)mongo_arg_i64(cmd, "limit", &limit);
    size_t start = (skip > 0) ? (size_t)skip : 0;
    if (start > n_hits) start = n_hits;
    size_t end = n_hits;
    if (limit > 0 && (size_t)limit < end - start) end = start + (size_t)limit;

    bson_t proj;
    int have_proj = (mongo_arg_doc(cmd, "projection", &proj) == 0);

    bson_t* batch = bson_create();
    size_t emitted = 0;
    if (batch) {
        for (size_t i = start; i < end; i++) {
            bson_t* out = mongo_project_raw(hits[i], have_proj ? &proj : NULL);
            if (!out) { free(hits); bson_destroy(batch); return mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED, "projection is not supported"); }
            mongo_array_append(batch, emitted++, out);
            bson_destroy(out);
        }
    }
    free(hits);

    bson_t* cursor = bson_create();
    bson_t* reply = bson_create();
    if (!batch || !cursor || !reply) { bson_destroy(batch); bson_destroy(cursor); bson_destroy(reply); return NULL; }
    bson_append_int64(cursor, "id", 0);   /* single batch: no getMore */
    bson_append_string(cursor, "ns", ns);
    bson_append_array(cursor, "firstBatch", batch);
    bson_append_document(reply, "cursor", cursor);
    bson_append_int32(reply, "ok", 1);
    bson_destroy(batch);
    bson_destroy(cursor);
    return reply;
}

static bson_t* mongo_cmd_count(mongo_catalog_t* cat, qihse_user_t* user, const char* db,
                               const bson_t* cmd, const char* coll_name) {
    mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
    mongo_collection_t* coll = d ? mongo_db_find_coll_locked(d, coll_name) : NULL;
    bson_t filter;
    int have_filter = (mongo_arg_doc(cmd, "query", &filter) == 0) || (mongo_arg_doc(cmd, "filter", &filter) == 0);
    size_t n = 0;
    bson_t** hits = mongo_coll_query_locked(coll, user, have_filter ? &filter : NULL, &n);
    free(hits);
    bson_t* reply = mongo_reply_ok();
    bson_append_int32(reply, "n", (int32_t)n);
    return reply;
}

static bson_t* mongo_cmd_distinct(mongo_catalog_t* cat, qihse_user_t* user, const char* db,
                                  const bson_t* cmd, const char* coll_name) {
    mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
    mongo_collection_t* coll = d ? mongo_db_find_coll_locked(d, coll_name) : NULL;
    const char* key = mongo_arg_str(cmd, "key");
    if (!key) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "distinct needs a key");
    bson_t filter;
    int have_filter = (mongo_arg_doc(cmd, "query", &filter) == 0);
    size_t n = 0;
    bson_t** hits = mongo_coll_query_locked(coll, user, have_filter ? &filter : NULL, &n);
    bson_t* values = bson_create();
    size_t nvals = 0;
    for (size_t i = 0; i < n; i++) {
        bson_element_t e;
        if (bson_find_path(hits[i], key, &e) != 0) continue;
        int dup = 0;
        size_t off = 0;
        bson_element_t prev;
        while (bson_iter(values, &off, &prev) == 0) {
            if (elem_equal(&prev, &e)) { dup = 1; break; }
        }
        if (dup) continue;
        mongo_array_append_value(values, nvals++, hits[i], key, &e);
    }
    free(hits);
    bson_t* reply = mongo_reply_ok();
    bson_append_array(reply, "values", values);
    bson_destroy(values);
    return reply;
}

static bson_t* mongo_cmd_aggregate(mongo_catalog_t* cat, qihse_user_t* user, const char* db,
                                   const bson_t* cmd, const char* coll_name) {
    char ns[300];
    snprintf(ns, sizeof(ns), "%s.%s", db, coll_name);
    mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
    mongo_collection_t* coll = d ? mongo_db_find_coll_locked(d, coll_name) : NULL;
    bson_element_t pe;
    if (bson_find_element(cmd, "pipeline", &pe) != 0 || pe.type != BSON_ARRAY) {
        return mongo_reply_error(MONGO_ERR_BAD_VALUE, "aggregate needs a pipeline array");
    }
    bson_t pipeline = bson_view(pe.v.doc.data, pe.v.doc.len);

    /* The pipeline runs over exactly the documents the principal may read, so
     * no stage can widen the result set beyond the caller's clearance. */
    size_t n_visible = 0;
    bson_t** visible = mongo_coll_query_locked(coll, user, NULL, &n_visible);
    size_t n_out = 0;
    bson_t** out = bson_aggregate((const bson_t* const*)visible, n_visible, &pipeline, 0, &n_out);
    free(visible);
    if (!out) {
        return mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED,
                                 "aggregation stage not implemented ($lookup/$facet/$graphLookup "
                                 "and computed expressions are refused)");
    }
    bson_t* batch = bson_create();
    for (size_t i = 0; i < n_out; i++) {
        /* Stage output is derived only from documents the caller may read, so
         * labelling it at the caller's clearance is not an escalation; it also
         * lets every output document pass the single reply gate below. */
        mongo_doc_label_for_write(out[i], user);
        bson_t* scrubbed = mongo_reply_doc(out[i], user);
        if (scrubbed) {
            mongo_array_append(batch, i, scrubbed);
            bson_destroy(scrubbed);
        }
    }
    mongo_docs_free(out, n_out);
    bson_t* cursor = bson_create();
    bson_t* reply = bson_create();
    bson_append_int64(cursor, "id", 0);
    bson_append_string(cursor, "ns", ns);
    bson_append_array(cursor, "firstBatch", batch);
    bson_append_document(reply, "cursor", cursor);
    bson_append_int32(reply, "ok", 1);
    bson_destroy(batch);
    bson_destroy(cursor);
    return reply;
}

/* ---- write commands ---- */
static bson_t* mongo_cmd_insert(mongo_catalog_t* cat, qihse_user_t* user, const char* db,
                                const bson_t* cmd, const char* coll_name) {
    bson_element_t de;
    if (bson_find_element(cmd, "documents", &de) != 0 || de.type != BSON_ARRAY) {
        return mongo_reply_error(MONGO_ERR_BAD_VALUE, "insert needs a documents array");
    }
    mongo_database_t* d = mongo_cat_get_db_locked(cat, db);
    mongo_collection_t* coll = d ? mongo_db_get_coll_locked(d, coll_name) : NULL;
    if (!coll) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "invalid database or collection name");
    bson_t docs = bson_view(de.v.doc.data, de.v.doc.len);
    size_t off = 0;
    bson_element_t doc;
    int32_t inserted = 0;
    while (bson_iter(&docs, &off, &doc) == 0) {
        if (doc.type != BSON_DOCUMENT) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "insert takes documents");
        bson_t view = bson_view(doc.v.doc.data, doc.v.doc.len);
        bson_t* copy = bson_copy(&view);
        if (!copy) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "out of memory");
        /* The label comes from the writer's authenticated clearance, never
         * from the client's bytes. */
        mongo_doc_label_for_write(copy, user);
        if (mongo_coll_add_locked(coll, copy) != 0) {
            bson_destroy(copy);
            return mongo_reply_error(MONGO_ERR_BAD_VALUE, "out of memory");
        }
        inserted++;
    }
    bson_t* reply = mongo_reply_ok();
    bson_append_int32(reply, "n", inserted);
    return reply;
}

static bson_t* mongo_cmd_update(mongo_catalog_t* cat, qihse_user_t* user, const char* db,
                                const bson_t* cmd, const char* coll_name) {
    bson_element_t ue;
    if (bson_find_element(cmd, "updates", &ue) != 0 || ue.type != BSON_ARRAY) {
        return mongo_reply_error(MONGO_ERR_BAD_VALUE, "update needs an updates array");
    }
    mongo_database_t* d = mongo_cat_get_db_locked(cat, db);
    mongo_collection_t* coll = d ? mongo_db_get_coll_locked(d, coll_name) : NULL;
    if (!coll) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "invalid database or collection name");
    bson_t specs = bson_view(ue.v.doc.data, ue.v.doc.len);
    size_t soff = 0;
    bson_element_t spec;
    int32_t matched = 0, modified = 0, upserted = 0;
    while (bson_iter(&specs, &soff, &spec) == 0) {
        if (spec.type != BSON_DOCUMENT) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "update spec must be a document");
        bson_t one = bson_view(spec.v.doc.data, spec.v.doc.len);
        bson_t q, u;
        int have_q = (mongo_arg_doc(&one, "q", &q) == 0);
        int have_u = (mongo_arg_doc(&one, "u", &u) == 0);
        if (!have_u) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "update spec needs u");
        bson_element_t me, upe;
        int multi = 0, upsert = 0;
        if (bson_find_element(&one, "multi", &me) == 0) multi = (me.type == BSON_BOOL) ? me.v.b : ((int)elem_as_num(&me) != 0);
        if (bson_find_element(&one, "upsert", &upe) == 0) upsert = (upe.type == BSON_BOOL) ? upe.v.b : ((int)elem_as_num(&upe) != 0);

        size_t n_hits = 0;
        size_t* hits = mongo_coll_match_indices_locked(coll, user, have_q ? &q : NULL, &n_hits);
        int32_t hits_taken = 0;
        for (size_t i = 0; i < n_hits; i++) {
            bson_t* target = coll->docs[hits[i]];
            uint16_t classif = 0, sci = 0;
            /* The label of an updated document is preserved: an update can
             * neither raise nor lower a document's classification. */
            int labelled = (mongo_doc_label(target, &classif, &sci) == 0);
            if (bson_apply_update(target, &u, 0) == 0) modified++;
            if (labelled) {
                bson_remove_key(target, MONGO_META_CLASSIF);
                bson_remove_key(target, MONGO_META_SCI);
                bson_append_int32(target, MONGO_META_CLASSIF, (int32_t)classif);
                bson_append_int32(target, MONGO_META_SCI, (int32_t)sci);
            }
            hits_taken++;
            if (!multi) break;
        }
        matched += hits_taken;
        free(hits);
        if (hits_taken == 0 && upsert) {
            bson_t* base = have_q ? bson_copy(&q) : bson_create();
            if (!base) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "out of memory");
            bson_remove_key(base, "_id");
            (void)bson_apply_update(base, &u, 1);
            mongo_doc_label_for_write(base, user);
            if (mongo_coll_add_locked(coll, base) != 0) {
                bson_destroy(base);
                return mongo_reply_error(MONGO_ERR_BAD_VALUE, "out of memory");
            }
            upserted++;
        }
    }
    bson_t* reply = mongo_reply_ok();
    bson_append_int32(reply, "n", matched + upserted);
    bson_append_int32(reply, "nModified", modified);
    return reply;
}

static bson_t* mongo_cmd_delete(mongo_catalog_t* cat, qihse_user_t* user, const char* db,
                                const bson_t* cmd, const char* coll_name) {
    bson_element_t de;
    if (bson_find_element(cmd, "deletes", &de) != 0 || de.type != BSON_ARRAY) {
        return mongo_reply_error(MONGO_ERR_BAD_VALUE, "delete needs a deletes array");
    }
    mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
    mongo_collection_t* coll = d ? mongo_db_find_coll_locked(d, coll_name) : NULL;
    if (!coll) return mongo_reply_error(MONGO_ERR_INVALID_NS, "ns not found");
    bson_t specs = bson_view(de.v.doc.data, de.v.doc.len);
    size_t soff = 0;
    bson_element_t spec;
    int32_t deleted = 0;
    while (bson_iter(&specs, &soff, &spec) == 0) {
        if (spec.type != BSON_DOCUMENT) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "delete spec must be a document");
        bson_t one = bson_view(spec.v.doc.data, spec.v.doc.len);
        bson_t q;
        int have_q = (mongo_arg_doc(&one, "q", &q) == 0);
        int64_t limit = 0;
        (void)mongo_arg_i64(&one, "limit", &limit);
        size_t n_hits = 0;
        size_t* hits = mongo_coll_match_indices_locked(coll, user, have_q ? &q : NULL, &n_hits);
        /* Delete from the end so the remaining indices stay valid. */
        for (size_t i = n_hits; i > 0; i--) {
            mongo_coll_remove_at_locked(coll, hits[i - 1]);
            deleted++;
            if (limit == 1) break;
        }
        free(hits);
    }
    bson_t* reply = mongo_reply_ok();
    bson_append_int32(reply, "n", deleted);
    return reply;
}

/* ---- metadata commands ---- */
static bson_t* mongo_cmd_list_collections(mongo_catalog_t* cat, qihse_user_t* user, const char* db) {
    bson_t* batch = bson_create();
    size_t n = 0;
    mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
    if (d) {
        for (size_t i = 0; i < d->count; i++) {
            /* A collection with rows outside the principal's clearance is not
             * enumerated: enumeration is not a way around a read denial. */
            if (!mongo_coll_fully_readable(d->colls[i], user)) continue;
            bson_t* entry = bson_create();
            bson_append_string(entry, "name", d->colls[i]->name);
            bson_append_string(entry, "type", "collection");
            mongo_array_append(batch, n++, entry);
            bson_destroy(entry);
        }
    }
    bson_t* cursor = bson_create();
    bson_t* reply = bson_create();
    bson_append_int64(cursor, "id", 0);
    bson_append_string(cursor, "ns", db);
    bson_append_array(cursor, "firstBatch", batch);
    bson_append_document(reply, "cursor", cursor);
    bson_append_int32(reply, "ok", 1);
    bson_destroy(batch);
    bson_destroy(cursor);
    return reply;
}

static bson_t* mongo_cmd_list_databases(mongo_catalog_t* cat, qihse_user_t* user) {
    bson_t* arr = bson_create();
    size_t n = 0;
    for (size_t i = 0; i < cat->count; i++) {
        mongo_database_t* d = cat->dbs[i];
        int readable = 1;
        for (size_t j = 0; j < d->count; j++) {
            if (!mongo_coll_fully_readable(d->colls[j], user)) { readable = 0; break; }
        }
        if (!readable) continue;
        bson_t* entry = bson_create();
        bson_append_string(entry, "name", d->name);
        bson_append_int32(entry, "sizeOnDisk", 0);
        bson_append_bool(entry, "empty", d->count == 0);
        mongo_array_append(arr, n++, entry);
        bson_destroy(entry);
    }
    bson_t* reply = mongo_reply_ok();
    bson_append_array(reply, "databases", arr);
    bson_destroy(arr);
    return reply;
}

static bson_t* mongo_cmd_stats(mongo_catalog_t* cat, qihse_user_t* user, const char* db,
                               const bson_t* cmd, const char* coll_name) {
    bson_t* reply = mongo_reply_ok();
    bson_append_string(reply, "db", db);
    int32_t objects = 0, collections = 0;
    mongo_database_t* d = mongo_cat_find_db_locked(cat, db);
    if (d) {
        for (size_t i = 0; i < d->count; i++) {
            if (coll_name && strcmp(d->colls[i]->name, coll_name) != 0) continue;
            if (!coll_name) collections++;
            for (size_t j = 0; j < d->colls[i]->count; j++) {
                if (mongo_doc_visible(d->colls[i]->docs[j], user)) objects++;
            }
        }
    }
    (void)cmd;
    bson_append_int32(reply, "objects", objects);
    if (!coll_name) bson_append_int32(reply, "collections", collections);
    return reply;
}

/* Options that change the semantics of a query and are not implemented.  A
 * driver that asks for a collation and silently gets a binary comparison would
 * receive a wrong answer, so the command is refused instead. */
static bson_t* mongo_reject_unsupported_options(const bson_t* cmd) {
    bson_element_t e;
    if (bson_find_element(cmd, "collation", &e) == 0) {
        return mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED,
                                 "collation is not implemented: comparisons are binary");
    }
    if (bson_find_element(cmd, "arrayFilters", &e) == 0) {
        return mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED, "arrayFilters is not implemented");
    }
    return NULL;
}

/* ---- dispatch ---- */
bson_t* mongo_dispatch_command_as(mongo_catalog_t* cat, qihse_user_t* user,
                                  const char* db_name, const bson_t* cmd) {
    if (!cat || !cmd || !db_name) {
        return mongo_reply_error(MONGO_ERR_BAD_VALUE, "malformed command document");
    }
    /* AGENTS.md invariant 1: no read path without an authenticated context.
     * A NULL principal is refused here, before any document is touched. */
    if (!user) {
        return mongo_reply_error(MONGO_ERR_UNAUTHORIZED,
                                 "not authorized: no authenticated security context");
    }
    /* One liveness check per command: revocation takes effect on the next
     * command rather than on the next document. */
    if (!qihse_auth_user_is_active(user)) {
        return mongo_reply_error(MONGO_ERR_UNAUTHORIZED,
                                 "not authorized: principal is not active");
    }
    {
        bson_t* refused = mongo_reject_unsupported_options(cmd);
        if (refused) return refused;
    }

    size_t off = 0;
    bson_element_t first;
    if (bson_iter(cmd, &off, &first) != 0) {
        return mongo_reply_error(MONGO_ERR_BAD_VALUE, "empty command document");
    }
    const char* command = first.key;
    const char* arg = (first.type == BSON_STRING) ? first.v.str : NULL;

    pthread_mutex_lock(&cat->lock);
    bson_t* reply = NULL;

    if (strcmp(command, "ping") == 0) {
        reply = mongo_reply_ok();
    } else if (strcmp(command, "hello") == 0 || strcmp(command, "isMaster") == 0 ||
               strcmp(command, "ismaster") == 0) {
        reply = mongo_reply_ok();
        bson_append_bool(reply, "isWritablePrimary", 1);
        bson_append_bool(reply, "ismaster", 1);
        bson_append_int32(reply, "minWireVersion", 0);
        bson_append_int32(reply, "maxWireVersion", 17);
        bson_append_int32(reply, "maxBsonObjectSize", 16 * 1024 * 1024);
        bson_append_int32(reply, "maxMessageSizeBytes", (int32_t)MONGO_MAX_MESSAGE_SIZE);
        bson_append_int32(reply, "maxWriteBatchSize", 100000);
        bson_append_string(reply, "authMechanism", "QIHSE-PLAINTEXT");
        bson_append_bool(reply, "localTime", 0);
    } else if (strcmp(command, "buildInfo") == 0 || strcmp(command, "buildinfo") == 0) {
        reply = mongo_reply_ok();
        bson_append_string(reply, "version", "1.0.0");
        bson_append_string(reply, "gitVersion", "qihse");
        bson_append_string(reply, "sysInfo", "QIHSE MongoDB wire adapter");
        bson_append_int32(reply, "maxBsonObjectSize", 16 * 1024 * 1024);
    } else if (strcmp(command, "endSessions") == 0 || strcmp(command, "killCursors") == 0) {
        reply = mongo_reply_ok();
        if (strcmp(command, "killCursors") == 0) bson_append_int32(reply, "cursorsKilled", 0);
    } else if (strcmp(command, "find") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "find needs a collection name");
        else reply = mongo_cmd_find(cat, user, db_name, cmd, arg);
    } else if (strcmp(command, "count") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "count needs a collection name");
        else reply = mongo_cmd_count(cat, user, db_name, cmd, arg);
    } else if (strcmp(command, "distinct") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "distinct needs a collection name");
        else reply = mongo_cmd_distinct(cat, user, db_name, cmd, arg);
    } else if (strcmp(command, "aggregate") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "aggregate needs a collection name");
        else reply = mongo_cmd_aggregate(cat, user, db_name, cmd, arg);
    } else if (strcmp(command, "insert") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "insert needs a collection name");
        else reply = mongo_cmd_insert(cat, user, db_name, cmd, arg);
    } else if (strcmp(command, "update") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "update needs a collection name");
        else reply = mongo_cmd_update(cat, user, db_name, cmd, arg);
    } else if (strcmp(command, "delete") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "delete needs a collection name");
        else reply = mongo_cmd_delete(cat, user, db_name, cmd, arg);
    } else if (strcmp(command, "listCollections") == 0) {
        reply = mongo_cmd_list_collections(cat, user, db_name);
    } else if (strcmp(command, "listDatabases") == 0) {
        reply = mongo_cmd_list_databases(cat, user);
    } else if (strcmp(command, "collStats") == 0 || strcmp(command, "dbStats") == 0) {
        reply = mongo_cmd_stats(cat, user, db_name, cmd,
                                strcmp(command, "collStats") == 0 ? arg : NULL);
    } else if (strcmp(command, "create") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "create needs a collection name");
        else {
            mongo_database_t* d = mongo_cat_get_db_locked(cat, db_name);
            mongo_collection_t* coll = d ? mongo_db_get_coll_locked(d, arg) : NULL;
            reply = coll ? mongo_reply_ok() : mongo_reply_error(MONGO_ERR_BAD_VALUE, "invalid name");
        }
    } else if (strcmp(command, "drop") == 0) {
        if (!arg) reply = mongo_reply_error(MONGO_ERR_BAD_VALUE, "drop needs a collection name");
        else {
            mongo_database_t* d = mongo_cat_find_db_locked(cat, db_name);
            mongo_collection_t* coll = d ? mongo_db_find_coll_locked(d, arg) : NULL;
            if (!coll) reply = mongo_reply_error(MONGO_ERR_INVALID_NS, "ns not found");
            else if (!mongo_coll_fully_readable(coll, user)) {
                /* Dropping is destructive and unobservable afterwards: a
                 * principal cannot destroy data it is not cleared to read. */
                reply = mongo_reply_error(MONGO_ERR_UNAUTHORIZED,
                                          "not authorized: collection holds data above your clearance");
            } else {
                mongo_db_remove_coll_locked(d, coll);
                reply = mongo_reply_ok();
            }
        }
    } else if (strcmp(command, "dropDatabase") == 0) {
        mongo_database_t* d = mongo_cat_find_db_locked(cat, db_name);
        int readable = 1;
        if (d) {
            for (size_t i = 0; i < d->count; i++) {
                if (!mongo_coll_fully_readable(d->colls[i], user)) { readable = 0; break; }
            }
        }
        if (!d) reply = mongo_reply_ok();
        else if (!readable) reply = mongo_reply_error(MONGO_ERR_UNAUTHORIZED,
                                                      "not authorized: database holds data above your clearance");
        else { mongo_cat_remove_db_locked(cat, d); reply = mongo_reply_ok(); }
    } else if (strcmp(command, "getMore") == 0) {
        reply = mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED,
                                  "getMore is not implemented: every cursor is returned as a single batch (id 0)");
    } else if (strcmp(command, "createIndexes") == 0 || strcmp(command, "listIndexes") == 0 ||
               strcmp(command, "dropIndexes") == 0) {
        reply = mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED,
                                  "secondary indexes are not implemented by the QIHSE MongoDB adapter");
    } else if (strcmp(command, "findAndModify") == 0 || strcmp(command, "findandmodify") == 0) {
        reply = mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED, "findAndModify is not implemented");
    } else if (strcmp(command, "saslStart") == 0 || strcmp(command, "saslContinue") == 0) {
        reply = mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED,
                                  "SCRAM-SHA-256 is not implemented; use the QIHSE \"authenticate\" command");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "no such command: %s", command);
        reply = mongo_reply_error(MONGO_ERR_NO_SUCH_CMD, msg);
    }
    pthread_mutex_unlock(&cat->lock);
    return reply;
}

bson_t* mongo_dispatch_command(mongo_catalog_t* cat, const char* db_name, const bson_t* cmd) {
    if (!cat) return mongo_reply_error(MONGO_ERR_BAD_VALUE, "malformed command document");
    pthread_mutex_lock(&cat->lock);
    qihse_user_t* user = cat->auth_user;
    pthread_mutex_unlock(&cat->lock);
    /* Fail closed when no principal is bound: the user-less entry point must
     * never be a way to reach data without a security context. */
    return mongo_dispatch_command_as(cat, user, db_name, cmd);
}

/* ===========================================================================
 * TCP server
 * =========================================================================== */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct {
    qihse_mongo_server_t* srv;
    int slot;
    int fd;
    uint32_t peer_ip;
} mongo_conn_t;

static int mongo_send_all(int fd, const uint8_t* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

/* Frame a reply document.  OP_MSG replies mirror the request's opcode;
 * OP_QUERY requests get a legacy OP_REPLY so an old driver can read the answer.
 * The frame is heap-allocated: the document can be up to MONGO_MAX_BSON_SIZE. */
static int mongo_send_reply(int fd, int32_t request_id, int32_t response_to,
                            int32_t opcode, const bson_t* doc) {
    size_t dlen = bson_size(doc);
    const uint8_t* ddata = bson_data(doc);
    if (!ddata || dlen == 0 || dlen > MONGO_MAX_BSON_SIZE) return -1;
    size_t head = (opcode == MONGO_OP_REPLY) ? 36u : 21u;
    size_t total = 16u + head + dlen;
    uint8_t* frame = (uint8_t*)malloc(total);
    if (!frame) return -1;
    mongo_wr_i32(frame, (int32_t)total);
    mongo_wr_i32(frame + 4, request_id);
    mongo_wr_i32(frame + 8, response_to);
    mongo_wr_i32(frame + 12, opcode);
    if (opcode == MONGO_OP_REPLY) {
        mongo_wr_i32(frame + 16, 8);   /* responseFlags: AwaitCapable */
        mongo_wr_i64(frame + 20, 0);   /* cursorID: 0, single batch */
        mongo_wr_i32(frame + 28, 0);   /* startingFrom */
        mongo_wr_i32(frame + 32, 1);   /* numberReturned */
        memcpy(frame + 36, ddata, dlen);
    } else {
        mongo_wr_i32(frame + 16, 0);   /* flags */
        frame[20] = 0;                 /* section kind 0 (body) */
        memcpy(frame + 21, ddata, dlen);
    }
    int rc = mongo_send_all(fd, frame, total);
    free(frame);
    return rc;
}

/* Split "db.collection" out of a namespace string inside a message body. */
static int mongo_ns_split(const uint8_t* body, size_t body_len, size_t off,
                          char* db, size_t db_cap, char* coll, size_t coll_cap) {
    long n = mongo_cstr_len(body, body_len, off);
    if (n <= 0) return -1;
    const char* ns = (const char*)(body + off);
    const char* dot = strchr(ns, '.');
    if (!dot || dot == ns || dot[1] == '\0') return -1;
    size_t dbl = (size_t)(dot - ns);
    if (dbl + 1u > db_cap || strlen(dot + 1) + 1u > coll_cap) return -1;
    memcpy(db, ns, dbl);
    db[dbl] = '\0';
    snprintf(coll, coll_cap, "%s", dot + 1);
    return 0;
}

/* authenticate / logout are the gate itself.  They are the only commands that
 * may run before a principal exists, and they are rate-limited per source IP
 * exactly like the PostgreSQL and Bolt adapters. */
static int mongo_is_auth_command(const bson_t* cmd, const char** which) {
    size_t off = 0;
    bson_element_t e;
    if (!cmd || bson_iter(cmd, &off, &e) != 0) return 0;
    if (strcmp(e.key, "authenticate") == 0 || strcmp(e.key, "qihseAuthenticate") == 0) {
        *which = "auth";
        return 1;
    }
    if (strcmp(e.key, "logout") == 0) {
        *which = "logout";
        return 1;
    }
    return 0;
}

static bson_t* mongo_conn_dispatch(mongo_catalog_t* cat, const bson_t* cmd, qihse_user_t** user,
                                   const char* db, uint32_t peer_ip) {
    const char* which = NULL;
    if (mongo_is_auth_command(cmd, &which)) {
        if (strcmp(which, "logout") == 0) {
            *user = NULL;
            return mongo_reply_ok();
        }
        const char* username = mongo_arg_str(cmd, "user");
        const char* password = mongo_arg_str(cmd, "pwd");
        if (!username || !password) {
            return mongo_reply_error(MONGO_ERR_BAD_VALUE, "authenticate needs user and pwd");
        }
        if (!qihse_auth_check_rate_limit(peer_ip)) {
            return mongo_reply_error(MONGO_ERR_UNAUTHORIZED, "too many authentication attempts");
        }
        qihse_user_t* authed = qihse_auth_authenticate_from(peer_ip, username, password);
        if (!authed) {
            return mongo_reply_error(MONGO_ERR_UNAUTHORIZED, "authentication failed");
        }
        qihse_auth_rate_limit_reset(peer_ip);
        *user = authed;
        bson_t* r = mongo_reply_ok();
        bson_append_string(r, "authenticatedUser", username);
        return r;
    }
    return mongo_dispatch_command_as(cat, *user, db, cmd);
}

/* Handle one parsed frame.  Returns 0 to continue the session, -1 to close it
 * (a malformed frame or a protocol violation ends the connection rather than
 * being guessed at). */
static int mongo_handle_frame(const mongo_msg_t* msg, qihse_mongo_server_t* srv, int fd,
                              qihse_user_t** user, char* default_db, size_t default_db_cap,
                              int32_t* next_id, uint32_t peer_ip) {
    mongo_catalog_t* cat = (mongo_catalog_t*)srv->catalog;
    switch (msg->opcode) {
        case MONGO_OP_MSG: {
            size_t off = 0;
            bson_t* cmd = mongo_msg_get_document(msg, &off);
            if (!cmd) return -1;
            const char* db = mongo_arg_str(cmd, "$db");
            if (!db) db = default_db;
            bson_t* reply = mongo_conn_dispatch(cat, cmd, user, db, peer_ip);
            bson_destroy(cmd);
            if (!reply) return -1;
            int rc = mongo_send_reply(fd, (*next_id)++, msg->request_id, MONGO_OP_MSG, reply);
            bson_destroy(reply);
            return rc;
        }
        case MONGO_OP_QUERY: {
            char db[128], coll[128];
            if (mongo_ns_split(msg->body, msg->body_len, 4, db, sizeof(db), coll, sizeof(coll)) != 0) return -1;
            size_t off = 0;
            bson_t* query = mongo_msg_get_document(msg, &off);
            if (!query) return -1;
            bson_t* reply = NULL;
            if (strcmp(coll, "$cmd") == 0) {
                reply = mongo_conn_dispatch(cat, query, user, db, peer_ip);
            } else {
                /* Legacy OP_QUERY on a collection is the pre-OP_MSG find form. */
                bson_t* synth = bson_create();
                if (synth) {
                    bson_append_string(synth, "find", coll);
                    bson_append_document(synth, "filter", query);
                    bson_append_string(synth, "$db", db);
                    reply = mongo_conn_dispatch(cat, synth, user, db, peer_ip);
                    bson_destroy(synth);
                }
            }
            bson_destroy(query);
            if (!reply) return -1;
            int rc = mongo_send_reply(fd, (*next_id)++, msg->request_id, MONGO_OP_REPLY, reply);
            bson_destroy(reply);
            snprintf(default_db, default_db_cap, "%s", db);
            return rc;
        }
        case MONGO_OP_INSERT: {
            char db[128], coll[128];
            if (mongo_ns_split(msg->body, msg->body_len, 4, db, sizeof(db), coll, sizeof(coll)) != 0) return -1;
            size_t off = 0;
            bson_t* doc = mongo_msg_get_document(msg, &off);
            if (!doc) return -1;
            bson_t* synth = bson_create();
            if (synth) {
                bson_append_string(synth, "insert", coll);
                bson_t* docs = bson_create();
                if (docs) {
                    bson_append_document(docs, "0", doc);
                    bson_append_array(synth, "documents", docs);
                    bson_destroy(docs);
                }
                bson_append_string(synth, "$db", db);
                bson_t* reply = mongo_conn_dispatch(cat, synth, user, db, peer_ip);
                /* Legacy write ops are fire-and-forget: no reply frame. */
                bson_destroy(reply);
                bson_destroy(synth);
            }
            bson_destroy(doc);
            return 0;
        }
        case MONGO_OP_UPDATE:
        case MONGO_OP_DELETE: {
            char db[128], coll[128];
            if (mongo_ns_split(msg->body, msg->body_len, 4, db, sizeof(db), coll, sizeof(coll)) != 0) return -1;
            /* ZERO(4) + ns + flags(4) + the operation documents */
            long first = mongo_first_doc_offset(msg);
            if (first < 0) return -1;
            size_t off = (size_t)first;
            bson_t* spec = mongo_msg_get_document(msg, &off);
            if (!spec) return -1;
            bson_t* synth = bson_create();
            if (synth) {
                bson_t* arr = bson_create();
                if (arr) {
                    bson_append_document(arr, "0", spec);
                    bson_append_string(synth, (msg->opcode == MONGO_OP_UPDATE) ? "update" : "delete", coll);
                    bson_append_array(synth, (msg->opcode == MONGO_OP_UPDATE) ? "updates" : "deletes", arr);
                    bson_destroy(arr);
                }
                bson_append_string(synth, "$db", db);
                bson_t* reply = mongo_conn_dispatch(cat, synth, user, db, peer_ip);
                bson_destroy(reply);
                bson_destroy(synth);
            }
            bson_destroy(spec);
            return 0;
        }
        case MONGO_OP_GET_MORE: {
            bson_t* reply = mongo_reply_error(MONGO_ERR_NOT_IMPLEMENTED,
                                              "getMore is not implemented: every cursor is returned as a single batch (id 0)");
            int rc = mongo_send_reply(fd, (*next_id)++, msg->request_id, MONGO_OP_REPLY, reply);
            bson_destroy(reply);
            return rc;
        }
        case MONGO_OP_KILL_CURSORS:
            return 0;   /* no cursors exist; no reply on the wire */
        default:
            /* A client must not send OP_REPLY/OP_MSG_LEGACY: protocol violation. */
            return -1;
    }
}

static void* mongo_conn_thread(void* arg) {
    mongo_conn_t* conn = (mongo_conn_t*)arg;
    qihse_mongo_server_t* srv = conn->srv;
    int slot = conn->slot;
    int fd = conn->fd;
    uint32_t peer_ip = conn->peer_ip;
    free(conn);

    qihse_user_t* user = NULL;   /* the connection's principal; NULL = unauthenticated */
    char default_db[128];
    snprintf(default_db, sizeof(default_db), "test");
    int32_t next_id = 1;

    size_t cap = 65536;
    size_t len = 0;
    uint8_t* buf = (uint8_t*)malloc(cap);
    if (buf) {
        for (;;) {
            if (!srv->running) break;
            if (len < 4u) {
                ssize_t r = recv(fd, buf + len, cap - len, 0);
                if (r <= 0) break;
                len += (size_t)r;
                continue;
            }
            /* The declared message length is attacker controlled: it is
             * refused before anything is allocated or copied. */
            int32_t declared = mongo_rd_i32(buf);
            if (declared < 16 || (uint32_t)declared > MONGO_MAX_MESSAGE_SIZE) break;
            if ((size_t)declared > cap) {
                uint8_t* nb = (uint8_t*)realloc(buf, (size_t)declared);
                if (!nb) break;
                buf = nb;
                cap = (size_t)declared;
            }
            if (len < (size_t)declared) {
                ssize_t r = recv(fd, buf + len, cap - len, 0);
                if (r <= 0) break;
                len += (size_t)r;
                continue;
            }
            mongo_msg_t msg;
            if (mongo_msg_parse(buf, (size_t)declared, &msg) != 0) break;
            if (mongo_handle_frame(&msg, srv, fd, &user, default_db, sizeof(default_db),
                                   &next_id, peer_ip) != 0) break;
            memmove(buf, buf + declared, len - (size_t)declared);
            len -= (size_t)declared;
        }
    }
    free(buf);
    close(fd);
    /* Last touch of the server: stop() joins this thread before the server
     * (and the catalog) can be freed. */
    pthread_mutex_lock(&srv->conn_lock);
    srv->conn_fds[slot] = -1;
    pthread_mutex_unlock(&srv->conn_lock);
    return NULL;
}

static void* mongo_accept_thread(void* arg) {
    qihse_mongo_server_t* srv = (qihse_mongo_server_t*)arg;
    while (srv->running) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int client_fd = accept(srv->fd, (struct sockaddr*)&peer, &plen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;   /* the listening socket was shut down */
        }
        mongo_conn_t* conn = (mongo_conn_t*)malloc(sizeof(*conn));
        if (!conn) { close(client_fd); continue; }
        conn->srv = srv;
        conn->fd = client_fd;
        conn->peer_ip = ntohl(peer.sin_addr.s_addr);
        pthread_mutex_lock(&srv->conn_lock);
        int slot = -1;
        for (int i = 0; i < MONGO_MAX_CONNECTIONS; i++) {
            if (srv->conn_fds[i] < 0 && srv->conn_threads[i] == 0) { slot = i; break; }
        }
        if (slot < 0) {
            pthread_mutex_unlock(&srv->conn_lock);
            close(client_fd);
            free(conn);
            continue;
        }
        conn->slot = slot;
        srv->conn_fds[slot] = client_fd;
        if (pthread_create(&srv->conn_threads[slot], NULL, mongo_conn_thread, conn) != 0) {
            srv->conn_fds[slot] = -1;
            srv->conn_threads[slot] = 0;
            pthread_mutex_unlock(&srv->conn_lock);
            close(client_fd);
            free(conn);
            continue;
        }
        srv->live_conns++;
        pthread_mutex_unlock(&srv->conn_lock);
    }
    return NULL;
}

qihse_mongo_server_t* qihse_mongo_server_create(uint16_t port, void* doc_store) {
    qihse_mongo_server_t* srv = (qihse_mongo_server_t*)calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    srv->fd = -1;
    srv->port = port;
    srv->doc_store = doc_store;
    for (int i = 0; i < MONGO_MAX_CONNECTIONS; i++) {
        srv->conn_fds[i] = -1;
        srv->conn_threads[i] = 0;
    }
    if (pthread_mutex_init(&srv->conn_lock, NULL) != 0) { free(srv); return NULL; }
    if (pthread_cond_init(&srv->conn_idle, NULL) != 0) {
        pthread_mutex_destroy(&srv->conn_lock);
        free(srv);
        return NULL;
    }
    /* No principal is bound here: until a connection authenticates, every
     * command through this catalog is refused (invariant 1).  The document
     * store handle is retained for future durable tiering and is NOT consulted
     * on any read path, so it cannot become a context-free read primitive. */
    srv->catalog = mongo_catalog_create_auth((qihse_document_store_t*)doc_store, NULL);
    if (!srv->catalog) {
        pthread_cond_destroy(&srv->conn_idle);
        pthread_mutex_destroy(&srv->conn_lock);
        free(srv);
        return NULL;
    }
    return srv;
}

int qihse_mongo_server_start(qihse_mongo_server_t* srv) {
    if (!srv) return -1;
    if (srv->running) return 0;
    if (qihse_auth_is_operator_password_default()) {
        fprintf(stderr, "[FATAL SECURITY ERROR] qihse_mongo_server_start: the operator "
                        "password is unset or still the default.  Rotate it before "
                        "exposing the MongoDB adapter.\n");
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(srv->port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    /* port 0 means "any port": report the one that was actually bound. */
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    if (getsockname(fd, (struct sockaddr*)&bound, &blen) == 0) srv->port = ntohs(bound.sin_port);
    srv->fd = fd;
    srv->running = 1;
    if (pthread_create(&srv->thread, NULL, mongo_accept_thread, srv) != 0) {
        srv->running = 0;
        close(fd);
        srv->fd = -1;
        return -1;
    }
    return 0;
}

int qihse_mongo_server_stop(qihse_mongo_server_t* srv) {
    if (!srv) return -1;
    if (!srv->running && srv->fd < 0) return 0;
    srv->running = 0;
    if (srv->fd >= 0) shutdown(srv->fd, SHUT_RDWR);
    if (srv->thread != 0) {
        pthread_join(srv->thread, NULL);
        srv->thread = 0;
    }
    if (srv->fd >= 0) {
        close(srv->fd);
        srv->fd = -1;
    }
    /* No new connection can be registered now (the accept thread is joined), so
     * this snapshot is complete: wake every client out of recv() and join it
     * before the catalog may be freed. */
    pthread_t tids[MONGO_MAX_CONNECTIONS];
    size_t n = 0;
    pthread_mutex_lock(&srv->conn_lock);
    for (int i = 0; i < MONGO_MAX_CONNECTIONS; i++) {
        if (srv->conn_threads[i] == 0) continue;
        if (srv->conn_fds[i] >= 0) shutdown(srv->conn_fds[i], SHUT_RDWR);
        tids[n++] = srv->conn_threads[i];
    }
    pthread_mutex_unlock(&srv->conn_lock);
    for (size_t i = 0; i < n; i++) pthread_join(tids[i], NULL);
    pthread_mutex_lock(&srv->conn_lock);
    for (int i = 0; i < MONGO_MAX_CONNECTIONS; i++) {
        srv->conn_fds[i] = -1;
        srv->conn_threads[i] = 0;
    }
    srv->live_conns = 0;
    pthread_mutex_unlock(&srv->conn_lock);
    return 0;
}

void qihse_mongo_server_destroy(qihse_mongo_server_t* srv) {
    if (!srv) return;
    qihse_mongo_server_stop(srv);
    mongo_catalog_destroy((mongo_catalog_t*)srv->catalog);
    srv->catalog = NULL;
    pthread_cond_destroy(&srv->conn_idle);
    pthread_mutex_destroy(&srv->conn_lock);
    free(srv);
}

bson_t** bson_aggregate(const bson_t* const* input, size_t n_in,
                        const bson_t* pipeline, size_t n_stages,
                        size_t* out_count) {
    if (out_count) *out_count = 0;
    if (!pipeline) return NULL;
    if (!input && n_in > 0) return NULL;

    bson_t** cur = (bson_t**)malloc((n_in ? n_in : 1) * sizeof(*cur));
    if (!cur) return NULL;
    size_t ncur = 0;
    for (size_t i = 0; i < n_in; i++) {
        bson_t* c = bson_copy(input[i]);
        if (!c) { mongo_docs_free(cur, ncur); return NULL; }
        cur[ncur++] = c;
    }

    if (n_stages > 0) {
        if (n_stages != 1) { mongo_docs_free(cur, ncur); return NULL; }
        bson_t** next = NULL;
        size_t nnext = 0;
        if (mongo_stage_run(cur, ncur, pipeline, &next, &nnext) != 0) {
            mongo_docs_free(cur, ncur);
            return NULL;
        }
        if (!next) {
            /* An empty result set is a success, not a failure: NULL from this
             * function means "the pipeline could not be evaluated". */
            next = (bson_t**)malloc(sizeof(*next));
            if (!next) return NULL;
        }
        if (out_count) *out_count = nnext;
        return next;
    }

    size_t soff = 0;
    bson_element_t st;
    while (bson_iter(pipeline, &soff, &st) == 0) {
        if (st.type != BSON_DOCUMENT) { mongo_docs_free(cur, ncur); return NULL; }
        bson_t stage = bson_view(st.v.doc.data, st.v.doc.len);
        bson_t** next = NULL;
        size_t nnext = 0;
        if (mongo_stage_run(cur, ncur, &stage, &next, &nnext) != 0) {
            mongo_docs_free(cur, ncur);
            return NULL;
        }
        cur = next;
        ncur = nnext;
    }
    if (!cur) {
        cur = (bson_t**)malloc(sizeof(*cur));
        if (!cur) return NULL;
    }
    if (out_count) *out_count = ncur;
    return cur;
}
