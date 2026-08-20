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
    if (!b || !key || !sub) return -1;
    bson_append_type_and_key(b, BSON_DOCUMENT, key);
    int32_t sz = (int32_t)sub->len;
    bson_ensure(b, sz);
    memcpy(b->data + b->len, &sz, 4);
    b->len += 4;
    memcpy(b->data + b->len, sub->data + 4, sub->len - 4);
    b->len += sub->len - 4;
    return 0;
}

int bson_append_array(bson_t* b, const char* key, const bson_t* sub) {
    if (!b || !key || !sub) return -1;
    bson_append_type_and_key(b, BSON_ARRAY, key);
    int32_t sz = (int32_t)sub->len;
    bson_ensure(b, sz);
    memcpy(b->data + b->len, &sz, 4);
    b->len += 4;
    memcpy(b->data + b->len, sub->data + 4, sub->len - 4);
    b->len += sub->len - 4;
    return 0;
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

static int bson_raw_iter(const bson_t* b, size_t* offset, raw_elem_t* e) {
    if (!b || !offset || !e) return -1;
    if (*offset == 0) *offset = 4;
    if (*offset >= b->len) return -1;
    uint8_t type = b->data[*offset];
    if (type == 0) return -1;
    e->type = (bson_type_t)type;
    e->elem_start = *offset;
    (*offset)++;
    e->key = (const char*)(b->data + *offset);
    size_t klen = strlen(e->key) + 1;
    *offset += klen;
    e->value_ptr = b->data + *offset;
    switch (type) {
        case BSON_INT32: e->value_len = 4; *offset += 4; break;
        case BSON_INT64:
        case BSON_DATETIME:
        case BSON_TIMESTAMP:
        case BSON_DOUBLE:
        case BSON_DECIMAL128:
            e->value_len = 8; *offset += 8; break;
        case BSON_STRING: {
            int32_t slen; memcpy(&slen, b->data + *offset, 4);
            e->value_len = 4 + slen; *offset += 4 + slen; break;
        }
        case BSON_BOOL: e->value_len = 1; *offset += 1; break;
        case BSON_NULL: e->value_len = 0; break;
        case BSON_BINARY: {
            int32_t blen; memcpy(&blen, b->data + *offset, 4);
            e->value_len = 5 + blen; *offset += 5 + blen; break;
        }
        case BSON_DOCUMENT:
        case BSON_ARRAY: {
            int32_t dlen; memcpy(&dlen, b->data + *offset, 4);
            e->value_len = dlen; *offset += dlen; break;
        }
        case BSON_OBJECTID: e->value_len = 12; *offset += 12; break;
        case BSON_REGEX: {
            const char* pat = (const char*)(b->data + *offset);
            size_t pl = strlen(pat) + 1; *offset += pl;
            const char* opt = (const char*)(b->data + *offset);
            size_t ol = strlen(opt) + 1; *offset += ol;
            e->value_len = pl + ol; break;
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
static void bson_to_json_rec(const bson_t* b, char* buf, size_t cap, size_t* len, int is_array);

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

static void bson_elem_to_json(const bson_element_t* e, char* buf, size_t cap, size_t* len) {
    switch (e->type) {
        case BSON_INT32: json_num((double)e->v.i32, buf, cap, len); break;
        case BSON_INT64: json_num((double)e->v.i64, buf, cap, len); break;
        case BSON_DOUBLE: json_num(e->v.d, buf, cap, len); break;
        case BSON_BOOL: { const char* s = e->v.b ? "true" : "false"; size_t l = strlen(s); if (*len + l < cap) { memcpy(buf + *len, s, l); *len += l; } } break;
        case BSON_STRING: if (*len < cap) buf[(*len)++] = '"'; json_escape(e->v.str, buf, cap, len); if (*len < cap) buf[(*len)++] = '"'; break;
        case BSON_NULL: { const char* s = "null"; size_t l = 4; if (*len + l < cap) { memcpy(buf + *len, s, l); *len += l; } } break;
        case BSON_DOCUMENT: { bson_t v = bson_view(e->v.doc.data, e->v.doc.len); bson_to_json_rec(&v, buf, cap, len, 0); } break;
        case BSON_ARRAY: { bson_t v = bson_view(e->v.doc.data, e->v.doc.len); bson_to_json_rec(&v, buf, cap, len, 1); } break;
        default: { const char* s = "null"; size_t l = 4; if (*len + l < cap) { memcpy(buf + *len, s, l); *len += l; } } break;
    }
}

static void bson_to_json_rec(const bson_t* b, char* buf, size_t cap, size_t* len, int is_array) {
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
        bson_elem_to_json(&e, buf, cap, len);
    }
    if (*len < cap) buf[(*len)++] = is_array ? ']' : '}';
}

char* bson_to_json(const bson_t* b) {
    if (!b) return NULL;
    char* buf = (char*)malloc(65536);
    if (!buf) return NULL;
    size_t len = 0;
    bson_to_json_rec(b, buf, 65536, &len, 0);
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

static int match_subfilter(const bson_t* doc, const bson_t* filter);

static int array_count(const bson_element_t* arr) {
    if (!arr || (arr->type != BSON_ARRAY && arr->type != BSON_DOCUMENT)) return -1;
    bson_t v = bson_view(arr->v.doc.data, arr->v.doc.len);
    size_t off = 0; bson_element_t e; int n = 0;
    while (bson_iter(&v, &off, &e) == 0) n++;
    return n;
}

int bson_match_operator(const bson_t* doc, const char* key, const bson_element_t* field,
                        const char* op, const bson_element_t* opval, const uint8_t* raw) {
    (void)raw;
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
                    if (match_subfilter(&iv, &sub)) return 1;
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
                if (bson_match_operator(doc, key, field, inner.key, &inner, NULL)) return 0;
            }
        }
        return 1;
    } else if (strcmp(op, "$where") == 0) {
        (void)doc; (void)key; (void)field; (void)opval;
        return 1;
    }
    return 0;
}

static int match_subfilter(const bson_t* doc, const bson_t* filter) {
    size_t off = 0;
    bson_element_t fe;
    while (bson_iter(filter, &off, &fe) == 0) {
        if (fe.key[0] == '$') {
            if (strcmp(fe.key, "$and") == 0) {
                if (fe.type != BSON_ARRAY) return 0;
                bson_t arr = bson_view(fe.v.doc.data, fe.v.doc.len);
                size_t aoff = 0; bson_element_t sub;
                while (bson_iter(&arr, &aoff, &sub) == 0) {
                    if (sub.type != BSON_DOCUMENT) return 0;
                    bson_t sv = bson_view(sub.v.doc.data, sub.v.doc.len);
                    if (!match_subfilter(doc, &sv)) return 0;
                }
            } else if (strcmp(fe.key, "$or") == 0) {
                if (fe.type != BSON_ARRAY) return 0;
                bson_t arr = bson_view(fe.v.doc.data, fe.v.doc.len);
                size_t aoff = 0; bson_element_t sub; int matched = 0;
                while (bson_iter(&arr, &aoff, &sub) == 0) {
                    if (sub.type == BSON_DOCUMENT) {
                        bson_t sv = bson_view(sub.v.doc.data, sub.v.doc.len);
                        if (match_subfilter(doc, &sv)) { matched = 1; break; }
                    }
                }
                if (!matched) return 0;
            } else if (strcmp(fe.key, "$nor") == 0) {
                if (fe.type != BSON_ARRAY) return 0;
                bson_t arr = bson_view(fe.v.doc.data, fe.v.doc.len);
                size_t aoff = 0; bson_element_t sub;
                while (bson_iter(&arr, &aoff, &sub) == 0) {
                    if (sub.type == BSON_DOCUMENT) {
                        bson_t sv = bson_view(sub.v.doc.data, sub.v.doc.len);
                        if (match_subfilter(doc, &sv)) return 0;
                    }
                }
            } else if (strcmp(fe.key, "$not") == 0) {
                if (fe.type == BSON_DOCUMENT) {
                    bson_t sv = bson_view(fe.v.doc.data, fe.v.doc.len);
                    if (match_subfilter(doc, &sv)) return 0;
                }
            } else if (strcmp(fe.key, "$where") == 0) {
                /* stubbed */
            } else {
                return 0;
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
                    if (!bson_match_operator(doc, fe.key, present ? &field : NULL, op.key, &op, NULL)) { all_ok = 0; break; }
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
    return match_subfilter(doc, filter);
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
                if (match_subfilter(&iv, &sub)) continue;
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
