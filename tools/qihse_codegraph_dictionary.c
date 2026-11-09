#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_dictionary.h"
#include "qihse_codegraph_progress.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zstd.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

/* QCGP0003: the QCGP0002 label/header table is preserved
 * exactly, while the body uses a reversible dictionary of exact quoted
 * strings and exact binary digests (16 or 32 bytes). References use dense varints.
 * A 16-byte digest uses dictionary kind 2 and requires outer feature bit 0;
 * legacy-only streams retain zero feature flags and their previous encoding.
 * Dictionary membership uses complete byte-and-length comparison, including all
 * 256 bits of a digest. Equal 128-bit prefixes never merge identities. Dense
 * varints identify dictionary positions rather than truncated content hashes.
 * This is a lossless byte transform, not a semantic JSON reconstruction.
 * Unknown fields, ordering, whitespace and numeric spelling remain exact. */
enum { OUTER = 56, HEADER_MAX = 256, KEY_MAX = 65535,
       VALUE_MAX = 16 * 1024 * 1024, TAG_LITERAL = 0,
       TAG_NODE = 1, TAG_EDGE = 2, WINDOW_LOG = 23 };
static const unsigned char magic[8] = {'Q','C','G','P','0','0','0','3'};
typedef struct { unsigned char *data; size_t len, cap; } buffer;
typedef struct { size_t off, len; } key_span;

typedef struct {
    size_t key_len, value_len;
    uint16_t classification, sci;
    uint8_t flags;
} record_header;

static bool active(qihse_user_t *user, uint16_t classification, uint16_t sci) {
    return user && qihse_auth_user_is_active(user) &&
           qihse_auth_can_access(user, classification, sci);
}
static bool limits(size_t *bytes, size_t *records) {
    if (!bytes || !records || !*bytes || !*records) { errno = EINVAL; return false; }
    if (*bytes > CG_DICTIONARY_MAX_RAW_BYTES) *bytes = CG_DICTIONARY_MAX_RAW_BYTES;
    if (*records > CG_DICTIONARY_MAX_RECORDS) *records = CG_DICTIONARY_MAX_RECORDS;
    return true;
}
static void release(buffer *b) {
    if (b->data) { OPENSSL_cleanse(b->data, b->len); free(b->data); }
    memset(b, 0, sizeof(*b));
}
static bool grow(buffer *b, size_t extra, size_t limit) {
    if (extra > limit || b->len > limit - extra) { errno = EFBIG; return false; }
    size_t want = b->len + extra;
    if (want <= b->cap) return true;
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < want) {
        if (cap > limit / 2) { cap = limit; break; }
        cap *= 2;
    }
    if (cap < want) { errno = EFBIG; return false; }
    unsigned char *next = realloc(b->data, cap);
    if (!next) { errno = ENOMEM; return false; }
    b->data = next; b->cap = cap;
    return true;
}
static bool append(buffer *b, const void *data, size_t amount, size_t limit) {
    if (!grow(b, amount, limit)) return false;
    if (amount) memcpy(b->data + b->len, data, amount);
    b->len += amount; return true;
}
static bool read_append(buffer *b, FILE *input, size_t amount, size_t limit) {
    if (!grow(b, amount, limit)) return false;
    if (fread(b->data + b->len, 1, amount, input) != amount) {
        errno = EINVAL; return false;
    }
    if (memchr(b->data + b->len, 0, amount)) { errno = EINVAL; return false; }
    b->len += amount; return true;
}
static uint16_t get16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t get32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t get64(const unsigned char *p) {
    uint64_t n = 0;
    for (size_t i = 0; i < 8; i++) n = (n << 8) | p[i];
    return n;
}
static void put16(unsigned char *p, uint16_t n) {
    p[0] = (unsigned char)(n >> 8); p[1] = (unsigned char)n;
}
static void put32(unsigned char *p, uint32_t n) {
    for (size_t i = 0; i < 4; i++) p[i] = (unsigned char)(n >> (24 - i * 8));
}
static void put64(unsigned char *p, uint64_t n) {
    for (size_t i = 0; i < 8; i++) p[i] = (unsigned char)(n >> (56 - i * 8));
}
static unsigned char hexchar(unsigned value) {
    return (unsigned char)(value < 10 ? '0' + value : 'a' + value - 10);
}
/* Parse only the seven stable snapshot fields. A future suffix stays in the
 * saved line verbatim; unsupported/changed field positions fail closed. */
static bool parse_header(const unsigned char *line, size_t length, record_header *r) {
    if (!line || !r || length < 2 || length >= HEADER_MAX ||
        line[length - 1] != '\n' || memchr(line, 0, length)) { errno = EINVAL; return false; }
    uint64_t field[7] = {0}; size_t pos = 0;
    for (size_t k = 0; k < 7; k++) {
        size_t start = pos;
        while (pos < length && line[pos] >= '0' && line[pos] <= '9') {
            unsigned digit = line[pos++] - '0';
            if (field[k] > (UINT64_MAX - digit) / 10) { errno = EINVAL; return false; }
            field[k] = field[k] * 10 + digit;
        }
        if (pos == start || pos >= length) { errno = EINVAL; return false; }
        if (k < 6) {
            if (line[pos] != ' ' && line[pos] != '\t') { errno = EINVAL; return false; }
            while (pos < length && (line[pos] == ' ' || line[pos] == '\t')) pos++;
        } else if (line[pos] != '\n' && line[pos] != ' ' && line[pos] != '\t') {
            errno = EINVAL; return false;
        }
    }
    if (!field[0] || field[0] > KEY_MAX || field[1] > VALUE_MAX ||
        field[3] > UINT16_MAX || field[4] > UINT16_MAX || field[5] > 1 ||
        (field[5] && field[1])) { errno = EINVAL; return false; }
    r->key_len = (size_t)field[0]; r->value_len = (size_t)field[1];
    r->classification = (uint16_t)field[3]; r->sci = (uint16_t)field[4];
    r->flags = (uint8_t)field[5];
    return true;
}
static bool compress_frame(const buffer *plain, buffer *encoded) {
    ZSTD_CCtx *ctx = ZSTD_createCCtx();
    if (!ctx) { errno = ENOMEM; return false; }
    size_t bound = ZSTD_compressBound(plain->len);
    size_t maximum = ZSTD_compressBound(CG_DICTIONARY_MAX_TOKEN_BYTES);
    bool ok = bound <= maximum &&
              grow(encoded, bound, maximum) &&
              !ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, 9)) &&
              !ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_windowLog, WINDOW_LOG)) &&
              !ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)) &&
              !ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(ctx, plain->len));
    if (ok) {
        static const unsigned char empty = 0;
        size_t n = ZSTD_compress2(ctx, encoded->data, encoded->cap,
                                  plain->len ? plain->data : &empty, plain->len);
        ok = !ZSTD_isError(n);
        if (ok) encoded->len = n;
    }
    if (!ok && errno == 0) errno = EINVAL;
    ZSTD_freeCCtx(ctx); return ok;
}
static bool decompress_frame(const unsigned char *source, size_t encoded_len,
                             size_t decoded_len, buffer *out) {
    ZSTD_frameHeader head;
    if (ZSTD_getFrameHeader(&head, source, encoded_len) != 0 ||
        head.checksumFlag != 1 || head.windowSize > (1u << WINDOW_LOG) ||
        head.frameContentSize != decoded_len ||
        ZSTD_findFrameCompressedSize(source, encoded_len) != encoded_len) {
        errno = EINVAL; return false;
    }
    if (!grow(out, decoded_len ? decoded_len : 1, CG_DICTIONARY_MAX_TOKEN_BYTES))
        return false;
    ZSTD_DCtx *ctx = ZSTD_createDCtx();
    if (!ctx) { errno = ENOMEM; return false; }
    size_t n = ZSTD_decompressDCtx(ctx, out->data, decoded_len,
                                   source, encoded_len);
    ZSTD_freeDCtx(ctx);
    if (ZSTD_isError(n) || n != decoded_len) { errno = EINVAL; return false; }
    out->len = decoded_len; return true;
}
static bool check_streams(FILE *input, FILE *output, qihse_user_t *user,
                          size_t *max_bytes, size_t *max_records) {
    if (!active(user, 0, 0)) { errno = EACCES; return false; }
    if (!input || !output || input == output ||
        !limits(max_bytes, max_records) || ferror(input) || ferror(output) ||
        ftello(output) != 0) { errno = EINVAL; return false; }
    return true;
}

typedef struct {
    size_t off;
    uint32_t len, id;
    bool digest;
} token;

static bool lower_hex(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}
static unsigned unhex(unsigned char c) {
    return c <= '9' ? c - '0' : c - 'a' + 10;
}
static bool varint(buffer *out, uint32_t n) {
    unsigned char bytes[5]; size_t used = 0;
    do { bytes[used++] = (unsigned char)((n & 127) | (n > 127 ? 128 : 0)); n >>= 7; } while (n);
    return append(out, bytes, used, CG_DICTIONARY_MAX_TOKEN_BYTES);
}
static bool read_varint(const buffer *input, size_t *offset, uint32_t *value) {
    uint32_t result = 0;
    for (unsigned shift = 0; shift <= 28; shift += 7) {
        if (*offset >= input->len) { errno = EINVAL; return false; }
        unsigned char byte = input->data[(*offset)++];
        if (shift == 28 && (byte & 240)) { errno = EINVAL; return false; }
        result |= (uint32_t)(byte & 127) << shift;
        if (!(byte & 128)) {
            if (shift && byte == 0) { errno = EINVAL; return false; }
            *value = result; return true;
        }
    }
    errno = EINVAL; return false;
}
static int compare_tokens(const void *left, const void *right, void *context) {
    const token *a = *(const token *const *)left;
    const token *b = *(const token *const *)right;
    const unsigned char *bytes = context;
    if (a->digest != b->digest) return a->digest ? -1 : 1;
    size_t n = a->len < b->len ? a->len : b->len;
    int result = memcmp(bytes + a->off, bytes + b->off, n);
    return result ? result : (a->len > b->len) - (a->len < b->len);
}
static bool add_token(token **items, size_t *count, size_t *capacity,
                       size_t off, size_t len, bool digest) {
    if (*count >= CG_DICTIONARY_MAX_TOKENS) { errno = E2BIG; return false; }
    if (*count == *capacity) {
        size_t next = *capacity ? *capacity * 2 : 256;
        if (next > CG_DICTIONARY_MAX_TOKENS) next = CG_DICTIONARY_MAX_TOKENS;
        token *p = realloc(*items, next * sizeof(*p));
        if (!p) { errno = ENOMEM; return false; }
        *items = p; *capacity = next;
    }
    (*items)[(*count)++] = (token){off, (uint32_t)len, UINT32_MAX, digest};
    return true;
}
/* Candidate spans need not interpret JSON semantics. Escaped quoted strings
 * and digest bytes are retained exactly, so even future/non-JSON values are
 * reversible. A run is never shortened, quantized, or canonicalized. */
static bool scan_tokens(const buffer *body, token **items, size_t *count) {
    size_t capacity = 0;
    for (size_t pos = 0; pos < body->len;) {
        size_t start = pos, end;
        if (body->data[pos] == '"') {
            end = ++pos;
            bool closed = false;
            while (end < body->len) {
                if (body->data[end] == '\\') { end += body->len - end > 1 ? 2 : 1; continue; }
                if (body->data[end++] == '"') { closed = true; break; }
            }
            if (!closed) break;
            size_t length = end - start;
            bool digest = length == 66 || length == 34;
            for (size_t i = start + 1; digest && i + 1 < end; ++i)
                digest = lower_hex(body->data[i]);
            if (digest) {
                if (!add_token(items, count, &capacity, start + 1, length - 2, true)) return false;
            } else if (length >= 10 &&
                       !add_token(items, count, &capacity, start, length, false)) return false;
            pos = end;
        } else if (lower_hex(body->data[pos])) {
            while (pos < body->len && lower_hex(body->data[pos])) pos++;
            if ((pos - start == 64 || pos - start == 32) &&
                !add_token(items, count, &capacity, start, pos - start, true)) return false;
        } else pos++;
    }
    return true;
}
static bool literal(buffer *out, const unsigned char *bytes, size_t length) {
    return !length || (varint(out, (uint32_t)length << 1) &&
                       append(out, bytes, length, CG_DICTIONARY_MAX_TOKEN_BYTES));
}
static bool encode_tokens(const buffer *body, buffer *out, uint32_t *features) {
    *features = 0;
    token *items = NULL, **sorted = NULL;
    buffer dictionary = {0};
    size_t count = 0; uint32_t entries = 0;
    bool ok = false;
    if (!scan_tokens(body, &items, &count)) goto done;
    sorted = malloc((count ? count : 1) * sizeof(*sorted));
    if (!sorted) { errno = ENOMEM; goto done; }
    for (size_t i = 0; i < count; ++i) sorted[i] = items + i;
    qsort_r(sorted, count, sizeof(*sorted), compare_tokens, body->data);
    for (size_t begin = 0; begin < count;) {
        size_t end = begin + 1;
        while (end < count && !compare_tokens(sorted + begin, sorted + end, body->data)) end++;
        token *item = sorted[begin];
        if (item->digest || end - begin > 1) {
            unsigned char kind = item->digest ? (item->len == 32 ? 2 : 1) : 0;
            if (kind == 2) *features |= CG_DICTIONARY_FEATURE_DIGEST128;
            if (!append(&dictionary, &kind, 1, CG_DICTIONARY_MAX_TOKEN_BYTES)) goto done;
            if (item->digest) {
                unsigned char digest[32];
                for (size_t i = 0; i < item->len / 2; ++i)
                    digest[i] = (unsigned char)((unhex(body->data[item->off + 2*i]) << 4) |
                                               unhex(body->data[item->off + 2*i + 1]));
                if (!append(&dictionary, digest, item->len / 2, CG_DICTIONARY_MAX_TOKEN_BYTES)) goto done;
            } else if (!varint(&dictionary, item->len) ||
                       !append(&dictionary, body->data + item->off, item->len,
                               CG_DICTIONARY_MAX_TOKEN_BYTES)) goto done;
            for (size_t i = begin; i < end; ++i) sorted[i]->id = entries;
            entries++;
        }
        begin = end;
    }
    if (!varint(out, entries) ||
        !append(out, dictionary.data, dictionary.len, CG_DICTIONARY_MAX_TOKEN_BYTES)) goto done;
    size_t previous = 0;
    for (size_t i = 0; i < count; ++i) {
        if (items[i].id == UINT32_MAX) continue;
        if (!literal(out, body->data + previous, items[i].off - previous) ||
            !varint(out, ((items[i].id + 1) << 1) | 1)) goto done;
        previous = items[i].off + items[i].len;
    }
    ok = literal(out, body->data ? body->data + previous : NULL, body->len - previous);
done:
    free(items); free(sorted); release(&dictionary);
    return ok;
}
static bool decode_tokens(const buffer *tokens, buffer *body, size_t expected, uint32_t features) {
    size_t offset = 0;
    uint32_t count;
    if (!read_varint(tokens, &offset, &count) || count > CG_DICTIONARY_MAX_TOKENS ||
        count > (tokens->len - offset) / 12) {
        errno = EINVAL; return false;
    }
    token *dictionary = calloc(count ? count : 1, sizeof(*dictionary));
    if (!dictionary) { errno = ENOMEM; return false; }
    bool ok = false;
    for (uint32_t i = 0; i < count; ++i) {
        if (offset == tokens->len) { errno = EINVAL; goto done; }
        unsigned char kind = tokens->data[offset++];
        uint32_t length = kind == 2 ? 16 : 32;
        if (kind > 2 || (kind == 2 && !(features & CG_DICTIONARY_FEATURE_DIGEST128)) || (!kind && (!read_varint(tokens, &offset, &length) || length < 10)) ||
            length > tokens->len - offset) { errno = EINVAL; goto done; }
        dictionary[i] = (token){offset, length, 0, kind != 0};
        offset += length;
    }
    while (offset < tokens->len) {
        uint32_t op;
        if (!read_varint(tokens, &offset, &op) || op < 2) { errno = EINVAL; goto done; }
        if (op & 1) {
            uint32_t id = (op >> 1) - 1;
            if (id >= count) { errno = EINVAL; goto done; }
            token *item = dictionary + id;
            if (item->digest) {
                unsigned char hex[64];
                for (size_t i = 0; i < item->len; ++i) {
                    unsigned char n = tokens->data[item->off + i];
                    hex[2*i] = hexchar(n >> 4); hex[2*i+1] = hexchar(n & 15);
                }
                if (!append(body, hex, item->len * 2, expected)) goto done;
            } else if (!append(body, tokens->data + item->off, item->len, expected)) goto done;
        } else {
            size_t length = op >> 1;
            if (length > tokens->len - offset ||
                !append(body, tokens->data + offset, length, expected)) {
                errno = EINVAL; goto done;
            }
            offset += length;
        }
    }
    ok = body->len == expected;
    if (!ok) errno = EINVAL;
done:
    free(dictionary); return ok;
}

bool cg_dictionary_encode_snapshot(FILE *authorized_export, FILE *packed_output,
                               qihse_user_t *principal, size_t max_bytes,
                               size_t max_records) {
    if (!check_streams(authorized_export, packed_output, principal,
                       &max_bytes, &max_records)) return false;
    buffer table = {0}, body = {0}, tokens = {0}, meta_zip = {0}, body_zip = {0};
    unsigned char *key = malloc(KEY_MAX);
    if (!key) { errno = ENOMEM; return false; }
    size_t raw_bytes = 0, records = 0;
    uint16_t required_class = 0, required_sci = 0;
    bool ok = false;
    uint32_t features = 0;
    cg_progress_emit("encode-v3","bytes",0,UINT64_MAX);
    for (;;) {
        char header[HEADER_MAX];
        if (!fgets(header, sizeof(header), authorized_export)) {
            if (ferror(authorized_export)) errno = EIO;
            else ok = true;
            break;
        }
        size_t hlen = strlen(header);
        record_header r;
        if (!parse_header((const unsigned char *)header, hlen, &r)) break;
        if (!active(principal, r.classification, r.sci)) { errno = EACCES; break; }
        if (records >= max_records) { errno = E2BIG; break; }
        if (hlen > max_bytes || r.key_len > max_bytes - hlen ||
            r.value_len + 1 > max_bytes - hlen - r.key_len ||
            raw_bytes > max_bytes - (hlen + r.key_len + r.value_len + 1)) {
            errno = EFBIG; break;
        }
        if (fread(key, 1, r.key_len, authorized_export) != r.key_len ||
            memchr(key, 0, r.key_len)) { errno = EINVAL; break; }
        /* Preserve exact key text until the reversible token transform can
         * share its digest with matching JSON values and endpoint references. */
        uint8_t tag = TAG_LITERAL;
        unsigned char length[2]; put16(length, (uint16_t)hlen);
        if (!append(&table, length, 2, max_bytes) ||
            !append(&table, header, hlen, max_bytes) ||
            !append(&table, &tag, 1, max_bytes)) break;
        if (!append(&body, key, r.key_len, max_bytes)) break;
        if (!read_append(&body, authorized_export, r.value_len, max_bytes)) break;
        if (fgetc(authorized_export) != '\n') { errno = EINVAL; break; }
        raw_bytes += hlen + r.key_len + r.value_len + 1;
        records++;
        if(!(records%1024))cg_progress_emit("encode-v3","bytes",raw_bytes,UINT64_MAX);
        if (r.classification > required_class) required_class = r.classification;
        required_sci |= r.sci;
    }
    if (ok && active(principal, required_class, required_sci))
        ok = encode_tokens(&body, &tokens, &features) && compress_frame(&table, &meta_zip) &&
             compress_frame(&tokens, &body_zip);
    else if (ok) { errno = EACCES; ok = false; }
    if (ok) {
        unsigned char outer[OUTER] = {0};
        memcpy(outer, magic, 8);
        put64(outer + 8, raw_bytes); put64(outer + 16, table.len);
        put64(outer + 24, body.len); put32(outer + 32, (uint32_t)records);
        put32(outer + 36, (uint32_t)meta_zip.len);
        put32(outer + 40, (uint32_t)body_zip.len);
        put32(outer + 44, features);
        put64(outer + 48, tokens.len);
        ok = fwrite(outer, 1, OUTER, packed_output) == OUTER &&
             fwrite(meta_zip.data, 1, meta_zip.len, packed_output) == meta_zip.len &&
             fwrite(body_zip.data, 1, body_zip.len, packed_output) == body_zip.len &&
             fflush(packed_output) == 0 &&
             active(principal, required_class, required_sci);
        if (!ok && errno == 0) errno = EIO;
    }
    if(ok)cg_progress_emit("encode-v3","bytes",raw_bytes,raw_bytes);
    release(&table); release(&body); release(&tokens); release(&meta_zip); release(&body_zip);
    OPENSSL_cleanse(key, KEY_MAX); free(key);
    return ok;
}

static bool parse_table(const buffer *table, size_t expected_records,
                        size_t max_bytes, qihse_user_t *user,
                        size_t *body_expected, size_t *raw_expected,
                        uint16_t *required_class, uint16_t *required_sci) {
    size_t off = 0, body = 0, raw = 0;
    for (size_t i = 0; i < expected_records; i++) {
        if (table->len - off < 2) { errno = EINVAL; return false; }
        size_t hlen = get16(table->data + off); off += 2;
        if (hlen >= HEADER_MAX || table->len - off < hlen + 1) {
            errno = EINVAL; return false;
        }
        record_header r;
        if (!parse_header(table->data + off, hlen, &r)) return false;
        off += hlen;
        uint8_t tag = table->data[off++];
        if (tag > TAG_EDGE || (tag != TAG_LITERAL && r.key_len != 66)) {
            errno = EINVAL; return false;
        }
        if (!active(user, r.classification, r.sci)) { errno = EACCES; return false; }
        size_t key_bytes = tag == TAG_LITERAL ? r.key_len : 32;
        if (key_bytes > max_bytes - body || r.value_len > max_bytes - body - key_bytes ||
            hlen > max_bytes - raw || r.key_len > max_bytes - raw - hlen ||
            r.value_len + 1 > max_bytes - raw - hlen - r.key_len) {
            errno = EFBIG; return false;
        }
        body += key_bytes + r.value_len;
        raw += hlen + r.key_len + r.value_len + 1;
        if (r.classification > *required_class) *required_class = r.classification;
        *required_sci |= r.sci;
    }
    if (off != table->len) { errno = EINVAL; return false; }
    *body_expected = body; *raw_expected = raw;
    return true;
}
static int compare_spans(const void *a, const void *b, void *context) {
    const unsigned char *raw = context;
    const key_span *x = a, *y = b;
    size_t common = x->len < y->len ? x->len : y->len;
    int cmp = memcmp(raw + x->off, raw + y->off, common);
    return cmp ? cmp : (x->len > y->len) - (x->len < y->len);
}
static bool reconstruct(const buffer *table, const buffer *body,
                        size_t expected_records, buffer *raw,
                        size_t max_bytes,qihse_user_t *principal,uint16_t required_class,uint16_t required_sci) {
    key_span *keys = calloc(expected_records ? expected_records : 1, sizeof(*keys));
    if (!keys) { errno = ENOMEM; return false; }
    size_t toff = 0, boff = 0;
    bool ok = true;
    for (size_t i = 0; i < expected_records; i++) {
        if(!(i%1024)){
            if(!active(principal,required_class,required_sci)){errno=EACCES;ok=false;break;}
            cg_progress_emit("decode","bytes",raw->len,UINT64_MAX);
        }
        size_t hlen = get16(table->data + toff); toff += 2;
        const unsigned char *header = table->data + toff;
        record_header r;
        if (!parse_header(header, hlen, &r) ||
            !append(raw, header, hlen, max_bytes)) { ok = false; break; }
        toff += hlen;
        uint8_t tag = table->data[toff++];
        keys[i] = (key_span){.off = raw->len, .len = r.key_len};
        if (tag == TAG_LITERAL) {
            if (memchr(body->data + boff, 0, r.key_len) ||
                !append(raw, body->data + boff, r.key_len, max_bytes)) {
                errno = EINVAL; ok = false; break;
            }
            boff += r.key_len;
        } else {
            unsigned char key[66]; key[0] = tag == TAG_NODE ? 'n' : 'e'; key[1] = ':';
            for (size_t j = 0; j < 32; j++) {
                key[2 + 2*j] = hexchar(body->data[boff+j] >> 4);
                key[3 + 2*j] = hexchar(body->data[boff+j] & 15);
            }
            if (!append(raw, key, sizeof(key), max_bytes)) { ok = false; break; }
            boff += 32;
        }
        if (memchr(body->data + boff, 0, r.value_len) ||
            !append(raw, body->data + boff, r.value_len, max_bytes) ||
            !append(raw, "\n", 1, max_bytes)) { errno = EINVAL; ok = false; break; }
        boff += r.value_len;
    }
    if (ok && boff != body->len) { errno = EINVAL; ok = false; }
    if (ok) {
        qsort_r(keys, expected_records, sizeof(*keys), compare_spans, raw->data);
        for (size_t i = 1; i < expected_records; i++) {
            if (compare_spans(keys + i - 1, keys + i, raw->data) == 0) {
                errno = EINVAL; ok = false; break;
            }
        }
    }
    free(keys); return ok;
}

/* A checksum only detects accidental corruption. The expected digest must
 * come from trusted publication metadata, never from the encoded file itself. */
static bool copy_verified_input(FILE *input, const cg_snapshot_checksum *expected,
                                qihse_user_t *principal, buffer *copy) {
    struct stat before, after;
    const size_t limit = 2 * CG_DICTIONARY_MAX_TOKEN_BYTES + OUTER;
    if (!cg_checksum_valid(expected) || !active(principal, 0, 0) ||
        fstat(fileno(input), &before) || !S_ISREG(before.st_mode) ||
        before.st_size < OUTER || (uint64_t)before.st_size > limit) {
        errno = EINVAL; return false;
    }
    if (!grow(copy, (size_t)before.st_size, limit)) return false;
    bool ok = true;
    /* Parse only the immutable pread copy. The checksum is computed over those
     * same bytes, ignoring caller stdio caches and pushback. */
    while (ok && copy->len < (size_t)before.st_size) {
        if (!active(principal, 0, 0)) { ok = false; break; }
        size_t want = (size_t)before.st_size - copy->len;
        if (want > 65536) want = 65536;
        ssize_t n = pread(fileno(input), copy->data + copy->len, want, (off_t)copy->len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        copy->len += (size_t)n;
    }
    cg_snapshot_checksum actual;
    if (ok) ok = cg_snapshot_checksum_buffer_user(copy->data, copy->len, principal,
                                                   expected->algorithm, &actual);
    if (!active(principal, 0, 0)) return false;
    if (!ok || fstat(fileno(input), &after) || after.st_dev != before.st_dev ||
        after.st_ino != before.st_ino || after.st_size != before.st_size ||
        after.st_mtim.tv_sec != before.st_mtim.tv_sec ||
        after.st_mtim.tv_nsec != before.st_mtim.tv_nsec ||
        after.st_ctim.tv_sec != before.st_ctim.tv_sec ||
        after.st_ctim.tv_nsec != before.st_ctim.tv_nsec || !active(principal, 0, 0)) {
        errno = EIO; return false;
    }
    if (strcmp(actual.hex, expected->hex)) { errno = EINVAL; return false; }
    return true;
}

static bool decode_verified_snapshot(FILE *packed_input, FILE *raw_output,
                                      qihse_user_t *principal, size_t max_bytes,
                                      size_t max_records) {
    unsigned char outer[OUTER];
    if (fread(outer, 1, OUTER, packed_input) != OUTER ||
        memcmp(outer, magic, 8) ||
        (get32(outer + 44) & ~CG_DICTIONARY_FEATURE_DIGEST128) ||
        get64(outer + 48) > CG_DICTIONARY_MAX_TOKEN_BYTES ||
        get64(outer + 48) > 2 * get64(outer + 24) + 16) {
        errno = EINVAL; return false;
    }
    /* Resource limits are distinct from corruption: the storage layer may
     * retry a valid generation through its bounded durable load path. */
    if (get64(outer + 8) > max_bytes || get64(outer + 16) > max_bytes ||
        get64(outer + 24) > max_bytes) { errno = EFBIG; return false; }
    if (get32(outer + 32) > max_records) { errno = E2BIG; return false; }
    size_t raw_len = (size_t)get64(outer + 8);
    size_t meta_len = (size_t)get64(outer + 16);
    size_t body_len = (size_t)get64(outer + 24);
    size_t token_len = (size_t)get64(outer + 48);
    size_t meta_zip_len = get32(outer + 36), body_zip_len = get32(outer + 40);
    if (!meta_zip_len || !body_zip_len ||
        meta_zip_len > ZSTD_compressBound(meta_len) ||
        body_zip_len > ZSTD_compressBound(token_len)) { errno = EINVAL; return false; }
    buffer meta_zip = {0}, body_zip = {0}, table = {0}, body = {0}, raw = {0}, tokens = {0};
    bool ok = false;
    if (!grow(&meta_zip, meta_zip_len, ZSTD_compressBound(CG_DICTIONARY_MAX_TOKEN_BYTES)) ||
        fread(meta_zip.data, 1, meta_zip_len, packed_input) != meta_zip_len)
        goto done;
    meta_zip.len = meta_zip_len;
    if (!decompress_frame(meta_zip.data, meta_zip.len, meta_len, &table)) goto done;
    uint16_t required_class = 0, required_sci = 0;
    size_t body_expected = 0, raw_expected = 0;
    size_t records = get32(outer + 32);
    if (!parse_table(&table, records, max_bytes, principal,
                     &body_expected, &raw_expected,
                     &required_class, &required_sci) ||
        body_expected != body_len || raw_expected != raw_len) {
        if (errno == 0) errno = EINVAL;
        goto done;
    }
    if (!grow(&body_zip, body_zip_len, ZSTD_compressBound(CG_DICTIONARY_MAX_TOKEN_BYTES)) ||
        fread(body_zip.data, 1, body_zip_len, packed_input) != body_zip_len)
        goto done;
    body_zip.len = body_zip_len;
    if (fgetc(packed_input) != EOF || ferror(packed_input) ||
        !decompress_frame(body_zip.data, body_zip.len, token_len, &tokens) ||
        !decode_tokens(&tokens, &body, body_len, get32(outer + 44)) ||
        !reconstruct(&table, &body, records, &raw, max_bytes,principal,required_class,required_sci) ||
        raw.len != raw_len || !active(principal, required_class, required_sci)) {
        if (errno == 0) errno = EINVAL;
        goto done;
    }
    /* No caller-visible bytes precede complete validation and authorization. */
    if ((raw.len && fwrite(raw.data, 1, raw.len, raw_output) != raw.len) ||
        fflush(raw_output) != 0 || !active(principal, required_class, required_sci)) {
        errno = EIO; goto done;
    }
    ok = true;
    cg_progress_emit("decode","bytes",raw.len,raw.len);
done:
    release(&meta_zip); release(&body_zip); release(&table);
    release(&body); release(&raw); release(&tokens);
    return ok;
}

bool cg_dictionary_decode_checksum_snapshot(FILE *encoded_input, FILE *raw_output,
                                qihse_user_t *principal, const cg_snapshot_checksum *expected,
                                size_t max_bytes, size_t max_records) {
    if (!check_streams(encoded_input, raw_output, principal, &max_bytes, &max_records))
        return false;
    buffer verified = {0};
    FILE *reader = NULL;
    bool ok = copy_verified_input(encoded_input, expected, principal, &verified);
    if (ok) {
        reader = fmemopen(verified.data, verified.len, "rb");
        ok = reader && decode_verified_snapshot(reader, raw_output, principal,
                                                max_bytes, max_records);
    }
    if (reader) fclose(reader);
    release(&verified);
    return ok;
}

bool cg_dictionary_decode_snapshot(FILE *input, FILE *output, qihse_user_t *user,
    const char *expected_sha256, size_t max_bytes, size_t max_records) {
    if (!expected_sha256 || strlen(expected_sha256) != 64) { errno=EINVAL; return false; }
    cg_snapshot_checksum expected = {.algorithm=CG_CHECKSUM_SHA256};
    memcpy(expected.hex, expected_sha256, 65);
    return cg_dictionary_decode_checksum_snapshot(input, output, user, &expected,
                                                   max_bytes, max_records);
}

/* ---- QCGP0004 bounded columnar chunks ----
 * Kept beside the token transform so v3 and v4 share exactly one lossless
 * dictionary implementation. No JSON schema/float/string normalization occurs.
 */
#include "codegraph_xxh3/include/qihse_xxh3.h"
#include "qihse_codegraph_chunked.h"
enum {
    CH_OUTER = 64,
    CH_HEADER = 112,
    CH_COLUMNS = 9,
    CH_BODY = 8,
    CH_TOKEN_LIMIT = 2 * CG_CHUNKED_MAX_CHUNK_BYTES + 16,
    CH_RECORD_LIMIT = 100000,
    CH_BUCKETS = 65536
};
_Static_assert(CG_CHUNKED_TARGET_RAW_BYTES >= (1u << 20) &&
                   CG_CHUNKED_TARGET_RAW_BYTES <= CG_CHUNKED_MAX_CHUNK_BYTES,
               "chunk target must be between one MiB and the hard bound");
static const unsigned char chunk_magic[8] = {'Q', 'C', 'G', 'P', '0', '0', '0', '4'};
typedef struct {
    buffer columns[CH_COLUMNS];
    size_t raw, records;
    uint16_t classification, sci;
} chunk_build;
static bool chunk_varint(buffer *b, uint64_t n, size_t limit) {
    unsigned char bytes[10];
    size_t used = 0;
    do {
        bytes[used++] = (unsigned char)((n & 127) | (n > 127 ? 128 : 0));
        n >>= 7;
    } while (n);
    return append(b, bytes, used, limit);
}
static bool chunk_read_varint(const buffer *b, size_t *off, uint64_t *value) {
    uint64_t n = 0;
    for (unsigned shift = 0; shift <= 63; shift += 7) {
        if (*off >= b->len) {
            errno = EINVAL;
            return false;
        }
        unsigned char c = b->data[(*off)++];
        if (shift == 63 && (c & 254)) {
            errno = EINVAL;
            return false;
        }
        n |= (uint64_t)(c & 127) << shift;
        if (!(c & 128)) {
            if (shift && !c) {
                errno = EINVAL;
                return false;
            }
            *value = n;
            return true;
        }
    }
    errno = EINVAL;
    return false;
}
static bool chunk_fields(const unsigned char *line, size_t len, uint64_t fields[7]) {
    record_header r;
    if (!parse_header(line, len, &r))
        return false;
    size_t off = 0;
    for (size_t k = 0; k < 7; k++) {
        fields[k] = 0;
        while (off < len && line[off] >= '0' && line[off] <= '9')
            fields[k] = fields[k] * 10 + (unsigned)(line[off++] - '0');
        if (k < 6)
            while (off < len && (line[off] == ' ' || line[off] == '\t'))
                off++;
    }
    return true;
}
static size_t chunk_format(char line[HEADER_MAX], const uint64_t f[7]) {
    int n =
        snprintf(line, HEADER_MAX, "%llu %llu %llu %llu %llu %llu %llu\n", (unsigned long long)f[0],
                 (unsigned long long)f[1], (unsigned long long)f[2], (unsigned long long)f[3],
                 (unsigned long long)f[4], (unsigned long long)f[5], (unsigned long long)f[6]);
    return n > 0 && n < HEADER_MAX ? (size_t)n : 0;
}
static void chunk_clear(chunk_build *b) {
    for (size_t i = 0; i < CH_COLUMNS; i++)
        release(b->columns + i);
    memset(b, 0, sizeof(*b));
}
static bool chunk_flush(chunk_build *b, FILE *out, qihse_user_t *user) {
    if (!b->records)
        return true;
    buffer zip[CH_COLUMNS] = {{0}}, tokens = {0};
    uint32_t features = 0;
    bool ok = false;
    if (!active(user, b->classification, b->sci) ||
        !encode_tokens(b->columns + CH_BODY, &tokens, &features) || tokens.len > CH_TOKEN_LIMIT)
        goto done;
    unsigned char h[CH_HEADER] = {0};
    put64(h, b->raw);
    put32(h + 8, (uint32_t)b->records);
    put32(h + 12, features);
    put64(h + 16, b->columns[CH_BODY].len);
    put64(h + 24, tokens.len);
    put16(h + 104, b->classification);
    put16(h + 106, b->sci);
    for (size_t i = 0; i < CH_COLUMNS; i++) {
        const buffer *plain = i == CH_BODY ? &tokens : b->columns + i;
        if (!compress_frame(plain, zip + i) || plain->len > UINT32_MAX || zip[i].len > UINT32_MAX)
            goto done;
        put32(h + 32 + 4 * i, (uint32_t)plain->len);
        put32(h + 68 + 4 * i, (uint32_t)zip[i].len);
    }
    if (fwrite(h, 1, sizeof(h), out) != sizeof(h))
        goto done;
    for (size_t i = 0; i < CH_COLUMNS; i++)
        if (fwrite(zip[i].data, 1, zip[i].len, out) != zip[i].len)
            goto done;
    ok = active(user, b->classification, b->sci);
done:
    for (size_t i = 0; i < CH_COLUMNS; i++)
        release(zip + i);
    release(&tokens);
    return ok;
}
static bool chunk_streams(FILE *in, FILE *out, qihse_user_t *user, size_t max_bytes,
                          size_t max_records) {
    if (!active(user, 0, 0)) {
        errno = EACCES;
        return false;
    }
    if (!in || !out || in == out || !max_bytes || !max_records ||
        max_bytes > CG_CHUNKED_MAX_RAW_BYTES || max_records > CG_CHUNKED_MAX_RECORDS ||
        ferror(in) || ferror(out) || ftello(out) != 0) {
        errno = EINVAL;
        return false;
    }
    return true;
}
bool cg_chunked_encode_snapshot(FILE *in, FILE *out, qihse_user_t *user, size_t max_bytes,
                                size_t max_records) {
    if (!chunk_streams(in, out, user, max_bytes, max_records))
        return false;
    chunk_build b = {0};
    uint64_t raw = 0, records = 0;
    uint32_t chunks = 0;
    uint16_t classification = 0, sci = 0;
    bool ok = false;
    unsigned char outer[CH_OUTER] = {0};
    if (fwrite(outer, 1, sizeof(outer), out) != sizeof(outer))
        goto done;
    cg_progress_emit("encode-v4", "bytes", 0, UINT64_MAX);
    for (;;) {
        char header[HEADER_MAX], canonical[HEADER_MAX];
        uint64_t f[7];
        if (!fgets(header, sizeof(header), in)) {
            if (ferror(in)) {
                errno = EIO;
                goto done;
            }
            break;
        }
        size_t hlen = strlen(header);
        if (!chunk_fields((unsigned char *)header, hlen, f))
            goto done;
        if (!active(user, (uint16_t)f[3], (uint16_t)f[4])) {
            errno = EACCES;
            goto done;
        }
        size_t amount = hlen + (size_t)f[0] + (size_t)f[1] + 1;
        if (amount > CG_CHUNKED_MAX_CHUNK_BYTES || amount > max_bytes || raw > max_bytes - amount) {
            errno = EFBIG;
            goto done;
        }
        if (records >= max_records) {
            errno = E2BIG;
            goto done;
        }
        if (b.records &&
            (b.raw + amount > CG_CHUNKED_TARGET_RAW_BYTES || b.records >= CH_RECORD_LIMIT)) {
            if (!chunk_flush(&b, out, user))
                goto done;
            chunks++;
            chunk_clear(&b);
            cg_progress_emit("encode-v4", "bytes", raw, UINT64_MAX);
        }
        for (size_t i = 0; i < 7; i++)
            if (!chunk_varint(b.columns + i, f[i], CG_CHUNKED_MAX_CHUNK_BYTES))
                goto done;
        size_t clen = chunk_format(canonical, f);
        unsigned char literal_header = clen != hlen || memcmp(canonical, header, hlen);
        if (!append(b.columns + 7, &literal_header, 1, CG_CHUNKED_MAX_CHUNK_BYTES))
            goto done;
        if (literal_header && (!chunk_varint(b.columns + 7, hlen, CG_CHUNKED_MAX_CHUNK_BYTES) ||
                               !append(b.columns + 7, header, hlen, CG_CHUNKED_MAX_CHUNK_BYTES)))
            goto done;
        if (!read_append(b.columns + CH_BODY, in, (size_t)f[0] + (size_t)f[1],
                         CG_CHUNKED_MAX_CHUNK_BYTES) ||
            fgetc(in) != '\n') {
            if (!errno)
                errno = EINVAL;
            goto done;
        }
        b.raw += amount;
        b.records++;
        raw += amount;
        records++;
        if (f[3] > b.classification)
            b.classification = (uint16_t)f[3];
        b.sci |= (uint16_t)f[4];
        if (f[3] > classification)
            classification = (uint16_t)f[3];
        sci |= (uint16_t)f[4];
    }
    if (b.records) {
        if (!chunk_flush(&b, out, user))
            goto done;
        chunks++;
    }
    if (!active(user, classification, sci)) {
        errno = EACCES;
        goto done;
    }
    memcpy(outer, chunk_magic, 8);
    put64(outer + 8, raw);
    put64(outer + 16, records);
    put32(outer + 24, chunks);
    put32(outer + 28, CG_CHUNKED_MAX_CHUNK_BYTES);
    put16(outer + 32, classification);
    put16(outer + 34, sci);
    if (fflush(out) || fseeko(out, 0, SEEK_SET) ||
        fwrite(outer, 1, sizeof(outer), out) != sizeof(outer) || fflush(out) ||
        fseeko(out, 0, SEEK_END))
        goto done;
    ok = active(user, classification, sci);
    if (ok)
        cg_progress_emit("encode-v4", "bytes", raw, raw);
done:
    chunk_clear(&b);
    return ok;
}
/* A bounded on-disk key set rejects duplicates across chunk boundaries without
 * retaining a whole-graph key table. Exact key bytes, not fingerprints, decide
 * equality. A pathological bucket chain is a resource-limit failure. */
typedef struct {
    FILE *file;
    uint64_t *heads;
} chunk_keys;
static bool chunk_key_add(chunk_keys *set, const unsigned char *key, size_t len) {
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= UINT64_C(1099511628211);
    }
    size_t bucket = (size_t)hash & (CH_BUCKETS - 1);
    uint64_t previous = set->heads[bucket];
    unsigned char h[20], *compare = NULL;
    bool ok = false;
    size_t hops = 0;
    while (previous) {
        if (++hops > 4096) {
            errno = E2BIG;
            goto done;
        }
        if (fseeko(set->file, (off_t)(previous - 1), SEEK_SET) ||
            fread(h, 1, sizeof(h), set->file) != sizeof(h))
            goto done;
        uint64_t next = get64(h);
        size_t prior_len = get32(h + 16);
        if (get64(h + 8) == hash && prior_len == len) {
            compare = malloc(len);
            if (!compare) {
                errno = ENOMEM;
                goto done;
            }
            if (fread(compare, 1, len, set->file) != len)
                goto done;
            if (!memcmp(compare, key, len)) {
                errno = EINVAL;
                goto done;
            }
            free(compare);
            compare = NULL;
        }
        previous = next;
    }
    if (fseeko(set->file, 0, SEEK_END))
        goto done;
    off_t off = ftello(set->file);
    if (off < 0)
        goto done;
    put64(h, set->heads[bucket]);
    put64(h + 8, hash);
    put32(h + 16, (uint32_t)len);
    if (fwrite(h, 1, sizeof(h), set->file) != sizeof(h) || fwrite(key, 1, len, set->file) != len)
        goto done;
    set->heads[bucket] = (uint64_t)off + 1;
    ok = true;
done:
    free(compare);
    return ok;
}
static bool chunk_same_source(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
/* Untrusted outer fields can reject a request early, never admit it. The
 * complete private copy/checksum and every copied column remain authoritative.
 * Bound temporary I/O by the caller's declared raw/record budget, not just the
 * codec's global ceiling. The generous encoded cap covers all nine Zstd bounds,
 * full literal-header exceptions and token worst-case expansion. */
static bool chunk_preflight(FILE *input, qihse_user_t *user, size_t max_bytes, size_t max_records,
                            struct stat *checked) {
    unsigned char h[CH_OUTER];
    struct stat st;
    if (fstat(fileno(input), &st) || !S_ISREG(st.st_mode) || st.st_size < CH_OUTER ||
        (uint64_t)st.st_size > CG_CHUNKED_MAX_RAW_BYTES) {
        errno = EINVAL;
        return false;
    }
    ssize_t n;
    do
        n = pread(fileno(input), h, sizeof(h), 0);
    while (n < 0 && errno == EINTR);
    if (n != (ssize_t)sizeof(h) || memcmp(h, chunk_magic, 8)) {
        errno = EINVAL;
        return false;
    }
    uint64_t raw = get64(h + 8), records = get64(h + 16), chunks = get32(h + 24);
    if (raw > max_bytes) {
        errno = EFBIG;
        return false;
    }
    if (records > max_records) {
        errno = E2BIG;
        return false;
    }
    if (chunks > records || chunks > raw || (records && !chunks) || (!records && (chunks || raw))) {
        errno = EINVAL;
        return false;
    }
    uint64_t encoded_cap = 4 * raw + 1024 * records + 4096 * chunks + CH_OUTER;
    if ((uint64_t)st.st_size > encoded_cap) {
        errno = EFBIG;
        return false;
    }
    if (!active(user, get16(h + 32), get16(h + 34))) {
        errno = EACCES;
        return false;
    }
    struct stat after;
    if (fstat(fileno(input), &after) || !chunk_same_source(&st, &after)) {
        errno = EIO;
        return false;
    }
    *checked = st;
    return true;
}
static bool chunk_source_copy(FILE *in, FILE *copy, qihse_user_t *user,
                              const cg_snapshot_checksum *expected, const struct stat *preflight) {
    struct stat before, after;
    if (!active(user, 0, 0)) {
        errno = EACCES;
        return false;
    }
    if (!cg_checksum_valid(expected) || fstat(fileno(in), &before) || !S_ISREG(before.st_mode) ||
        before.st_size < CH_OUTER || (uint64_t)before.st_size > CG_CHUNKED_MAX_RAW_BYTES ||
        !chunk_same_source(&before, preflight)) {
        errno = EINVAL;
        return false;
    }
    unsigned char *bytes = malloc(65536);
    if (!bytes) {
        errno = ENOMEM;
        return false;
    }
    off_t offset = 0;
    bool ok = false;
    EVP_MD_CTX *sha = NULL;
    qx3_stream *xxh = NULL;
    if (expected->algorithm == CG_CHECKSUM_XXH3_128) {
        const qx3_backend *backend = qx3_backend_get("auto");
        if (!backend || !(xxh = qx3_stream_create(backend, 0)))
            goto done;
    } else {
        sha = EVP_MD_CTX_new();
        if (!sha || EVP_DigestInit_ex(sha, EVP_sha256(), NULL) != 1)
            goto done;
    }
    while (offset < before.st_size) {
        if (!active(user, 0, 0)) {
            errno = EACCES;
            goto done;
        }
        size_t n =
            (uint64_t)(before.st_size - offset) > 65536 ? 65536 : (size_t)(before.st_size - offset);
        ssize_t got = pread(fileno(in), bytes, n, offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0 || fwrite(bytes, 1, (size_t)got, copy) != (size_t)got) {
            errno = EIO;
            goto done;
        }
        if (xxh ? qx3_stream_update(xxh, bytes, (size_t)got) != 0
                : EVP_DigestUpdate(sha, bytes, (size_t)got) != 1)
            goto done;
        offset += got;
    }
    cg_snapshot_checksum actual = {.algorithm = expected->algorithm};
    if (xxh)
        qx3_hex(qx3_stream_digest(xxh), actual.hex);
    else {
        unsigned char digest[32];
        unsigned length = 0;
        if (EVP_DigestFinal_ex(sha, digest, &length) != 1 || length != 32)
            goto done;
        for (size_t i = 0; i < 32; i++) {
            actual.hex[2 * i] = (char)hexchar(digest[i] >> 4);
            actual.hex[2 * i + 1] = (char)hexchar(digest[i] & 15);
        }
        actual.hex[64] = 0;
    }
    if (fflush(copy) || strcmp(actual.hex, expected->hex)) {
        errno = EINVAL;
        goto done;
    }
    if (fstat(fileno(in), &after) || !chunk_same_source(&before, &after)) {
        errno = EIO;
        goto done;
    }
    ok = active(user, 0, 0) && !fseeko(copy, 0, SEEK_SET);
done:
    EVP_MD_CTX_free(sha);
    qx3_stream_free(xxh);
    OPENSSL_cleanse(bytes, 65536);
    free(bytes);
    return ok;
}
static bool chunk_decode_one(FILE *in, FILE *stage, chunk_keys *keys, qihse_user_t *user,
                             size_t remaining_bytes, size_t remaining_records, size_t *raw_count,
                             size_t *record_count, uint16_t *class_total, uint16_t *sci_total) {
    unsigned char h[CH_HEADER];
    buffer col[CH_COLUMNS] = {{0}}, zip = {0}, body = {0};
    bool ok = false;
    if (fread(h, 1, sizeof(h), in) != sizeof(h) || get32(h + 108) ||
        (get32(h + 12) & ~CG_DICTIONARY_FEATURE_DIGEST128)) {
        errno = EINVAL;
        goto done;
    }
    uint64_t raw = get64(h), bodylen = get64(h + 16), tokens = get64(h + 24);
    size_t records = get32(h + 8);
    if (raw > CG_CHUNKED_MAX_CHUNK_BYTES || !raw || !records || records > CH_RECORD_LIMIT ||
        records > raw / 16 || bodylen > raw || tokens > CH_TOKEN_LIMIT ||
        tokens > 2 * bodylen + 16 || get32(h + 64) != tokens) {
        errno = EINVAL;
        goto done;
    }
    if (raw > remaining_bytes) {
        errno = EFBIG;
        goto done;
    }
    if (records > remaining_records) {
        errno = E2BIG;
        goto done;
    }
    uint16_t required_class = get16(h + 104), required_sci = get16(h + 106);
    if (!active(user, required_class, required_sci)) {
        errno = EACCES;
        goto done;
    }
    /* Metadata columns precede the body. Authorize all rows in this chunk
     * before allocating or expanding its value token stream. */
    for (size_t i = 0; i < CH_COLUMNS; i++) {
        if (!active(user, required_class, required_sci)) {
            errno = EACCES;
            goto done;
        }
        size_t plain = get32(h + 32 + 4 * i), encoded = get32(h + 68 + 4 * i);
        size_t limit = i == CH_BODY ? CH_TOKEN_LIMIT
                       : i == 7     ? (size_t)raw + 4 * records
                                    : 10 * records;
        if ((i < CH_BODY && plain < records) || plain > limit || !encoded ||
            encoded > ZSTD_compressBound(plain) ||
            !grow(&zip, encoded, ZSTD_compressBound(CH_TOKEN_LIMIT)) ||
            fread(zip.data, 1, encoded, in) != encoded) {
            errno = EINVAL;
            goto done;
        }
        zip.len = encoded;
        if (!decompress_frame(zip.data, zip.len, plain, col + i))
            goto done;
        zip.len = 0;
        if (i == 7) {
            size_t off[8] = {0};
            uint16_t cls = 0, sci = 0;
            size_t expected_raw = 0, expected_body = 0;
            for (size_t r = 0; r < records; r++) {
                uint64_t f[7];
                for (size_t j = 0; j < 7; j++)
                    if (!chunk_read_varint(col + j, off + j, f + j))
                        goto done;
                if (!f[0] || f[0] > KEY_MAX || f[1] > VALUE_MAX || f[3] > UINT16_MAX ||
                    f[4] > UINT16_MAX || f[5] > 1 || (f[5] && f[1])) {
                    errno = EINVAL;
                    goto done;
                }
                if (!active(user, (uint16_t)f[3], (uint16_t)f[4])) {
                    errno = EACCES;
                    goto done;
                }
                char canonical[HEADER_MAX];
                size_t hlen = chunk_format(canonical, f);
                if (!hlen || off[7] >= col[7].len) {
                    errno = EINVAL;
                    goto done;
                }
                unsigned flag = col[7].data[off[7]++];
                if (flag > 1) {
                    errno = EINVAL;
                    goto done;
                }
                if (flag) {
                    uint64_t length, actual[7];
                    if (!chunk_read_varint(col + 7, off + 7, &length) || length >= HEADER_MAX ||
                        length > col[7].len - off[7])
                        goto done;
                    const unsigned char *header = col[7].data + off[7];
                    hlen = (size_t)length;
                    off[7] += hlen;
                    if (!chunk_fields(header, hlen, actual) || memcmp(actual, f, sizeof(f))) {
                        errno = EINVAL;
                        goto done;
                    }
                }
                size_t amount = hlen + (size_t)f[0] + (size_t)f[1] + 1;
                if (amount > raw - expected_raw) {
                    errno = EINVAL;
                    goto done;
                }
                expected_raw += amount;
                expected_body += (size_t)f[0] + (size_t)f[1];
                if (f[3] > cls)
                    cls = (uint16_t)f[3];
                sci |= (uint16_t)f[4];
            }
            for (size_t j = 0; j < 8; j++)
                if (off[j] != col[j].len) {
                    errno = EINVAL;
                    goto done;
                }
            if (cls != required_class || sci != required_sci || expected_raw != raw ||
                expected_body != bodylen) {
                errno = EINVAL;
                goto done;
            }
        }
    }
    if (!decode_tokens(col + CH_BODY, &body, (size_t)bodylen, get32(h + 12)))
        goto done;
    size_t off[8] = {0}, bodyoff = 0, total = 0;
    for (size_t r = 0; r < records; r++) {
        uint64_t f[7];
        for (size_t i = 0; i < 7; i++)
            if (!chunk_read_varint(col + i, off + i, f + i))
                goto done;
        char canonical[HEADER_MAX];
        size_t hlen = chunk_format(canonical, f);
        const unsigned char *header = (unsigned char *)canonical;
        if (!hlen || off[7] >= col[7].len) {
            errno = EINVAL;
            goto done;
        }
        unsigned flag = col[7].data[off[7]++];
        if (flag > 1) {
            errno = EINVAL;
            goto done;
        }
        if (flag) {
            uint64_t length, actual[7];
            if (!chunk_read_varint(col + 7, off + 7, &length) || length >= HEADER_MAX ||
                length > col[7].len - off[7])
                goto done;
            header = col[7].data + off[7];
            hlen = (size_t)length;
            off[7] += hlen;
            if (!chunk_fields(header, hlen, actual) || memcmp(actual, f, sizeof(f))) {
                errno = EINVAL;
                goto done;
            }
        }
        if (f[0] > body.len - bodyoff || f[1] > body.len - bodyoff - f[0] ||
            memchr(body.data + bodyoff, 0, (size_t)(f[0] + f[1])) ||
            !chunk_key_add(keys, body.data + bodyoff, (size_t)f[0]))
            goto done;
        size_t amount = hlen + (size_t)f[0] + (size_t)f[1] + 1;
        if (amount > raw - total || fwrite(header, 1, hlen, stage) != hlen ||
            fwrite(body.data + bodyoff, 1, (size_t)(f[0] + f[1]), stage) != (size_t)(f[0] + f[1]) ||
            fputc('\n', stage) == EOF)
            goto done;
        bodyoff += (size_t)(f[0] + f[1]);
        total += amount;
    }
    if (total != raw || bodyoff != body.len || off[7] != col[7].len) {
        errno = EINVAL;
        goto done;
    }
    if (required_class > *class_total)
        *class_total = required_class;
    *sci_total |= required_sci;
    *raw_count = total;
    *record_count = records;
    ok = active(user, required_class, required_sci);
done:
    for (size_t i = 0; i < CH_COLUMNS; i++)
        release(col + i);
    release(&zip);
    release(&body);
    return ok;
}
bool cg_chunked_decode_checksum_snapshot(FILE *in, FILE *out, qihse_user_t *user,
                                         const cg_snapshot_checksum *expected, size_t max_bytes,
                                         size_t max_records) {
    struct stat preflight;
    if (!chunk_streams(in, out, user, max_bytes, max_records) ||
        !chunk_preflight(in, user, max_bytes, max_records, &preflight))
        return false;
    FILE *copy = tmpfile(), *stage = tmpfile();
    chunk_keys keys = {tmpfile(), NULL};
    bool ok = false;
    unsigned char outer[CH_OUTER];
    uint16_t cls = 0, sci = 0;
    keys.heads = calloc(CH_BUCKETS, sizeof(*keys.heads));
    if (!copy || !stage || !keys.file || !keys.heads) {
        errno = ENOMEM;
        goto done;
    }
    if (!chunk_source_copy(in, copy, user, expected, &preflight) ||
        fread(outer, 1, sizeof(outer), copy) != sizeof(outer) || memcmp(outer, chunk_magic, 8) ||
        get32(outer + 28) != CG_CHUNKED_MAX_CHUNK_BYTES)
        goto done;
    for (size_t i = 36; i < CH_OUTER; i++)
        if (outer[i]) {
            errno = EINVAL;
            goto done;
        }
    uint64_t raw = get64(outer + 8), records = get64(outer + 16);
    size_t chunks = get32(outer + 24);
    if (raw > max_bytes) {
        errno = EFBIG;
        goto done;
    }
    if (records > max_records) {
        errno = E2BIG;
        goto done;
    }
    if (chunks > records || (records && !chunks) || (!records && (chunks || raw)) || chunks > raw) {
        errno = EINVAL;
        goto done;
    }
    if (!active(user, get16(outer + 32), get16(outer + 34))) {
        errno = EACCES;
        goto done;
    }
    size_t total = 0, count = 0;
    for (size_t c = 0; c < chunks; c++) {
        size_t bytes = 0, rows = 0;
        if (!chunk_decode_one(copy, stage, &keys, user, (size_t)raw - total,
                              (size_t)records - count, &bytes, &rows, &cls, &sci))
            goto done;
        total += bytes;
        count += rows;
        cg_progress_emit("decode", "bytes", total, raw);
    }
    if (total != raw || count != records || cls != get16(outer + 32) || sci != get16(outer + 34) ||
        fgetc(copy) != EOF || ferror(copy) || !active(user, cls, sci) || fflush(stage) ||
        fseeko(stage, 0, SEEK_SET))
        goto done;
    unsigned char *bytes = malloc(65536);
    if (!bytes) {
        errno = ENOMEM;
        goto done;
    }
    for (;;) {
        size_t n = fread(bytes, 1, 65536, stage);
        if (!n)
            break;
        if (!active(user, cls, sci) || fwrite(bytes, 1, n, out) != n) {
            free(bytes);
            goto done;
        }
    }
    free(bytes);
    ok = !ferror(stage) && !fflush(out) && active(user, cls, sci);
done:
    if (copy)
        fclose(copy);
    if (stage)
        fclose(stage);
    if (keys.file)
        fclose(keys.file);
    free(keys.heads);
    return ok;
}
