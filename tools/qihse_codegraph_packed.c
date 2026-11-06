#define _GNU_SOURCE
#include "qihse_codegraph_packed.h"
#include <openssl/crypto.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

/* QCGP0002: header[48], Zstd header-table frame, Zstd body frame.
 * Table entries are u16 exact QIHSE header-line length, exact header bytes,
 * then key tag (0=literal, 1=n: digest, 2=e: digest). The body contains the
 * corresponding key bytes (32-byte digest or original literal) followed by
 * the exact value bytes. This puts every classification/SCI label in a frame
 * that can be authenticated before a body byte is decompressed. */
enum { OUTER = 48, HEADER_MAX = 256, KEY_MAX = 65535,
       VALUE_MAX = 16 * 1024 * 1024, TAG_LITERAL = 0,
       TAG_NODE = 1, TAG_EDGE = 2, WINDOW_LOG = 23 };
static const unsigned char magic[8] = {'Q','C','G','P','0','0','0','2'};
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
    if (*bytes > CG_PACKED_MAX_RAW_BYTES) *bytes = CG_PACKED_MAX_RAW_BYTES;
    if (*records > CG_PACKED_MAX_RECORDS) *records = CG_PACKED_MAX_RECORDS;
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
static int hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
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
static uint8_t key_tag(const unsigned char *key, size_t length) {
    if (length != 66 || key[1] != ':' || (key[0] != 'n' && key[0] != 'e'))
        return TAG_LITERAL;
    for (size_t i = 2; i < 66; i++) if (hex(key[i]) < 0) return TAG_LITERAL;
    return key[0] == 'n' ? TAG_NODE : TAG_EDGE;
}
static bool compress_frame(const buffer *plain, buffer *encoded) {
    ZSTD_CCtx *ctx = ZSTD_createCCtx();
    if (!ctx) { errno = ENOMEM; return false; }
    size_t bound = ZSTD_compressBound(plain->len);
    size_t maximum = ZSTD_compressBound(CG_PACKED_MAX_RAW_BYTES);
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
    if (!grow(out, decoded_len ? decoded_len : 1, CG_PACKED_MAX_RAW_BYTES))
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

bool cg_packed_encode_snapshot(FILE *authorized_export, FILE *packed_output,
                               qihse_user_t *principal, size_t max_bytes,
                               size_t max_records) {
    if (!check_streams(authorized_export, packed_output, principal,
                       &max_bytes, &max_records)) return false;
    buffer table = {0}, body = {0}, meta_zip = {0}, body_zip = {0};
    unsigned char *key = malloc(KEY_MAX);
    if (!key) { errno = ENOMEM; return false; }
    size_t raw_bytes = 0, records = 0;
    uint16_t required_class = 0, required_sci = 0;
    bool ok = false;
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
        uint8_t tag = key_tag(key, r.key_len);
        unsigned char length[2]; put16(length, (uint16_t)hlen);
        if (!append(&table, length, 2, max_bytes) ||
            !append(&table, header, hlen, max_bytes) ||
            !append(&table, &tag, 1, max_bytes)) break;
        if (tag == TAG_LITERAL) {
            if (!append(&body, key, r.key_len, max_bytes)) break;
        } else {
            unsigned char digest_key[32];
            for (size_t i = 0; i < 32; i++)
                digest_key[i] = (unsigned char)((hex(key[2+i*2]) << 4) |
                                                 hex(key[3+i*2]));
            if (!append(&body, digest_key, 32, max_bytes)) break;
        }
        if (!read_append(&body, authorized_export, r.value_len, max_bytes)) break;
        if (fgetc(authorized_export) != '\n') { errno = EINVAL; break; }
        raw_bytes += hlen + r.key_len + r.value_len + 1;
        records++;
        if (r.classification > required_class) required_class = r.classification;
        required_sci |= r.sci;
    }
    if (ok && active(principal, required_class, required_sci))
        ok = compress_frame(&table, &meta_zip) && compress_frame(&body, &body_zip);
    else if (ok) { errno = EACCES; ok = false; }
    if (ok) {
        unsigned char outer[OUTER] = {0};
        memcpy(outer, magic, 8);
        put64(outer + 8, raw_bytes); put64(outer + 16, table.len);
        put64(outer + 24, body.len); put32(outer + 32, (uint32_t)records);
        put32(outer + 36, (uint32_t)meta_zip.len);
        put32(outer + 40, (uint32_t)body_zip.len);
        ok = fwrite(outer, 1, OUTER, packed_output) == OUTER &&
             fwrite(meta_zip.data, 1, meta_zip.len, packed_output) == meta_zip.len &&
             fwrite(body_zip.data, 1, body_zip.len, packed_output) == body_zip.len &&
             fflush(packed_output) == 0 &&
             active(principal, required_class, required_sci);
        if (!ok && errno == 0) errno = EIO;
    }
    release(&table); release(&body); release(&meta_zip); release(&body_zip);
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
                        size_t max_bytes) {
    key_span *keys = calloc(expected_records ? expected_records : 1, sizeof(*keys));
    if (!keys) { errno = ENOMEM; return false; }
    size_t toff = 0, boff = 0;
    bool ok = true;
    for (size_t i = 0; i < expected_records; i++) {
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
                key_tag(body->data + boff, r.key_len) != TAG_LITERAL ||
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

bool cg_packed_decode_snapshot(FILE *packed_input, FILE *raw_output,
                               qihse_user_t *principal, size_t max_bytes,
                               size_t max_records) {
    if (!check_streams(packed_input, raw_output, principal,
                       &max_bytes, &max_records)) return false;
    unsigned char outer[OUTER];
    if (fread(outer, 1, OUTER, packed_input) != OUTER ||
        memcmp(outer, magic, 8) || get32(outer + 44) ||
        get64(outer + 8) > max_bytes || get64(outer + 16) > max_bytes ||
        get64(outer + 24) > max_bytes || get32(outer + 32) > max_records) {
        errno = EINVAL; return false;
    }
    size_t raw_len = (size_t)get64(outer + 8);
    size_t meta_len = (size_t)get64(outer + 16);
    size_t body_len = (size_t)get64(outer + 24);
    size_t meta_zip_len = get32(outer + 36), body_zip_len = get32(outer + 40);
    if (!meta_zip_len || !body_zip_len ||
        meta_zip_len > ZSTD_compressBound(meta_len) ||
        body_zip_len > ZSTD_compressBound(body_len)) { errno = EINVAL; return false; }
    buffer meta_zip = {0}, body_zip = {0}, table = {0}, body = {0}, raw = {0};
    bool ok = false;
    if (!grow(&meta_zip, meta_zip_len, ZSTD_compressBound(CG_PACKED_MAX_RAW_BYTES)) ||
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
    if (!grow(&body_zip, body_zip_len, ZSTD_compressBound(CG_PACKED_MAX_RAW_BYTES)) ||
        fread(body_zip.data, 1, body_zip_len, packed_input) != body_zip_len)
        goto done;
    body_zip.len = body_zip_len;
    if (fgetc(packed_input) != EOF || ferror(packed_input) ||
        !decompress_frame(body_zip.data, body_zip.len, body_len, &body) ||
        !reconstruct(&table, &body, records, &raw, max_bytes) ||
        raw.len != raw_len || !active(principal, required_class, required_sci)) {
        if (errno == 0) errno = EINVAL;
        goto done;
    }
    /* No caller-visible bytes precede complete validation and authorization. */
    if ((raw.len && fwrite(raw.data, 1, raw.len, raw_output) != raw.len) ||
        fflush(raw_output) != 0) {
        errno = EIO; goto done;
    }
    ok = true;
done:
    release(&meta_zip); release(&body_zip); release(&table);
    release(&body); release(&raw);
    return ok;
}
