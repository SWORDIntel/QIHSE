#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
/* The codec is bounded to 64 MiB and keys to 65535 bytes. */
typedef struct { uint32_t off; uint16_t len; uint8_t tag; } key_span;

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
    size_t maximum = ZSTD_compressBound(CG_PACKED_MAX_RAW_BYTES);
    bool ok = bound <= maximum &&
              grow(encoded, bound, maximum) &&
              !ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, CG_CODEGRAPH_ZSTD_LEVEL)) &&
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
        /* Keep digest-shaped keys in text: values repeat their hex IDs, so
         * Zstd can back-reference the exact key. The decoder still accepts
         * older digest-tagged QCGP0002 frames. */
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
/* Keys are compared in their logical text form, including the older digest
 * tags. Most snapshots have literal keys, so their sort is a direct memcmp. */
static const unsigned char *span_key(const key_span *span, const unsigned char *body,
                                      unsigned char expanded[66]) {
    if (span->tag == TAG_LITERAL) return body + span->off;
    expanded[0] = span->tag == TAG_NODE ? 'n' : 'e'; expanded[1] = ':';
    for (size_t j = 0; j < 32; j++) {
        expanded[2 + 2*j] = hexchar(body[span->off+j] >> 4);
        expanded[3 + 2*j] = hexchar(body[span->off+j] & 15);
    }
    return expanded;
}
static int compare_spans(const void *a, const void *b, void *context) {
    const unsigned char *body = context;
    const key_span *x = a, *y = b;
    unsigned char expanded_x[66], expanded_y[66];
    const unsigned char *kx = span_key(x, body, expanded_x);
    const unsigned char *ky = span_key(y, body, expanded_y);
    size_t common = x->len < y->len ? x->len : y->len;
    int cmp = memcmp(kx, ky, common);
    return cmp ? cmp : (x->len > y->len) - (x->len < y->len);
}
/* The table has already been bounds-checked and authorized. Check body text
 * and logical key uniqueness directly over byte spans, without reconstructing
 * another complete KV image just to sort its keys. */
static bool validate_body(const buffer *table, const buffer *body,
                           size_t expected_records) {
    key_span *keys = calloc(expected_records ? expected_records : 1, sizeof(*keys));
    if (!keys) { errno = ENOMEM; return false; }
    size_t toff = 0, boff = 0;
    bool ok = true;
    for (size_t i = 0; i < expected_records; i++) {
        size_t hlen = get16(table->data + toff); toff += 2;
        record_header r;
        if (!parse_header(table->data + toff, hlen, &r)) { ok = false; break; }
        toff += hlen;
        uint8_t tag = table->data[toff++];
        size_t key_bytes = tag == TAG_LITERAL ? r.key_len : 32;
        if (boff > body->len || key_bytes > body->len - boff ||
            r.value_len > body->len - boff - key_bytes) {
            errno = EINVAL; ok = false; break;
        }
        keys[i] = (key_span){.off = (uint32_t)boff, .len = (uint16_t)r.key_len, .tag = tag};
        if (tag == TAG_LITERAL && memchr(body->data + boff, 0, key_bytes)) {
            errno = EINVAL; ok = false; break;
        }
        boff += key_bytes;
        if (r.value_len && memchr(body->data + boff, 0, r.value_len)) {
            errno = EINVAL; ok = false; break;
        }
        boff += r.value_len;
    }
    if (ok && (boff != body->len || toff != table->len)) { errno = EINVAL; ok = false; }
    if (ok) {
        qsort_r(keys, expected_records, sizeof(*keys), compare_spans, body->data);
        for (size_t i = 1; i < expected_records; i++) {
            if (compare_spans(keys + i - 1, keys + i, body->data) == 0) {
                errno = EINVAL; ok = false; break;
            }
        }
    }
    free(keys); return ok;
}

typedef struct {
    buffer table, body;
    qihse_user_t *principal;
    uint16_t required_class, required_sci;
    size_t table_off, body_off, remaining_records;
    const unsigned char *chunks[4];
    size_t lengths[4], chunk, chunk_off;
    unsigned char expanded_key[66];
} packed_reader;

static bool next_record(packed_reader *s) {
    size_t hlen = get16(s->table.data + s->table_off); s->table_off += 2;
    const unsigned char *header = s->table.data + s->table_off;
    record_header r;
    if (!parse_header(header, hlen, &r)) return false;
    s->table_off += hlen;
    uint8_t tag = s->table.data[s->table_off++];
    key_span key = {.off = (uint32_t)s->body_off, .len = (uint16_t)r.key_len, .tag = tag};
    s->chunks[0] = header; s->lengths[0] = hlen;
    s->chunks[1] = span_key(&key, s->body.data, s->expanded_key);
    s->lengths[1] = r.key_len;
    s->body_off += tag == TAG_LITERAL ? r.key_len : 32;
    s->chunks[2] = s->body.data + s->body_off; s->lengths[2] = r.value_len;
    s->body_off += r.value_len;
    s->chunks[3] = (const unsigned char *)"\n"; s->lengths[3] = 1;
    s->chunk = s->chunk_off = 0;
    s->remaining_records--;
    return true;
}
static ssize_t packed_read(void *cookie, char *output, size_t capacity) {
    packed_reader *s = cookie;
    if (!active(s->principal, s->required_class, s->required_sci)) {
        errno = EACCES; return -1;
    }
    size_t used = 0;
    while (used < capacity) {
        if (s->chunk == 4) {
            if (!s->remaining_records) break;
            if (!next_record(s)) return -1;
        }
        size_t n = s->lengths[s->chunk] - s->chunk_off;
        if (n > capacity - used) n = capacity - used;
        if (n) memcpy(output + used, s->chunks[s->chunk] + s->chunk_off, n);
        used += n; s->chunk_off += n;
        if (s->chunk_off == s->lengths[s->chunk]) {
            s->chunk++; s->chunk_off = 0;
        }
    }
    return (ssize_t)used;
}
static int packed_close(void *cookie) {
    packed_reader *s = cookie;
    release(&s->table); release(&s->body);
    OPENSSL_cleanse(s, sizeof(*s)); free(s);
    return 0;
}

static FILE *open_snapshot_stream(FILE *packed_input, qihse_user_t *principal,
                                  size_t max_bytes, size_t max_records,
                                  size_t *raw_bytes, packed_reader **reader_state) {
    if (!active(principal, 0, 0)) { errno = EACCES; return NULL; }
    if (!packed_input || !limits(&max_bytes, &max_records) || ferror(packed_input)) {
        errno = EINVAL; return NULL;
    }
    unsigned char outer[OUTER];
    if (fread(outer, 1, OUTER, packed_input) != OUTER) {
        errno = ferror(packed_input) ? EIO : EINVAL; return NULL;
    }
    if (memcmp(outer, magic, 8) || get32(outer + 44)) { errno = EINVAL; return NULL; }
    if (get64(outer + 8) > max_bytes || get64(outer + 16) > max_bytes ||
        get64(outer + 24) > max_bytes) { errno = EFBIG; return NULL; }
    if (get32(outer + 32) > max_records) { errno = E2BIG; return NULL; }
    size_t raw_len = (size_t)get64(outer + 8);
    size_t meta_len = (size_t)get64(outer + 16);
    size_t body_len = (size_t)get64(outer + 24);
    size_t meta_zip_len = get32(outer + 36), body_zip_len = get32(outer + 40);
    if (!meta_zip_len || !body_zip_len ||
        meta_zip_len > ZSTD_compressBound(meta_len) ||
        body_zip_len > ZSTD_compressBound(body_len)) { errno = EINVAL; return NULL; }
    buffer encoded = {0};
    packed_reader *state = calloc(1, sizeof(*state));
    if (!state) { errno = ENOMEM; return NULL; }
    FILE *result = NULL;
    if (!grow(&encoded, meta_zip_len, ZSTD_compressBound(CG_PACKED_MAX_RAW_BYTES)))
        goto done;
    if (fread(encoded.data, 1, meta_zip_len, packed_input) != meta_zip_len) {
        errno = ferror(packed_input) ? EIO : EINVAL; goto done;
    }
    encoded.len = meta_zip_len;
    if (!decompress_frame(encoded.data, encoded.len, meta_len, &state->table)) goto done;
    release(&encoded);
    size_t body_expected = 0, raw_expected = 0;
    size_t records = get32(outer + 32);
    if (!parse_table(&state->table, records, max_bytes, principal,
                     &body_expected, &raw_expected,
                     &state->required_class, &state->required_sci)) goto done;
    if (body_expected != body_len || raw_expected != raw_len) { errno = EINVAL; goto done; }
    /* Consume/decode the body only after all labels pass. The source FILE
     * may already have prefetched compressed bytes into its stdio buffer. */
    if (!grow(&encoded, body_zip_len, ZSTD_compressBound(CG_PACKED_MAX_RAW_BYTES)))
        goto done;
    if (fread(encoded.data, 1, body_zip_len, packed_input) != body_zip_len) {
        errno = ferror(packed_input) ? EIO : EINVAL; goto done;
    }
    encoded.len = body_zip_len;
    if (fgetc(packed_input) != EOF || ferror(packed_input)) { errno = EINVAL; goto done; }
    if (!decompress_frame(encoded.data, encoded.len, body_len, &state->body)) goto done;
    release(&encoded);
    if (!validate_body(&state->table, &state->body, records)) goto done;
    if (!active(principal, state->required_class, state->required_sci)) {
        errno = EACCES; goto done;
    }
    state->principal = principal; state->remaining_records = records; state->chunk = 4;
    cookie_io_functions_t io = {.read = packed_read, .close = packed_close};
    result = fopencookie(state, "rb", io);
    if (!result) goto done;
    if (raw_bytes) *raw_bytes = raw_len;
    if (reader_state) *reader_state = state;
done:
    {
        int error = errno;
        release(&encoded);
        if (!result) packed_close(state);
        errno = error;
    }
    return result;
}

qihse_kv_store_t *cg_packed_open_snapshot_user(FILE *packed_input, qihse_user_t *principal,
                                               size_t max_bytes, size_t max_records,
                                               size_t *raw_bytes) {
    packed_reader *state = NULL;
    size_t size = 0;
    FILE *reader = open_snapshot_stream(packed_input, principal, max_bytes, max_records,
                                        &size, &state);
    if (!reader) return NULL;
    /* The plaintext stream is private to the authenticated KV parser. It may
     * buffer bytes, so the parser and this return boundary both recheck the
     * principal before a detached store can escape. */
    qihse_kv_store_t *store = qihse_kv_open_snapshot_user(reader, principal,
                                                        max_bytes, max_records);
    int error = errno;
    int trailing = store ? fgetc(reader) : EOF;
    if (store && (trailing != EOF || ferror(reader) ||
                  !active(principal, state->required_class, state->required_sci))) {
        qihse_kv_store_destroy(store); store = NULL;
        error = trailing != EOF ? EINVAL : ferror(reader) ? EIO : EACCES;
    }
    fclose(reader);
    if (store && raw_bytes) *raw_bytes = size;
    if (!store) errno = error;
    return store;
}

bool cg_packed_decode_snapshot(FILE *packed_input, FILE *raw_output,
                               qihse_user_t *principal, size_t max_bytes,
                               size_t max_records) {
    if (!check_streams(packed_input, raw_output, principal,
                       &max_bytes, &max_records)) return false;
    packed_reader *state = NULL;
    FILE *reader = open_snapshot_stream(packed_input, principal,
                                         max_bytes, max_records, NULL, &state);
    if (!reader) return false;
    const size_t capacity = 65536;
    unsigned char *copy = malloc(capacity);
    if (!copy) { fclose(reader); errno = ENOMEM; return false; }
    bool ok = true;
    size_t n;
    while ((n = fread(copy, 1, capacity, reader)) != 0) {
        /* FILE can satisfy a read from its stdio buffer without invoking the
         * read callback. Recheck labels at the output boundary as well. */
        if (!active(principal, state->required_class, state->required_sci)) {
            errno = EACCES; ok = false; break;
        }
        if (fwrite(copy, 1, n, raw_output) != n) { errno = EIO; ok = false; break; }
    }
    if (ferror(reader)) ok = false;
    if (ok && fflush(raw_output)) { errno = EIO; ok = false; }
    if (ok && !active(principal, state->required_class, state->required_sci)) {
        errno = EACCES; ok = false;
    }
    int error = errno;
    fclose(reader);
    OPENSSL_cleanse(copy, capacity); free(copy);
    errno = error;
    return ok;
}
