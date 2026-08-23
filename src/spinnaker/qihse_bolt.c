#include "qihse_bolt.h"
#include "qihse_protocol_translate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define htobe32(x) htonl(x)
#define be32toh(x) ntohl(x)
#define htobe16(x) htons(x)
#define be16toh(x) ntohs(x)
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ============================================================
 * PackStream encoder
 * ============================================================ */

void qihse_bolt_buf_init(qihse_bolt_buf_t* b, size_t initial_cap) {
    b->cap = initial_cap ? initial_cap : 64;
    b->buf = (uint8_t*)malloc(b->cap);
    b->len = 0;
}

void qihse_bolt_buf_free(qihse_bolt_buf_t* b) {
    free(b->buf);
    b->buf = NULL;
    b->len = b->cap = 0;
}

void qihse_bolt_buf_reserve(qihse_bolt_buf_t* b, size_t extra) {
    if (b->len + extra <= b->cap) return;
    size_t ncap = b->cap ? b->cap : 64;
    while (ncap < b->len + extra) ncap *= 2;
    b->buf = (uint8_t*)realloc(b->buf, ncap);
    b->cap = ncap;
}

void qihse_bolt_buf_append(qihse_bolt_buf_t* b, const void* data, size_t n) {
    qihse_bolt_buf_reserve(b, n);
    memcpy(b->buf + b->len, data, n);
    b->len += n;
}

static void bolt_put_u8(qihse_bolt_buf_t* b, uint8_t v) { qihse_bolt_buf_append(b, &v, 1); }
static void bolt_put_u16be(qihse_bolt_buf_t* b, uint16_t v) {
    uint8_t bytes[2] = { (uint8_t)(v >> 8), (uint8_t)(v & 0xFF) };
    qihse_bolt_buf_append(b, bytes, 2);
}

static void bolt_put_u32be(qihse_bolt_buf_t* b, uint32_t v) {
    uint8_t bytes[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                         (uint8_t)(v >> 8), (uint8_t)(v & 0xFF) };
    qihse_bolt_buf_append(b, bytes, 4);
}

static void bolt_put_u64be(qihse_bolt_buf_t* b, uint64_t v) {
    uint8_t bytes[8];
    for (int i = 0; i < 8; i++) bytes[i] = (uint8_t)(v >> (56 - 8 * i));
    qihse_bolt_buf_append(b, bytes, 8);
}

static void bolt_put_i16be(qihse_bolt_buf_t* b, int16_t v) {
    bolt_put_u16be(b, (uint16_t)v);
}

static void bolt_put_i32be(qihse_bolt_buf_t* b, int32_t v) {
    bolt_put_u32be(b, (uint32_t)v);
}

static void bolt_put_i64be(qihse_bolt_buf_t* b, int64_t v) {
    bolt_put_u64be(b, (uint64_t)v);
}

void qihse_bolt_encode_null(qihse_bolt_buf_t* b) {
    uint8_t z = 0xC0;
    qihse_bolt_buf_append(b, &z, 1);
}

void qihse_bolt_encode_bool(qihse_bolt_buf_t* b, bool val) {
    uint8_t z = val ? 0xC3 : 0xC2;
    qihse_bolt_buf_append(b, &z, 1);
}

void qihse_bolt_encode_int(qihse_bolt_buf_t* b, int64_t val) {
    if (val >= -16 && val <= 127) {
        uint8_t z = (uint8_t)(int8_t)val;
        qihse_bolt_buf_append(b, &z, 1);
    } else if (val >= -128 && val <= 127) {
        uint8_t hdr = 0xC8;
        int8_t v = (int8_t)val;
        qihse_bolt_buf_append(b, &hdr, 1);
        qihse_bolt_buf_append(b, &v, 1);
    } else if (val >= -32768 && val <= 32767) {
        uint8_t hdr = 0xC9;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_i16be(b, (int16_t)val);
    } else if (val >= -2147483648LL && val <= 2147483647LL) {
        uint8_t hdr = 0xCA;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_i32be(b, (int32_t)val);
    } else {
        uint8_t hdr = 0xCB;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_i64be(b, val);
    }
}

void qihse_bolt_encode_float(qihse_bolt_buf_t* b, double val) {
    uint8_t hdr = 0xC1;
    qihse_bolt_buf_append(b, &hdr, 1);
    uint64_t bits;
    memcpy(&bits, &val, 8);
    bolt_put_u64be(b, bits);
}

void qihse_bolt_encode_string(qihse_bolt_buf_t* b, const char* str) {
    size_t len = str ? strlen(str) : 0;
    if (len <= 0xFF) {
        uint8_t hdr = 0xD0;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u8(b, (uint8_t)len);
    } else if (len <= 0xFFFF) {
        uint8_t hdr = 0xD1;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u16be(b, (uint16_t)len);
    } else {
        uint8_t hdr = 0xD2;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u32be(b, (uint32_t)len);
    }
    if (len) qihse_bolt_buf_append(b, str, len);
}

void qihse_bolt_encode_list_begin(qihse_bolt_buf_t* b, size_t count) {
    if (count <= 0xFF) {
        uint8_t hdr = 0xD4;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u8(b, (uint8_t)count);
    } else if (count <= 0xFFFF) {
        uint8_t hdr = 0xD5;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u16be(b, (uint16_t)count);
    } else {
        uint8_t hdr = 0xD6;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u32be(b, (uint32_t)count);
    }
}

void qihse_bolt_encode_map_begin(qihse_bolt_buf_t* b, size_t count) {
    if (count < 16) {
        uint8_t hdr = 0xD7 | (uint8_t)count;
        qihse_bolt_buf_append(b, &hdr, 1);
    } else if (count <= 0xFFFF) {
        uint8_t hdr = 0xD8;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u16be(b, (uint16_t)count);
    } else {
        uint8_t hdr = 0xD9;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u32be(b, (uint32_t)count);
    }
}

void qihse_bolt_encode_struct_begin(qihse_bolt_buf_t* b, uint8_t signature, size_t nfields) {
    if (nfields < 16) {
        uint8_t hdr = 0xB0 | (uint8_t)nfields;
        qihse_bolt_buf_append(b, &hdr, 1);
    } else if (nfields <= 0xFFFF) {
        uint8_t hdr = 0xB1;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u16be(b, (uint16_t)nfields);
    } else {
        uint8_t hdr = 0xB2;
        qihse_bolt_buf_append(b, &hdr, 1);
        bolt_put_u32be(b, (uint32_t)nfields);
    }
    qihse_bolt_buf_append(b, &signature, 1);
}

/* ============================================================
 * PackStream decoder
 * ============================================================ */

void qihse_bolt_decoder_init(qihse_bolt_decoder_t* d, const uint8_t* data, size_t len) {
    d->data = data;
    d->len = len;
    d->pos = 0;
}

static int bolt_have(qihse_bolt_decoder_t* d, size_t n) {
    return d->pos + n <= d->len;
}

static uint16_t bolt_get_u16be(qihse_bolt_decoder_t* d) {
    const uint8_t* p = d->data + d->pos;
    uint16_t v = ((uint16_t)p[0] << 8) | p[1];
    d->pos += 2;
    return v;
}

static uint32_t bolt_get_u32be(qihse_bolt_decoder_t* d) {
    const uint8_t* p = d->data + d->pos;
    uint32_t v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                 ((uint32_t)p[2] << 8) | p[3];
    d->pos += 4;
    return v;
}

static uint64_t bolt_get_u64be(qihse_bolt_decoder_t* d) {
    const uint8_t* p = d->data + d->pos;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    d->pos += 8;
    return v;
}

static qihse_bolt_value_t* bolt_new_value(qihse_bolt_type_t t) {
    qihse_bolt_value_t* v = (qihse_bolt_value_t*)calloc(1, sizeof(qihse_bolt_value_t));
    if (v) v->type = t;
    return v;
}

void qihse_bolt_value_free(qihse_bolt_value_t* v) {
    if (!v) return;
    switch (v->type) {
        case QIHSE_BOLT_STRING:
            free(v->v.s.data);
            break;
        case QIHSE_BOLT_LIST:
            for (size_t i = 0; i < v->v.list.count; i++)
                qihse_bolt_value_free(v->v.list.items[i]);
            free(v->v.list.items);
            break;
        case QIHSE_BOLT_MAP:
            for (size_t i = 0; i < v->v.map.count; i++) {
                qihse_bolt_value_free(v->v.map.keys[i]);
                qihse_bolt_value_free(v->v.map.vals[i]);
            }
            free(v->v.map.keys);
            free(v->v.map.vals);
            break;
        case QIHSE_BOLT_STRUCT:
            for (size_t i = 0; i < v->v.strct.nfields; i++)
                qihse_bolt_value_free(v->v.strct.fields[i]);
            free(v->v.strct.fields);
            break;
        default:
            break;
    }
    free(v);
}

qihse_bolt_value_t* qihse_bolt_decode(qihse_bolt_decoder_t* d) {
    if (!bolt_have(d, 1)) return NULL;
    uint8_t marker = d->data[d->pos++];

    /* Tiny ints: 0..127 (positive) and 0x80..0x8F (-16..-1) */
    if (marker <= 0x7F) {
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_INT);
        v->v.i = (int8_t)marker;
        return v;
    }
    /* 0x80-0x8F are tiny negative ints (-16 to -1) */
    if (marker >= 0x80 && marker <= 0x8F) {
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_INT);
        v->v.i = (int8_t)marker;
        return v;
    }

    switch (marker) {
        case 0xC0: return bolt_new_value(QIHSE_BOLT_NULL);
        case 0xC2: { qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_BOOL); v->v.b = false; return v; }
        case 0xC3: { qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_BOOL); v->v.b = true; return v; }
        case 0xC8:
            if (!bolt_have(d, 1)) return NULL;
            { qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_INT);
              v->v.i = (int8_t)d->data[d->pos++]; return v; }
        case 0xC9:
            if (!bolt_have(d, 2)) return NULL;
            { qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_INT);
              v->v.i = (int16_t)bolt_get_u16be(d); return v; }
        case 0xCA:
            if (!bolt_have(d, 4)) return NULL;
            { qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_INT);
              v->v.i = (int32_t)bolt_get_u32be(d); return v; }
        case 0xCB:
            if (!bolt_have(d, 8)) return NULL;
            { qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_INT);
              v->v.i = (int64_t)bolt_get_u64be(d); return v; }
        case 0xC1: {
            if (!bolt_have(d, 8)) return NULL;
            uint64_t bits = bolt_get_u64be(d);
            qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_FLOAT);
            memcpy(&v->v.f, &bits, 8);
            return v;
        }
        default:
            break;
    }

    /* Strings */
    if (marker == 0xD0) {
        if (!bolt_have(d, 1)) return NULL;
        size_t len = d->data[d->pos++];
        if (!bolt_have(d, len)) return NULL;
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_STRING);
        v->v.s.len = len;
        v->v.s.data = (char*)malloc(len + 1);
        memcpy(v->v.s.data, d->data + d->pos, len);
        v->v.s.data[len] = '\0';
        d->pos += len;
        return v;
    }
    if (marker == 0xD1) {
        if (!bolt_have(d, 2)) return NULL;
        uint16_t len = bolt_get_u16be(d);
        if (!bolt_have(d, len)) return NULL;
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_STRING);
        v->v.s.len = len;
        v->v.s.data = (char*)malloc(len + 1);
        memcpy(v->v.s.data, d->data + d->pos, len);
        v->v.s.data[len] = '\0';
        d->pos += len;
        return v;
    }
    if (marker == 0xD2) {
        if (!bolt_have(d, 4)) return NULL;
        uint32_t len = bolt_get_u32be(d);
        if (!bolt_have(d, len)) return NULL;
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_STRING);
        v->v.s.len = len;
        v->v.s.data = (char*)malloc(len + 1);
        memcpy(v->v.s.data, d->data + d->pos, len);
        v->v.s.data[len] = '\0';
        d->pos += len;
        return v;
    }

    /* Lists */
    if (marker == 0xD4) {
        if (!bolt_have(d, 1)) return NULL;
        size_t count = d->data[d->pos++];
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_LIST);
        v->v.list.count = count;
        v->v.list.items = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < count; i++) {
            v->v.list.items[i] = qihse_bolt_decode(d);
            if (!v->v.list.items[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }
    if (marker == 0xD5) {
        if (!bolt_have(d, 2)) return NULL;
        uint16_t count = bolt_get_u16be(d);
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_LIST);
        v->v.list.count = count;
        v->v.list.items = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < count; i++) {
            v->v.list.items[i] = qihse_bolt_decode(d);
            if (!v->v.list.items[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }
    if (marker == 0xD6) {
        if (!bolt_have(d, 4)) return NULL;
        uint32_t count = bolt_get_u32be(d);
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_LIST);
        v->v.list.count = count;
        v->v.list.items = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < count; i++) {
            v->v.list.items[i] = qihse_bolt_decode(d);
            if (!v->v.list.items[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }

    /* Maps */
    if ((marker & 0xF0) == 0xD7) {
        size_t count = marker - 0xD4;
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_MAP);
        v->v.map.count = count;
        v->v.map.keys = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        v->v.map.vals = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < count; i++) {
            v->v.map.keys[i] = qihse_bolt_decode(d);
            v->v.map.vals[i] = qihse_bolt_decode(d);
            if (!v->v.map.keys[i] || !v->v.map.vals[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }
    if (marker == 0xD8) {
        if (!bolt_have(d, 2)) return NULL;
        uint16_t count = bolt_get_u16be(d);
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_MAP);
        v->v.map.count = count;
        v->v.map.keys = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        v->v.map.vals = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < count; i++) {
            v->v.map.keys[i] = qihse_bolt_decode(d);
            v->v.map.vals[i] = qihse_bolt_decode(d);
            if (!v->v.map.keys[i] || !v->v.map.vals[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }
    if (marker == 0xD9) {
        if (!bolt_have(d, 4)) return NULL;
        uint32_t count = bolt_get_u32be(d);
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_MAP);
        v->v.map.count = count;
        v->v.map.keys = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        v->v.map.vals = (qihse_bolt_value_t**)calloc(count ? count : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < count; i++) {
            v->v.map.keys[i] = qihse_bolt_decode(d);
            v->v.map.vals[i] = qihse_bolt_decode(d);
            if (!v->v.map.keys[i] || !v->v.map.vals[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }

    /* Structs */
    if ((marker & 0xF0) == 0xB0) {
        size_t nfields = marker & 0x0F;
        if (!bolt_have(d, 1)) return NULL;
        uint8_t sig = d->data[d->pos++];
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_STRUCT);
        v->v.strct.signature = sig;
        v->v.strct.nfields = nfields;
        v->v.strct.fields = (qihse_bolt_value_t**)calloc(nfields ? nfields : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < nfields; i++) {
            v->v.strct.fields[i] = qihse_bolt_decode(d);
            if (!v->v.strct.fields[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }
    if (marker == 0xB1) {
        if (!bolt_have(d, 3)) return NULL;
        uint16_t nfields = bolt_get_u16be(d);
        uint8_t sig = d->data[d->pos++];
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_STRUCT);
        v->v.strct.signature = sig;
        v->v.strct.nfields = nfields;
        v->v.strct.fields = (qihse_bolt_value_t**)calloc(nfields ? nfields : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < nfields; i++) {
            v->v.strct.fields[i] = qihse_bolt_decode(d);
            if (!v->v.strct.fields[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }
    if (marker == 0xB2) {
        if (!bolt_have(d, 5)) return NULL;
        uint32_t nfields = bolt_get_u32be(d);
        uint8_t sig = d->data[d->pos++];
        qihse_bolt_value_t* v = bolt_new_value(QIHSE_BOLT_STRUCT);
        v->v.strct.signature = sig;
        v->v.strct.nfields = nfields;
        v->v.strct.fields = (qihse_bolt_value_t**)calloc(nfields ? nfields : 1, sizeof(qihse_bolt_value_t*));
        for (size_t i = 0; i < nfields; i++) {
            v->v.strct.fields[i] = qihse_bolt_decode(d);
            if (!v->v.strct.fields[i]) { qihse_bolt_value_free(v); return NULL; }
        }
        return v;
    }

    return NULL;
}

/* ============================================================
 * Message framing (chunking)
 * ============================================================ */

void qihse_bolt_encode_message(qihse_bolt_buf_t* b, uint8_t signature,
                               const uint8_t* payload, size_t payload_len) {
    /* Single chunk: 2-byte big-endian length (signature + payload), then body,
     * then 0x0000 end-of-message marker. */
    uint16_t chunk_len = (uint16_t)(payload_len + 1);
    bolt_put_u16be(b, chunk_len);
    qihse_bolt_buf_append(b, &signature, 1);
    if (payload_len) qihse_bolt_buf_append(b, payload, payload_len);
    /* end-of-message marker */
    bolt_put_u16be(b, 0x0000);
}

int qihse_bolt_decode_message(const uint8_t* data, size_t len,
                              uint8_t* out_sig, uint8_t** out_payload, size_t* out_payload_len,
                              size_t* out_consumed) {
    size_t pos = 0;
    qihse_bolt_buf_t acc;
    qihse_bolt_buf_init(&acc, 64);
    int got_sig = 0;
    uint8_t sig = 0;

    while (pos + 2 <= len) {
        uint16_t chunk_len = ((uint16_t)data[pos] << 8) | data[pos + 1];
        pos += 2;
        if (chunk_len == 0) {
            /* end of message */
            if (!got_sig) { qihse_bolt_buf_free(&acc); return -1; }
            if (out_sig) *out_sig = sig;
            if (out_payload) {
                *out_payload = acc.buf;
                acc.buf = NULL;
            } else {
                qihse_bolt_buf_free(&acc);
            }
            if (out_payload_len) *out_payload_len = acc.len;
            if (out_consumed) *out_consumed = pos;
            return 0;
        }
        if (pos + chunk_len > len) {
            /* not enough data yet */
            qihse_bolt_buf_free(&acc);
            if (out_consumed) *out_consumed = 0;
            return 1;
        }
        if (!got_sig) {
            sig = data[pos];
            got_sig = 1;
            qihse_bolt_buf_append(&acc, data + pos + 1, chunk_len - 1);
        } else {
            qihse_bolt_buf_append(&acc, data + pos, chunk_len);
        }
        pos += chunk_len;
    }
    qihse_bolt_buf_free(&acc);
    if (out_consumed) *out_consumed = 0;
    return 1;
}

/* ============================================================
 * Socket helpers
 * ============================================================ */

static void bolt_write_all(int fd, const uint8_t* buf, size_t len) {
    if (fd < 0) return;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)w;
    }
}

static ssize_t bolt_read_all(int fd, uint8_t* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

/* ============================================================
 * Handshake
 * ============================================================ */

bool qihse_bolt_handshake(int fd, uint32_t* out_version) {
    /* Receive magic + 4 version proposals */
    uint8_t hdr[20];
    if (bolt_read_all(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) return false;
    uint32_t magic = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                     ((uint32_t)hdr[2] << 8) | hdr[3];
    if (magic != QIHSE_BOLT_MAGIC) return false;

    /* Inspect 4 proposed versions, pick 4.0 if offered, else 0 */
    uint32_t chosen = 0;
    for (int i = 0; i < 4; i++) {
        uint32_t v = ((uint32_t)hdr[4 + i*4] << 24) | ((uint32_t)hdr[5 + i*4] << 16) |
                     ((uint32_t)hdr[6 + i*4] << 8) | hdr[7 + i*4];
        if (v == QIHSE_BOLT_VERSION_4) { chosen = QIHSE_BOLT_VERSION_4; break; }
    }
    /* Respond with selected version (big-endian) */
    uint8_t resp[4] = {
        (uint8_t)(chosen >> 24), (uint8_t)(chosen >> 16),
        (uint8_t)(chosen >> 8), (uint8_t)(chosen & 0xFF)
    };
    bolt_write_all(fd, resp, 4);
    if (out_version) *out_version = chosen;
    return chosen != 0;
}

/* ============================================================
 * Server message helpers
 * ============================================================ */

static void bolt_send_success(int fd, const char* key, const char* val) {
    qihse_bolt_buf_t body;
    qihse_bolt_buf_init(&body, 64);
    size_t nkeys = (key && val) ? 1 : 0;
    qihse_bolt_encode_map_begin(&body, nkeys);
    if (nkeys) {
        qihse_bolt_encode_string(&body, key);
        qihse_bolt_encode_string(&body, val);
    }
    qihse_bolt_buf_t msg;
    qihse_bolt_buf_init(&msg, body.len + 4);
    qihse_bolt_encode_message(&msg, QIHSE_BOLT_MSG_SUCCESS, body.buf, body.len);
    bolt_write_all(fd, msg.buf, msg.len);
    qihse_bolt_buf_free(&body);
    qihse_bolt_buf_free(&msg);
}

static void bolt_send_failure(int fd, const char* code, const char* message) {
    qihse_bolt_buf_t body;
    qihse_bolt_buf_init(&body, 64);
    qihse_bolt_encode_map_begin(&body, 2);
    qihse_bolt_encode_string(&body, "code");
    qihse_bolt_encode_string(&body, code ? code : "Neo.ClientError.General.Unknown");
    qihse_bolt_encode_string(&body, "message");
    qihse_bolt_encode_string(&body, message ? message : "unknown error");
    qihse_bolt_buf_t msg;
    qihse_bolt_buf_init(&msg, body.len + 4);
    qihse_bolt_encode_message(&msg, QIHSE_BOLT_MSG_FAILURE, body.buf, body.len);
    bolt_write_all(fd, msg.buf, msg.len);
    qihse_bolt_buf_free(&body);
    qihse_bolt_buf_free(&msg);
}

static void bolt_send_ignored(int fd) {
    qihse_bolt_buf_t msg;
    qihse_bolt_buf_init(&msg, 8);
    qihse_bolt_encode_message(&msg, QIHSE_BOLT_MSG_IGNORED, NULL, 0);
    bolt_write_all(fd, msg.buf, msg.len);
    qihse_bolt_buf_free(&msg);
}

static void bolt_send_record(int fd, const qihse_bolt_value_t* const* fields, size_t nfields) {
    qihse_bolt_buf_t body;
    qihse_bolt_buf_init(&body, 64);
    qihse_bolt_encode_list_begin(&body, nfields);
    for (size_t i = 0; i < nfields; i++) {
        /* re-encode each field */
        const qihse_bolt_value_t* v = fields[i];
        if (!v) { qihse_bolt_encode_null(&body); continue; }
        switch (v->type) {
            case QIHSE_BOLT_NULL: qihse_bolt_encode_null(&body); break;
            case QIHSE_BOLT_BOOL: qihse_bolt_encode_bool(&body, v->v.b); break;
            case QIHSE_BOLT_INT: qihse_bolt_encode_int(&body, v->v.i); break;
            case QIHSE_BOLT_FLOAT: qihse_bolt_encode_float(&body, v->v.f); break;
            case QIHSE_BOLT_STRING: qihse_bolt_encode_string(&body, v->v.s.data); break;
            default: qihse_bolt_encode_null(&body); break;
        }
    }
    qihse_bolt_buf_t msg;
    qihse_bolt_buf_init(&msg, body.len + 4);
    qihse_bolt_encode_message(&msg, QIHSE_BOLT_MSG_RECORD, body.buf, body.len);
    bolt_write_all(fd, msg.buf, msg.len);
    qihse_bolt_buf_free(&body);
    qihse_bolt_buf_free(&msg);
}

/* ============================================================
 * Client handler
 * ============================================================ */

void qihse_bolt_handle_client(int client_fd, qihse_uwp_context_t* ctx) {
    if (client_fd < 0) return;
    uint32_t version = 0;
    if (!qihse_bolt_handshake(client_fd, &version)) {
        close(client_fd);
        return;
    }

    /* Read loop: accumulate bytes, decode messages */
    uint8_t rbuf[65536];
    qihse_bolt_buf_t accum;
    qihse_bolt_buf_init(&accum, 4096);
    bool authenticated = false;
    /* Authenticated user for this session.  Populated during HELLO.
     * Every qihse_uwp_dispatch() call in this session passes bolt_user so
     * that the in-process dispatch path enforces the same auth requirement
     * as the socket-facing uwp_route_payload(). */
    qihse_user_t* bolt_user = NULL;

    for (;;) {
        ssize_t r = read(client_fd, rbuf, sizeof(rbuf));
        if (r <= 0) break;
        qihse_bolt_buf_append(&accum, rbuf, (size_t)r);

        /* Process all complete messages */
        for (;;) {
            uint8_t sig = 0;
            uint8_t* payload = NULL;
            size_t payload_len = 0;
            size_t consumed = 0;
            int rc = qihse_bolt_decode_message(accum.buf, accum.len,
                                               &sig, &payload, &payload_len, &consumed);
            if (rc == 1) break; /* need more data */
            if (rc < 0) { qihse_bolt_buf_free(&accum); close(client_fd); return; }

            /* shift accumulator */
            if (consumed > 0 && consumed < accum.len) {
                memmove(accum.buf, accum.buf + consumed, accum.len - consumed);
                accum.len -= consumed;
            } else {
                accum.len = 0;
            }

            switch (sig) {
                case QIHSE_BOLT_MSG_HELLO: {
                    /* Decode the principal/credentials map and authenticate.
                     * Bolt 4.x HELLO payload: {scheme, principal, credentials, ...}.
                     * We extract principal (username) and credentials (password). */
                    const char* username = NULL;
                    const char* password = NULL;
                    qihse_bolt_decoder_t hdec;
                    qihse_bolt_decoder_init(&hdec, payload, payload_len);
                    qihse_bolt_value_t* hello_map = qihse_bolt_decode(&hdec);
                    if (hello_map && hello_map->type == QIHSE_BOLT_MAP) {
                        for (size_t ki = 0; ki < hello_map->v.map.count; ki++) {
                            qihse_bolt_value_t* k = hello_map->v.map.keys[ki];
                            qihse_bolt_value_t* v = hello_map->v.map.vals[ki];
                            if (!k || k->type != QIHSE_BOLT_STRING || !v) continue;
                            if (strcmp(k->v.s.data, "principal") == 0 &&
                                v->type == QIHSE_BOLT_STRING) {
                                username = v->v.s.data;
                            }
                            if (strcmp(k->v.s.data, "credentials") == 0 &&
                                v->type == QIHSE_BOLT_STRING) {
                                password = v->v.s.data;
                            }
                        }
                    }
                    if (username && password) {
                        bolt_user = qihse_auth_authenticate(username, password);
                    }
                    if (bolt_user) {
                        authenticated = true;
                        bolt_send_success(client_fd, "server", "QIHSE/1.0");
                    } else {
                        bolt_send_failure(client_fd,
                                          "Neo.ClientError.Security.Unauthorized",
                                          "Authentication failed");
                    }
                    qihse_bolt_value_free(hello_map);
                    break;
                }
                case QIHSE_BOLT_MSG_GOODBYE:
                    free(payload);
                    goto done;
                case QIHSE_BOLT_MSG_RESET:
                    bolt_send_success(client_fd, NULL, NULL);
                    break;
                case QIHSE_BOLT_MSG_RUN: {
                    /* Decode payload: string cypher, map params, map extra */
                    qihse_bolt_decoder_t dec;
                    qihse_bolt_decoder_init(&dec, payload, payload_len);
                    qihse_bolt_value_t* cypher = qihse_bolt_decode(&dec);
                    const char* cy = (cypher && cypher->type == QIHSE_BOLT_STRING)
                                     ? cypher->v.s.data : "";
                    /* Translate to UWP and execute */
                    size_t cypher_len = strlen(cy);
                    if (cypher_len > QIHSE_UWP_TRANSLATE_MAX_PAYLOAD ||
                        cypher_len > SIZE_MAX - sizeof(qihse_uwp_header_t)) {
                        fprintf(stderr, "qihse: Bolt Cypher payload is too large (%zu bytes; max %u)\n",
                                cypher_len, QIHSE_UWP_TRANSLATE_MAX_PAYLOAD);
                        bolt_send_failure(client_fd, "Neo.ClientError.Request.Invalid",
                                          "Cypher query exceeds the UWP translation payload limit");
                        qihse_bolt_value_free(cypher);
                        break;
                    }
                    size_t uwp_cap = sizeof(qihse_uwp_header_t) + cypher_len;
                    uint8_t* uwp_pkt = (uint8_t*)malloc(uwp_cap);
                    size_t uwp_len = 0;
                    int translate_rc = uwp_pkt
                        ? qihse_translate_bolt_run_to_uwp(cy, NULL, uwp_pkt, uwp_cap, &uwp_len)
                        : -1;
                    if (translate_rc < 0) {
                        fprintf(stderr, "qihse: Bolt Cypher translation failed (required %zu bytes, capacity %zu)\n",
                                uwp_len, uwp_cap);
                        bolt_send_failure(client_fd, "Neo.ClientError.Request.Invalid",
                                          "Unable to translate Cypher query to UWP");
                        free(uwp_pkt);
                        qihse_bolt_value_free(cypher);
                        break;
                    }
                    uint8_t resp[256];
                    size_t resp_len = 0;
                    if (ctx) {
                        qihse_uwp_dispatch(ctx, bolt_user, (const qihse_uwp_header_t*)uwp_pkt,
                                           uwp_pkt + sizeof(qihse_uwp_header_t),
                                           uwp_len - sizeof(qihse_uwp_header_t),
                                           resp, sizeof(resp), &resp_len);
                    }
                    bolt_send_success(client_fd, "t_first", "1");
                    bolt_send_success(client_fd, "qid", "0");
                    free(uwp_pkt);
                    qihse_bolt_value_free(cypher);
                    break;
                }
                case QIHSE_BOLT_MSG_PULL: {
                    /* Return a single empty record then SUCCESS */
                    bolt_send_record(client_fd, NULL, 0);
                    bolt_send_success(client_fd, "bookmark", "qihse:0");
                    break;
                }
                case QIHSE_BOLT_MSG_DISCARD:
                    bolt_send_success(client_fd, NULL, NULL);
                    break;
                case QIHSE_BOLT_MSG_BEGIN: {
                    uint8_t uwp_pkt[sizeof(qihse_uwp_header_t)];
                    size_t uwp_len = 0;
                    if (qihse_translate_bolt_begin_to_uwp(uwp_pkt, sizeof(uwp_pkt), &uwp_len) < 0) {
                        fprintf(stderr, "qihse: Bolt BEGIN translation failed (required %zu bytes, capacity %zu)\n",
                                uwp_len, sizeof(uwp_pkt));
                        bolt_send_failure(client_fd, "Neo.ClientError.Request.Invalid",
                                          "Unable to translate BEGIN to UWP");
                        break;
                    }
                    uint8_t resp[256];
                    size_t resp_len = 0;
                    if (ctx) {
                        qihse_uwp_dispatch(ctx, bolt_user, (const qihse_uwp_header_t*)uwp_pkt,
                                           uwp_pkt + sizeof(qihse_uwp_header_t),
                                           uwp_len - sizeof(qihse_uwp_header_t),
                                           resp, sizeof(resp), &resp_len);
                    }
                    bolt_send_success(client_fd, NULL, NULL);
                    break;
                }
                case QIHSE_BOLT_MSG_COMMIT: {
                    uint8_t uwp_pkt[sizeof(qihse_uwp_header_t)];
                    size_t uwp_len = 0;
                    if (qihse_translate_bolt_commit_to_uwp(uwp_pkt, sizeof(uwp_pkt), &uwp_len) < 0) {
                        fprintf(stderr, "qihse: Bolt COMMIT translation failed (required %zu bytes, capacity %zu)\n",
                                uwp_len, sizeof(uwp_pkt));
                        bolt_send_failure(client_fd, "Neo.ClientError.Request.Invalid",
                                          "Unable to translate COMMIT to UWP");
                        break;
                    }
                    uint8_t resp[256];
                    size_t resp_len = 0;
                    if (ctx) {
                        qihse_uwp_dispatch(ctx, bolt_user, (const qihse_uwp_header_t*)uwp_pkt,
                                           uwp_pkt + sizeof(qihse_uwp_header_t),
                                           uwp_len - sizeof(qihse_uwp_header_t),
                                           resp, sizeof(resp), &resp_len);
                    }
                    bolt_send_success(client_fd, "bookmark", "qihse:0");
                    break;
                }
                case QIHSE_BOLT_MSG_ROLLBACK: {
                    uint8_t uwp_pkt[sizeof(qihse_uwp_header_t)];
                    size_t uwp_len = 0;
                    if (qihse_translate_bolt_rollback_to_uwp(uwp_pkt, sizeof(uwp_pkt), &uwp_len) < 0) {
                        fprintf(stderr, "qihse: Bolt ROLLBACK translation failed (required %zu bytes, capacity %zu)\n",
                                uwp_len, sizeof(uwp_pkt));
                        bolt_send_failure(client_fd, "Neo.ClientError.Request.Invalid",
                                          "Unable to translate ROLLBACK to UWP");
                        break;
                    }
                    uint8_t resp[256];
                    size_t resp_len = 0;
                    if (ctx) {
                        qihse_uwp_dispatch(ctx, bolt_user, (const qihse_uwp_header_t*)uwp_pkt,
                                           uwp_pkt + sizeof(qihse_uwp_header_t),
                                           uwp_len - sizeof(qihse_uwp_header_t),
                                           resp, sizeof(resp), &resp_len);
                    }
                    bolt_send_success(client_fd, NULL, NULL);
                    break;
                }
                default:
                    bolt_send_ignored(client_fd);
                    break;
            }
            free(payload);
            (void)authenticated;
        }
    }

done:
    qihse_bolt_buf_free(&accum);
    close(client_fd);
}

/* ============================================================
 * Server
 * ============================================================ */

bool qihse_start_bolt_server(qihse_uwp_context_t* ctx, uint16_t port, const char* bind_address) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("bolt socket"); return false; }
    int opt = 1;
#ifdef _WIN32
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (bind_address && bind_address[0] != '\0')
        addr.sin_addr.s_addr = inet_addr(bind_address);
    else
        addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bolt bind");
        close(server_fd);
        return false;
    }
    if (listen(server_fd, 128) < 0) {
        perror("bolt listen");
        close(server_fd);
        return false;
    }
    printf("[QIHSE BOLT] Server online on %s:%d\n",
           bind_address ? bind_address : "0.0.0.0", port);

    for (;;) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(server_fd, (struct sockaddr*)&caddr, &clen);
        if (cfd < 0) continue;
        qihse_bolt_handle_client(cfd, ctx);
    }
    close(server_fd);
    return true;
}
