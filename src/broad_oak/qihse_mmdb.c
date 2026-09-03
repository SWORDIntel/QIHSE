

#include "qihse_mmdb.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#endif

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

#define MMDB_METADATA_SENTINEL "\xab\xcd\xefMaxMind.com"
#define MMDB_METADATA_SENTINEL_LEN 14
#define MMDB_DATA_SECTION_SEPARATOR_SIZE 16

/* MaxMind data-section type tags */
#define MMDB_TYPE_EXTENDED  0
#define MMDB_TYPE_POINTER   1
#define MMDB_TYPE_STRING    2
#define MMDB_TYPE_DOUBLE    3
#define MMDB_TYPE_BYTES     4
#define MMDB_TYPE_UINT16    5
#define MMDB_TYPE_UINT32    6
#define MMDB_TYPE_MAP       7
#define MMDB_TYPE_INT32     8
#define MMDB_TYPE_UINT64    9
#define MMDB_TYPE_UINT128  10
#define MMDB_TYPE_ARRAY    11
#define MMDB_TYPE_CACHE    12
#define MMDB_TYPE_END_MARKER 13
#define MMDB_TYPE_BOOLEAN  14
#define MMDB_TYPE_FLOAT    15

/* --------------------------------------------------------------------------
 * Metadata decoder (msgpack-like TLV subset used by MaxMind for metadata)
 * -------------------------------------------------------------------------- */

typedef struct {
    const uint8_t* buf;
    size_t         len;
    size_t         pos;
} mmdb_cursor_t;

static uint8_t cur_read_u8(mmdb_cursor_t* c) {
    if (c->pos >= c->len) return 0;
    return c->buf[c->pos++];
}

static uint32_t cur_read_u16(mmdb_cursor_t* c) {
    if (c->pos + 2 > c->len) return 0;
    uint32_t v = ((uint32_t)c->buf[c->pos] << 8) | c->buf[c->pos + 1];
    c->pos += 2;
    return v;
}

/* Decode type + size header. Returns type; sets *out_size. */
static int mmdb_decode_type_size(mmdb_cursor_t* c, uint32_t* out_size) {
    if (c->pos >= c->len) return -1;
    uint8_t ctrl = cur_read_u8(c);
    int type = (ctrl >> 5) & 0x07;
    uint32_t sz = ctrl & 0x1f;

    if (type == MMDB_TYPE_EXTENDED) {
        if (c->pos >= c->len) return -1;
        type = cur_read_u8(c) + 7;
    }

    if (sz == 29) {
        sz = 29 + cur_read_u8(c);
    } else if (sz == 30) {
        sz = 285 + cur_read_u16(c);
    } else if (sz == 31) {
        if (c->pos + 3 > c->len) return -1;
        sz = 65821 +
             (((uint32_t)c->buf[c->pos]     << 16) |
              ((uint32_t)c->buf[c->pos + 1] <<  8) |
               (uint32_t)c->buf[c->pos + 2]);
        c->pos += 3;
    }

    *out_size = sz;
    return type;
}

/* --------------------------------------------------------------------------
 * Data-section pointer resolution and full decoder
 * -------------------------------------------------------------------------- */

/*
 * Decode a POINTER value. ctrl is the byte that triggered MMDB_TYPE_POINTER.
 * The cursor c->pos must be AFTER ctrl. Returns the absolute file offset.
 */
static size_t mmdb_decode_pointer(const qihse_mmdb_t* db,
                                   mmdb_cursor_t* c, uint8_t ctrl) {
    uint32_t ptr_size  = (ctrl >> 3) & 0x3;
    uint32_t value_bits = ctrl & 0x7;
    size_t ptr = 0;
    switch (ptr_size) {
        case 0:
            ptr = ((size_t)value_bits << 8) | cur_read_u8(c);
            break;
        case 1:
            ptr = ((size_t)value_bits << 16) |
                  ((size_t)cur_read_u8(c) << 8) | cur_read_u8(c);
            ptr += 2048;
            break;
        case 2:
            ptr = ((size_t)value_bits << 24) |
                  ((size_t)cur_read_u8(c) << 16) |
                  ((size_t)cur_read_u8(c) <<  8) | cur_read_u8(c);
            ptr += 526336;
            break;
        case 3:
            ptr = ((size_t)cur_read_u8(c) << 24) |
                  ((size_t)cur_read_u8(c) << 16) |
                  ((size_t)cur_read_u8(c) <<  8) | cur_read_u8(c);
            break;
    }
    return db->data_section_offset + ptr;
}

/* Forward declarations for mutual recursion */
static void   mmdb_skip_value(const qihse_mmdb_t* db, mmdb_cursor_t* c);
static bool   mmdb_walk_map(const qihse_mmdb_t* db, mmdb_cursor_t* c,
                             uint32_t num_keys, const char** key_path,
                             char* out, size_t out_len);
static bool   mmdb_get_string(const qihse_mmdb_t* db, size_t offset,
                               const char** key_path, char* out, size_t out_len);

/* Read the string at cursor into a caller-supplied buffer. */
static bool mmdb_read_string_at(const qihse_mmdb_t* db, size_t offset,
                                 char* out, size_t out_len) {
    if (offset >= db->data_len) return false;
    mmdb_cursor_t c = { db->data, db->data_len, offset };
    uint32_t sz = 0;
    int type = mmdb_decode_type_size(&c, &sz);
    if (type == MMDB_TYPE_POINTER) {
        uint8_t ctrl = db->data[offset];
        mmdb_cursor_t tmp = { db->data, db->data_len, offset + 1 };
        size_t ptr_off = mmdb_decode_pointer(db, &tmp, ctrl);
        return mmdb_read_string_at(db, ptr_off, out, out_len);
    }
    if (type != MMDB_TYPE_STRING) return false;
    size_t copy = sz < out_len - 1 ? sz : out_len - 1;
    if (c.pos + copy > db->data_len) return false;
    memcpy(out, db->data + c.pos, copy);
    out[copy] = '\0';
    return true;
}

/* Skip one complete value (including pointer indirection width bytes) */
static void mmdb_skip_value(const qihse_mmdb_t* db, mmdb_cursor_t* c) {
    if (c->pos >= c->len) return;
    uint8_t ctrl = cur_read_u8(c);
    int type = (ctrl >> 5) & 0x07;
    uint32_t sz = ctrl & 0x1f;
    if (type == MMDB_TYPE_EXTENDED) {
        if (c->pos >= c->len) return;
        type = cur_read_u8(c) + 7;
    }
    if (type == MMDB_TYPE_POINTER) {
        /* extra bytes after ctrl: ptr_size 0→1, 1→2, 2→3, 3→4 */
        uint32_t ptr_size = (ctrl >> 3) & 0x3;
        c->pos += ptr_size + 1;
        return;
    }
    /* decode size extension */
    if (sz == 29)      { sz = 29  + cur_read_u8(c); }
    else if (sz == 30) { sz = 285 + cur_read_u16(c); }
    else if (sz == 31) {
        sz = 65821 + (((uint32_t)cur_read_u8(c) << 16) |
                       ((uint32_t)cur_read_u8(c) <<  8) |
                        (uint32_t)cur_read_u8(c));
    }
    switch (type) {
        case MMDB_TYPE_MAP:   for (uint32_t i = 0; i < sz * 2; i++) mmdb_skip_value(db, c); break;
        case MMDB_TYPE_ARRAY: for (uint32_t i = 0; i < sz;     i++) mmdb_skip_value(db, c); break;
        default: c->pos += sz; break;
    }
}

/*
 * Walk a map of num_keys entries at cursor, looking for key_path[0].
 * key_path is NULL-terminated. On terminal key, extract string into out.
 */
static bool mmdb_walk_map(const qihse_mmdb_t* db, mmdb_cursor_t* c,
                           uint32_t num_keys, const char** key_path,
                           char* out, size_t out_len) {
    char key_buf[128];

    for (uint32_t i = 0; i < num_keys; i++) {
        if (c->pos >= c->len) return false;

        /* --- Decode key --- */
        size_t key_start = c->pos;
        uint8_t kctrl = cur_read_u8(c);
        int ktype = (kctrl >> 5) & 0x07;
        uint32_t ksz  = kctrl & 0x1f;
        if (ktype == MMDB_TYPE_EXTENDED) { ktype = cur_read_u8(c) + 7; }

        bool key_matched = false;
        size_t ptr_key_offset = 0;
        bool key_is_pointer = false;

        if (ktype == MMDB_TYPE_POINTER) {
            /* pointer key — resolve and compare via mmdb_read_string_at */
            ptr_key_offset = mmdb_decode_pointer(db, c, kctrl);
            key_is_pointer = true;
            /* decode the key string for comparison */
            if (key_path[0] &&
                mmdb_read_string_at(db, ptr_key_offset, key_buf, sizeof(key_buf)) &&
                strcmp(key_buf, key_path[0]) == 0) {
                key_matched = true;
            }
            (void)key_start;
        } else {
            /* inline string key */
            if (ksz == 29)      { ksz = 29  + cur_read_u8(c); }
            else if (ksz == 30) { ksz = 285 + cur_read_u16(c); }
            else if (ksz == 31) {
                ksz = 65821 + (((uint32_t)cur_read_u8(c) << 16) |
                                ((uint32_t)cur_read_u8(c) <<  8) |
                                 (uint32_t)cur_read_u8(c));
            }
            if (key_path[0] && ksz == strlen(key_path[0]) &&
                c->pos + ksz <= c->len &&
                memcmp(db->data + c->pos, key_path[0], ksz) == 0) {
                key_matched = true;
            }
            c->pos += ksz;
            (void)key_is_pointer; (void)ptr_key_offset;
        }

        /* --- Decode value --- */
        if (!key_matched) {
            mmdb_skip_value(db, c);
            continue;
        }

        /* We have a key match — extract or descend */
        if (c->pos >= c->len) return false;
        uint8_t vctrl = db->data[c->pos];
        int vtype = (vctrl >> 5) & 0x07;

        if (vtype == MMDB_TYPE_POINTER) {
            /* Value is a pointer */
            c->pos++;
            size_t ptr_off = mmdb_decode_pointer(db, c, vctrl);
            return mmdb_get_string(db, ptr_off, key_path + 1, out, out_len);
        }

        /* Decode value in-line */
        uint32_t vsz = 0;
        int valtype = mmdb_decode_type_size(c, &vsz);
        if (valtype < 0) return false;

        if (valtype == MMDB_TYPE_STRING && key_path[1] == NULL) {
            size_t copy = vsz < out_len - 1 ? vsz : out_len - 1;
            if (c->pos + copy > c->len) return false;
            memcpy(out, db->data + c->pos, copy);
            out[copy] = '\0';
            return true;
        } else if (valtype == MMDB_TYPE_MAP && key_path[1] != NULL) {
            return mmdb_walk_map(db, c, vsz, key_path + 1, out, out_len);
        } else if (key_path[1] == NULL && valtype == MMDB_TYPE_DOUBLE) {
            if (c->pos + 8 > c->len) return false;
            uint64_t bits = 0;
            for (int i = 0; i < 8; i++) bits = (bits << 8) | db->data[c->pos + i];
            double val; memcpy(&val, &bits, 8);
            snprintf(out, out_len, "%.6f", val);
            return true;
        } else if (key_path[1] == NULL && valtype == MMDB_TYPE_FLOAT) {
            if (c->pos + 4 > c->len) return false;
            uint32_t bits = 0;
            for (int i = 0; i < 4; i++) bits = (bits << 8) | db->data[c->pos + i];
            float val; memcpy(&val, &bits, 4);
            snprintf(out, out_len, "%.6f", (double)val);
            return true;
        } else if (key_path[1] == NULL &&
                   (valtype == MMDB_TYPE_UINT16 || valtype == MMDB_TYPE_UINT32 ||
                    valtype == MMDB_TYPE_INT32 || valtype == MMDB_TYPE_UINT64)) {
            if (c->pos + vsz > c->len) return false;
            uint64_t val = 0;
            for (uint32_t i = 0; i < vsz; i++) val = (val << 8) | db->data[c->pos + i];
            if (valtype == MMDB_TYPE_INT32 && vsz == 4 && (val & 0x80000000)) {
                int64_t sval = (int64_t)(int32_t)(uint32_t)val;
                snprintf(out, out_len, "%lld", (long long)sval);
            } else {
                snprintf(out, out_len, "%llu", (unsigned long long)val);
            }
            return true;
        } else if (key_path[1] == NULL && valtype == MMDB_TYPE_BOOLEAN) {
            snprintf(out, out_len, "%s", vsz ? "true" : "false");
            return true;
        }
        return false;
    }
    return false;
}

/* Entry point: decode value at offset, optionally walk key_path, extract string */
static bool mmdb_get_string(const qihse_mmdb_t* db, size_t offset,
                             const char** key_path, char* out, size_t out_len) {
    if (offset >= db->data_len) return false;

    uint8_t ctrl = db->data[offset];
    int type = (ctrl >> 5) & 0x07;

    if (type == MMDB_TYPE_POINTER) {
        mmdb_cursor_t tmp = { db->data, db->data_len, offset + 1 };
        size_t ptr_off = mmdb_decode_pointer(db, &tmp, ctrl);
        return mmdb_get_string(db, ptr_off, key_path, out, out_len);
    }

    mmdb_cursor_t c = { db->data, db->data_len, offset };
    uint32_t sz = 0;
    int valtype = mmdb_decode_type_size(&c, &sz);
    if (valtype < 0) return false;

    if (valtype == MMDB_TYPE_MAP) {
        if (key_path == NULL || key_path[0] == NULL) return false;
        return mmdb_walk_map(db, &c, sz, key_path, out, out_len);
    } else if (valtype == MMDB_TYPE_STRING) {
        if (key_path != NULL && key_path[0] != NULL) return false;
        size_t copy = sz < out_len - 1 ? sz : out_len - 1;
        if (c.pos + copy > db->data_len) return false;
        memcpy(out, db->data + c.pos, copy);
        out[copy] = '\0';
        return true;
    } else if (valtype == MMDB_TYPE_DOUBLE) {
        if (key_path != NULL && key_path[0] != NULL) return false;
        if (c.pos + 8 > db->data_len) return false;
        uint64_t bits = 0;
        for (int i = 0; i < 8; i++) bits = (bits << 8) | db->data[c.pos + i];
        double val;
        memcpy(&val, &bits, 8);
        snprintf(out, out_len, "%.6f", val);
        return true;
    } else if (valtype == MMDB_TYPE_FLOAT) {
        if (key_path != NULL && key_path[0] != NULL) return false;
        if (c.pos + 4 > db->data_len) return false;
        uint32_t bits = 0;
        for (int i = 0; i < 4; i++) bits = (bits << 8) | db->data[c.pos + i];
        float val;
        memcpy(&val, &bits, 4);
        snprintf(out, out_len, "%.6f", (double)val);
        return true;
    } else if (valtype == MMDB_TYPE_UINT16 || valtype == MMDB_TYPE_UINT32 ||
               valtype == MMDB_TYPE_INT32) {
        if (key_path != NULL && key_path[0] != NULL) return false;
        if (c.pos + sz > db->data_len) return false;
        uint64_t val = 0;
        for (uint32_t i = 0; i < sz; i++) val = (val << 8) | db->data[c.pos + i];
        if (valtype == MMDB_TYPE_INT32 && sz == 4 && (val & 0x80000000)) {
            int64_t sval = (int64_t)(int32_t)(uint32_t)val;
            snprintf(out, out_len, "%lld", (long long)sval);
        } else {
            snprintf(out, out_len, "%llu", (unsigned long long)val);
        }
        return true;
    } else if (valtype == MMDB_TYPE_UINT64) {
        if (key_path != NULL && key_path[0] != NULL) return false;
        if (c.pos + sz > db->data_len) return false;
        uint64_t val = 0;
        for (uint32_t i = 0; i < sz; i++) val = (val << 8) | db->data[c.pos + i];
        snprintf(out, out_len, "%llu", (unsigned long long)val);
        return true;
    } else if (valtype == MMDB_TYPE_BOOLEAN) {
        if (key_path != NULL && key_path[0] != NULL) return false;
        snprintf(out, out_len, "%s", sz ? "true" : "false");
        return true;
    }
    return false;
}

/* --------------------------------------------------------------------------
 * Metadata parsing
 * -------------------------------------------------------------------------- */

/* Read a variable-length uint from metadata cursor (1-4 bytes, big-endian) */
static uint64_t meta_read_uint(mmdb_cursor_t* c, uint32_t byte_count) {
    uint64_t v = 0;
    for (uint32_t i = 0; i < byte_count; i++) {
        v = (v << 8) | cur_read_u8(c);
    }
    return v;
}

static bool mmdb_parse_metadata(qihse_mmdb_t* db, const uint8_t* meta_start, size_t meta_len) {
    mmdb_cursor_t c = { meta_start, meta_len, 0 };

    uint32_t map_sz = 0;
    int type = mmdb_decode_type_size(&c, &map_sz);
    if (type != MMDB_TYPE_MAP) return false;

    for (uint32_t i = 0; i < map_sz; i++) {
        /* Key */
        uint32_t key_sz = 0;
        int key_type = mmdb_decode_type_size(&c, &key_sz);
        if (key_type != MMDB_TYPE_STRING) return false;
        if (c.pos + key_sz > c.len) return false;

        char key[64] = {0};
        size_t copy = key_sz < sizeof(key) - 1 ? key_sz : sizeof(key) - 1;
        memcpy(key, c.buf + c.pos, copy);
        c.pos += key_sz;

        /* Value */
        uint32_t val_sz = 0;
        int val_type = mmdb_decode_type_size(&c, &val_sz);

        if (strcmp(key, "ip_version") == 0) {
            db->ip_version = (uint32_t)meta_read_uint(&c, val_sz);
        } else if (strcmp(key, "record_size") == 0) {
            db->record_size = (uint32_t)meta_read_uint(&c, val_sz);
        } else if (strcmp(key, "node_count") == 0) {
            db->node_count = (uint32_t)meta_read_uint(&c, val_sz);
        } else {
            /* Skip unknown values */
            if (val_type == MMDB_TYPE_MAP) {
                for (uint32_t j = 0; j < val_sz * 2; j++) mmdb_skip_value(NULL, &c);
            } else if (val_type == MMDB_TYPE_ARRAY) {
                for (uint32_t j = 0; j < val_sz; j++) mmdb_skip_value(NULL, &c);
            } else {
                c.pos += val_sz;
            }
        }
    }
    return db->record_size > 0 && db->node_count > 0;
}

/* --------------------------------------------------------------------------
 * Search tree: read a record from a node
 * -------------------------------------------------------------------------- */

/* Read left (bit=0) or right (bit=1) record from node index */
static uint32_t mmdb_read_record(const qihse_mmdb_t* db, uint32_t node, int bit) {
    const uint8_t* p = db->data + (size_t)node * db->node_byte_size;

    if (db->record_size == 24) {
        /* 3 bytes per record, 6 bytes per node */
        if (bit == 0) {
            return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
        } else {
            return ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 8) | p[5];
        }
    } else if (db->record_size == 28) {
        /* 3.5 bytes per record — middle byte split: high nibble=right, low nibble=left */
        if (bit == 0) {
            return ((uint32_t)(p[3] & 0x0f) << 24) |
                   ((uint32_t)p[0] << 16) |
                   ((uint32_t)p[1] <<  8) |
                    (uint32_t)p[2];
        } else {
            return ((uint32_t)(p[3] >> 4) << 24) |
                   ((uint32_t)p[4] << 16) |
                   ((uint32_t)p[5] <<  8) |
                    (uint32_t)p[6];
        }
    } else if (db->record_size == 32) {
        /* 4 bytes per record, 8 bytes per node */
        if (bit == 0) {
            return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                   ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
        } else {
            return ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                   ((uint32_t)p[6] << 8)  |  (uint32_t)p[7];
        }
    }
    return db->node_count; /* no data */
}

/* --------------------------------------------------------------------------
 * IP address parsing
 * -------------------------------------------------------------------------- */

static bool parse_ipv4(const char* ip_str, uint8_t out[4]) {
    struct in_addr a;
    if (inet_pton(AF_INET, ip_str, &a) != 1) return false;
    memcpy(out, &a.s_addr, 4);
    return true;
}

static bool parse_ipv6(const char* ip_str, uint8_t out[16]) {
    struct in6_addr a;
    if (inet_pton(AF_INET6, ip_str, &a) != 1) return false;
    memcpy(out, a.s6_addr, 16);
    return true;
}

/* Walk the search tree for the given IP bytes; returns data-section offset
   or 0 on no-data. bit_count = number of bits to process. */
static size_t mmdb_walk_tree(const qihse_mmdb_t* db,
                              const uint8_t* ip_bytes, int bit_count) {
    uint32_t node = 0;

    /* IPv4-in-IPv6 databases: start at node 96 */
    if (db->ip_version == 6 && bit_count == 32) {
        for (int i = 0; i < 96; i++) {
            node = mmdb_read_record(db, node, 0);
            if (node >= db->node_count) return 0;
        }
    }

    for (int i = 0; i < bit_count; i++) {
        int bit = (ip_bytes[i / 8] >> (7 - (i % 8))) & 1;
        node = mmdb_read_record(db, node, bit);

        if (node >= db->node_count) {
            if (node == db->node_count) return 0; /* no data */
            /* node > node_count: offset into data section */
            size_t offset = db->data_section_offset +
                            (node - db->node_count) -
                            MMDB_DATA_SECTION_SEPARATOR_SIZE;
            return offset;
        }
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

qihse_mmdb_t* qihse_mmdb_open(const char* path) {
    if (!path) return NULL;

#ifndef _WIN32
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return NULL; }
#else
    FILE* f = fopen(path, "rb");
#endif
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (flen <= 0) { fclose(f); return NULL; }

    uint8_t* buf = malloc((size_t)flen);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)flen, f) != (size_t)flen) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);

    /* Find metadata sentinel (scan backwards from end) */
    ssize_t meta_pos = -1;
    for (ssize_t i = (ssize_t)flen - (ssize_t)MMDB_METADATA_SENTINEL_LEN; i >= 0; i--) {
        if (memcmp(buf + i, MMDB_METADATA_SENTINEL, MMDB_METADATA_SENTINEL_LEN) == 0) {
            meta_pos = i + MMDB_METADATA_SENTINEL_LEN;
            break;
        }
    }
    if (meta_pos < 0) { free(buf); return NULL; }

    qihse_mmdb_t* db = calloc(1, sizeof(*db));
    if (!db) { free(buf); return NULL; }
    db->data     = buf;
    db->data_len = (size_t)flen;

    /* Parse metadata */
    if (!mmdb_parse_metadata(db,
                             buf + meta_pos,
                             (size_t)flen - (size_t)meta_pos)) {
        free(buf); free(db); return NULL;
    }

    /* Derive geometry */
    db->node_byte_size     = (db->record_size * 2) / 8;
    db->search_tree_size   = (size_t)db->node_count * db->node_byte_size;
    db->data_section_offset = db->search_tree_size + MMDB_DATA_SECTION_SEPARATOR_SIZE;

    return db;
}

void qihse_mmdb_close(qihse_mmdb_t* db) {
    if (!db) return;
    free(db->data);
    free(db);
}

bool qihse_mmdb_lookup_string(qihse_mmdb_t* db,
                              const char*   ip,
                              const char**  key_path,
                              char*         out,
                              size_t        out_len) {
    if (!db || !ip || !out || out_len == 0) return false;
    out[0] = '\0';

    uint8_t ip_bytes[16];
    int bit_count = 0;
    bool is_ipv4 = false;

    if (parse_ipv4(ip, ip_bytes)) {
        bit_count = 32;
        is_ipv4   = true;
    } else if (parse_ipv6(ip, ip_bytes)) {
        bit_count = 128;
    } else {
        return false;
    }

    /* For IPv4 in a v6 database, bit_count stays 32 but we enter at node 96 */
    if (db->ip_version == 4 && !is_ipv4) return false;

    size_t data_offset = mmdb_walk_tree(db, ip_bytes, bit_count);
    if (data_offset == 0) return false;

    return mmdb_get_string(db, data_offset, key_path, out, out_len);
}
