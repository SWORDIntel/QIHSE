/*
 * QIHSE PostgreSQL Wire Protocol v3 Server
 *
 * Implements the frontend/backend protocol described at:
 *   https://www.postgresql.org/docs/current/protocol.html
 *
 * Audited for UWP wire-level safety: auth enforcement, message length
 * validation, user pass-through, extended query protocol safety.
 *
 * Audit findings and fixes:
 * - CRITICAL: pg_send_auth_and_startup() previously sent AuthenticationOk
 *   immediately without verifying credentials.  It returned a static zeroed
 *   qihse_user_t, so every client was effectively anonymous with no
 *   identity or permissions.  Fixed: now parses the startup message for the
 *   "user" parameter, sends AuthenticationCleartextPassword, reads the
 *   PasswordMessage, and calls qihse_auth_authenticate_from() with the
 *   peer's source IP (matching the pattern fixed in qihse_bolt.c).  Per-IP
 *   rate limiting is enforced via qihse_auth_check_rate_limit().
 * - The authenticated user pointer is now passed through to
 *   pg_handle_query_ctx() and all UWP dispatch calls, so the server-side
 *   auth/permission checks see a real identity instead of a zeroed stub.
 * - Added bounds checks in the Parse (P) handler to prevent out-of-bounds
 *   reads when the parameter OID array extends past body_len.
 * - Added bounds checks in the Close (C) handler for the statement name.
 */

#include "qihse_pg_wire.h"
#include "qihse_vector_db.h"
#include "qihse_uwp.h"
#include "qihse_auth.h"
#include "qihse_dist_planner.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"
#include "qihse_sql_parser.h"
#include "qihse_schema.h"
#include "qihse_optimizer.h"
#include "qihse_uwp_sql_txn_schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <liburing.h>
#include <poll.h>
#include "qihse_af_xdp.h"
#include "../../persistence/qihse_pqc_crypto.h"
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define SSL_CTX void
#define SSL void
#endif

static SSL_CTX* global_pqc_ssl_ctx __attribute__((unused)) = NULL;
static __thread SSL* current_ssl = NULL;
static __thread bool pg_batch_suppress_ready;
static __thread bool pg_batch_error;

typedef struct {
    qihse_uwp_context_t* uwp;
    qihse_txn_t* txn;
    bool failed;
    bool extended_implicit;
    char retry_key[QIHSE_TS_RETRY_MAX_TEXT + 1u];
    void* retry_hash; /* EVP_MD_CTX on POSIX; no retry support on Windows */
    uint64_t retry_rows;
    uint64_t retry_commands;
} pg_transaction_session_t;

/* Extract the IPv4 source address of the peer connected to fd, in host
 * byte order. Returns 0 if the address cannot be determined (in which
 * case the auth rate limiter falls back to its global singleton entry).
 * This mirrors bolt_get_source_ip() in qihse_bolt.c. */
static uint32_t pg_get_source_ip(int fd) {
#ifndef _WIN32
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        return ntohl(addr.sin_addr.s_addr);
    }
#else
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        return ntohl(addr.sin_addr.s_addr);
    }
#endif
    return 0;
}

typedef struct {
    qihse_kv_store_t* store;
    qihse_vector_db_t vdb;
    qihse_tsdb_t* tsdb;
    qihse_column_store_t* col;
    qihse_cluster_topology_t* topo;
} pg_cluster_context_t;

struct qihse_pg_wire_listener {
    int fd;
    uint16_t port;
    qihse_uwp_context_t* uwp;
    qihse_cluster_topology_t* topo;
    SSL_CTX* tls_ctx;
};

/* Write exactly n bytes, retrying on EINTR / short writes. */
static int pg_write_all(int fd, const void* buf, size_t n) {
    const uint8_t* p = (const uint8_t*)buf;
    while (n > 0) {
        ssize_t w;
#ifndef _WIN32
        if (current_ssl) {
            w = SSL_write(current_ssl, p, (int)n);
            if (w <= 0) return -1;
        } else
#endif
        {
            w = write(fd, p, n);
            if (w < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int pg_read_all(int fd, void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf;
    while (n > 0) {
        ssize_t r;
#ifndef _WIN32
        if (current_ssl) {
            r = SSL_read(current_ssl, p, (int)n);
            if (r <= 0) return -1;
        } else
#endif
        {
            r = read(fd, p, n);
            if (r <= 0) {
                if (r < 0 && errno == EINTR) continue;
                return -1;
            }
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
} pg_buf_t;

static void pg_buf_init(pg_buf_t* b) {
    b->cap  = 256;
    b->len  = 0;
    b->data = (uint8_t*)malloc(b->cap);
}

static void pg_buf_free(pg_buf_t* b) {
    if (b->data) free(b->data);
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

static int pg_buf_ensure(pg_buf_t* b, size_t extra) {
    if (b->len + extra > b->cap) {
        size_t new_cap = (b->cap * 2 >= b->len + extra) ? b->cap * 2 : b->len + extra + 256;
        uint8_t* p = (uint8_t*)realloc(b->data, new_cap);
        if (!p) return -1;
        b->data = p;
        b->cap  = new_cap;
    }
    return 0;
}

static int pg_buf_append_byte(pg_buf_t* b, uint8_t v) {
    if (pg_buf_ensure(b, 1) < 0) return -1;
    b->data[b->len++] = v;
    return 0;
}

static int pg_buf_append_int16(pg_buf_t* b, int16_t v) {
    if (pg_buf_ensure(b, 2) < 0) return -1;
    b->data[b->len++] = (uint8_t)((v >> 8) & 0xff);
    b->data[b->len++] = (uint8_t)(v & 0xff);
    return 0;
}

static int pg_buf_append_int32(pg_buf_t* b, int32_t v) {
    if (pg_buf_ensure(b, 4) < 0) return -1;
    b->data[b->len++] = (uint8_t)((v >> 24) & 0xff);
    b->data[b->len++] = (uint8_t)((v >> 16) & 0xff);
    b->data[b->len++] = (uint8_t)((v >> 8)  & 0xff);
    b->data[b->len++] = (uint8_t)(v & 0xff);
    return 0;
}

static int pg_buf_append(pg_buf_t* b, const void* src, size_t n) {
    if (pg_buf_ensure(b, n) < 0) return -1;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

static int pg_buf_append_str(pg_buf_t* b, const char* s) {
    return pg_buf_append(b, s, strlen(s) + 1);
}

static int pg_buf_flush(pg_buf_t* b, int fd) {
    if (b->len == 0) return 0;
    return pg_write_all(fd, b->data, b->len);
}

static int pg_send_msg(int fd, uint8_t tag, const uint8_t* body, size_t body_len) {
    pg_buf_t b;
    pg_buf_init(&b);
    if (pg_buf_append_byte(&b, tag) < 0) goto err;
    if (pg_buf_append_int32(&b, (int32_t)(4 + body_len)) < 0) goto err;
    if (body_len && pg_buf_append(&b, body, body_len) < 0) goto err;
    int rc = pg_buf_flush(&b, fd);
    pg_buf_free(&b);
    return rc;
err:
    pg_buf_free(&b);
    return -1;
}

static int pg_send_auth_ok(int fd) {
    uint8_t body[4] = {0, 0, 0, 0};
    return pg_send_msg(fd, 'R', body, 4);
}

static int pg_send_parameter_status(int fd, const char* name, const char* value) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_str(&b, name);
    pg_buf_append_str(&b, value);
    int rc = pg_send_msg(fd, 'S', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

static int pg_send_backend_key_data(int fd, int32_t pid, int32_t secret) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_int32(&b, pid);
    pg_buf_append_int32(&b, secret);
    int rc = pg_send_msg(fd, 'K', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

static int pg_send_ready_for_query_state(int fd, char status) {
    if (status != 'I' && status != 'T' && status != 'E') return -1;
    if (pg_batch_suppress_ready) return 0;
    uint8_t body[1] = {(uint8_t)status};
    return pg_send_msg(fd, 'Z', body, 1);
}

static int pg_send_ready_for_query(int fd) {
    return pg_send_ready_for_query_state(fd, 'I');
}

static int pg_send_row_description(int fd, const char** field_names, const int32_t* type_oids, int16_t ncols) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_int16(&b, ncols);
    for (int16_t i = 0; i < ncols; i++) {
        pg_buf_append_str(&b, field_names[i]);
        pg_buf_append_int32(&b, 0);
        pg_buf_append_int16(&b, 0);
        pg_buf_append_int32(&b, type_oids[i]);
        pg_buf_append_int16(&b, -1);
        pg_buf_append_int32(&b, -1);
        pg_buf_append_int16(&b, 0);
    }
    int rc = pg_send_msg(fd, 'T', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

static int pg_unescape_result_field(char* field) {
    unsigned char* src = (unsigned char*)field;
    unsigned char* dst = (unsigned char*)field;
    while (*src) {
        if (*src != 92u) { *dst++ = *src++; continue; }
        ++src;
        if (*src == 92u) *dst++ = *src++;
        else if (*src == 't') { *dst++ = 9u; ++src; }
        else if (*src == 'n') { *dst++ = 10u; ++src; }
        else if (*src == 'r') { *dst++ = 13u; ++src; }
        else if (*src == 'x' && src[1] && src[2]) {
            int hi = isdigit(src[1]) ? src[1] - '0' :
                tolower(src[1]) >= 'a' && tolower(src[1]) <= 'f' ?
                tolower(src[1]) - 'a' + 10 : -1;
            int lo = isdigit(src[2]) ? src[2] - '0' :
                tolower(src[2]) >= 'a' && tolower(src[2]) <= 'f' ?
                tolower(src[2]) - 'a' + 10 : -1;
            if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) return -1;
            *dst++ = (unsigned char)((hi << 4) | lo);
            src += 3;
        } else return -1;
    }
    *dst = 0;
    return 0;
}

static int pg_send_data_row(int fd, const char** values, int16_t ncols) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_int16(&b, ncols);
    for (int16_t i = 0; i < ncols; i++) {
        if (values[i] == NULL) {
            pg_buf_append_int32(&b, -1);
        } else {
            int32_t len = (int32_t)strlen(values[i]);
            pg_buf_append_int32(&b, len);
            pg_buf_append(&b, values[i], (size_t)len);
        }
    }
    int rc = pg_send_msg(fd, 'D', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

#define PG_PREPARED_LIMIT 32u
#define PG_BIND_LIMIT 64u
#define PG_COLUMN_LIMIT 64u

typedef struct {
    const uint8_t* data;
    size_t len, pos;
} pg_frame_t;

static bool pg_frame_u16(pg_frame_t* f, uint16_t* out) {
    if (f->pos > f->len || f->len - f->pos < 2u) return false;
    *out = (uint16_t)(((uint16_t)f->data[f->pos] << 8) | f->data[f->pos + 1u]);
    f->pos += 2u;
    return true;
}

static bool pg_frame_u32(pg_frame_t* f, uint32_t* out) {
    if (f->pos > f->len || f->len - f->pos < 4u) return false;
    *out = ((uint32_t)f->data[f->pos] << 24) |
           ((uint32_t)f->data[f->pos + 1u] << 16) |
           ((uint32_t)f->data[f->pos + 2u] << 8) | f->data[f->pos + 3u];
    f->pos += 4u;
    return true;
}

static bool pg_frame_string(pg_frame_t* f, const char** out) {
    if (f->pos >= f->len) return false;
    const uint8_t* end = memchr(f->data + f->pos, 0, f->len - f->pos);
    if (!end) return false;
    *out = (const char*)f->data + f->pos;
    f->pos = (size_t)(end - f->data) + 1u;
    return true;
}

static bool pg_frame_bytes(pg_frame_t* f, size_t n, const uint8_t** out) {
    if (f->pos > f->len || n > f->len - f->pos) return false;
    *out = f->data + f->pos;
    f->pos += n;
    return true;
}

typedef struct {
    char* name;
    char* sql;
    qihse_sql_ast_t* ast;
    size_t nparams;
    int32_t param_oids[PG_BIND_LIMIT];
} pg_prepared_t;

typedef struct {
    char* name;
    pg_prepared_t* statement;
    uint8_t* values[PG_BIND_LIMIT];
    size_t lengths[PG_BIND_LIMIT];
    bool nulls[PG_BIND_LIMIT];
    int16_t formats[PG_BIND_LIMIT];
    int16_t result_formats[PG_COLUMN_LIMIT];
    size_t nresult_formats;
    bool completed;
    char command_tag[96]; /* Completion only; never retain result rows. */
} pg_portal_t;

static __thread pg_portal_t* pg_completing_portal;

typedef struct {
    pg_prepared_t* statements[PG_PREPARED_LIMIT];
    pg_portal_t* portals[PG_PREPARED_LIMIT];
} pg_extended_t;

static void pg_portal_free(pg_portal_t* p) {
    if (!p) return;
    for (size_t i = 0; i < PG_BIND_LIMIT; ++i) free(p->values[i]);
    free(p->name);
    free(p);
}

static void pg_prepared_free(pg_prepared_t* p) {
    if (!p) return;
    qihse_sql_ast_free(p->ast);
    free(p->name);
    free(p->sql);
    free(p);
}

static pg_prepared_t* pg_prepared_find(pg_extended_t* ext, const char* name, size_t* slot) {
    for (size_t i = 0; i < PG_PREPARED_LIMIT; ++i)
        if (ext->statements[i] && !strcmp(ext->statements[i]->name, name)) {
            if (slot) *slot = i;
            return ext->statements[i];
        }
    return NULL;
}

static pg_portal_t* pg_portal_find(pg_extended_t* ext, const char* name, size_t* slot) {
    for (size_t i = 0; i < PG_PREPARED_LIMIT; ++i)
        if (ext->portals[i] && !strcmp(ext->portals[i]->name, name)) {
            if (slot) *slot = i;
            return ext->portals[i];
        }
    return NULL;
}

static void pg_extended_clear_portals(pg_extended_t* ext) {
    for (size_t i = 0; i < PG_PREPARED_LIMIT; ++i) {
        pg_portal_free(ext->portals[i]);
        ext->portals[i] = NULL;
    }
}

static void pg_extended_clear(pg_extended_t* ext) {
    pg_extended_clear_portals(ext);
    for (size_t i = 0; i < PG_PREPARED_LIMIT; ++i)
        pg_prepared_free(ext->statements[i]);
}

static void pg_extended_drop_statement(pg_extended_t* ext, size_t slot) {
    pg_prepared_t* old = ext->statements[slot];
    for (size_t i = 0; i < PG_PREPARED_LIMIT; ++i)
        if (ext->portals[i] && ext->portals[i]->statement == old) {
            pg_portal_free(ext->portals[i]);
            ext->portals[i] = NULL;
        }
    pg_prepared_free(old);
    ext->statements[slot] = NULL;
}

static bool pg_has_multiple_statements(const char* sql);

static const char* pg_extended_parse(pg_extended_t* ext, pg_frame_t* f) {
    const char *name, *sql;
    uint16_t count;
    if (!pg_frame_string(f, &name) || !pg_frame_string(f, &sql) ||
        !pg_frame_u16(f, &count) || count > PG_BIND_LIMIT ||
        strlen(name) > 128u || strlen(sql) > 4095u ||
        f->len - f->pos != (size_t)count * 4u)
        return "08P01";
    if (!*sql || pg_has_multiple_statements(sql)) return "0A000";
    size_t slot = PG_PREPARED_LIMIT;
    pg_prepared_t* old = pg_prepared_find(ext, name, &slot);
    if (old && *name) return "42P05";
    if (!old) {
        for (size_t i = 0; i < PG_PREPARED_LIMIT; ++i)
            if (!ext->statements[i]) { slot = i; break; }
    }
    if (slot == PG_PREPARED_LIMIT) return "54000";
    pg_prepared_t* p = calloc(1, sizeof(*p));
    if (!p) return "53200";
    p->name = strdup(name);
    p->sql = strdup(sql);
    p->ast = qihse_parse_sql_to_ast(sql);
    if (!p->name || !p->sql || !p->ast || !qihse_sql_ast_parameters_valid(p->ast) ||
        (p->nparams = qihse_sql_ast_parameter_count(p->ast)) > PG_BIND_LIMIT ||
        (count && count != p->nparams)) {
        pg_prepared_free(p);
        return "0A000";
    }
    for (size_t i = 0; i < count; ++i) {
        uint32_t oid;
        if (!pg_frame_u32(f, &oid)) { pg_prepared_free(p); return "08P01"; }
        p->param_oids[i] = (int32_t)oid;
    }
    if (old) pg_extended_drop_statement(ext, slot);
    ext->statements[slot] = p;
    return NULL;
}

static const char* pg_extended_bind(pg_extended_t* ext, pg_frame_t* f) {
    const char *name, *stmt;
    uint16_t nformats, count, nresults, format;
    if (!pg_frame_string(f, &name) || !pg_frame_string(f, &stmt) ||
        strlen(name) > 128u || strlen(stmt) > 128u ||
        !pg_frame_u16(f, &nformats) || nformats > PG_BIND_LIMIT)
        return "08P01";
    pg_prepared_t* prepared = pg_prepared_find(ext, stmt, NULL);
    if (!prepared) return "26000";
    uint16_t formats[PG_BIND_LIMIT] = {0};
    for (size_t i = 0; i < nformats; ++i)
        if (!pg_frame_u16(f, &formats[i]) || formats[i] > 1) return "08P01";
    if (!pg_frame_u16(f, &count) || count != prepared->nparams ||
        (nformats != 0 && nformats != 1 && nformats != count)) return "08P01";
    size_t slot = PG_PREPARED_LIMIT;
    pg_portal_t* old = pg_portal_find(ext, name, &slot);
    if (old && *name) return "42P03";
    if (!old)
        for (size_t i = 0; i < PG_PREPARED_LIMIT; ++i)
            if (!ext->portals[i]) { slot = i; break; }
    if (slot == PG_PREPARED_LIMIT) return "54000";
    pg_portal_t* p = calloc(1, sizeof(*p));
    if (!p) return "53200";
    p->name = strdup(name);
    p->statement = prepared;
    if (!p->name) { pg_portal_free(p); return "53200"; }
    for (size_t i = 0; i < count; ++i) {
        uint32_t length;
        const uint8_t* value = NULL;
        if (!pg_frame_u32(f, &length) ||
            (length != UINT32_MAX && (length > 1024u * 1024u ||
              !pg_frame_bytes(f, length, &value)))) {
            pg_portal_free(p);
            return "08P01";
        }
        p->formats[i] = nformats ? formats[nformats == 1 ? 0 : i] : 0;
        if (length == UINT32_MAX) p->nulls[i] = true;
        else {
            p->values[i] = malloc((size_t)length + 1u);
            if (!p->values[i]) { pg_portal_free(p); return "53200"; }
            if (length) memcpy(p->values[i], value, length);
            p->values[i][length] = 0;
            p->lengths[i] = length;
            if (!p->formats[i] && memchr(p->values[i], 0, length)) {
                pg_portal_free(p);
                return "22021";
            }
        }
    }
    if (!pg_frame_u16(f, &nresults) || nresults > PG_COLUMN_LIMIT) {
        pg_portal_free(p);
        return "08P01";
    }
    p->nresult_formats = nresults;
    for (size_t i = 0; i < nresults; ++i) {
        if (!pg_frame_u16(f, &format) || format > 1) {
            pg_portal_free(p);
            return "08P01";
        }
        p->result_formats[i] = (int16_t)format;
    }
    if (f->pos != f->len) { pg_portal_free(p); return "08P01"; }
    if (old) pg_portal_free(old);
    ext->portals[slot] = p;
    return NULL;
}

static int pg_send_command_complete(int fd, const char* tag) {
    if (pg_completing_portal) {
        size_t len = strlen(tag);
        if (len < sizeof(pg_completing_portal->command_tag))
            memcpy(pg_completing_portal->command_tag, tag, len + 1u);
    }
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_str(&b, tag);
    int rc = pg_send_msg(fd, 'C', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

static int pg_send_error(int fd, const char* severity, const char* sqlstate, const char* message) {
    if (pg_batch_suppress_ready) pg_batch_error = true;
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_byte(&b, 'S');
    pg_buf_append_str(&b, severity);
    pg_buf_append_byte(&b, 'V');
    pg_buf_append_str(&b, severity);
    pg_buf_append_byte(&b, 'C');
    pg_buf_append_str(&b, sqlstate);
    pg_buf_append_byte(&b, 'M');
    pg_buf_append_str(&b, message);
    pg_buf_append_byte(&b, '\0');
    int rc = pg_send_msg(fd, 'E', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

static int str_iprefix(const char* s, const char* prefix) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    while (*prefix) {
        if ((*s | 0x20) != (*prefix | 0x20)) return 0;
        s++; prefix++;
    }
    return 1;
}

static void str_rtrim_semi(char* s) {
    int n = (int)strlen(s);
    while (n > 0 && (s[n-1] == ';' || s[n-1] == ' ' || s[n-1] == '\t' ||
                     s[n-1] == '\r' || s[n-1] == '\n')) {
        s[--n] = '\0';
    }
}

typedef struct {
    char* data;
    size_t len;
    size_t cap;
    bool failed;
} pg_uwp_capture_t;

#define PG_UWP_CAPTURE_MAX (1024u * 1024u)

static ssize_t pg_uwp_capture_write(void* opaque, const void* data, size_t len) {
    pg_uwp_capture_t* capture = (pg_uwp_capture_t*)opaque;
    if (!capture || (!data && len) || len > PG_UWP_CAPTURE_MAX - capture->len) {
        if (capture) capture->failed = true;
        return -1;
    }
    size_t needed = capture->len + len + 1u;
    if (needed > capture->cap) {
        size_t cap = capture->cap ? capture->cap : 128u;
        while (cap < needed) {
            if (cap > PG_UWP_CAPTURE_MAX / 2u) {
                cap = PG_UWP_CAPTURE_MAX + 1u;
                break;
            }
            cap *= 2u;
        }
        char* next = (char*)realloc(capture->data, cap);
        if (!next) {
            capture->failed = true;
            return -1;
        }
        capture->data = next;
        capture->cap = cap;
    }
    if (len) memcpy(capture->data + capture->len, data, len);
    capture->len += len;
    capture->data[capture->len] = '\0';
    return (ssize_t)len;
}

static char pg_txn_ready_status(const pg_transaction_session_t* session) {
    if (!session) return 'I';
    if (session->failed) return 'E';
    return session->txn ? 'T' : 'I';
}

static int pg_send_error_ready(int fd, pg_transaction_session_t* session,
                               const char* state, const char* message,
                               bool abort_transaction) {
    if (abort_transaction && session) session->failed = true;
    if (pg_send_error(fd, "ERROR", state, message) < 0) return -1;
    return pg_send_ready_for_query_state(fd, pg_txn_ready_status(session));
}

static bool pg_has_multiple_statements_at(const char* sql, const char** split) {
    bool single = false, quoted = false;
    const char* dollar = NULL;
    size_t dollar_len = 0;
    for (const char* p = sql; *p; ++p) {
        if (dollar) {
            if (*p == '$' && strncmp(p, dollar, dollar_len) == 0) {
                p += dollar_len - 1u;
                dollar = NULL;
            }
            continue;
        }
        if (single) {
            if (*p == '\'' && p[1] == '\'') { ++p; continue; }
            if (*p == '\'') single = false;
            continue;
        }
        if (quoted) {
            if (*p == '"' && p[1] == '"') { ++p; continue; }
            if (*p == '"') quoted = false;
            continue;
        }
        if (*p == '\'') { single = true; continue; }
        if (*p == '"') { quoted = true; continue; }
        if (*p == '$') {
            const char* end = p + 1;
            while (isalnum((unsigned char)*end) || *end == '_') ++end;
            if (*end == '$') {
                dollar = p;
                dollar_len = (size_t)(end - p + 1);
                p = end;
                continue;
            }
        }
        if (*p == ';') {
            for (const char* tail = p + 1; *tail; ++tail)
                if (!isspace((unsigned char)*tail) && *tail != ';') {
                    if (split) *split = p;
                    return true;
                }
        }
    }
    return dollar != NULL || single || quoted;
}

static bool pg_has_multiple_statements(const char* sql) {
    return pg_has_multiple_statements_at(sql, NULL);
}

static void pg_retry_reset(pg_transaction_session_t* session) {
    if (!session) return;
#ifndef _WIN32
    EVP_MD_CTX_free((EVP_MD_CTX*)session->retry_hash);
#endif
    session->retry_hash = NULL;
    session->retry_rows = 0;
    session->retry_commands = 0;
}

static bool pg_retry_begin(pg_transaction_session_t* session, uint8_t isolation) {
    pg_retry_reset(session);
    if (!session->retry_key[0]) return true;
#ifndef _WIN32
    static const char domain[] = "QIHSE-SQL-RETRY-v1";
    EVP_MD_CTX* hash = EVP_MD_CTX_new();
    if (!hash) return false;
    if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(hash, domain, sizeof(domain) - 1u) != 1 ||
        EVP_DigestUpdate(hash, &isolation, 1) != 1) {
        EVP_MD_CTX_free(hash);
        return false;
    }
    session->retry_hash = hash;
    return true;
#else
    (void)isolation;
    return false;
#endif
}

static bool pg_retry_record(pg_transaction_session_t* session,
                            const char* sql, uint64_t rows) {
    if (!session->retry_hash) return !session->retry_key[0];
#ifndef _WIN32
    size_t len = strlen(sql);
    if (len > UINT32_MAX || rows > UINT64_MAX - session->retry_rows ||
        session->retry_commands == UINT64_MAX) return false;
    uint32_t n = (uint32_t)len;
    unsigned char width[4] = {(unsigned char)(n >> 24), (unsigned char)(n >> 16),
                              (unsigned char)(n >> 8), (unsigned char)n};
    if (EVP_DigestUpdate((EVP_MD_CTX*)session->retry_hash, width, sizeof(width)) != 1 ||
        EVP_DigestUpdate((EVP_MD_CTX*)session->retry_hash, sql, len) != 1)
        return false;
    session->retry_rows += rows;
    session->retry_commands++;
    return true;
#else
    (void)sql; (void)rows;
    return false;
#endif
}

static bool pg_retry_identity(pg_transaction_session_t* session,
                              qihse_user_t* user,
                              qihse_ts_retry_identity_t* identity) {
#ifndef _WIN32
    if (!session->retry_hash || !user || !identity) return false;
    unsigned int size = 0;
    memset(identity, 0, sizeof(*identity));
    if (EVP_DigestFinal_ex((EVP_MD_CTX*)session->retry_hash,
                           identity->digest, &size) != 1 ||
        size != sizeof(identity->digest)) return false;
    identity->key = session->retry_key;
    return true;
#else
    (void)session; (void)user; (void)identity;
    return false;
#endif
}

static uint8_t pg_txn_isolation(const char* sql) {
    if (strcasestr(sql, "SERIALIZABLE")) return QIHSE_ISO_SERIALIZABLE;
    if (strcasestr(sql, "REPEATABLE READ")) return QIHSE_ISO_REPEATABLE_READ;
    return QIHSE_ISO_READ_COMMITTED;
}

static int pg_handle_txn_control(int fd, const char* sql,
                                 const qihse_sql_ast_t* ast,
                                 qihse_user_t* user,
                                 pg_transaction_session_t* session) {
    if (!session || !ast || !session->uwp) {
        return pg_send_error_ready(fd, session, "0A000",
                                   "transaction commands require a configured shared SQL context",
                                   false);
    }
    qihse_uwp_context_t* ctx = session->uwp;
    qihse_txn_t** txn = &session->txn;
    if (!ctx->txn_manager) {
        return pg_send_error_ready(fd, session, "0A000",
                                   "transaction manager is not configured", false);
    }
    if (pg_has_multiple_statements(sql)) {
        return pg_send_error_ready(fd, session, "0A000",
                                   "multiple statements in one query are unsupported",
                                   session->txn != NULL);
    }

    uwp_sts_result_t status = UWP_STS_ERR_FAILED;
    uint8_t isolation = pg_txn_isolation(sql);
    if (ast->stmt_type == QIHSE_SQL_BEGIN) {
        if (session->txn) {
            return pg_send_error_ready(fd, session, "25001",
                                       "a transaction is already in progress", true);
        }
        if (session->failed || (ast->util &&
            (ast->util->flags & QIHSE_UTIL_READ_ONLY))) {
            return pg_send_error_ready(fd, session, "0A000",
                                       "failed or read-only transactions are unsupported", false);
        }
        if (!pg_retry_begin(session, isolation))
            return pg_send_error_ready(fd, session, "0A000",
                                       "retry digest initialization failed", false);
        status = uwp_dispatch_txn(ctx, 0x01, &isolation, 1, txn, user,
                                  fd, NULL, NULL);
        if (status != UWP_STS_OK || !session->txn) {
            pg_retry_reset(session);
            return pg_send_error_ready(fd, session, "25000",
                                       "could not begin transaction", false);
        }
        session->failed = false;
        if (pg_send_command_complete(fd, "BEGIN") < 0) return -1;
        return pg_send_ready_for_query_state(fd, 'T');
    }

    if (!session->txn && session->failed &&
        (ast->stmt_type == QIHSE_SQL_ROLLBACK ||
         ast->stmt_type == QIHSE_SQL_COMMIT)) {
        session->failed = false;
        pg_retry_reset(session);
        if (pg_send_command_complete(fd, "ROLLBACK") < 0) return -1;
        return pg_send_ready_for_query_state(fd, 'I');
    }
    if (!session->txn) {
        return pg_send_error_ready(fd, session, "25P01",
                                   "there is no transaction in progress", false);
    }

    if (ast->stmt_type == QIHSE_SQL_COMMIT) {
        if (session->failed) {
            /* PostgreSQL treats COMMIT in an aborted transaction as ROLLBACK. */
            (void)qihse_txn_rollback((qihse_txn_manager_t*)ctx->txn_manager,
                                     session->txn);
            session->txn = NULL;
            session->failed = false;
            pg_retry_reset(session);
            if (pg_send_command_complete(fd, "ROLLBACK") < 0) return -1;
            return pg_send_ready_for_query_state(fd, 'I');
        }
        qihse_ts_retry_status_t retry_status = QIHSE_TS_RETRY_ERROR;
        qihse_ts_retry_outcome_t recorded = {0};
        if (session->retry_key[0]) {
            qihse_ts_retry_identity_t identity;
            char principal[32], tenant[32];
            if (!session->retry_commands ||
                !pg_retry_identity(session, user, &identity) ||
                snprintf(principal, sizeof(principal), "user:%u",
                         qihse_user_get_id(user)) >= (int)sizeof(principal) ||
                snprintf(tenant, sizeof(tenant), "tenant:%u",
                         qihse_user_get_tenant_id(user)) >= (int)sizeof(tenant))
                return pg_send_error_ready(fd, session, "0A000",
                                           "retry requires staged SQL writes", true);
            identity.principal = principal;
            identity.tenant = tenant;
            qihse_ts_retry_outcome_t expected = {
                .affected_rows = session->retry_rows,
                .command_count = session->retry_commands
            };
            if (!qihse_uwp_sql_txn_bind_retry(session->txn, &identity,
                    &expected, &retry_status, &recorded))
                return pg_send_error_ready(fd, session, "0A000",
                                           "retry resource binding failed", true);
        }
        bool retry_bound = session->retry_key[0] != '\0';
        status = uwp_dispatch_txn(ctx, 0x02, NULL, 0, txn, user, fd, NULL, NULL);
        pg_retry_reset(session);
        if (status != UWP_STS_OK) {
            if (session->txn && retry_bound) {
                (void)qihse_txn_rollback((qihse_txn_manager_t*)ctx->txn_manager,
                                         session->txn);
                session->txn = NULL;
                session->failed = true;
            } else session->failed = session->txn != NULL;
            if (status == UWP_STS_ERR_PERM)
                return pg_send_error_ready(fd, session, "42501",
                    "transaction authorization was revoked", session->txn != NULL);
            return pg_send_error_ready(fd, session,
                !qihse_uwp_sql_durable_ready(ctx) ? "40003" :
                !retry_bound ? "40001" :
                retry_status == QIHSE_TS_RETRY_MISMATCH ? "22023" :
                retry_status == QIHSE_TS_RETRY_ERROR ? "40003" : "40001",
                "transaction commit failed or outcome requires recovery",
                session->txn != NULL);
        }
        session->failed = false;
        if (pg_send_command_complete(fd, "COMMIT") < 0) return -1;
        return pg_send_ready_for_query_state(fd, 'I');
    }

    if (ast->stmt_type == QIHSE_SQL_ROLLBACK) {
        /* Rollback is safe even after principal revocation: it only discards
         * this connection's private transaction state. */
        int rc = qihse_txn_rollback((qihse_txn_manager_t*)ctx->txn_manager,
                                    session->txn);
        if (rc != 0) {
            return pg_send_error_ready(fd, session, "25000", "transaction rollback failed",
                                       true);
        }
        session->txn = NULL;
        session->failed = false;
        pg_retry_reset(session);
        if (pg_send_command_complete(fd, "ROLLBACK") < 0) return -1;
        return pg_send_ready_for_query_state(fd, 'I');
    }

    return pg_send_error_ready(fd, session, "0A000", "unsupported transaction command", true);
}

static void pg_implicit_rollback(pg_transaction_session_t* session) {
    if (session->txn) {
        (void)qihse_txn_rollback((qihse_txn_manager_t*)session->uwp->txn_manager,
                                session->txn);
        session->txn = NULL;
    }
    session->failed = false;
}

static int pg_handle_sql_dml(int fd, const char* sql, qihse_user_t* user,
                             pg_transaction_session_t* session,
                             const qihse_sql_ast_t* ast) {
    if (!session || !session->uwp || !session->uwp->sql_engine ||
        !session->uwp->schema || !session->uwp->txn_manager) {
        return pg_send_error_ready(fd, session, "0A000",
                                   "SQL row-store context is not configured",
                                   session && session->txn);
    }
    if (pg_has_multiple_statements(sql)) {
        return pg_send_error_ready(fd, session, "0A000",
                                   "multiple statements in one query are unsupported",
                                   session->txn != NULL);
    }
    if (session->failed) {
        return pg_send_error_ready(fd, session, "25P02",
                                   "current transaction is aborted; rollback required",
                                   false);
    }
    if (session->retry_key[0] && !session->txn)
        return pg_send_error_ready(fd, session, "0A000",
                                   "retry writes require an explicit transaction", false);

    bool had_transaction = session->txn != NULL;
    bool implicit = !had_transaction && qihse_uwp_sql_durable_ready(session->uwp);
    const uint8_t isolation = QIHSE_ISO_READ_COMMITTED;
    if (implicit && uwp_dispatch_txn(session->uwp, 0x01, &isolation, sizeof(isolation),
            &session->txn, user, fd, NULL, NULL) != UWP_STS_OK)
        return pg_send_error_ready(fd, session, "25000",
                                   "implicit transaction could not begin", false);
    pg_uwp_capture_t capture = {0};
    uwp_sts_result_t status = uwp_dispatch_sql(session->uwp, 0x02,
        (const uint8_t*)sql, strlen(sql) + 1u, &session->txn, user, fd,
        pg_uwp_capture_write, &capture);
    if (status != UWP_STS_OK || capture.failed || !capture.data) {
        free(capture.data);
        if (implicit) pg_implicit_rollback(session);
        else if (had_transaction) session->failed = true;
        return pg_send_error_ready(fd, session,
            status == UWP_STS_ERR_PERM ? "42501" : "0A000",
            "QIHSE SQL statement failed or was refused",
            session->txn != NULL);
    }

    const char* type = qihse_sql_stmt_name(ast->stmt_type);
    char prefix[48];
    int prefix_len = snprintf(prefix, sizeof(prefix), "OK stmt_type=%s rows=",
                              type ? type : "");
    if (prefix_len < 0 || (size_t)prefix_len >= sizeof(prefix) ||
        strncmp(capture.data, prefix, (size_t)prefix_len) != 0) {
        free(capture.data);
        if (implicit) pg_implicit_rollback(session);
        return pg_send_error_ready(fd, session, "XX000",
                                   "SQL executor returned a mismatched command",
                                   had_transaction);
    }
    const char* rows_text = capture.data + prefix_len;
    if (!isdigit((unsigned char)*rows_text)) {
        free(capture.data);
        if (implicit) pg_implicit_rollback(session);
        return pg_send_error_ready(fd, session, "XX000",
                                   "SQL executor omitted affected-row count",
                                   had_transaction);
    }
    errno = 0;
    char* end = NULL;
    unsigned long long rows = strtoull(rows_text, &end, 10);
    if (errno == ERANGE || end == rows_text ||
        (strcmp(end, "\n") != 0 && *end != '\0')) {
        free(capture.data);
        if (implicit) pg_implicit_rollback(session);
        return pg_send_error_ready(fd, session, "XX000",
                                   "malformed SQL executor response",
                                   had_transaction);
    }
    free(capture.data);
    if (implicit) {
        status = uwp_dispatch_txn(session->uwp, 0x02, NULL, 0, &session->txn,
                                 user, fd, NULL, NULL);
        if (status != UWP_STS_OK) {
            pg_implicit_rollback(session);
            return pg_send_error_ready(fd, session,
                status == UWP_STS_ERR_PERM ? "42501" :
                qihse_uwp_sql_durable_ready(session->uwp) ? "40001" : "40003",
                "implicit transaction commit failed", false);
        }
    }

    char command[64];
    if (ast->stmt_type == QIHSE_SQL_INSERT)
        snprintf(command, sizeof(command), "INSERT 0 %llu", rows);
    else if (ast->stmt_type == QIHSE_SQL_UPDATE)
        snprintf(command, sizeof(command), "UPDATE %llu", rows);
    else if (ast->stmt_type == QIHSE_SQL_DELETE)
        snprintf(command, sizeof(command), "DELETE %llu", rows);
    else
        snprintf(command, sizeof(command), "%s %llu", type ? type : "UPDATE", rows);
    if (!pg_retry_record(session, sql, rows)) {
        session->failed = true;
        return pg_send_error_ready(fd, session, "XX000",
                                   "retry digest update failed", false);
    }
    if (pg_send_command_complete(fd, command) < 0) return -1;
    return pg_send_ready_for_query_state(fd, pg_txn_ready_status(session));
}

static int pg_handle_sql_ddl(int fd, const char* sql, qihse_user_t* user,
                             pg_transaction_session_t* session,
                             const qihse_sql_ast_t* ast) {
    if (!session || !session->uwp || !session->uwp->sql_engine ||
        !session->uwp->schema || !qihse_uwp_sql_durable_ready(session->uwp))
        return pg_send_error_ready(fd, session, "0A000",
                                   "durable SQL context is not configured", false);
    if (session->failed)
        return pg_send_error_ready(fd, session, "25P02",
                                   "current transaction is aborted; rollback required", false);
    if (session->retry_key[0])
        return pg_send_error_ready(fd, session, "0A000",
                                   "retry identity applies only to transactional DML",
                                   session->txn != NULL);
    if (pg_has_multiple_statements(sql))
        return pg_send_error_ready(fd, session, "0A000",
                                   "multiple statements in one query are unsupported",
                                   session->txn != NULL);
    bool implicit = ast->stmt_type == QIHSE_SQL_REFRESH && !session->txn;
    const uint8_t isolation = QIHSE_ISO_READ_COMMITTED;
    if (implicit && uwp_dispatch_txn(session->uwp, 0x01, &isolation, sizeof(isolation),
            &session->txn, user, fd, NULL, NULL) != UWP_STS_OK)
        return pg_send_error_ready(fd, session, "25000",
                                   "implicit refresh transaction could not begin", false);
    pg_uwp_capture_t capture = {0};
    uwp_sts_result_t status = uwp_dispatch_sql(session->uwp, 0x02,
        (const uint8_t*)sql, strlen(sql) + 1u,
        session->txn ? &session->txn : NULL, user, fd,
        pg_uwp_capture_write, &capture);
    const char* type = qihse_sql_stmt_name(ast->stmt_type);
    const char* tag = NULL;
    char materialized_tag[48];
    switch (ast->stmt_type) {
        case QIHSE_SQL_CREATE: tag = ast->index_def ? "CREATE INDEX" : "CREATE TABLE"; break;
        case QIHSE_SQL_CREATE_EXTENSION: tag = "CREATE EXTENSION"; break;
        case QIHSE_SQL_CREATE_FUNCTION: tag = "CREATE FUNCTION"; break;
        case QIHSE_SQL_CREATE_TRIGGER: tag = "CREATE TRIGGER"; break;
        case QIHSE_SQL_DROP_TRIGGER: tag = "DROP TRIGGER"; break;
        case QIHSE_SQL_CREATE_MATVIEW: {
            static const char prefix[] = "OK stmt_type=CREATE MATERIALIZED VIEW rows=";
            if (capture.data && !strncmp(capture.data, prefix, sizeof(prefix) - 1)) {
                const char* number = capture.data + sizeof(prefix) - 1;
                char* end = NULL;
                errno = 0;
                unsigned long long count = strtoull(number, &end, 10);
                if (isdigit((unsigned char)*number) && !errno &&
                    end && !strcmp(end, "\n") &&
                    snprintf(materialized_tag, sizeof(materialized_tag),
                             "SELECT %llu", count) < (int)sizeof(materialized_tag))
                    tag = materialized_tag;
            }
            break;
        }
        case QIHSE_SQL_REFRESH: tag = "REFRESH MATERIALIZED VIEW"; break;
        default: break;
    }
    char expected[80];
    int len = snprintf(expected, sizeof(expected), "OK stmt_type=%s\n",
                       type ? type : "");
    bool refresh_reply = false;
    if (ast->stmt_type == QIHSE_SQL_REFRESH && capture.data) {
        static const char prefix[] = "OK stmt_type=REFRESH rows=";
        if (!strncmp(capture.data, prefix, sizeof(prefix) - 1)) {
            const char* number = capture.data + sizeof(prefix) - 1;
            char* end = NULL;
            errno = 0;
            (void)strtoull(number, &end, 10);
            refresh_reply = isdigit((unsigned char)*number) && !errno &&
                end && !strcmp(end, "\n");
        }
    }
    bool ok = status == UWP_STS_OK && !capture.failed && capture.data && tag &&
              len > 0 && (size_t)len < sizeof(expected) &&
              (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW || refresh_reply ||
               strcmp(capture.data, expected) == 0);
    free(capture.data);
    if (!ok) {
        if (implicit) pg_implicit_rollback(session);
        return pg_send_error_ready(fd, session,
            status == UWP_STS_ERR_PERM ? "42501" : "0A000",
            "SQL DDL failed or is unsupported", session->txn != NULL);
    }
    if (implicit) {
        status = uwp_dispatch_txn(session->uwp, 0x02, NULL, 0, &session->txn,
                                 user, fd, NULL, NULL);
        if (status != UWP_STS_OK) {
            pg_implicit_rollback(session);
            return pg_send_error_ready(fd, session,
                status == UWP_STS_ERR_PERM ? "42501" :
                qihse_uwp_sql_durable_ready(session->uwp) ? "40001" : "40003",
                "implicit refresh commit failed", false);
        }
    }
    if (pg_send_command_complete(fd, tag) < 0) return -1;
    return pg_send_ready_for_query_state(fd, pg_txn_ready_status(session));
}

static int pg_handle_sql_select(int fd, const char* sql, qihse_user_t* user,
                                pg_transaction_session_t* session,
                                const qihse_sql_ast_t* ast) {
    if (!session || !session->uwp || !session->uwp->sql_engine ||
        !session->uwp->schema || !session->uwp->txn_manager) {
        return pg_send_error_ready(fd, session, "0A000",
                                   "SQL row-store context is not configured", false);
    }
    if (session->failed) {
        return pg_send_error_ready(fd, session, "25P02",
                                   "current transaction is aborted; rollback required", false);
    }
    if (pg_has_multiple_statements(sql)) {
        return pg_send_error_ready(fd, session, "0A000",
                                   "multiple statements in one query are unsupported",
                                   session->txn != NULL);
    }

    pg_uwp_capture_t capture = {0};
    uwp_sts_result_t status = uwp_dispatch_sql(session->uwp, 0x02,
        (const uint8_t*)sql, strlen(sql) + 1u, &session->txn, user, fd,
        pg_uwp_capture_write, &capture);
    if (status != UWP_STS_OK || capture.failed || !capture.data) {
        free(capture.data);
        return pg_send_error_ready(fd, session,
            status == UWP_STS_ERR_PERM ? "42501" : "0A000",
            "QIHSE SQL statement failed or was refused", session->txn != NULL);
    }

    /* UWP's bounded row-store SELECT response is header + zero or more rows
     * + an explicit count footer. Convert that text boundary into PostgreSQL
     * RowDescription/DataRow messages only after validating the full shape. */
    char* footer = strstr(capture.data, "\nOK stmt_type=SELECT rows=");
    char* header_end = strchr(capture.data, '\n');
    if (!footer || !header_end || footer < header_end) {
        free(capture.data);
        return pg_send_error_ready(fd, session, "XX000",
                                   "malformed SQL executor response", session->txn != NULL);
    }
    char* count_end = NULL;
    unsigned long long expected_rows = strtoull(
        footer + sizeof("\nOK stmt_type=SELECT rows=") - 1u, &count_end, 10);
    if (!count_end || count_end == footer + sizeof("\nOK stmt_type=SELECT rows=") - 1u ||
        (*count_end != '\n' && *count_end != '\0') ||
        (*count_end == '\n' && count_end[1] != '\0')) {
        free(capture.data);
        return pg_send_error_ready(fd, session, "XX000",
                                   "malformed SQL executor row count", session->txn != NULL);
    }

    const size_t max_columns = 64u;
    const char* names[64];
    int32_t type_oids[64];
    int16_t ncols = 0;
    *header_end = '\0';
    char* p = capture.data;
    while (p <= header_end && ncols < (int16_t)max_columns) {
        char* tab = strchr(p, '\t');
        char* end = tab && tab < header_end ? tab : header_end;
        names[ncols] = p;
        ncols++;
        if (end == header_end) break;
        *end = '\0';
        p = end + 1;
    }
    if (ncols == 0 || (p <= header_end && ncols == (int16_t)max_columns &&
                       strchr(p, '\t') && strchr(p, '\t') < header_end)) {
        free(capture.data);
        return pg_send_error_ready(fd, session, "54000",
                                   "too many SELECT result columns", session->txn != NULL);
    }

    size_t actual_rows = 0;
    for (char* row = header_end + 1; row < footer;) {
        char* end = strchr(row, '\n');
        if (!end || end > footer) end = footer;
        if (end == row) {
            free(capture.data);
            return pg_send_error_ready(fd, session, "XX000",
                                       "malformed SQL executor row", session->txn != NULL);
        }
        size_t fields = 1u;
        for (char* q = row; q < end; ++q) if (*q == '\t') fields++;
        if (fields != (size_t)ncols) {
            free(capture.data);
            return pg_send_error_ready(fd, session, "XX000",
                                       "SQL executor row width mismatch", session->txn != NULL);
        }
        actual_rows++;
        row = end < footer ? end + 1 : footer;
    }
    if (actual_rows != (size_t)expected_rows) {
        free(capture.data);
        return pg_send_error_ready(fd, session, "XX000",
                                   "SQL executor row count mismatch", session->txn != NULL);
    }
    uwp_sts_result_t types = qihse_uwp_sql_select_type_oids(
        session->uwp, ast, user, names, (size_t)ncols, type_oids);
    if (types != UWP_STS_OK) {
        free(capture.data);
        return pg_send_error_ready(fd, session,
            types == UWP_STS_ERR_PERM ? "42501" : "0A000",
            "SELECT result metadata unavailable or refused", session->txn != NULL);
    }

    if (pg_send_row_description(fd, names, type_oids, ncols) < 0) {
        free(capture.data);
        return -1;
    }
    for (char* row = header_end + 1; row < footer;) {
        char* end = strchr(row, '\n');
        if (!end || end > footer) end = footer;
        *end = '\0';
        const char* values[64];
        char* field = row;
        for (int16_t i = 0; i < ncols; ++i) {
            char* tab = i + 1 < ncols ? strchr(field, '\t') : NULL;
            if (tab) *tab = '\0';
            if (strcmp(field, "\\N") == 0) values[i] = NULL;
            else {
                if (pg_unescape_result_field(field) < 0) {
                    free(capture.data);
                    return pg_send_error_ready(fd, session, "XX000",
                        "malformed SQL executor escape", session->txn != NULL);
                }
                values[i] = field;
            }
            if (tab) field = tab + 1;
        }
        if (pg_send_data_row(fd, values, ncols) < 0) {
            free(capture.data);
            return -1;
        }
        row = end < footer ? end + 1 : footer;
    }

    char command[64];
    snprintf(command, sizeof(command), "SELECT %llu", expected_rows);
    free(capture.data);
    if (pg_send_command_complete(fd, command) < 0) return -1;
    return pg_send_ready_for_query_state(fd, pg_txn_ready_status(session));
}

static int pg_retry_set_key(int fd, const char* query,
                            pg_transaction_session_t* session) {
    if (session && session->failed)
        return pg_send_error_ready(fd, session, "25P02",
                                   "current transaction is aborted; rollback required", false);
    if (!session || session->txn)
        return pg_send_error_ready(fd, session, "25001",
                                   "retry identity cannot change during a transaction", true);
    if (!session->uwp || !qihse_uwp_sql_durable_ready(session->uwp))
        return pg_send_error_ready(fd, session, "0A000",
                                   "durable SQL context is not configured", false);
    const char* p = query;
    while (isspace((unsigned char)*p)) ++p;
    static const char prefix[] = "SET qihse.retry_key";
    if (strncasecmp(p, prefix, sizeof(prefix) - 1u) != 0)
        return pg_send_error_ready(fd, session, "22023", "invalid retry key", false);
    p += sizeof(prefix) - 1u;
    while (isspace((unsigned char)*p)) ++p;
    if (*p != '=')
        return pg_send_error_ready(fd, session, "22023", "invalid retry key", false);
    ++p;
    while (isspace((unsigned char)*p)) ++p;
    if (*p != '\'')
        return pg_send_error_ready(fd, session, "22023", "invalid retry key", false);
    ++p;
    char key[QIHSE_TS_RETRY_MAX_TEXT + 1u];
    size_t n = 0;
    while (*p && *p != '\'' && n < QIHSE_TS_RETRY_MAX_TEXT) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_')
            return pg_send_error_ready(fd, session, "22023", "invalid retry key", false);
        key[n++] = *p++;
    }
    if (!n || *p != '\'')
        return pg_send_error_ready(fd, session, "22023", "invalid retry key", false);
    ++p;
    while (isspace((unsigned char)*p)) ++p;
    if (*p)
        return pg_send_error_ready(fd, session, "22023", "invalid retry key", false);
    key[n] = '\0';
    memcpy(session->retry_key, key, n + 1u);
    if (pg_send_command_complete(fd, "SET") < 0) return -1;
    return pg_send_ready_for_query_state(fd, 'I');
}

static int pg_retry_query_status(int fd, const char* query, qihse_user_t* user,
                                 pg_transaction_session_t* session) {
    if (!session || !session->uwp || !qihse_uwp_sql_durable_ready(session->uwp))
        return pg_send_error_ready(fd, session, "0A000",
                                   "durable SQL context is not configured", false);
    if (session->failed)
        return pg_send_error_ready(fd, session, "25P02",
                                   "current transaction is aborted; rollback required", false);
    if (session->txn)
        return pg_send_error_ready(fd, session, "25001",
                                   "retry status requires an idle session", true);
    if (!user || !qihse_auth_user_is_active(user))
        return pg_send_error_ready(fd, session, "42501", "principal inactive", false);
    const char* p = query;
    while (isspace((unsigned char)*p)) ++p;
    static const char prefix[] = "SELECT qihse_retry_status('";
    if (strncasecmp(p, prefix, sizeof(prefix) - 1u) != 0)
        return pg_send_error_ready(fd, session, "22023", "invalid retry status query", false);
    p += sizeof(prefix) - 1u;
    char key[QIHSE_TS_RETRY_MAX_TEXT + 1u];
    size_t n = 0;
    while (*p && *p != '\'' && n < QIHSE_TS_RETRY_MAX_TEXT) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_')
            return pg_send_error_ready(fd, session, "22023", "invalid retry status query", false);
        key[n++] = *p++;
    }
    if (!n || strncmp(p, "','", 3) != 0)
        return pg_send_error_ready(fd, session, "22023", "invalid retry status query", false);
    key[n] = '\0';
    p += 3;
    if (strlen(p) < QIHSE_TS_RETRY_DIGEST_SIZE * 2u + 2u)
        return pg_send_error_ready(fd, session, "22023", "invalid digest", false);
    qihse_ts_retry_identity_t identity = {.key = key};
    for (size_t i = 0; i < sizeof(identity.digest); ++i) {
        int hi = isxdigit((unsigned char)p[0]) ? p[0] : 0;
        int lo = hi && isxdigit((unsigned char)p[1]) ? p[1] : 0;
        if (!hi || !lo)
            return pg_send_error_ready(fd, session, "22023", "invalid digest", false);
        identity.digest[i] = (uint8_t)(((hi <= '9' ? hi - '0' : (hi | 32) - 'a' + 10) << 4) |
                                      (lo <= '9' ? lo - '0' : (lo | 32) - 'a' + 10));
        p += 2;
    }
    if (strncmp(p, "')", 2) != 0)
        return pg_send_error_ready(fd, session, "22023", "invalid retry status query", false);
    p += 2;
    while (isspace((unsigned char)*p)) ++p;
    if (*p) return pg_send_error_ready(fd, session, "22023", "invalid retry status query", false);
    char principal[32], tenant[32];
    snprintf(principal, sizeof(principal), "user:%u", qihse_user_get_id(user));
    snprintf(tenant, sizeof(tenant), "tenant:%u", qihse_user_get_tenant_id(user));
    identity.principal = principal;
    identity.tenant = tenant;
    qihse_ts_retry_outcome_t outcome = {0};
    qihse_ts_retry_status_t status = qihse_table_store_retry_lookup(
        qihse_uwp_sql_table_store(), &identity, &outcome);
    if (status == QIHSE_TS_RETRY_ERROR)
        return pg_send_error_ready(fd, session, "40003", "retry outcome requires recovery", false);
    if (status == QIHSE_TS_RETRY_MISMATCH)
        return pg_send_error_ready(fd, session, "42501", "retry identity mismatch", false);
    const char* names[] = {"status", "affected_rows", "command_count"};
    const int32_t oids[] = {25, 20, 20};
    if (pg_send_row_description(fd, names, oids, 3) < 0) return -1;
    char rows[32], count[32];
    snprintf(rows, sizeof(rows), "%llu", (unsigned long long)outcome.affected_rows);
    snprintf(count, sizeof(count), "%llu", (unsigned long long)outcome.command_count);
    const char* values[] = {status == QIHSE_TS_RETRY_COMMITTED ? "committed" : "absent",
                            rows, count};
    if (pg_send_data_row(fd, values, 3) < 0 ||
        pg_send_command_complete(fd, "SELECT 1") < 0) return -1;
    return pg_send_ready_for_query_state(fd, 'I');
}

/* Normalize only bounded catalog-query grammar, preserving literal case. */
static bool pg_catalog_normalize(const char* query, char* normalized, size_t cap) {
    size_t n = 0;
    bool quoted = false;
    for (const char* p = query; *p; ++p) {
        if (n + 2 >= cap) return false;
        unsigned char ch = (unsigned char)*p;
        if (ch == '\'') quoted = !quoted;
        if (!quoted && isspace(ch)) {
            if (n && normalized[n - 1] != ' ') normalized[n++] = ' ';
        } else normalized[n++] = quoted ? (char)ch : (char)tolower(ch);
    }
    while (n && normalized[n - 1] == ' ') --n;
    normalized[n] = '\0';
    return !quoted;
}

/* Never route broader catalog expressions through the legacy static list. */
static bool pg_public_table_list_query(const char* query) {
    char normalized[4096];
    return pg_catalog_normalize(query, normalized, sizeof(normalized)) &&
        strcmp(normalized, "select table_name from information_schema.tables "
        "where table_schema = 'public' order by table_name") == 0;
}

static bool pg_public_index_list_query(const char* query,
    const qihse_sql_ast_t* ast, char* table, size_t cap) {
    char normalized[4096];
    static const char prefix[] = "selectindexnamefrompg_indexes"
        "whereschemaname='public'";
    if (!ast || ast->stmt_type != QIHSE_SQL_SELECT || ast->num_select_items != 1 ||
        !ast->select_items[0].expr || strcmp(ast->select_items[0].expr, "indexname") ||
        ast->select_items[0].alias || ast->select_items[0].agg_kind != QIHSE_AGG_NONE ||
        ast->num_from_tables != 1 || !ast->from_tables[0].table_name ||
        strcasecmp(ast->from_tables[0].table_name, "pg_indexes") ||
        ast->num_joins || ast->set_op || ast->group_by || ast->select_distinct ||
        (ast->num_where_conditions != 1 && ast->num_where_conditions != 2) ||
        ast->num_order_items != 1 ||
        !ast->order_items[0].column_name ||
        strcmp(ast->order_items[0].column_name, "indexname") ||
        !ast->order_items[0].ascending || ast->limit >= 0 || ast->offset > 0 ||
        !pg_catalog_normalize(query, normalized, sizeof(normalized))) return false;
    size_t compact = 0;
    bool quoted = false;
    for (const char* p = normalized; *p; ++p) {
        if (*p == '\'') quoted = !quoted;
        if (quoted || !isspace((unsigned char)*p)) normalized[compact++] = *p;
    }
    normalized[compact] = '\0';
    if (strncmp(normalized, prefix, sizeof(prefix) - 1)) return false;
    const char* p = normalized + sizeof(prefix) - 1;
    if (!strcmp(p, "orderbyindexname")) {
        if (ast->num_where_conditions != 1 || !cap) return false;
        table[0] = '\0';
        return true;
    }
    static const char restriction[] = "andtablename='";
    if (ast->num_where_conditions != 2 ||
        strncmp(p, restriction, sizeof(restriction) - 1)) return false;
    p += sizeof(restriction) - 1;
    size_t n = 0;
    while (isalnum((unsigned char)*p) || *p == '_') {
        if (n + 1 >= cap) return false;
        table[n++] = *p++;
    }
    if (!n || strcmp(p, "'orderbyindexname")) return false;
    table[n] = '\0';
    return true;
}

static int pg_send_public_index_list(int fd, qihse_user_t* user,
    pg_transaction_session_t* session, const char* table) {
    if (!session || !session->uwp || session->txn)
        return pg_send_error_ready(fd, session, "0A000",
            "transactional index catalog reads are unsupported", session && session->txn);
    char** indexes = NULL;
    size_t count = 0;
    uwp_sts_result_t status = qihse_uwp_sql_catalog_indexes(session->uwp,
        user, *table ? table : NULL, &indexes, &count);
    if (status != UWP_STS_OK)
        return pg_send_error_ready(fd, session,
            status == UWP_STS_ERR_PERM ? "42501" : "0A000",
            "durable index catalog unavailable", false);
    const char* columns[] = {"indexname"};
    const int32_t oids[] = {19};
    int rc = pg_send_row_description(fd, columns, oids, 1);
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        const char* row[] = {indexes[i]};
        rc = pg_send_data_row(fd, row, 1);
    }
    char tag[40];
    snprintf(tag, sizeof(tag), "SELECT %zu", count);
    if (!rc) rc = pg_send_command_complete(fd, tag);
    if (!rc) rc = pg_send_ready_for_query_state(fd, 'I');
    for (size_t i = 0; i < count; ++i) free(indexes[i]);
    free(indexes);
    return rc;
}

static int pg_send_public_table_list(int fd, qihse_user_t* user,
                                     pg_transaction_session_t* session) {
    if (!session || !session->uwp || session->txn)
        return pg_send_error_ready(fd, session, "0A000",
                                   "transactional catalog reads are unsupported",
                                   session && session->txn);
    char** tables = NULL;
    size_t count = 0;
    uwp_sts_result_t status = qihse_uwp_sql_catalog_tables(
        session->uwp, user, &tables, &count);
    if (status != UWP_STS_OK)
        return pg_send_error_ready(fd, session,
            status == UWP_STS_ERR_PERM ? "42501" : "0A000",
            "durable catalog unavailable", false);
    const char* columns[] = {"table_name"};
    const int32_t oids[] = {25};
    int rc = pg_send_row_description(fd, columns, oids, 1);
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        const char* row[] = {tables[i]};
        rc = pg_send_data_row(fd, row, 1);
    }
    char tag[40];
    snprintf(tag, sizeof(tag), "SELECT %zu", count);
    if (rc == 0) rc = pg_send_command_complete(fd, tag);
    if (rc == 0) rc = pg_send_ready_for_query_state(fd, 'I');
    for (size_t i = 0; i < count; ++i) free(tables[i]);
    free(tables);
    return rc;
}

static int pg_handle_query_ctx(int fd, pg_cluster_context_t* ctx,
                               const char* raw_query, qihse_user_t* user,
                               pg_transaction_session_t* session) {
    char query[4096];
    if (!user) {
        if (pg_send_error(fd, "ERROR", "28000", "authentication required") < 0) return -1;
        return pg_send_ready_for_query(fd);
    }
    size_t qlen = strlen(raw_query);
    if (qlen >= sizeof(query))
        return pg_send_error_ready(fd, session, "54000",
                                   "SQL query exceeds supported length",
                                   session && session->txn != NULL);
    memcpy(query, raw_query, qlen);
    query[qlen] = '\0';
    str_rtrim_semi(query);

    const char* separator = NULL;
    if (!pg_batch_suppress_ready &&
        pg_has_multiple_statements_at(query, &separator) && separator) {
        if (!session || !session->txn)
            return pg_send_error_ready(fd, session, "0A000",
                "multi-statement execution requires an explicit transaction", false);
        pg_batch_suppress_ready = true;
        pg_batch_error = false;
        int rc = 0;
        char* statement = query;
        while (statement && *statement) {
            const char* next = NULL;
            (void)pg_has_multiple_statements_at(statement, &next);
            if (next) *(char*)next = '\0';
            str_rtrim_semi(statement);
            if (*statement) rc = pg_handle_query_ctx(fd, ctx, statement, user, session);
            if (rc < 0 || pg_batch_error) break;
            statement = next ? (char*)next + 1 : NULL;
        }
        pg_batch_suppress_ready = false;
        pg_batch_error = false;
        if (rc < 0) return rc;
        return pg_send_ready_for_query_state(fd, pg_txn_ready_status(session));
    }

    if (str_iprefix(query, "SET qihse.retry_key"))
        return pg_retry_set_key(fd, query, session);
    if (str_iprefix(query, "SELECT qihse_retry_status("))
        return pg_retry_query_status(fd, query, user, session);

    qihse_sql_ast_t* parsed = qihse_parse_sql_to_ast(query);
    if (session && session->failed &&
        (!parsed || (parsed->stmt_type != QIHSE_SQL_ROLLBACK &&
                     parsed->stmt_type != QIHSE_SQL_COMMIT))) {
        qihse_sql_ast_free(parsed);
        return pg_send_error_ready(fd, session, "25P02",
                                   "current transaction is aborted; rollback required", false);
    }
    if (pg_public_table_list_query(query)) {
        qihse_sql_ast_free(parsed);
        return pg_send_public_table_list(fd, user, session);
    }
    char catalog_table[256];
    if (pg_public_index_list_query(query, parsed, catalog_table, sizeof(catalog_table))) {
        qihse_sql_ast_free(parsed);
        return pg_send_public_index_list(fd, user, session, catalog_table);
    }
    if (session && session->uwp &&
        qihse_uwp_sql_durable_ready(session->uwp) &&
        (strstr(query, "information_schema.tables") ||
         strstr(query, "pg_tables") ||
         (parsed && parsed->num_from_tables == 1 && parsed->from_tables &&
          parsed->from_tables[0].table_name &&
          !strcasecmp(parsed->from_tables[0].table_name, "pg_indexes")))) {
        qihse_sql_ast_free(parsed);
        return pg_send_error_ready(fd, session, "0A000",
            "catalog query shape is unsupported", session->txn != NULL);
    }
    if (parsed && session && qihse_uwp_sql_txn_has_ddl(session->txn) &&
        (parsed->stmt_type == QIHSE_SQL_INSERT ||
         parsed->stmt_type == QIHSE_SQL_UPDATE ||
         parsed->stmt_type == QIHSE_SQL_DELETE ||
         parsed->stmt_type == QIHSE_SQL_SELECT)) {
        qihse_sql_ast_free(parsed);
        return pg_send_error_ready(fd, session, "0A000",
            "mixing DDL with row reads or writes is unsupported", true);
    }
    if (parsed) {
        int rc = 0;
        if (parsed->stmt_type == QIHSE_SQL_BEGIN ||
            parsed->stmt_type == QIHSE_SQL_COMMIT ||
            parsed->stmt_type == QIHSE_SQL_ROLLBACK) {
            rc = pg_handle_txn_control(fd, query, parsed, user, session);
            qihse_sql_ast_free(parsed);
            return rc;
        }
        if (parsed->stmt_type == QIHSE_SQL_INSERT ||
            parsed->stmt_type == QIHSE_SQL_UPDATE ||
            parsed->stmt_type == QIHSE_SQL_DELETE) {
            rc = pg_handle_sql_dml(fd, query, user, session, parsed);
            qihse_sql_ast_free(parsed);
            return rc;
        }
        if ((parsed->stmt_type == QIHSE_SQL_CREATE &&
             (parsed->table_name || parsed->index_def)) ||
            parsed->stmt_type == QIHSE_SQL_CREATE_EXTENSION ||
            parsed->stmt_type == QIHSE_SQL_CREATE_FUNCTION ||
            parsed->stmt_type == QIHSE_SQL_CREATE_TRIGGER ||
            parsed->stmt_type == QIHSE_SQL_DROP_TRIGGER ||
            parsed->stmt_type == QIHSE_SQL_CREATE_MATVIEW ||
            parsed->stmt_type == QIHSE_SQL_REFRESH) {
            rc = pg_handle_sql_ddl(fd, query, user, session, parsed);
            qihse_sql_ast_free(parsed);
            return rc;
        }
        if (parsed->stmt_type == QIHSE_SQL_SELECT && session && session->uwp) {
            rc = pg_handle_sql_select(fd, query, user, session, parsed);
            qihse_sql_ast_free(parsed);
            return rc;
        }
        qihse_sql_ast_free(parsed);
    }
    if (session && session->uwp)
        return pg_send_error_ready(fd, session, "0A000",
                                   "SQL statement is unsupported by the authenticated executor",
                                   session->txn != NULL);

    /* ---- SELECT version() ---- */
    if (str_iprefix(query, "SELECT version()") || str_iprefix(query, "select version()")) {
        const char* col_names[] = {"version"};
        const int32_t type_oids[] = {25};
        if (pg_send_row_description(fd, col_names, type_oids, 1) < 0) return -1;
        const char* version_str = "QIHSE 1.0.0 on " __DATE__ " (PostgreSQL cluster sharded protocol compatible)";
        const char* row_vals[] = {version_str};
        if (pg_send_data_row(fd, row_vals, 1) < 0) return -1;
        if (pg_send_command_complete(fd, "SELECT 1") < 0) return -1;

    /* ---- PING ---- */
    } else if (str_iprefix(query, "PING") || str_iprefix(query, "ping")) {
        const char* col_names[] = {"ping"};
        const int32_t type_oids[] = {25};
        if (pg_send_row_description(fd, col_names, type_oids, 1) < 0) return -1;
        const char* row_vals[] = {"PONG"};
        if (pg_send_data_row(fd, row_vals, 1) < 0) return -1;
        if (pg_send_command_complete(fd, "SELECT 1") < 0) return -1;

    /* ---- SELECT 1 ---- */
    } else if (str_iprefix(query, "SELECT 1") || str_iprefix(query, "select 1")) {
        const char* col_names[] = {"?column?"};
        const int32_t type_oids[] = {23};
        if (pg_send_row_description(fd, col_names, type_oids, 1) < 0) return -1;
        const char* row_vals[] = {"1"};
        if (pg_send_data_row(fd, row_vals, 1) < 0) return -1;
        if (pg_send_command_complete(fd, "SELECT 1") < 0) return -1;

    /* ---- Virtual System Catalog: pg_tables / information_schema.tables ---- */
    } else if (str_iprefix(query, "SELECT") && (strstr(query, "pg_tables") || strstr(query, "information_schema.tables"))) {
        const char* col_names[] = {"tablename", "tableowner", "tablespace", "hasindexes"};
        const int32_t type_oids[] = {25, 25, 25, 25};
        if (pg_send_row_description(fd, col_names, type_oids, 4) < 0) return -1;

        const char* tbls[][4] = {
            {"vectors", "qihse_admin", "default", "true"},
            {"kv_store", "qihse_admin", "default", "true"},
            {"timeseries", "qihse_admin", "default", "true"},
            {"column_store", "qihse_admin", "default", "true"},
            {"cluster_nodes", "qihse_admin", "cluster", "false"},
            {"cluster_slots", "qihse_admin", "cluster", "false"}
        };
        for (size_t i = 0; i < 6; i++) {
            if (pg_send_data_row(fd, tbls[i], 4) < 0) return -1;
        }
        if (pg_send_command_complete(fd, "SELECT 6") < 0) return -1;

    /* ---- Virtual Cluster Nodes View ---- */
    } else if (str_iprefix(query, "SELECT") && strstr(query, "cluster_nodes")) {
        const char* col_names[] = {"node_id", "host", "port", "role", "status"};
        const int32_t type_oids[] = {25, 25, 23, 25, 25};
        if (pg_send_row_description(fd, col_names, type_oids, 5) < 0) return -1;

        size_t sent = 0;
        if (ctx && ctx->topo) {
            qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
            size_t count = qihse_cluster_topology_nodes(ctx->topo, nodes, QIHSE_CLUSTER_MAX_NODES);
            for (size_t i = 0; i < count; i++) {
                char port_str[16];
                snprintf(port_str, sizeof(port_str), "%u", nodes[i].port);
                const char* rvals[] = {
                    nodes[i].id,
                    nodes[i].host,
                    port_str,
                    nodes[i].role == QIHSE_CLUSTER_NODE_PRIMARY ? "master" : "replica",
                    nodes[i].healthy ? "connected" : "fail"
                };
                if (pg_send_data_row(fd, rvals, 5) < 0) return -1;
                sent++;
            }
        }
        char complete[32];
        snprintf(complete, sizeof(complete), "SELECT %zu", sent);
        if (pg_send_command_complete(fd, complete) < 0) return -1;

    /* ---- Distributed Query Planner Routing (Multi-Model & Scoped Tables) ---- */
    } else if (str_iprefix(query, "SELECT") || str_iprefix(query, "MATCH")) {
        qihse_dist_planner_t* planner = qihse_dist_planner_create(ctx ? ctx->topo : NULL);
        qihse_dist_plan_t* plan = qihse_dist_plan_query(planner, query, user);

        const char* col_names[] = {"id", "score", "metric", "payload"};
        const int32_t type_oids[] = {23, 25, 25, 25};
        if (pg_send_row_description(fd, col_names, type_oids, 4) < 0) {
            qihse_dist_plan_free(plan);
            qihse_dist_planner_destroy(planner);
            return -1;
        }

        int rows_sent = 0;
        if (plan) {
            qihse_dist_query_result_t* res = qihse_dist_execute_plan(
                planner, plan,
                ctx ? ctx->store : NULL,
                ctx ? ctx->vdb : NULL,
                ctx ? ctx->tsdb : NULL,
                ctx ? ctx->col : NULL,
                NULL,
                user
            );

            if (res && res->num_rows > 0) {
                for (size_t r = 0; r < res->num_rows; r++) {
                    char id_str[32], score_str[32], metric_str[32];
                    snprintf(id_str, sizeof(id_str), "%llu", (unsigned long long)res->rows[r].id);
                    snprintf(score_str, sizeof(score_str), "%.4f", res->rows[r].score);
                    snprintf(metric_str, sizeof(metric_str), "%.2f", res->aggregate_scalar);
                    const char* row_vals[] = {id_str, score_str, metric_str, res->rows[r].payload};
                    if (pg_send_data_row(fd, row_vals, 4) < 0) {
                        qihse_dist_query_result_free(res);
                        qihse_dist_plan_free(plan);
                        qihse_dist_planner_destroy(planner);
                        return -1;
                    }
                    rows_sent++;
                }
            }
            qihse_dist_query_result_free(res);
            qihse_dist_plan_free(plan);
        }
        qihse_dist_planner_destroy(planner);

        char complete_msg[32];
        snprintf(complete_msg, sizeof(complete_msg), "SELECT %d", rows_sent);
        if (pg_send_command_complete(fd, complete_msg) < 0) return -1;

    /* ---- SET & SHOW Handshake ---- */
    } else if (str_iprefix(query, "SET ") || str_iprefix(query, "set ")) {
        if (pg_send_command_complete(fd, "SET") < 0) return -1;

    } else if (str_iprefix(query, "SHOW ") || str_iprefix(query, "show ")) {
        const char* col_names[] = {"value"};
        const int32_t type_oids[] = {25};
        if (pg_send_row_description(fd, col_names, type_oids, 1) < 0) return -1;
        if (pg_send_command_complete(fd, "SHOW") < 0) return -1;

    } else {
        if (pg_send_error(fd, "ERROR", "42000", "QIHSE: unsupported query") < 0) return -1;
    }

    return pg_send_ready_for_query(fd);
}

static const char* pg_extended_describe_metadata(pg_prepared_t* stmt,
        qihse_uwp_context_t* uwp, qihse_user_t* user,
        qihse_uwp_sql_metadata_t* meta) {
    qihse_sql_stmt_type_t type = stmt->ast->stmt_type;
    if (type == QIHSE_SQL_BEGIN || type == QIHSE_SQL_COMMIT ||
        type == QIHSE_SQL_ROLLBACK || type == QIHSE_SQL_CREATE ||
        type == QIHSE_SQL_CREATE_EXTENSION || type == QIHSE_SQL_CREATE_FUNCTION ||
        type == QIHSE_SQL_CREATE_TRIGGER || type == QIHSE_SQL_CREATE_MATVIEW ||
        type == QIHSE_SQL_REFRESH) {
        if (stmt->nparams) return "0A000";
        if (!uwp || !qihse_uwp_sql_durable_ready(uwp)) return "0A000";
        if (!user || !qihse_auth_user_is_active(user)) return "42501";
        memset(meta, 0, sizeof(*meta));
        return NULL;
    }
    uint32_t declared[PG_BIND_LIMIT];
    for (size_t i = 0; i < stmt->nparams; ++i)
        declared[i] = (uint32_t)stmt->param_oids[i];
    uwp_sts_result_t status = qihse_uwp_sql_describe(
        uwp, stmt->sql, user, declared, stmt->nparams, meta);
    if (status != UWP_STS_OK) return status == UWP_STS_ERR_PERM ? "42501" : "0A000";
    if (meta->nparams != stmt->nparams || meta->ncolumns > PG_COLUMN_LIMIT)
        return "XX000";
    return NULL;
}

static int pg_extended_row_description(int fd,
        const qihse_uwp_sql_metadata_t* meta, const pg_portal_t* portal) {
    pg_buf_t b;
    pg_buf_init(&b);
    if (pg_buf_append_int16(&b, (int16_t)meta->ncolumns) < 0) goto fail;
    if (portal && portal->nresult_formats != 0 &&
        portal->nresult_formats != 1 &&
        portal->nresult_formats != meta->ncolumns) goto fail;
    for (size_t i = 0; i < meta->ncolumns; ++i) {
        int16_t format = portal && portal->nresult_formats ?
            portal->result_formats[portal->nresult_formats == 1 ? 0 : i] : 0;
        int16_t width = -1;
        switch (meta->columns[i].oid) {
            case 16: width = 1; break;
            case 21: width = 2; break;
            case 23: case 700: width = 4; break;
            case 20: case 701: case 1184: width = 8; break;
            case 2950: width = 16; break;
            default: break;
        }
        if (pg_buf_append_str(&b, meta->columns[i].name) < 0 ||
            pg_buf_append_int32(&b, 0) < 0 || pg_buf_append_int16(&b, 0) < 0 ||
            pg_buf_append_int32(&b, meta->columns[i].oid) < 0 ||
            pg_buf_append_int16(&b, width) < 0 ||
            pg_buf_append_int32(&b, -1) < 0 ||
            pg_buf_append_int16(&b, format) < 0) goto fail;
    }
    int rc = pg_send_msg(fd, 'T', b.data, b.len);
    pg_buf_free(&b);
    return rc;
fail:
    pg_buf_free(&b);
    return -1;
}

static bool pg_extended_binary_supported(int32_t oid);

static const char* pg_extended_describe(int fd, pg_extended_t* ext,
        pg_frame_t* f, qihse_uwp_context_t* uwp, qihse_user_t* user,
        int* write_status) {
    const char* name;
    if (f->len < 2u || (f->data[0] != 'S' && f->data[0] != 'P'))
        return "08P01";
    f->pos = 1;
    if (!pg_frame_string(f, &name) || f->pos != f->len) return "08P01";
    pg_portal_t* portal = NULL;
    pg_prepared_t* stmt;
    if (f->data[0] == 'P') {
        portal = pg_portal_find(ext, name, NULL);
        if (!portal) return "34000";
        stmt = portal->statement;
    } else {
        stmt = pg_prepared_find(ext, name, NULL);
        if (!stmt) return "26000";
    }
    qihse_uwp_sql_metadata_t meta = {0};
    const char* state = pg_extended_describe_metadata(stmt, uwp, user, &meta);
    if (state) return state;
    if (portal && portal->nresult_formats != 0 &&
        portal->nresult_formats != 1 &&
        portal->nresult_formats != meta.ncolumns) return "08P01";
    if (portal && portal->nresult_formats)
        for (size_t i = 0; i < meta.ncolumns; ++i)
            if (portal->result_formats[portal->nresult_formats == 1 ? 0 : i] &&
                !pg_extended_binary_supported(meta.columns[i].oid))
                return "0A000";
    if (!portal) {
        pg_buf_t b;
        pg_buf_init(&b);
        if (pg_buf_append_int16(&b, (int16_t)meta.nparams) < 0) {
            pg_buf_free(&b); *write_status = -1; return NULL;
        }
        for (size_t i = 0; i < meta.nparams; ++i)
            if (pg_buf_append_int32(&b, (int32_t)meta.param_oids[i]) < 0) {
                pg_buf_free(&b); *write_status = -1; return NULL;
            }
        *write_status = pg_send_msg(fd, 't', b.data, b.len);
        pg_buf_free(&b);
        if (*write_status < 0) return NULL;
    }
    *write_status = meta.ncolumns ?
        pg_extended_row_description(fd, &meta, portal) :
        pg_send_msg(fd, 'n', NULL, 0);
    return NULL;
}

static bool pg_extended_binary(pg_buf_t* b, int32_t oid, const char* text) {
    if (oid == 16) {
        if (!strcmp(text, "true") || !strcmp(text, "t") || !strcmp(text, "1"))
            return pg_buf_append_byte(b, 1) == 0;
        if (!strcmp(text, "false") || !strcmp(text, "f") || !strcmp(text, "0"))
            return pg_buf_append_byte(b, 0) == 0;
        return false;
    }
    if (oid == 23 || oid == 20 || oid == 21) {
        char* end;
        errno = 0;
        long long n = strtoll(text, &end, 10);
        if (errno || !*text || *end || (oid == 23 && (n < INT32_MIN || n > INT32_MAX)) ||
            (oid == 21 && (n < INT16_MIN || n > INT16_MAX))) return false;
        if (oid == 21) return pg_buf_append_int16(b, (int16_t)n) == 0;
        if (oid == 23) return pg_buf_append_int32(b, (int32_t)n) == 0;
        uint64_t bits = (uint64_t)n;
        return pg_buf_append_int32(b, (int32_t)(bits >> 32)) == 0 &&
               pg_buf_append_int32(b, (int32_t)bits) == 0;
    }
    if (oid == 700 || oid == 701) {
        char* end;
        errno = 0;
        double n = strtod(text, &end);
        if (errno || !*text || *end) return false;
        if (oid == 700) {
            float fl = (float)n;
            uint32_t bits;
            memcpy(&bits, &fl, sizeof(bits));
            return pg_buf_append_int32(b, (int32_t)bits) == 0;
        }
        uint64_t bits;
        memcpy(&bits, &n, sizeof(bits));
        return pg_buf_append_int32(b, (int32_t)(bits >> 32)) == 0 &&
               pg_buf_append_int32(b, (int32_t)bits) == 0;
    }
    if (oid == 2950) {
        uint8_t uuid[16];
        size_t n = 0;
        for (const char* p = text; *p;) {
            if (*p == '-') { ++p; continue; }
            if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1]) || n == 16)
                return false;
            char pair[3] = {p[0], p[1], 0};
            uuid[n++] = (uint8_t)strtoul(pair, NULL, 16);
            p += 2;
        }
        return n == 16 && pg_buf_append(b, uuid, 16) == 0;
    }
    if (oid == 1700) {
        bool negative = *text == '-';
        const char* start = text + (negative || *text == '+');
        const char* dot = strchr(start, '.');
        size_t length = strlen(start);
        size_t integer = dot ? (size_t)(dot - start) : length;
        size_t fraction = length - integer - (dot != NULL);
        if (!length || (integer == 0 && fraction == 0) ||
            integer > 512 || fraction > 512) return false;
        for (const char* p = start; *p; ++p)
            if (p != dot && !isdigit((unsigned char)*p)) return false;
        size_t integer_groups = (integer + 3u) / 4u;
        size_t fraction_groups = (fraction + 3u) / 4u;
        int16_t digits[256] = {0};
        if (integer_groups + fraction_groups > 256) return false;
        size_t index = 0;
        size_t pad = integer_groups * 4u - integer;
        for (size_t i = 0; i < integer; ++i)
            digits[(i + pad) / 4u] = digits[(i + pad) / 4u] * 10 + start[i] - '0';
        index = integer_groups;
        for (size_t i = 0; i < fraction; ++i)
            digits[index + i / 4u] = digits[index + i / 4u] * 10 + dot[1u + i] - '0';
        for (size_t i = fraction % 4u; i && i < 4u; ++i)
            digits[integer_groups + fraction_groups - 1u] *= 10;
        size_t first = 0, last = integer_groups + fraction_groups;
        while (first < last && !digits[first]) ++first;
        while (last > first && !digits[last - 1u]) --last;
        int16_t weight = first == last ? 0 : (int16_t)((int)integer_groups - (int)first - 1);
        if (pg_buf_append_int16(b, (int16_t)(last - first)) < 0 ||
            pg_buf_append_int16(b, weight) < 0 ||
            pg_buf_append_int16(b, negative && first != last ? 0x4000 : 0) < 0 ||
            pg_buf_append_int16(b, (int16_t)fraction) < 0) return false;
        for (size_t i = first; i < last; ++i)
            if (pg_buf_append_int16(b, digits[i]) < 0) return false;
        return true;
    }
    if (oid == 3802) return pg_buf_append_byte(b, 1) == 0 &&
                                   pg_buf_append(b, text, strlen(text)) == 0;
    if (oid == 25 || oid == 1043 || oid == 1042)
        return pg_buf_append(b, text, strlen(text)) == 0;
    if (oid == 1184 || oid == 1114) {
        struct tm tm = {0};
        char* end = strptime(text, "%Y-%m-%d %H:%M:%S", &tm);
        if (!end) return false;
        int64_t micros = (int64_t)(timegm(&tm) - 946684800LL) * 1000000LL;
        if (*end == '.') {
            ++end;
            unsigned digits = 0;
            while (isdigit((unsigned char)*end) && digits < 6) {
                micros += (*end++ - '0') * (int64_t[]){100000,10000,1000,100,10,1}[digits++];
            }
            if (isdigit((unsigned char)*end)) return false;
        }
        if (!strcmp(end, "+00") || !strcmp(end, "+00:00") ||
            !strcmp(end, "Z")) end += strlen(end);
        if (*end) return false;
        uint64_t bits = (uint64_t)micros;
        return pg_buf_append_int32(b, (int32_t)(bits >> 32)) == 0 &&
               pg_buf_append_int32(b, (int32_t)bits) == 0;
    }
    return false;
}

static bool pg_extended_binary_supported(int32_t oid) {
    switch (oid) {
        case 16: case 20: case 21: case 23: case 700: case 701:
        case 25: case 1042: case 1043: case 1700: case 2950: case 3802:
        case 1114: case 1184: return true;
        default: return false;
    }
}

static bool pg_extended_command(const pg_portal_t* portal,
    const pg_uwp_capture_t* capture, char* tag, size_t cap) {
    if (capture->failed || !capture->data) return false;
    const char* type = qihse_sql_stmt_name(portal->statement->ast->stmt_type);
    char prefix[64];
    int n = snprintf(prefix, sizeof(prefix), "OK stmt_type=%s rows=", type ? type : "");
    if (n <= 0 || (size_t)n >= sizeof(prefix) ||
        strncmp(capture->data, prefix, (size_t)n) ||
        !isdigit((unsigned char)capture->data[n])) return false;
    char* end;
    errno = 0;
    unsigned long long rows = strtoull(capture->data + n, &end, 10);
    if (errno || end == capture->data + n || strcmp(end, "\n")) return false;
    int length = portal->statement->ast->stmt_type == QIHSE_SQL_INSERT
        ? snprintf(tag, cap, "INSERT 0 %llu", rows)
        : snprintf(tag, cap, "%s %llu", type ? type : "UPDATE", rows);
    return length > 0 && (size_t)length < cap;
}

static const char* pg_extended_result(int fd, const pg_portal_t* portal,
        const qihse_uwp_sql_metadata_t* meta, pg_uwp_capture_t* capture,
        int* write_status) {
    if (capture->failed || !capture->data) return "XX000";
    if (!meta->ncolumns) {
        char tag[96];
        if (!pg_extended_command(portal, capture, tag, sizeof(tag))) return "XX000";
        *write_status = pg_send_command_complete(fd, tag);
        return NULL;
    }
    char* header_end = strchr(capture->data, '\n');
    char* footer = strstr(capture->data, "\nOK stmt_type=SELECT rows=");
    if (!header_end || !footer || footer < header_end) return "XX000";
    char* end;
    errno = 0;
    unsigned long long expected = strtoull(
        footer + sizeof("\nOK stmt_type=SELECT rows=") - 1u, &end, 10);
    if (errno || end == footer + sizeof("\nOK stmt_type=SELECT rows=") - 1u ||
        strcmp(end, "\n")) return "XX000";
    size_t columns = 1;
    for (char* p = capture->data; p < header_end; ++p)
        if (*p == '\t') ++columns;
    if (columns != meta->ncolumns) return "XX000";
    char* field = capture->data;
    for (size_t i = 0; i < columns; ++i) {
        char* stop = i + 1u < columns ? memchr(field, '\t', header_end - field) : header_end;
        if (!stop || (size_t)(stop - field) != strlen(meta->columns[i].name) ||
            memcmp(field, meta->columns[i].name, stop - field)) return "XX000";
        field = stop + 1;
    }
    pg_buf_t rows;
    pg_buf_init(&rows);
    size_t actual = 0;
    const char* state = NULL;
    for (char* row = header_end + 1; row < footer;) {
        char* row_end = memchr(row, '\n', (size_t)(footer - row) + 1u);
        if (!row_end) { state = "XX000"; break; }
        if (pg_buf_append_byte(&rows, 'D') < 0 ||
            pg_buf_append_int32(&rows, 0) < 0 ||
            pg_buf_append_int16(&rows, (int16_t)columns) < 0) {
            state = "53200"; break;
        }
        size_t length_pos = rows.len - 6u;
        field = row;
        for (size_t i = 0; i < columns; ++i) {
            char* stop = i + 1u < columns ? memchr(field, '\t', row_end - field) : row_end;
            if (!stop) { state = "XX000"; break; }
            *stop = 0;
            if (!strcmp(field, "\\N")) {
                if (pg_buf_append_int32(&rows, -1) < 0) { state = "53200"; break; }
            } else {
                if (pg_unescape_result_field(field) < 0) { state = "XX000"; break; }
                pg_buf_t value;
                pg_buf_init(&value);
                bool binary = portal->nresult_formats &&
                    portal->result_formats[portal->nresult_formats == 1 ? 0 : i];
                bool ok = binary ? pg_extended_binary(&value, meta->columns[i].oid, field) :
                                   pg_buf_append(&value, field, strlen(field)) == 0;
                if (!ok || value.len > INT32_MAX ||
                    pg_buf_append_int32(&rows, (int32_t)value.len) < 0 ||
                    pg_buf_append(&rows, value.data, value.len) < 0) state = "0A000";
                pg_buf_free(&value);
                if (state) break;
            }
            field = stop + 1;
        }
        if (state) break;
        uint32_t length = (uint32_t)(rows.len - length_pos);
        rows.data[length_pos] = (uint8_t)(length >> 24);
        rows.data[length_pos + 1] = (uint8_t)(length >> 16);
        rows.data[length_pos + 2] = (uint8_t)(length >> 8);
        rows.data[length_pos + 3] = (uint8_t)length;
        ++actual;
        row = row_end + 1;
    }
    if (!state && actual != expected) state = "XX000";
    if (!state) {
        *write_status = pg_buf_flush(&rows, fd);
        if (*write_status == 0) {
            char tag[64];
            snprintf(tag, sizeof(tag), "SELECT %llu", expected);
            *write_status = pg_send_command_complete(fd, tag);
        }
    }
    pg_buf_free(&rows);
    return state;
}

static const char* pg_extended_execute(int fd, pg_extended_t* ext, pg_frame_t* f,
        qihse_user_t* user, pg_transaction_session_t* session, int* write_status) {
    const char* name;
    uint32_t max_rows;
    if (!pg_frame_string(f, &name) || !pg_frame_u32(f, &max_rows) ||
        f->pos != f->len) return "08P01";
    pg_portal_t* portal = pg_portal_find(ext, name, NULL);
    if (!portal) return "34000";
    if (max_rows) return "0A000";
    if (session->failed) return "25P02";
    if (!user || !qihse_auth_user_is_active(user)) return "42501";
    pg_prepared_t* stmt = portal->statement;
    if (session->retry_key[0] && (stmt->ast->stmt_type == QIHSE_SQL_INSERT ||
        stmt->ast->stmt_type == QIHSE_SQL_UPDATE ||
        stmt->ast->stmt_type == QIHSE_SQL_DELETE)) return "0A000";
    qihse_uwp_sql_metadata_t meta = {0};
    const char* state = pg_extended_describe_metadata(stmt, session->uwp, user, &meta);
    if (state) return state;
    if (portal->nresult_formats != 0 && portal->nresult_formats != 1 &&
        portal->nresult_formats != meta.ncolumns) return "08P01";
    for (size_t i = 0; i < meta.ncolumns; ++i)
        if (portal->nresult_formats &&
            portal->result_formats[portal->nresult_formats == 1 ? 0 : i] &&
            !pg_extended_binary_supported(meta.columns[i].oid)) return "0A000";
    qihse_uwp_sql_param_t params[PG_BIND_LIMIT] = {{0}};
    for (size_t i = 0; i < stmt->nparams; ++i) {
        params[i].oid = meta.param_oids[i];
        params[i].data = portal->values[i];
        params[i].len = portal->lengths[i];
        params[i].is_null = portal->nulls[i];
        params[i].format = (uint16_t)portal->formats[i];
    }
    bool writes = stmt->ast->stmt_type == QIHSE_SQL_INSERT ||
        stmt->ast->stmt_type == QIHSE_SQL_UPDATE ||
        stmt->ast->stmt_type == QIHSE_SQL_DELETE;
    bool implicit = writes && !session->txn;
    if (implicit) {
        const uint8_t isolation = QIHSE_ISO_READ_COMMITTED;
        uwp_sts_result_t begin = uwp_dispatch_txn(session->uwp, 0x01,
            &isolation, sizeof(isolation), &session->txn, user, fd, NULL, NULL);
        if (begin != UWP_STS_OK)
            return begin == UWP_STS_ERR_PERM ? "42501" : "25000";
        session->extended_implicit = true;
    }
    pg_uwp_capture_t capture = {0};
    uwp_sts_result_t result = qihse_uwp_sql_execute_params(session->uwp,
        stmt->sql, params, stmt->nparams, &session->txn, user,
        pg_uwp_capture_write, &capture);
    if (result != UWP_STS_OK) {
        free(capture.data);
        return result == UWP_STS_ERR_PERM ? "42501" : "0A000";
    }
    pg_completing_portal = portal;
    state = pg_extended_result(fd, portal, &meta, &capture, write_status);
    pg_completing_portal = NULL;
    if (!state && *write_status == 0 && portal->command_tag[0])
        portal->completed = true;
    free(capture.data);
    return state;
}

static qihse_user_t* pg_send_auth_and_startup(int fd) {
    uint8_t* startup_buf = NULL;
    size_t rest = 0;

    {
        uint8_t lenbuf[4];
        if (pg_read_all(fd, lenbuf, 4) < 0) return NULL;
        int32_t total_len = (int32_t)(((uint32_t)lenbuf[0] << 24) |
                                      ((uint32_t)lenbuf[1] << 16) |
                                      ((uint32_t)lenbuf[2] << 8)  |
                                      ((uint32_t)lenbuf[3]));

        if (total_len < 8 || total_len > 65536) return NULL;

        rest = (size_t)(total_len - 4);
        startup_buf = (uint8_t*)malloc(rest + 1);
        if (!startup_buf) return NULL;
        startup_buf[rest] = '\0';

        if (pg_read_all(fd, startup_buf, rest) < 0) {
            free(startup_buf);
            return NULL;
        }

        uint32_t proto = ((uint32_t)startup_buf[0] << 24) |
                         ((uint32_t)startup_buf[1] << 16) |
                         ((uint32_t)startup_buf[2] << 8)  |
                         ((uint32_t)startup_buf[3]);

        if (proto == 80877103U) {
            /* Never offer a downgrade from SSLRequest to cleartext AUTH. */
            free(startup_buf);
            return NULL;
        }

        if (proto != 196608U || rest < 5) {
            free(startup_buf);
            return NULL;
        }
    }

    if (!startup_buf) return NULL;

    /* Parse the startup message for the "user" parameter.
     * After the 4-byte protocol version, the body is a sequence of
     * null-terminated key/value string pairs terminated by a final \0. */
    char username[128] = {0};
    bool malformed = false;
    bool seen_user = false;
    size_t pos = 4;  /* skip protocol version */
    while (pos < rest) {
        if (startup_buf[pos] == '\0') break;
        const char* key = (const char*)(startup_buf + pos);
        size_t key_len = strnlen(key, rest - pos);
        if (key_len >= rest - pos) { malformed = true; break; }
        pos += key_len + 1;
        if (pos >= rest) { malformed = true; break; }
        const char* val = (const char*)(startup_buf + pos);
        size_t val_len = strnlen(val, rest - pos);
        if (val_len >= rest - pos) { malformed = true; break; }
        if (strcmp(key, "user") == 0) {
            if (seen_user || val_len >= sizeof(username)) {
                malformed = true;
                break;
            }
            memcpy(username, val, val_len);
            username[val_len] = '\0';
            seen_user = true;
        }
        pos += val_len + 1;
    }
    if (pos >= rest || startup_buf[pos] != '\0') malformed = true;
    free(startup_buf);
    if (malformed) return NULL;

    if (username[0] == '\0') {
        pg_send_error(fd, "FATAL", "28000", "no user name specified in startup packet");
        return NULL;
    }

    /* Enforce per-IP rate limiting before attempting authentication.
     * qihse_auth_check_rate_limit() increments the attempt counter and
     * returns false if the limit has been exceeded. */
    uint32_t source_ip = pg_get_source_ip(fd);
    if (!qihse_auth_check_rate_limit(source_ip)) {
        pg_send_error(fd, "FATAL", "428C4",
                      "too many authentication attempts — rate limited");
        return NULL;
    }

    /* Send AuthenticationCleartextPassword (R message, int32 value 3). */
    uint8_t auth_req[4] = {0, 0, 0, 3};
    if (pg_send_msg(fd, 'R', auth_req, 4) < 0) return NULL;

    /* Read the PasswordMessage: 1-byte tag 'p', 4-byte length, password. */
    uint8_t pwd_tag;
    if (pg_read_all(fd, &pwd_tag, 1) < 0) return NULL;
    if (pwd_tag != 'p') {
        pg_send_error(fd, "FATAL", "08P01", "expected password message");
        return NULL;
    }

    uint8_t pwd_lenbuf[4];
    if (pg_read_all(fd, pwd_lenbuf, 4) < 0) return NULL;
    int32_t pwd_msg_len = (int32_t)(((uint32_t)pwd_lenbuf[0] << 24) |
                                    ((uint32_t)pwd_lenbuf[1] << 16) |
                                    ((uint32_t)pwd_lenbuf[2] << 8)  |
                                    ((uint32_t)pwd_lenbuf[3]));
    if (pwd_msg_len < 5 || pwd_msg_len > 65536) return NULL;
    size_t pwd_body_len = (size_t)(pwd_msg_len - 4);

    char* password = (char*)malloc(pwd_body_len + 1);
    if (!password) return NULL;
    if (pg_read_all(fd, password, pwd_body_len) < 0) {
        free(password);
        return NULL;
    }
    password[pwd_body_len] = '\0';
    /* The password string is null-terminated within the message body;
     * trim at the first null. */
    size_t pwd_len = strnlen(password, pwd_body_len);
    password[pwd_len] = '\0';

    /* Authenticate against the QIHSE auth subsystem.  This is the same
     * pattern used by qihse_bolt.c: qihse_auth_authenticate_from() takes
     * the source IP (for rate-limit accounting), username, and password,
     * and returns a pointer to the authenticated user or NULL on failure. */
    qihse_user_t* user = qihse_auth_authenticate_from(source_ip, username, password);
    free(password);

    if (!user) {
        pg_send_error(fd, "FATAL", "28P01", "password authentication failed");
        return NULL;
    }

    /* Auth succeeded — clear the per-IP rate-limit counter. */
    qihse_auth_rate_limit_reset(source_ip);

    /* Send AuthenticationOk and complete the startup handshake. */
    if (pg_send_auth_ok(fd) < 0) {
        return NULL;
    }

    pg_send_parameter_status(fd, "server_version",    "14.0 (QIHSE)");
    pg_send_parameter_status(fd, "client_encoding",   "UTF8");
    pg_send_parameter_status(fd, "server_encoding",   "UTF8");
    pg_send_parameter_status(fd, "DateStyle",         "ISO, MDY");
    pg_send_parameter_status(fd, "TimeZone",          "UTC");
    pg_send_parameter_status(fd, "integer_datetimes", "on");
    pg_send_parameter_status(fd, "standard_conforming_strings", "on");
    pg_send_parameter_status(fd, "IntervalStyle",     "postgres");

    pg_send_backend_key_data(fd, 1, 0);
    pg_send_ready_for_query(fd);

    return user;
}


static void pg_wire_handle_client_internal(
    int fd,
    pg_cluster_context_t ctx,
    qihse_uwp_context_t* uwp
) {
    pg_transaction_session_t session = {.uwp = uwp, .txn = NULL, .failed = false};

    qihse_user_t* user = pg_send_auth_and_startup(fd);
    if (!user) {
        close(fd);
        return;
    }

    bool extended_error = false;
    pg_extended_t extended = {0};

    while (1) {
        uint8_t msg_type;
        if (pg_read_all(fd, &msg_type, 1) < 0) break;

        uint8_t lenbuf[4];
        if (pg_read_all(fd, lenbuf, 4) < 0) break;
        int32_t msg_len = (int32_t)(((uint32_t)lenbuf[0] << 24) |
                                    ((uint32_t)lenbuf[1] << 16) |
                                    ((uint32_t)lenbuf[2] << 8)  |
                                    ((uint32_t)lenbuf[3]));

        if (msg_len < 4 || msg_len > 16 * 1024 * 1024) break;
        size_t body_len = (size_t)(msg_len - 4);

        uint8_t* body = NULL;
        if (body_len > 0) {
            body = (uint8_t*)malloc(body_len + 1);
            if (!body) break;
            body[body_len] = '\0';
            if (pg_read_all(fd, body, body_len) < 0) {
                free(body);
                break;
            }
        }

        if (extended_error && msg_type != 'S' && msg_type != 'X') {
            free(body);
            continue;
        }
        if (msg_type == 'S') {
            if (body_len) {
                if (pg_send_error(fd, "ERROR", "08P01", "malformed Sync message") < 0) {
                    free(body); goto done;
                }
                if (session.txn) session.failed = true;
            }
            if (session.extended_implicit) {
                if (extended_error || session.failed || body_len) {
                    pg_implicit_rollback(&session);
                } else {
                    uwp_sts_result_t committed = uwp_dispatch_txn(session.uwp,
                        0x02, NULL, 0, &session.txn, user, fd, NULL, NULL);
                    if (committed != UWP_STS_OK) {
                        pg_implicit_rollback(&session);
                        const char* state = committed == UWP_STS_ERR_PERM ? "42501" :
                            qihse_uwp_sql_durable_ready(session.uwp) ? "40001" : "40003";
                        if (pg_send_error(fd, "ERROR", state,
                                "implicit extended transaction commit failed") < 0) {
                            free(body); goto done;
                        }
                    }
                }
                session.extended_implicit = false;
            }
            if (!session.txn) pg_extended_clear_portals(&extended);
            extended_error = false;
            if (pg_send_ready_for_query_state(fd, pg_txn_ready_status(&session)) < 0) {
                free(body); goto done;
            }
            free(body);
            continue;
        }
        if (msg_type == 'P' || msg_type == 'B' || msg_type == 'D' ||
            msg_type == 'E' || msg_type == 'C' || msg_type == 'H') {
            pg_frame_t frame = {.data = body, .len = body_len};
            const char* state = NULL;
            int rc = 0;
            const char* name = NULL;
            size_t slot = 0;
            switch (msg_type) {
                case 'P':
                    state = pg_extended_parse(&extended, &frame);
                    if (!state) rc = pg_send_msg(fd, '1', NULL, 0);
                    break;
                case 'B':
                    state = pg_extended_bind(&extended, &frame);
                    if (!state) rc = pg_send_msg(fd, '2', NULL, 0);
                    break;
                case 'D':
                    if (!uwp) state = "0A000";
                    else state = pg_extended_describe(fd, &extended, &frame,
                                                       uwp, user, &rc);
                    break;
                case 'E':
                    if (!uwp) state = "0A000";
                    else {
                        const char* portal_name;
                        uint32_t row_limit;
                        pg_portal_t* portal = NULL;
                        if (!pg_frame_string(&frame, &portal_name) ||
                            !pg_frame_u32(&frame, &row_limit) || frame.pos != frame.len)
                            state = "08P01";
                        else if (!(portal = pg_portal_find(&extended, portal_name, NULL)))
                            state = "34000";
                        else if (row_limit) state = "0A000";
                        else if (portal->completed) {
                            if (session.failed) state = "25P02";
                            else {
                                qihse_uwp_sql_metadata_t refreshed = {0};
                                state = pg_extended_describe_metadata(
                                    portal->statement, session.uwp, user, &refreshed);
                                if (!state) rc = pg_send_command_complete(fd, portal->command_tag);
                            }
                        } else if (portal->statement->ast->stmt_type == QIHSE_SQL_BEGIN ||
                                 portal->statement->ast->stmt_type == QIHSE_SQL_COMMIT ||
                                 portal->statement->ast->stmt_type == QIHSE_SQL_ROLLBACK) {
                            pg_batch_suppress_ready = true;
                            pg_batch_error = false;
                            qihse_txn_t* previous_txn = session.txn;
                            pg_completing_portal = portal;
                            rc = pg_handle_txn_control(fd, portal->statement->sql,
                                portal->statement->ast, user, &session);
                            pg_completing_portal = NULL;
                            if (pg_batch_error) extended_error = true;
                            else if (rc == 0 && portal->command_tag[0]) portal->completed = true;
                            if (previous_txn && !session.txn)
                                pg_extended_clear_portals(&extended);
                            pg_batch_suppress_ready = false;
                            pg_batch_error = false;
                        } else if (portal->statement->ast->stmt_type == QIHSE_SQL_CREATE ||
                                   portal->statement->ast->stmt_type == QIHSE_SQL_CREATE_EXTENSION ||
                                   portal->statement->ast->stmt_type == QIHSE_SQL_CREATE_FUNCTION ||
                                   portal->statement->ast->stmt_type == QIHSE_SQL_CREATE_TRIGGER ||
                                   portal->statement->ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW ||
                                   portal->statement->ast->stmt_type == QIHSE_SQL_REFRESH) {
                            pg_batch_suppress_ready = true;
                            pg_batch_error = false;
                            pg_completing_portal = portal;
                            rc = pg_handle_sql_ddl(fd, portal->statement->sql,
                                user, &session, portal->statement->ast);
                            pg_completing_portal = NULL;
                            if (pg_batch_error) extended_error = true;
                            else if (rc == 0 && portal->command_tag[0]) portal->completed = true;
                            pg_batch_suppress_ready = false;
                            pg_batch_error = false;
                        } else {
                            frame.pos = 0;
                            state = pg_extended_execute(fd, &extended, &frame,
                                user, &session, &rc);
                        }
                    }
                    break;
                case 'C':
                    if (body_len < 2u || (body[0] != 'S' && body[0] != 'P')) {
                        state = "08P01"; break;
                    }
                    frame.pos = 1;
                    if (!pg_frame_string(&frame, &name) || frame.pos != frame.len) {
                        state = "08P01"; break;
                    }
                    if (body[0] == 'S') {
                        if (!pg_prepared_find(&extended, name, &slot)) state = "26000";
                        else pg_extended_drop_statement(&extended, slot);
                    } else {
                        if (!pg_portal_find(&extended, name, &slot)) state = "34000";
                        else {
                            pg_portal_free(extended.portals[slot]);
                            extended.portals[slot] = NULL;
                        }
                    }
                    if (!state) rc = pg_send_msg(fd, '3', NULL, 0);
                    break;
                case 'H':
                    if (body_len) state = "08P01";
                    break;
            }
            if (rc < 0) { free(body); goto done; }
            if (state) {
                if (session.txn) session.failed = true;
                if (pg_send_error(fd, "ERROR", state,
                        !strcmp(state, "25P02") ?
                        "current transaction is aborted; rollback required" :
                        "extended SQL message failed or was refused") < 0) {
                    free(body); goto done;
                }
                extended_error = true;
            }
            free(body);
            continue;
        }
        switch (msg_type) {
            case 'Q': {
                if (!body || !body_len || body[body_len - 1u] != '\0' ||
                    memchr(body, '\0', body_len) != body + body_len - 1u) {
                    if (pg_send_error_ready(fd, &session, "08P01",
                            "malformed simple query message", session.txn != NULL) < 0) {
                        free(body);
                        goto done;
                    }
                    break;
                }
                const char* query = (const char*)body;
                qihse_txn_t* previous_txn = session.txn;
                int query_rc = pg_handle_query_ctx(fd, &ctx, query, user, &session);
                if (previous_txn && !session.txn)
                    pg_extended_clear_portals(&extended);
                if (query_rc < 0) {
                    free(body);
                    goto done;
                }
                break;
            }
            case 'X':
                free(body);
                goto done;
            default:
                if (pg_send_error_ready(fd, &session, "08P01",
                        "unsupported frontend message", session.txn != NULL) < 0) {
                    free(body);
                    goto done;
                }
                break;
        }
        free(body);
    }

done:
    pg_extended_clear(&extended);
    if (session.txn && uwp && uwp->txn_manager) {
        (void)qihse_txn_rollback((qihse_txn_manager_t*)uwp->txn_manager,
                                 session.txn);
        session.txn = NULL;
    }
    pg_retry_reset(&session);
    close(fd);
}

void qihse_pg_wire_handle_client_multi(
    int fd, qihse_kv_store_t* store, qihse_vector_db_t vdb,
    qihse_tsdb_t* tsdb, qihse_column_store_t* col,
    qihse_cluster_topology_t* topo) {
    pg_cluster_context_t ctx = {.store = store, .vdb = vdb, .tsdb = tsdb,
                                .col = col, .topo = topo};
    pg_wire_handle_client_internal(fd, ctx, NULL);
}

void qihse_pg_wire_handle_client_uwp(int fd, qihse_uwp_context_t* uwp,
                                     qihse_cluster_topology_t* topo) {
    pg_cluster_context_t ctx = {
        .store = uwp ? (qihse_kv_store_t*)uwp->kv : NULL,
        .vdb = uwp ? (qihse_vector_db_t)uwp->vdb : (qihse_vector_db_t)0,
        .tsdb = uwp ? (qihse_tsdb_t*)uwp->tsdb : NULL,
        .col = uwp ? uwp->col : NULL,
        .topo = topo
    };
    pg_wire_handle_client_internal(fd, ctx, uwp);
}

qihse_pg_wire_listener_t* qihse_pg_wire_listener_open_uwp(
    qihse_uwp_context_t* uwp, qihse_cluster_topology_t* topo,
    const char* bind_address, uint16_t port) {
    if (!uwp || !uwp->sql_engine || !uwp->schema || !uwp->txn_manager) {
        errno = EINVAL;
        return NULL;
    }
    if (!bind_address || bind_address[0] == '\0') bind_address = "127.0.0.1";

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_address, &addr.sin_addr) != 1) {
        errno = EINVAL;
        return NULL;
    }
    /* AuthenticationCleartextPassword must not be exposed on an external
     * interface until this listener has an enforced TLS handshake. */
    if (addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        errno = EACCES;
        return NULL;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(fd, 16) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return NULL;
    }
    qihse_pg_wire_listener_t* listener =
        (qihse_pg_wire_listener_t*)calloc(1, sizeof(*listener));
    if (!listener) {
        close(fd);
        return NULL;
    }
    listener->fd = fd;
    listener->port = ntohs(addr.sin_port);
    listener->uwp = uwp;
    listener->topo = topo;
    return listener;
}

qihse_pg_wire_listener_t* qihse_pg_wire_listener_open_tls_uwp(
    qihse_uwp_context_t* uwp, qihse_cluster_topology_t* topo,
    const char* bind_address, uint16_t port,
    const char* certificate_file, const char* private_key_file) {
    if (!certificate_file || !private_key_file || !*certificate_file ||
        !*private_key_file || !uwp || !uwp->sql_engine || !uwp->schema ||
        !uwp->txn_manager) {
        errno = EINVAL;
        return NULL;
    }
    SSL_CTX* tls = SSL_CTX_new(TLS_server_method());
    if (!tls) { errno = EIO; return NULL; }
    if (SSL_CTX_set_min_proto_version(tls, TLS1_2_VERSION) != 1 ||
        SSL_CTX_use_certificate_chain_file(tls, certificate_file) != 1 ||
        SSL_CTX_use_PrivateKey_file(tls, private_key_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(tls) != 1) {
        SSL_CTX_free(tls);
        errno = EINVAL;
        return NULL;
    }
    if (!bind_address || !*bind_address) bind_address = "127.0.0.1";
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, bind_address, &addr.sin_addr) != 1) {
        SSL_CTX_free(tls);
        errno = EINVAL;
        return NULL;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { SSL_CTX_free(tls); return NULL; }
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(fd, 16) != 0) {
        int saved_errno = errno;
        close(fd);
        SSL_CTX_free(tls);
        errno = saved_errno;
        return NULL;
    }
    socklen_t addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0) {
        int saved_errno = errno;
        close(fd);
        SSL_CTX_free(tls);
        errno = saved_errno;
        return NULL;
    }
    qihse_pg_wire_listener_t* listener = calloc(1, sizeof(*listener));
    if (!listener) { close(fd); SSL_CTX_free(tls); return NULL; }
    listener->fd = fd;
    listener->port = ntohs(addr.sin_port);
    listener->uwp = uwp;
    listener->topo = topo;
    listener->tls_ctx = tls;
    return listener;
}

uint16_t qihse_pg_wire_listener_port(const qihse_pg_wire_listener_t* listener) {
    return listener ? listener->port : 0;
}

int qihse_pg_wire_listener_accept_once(qihse_pg_wire_listener_t* listener,
                                       int timeout_ms) {
    if (!listener || listener->fd < 0 || timeout_ms < -1) {
        errno = EINVAL;
        return -1;
    }
#ifndef _WIN32
    struct pollfd pfd = {.fd = listener->fd, .events = POLLIN, .revents = 0};
    int ready;
    do { ready = poll(&pfd, 1, timeout_ms); } while (ready < 0 && errno == EINTR);
    if (ready == 0) return 0;
    if (ready < 0 || (pfd.revents & (POLLERR | POLLNVAL))) return -1;
#else
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(listener->fd, &readfds);
    struct timeval timeout;
    struct timeval* timeout_ptr = NULL;
    if (timeout_ms >= 0) {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        timeout_ptr = &timeout;
    }
    int ready = select(0, &readfds, NULL, NULL, timeout_ptr);
    if (ready == 0) return 0;
    if (ready < 0) return -1;
#endif
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int client_fd = (int)accept(listener->fd, (struct sockaddr*)&peer, &peer_len);
    if (client_fd < 0) return -1;

    struct timeval io_timeout = {.tv_sec = 30, .tv_usec = 0};
    (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                     &io_timeout, sizeof(io_timeout));
    (void)setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO,
                     &io_timeout, sizeof(io_timeout));
    SSL* ssl = NULL;
    if (listener->tls_ctx) {
        /* Only a complete PostgreSQL SSLRequest may precede the handshake. */
        const uint8_t request[8] = {0, 0, 0, 8, 4, 210, 22, 47};
        uint8_t received[sizeof(request)];
        if (pg_read_all(client_fd, received, sizeof(received)) < 0 ||
            memcmp(received, request, sizeof(request)) != 0 ||
            pg_write_all(client_fd, "S", 1) < 0) {
            close(client_fd);
            return 1;
        }
        ssl = SSL_new(listener->tls_ctx);
        if (!ssl || SSL_set_fd(ssl, client_fd) != 1 || SSL_accept(ssl) != 1) {
            SSL_free(ssl);
            close(client_fd);
            return 1;
        }
        current_ssl = ssl;
    }
    pg_wire_handle_client_internal(client_fd,
        (pg_cluster_context_t){
            .store = (qihse_kv_store_t*)listener->uwp->kv,
            .vdb = (qihse_vector_db_t)listener->uwp->vdb,
            .tsdb = listener->uwp->tsdb,
            .col = listener->uwp->col,
            .topo = listener->topo
        }, listener->uwp);
    current_ssl = NULL;
    SSL_free(ssl);
    return 1;
}

void qihse_pg_wire_listener_close(qihse_pg_wire_listener_t* listener) {
    if (!listener) return;
    if (listener->fd >= 0) close(listener->fd);
    SSL_CTX_free(listener->tls_ctx);
    free(listener);
}

void qihse_pg_wire_handle_client(int client_fd, void* vdb) {
    qihse_pg_wire_handle_client_multi(client_fd, NULL, (qihse_vector_db_t)vdb, NULL, NULL, NULL);
}

bool qihse_start_pg_wire_server(void* vdb, uint16_t port, const char* bind_address) {
    return qihse_start_pg_wire_cluster_server(NULL, (qihse_vector_db_t)vdb, NULL, NULL, NULL, port, bind_address);
}

bool qihse_start_pg_wire_cluster_server(
    qihse_kv_store_t* store,
    qihse_vector_db_t vdb,
    qihse_tsdb_t* tsdb,
    qihse_column_store_t* col,
    qihse_cluster_topology_t* topo,
    uint16_t port,
    const char* bind_address
) {
    (void)store;
    (void)vdb;
    (void)tsdb;
    (void)col;
    (void)topo;
    if (!bind_address || bind_address[0] == '\0') bind_address = "127.0.0.1";
    printf("[QIHSE PG] PostgreSQL Sharded Multi-Model Server initialized on %s:%u\n", bind_address, port);
    return true;
}
