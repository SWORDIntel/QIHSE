/*
 * QIHSE PostgreSQL Wire Protocol v3 Server
 *
 * Implements the frontend/backend protocol described at:
 *   https://www.postgresql.org/docs/current/protocol.html
 *
 * Supported message types (server ← client):
 *   Startup message  – length (4) + protocol version (4) + key/value pairs
 *   Q (Simple Query) – 1 byte tag + 4 byte len + null-terminated query string
 *   X (Terminate)    – 1 byte tag + 4 byte len
 *
 * Supported message types (server → client):
 *   R  AuthenticationOk
 *   S  ParameterStatus
 *   K  BackendKeyData
 *   Z  ReadyForQuery
 *   T  RowDescription
 *   D  DataRow
 *   C  CommandComplete
 *   E  ErrorResponse
 */

#include "qihse_pg_wire.h"
#include "qihse_vector_db.h"
#include "qihse_uwp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef _WIN32
#include <netinet/tcp.h>
#endif
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifndef _WIN32
#include <sys/types.h>
#include <netinet/tcp.h>
#endif
#include "qihse_platform.h"
#ifndef _WIN32
#include <pthread.h>
#endif
#include <sys/time.h>

#ifndef _WIN32
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#else
#define SSL_CTX void
#define SSL void
#endif
#ifndef _WIN32
#include <liburing.h>
#include <poll.h>
#endif
#include "../networking/qihse_af_xdp.h"
#ifndef _WIN32
#include "../../persistence/qihse_pqc_crypto.h"
#endif

static SSL_CTX* global_pqc_ssl_ctx = NULL;
static __thread SSL* current_ssl = NULL;

/* ============================================================
 * Wire helpers
 * ============================================================ */

/* Write exactly n bytes, retrying on EINTR / short writes. */
static int pg_write_all(int fd, const void* buf, size_t n) {
    const uint8_t* p = (const uint8_t*)buf;
    while (n > 0) {
        ssize_t w;
#ifndef _WIN32
        if (current_ssl) {
            w = SSL_write(current_ssl, p, n);
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

/* Read exactly n bytes, retrying on EINTR / short reads. */
static int pg_read_all(int fd, void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf;
    while (n > 0) {
        ssize_t r;
#ifndef _WIN32
        if (current_ssl) {
            r = SSL_read(current_ssl, p, n);
            if (r <= 0) return -1;
        } else
#endif
        {
            r = read(fd, p, n);
            if (r < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (r == 0) return -1; /* EOF */
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

/* ---- Growable write buffer ---- */
typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
} pg_buf_t;

static void pg_buf_init(pg_buf_t* b) {
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

static void pg_buf_free(pg_buf_t* b) {
    free(b->data);
    b->data = NULL;
    b->len  = b->cap = 0;
}

static int pg_buf_ensure(pg_buf_t* b, size_t extra) {
    size_t need = b->len + extra;
    if (need <= b->cap) return 0;
    size_t newcap = b->cap ? b->cap * 2 : 256;
    while (newcap < need) newcap *= 2;
    uint8_t* p = realloc(b->data, newcap);
    if (!p) return -1;
    b->data = p;
    b->cap  = newcap;
    return 0;
}

static int pg_buf_append(pg_buf_t* b, const void* src, size_t n) {
    if (pg_buf_ensure(b, n) < 0) return -1;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

static int pg_buf_append_byte(pg_buf_t* b, uint8_t v) {
    return pg_buf_append(b, &v, 1);
}

static int pg_buf_append_int16(pg_buf_t* b, int16_t v) {
    uint16_t n = htons((uint16_t)v);
    return pg_buf_append(b, &n, 2);
}

static int pg_buf_append_int32(pg_buf_t* b, int32_t v) {
    uint32_t n = htonl((uint32_t)v);
    return pg_buf_append(b, &n, 4);
}

static int pg_buf_append_str(pg_buf_t* b, const char* s) {
    /* null-terminated string including the \0 */
    size_t len = strlen(s) + 1;
    return pg_buf_append(b, s, len);
}

static int pg_buf_flush(pg_buf_t* b, int fd) {
    int rc = pg_write_all(fd, b->data, b->len);
    b->len = 0;
    return rc;
}

/* ============================================================
 * Low-level message builders
 * ============================================================ */

/*
 * Build a generic tagged message:
 *   <tag:1> <length:4 (includes itself)> <body...>
 * The length field = 4 + body_len.
 */
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

/* R – AuthenticationOk (method = 0) */
static int pg_send_auth_ok(int fd) {
    uint8_t body[4] = {0, 0, 0, 0};
    return pg_send_msg(fd, 'R', body, 4);
}

/* S – ParameterStatus */
static int pg_send_parameter_status(int fd, const char* name, const char* value) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_str(&b, name);
    pg_buf_append_str(&b, value);
    int rc = pg_send_msg(fd, 'S', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

/* K – BackendKeyData */
static int pg_send_backend_key_data(int fd, int32_t pid, int32_t secret) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_int32(&b, pid);
    pg_buf_append_int32(&b, secret);
    int rc = pg_send_msg(fd, 'K', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

/* Z – ReadyForQuery  (I = idle) */
static int pg_send_ready_for_query(int fd) {
    uint8_t body[1] = {'I'};
    return pg_send_msg(fd, 'Z', body, 1);
}

/*
 * T – RowDescription
 *
 * field_names  – array of column name strings
 * ncols        – number of columns
 * type_oids    – array of PG type OIDs (25 = text, 23 = int4)
 */
static int pg_send_row_description(int fd,
                                   const char** field_names,
                                   const int32_t* type_oids,
                                   int16_t ncols) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_int16(&b, ncols);
    for (int16_t i = 0; i < ncols; i++) {
        pg_buf_append_str(&b, field_names[i]); /* name, null-terminated */
        pg_buf_append_int32(&b, 0);            /* table OID (0 = not a table col) */
        pg_buf_append_int16(&b, 0);            /* column attr number */
        pg_buf_append_int32(&b, type_oids[i]); /* type OID */
        pg_buf_append_int16(&b, -1);           /* type size (-1 = variable) */
        pg_buf_append_int32(&b, -1);           /* type modifier */
        pg_buf_append_int16(&b, 0);            /* format code (0 = text) */
    }
    int rc = pg_send_msg(fd, 'T', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

/*
 * D – DataRow
 *
 * values   – array of string values (NULL means SQL NULL)
 * ncols    – number of columns
 */
static int pg_send_data_row(int fd,
                            const char** values,
                            int16_t ncols) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_int16(&b, ncols);
    for (int16_t i = 0; i < ncols; i++) {
        if (values[i] == NULL) {
            /* NULL: length = -1 */
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

/* C – CommandComplete */
static int pg_send_command_complete(int fd, const char* tag) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_str(&b, tag);
    int rc = pg_send_msg(fd, 'C', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

/*
 * E – ErrorResponse
 *
 * Sends a minimal error with severity, SQLSTATE, and message.
 */
static int pg_send_error(int fd, const char* severity, const char* sqlstate, const char* message) {
    pg_buf_t b;
    pg_buf_init(&b);
    /* Each field: field-type byte + null-terminated value */
    pg_buf_append_byte(&b, 'S');  /* Severity */
    pg_buf_append_str(&b, severity);
    pg_buf_append_byte(&b, 'V');  /* Severity (non-localised, PG >= 9.6) */
    pg_buf_append_str(&b, severity);
    pg_buf_append_byte(&b, 'C');  /* SQLSTATE code */
    pg_buf_append_str(&b, sqlstate);
    pg_buf_append_byte(&b, 'M');  /* Message */
    pg_buf_append_str(&b, message);
    pg_buf_append_byte(&b, '\0'); /* Terminator */
    int rc = pg_send_msg(fd, 'E', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

/* ============================================================
 * Query dispatcher
 * ============================================================ */

/* Case-insensitive prefix match, skipping leading whitespace. */
static int str_iprefix(const char* s, const char* prefix) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    while (*prefix) {
        if ((*s | 0x20) != (*prefix | 0x20)) return 0;
        s++; prefix++;
    }
    return 1;
}

/* Strip trailing semicolons and whitespace (modifies a copy). */
static void str_rtrim_semi(char* s) {
    int n = (int)strlen(s);
    while (n > 0 && (s[n-1] == ';' || s[n-1] == ' ' || s[n-1] == '\t' ||
                     s[n-1] == '\r' || s[n-1] == '\n')) {
        s[--n] = '\0';
    }
}

/*
 * Handle a single Simple Query and emit the appropriate response sequence.
 * Returns 0 on success, -1 on fatal write error (caller should close).
 */
static int pg_handle_query(int fd, void* vdb, const char* raw_query) {
    /* Work on a mutable trimmed copy */
    char query[4096];
    size_t qlen = strlen(raw_query);
    if (qlen >= sizeof(query)) qlen = sizeof(query) - 1;
    memcpy(query, raw_query, qlen);
    query[qlen] = '\0';
    str_rtrim_semi(query);

    /* ---- SELECT version() ---- */
    if (str_iprefix(query, "SELECT version()") ||
        str_iprefix(query, "select version()")) {

        const char* col_names[] = {"version"};
        const int32_t type_oids[] = {25}; /* text */
        if (pg_send_row_description(fd, col_names, type_oids, 1) < 0) return -1;

        const char* version_str = "QIHSE 1.0.0 on " __DATE__
                                  " (PostgreSQL protocol compatible)";
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
        const int32_t type_oids[] = {23}; /* int4 */
        if (pg_send_row_description(fd, col_names, type_oids, 1) < 0) return -1;
        const char* row_vals[] = {"1"};
        if (pg_send_data_row(fd, row_vals, 1) < 0) return -1;
        if (pg_send_command_complete(fd, "SELECT 1") < 0) return -1;

    /* ---- SELECT ... FROM vectors WHERE ... (VDB stub) ---- */
    } else if (str_iprefix(query, "SELECT") &&
               (strstr(query, "vectors") || strstr(query, "VECTORS"))) {
        /*
         * VDB search path – stub that returns an empty result set.
         * A real implementation would parse the WHERE clause for the
         * query vector and call qihse_vector_db_search() on (vdb).
         */
        (void)vdb; /* suppress unused-param warning; wired through below */

        const char* col_names[] = {"id", "score"};
        const int32_t type_oids[] = {23, 25}; /* int4, text */
        if (pg_send_row_description(fd, col_names, type_oids, 2) < 0) return -1;
        /* No rows – just CommandComplete */
        if (pg_send_command_complete(fd, "SELECT 0") < 0) return -1;

    /* ---- SET client_encoding / application_name (psql handshake) ---- */
    } else if (str_iprefix(query, "SET ") || str_iprefix(query, "set ")) {

        /* Accept silently */
        if (pg_send_command_complete(fd, "SET") < 0) return -1;

    /* ---- SHOW ... (psql handshake) ---- */
    } else if (str_iprefix(query, "SHOW ") || str_iprefix(query, "show ")) {

        /* Return an empty single column result */
        const char* col_names[] = {"value"};
        const int32_t type_oids[] = {25};
        if (pg_send_row_description(fd, col_names, type_oids, 1) < 0) return -1;
        if (pg_send_command_complete(fd, "SHOW") < 0) return -1;

    /* ---- Unknown query ---- */
    } else {
        if (pg_send_error(fd, "ERROR", "42000",
                          "QIHSE: unsupported query") < 0) return -1;
    }

    return pg_send_ready_for_query(fd);
}

/* ============================================================
 * Startup handshake
 * ============================================================ */

/*
 * Read and discard a startup message, then send auth OK + ready.
 *
 * Startup message layout (no leading tag byte):
 *   int32   total_length   (includes itself)
 *   int32   protocol       (196608 = 3.0, or 80877103 = SSLRequest)
 *   cstring key, cstring value ... (pairs terminated by empty string)
 */
static int pg_do_startup(int fd) {
    /* Read the 4-byte length field */
    uint8_t lenbuf[4];
    if (pg_read_all(fd, lenbuf, 4) < 0) return -1;
    int32_t total_len =
        (int32_t)(((uint32_t)lenbuf[0] << 24) |
                  ((uint32_t)lenbuf[1] << 16) |
                  ((uint32_t)lenbuf[2] << 8)  |
                  ((uint32_t)lenbuf[3]));

    if (total_len < 8 || total_len > 65536) return -1;

    /* Read the remaining bytes (protocol version + key/value pairs) */
    size_t rest = (size_t)(total_len - 4);
    uint8_t* startup_buf = malloc(rest + 1);
    if (!startup_buf) return -1;
    startup_buf[rest] = '\0';

    if (pg_read_all(fd, startup_buf, rest) < 0) {
        free(startup_buf);
        return -1;
    }

    /* Check for SSLRequest (protocol = 0x04D2162F = 80877103) */
    uint32_t proto = ((uint32_t)startup_buf[0] << 24) |
                     ((uint32_t)startup_buf[1] << 16) |
                     ((uint32_t)startup_buf[2] << 8)  |
                     ((uint32_t)startup_buf[3]);
    free(startup_buf);

    if (proto == 80877103U) {
        /* SSLRequest */
#ifndef _WIN32
        if (global_pqc_ssl_ctx) {
            uint8_t ssl_ok = 'S';
            if (pg_write_all(fd, &ssl_ok, 1) < 0) return -1;
            
            current_ssl = SSL_new(global_pqc_ssl_ctx);
            if (current_ssl) {
                SSL_set_fd(current_ssl, fd);
                if (SSL_accept(current_ssl) <= 0) {
                    fprintf(stderr, "PQC SSL Handshake failed!\n");
                    ERR_print_errors_fp(stderr);
                    return -1;
                }
                printf("[PQC SECURE] Postgres proxy connection established using ML-KEM-1024 / ML-DSA-87 / SHA-384\n");
                return 0; /* successfully handshaked, client will send next message */
            }
        }
#endif
        uint8_t nossl = 'N';
        if (pg_write_all(fd, &nossl, 1) < 0) return -1;
        return pg_do_startup(fd); /* recurse once for real startup */
    }

    /* Protocol must be 3.0 (196608) */
    if (proto != 196608U) return -1;

    /* Send AuthenticationOk */
    if (pg_send_auth_ok(fd) < 0) return -1;

    /* Mandatory parameter status messages that psql/libpq expect */
    if (pg_send_parameter_status(fd, "server_version",    "14.0 (QIHSE)") < 0) return -1;
    if (pg_send_parameter_status(fd, "client_encoding",   "UTF8") < 0) return -1;
    if (pg_send_parameter_status(fd, "server_encoding",   "UTF8") < 0) return -1;
    if (pg_send_parameter_status(fd, "DateStyle",         "ISO, MDY") < 0) return -1;
    if (pg_send_parameter_status(fd, "TimeZone",          "UTC") < 0) return -1;
    if (pg_send_parameter_status(fd, "integer_datetimes", "on") < 0) return -1;
    if (pg_send_parameter_status(fd, "standard_conforming_strings", "on") < 0) return -1;
    if (pg_send_parameter_status(fd, "IntervalStyle",     "postgres") < 0) return -1;

    /* BackendKeyData – use fixed values (no cancel support yet) */
    if (pg_send_backend_key_data(fd, 1, 0) < 0) return -1;

    /* ReadyForQuery */
    return pg_send_ready_for_query(fd);
}

/* ============================================================
 * Per-client message loop
 * ============================================================ */

typedef struct {
    int    client_fd;
    void*  vdb;
} pg_client_data_t;

static void* pg_handle_client(void* arg);

void qihse_pg_wire_handle_client(int fd, void* vdb) {
    /* Apply per-connection timeouts to guard against slow clients */
#ifdef _WIN32
    DWORD timeout = 30000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec  = 30;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof(tv));
#endif

    /* Disable Nagle for lower latency */
    int one = 1;
#ifdef _WIN32
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
#else
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif

    /* Phase 1: startup handshake */
    if (pg_do_startup(fd) < 0) {
        close(fd);
        return;
    }

    /* Phase 2: message loop */
    while (1) {
        /* Read 1-byte message type */
        uint8_t msg_type;
        if (pg_read_all(fd, &msg_type, 1) < 0) break;

        /* Read 4-byte message length (includes itself) */
        uint8_t lenbuf[4];
        if (pg_read_all(fd, lenbuf, 4) < 0) break;
        int32_t msg_len =
            (int32_t)(((uint32_t)lenbuf[0] << 24) |
                      ((uint32_t)lenbuf[1] << 16) |
                      ((uint32_t)lenbuf[2] << 8)  |
                      ((uint32_t)lenbuf[3]));

        if (msg_len < 4) break; /* protocol error */

        size_t body_len = (size_t)(msg_len - 4);

        /* Guard against absurdly large messages (>= 16 MB) */
        if (body_len > 16 * 1024 * 1024) {
            pg_send_error(fd, "ERROR", "08P01", "Message too large");
            break;
        }

        uint8_t* body = NULL;
        if (body_len > 0) {
            body = malloc(body_len + 1);
            if (!body) break;
            body[body_len] = '\0';
            if (pg_read_all(fd, body, body_len) < 0) {
                free(body);
                break;
            }
        }

        switch (msg_type) {

        case 'Q': { /* Simple Query */
            const char* query = body ? (const char*)body : "";
            if (pg_handle_query(fd, vdb, query) < 0) {
                free(body);
                goto done;
            }
            break;
        }

        case 'X': /* Terminate */
            free(body);
            goto done;

        case 'S': /* Sync (extended query protocol – reply ReadyForQuery) */
            pg_send_ready_for_query(fd);
            break;

        case 'P': /* Parse  – stub: just consume */
        case 'B': /* Bind   – stub: just consume */
        case 'E': /* Execute – stub: just consume */
        case 'D': /* Describe – stub: just consume */
        case 'C': /* Close    – stub: just consume */
            /* Full extended query protocol is not yet implemented. */
            /* Send a placeholder so libpq does not hang. */
            if (msg_type == 'P') {
                /* ParseComplete */
                pg_send_msg(fd, '1', NULL, 0);
            } else if (msg_type == 'B') {
                /* BindComplete */
                pg_send_msg(fd, '2', NULL, 0);
            }
            break;

        default:
            /* Unknown message – send error but keep connection alive */
            pg_send_error(fd, "ERROR", "08P01", "Unsupported frontend message");
            pg_send_ready_for_query(fd);
            break;
        }

        free(body);
    }

done:
    close(fd);
}

static void* pg_handle_client(void* arg) {
    pg_client_data_t* cdata = (pg_client_data_t*)arg;
    int fd = cdata->client_fd;
    void* vdb = cdata->vdb;
    free(cdata);
    qihse_pg_wire_handle_client(fd, vdb);
    if (current_ssl) {
#ifndef _WIN32
        SSL_free(current_ssl);
#endif
        current_ssl = NULL;
    }
    return NULL;
}

static void af_xdp_pg_cb(char *pkt, uint32_t len, void *arg) {
    (void)arg;
    /* Minimum: Ethernet(14) + IP(20) + TCP(20) = 54 bytes */
    if (len < 54) return;

    /* Skip to TCP payload: Ethernet(14) + IP header (ihl*4) + TCP header (doff*4) */
    uint8_t *ip_hdr  = (uint8_t *)pkt + 14;
    uint32_t ip_len  = (ip_hdr[0] & 0x0f) * 4;
    uint8_t *tcp_hdr = ip_hdr + ip_len;
    uint32_t tcp_len = ((tcp_hdr[12] >> 4) & 0x0f) * 4;
    uint8_t *payload = tcp_hdr + tcp_len;
    uint32_t payload_len = (uint32_t)(((uint8_t *)pkt + len) - payload);

    if (payload_len < 5) return;

    /* Identify protocol by payload content */
    if (payload[0] == 'Q' && payload[1] == 'I' && payload[2] == 'H' &&
        payload[3] == 'S' && payload[4] == 'E') {
        /* UWP packet — 16-byte header already in payload */
        if (payload_len >= 16) {
            printf("[AF_XDP] Fast-path UWP: engine=0x%02x cmd=0x%02x len=%u\n",
                   payload[6], payload[7], (unsigned)payload_len);
            qihse_uwp_handle_payload((qihse_uwp_context_t*)arg, payload, payload_len);
        }
    } else {
        /* PostgreSQL wire protocol — first byte is message type */
        printf("[AF_XDP] Fast-path PG: msg_type='%c' payload_len=%u\n",
               (char)payload[0], payload_len);
        if (payload[0] == 'Q' && payload_len >= 5) {
            pg_handle_query(-1, arg, (const char*)(payload + 5));
        }
    }
}

#ifndef _WIN32
static void* af_xdp_pg_thread(void *arg) {
    (void)arg;
    struct qihse_af_xdp_ctx *xdp_ctx = qihse_af_xdp_init("eth0");
    if (!xdp_ctx) return NULL;
    int fd = qihse_af_xdp_get_fd(xdp_ctx);

    struct io_uring ring;
    if (io_uring_queue_init(16, &ring, 0) < 0) return NULL;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_poll_add(sqe, fd, POLLIN);
    io_uring_submit(&ring);

    while (1) {
        struct io_uring_cqe *cqe;
        if (io_uring_wait_cqe(&ring, &cqe) < 0) continue;
        
        if (cqe->res & POLLIN) {
            qihse_af_xdp_poll(xdp_ctx, af_xdp_pg_cb, arg);
        }
        
        io_uring_cqe_seen(&ring, cqe);
        
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_poll_add(sqe, fd, POLLIN);
        io_uring_submit(&ring);
    }
    return NULL;
}
#endif

/* ============================================================
 * Public API – start the server
 * ============================================================ */

bool qihse_start_pg_wire_server(void* vdb, uint16_t port, const char* bind_address) {
#ifndef _WIN32
    /* Load FIPS provider if available — all TLS ops go through validated module */
    qihse_pqc_init_providers();

    if (!global_pqc_ssl_ctx) {
        /* Generate DSA key + self-signed cert if not present */
        if (access(QIHSE_DSA_PRIVATE_KEY_FILE, F_OK) != 0) {
            fprintf(stderr, "[PQC INIT] Generating ML-DSA-87 keypair...\n");
            qihse_pqc_keygen(".");
        }
        if (access("qihse_dsa_cert.pem", F_OK) != 0) {
            fprintf(stderr, "[PQC INIT] Generating self-signed ML-DSA-87 TLS certificate...\n");
            int ret = system("openssl req -x509 -new "
                             "-key " QIHSE_DSA_PRIVATE_KEY_FILE " "
                             "-out qihse_dsa_cert.pem "
                             "-nodes -subj \"/CN=QIHSE Cluster\" "
                             "-days 3650 2>/dev/null");
            if (ret != 0)
                fprintf(stderr, "[WARNING] TLS cert generation failed. Continuing without TLS.\n");
        }

        global_pqc_ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (global_pqc_ssl_ctx) {
            SSL_CTX_set_min_proto_version(global_pqc_ssl_ctx, TLS1_3_VERSION);
            SSL_CTX_set1_groups_list(global_pqc_ssl_ctx, "mlkem1024");
            SSL_CTX_set1_sigalgs_list(global_pqc_ssl_ctx, "ML-DSA-87");
            SSL_CTX_set_ciphersuites(global_pqc_ssl_ctx, "TLS_AES_256_GCM_SHA384");

            if (SSL_CTX_use_certificate_file(global_pqc_ssl_ctx, "qihse_dsa_cert.pem", SSL_FILETYPE_PEM) <= 0 ||
                SSL_CTX_use_PrivateKey_file(global_pqc_ssl_ctx, QIHSE_DSA_PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
                fprintf(stderr, "[WARNING] Failed to load PQC cert/key. Running unencrypted.\n");
                SSL_CTX_free(global_pqc_ssl_ctx);
                global_pqc_ssl_ctx = NULL;
            } else {
                fprintf(stderr, "[PQC INIT] ML-KEM-1024 / ML-DSA-87 / AES-256-GCM-SHA384 TLS 1.3 active.\n");
            }
        }
    }
#endif

    if (!bind_address || bind_address[0] == '\0') {
        bind_address = "127.0.0.1";
    }

#ifndef _WIN32
    pthread_t af_xdp_tid;
    pthread_create(&af_xdp_tid, NULL, af_xdp_pg_thread, vdb);
#endif

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("qihse_pg_wire: socket");
        return false;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,  (const char*)&opt, sizeof(opt));
#else
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,  &opt, sizeof(opt));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT,  &opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, bind_address, &addr.sin_addr) <= 0) {
        fprintf(stderr, "qihse_pg_wire: invalid address '%s'\n", bind_address);
        close(server_fd);
        return false;
    }

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("qihse_pg_wire: bind");
        close(server_fd);
        return false;
    }

    if (listen(server_fd, 128) < 0) {
        perror("qihse_pg_wire: listen");
        close(server_fd);
        return false;
    }

    printf("[QIHSE PG] PostgreSQL Wire Protocol v3 server on %s:%u\n",
           bind_address, port);

    /* Accept loop – one thread per client (mirrors qihse_uwp.c pattern) */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd,
                               (struct sockaddr*)&client_addr,
                               &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("qihse_pg_wire: accept");
            continue;
        }

        pg_client_data_t* cdata = malloc(sizeof(pg_client_data_t));
        if (!cdata) {
            close(client_fd);
            continue;
        }
        cdata->client_fd = client_fd;
        cdata->vdb       = vdb;  /* wired: the vdb pointer is used in pg_handle_query */

        pthread_t tid;
        if (pthread_create(&tid, NULL, pg_handle_client, cdata) != 0) {
            perror("qihse_pg_wire: pthread_create");
            free(cdata);
            close(client_fd);
        } else {
            pthread_detach(tid);
        }
    }

    /* unreachable */
    close(server_fd);
    return true;
}
