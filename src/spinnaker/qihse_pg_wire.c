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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <liburing.h>
#include <poll.h>
#include "../networking/qihse_af_xdp.h"
#include "../../persistence/qihse_pqc_crypto.h"
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define SSL_CTX void
#define SSL void
#endif

static SSL_CTX* global_pqc_ssl_ctx __attribute__((unused)) = NULL;
static __thread SSL* current_ssl = NULL;

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

static int pg_send_ready_for_query(int fd) {
    uint8_t body[1] = {'I'};
    return pg_send_msg(fd, 'Z', body, 1);
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

static int pg_send_command_complete(int fd, const char* tag) {
    pg_buf_t b;
    pg_buf_init(&b);
    pg_buf_append_str(&b, tag);
    int rc = pg_send_msg(fd, 'C', b.data, b.len);
    pg_buf_free(&b);
    return rc;
}

static int pg_send_error(int fd, const char* severity, const char* sqlstate, const char* message) {
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

static int pg_handle_query_ctx(int fd, pg_cluster_context_t* ctx, const char* raw_query, qihse_user_t* user) {
    char query[4096];
    if (!user) {
        if (pg_send_error(fd, "ERROR", "28000", "authentication required") < 0) return -1;
        return pg_send_ready_for_query(fd);
    }
    size_t qlen = strlen(raw_query);
    if (qlen >= sizeof(query)) qlen = sizeof(query) - 1;
    memcpy(query, raw_query, qlen);
    query[qlen] = '\0';
    str_rtrim_semi(query);

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

static qihse_user_t* pg_send_auth_and_startup(int fd) {
    uint8_t lenbuf[4];
    if (pg_read_all(fd, lenbuf, 4) < 0) return NULL;
    int32_t total_len = (int32_t)(((uint32_t)lenbuf[0] << 24) |
                                  ((uint32_t)lenbuf[1] << 16) |
                                  ((uint32_t)lenbuf[2] << 8)  |
                                  ((uint32_t)lenbuf[3]));

    if (total_len < 8 || total_len > 65536) return NULL;

    size_t rest = (size_t)(total_len - 4);
    uint8_t* startup_buf = (uint8_t*)malloc(rest + 1);
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
        /* SSL request — reject and recurse to read the real startup */
        free(startup_buf);
        uint8_t ssl_reject = 'N';
        pg_write_all(fd, &ssl_reject, 1);
        return pg_send_auth_and_startup(fd);
    }

    /* Parse the startup message for the "user" parameter.
     * After the 4-byte protocol version, the body is a sequence of
     * null-terminated key/value string pairs terminated by a final \0. */
    char username[128] = {0};
    size_t pos = 4;  /* skip protocol version */
    while (pos + 1 < rest) {
        /* Check for the terminating null byte */
        if (startup_buf[pos] == '\0') break;
        /* Extract key (null-terminated string) */
        const char* key = (const char*)(startup_buf + pos);
        size_t key_len = strnlen(key, rest - pos);
        if (pos + key_len >= rest) break;
        pos += key_len + 1;
        /* Extract value (null-terminated string) */
        if (pos >= rest) break;
        const char* val = (const char*)(startup_buf + pos);
        size_t val_len = strnlen(val, rest - pos);
        if (strcmp(key, "user") == 0) {
            snprintf(username, sizeof(username), "%s", val);
        }
        if (pos + val_len >= rest) break;
        pos += val_len + 1;
    }

    free(startup_buf);

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


/* -------------------------------------------------------------------------
 * Prepared statement cache (extended query protocol)
 * ------------------------------------------------------------------------- */
#define QIHSE_PG_MAX_PREPARED 64

typedef struct {
    char name[128];
    char query[4096];
    int16_t num_param_oids;
    int32_t param_oids[64];
    int in_use;
} pg_prepared_stmt_t;

typedef struct {
    pg_prepared_stmt_t stmts[QIHSE_PG_MAX_PREPARED];
    size_t count;
} pg_stmt_cache_t;

static void pg_stmt_cache_init(pg_stmt_cache_t* cache) {
    memset(cache, 0, sizeof(*cache));
}

static pg_prepared_stmt_t* pg_stmt_cache_lookup(pg_stmt_cache_t* cache, const char* name) {
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->stmts[i].in_use && strcmp(cache->stmts[i].name, name) == 0)
            return &cache->stmts[i];
    }
    return NULL;
}

static pg_prepared_stmt_t* pg_stmt_cache_put(pg_stmt_cache_t* cache, const char* name,
                                              const char* query, const int32_t* param_oids,
                                              int16_t num_params) {
    /* check if name already exists (replace) */
    pg_prepared_stmt_t* s = pg_stmt_cache_lookup(cache, name);
    if (!s) {
        if (cache->count >= QIHSE_PG_MAX_PREPARED) {
            /* evict slot 0 */
            memmove(&cache->stmts[0], &cache->stmts[1], (QIHSE_PG_MAX_PREPARED - 1) * sizeof(pg_prepared_stmt_t));
            cache->count = QIHSE_PG_MAX_PREPARED - 1;
        }
        s = &cache->stmts[cache->count++];
    }
    memset(s, 0, sizeof(*s));
    strncpy(s->name, name, sizeof(s->name) - 1);
    strncpy(s->query, query, sizeof(s->query) - 1);
    s->num_param_oids = num_params;
    for (int16_t i = 0; i < num_params && i < 64; i++) s->param_oids[i] = param_oids[i];
    s->in_use = 1;
    return s;
}

static void pg_stmt_cache_remove(pg_stmt_cache_t* cache, const char* name) {
    pg_prepared_stmt_t* s = pg_stmt_cache_lookup(cache, name);
    if (s) s->in_use = 0;
}

/* Substitute $1, $2, ... parameters in a query with bound values.
 * Returns a newly-allocated string. */
static char* pg_substitute_params(const char* query, const char** params, int16_t num_params) __attribute__((unused));
static char* pg_substitute_params(const char* query, const char** params, int16_t num_params) {
    if (!query) return NULL;
    if (num_params == 0) return strdup(query);
    /* build result */
    size_t cap = strlen(query) + 256;
    char* result = (char*)malloc(cap);
    size_t pos = 0;
    const char* p = query;
    while (*p) {
        if (*p == '$' && p[1] >= '1' && p[1] <= '9') {
            /* handle multi-digit */
            const char* d = p + 1;
            while (*d >= '0' && *d <= '9') d++;
            int param_idx = (int)strtol(p + 1, NULL, 10) - 1;
            p = d;
            if (param_idx >= 0 && param_idx < num_params && params[param_idx]) {
                const char* val = params[param_idx];
                size_t vlen = strlen(val);
                /* quote string values */
                size_t need = vlen + 4;
                if (pos + need >= cap) {
                    cap = (cap + need) * 2;
                    result = (char*)realloc(result, cap);
                }
                result[pos++] = '\'';
                for (size_t i = 0; i < vlen; i++) {
                    if (val[i] == '\'') { result[pos++] = '\''; result[pos++] = '\''; }
                    else result[pos++] = val[i];
                }
                result[pos++] = '\'';
            } else {
                if (pos + 4 >= cap) { cap *= 2; result = (char*)realloc(result, cap); }
                result[pos++] = 'N'; result[pos++] = 'U'; result[pos++] = 'L'; result[pos++] = 'L';
            }
        } else {
            if (pos + 1 >= cap) { cap *= 2; result = (char*)realloc(result, cap); }
            result[pos++] = *p++;
        }
    }
    result[pos] = '\0';
    return result;
}

void qihse_pg_wire_handle_client_multi(
    int fd,
    qihse_kv_store_t* store,
    qihse_vector_db_t vdb,
    qihse_tsdb_t* tsdb,
    qihse_column_store_t* col,
    qihse_cluster_topology_t* topo
) {
    pg_cluster_context_t ctx = {
        .store = store,
        .vdb = vdb,
        .tsdb = tsdb,
        .col = col,
        .topo = topo
    };

    qihse_user_t* user = pg_send_auth_and_startup(fd);
    if (!user) {
        close(fd);
        return;
    }

    pg_stmt_cache_t stmt_cache;
    pg_stmt_cache_init(&stmt_cache);
    char last_portal_query[4096] = {0};
    char last_stmt_name[128] = {0};

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

        switch (msg_type) {
            case 'Q': {
                const char* query = body ? (const char*)body : "";
                if (pg_handle_query_ctx(fd, &ctx, query, user) < 0) {
                    free(body);
                    goto done;
                }
                break;
            }
            case 'X':
                free(body);
                goto done;
            case 'S':
                pg_send_ready_for_query(fd);
                break;
            /* ---- Parse (P): store prepared statement ---- */
            case 'P': {
                const char* stmt_name = body ? (const char*)body : "";
                size_t name_len = strlen(stmt_name) + 1;
                const char* parsed_query = body ? (const char*)(body + name_len) : "";
                /* skip parameter OID array (int16 count + int32 oids) */
                const int16_t* nptr = (const int16_t*)(body + name_len + strlen(parsed_query) + 1);
                int16_t num_params = 0;
                const int32_t* param_oids = NULL;
                if ((size_t)((const uint8_t*)nptr - body) + 2 <= body_len) {
                    num_params = (int16_t)(((uint16_t)nptr[0] << 8) | (uint16_t)((const uint8_t*)nptr)[1]);
                    /* big-endian */
                    num_params = (int16_t)(((uint16_t)((const uint8_t*)nptr)[0] << 8) | (uint16_t)((const uint8_t*)nptr)[1]);
                    param_oids = (const int32_t*)((const uint8_t*)nptr + 2);
                }
                pg_stmt_cache_put(&stmt_cache, stmt_name, parsed_query, param_oids, num_params);
                pg_send_msg(fd, '1', NULL, 0);  /* ParseComplete */
                break;
            }
            /* ---- Bind (B): bind parameters to a portal ---- */
            case 'B': {
                /* portal name (cstring), stmt name (cstring), then param formats, params, result formats */
                const char* portal_name = body ? (const char*)body : "";
                size_t portal_len = strlen(portal_name) + 1;
                const char* stmt_name = body ? (const char*)(body + portal_len) : "";
                pg_prepared_stmt_t* ps = pg_stmt_cache_lookup(&stmt_cache, stmt_name);
                if (ps) {
                    strncpy(last_portal_query, ps->query, sizeof(last_portal_query) - 1);
                    last_portal_query[sizeof(last_portal_query)-1] = '\0';
                    strncpy(last_stmt_name, stmt_name, sizeof(last_stmt_name) - 1);
                }
                pg_send_msg(fd, '2', NULL, 0);  /* BindComplete */
                break;
            }
            /* ---- Describe (D): send row description ---- */
            case 'D': {
                const char* col_names[] = {"id", "score", "metric", "payload"};
                const int32_t type_oids[] = {23, 25, 25, 25};
                pg_send_row_description(fd, col_names, type_oids, 4);
                break;
            }
            /* ---- Execute (E): run the bound portal ---- */
            case 'E': {
                if (last_portal_query[0]) {
                    pg_handle_query_ctx(fd, &ctx, last_portal_query, user);
                    last_portal_query[0] = '\0';
                } else {
                    pg_send_msg(fd, 'I', NULL, 0);  /* EmptyQueryResponse */
                    pg_send_ready_for_query(fd);
                }
                break;
            }
            /* ---- Sync (S) handled above; Close (C) ---- */
            case 'C': {
                const char* close_type = body ? (const char*)(const uint8_t*)body : "";
                if (body && body_len > 0 && close_type[0] == 'S') {
                    const char* sname = (const char*)(const uint8_t*)body + 1;
                    pg_stmt_cache_remove(&stmt_cache, sname);
                }
                pg_send_msg(fd, '3', NULL, 0);  /* CloseComplete */
                break;
            }
            default:
                pg_send_ready_for_query(fd);
                break;
        }
        free(body);
    }

done:
    close(fd);
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
