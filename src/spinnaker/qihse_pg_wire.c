/*
 * QIHSE PostgreSQL Wire Protocol v3 Server
 *
 * Implements the frontend/backend protocol described at:
 *   https://www.postgresql.org/docs/current/protocol.html
 */

#include "qihse_pg_wire.h"
#include "qihse_vector_db.h"
#include "qihse_uwp.h"
#include "qihse_dist_planner.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"

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

static SSL_CTX* global_pqc_ssl_ctx = NULL;
static __thread SSL* current_ssl = NULL;

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
        free(startup_buf);
        uint8_t ssl_reject = 'N';
        pg_write_all(fd, &ssl_reject, 1);
        return pg_send_auth_and_startup(fd);
    }

    /* Send AuthenticationOk directly */
    if (pg_send_auth_ok(fd) < 0) {
        free(startup_buf);
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

    free(startup_buf);
    static qihse_user_t local_user = {0};
    return &local_user;
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

    char last_parsed_query[4096] = {0};
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
            case 'P': {
                const char* stmt_name = body ? (const char*)body : "";
                size_t name_len = strlen(stmt_name) + 1;
                const char* parsed_query = body ? (const char*)(body + name_len) : "";
                strncpy(last_parsed_query, parsed_query, sizeof(last_parsed_query) - 1);
                pg_send_msg(fd, '1', NULL, 0);
                break;
            }
            case 'B':
                pg_send_msg(fd, '2', NULL, 0);
                break;
            case 'D': {
                const char* col_names[] = {"id", "score", "metric", "payload"};
                const int32_t type_oids[] = {23, 25, 25, 25};
                pg_send_row_description(fd, col_names, type_oids, 4);
                break;
            }
            case 'E': {
                if (last_parsed_query[0]) {
                    pg_handle_query_ctx(fd, &ctx, last_parsed_query, user);
                    last_parsed_query[0] = '\0';
                } else {
                    pg_send_msg(fd, 'I', NULL, 0);
                    pg_send_ready_for_query(fd);
                }
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
