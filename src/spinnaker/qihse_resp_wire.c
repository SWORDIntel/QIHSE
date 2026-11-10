#include "qihse_resp_wire.h"
#include "qihse_resp_engine.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <ctype.h>
#include "qihse_platform.h"
#ifndef _WIN32
#include <pthread.h>
#include <liburing.h>
#include <poll.h>
#include "qihse_af_xdp.h"
#endif
#include "../broad_oak/qihse_quantum_defense.h"

typedef struct {
    int client_fd;
    qihse_kv_store_t* store;
    qihse_vector_db_t vdb;
} qihse_resp_client_ctx_t;

void* qihse_resp_client_thread(void* arg) {
    qihse_resp_client_ctx_t* ctx = (qihse_resp_client_ctx_t*)arg;
    qihse_resp_handle_client(ctx->client_fd, ctx->store, ctx->vdb);
    free(ctx);
    return NULL;
}


typedef enum {
    RESP_FRAME_ERROR = -1,
    RESP_FRAME_MORE = 0,
    RESP_FRAME_READY = 1
} resp_frame_status_t;

static const char* resp_find_crlf(const char* p, const char* end) {
    while ((size_t)(end - p) >= 2u) {
        if (p[0] == '\r' && p[1] == '\n') return p;
        ++p;
    }
    return NULL;
}

static bool resp_parse_decimal(const char* p, size_t len, size_t limit,
                               size_t* value) {
    if (!p || !len || !value) return false;
    size_t n = 0;
    for (size_t i = 0; i < len; ++i) {
        if (p[i] < '0' || p[i] > '9') return false;
        size_t digit = (size_t)(p[i] - '0');
        if (digit > limit || n > (limit - digit) / 10u) return false;
        n = n * 10u + digit;
    }
    *value = n;
    return true;
}

/* Parse exactly the first RESP array frame. Incomplete input is retained by
 * the socket loop; malformed framing and embedded NULs fail closed. */
static resp_frame_status_t parse_resp_array(char* buf, size_t buf_len,
                                             char** args, size_t max_args,
                                             size_t* consumed, size_t* argc_out,
                                             bool terminate_fields) {
    if (!buf || !args || !consumed || !argc_out) return RESP_FRAME_ERROR;
    *consumed = 0;
    *argc_out = 0;
    if (!buf_len) return RESP_FRAME_MORE;
    if (buf[0] != '*') return RESP_FRAME_ERROR;
    const char* end = buf + buf_len;
    const char* line_end = resp_find_crlf(buf + 1, end);
    if (!line_end) return buf_len > 32u ? RESP_FRAME_ERROR : RESP_FRAME_MORE;
    size_t argc;
    if (!resp_parse_decimal(buf + 1, (size_t)(line_end - (buf + 1)),
                            max_args, &argc) || argc == 0u)
        return RESP_FRAME_ERROR;
    char* p = (char*)line_end + 2;
    for (size_t i = 0; i < argc; ++i) {
        if (p >= end) return RESP_FRAME_MORE;
        if (*p != '$') return RESP_FRAME_ERROR;
        line_end = resp_find_crlf(p + 1, end);
        if (!line_end) return (size_t)(end - p) > 32u ? RESP_FRAME_ERROR : RESP_FRAME_MORE;
        size_t field_len;
        if (!resp_parse_decimal(p + 1, (size_t)(line_end - (p + 1)),
                                1024u * 1024u, &field_len))
            return RESP_FRAME_ERROR;
        p = (char*)line_end + 2;
        if (field_len > (size_t)(end - p) ||
            (size_t)(end - p) - field_len < 2u)
            return RESP_FRAME_MORE;
        if (memchr(p, '\0', field_len) || p[field_len] != '\r' ||
            p[field_len + 1u] != '\n')
            return RESP_FRAME_ERROR;
        args[i] = p;
        if (terminate_fields) p[field_len] = '\0';
        p += field_len + 2u;
    }
    *consumed = (size_t)(p - buf);
    *argc_out = argc;
    return RESP_FRAME_READY;
}

static bool resp_write_all(int fd, const char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
#ifdef _WIN32
        int amount = len - off > INT_MAX ? INT_MAX : (int)(len - off);
        int w = send(fd, buf + off, amount, 0);
        if (w == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAEINTR) continue;
            shutdown(fd, SD_BOTH);
            return false;
        }
        if (w == 0) { shutdown(fd, SD_BOTH); return false; }
#else
        ssize_t w = send(fd, buf + off, len - off,
#ifdef MSG_NOSIGNAL
                         MSG_NOSIGNAL
#else
                         0
#endif
        );
        if (w < 0) {
            if (errno == EINTR) continue;
            shutdown(fd, SHUT_RDWR);
            return false;
        }
        if (w == 0) { shutdown(fd, SHUT_RDWR); return false; }
#endif
        off += (size_t)w;
    }
    return true;
}

#ifdef QIHSE_RESP_WIRE_TESTING
bool qihse_resp_wire_test_write_all(int fd, const char* buf, size_t len) {
    return resp_write_all(fd, buf, len);
}
#endif

static void resp_write_bulk(int fd, const char* value) {
    if (!value) { resp_write_all(fd, "$-1\r\n", 5u); return; }
    size_t len = strlen(value);
    char header[64];
    int n = snprintf(header, sizeof(header), "$%zu\r\n", len);
    resp_write_all(fd, header, (size_t)n);
    resp_write_all(fd, value, len);
    resp_write_all(fd, "\r\n", 2u);
}

void qihse_resp_handle_client(int client_fd, qihse_kv_store_t* store, qihse_vector_db_t vdb) {
    if (qihse_resp_engine_handle_legacy(client_fd, store, vdb)) return;
#ifdef _WIN32
    DWORD timeout = 30000;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#ifdef SO_NOSIGPIPE
    int no_sigpipe = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
               sizeof(no_sigpipe));
#endif
#endif
    enum { MAX_FRAME_BYTES = 1024 * 1024, MAX_ARGS = 2048 };
    char* buffer = malloc((size_t)MAX_FRAME_BYTES + 1u);
    char* frame = malloc((size_t)MAX_FRAME_BYTES + 1u);
    char** args = malloc(MAX_ARGS * sizeof(*args));
    if (!buffer || !frame || !args) {
        free(buffer); free(frame); free(args); close(client_fd); return;
    }
    size_t buffered = 0u;
    qihse_user_t* current_user = NULL;
    while (1) {
        size_t consumed = 0u;
        size_t parsed_argc = 0u;
        resp_frame_status_t status = RESP_FRAME_MORE;
        const char* line_end = NULL;
        while (status == RESP_FRAME_MORE) {
            if (buffered > 0u && buffer[0] != '*') {
                line_end = resp_find_crlf(buffer, buffer + buffered);
                if (line_end) {
                    consumed = (size_t)(line_end - buffer) + 2u;
                    status = RESP_FRAME_READY;
                    break;
                }
                if (buffered == MAX_FRAME_BYTES) status = RESP_FRAME_ERROR;
            } else {
                status = parse_resp_array(buffer, buffered, args, MAX_ARGS,
                                          &consumed, &parsed_argc, false);
                if (status == RESP_FRAME_READY && consumed > MAX_FRAME_BYTES)
                    status = RESP_FRAME_ERROR;
            }
            if (status != RESP_FRAME_MORE) break;
            if (buffered == MAX_FRAME_BYTES) { status = RESP_FRAME_ERROR; break; }
#ifdef _WIN32
            int received = recv(client_fd, buffer + buffered,
                                (int)((size_t)MAX_FRAME_BYTES - buffered), 0);
            if (received == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) continue;
#else
            ssize_t received = recv(client_fd, buffer + buffered,
                                    (size_t)MAX_FRAME_BYTES - buffered, 0);
            if (received < 0 && errno == EINTR) continue;
#endif
            if (received <= 0) goto client_done;
            buffered += (size_t)received;
            buffer[buffered] = '\0';
        }
        if (status != RESP_FRAME_READY || consumed == 0u) {
            const char* reply = "-ERR malformed RESP request\r\n";
            resp_write_all(client_fd, reply, strlen(reply));
            break;
        }

        memcpy(frame, buffer, consumed);
        frame[consumed] = '\0';
        int argc = 0;
        if (buffer[0] == '*') {
            size_t frame_consumed = 0u;
            status = parse_resp_array(frame, consumed, args, MAX_ARGS,
                                      &frame_consumed, &parsed_argc, true);
            if (status != RESP_FRAME_READY || frame_consumed != consumed ||
                parsed_argc > INT_MAX) {
                const char* reply = "-ERR malformed RESP request\r\n";
                resp_write_all(client_fd, reply, strlen(reply));
                break;
            }
            argc = (int)parsed_argc;
        } else {
            if (memchr(frame, '\0', consumed - 2u)) {
                const char* reply = "-ERR malformed inline request\r\n";
                resp_write_all(client_fd, reply, strlen(reply));
                break;
            }
            char* save_ptr = NULL;
            char* token = strtok_r(frame, " \r\n", &save_ptr);
            while (token && argc < MAX_ARGS) {
                args[argc++] = token;
                token = strtok_r(NULL, " \r\n", &save_ptr);
            }
            if (token) {
                const char* reply = "-ERR malformed inline request\r\n";
                resp_write_all(client_fd, reply, strlen(reply));
                break;
            }
        }

        buffered -= consumed;
        if (buffered) memmove(buffer, buffer + consumed, buffered);
        
        if (argc > 0) {
            // Require auth at every network protocol entrypoint
            if (!current_user && strcasecmp(args[0], "AUTH") != 0 && strcasecmp(args[0], "PING") != 0) {
                const char* reply = "-NOAUTH Authentication required.\r\n";
                resp_write_all(client_fd, reply, strlen(reply));
                continue;
            }

            if (strcasecmp(args[0], "PING") == 0) {
                const char* reply = "+PONG\r\n";
                resp_write_all(client_fd, reply, strlen(reply));
            } else if (strcasecmp(args[0], "AUTH") == 0 && argc >= 3) {
                current_user = qihse_auth_authenticate(args[1], args[2]);
                if (current_user) {
                    const char* reply = "+OK\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                } else {
                    const char* reply = "-ERR invalid credentials\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                }
            } else if (strcasecmp(args[0], "SET") == 0 && argc >= 3) {
                if (qihse_kv_set_user(store, args[1], args[2], 0, 0, current_user)) {
                    const char* reply = "+OK\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                } else {
                    const char* reply = "-ERR Access denied or set failed\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                }
            } else if (strcasecmp(args[0], "GET") == 0 && argc >= 2) {
                char* val = qihse_kv_get_user(store, args[1], current_user);
                
                if (qihse_kv_store_is_under_attack(store)) {
                    free(val);
#ifndef _WIN32
                    qihse_qdd_execute_active_measure(client_fd);
#endif
                    break;
                }
                
                resp_write_bulk(client_fd, val);
                free(val);
            } else if (strcasecmp(args[0], "DEL") == 0 && argc >= 2) {
                if (qihse_kv_del_user(store, args[1], current_user)) {
                    const char* reply = ":1\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                } else {
                    const char* reply = ":0\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                }
            } else if (strcasecmp(args[0], "MSET") == 0 && argc >= 3) {
                bool all_ok = true;
                for (int i = 1; i < argc - 1; i += 2) {
                    if (!qihse_kv_set_user(store, args[i], args[i+1], 0, 0, current_user)) {
                        all_ok = false;
                        break;
                    }
                }
                if (all_ok) {
                    const char* reply = "+OK\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                } else {
                    const char* reply = "-ERR Access denied or set failed\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                }
            } else if (strcasecmp(args[0], "MGET") == 0 && argc >= 2) {
                char header[64];
                int n = snprintf(header, sizeof(header), "*%d\r\n", argc - 1);
                resp_write_all(client_fd, header, (size_t)n);
                for (int i = 1; i < argc; i++) {
                    char* value = qihse_kv_get_user(store, args[i], current_user);
                    resp_write_bulk(client_fd, value);
                    free(value);
                }
            } else if (strcasecmp(args[0], "INFO") == 0) {
                const char* info = "# Server\r\nredis_version:7.0.0 (QIHSE Wire Proxy)\r\n# Memory\r\nused_memory_human:0B\r\n";
                char reply[1024];
                snprintf(reply, sizeof(reply), "$%zu\r\n%s\r\n", strlen(info), info);
                resp_write_all(client_fd, reply, strlen(reply));
            } else if (strcasecmp(args[0], "VECSET") == 0 && argc >= 3) {
                if (!current_user) {
                    const char* reply = "-NOAUTH Authentication required.\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                if (qihse_user_get_tenant_id(current_user) != QIHSE_TENANT_SYSTEM) {
                    const char* reply = "-NOPERM tenant vector access requires the primary RESP adapter\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                uint64_t id = strtoull(args[1], NULL, 10);
                if (!qihse_auth_can_access_object(current_user, 0, id, QIHSE_ACL_WRITE)) {
                    const char* reply = "-ERR Access denied\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                int dim = (int)strtol(args[2], NULL, 10);
                if (dim <= 0 || dim > 2048) {
                    const char* reply = "-ERR invalid dimension\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                } else if (argc >= 3 + dim) {
                    float *vec = malloc(dim * sizeof(float));
                    if (!vec) {
                        const char* reply = "-ERR out of memory\r\n";
                        resp_write_all(client_fd, reply, strlen(reply));
                        continue;
                    }
                    for (int i = 0; i < dim; i++) {
                        vec[i] = strtof(args[3 + i], NULL);
                    }
                    bool stored = qihse_resp_vdb_access_lock(NULL, vdb);
                    if (stored) {
                        stored = qihse_vector_db_upsert_by_ids_user(vdb,
                            current_user, &id, vec, 1, dim, NULL, NULL, NULL, NULL);
                        qihse_resp_vdb_access_unlock(NULL, vdb);
                    }
                    const char* reply = stored ? "+OK\r\n" :
                                                 "-ERR vector upsert failed\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    free(vec);
                } else {
                    const char* reply = "-ERR invalid VECSET format\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                }
            } else if (strcasecmp(args[0], "VECGET") == 0 && argc >= 2) {
                if (!current_user) {
                    const char* reply = "-NOAUTH Authentication required.\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                if (qihse_user_get_tenant_id(current_user) != QIHSE_TENANT_SYSTEM) {
                    const char* reply = "-NOPERM tenant vector access requires the primary RESP adapter\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                uint64_t id = strtoull(args[1], NULL, 10);
                if (!qihse_auth_can_access_object(current_user, 0, id, QIHSE_ACL_READ)) {
                    const char* reply = "-ERR Access denied\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                if (!qihse_resp_vdb_access_lock(NULL, vdb)) {
                    const char* reply = "-ERR vector database lock failed\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                size_t dims = qihse_vector_db_get_dims(vdb);
                if (dims == 0) {
                    const char* reply = "-ERR vector database not initialized\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                } else {
                    float* vec = (float*)malloc(dims * sizeof(float));
                    if (!vec) {
                        const char* reply = "-ERR out of memory\r\n";
                        resp_write_all(client_fd, reply, strlen(reply));
                    } else if (qihse_vector_db_get_vector_by_id_user(vdb, current_user, id, vec, &dims)) {
                        char header[64];
                        snprintf(header, sizeof(header), "*%zu\r\n", dims);
                        resp_write_all(client_fd, header, strlen(header));
                        for (size_t i = 0; i < dims; i++) {
                            char val[64];
                            snprintf(val, sizeof(val), "$%zu\r\n%.6g\r\n",
                                     (size_t)snprintf(NULL, 0, "%.6g", vec[i]),
                                     vec[i]);
                            resp_write_all(client_fd, val, strlen(val));
                        }
                    } else {
                        const char* reply = "-ERR vector not found\r\n";
                        resp_write_all(client_fd, reply, strlen(reply));
                    }
                    free(vec);
                }
                qihse_resp_vdb_access_unlock(NULL, vdb);
            } else if (strcasecmp(args[0], "VECSEARCH") == 0 && argc >= 3) {
                if (!current_user) {
                    const char* reply = "-NOAUTH Authentication required.\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                if (qihse_user_get_tenant_id(current_user) != QIHSE_TENANT_SYSTEM) {
                    const char* reply = "-NOPERM tenant vector access requires the primary RESP adapter\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                    continue;
                }
                int dim = (int)strtol(args[1], NULL, 10);
                int top_k = (int)strtol(args[2], NULL, 10);
                if (dim <= 0 || dim > 2048 || top_k <= 0 || top_k > 1000) {
                    const char* reply = "-ERR invalid parameters\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                } else if (argc >= 3 + dim) {
                    float *vec = malloc(dim * sizeof(float));
                    if (!vec) {
                        const char* reply = "-ERR out of memory\r\n";
                        resp_write_all(client_fd, reply, strlen(reply));
                        continue;
                    }
                    for (int i = 0; i < dim; i++) {
                        vec[i] = strtof(args[3 + i], NULL);
                    }
                    qihse_vector_query_t query;
                    memset(&query, 0, sizeof(query));
                    query.query_vector = vec;
                    query.vector_dims = dim;
                    query.top_k = top_k;
                    query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
                    query.user = current_user;
                    
                    qihse_vector_result_t *results = malloc(top_k * sizeof(qihse_vector_result_t));
                    if (!results) {
                        free(vec);
                        const char* reply = "-ERR out of memory\r\n";
                        resp_write_all(client_fd, reply, strlen(reply));
                        continue;
                    }
                    int found = -1;
                    if (qihse_resp_vdb_access_lock(NULL, vdb)) {
                        found = qihse_vector_db_search(vdb, &query, results, top_k);
                        qihse_resp_vdb_access_unlock(NULL, vdb);
                    }
                    
                    if (found >= 0) {
                        char reply[1024];
                        snprintf(reply, sizeof(reply), "*%d\r\n", found);
                        resp_write_all(client_fd, reply, strlen(reply));
                        for (int i = 0; i < found; i++) {
                            char item[128];
                            snprintf(item, sizeof(item), ":%llu\r\n", (unsigned long long)results[i].id);
                            resp_write_all(client_fd, item, strlen(item));
                        }
                    } else {
                        const char* reply = "-ERR search failed\r\n";
                        resp_write_all(client_fd, reply, strlen(reply));
                    }
                    free(results);
                    free(vec);
                } else {
                    const char* reply = "-ERR invalid VECSEARCH format\r\n";
                    resp_write_all(client_fd, reply, strlen(reply));
                }
            } else {
                const char* reply = "-ERR unknown command\r\n";
                resp_write_all(client_fd, reply, strlen(reply));
            }
        }
    }
client_done:
    free(args);
    free(frame);
    free(buffer);
    close(client_fd);
}

static bool qihse_mem_contains(const char* haystack, size_t haystack_len, const char* needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) return false;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) return true;
    }
    return false;
}

static void af_xdp_resp_cb(char *pkt, uint32_t len, void *arg) {
    (void)arg;
    if (len > 54) {
        char *payload = pkt + 54;
        size_t payload_len = (size_t)len - 54u;
        if (qihse_mem_contains(payload, payload_len, "PING", 4)) {
            printf("[AF_XDP RESP] Fast-path zero-copy bypass: PING\n");
        } else if (qihse_mem_contains(payload, payload_len, "GET", 3)) {
            printf("[AF_XDP RESP] Fast-path zero-copy bypass: GET\n");
        } else if (qihse_mem_contains(payload, payload_len, "SET", 3)) {
            printf("[AF_XDP RESP] Fast-path zero-copy bypass: SET\n");
        }
    }
}

#ifndef _WIN32
static void* af_xdp_resp_thread(void *arg) {
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
            qihse_af_xdp_poll(xdp_ctx, af_xdp_resp_cb, arg);
        }
        
        io_uring_cqe_seen(&ring, cqe);
        
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_poll_add(sqe, fd, POLLIN);
        io_uring_submit(&ring);
    }
    return NULL;
}
#endif

bool qihse_start_resp_server(qihse_kv_store_t* store, qihse_vector_db_t vdb, uint16_t port, const char* bind_address) {
    if (qihse_auth_is_operator_password_default()) {
        fprintf(stderr, "[FATAL SECURITY ERROR] Default operator password detected. "
                        "You must rotate the default operator password before starting network services.\n");
        return false;
    }

    if (qihse_resp_engine_run_legacy(store, vdb, port, bind_address)) return true;

    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return false;
    }

#ifndef _WIN32
    pthread_t af_xdp_tid;
    qihse_resp_client_ctx_t* af_ctx = malloc(sizeof(qihse_resp_client_ctx_t));
    af_ctx->client_fd = -1;
    af_ctx->store = store;
    af_ctx->vdb = vdb;
    pthread_create(&af_xdp_tid, NULL, af_xdp_resp_thread, af_ctx);
#endif

#ifdef _WIN32
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt))) {
#else
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
#endif
        perror("setsockopt");
        close(server_fd);
        return false;
    }

    address.sin_family = AF_INET;
    const char* final_bind = bind_address;
    if (!final_bind || strcmp(final_bind, "0.0.0.0") == 0 || final_bind[0] == '\0') {
        final_bind = "127.0.0.1";
    }
    address.sin_addr.s_addr = inet_addr(final_bind);
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return false;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return false;
    }

    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        qihse_resp_client_ctx_t* ctx = malloc(sizeof(qihse_resp_client_ctx_t));
        ctx->client_fd = client_fd;
        ctx->store = store;
        ctx->vdb = vdb;
        
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, qihse_resp_client_thread, ctx) != 0) {
            perror("pthread_create failed");
            close(client_fd);
            free(ctx);
            continue;
        }
        pthread_detach(thread_id);
    }

    return true;
}

#ifdef _WIN32
typedef enum {
    QIHSE_IOCP_READ,
    QIHSE_IOCP_WRITE
} qihse_iocp_op_t;

typedef struct {
    WSAOVERLAPPED overlapped;
    SOCKET socket;
    qihse_iocp_op_t op_type;
    WSABUF wsa_buf;
    char buffer[65536];
    DWORD bytes_transferred;
    qihse_kv_store_t* store;
    qihse_vector_db_t vdb;
} qihse_iocp_ctx_t;

static DWORD WINAPI iocp_worker_thread(LPVOID completion_port) {
    HANDLE iocp = (HANDLE)completion_port;
    DWORD bytes_transferred;
    ULONG_PTR completion_key;
    qihse_iocp_ctx_t* ctx;

    while (1) {
        BOOL result = GetQueuedCompletionStatus(iocp, &bytes_transferred, &completion_key, (LPOVERLAPPED*)&ctx, INFINITE);
        if (!result || bytes_transferred == 0) {
            if (ctx) {
                closesocket(ctx->socket);
                free(ctx);
            }
            continue;
        }

        if (ctx->op_type == QIHSE_IOCP_READ) {
            ctx->buffer[bytes_transferred] = '\0';
            
            // Re-use the existing RESP parser logic over the buffer.
            // For a highly optimized IOCP we would parse inline, but here we call the parser manually
            // and construct the reply in ctx->buffer, then issue a WSASend.
            
            // Very simplified fast-path for PING/GET to demonstrate RIO/IOCP zero-copy semantics:
            char* reply_ptr = "+OK\r\n";
            if (strncasecmp(ctx->buffer, "PING", 4) == 0) {
                reply_ptr = "+PONG\r\n";
            } else if (strncasecmp(ctx->buffer, "GET", 3) == 0) {
                // Parse GET key... 
                // reply_ptr = value
            }
            
            strncpy(ctx->buffer, reply_ptr, sizeof(ctx->buffer) - 1);\n            ctx->buffer[sizeof(ctx->buffer) - 1] = '\0';
            ctx->wsa_buf.buf = ctx->buffer;
            ctx->wsa_buf.len = strlen(ctx->buffer);
            ctx->op_type = QIHSE_IOCP_WRITE;
            
            DWORD flags = 0;
            ZeroMemory(&ctx->overlapped, sizeof(WSAOVERLAPPED));
            WSASend(ctx->socket, &ctx->wsa_buf, 1, NULL, flags, &ctx->overlapped, NULL);
            
        } else if (ctx->op_type == QIHSE_IOCP_WRITE) {
            // Write completed, repost read
            ctx->wsa_buf.buf = ctx->buffer;
            ctx->wsa_buf.len = sizeof(ctx->buffer) - 1;
            ctx->op_type = QIHSE_IOCP_READ;
            DWORD flags = 0;
            ZeroMemory(&ctx->overlapped, sizeof(WSAOVERLAPPED));
            WSARecv(ctx->socket, &ctx->wsa_buf, 1, NULL, &flags, &ctx->overlapped, NULL);
        }
    }
    return 0;
}

bool qihse_start_resp_server_iocp(qihse_kv_store_t* store, qihse_vector_db_t vdb, uint16_t port, const char* bind_address) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!iocp) return false;

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    for (DWORD i = 0; i < sysinfo.dwNumberOfProcessors; i++) {
        CreateThread(NULL, 0, iocp_worker_thread, iocp, 0, NULL);
    }

    SOCKET listen_sock = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    bind(listen_sock, (struct sockaddr*)&address, sizeof(address));
    listen(listen_sock, SOMAXCONN);

    while (1) {
        SOCKET client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock == INVALID_SOCKET) continue;

        CreateIoCompletionPort((HANDLE)client_sock, iocp, (ULONG_PTR)client_sock, 0);

        qihse_iocp_ctx_t* ctx = malloc(sizeof(qihse_iocp_ctx_t));
        ZeroMemory(ctx, sizeof(qihse_iocp_ctx_t));
        ctx->socket = client_sock;
        ctx->store = store;
        ctx->vdb = vdb;
        ctx->op_type = QIHSE_IOCP_READ;
        ctx->wsa_buf.buf = ctx->buffer;
        ctx->wsa_buf.len = sizeof(ctx->buffer) - 1;

        DWORD flags = 0;
        WSARecv(client_sock, &ctx->wsa_buf, 1, NULL, &flags, &ctx->overlapped, NULL);
    }
    return true;
}
#endif
