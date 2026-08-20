#include "qihse_uwp.h"
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_document.h"
#include "qihse_column.h"
#include "qihse_timeseries.h"
#include "qihse_event_stream.h"
#include "qihse_pg_wire.h"
#include "qihse_resp_wire.h"
#include "qihse_qql_parser.h"
#ifndef _WIN32
#include <liburing.h>
#include "../networking/qihse_af_xdp.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifndef _WIN32
#include <endian.h>
#else
#include <winsock2.h>
#define le32toh(x) (x)
#define le64toh(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#include <sys/time.h>
#include "qihse_platform.h"
#ifndef _WIN32
#include <pthread.h>
#endif
#ifndef _WIN32
#include <poll.h>
#endif

static void uwp_write_all(int fd, const char* buf, size_t len) {
    if (fd < 0) return;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
#ifdef EPIPE
            if (errno == EPIPE) break;
#endif
            break;
        }
        off += (size_t)w;
    }
}

static bool uwp_route_payload(int client_fd, qihse_uwp_context_t* ctx, qihse_uwp_header_t* header, uint8_t* payload, size_t actual_payload_len, qihse_user_t** user_slot) {
    /* Magic Byte Verification */
    if (memcmp(header->magic, "QIHSE", 5) != 0) {
        if (client_fd >= 0) close(client_fd);
        return false;
    }

    uint64_t len = le64toh(header->payload_length);
    if (len > actual_payload_len) {
        if (client_fd >= 0) close(client_fd);
        return false;
    }

    if (header->target_engine == QIHSE_UWP_TARGET_AUTH && header->command_opcode == 0x01) {
        if (!ctx || len == 0 || !user_slot) return false;
        size_t username_len = strnlen((char*)payload, len);
        if (username_len >= len - 1) return false;
        char* username = (char*)payload;
        char* password = username + username_len + 1;
        size_t password_max_len = len - (username_len + 1);
        if (strnlen(password, password_max_len) == password_max_len) return false;
        *user_slot = qihse_auth_authenticate(username, password);
        if (!*user_slot) {
            const char* reply = "ERR_AUTH\n";
            uwp_write_all(client_fd, reply, strlen(reply));
            return false;
        }
        const char* reply = "OK\n";
        uwp_write_all(client_fd, reply, 3);
        return true;
    }

    qihse_user_t* current_user = (user_slot && *user_slot) ? *user_slot : NULL;
    if (!ctx || !current_user) {
        const char* reply = "ERR_AUTH\n";
        uwp_write_all(client_fd, reply, strlen(reply));
        if (client_fd >= 0) close(client_fd);
        return false;
    }
    
    switch(header->target_engine) {
        case QIHSE_UWP_TARGET_KV:
            if (header->command_opcode == 0x01 && ctx->kv) {
                if (len == 0) break;
                size_t key_len = strnlen((char*)payload, len);
                if (key_len >= len - 1) break; /* Must have a null terminator and room for value */
                
                char* key = (char*)payload;
                char* val = key + key_len + 1;
                size_t val_max_len = len - (key_len + 1);
                if (strnlen(val, val_max_len) == val_max_len) break; /* Missing null terminator for val */
                
                if (!qihse_kv_set_user(ctx->kv, key, val, 0, 0, current_user)) break;
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;
            
        case QIHSE_UWP_TARGET_VECTOR:
            if (header->command_opcode == 0x01 && ctx->vdb) {
                /* VDB SET: 8 byte ID, 4 byte dims, N floats */
                if (len < 12) break;
                uint64_t id;
                uint32_t dims;
                memcpy(&id, payload, sizeof(uint64_t));
                id = le64toh(id);
                memcpy(&dims, payload + 8, sizeof(uint32_t));
                dims = le32toh(dims);
                
                if (dims > 4096) break;
                /* Check for integer overflow and validate boundaries */
                uint64_t expected_len = 12 + ((uint64_t)dims * sizeof(float));
                if (len < expected_len) break;

                float* vec = (float*)(payload + 12);
                if (!qihse_auth_can_access(current_user, 0, 0)) break;
                qihse_vector_db_upsert_by_ids(ctx->vdb, &id, vec, 1, dims, NULL, NULL, NULL, NULL);
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;
            
        case QIHSE_UWP_TARGET_DOC:
#ifndef _WIN32
            if (header->command_opcode == 0x01 && ctx->doc) {
                /* DOC SET: 8 byte ID, remaining is JSON string */
                if (len < 9) break;
                uint64_t doc_id;
                memcpy(&doc_id, payload, sizeof(uint64_t));
                doc_id = le64toh(doc_id);
                char* json = (char*)(payload + 8);
                size_t json_max_len = (size_t)(len - 8);
                if (strnlen(json, json_max_len) == json_max_len) break; /* Missing null terminator */
                if (!qihse_auth_can_access(current_user, 0, 0)) break;
                qihse_doc_store_insert_json(ctx->doc, doc_id, json);
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
#endif
            break;
            
        case QIHSE_UWP_TARGET_COL:
#ifndef _WIN32
            if (header->command_opcode == 0x01 && ctx->col) {
                /* COL APPEND F32: string col name, float value */
                if (len == 0) break;
                size_t col_name_len = strnlen((char*)payload, len);
                if (col_name_len >= len) break;
                
                if (len - (col_name_len + 1) < sizeof(float)) break;

                char* col_name = (char*)payload;
                float fv;
                memcpy(&fv, payload + col_name_len + 1, sizeof(float));
                if (!qihse_auth_can_access(current_user, 0, 0)) break;
                qihse_column_append_float32(ctx->col, col_name, fv, 0, 0);
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
#endif
            break;
            
        case QIHSE_UWP_TARGET_TSDB:
#ifndef _WIN32
            if (header->command_opcode == 0x01 && ctx->tsdb) {
                /* TSDB INSERT: 8 byte series, 8 byte ts, 8 byte double */
                if (len < 24) break;
                uint64_t series, ts;
                memcpy(&series, payload, sizeof(uint64_t));
                series = le64toh(series);
                memcpy(&ts, payload + 8, sizeof(uint64_t));
                ts = le64toh(ts);
                double dv;
                memcpy(&dv, payload + 16, sizeof(double));
                if (!qihse_auth_can_access(current_user, 0, 0)) break;
                qihse_tsdb_insert(ctx->tsdb, series, ts, dv, 0, 0);
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
#endif
            break;
            
        case QIHSE_UWP_TARGET_STREAM:
#ifndef _WIN32
            if (header->command_opcode == 0x01 && ctx->stream) {
                /* STREAM APPEND: string topic, trailing payload */
                if (len == 0) break;
                size_t topic_len = strnlen((char*)payload, len);
                if (topic_len >= len) break;

                char* topic = (char*)payload;
                uint8_t* msg = (uint8_t*)(payload + topic_len + 1);
                size_t msg_len = len - (topic_len + 1);
                if (!qihse_auth_can_access(current_user, 0, 0)) break;
                qihse_event_stream_append(ctx->stream, topic, msg, msg_len);
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
#endif
            break;

        /* ---- New UWP targets (stub dispatch infrastructure) ---- */
        case QIHSE_UWP_TARGET_SQL:
            /* 0x01=PARSE 0x02=EXECUTE 0x03=BIND 0x04=DESCRIBE 0x05=CLOSE */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x05) {
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;

        case QIHSE_UWP_TARGET_TXN:
            /* 0x01=BEGIN 0x02=COMMIT 0x03=ROLLBACK 0x04=SAVEPOINT 0x05=ROLLBACK_TO_SAVEPOINT */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x05) {
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;

        case QIHSE_UWP_TARGET_GRAPH2:
            /* 0x01=MATCH 0x02=CREATE 0x03=MERGE 0x04=DELETE 0x05=SET 0x06=REMOVE 0x10=ALGO */
            if ((header->command_opcode >= 0x01 && header->command_opcode <= 0x06) ||
                header->command_opcode == 0x10) {
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;

        case QIHSE_UWP_TARGET_INDEX:
            /* 0x01=CREATE_INDEX 0x02=SCAN 0x03=INSERT 0x04=BULK_LOAD 0x05=DROP */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x05) {
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;

        case QIHSE_UWP_TARGET_SCHEMA:
            /* 0x01=CREATE_TABLE 0x02=DROP_TABLE 0x03=ALTER_TABLE 0x04=GET_TABLE
             * 0x05=CREATE_INDEX 0x06=DROP_INDEX */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x06) {
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;

        case QIHSE_UWP_TARGET_REPL:
            /* 0x01=APPEND_WAL 0x02=SHIP_WAL 0x03=SYNC_REPLICA 0x04=STATUS */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x04) {
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;

        case QIHSE_UWP_TARGET_POOL:
            /* 0x01=ACQUIRE 0x02=RELEASE 0x03=STATS */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x03) {
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
            }
            break;

        default:
            /* Unknown target, ignore */
            break;
    }
    return false;
}

/* In-process UWP dispatcher used by protocol translation layers and Bolt server.
 * Executes a UWP packet without a socket and writes the textual reply into
 * out_response (a simple "OK\n" stub for now). Returns true on success. */
bool qihse_uwp_dispatch(qihse_uwp_context_t* ctx, const qihse_uwp_header_t* header,
                        const uint8_t* payload, size_t payload_len,
                        uint8_t* out_response, size_t out_cap, size_t* out_len) {
    if (!ctx || !header) return false;
    if (memcmp(header->magic, "QIHSE", 5) != 0) return false;
    uint64_t plen = le64toh(header->payload_length);
    if (plen > payload_len) return false;

    /* Validate target is in the known set */
    uint8_t t = header->target_engine;
    bool known = (t <= QIHSE_UWP_TARGET_STREAM) ||
                 (t == QIHSE_UWP_TARGET_SQL) || (t == QIHSE_UWP_TARGET_TXN) ||
                 (t == QIHSE_UWP_TARGET_GRAPH2) || (t == QIHSE_UWP_TARGET_INDEX) ||
                 (t == QIHSE_UWP_TARGET_SCHEMA) || (t == QIHSE_UWP_TARGET_REPL) ||
                 (t == QIHSE_UWP_TARGET_POOL);
    if (!known) return false;

    /* Stub: produce an "OK\n" response for any valid command opcode */
    if (out_response && out_cap >= 3) {
        memcpy(out_response, "OK\n", 3);
        if (out_len) *out_len = 3;
    } else if (out_len) {
        *out_len = 0;
    }
    (void)payload;
    return true;
}

void qihse_uwp_handle_payload(qihse_uwp_context_t* ctx, const uint8_t* payload_data, size_t len) {
    if (len < sizeof(qihse_uwp_header_t)) return;
    qihse_uwp_header_t* header = (qihse_uwp_header_t*)payload_data;
    uint8_t* payload = (uint8_t*)payload_data + sizeof(qihse_uwp_header_t);
    uwp_route_payload(-1, ctx, header, payload, len - sizeof(qihse_uwp_header_t), NULL);
}

#ifndef _WIN32
#include <liburing.h>
#endif

#define URING_ENTRIES 1024
#define URING_BUF_SIZE 8192

typedef enum {
    EVENT_ACCEPT = 0,
    EVENT_READ,
    EVENT_WRITE,
    EVENT_XDP_POLL
} uwp_event_type_t;

typedef struct {
    uwp_event_type_t type;
    int fd;
    qihse_uwp_context_t* ctx;
    qihse_user_t* user;
    uint8_t buf[URING_BUF_SIZE];
    size_t buf_len;
} uwp_event_ctx_t;

#ifndef _WIN32
static void uwp_add_accept(struct io_uring *ring, int server_fd, qihse_uwp_context_t* uwp_ctx, struct sockaddr_in *client_addr, socklen_t *client_len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
    if (!ev) return;
    ev->type = EVENT_ACCEPT;
    ev->fd = server_fd;
    ev->ctx = uwp_ctx;
    ev->user = NULL;
    
    io_uring_prep_accept(sqe, server_fd, (struct sockaddr *)client_addr, client_len, 0);
    io_uring_sqe_set_data(sqe, ev);
}

static void uwp_add_read(struct io_uring *ring, int client_fd, qihse_uwp_context_t* uwp_ctx, qihse_user_t* user) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
    if (!ev) return;
    ev->type = EVENT_READ;
    ev->fd = client_fd;
    ev->ctx = uwp_ctx;
    ev->user = user;
    
    io_uring_prep_recv(sqe, client_fd, ev->buf, URING_BUF_SIZE, 0);
    io_uring_sqe_set_data(sqe, ev);
}

static void uwp_add_write(struct io_uring *ring, int client_fd, const char* reply_str) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
    if (!ev) return;
    ev->type = EVENT_WRITE;
    ev->fd = client_fd;
    ev->ctx = NULL; // not needed for write completion
    ev->user = NULL;
    ev->buf_len = strlen(reply_str);
    memcpy(ev->buf, reply_str, ev->buf_len);
    
    io_uring_prep_send(sqe, client_fd, ev->buf, ev->buf_len, MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, ev);
}
#endif

bool qihse_start_uwp_server(qihse_uwp_context_t* ctx, uint16_t port, const char* bind_address) {
    if (qihse_auth_is_operator_password_default()) {
        fprintf(stderr, "[FATAL SECURITY ERROR] Default operator password detected. "
                        "You must rotate the default operator password before starting network services.\n");
        return false;
    }

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return false;
    }

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
    if (bind_address && bind_address[0] != '\0') {
        address.sin_addr.s_addr = inet_addr(bind_address);
    } else {
        address.sin_addr.s_addr = INADDR_ANY;
    }
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return false;
    }

    if (listen(server_fd, 1000) < 0) {
        perror("listen");
        close(server_fd);
        return false;
    }

    printf("[QIHSE UWP] Multiplexer Online on %s:%d (Zero-Copy io_uring Network Engine)\n", 
           bind_address ? bind_address : "0.0.0.0", port);

#ifndef _WIN32
    struct io_uring ring;
    if (io_uring_queue_init(URING_ENTRIES, &ring, 0) < 0) {
        perror("io_uring_queue_init");
        return false;
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    uwp_add_accept(&ring, server_fd, ctx, &client_addr, &client_len);
    
    struct qihse_af_xdp_ctx *xdp_ctx = NULL;
    const char *xdp_iface = getenv("QIHSE_XDP_IFACE");
    if (xdp_iface) {
        xdp_ctx = qihse_af_xdp_init(xdp_iface);
        if (xdp_ctx) {
            int xdp_fd = qihse_af_xdp_get_fd(xdp_ctx);
            if (xdp_fd >= 0) {
                struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
                uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
                if (!ev) {
                    fprintf(stderr, "[QIHSE UWP] malloc failed for XDP event ctx\n");
                }
                if (ev) {
                    ev->type = EVENT_XDP_POLL;
                    ev->fd = xdp_fd;
                    ev->ctx = ctx;
                    io_uring_prep_poll_add(sqe, xdp_fd, POLLIN);
                    io_uring_sqe_set_data(sqe, ev);
                    printf("[QIHSE UWP] AF_XDP socket registered in io_uring for %s\n", xdp_iface);
                }
            }
        }
    }

    io_uring_submit(&ring);

    while (1) {
        struct io_uring_cqe *cqe;
        int ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            perror("io_uring_wait_cqe");
            break;
        }

        uwp_event_ctx_t *ev = (uwp_event_ctx_t *)io_uring_cqe_get_data(cqe);
        int res = cqe->res;
        io_uring_cqe_seen(&ring, cqe);

        if (ev->type == EVENT_ACCEPT) {
            uwp_add_accept(&ring, server_fd, ctx, &client_addr, &client_len);
            if (res >= 0) {
                struct timeval tv;
                tv.tv_sec = 30;
                tv.tv_usec = 0;
                setsockopt(res, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(res, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                uwp_add_read(&ring, res, ctx, NULL);
            }
            io_uring_submit(&ring);
        } else if (ev->type == EVENT_READ) {
            if (res <= 0) {
                close(ev->fd);
            } else {
                if (res >= (int)sizeof(ev->buf)) {
                    close(ev->fd);
                    free(ev);
                    continue;
                }
                ev->buf[res] = '\0';
                
                // Extremely simple dispatcher for the async loop:
                if (res >= (int)sizeof(qihse_uwp_header_t) && memcmp(ev->buf, "QIHSE", 5) == 0) {
                    qihse_uwp_header_t* header = (qihse_uwp_header_t*)ev->buf;
                    uint64_t expected_len = le64toh(header->payload_length);
                    if (res >= (int)(sizeof(qihse_uwp_header_t) + expected_len)) {
                        uint8_t* payload = ev->buf + sizeof(qihse_uwp_header_t);
                        if (uwp_route_payload(ev->fd, ev->ctx, header, payload, res - sizeof(qihse_uwp_header_t), &ev->user)) {
                            uwp_add_read(&ring, ev->fd, ev->ctx, ev->user);
                            io_uring_submit(&ring);
                        } else {
                            close(ev->fd);
                        }
                    } else {
                        uwp_add_write(&ring, ev->fd, "ERR_SHORT\n");
                        io_uring_submit(&ring);
                    }
                } else {
                    // QQL
#ifndef _WIN32
                    void* ast = qihse_parse_qql_to_ast((char*)ev->buf);
                    (void)ast;
#endif
                    uwp_add_write(&ring, ev->fd, "QQL OK\n");
                    io_uring_submit(&ring);
                }
            }
        } else if (ev->type == EVENT_WRITE) {
            close(ev->fd);
        } else if (ev->type == EVENT_XDP_POLL) {
            if (xdp_ctx) {
                qihse_af_xdp_poll(xdp_ctx, NULL, NULL);
            }
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            io_uring_prep_poll_add(sqe, ev->fd, POLLIN);
            io_uring_sqe_set_data(sqe, ev);
            io_uring_submit(&ring);
            continue;
        }
        free(ev);
    }
    
    io_uring_queue_exit(&ring);
    if (xdp_ctx && xdp_iface) {
        qihse_af_xdp_teardown(xdp_ctx, xdp_iface);
    }
#else
    // Windows Fallback loop
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buf[8192];
    
    while(1) {
        SOCKET client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock == INVALID_SOCKET) continue;
        
        int res = recv(client_sock, buf, sizeof(buf) - 1, 0);
        if (res > 0) {
            buf[res] = '\0';
            if (res >= (int)sizeof(qihse_uwp_header_t) && memcmp(buf, "QIHSE", 5) == 0) {
                qihse_uwp_header_t* header = (qihse_uwp_header_t*)buf;
                uint64_t expected_len = le64toh(header->payload_length);
                if (res >= (int)(sizeof(qihse_uwp_header_t) + expected_len)) {
                    uint8_t* payload = (uint8_t*)buf + sizeof(qihse_uwp_header_t);
                    qihse_user_t* current_user = NULL;
                    uwp_route_payload(client_sock, ctx, header, payload, res - sizeof(qihse_uwp_header_t), &current_user);
                } else {
                    send(client_sock, "ERR_SHORT\n", 10, MSG_NOSIGNAL);
                }
            } else {
#ifndef _WIN32
                void* ast = qihse_parse_qql_to_ast(buf);
                (void)ast;
#endif
                send(client_sock, "QQL OK\n", 7, MSG_NOSIGNAL);
            }
        }
        closesocket(client_sock);
    }
#endif
    return true;
}
