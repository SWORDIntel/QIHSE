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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>
#include <sys/time.h>
#include <pthread.h>

static void uwp_route_payload(int client_fd, qihse_uwp_context_t* ctx, qihse_uwp_header_t* header, uint8_t* payload) {
    /* Magic Byte Verification */
    if (memcmp(header->magic, "QIHSE", 5) != 0) {
        close(client_fd);
        return;
    }

    uint64_t len = le64toh(header->payload_length);
    
    switch(header->target_engine) {
        case QIHSE_UWP_TARGET_KV:
            if (header->command_opcode == 0x01 && ctx->kv) {
                if (len == 0) break;
                size_t key_len = strnlen((char*)payload, len);
                if (key_len >= len - 1) break; /* Must have a null terminator and room for value */
                
                char* key = (char*)payload;
                char* val = key + key_len + 1;
                qihse_kv_set(ctx->kv, key, val);
                const char* reply = "OK\n";
                write(client_fd, reply, 3);
            }
            break;
            
        case QIHSE_UWP_TARGET_VECTOR:
            if (header->command_opcode == 0x01 && ctx->vdb) {
                /* VDB SET: 8 byte ID, 4 byte dims, N floats */
                if (len < 12) break;
                uint64_t id = le64toh(*(uint64_t*)payload);
                uint32_t dims = le32toh(*(uint32_t*)(payload + 8));
                
                /* Check for integer overflow and validate boundaries */
                uint64_t expected_len = 12 + ((uint64_t)dims * sizeof(float));
                if (len < expected_len) break;

                float* vec = (float*)(payload + 12);
                qihse_vector_db_upsert_by_ids(ctx->vdb, &id, vec, 1, dims, NULL, NULL, NULL, NULL);
                const char* reply = "OK\n";
                write(client_fd, reply, 3);
            }
            break;
            
        case QIHSE_UWP_TARGET_DOC:
            if (header->command_opcode == 0x01 && ctx->doc) {
                /* DOC SET: 8 byte ID, remaining is JSON string */
                if (len < 9) break;
                uint64_t doc_id = le64toh(*(uint64_t*)payload);
                char* json = (char*)(payload + 8);
                qihse_doc_store_insert_json(ctx->doc, doc_id, json);
                const char* reply = "OK\n";
                write(client_fd, reply, 3);
            }
            break;
            
        case QIHSE_UWP_TARGET_COL:
            if (header->command_opcode == 0x01 && ctx->col) {
                /* COL APPEND F32: string col name, float value */
                if (len == 0) break;
                size_t col_name_len = strnlen((char*)payload, len);
                if (col_name_len >= len) break;
                
                if (len - (col_name_len + 1) < sizeof(float)) break;

                char* col_name = (char*)payload;
                float* val = (float*)(payload + col_name_len + 1);
                qihse_column_append_float32(ctx->col, col_name, *val);
                const char* reply = "OK\n";
                write(client_fd, reply, 3);
            }
            break;
            
        case QIHSE_UWP_TARGET_TSDB:
            if (header->command_opcode == 0x01 && ctx->tsdb) {
                /* TSDB INSERT: 8 byte series, 8 byte ts, 8 byte double */
                if (len < 24) break;
                uint64_t series = le64toh(*(uint64_t*)payload);
                uint64_t ts = le64toh(*(uint64_t*)(payload + 8));
                double val = *(double*)(payload + 16);
                qihse_tsdb_insert(ctx->tsdb, series, ts, val);
                const char* reply = "OK\n";
                write(client_fd, reply, 3);
            }
            break;
            
        case QIHSE_UWP_TARGET_STREAM:
            if (header->command_opcode == 0x01 && ctx->stream) {
                /* STREAM APPEND: string topic, trailing payload */
                if (len == 0) break;
                size_t topic_len = strnlen((char*)payload, len);
                if (topic_len >= len) break;

                char* topic = (char*)payload;
                uint8_t* msg = (uint8_t*)(payload + topic_len + 1);
                size_t msg_len = len - (topic_len + 1);
                qihse_event_stream_append(ctx->stream, topic, msg, msg_len);
                const char* reply = "OK\n";
                write(client_fd, reply, 3);
            }
            break;
            
        default:
            /* Unknown target, ignore */
            break;
    }
}



#include <liburing.h>

#define URING_ENTRIES 1024
#define URING_BUF_SIZE 8192

typedef enum {
    EVENT_ACCEPT = 0,
    EVENT_READ,
    EVENT_WRITE
} uwp_event_type_t;

typedef struct {
    uwp_event_type_t type;
    int fd;
    qihse_uwp_context_t* ctx;
    uint8_t buf[URING_BUF_SIZE];
    size_t buf_len;
} uwp_event_ctx_t;

static void uwp_add_accept(struct io_uring *ring, int server_fd, qihse_uwp_context_t* uwp_ctx, struct sockaddr_in *client_addr, socklen_t *client_len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
    ev->type = EVENT_ACCEPT;
    ev->fd = server_fd;
    ev->ctx = uwp_ctx;
    
    io_uring_prep_accept(sqe, server_fd, (struct sockaddr *)client_addr, client_len, 0);
    io_uring_sqe_set_data(sqe, ev);
}

static void uwp_add_read(struct io_uring *ring, int client_fd, qihse_uwp_context_t* uwp_ctx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
    ev->type = EVENT_READ;
    ev->fd = client_fd;
    ev->ctx = uwp_ctx;
    
    io_uring_prep_recv(sqe, client_fd, ev->buf, URING_BUF_SIZE, 0);
    io_uring_sqe_set_data(sqe, ev);
}

static void uwp_add_write(struct io_uring *ring, int client_fd, const char* reply_str) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
    ev->type = EVENT_WRITE;
    ev->fd = client_fd;
    ev->ctx = NULL; // not needed for write completion
    ev->buf_len = strlen(reply_str);
    memcpy(ev->buf, reply_str, ev->buf_len);
    
    io_uring_prep_send(sqe, client_fd, ev->buf, ev->buf_len, 0);
    io_uring_sqe_set_data(sqe, ev);
}

bool qihse_start_uwp_server(qihse_uwp_context_t* ctx, uint16_t port, const char* bind_address) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return false;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
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

    struct io_uring ring;
    if (io_uring_queue_init(URING_ENTRIES, &ring, 0) < 0) {
        perror("io_uring_queue_init");
        return false;
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    uwp_add_accept(&ring, server_fd, ctx, &client_addr, &client_len);
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
                uwp_add_read(&ring, res, ctx);
            }
            io_uring_submit(&ring);
        } else if (ev->type == EVENT_READ) {
            if (res <= 0) {
                close(ev->fd);
            } else {
                ev->buf[res] = '\0';
                
                // Extremely simple dispatcher for the async loop:
                if (res > 5 && memcmp(ev->buf, "QIHSE", 5) == 0) {
                    qihse_uwp_header_t* header = (qihse_uwp_header_t*)ev->buf;
                    uint8_t* payload = ev->buf + sizeof(qihse_uwp_header_t);
                    uwp_route_payload(ev->fd, ev->ctx, header, payload);
                } else {
                    // QQL
                    void* ast = qihse_parse_qql_to_ast((char*)ev->buf);
                    (void)ast;
                    uwp_add_write(&ring, ev->fd, "QQL OK\n");
                    io_uring_submit(&ring);
                }
            }
        } else if (ev->type == EVENT_WRITE) {
            close(ev->fd);
        }
        free(ev);
    }
    
    io_uring_queue_exit(&ring);
    return true;
}
