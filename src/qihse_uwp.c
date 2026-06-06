#include "qihse_uwp.h"
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_document.h"
#include "qihse_column.h"
#include "qihse_timeseries.h"
#include "qihse_event_stream.h"

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

typedef struct {
    int client_fd;
    qihse_uwp_context_t* ctx;
} client_thread_data_t;

static void* uwp_handle_client_thread(void* arg) {
    client_thread_data_t* data = (client_thread_data_t*)arg;
    int client_fd = data->client_fd;
    qihse_uwp_context_t* ctx = data->ctx;
    free(data);

    /* Address Slowloris: apply socket timeouts */
    struct timeval tv;
    tv.tv_sec = 5;  /* 5 seconds timeout */
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

    qihse_uwp_header_t header;
    
    while (1) {
        size_t header_read = 0;
        /* Robust TCP stream read */
        while (header_read < sizeof(qihse_uwp_header_t)) {
            ssize_t r = read(client_fd, ((uint8_t*)&header) + header_read, sizeof(qihse_uwp_header_t) - header_read);
            if (r <= 0) goto cleanup;
            header_read += r;
        }

        uint64_t payload_len = le64toh(header.payload_length);
        if (payload_len > 1024 * 1024 * 100) { 
            // Reject payloads > 100MB to prevent OOM
            break;
        }

        uint8_t* payload = NULL;
        if (payload_len > 0) {
            payload = malloc(payload_len + 1);
            if (!payload) break;
            
            size_t total_read = 0;
            while (total_read < payload_len) {
                ssize_t r = read(client_fd, payload + total_read, payload_len - total_read);
                if (r <= 0) {
                    free(payload);
                    goto cleanup;
                }
                total_read += r;
            }
            payload[payload_len] = '\0'; // Safety null terminator
        }

        uwp_route_payload(client_fd, ctx, &header, payload);
        
        if (payload) {
            free(payload);
        }
    }

cleanup:
    close(client_fd);
    return NULL;
}

bool qihse_start_uwp_server(qihse_uwp_context_t* ctx, uint16_t port, const char* bind_address) {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

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

    printf("[QIHSE UWP] Multiplexer Online on %s:%d (Zero-Copy Binary Protocol)\n", 
           bind_address ? bind_address : "0.0.0.0", port);

    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        /* Spawn a thread per client to prevent one blocked connection from stalling the entire server */
        client_thread_data_t* data = malloc(sizeof(client_thread_data_t));
        if (!data) {
            close(client_fd);
            continue;
        }
        data->client_fd = client_fd;
        data->ctx = ctx;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, uwp_handle_client_thread, data) != 0) {
            perror("pthread_create");
            free(data);
            close(client_fd);
        } else {
            pthread_detach(thread_id);
        }
    }

    return true;
}
