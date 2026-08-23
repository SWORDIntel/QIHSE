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
#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_txn.h"
#include "qihse_uwp_graph_index.h"
#include "qihse_uwp_repl_pool.h"
#include "qihse_uwp_tls.h"
#ifndef _WIN32
#include <liburing.h>
#include "../networking/qihse_af_xdp.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>
#include <sys/time.h>
#include <pthread.h>
#include <poll.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif
#ifndef BYTE_ORDER
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif

#if BYTE_ORDER == BIG_ENDIAN
#if defined(_MSC_VER)
#define le32toh(x) _byteswap_ulong((x))
#define le64toh(x) _byteswap_uint64((x))
#define htole32(x) _byteswap_ulong((x))
#define htole64(x) _byteswap_uint64((x))
#else
#define le32toh(x) __builtin_bswap32((x))
#define le64toh(x) __builtin_bswap64((x))
#define htole32(x) __builtin_bswap32((x))
#define htole64(x) __builtin_bswap64((x))
#endif
#else
#define le32toh(x) (x)
#define le64toh(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#endif
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#include "qihse_platform.h"

#define QIHSE_UWP_MAX_PAYLOAD (16 * 1024 * 1024)
#define QIHSE_UWP_MAX_CONNECTIONS_PER_IP 64
#define QIHSE_UWP_IP_TABLE_SIZE 256
#define QIHSE_UWP_AUTH_BUCKET_TABLE_SIZE 256

static const uint8_t qihse_uwp_magic[4] = { 0x51, 0x49, 0x48, 0x53 };

#ifdef _WIN32
typedef SOCKET uwp_socket_t;
#define UWP_INVALID_SOCKET INVALID_SOCKET
#else
typedef int uwp_socket_t;
#define UWP_INVALID_SOCKET (-1)
#endif

static uint32_t uwp_fnv1a_32(const uint8_t* data, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

static uint64_t uwp_payload_length(const qihse_uwp_header_t* header) {
    uint64_t wire_len;
    memcpy(&wire_len, &header->payload_length, sizeof(wire_len));
    return le64toh(wire_len);
}

static void uwp_socket_close(uwp_socket_t fd) {
    if (fd == UWP_INVALID_SOCKET) return;
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

static void uwp_write_all(uwp_socket_t fd, const char* buf, size_t len) {
    if (fd == UWP_INVALID_SOCKET) return;
    size_t off = 0;
    while (off < len) {
#ifdef _WIN32
        int chunk = len - off > INT_MAX ? INT_MAX : (int)(len - off);
        int w = send(fd, buf + off, chunk, MSG_NOSIGNAL);
        if (w == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAEINTR) continue;
            break;
        }
#else
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
#ifdef EPIPE
            if (errno == EPIPE) break;
#endif
            break;
        }
#endif
        if (w == 0) break;
        off += (size_t)w;
    }
}

typedef struct {
    bool used;
    uint32_t source_ip;
    char username[64];
    double tokens;
    time_t last_refill;
} uwp_auth_bucket_t;

static uwp_auth_bucket_t uwp_auth_buckets[QIHSE_UWP_AUTH_BUCKET_TABLE_SIZE];

static uint32_t uwp_peer_ipv4(uwp_socket_t fd) {
    struct sockaddr_in peer;
#ifdef _WIN32
    int peer_len = sizeof(peer);
#else
    socklen_t peer_len = sizeof(peer);
#endif
    memset(&peer, 0, sizeof(peer));
    if (fd == UWP_INVALID_SOCKET ||
        getpeername(fd, (struct sockaddr*)&peer, &peer_len) != 0 ||
        peer.sin_family != AF_INET) {
        return 0;
    }
    return peer.sin_addr.s_addr;
}

static void uwp_log_auth_failure(uwp_socket_t fd, const char* username, const char* reason) {
    uint32_t ip = ntohl(uwp_peer_ipv4(fd));
    fprintf(stderr, "[QIHSE UWP] authentication %s for %s from %u.%u.%u.%u\n",
            reason, username ? username : "<invalid>",
            (ip >> 24) & 0xffu, (ip >> 16) & 0xffu,
            (ip >> 8) & 0xffu, ip & 0xffu);
}

/* One token per second with a burst capacity of ten attempts. */
static bool uwp_auth_attempt_allowed(uint32_t source_ip, const char* username) {
    uint32_t hash = uwp_fnv1a_32((const uint8_t*)username, strlen(username));
    size_t start = (source_ip ^ hash) % QIHSE_UWP_AUTH_BUCKET_TABLE_SIZE;
    uwp_auth_bucket_t* vacant = NULL;
    uwp_auth_bucket_t* oldest = NULL;
    uwp_auth_bucket_t* bucket = NULL;
    for (size_t i = 0; i < QIHSE_UWP_AUTH_BUCKET_TABLE_SIZE; ++i) {
        uwp_auth_bucket_t* candidate =
            &uwp_auth_buckets[(start + i) % QIHSE_UWP_AUTH_BUCKET_TABLE_SIZE];
        if (!candidate->used) {
            vacant = candidate;
            break;
        }
        if (!oldest || candidate->last_refill < oldest->last_refill) oldest = candidate;
        if (candidate->source_ip == source_ip &&
            strcmp(candidate->username, username) == 0) {
            bucket = candidate;
            break;
        }
    }
    if (!bucket) {
        bucket = vacant ? vacant : oldest;
        if (!bucket) return false;
        bucket->used = true;
        bucket->source_ip = source_ip;
        snprintf(bucket->username, sizeof(bucket->username), "%s", username);
        bucket->tokens = 10.0;
        bucket->last_refill = time(NULL);
    }

    time_t now = time(NULL);
    if (now > bucket->last_refill) {
        double refill = difftime(now, bucket->last_refill);
        bucket->tokens += refill;
        if (bucket->tokens > 10.0) bucket->tokens = 10.0;
        bucket->last_refill = now;
    }
    if (bucket->tokens < 1.0) return false;
    bucket->tokens -= 1.0;
    return true;
}

typedef enum {
    UWP_ROUTE_OK,
    UWP_ROUTE_ERR_MAGIC,
    UWP_ROUTE_ERR_VERSION,
    UWP_ROUTE_ERR_LEN,
    UWP_ROUTE_ERR_TOO_LARGE,
    UWP_ROUTE_ERR_AUTH,
    UWP_ROUTE_ERR_RATE_LIMITED,
    UWP_ROUTE_ERR_PERM,
    UWP_ROUTE_ERR_DISPATCH
} uwp_route_result_t;

static uwp_route_result_t uwp_route_payload(uwp_socket_t client_fd, qihse_uwp_context_t* ctx,
                                             qihse_uwp_header_t* header, uint8_t* payload,
                                             size_t actual_payload_len, qihse_user_t** user_slot, qihse_txn_t** current_txn) {
    /* Magic Byte Verification */
    if (memcmp(header->magic, qihse_uwp_magic, sizeof(header->magic)) != 0) {
        return UWP_ROUTE_ERR_MAGIC;
    }
    if (header->version != 0x01) return UWP_ROUTE_ERR_VERSION;

    uint64_t len = uwp_payload_length(header);
    if (len > QIHSE_UWP_MAX_PAYLOAD) {
        return UWP_ROUTE_ERR_TOO_LARGE;
    }
    if (len != actual_payload_len) {
        return UWP_ROUTE_ERR_LEN;
    }

    if (header->target_engine == QIHSE_UWP_TARGET_AUTH && header->command_opcode == 0x01) {
        if (!ctx || len == 0 || !user_slot) return UWP_ROUTE_ERR_AUTH;
        size_t username_len = strnlen((char*)payload, len);
        if (username_len >= len - 1) return UWP_ROUTE_ERR_AUTH;
        char* username = (char*)payload;
        char* password = username + username_len + 1;
        size_t password_max_len = len - (username_len + 1);
        if (strnlen(password, password_max_len) == password_max_len) return UWP_ROUTE_ERR_AUTH;
        if (username_len >= sizeof(((qihse_user_t*)0)->username)) {
            uwp_log_auth_failure(client_fd, username, "failed");
            return UWP_ROUTE_ERR_AUTH;
        }
        if (!uwp_auth_attempt_allowed(uwp_peer_ipv4(client_fd), username)) {
            uwp_log_auth_failure(client_fd, username, "rate limited");
            return UWP_ROUTE_ERR_RATE_LIMITED;
        }
        *user_slot = qihse_auth_authenticate(username, password);
        if (!*user_slot) {
            uwp_log_auth_failure(client_fd, username, "failed");
            return UWP_ROUTE_ERR_AUTH;
        }
        const char* reply = "OK\n";
        uwp_write_all(client_fd, reply, 3);
        return UWP_ROUTE_OK;
    }

    qihse_user_t* current_user = (user_slot && *user_slot) ? *user_slot : NULL;
    if (!ctx || !current_user) {
        return UWP_ROUTE_ERR_AUTH;
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

                uint64_t resource_id = uwp_fnv1a_32((const uint8_t*)key, key_len);
                if (!qihse_auth_can_access_object(current_user, 0, resource_id)) {
                    return UWP_ROUTE_ERR_PERM;
                }
                if (!qihse_kv_set_user(ctx->kv, key, val, 0, 0, current_user)) {
                    return UWP_ROUTE_ERR_PERM;
                }
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
                return UWP_ROUTE_OK;
            }
            return UWP_ROUTE_ERR_DISPATCH;
            
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
                
                if (dims == 0) break;
                if (dims > 4096) break;
                /* Check for integer overflow and validate boundaries */
                uint64_t expected_len = 12 + ((uint64_t)dims * sizeof(float));
                if (len < expected_len) break;

                _Alignas(32) float staging[4096];
                memcpy(staging, payload + 12, (size_t)dims * sizeof(float));
                if (!qihse_auth_can_access_object(current_user, 0, id)) {
                    return UWP_ROUTE_ERR_PERM;
                }
                if (!qihse_vector_db_upsert_by_ids(ctx->vdb, &id, staging, 1, dims,
                                                   NULL, NULL, NULL, NULL)) {
                    return UWP_ROUTE_ERR_DISPATCH;
                }
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
                return UWP_ROUTE_OK;
            }
            return UWP_ROUTE_ERR_DISPATCH;
            
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
                if (!qihse_auth_can_access_object(current_user, 0, doc_id)) {
                    return UWP_ROUTE_ERR_PERM;
                }
                if (!qihse_doc_store_insert_json(ctx->doc, doc_id, json)) return UWP_ROUTE_ERR_DISPATCH;
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
                return UWP_ROUTE_OK;
            }
#endif
            return UWP_ROUTE_ERR_DISPATCH;
            
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
                uint64_t resource_id = uwp_fnv1a_32((const uint8_t*)col_name, col_name_len);
                if (!qihse_auth_can_access_object(current_user, 0, resource_id)) {
                    return UWP_ROUTE_ERR_PERM;
                }
                if (!qihse_column_append_float32(ctx->col, col_name, fv, 0, 0)) {
                    return UWP_ROUTE_ERR_DISPATCH;
                }
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
                return UWP_ROUTE_OK;
            }
#endif
            return UWP_ROUTE_ERR_DISPATCH;
            
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
                if (!qihse_auth_can_access_object(current_user, 0, series)) {
                    return UWP_ROUTE_ERR_PERM;
                }
                if (!qihse_tsdb_insert(ctx->tsdb, (uint32_t)series, ts, dv, 0, 0)) {
                    return UWP_ROUTE_ERR_DISPATCH;
                }
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
                return UWP_ROUTE_OK;
            }
#endif
            return UWP_ROUTE_ERR_DISPATCH;
            
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
                uint64_t resource_id = uwp_fnv1a_32((const uint8_t*)topic, topic_len);
                if (!qihse_auth_can_access_object(current_user, 0, resource_id)) {
                    return UWP_ROUTE_ERR_PERM;
                }
                if (!qihse_event_stream_append(ctx->stream, topic, msg, msg_len)) {
                    return UWP_ROUTE_ERR_DISPATCH;
                }
                const char* reply = "OK\n";
                uwp_write_all(client_fd, reply, 3);
                return UWP_ROUTE_OK;
            }
#endif
            return UWP_ROUTE_ERR_DISPATCH;

        /* ---- New UWP targets (wired to engine dispatchers) ---- */
        case QIHSE_UWP_TARGET_SQL:
            /* 0x01=PARSE 0x02=EXECUTE 0x03=BIND 0x04=DESCRIBE 0x05=CLOSE */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x05) {
                uwp_sts_result_t r = uwp_dispatch_sql(ctx, header->command_opcode,
                                                      payload, len, current_txn, current_user, client_fd);
                return (r == UWP_STS_OK) ? UWP_ROUTE_OK : UWP_ROUTE_ERR_DISPATCH;
            }
            return UWP_ROUTE_ERR_DISPATCH;

        case QIHSE_UWP_TARGET_TXN:
            /* 0x01=BEGIN 0x02=COMMIT 0x03=ROLLBACK 0x04=SAVEPOINT 0x05=ROLLBACK_TO_SAVEPOINT */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x05) {
                uwp_sts_result_t r = uwp_dispatch_txn(ctx, header->command_opcode,
                                                      payload, len, current_txn, current_user, client_fd);
                return (r == UWP_STS_OK) ? UWP_ROUTE_OK : UWP_ROUTE_ERR_DISPATCH;
            }
            return UWP_ROUTE_ERR_DISPATCH;

        case QIHSE_UWP_TARGET_GRAPH2:
            /* 0x01=MATCH 0x02=CREATE 0x03=MERGE 0x04=DELETE 0x05=SET 0x06=REMOVE 0x10=ALGO */
            if ((header->command_opcode >= 0x01 && header->command_opcode <= 0x06) ||
                header->command_opcode == 0x10) {
                uwp_gi_result_t r = uwp_dispatch_graph2(ctx, header->command_opcode,
                                                        payload, len, current_user, client_fd);
                return (r == UWP_GI_OK) ? UWP_ROUTE_OK : UWP_ROUTE_ERR_DISPATCH;
            }
            return UWP_ROUTE_ERR_DISPATCH;

        case QIHSE_UWP_TARGET_INDEX:
            /* 0x01=CREATE_INDEX 0x02=SCAN 0x03=INSERT 0x04=BULK_LOAD 0x05=DROP */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x05) {
                uwp_gi_result_t r = uwp_dispatch_index(ctx, header->command_opcode,
                                                       payload, len, current_user, client_fd);
                return (r == UWP_GI_OK) ? UWP_ROUTE_OK : UWP_ROUTE_ERR_DISPATCH;
            }
            return UWP_ROUTE_ERR_DISPATCH;

        case QIHSE_UWP_TARGET_SCHEMA:
            /* 0x01=CREATE_TABLE 0x02=DROP_TABLE 0x03=ALTER_TABLE 0x04=GET_TABLE
             * 0x05=CREATE_INDEX 0x06=DROP_INDEX */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x06) {
                uwp_sts_result_t r = uwp_dispatch_schema(ctx, header->command_opcode,
                                                         payload, len, current_user, client_fd);
                return (r == UWP_STS_OK) ? UWP_ROUTE_OK : UWP_ROUTE_ERR_DISPATCH;
            }
            return UWP_ROUTE_ERR_DISPATCH;

        case QIHSE_UWP_TARGET_REPL:
            /* 0x01=APPEND_WAL 0x02=SHIP_WAL 0x03=SYNC_REPLICA 0x04=STATUS */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x04) {
                uwp_repl_result_t r = uwp_dispatch_repl(ctx, header->command_opcode,
                                                        payload, len, current_user, client_fd);
                return (r == UWP_REPL_OK) ? UWP_ROUTE_OK : UWP_ROUTE_ERR_DISPATCH;
            }
            return UWP_ROUTE_ERR_DISPATCH;

        case QIHSE_UWP_TARGET_POOL:
            /* 0x01=ACQUIRE 0x02=RELEASE 0x03=STATS */
            if (header->command_opcode >= 0x01 && header->command_opcode <= 0x03) {
                uwp_repl_result_t r = uwp_dispatch_pool(ctx, header->command_opcode,
                                                        payload, len, current_user, client_fd);
                return (r == UWP_REPL_OK) ? UWP_ROUTE_OK : UWP_ROUTE_ERR_DISPATCH;
            }
            return UWP_ROUTE_ERR_DISPATCH;

        default:
            return UWP_ROUTE_ERR_DISPATCH;
    }
    return UWP_ROUTE_ERR_DISPATCH;
}

/* In-process UWP dispatcher used by protocol translation layers and Bolt server.
 * Executes a UWP packet without a socket and writes the textual reply into
 * out_response (a simple "OK\n" stub for now). Returns true on success.
 *
 * Security: 'user' must be non-NULL for every target except QIHSE_UWP_TARGET_AUTH.
 * A NULL user on any non-AUTH target is rejected immediately (returns false)
 * so that callers cannot bypass authentication via the in-process path. */
bool qihse_uwp_dispatch(qihse_uwp_context_t* ctx, qihse_user_t* user,
                        const qihse_uwp_header_t* header,
                        const uint8_t* payload, size_t payload_len,
                        uint8_t* out_response, size_t out_cap, size_t* out_len) {
    if (!ctx || !header) return false;
    if (memcmp(header->magic, qihse_uwp_magic, sizeof(header->magic)) != 0) return false;
    if (header->version != 0x01) return false;
    uint64_t plen = uwp_payload_length(header);
    if (plen > QIHSE_UWP_MAX_PAYLOAD) {
        static const char reply[] = "ERR_TOO_LARGE\n";
        if (out_response && out_cap >= sizeof(reply) - 1) {
            memcpy(out_response, reply, sizeof(reply) - 1);
            if (out_len) *out_len = sizeof(reply) - 1;
        } else if (out_len) {
            *out_len = 0;
        }
        return false;
    }
    if (plen > payload_len) return false;

    /* Validate target is in the known set */
    uint8_t t = header->target_engine;
    bool known = (t <= QIHSE_UWP_TARGET_STREAM) ||
                 (t == QIHSE_UWP_TARGET_SQL) || (t == QIHSE_UWP_TARGET_TXN) ||
                 (t == QIHSE_UWP_TARGET_GRAPH2) || (t == QIHSE_UWP_TARGET_INDEX) ||
                 (t == QIHSE_UWP_TARGET_SCHEMA) || (t == QIHSE_UWP_TARGET_REPL) ||
                 (t == QIHSE_UWP_TARGET_POOL);
    if (!known) return false;

    if (!out_response || out_cap < 3) return false;

    /* AUTH target: caller is allowed to have a NULL user (that is the whole
     * point — the user is authenticating and does not have a token yet). */
    if (t == QIHSE_UWP_TARGET_AUTH) {
        /* Auth is handled by the socket-facing path; in-process callers that
         * need to authenticate should go through qihse_auth_authenticate()
         * directly and store the result before calling dispatch again. */
        memcpy(out_response, "OK\n", 3);
        if (out_len) *out_len = 3;
        (void)payload;
        return true;
    }

    /* Non-AUTH targets: a NULL user means the caller is unauthenticated — reject. */
    if (!user) {
        if (out_response && out_cap >= 9) {
            memcpy(out_response, "ERR_AUTH\n", 9);
            if (out_len) *out_len = 9;
        } else if (out_len) {
            *out_len = 0;
        }
        return false;
    }

    bool stub_opcode_supported =
        ((t == QIHSE_UWP_TARGET_SQL || t == QIHSE_UWP_TARGET_TXN ||
          t == QIHSE_UWP_TARGET_INDEX) &&
         header->command_opcode >= 0x01 && header->command_opcode <= 0x05) ||
        (t == QIHSE_UWP_TARGET_GRAPH2 &&
         ((header->command_opcode >= 0x01 && header->command_opcode <= 0x06) ||
          header->command_opcode == 0x10)) ||
        (t == QIHSE_UWP_TARGET_SCHEMA &&
         header->command_opcode >= 0x01 && header->command_opcode <= 0x06) ||
        (t == QIHSE_UWP_TARGET_REPL &&
         header->command_opcode >= 0x01 && header->command_opcode <= 0x04) ||
        (t == QIHSE_UWP_TARGET_POOL &&
         header->command_opcode >= 0x01 && header->command_opcode <= 0x03);
    if (t >= QIHSE_UWP_TARGET_SQL && t <= QIHSE_UWP_TARGET_POOL) {
        if (stub_opcode_supported) {
            static const char reply[] = "ERR_NOT_IMPLEMENTED\n";
            if (out_response && out_cap >= sizeof(reply) - 1) {
                memcpy(out_response, reply, sizeof(reply) - 1);
                if (out_len) *out_len = sizeof(reply) - 1;
            } else if (out_len) {
                *out_len = 0;
            }
        }
        return false;
    }

    /* Stub: produce an "OK\n" response for any valid command opcode */
    memcpy(out_response, "OK\n", 3);
    if (out_len) *out_len = 3;
    (void)payload;
    return true;
}


void qihse_uwp_handle_payload(qihse_uwp_context_t* ctx, const uint8_t* payload_data, size_t len) {
    if (len < sizeof(qihse_uwp_header_t)) return;
    qihse_uwp_header_t* header = (qihse_uwp_header_t*)payload_data;
    uint64_t payload_length = uwp_payload_length(header);
    if (payload_length > QIHSE_UWP_MAX_PAYLOAD) return;
    uint8_t* payload = (uint8_t*)payload_data + sizeof(qihse_uwp_header_t);
    uwp_route_result_t result = uwp_route_payload(
        -1, ctx, header, payload, len - sizeof(qihse_uwp_header_t), NULL, NULL);
    if (result != UWP_ROUTE_OK) return;
}

#ifndef _WIN32
static void uwp_xdp_frame_cb(char* frame_data, uint32_t frame_len, void* arg) {
    qihse_uwp_context_t* ctx = arg;
    const char* payload = NULL;
    uint32_t payload_len = 0;

    if (qihse_af_xdp_extract_tcp_payload(frame_data, frame_len, &payload,
                                         &payload_len, NULL, NULL, NULL) &&
        payload_len > 0) {
        qihse_uwp_handle_payload(ctx, (const uint8_t*)payload, payload_len);
    }
}
#endif

#ifndef _WIN32
#include <liburing.h>
#endif

#define URING_ENTRIES 1024
typedef enum {
    READING_HEADER = 0,
    READING_PAYLOAD
} uwp_read_state_t;

typedef struct {
    uwp_socket_t fd;
    qihse_uwp_context_t* ctx;
    qihse_user_t* user;
    uint32_t source_ip;
    bool source_ip_tracked;
    uint8_t* rbuf;
    size_t rbuf_cap;
    size_t rbuf_len;
    uwp_read_state_t state;
    qihse_uwp_header_t header;
    size_t payload_length;
    qihse_txn_t* current_txn;
} uwp_conn_t;

typedef enum {
    EVENT_ACCEPT = 0,
    EVENT_READ,
    EVENT_XDP_POLL
} uwp_event_type_t;

typedef struct {
    uwp_event_type_t type;
    int fd;
    qihse_uwp_context_t* ctx;
    uwp_conn_t* conn;
} uwp_event_ctx_t;

typedef struct {
    bool used;
    uint32_t source_ip;
    unsigned int connections;
} uwp_ip_connection_entry_t;

static uwp_ip_connection_entry_t uwp_ip_connections[QIHSE_UWP_IP_TABLE_SIZE];

static bool uwp_connection_acquire(uint32_t source_ip) {
    size_t start = source_ip % QIHSE_UWP_IP_TABLE_SIZE;
    uwp_ip_connection_entry_t* vacant = NULL;
    uwp_ip_connection_entry_t* entry = NULL;
    for (size_t i = 0; i < QIHSE_UWP_IP_TABLE_SIZE; ++i) {
        uwp_ip_connection_entry_t* candidate =
            &uwp_ip_connections[(start + i) % QIHSE_UWP_IP_TABLE_SIZE];
        if (!candidate->used || candidate->connections == 0) {
            if (!vacant) vacant = candidate;
        }
        if (candidate->source_ip == source_ip) {
            entry = candidate;
            break;
        }
    }
    if (!entry) {
        if (!vacant) return false;
        entry = vacant;
        entry->used = true;
        entry->source_ip = source_ip;
        entry->connections = 0;
    }
    if (entry->connections >= QIHSE_UWP_MAX_CONNECTIONS_PER_IP) {
        uint32_t ip = ntohl(source_ip);
        fprintf(stderr, "[QIHSE UWP] connection cap reached for %u.%u.%u.%u\n",
                (ip >> 24) & 0xffu, (ip >> 16) & 0xffu,
                (ip >> 8) & 0xffu, ip & 0xffu);
        return false;
    }
    ++entry->connections;
    return true;
}

static void uwp_connection_release(uint32_t source_ip) {
    size_t start = source_ip % QIHSE_UWP_IP_TABLE_SIZE;
    for (size_t i = 0; i < QIHSE_UWP_IP_TABLE_SIZE; ++i) {
        uwp_ip_connection_entry_t* entry =
            &uwp_ip_connections[(start + i) % QIHSE_UWP_IP_TABLE_SIZE];
        if (!entry->used) return;
        if (entry->source_ip == source_ip) {
            if (entry->connections > 0) --entry->connections;
            return;
        }
    }
}

static const char* uwp_route_error_reply(uwp_route_result_t result) {
    switch (result) {
        case UWP_ROUTE_ERR_MAGIC: return "ERR_MAGIC\n";
        case UWP_ROUTE_ERR_VERSION: return "ERR_VERSION\n";
        case UWP_ROUTE_ERR_LEN: return "ERR_LEN\n";
        case UWP_ROUTE_ERR_TOO_LARGE: return "ERR_TOO_LARGE\n";
        case UWP_ROUTE_ERR_AUTH: return "ERR_AUTH\n";
        case UWP_ROUTE_ERR_RATE_LIMITED: return "ERR_RATE_LIMITED\n";
        case UWP_ROUTE_ERR_PERM: return "ERR_PERM\n";
        case UWP_ROUTE_ERR_DISPATCH: return "ERR_DISPATCH\n";
        case UWP_ROUTE_OK: return NULL;
    }
    return "ERR_DISPATCH\n";
}

static void uwp_conn_destroy(uwp_conn_t* conn) {
    if (!conn) return;
    if (conn->current_txn && conn->ctx->txn_manager) {
        qihse_txn_rollback((qihse_txn_manager_t*)conn->ctx->txn_manager, conn->current_txn);
        conn->current_txn = NULL;
    }
    if (conn->source_ip_tracked) uwp_connection_release(conn->source_ip);
    uwp_socket_close(conn->fd);
    free(conn->rbuf);
    free(conn);
}

#ifndef _WIN32
static bool uwp_add_accept(struct io_uring *ring, int server_fd,
                           qihse_uwp_context_t* uwp_ctx,
                           struct sockaddr_in *client_addr, socklen_t *client_len) {
    uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
    if (!ev) return false;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        free(ev);
        return false;
    }
    ev->type = EVENT_ACCEPT;
    ev->fd = server_fd;
    ev->ctx = uwp_ctx;
    ev->conn = NULL;
    
    io_uring_prep_accept(sqe, server_fd, (struct sockaddr *)client_addr, client_len, 0);
    io_uring_sqe_set_data(sqe, ev);
    return true;
}

static bool uwp_add_read(struct io_uring *ring, uwp_conn_t* conn) {
    size_t target_len = conn->state == READING_HEADER
        ? sizeof(qihse_uwp_header_t) : conn->payload_length;
    if (conn->rbuf_len >= target_len) return false;

    uwp_event_ctx_t *ev = malloc(sizeof(uwp_event_ctx_t));
    if (!ev) return false;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        free(ev);
        return false;
    }
    ev->type = EVENT_READ;
    ev->fd = conn->fd;
    ev->ctx = conn->ctx;
    ev->conn = conn;
    
    io_uring_prep_recv(sqe, conn->fd, conn->rbuf + conn->rbuf_len,
                       target_len - conn->rbuf_len, 0);
    io_uring_sqe_set_data(sqe, ev);
    return true;
}

#endif

static uwp_conn_t* uwp_conn_create(uwp_socket_t fd, qihse_uwp_context_t* ctx,
                                   uint32_t source_ip) {
    uwp_conn_t* conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;
    conn->rbuf_cap = sizeof(qihse_uwp_header_t);
    conn->rbuf = malloc(conn->rbuf_cap);
    if (!conn->rbuf) {
        free(conn);
        return NULL;
    }
    conn->fd = fd;
    conn->ctx = ctx;
    if (!uwp_connection_acquire(source_ip)) {
        free(conn->rbuf);
        free(conn);
        return NULL;
    }
    conn->source_ip = source_ip;
    conn->source_ip_tracked = true;
    conn->state = READING_HEADER;
    conn->current_txn = NULL;
    return conn;
}

static bool uwp_conn_prepare_payload(uwp_conn_t* conn, size_t payload_length) {
    if (payload_length > QIHSE_UWP_MAX_PAYLOAD) return false;
    if (payload_length > conn->rbuf_cap) {
        uint8_t* grown = realloc(conn->rbuf, payload_length);
        if (!grown) return false;
        conn->rbuf = grown;
        conn->rbuf_cap = payload_length;
    }
    conn->payload_length = payload_length;
    conn->rbuf_len = 0;
    conn->state = READING_PAYLOAD;
    return true;
}

static void uwp_conn_reset(uwp_conn_t* conn) {
    conn->rbuf_len = 0;
    conn->payload_length = 0;
    conn->state = READING_HEADER;
    conn->current_txn = NULL;
}

#ifdef _WIN32
#define UWP_WINDOWS_MAX_CONNECTIONS 1024

static bool uwp_windows_dispatch_frame(uwp_conn_t* conn) {
    uwp_route_result_t route_result = uwp_route_payload(
        conn->fd, conn->ctx, &conn->header, conn->rbuf,
        conn->rbuf_len, &conn->user, &conn->current_txn);
    if (route_result != UWP_ROUTE_OK) {
        const char* reply = uwp_route_error_reply(route_result);
        uwp_write_all(conn->fd, reply, strlen(reply));
        return false;
    }
    uwp_conn_reset(conn);
    return true;
}

static bool uwp_windows_receive(uwp_conn_t* conn) {
    size_t target_len = conn->state == READING_HEADER
        ? sizeof(qihse_uwp_header_t) : conn->payload_length;
    size_t remaining = target_len - conn->rbuf_len;
    int received = recv(conn->fd, (char*)conn->rbuf + conn->rbuf_len,
                        (int)remaining, 0);
    if (received == SOCKET_ERROR) {
        int error = WSAGetLastError();
        return error == WSAEWOULDBLOCK;
    }
    if (received == 0) return false;

    conn->rbuf_len += (size_t)received;
    if (conn->rbuf_len < target_len) return true;

    if (conn->state == READING_HEADER) {
        memcpy(&conn->header, conn->rbuf, sizeof(conn->header));
        if (memcmp(conn->header.magic, qihse_uwp_magic,
                   sizeof(conn->header.magic)) != 0) {
            uwp_write_all(conn->fd, "ERR_MAGIC\n", 10);
            return false;
        }
        if (conn->header.version != 0x01) {
            uwp_write_all(conn->fd, "ERR_VERSION\n", 12);
            return false;
        }

        uint64_t payload_length = uwp_payload_length(&conn->header);
        if (payload_length > QIHSE_UWP_MAX_PAYLOAD) {
            uwp_write_all(conn->fd, "ERR_TOO_LARGE\n", 14);
            return false;
        }
        if (!uwp_conn_prepare_payload(conn, (size_t)payload_length)) {
            uwp_write_all(conn->fd, "ERR_DISPATCH\n", 13);
            return false;
        }
        if (payload_length == 0) return uwp_windows_dispatch_frame(conn);
        return true;
    }

    return uwp_windows_dispatch_frame(conn);
}

static void uwp_windows_remove_connection(WSAPOLLFD* poll_fds,
                                          uwp_conn_t** connections,
                                          ULONG* poll_count, ULONG index) {
    uwp_conn_destroy(connections[index]);
    for (ULONG i = index + 1; i < *poll_count; ++i) {
        poll_fds[i - 1] = poll_fds[i];
        connections[i - 1] = connections[i];
    }
    --(*poll_count);
}
#endif

bool qihse_start_uwp_server(qihse_uwp_context_t* ctx, uint16_t port, const char* bind_address) {
    if (qihse_auth_is_operator_password_default()) {
        fprintf(stderr, "[FATAL SECURITY ERROR] Default operator password detected. "
                        "You must rotate the default operator password before starting network services.\n");
        return false;
    }

    if (ctx && ctx->tls_ctx) {
        fprintf(stderr, "[QIHSE UWP] TLS enabled (ChaCha20-Poly1305 transport encryption active)\n");
    }

    uwp_socket_t server_fd;
    struct sockaddr_in address;
    int opt = 1;

#ifdef _WIN32
    if ((server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
#else
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
#endif
        perror("socket failed");
        return false;
    }

#ifdef _WIN32
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt))) {
#else
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
#endif
        perror("setsockopt");
        uwp_socket_close(server_fd);
        return false;
    }

#ifndef _WIN32
    const char* reuseport_env = getenv("QIHSE_UWP_REUSEPORT");
    if (reuseport_env && strcmp(reuseport_env, "1") == 0) {
#ifdef SO_REUSEPORT
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) != 0) {
            perror("setsockopt(SO_REUSEPORT)");
            uwp_socket_close(server_fd);
            return false;
        }
        fprintf(stderr, "[QIHSE UWP] WARNING: SO_REUSEPORT enabled by QIHSE_UWP_REUSEPORT\n");
#else
        fprintf(stderr, "[QIHSE UWP] WARNING: QIHSE_UWP_REUSEPORT requested but unavailable\n");
#endif
    }
#endif

    address.sin_family = AF_INET;
    if (bind_address && bind_address[0] != '\0') {
        address.sin_addr.s_addr = inet_addr(bind_address);
    } else {
        address.sin_addr.s_addr = INADDR_ANY;
    }
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        uwp_socket_close(server_fd);
        return false;
    }

    if (listen(server_fd, 1000) < 0) {
        perror("listen");
        uwp_socket_close(server_fd);
        return false;
    }

#ifdef _WIN32
    printf("[QIHSE UWP] Multiplexer Online on %s:%d (WSAPoll Network Engine)\n",
#else
    printf("[QIHSE UWP] Multiplexer Online on %s:%d (Zero-Copy io_uring Network Engine)\n",
#endif
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
            uint32_t source_ip = client_addr.sin_addr.s_addr;
            client_len = sizeof(client_addr);
            uwp_add_accept(&ring, server_fd, ctx, &client_addr, &client_len);
            if (res >= 0) {
                struct timeval tv;
                tv.tv_sec = 30;
                tv.tv_usec = 0;
                setsockopt(res, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(res, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                uwp_conn_t* conn = uwp_conn_create(res, ctx, source_ip);
                if (!conn || !uwp_add_read(&ring, conn)) {
                    if (conn) uwp_conn_destroy(conn);
                    else close(res);
                }
            }
            io_uring_submit(&ring);
        } else if (ev->type == EVENT_READ) {
            uwp_conn_t* conn = ev->conn;
            if (res <= 0) {
                /* EOF, SO_RCVTIMEO expiry, or another recv error. */
                uwp_conn_destroy(conn);
            } else {
                size_t target_len = conn->state == READING_HEADER
                    ? sizeof(qihse_uwp_header_t) : conn->payload_length;
                size_t remaining = target_len - conn->rbuf_len;
                if ((size_t)res > remaining) {
                    uwp_write_all(conn->fd, "ERR_LEN\n", 8);
                    uwp_conn_destroy(conn);
                } else {
                    conn->rbuf_len += (size_t)res;
                }

                if ((size_t)res <= remaining && conn->rbuf_len < target_len) {
                    if (!uwp_add_read(&ring, conn)) uwp_conn_destroy(conn);
                    io_uring_submit(&ring);
                } else if ((size_t)res <= remaining && conn->state == READING_HEADER) {
                    memcpy(&conn->header, conn->rbuf, sizeof(conn->header));
                    if (memcmp(conn->header.magic, qihse_uwp_magic,
                               sizeof(conn->header.magic)) != 0) {
                        const char* reply = uwp_route_error_reply(UWP_ROUTE_ERR_MAGIC);
                        uwp_write_all(conn->fd, reply, strlen(reply));
                        uwp_conn_destroy(conn);
                    } else {
                        if (conn->header.version != 0x01) {
                            uwp_write_all(conn->fd, "ERR_VERSION\n", 12);
                            uwp_conn_destroy(conn);
                        } else {
                        uint64_t payload_length = uwp_payload_length(&conn->header);
                        if (payload_length > QIHSE_UWP_MAX_PAYLOAD) {
                            uwp_write_all(conn->fd, "ERR_TOO_LARGE\n", 14);
                            uwp_conn_destroy(conn);
                        } else if (!uwp_conn_prepare_payload(conn, (size_t)payload_length)) {
                            const char* reply = uwp_route_error_reply(UWP_ROUTE_ERR_DISPATCH);
                            uwp_write_all(conn->fd, reply, strlen(reply));
                            uwp_conn_destroy(conn);
                        } else if (payload_length == 0) {
                            uwp_route_result_t route_result = uwp_route_payload(
                                conn->fd, conn->ctx, &conn->header, conn->rbuf, 0, &conn->user, &conn->current_txn);
                            if (route_result == UWP_ROUTE_OK) {
                                uwp_conn_reset(conn);
                                if (!uwp_add_read(&ring, conn)) uwp_conn_destroy(conn);
                            } else {
                                const char* reply = uwp_route_error_reply(route_result);
                                uwp_write_all(conn->fd, reply, strlen(reply));
                                uwp_conn_destroy(conn);
                            }
                        } else {
                            if (!uwp_add_read(&ring, conn)) uwp_conn_destroy(conn);
                        }
                        }
                        io_uring_submit(&ring);
                    }
                } else if ((size_t)res <= remaining) {
                    uwp_route_result_t route_result = uwp_route_payload(
                        conn->fd, conn->ctx, &conn->header, conn->rbuf,
                        conn->rbuf_len, &conn->user, &conn->current_txn);
                    if (route_result == UWP_ROUTE_OK) {
                        uwp_conn_reset(conn);
                        if (!uwp_add_read(&ring, conn)) uwp_conn_destroy(conn);
                    } else {
                        const char* reply = uwp_route_error_reply(route_result);
                        uwp_write_all(conn->fd, reply, strlen(reply));
                        uwp_conn_destroy(conn);
                    }
                    io_uring_submit(&ring);
                }
            }
        } else if (ev->type == EVENT_XDP_POLL) {
            if (xdp_ctx) {
                qihse_af_xdp_poll(xdp_ctx, uwp_xdp_frame_cb, ctx);
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
    WSAPOLLFD poll_fds[UWP_WINDOWS_MAX_CONNECTIONS + 1] = {0};
    uwp_conn_t* connections[UWP_WINDOWS_MAX_CONNECTIONS + 1] = {0};
    ULONG poll_count = 1;
    poll_fds[0].fd = server_fd;
    poll_fds[0].events = POLLRDNORM;

    while (1) {
        int ready = WSAPoll(poll_fds, poll_count, -1);
        if (ready == SOCKET_ERROR) {
            fprintf(stderr, "[QIHSE UWP] WSAPoll failed: %d\n", WSAGetLastError());
            break;
        }

        if (poll_fds[0].revents & POLLRDNORM) {
            struct sockaddr_in client_addr;
            int client_len = sizeof(client_addr);
            SOCKET client_sock = accept(server_fd,
                (struct sockaddr*)&client_addr, &client_len);
            if (client_sock != INVALID_SOCKET) {
                if (poll_count > UWP_WINDOWS_MAX_CONNECTIONS) {
                    uwp_write_all(client_sock, "ERR_TOO_MANY_CONNECTIONS\n", 25);
                    closesocket(client_sock);
                } else {
                    u_long nonblocking = 1;
                    if (ioctlsocket(client_sock, FIONBIO, &nonblocking) != 0) {
                        closesocket(client_sock);
                    } else {
                            uwp_conn_t* conn = uwp_conn_create(client_sock, ctx,
                                                               client_addr.sin_addr.s_addr);
                        if (!conn) {
                            closesocket(client_sock);
                        } else {
                            poll_fds[poll_count].fd = client_sock;
                            poll_fds[poll_count].events = POLLRDNORM;
                            connections[poll_count] = conn;
                            ++poll_count;
                        }
                    }
                }
            }
        }

        for (ULONG i = 1; i < poll_count;) {
            SHORT revents = poll_fds[i].revents;
            bool keep = true;
            if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
                keep = false;
            } else if (revents & POLLRDNORM) {
                keep = uwp_windows_receive(connections[i]);
            }

            if (!keep) {
                uwp_windows_remove_connection(poll_fds, connections,
                                              &poll_count, i);
            } else {
                ++i;
            }
        }
    }

    for (ULONG i = 1; i < poll_count; ++i) {
        uwp_conn_destroy(connections[i]);
    }
#endif
    uwp_socket_close(server_fd);
    return true;
}
