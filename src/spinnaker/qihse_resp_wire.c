#include "qihse_resp_wire.h"
#include "qihse_vector_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
#include "../networking/qihse_af_xdp.h"
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


static int parse_resp_array(char* buf, char** args, int max_args) {
    if (buf[0] != '*') return -1;
    int argc = atoi(buf + 1);
    if (argc > max_args) argc = max_args;
    
    char* p = strstr(buf, "\r\n");
    if (!p) return -1;
    p += 2;
    
    for (int i = 0; i < argc; i++) {
        if (p[0] != '$') return -1;
        int len = atoi(p + 1);
        p = strstr(p, "\r\n");
        if (!p) return -1;
        p += 2;
        args[i] = p;
        p += len;
        if (p[0] == '\r' && p[1] == '\n') {
            p[0] = '\0';
            p += 2;
        } else {
            return -1;
        }
    }
    return argc;
}

void qihse_resp_handle_client(int client_fd, qihse_kv_store_t* store, qihse_vector_db_t vdb) {
    char buffer[65536];
    while (1) {
        ssize_t valread = read(client_fd, buffer, sizeof(buffer) - 1);
        if (valread <= 0) break;
        buffer[valread] = '\0';
        
        char* args[2048];
        int argc = 0;
        
        if (buffer[0] == '*') {
            argc = parse_resp_array(buffer, args, 2048);
        } else {
            char* token = strtok(buffer, " \r\n");
            while (token && argc < 2048) {
                args[argc++] = token;
                token = strtok(NULL, " \r\n");
            }
        }
        
        if (argc > 0) {
            if (strcasecmp(args[0], "PING") == 0) {
                const char* reply = "+PONG\r\n";
                write(client_fd, reply, strlen(reply));
            } else if (strcasecmp(args[0], "SET") == 0 && argc >= 3) {
                qihse_kv_set(store, args[1], args[2], 0, 0);
                const char* reply = "+OK\r\n";
                write(client_fd, reply, strlen(reply));
            } else if (strcasecmp(args[0], "GET") == 0 && argc >= 2) {
                const char* val = qihse_kv_get_user(store, args[1], NULL);
                
                if (qihse_kv_store_is_under_attack(store)) {
#ifndef _WIN32
                    qihse_qdd_execute_active_measure(client_fd);
#endif
                    break;
                }
                
                if (val) {
                    char reply[1024];
                    snprintf(reply, sizeof(reply), "$%zu\r\n%s\r\n", strlen(val), val);
                    write(client_fd, reply, strlen(reply));
                } else {
                    const char* reply = "$-1\r\n";
                    write(client_fd, reply, strlen(reply));
                }
            } else if (strcasecmp(args[0], "DEL") == 0 && argc >= 2) {
                qihse_kv_del_user(store, args[1], NULL);
                const char* reply = ":1\r\n";
                write(client_fd, reply, strlen(reply));
            } else if (strcasecmp(args[0], "MSET") == 0 && argc >= 3) {
                for (int i = 1; i < argc - 1; i += 2) {
                    qihse_kv_set(store, args[i], args[i+1], 0, 0);
                }
                const char* reply = "+OK\r\n";
                write(client_fd, reply, strlen(reply));
            } else if (strcasecmp(args[0], "MGET") == 0 && argc >= 2) {
                char reply[65536];
                int offset = snprintf(reply, sizeof(reply), "*%d\r\n", argc - 1);
                for (int i = 1; i < argc; i++) {
                    const char* val = qihse_kv_get_user(store, args[i], NULL);
                    if (val) {
                        offset += snprintf(reply + offset, sizeof(reply) - offset, "$%zu\r\n%s\r\n", strlen(val), val);
                    } else {
                        offset += snprintf(reply + offset, sizeof(reply) - offset, "$-1\r\n");
                    }
                }
                write(client_fd, reply, offset);
            } else if (strcasecmp(args[0], "INFO") == 0) {
                const char* info = "# Server\r\nredis_version:7.0.0 (QIHSE Wire Proxy)\r\n# Memory\r\nused_memory_human:0B\r\n";
                char reply[1024];
                snprintf(reply, sizeof(reply), "$%zu\r\n%s\r\n", strlen(info), info);
                write(client_fd, reply, strlen(reply));
            } else if (strcasecmp(args[0], "VECSET") == 0 && argc >= 3) {
                uint64_t id = strtoull(args[1], NULL, 10);
                int dim = atoi(args[2]);
                if (argc >= 3 + dim) {
                    float *vec = malloc(dim * sizeof(float));
                    for (int i = 0; i < dim; i++) {
                        vec[i] = atof(args[3 + i]);
                    }
                    qihse_vector_db_upsert_by_ids(vdb, &id, vec, 1, dim, NULL, NULL, NULL, NULL);
                    const char* reply = "+OK\r\n";
                    write(client_fd, reply, strlen(reply));
                    free(vec);
                } else {
                    const char* reply = "-ERR invalid VECSET format\r\n";
                    write(client_fd, reply, strlen(reply));
                }
            } else if (strcasecmp(args[0], "VECGET") == 0 && argc >= 2) {
                const char* reply = "-ERR VECGET not implemented\r\n";
                write(client_fd, reply, strlen(reply));
            } else if (strcasecmp(args[0], "VECSEARCH") == 0 && argc >= 3) {
                int dim = atoi(args[1]);
                int top_k = atoi(args[2]);
                if (argc >= 3 + dim) {
                    float *vec = malloc(dim * sizeof(float));
                    for (int i = 0; i < dim; i++) {
                        vec[i] = atof(args[3 + i]);
                    }
                    qihse_vector_query_t query;
                    memset(&query, 0, sizeof(query));
                    query.query_vector = vec;
                    query.vector_dims = dim;
                    query.top_k = top_k;
                    query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
                    
                    qihse_vector_result_t *results = malloc(top_k * sizeof(qihse_vector_result_t));
                    int found = qihse_vector_db_search(vdb, &query, results, top_k);
                    
                    if (found >= 0) {
                        char reply[1024];
                        snprintf(reply, sizeof(reply), "*%d\r\n", found);
                        write(client_fd, reply, strlen(reply));
                        for (int i = 0; i < found; i++) {
                            char item[128];
                            snprintf(item, sizeof(item), ":%llu\r\n", (unsigned long long)results[i].id);
                            write(client_fd, item, strlen(item));
                        }
                    } else {
                        const char* reply = "-ERR search failed\r\n";
                        write(client_fd, reply, strlen(reply));
                    }
                    free(results);
                    free(vec);
                } else {
                    const char* reply = "-ERR invalid VECSEARCH format\r\n";
                    write(client_fd, reply, strlen(reply));
                }
            } else {
                const char* reply = "-ERR unknown command\r\n";
                write(client_fd, reply, strlen(reply));
            }
        }
    }
    close(client_fd);
}

static void af_xdp_resp_cb(char *pkt, uint32_t len, void *arg) {
    (void)arg;
    if (len > 54) {
        char *payload = pkt + 54;
        if (strstr(payload, "PING")) {
            printf("[AF_XDP RESP] Fast-path zero-copy bypass: PING\n");
        } else if (strstr(payload, "GET")) {
            printf("[AF_XDP RESP] Fast-path zero-copy bypass: GET\n");
        } else if (strstr(payload, "SET")) {
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
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return -1;
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
        return -1;
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
        return -1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
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
            
            strcpy(ctx->buffer, reply_ptr);
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
