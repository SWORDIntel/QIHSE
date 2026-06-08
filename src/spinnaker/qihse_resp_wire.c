#include "qihse_resp_wire.h"
#include "qihse_vector_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>

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

bool qihse_start_resp_server(qihse_kv_store_t* store, qihse_vector_db_t vdb, uint16_t port, const char* bind_address) {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return -1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
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
