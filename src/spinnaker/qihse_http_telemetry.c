#include "qihse_platform.h"
#include "qihse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#define close_socket close
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

void* qihse_http_telemetry_thread(void* arg) {
    (void)arg;
    int port = 8080;
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) return NULL;

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) return NULL;
    if (listen(server_fd, 3) < 0) return NULL;

    printf("[TELEMETRY] HTTP Dashboard Server listening natively on port %d\n", port);

    while (1) {
        int client_socket = accept(server_fd, NULL, NULL);
        if (client_socket < 0) continue;

        char buffer[1024] = {0};
        int r = recv(client_socket, buffer, 1024, 0);
        if (r <= 0) { close_socket(client_socket); continue; }

        if (strncmp(buffer, "GET", 3) == 0) {
            qihse_performance_stats_t stats;
            memset(&stats, 0, sizeof(stats));
            qihse_get_performance_stats(&stats);
            
            /* Cumulative stats are not throughput, and unknown counts are not real data. */
            double average_latency_ms = stats.total_operations
                ? (double)stats.total_time_ns / (double)stats.total_operations / 1000000.0
                : 0.0;
            char response_body[1024];
            snprintf(response_body, sizeof(response_body),
                     "{\"qps\":0,\"qps_measured\":false,\"latency\":%.3f,"
                     "\"active_vectors\":0,\"active_vectors_measured\":false,"
                     "\"total_operations\":%zu}",
                     average_latency_ms, stats.total_operations);

            char http_response[2048];
            snprintf(http_response, sizeof(http_response),
                     "HTTP/1.1 200 OK\r\n"
                     "Access-Control-Allow-Origin: http://localhost\r\n"
                     "Content-Type: application/json\r\n"
                     "Connection: close\r\n"
                     "Content-Length: %zu\r\n\r\n%s",
                     strlen(response_body), response_body);

            send(client_socket, http_response, strlen(http_response), MSG_NOSIGNAL);
        }
        close_socket(client_socket);
    }
    return NULL;
}

void qihse_start_http_telemetry_server(void) {
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, qihse_http_telemetry_thread, NULL);
}
