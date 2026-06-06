#include "qihse_pg_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

bool qihse_start_pg_wire_server(void* vdb, uint16_t port, const char* bind_address) {
    if (!bind_address) {
        bind_address = "127.0.0.1";
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("qihse_pg_wire: socket creation failed");
        return false;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("qihse_pg_wire: setsockopt SO_REUSEADDR failed");
        close(server_fd);
        return false;
    }

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    
    if (inet_pton(AF_INET, bind_address, &address.sin_addr) <= 0) {
        fprintf(stderr, "qihse_pg_wire: invalid bind address %s\n", bind_address);
        close(server_fd);
        return false;
    }

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("qihse_pg_wire: bind failed");
        close(server_fd);
        return false;
    }

    if (listen(server_fd, 10) < 0) {
        perror("qihse_pg_wire: listen failed");
        close(server_fd);
        return false;
    }

    printf("QIHSE PostgreSQL Wire Protocol Server listening on %s:%u\n", bind_address, port);

    // Note: Event loop and accept loop are intentionally omitted for now.
    // The server_fd would normally be added to an event loop (e.g., epoll/kqueue) here.

    return true;
}
