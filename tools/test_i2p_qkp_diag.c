#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include "include/qihse_qkp.h"
#include "include/qihse_auth.h"

static bool socket_send_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = send(fd, p + done, len - done, MSG_NOSIGNAL);
        if (w <= 0) return false;
        done += (size_t)w;
    }
    return true;
}

static bool socket_recv_all(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t r = recv(fd, p + done, len - done, 0);
        if (r <= 0) return false;
        done += (size_t)r;
    }
    return true;
}

static int connect_i2p_socks5(const char* host, uint16_t port, uint16_t socks_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in proxy;
    memset(&proxy, 0, sizeof(proxy));
    proxy.sin_family = AF_INET;
    proxy.sin_port = htons(socks_port);
    proxy.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&proxy, sizeof(proxy)) != 0) { close(fd); return -1; }

    const uint8_t greeting[] = {0x05u, 0x01u, 0x00u};
    uint8_t reply[4];
    if (!socket_send_all(fd, greeting, sizeof(greeting)) || !socket_recv_all(fd, reply, 2u) ||
        reply[0] != 0x05u || reply[1] != 0x00u) { close(fd); return -1; }
    uint8_t request[4u + 1u + 255u + 2u];
    size_t host_len = strlen(host);
    request[0] = 0x05u; request[1] = 0x01u; request[2] = 0x00u; request[3] = 0x03u;
    request[4] = (uint8_t)host_len;
    memcpy(request + 5u, host, host_len);
    request[5u + host_len] = (uint8_t)(port >> 8);
    request[6u + host_len] = (uint8_t)port;
    if (!socket_send_all(fd, request, 7u + host_len) || !socket_recv_all(fd, reply, sizeof(reply)) ||
        reply[0] != 0x05u || reply[1] != 0x00u) { close(fd); return -1; }
    size_t bound_len = 0u;
    if (reply[3] == 0x01u) bound_len = 4u;
    else if (reply[3] == 0x04u) bound_len = 16u;
    else if (reply[3] == 0x03u) {
        uint8_t n = 0u;
        if (!socket_recv_all(fd, &n, 1u)) { close(fd); return -1; }
        bound_len = n;
    } else { close(fd); return -1; }
    uint8_t discard[18u];
    if (!socket_recv_all(fd, discard, bound_len + 2u)) { close(fd); return -1; }
    return fd;
}

int main(int argc, char** argv) {
    const char* i2p_host = argc > 1 ? argv[1] : "q5vsroyasn52n6st5gksx3en7lzaghcxq4vgyjz757o7tonhtoga.b32.i2p";
    uint16_t port = 7101;
    uint16_t socks_port = 4447;

    printf("[1] Connecting via SOCKS5 (127.0.0.1:%u) to %s:%u...\n", socks_port, i2p_host, port);
    int fd = connect_i2p_socks5(i2p_host, port, socks_port);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect via SOCKS5\n");
        return 1;
    }
    printf("[2] SOCKS5 stream opened! fd=%d\n", fd);

    qihse_qkp_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.node_id = "node1";
    cfg.dsa_key_path = "/etc/qihse/keys/qihse_dsa_key.pem";
    cfg.kem_key_path = "/etc/qihse/keys/qihse_kem_key.pem";
    cfg.kem_pub_path = "/etc/qihse/keys/qihse_kem_pub.pem";
    const char* trusted[] = {
        "/opt/qihse/data/peers/node0.pem",
        "/opt/qihse/data/peers/node1.pem",
        "/opt/qihse/data/peers/node2.pem"
    };
    cfg.trusted_pubs = trusted;
    cfg.trusted_count = 3;

    printf("[3] Negotiating QKP1 post-quantum session...\n");
    qihse_qkp_session_t* s = NULL;
    qihse_qkp_result_t res = qihse_qkp_client_negotiate(fd, &cfg, &s);
    printf("    qihse_qkp_client_negotiate result: %d (0=SECURE)\n", res);
    if (res != QIHSE_QKP_SECURE || !s) {
        fprintf(stderr, "QKP1 negotiation failed!\n");
        close(fd);
        return 2;
    }
    printf("[4] QKP1 session ESTABLISHED!\n");

    bool is_peer = qihse_qkp_client_session_is_replication_peer(
        s, "node0", "/opt/qihse/data/peers/node0.pem");
    printf("[5] qihse_qkp_client_session_is_replication_peer result: %s\n",
           is_peer ? "TRUE (MATCH!)" : "FALSE (MISMATCH!)");

    // Test sending sealed AUTH command
    const char auth_cmd[] = "*2\r\n$4\r\nAUTH\r\n$29\r\nstageb-local-operator-password\r\n";
    printf("[6] Sending sealed AUTH command over I2P...\n");
    if (!qihse_qkp_send_sealed(s, fd, auth_cmd, strlen(auth_cmd))) {
        fprintf(stderr, "Failed to send sealed AUTH\n");
    } else {
        uint8_t reply[1024];
        ssize_t n = qihse_qkp_recv_sealed(s, fd, reply, sizeof(reply) - 1);
        if (n > 0) {
            printf("[7] Received %zd bytes from node0: ", n);
            for (ssize_t i = 0; i < n; i++) {
                char c = (char)reply[i];
                if (c == '\r') printf("\\r");
                else if (c == '\n') printf("\\n");
                else putchar(c);
            }
            printf("\n");
        } else {
            printf("[7] Recv returned %zd\n", n);
        }
    }

    qihse_qkp_session_free(s);
    close(fd);
    printf("[8] Clean teardown complete.\n");
    return 0;
}
