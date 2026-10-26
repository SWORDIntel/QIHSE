/* Include the implementation to fuzz the bounded decoder/encoder and exercise
 * failure states with deterministic sealed peers. Real handshakes and principal
 * authorization are covered separately by test_qkp_admin.c. */
#include <assert.h>
#include "../src/spinnaker/qihse_qkp.c"

static qihse_qkp_session_t* test_session(qkp_role_t role) {
    qihse_qkp_session_t* session = calloc(1u, sizeof(*session));
    assert(session);
    session->role = role;
    session->tx_seq = session->rx_seq = 1u;
    assert(qkp_session_init_cipher_contexts(session));
    return session;
}

static void test_wire(const char* reply, bool fragmented, bool good) {
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    struct timeval timeout = {0, 100000};
    assert(setsockopt(fd[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    qihse_qkp_admin_client_t* client = calloc(1u, sizeof(*client));
    assert(client);
    client->fd = fd[0];
    client->session = test_session(QKP_ROLE_CLIENT);
    qihse_qkp_session_t* peer = test_session(QKP_ROLE_SERVER);
    if (reply) {
        size_t n = strlen(reply);
        size_t first = fragmented ? n / 2u : n;
        assert(qihse_qkp_send_sealed(peer, fd[1], reply, first));
        if (first < n) assert(qihse_qkp_send_sealed(peer, fd[1], reply + first, n - first));
    }
    const char* args[] = {"ECHO", "a\0b\n"};
    size_t lengths[] = {4u, 4u};
    char* output = NULL;
    size_t output_len = 0u;
    char error[256];
    int rc = qihse_qkp_admin_command(client, 2u, args, lengths,
                                    &output, &output_len, error, sizeof(error));
    if (good) {
        assert(rc == 0 && output && output_len == strlen(reply));
        assert(memcmp(output, reply, output_len) == 0);
    } else {
        assert(rc == 5 && !output && output_len == 0u && client->failed);
        assert(qihse_qkp_admin_command(client, 2u, args, lengths,
                                       &output, &output_len, error, sizeof(error)) == 2);
    }
    uint8_t received[128];
    const char expected[] = "*2\r\n$4\r\nECHO\r\n$4\r\na\0b\n\r\n";
    ssize_t n = qihse_qkp_recv_sealed(peer, fd[1], received, sizeof(received));
    assert(n == (ssize_t)sizeof(expected) - 1);
    assert(memcmp(received, expected, (size_t)n) == 0);
    free(output);
    qihse_qkp_admin_close(client);
    qihse_qkp_session_free(peer);
    close(fd[1]);
}

int main(void) {
    const char* args[] = {"ECHO", "a\0b"};
    size_t lengths[] = {4u, 3u}, len = 0u;
    char* encoded = qkp_admin_encode_resp(2u, args, lengths, &len);
    const char expected[] = "*2\r\n$4\r\nECHO\r\n$3\r\na\0b\r\n";
    assert(encoded && len == sizeof(expected) - 1u && memcmp(encoded, expected, len) == 0);
    free(encoded);
    lengths[1] = SIZE_MAX;
    assert(!qkp_admin_encode_resp(2u, args, lengths, &len));
    assert(!qkp_admin_encode_resp(0u, args, NULL, &len));
    assert(!qkp_admin_encode_resp(65537u, args, NULL, &len));
    const char* null_arg[] = {NULL};
    assert(!qkp_admin_encode_resp(1u, null_arg, NULL, &len));

    const char valid[] = "*2\r\n$5\r\na\0b\r\n\r\n:-12\r\n";
    for (size_t i = 0; i < sizeof(valid) - 1u; i++) {
        char* exact = malloc(i ? i : 1u);
        assert(exact);
        memcpy(exact, valid, i);
        assert(qkp_admin_resp_measure(exact, i, 0) == 0);
        free(exact);
    }
    assert(qkp_admin_resp_measure(valid, sizeof(valid) - 1u, 0) == (ssize_t)sizeof(valid) - 1);
    uint32_t seed = 7u;
    for (size_t i = 0; i < 50000u; i++) {
        size_t size = i % 256u;
        char* data = malloc(size ? size : 1u);
        assert(data);
        for (size_t j = 0; j < size; j++) {
            seed = seed * 1664525u + 1013904223u;
            data[j] = (char)(seed >> 24);
        }
        char* output = NULL;
        size_t output_len = 0u;
        (void)qihse_qkp_admin_format(data, size, (i & 1u) != 0u, &output, &output_len, NULL);
        free(output);
        free(data);
    }
    test_wire("*2\r\n$4\r\ntext\r\n:23\r\n", true, true);
    test_wire("-CUSTOM rejected\r\n", false, true);
    test_wire("$1\r\nx!!", false, false);
    test_wire("+OK\r\n+EXTRA\r\n", false, false);
    test_wire(NULL, false, false);
    puts("admin protocol: binary encoding, bounded decoder, sealed framing and failed-client state OK");
    return 0;
}
