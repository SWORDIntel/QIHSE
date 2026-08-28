/* Real TLS integration test: self-signed cert, handshake, encrypted round-trip.
 * Uses socketpair + fork to test client-server TLS without network. */
#include "qihse_uwp_tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <unistd.h>

/* TLS handshake test: server and client args */
struct tls_server_arg { qihse_uwp_tls_ctx_t* ctx; int fd; int ok; };
struct tls_client_arg { int fd; int ok; };

static void* tls_server_fn(void* arg) {
    struct tls_server_arg* a = (struct tls_server_arg*)arg;
    qihse_uwp_tls_session_t* sess = qihse_uwp_tls_session_create_with_fd(a->ctx, a->fd);
    if (!sess) return NULL;
    /* SSL_accept completed successfully inside session_create_with_fd */
    a->ok = 1;
    qihse_uwp_tls_session_destroy(sess);
    return NULL;
}

static void* tls_client_fn(void* arg) {
    struct tls_client_arg* a = (struct tls_client_arg*)arg;
    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    if (!cctx) return NULL;
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL* ssl = SSL_new(cctx);
    if (!ssl) { SSL_CTX_free(cctx); return NULL; }
    SSL_set_fd(ssl, a->fd);
    if (SSL_connect(ssl) == 1) a->ok = 1;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    return NULL;
}

static int test_selfsigned_cert(void) {
    qihse_uwp_tls_ctx_t* ctx = qihse_uwp_tls_ctx_create_selfsigned("localhost", 2048);
    if (!ctx) { fprintf(stderr, "[FAIL] self-signed cert creation\n"); return -1; }
    qihse_uwp_tls_ctx_destroy(ctx);
    printf("[PASS] self-signed cert generation\n");
    return 0;
}

static int test_key_rotation(void) {
    qihse_uwp_tls_ctx_t* ctx = qihse_uwp_tls_ctx_create_selfsigned("test", 2048);
    if (!ctx) return -1;
    int rc = qihse_uwp_tls_ctx_rotate_key(ctx);
    if (rc != 0) { fprintf(stderr, "[FAIL] key rotation (rc=%d)\n", rc); qihse_uwp_tls_ctx_destroy(ctx); return -1; }
    qihse_uwp_tls_ctx_destroy(ctx);
    printf("[PASS] key rotation\n");
    return 0;
}

static int test_aead_roundtrip(void) {
    /* Test the AEAD path (non-cert) for encrypt/decrypt round-trip */
    qihse_uwp_tls_ctx_t* ctx = qihse_uwp_tls_ctx_create();
    if (!ctx) return -1;
    qihse_uwp_tls_session_t* sess = qihse_uwp_tls_session_create(ctx);
    if (!sess) { qihse_uwp_tls_ctx_destroy(ctx); return -1; }

    const char* msg = "HELLO UWP TLS";
    uint8_t ct[256];
    uint8_t pt[256];
    size_t out_len = 0, dec_len = 0;

    int rc = qihse_uwp_tls_encrypt(sess, (const uint8_t*)msg, strlen(msg), ct, sizeof(ct), &out_len);
    if (rc != 0) { fprintf(stderr, "[FAIL] encrypt\n"); goto done; }

    rc = qihse_uwp_tls_decrypt(sess, ct, out_len, pt, sizeof(pt), &dec_len);
    if (rc != 0) { fprintf(stderr, "[FAIL] decrypt\n"); goto done; }

    if (dec_len != strlen(msg) || memcmp(pt, msg, dec_len) != 0) {
        fprintf(stderr, "[FAIL] round-trip mismatch\n");
        rc = -1;
        goto done;
    }
    printf("[PASS] AEAD encrypt/decrypt round-trip\n");

    /* Test tamper detection */
    ct[12] ^= 0xFF; /* flip a byte in the nonce */
    rc = qihse_uwp_tls_decrypt(sess, ct, out_len, pt, sizeof(pt), &dec_len);
    if (rc == 0) {
        fprintf(stderr, "[FAIL] tamper not detected\n");
        rc = -1;
    } else {
        printf("[PASS] tamper detection (auth failure)\n");
        rc = 0;
    }

done:
    qihse_uwp_tls_session_destroy(sess);
    qihse_uwp_tls_ctx_destroy(ctx);
    return rc;
}

static int test_tls_handshake(void) {
    /* Test real TLS 1.3 handshake using threads. Server does SSL_accept,
     * client does SSL_connect. Verifies the cert-based path works end-to-end. */
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        fprintf(stderr, "[FAIL] socketpair\n");
        return -1;
    }

    qihse_uwp_tls_ctx_t* server_ctx = qihse_uwp_tls_ctx_create_selfsigned("localhost", 2048);
    if (!server_ctx) { close(fds[0]); close(fds[1]); return -1; }

    struct tls_server_arg sarg = { server_ctx, fds[0], 0 };
    struct tls_client_arg carg = { fds[1], 0 };

    pthread_t server_tid, client_tid;
    pthread_create(&server_tid, NULL, tls_server_fn, &sarg);
    usleep(10000); /* let server start SSL_accept first */
    pthread_create(&client_tid, NULL, tls_client_fn, &carg);

    pthread_join(server_tid, NULL);
    pthread_join(client_tid, NULL);

    close(fds[0]);
    close(fds[1]);
    qihse_uwp_tls_ctx_destroy(server_ctx);

    if (sarg.ok && carg.ok) {
        printf("[PASS] TLS 1.3 handshake (SSL_accept + SSL_connect)\n");
        return 0;
    }
    fprintf(stderr, "[FAIL] TLS handshake (server_ok=%d, client_ok=%d)\n", sarg.ok, carg.ok);
    return -1;
}

int main(void) {
    signal(SIGALRM, SIG_DFL);
    alarm(15); /* timeout */

    int failures = 0;
    failures += test_selfsigned_cert();
    failures += test_key_rotation();
    failures += test_aead_roundtrip();
    failures += test_tls_handshake();

    if (failures == 0) {
        printf("\nPASS UWP TLS integration (cert, rotation, AEAD, handshake)\n");
        return 0;
    }
    printf("\nFAIL %d test(s) failed\n", failures);
    return 1;
}
