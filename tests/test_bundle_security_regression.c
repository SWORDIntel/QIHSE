/* Session-bundle delivery security regression test (AGENTS.md invariant #3,
 * U3). Covers the positive path (compose + chunked blob delivery + delta
 * pull + system-domain compose on behalf of a tenant) and the negative
 * surface: cross-tenant compose, foreign blob chunk reads, unauthenticated
 * access, the commons-poisoning sanity gate, and mid-transfer revocation —
 * each asserted with no protected payload disclosure.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_blob.h"
#include "qihse_kv_store.h"
#include "qihse_pqc_crypto.h"
#include "qihse_resp_wire.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

#define TENANT7_PW "BundleTenant7Pa1!"
#define TENANT8_PW "BundleTenant8Pa1!"
#define OPERATOR_PASSWORD "OperatorBundlePa1!"
#define BUILD_FP "0123456789abcdef"

/* qihse_pqc_keygen() ignores out_dir when the compiled-in key dir is
 * absolute, so generate the test keypairs directly through OpenSSL (the
 * oqs provider is already loaded by qihse_pqc_init_providers). */
static bool write_keypair_pem(const char* algorithm, const char* priv_path, const char* pub_path) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, algorithm);
    if (!pkey) return false;
    FILE* priv = fopen(priv_path, "wb");
    FILE* pub = pub_path ? fopen(pub_path, "wb") : NULL;
    bool ok = priv && pub &&
              PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL) == 1 &&
              PEM_write_PUBKEY(pub, pkey) == 1;
    if (priv) fclose(priv);
    if (pub) fclose(pub);
    chmod(priv_path, 0600);
    EVP_PKEY_free(pkey);
    return ok;
}

typedef struct { qihse_resp_server_t* server; int fd; } server_thread_arg_t;

static void* server_thread(void* argument) {
    server_thread_arg_t* args = (server_thread_arg_t*)argument;
    assert(qihse_resp_server_handle_client_fd(args->server, args->fd));
    return NULL;
}

typedef struct { int fd; } test_client_t;

static void client_init(test_client_t* client, qihse_resp_server_t* server) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    server_thread_arg_t* args = malloc(sizeof(*args));
    assert(args != NULL);
    args->server = server;
    args->fd = sockets[1];
    pthread_t thread;
    assert(pthread_create(&thread, NULL, server_thread, args) == 0);
    pthread_detach(thread);
    client->fd = sockets[0];
}

static void send_command(int fd, size_t argc, const char** argv) {
    char header[64];
    int written = snprintf(header, sizeof(header), "*%zu\r\n", argc);
    assert(written > 0);
    assert(write(fd, header, (size_t)written) == (ssize_t)written);
    for (size_t i = 0; i < argc; i++) {
        written = snprintf(header, sizeof(header), "$%zu\r\n", strlen(argv[i]));
        assert(written > 0);
        assert(write(fd, header, (size_t)written) == (ssize_t)written);
        assert(write(fd, argv[i], strlen(argv[i])) == (ssize_t)strlen(argv[i]));
        assert(write(fd, "\r\n", 2) == 2);
    }
}

/* Reads ONE complete RESP reply by parsing the wire format (simple/error
 * strings, integers, bulk strings) — no timing heuristics. */
static char* read_reply(test_client_t* client) {
    size_t cap = 256 * 1024u; /* manifests carry a 1568-byte KEM ciphertext in hex */
    char* buffer = malloc(cap);
    assert(buffer != NULL);
    size_t len = 0;
    for (;;) {
        /* Read until we have a full type line ending in CRLF. */
        size_t line_end = 0;
        for (;;) {
            if (len >= cap - 1u) assert(false);
            struct pollfd pfd = { client->fd, POLLIN, 0 };
            int ready = poll(&pfd, 1, 20000);
            assert(ready > 0);
            ssize_t received = read(client->fd, buffer + len, cap - len - 1u);
            assert(received > 0);
            len += (size_t)received;
            buffer[len] = '\0';
            char* crlf = memchr(buffer, '\r', len);
            if (crlf && (size_t)(crlf - buffer) + 1u < len && crlf[1] == '\n') {
                line_end = (size_t)(crlf - buffer);
                break;
            }
        }
        char type = buffer[0];
        if (type == '+' || type == '-' || type == ':') {
            return buffer; /* simple reply complete at first CRLF */
        }
        assert(type == '$');
        uint64_t bulk_len = 0;
        for (size_t i = 1; i < line_end; i++) {
            assert(buffer[i] >= '0' && buffer[i] <= '9');
            bulk_len = bulk_len * 10u + (uint64_t)(buffer[i] - '0');
        }
        size_t needed = line_end + 2u + (size_t)bulk_len + 2u;
        while (len < needed) {
            struct pollfd pfd = { client->fd, POLLIN, 0 };
            int ready = poll(&pfd, 1, 20000);
            assert(ready > 0);
            ssize_t received = read(client->fd, buffer + len, cap - len - 1u);
            assert(received > 0);
            len += (size_t)received;
            buffer[len] = '\0';
        }
        return buffer;
    }
}

static void expect_contains(test_client_t* client, const char* needle) {
    char* reply = read_reply(client);
    if (strstr(reply, needle) == NULL) {
        fprintf(stderr, "expected '%s' in reply (%zu bytes): ", needle, strlen(reply));
        for (size_t i = 0; i < strlen(reply) && i < 96; i++) fputc((unsigned char)reply[i] >= 32 && (unsigned char)reply[i] < 127 ? reply[i] : '.', stderr);
        fputc('\n', stderr);
        assert(false);
    }
    free(reply);
}


/* One reply must contain `needle` and must not leak `absent`. */
static void expect_contains_not(test_client_t* client, const char* needle, const char* absent) {
    char* reply = read_reply(client);
    if (needle && strstr(reply, needle) == NULL) {
        fprintf(stderr, "expected '%s' in reply (%zu bytes): ", needle, strlen(reply));
        for (size_t i = 0; i < strlen(reply) && i < 96; i++) fputc((unsigned char)reply[i] >= 32 && (unsigned char)reply[i] < 127 ? reply[i] : '.', stderr);
        fputc('\n', stderr);
        assert(false);
    }
    if (absent && strstr(reply, absent) != NULL) {
        fprintf(stderr, "payload leak: '%s' present in reply\n", absent);
        assert(false);
    }
    free(reply);
}


int main(void) {
    char data_dir[] = "/tmp/qihse-bundle-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    char keys_dir[512];
    snprintf(keys_dir, sizeof(keys_dir), "%s/keys", data_dir);
    assert(mkdir(keys_dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    qihse_pqc_init_providers();

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(operator_user, 7, 71,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT7_PW, false);
    assert(tenant7 != NULL);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(operator_user, 8, 72,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT8_PW, false);
    assert(tenant8 != NULL);

    /* Tenant client key material: fresh ML-KEM-1024 keypair per tenant
     * (private stays client-side; public published to the composer's
     * keys_dir) + an ML-DSA-87 server signing key for manifest signatures. */
    char tenant7_kem_priv[600], published[600], dsa_key_path[600], dsa_pub[600];
    snprintf(tenant7_kem_priv, sizeof(tenant7_kem_priv), "%s/tenant-7-kem_priv.pem", keys_dir);
    snprintf(published, sizeof(published), "%s/tenant-7-kem_pub.pem", keys_dir);
    char tenant8_kem_priv[600], published8[600];
    snprintf(tenant8_kem_priv, sizeof(tenant8_kem_priv), "%s/tenant-8-kem_priv.pem", keys_dir);
    snprintf(published8, sizeof(published8), "%s/tenant-8-kem_pub.pem", keys_dir);
    snprintf(dsa_key_path, sizeof(dsa_key_path), "%s/qihse_dsa_key.pem", keys_dir);
    snprintf(dsa_pub, sizeof(dsa_pub), "%s/qihse_dsa_pub.pem", keys_dir);
    assert(write_keypair_pem("ML-KEM-1024", tenant7_kem_priv, published));
    assert(write_keypair_pem("ML-KEM-1024", tenant8_kem_priv, published8));
    assert(write_keypair_pem("ML-DSA-87", dsa_key_path, dsa_pub));

    /* Content + blob store + pointers. */
    qihse_blob_store_t* blobs;
    {
        char blob_dir[512];
        snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", data_dir);
        blobs = qihse_blob_store_create(blob_dir);
    }
    assert(blobs != NULL);
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);

    uint8_t pattern[100000];
    for (size_t i = 0; i < sizeof(pattern); i++) pattern[i] = (uint8_t)(i * 3u);
    uint8_t script[5000];
    memset(script, 0x5A, sizeof(script));
    uint8_t pattern_hash[QIHSE_BLOB_HASH_BYTES], script_hash[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_PATTERN_BUNDLE, 0, 0,
                                      operator_user, pattern, sizeof(pattern), pattern_hash));
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                      operator_user, script, sizeof(script), script_hash));
    char pattern_hex[QIHSE_BLOB_HASH_HEX], script_hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(pattern_hash, pattern_hex);
    qihse_blob_hash_to_hex(script_hash, script_hex);

    char pointer_key[128];
    snprintf(pointer_key, sizeof(pointer_key), "t:7/bundle/pattern/%s", BUILD_FP);
    assert(qihse_kv_set_user(store, pointer_key, pattern_hex, 0, 0, operator_user));
    assert(qihse_kv_set_user(store, "t:7/bundle/scripts", script_hex, 0, 0, operator_user));

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0;
    config.auth_required = true;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    config.blobs = blobs;
    config.bundle_keys_dir = keys_dir;
    config.bundle_dsa_private_key_path = dsa_key_path;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    /* --- Positive: tenant 7 composes and pulls its bundle ---------------- */
    test_client_t t7;
    client_init(&t7, server);
    const char* auth7[] = { "AUTH", "User_71", TENANT7_PW };
    send_command(t7.fd, 3, auth7);
    expect_contains(&t7, "+OK");

    const char* prepare[] = { "BUNDLE.PREPARE", BUILD_FP };
    send_command(t7.fd, 2, prepare);
    {
        char* manifest = read_reply(&t7);
        assert(strstr(manifest, "QHSE-BUNDLE 1") != NULL);
        assert(strstr(manifest, "tenant:7") != NULL);
        assert(strstr(manifest, "session-key:MLKEM1024 ") != NULL);
        assert(strstr(manifest, pattern_hex) != NULL);
        assert(strstr(manifest, script_hex) != NULL);
        free(manifest);
    }

    /* Chunked delivery round-trip. */
    const char* chunk0[] = { "BUNDLE.CHUNK", pattern_hex, "0" };
    send_command(t7.fd, 3, chunk0);
    {
        char* chunk = read_reply(&t7);
        assert(memcmp(chunk, "$65536\r\n", 8) == 0);
        assert(memcmp(chunk + 8, pattern, 65536) == 0);
        free(chunk);
    }
    const char* chunk_tail[] = { "BUNDLE.CHUNK", pattern_hex, "98304" };
    send_command(t7.fd, 3, chunk_tail);
    {
        char* chunk = read_reply(&t7);
        assert(memcmp(chunk, "$1696\r\n", 7) == 0);
        assert(memcmp(chunk + 7, pattern + 98304, 1696) == 0);
        free(chunk);
    }

    /* Delta: client already holds the pattern blob. */
    const char* prepare_delta[] = { "BUNDLE.PREPARE", BUILD_FP, pattern_hex };
    send_command(t7.fd, 3, prepare_delta);
    {
        char* manifest = read_reply(&t7);
        assert(strstr(manifest, "QHSE-BUNDLE 1") != NULL);
        assert(strstr(manifest, pattern_hex) == NULL); /* delta excluded */
        assert(strstr(manifest, script_hex) != NULL);
        free(manifest);
    }

    /* --- Negative: cross-tenant compose + chunk --------------------------- */
    test_client_t t8;
    client_init(&t8, server);
    const char* auth8[] = { "AUTH", "User_72", TENANT8_PW };
    send_command(t8.fd, 3, auth8);
    expect_contains(&t8, "+OK");
    const char* foreign_prepare[] = { "BUNDLE.PREPARE", BUILD_FP };
    send_command(t8.fd, 2, foreign_prepare);
    expect_contains_not(&t8, "ERR bundle compose failed", pattern_hex);
    const char* foreign_chunk[] = { "BUNDLE.CHUNK", pattern_hex, "0" };
    send_command(t8.fd, 3, foreign_chunk);
    expect_contains(&t8, "ERR blob read denied");

    /* Commons-poisoning sanity gate: tenant 8's pointer names tenant 7's
     * pattern blob — the binding check must refuse it. */
    char bad_pointer_key[128];
    snprintf(bad_pointer_key, sizeof(bad_pointer_key), "t:8/bundle/pattern/%s", BUILD_FP);
    assert(qihse_kv_set_user(store, bad_pointer_key, pattern_hex, 0, 0, operator_user));
    send_command(t8.fd, 2, foreign_prepare);
    expect_contains(&t8, "sanity gate rejected");

    /* --- Negative: unauthenticated prepare -------------------------------- */
    test_client_t anon;
    client_init(&anon, server);
    send_command(anon.fd, 2, prepare);
    expect_contains(&anon, "NOAUTH");

    /* --- Positive control: system-domain compose on behalf of tenant 8 ---- */
    test_client_t op;
    client_init(&op, server);
    const char* auth_op[] = { "AUTH", "GODMODE_OP", OPERATOR_PASSWORD };
    send_command(op.fd, 3, auth_op);
    expect_contains(&op, "+OK");
    const char* op_prepare[] = { "BUNDLE.PREPARE", "7", BUILD_FP };
    send_command(op.fd, 3, op_prepare);
    expect_contains(&op, "QHSE-BUNDLE 1");

    /* --- Session-key freshness: two composes produce different ciphertexts */
    const char* prepare_again[] = { "BUNDLE.PREPARE", BUILD_FP };
    send_command(t7.fd, 2, prepare);
    {
        char* first = read_reply(&t7);
        send_command(t7.fd, 2, prepare_again);
        char* second = read_reply(&t7);
        assert(strstr(first, "session-key:MLKEM1024 ") != NULL);
        assert(strstr(second, "session-key:MLKEM1024 ") != NULL);
        /* Compare the first 64 hex chars of each ciphertext. */
        const char* a = strstr(first, "session-key:MLKEM1024 ") + 22;
        const char* b = strstr(second, "session-key:MLKEM1024 ") + 22;
        assert(memcmp(a, b, 64) != 0); /* fresh encapsulation every session */
        free(first);
        free(second);
    }

    /* --- Negative: revocation mid-transfer -------------------------------- */
    assert(qihse_auth_destroy_user(operator_user, 71));
    send_command(t7.fd, 3, chunk0);
    /* The per-command revocation gate fires before the blob layer even runs. */
    expect_contains(&t7, "NOAUTH Session principal revoked");
    send_command(t7.fd, 2, prepare);
    expect_contains(&t7, "NOAUTH");

    close(t7.fd);
    close(t8.fd);
    close(anon.fd);
    close(op.fd);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    qihse_blob_store_destroy(blobs);
    printf("test_bundle_security_regression: all assertions passed\n");
    return 0;
}
