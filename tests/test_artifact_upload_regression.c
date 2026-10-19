/* Principal-bearing RESP upload, exact digest, range read, and denial tests. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_blob.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#define OP_PW "ArtifactOperatorPassword1!"
#define T7_PW "ArtifactTenantSevenPass1!"
#define T8_PW "ArtifactTenantEightPass1!"

typedef struct { qihse_resp_server_t* server; int fd; } worker_t;
typedef struct { int fd; pthread_t thread; } client_t;

static void* serve(void* opaque) {
    worker_t* w = opaque;
    (void)qihse_resp_server_handle_client_fd(w->server, w->fd);
    free(w);
    return NULL;
}

static client_t connect_client(qihse_resp_server_t* server) {
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct timeval timeout = {.tv_sec = 8};
    assert(setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    worker_t* w = malloc(sizeof(*w));
    assert(w);
    *w = (worker_t){server, pair[1]};
    client_t client = {.fd = pair[0]};
    assert(pthread_create(&client.thread, NULL, serve, w) == 0);
    return client;
}

static void disconnect_client(client_t* c) {
    shutdown(c->fd, SHUT_RDWR);
    close(c->fd);
    assert(pthread_join(c->thread, NULL) == 0);
}

static void write_all(int fd, const void* data, size_t len) {
    const uint8_t* bytes = data;
    while (len) {
        ssize_t written = write(fd, bytes, len);
        assert(written > 0);
        bytes += written;
        len -= (size_t)written;
    }
}

static void send_args(int fd, size_t count, const void* const* args, const size_t* lens) {
    char header[64];
    int n = snprintf(header, sizeof(header), "*%zu\r\n", count);
    write_all(fd, header, (size_t)n);
    for (size_t i = 0; i < count; i++) {
        n = snprintf(header, sizeof(header), "$%zu\r\n", lens[i]);
        write_all(fd, header, (size_t)n);
        write_all(fd, args[i], lens[i]);
        write_all(fd, "\r\n", 2);
    }
}

#define CMD(fd, ...) do { \
    const char* v[] = {__VA_ARGS__}; \
    size_t n[sizeof(v) / sizeof(v[0])]; \
    for (size_t i = 0; i < sizeof(n) / sizeof(n[0]); i++) n[i] = strlen(v[i]); \
    send_args(fd, sizeof(n) / sizeof(n[0]), (const void* const*)v, n); \
} while (0)

static size_t read_reply(int fd, uint8_t* out, size_t cap) {
    size_t used = 0;
    do {
        assert(used < cap);
        assert(read(fd, out + used, 1) == 1);
        used++;
    } while (used < 2 || out[used - 2] != '\r' || out[used - 1] != '\n');
    if (out[0] == '$') {
        out[used - 2] = '\0';
        size_t len = (size_t)strtoull((char*)out + 1, NULL, 10);
        assert(len + 2 <= cap - used);
        size_t want = used + len + 2;
        while (used < want) {
            ssize_t got = read(fd, out + used, want - used);
            assert(got > 0);
            used += (size_t)got;
        }
        assert(out[used - 2] == '\r' && out[used - 1] == '\n');
        return len;
    }
    assert(used < cap);
    out[used] = '\0';
    return used;
}

static void expect_prefix(client_t* c, char prefix) {
    uint8_t reply[4096];
    read_reply(c->fd, reply, sizeof(reply));
    assert(reply[0] == prefix);
}

int main(void) {
    char data_dir[512], staging[560], blob_dir[560];
    const char* tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = P_tmpdir;
    assert(snprintf(data_dir, sizeof(data_dir), "%s/qihse-artifact-XXXXXX", tmp) < (int)sizeof(data_dir));
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OP_PW));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user);
    assert(qihse_auth_create_tenant_user(operator_user, 7, 71, QIHSE_ROLE_GUEST, 91, 0, T7_PW, false));
    assert(qihse_auth_create_tenant_user(operator_user, 8, 72, QIHSE_ROLE_GUEST, 91, 0, T8_PW, false));
    snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", data_dir);
    snprintf(staging, sizeof(staging), "%s/staging", data_dir);
    assert(mkdir(staging, 0700) == 0);
    qihse_blob_store_t* blobs = qihse_blob_store_create(blob_dir);
    qihse_kv_store_t* kv = qihse_kv_store_create();
    char vdb_path[560];
    snprintf(vdb_path, sizeof(vdb_path), "%s/forensic.qdb", data_dir);
    qihse_vector_db_t forensic = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL,
                            vdb_path, QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED);
    assert(blobs && kv && forensic);
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = kv;
    config.blobs = blobs;
    config.forensic_vdb = forensic;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    config.enable_artifact_uploads = true;
    config.artifact_staging_dir = staging;
    config.auth_required = false;
    assert(qihse_resp_server_create(&config) == NULL);
    config.auth_required = true;
    assert(chmod(staging, 0755) == 0);
    assert(qihse_resp_server_create(&config) == NULL);
    assert(chmod(staging, 0700) == 0);
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server);
    uint8_t data[37] = {'M', 'D', 'M', 'P', 0, 255, 4, 3};
    for (size_t i = 8; i < sizeof(data); i++) data[i] = (uint8_t)(i * 23u);
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    unsigned int hlen = 0;
    assert(EVP_Digest(data, sizeof(data), hash, &hlen, EVP_sha384(), NULL) == 1);
    assert(hlen == sizeof(hash));
    char hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(hash, hex);

    qihse_resp_server_config_t remote_config = config;
    remote_config.bind_address = "0.0.0.0";
    qihse_resp_server_t* remote_server = qihse_resp_server_create(&remote_config);
    assert(remote_server);
    client_t unsealed = connect_client(remote_server);
    CMD(unsealed.fd, "AUTH", "GODMODE_OP", OP_PW); expect_prefix(&unsealed, '+');
    CMD(unsealed.fd, "ARTIFACT.BEGIN", "7", "95", "0", "37", hex);
    expect_prefix(&unsealed, '-');
    disconnect_client(&unsealed);
    qihse_resp_server_destroy(remote_server);

    client_t unauth = connect_client(server);
    CMD(unauth.fd, "ARTIFACT.BEGIN", "7", "95", "0", "37", hex);
    expect_prefix(&unauth, '-');
    disconnect_client(&unauth);

    client_t low = connect_client(server);
    CMD(low.fd, "AUTH", "User_71", T7_PW); expect_prefix(&low, '+');
    CMD(low.fd, "ARTIFACT.BEGIN", "7", "95", "0", "37", hex);
    expect_prefix(&low, '-');
    CMD(low.fd, "ARTIFACT.BEGIN", "7", "0", "0", "37", hex);
    expect_prefix(&low, '-'); /* authenticated tenant cannot exhaust disk */
    CMD(low.fd, "ARTIFACT.BEGIN", "8", "0", "0", "37", hex);
    expect_prefix(&low, '-');

    client_t op = connect_client(server);
    CMD(op.fd, "AUTH", "GODMODE_OP", OP_PW); expect_prefix(&op, '+');
    CMD(op.fd, "ARTIFACT.BEGIN", "7", "95", "0", "37", hex);
    expect_prefix(&op, '+');
    CMD(op.fd, "ARTIFACT.COMMIT"); expect_prefix(&op, '-');
    const void* bad_chunk[] = {"ARTIFACT.CHUNK", "1", data};
    size_t bad_sizes[] = {14, 1, sizeof(data)};
    send_args(op.fd, 3, bad_chunk, bad_sizes); expect_prefix(&op, '-');
    const void* chunk[] = {"ARTIFACT.CHUNK", "0", data};
    size_t chunk_sizes[] = {14, 1, sizeof(data)};
    send_args(op.fd, 3, chunk, chunk_sizes); expect_prefix(&op, ':');
    CMD(op.fd, "ARTIFACT.COMMIT");
    uint8_t reply[4096];
    assert(read_reply(op.fd, reply, sizeof(reply)) == strlen(hex));
    assert(memcmp(reply + 5, hex, strlen(hex)) == 0); /* $96\r\n + payload */

    CMD(op.fd, "ARTIFACT.GET", hex, "4", "12");
    assert(read_reply(op.fd, reply, sizeof(reply)) == 12);
    assert(memcmp(reply + 5, data + 4, 12) == 0); /* $12\r\n + binary payload */
    uint8_t empty_hash[QIHSE_BLOB_HASH_BYTES];
    assert(EVP_Digest("", 0, empty_hash, &hlen, EVP_sha384(), NULL) == 1);
    char empty_hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(empty_hash, empty_hex);
    CMD(op.fd, "ARTIFACT.BEGIN", "7", "95", "0", "0", empty_hex); expect_prefix(&op, '+');
    CMD(op.fd, "ARTIFACT.COMMIT");
    assert(read_reply(op.fd, reply, sizeof(reply)) == strlen(empty_hex));
    CMD(op.fd, "ARTIFACT.GET", empty_hex, "0", "0");
    assert(read_reply(op.fd, reply, sizeof(reply)) == 0);
    CMD(low.fd, "ARTIFACT.GET", hex, "0", "12"); expect_prefix(&low, '-');
    float vector[1024] = {1.0f};
    const void* vec_args[] = {"FORENSIC.SET", "17", hex, "0", "37", vector};
    size_t vec_sizes[] = {12, 2, strlen(hex), 1, 2, sizeof(vector)};
    send_args(low.fd, 6, vec_args, vec_sizes); expect_prefix(&low, '-');
    send_args(op.fd, 6, vec_args, vec_sizes); expect_prefix(&op, '+');
    CMD(low.fd, "FORENSIC.SEARCH", "1"); expect_prefix(&low, '-');
    const void* query[] = {"FORENSIC.SEARCH", "1", vector};
    size_t query_sizes[] = {15, 1, sizeof(vector)};
    send_args(op.fd, 3, query, query_sizes);
    char header[64];
    size_t pos = 0;
    do {
        assert(pos + 1 < sizeof(header));
        assert(read(op.fd, header + pos, 1) == 1);
        pos++;
    } while (pos < 2 || header[pos - 2] != '\r' || header[pos - 1] != '\n');
    assert(pos == 4 && memcmp(header, "*1\r\n", 4) == 0);
    pos = 0;
    do {
        assert(pos + 1 < sizeof(header));
        assert(read(op.fd, header + pos, 1) == 1);
        pos++;
    } while (pos < 2 || header[pos - 2] != '\r' || header[pos - 1] != '\n');
    assert(pos == 4 && memcmp(header, "*3\r\n", 4) == 0);
    assert(read_reply(op.fd, reply, sizeof(reply)) == 2); /* id=17 */
    read_reply(op.fd, reply, sizeof(reply)); /* score */
    assert(read_reply(op.fd, reply, sizeof(reply)) > strlen(hex)); /* source reference */
    client_t other = connect_client(server);
    CMD(other.fd, "AUTH", "User_72", T8_PW); expect_prefix(&other, '+');
    CMD(other.fd, "ARTIFACT.GET", hex, "0", "12"); expect_prefix(&other, '-');

    CMD(op.fd, "ARTIFACT.BEGIN", "7", "95", "0", "4294967297", hex);
    expect_prefix(&op, '-');
    char wrong_hash[QIHSE_BLOB_HASH_HEX];
    memset(wrong_hash, '0', QIHSE_BLOB_HASH_HEX - 1u);
    wrong_hash[QIHSE_BLOB_HASH_HEX - 1u] = '\0';
    CMD(op.fd, "ARTIFACT.BEGIN", "7", "95", "0", "37", wrong_hash);
    expect_prefix(&op, '+');
    send_args(op.fd, 3, chunk, chunk_sizes); expect_prefix(&op, ':');
    CMD(op.fd, "ARTIFACT.COMMIT"); expect_prefix(&op, '-');
    CMD(op.fd, "ARTIFACT.GET", wrong_hash, "0", "12"); expect_prefix(&op, '-');
    CMD(op.fd, "ARTIFACT.BEGIN", "7", "95", "0", "37", hex);
    expect_prefix(&op, '+');
    CMD(op.fd, "ARTIFACT.ABORT"); expect_prefix(&op, '+');
    disconnect_client(&other);
    disconnect_client(&low);
    disconnect_client(&op);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(kv);
    qihse_vector_db_destroy(forensic);
    qihse_blob_store_destroy(blobs);
    puts("test_artifact_upload_regression: all assertions passed");
    return 0;
}
