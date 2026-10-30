#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "qihse_pg_wire.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_auth.h"
#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_schema.h"

typedef struct {
    int server_fd;
    qihse_kv_store_t* store;
    qihse_cluster_topology_t* topo;
    qihse_uwp_context_t* uwp;
} server_thread_args_t;

typedef struct {
    qihse_pg_wire_listener_t* listener;
    int result;
} listener_thread_args_t;

static void* listener_once_worker(void* arg) {
    listener_thread_args_t* a = (listener_thread_args_t*)arg;
    a->result = qihse_pg_wire_listener_accept_once(a->listener, 10000);
    return NULL;
}

static void* server_worker(void* arg) {
    server_thread_args_t* a = (server_thread_args_t*)arg;
    qihse_pg_wire_handle_client_uwp(a->server_fd, a->uwp, a->topo);
    return NULL;
}

static __thread SSL* test_ssl;

static void write_all(int fd, const void* data, size_t len) {
    const uint8_t* p = data;
    while (len) {
        ssize_t n = test_ssl ? SSL_write(test_ssl, p, (int)len) : write(fd, p, len);
        if (!test_ssl && n < 0 && errno == EINTR) continue;
        assert(n > 0);
        p += n;
        len -= (size_t)n;
    }
}

static void read_all(int fd, void* data, size_t len) {
    uint8_t* p = data;
    while (len) {
        ssize_t n = test_ssl ? SSL_read(test_ssl, p, (int)len) : read(fd, p, len);
        if (!test_ssl && n < 0 && errno == EINTR) continue;
        assert(n > 0); /* EOF or receive timeout is a test failure. */
        p += n;
        len -= (size_t)n;
    }
}

static void read_until_ready(int fd) {
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, sizeof(wire_len));
        uint32_t len = ntohl(wire_len);
        assert(len >= 4 && len <= 1024 * 1024);
        char* body = malloc(len - 4 ? len - 4 : 1);
        assert(body);
        read_all(fd, body, len - 4);
        free(body);
        if (tag == 'Z') return;
    }
}

static char read_ready_status(int fd) {
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, sizeof(wire_len));
        uint32_t len = ntohl(wire_len);
        assert(len >= 4 && len <= 1024 * 1024);
        char* body = malloc(len - 4 ? len - 4 : 1);
        assert(body);
        read_all(fd, body, len - 4);
        if (tag == 'Z') {
            assert(len == 5);
            char status = body[0];
            free(body);
            return status;
        }
        free(body);
    }
}

static void send_pg_msg(int fd, uint8_t tag, const char* body, size_t body_len) {
    uint32_t msg_len = (uint32_t)(4 + body_len);
    uint8_t header[5];
    header[0] = tag;
    header[1] = (uint8_t)((msg_len >> 24) & 0xff);
    header[2] = (uint8_t)((msg_len >> 16) & 0xff);
    header[3] = (uint8_t)((msg_len >> 8) & 0xff);
    header[4] = (uint8_t)(msg_len & 0xff);
    write_all(fd, header, 5);
    if (body_len > 0) {
        write_all(fd, body, body_len);
    }
}

static void start_pg_client(int fd, const char* username, const char* password) {
    uint8_t startup[512];
    size_t pos = 0;
    const char* keys[] = {"user", "database"};
    const char* values[] = {username, "qihse"};
    for (size_t i = 0; i < 2; ++i) {
        size_t key_len = strlen(keys[i]) + 1u;
        size_t value_len = strlen(values[i]) + 1u;
        memcpy(startup + pos, keys[i], key_len); pos += key_len;
        memcpy(startup + pos, values[i], value_len); pos += value_len;
    }
    startup[pos++] = '\0';
    uint32_t packet_len = htonl((uint32_t)(8u + pos));
    uint32_t protocol = htonl(196608u);
    write_all(fd, &packet_len, sizeof(packet_len));
    write_all(fd, &protocol, sizeof(protocol));
    write_all(fd, startup, pos);

    uint8_t tag;
    uint32_t wire_len, auth_type;
    read_all(fd, &tag, 1);
    assert(tag == 'R');
    read_all(fd, &wire_len, sizeof(wire_len));
    assert(ntohl(wire_len) == 8u);
    read_all(fd, &auth_type, sizeof(auth_type));
    assert(ntohl(auth_type) == 3u);

    size_t password_len = strlen(password) + 1u;
    uint8_t password_tag = 'p';
    uint32_t password_msg_len = htonl((uint32_t)(4u + password_len));
    write_all(fd, &password_tag, 1);
    write_all(fd, &password_msg_len, sizeof(password_msg_len));
    write_all(fd, password, password_len);
    read_until_ready(fd);
}

static char read_ready_status_capture_error(int fd, uint8_t* error,
                                            size_t error_cap,
                                            size_t* error_len) {
    if (error_len) *error_len = 0;
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, sizeof(wire_len));
        uint32_t len = ntohl(wire_len);
        assert(len >= 4 && len <= 1024 * 1024);
        size_t body_len = (size_t)len - 4u;
        uint8_t* body = malloc(body_len ? body_len : 1u);
        assert(body);
        read_all(fd, body, body_len);
        assert(tag != 'T' && tag != 'D'); /* Denial must not disclose metadata or rows. */
        if (tag == 'E' && error && error_cap && error_len) {
            size_t copy = body_len < error_cap - 1u ? body_len : error_cap - 1u;
            memcpy(error, body, copy);
            *error_len = copy;
        }
        if (tag == 'Z') {
            assert(body_len == 1u);
            char result = (char)body[0];
            free(body);
            return result;
        }
        free(body);
    }
}

static bool contains_bytes(const void* haystack, size_t haystack_len,
                           const char* needle);

static size_t read_pg_response(int fd, uint8_t* tag, uint8_t* body, size_t cap) {
    uint32_t wire_len;
    read_all(fd, tag, 1);
    read_all(fd, &wire_len, 4);
    size_t len = ntohl(wire_len);
    assert(len >= 4 && len - 4 <= cap);
    read_all(fd, body, len - 4);
    return len - 4;
}

static void send_prepared_select(int fd, const char* name, const char* sql,
                                 uint32_t oid) {
    uint8_t body[512];
    size_t n = strlen(name) + 1;
    assert(n + strlen(sql) + 1 + 6 <= sizeof(body));
    memcpy(body, name, n);
    memcpy(body + n, sql, strlen(sql) + 1);
    n += strlen(sql) + 1;
    body[n++] = 0; body[n++] = 1;
    uint32_t network_oid = htonl(oid);
    memcpy(body + n, &network_oid, 4); n += 4;
    send_pg_msg(fd, 'P', (char*)body, n);
}

static void send_bound_portal(int fd, const char* portal, const char* statement,
                              int16_t format, const void* value, int32_t size) {
    uint8_t body[512];
    size_t n = strlen(portal) + 1u;
    size_t statement_len = strlen(statement) + 1;
    assert(n + statement_len + 16 + (size > 0 ? (size_t)size : 0) <= sizeof(body));
    memcpy(body, portal, n);
    memcpy(body + n, statement, statement_len); n += statement_len;
    body[n++] = 0; body[n++] = 1; /* one parameter format */
    body[n++] = (uint8_t)(format >> 8); body[n++] = (uint8_t)format;
    body[n++] = 0; body[n++] = 1; /* one parameter */
    uint32_t network_size = htonl((uint32_t)size);
    memcpy(body + n, &network_size, 4); n += 4;
    if (size > 0) { memcpy(body + n, value, (size_t)size); n += (size_t)size; }
    body[n++] = 0; body[n++] = 0; /* text result */
    send_pg_msg(fd, 'B', (char*)body, n);
}

static void send_bound_select(int fd, const char* statement, int16_t format,
                              const void* value, int32_t size) {
    send_bound_portal(fd, "", statement, format, value, size);
}

static void assert_extended_select_state(int fd, const char* expected,
                                         bool row_expected, char ready) {
    uint8_t tag, body[1024];
    size_t n = read_pg_response(fd, &tag, body, sizeof(body));
    assert(tag == '1' && n == 0); /* ParseComplete */
    n = read_pg_response(fd, &tag, body, sizeof(body));
    assert(tag == '2' && n == 0); /* BindComplete */
    bool found = false, completed = false;
    for (;;) {
        n = read_pg_response(fd, &tag, body, sizeof(body));
        if (tag == 'D') {
            assert(row_expected && !found && !completed);
            assert(expected && contains_bytes(body, n, expected));
            found = true;
        } else if (tag == 'C') {
            assert(!completed && n > 0 && body[n - 1] == 0 && found == row_expected);
            completed = true;
        } else if (tag == 'Z') {
            assert(completed && n == 1 && body[0] == ready && found == row_expected);
            return;
        } else {
            assert(!"unexpected extended response or error");
        }
    }
}

static void assert_extended_select(int fd, const char* expected, bool row_expected) {
    assert_extended_select_state(fd, expected, row_expected, 'I');
}

static char read_extended_error_sync(int fd, const char* sqlstate) {
    uint8_t tag, body[512];
    size_t n = read_pg_response(fd, &tag, body, sizeof(body));
    assert(tag == 'E' && n > 0); /* No ParseComplete, BindComplete or rows. */
    assert(!contains_bytes(body, n, "PG-WIRE-PROTECTED-MARKER"));
    if (sqlstate) assert(contains_bytes(body, n, sqlstate));
    n = read_pg_response(fd, &tag, body, sizeof(body));
    assert(tag == 'Z' && n == 1);
    return (char)body[0];
}

static char read_extended_denial_sync(int fd, const char* sqlstate) {
    uint8_t tag, body[512];
    bool denied = false;
    for (;;) {
        size_t n = read_pg_response(fd, &tag, body, sizeof(body));
        if (tag == 'E') {
            assert(!denied && (!sqlstate || contains_bytes(body, n, sqlstate)));
            assert(!contains_bytes(body, n, "PG-WIRE-PROTECTED-MARKER"));
            denied = true;
        } else if (tag == 'Z') {
            assert(denied && n == 1);
            return (char)body[0];
        } else {
            assert(!denied && (tag == '1' || tag == '2'));
        }
    }
}

static char read_ready_status_capture_all(int fd, uint8_t* output,
                                          size_t cap, size_t* output_len) {
    *output_len = 0;
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, 4);
        uint32_t len = ntohl(wire_len);
        assert(len >= 4 && len <= 1024 * 1024);
        size_t n = len - 4u;
        assert(n <= cap - *output_len);
        read_all(fd, output + *output_len, n);
        *output_len += n;
        if (tag == 'Z') {
            assert(n == 1u);
            return (char)output[*output_len - 1u];
        }
    }
}

static char read_ready_status_capture_row(int fd, uint8_t* row,
                                          size_t cap, size_t* row_len) {
    *row_len = 0;
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, 4);
        uint32_t len = ntohl(wire_len);
        assert(len >= 4 && len <= 1024 * 1024);
        size_t n = len - 4u;
        uint8_t* body = malloc(n ? n : 1u);
        assert(body);
        read_all(fd, body, n);
        if (tag == 'D' || tag == 'E') {
            assert(n <= cap);
            memcpy(row, body, n);
            *row_len = n;
        }
        if (tag == 'Z') {
            assert(n == 1);
            char status = (char)body[0];
            free(body);
            return status;
        }
        free(body);
    }
}

static void assert_select_types(int fd, const int32_t* expected, size_t count,
                                const char* value) {
    bool saw_description = false, saw_value = false;
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, 4);
        size_t n = ntohl(wire_len) - 4u;
        assert(n <= 1024 * 1024);
        uint8_t* body = malloc(n ? n : 1);
        assert(body);
        read_all(fd, body, n);
        if (tag == 'T') {
            assert(!saw_description && n >= 2 &&
                   (((size_t)body[0] << 8) | body[1]) == count);
            size_t off = 2;
            for (size_t i = 0; i < count; ++i) {
                size_t name_len = strnlen((char*)body + off, n - off);
                assert(name_len < n - off);
                off += name_len + 1;
                assert(n - off >= 18);
                uint32_t oid;
                memcpy(&oid, body + off + 6, 4);
                assert((int32_t)ntohl(oid) == expected[i]);
                off += 18;
            }
            assert(off == n);
            saw_description = true;
        } else if (tag == 'D') {
            assert(saw_description);
            if (value && contains_bytes(body, n, value)) saw_value = true;
        } else if (tag == 'E') {
            assert(!"SELECT disclosed an error instead of typed rows");
        } else if (tag == 'Z') {
            assert(n == 1 && body[0] == 'I' && saw_description);
            assert(!value || saw_value);
            free(body);
            return;
        }
        free(body);
    }
}

static void assert_select_nullability(int fd, const int32_t* expected,
                                      const bool* null_fields, size_t count) {
    bool saw_description = false, saw_row = false;
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, 4);
        size_t n = ntohl(wire_len) - 4u;
        assert(n <= 1024 * 1024);
        uint8_t* body = malloc(n ? n : 1u);
        assert(body);
        read_all(fd, body, n);
        if (tag == 'T') {
            assert(!saw_description && n >= 2 &&
                   (((size_t)body[0] << 8) | body[1]) == count);
            size_t off = 2;
            for (size_t i = 0; i < count; ++i) {
                size_t name_len = strnlen((char*)body + off, n - off);
                assert(name_len < n - off);
                off += name_len + 1;
                assert(n - off >= 18);
                uint32_t oid;
                memcpy(&oid, body + off + 6, 4);
                assert((int32_t)ntohl(oid) == expected[i]);
                off += 18;
            }
            assert(off == n);
            saw_description = true;
        } else if (tag == 'D') {
            assert(saw_description && !saw_row && n >= 2 &&
                   (((size_t)body[0] << 8) | body[1]) == count);
            size_t off = 2;
            for (size_t i = 0; i < count; ++i) {
                assert(n - off >= 4);
                uint32_t raw;
                memcpy(&raw, body + off, 4);
                int32_t len = (int32_t)ntohl(raw);
                off += 4;
                assert(len >= -1 && (null_fields[i] ? len == -1 : len >= 0));
                if (len >= 0) { assert((size_t)len <= n - off); off += (size_t)len; }
            }
            assert(off == n);
            saw_row = true;
        } else if (tag == 'E') {
            fprintf(stderr, "typed SELECT error:");
            for (size_t j = 0; j < n; ++j)
                if (body[j] >= 32 && body[j] < 127) fputc(body[j], stderr);
                else fprintf(stderr, "<%02x>", body[j]);
            fputc(10, stderr);
            assert(!"typed SELECT returned an error");
        } else if (tag == 'Z') {
            assert(n == 1 && body[0] == 'I' && saw_description && saw_row);
            free(body);
            return;
        }
        free(body);
    }
}

static void retry_digest_hex(const char* sql, char hex[65]) {
    static const char domain[] = "QIHSE-SQL-RETRY-v1";
    EVP_MD_CTX* hash = EVP_MD_CTX_new();
    assert(hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1);
    assert(EVP_DigestUpdate(hash, domain, sizeof(domain) - 1) == 1);
    uint8_t isolation = QIHSE_ISO_READ_COMMITTED;
    assert(EVP_DigestUpdate(hash, &isolation, 1) == 1);
    uint32_t n = (uint32_t)strlen(sql);
    uint8_t width[4] = {(uint8_t)(n >> 24), (uint8_t)(n >> 16),
                        (uint8_t)(n >> 8), (uint8_t)n};
    assert(EVP_DigestUpdate(hash, width, sizeof(width)) == 1);
    assert(EVP_DigestUpdate(hash, sql, n) == 1);
    uint8_t digest[32];
    unsigned int digest_len = 0;
    assert(EVP_DigestFinal_ex(hash, digest, &digest_len) == 1 && digest_len == 32);
    EVP_MD_CTX_free(hash);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        hex[2*i] = digits[digest[i] >> 4];
        hex[2*i + 1] = digits[digest[i] & 15];
    }
    hex[64] = '\0';
}

static bool contains_bytes(const void* haystack, size_t haystack_len,
                           const char* needle) {
    size_t needle_len = strlen(needle);
    if (!needle_len || needle_len > haystack_len) return false;
    const uint8_t* bytes = haystack;
    for (size_t i = 0; i <= haystack_len - needle_len; ++i)
        if (memcmp(bytes + i, needle, needle_len) == 0) return true;
    return false;
}

static uint64_t table_resource_id(const char* name) {
    uint32_t hash = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)name; *p; ++p) {
        hash ^= *p;
        hash *= 16777619u;
    }
    return (uint64_t)hash;
}

static void make_test_certificate(char* cert_path, char* key_path) {
    int cert_fd = mkstemp(cert_path);
    int key_fd = mkstemp(key_path);
    assert(cert_fd >= 0 && key_fd >= 0);
    FILE* cert_file = fdopen(cert_fd, "w");
    FILE* key_file = fdopen(key_fd, "w");
    assert(cert_file && key_file);
    EVP_PKEY* key = EVP_RSA_gen(2048);
    X509* cert = X509_new();
    assert(key && cert);
    assert(X509_set_version(cert, 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(cert), -60));
    assert(X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
    assert(X509_set_pubkey(cert, key) == 1);
    X509_NAME* name = X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      (const unsigned char*)"localhost", -1, -1, 0) == 1);
    assert(X509_set_issuer_name(cert, name) == 1);
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION* san = X509V3_EXT_conf_nid(NULL, &ctx,
                                               NID_subject_alt_name,
                                               "DNS:localhost,IP:127.0.0.1");
    assert(san && X509_add_ext(cert, san, -1) == 1);
    X509_EXTENSION_free(san);
    assert(X509_sign(cert, key, EVP_sha256()) > 0);
    assert(PEM_write_X509(cert_file, cert) == 1);
    assert(PEM_write_PrivateKey(key_file, key, NULL, NULL, 0, NULL, NULL) == 1);
    assert(fclose(cert_file) == 0 && fclose(key_file) == 0);
    X509_free(cert);
    EVP_PKEY_free(key);
}

static int connect_test_port(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    assert(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}

static void test_pg_wire_handshake_and_queries() {
    printf("Testing PostgreSQL Wire Protocol Sharded Multi-Model Ingress...\n");
    signal(SIGPIPE, SIG_IGN);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("PGWireClusterTestPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    qihse_user_t* user = qihse_auth_create_user(op, 1, QIHSE_ROLE_OPERATOR, 0xFFFF, 0xFFFF, "PGWireClusterTestPass123!", false);
    assert(user);
    qihse_user_t* guest = qihse_auth_create_user(
        op, 2, QIHSE_ROLE_GUEST, 0, 0, "PGWireGuestPass123!", false);
    assert(guest && qihse_user_get_classification(guest) == 0u);
    qihse_user_t* tenant = qihse_auth_create_tenant_user(
        op, 7, 107, QIHSE_ROLE_ANALYST, 2, 0, "PGWireTenantPass123!", false);
    assert(tenant);

    qihse_uwp_context_t uwp;
    memset(&uwp, 0, sizeof(uwp));
    static int sql_engine_placeholder;
    uwp.sql_engine = &sql_engine_placeholder;
    uwp.schema = qihse_schema_registry_create();
    uwp.txn_manager = qihse_txn_manager_create();
    assert(uwp.schema && uwp.txn_manager);
    /* Provision a disposable versioned row/catalog fixture before binding
     * pgwire. Only the durable context may acknowledge bounded runtime DDL. */
    char durable_dir[] = "build/test_pgwire_durable_XXXXXX";
    assert(mkdtemp(durable_dir));
    char durable_path[256], lock_path[264];
    assert(snprintf(durable_path, sizeof durable_path, "%s/rows.snap",
                    durable_dir) < (int)sizeof durable_path);
    assert(snprintf(lock_path, sizeof lock_path, "%s.lock", durable_path)
           < (int)sizeof lock_path);
    qihse_table_store_t* fixture = qihse_table_store_open_durable(durable_path);
    assert(fixture);
    const char* names[] = {"pg_txn_wire", "pg_txn_protected", "pg_txn_labeled"};
    qihse_col_def_t columns[2] = {{(char*)"id", QIHSE_TS_INT32},
                                  {(char*)"note", QIHSE_TS_STRING}};
    for (size_t i = 0; i < 3; ++i) {
        char ddl[256];
        assert(snprintf(ddl, sizeof ddl,
                        i == 2 ? "CREATE TABLE %s (id INT, note TEXT, "
                                 "__qihse_tenant_id INT, __qihse_classification INT, "
                                 "__qihse_sci INT)" :
                                 "CREATE TABLE %s (id INT, note TEXT)",
                        names[i]) < (int)sizeof ddl);
        qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(ddl);
        assert(ast);
        assert(qihse_schema_create_table(uwp.schema, ast) == 0);
        qihse_sql_ast_free(ast);
    }
    qihse_col_def_t labeled_columns[5] = {
        {(char*)"id", QIHSE_TS_INT32}, {(char*)"note", QIHSE_TS_STRING},
        {(char*)"__qihse_tenant_id", QIHSE_TS_INT32},
        {(char*)"__qihse_classification", QIHSE_TS_INT32},
        {(char*)"__qihse_sci", QIHSE_TS_INT32}
    };
    uint8_t *catalog = NULL, *initial = NULL;
    size_t catalog_len = 0, initial_len = 0;
    qihse_schema_registry_t* empty = qihse_schema_registry_create();
    assert(empty && qihse_schema_serialize(empty, &initial, &initial_len) == 0);
    qihse_schema_registry_destroy(empty);
    assert(qihse_table_store_set_schema_image(fixture, initial, initial_len));
    assert(qihse_schema_serialize(uwp.schema, &catalog, &catalog_len) == 0);
    qihse_ts_new_table_t staged[] = {
        {.name = names[0], .cols = columns, .num_cols = 2},
        {.name = names[1], .cols = columns, .num_cols = 2},
        {.name = names[2], .cols = labeled_columns, .num_cols = 5}
    };
    assert(qihse_table_store_create_tables_with_schema(fixture, staged, 3,
        initial, initial_len, catalog, catalog_len));
    free(initial);
    free(catalog);
    qihse_table_t* seeded = qihse_table_store_find_table(
        fixture, "pg_txn_protected");
    assert(seeded);
    qihse_col_value_t protected_row[2] = {
        {.type = QIHSE_TS_INT32, .v.i32 = 7},
        {.type = QIHSE_TS_STRING, .v.str = (char*)"PG-WIRE-PROTECTED-MARKER"}
    };
    qihse_table_txn_t* seed_txn = qihse_table_txn_begin(seeded);
    assert(seed_txn && qihse_table_txn_insert(seed_txn, protected_row, 2) >= 0);
    assert(qihse_table_txn_commit(seed_txn));
    qihse_table_store_destroy(fixture);
    assert(qihse_uwp_sql_open_durable(&uwp, durable_path) == 0);
    assert(qihse_uwp_sql_durable_ready(&uwp));
    assert(qihse_auth_grant_object(op, guest, 0u,
                                   table_resource_id("pg_txn_wire"),
                                   QIHSE_ACL_READ));
    assert(qihse_auth_grant_object(op, tenant, 0u,
                                   table_resource_id("pg_txn_labeled"),
                                   QIHSE_ACL_READ | QIHSE_ACL_WRITE));

    int fds[2];
    int rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(rc == 0);
    struct timeval io_timeout = { .tv_sec = 30 };
    assert(setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);
    assert(setsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);
    assert(setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);
    assert(setsockopt(fds[1], SOL_SOCKET, SO_SNDTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    qihse_cluster_node_id_from_seed("alpha", 5, node.id);
    strncpy(node.host, "127.0.0.1", sizeof(node.host) - 1);
    node.port = 5432;
    node.healthy = true;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    uint16_t idx = 0;
    qihse_cluster_topology_upsert_node(topo, &node, &idx);
    qihse_cluster_topology_set_local_node(topo, idx);

    qihse_kv_store_t* kv = qihse_kv_store_create();
    qihse_kv_set(kv, "{device_4096}", "pg_wire_test_val", 0, 0);

    server_thread_args_t sargs = {
        .server_fd = fds[1],
        .store = kv,
        .topo = topo,
        .uwp = &uwp
    };

    pthread_t stid;
    pthread_create(&stid, NULL, server_worker, &sargs);

    const char* password = "PGWireClusterTestPass123!";
    start_pg_client(fds[0], "User_1", password);
    printf("  -> Startup handshake OK (AuthOk + ParameterStatus + ReadyForQuery)\n");

    const char* begin = "BEGIN\0";
    const char* rollback = "ROLLBACK\0";
    const char* commit = "COMMIT\0";
    const char* create_runtime = "CREATE TABLE pg_runtime (id INT, note TEXT)";
    send_pg_msg(fds[0], 'Q', create_runtime, strlen(create_runtime) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_schema_get_table(uwp.schema, "pg_runtime"));
    assert(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "pg_runtime"));
    const char* refused_create[] = {
        "CREATE TABLE pg_runtime (id INT, note TEXT)",
        "CREATE TABLE pg_tail (id INT) garbage",
        "CREATE TABLE pg_unclosed (id INT"
    };
    uint8_t ddl_error[512];
    size_t ddl_error_len = 0;
    for (size_t i = 0; i < sizeof(refused_create) / sizeof(refused_create[0]); ++i) {
        send_pg_msg(fds[0], 'Q', refused_create[i], strlen(refused_create[i]) + 1);
        assert(read_ready_status_capture_error(fds[0], ddl_error,
                sizeof(ddl_error), &ddl_error_len) == 'I');
        assert(ddl_error_len > 0);
    }
    assert(!qihse_schema_get_table(uwp.schema, "pg_tail") &&
           !qihse_schema_get_table(uwp.schema, "pg_unclosed"));
    const char* create_key = "CREATE TABLE pg_key (id INT PRIMARY KEY)";
    send_pg_msg(fds[0], 'Q', create_key, strlen(create_key) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_schema_get_table(uwp.schema, "pg_key"));
    const char* key_insert = "INSERT INTO pg_key VALUES (7)";
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', key_insert, strlen(key_insert) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', key_insert, strlen(key_insert) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status_capture_error(fds[0], ddl_error,
            sizeof(ddl_error), &ddl_error_len) == 'I');
    assert(ddl_error_len > 0);
    assert(qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_key")) == 1);
    const char* create_key_if_absent =
        "CREATE TABLE IF NOT EXISTS pg_key (id INT PRIMARY KEY)";
    send_pg_msg(fds[0], 'Q', create_key_if_absent,
                strlen(create_key_if_absent) + 1);
    assert(read_ready_status_capture_error(fds[0], ddl_error,
            sizeof(ddl_error), &ddl_error_len) == 'I');
    assert(ddl_error_len == 0);
    assert(qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_key")) == 1);
    const char* unsupported_if_absent =
        "CREATE TABLE IF NOT EXISTS pg_key (id NUMERIC PRIMARY KEY)";
    send_pg_msg(fds[0], 'Q', unsupported_if_absent,
                strlen(unsupported_if_absent) + 1);
    assert(read_ready_status_capture_error(fds[0], ddl_error,
            sizeof(ddl_error), &ddl_error_len) == 'I');
    assert(contains_bytes(ddl_error, ddl_error_len, "0A000"));
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* create_inside_txn = "CREATE TABLE pg_in_txn (id INT)";
    send_pg_msg(fds[0], 'Q', create_inside_txn, strlen(create_inside_txn) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    assert(!qihse_schema_get_table(uwp.schema, "pg_in_txn"));
    assert(!qihse_table_store_find_table(qihse_uwp_sql_table_store(), "pg_in_txn"));
    send_pg_msg(fds[0], 'Q', rollback, strlen(rollback) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(!qihse_schema_get_table(uwp.schema, "pg_in_txn"));
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', create_inside_txn, strlen(create_inside_txn) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* second_create = "CREATE TABLE pg_in_txn_second (id BIGINT PRIMARY KEY)";
    send_pg_msg(fds[0], 'Q', second_create, strlen(second_create) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    assert(!qihse_schema_get_table(uwp.schema, "pg_in_txn_second"));
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_schema_get_table(uwp.schema, "pg_in_txn"));
    assert(qihse_schema_get_table(uwp.schema, "pg_in_txn_second"));
    assert(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "pg_in_txn"));
    assert(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "pg_in_txn_second"));
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* conflicted_ddl = "CREATE TABLE pg_conflicted (id INT)";
    send_pg_msg(fds[0], 'Q', conflicted_ddl, strlen(conflicted_ddl) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* competing_ddl = "CREATE TABLE pg_competing (id INT)";
    assert(uwp_dispatch_sql(&uwp, 0x02, (const uint8_t*)competing_ddl,
        strlen(competing_ddl) + 1, NULL, op, -1, NULL, NULL) == UWP_STS_OK);
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status_capture_error(fds[0], ddl_error,
        sizeof(ddl_error), &ddl_error_len) == 'I');
    assert(contains_bytes(ddl_error, ddl_error_len, "40001"));
    assert(!qihse_schema_get_table(uwp.schema, "pg_conflicted") &&
           !qihse_table_store_find_table(qihse_uwp_sql_table_store(),
                                         "pg_conflicted"));
    assert(qihse_schema_get_table(uwp.schema, "pg_competing"));
    const char* install_extension = "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";";
    qihse_sql_ast_t* extension_ast = qihse_parse_sql_to_ast(install_extension);
    assert(extension_ast && extension_ast->stmt_type == QIHSE_SQL_CREATE_EXTENSION &&
           extension_ast->raw_sql);
    qihse_sql_ast_free(extension_ast);
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', install_extension, strlen(install_extension) + 1);
    char extension_status = read_ready_status_capture_error(fds[0], ddl_error,
        sizeof(ddl_error), &ddl_error_len);
    if (extension_status != 'T')
        fprintf(stderr, "CREATE EXTENSION failed: %.*s\n",
            (int)ddl_error_len, ddl_error);
    assert(extension_status == 'T');
    assert(!qihse_schema_has_extension(uwp.schema, "uuid-ossp"));
    send_pg_msg(fds[0], 'Q', rollback, strlen(rollback) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(!qihse_schema_has_extension(uwp.schema, "uuid-ossp"));
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', install_extension, strlen(install_extension) + 1);
    extension_status = read_ready_status_capture_error(fds[0], ddl_error,
        sizeof(ddl_error), &ddl_error_len);
    if (extension_status != 'T')
        fprintf(stderr, "CREATE EXTENSION failed: %.*s\n",
            (int)ddl_error_len, ddl_error);
    assert(extension_status == 'T');
    assert(!qihse_schema_has_extension(uwp.schema, "uuid-ossp"));
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_schema_has_extension(uwp.schema, "uuid-ossp"));
    const char* unsupported_extension = "CREATE EXTENSION IF NOT EXISTS postgis";
    send_pg_msg(fds[0], 'Q', unsupported_extension, strlen(unsupported_extension) + 1);
    assert(read_ready_status_capture_error(fds[0], ddl_error,
        sizeof(ddl_error), &ddl_error_len) == 'I');
    assert(contains_bytes(ddl_error, ddl_error_len, "0A000"));
    puts("PASS durable DDL: transactional table and extension catalog state, rollback, and unsupported-feature refusal");
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert1 = "INSERT INTO pg_txn_wire VALUES (1, 'rollback')\0";
    send_pg_msg(fds[0], 'Q', insert1, strlen(insert1) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    qihse_table_t* table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_txn_wire");
    assert(table && qihse_table_row_count(table) == 0);
    send_pg_msg(fds[0], 'Q', rollback, strlen(rollback) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 0);

    /* A statement error aborts the transaction; later writes stay private,
     * and COMMIT resolves as a rollback. */
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* bad_insert = "INSERT INTO missing_pg_txn_table VALUES (9, 'nope')\0";
    send_pg_msg(fds[0], 'Q', bad_insert, strlen(bad_insert) + 1);
    assert(read_ready_status(fds[0]) == 'E');
    send_pg_msg(fds[0], 'Q', insert1, strlen(insert1) + 1);
    assert(read_ready_status(fds[0]) == 'E');
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 0);

    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert2 =
        "INSERT INTO pg_txn_wire VALUES (2, 'PG-WIRE-ALLOWED-ROW')\0";
    send_pg_msg(fds[0], 'Q', insert2, strlen(insert2) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 1);

    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* own_row = "INSERT INTO pg_txn_wire VALUES (4, 'txn-visible')";
    send_pg_msg(fds[0], 'Q', own_row, strlen(own_row) + 1u);
    assert(read_ready_status(fds[0]) == 'T');
    const char* own_select = "SELECT note FROM pg_txn_wire WHERE id = 4";
    uint8_t txn_row[512];
    size_t txn_row_len = 0;
    send_pg_msg(fds[0], 'Q', own_select, strlen(own_select) + 1u);
    assert(read_ready_status_capture_row(fds[0], txn_row,
                                          sizeof(txn_row), &txn_row_len) == 'T');
    assert(contains_bytes(txn_row, txn_row_len, "txn-visible"));
    send_pg_msg(fds[0], 'Q', rollback, strlen(rollback) + 1u);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 1);

    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert3 = "INSERT INTO pg_txn_wire VALUES (3, 'disconnect')\0";
    send_pg_msg(fds[0], 'Q', insert3, strlen(insert3) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    assert(qihse_table_row_count(table) == 1);

    /* Disconnecting with a healthy active transaction rolls back its private
     * row shadow. */
    uint32_t term_len = htonl(4);
    uint8_t term_tag = 'X';
    write_all(fds[0], &term_tag, 1);
    write_all(fds[0], &term_len, 4);

    struct timespec join_deadline;
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(stid, NULL, &join_deadline) == 0);
    close(fds[0]);
    assert(qihse_table_row_count(table) == 1);

    int retry_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, retry_fds) == 0);
    for (size_t i = 0; i < 2; ++i) {
        assert(setsockopt(retry_fds[i], SOL_SOCKET, SO_RCVTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
        assert(setsockopt(retry_fds[i], SOL_SOCKET, SO_SNDTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
    }
    server_thread_args_t retry_args = {
        .server_fd = retry_fds[1], .store = kv, .topo = topo, .uwp = &uwp
    };
    pthread_t retry_thread;
    assert(pthread_create(&retry_thread, NULL, server_worker, &retry_args) == 0);
    start_pg_client(retry_fds[0], "User_1", password);
    {
        uint8_t err[512];
        size_t err_len = 0;
        const char* bad_set = "SET qihse.retry_key = 'incomplete";
        send_pg_msg(retry_fds[0], 'Q', bad_set, strlen(bad_set) + 1);
        assert(read_ready_status_capture_error(retry_fds[0], err,
                                               sizeof(err), &err_len) == 'I');
        assert(contains_bytes(err, err_len, "22023"));
        const char* bad_status = "SELECT qihse_retry_status('request_01','deadbeef')";
        send_pg_msg(retry_fds[0], 'Q', bad_status, strlen(bad_status) + 1);
        assert(read_ready_status_capture_error(retry_fds[0], err,
                                               sizeof(err), &err_len) == 'I');
        assert(contains_bytes(err, err_len, "22023"));
        char oversized[4200];
        memset(oversized, ' ', sizeof(oversized));
        const char* prefix = "SET qihse.retry_key = 'truncated_key'";
        memcpy(oversized, prefix, strlen(prefix));
        oversized[sizeof(oversized) - 1] = '\0';
        send_pg_msg(retry_fds[0], 'Q', oversized, sizeof(oversized));
        assert(read_ready_status_capture_error(retry_fds[0], err,
                                               sizeof(err), &err_len) == 'I');
        assert(contains_bytes(err, err_len, "54000"));
        const char* begin_bad = "BEGIN";
        send_pg_msg(retry_fds[0], 'Q', begin_bad, strlen(begin_bad) + 1);
        assert(read_ready_status(retry_fds[0]) == 'T');
        send_pg_msg(retry_fds[0], 'Q', bad_set, strlen(bad_set) + 1);
        assert(read_ready_status_capture_error(retry_fds[0], err,
                                               sizeof(err), &err_len) == 'E');
        assert(contains_bytes(err, err_len, "25001"));
        send_pg_msg(retry_fds[0], 'Q', bad_status, strlen(bad_status) + 1);
        assert(read_ready_status_capture_error(retry_fds[0], err,
                                               sizeof(err), &err_len) == 'E');
        assert(contains_bytes(err, err_len, "25P02"));
        const char* rollback_bad = "ROLLBACK";
        send_pg_msg(retry_fds[0], 'Q', rollback_bad, strlen(rollback_bad) + 1);
        assert(read_ready_status(retry_fds[0]) == 'I');
    }
    const char* retry_set = "SET qihse.retry_key = 'request_01'";
    send_pg_msg(retry_fds[0], 'Q', retry_set, strlen(retry_set) + 1);
    assert(read_ready_status(retry_fds[0]) == 'I');
    const char* retry_insert = "INSERT INTO pg_runtime VALUES (1, 'once')";
    {
        uint8_t err[512];
        size_t err_len = 0;
        /* Execute needs a portal cstring and max-row count even with retry
         * enabled; a truncated frame is a protocol violation. */
        send_pg_msg(retry_fds[0], 'E', "", 0);
        send_pg_msg(retry_fds[0], 'S', NULL, 0);
        assert(read_ready_status_capture_error(retry_fds[0], err,
                                               sizeof(err), &err_len) == 'I');
        assert(contains_bytes(err, err_len, "08P01"));
        send_pg_msg(retry_fds[0], 'Q', begin, strlen(begin) + 1);
        assert(read_ready_status(retry_fds[0]) == 'T');
        send_pg_msg(retry_fds[0], 'E', "", 0);
        send_pg_msg(retry_fds[0], 'S', NULL, 0);
        assert(read_ready_status_capture_error(retry_fds[0], err,
                                               sizeof(err), &err_len) == 'E');
        assert(contains_bytes(err, err_len, "08P01"));
        send_pg_msg(retry_fds[0], 'Q', retry_insert, strlen(retry_insert) + 1);
        assert(read_ready_status_capture_error(retry_fds[0], err,
                                               sizeof(err), &err_len) == 'E');
        assert(contains_bytes(err, err_len, "25P02"));
        send_pg_msg(retry_fds[0], 'Q', rollback, strlen(rollback) + 1);
        assert(read_ready_status(retry_fds[0]) == 'I');
    }
    qihse_table_t* runtime_table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_runtime");
    assert(runtime_table && qihse_table_row_count(runtime_table) == 0);
    /* A typed write cannot hide behind the digest of a simple write. The
     * refusal aborts the whole transaction, including its staged simple row. */
    const char* retry_typed_sql =
        "INSERT INTO pg_runtime VALUES ($1, 'hidden-typed-write')";
    uint32_t retry_typed_id = htonl(99);
    const char retry_execute[] = "\0\0\0\0\0";
    send_pg_msg(retry_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(retry_fds[0]) == 'T');
    send_pg_msg(retry_fds[0], 'Q', retry_insert, strlen(retry_insert) + 1u);
    assert(read_ready_status(retry_fds[0]) == 'T');
    send_prepared_select(retry_fds[0], "retry_typed", retry_typed_sql, 23);
    send_bound_select(retry_fds[0], "retry_typed", 1,
                      &retry_typed_id, sizeof(retry_typed_id));
    send_pg_msg(retry_fds[0], 'E', retry_execute, sizeof(retry_execute) - 1u);
    send_pg_msg(retry_fds[0], 'E', retry_execute, sizeof(retry_execute) - 1u);
    send_pg_msg(retry_fds[0], 'S', NULL, 0);
    assert(read_extended_denial_sync(retry_fds[0], "0A000") == 'E');
    send_pg_msg(retry_fds[0], 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(retry_fds[0]) == 'I');
    assert(qihse_table_row_count(runtime_table) == 0);
    for (size_t attempt = 0; attempt < 2; ++attempt) {
        send_pg_msg(retry_fds[0], 'Q', begin, strlen(begin) + 1);
        assert(read_ready_status(retry_fds[0]) == 'T');
        send_pg_msg(retry_fds[0], 'Q', retry_insert, strlen(retry_insert) + 1);
        assert(read_ready_status(retry_fds[0]) == 'T');
        send_pg_msg(retry_fds[0], 'Q', commit, strlen(commit) + 1);
        assert(read_ready_status(retry_fds[0]) == 'I');
        assert(qihse_table_row_count(runtime_table) == 1);
    }
    /* The same committed key and simple digest cannot mask a changed typed
     * value, and the failed retry cannot add either row. */
    retry_typed_id = htonl(100);
    send_pg_msg(retry_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(retry_fds[0]) == 'T');
    send_pg_msg(retry_fds[0], 'Q', retry_insert, strlen(retry_insert) + 1u);
    assert(read_ready_status(retry_fds[0]) == 'T');
    send_bound_select(retry_fds[0], "retry_typed", 1,
                      &retry_typed_id, sizeof(retry_typed_id));
    send_pg_msg(retry_fds[0], 'E', retry_execute, sizeof(retry_execute) - 1u);
    send_pg_msg(retry_fds[0], 'S', NULL, 0);
    assert(read_extended_denial_sync(retry_fds[0], "0A000") == 'E');
    send_pg_msg(retry_fds[0], 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(retry_fds[0]) == 'I');
    assert(qihse_table_row_count(runtime_table) == 1);
    char digest[65], status_sql[256];
    retry_digest_hex(retry_insert, digest);
    assert(snprintf(status_sql, sizeof(status_sql),
                    "SELECT qihse_retry_status('request_01','%s')", digest)
           < (int)sizeof(status_sql));
    send_pg_msg(retry_fds[0], 'Q', status_sql, strlen(status_sql) + 1);
    uint8_t retry_row[512];
    size_t retry_row_len = 0;
    assert(read_ready_status_capture_row(retry_fds[0], retry_row,
                                          sizeof(retry_row), &retry_row_len) == 'I');
    assert(contains_bytes(retry_row, retry_row_len, "committed"));
    char invalid_status[256];
    assert(snprintf(invalid_status, sizeof(invalid_status),
                    "SELECT qihse_retry_status('request_01','0%s')", digest + 1)
           < (int)sizeof(invalid_status));
    send_pg_msg(retry_fds[0], 'Q', invalid_status, strlen(invalid_status) + 1);
    assert(read_ready_status_capture_error(retry_fds[0], retry_row,
                                           sizeof(retry_row), &retry_row_len) == 'I');
    assert(contains_bytes(retry_row, retry_row_len, "42501"));
    send_pg_msg(retry_fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(retry_fds[0]) == 'T');
    const char* reused_key = "INSERT INTO pg_runtime VALUES (2, 'different')";
    send_pg_msg(retry_fds[0], 'Q', reused_key, strlen(reused_key) + 1);
    assert(read_ready_status(retry_fds[0]) == 'T');
    send_pg_msg(retry_fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status_capture_error(retry_fds[0], retry_row,
                                           sizeof(retry_row), &retry_row_len) == 'I');
    assert(contains_bytes(retry_row, retry_row_len, "22023"));
    assert(qihse_table_row_count(runtime_table) == 1);
    write_all(retry_fds[0], &term_tag, 1);
    write_all(retry_fds[0], &term_len, 4);
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(retry_thread, NULL, &join_deadline) == 0);
    close(retry_fds[0]);
    puts("PASS pgwire retry identity: committed lookup, duplicate no-op, mismatch refused");

    int typed_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, typed_fds) == 0);
    server_thread_args_t typed_args = {
        .server_fd = typed_fds[1], .store = kv, .topo = topo, .uwp = &uwp
    };
    pthread_t typed_thread;
    assert(pthread_create(&typed_thread, NULL, server_worker, &typed_args) == 0);
    start_pg_client(typed_fds[0], "User_1", password);
    const char* typed_create =
        "CREATE TABLE pg_typed (id INT, big BIGINT, note TEXT, label VARCHAR(40))";
    send_pg_msg(typed_fds[0], 'Q', typed_create, strlen(typed_create) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'I');
    const char* typed_insert =
        "INSERT INTO pg_typed VALUES (12, 42, '12', 'twelve')";
    send_pg_msg(typed_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'T');
    send_pg_msg(typed_fds[0], 'Q', typed_insert, strlen(typed_insert) + 1u);
    uint8_t typed_error[512];
    size_t typed_error_len = 0;
    assert(read_ready_status_capture_error(typed_fds[0], typed_error,
                                           sizeof(typed_error), &typed_error_len) == 'T');
    assert(typed_error_len == 0);
    send_pg_msg(typed_fds[0], 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'I');
    /* A completed named portal returns CommandComplete again, never a
     * second INSERT, even across Sync within the same transaction. */
    qihse_table_t* typed_table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_typed");
    assert(typed_table && qihse_table_row_count(typed_table) == 1);
    const char* portal_insert =
        "INSERT INTO pg_typed VALUES ($1, 43, '13', 'thirteen')";
    uint32_t portal_id = htonl(13);
    send_pg_msg(typed_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'T');
    send_prepared_select(typed_fds[0], "portal_insert", portal_insert, 23);
    const char named_execute[] = "portal_once\0\0\0\0\0";
    send_bound_portal(typed_fds[0], "portal_once", "portal_insert", 1,
                      &portal_id, sizeof(portal_id));
    send_pg_msg(typed_fds[0], 'E', named_execute, sizeof(named_execute) - 1u);
    send_pg_msg(typed_fds[0], 'S', NULL, 0);
    uint8_t portal_tag, portal_response[512];
    size_t portal_len = read_pg_response(typed_fds[0], &portal_tag,
                                          portal_response, sizeof(portal_response));
    assert(portal_tag == '1' && portal_len == 0);
    portal_len = read_pg_response(typed_fds[0], &portal_tag,
                                  portal_response, sizeof(portal_response));
    assert(portal_tag == '2' && portal_len == 0);
    portal_len = read_pg_response(typed_fds[0], &portal_tag,
                                  portal_response, sizeof(portal_response));
    assert(portal_tag == 'C' && !strcmp((char*)portal_response, "INSERT 0 1"));
    assert(read_ready_status(typed_fds[0]) == 'T');
    send_pg_msg(typed_fds[0], 'E', named_execute, sizeof(named_execute) - 1u);
    send_pg_msg(typed_fds[0], 'S', NULL, 0);
    portal_len = read_pg_response(typed_fds[0], &portal_tag,
                                  portal_response, sizeof(portal_response));
    assert(portal_tag == 'C' && portal_len == sizeof("INSERT 0 1") &&
           !strcmp((char*)portal_response, "INSERT 0 1"));
    assert(read_ready_status(typed_fds[0]) == 'T');
    /* Close releases cached state; rebinding the same portal name executes
     * the new parameter exactly once. */
    const char close_portal[] = "Pportal_once\0";
    send_pg_msg(typed_fds[0], 'C', close_portal, sizeof(close_portal) - 1u);
    portal_len = read_pg_response(typed_fds[0], &portal_tag,
                                  portal_response, sizeof(portal_response));
    assert(portal_tag == '3' && portal_len == 0);
    portal_id = htonl(14);
    send_bound_portal(typed_fds[0], "portal_once", "portal_insert", 1,
                      &portal_id, sizeof(portal_id));
    send_pg_msg(typed_fds[0], 'E', named_execute, sizeof(named_execute) - 1u);
    send_pg_msg(typed_fds[0], 'S', NULL, 0);
    portal_len = read_pg_response(typed_fds[0], &portal_tag,
                                  portal_response, sizeof(portal_response));
    assert(portal_tag == '2' && portal_len == 0);
    portal_len = read_pg_response(typed_fds[0], &portal_tag,
                                  portal_response, sizeof(portal_response));
    assert(portal_tag == 'C' && portal_len == sizeof("INSERT 0 1") &&
           !strcmp((char*)portal_response, "INSERT 0 1"));
    assert(read_ready_status(typed_fds[0]) == 'T');
    send_pg_msg(typed_fds[0], 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'I');
    assert(qihse_table_row_count(typed_table) == 3);
    /* Extended messages without BEGIN share an implicit transaction through
     * Sync: a later decoding failure must roll back the earlier Execute. */
    portal_id = htonl(15);
    send_bound_portal(typed_fds[0], "implicit_ok", "portal_insert", 1,
                      &portal_id, sizeof(portal_id));
    const char implicit_ok_execute[] = "implicit_ok\0\0\0\0\0";
    const char implicit_bad_execute[] = "implicit_bad\0\0\0\0\0";
    send_pg_msg(typed_fds[0], 'E', implicit_ok_execute,
                sizeof(implicit_ok_execute) - 1u);
    const uint8_t short_int = 1;
    send_bound_portal(typed_fds[0], "implicit_bad", "portal_insert", 1,
                      &short_int, sizeof(short_int));
    send_pg_msg(typed_fds[0], 'E', implicit_bad_execute,
                sizeof(implicit_bad_execute) - 1u);
    send_pg_msg(typed_fds[0], 'S', NULL, 0);
    assert(read_ready_status_capture_error(typed_fds[0], typed_error,
        sizeof(typed_error), &typed_error_len) == 'I');
    assert(contains_bytes(typed_error, typed_error_len, "0A000"));
    assert(qihse_table_row_count(typed_table) == 3);
    send_bound_portal(typed_fds[0], "implicit_ok", "portal_insert", 1,
                      &portal_id, sizeof(portal_id));
    send_pg_msg(typed_fds[0], 'E', implicit_ok_execute,
                sizeof(implicit_ok_execute) - 1u);
    send_pg_msg(typed_fds[0], 'S', NULL, 0);
    assert(read_ready_status_capture_error(typed_fds[0], typed_error,
        sizeof(typed_error), &typed_error_len) == 'I');
    assert(typed_error_len == 0 && qihse_table_row_count(typed_table) == 4);
    const char* typed_select =
        "SELECT id, big, note, label FROM pg_typed WHERE id = 12";
    const int32_t typed_oids[] = {23, 20, 25, 1043};
    send_pg_msg(typed_fds[0], 'Q', typed_select, strlen(typed_select) + 1u);
    assert_select_types(typed_fds[0], typed_oids, 4, "42");
    const char* typed_alias = "SELECT id AS lookup_id FROM pg_typed WHERE id = 12";
    send_pg_msg(typed_fds[0], 'Q', typed_alias, strlen(typed_alias) + 1u);
    assert_select_types(typed_fds[0], typed_oids, 1, "12");
    const char* typed_empty = "SELECT id FROM pg_typed WHERE id = 999";
    send_pg_msg(typed_fds[0], 'Q', typed_empty, strlen(typed_empty) + 1u);
    assert_select_types(typed_fds[0], typed_oids, 1, NULL);
    const char* typed_star = "SELECT * FROM pg_typed WHERE id = 12";
    send_pg_msg(typed_fds[0], 'Q', typed_star, strlen(typed_star) + 1u);
    assert_select_types(typed_fds[0], typed_oids, 4, "twelve");
    const char null_execute[] = "\0\0\0\0\0";
    const char* null_index = "CREATE INDEX pg_typed_note_idx ON pg_typed(note)";
    send_pg_msg(typed_fds[0], 'Q', null_index, strlen(null_index) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'I');
    const char* null_update = "UPDATE pg_typed SET note = 'NULL' WHERE id = 12";
    send_pg_msg(typed_fds[0], 'Q', null_update, strlen(null_update) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'I');
    const char* null_lookup = "SELECT id FROM pg_typed WHERE note = 'NULL'";
    send_pg_msg(typed_fds[0], 'Q', null_lookup, strlen(null_lookup) + 1u);
    assert_select_types(typed_fds[0], typed_oids, 1, "12");
    send_prepared_select(typed_fds[0], "", "SELECT id FROM pg_typed WHERE note = $1", 25);
    send_bound_select(typed_fds[0], "", 0, "NULL", 4);
    send_pg_msg(typed_fds[0], 'E', null_execute, sizeof(null_execute) - 1u);
    send_pg_msg(typed_fds[0], 'S', NULL, 0);
    assert_extended_select(typed_fds[0], "12", true);
    send_prepared_select(typed_fds[0], "", "SELECT id FROM pg_typed WHERE note = $1", 25);
    send_bound_select(typed_fds[0], "", 0, NULL, -1);
    send_pg_msg(typed_fds[0], 'E', null_execute, sizeof(null_execute) - 1u);
    send_pg_msg(typed_fds[0], 'S', NULL, 0);
    assert_extended_select(typed_fds[0], NULL, false);
    const char* native_create =
        "CREATE TABLE pg_native_types (uid UUID, doc JSONB, enabled BOOLEAN, "
        "created TIMESTAMPTZ, note TEXT)";
    send_pg_msg(typed_fds[0], 'Q', native_create, strlen(native_create) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'I');
    const char* native_insert =
        "INSERT INTO pg_native_types VALUES "
        "('01234567-89ab-cdef-0123-456789abcdef', 'true', true, "
        "'2024-01-02T03:04:05.123456Z', '')";
    send_pg_msg(typed_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'T');
    send_pg_msg(typed_fds[0], 'Q', native_insert, strlen(native_insert) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'T');
    send_pg_msg(typed_fds[0], 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'I');
    const char* native_select = "SELECT * FROM pg_native_types";
    const int32_t native_oids[] = {2950, 3802, 16, 1184, 25};
    send_pg_msg(typed_fds[0], 'Q', native_select, strlen(native_select) + 1u);
    assert_select_types(typed_fds[0], native_oids, 5,
                        "01234567-89ab-cdef-0123-456789abcdef");
    send_pg_msg(typed_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'T');
    const char* native_null_update =
        "UPDATE pg_native_types SET uid = NULL, doc = NULL, enabled = NULL, "
        "created = NULL, note = NULL WHERE uid = '01234567-89ab-cdef-0123-456789abcdef'";
    send_pg_msg(typed_fds[0], 'Q', native_null_update,
                strlen(native_null_update) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'T');
    send_pg_msg(typed_fds[0], 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(typed_fds[0]) == 'I');
    send_pg_msg(typed_fds[0], 'Q', native_select, strlen(native_select) + 1u);
    const bool native_nulls[] = {true, true, true, true, true};
    assert_select_nullability(typed_fds[0], native_oids, native_nulls, 5);
    const char* unknown_expr = "SELECT 12 AS id FROM pg_typed";
    send_pg_msg(typed_fds[0], 'Q', unknown_expr, strlen(unknown_expr) + 1u);
    assert(read_ready_status_capture_error(typed_fds[0], typed_error,
                                           sizeof(typed_error), &typed_error_len) == 'I');
    assert(typed_error_len && !contains_bytes(typed_error, typed_error_len, "twelve"));
    write_all(typed_fds[0], &term_tag, 1);
    write_all(typed_fds[0], &term_len, 4);
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(typed_thread, NULL, &join_deadline) == 0);
    close(typed_fds[0]);

    /* A second authenticated, clearance-0 principal may read the explicitly
     * granted table. Access to the ungranted table is refused by the UWP SQL
     * executor, and the protected marker is absent from the wire error. */
    int guest_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, guest_fds) == 0);
    for (size_t i = 0; i < 2; ++i) {
        assert(setsockopt(guest_fds[i], SOL_SOCKET, SO_RCVTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
        assert(setsockopt(guest_fds[i], SOL_SOCKET, SO_SNDTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
    }
    server_thread_args_t guest_args = {
        .server_fd = guest_fds[1], .store = kv, .topo = topo, .uwp = &uwp
    };
    pthread_t guest_thread;
    assert(pthread_create(&guest_thread, NULL, server_worker, &guest_args) == 0);
    start_pg_client(guest_fds[0], "User_2", "PGWireGuestPass123!");

    const char* allowed_read =
        "SELECT id, note FROM pg_txn_wire WHERE id = 2\0";
    send_pg_msg(guest_fds[0], 'Q', allowed_read, strlen(allowed_read) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'I');

    const char* denied_read =
        "SELECT note FROM pg_txn_protected WHERE id = 7\0";
    send_pg_msg(guest_fds[0], 'Q', denied_read, strlen(denied_read) + 1u);
    uint8_t error_body[512];
    size_t error_len = 0;
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'I');
    assert(error_len > 0);
    assert(!contains_bytes(error_body, error_len, "PG-WIRE-PROTECTED-MARKER"));
    send_pg_msg(guest_fds[0], 'Q', typed_select, strlen(typed_select) + 1u);
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'I');
    assert(contains_bytes(error_body, error_len, "42501"));
    assert(!contains_bytes(error_body, error_len, "twelve"));
    /* A captured READ must be reauthorized at COMMIT, with permission failure
     * kept distinct from retryable serialization conflicts. */
    send_pg_msg(guest_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'T');
    send_pg_msg(guest_fds[0], 'Q', allowed_read, strlen(allowed_read) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'T');
    assert(qihse_auth_revoke_object(op, guest, 0u,
                                    table_resource_id("pg_txn_wire")));
    send_pg_msg(guest_fds[0], 'Q', commit, strlen(commit) + 1u);
    char revoked_status = read_ready_status_capture_error(guest_fds[0], error_body,
        sizeof(error_body), &error_len);
    assert(revoked_status == 'E' || revoked_status == 'I');
    assert(contains_bytes(error_body, error_len, "42501"));
    assert(!contains_bytes(error_body, error_len, "40001"));
    send_pg_msg(guest_fds[0], 'Q', rollback, strlen(rollback) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'I');
    assert(qihse_auth_grant_object(op, guest, 0u,
        table_resource_id("pg_txn_wire"), QIHSE_ACL_READ));
    const char execute[] = "\0\0\0\0\0"; /* unnamed portal, unlimited rows */
    const char describe_stmt[] = "Styped_select\0";
    const char malformed[] = {'s', 't', 'm', 't'};
    uint8_t response_tag, response[512];
    size_t response_len;
    send_prepared_select(guest_fds[0], "typed_select",
        "SELECT note FROM pg_txn_wire WHERE id = $1", 23);
    send_pg_msg(guest_fds[0], 'D', describe_stmt, sizeof(describe_stmt) - 1u);
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    response_len = read_pg_response(guest_fds[0], &response_tag, response, sizeof(response));
    assert(response_tag == '1' && response_len == 0);
    response_len = read_pg_response(guest_fds[0], &response_tag, response, sizeof(response));
    assert(response_tag == 't' && response_len == 6 &&
           response[0] == 0 && response[1] == 1 && response[5] == 23);
    response_len = read_pg_response(guest_fds[0], &response_tag, response, sizeof(response));
    assert(response_tag == 'T' && response_len > 2); /* Describe never runs SELECT. */
    response_len = read_pg_response(guest_fds[0], &response_tag, response, sizeof(response));
    assert(response_tag == 'Z' && response_len == 1 && response[0] == 'I');

    uint32_t binary_id = htonl(2);
    send_pg_msg(guest_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'T');
    send_prepared_select(guest_fds[0], "", "SELECT note FROM pg_txn_wire WHERE id = $1", 23);
    send_bound_select(guest_fds[0], "", 1, &binary_id, sizeof(binary_id));
    send_pg_msg(guest_fds[0], 'E', execute, sizeof(execute) - 1u);
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert_extended_select_state(guest_fds[0], "PG-WIRE-ALLOWED-ROW", true, 'T');
    /* Completed portals survive Sync only inside an explicit transaction.
     * Even their cached SELECT count is withheld after ACL revocation. */
    assert(qihse_auth_revoke_object(op, guest, 0u,
                                    table_resource_id("pg_txn_wire")));
    send_pg_msg(guest_fds[0], 'E', execute, sizeof(execute) - 1u);
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_denial_sync(guest_fds[0], "42501") == 'E');
    assert(qihse_auth_grant_object(op, guest, 0u,
        table_resource_id("pg_txn_wire"), QIHSE_ACL_READ));
    send_pg_msg(guest_fds[0], 'E', execute, sizeof(execute) - 1u);
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_denial_sync(guest_fds[0], "25P02") == 'E');
    send_pg_msg(guest_fds[0], 'Q', rollback, strlen(rollback) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'I');

    const char* injection = "' OR 1=1 --";
    send_prepared_select(guest_fds[0], "",
        "SELECT id FROM pg_txn_wire WHERE note = $1", 25);
    send_bound_select(guest_fds[0], "", 0, injection, (int32_t)strlen(injection));
    send_pg_msg(guest_fds[0], 'E', execute, sizeof(execute) - 1u);
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert_extended_select(guest_fds[0], NULL, false);

    send_prepared_select(guest_fds[0], "",
        "SELECT note FROM pg_txn_wire WHERE id = $1", 23);
    send_bound_select(guest_fds[0], "", 0, NULL, -1); /* SQL NULL, not 'NULL'. */
    send_pg_msg(guest_fds[0], 'E', execute, sizeof(execute) - 1u);
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert_extended_select(guest_fds[0], NULL, false);

    /* Protected rows stay inaccessible even through correctly typed Bind. */
    send_prepared_select(guest_fds[0], "",
        "SELECT note FROM pg_txn_protected WHERE id = $1", 23);
    uint32_t protected_id = htonl(7);
    send_bound_select(guest_fds[0], "", 1, &protected_id, sizeof(protected_id));
    send_pg_msg(guest_fds[0], 'E', execute, sizeof(execute) - 1u);
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_denial_sync(guest_fds[0], "42501") == 'I');

    send_prepared_select(guest_fds[0], "",
        "SELECT note FROM pg_txn_wire WHERE id = $1", 23);
    send_bound_select(guest_fds[0], "", 1, &binary_id, 3); /* invalid INT4 width */
    send_pg_msg(guest_fds[0], 'E', execute, sizeof(execute) - 1u);
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_denial_sync(guest_fds[0], NULL) == 'I');

    send_pg_msg(guest_fds[0], 'P', malformed, sizeof(malformed));
    send_pg_msg(guest_fds[0], 'B', malformed, sizeof(malformed));
    send_pg_msg(guest_fds[0], 'D', malformed, sizeof(malformed));
    send_pg_msg(guest_fds[0], 'E', malformed, sizeof(malformed));
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_error_sync(guest_fds[0], NULL) == 'I');
    send_pg_msg(guest_fds[0], 'B', malformed, sizeof(malformed));
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_error_sync(guest_fds[0], NULL) == 'I');
    send_pg_msg(guest_fds[0], 'D', malformed, sizeof(malformed));
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_error_sync(guest_fds[0], NULL) == 'I');
    send_pg_msg(guest_fds[0], 'E', malformed, sizeof(malformed));
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_error_sync(guest_fds[0], NULL) == 'I');
    send_pg_msg(guest_fds[0], 'Q', allowed_read, strlen(allowed_read) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'I');
    send_pg_msg(guest_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'T');
    send_pg_msg(guest_fds[0], 'P', malformed, sizeof(malformed));
    send_pg_msg(guest_fds[0], 'S', NULL, 0);
    assert(read_extended_error_sync(guest_fds[0], NULL) == 'E');
    send_pg_msg(guest_fds[0], 'Q', allowed_read, strlen(allowed_read) + 1u);
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'E');
    assert(contains_bytes(error_body, error_len, "25P02"));
    send_pg_msg(guest_fds[0], 'Q', rollback, strlen(rollback) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'I');
    send_pg_msg(guest_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'T');
    send_pg_msg(guest_fds[0], 'Q', denied_read, strlen(denied_read) + 1u);
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'E');
    assert(!contains_bytes(error_body, error_len, "PG-WIRE-PROTECTED-MARKER"));
    send_pg_msg(guest_fds[0], 'Q', rollback, strlen(rollback) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'I');
    const char* guest_create = "CREATE TABLE pg_unauthorized (id INT)";
    send_pg_msg(guest_fds[0], 'Q', guest_create, strlen(guest_create) + 1u);
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'I');
    assert(contains_bytes(error_body, error_len, "42501"));
    assert(!qihse_schema_get_table(uwp.schema, "pg_unauthorized"));
    const char* guest_create_if_absent =
        "CREATE TABLE IF NOT EXISTS pg_txn_protected (id INT, note TEXT)";
    send_pg_msg(guest_fds[0], 'Q', guest_create_if_absent,
                strlen(guest_create_if_absent) + 1u);
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'I');
    assert(contains_bytes(error_body, error_len, "42501"));
    assert(!contains_bytes(error_body, error_len, "PG-WIRE-PROTECTED-MARKER"));
    assert(qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_txn_protected")) == 1);
    const char* guest_catalog = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name";
    uint8_t catalog_wire[8192];
    size_t catalog_wire_len = 0;
    send_pg_msg(guest_fds[0], 'Q', guest_catalog, strlen(guest_catalog) + 1u);
    assert(read_ready_status_capture_all(guest_fds[0], catalog_wire,
            sizeof(catalog_wire), &catalog_wire_len) == 'I');
    assert(contains_bytes(catalog_wire, catalog_wire_len, "pg_txn_wire"));
    assert(!contains_bytes(catalog_wire, catalog_wire_len, "pg_txn_protected"));
    send_pg_msg(guest_fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(guest_fds[0]) == 'T');
    send_pg_msg(guest_fds[0], 'Q', guest_create, strlen(guest_create) + 1u);
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'E');
    assert(contains_bytes(error_body, error_len, "42501"));
    send_pg_msg(guest_fds[0], 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'I');
    assert(!qihse_schema_get_table(uwp.schema, "pg_unauthorized") &&
           !qihse_table_store_find_table(qihse_uwp_sql_table_store(),
                                         "pg_unauthorized"));
    send_pg_msg(guest_fds[0], 'Q', status_sql, strlen(status_sql) + 1);
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'I');
    assert(contains_bytes(error_body, error_len, "42501"));
    assert(!contains_bytes(error_body, error_len, "committed"));
    puts("PASS low-clearance PG wire SELECT and retry outcome: denied without disclosure");

    write_all(guest_fds[0], &term_tag, 1);
    write_all(guest_fds[0], &term_len, 4);
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(guest_thread, NULL, &join_deadline) == 0);
    close(guest_fds[0]);
    qihse_table_t* protected_table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_txn_protected");
    assert(protected_table && qihse_table_row_count(protected_table) == 1);

    /* A row-label denial rolls back the UWP handle, but pgwire must retain
     * the aborted protocol state until an explicit rollback. */
    int tenant_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, tenant_fds) == 0);
    for (size_t i = 0; i < 2; ++i) {
        assert(setsockopt(tenant_fds[i], SOL_SOCKET, SO_RCVTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
        assert(setsockopt(tenant_fds[i], SOL_SOCKET, SO_SNDTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
    }
    server_thread_args_t tenant_args = {
        .server_fd = tenant_fds[1], .store = kv, .topo = topo, .uwp = &uwp
    };
    pthread_t tenant_thread;
    assert(pthread_create(&tenant_thread, NULL, server_worker, &tenant_args) == 0);
    start_pg_client(tenant_fds[0], "User_107", "PGWireTenantPass123!");
    send_pg_msg(tenant_fds[0], 'Q', guest_catalog, strlen(guest_catalog) + 1u);
    catalog_wire_len = 0;
    assert(read_ready_status_capture_all(tenant_fds[0], catalog_wire,
            sizeof(catalog_wire), &catalog_wire_len) == 'I');
    assert(contains_bytes(catalog_wire, catalog_wire_len, "pg_txn_labeled"));
    assert(!contains_bytes(catalog_wire, catalog_wire_len, "pg_txn_protected"));
    const char* cross_tenant_read =
        "SELECT note FROM pg_txn_protected WHERE id = 7";
    send_pg_msg(tenant_fds[0], 'Q', cross_tenant_read,
                strlen(cross_tenant_read) + 1u);
    assert(read_ready_status_capture_error(tenant_fds[0], error_body,
            sizeof(error_body), &error_len) == 'I');
    assert(contains_bytes(error_body, error_len, "42501"));
    assert(!contains_bytes(error_body, error_len,
                           "PG-WIRE-PROTECTED-MARKER"));
    qihse_table_t* labeled = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_txn_labeled");
    assert(labeled && qihse_table_row_count(labeled) == 0);
    send_pg_msg(tenant_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(tenant_fds[0]) == 'T');
    const char* forged =
        "INSERT INTO pg_txn_labeled VALUES (1, 'forged', 8, 1, 0)";
    send_pg_msg(tenant_fds[0], 'Q', forged, strlen(forged) + 1u);
    uint8_t label_error[512];
    size_t label_error_len = 0;
    assert(read_ready_status_capture_error(tenant_fds[0], label_error,
                                           sizeof(label_error), &label_error_len) == 'E');
    assert(contains_bytes(label_error, label_error_len, "42501"));
    assert(qihse_table_row_count(labeled) == 0);
    const char* valid =
        "INSERT INTO pg_txn_labeled VALUES (2, 'valid', 7, 1, 0)";
    send_pg_msg(tenant_fds[0], 'Q', valid, strlen(valid) + 1u);
    assert(read_ready_status_capture_error(tenant_fds[0], label_error,
                                           sizeof(label_error), &label_error_len) == 'E');
    assert(contains_bytes(label_error, label_error_len, "25P02"));
    assert(qihse_table_row_count(labeled) == 0);
    send_pg_msg(tenant_fds[0], 'Q', rollback, strlen(rollback) + 1u);
    assert(read_ready_status(tenant_fds[0]) == 'I');
    send_pg_msg(tenant_fds[0], 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(tenant_fds[0]) == 'T');
    send_pg_msg(tenant_fds[0], 'Q', valid, strlen(valid) + 1u);
    assert(read_ready_status(tenant_fds[0]) == 'T');
    send_pg_msg(tenant_fds[0], 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(tenant_fds[0]) == 'I');
    assert(qihse_table_row_count(labeled) == 1);
    write_all(tenant_fds[0], &term_tag, 1);
    write_all(tenant_fds[0], &term_len, 4);
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(tenant_thread, NULL, &join_deadline) == 0);
    close(tenant_fds[0]);
    puts("PASS row-label denial: 42501, aborted 25P02, rollback and recovery");

    /* Cleartext password authentication must not bind beyond loopback. */
    errno = 0;
    assert(qihse_pg_wire_listener_open_uwp(&uwp, topo, "0.0.0.0", 0) == NULL);
    assert(errno == EACCES);
    errno = 0;
    assert(qihse_pg_wire_listener_open_uwp(&uwp, topo, "192.0.2.1", 0) == NULL);
    assert(errno == EACCES);

    /* Exercise the public TCP listener rather than only the socketpair
     * handler. It must retain the same authenticated transaction path. */
    qihse_pg_wire_listener_t* listener = qihse_pg_wire_listener_open_uwp(
        &uwp, topo, "127.0.0.1", 0);
    assert(listener);
    uint16_t listen_port = qihse_pg_wire_listener_port(listener);
    assert(listen_port != 0);
    listener_thread_args_t listener_args = {.listener = listener, .result = -9};
    pthread_t listener_thread;
    assert(pthread_create(&listener_thread, NULL, listener_once_worker,
                          &listener_args) == 0);

    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(tcp_fd >= 0);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(listen_port);
    assert(inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) == 1);
    assert(connect(tcp_fd, (struct sockaddr*)&server_addr,
                   sizeof(server_addr)) == 0);
    for (size_t i = 0; i < 2; ++i) {
        assert(setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
        assert(setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
    }
    start_pg_client(tcp_fd, "User_1", password);
    send_pg_msg(tcp_fd, 'Q', begin, strlen(begin) + 1u);
    assert(read_ready_status(tcp_fd) == 'T');
    const char* listener_insert =
        "INSERT INTO pg_txn_wire VALUES (3, 'tcp-listener-transaction')\0";
    send_pg_msg(tcp_fd, 'Q', listener_insert, strlen(listener_insert) + 1u);
    assert(read_ready_status(tcp_fd) == 'T');
    send_pg_msg(tcp_fd, 'Q', commit, strlen(commit) + 1u);
    assert(read_ready_status(tcp_fd) == 'I');
    assert(qihse_table_row_count(table) == 2);
    write_all(tcp_fd, &term_tag, 1);
    write_all(tcp_fd, &term_len, 4);
    close(tcp_fd);
    assert(pthread_join(listener_thread, NULL) == 0);
    assert(listener_args.result == 1);
    qihse_pg_wire_listener_close(listener);
    puts("PASS public TCP PG listener: authenticated transaction committed");

    /* The public TCP listener must carry the same low-clearance READ denial
     * as the embeddable handler and must never serialize the protected value. */
    listener = qihse_pg_wire_listener_open_uwp(
        &uwp, topo, "127.0.0.1", 0);
    assert(listener);
    listen_port = qihse_pg_wire_listener_port(listener);
    assert(listen_port != 0);
    listener_args = (listener_thread_args_t){.listener = listener, .result = -9};
    assert(pthread_create(&listener_thread, NULL, listener_once_worker,
                          &listener_args) == 0);

    int guest_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(guest_tcp_fd >= 0);
    server_addr.sin_port = htons(listen_port);
    assert(connect(guest_tcp_fd, (struct sockaddr*)&server_addr,
                   sizeof(server_addr)) == 0);
    assert(setsockopt(guest_tcp_fd, SOL_SOCKET, SO_RCVTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);
    assert(setsockopt(guest_tcp_fd, SOL_SOCKET, SO_SNDTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);
    start_pg_client(guest_tcp_fd, "User_2", "PGWireGuestPass123!");
    const char* listener_denied_read =
        "SELECT note FROM pg_txn_protected WHERE id = 7\0";
    send_pg_msg(guest_tcp_fd, 'Q', listener_denied_read,
                strlen(listener_denied_read) + 1u);
    uint8_t listener_error[512];
    size_t listener_error_len = 0;
    assert(read_ready_status_capture_error(guest_tcp_fd, listener_error,
                                           sizeof(listener_error),
                                           &listener_error_len) == 'I');
    assert(listener_error_len > 0);
    assert(!contains_bytes(listener_error, listener_error_len,
                           "PG-WIRE-PROTECTED-MARKER"));
    write_all(guest_tcp_fd, &term_tag, 1);
    write_all(guest_tcp_fd, &term_len, 4);
    close(guest_tcp_fd);
    assert(pthread_join(listener_thread, NULL) == 0);
    assert(listener_args.result == 1);
    qihse_pg_wire_listener_close(listener);
    puts("PASS public TCP PG listener: low-clearance read denied without disclosure");

    /* A loopback SSLRequest must not be answered 'N' followed by cleartext. */
    listener = qihse_pg_wire_listener_open_uwp(&uwp, topo, "127.0.0.1", 0);
    assert(listener);
    listener_args = (listener_thread_args_t){.listener = listener, .result = -9};
    assert(pthread_create(&listener_thread, NULL, listener_once_worker,
                          &listener_args) == 0);
    int probe_fd = connect_test_port(qihse_pg_wire_listener_port(listener));
    const uint8_t ssl_request[8] = {0, 0, 0, 8, 4, 210, 22, 47};
    write_all(probe_fd, ssl_request, sizeof(ssl_request));
    uint8_t reply;
    assert(read(probe_fd, &reply, 1) == 0);
    close(probe_fd);
    assert(pthread_join(listener_thread, NULL) == 0);
    assert(listener_args.result == 1);
    qihse_pg_wire_listener_close(listener);

    char cert_path[] = "build/pg_wire_cert_XXXXXX";
    char key_path[] = "build/pg_wire_key_XXXXXX";
    errno = 0;
    assert(qihse_pg_wire_listener_open_tls_uwp(&uwp, topo, "0.0.0.0", 0,
                                                NULL, NULL) == NULL);
    assert(errno == EINVAL);
    make_test_certificate(cert_path, key_path);
    errno = 0;
    assert(qihse_pg_wire_listener_open_tls_uwp(&uwp, topo, "0.0.0.0", 0,
                                                cert_path, cert_path) == NULL);
    assert(errno == EINVAL);
    listener = qihse_pg_wire_listener_open_tls_uwp(&uwp, topo, "127.0.0.1", 0,
                                                     cert_path, key_path);
    assert(listener);
    SSL_CTX* client_ctx = SSL_CTX_new(TLS_client_method());
    assert(client_ctx);
    assert(SSL_CTX_load_verify_locations(client_ctx, cert_path, NULL) == 1);
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
    listen_port = qihse_pg_wire_listener_port(listener);

    /* Direct cleartext startup must not reach AuthenticationCleartextPassword. */
    listener_args = (listener_thread_args_t){.listener = listener, .result = -9};
    assert(pthread_create(&listener_thread, NULL, listener_once_worker,
                          &listener_args) == 0);
    probe_fd = connect_test_port(listen_port);
    uint8_t clear_startup[8] = {0, 0, 0, 8, 0, 3, 0, 0};
    write_all(probe_fd, clear_startup, sizeof(clear_startup));
    assert(read(probe_fd, &reply, 1) == 0);
    close(probe_fd);
    assert(pthread_join(listener_thread, NULL) == 0);
    assert(listener_args.result == 1);

    /* A client verifying the wrong server identity must abort before AUTH. */
    listener_args = (listener_thread_args_t){.listener = listener, .result = -9};
    assert(pthread_create(&listener_thread, NULL, listener_once_worker,
                          &listener_args) == 0);
    int tls_fd = connect_test_port(listen_port);
    write_all(tls_fd, ssl_request, sizeof(ssl_request));
    read_all(tls_fd, &reply, 1);
    assert(reply == 'S');
    test_ssl = SSL_new(client_ctx);
    assert(test_ssl && SSL_set_fd(test_ssl, tls_fd) == 1);
    assert(SSL_set1_host(test_ssl, "wrong.example") == 1);
    assert(SSL_connect(test_ssl) <= 0);
    assert(SSL_get_verify_result(test_ssl) != X509_V_OK);
    SSL_free(test_ssl);
    test_ssl = NULL;
    close(tls_fd);
    assert(pthread_join(listener_thread, NULL) == 0);
    assert(listener_args.result == 1);

    /* Verified TLS must still enforce the QIHSE principal/password mapping. */
    listener_args = (listener_thread_args_t){.listener = listener, .result = -9};
    assert(pthread_create(&listener_thread, NULL, listener_once_worker,
                          &listener_args) == 0);
    tls_fd = connect_test_port(listen_port);
    write_all(tls_fd, ssl_request, sizeof(ssl_request));
    read_all(tls_fd, &reply, 1);
    assert(reply == 'S');
    test_ssl = SSL_new(client_ctx);
    assert(test_ssl && SSL_set_fd(test_ssl, tls_fd) == 1);
    assert(SSL_set1_host(test_ssl, "localhost") == 1);
    assert(SSL_connect(test_ssl) == 1);
    assert(SSL_get_verify_result(test_ssl) == X509_V_OK);
    start_pg_client(tls_fd, "User_2", "PGWireGuestPass123!");
    send_pg_msg(tls_fd, 'Q', listener_denied_read,
                strlen(listener_denied_read) + 1u);
    listener_error_len = 0;
    assert(read_ready_status_capture_error(tls_fd, listener_error,
                                           sizeof(listener_error),
                                           &listener_error_len) == 'I');
    assert(listener_error_len > 0);
    assert(!contains_bytes(listener_error, listener_error_len,
                           "PG-WIRE-PROTECTED-MARKER"));
    write_all(tls_fd, &term_tag, 1);
    write_all(tls_fd, &term_len, 4);
    SSL_free(test_ssl);
    test_ssl = NULL;
    close(tls_fd);
    assert(pthread_join(listener_thread, NULL) == 0);
    assert(listener_args.result == 1);

    /* An invalid password on a verified TLS session must never yield AuthOk. */
    listener_args = (listener_thread_args_t){.listener = listener, .result = -9};
    assert(pthread_create(&listener_thread, NULL, listener_once_worker,
                          &listener_args) == 0);
    tls_fd = connect_test_port(listen_port);
    write_all(tls_fd, ssl_request, sizeof(ssl_request));
    read_all(tls_fd, &reply, 1);
    assert(reply == 'S');
    test_ssl = SSL_new(client_ctx);
    assert(test_ssl && SSL_set_fd(test_ssl, tls_fd) == 1);
    assert(SSL_set1_host(test_ssl, "localhost") == 1);
    assert(SSL_connect(test_ssl) == 1);
    const char startup_params[] = "user\0User_1\0database\0qihse\0";
    uint32_t packet_len = htonl(8u + sizeof(startup_params));
    uint32_t protocol = htonl(196608u);
    write_all(tls_fd, &packet_len, 4);
    write_all(tls_fd, &protocol, 4);
    write_all(tls_fd, startup_params, sizeof(startup_params));
    uint32_t wire_len, auth_type;
    read_all(tls_fd, &reply, 1);
    assert(reply == 'R');
    read_all(tls_fd, &wire_len, 4);
    read_all(tls_fd, &auth_type, 4);
    assert(ntohl(wire_len) == 8 && ntohl(auth_type) == 3);
    const char wrong_password[] = "not-the-password";
    send_pg_msg(tls_fd, 'p', wrong_password, sizeof(wrong_password));
    read_all(tls_fd, &reply, 1);
    assert(reply == 'E');
    read_all(tls_fd, &wire_len, 4);
    assert(ntohl(wire_len) >= 4 && ntohl(wire_len) < 1024);
    uint8_t auth_error[1024];
    read_all(tls_fd, auth_error, ntohl(wire_len) - 4);
    assert(contains_bytes(auth_error, ntohl(wire_len) - 4, "28P01"));
    SSL_free(test_ssl);
    test_ssl = NULL;
    close(tls_fd);
    assert(pthread_join(listener_thread, NULL) == 0);
    assert(listener_args.result == 1);

    /* A second SSLRequest within TLS is not an authentication bypass. */
    listener_args = (listener_thread_args_t){.listener = listener, .result = -9};
    assert(pthread_create(&listener_thread, NULL, listener_once_worker,
                          &listener_args) == 0);
    tls_fd = connect_test_port(listen_port);
    write_all(tls_fd, ssl_request, sizeof(ssl_request));
    read_all(tls_fd, &reply, 1);
    assert(reply == 'S');
    test_ssl = SSL_new(client_ctx);
    assert(test_ssl && SSL_set_fd(test_ssl, tls_fd) == 1);
    assert(SSL_set1_host(test_ssl, "localhost") == 1);
    assert(SSL_connect(test_ssl) == 1);
    write_all(tls_fd, ssl_request, sizeof(ssl_request));
    assert(SSL_read(test_ssl, &reply, 1) <= 0);
    SSL_free(test_ssl);
    test_ssl = NULL;
    close(tls_fd);
    assert(pthread_join(listener_thread, NULL) == 0);
    assert(listener_args.result == 1);
    SSL_CTX_free(client_ctx);
    qihse_pg_wire_listener_close(listener);
    assert(unlink(cert_path) == 0 && unlink(key_path) == 0);
    puts("PASS TLS listener: verified client, principal ACL and downgrade rejection");

    assert(qihse_table_row_count(table) == 2);
    qihse_kv_store_destroy(kv);
    qihse_cluster_topology_destroy(topo);
    qihse_uwp_sql_close_durable(&uwp);
    qihse_uwp_context_t reopened = {0};
    assert(qihse_uwp_sql_open_durable(&reopened, durable_path) == 0);
    assert(qihse_schema_get_table(reopened.schema, "pg_runtime"));
    assert(qihse_table_store_table_count(qihse_uwp_sql_table_store()) == 10);
    assert(qihse_schema_get_table(reopened.schema, "pg_typed"));
    assert(qihse_schema_get_table(reopened.schema, "pg_in_txn"));
    assert(qihse_schema_get_table(reopened.schema, "pg_in_txn_second"));
    assert(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "pg_runtime"));
    assert(qihse_table_row_count(qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_key")) == 1);
    int recovered_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, recovered_fds) == 0);
    for (size_t i = 0; i < 2; ++i) {
        assert(setsockopt(recovered_fds[i], SOL_SOCKET, SO_RCVTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
        assert(setsockopt(recovered_fds[i], SOL_SOCKET, SO_SNDTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
    }
    server_thread_args_t recovered_args = {.server_fd = recovered_fds[1],
                                           .uwp = &reopened};
    pthread_t recovered_thread;
    assert(pthread_create(&recovered_thread, NULL,
                          server_worker, &recovered_args) == 0);
    start_pg_client(recovered_fds[0], "User_1", password);
    send_pg_msg(recovered_fds[0], 'Q', status_sql, strlen(status_sql) + 1);
    assert(read_ready_status_capture_row(recovered_fds[0], retry_row,
                                         sizeof(retry_row), &retry_row_len) == 'I');
    assert(contains_bytes(retry_row, retry_row_len, "committed"));
    write_all(recovered_fds[0], &term_tag, 1);
    write_all(recovered_fds[0], &term_len, 4);
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(recovered_thread, NULL, &join_deadline) == 0);
    close(recovered_fds[0]);
    reopened.txn_manager = uwp.txn_manager;
    reopened.sql_engine = uwp.sql_engine;
    qihse_user_t* revoked_ddl_user = qihse_auth_create_user(op, 341,
        QIHSE_ROLE_OPERATOR, 0, 0, "PGWireDDLRevokedOperator123!", false);
    assert(revoked_ddl_user);
    qihse_txn_t* staged_ddl_txn = NULL;
    uint8_t ddl_isolation = QIHSE_ISO_READ_COMMITTED;
    assert(uwp_dispatch_txn(&reopened, 0x01, &ddl_isolation, 1,
        &staged_ddl_txn, revoked_ddl_user, -1, NULL, NULL) == UWP_STS_OK);
    const char* revoked_ddl = "CREATE TABLE pg_revoked_ddl (id INT)";
    assert(uwp_dispatch_sql(&reopened, 0x02, (const uint8_t*)revoked_ddl,
        strlen(revoked_ddl) + 1, &staged_ddl_txn, revoked_ddl_user, -1,
        NULL, NULL) == UWP_STS_OK);
    assert(!qihse_schema_get_table(reopened.schema, "pg_revoked_ddl"));
    assert(qihse_auth_destroy_user(op, 341));
    assert(uwp_dispatch_txn(&reopened, 0x02, NULL, 0, &staged_ddl_txn,
        revoked_ddl_user, -1, NULL, NULL) == UWP_STS_ERR_PERM);
    assert(staged_ddl_txn);
    assert(uwp_dispatch_txn(&reopened, 0x03, NULL, 0, &staged_ddl_txn,
        op, -1, NULL, NULL) == UWP_STS_OK);
    assert(!staged_ddl_txn &&
           !qihse_schema_get_table(reopened.schema, "pg_revoked_ddl") &&
           !qihse_table_store_find_table(qihse_uwp_sql_table_store(),
                                         "pg_revoked_ddl"));
    qihse_uwp_sql_close_durable(&reopened);
    qihse_schema_registry_destroy((qihse_schema_registry_t*)reopened.schema);
    qihse_txn_manager_destroy((qihse_txn_manager_t*)uwp.txn_manager);
    qihse_schema_registry_destroy((qihse_schema_registry_t*)uwp.schema);
    assert(unlink(durable_path) == 0);
    assert(unlink(lock_path) == 0);
    assert(rmdir(durable_dir) == 0);
}

int main() {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_pg_wire_txn_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    printf("==============================================================\n");
    printf("  QIHSE PostgreSQL Wire Transaction Tests                      \n");
    printf("==============================================================\n");

    test_pg_wire_handshake_and_queries();

    printf("\nPostgreSQL Wire transaction tests PASSED!\n");
    return 0;
}
