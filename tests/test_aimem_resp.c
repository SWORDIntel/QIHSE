/* Authenticated RESP surface for native QIHSE AI memory. */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static qihse_resp_server_t* server;

static size_t run(qihse_user_t* user, size_t argc, const char* const* argv,
                  uint8_t** out) {
    qihse_resp_arg_t args[16];
    assert(argc <= 16u);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    size_t len = 0;
    assert(qihse_resp_server_execute(server, user, argc, args, out, &len));
    return len;
}

static void expect_contains(qihse_user_t* user, size_t argc,
                            const char* const* argv, const char* needle) {
    uint8_t* reply = NULL;
    size_t len = run(user, argc, argv, &reply);
    assert(len < 16384u);
    char* text = calloc(len + 1u, 1u);
    assert(text);
    memcpy(text, reply, len);
    if (!strstr(text, needle)) fprintf(stderr, "expected response containing [%s], got [%s]\n", needle, text);
    assert(strstr(text, needle) != NULL);
    free(text);
    free(reply);
}

static char* extract_bulk_id(const uint8_t* reply, size_t len) {
    /* STORE returns one RESP bulk string. */
    const char* p = (const char*)reply;
    const char* body = strstr(p, "\r\n");
    if (!body || p[0] != '$') fprintf(stderr, "expected bulk id, got [%.*s]\n", (int)len, p);
    assert(body && body + 2 < p + len);
    body += 2;
    const char* end = strstr(body, "\r\n");
    assert(end && (size_t)(end - body) == QIHSE_AIMEM_ID_LEN);
    return strndup(body, QIHSE_AIMEM_ID_LEN);
}

static char* extract_array_bulk(const uint8_t* reply, size_t len, size_t wanted) {
    const char* p = (const char*)reply;
    const char* end = p + len;
    assert(p < end && *p == '*');
    p = strstr(p, "\r\n");
    assert(p); p += 2;
    for (size_t item = 0; item <= wanted; item++) {
        assert(p < end && *p == '$');
        char* length_end = NULL;
        long n = strtol(p + 1, &length_end, 10);
        assert(n >= 0 && length_end && length_end + 2 <= end &&
               length_end[0] == '\r' && length_end[1] == '\n');
        const char* body = length_end + 2;
        assert(body + n + 2 <= end && body[n] == '\r' && body[n + 1] == '\n');
        if (item == wanted) return strndup(body, (size_t)n);
        p = body + n + 2;
    }
    return NULL;
}

#define EVENT_REPLAY_THREADS 10u
#define EVENT_REPLAY_OPS_PER_THREAD 1000u
#define EVENT_REPLAY_DISTINCT 100u
typedef struct {
    qihse_user_t* user;
    uint64_t* latency_us;
    char project[32];
    bool ok;
} event_replay_worker_t;

#define HANDOFF_CLAIM_THREADS 100u
typedef struct {
    qihse_user_t* user;
    const char* id;
    bool expected_winner;
    size_t accepted;
    size_t denied;
} handoff_claim_worker_t;

static uint64_t monotonic_us(void) {
    struct timespec ts;
    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void* event_replay_worker(void* opaque) {
    event_replay_worker_t* w = (event_replay_worker_t*)opaque;
    w->ok = true;
    for (size_t i = 0; i < EVENT_REPLAY_OPS_PER_THREAD; i++) {
        unsigned event_no = (unsigned)(i % EVENT_REPLAY_DISTINCT);
        char event_id[32], summary[64];
        snprintf(event_id, sizeof event_id, "load-%03u", event_no);
        snprintf(summary, sizeof summary, "load event summary %03u", event_no);
        const char* args[] = { "AIMEM", "EVENT", "APPEND", w->project,
            "load-tree", "load-stream", "load-session", "load-test", event_id,
            "checkpoint", "1792500000000", summary };
        uint8_t* reply = NULL;
        uint64_t start = monotonic_us();
        size_t len = run(w->user, 12u, args, &reply);
        w->latency_us[i] = monotonic_us() - start;
        if (!reply || len < 5u || reply[0] != '$') w->ok = false;
        else {
            char* id = extract_bulk_id(reply, len);
            free(id);
        }
        free(reply);
        if (!w->ok) break;
    }
    return NULL;
}

static int compare_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static void* handoff_claim_worker(void* opaque) {
    handoff_claim_worker_t* w = (handoff_claim_worker_t*)opaque;
    const char* args[] = { "AIMEM", "HANDOFF", "ACCEPT", w->id, "1" };
    uint8_t* reply = NULL;
    size_t len = run(w->user, 5u, args, &reply);
    if (w->expected_winner && len >= 8u && strstr((const char*)reply, "ACCEPTED"))
        w->accepted++;
    else if (!w->expected_winner && reply &&
             (strstr((const char*)reply, "CONFLICT") || strstr((const char*)reply, "$-1")))
        w->denied++;
    free(reply);
    return NULL;
}

static bool fd_write_all(int fd, const void* buffer, size_t length) {
    const char* p = buffer;
    while (length) {
        ssize_t n = write(fd, p, length);
        if (n <= 0) return false;
        p += n; length -= (size_t)n;
    }
    return true;
}

static bool fd_read_line(int fd, char* out, size_t cap) {
    size_t used = 0;
    while (used + 1u < cap) {
        char c;
        if (read(fd, &c, 1u) != 1) return false;
        out[used++] = c;
        if (used >= 2u && out[used - 2u] == '\r' && out[used - 1u] == '\n') {
            out[used] = '\0'; return true;
        }
    }
    return false;
}

static bool fd_send3(int fd, const char* a, const char* b, const char* c) {
    const char* values[] = { a, b, c };
    char line[64];
    if (!fd_write_all(fd, "*3\r\n", 4u)) return false;
    for (size_t i = 0; i < 3u; i++) {
        int n = snprintf(line, sizeof line, "$%zu\r\n", strlen(values[i]));
        if (n <= 0 || !fd_write_all(fd, line, (size_t)n) ||
            !fd_write_all(fd, values[i], strlen(values[i])) ||
            !fd_write_all(fd, "\r\n", 2u)) return false;
    }
    return true;
}

static int network_claim_child(uint16_t port, const char* username,
        const char* password, const char* handoff_id, bool recipient) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 10;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr); addr.sin_family = AF_INET;
    addr.sin_port = htons(port); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) != 0 ||
        !fd_send3(fd, "AUTH", username, password)) { close(fd); return 11; }
    char line[256];
    if (!fd_read_line(fd, line, sizeof line) || strncmp(line, "+OK", 3u) != 0) {
        close(fd); return 12;
    }
    char accepts[128];
    snprintf(accepts, sizeof accepts, "AIMEM HANDOFF ACCEPT %s 1", handoff_id);
    /* Build the five-element command directly. */
    const char* args[] = { "AIMEM", "HANDOFF", "ACCEPT", handoff_id, "1" };
    for (size_t attempt = 0; attempt < 4u; attempt++) {
        char header[32];
        if (!fd_write_all(fd, "*5\r\n", 4u)) { close(fd); return 13; }
        for (size_t i = 0; i < 5u; i++) {
            int n = snprintf(header, sizeof header, "$%zu\r\n", strlen(args[i]));
            if (n <= 0 || !fd_write_all(fd, header, (size_t)n) ||
                !fd_write_all(fd, args[i], strlen(args[i])) || !fd_write_all(fd, "\r\n", 2u)) {
                close(fd); return 14;
            }
        }
        if (!fd_read_line(fd, line, sizeof line)) { close(fd); return 15; }
        bool accepted = strncmp(line, "$8\r\n", 4u) == 0;
        if (accepted) {
            char body[32];
            if (!fd_read_line(fd, body, sizeof body) || strcmp(body, "ACCEPTED\r\n") != 0) {
                close(fd); return 16;
            }
        }
        if (accepted != recipient) { close(fd); return 17; }
        (void)accepts;
    }
    close(fd); return 0;
}

int main(void) {
    char data_root[] = "build/aimem_resp_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* guest = qihse_auth_create_user(op, 9041u, QIHSE_ROLE_GUEST,
                                                  0u, 0u, "GuestPass123!", false);
    qihse_user_t* system_low_reader = qihse_auth_create_user(op, 9046u,
        QIHSE_ROLE_GUEST, 0u, 0u, "SystemLowReader123!", false);
    assert(system_low_reader);
    assert(guest);
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(op, 7u, 9042u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Tenant7Pass123!", false);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(op, 8u, 9043u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Tenant8Pass123!", false);
    qihse_user_t* tenant7_reader = qihse_auth_create_tenant_user(op, 7u, 9044u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Tenant7Reader123!", false);
    assert(tenant7 && tenant8 && tenant7_reader);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.enable_uwp_bridge = true;
    cfg.port = 0;
    server = qihse_resp_server_create(&cfg);
    assert(server);

    /* The in-process execution API requires an explicit principal.  Network
     * sessions enforce the unauthenticated NOAUTH path before dispatch; here
     * verify that callers cannot bypass that contract with a NULL principal. */
    const char* unauth[] = { "AIMEM", "COUNT" };
    uint8_t* unauth_reply = NULL;
    size_t unauth_len = 0;
    assert(!qihse_resp_server_execute(server, NULL, 2u,
                                      (const qihse_resp_arg_t[]) {
                                          { (const uint8_t*)unauth[0], strlen(unauth[0]) },
                                          { (const uint8_t*)unauth[1], strlen(unauth[1]) }
                                      }, &unauth_reply, &unauth_len));

    const char* store_public[] = { "AIMEM", "STORE", "1", "public memory", "public-1" };
    uint8_t* reply = NULL;
    size_t reply_len = run(guest, 5u, store_public, &reply);
    char* public_id = extract_bulk_id(reply, reply_len);
    free(reply);
    assert(strlen(public_id) == QIHSE_AIMEM_ID_LEN);

    /* Same principal + idempotency key returns the stable original id. */
    reply = NULL;
    reply_len = run(guest, 5u, store_public, &reply);
    char* public_id_again = extract_bulk_id(reply, reply_len);
    assert(strcmp(public_id, public_id_again) == 0);
    free(public_id_again);
    free(reply);

    const char* store_secret[] = { "AIMEM", "STORE", "2", "classified memory", "secret-1" };
    reply = NULL;
    reply_len = run(op, 5u, store_secret, &reply);
    char* secret_id = extract_bulk_id(reply, reply_len);
    free(reply);

    const char* count[] = { "AIMEM", "COUNT" };
    expect_contains(guest, 2u, count, ":1\r\n");
    const char* recall_public[] = { "AIMEM", "RECALL", "public", "8", "hybrid" };
    expect_contains(guest, 5u, recall_public, public_id);
    const char* recall_secret[] = { "AIMEM", "RECALL", "classified", "8", "hybrid" };
    expect_contains(guest, 5u, recall_secret, "*1\r\n");

    const char* get_public[] = { "AIMEM", "GET", "placeholder" };
    get_public[2] = public_id;
    expect_contains(guest, 3u, get_public, "public memory");
    const char* get_secret[] = { "AIMEM", "GET", "placeholder" };
    get_secret[2] = secret_id;
    expect_contains(guest, 3u, get_secret, "$-1\r\n");

    /* QH-01 migration is explicit, system-Operator-only, label preserving and
     * retryable. The low-clearance adapter call must disclose no payload. */
    const char* migrate_secret[] = { "AIMEM", "MIGRATE-LEGACY", "placeholder",
        "project-migrated", "tree-a", "stream-a", "session-a" };
    migrate_secret[2] = secret_id;
    expect_contains(guest, 7u, migrate_secret,
                    "NOPERM AIMEM legacy migration requires a system Operator");
    reply = NULL;
    reply_len = run(op, 7u, migrate_secret, &reply);
    char* migrated_id = extract_bulk_id(reply, reply_len);
    assert(strcmp(migrated_id, secret_id) == 0);
    free(migrated_id); free(reply);
    expect_contains(op, 3u, get_secret, "$-1\r\n");
    const char* migrated_get[] = { "AIMEM", "GET-SCOPED", "placeholder",
        "project-migrated", "tree-a", "stream-a", "session-a" };
    migrated_get[2] = secret_id;
    expect_contains(op, 7u, migrated_get, "classified memory");
    expect_contains(guest, 7u, migrated_get, "$-1\r\n");
    reply = NULL;
    reply_len = run(op, 7u, migrate_secret, &reply);
    migrated_id = extract_bulk_id(reply, reply_len);
    assert(strcmp(migrated_id, secret_id) == 0);
    free(migrated_id); free(reply);
    /* The historical unscoped idempotency mapping is deliberately not
     * redirected across scopes; replay fails closed after migration. */
    expect_contains(op, 5u, store_secret, "ERR CONFLICT");

    const char* forget[] = { "AIMEM", "FORGET", "placeholder" };
    forget[2] = public_id;
    expect_contains(guest, 3u, forget, ":1\r\n");
    expect_contains(guest, 2u, count, ":0\r\n");

    /* QH-01: explicit project scope is enforced by the server for search,
     * counts and direct-ID paths. Legacy global verbs never reveal scoped rows. */
    const char* scoped_store[] = { "AIMEM", "STORE-SCOPED", "1",
        "alpha scoped marker", "project-alpha", "", "", "", "scoped-key-1" };
    reply = NULL;
    reply_len = run(guest, 9u, scoped_store, &reply);
    char* scoped_id = extract_bulk_id(reply, reply_len);
    free(reply);
    reply = NULL;
    reply_len = run(guest, 9u, scoped_store, &reply);
    char* scoped_retry_id = extract_bulk_id(reply, reply_len);
    assert(strcmp(scoped_id, scoped_retry_id) == 0);
    free(scoped_retry_id);
    free(reply);
    const char* scoped_get[] = { "AIMEM", "GET-SCOPED", "placeholder",
        "project-alpha", "", "", "" };
    scoped_get[2] = scoped_id;
    expect_contains(guest, 7u, scoped_get, "alpha scoped marker");
    const char* scoped_wrong_project[] = { "AIMEM", "GET-SCOPED", "placeholder",
        "project-beta", "", "", "" };
    scoped_wrong_project[2] = scoped_id;
    expect_contains(guest, 7u, scoped_wrong_project, "$-1\r\n");
    const char* scoped_count[] = { "AIMEM", "COUNT-SCOPED", "project-alpha", "", "", "" };
    expect_contains(guest, 6u, scoped_count, ":1\r\n");
    const char* wrong_count[] = { "AIMEM", "COUNT-SCOPED", "project-beta", "", "", "" };
    expect_contains(guest, 6u, wrong_count, ":0\r\n");
    const char* scoped_recall[] = { "AIMEM", "RECALL-SCOPED", "alpha scoped", "8",
        "bm25", "0", "project-alpha", "", "", "" };
    expect_contains(guest, 10u, scoped_recall, scoped_id);
    const char* scoped_semantic[] = { "AIMEM", "RECALL-SCOPED", "alpha scoped", "8",
        "semantic", "0", "project-alpha", "", "", "" };
    expect_contains(guest, 10u, scoped_semantic, scoped_id);
    const char* scoped_hybrid[] = { "AIMEM", "RECALL-SCOPED", "alpha scoped", "8",
        "hybrid", "0", "project-alpha", "", "", "" };
    expect_contains(guest, 10u, scoped_hybrid, scoped_id);
    const char* wrong_recall[] = { "AIMEM", "RECALL-SCOPED", "alpha scoped", "8",
        "bm25", "0", "project-beta", "", "", "" };
    expect_contains(guest, 10u, wrong_recall, "*0\r\n");
    const char* scoped_other_project[] = { "AIMEM", "STORE-SCOPED", "1",
        "beta scoped marker", "project-beta", "", "", "", "scoped-key-1" };
    reply = NULL;
    reply_len = run(guest, 9u, scoped_other_project, &reply);
    char* other_project_id = extract_bulk_id(reply, reply_len);
    assert(strcmp(scoped_id, other_project_id) != 0);
    free(other_project_id);
    free(reply);
    const char* legacy_scoped_get[] = { "AIMEM", "GET", "placeholder" };
    legacy_scoped_get[2] = scoped_id;
    expect_contains(guest, 3u, legacy_scoped_get, "$-1\r\n");
    const char* legacy_recall[] = { "AIMEM", "RECALL", "alpha scoped", "8", "bm25" };
    expect_contains(guest, 5u, legacy_recall, "*0\r\n");

    /* A protected record in the requested project remains hidden on every
     * scoped access path for a low-clearance actor. */
    const char* high_store[] = { "AIMEM", "STORE-SCOPED", "2",
        "QH01_HIGH_SCOPE_MARKER", "project-high", "", "", "" };
    reply = NULL;
    reply_len = run(op, 8u, high_store, &reply);
    char* high_scoped_id = extract_bulk_id(reply, reply_len);
    free(reply);
    const char* high_get[] = { "AIMEM", "GET-SCOPED", "placeholder",
        "project-high", "", "", "" };
    high_get[2] = high_scoped_id;
    expect_contains(guest, 7u, high_get, "$-1\r\n");
    const char* high_count[] = { "AIMEM", "COUNT-SCOPED", "project-high", "", "", "" };
    expect_contains(guest, 6u, high_count, ":0\r\n");
    const char* high_recall[] = { "AIMEM", "RECALL-SCOPED", "QH01_HIGH_SCOPE_MARKER",
        "8", "bm25", "0", "project-high", "", "", "" };
    expect_contains(guest, 10u, high_recall, "*0\r\n");
    const char* high_forget[] = { "AIMEM", "FORGET-SCOPED", "placeholder",
        "project-high", "", "", "" };
    high_forget[2] = high_scoped_id;
    expect_contains(guest, 7u, high_forget, ":0\r\n");

    const char* worktree_store[] = { "AIMEM", "STORE-SCOPED", "1",
        "checkout boundary marker", "project-alpha", "checkout-a", "stream-a", "session-a" };
    reply = NULL;
    reply_len = run(guest, 8u, worktree_store, &reply);
    char* worktree_id = extract_bulk_id(reply, reply_len);
    free(reply);
    const char* worktree_count[] = { "AIMEM", "COUNT-SCOPED", "project-alpha",
        "checkout-a", "", "" };
    expect_contains(guest, 6u, worktree_count, ":1\r\n");
    const char* workstream_count[] = { "AIMEM", "COUNT-SCOPED", "project-alpha",
        "checkout-a", "stream-a", "" };
    expect_contains(guest, 6u, workstream_count, ":1\r\n");
    const char* session_count[] = { "AIMEM", "COUNT-SCOPED", "project-alpha",
        "checkout-a", "stream-a", "session-a" };
    expect_contains(guest, 6u, session_count, ":1\r\n");
    const char* sibling_stream_count[] = { "AIMEM", "COUNT-SCOPED", "project-alpha",
        "checkout-a", "stream-b", "" };
    expect_contains(guest, 6u, sibling_stream_count, ":0\r\n");
    const char* sibling_session_count[] = { "AIMEM", "COUNT-SCOPED", "project-alpha",
        "checkout-a", "stream-a", "session-b" };
    expect_contains(guest, 6u, sibling_session_count, ":0\r\n");
    const char* orphan_stream_store[] = { "AIMEM", "STORE-SCOPED", "1",
        "invalid orphan stream", "project-alpha", "", "stream-a", "" };
    expect_contains(guest, 8u, orphan_stream_store,
                    "ERR invalid or incomplete AIMEM project scope");
    const char* orphan_session_count[] = { "AIMEM", "COUNT-SCOPED", "project-alpha",
        "checkout-a", "", "session-a" };
    expect_contains(guest, 6u, orphan_session_count, "ERR invalid AIMEM scope");
    const char* wrong_worktree_get[] = { "AIMEM", "GET-SCOPED", "placeholder",
        "project-alpha", "checkout-b", "", "" };
    wrong_worktree_get[2] = worktree_id;
    expect_contains(guest, 7u, wrong_worktree_get, "$-1\r\n");
    const char* project_count[] = { "AIMEM", "COUNT-SCOPED", "project-alpha", "", "", "" };
    expect_contains(guest, 6u, project_count, ":2\r\n");
    const char* wrong_worktree_recall[] = { "AIMEM", "RECALL-SCOPED",
        "checkout boundary", "8", "hybrid", "0", "project-alpha",
        "checkout-b", "", "" };
    expect_contains(guest, 10u, wrong_worktree_recall, "*0\r\n");

    /* Same numeric principal and project in separate tenants must remain
     * isolated at the native AIMEM key namespace, including direct ID reads. */
    const char* tenant7_store[] = { "AIMEM", "STORE-SCOPED", "1",
        "tenant seven marker", "shared-project", "", "", "" };
    reply = NULL;
    reply_len = run(tenant7, 8u, tenant7_store, &reply);
    char* tenant7_id = extract_bulk_id(reply, reply_len);
    free(reply);
    qihse_ai_memory_hit_t native_hit;
    memset(&native_hit, 0, sizeof native_hit);
    assert(!qihse_ai_memory_get(server, tenant8, tenant7_id, &native_hit));
    assert(!qihse_ai_memory_store(server, tenant7, "unscoped tenant memory",
                                  QIHSE_AIMEM_EPISODIC, NULL));
    assert(!qihse_ai_memory_forget(server, tenant8, tenant7_id));
    assert(qihse_ai_memory_count(server, tenant8) == 0u);
    qihse_ai_memory_hit_t native_hits[2];
    assert(qihse_ai_memory_recall(server, tenant8, "tenant seven", 2u,
                                  native_hits, 2u) == 0u);
    const char* tenant8_get[] = { "AIMEM", "GET-SCOPED", "placeholder",
        "shared-project", "", "", "" };
    tenant8_get[2] = tenant7_id;
    expect_contains(tenant8, 7u, tenant8_get, "$-1\r\n");
    const char* tenant8_count[] = { "AIMEM", "COUNT-SCOPED", "shared-project", "", "", "" };
    expect_contains(tenant8, 6u, tenant8_count, ":0\r\n");
    const char* tenant8_recall[] = { "AIMEM", "RECALL-SCOPED", "tenant seven marker",
        "8", "bm25", "0", "shared-project", "", "", "" };
    expect_contains(tenant8, 10u, tenant8_recall, "*0\r\n");
    const char* tenant8_store[] = { "AIMEM", "STORE-SCOPED", "1",
        "tenant eight marker", "shared-project", "", "", "" };
    reply = NULL;
    reply_len = run(tenant8, 8u, tenant8_store, &reply);
    char* tenant8_id = extract_bulk_id(reply, reply_len);
    free(reply);
    assert(strcmp(tenant7_id, tenant8_id) != 0);

    const char* evidence_store[] = { "AIMEM", "STORE-SCOPED", "1", "evidence source",
        "project-events", "checkout-a", "stream-a", "session-1" };
    reply = NULL;
    reply_len = run(tenant7, 8u, evidence_store, &reply);
    char* evidence_id = extract_bulk_id(reply, reply_len);
    free(reply);
    const char* event_append[] = { "AIMEM", "EVENT", "APPEND", "project-events",
        "checkout-a", "stream-a", "session-1", "hax", "evt-0001",
        "task_completed", "1792500000000", "completed typed event", "placeholder" };
    event_append[12] = evidence_id;
    reply = NULL;
    reply_len = run(tenant7, 13u, event_append, &reply);
    char* event_doc_id = extract_bulk_id(reply, reply_len);
    free(reply);
    reply = NULL;
    reply_len = run(tenant7, 13u, event_append, &reply);
    char* event_retry_id = extract_bulk_id(reply, reply_len);
    assert(strcmp(event_doc_id, event_retry_id) == 0);
    free(event_retry_id);
    free(reply);
    const char* event_read[] = { "AIMEM", "EVENT", "READ", "placeholder",
        "project-events", "checkout-a", "stream-a", "session-1" };
    event_read[3] = event_doc_id;
    expect_contains(tenant7, 8u, event_read, "QHEV2|hax|evt-0001|task_completed|");
    expect_contains(tenant8, 8u, event_read, "$-1\r\n");
    const char* project_grant[] = { "AIMEM", "PROJECT", "GRANT", "project-events", "9044" };
    expect_contains(tenant7, 5u, project_grant, "+OK\r\n");
    expect_contains(tenant7_reader, 8u, event_read, "QHEV2|hax|evt-0001|task_completed|");
    const char* grantee_forget[] = { "AIMEM", "FORGET-SCOPED", "placeholder",
        "project-events", "checkout-a", "stream-a", "session-1" };
    grantee_forget[2] = event_doc_id;
    expect_contains(tenant7_reader, 7u, grantee_forget, ":0\r\n");
    const char* foreign_grant[] = { "AIMEM", "PROJECT", "GRANT", "project-events", "9043" };
    expect_contains(tenant7, 5u, foreign_grant, "NOPERM");
    const char* project_revoke[] = { "AIMEM", "PROJECT", "REVOKE", "project-events", "9044" };
    expect_contains(tenant7, 5u, project_revoke, "+OK\r\n");
    expect_contains(tenant7_reader, 8u, event_read, "$-1\r\n");
    free(evidence_id);

    qihse_user_t* tenant7_competitor = qihse_auth_create_tenant_user(op, 7u, 9045u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Tenant7Competitor123!", false);
    assert(tenant7_competitor);
    expect_contains(tenant7, 5u, project_grant, "+OK\r\n");
    const char* competitor_grant[] = { "AIMEM", "PROJECT", "GRANT", "project-events", "9045" };
    expect_contains(tenant7, 5u, competitor_grant, "+OK\r\n");
    const char* bad_evidence_offer[] = { "AIMEM", "HANDOFF", "OFFER", "9044", "60000",
        "project-events", "checkout-a", "stream-a", "session-1", "bad pointer", "placeholder" };
    bad_evidence_offer[10] = tenant8_id;
    expect_contains(tenant7, 11u, bad_evidence_offer, "NOPERM");
    const char* handoff_offer[] = { "AIMEM", "HANDOFF", "OFFER", "9044", "60000",
        "project-events", "checkout-a", "stream-a", "session-1", "review durable handoff", "placeholder" };
    handoff_offer[10] = event_doc_id;
    reply = NULL;
    reply_len = run(tenant7, 11u, handoff_offer, &reply);
    char* handoff_id = extract_bulk_id(reply, reply_len);
    free(reply);
    pthread_t handoff_threads[HANDOFF_CLAIM_THREADS];
    handoff_claim_worker_t claimers[HANDOFF_CLAIM_THREADS];
    for (size_t i = 0; i < HANDOFF_CLAIM_THREADS; i++) {
        claimers[i] = (handoff_claim_worker_t) {
            .user = i % 2u ? tenant7_reader : tenant7_competitor,
            .id = handoff_id,
            .expected_winner = i % 2u != 0u,
            .accepted = 0u, .denied = 0u
        };
        assert(pthread_create(&handoff_threads[i], NULL, handoff_claim_worker,
                              &claimers[i]) == 0);
    }
    size_t accepted = 0u, denied = 0u;
    for (size_t i = 0; i < HANDOFF_CLAIM_THREADS; i++) {
        assert(pthread_join(handoff_threads[i], NULL) == 0);
        accepted += claimers[i].accepted;
        denied += claimers[i].denied;
    }
    fprintf(stderr, "AIMEM handoff claim race: accepted=%zu denied=%zu\n", accepted, denied);
    assert(accepted == HANDOFF_CLAIM_THREADS / 2u);
    assert(denied == HANDOFF_CLAIM_THREADS / 2u);
    const char* handoff_get[] = { "AIMEM", "HANDOFF", "GET", "placeholder" };
    handoff_get[3] = handoff_id;
    expect_contains(tenant7, 4u, handoff_get, "ACCEPTED");
    expect_contains(tenant7, 4u, handoff_get, "$1\r\n2\r\n");
    const char* handoff_cancel[] = { "AIMEM", "HANDOFF", "CANCEL", "placeholder", "1" };
    handoff_cancel[3] = handoff_id;
    expect_contains(tenant7, 5u, handoff_cancel, "ERR CONFLICT");
    free(handoff_id);

    const char* expiry_offer[] = { "AIMEM", "HANDOFF", "OFFER", "9044", "1",
        "project-events", "checkout-a", "stream-a", "session-1", "expires soon" };
    reply = NULL;
    reply_len = run(tenant7, 10u, expiry_offer, &reply);
    char* expiry_id = extract_bulk_id(reply, reply_len);
    free(reply);
    usleep(5000u);
    const char* expiry_get[] = { "AIMEM", "HANDOFF", "GET", "placeholder" };
    expiry_get[3] = expiry_id;
    expect_contains(tenant7, 4u, expiry_get, "EXPIRED");
    expect_contains(tenant7, 4u, expiry_get, "$1\r\n2\r\n");
    free(expiry_id);

    /* QH-04 wire adapter: durable create/revise, exact/history/latest, and
     * the mandatory low-clearance/high-data direct-ID denial. */
    const char* knowledge_create[] = { "AIMEM", "KNOWLEDGE", "CREATE", "1", "1",
        "curated lineage v1", "project-events", "checkout-a", "stream-a", "session-1" };
    reply = NULL;
    reply_len = run(tenant7, 10u, knowledge_create, &reply);
    char* knowledge_id = extract_array_bulk(reply, reply_len, 0u);
    char* knowledge_v1 = extract_array_bulk(reply, reply_len, 1u);
    char* knowledge_content = extract_array_bulk(reply, reply_len, 14u);
    assert(strcmp(knowledge_content, "curated lineage v1") == 0);
    free(knowledge_content);
    free(reply);
    const char* knowledge_get[] = { "AIMEM", "KNOWLEDGE", "GET", "placeholder",
        "project-events", "checkout-a", "stream-a", "session-1" };
    knowledge_get[3] = knowledge_v1;
    expect_contains(tenant7_reader, 8u, knowledge_get, "curated lineage v1");
    const char* knowledge_revise[] = { "AIMEM", "KNOWLEDGE", "REVISE", "placeholder",
        "placeholder", "1", "1", "curated lineage v2" };
    knowledge_revise[3] = knowledge_id; knowledge_revise[4] = knowledge_v1;
    expect_contains(tenant7, 8u, knowledge_revise, "curated lineage v2");
    expect_contains(tenant7, 8u, knowledge_revise, "ERR CONFLICT");
    const char* knowledge_latest[] = { "AIMEM", "KNOWLEDGE", "LATEST", "placeholder",
        "project-events", "checkout-a", "stream-a", "session-1" };
    knowledge_latest[3] = knowledge_id;
    expect_contains(tenant7_reader, 8u, knowledge_latest, "curated lineage v2");

    const char* high_knowledge_create[] = { "AIMEM", "KNOWLEDGE", "CREATE", "2", "1",
        "QH04_WIRE_HIGH_MARKER", "project-high", "", "", "" };
    const char* low_high_scope_seed[] = { "AIMEM", "STORE-SCOPED", "1",
        "low project membership seed", "project-high", "", "", "" };
    reply = NULL;
    reply_len = run(guest, 8u, low_high_scope_seed, &reply);
    char* low_high_seed_id = extract_bulk_id(reply, reply_len);
    free(low_high_seed_id); free(reply);
    const char* low_high_grant[] = { "AIMEM", "PROJECT", "GRANT", "project-high", "9046" };
    expect_contains(guest, 5u, low_high_grant, "+OK\r\n");
    reply = NULL;
    reply_len = run(op, 10u, high_knowledge_create, &reply);
    char* high_knowledge_v1 = extract_array_bulk(reply, reply_len, 1u);
    free(reply);
    const char* high_knowledge_get[] = { "AIMEM", "KNOWLEDGE", "GET", "placeholder",
        "project-high", "", "", "" };
    high_knowledge_get[3] = high_knowledge_v1;
    expect_contains(system_low_reader, 8u, high_knowledge_get, "$-1\r\n");
    free(high_knowledge_v1); free(knowledge_v1); free(knowledge_id);

    const char* event_conflict[] = { "AIMEM", "EVENT", "APPEND", "project-events",
        "checkout-a", "stream-a", "session-1", "hax", "evt-0001",
        "task_completed", "1792500000000", "conflicting event bytes" };
    expect_contains(tenant7, 12u, event_conflict, "ERR CONFLICT");
    const char* invalid_event[] = { "AIMEM", "EVENT", "APPEND", "project-events",
        "checkout-a", "stream-a", "session-1", "hax", "evt-0002",
        "execute_command", "1792500000000", "must reject unregistered kind" };
    expect_contains(tenant7, 12u, invalid_event, "ERR invalid AIMEM event fields");

    /* Ten simulated agents share one authenticated principal across ten
     * projects. 10,000 at-least-once deliveries over 100 deterministic event
     * identities per project must converge to exactly 100 records each. */
    pthread_t replay_threads[EVENT_REPLAY_THREADS];
    event_replay_worker_t workers[EVENT_REPLAY_THREADS];
    uint64_t* latencies = calloc(EVENT_REPLAY_THREADS * EVENT_REPLAY_OPS_PER_THREAD,
                                  sizeof(*latencies));
    assert(latencies);
    uint64_t replay_started = monotonic_us();
    for (size_t i = 0; i < EVENT_REPLAY_THREADS; i++) {
        workers[i] = (event_replay_worker_t) {
            .user = tenant7,
            .latency_us = latencies + i * EVENT_REPLAY_OPS_PER_THREAD,
            .project = {0},
            .ok = false
        };
        snprintf(workers[i].project, sizeof workers[i].project,
                 "load-project-%zu", i);
        assert(pthread_create(&replay_threads[i], NULL, event_replay_worker,
                              &workers[i]) == 0);
    }
    for (size_t i = 0; i < EVENT_REPLAY_THREADS; i++) {
        assert(pthread_join(replay_threads[i], NULL) == 0);
        assert(workers[i].ok);
    }
    uint64_t elapsed_us = monotonic_us() - replay_started;
    qsort(latencies, EVENT_REPLAY_THREADS * EVENT_REPLAY_OPS_PER_THREAD,
          sizeof(*latencies), compare_u64);
    fprintf(stderr, "AIMEM durable event append: p50=%llu us p95=%llu us throughput=%.1f ops/s (%u calls, %u threads)\n",
            (unsigned long long)latencies[5000u],
            (unsigned long long)latencies[9500u],
            elapsed_us ? (double)(EVENT_REPLAY_THREADS * EVENT_REPLAY_OPS_PER_THREAD) * 1000000.0 / (double)elapsed_us : 0.0,
            (unsigned)(EVENT_REPLAY_THREADS * EVENT_REPLAY_OPS_PER_THREAD),
            (unsigned)EVENT_REPLAY_THREADS);
    free(latencies);
    for (size_t i = 0; i < EVENT_REPLAY_THREADS; i++) {
        char project[32];
        snprintf(project, sizeof project, "load-project-%zu", i);
        const char* load_count[] = { "AIMEM", "COUNT-SCOPED", project,
            "load-tree", "load-stream", "load-session", "3" };
        expect_contains(tenant7, 7u, load_count, ":100\r\n");
    }

    const char* high_event[] = { "AIMEM", "EVENT", "APPEND", "project-high-events",
        "", "", "", "operator", "evt-secret", "observation",
        "1792500000001", "QH02_HIGH_EVENT_MARKER" };
    reply = NULL;
    reply_len = run(op, 12u, high_event, &reply);
    char* high_event_id = extract_bulk_id(reply, reply_len);
    free(reply);
    const char* low_event_read[] = { "AIMEM", "EVENT", "READ", "placeholder",
        "project-high-events", "", "", "" };
    low_event_read[3] = high_event_id;
    expect_contains(guest, 8u, low_event_read, "$-1\r\n");
    free(high_event_id);
    free(tenant7_id);
    free(tenant8_id);

    free(public_id);
    free(secret_id);
    free(scoped_id);
    free(high_scoped_id);
    free(worktree_id);
    const char* process_offer[] = { "AIMEM", "HANDOFF", "OFFER", "9044", "60000",
        "project-events", "checkout-a", "stream-a", "session-1", "fork race evidence", "placeholder" };
    process_offer[10] = event_doc_id;
    reply = NULL;
    reply_len = run(tenant7, 11u, process_offer, &reply);
    char* process_handoff_id = extract_bulk_id(reply, reply_len);
    free(reply);
    free(event_doc_id);
    assert(qihse_resp_server_start(server));
    uint16_t listener_port = qihse_resp_server_port(server);
    assert(listener_port != 0u);
    pid_t recipient_child = fork();
    assert(recipient_child >= 0);
    if (recipient_child == 0) _exit(network_claim_child(listener_port,
        qihse_user_get_username(tenant7_reader), "Tenant7Reader123!",
        process_handoff_id, true));
    pid_t competitor_child = fork();
    assert(competitor_child >= 0);
    if (competitor_child == 0) _exit(network_claim_child(listener_port,
        qihse_user_get_username(tenant7_competitor), "Tenant7Competitor123!",
        process_handoff_id, false));
    int recipient_status = 0, competitor_status = 0;
    assert(waitpid(recipient_child, &recipient_status, 0) == recipient_child);
    assert(waitpid(competitor_child, &competitor_status, 0) == competitor_child);
    assert(WIFEXITED(recipient_status) && WEXITSTATUS(recipient_status) == 0);
    assert(WIFEXITED(competitor_status) && WEXITSTATUS(competitor_status) == 0);
    free(process_handoff_id);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    puts("PASS authenticated AIMEM RESP protocol and principal enforcement");
    return 0;
}
