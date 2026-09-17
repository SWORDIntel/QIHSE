/*
 * test_repl.c — streaming replication, read-replica routing and the
 * connection pooler.
 *
 * Exercises:
 *   src/spinnaker/qihse_repl.c        — replication context, slots, WAL shipping
 *   src/spinnaker/qihse_read_replica.c— replica pool, round-robin routing, health
 *   src/spinnaker/qihse_pooler.c      — backend registry, modes, admin console
 *
 *   1. Replication context lifecycle and state machine
 *   2. Replication slots: create, duplicate refused, advance, drop, count
 *   3. WAL shipping over a real loopback TCP socket: the peer must receive the
 *      [LSN][length][data] frame byte-for-byte, and get_status must reflect it
 *   4. Refusals: shipping while not streaming, and connecting to a dead port
 *   5. Read-replica pool: add/remove, round-robin routing, active count
 *   6. Read-replica health checking against a live listener and a dead port
 *   7. Pooler: config, backend registry, pooling modes, admin console
 *
 * NOT covered here (see docs/architecture/replication_backup.md):
 *   - src/tractable/qihse_parallel_query.c — a stub: the scan workers count
 *     nothing ("TODO: actual KV store iteration with partitioning") and the
 *     aggregate/join paths are TODOs.
 *   - src/tractable/qihse_backup.c — the authenticated backup/restore API has
 *     no test in this repository; the only backup test is
 *     tests/test_federation_backup.c, which covers the federation writer/reader.
 *   - qihse_repl_apply_wal() records the LSN only; it does not replay the WAL
 *     into a local store ("In a real implementation, this would replay...").
 */
#include "qihse_repl.h"
#include "qihse_read_replica.h"
#include "qihse_pooler.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

/* ── Loopback helpers ───────────────────────────────────────────────────── */

/* Create a listening TCP socket on an ephemeral loopback port. */
static int listen_loopback(uint16_t* out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    int opt = 1;
    assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    assert(listen(fd, 4) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

static int accept_with_timeout(int listen_fd, int timeout_sec) {
    struct timeval tv = {timeout_sec, 0};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(listen_fd, &rfds);
    int rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) return -1;
    return accept(listen_fd, NULL, NULL);
}

static ssize_t read_exact(int fd, void* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, (char*)buf + off, len - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

/* ── 1/2. Context and slots ─────────────────────────────────────────────── */

static void test_repl_context_and_slots(void) {
    qihse_repl_context_t* ctx = qihse_repl_create(REPL_ROLE_REPLICA);
    assert(ctx);
    assert(ctx->role == REPL_ROLE_REPLICA);
    assert(ctx->state == REPL_STATE_DISCONNECTED);
    assert(ctx->stream_fd == -1);
    assert(qihse_repl_slot_count(ctx) == 0);

    uint64_t last = 1, flush = 1;
    repl_state_t state = REPL_STATE_ERROR;
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(last == 0 && flush == 0 && state == REPL_STATE_DISCONNECTED);

    /* Slots: create, duplicate refused, advance, count, drop. */
    assert(qihse_repl_create_slot(ctx, "slot_a") == 0);
    assert(qihse_repl_create_slot(ctx, "slot_b") == 0);
    assert(qihse_repl_slot_count(ctx) == 2);
    assert(qihse_repl_create_slot(ctx, "slot_a") == -1);
    assert(qihse_repl_create_slot(ctx, NULL) == -1);

    assert(qihse_repl_advance_slot(ctx, "slot_a", 500) == 0);
    assert(qihse_repl_advance_slot(ctx, "slot_a", 900) == 0);
    /* Advancing to a lower LSN must not move the restart point backwards. */
    assert(qihse_repl_advance_slot(ctx, "slot_a", 100) == 0);
    for (size_t i = 0; i < ctx->num_slots; i++) {
        if (strcmp(ctx->slots[i].name, "slot_a") == 0) {
            assert(ctx->slots[i].restart_lsn == 900);
            assert(ctx->slots[i].confirmed_flush_lsn == 100);
        }
    }
    assert(qihse_repl_advance_slot(ctx, "absent", 1) == -1);
    assert(qihse_repl_drop_slot(ctx, "slot_b") == 0);
    assert(qihse_repl_slot_count(ctx) == 1);
    assert(qihse_repl_drop_slot(ctx, "slot_b") == -1);

    /* Shipping before streaming is refused. */
    const uint8_t data[4] = {1, 2, 3, 4};
    assert(qihse_repl_ship_wal(ctx, data, sizeof(data), 1) == -1);
    assert(qihse_repl_start_streaming(ctx) == -1);   /* not connected */

    qihse_repl_destroy(ctx);
    printf("PASS replication context: state machine, slot lifecycle, refusal before streaming\n");
}

/* ── 3/4. WAL shipping over a real socket ───────────────────────────────── */

static void test_repl_ship_wal(void) {
    uint16_t port = 0;
    int listener = listen_loopback(&port);

    qihse_repl_context_t* ctx = qihse_repl_create(REPL_ROLE_REPLICA);
    assert(ctx);
    assert(qihse_repl_connect_primary(ctx, "127.0.0.1", port) == 0);
    assert(ctx->state == REPL_STATE_CONNECTING);
    assert(ctx->primary_port == port);

    int peer = accept_with_timeout(listener, 5);
    assert(peer >= 0);

    assert(qihse_repl_start_streaming(ctx) == 0);
    assert(ctx->state == REPL_STATE_STREAMING);

    /* The wire frame is [LSN:8][length:8][data]. */
    const char* wal = "WAL-RECORD-42";
    size_t wal_len = strlen(wal);
    assert(qihse_repl_ship_wal(ctx, (const uint8_t*)wal, wal_len, 4242) == 0);

    uint64_t hdr[2];
    assert(read_exact(peer, hdr, sizeof(hdr)) == (ssize_t)sizeof(hdr));
    assert(hdr[0] == 4242);
    assert(hdr[1] == wal_len);
    char got[64];
    memset(got, 0, sizeof(got));
    assert(read_exact(peer, got, wal_len) == (ssize_t)wal_len);
    assert(memcmp(got, wal, wal_len) == 0);

    uint64_t last = 0, flush = 0;
    repl_state_t state = REPL_STATE_ERROR;
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(last == 4242);
    assert(state == REPL_STATE_STREAMING);

    /* Applying a record advances the flush LSN (it does not replay; see the
     * header note). */
    assert(qihse_repl_apply_wal(ctx, (const uint8_t*)wal, wal_len, 5000) == 0);
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(flush == 5000);
    assert(qihse_repl_apply_wal(ctx, NULL, 0, 1) == -1);

    assert(qihse_repl_stop(ctx) == 0);
    assert(ctx->state == REPL_STATE_DISCONNECTED);
    close(peer);
    close(listener);

    /* Connecting to a port with no listener fails and reports ERROR. */
    int dead = socket(AF_INET, SOCK_STREAM, 0);
    assert(dead >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(dead, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    socklen_t alen = sizeof(addr);
    assert(getsockname(dead, (struct sockaddr*)&addr, &alen) == 0);
    uint16_t dead_port = ntohs(addr.sin_port);
    close(dead);

    qihse_repl_context_t* ctx2 = qihse_repl_create(REPL_ROLE_REPLICA);
    assert(ctx2);
    assert(qihse_repl_connect_primary(ctx2, "127.0.0.1", dead_port) == -1);
    assert(ctx2->state == REPL_STATE_ERROR);
    assert(qihse_repl_connect_primary(ctx2, "not-an-ip", 5432) == -1);
    assert(qihse_repl_connect_primary(ctx2, NULL, 5432) == -1);
    qihse_repl_destroy(ctx2);

    qihse_repl_destroy(ctx);
    printf("PASS replication shipping: [LSN][len][data] frame on the wire, status, refusals\n");
}

/* ── 5/6. Read replica pool ─────────────────────────────────────────────── */

static void test_read_replica_pool(void) {
    qihse_read_replica_pool_t* pool = qihse_read_replica_pool_create();
    assert(pool);
    assert(qihse_read_replica_active_count(pool) == 0);
    char* host = NULL;
    uint16_t port = 0;
    assert(qihse_read_replica_route(pool, &host, &port) == -1);

    assert(qihse_read_replica_pool_add(pool, "10.0.0.2", 5432) == 0);
    assert(qihse_read_replica_pool_add(pool, "10.0.0.3", 5433) == 0);
    assert(qihse_read_replica_pool_add(pool, "10.0.0.4", 5434) == 0);
    assert(qihse_read_replica_active_count(pool) == 3);

    /* Round-robin over the three healthy replicas. */
    const uint16_t want[3] = {5432, 5433, 5434};
    for (int i = 0; i < 3; i++) {
        assert(qihse_read_replica_route(pool, &host, &port) == 0);
        assert(host && port == want[i]);
        free(host);
        host = NULL;
    }
    /* Wraps around. */
    assert(qihse_read_replica_route(pool, &host, &port) == 0);
    assert(port == 5432);
    free(host);
    host = NULL;

    /* Removal takes a replica out of rotation. */
    assert(qihse_read_replica_pool_remove(pool, "10.0.0.3", 5433) == 0);
    assert(qihse_read_replica_active_count(pool) == 2);
    assert(qihse_read_replica_pool_remove(pool, "10.0.0.3", 5433) == -1);
    int seen5433 = 0;
    for (int i = 0; i < 6; i++) {
        assert(qihse_read_replica_route(pool, &host, &port) == 0);
        if (port == 5433) seen5433 = 1;
        free(host);
        host = NULL;
    }
    assert(!seen5433);
    assert(qihse_read_replica_pool_add(pool, NULL, 1) == -1);

    /* Health checking against unreachable addresses marks them unhealthy. */
    int healthy = qihse_read_replica_health_check(pool);
    assert(healthy == 0);
    assert(qihse_read_replica_active_count(pool) == 0);
    assert(qihse_read_replica_route(pool, &host, &port) == -1);

    /* A live listener is reported healthy and becomes routable again. */
    uint16_t live_port = 0;
    int listener = listen_loopback(&live_port);
    qihse_read_replica_pool_t* live = qihse_read_replica_pool_create();
    assert(live);
    assert(qihse_read_replica_pool_add(live, "127.0.0.1", live_port) == 0);
    assert(qihse_read_replica_health_check(live) == 1);
    assert(qihse_read_replica_active_count(live) == 1);
    assert(qihse_read_replica_route(live, &host, &port) == 0);
    assert(strcmp(host, "127.0.0.1") == 0 && port == live_port);
    free(host);
    qihse_read_replica_pool_destroy(live);
    close(listener);

    qihse_read_replica_pool_destroy(pool);
    printf("PASS read replicas: round-robin routing, removal, health check against live/dead ports\n");
}

/* ── 7. Pooler ──────────────────────────────────────────────────────────── */

static void test_pooler(void) {
    qihse_pooler_config_t config;
    qihse_pooler_config_defaults(&config);
    config.mode = POOL_TRANSACTION;
    config.max_connections = 100;
    config.max_per_client = 10;
    config.idle_timeout_ms = 30000;
    config.pool_mode = POOL_TRANSACTION;

    qihse_pooler_t* pool = qihse_pooler_create_ex(&config);
    assert(pool);
    const qihse_pooler_config_t* got = qihse_pooler_get_config(pool);
    assert(got);
    assert(got->mode == POOL_TRANSACTION);
    assert(got->max_connections == 100);
    assert(got->max_per_client == 10);
    assert(qihse_pooler_get_mode(pool) == POOL_TRANSACTION);
    assert(strcmp(qihse_pooler_mode_str(POOL_TRANSACTION), "transaction") == 0);
    assert(strcmp(qihse_pooler_mode_str(POOL_SESSION), "session") == 0);
    assert(strcmp(qihse_pooler_mode_str(POOL_STATEMENT), "statement") == 0);

    assert(qihse_pooler_set_mode(pool, POOL_SESSION) == 0);
    assert(qihse_pooler_get_mode(pool) == POOL_SESSION);

    assert(qihse_pooler_backend_count(pool) == 0);
    assert(qihse_pooler_add_backend(pool, "10.0.0.1", 5432) == 0);
    assert(qihse_pooler_add_backend(pool, "10.0.0.2", 5432) == 0);
    assert(qihse_pooler_backend_count(pool) == 2);
    assert(qihse_pooler_remove_backend(pool, "10.0.0.1", 5432) == 0);
    assert(qihse_pooler_backend_count(pool) == 1);
    assert(qihse_pooler_remove_backend(pool, "10.0.0.1", 5432) == -1);
    assert(qihse_pooler_active_count(pool) == 0);
    assert(qihse_pooler_wait_count(pool) == 0);

    /* Admin console: parse and execute SHOW VERSION. */
    qihse_admin_cmd_t cmd = QIHSE_ADMIN_UNKNOWN;
    char arg[64];
    assert(qihse_pooler_parse_admin("SHOW VERSION", &cmd, arg, sizeof(arg)) == 0);
    assert(cmd == QIHSE_ADMIN_SHOW_VERSION);
    assert(qihse_pooler_parse_admin("SHOW POOLS", &cmd, arg, sizeof(arg)) == 0);
    assert(cmd == QIHSE_ADMIN_SHOW_POOLS);
    assert(qihse_pooler_parse_admin("PAUSE db1", &cmd, arg, sizeof(arg)) == 0);
    assert(cmd == QIHSE_ADMIN_PAUSE && strcmp(arg, "db1") == 0);
    assert(qihse_pooler_parse_admin("NOT A COMMAND", &cmd, arg, sizeof(arg)) == -1);
    assert(cmd == QIHSE_ADMIN_UNKNOWN);

    char* text = qihse_pooler_admin(pool, "SHOW VERSION");
    assert(text);
    assert(strlen(text) > 0);
    free(text);
    text = qihse_pooler_admin(pool, "SHOW POOLS");
    assert(text);
    free(text);

    /* Databases and users. */
    assert(qihse_pooler_database_count(pool) == 0);
    assert(qihse_pooler_add_database(pool, "app", "10.0.0.9", 5432) == 0);
    assert(qihse_pooler_database_count(pool) == 1);
    const qihse_database_t* db = qihse_pooler_find_database(pool, "app");
    assert(db && strcmp(db->name, "app") == 0);
    assert(qihse_pooler_find_database(pool, "absent") == NULL);
    assert(qihse_pooler_add_user(pool, "alice", "secret") == 0);
    assert(qihse_pooler_user_count(pool) == 1);
    assert(qihse_pooler_find_user(pool, "alice") != NULL);
    assert(qihse_pooler_find_user(pool, "bob") == NULL);

    /* Pause/resume is database-scoped and idempotent per direction. */
    assert(qihse_pooler_pause(pool, "app") == 0);
    assert(qihse_pooler_resume(pool, "app") == 0);
    assert(qihse_pooler_disable_db(pool, "app") == 0);
    assert(qihse_pooler_enable_db(pool, "app") == 0);

    qihse_pooler_destroy(pool);
    printf("PASS pooler: config, backends, modes, admin parse/execute, databases, users\n");
}

int main(void) {
    test_repl_context_and_slots();
    test_repl_ship_wal();
    test_read_replica_pool();
    test_pooler();
    printf("test_repl: all replication/pooler tests passed (backup/restore and "
           "parallel query are not covered here; parallel query is a stub)\n");
    return 0;
}
