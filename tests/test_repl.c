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
 *   8. Replica-side apply: a record produced by qihse_wal_append() and read
 *      back from the segment must reach the store bound with
 *      qihse_repl_set_store(); a retransmitted record must not be applied
 *      twice; a record below the applied watermark must be a no-op; a
 *      truncated, checksum-broken, length-inconsistent or unknown-op record
 *      must be refused with nothing applied and no LSN advanced; and a context
 *      with no bound store must refuse rather than acknowledge
 *
 * NOT covered here (see docs/architecture/replication_backup.md):
 *   - src/tractable/qihse_parallel_query.c — a stub: the scan workers count
 *     nothing ("TODO: actual KV store iteration with partitioning") and the
 *     aggregate/join paths are TODOs.
 *   - src/tractable/qihse_backup.c — the authenticated backup/restore API has
 *     no test in this repository; the only backup test is
 *     tests/test_federation_backup.c, which covers the federation writer/reader.
 *   - Transaction boundaries: the applier applies each record as it arrives
 *     (txn_id is carried in the record but the context keeps no BEGIN/COMMIT
 *     state), so a record stream must be committed by the caller.
 */
#include "qihse_repl.h"
#include "qihse_read_replica.h"
#include "qihse_pooler.h"
#include "qihse_kv_store.h"
#include "qihse_wal.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

/* ── Apply helpers ──────────────────────────────────────────────────────── */

#define APPLY_DIR "tests/.tmp-repl-apply"
#define APPLY_KEY "repl:apply"

static uint8_t* read_whole_file(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t* buf = (uint8_t*)malloc((size_t)size);
    if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)size;
    return buf;
}

/* Produce n records with the public WAL API in a scratch directory and return
 * the segment bytes, which is exactly what qihse_repl_ship_wal() puts in the
 * frame payload.  The segment is unlinked so the next call starts at LSN 1
 * again; the caller slices it with record_slice(). */
static uint8_t* wal_segment(const char* const keys[], const char* const values[],
                            const qihse_wal_op_t ops[], size_t n, size_t* out_len) {
    if (mkdir(APPLY_DIR, 0700) != 0 && errno != EEXIST) return NULL;
    qihse_wal_t* wal = qihse_wal_create(APPLY_DIR, 1u << 20, QIHSE_WAL_DURABILITY_FDATASYNC);
    if (!wal) return NULL;
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++) {
        ok = qihse_wal_append(wal, 7u, 0u, ops[i],
                              keys[i], (uint32_t)strlen(keys[i]),
                              values[i], values[i] ? (uint32_t)strlen(values[i]) : 0u)
             != QIHSE_WAL_INVALID_LSN;
    }
    if (ok) ok = (qihse_wal_flush(wal) == 0);
    qihse_wal_destroy(wal);
    if (!ok) return NULL;

    char path[512];
    snprintf(path, sizeof(path), "%s/wal_%020lu.log", APPLY_DIR, 0ul);
    uint8_t* buf = read_whole_file(path, out_len);
    unlink(path);
    return buf;
}

/* One record inside a segment: [30-byte header][key][value].  Returns its
 * length in bytes and its LSN. */
static size_t record_slice(const uint8_t* seg, size_t off, size_t seg_len,
                           const uint8_t** out, uint64_t* out_lsn) {
    assert(seg_len - off >= (size_t)QIHSE_WAL_RECORD_HEADER_SIZE);
    uint32_t klen = 0, vlen = 0;
    memcpy(&klen, seg + off + 18, 4);
    memcpy(&vlen, seg + off + 22, 4);
    size_t n = (size_t)QIHSE_WAL_RECORD_HEADER_SIZE + (size_t)klen + (size_t)vlen;
    assert(off + n <= seg_len);
    if (out_lsn) memcpy(out_lsn, seg + off, 8);
    *out = seg + off;
    return n;
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

    /* Applying is the replica side of the same frame; the full contract is
     * exercised in test_repl_apply_wal().  Argument errors are refusals, never
     * silent no-ops, and an apply must not disturb the shipping position. */
    assert(qihse_repl_apply_wal(ctx, (const uint8_t*)wal, wal_len, 5000) == -1);
    assert(qihse_repl_apply_wal(ctx, NULL, 0, 1) == -1);
    assert(qihse_repl_apply_wal(NULL, (const uint8_t*)wal, wal_len, 5000) == -1);
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(last == 4242 && flush == 0);

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

/* ── 8. Replica-side apply ──────────────────────────────────────────────── */

static void test_repl_apply_wal(void) {
    /* Five real records in one segment: UPDATE, UPDATE, DELETE, a well-formed
     * record whose op the applier cannot map to a mutation, and a DELETE of a
     * key that is not there. */
    const char* keys[5] = {APPLY_KEY, APPLY_KEY, APPLY_KEY, APPLY_KEY, "repl:absent"};
    const char* values[5] = {"after", "third", NULL, "x", NULL};
    const qihse_wal_op_t ops[5] = {QIHSE_WAL_OP_UPDATE, QIHSE_WAL_OP_UPDATE,
                                   QIHSE_WAL_OP_DELETE, (qihse_wal_op_t)99,
                                   QIHSE_WAL_OP_DELETE};
    size_t seg_len = 0;
    uint8_t* seg = wal_segment(keys, values, ops, 5, &seg_len);
    assert(seg);

    const uint8_t* rec[5];
    size_t rec_len[5] = {0, 0, 0, 0, 0};
    uint64_t lsn[5] = {0, 0, 0, 0, 0};
    size_t off = 0;
    for (int i = 0; i < 5; i++) {
        rec_len[i] = record_slice(seg, off, seg_len, &rec[i], &lsn[i]);
        off += rec_len[i];
    }
    assert(off == seg_len);
    assert(lsn[0] < lsn[1] && lsn[1] < lsn[2] && lsn[2] < lsn[3] && lsn[3] < lsn[4]);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    assert(qihse_kv_set(store, APPLY_KEY, "before", 0, 0));

    qihse_repl_context_t* ctx = qihse_repl_create(REPL_ROLE_REPLICA);
    assert(ctx);
    assert(qihse_repl_get_store(ctx) == NULL);

    uint64_t last = 0, flush = 0;
    repl_state_t state = REPL_STATE_ERROR;
    char* got = NULL;

    /* ── 8a. a context with no bound store accepts nothing ─────────────── */
    assert(qihse_repl_apply_wal(ctx, rec[0], rec_len[0], lsn[0]) == -1);
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(flush == 0 && last == 0);
    got = qihse_kv_get(store, APPLY_KEY);
    assert(got && strcmp(got, "before") == 0);
    free(got);
    got = NULL;
    assert(qihse_repl_set_store(NULL, store) == -1);
    assert(qihse_repl_get_store(NULL) == NULL);

    /* ── 8b. an accepted record reaches the bound store ────────────────── */
    assert(qihse_repl_set_store(ctx, store) == 0);
    assert(qihse_repl_get_store(ctx) == store);
    assert(qihse_repl_apply_wal(ctx, rec[0], rec_len[0], lsn[0]) == 0);
    got = qihse_kv_get(store, APPLY_KEY);
    assert(got && strcmp(got, "after") == 0);
    free(got);
    got = NULL;
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(flush == lsn[0]);
    assert(state == REPL_STATE_DISCONNECTED);   /* apply needs no live stream */

    /* ── 8c. a retransmitted record is not applied twice ───────────────── */
    /* Move the key away from what the record carries: if the duplicate were
     * applied again, the value would come back. */
    assert(qihse_kv_set(store, APPLY_KEY, "moved-by-test", 0, 0));
    assert(qihse_repl_apply_wal(ctx, rec[0], rec_len[0], lsn[0]) == 0);
    got = qihse_kv_get(store, APPLY_KEY);
    assert(got && strcmp(got, "moved-by-test") == 0);
    free(got);
    got = NULL;

    /* ── 8d. malformed records are refused; nothing applied, no LSN moved ─ */
    uint8_t* bad = (uint8_t*)malloc(rec_len[1]);
    assert(bad);
    /* truncated: the declared lengths no longer describe the buffer */
    assert(qihse_repl_apply_wal(ctx, rec[1], rec_len[1] - 1, lsn[1]) == -1);
    /* a flipped value byte: the CRC32 no longer matches */
    memcpy(bad, rec[1], rec_len[1]);
    bad[rec_len[1] - 1] ^= 0x01u;
    assert(qihse_repl_apply_wal(ctx, bad, rec_len[1], lsn[1]) == -1);
    /* a flipped checksum field */
    memcpy(bad, rec[1], rec_len[1]);
    bad[26] ^= 0x01u;
    assert(qihse_repl_apply_wal(ctx, bad, rec_len[1], lsn[1]) == -1);
    /* a declared key length that disagrees with the encoded length */
    memcpy(bad, rec[1], rec_len[1]);
    uint32_t klen = 0;
    memcpy(&klen, rec[1] + 18, 4);
    klen += 1u;
    memcpy(bad + 18, &klen, 4);
    assert(qihse_repl_apply_wal(ctx, bad, rec_len[1], lsn[1]) == -1);
    free(bad);
    /* a well-formed record whose op the applier cannot map to a mutation */
    assert(qihse_repl_apply_wal(ctx, rec[3], rec_len[3], lsn[3]) == -1);
    /* a well-formed record whose own LSN is not the LSN the caller declared:
     * the position must never be advanced by a record that describes another
     * position */
    assert(qihse_repl_apply_wal(ctx, rec[1], rec_len[1], lsn[2]) == -1);
    /* a mutation the store refuses.  A DELETE of a key that is not there is
     * refused rather than reported as applied: the applier runs without a
     * principal, so it cannot tell "absent" from "present but above the
     * caller's clearance", and the store's false must not become success. */
    assert(!qihse_kv_exists(store, "repl:absent"));
    assert(qihse_repl_apply_wal(ctx, rec[4], rec_len[4], lsn[4]) == -1);

    /* none of the refusals moved the position or touched the store */
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(flush == lsn[0]);
    got = qihse_kv_get(store, APPLY_KEY);
    assert(got && strcmp(got, "moved-by-test") == 0);
    free(got);
    got = NULL;

    /* a refusal does not consume the record: the same LSN still applies */
    assert(qihse_repl_apply_wal(ctx, rec[1], rec_len[1], lsn[1]) == 0);
    got = qihse_kv_get(store, APPLY_KEY);
    assert(got && strcmp(got, "third") == 0);
    free(got);
    got = NULL;

    /* ── 8e. ordering: a record below the watermark is a no-op ─────────── */
    assert(qihse_repl_apply_wal(ctx, rec[2], rec_len[2], lsn[2]) == 0);
    assert(!qihse_kv_exists(store, APPLY_KEY));
    assert(qihse_repl_apply_wal(ctx, rec[1], rec_len[1], lsn[1]) == 0);  /* older */
    assert(!qihse_kv_exists(store, APPLY_KEY));  /* the delete was not undone */
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(flush == lsn[2]);

    /* ── 8f. argument errors, and unbinding refuses again ──────────────── */
    assert(qihse_repl_apply_wal(ctx, NULL, rec_len[0], lsn[0]) == -1);
    assert(qihse_repl_apply_wal(ctx, rec[0], 0, lsn[0]) == -1);
    assert(qihse_repl_apply_wal(ctx, rec[0], rec_len[0], QIHSE_WAL_INVALID_LSN) == -1);
    assert(qihse_repl_apply_wal(NULL, rec[0], rec_len[0], lsn[0]) == -1);
    /* Unbinding refuses even a duplicate: the store check comes first, so a
     * caller is never told "applied" while nothing can be applied. */
    assert(qihse_repl_set_store(ctx, NULL) == 0);
    assert(qihse_repl_get_store(ctx) == NULL);
    assert(qihse_repl_apply_wal(ctx, rec[0], rec_len[0], lsn[0]) == -1);
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0);
    assert(flush == lsn[2]);

    /* ── 8g. the replay staging area does not outlive the context ──────── */
    assert(ctx->stage_dir != NULL);   /* created by the first apply */
    char stage_dir[512];
    snprintf(stage_dir, sizeof(stage_dir), "%s", ctx->stage_dir);
    qihse_repl_destroy(ctx);
    assert(access(stage_dir, F_OK) != 0);   /* removed with the context */

    qihse_kv_store_destroy(store);
    free(seg);
    rmdir(APPLY_DIR);
    printf("PASS replication apply: a bound store receives the record, a "
           "retransmission is a no-op, malformed records are refused whole\n");
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
    test_repl_apply_wal();
    test_read_replica_pool();
    test_pooler();
    printf("test_repl: all replication/pooler tests passed (backup/restore and "
           "parallel query are not covered here; parallel query is a stub)\n");
    return 0;
}
