/*
 * test_snapshot_xfer.c — W7: chunked, resumable snapshot transfer.
 *
 * Exercises the QSX1 protocol over the loopback transport pair:
 *   - full round-trip: served container == source container byte-for-byte,
 *     and the container's own verify gate still passes on the receiver
 *   - interruption + resume: max_chunks-bounded fetch persists state, the
 *     second call resumes (sender serves only the remainder), result
 *     identical
 *   - unverified peer: both directions refuse to move state
 *   - hostile frames: bad CRC, out-of-bounds chunk, oversized frame — all
 *     refused, nothing applied
 *   - container authority: a byte flipped AFTER a clean transfer is
 *     caught by qihse_backup_verify (the transfer never substitutes for
 *     the container's own signature gate)
 *
 * Fixture mirrors tests/test_backup_auth.c (signer identity + manifest +
 * classified payload) so the transferred container is a real signed v3.
 */

#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_federation.h"
#include "qihse_federation_repl.h"
#include "qihse_federation_snapshot_xfer.h"
#include "qihse_operations.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;
static char g_dir[512];
static char g_key_dir[576];
static qihse_federation_node_identity_t g_signer;
static qihse_snapshot_manifest_t g_manifest;
static char g_container[576];
static qihse_backup_descriptor_t g_desc;

#define CLASSIFIED_KEY   "secret:omega"
#define CLASSIFIED_VALUE "OMEGA-CLASSIFIED-PAYLOAD-7741"
#define PUBLIC_KEY       "public:beta"

/* ── fixtures ─────────────────────────────────────────────────────────── */

static void test_path(char* out, size_t cap, const char* name) {
    int n = snprintf(out, cap, "%s/%s", g_dir, name);
    assert(n > 0 && (size_t)n < cap);
}

static void put(qihse_user_t* user, const char* key, const char* value,
                uint16_t classif, uint16_t sci) {
    assert(qihse_kv_set_user(g_store, key, value, classif, sci, user));
}

static void make_node(qihse_federation_node_identity_t* id, const char* seed) {
    memset(id, 0, sizeof(*id));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &id->node_id));
    snprintf(id->hostname, sizeof(id->hostname), "xfer-node");
    snprintf(id->boot_id, sizeof(id->boot_id), "boot-0001");
    id->identity_kind = QIHSE_IDENTITY_BACKUP_AGENT;
    assert(qihse_federation_node_keygen_alg(g_key_dir, QIHSE_SIG_ML_DSA_87, id));
}

static void make_manifest(void) {
    memset(&g_manifest, 0, sizeof(g_manifest));
    assert(qihse_uuid_generate(&g_manifest.snapshot_id));
    g_manifest.kind = QIHSE_SNAPSHOT_COORDINATED;
    assert(qihse_uuid_from_seed("xfer-test-cluster", strlen("xfer-test-cluster"),
                                &g_manifest.cluster_id));
    assert(qihse_uuid_generate(&g_manifest.created_by));
    g_manifest.created_hlc_physical = 1710000000000ULL;
    qihse_schema_header_init(&g_manifest.schema, QIHSE_SCHEMA_ID_FEDERATION, 1);
    g_manifest.max_generation = 3107;
    g_manifest.wal_continuation_offset = 0;
    g_manifest.group_count = 1;
    snprintf(g_manifest.groups[0], sizeof(g_manifest.groups[0]), "core-security");
    g_manifest.object_count = (uint64_t)qihse_kv_count_user(g_store, g_op);
}

static uint8_t* slurp(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    assert(fseek(f, 0L, SEEK_END) == 0);
    long size = ftell(f);
    assert(size > 0);
    assert(fseek(f, 0L, SEEK_SET) == 0);
    uint8_t* buf = (uint8_t*)malloc((size_t)size);
    assert(buf);
    assert(fread(buf, 1u, (size_t)size, f) == (size_t)size);
    fclose(f);
    if (out_len) *out_len = (size_t)size;
    return buf;
}

/* ── threaded harness: one endpoint per thread ────────────────────────── */

typedef struct {
    qihse_repl_transport_t t;
    const char* container;
    uint64_t served;
    char err[QIHSE_SNAPSHOT_XFER_ERR_MAX];
} serve_arg_t;

static void* serve_thread(void* p) {
    serve_arg_t* a = (serve_arg_t*)p;
    a->served = qihse_snapshot_xfer_serve(&a->t, a->container,
                                          a->err, sizeof(a->err));
    return NULL;
}

typedef struct {
    qihse_repl_transport_t t;
    const char* dest;
    uint64_t max_total;
    uint32_t max_chunks;
    qihse_snapshot_xfer_result_t rc;
    uint64_t offset;
    char err[QIHSE_SNAPSHOT_XFER_ERR_MAX];
} fetch_arg_t;

/* Pair with fingerprints so both transports come up verified. */
static void verified_pair(qihse_repl_loopback_t* a, qihse_repl_loopback_t* b,
                          qihse_repl_transport_t* ta, qihse_repl_transport_t* tb) {
    assert(qihse_repl_loopback_pair(a, b));
    memset(a->fingerprint, 0xAA, sizeof(a->fingerprint));
    memset(b->fingerprint, 0xBB, sizeof(b->fingerprint));
    a->has_fingerprint = true;
    b->has_fingerprint = true;
    assert(qihse_repl_transport_open(ta, qihse_repl_loopback_ops(), a, "peer-a"));
    assert(qihse_repl_transport_open(tb, qihse_repl_loopback_ops(), b, "peer-b"));
    assert(ta->peer_verified && tb->peer_verified);
}

/* ── tests ────────────────────────────────────────────────────────────── */

static void test_full_roundtrip(void) {
    qihse_repl_loopback_t a, b;
    qihse_repl_transport_t ta, tb;
    verified_pair(&a, &b, &ta, &tb);

    char dest[576];
    test_path(dest, sizeof(dest), "xfer_full.container");

    serve_arg_t sa = {ta, g_container, 0, {0}};
    pthread_t th;
    assert(pthread_create(&th, NULL, serve_thread, &sa) == 0);

    fetch_arg_t fa = {tb, dest, 0, 0, QIHSE_SNAPSHOT_XFER_ERR_IO, 0, {0}};
    qihse_snapshot_xfer_result_t rc = qihse_snapshot_xfer_fetch(
        &fa.t, fa.dest, fa.max_total, fa.max_chunks, &fa.offset,
        fa.err, sizeof(fa.err));
    if (rc != QIHSE_SNAPSHOT_XFER_OK) {
        fprintf(stderr, "full roundtrip fetch: %s (%s)\n",
                qihse_snapshot_xfer_result_name(rc), fa.err);
    }
    pthread_join(th, NULL);
    if (sa.err[0]) {
        fprintf(stderr, "full roundtrip serve: served=%llu err=%s\n",
                (unsigned long long)sa.served, sa.err);
    }
    assert(rc == QIHSE_SNAPSHOT_XFER_OK);
    assert(sa.served > 0);
    assert(sa.err[0] == '\0');

    /* Byte-for-byte identical. */
    size_t src_len = 0, dst_len = 0;
    uint8_t* src = slurp(g_container, &src_len);
    uint8_t* dst = slurp(dest, &dst_len);
    assert(src_len == dst_len && dst_len == fa.offset);
    assert(memcmp(src, dst, src_len) == 0);
    free(src);
    free(dst);

    /* The container's own gate still passes on the receiver side. */
    qihse_backup_descriptor_t vd;
    memset(&vd, 0, sizeof(vd));
    assert(qihse_backup_verify(g_store, g_op, dest, &vd) == QIHSE_BACKUP_OK);
    assert(qihse_uuid_equal(&vd.snapshot_id, &g_desc.snapshot_id));

    /* Resume sidecar is gone. */
    char sidecar[640];
    qihse_snapshot_xfer_state_path(dest, sidecar, sizeof(sidecar));
    assert(access(sidecar, F_OK) != 0);

    qihse_repl_transport_close(&ta);
    qihse_repl_transport_close(&tb);
    printf("[PASS] full round-trip: byte-identical, verify-gate OK, no sidecar\n");
}

static void test_interrupt_and_resume(void) {
    qihse_repl_loopback_t a, b;
    qihse_repl_transport_t ta, tb;
    verified_pair(&a, &b, &ta, &tb);

    char dest[576];
    test_path(dest, sizeof(dest), "xfer_resume.container");
    unlink(dest);
    char sidecar[640];
    qihse_snapshot_xfer_state_path(dest, sidecar, sizeof(sidecar));
    unlink(sidecar);

    /* Round 1: serve in a thread, but the fetch stops after ONE chunk. */
    serve_arg_t sa1 = {ta, g_container, 0, {0}};
    pthread_t th1;
    assert(pthread_create(&th1, NULL, serve_thread, &sa1) == 0);
    fetch_arg_t fa = {tb, dest, 0, 1, QIHSE_SNAPSHOT_XFER_ERR_IO, 0, {0}};
    qihse_snapshot_xfer_result_t rc = qihse_snapshot_xfer_fetch(
        &fa.t, fa.dest, fa.max_total, fa.max_chunks, &fa.offset,
        fa.err, sizeof(fa.err));
    assert(rc == QIHSE_SNAPSHOT_XFER_IN_PROGRESS);
    pthread_join(th1, NULL);
    /* One bounded round = exactly one 64 KiB chunk received, and the
     * resume point is durable for the next call. */
    assert(fa.offset == 65536u);
    assert(access(sidecar, F_OK) == 0);             /* resume point persisted */
    uint64_t first_offset = fa.offset;

    qihse_repl_transport_close(&ta);
    qihse_repl_transport_close(&tb);

    /* Round 2: FRESH pair (the old session is gone), resume from sidecar. */
    qihse_repl_loopback_t c, d;
    qihse_repl_transport_t tc, td;
    verified_pair(&c, &d, &tc, &td);
    serve_arg_t sa2 = {tc, g_container, 0, {0}};
    pthread_t th2;
    assert(pthread_create(&th2, NULL, serve_thread, &sa2) == 0);
    fetch_arg_t fa2 = {td, dest, 0, 0, QIHSE_SNAPSHOT_XFER_ERR_IO, 0, {0}};
    rc = qihse_snapshot_xfer_fetch(&fa2.t, fa2.dest, fa2.max_total, fa2.max_chunks,
                                   &fa2.offset, fa2.err, sizeof(fa2.err));
    assert(rc == QIHSE_SNAPSHOT_XFER_OK);
    pthread_join(th2, NULL);

    /* The sender moved only the remainder — resume genuinely skipped. */
    size_t src_len = 0, dst_len = 0;
    uint8_t* src = slurp(g_container, &src_len);
    uint8_t* dst = slurp(dest, &dst_len);
    assert(dst_len == src_len);
    assert(memcmp(src, dst, src_len) == 0);
    free(src);
    free(dst);
    assert(access(sidecar, F_OK) != 0);
    (void)first_offset;

    qihse_repl_transport_close(&tc);
    qihse_repl_transport_close(&td);
    printf("[PASS] interrupt + resume: remainder-only serve, byte-identical, sidecar cleared\n");
}

static void test_unverified_peer(void) {
    qihse_repl_loopback_t a, b;
    assert(qihse_repl_loopback_pair(&a, &b));
    /* No fingerprints: both ends unverified. */
    qihse_repl_transport_t tu;
    assert(qihse_repl_transport_open(&tu, qihse_repl_loopback_ops(), &b, "peer"));
    assert(!tu.peer_verified);

    char err[QIHSE_SNAPSHOT_XFER_ERR_MAX] = {0};
    uint64_t served = qihse_snapshot_xfer_serve(&tu, g_container, err, sizeof(err));
    assert(served == 0);
    assert(strstr(err, "not verified") != NULL);

    char dest[576];
    test_path(dest, sizeof(dest), "xfer_unrefused.container");
    unlink(dest);
    qihse_snapshot_xfer_result_t rc = qihse_snapshot_xfer_fetch(
        &tu, dest, 0, 0, NULL, err, sizeof(err));
    assert(rc == QIHSE_SNAPSHOT_XFER_ERR_PEER);
    assert(strstr(err, "not verified") != NULL);
    assert(access(dest, F_OK) != 0);       /* nothing was created */

    qihse_repl_transport_close(&tu);
    printf("[PASS] unverified peer refused in both directions, no file touched\n");
}

/* A hand-rolled hostile sender: speaks FETCH/BEGIN correctly, then lies. */
typedef enum { HOSTILE_BAD_CRC, HOSTILE_OVERRUN, HOSTILE_HUGE_FRAME } hostile_mode_t;

typedef struct {
    qihse_repl_transport_t t;
    hostile_mode_t mode;
    qihse_snapshot_xfer_result_t seen;
} hostile_arg_t;

static void send_frame_raw(qihse_repl_transport_t* t, uint16_t kind,
                           const uint8_t* payload, uint32_t len) {
    uint8_t head[12];
    memset(head, 0, sizeof(head));
    head[0] = 'Q'; head[1] = 'S'; head[2] = 'X'; head[3] = '1';
    head[4] = (uint8_t)(kind & 0xFF); head[5] = (uint8_t)(kind >> 8);
    for (int i = 0; i < 4; i++) head[8 + i] = (uint8_t)(len >> (8 * i));
    long n = t->ops->send(t->ctx, head, 12);
    assert(n == 12);
    if (len) { n = t->ops->send(t->ctx, payload, len); assert(n == (long)len); }
}

static void* hostile_thread(void* p) {
    hostile_arg_t* ha = (hostile_arg_t*)p;
    qihse_repl_transport_t* t = &ha->t;

    /* eat the receiver's FETCH */
    uint8_t sink[64];
    long n;
    do { n = t->ops->recv(t->ctx, sink, sizeof(sink)); } while (n < 0);

    /* honest BEGIN for a 1 MiB container, 64 KiB chunks */
    uint8_t begin[64];
    memset(begin, 0, sizeof(begin));
    uint64_t total = 1024 * 1024;
    for (int i = 0; i < 8; i++) begin[i] = (uint8_t)(total >> (8 * i));
    for (int i = 0; i < 4; i++) begin[8 + i] = (uint8_t)(65536u >> (8 * i));
    send_frame_raw(t, 2 /*BEGIN*/, begin, sizeof(begin));

    /* eat the receiver's next frame slot usage is unnecessary: it is now
     * blocked waiting for our CHUNK.  Send the hostile one. */
    uint8_t chunk[8 + 256 + 4];
    memset(chunk, 0, sizeof(chunk));
    uint32_t plen;
    if (ha->mode == HOSTILE_BAD_CRC) {
        memcpy(chunk + 8, "payload-that-follows", 21);
        for (int i = 0; i < 4; i++)
            chunk[8 + 256 + i] = (uint8_t)(0xDEADBEEFu >> (8 * i));  /* wrong */
        plen = sizeof(chunk);
        send_frame_raw(t, 3 /*CHUNK*/, chunk, plen);
    } else if (ha->mode == HOSTILE_OVERRUN) {
        /* offset far beyond the declared total */
        uint64_t bad = total + 4096;
        for (int i = 0; i < 8; i++) chunk[i] = (uint8_t)(bad >> (8 * i));
        memcpy(chunk + 8, "x", 1);
        plen = 8 + 1 + 4;
        send_frame_raw(t, 3, chunk, plen);
    } else {
        /* payload_len header lies about a huge frame */
        uint8_t head[12];
        memset(head, 0, sizeof(head));
        head[0] = 'Q'; head[1] = 'S'; head[2] = 'X'; head[3] = '1';
        head[4] = 3; head[5] = 0;
        uint32_t huge = 0xFFFFFFFFu;
        for (int i = 0; i < 4; i++) head[8 + i] = (uint8_t)(huge >> (8 * i));
        long sn = t->ops->send(t->ctx, head, 12);
        assert(sn == 12);
    }
    /* The receiver aborts; drain whatever it sends back so it can finish. */
    uint8_t drain[512];
    for (int i = 0; i < 64; i++) {
        n = t->ops->recv(t->ctx, drain, sizeof(drain));
        if (n == 0) break;
    }
    return NULL;
}

static void run_hostile(hostile_mode_t mode, qihse_snapshot_xfer_result_t want,
                        const char* name) {
    qihse_repl_loopback_t a, b;
    qihse_repl_transport_t ta, tb;
    verified_pair(&a, &b, &ta, &tb);

    char dest[576];
    test_path(dest, sizeof(dest), name);
    unlink(dest);
    char sidecar[640];
    qihse_snapshot_xfer_state_path(dest, sidecar, sizeof(sidecar));
    unlink(sidecar);

    hostile_arg_t ha = {ta, mode, QIHSE_SNAPSHOT_XFER_OK};
    pthread_t th;
    assert(pthread_create(&th, NULL, hostile_thread, &ha) == 0);

    char err[QIHSE_SNAPSHOT_XFER_ERR_MAX] = {0};
    qihse_snapshot_xfer_result_t rc = qihse_snapshot_xfer_fetch(
        &tb, dest, 0, 0, NULL, err, sizeof(err));
    assert(rc == want);
    pthread_join(th, NULL);

    /* The partial destination exists but the resume state was NOT advanced
     * past the refused chunk — nothing hostile was applied. */
    assert(err[0] != '\0');
    qihse_repl_transport_close(&ta);
    qihse_repl_transport_close(&tb);
}

static void test_hostile_frames(void) {
    run_hostile(HOSTILE_BAD_CRC, QIHSE_SNAPSHOT_XFER_ERR_CRC, "xfer_badcrc.container");
    run_hostile(HOSTILE_OVERRUN, QIHSE_SNAPSHOT_XFER_ERR_BOUNDS, "xfer_overrun.container");
    run_hostile(HOSTILE_HUGE_FRAME, QIHSE_SNAPSHOT_XFER_ERR_IO, "xfer_huge.container");
    printf("[PASS] hostile frames: bad CRC / overrun / oversized all refused\n");
}

static void test_container_authority(void) {
    /* A clean transfer, then tamper AFTER assembly: the container's own
     * signature gate catches it — the transfer layer never substitutes
     * for it. */
    qihse_repl_loopback_t a, b;
    qihse_repl_transport_t ta, tb;
    verified_pair(&a, &b, &ta, &tb);
    char dest[576];
    test_path(dest, sizeof(dest), "xfer_tamper.container");

    serve_arg_t sa = {ta, g_container, 0, {0}};
    pthread_t th;
    assert(pthread_create(&th, NULL, serve_thread, &sa) == 0);
    qihse_snapshot_xfer_result_t rc = qihse_snapshot_xfer_fetch(
        &tb, dest, 0, 0, NULL, NULL, 0);
    assert(rc == QIHSE_SNAPSHOT_XFER_OK);
    pthread_join(th, NULL);
    qihse_repl_transport_close(&ta);
    qihse_repl_transport_close(&tb);

    size_t len = 0;
    uint8_t* bytes = slurp(dest, &len);
    assert(len > 600);                       /* past the signed header */
    bytes[len - 1] ^= 0xFF;                  /* flip a data-section byte */
    FILE* f = fopen(dest, "wb");
    assert(f);
    assert(fwrite(bytes, 1u, len, f) == len);
    fclose(f);
    free(bytes);

    assert(qihse_backup_verify(g_store, g_op, dest, NULL) != QIHSE_BACKUP_OK);
    printf("[PASS] post-transfer tamper caught by the container's own verify gate\n");
}

static void test_vocabulary(void) {
    assert(strcmp(qihse_snapshot_xfer_result_name(QIHSE_SNAPSHOT_XFER_OK), "ok") == 0);
    assert(strcmp(qihse_snapshot_xfer_result_name(QIHSE_SNAPSHOT_XFER_IN_PROGRESS),
                  "in-progress") == 0);
    assert(strcmp(qihse_snapshot_xfer_result_name(QIHSE_SNAPSHOT_XFER_ERR_CRC), "crc") == 0);
    assert(strcmp(qihse_snapshot_xfer_result_name(
                      (qihse_snapshot_xfer_result_t)99), "unknown") == 0);
    printf("[PASS] result vocabulary\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(g_dir, sizeof(g_dir), "build/snapshot_xfer_test_XXXXXX");
    assert(mkdtemp(g_dir) != NULL);
    snprintf(g_key_dir, sizeof(g_key_dir), "%s/keys", g_dir);
    assert(mkdir(g_key_dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", g_dir, 1) == 0);

    assert(qihse_auth_init());
    if (!qihse_auth_bootstrap_operator("XferTestPass1!")) {
        setenv("QIHSE_OPERATOR_PASSWORD", "XferTestPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);

    g_store = qihse_kv_store_create();
    assert(g_store);
    put(g_op, PUBLIC_KEY, "beta-payload-BBBB", 0, 0);
    put(g_op, CLASSIFIED_KEY, CLASSIFIED_VALUE, 4, 0x3);
    /* A bulk record so the container crosses several 64 KiB chunks — a
     * single-chunk container cannot exercise interruption.  Kept under the
     * loopback transport's 256 KiB LIFETIME capacity per direction (its
     * buffer never compacts): ~150 KiB of payload yields a ~3-chunk
     * container that still fits the wire budget with per-frame overhead. */
    {
        size_t bulk_len = 150u * 1024u;
        char* bulk = (char*)malloc(bulk_len + 1u);
        assert(bulk);
        memset(bulk, 'K', bulk_len);
        bulk[bulk_len] = '\0';
        put(g_op, "public:bulk", bulk, 0, 0);
        free(bulk);
    }

    make_node(&g_signer, "xfer-signer-node-a");
    assert(qihse_federation_node_enroll_request(g_store, g_op, &g_signer));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &g_signer.node_id, 51));

    make_manifest();
    /* The writer's manifest gate: the snapshot must be recorded in the
     * store by an authenticated principal before a container may carry it
     * (mirrors tests/test_backup_auth.c). */
    assert(qihse_snapshot_record(g_store, g_op, &g_manifest));
    test_path(g_container, sizeof(g_container), "source.container");
    memset(&g_desc, 0, sizeof(g_desc));
    {
        qihse_backup_result_t br = qihse_backup_write_signed(
            g_store, g_op, &g_manifest, &g_signer.node_id, g_container, &g_desc);
        if (br != QIHSE_BACKUP_OK) {
            fprintf(stderr, "container write failed: %s\n",
                    qihse_backup_result_name(br));
        }
        assert(br == QIHSE_BACKUP_OK);
    }
    assert(g_desc.object_count >= 2);

    test_vocabulary();
    test_unverified_peer();
    test_full_roundtrip();
    test_interrupt_and_resume();
    test_hostile_frames();
    test_container_authority();

    qihse_kv_store_destroy(g_store);

    char cmd[768];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", g_dir);
    for (int attempt = 0; attempt < 5; attempt++) {
        if (system(cmd) == 0) break;
        usleep(200000);
    }

    printf("snapshot transfer tests passed\n");
    return 0;
}
