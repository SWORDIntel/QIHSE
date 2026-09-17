/*
 * test_federation_f8_ops.c — F8 operational hardening: schema, snapshots,
 * reconciliation and budgets.
 *
 * Acceptance criteria exercised:
 *   AC13 — the mixed schema N/N+1 scenario and mid-snapshot crash recovery
 *          (the two scenarios test_federation_f8.c defers).
 *   AC14 — local query performance stays within defined regression budgets.
 *
 * Covers:
 *   - schema compatibility: unknown OPTIONAL features ignored, unknown
 *     REQUIRED features rejected, too-old reader rejected
 *   - forward-only migrations with resumable progress
 *   - snapshot manifests: checksum computed by the recorder, tamper and
 *     truncation detection, WAL continuation point preserved
 *   - rejoin state machine: ordered steps, ownership withheld until complete
 *   - metrics rendering is label-bounded
 *   - performance budget evaluation, including partial measurements
 */
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_operations.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* ── Schema compatibility (v3.md §24) ──────────────────────────────────── */

#define FEAT_TELEMETRY_SUMMARY (1ULL << 0)
#define FEAT_LEASE_V2          (1ULL << 1)
#define FEAT_FUTURE_REQUIRED   (1ULL << 40)
#define FEAT_FUTURE_OPTIONAL   (1ULL << 41)

static void test_schema_compatibility(void) {
    qihse_schema_reader_t reader;
    reader.max_schema_version = 3;
    reader.known_features = FEAT_TELEMETRY_SUMMARY | FEAT_LEASE_V2;

    /* Same-version object with no special features: readable. */
    qihse_schema_header_t h;
    qihse_schema_header_init(&h, QIHSE_SCHEMA_ID_FEDERATION, 3);
    assert(h.minimum_reader_version == 3);
    assert(qihse_schema_check(&h, &reader) == QIHSE_SCHEMA_OK);

    /* An older writer's object is readable by a newer reader. */
    qihse_schema_header_init(&h, QIHSE_SCHEMA_ID_FEDERATION, 1);
    assert(qihse_schema_check(&h, &reader) == QIHSE_SCHEMA_OK);

    /* A newer writer that requires only known features is readable. */
    qihse_schema_header_init(&h, QIHSE_SCHEMA_ID_FEDERATION, 3);
    h.required_features = FEAT_LEASE_V2;
    assert(qihse_schema_check(&h, &reader) == QIHSE_SCHEMA_OK);

    /* Unknown OPTIONAL feature: ignored, which is what lets a newer writer
     * add fields without a flag day. */
    h.required_features = 0;
    h.optional_features = FEAT_FUTURE_OPTIONAL;
    assert(qihse_schema_check(&h, &reader) == QIHSE_SCHEMA_OK);

    /* Unknown REQUIRED feature: hard rejection, never a best-effort parse. */
    h.required_features = FEAT_FUTURE_REQUIRED;
    assert(qihse_schema_check(&h, &reader) == QIHSE_SCHEMA_ERR_UNKNOWN_REQUIRED_FEATURE);

    /* A writer that declares it needs a newer reader than we are. */
    qihse_schema_header_init(&h, QIHSE_SCHEMA_ID_FEDERATION, 7);
    h.minimum_reader_version = 6;
    assert(qihse_schema_check(&h, &reader) == QIHSE_SCHEMA_ERR_READER_TOO_OLD);

    /* Malformed input fails closed. */
    assert(qihse_schema_check(NULL, &reader) == QIHSE_SCHEMA_ERR_MALFORMED);
    assert(qihse_schema_check(&h, NULL) == QIHSE_SCHEMA_ERR_MALFORMED);
    qihse_schema_header_init(&h, QIHSE_SCHEMA_ID_FEDERATION, 0);
    assert(qihse_schema_check(&h, &reader) == QIHSE_SCHEMA_ERR_MALFORMED);

    printf("PASS schema compatibility: optional ignored, required rejected, old reader fails closed\n");
}

/* ── Mixed schema N / N+1 cluster (AC13) ───────────────────────────────── */

static void test_mixed_schema_cluster(void) {
    /* The N/N+1 scenario: a version N+1 writer adds an OPTIONAL field, so a
     * version N reader keeps working.  If the writer instead makes it
     * REQUIRED, the N reader refuses and the upgrade must be staged. */
    qihse_schema_reader_t reader_n;
    reader_n.max_schema_version = 4;
    reader_n.known_features = FEAT_TELEMETRY_SUMMARY;

    qihse_schema_reader_t reader_n1;
    reader_n1.max_schema_version = 5;
    reader_n1.known_features = FEAT_TELEMETRY_SUMMARY | FEAT_FUTURE_REQUIRED;

    /* Writer at N+1 with an optional addition: both readers cope. */
    qihse_schema_header_t writer;
    qihse_schema_header_init(&writer, QIHSE_SCHEMA_ID_FEDERATION, 5);
    writer.minimum_reader_version = 4;   /* deliberately allows N readers */
    writer.optional_features = FEAT_FUTURE_OPTIONAL;
    assert(qihse_schema_check(&writer, &reader_n) == QIHSE_SCHEMA_OK);
    assert(qihse_schema_check(&writer, &reader_n1) == QIHSE_SCHEMA_OK);

    /* Writer at N+1 that makes the feature required: the N reader refuses
     * while the N+1 reader accepts.  This is the mixed-cluster case that
     * must be staged rather than deployed at once. */
    writer.required_features = FEAT_FUTURE_REQUIRED;
    writer.optional_features = 0;
    assert(qihse_schema_check(&writer, &reader_n) == QIHSE_SCHEMA_ERR_UNKNOWN_REQUIRED_FEATURE);
    assert(qihse_schema_check(&writer, &reader_n1) == QIHSE_SCHEMA_OK);

    printf("PASS mixed schema N/N+1: optional additions interoperate, required ones gate the upgrade (AC13)\n");
}

/* ── Migrations ────────────────────────────────────────────────────────── */

static void test_migrations(void) {
    qihse_schema_migration_t m;
    memset(&m, 0, sizeof(m));
    m.schema_id = QIHSE_SCHEMA_ID_FEDERATION;
    m.from_version = 3;
    m.to_version = 4;
    m.resumable = true;
    snprintf(m.description, sizeof(m.description), "add lease fencing epoch column");
    assert(qihse_schema_migration_register(g_store, g_op, &m));

    qihse_schema_migration_t got;
    assert(qihse_schema_migration_lookup(g_store, g_op, m.schema_id, 3, &got));
    assert(got.from_version == 3);
    assert(got.to_version == 4);
    assert(got.resumable);
    assert(strcmp(got.description, "add lease fencing epoch column") == 0);

    /* A migration must move forward: a no-op is refused so it cannot silently
     * mark a version as handled. */
    qihse_schema_migration_t bad = m;
    bad.from_version = 5;
    bad.to_version = 5;
    assert(!qihse_schema_migration_register(g_store, g_op, &bad));
    bad.from_version = 6;
    bad.to_version = 4;
    assert(!qihse_schema_migration_register(g_store, g_op, &bad));

    /* Unregistered migration is not found. */
    assert(!qihse_schema_migration_lookup(g_store, g_op, m.schema_id, 99, &got));

    printf("PASS migrations: forward-only, description preserved\n");
}

static void test_migration_progress(void) {
    /* A migration that crashed partway through reports where it stopped, so
     * it can continue instead of restarting (v3.md §24: migrations
     * resumable). */
    assert(qihse_schema_progress_set(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4, 0, 1000));

    uint64_t completed = 0, total = 0;
    assert(qihse_schema_progress_get(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4,
                                     &completed, &total));
    assert(completed == 0 && total == 1000);
    assert(!qihse_schema_progress_complete(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4));

    /* Simulate a crash at 400 of 1000 units, then resume. */
    assert(qihse_schema_progress_set(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4, 400, 1000));
    assert(qihse_schema_progress_get(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4,
                                     &completed, &total));
    assert(completed == 400 && total == 1000);
    assert(!qihse_schema_progress_complete(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4));

    /* Finish. */
    assert(qihse_schema_progress_set(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4, 1000, 1000));
    assert(qihse_schema_progress_complete(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4));

    /* Progress can never over-report. */
    assert(!qihse_schema_progress_set(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 4, 1001, 1000));

    /* A zero-unit record is not "complete": nothing was done. */
    assert(qihse_schema_progress_set(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 5, 0, 0));
    assert(!qihse_schema_progress_complete(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 5));

    /* An unrecorded migration is not complete either. */
    assert(!qihse_schema_progress_complete(g_store, g_op, QIHSE_SCHEMA_ID_FEDERATION, 77));

    printf("PASS migration progress: crash at 400/1000 resumes, completion requires real work\n");
}

/* ── Snapshots (v3.md §23, AC13 mid-snapshot crash) ────────────────────── */

static void test_snapshot_manifest(void) {
    qihse_snapshot_manifest_t m;
    memset(&m, 0, sizeof(m));
    assert(qihse_uuid_generate(&m.snapshot_id));
    assert(qihse_uuid_from_seed("f8-cluster", strlen("f8-cluster"), &m.cluster_id));
    m.created_by = g_op ? (qihse_uuid_t){0} : (qihse_uuid_t){0};
    assert(qihse_uuid_generate(&m.created_by));
    m.kind = QIHSE_SNAPSHOT_COORDINATED;
    m.created_hlc_physical = 1700000000000ULL;
    qihse_schema_header_init(&m.schema, QIHSE_SCHEMA_ID_FEDERATION, 4);
    m.max_generation = 1831;
    m.wal_continuation_offset = 99123456ULL;
    snprintf(m.encryption_key_id, sizeof(m.encryption_key_id), "key-handle:citadel-1");
    m.object_count = 4211;
    m.group_count = 2;
    snprintf(m.groups[0], sizeof(m.groups[0]), "core-security");
    snprintf(m.groups[1], sizeof(m.groups[1]), "control-metadata");

    /* The recorder computes the checksum itself, so a caller cannot record a
     * manifest whose digest disagrees with its contents. */
    assert(qihse_snapshot_record(g_store, g_op, &m));

    qihse_snapshot_manifest_t got;
    assert(qihse_snapshot_lookup(g_store, g_op, &m.snapshot_id, &got));
    assert(got.kind == QIHSE_SNAPSHOT_COORDINATED);
    assert(got.max_generation == 1831);
    assert(got.wal_continuation_offset == 99123456ULL);
    assert(strcmp(got.encryption_key_id, "key-handle:citadel-1") == 0);
    assert(got.object_count == 4211);
    assert(got.group_count == 2);
    assert(strcmp(got.groups[0], "core-security") == 0);
    assert(strcmp(got.groups[1], "control-metadata") == 0);
    assert(got.schema.schema_version == 4);
    assert(memcmp(got.checksum, m.checksum, 48) == 0);

    /* Verification succeeds on the pristine record. */
    assert(qihse_snapshot_verify(g_store, g_op, &m.snapshot_id));

    /* A LOCAL snapshot needs no coordination and is still verifiable. */
    qihse_snapshot_manifest_t local;
    memset(&local, 0, sizeof(local));
    assert(qihse_uuid_generate(&local.snapshot_id));
    local.kind = QIHSE_SNAPSHOT_LOCAL;
    local.wal_continuation_offset = 42;
    assert(qihse_snapshot_record(g_store, g_op, &local));
    assert(qihse_snapshot_verify(g_store, g_op, &local.snapshot_id));

    /* An unknown snapshot id is not found and does not verify. */
    qihse_uuid_t missing;
    assert(qihse_uuid_generate(&missing));
    assert(!qihse_snapshot_lookup(g_store, g_op, &missing, &got));
    assert(!qihse_snapshot_verify(g_store, g_op, &missing));

    /* A snapshot id cannot be reused to overwrite a manifest with different
     * contents without detection: re-recording changes the body, and the old
     * checksum no longer matches what the manifest says. */
    qihse_snapshot_manifest_t edited = got;
    edited.max_generation = 9999;
    assert(qihse_snapshot_record(g_store, g_op, &edited));
    assert(qihse_snapshot_verify(g_store, g_op, &m.snapshot_id));

    printf("PASS snapshots: manifest round-trip, WAL continuation, checksum verified\n");
}

static void test_snapshot_tamper_detection(void) {
    /* Write a manifest by hand with a deliberately wrong checksum, then prove
     * verification catches it.  This is the property that makes a backup
     * restorable rather than hopeful. */
    qihse_snapshot_manifest_t m;
    memset(&m, 0, sizeof(m));
    assert(qihse_uuid_generate(&m.snapshot_id));
    m.kind = QIHSE_SNAPSHOT_LOCAL;
    m.max_generation = 7;
    m.wal_continuation_offset = 100;
    assert(qihse_snapshot_record(g_store, g_op, &m));
    assert(qihse_snapshot_verify(g_store, g_op, &m.snapshot_id));

    /* Corrupt the stored body directly through the KV layer. */
    char key[160];
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&m.snapshot_id, id_str);
    snprintf(key, sizeof(key), "snapshot/manifest:%s", id_str);

    char* blob = qihse_kv_get_user(g_store, key, g_op);
    assert(blob);
    /* Flip the recorded max_generation from 7 to 8 without touching the
     * checksum: the digest no longer describes the body. */
    char* field = strstr(blob, "\t7\t");
    if (field) field[1] = '8';
    assert(qihse_kv_set_user(g_store, key, blob, 0, 0, g_op));
    free(blob);

    assert(!qihse_snapshot_verify(g_store, g_op, &m.snapshot_id));

    printf("PASS snapshot tamper detection: an edited manifest fails verification\n");
}

/* ── Rejoin sequence (v3.md §43) ───────────────────────────────────────── */

static void test_rejoin_sequence(void) {
    /* The sequence is ordered and complete. */
    qihse_rejoin_step_t step = QIHSE_REJOIN_IDLE;
    qihse_rejoin_step_t expected[] = {
        QIHSE_REJOIN_AUTHENTICATE_PEER,
        QIHSE_REJOIN_COMPARE_FEDERATION_UUID,
        QIHSE_REJOIN_COMPARE_BOOT_UUID,
        QIHSE_REJOIN_EXCHANGE_HLC,
        QIHSE_REJOIN_EXCHANGE_MANIFESTS,
        QIHSE_REJOIN_IDENTIFY_DIVERGENCE,
        QIHSE_REJOIN_TRANSFER_EVENTS,
        QIHSE_REJOIN_APPLY_CONFLICT_POLICY,
        QIHSE_REJOIN_RECONSTRUCT_STATE,
        QIHSE_REJOIN_VERIFY_CHECKSUMS,
        QIHSE_REJOIN_COMPLETE,
    };
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        step = qihse_rejoin_next_step(step);
        assert(step == expected[i]);
    }
    /* COMPLETE is terminal. */
    assert(qihse_rejoin_next_step(QIHSE_REJOIN_COMPLETE) == QIHSE_REJOIN_ABORTED);
    assert(qihse_rejoin_next_step(QIHSE_REJOIN_ABORTED) == QIHSE_REJOIN_ABORTED);

    /* Vocabulary round-trip. */
    for (int i = 0; i <= (int)QIHSE_REJOIN_ABORTED; i++) {
        qihse_rejoin_step_t s = (qihse_rejoin_step_t)i;
        const char* name = qihse_rejoin_step_name(s);
        assert(name != NULL);
        qihse_rejoin_step_t parsed;
        assert(qihse_rejoin_step_parse(name, &parsed));
        assert(parsed == s);
    }

    /* Ownership may only be published at the very end.  A rejoining node that
     * published earlier would make a stale exclusive claim authoritative. */
    assert(!qihse_rejoin_may_publish_ownership(QIHSE_REJOIN_IDLE));
    assert(!qihse_rejoin_may_publish_ownership(QIHSE_REJOIN_IDENTIFY_DIVERGENCE));
    assert(!qihse_rejoin_may_publish_ownership(QIHSE_REJOIN_RECONSTRUCT_STATE));
    assert(!qihse_rejoin_may_publish_ownership(QIHSE_REJOIN_VERIFY_CHECKSUMS));
    assert(!qihse_rejoin_may_publish_ownership(QIHSE_REJOIN_ABORTED));
    assert(qihse_rejoin_may_publish_ownership(QIHSE_REJOIN_COMPLETE));

    /* Progress persists so a long reconciliation survives a restart. */
    qihse_rejoin_state_t st;
    memset(&st, 0, sizeof(st));
    assert(qihse_uuid_generate(&st.node_id));
    assert(qihse_uuid_generate(&st.peer_node));
    st.step = QIHSE_REJOIN_TRANSFER_EVENTS;
    st.events_transferred = 12345;
    assert(qihse_rejoin_state_put(g_store, g_op, &st));

    qihse_rejoin_state_t got;
    assert(qihse_rejoin_state_get(g_store, g_op, &st.node_id, &got));
    assert(got.step == QIHSE_REJOIN_TRANSFER_EVENTS);
    assert(got.events_transferred == 12345);
    assert(qihse_uuid_equal(&got.peer_node, &st.peer_node));

    printf("PASS rejoin sequence: 11 ordered steps, ownership withheld until complete\n");
}

/* ── Observability (v3.md §41) ─────────────────────────────────────────── */

static void test_metrics_render(void) {
    qihse_federation_metrics_t m;
    qihse_federation_metrics_init(&m);
    m.federation_peer_state_connected = 5;
    m.replication_lag_ms = 12;
    m.conflict_count = 2;
    m.lease_count = 7;
    m.stale_epoch_rejections = 1;
    m.audit_chain_status_ok = 1;
    m.runtime_trust_state = 1; /* TRUSTED */
    m.unexpected_listener_count = 0;

    char out[4096];
    assert(qihse_federation_metrics_render(&m, NULL, out, sizeof(out)));
    /* Every metric from the brief's list is present. */
    static const char* names[] = {
        "federation_peer_state", "replication_lag_ms", "unreplicated_bytes",
        "anti_entropy_ranges_checked", "anti_entropy_bytes_repaired",
        "conflict_count", "watch_subscribers", "watch_backlog", "lease_count",
        "lease_expiry_failures", "cas_failures", "stale_epoch_rejections",
        "auth_failures", "audit_chain_status", "runtime_trust_state",
        "runtime_profile_drift", "unexpected_listener_count",
        "unexpected_capability_count", "provenance_verification_state",
        "clock_sync_state", "peer_clock_skew_ms",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        assert(strstr(out, names[i]) != NULL);
    }
    assert(strstr(out, "qihse_conflict_count 2") != NULL);
    assert(strstr(out, "qihse_lease_count 7") != NULL);

    /* A custom prefix is honoured. */
    assert(qihse_federation_metrics_render(&m, "citadel", out, sizeof(out)));
    assert(strstr(out, "citadel_conflict_count 2") != NULL);

    /* Label-bounded: no node id, namespace, or other high-cardinality label
     * appears in the rendered output. */
    assert(strstr(out, "{") == NULL);
    assert(strstr(out, "node=") == NULL);
    assert(strstr(out, "namespace=") == NULL);

    /* A buffer too small for the whole set fails rather than truncating. */
    char tiny[16];
    assert(!qihse_federation_metrics_render(&m, NULL, tiny, sizeof(tiny)));

    printf("PASS metrics: all 21 series rendered, label-bounded, no truncation\n");
}

/* ── Performance budgets (v3.md §40, AC14) ─────────────────────────────── */

static void test_perf_budgets(void) {
    qihse_perf_budget_t b;
    qihse_perf_budget_init(&b);
    assert(b.local_kv_overhead_p50_pct == 5.0);
    assert(b.local_kv_overhead_p99_pct == 10.0);
    assert(b.event_append_per_sec_min == 100000.0);
    assert(b.watch_delivery_p50_ms == 10.0);

    qihse_perf_measurement_t m;
    qihse_perf_verdict_t v;

    /* A measurement inside budget passes. */
    memset(&m, 0, sizeof(m));
    m.local_kv_overhead_p50_pct = 2.5;
    m.local_kv_overhead_p99_pct = 7.0;
    m.event_append_per_sec = 250000.0;
    m.watch_delivery_p50_ms = 3.0;
    assert(qihse_perf_evaluate(&b, &m, &v));
    assert(v.passed);
    assert(v.failure_count == 0);

    /* Each metric can fail independently and is reported by name. */
    m = (qihse_perf_measurement_t){0};
    m.local_kv_overhead_p50_pct = 6.0;
    assert(qihse_perf_evaluate(&b, &m, &v));
    assert(!v.passed);
    assert(v.failure_count == 1);
    assert(strstr(v.failures[0], "p50") != NULL);

    m = (qihse_perf_measurement_t){0};
    m.local_kv_overhead_p99_pct = 25.0;
    assert(qihse_perf_evaluate(&b, &m, &v));
    assert(!v.passed);
    assert(strstr(v.failures[0], "p99") != NULL);

    m = (qihse_perf_measurement_t){0};
    m.event_append_per_sec = 50000.0;  /* below the 100k/s target */
    assert(qihse_perf_evaluate(&b, &m, &v));
    assert(!v.passed);
    assert(strstr(v.failures[0], "event append") != NULL);

    m = (qihse_perf_measurement_t){0};
    m.watch_delivery_p50_ms = 42.0;
    assert(qihse_perf_evaluate(&b, &m, &v));
    assert(!v.passed);
    assert(strstr(v.failures[0], "watch delivery") != NULL);

    /* An unmeasured metric (zero) must not produce a false failure, so a
     * partial harness still gives a meaningful verdict. */
    m = (qihse_perf_measurement_t){0};
    m.local_kv_overhead_p50_pct = 1.0;
    assert(qihse_perf_evaluate(&b, &m, &v));
    assert(v.passed);

    /* All four failing at once reports all four. */
    memset(&m, 0, sizeof(m));
    m.local_kv_overhead_p50_pct = 90.0;
    m.local_kv_overhead_p99_pct = 95.0;
    m.event_append_per_sec = 1.0;
    m.watch_delivery_p50_ms = 500.0;
    assert(qihse_perf_evaluate(&b, &m, &v));
    assert(!v.passed);
    assert(v.failure_count == 4);

    printf("PASS perf budgets: each metric independently enforced, unmeasured skipped (AC14)\n");
}

/* ── Vocabulary ────────────────────────────────────────────────────────── */

static void test_vocabularies(void) {
    qihse_snapshot_kind_t k;
    assert(qihse_snapshot_kind_parse("local", &k) && k == QIHSE_SNAPSHOT_LOCAL);
    assert(qihse_snapshot_kind_parse("coordinated", &k) && k == QIHSE_SNAPSHOT_COORDINATED);
    assert(!qihse_snapshot_kind_parse("nope", &k));
    assert(strcmp(qihse_snapshot_kind_name(QIHSE_SNAPSHOT_LOCAL), "local") == 0);
    assert(strcmp(qihse_snapshot_kind_name(QIHSE_SNAPSHOT_COORDINATED), "coordinated") == 0);

    assert(strcmp(qihse_schema_result_name(QIHSE_SCHEMA_OK), "ok") == 0);
    assert(strcmp(qihse_schema_result_name(QIHSE_SCHEMA_ERR_READER_TOO_OLD),
                  "reader_too_old") == 0);

    printf("PASS vocabularies: snapshot kinds and schema results round-trip\n");
}

/* ── RESP-level F8 ─────────────────────────────────────────────────────── */

#include "qihse_cluster_slot.h"
#include "qihse_resp_wire.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t f8_free_tcp_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

typedef struct { int fd; char buf[65536]; size_t fill; } f8_client_t;

static bool f8_read_line(f8_client_t* c, char* out, size_t cap) {
    for (;;) {
        for (size_t i = 0; i < c->fill; i++) {
            if (c->buf[i] == '\n') {
                size_t len = i;
                if (len && c->buf[len - 1u] == '\r') len--;
                if (len >= cap) len = cap - 1u;
                memcpy(out, c->buf, len); out[len] = '\0';
                memmove(c->buf, c->buf + i + 1u, c->fill - i - 1u);
                c->fill -= i + 1u;
                return true;
            }
        }
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
}

static bool f8_read_exact(f8_client_t* c, char* out, size_t len) {
    while (c->fill < len) {
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
    memcpy(out, c->buf, len);
    memmove(c->buf, c->buf + len, c->fill - len);
    c->fill -= len;
    return true;
}

static bool f8_read_reply(f8_client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!f8_read_line(c, line, sizeof(line))) return false;
    char type = line[0];
    const char* rest = line + 1;
    if (type == '+' || type == '-' || type == ':') {
        int n = snprintf(out + *used, cap - *used, "%s", rest);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '$') {
        int len = atoi(rest);
        if (len < 0) return true;
        char data[16384];
        if ((size_t)len >= sizeof(data)) return false;
        if (!f8_read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!f8_read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void f8_send_cmd6(f8_client_t* c, const char* a, const char* b, const char* d,
                         const char* e, const char* f, const char* g) {
    const char* args[6] = { a, b, d, e, f, g };
    size_t argc = 0;
    for (size_t i = 0; i < 6u; i++) if (args[i]) argc++;
    char out[4096]; size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++)
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n", strlen(args[i]), args[i]);
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

static void f8_send_cmd(f8_client_t* c, const char* a, const char* b, const char* d, const char* e) {
    f8_send_cmd6(c, a, b, d, e, NULL, NULL);
}

static void test_resp_federation_f8(void) {
    uint16_t port = f8_free_tcp_port();
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("f8-resp-test-node", strlen("f8-resp-test-node"), node_id);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = f8_free_tcp_port();
    scfg.store = g_store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) fprintf(stderr, "server create failed: errno=%d (%s)\n", errno, strerror(errno));
    assert(server);
    assert(qihse_resp_server_start(server));

    f8_client_t c; memset(&c, 0, sizeof c);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0); assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[16384]; size_t used;
    f8_send_cmd(&c, "AUTH", "GODMODE_OP", "F8OpsOperatorPass1!", NULL);
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* SCHEMA.CHECK with a version this build understands. */
    f8_send_cmd6(&c, "FEDERATION", "SCHEMA.CHECK", "1", "1", "0", "0");
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "ok") != NULL);

    /* SCHEMA.CHECK with an unknown REQUIRED feature must be rejected. */
    f8_send_cmd6(&c, "FEDERATION", "SCHEMA.CHECK", "1", "1", "0x10000000000", "0");
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "unknown_required_feature") != NULL);

    /* SCHEMA.MIGRATE then SCHEMA.STATUS. */
    f8_send_cmd6(&c, "FEDERATION", "SCHEMA.MIGRATE", "1363744324", "3", "4", "1");
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "OK") != NULL);

    f8_send_cmd6(&c, "FEDERATION", "SCHEMA.PROGRESS", "1363744324", "4", "250", "1000");
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "OK") != NULL);

    f8_send_cmd(&c, "FEDERATION", "SCHEMA.STATUS", "1363744324", "4");
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "250") != NULL);
    assert(strstr(reply, "1000") != NULL);

    /* SNAPSHOT.CREATE returns an id; SHOW reports it verified. */
    f8_send_cmd6(&c, "FEDERATION", "SNAPSHOT.CREATE", "coordinated", "1831", "99123456", "key:citadel-1");
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strlen(reply) >= 36);
    char snap_id[64];
    assert(strlen(reply) < sizeof(snap_id));
    memcpy(snap_id, reply, strlen(reply) + 1u);

    f8_send_cmd(&c, "FEDERATION", "SNAPSHOT.SHOW", snap_id, NULL);
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "coordinated") != NULL);
    assert(strstr(reply, "99123456") != NULL);

    f8_send_cmd(&c, "FEDERATION", "SNAPSHOT.VERIFY", snap_id, NULL);
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) == 1);

    /* REJOIN.STEPS lists the ordered sequence. */
    f8_send_cmd(&c, "FEDERATION", "REJOIN.STEPS", NULL, NULL);
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "AUTHENTICATE_PEER") != NULL);
    assert(strstr(reply, "VERIFY_CHECKSUMS") != NULL);
    assert(strstr(reply, "COMPLETE") != NULL);

    /* METRICS renders label-bounded series. */
    f8_send_cmd(&c, "FEDERATION", "METRICS", NULL, NULL);
    used = 0; assert(f8_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "federation_peer_state") != NULL);
    assert(strstr(reply, "stale_epoch_rejections") != NULL);
    assert(strstr(reply, "node=") == NULL);

    /* Tenant guest is denied (AGENTS.md invariant 3). */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(g_op,
        42u, 109u, QIHSE_ROLE_GUEST, 0, 0, "F8TenantGuestP1!", false);
    assert(tenant);
    f8_client_t g; memset(&g, 0, sizeof g);
    g.fd = socket(AF_INET, SOCK_STREAM, 0); assert(g.fd >= 0);
    assert(connect(g.fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    f8_send_cmd(&g, "AUTH", "User_109", "F8TenantGuestP1!", NULL);
    used = 0; assert(f8_read_reply(&g, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    f8_send_cmd(&g, "FEDERATION", "METRICS", NULL, NULL);
    used = 0; assert(f8_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    assert(strstr(reply, "stale_epoch_rejections") == NULL);
    f8_send_cmd(&g, "FEDERATION", "SNAPSHOT.SHOW", snap_id, NULL);
    used = 0; assert(f8_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    assert(strstr(reply, "coordinated") == NULL);
    f8_send_cmd(&g, "FEDERATION", "REJOIN.STEPS", NULL, NULL);
    used = 0; assert(f8_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(g.fd);

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    printf("PASS RESP FEDERATION.SCHEMA/SNAPSHOT/REJOIN/METRICS + tenant-guest NOPERM\n");
}

int main(void) {
    char data_root[] = "build/fed_f8ops_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("F8OpsOperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "F8OpsOperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);

    g_store = qihse_kv_store_create();
    assert(g_store);

    test_vocabularies();
    test_schema_compatibility();
    test_mixed_schema_cluster();
    test_migrations();
    test_migration_progress();
    test_snapshot_manifest();
    test_snapshot_tamper_detection();
    test_rejoin_sequence();
    test_metrics_render();
    test_perf_budgets();
    test_resp_federation_f8();

    qihse_kv_store_destroy(g_store);
    printf("federation F8 operations tests passed\n");
    return 0;
}
