/*
 * test_metrics_w52_telemetry.c — W5.2 telemetry expansion.
 *
 * Covers the label-bounded extension of src/spinnaker/qihse_metrics.c and the
 * series it now feeds from the RESP engine:
 *
 *   1.  Registry bound: a labelled family declares its complete value set, an
 *       undeclared value is refused (and counted), and neither the refusal nor
 *       a rejected registration can add a series.  This is the property that
 *       keeps a metrics system from becoming a memory leak.
 *   2.  Histogram buckets: cumulative Prometheus `_bucket` semantics, +Inf
 *       equal to `_count`, and a bounds ladder that must be strictly
 *       increasing.
 *   3.  Per-query-type counters and latency histograms MOVE when commands are
 *       dispatched — asserted as deltas against a rendered exposition, not as
 *       "the field exists".
 *   4.  Error counters move on an error reply and do NOT move on a successful
 *       command (the control that makes the error count mean something).
 *   5.  Backend attribution and availability: `qihse_backend_queries_total`
 *       follows the command, `qihse_backend_available` follows the engines
 *       actually attached to the server (0 -> 1 when a tsdb is attached).
 *   6.  Cluster/replication status: topology gauges sampled at scrape, and
 *       `qihse_replication_attempts_total` / `_failures_total` moving when a
 *       write to a redundancy peer fails.
 *   7.  XDP counters: `qihse_xdp_ingest_denied_total` moves on a refusal and
 *       `qihse_xdp_artifacts_ingested_total` moves on an accepted frame.
 *
 * NOT covered here, and not claimed: the W5.1 optimizer decision/rollback
 * counters (that workstream has not landed), per-peer replication lag (the
 * RESP server holds one redundancy peer, not a peer set), and a native
 * quantile estimator (p50/p95/p99 are derived from these buckets by the
 * scraper; the registry deliberately keeps no reservoir).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "qihse_af_xdp.h"
#include "qihse_auth.h"
#include "qihse_metrics.h"
#include "qihse_resp_wire.h"
#include "qihse_timeseries.h"

#define OPERATOR_PASSWORD "W52TelemetryOp1!"
#define GUEST_PASSWORD    "W52TelemetryGuest1!"

static qihse_user_t* g_operator = NULL;
static qihse_user_t* g_guest = NULL;
static qihse_resp_server_t* g_server = NULL;

/* ── Exposition helpers ─────────────────────────────────────────────────── */

/* Read one series from a rendered exposition.  Returns false when the series
 * is absent, which is a failure in every caller below. */
static bool metric_value(const char* text, const char* series, double* out) {
    if (!text || !series || !out) return false;
    size_t slen = strlen(series);
    const char* line = text;
    while (line && *line) {
        const char* eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);
        if (len > slen && strncmp(line, series, slen) == 0 && line[slen] == ' ') {
            *out = strtod(line + slen + 1u, NULL);
            return true;
        }
        if (!eol) break;
        line = eol + 1;
    }
    return false;
}

static double require_metric(const char* text, const char* series) {
    double value = 0.0;
    if (!metric_value(text, series, &value)) {
        fprintf(stderr, "missing series %s in:\n%s\n", series, text);
        assert(false);
    }
    return value;
}

static size_t count_lines_with_prefix(const char* text, const char* prefix) {
    size_t count = 0;
    size_t plen = strlen(prefix);
    const char* line = text;
    while (line && *line) {
        const char* eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);
        if (len >= plen && strncmp(line, prefix, plen) == 0) count++;
        if (!eol) break;
        line = eol + 1;
    }
    return count;
}

/* Run one command through the stateless execute path and return its reply as
 * a NUL-terminated string (the raw reply buffer is not NUL-terminated). */
static char* exec_command(size_t argc, const char* const* argv) {
    qihse_resp_arg_t args[8];
    assert(argc > 0 && argc <= 8);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t* reply = NULL;
    size_t reply_len = 0;
    assert(qihse_resp_server_execute(g_server, g_operator, argc, args, &reply, &reply_len));
    char* text = (char*)malloc(reply_len + 1u);
    assert(text != NULL);
    memcpy(text, reply, reply_len);
    text[reply_len] = '\0';
    free(reply);
    return text;
}

static char* render_metrics(void) {
    const char* render[] = { "METRICS.RENDER" };
    char* text = exec_command(1, render);
    assert(strstr(text, "qihse_queries_total") != NULL);
    return text;
}

/* ── 1 + 2. Registry bounds and histogram buckets ───────────────────────── */

static void test_registry_bound(void) {
    qihse_metrics_registry_t* reg = qihse_metrics_create();
    assert(reg != NULL);

    static const char* const values[] = { "alpha", "beta", "gamma" };
    assert(qihse_metrics_register_bounded(reg, "qihse_test_total", "bounded",
                                          METRIC_COUNTER, "type", values, 3) == 0);
    /* A labelled family occupies exactly its declared value count. */
    assert(qihse_metrics_count(reg) == 3);

    qihse_metric_series_t* beta = qihse_metrics_series(reg, "qihse_test_total", "beta");
    assert(beta != NULL);
    assert(qihse_metrics_series_increment(beta, 2) == 0);

    /* An undeclared label value is refused, creates no series, and is
     * counted — the bound is enforced, not merely documented. */
    assert(qihse_metrics_series(reg, "qihse_test_total", "delta") == NULL);
    assert(qihse_metrics_count(reg) == 3);
    assert(reg->label_rejected_total == 1);
    /* A caller-supplied key or query string cannot become a label. */
    assert(qihse_metrics_series(reg, "qihse_test_total", "user:42:some-key") == NULL);
    assert(qihse_metrics_count(reg) == 3);
    assert(reg->label_rejected_total == 2);

    /* The name-only API deliberately cannot address a labelled member. */
    assert(qihse_metrics_increment(reg, "qihse_test_total", 1) == -1);
    /* Re-registering the family under the same name is refused. */
    assert(qihse_metrics_register(reg, "qihse_test_total", "dup", METRIC_COUNTER) == -1);
    /* Too many values for one family, duplicate values, and a value that
     * would rewrite the exposition format are all refused. */
    static const char* const too_many[QIHSE_METRICS_MAX_LABEL_VALUES + 1u] = {
        "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11","v12","v13","v14","v15",
        "v16","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","v28","v29",
        "v30","v31","v32"
    };
    assert(qihse_metrics_register_bounded(reg, "qihse_overflow_total", "too many",
                                          METRIC_COUNTER, "type", too_many,
                                          QIHSE_METRICS_MAX_LABEL_VALUES + 1u) == -1);
    static const char* const dupes[] = { "a", "a" };
    assert(qihse_metrics_register_bounded(reg, "qihse_dup_total", "dupes",
                                          METRIC_COUNTER, "type", dupes, 2) == -1);
    static const char* const hostile[] = { "a\",injected=\"1" };
    assert(qihse_metrics_register_bounded(reg, "qihse_hostile_total", "hostile",
                                          METRIC_COUNTER, "type", hostile, 1) == -1);
    assert(qihse_metrics_count(reg) == 3);

    char* text = qihse_metrics_export(reg);
    assert(text != NULL);
    assert(strstr(text, "qihse_test_total{type=\"beta\"} 2") != NULL);
    free(text);
    qihse_metrics_destroy(reg);
    printf("PASS metrics bound: undeclared label refused, counted, no series created\n");
}

static void test_histogram_buckets(void) {
    qihse_metrics_registry_t* reg = qihse_metrics_create();
    assert(reg != NULL);
    static const char* const values[] = { "fast", "slow" };
    assert(qihse_metrics_register_bounded(reg, "qihse_test_seconds", "latency",
                                          METRIC_HISTOGRAM, "type", values, 2) == 0);
    static const double bounds[] = { 0.001, 0.01 };
    assert(qihse_metrics_set_buckets(reg, "qihse_test_seconds", "fast", bounds, 2) == 0);
    assert(qihse_metrics_set_buckets(reg, "qihse_test_seconds", "slow", bounds, 2) == 0);
    /* A ladder that is not strictly increasing is refused: a non-monotonic
     * ladder makes every derived quantile meaningless. */
    static const double bad_bounds[] = { 0.01, 0.001 };
    assert(qihse_metrics_set_buckets(reg, "qihse_test_seconds", "fast", bad_bounds, 2) == -1);
    static const double zero_bounds[] = { 0.0 };
    assert(qihse_metrics_set_buckets(reg, "qihse_test_seconds", "fast", zero_bounds, 1) == -1);

    qihse_metric_series_t* fast = qihse_metrics_series(reg, "qihse_test_seconds", "fast");
    qihse_metric_series_t* slow = qihse_metrics_series(reg, "qihse_test_seconds", "slow");
    assert(fast && slow);
    assert(qihse_metrics_series_observe(fast, 0.0005) == 0); /* bucket 0 */
    assert(qihse_metrics_series_observe(fast, 0.005) == 0);  /* bucket 1 */
    assert(qihse_metrics_series_observe(fast, 1.0) == 0);    /* +Inf only */

    qihse_metric_snapshot_t snap;
    assert(qihse_metrics_series_snapshot(fast, &snap) == 0);
    assert(snap.num_bounds == 2);
    assert(snap.count == 3);
    assert(snap.buckets[0] == 1); /* cumulative */
    assert(snap.buckets[1] == 2);
    assert(snap.buckets[2] == 3); /* +Inf == count */
    assert(snap.sum > 1.0054 && snap.sum < 1.0056);
    /* The other member of the family saw nothing. */
    assert(qihse_metrics_series_snapshot(slow, &snap) == 0);
    assert(snap.count == 0 && snap.buckets[2] == 0);

    char* text = qihse_metrics_export(reg);
    assert(text != NULL);
    assert(strstr(text, "# TYPE qihse_test_seconds histogram") != NULL);
    assert(strstr(text, "qihse_test_seconds_bucket{type=\"fast\",le=\"0.001\"} 1") != NULL);
    assert(strstr(text, "qihse_test_seconds_bucket{type=\"fast\",le=\"0.01\"} 2") != NULL);
    assert(strstr(text, "qihse_test_seconds_bucket{type=\"fast\",le=\"+Inf\"} 3") != NULL);
    assert(strstr(text, "qihse_test_seconds_count{type=\"fast\"} 3") != NULL);
    assert(strstr(text, "qihse_test_seconds_bucket{type=\"slow\",le=\"+Inf\"} 0") != NULL);
    free(text);
    qihse_metrics_destroy(reg);
    printf("PASS histogram: cumulative buckets, +Inf == count, monotonic ladder enforced\n");
}

/* ── 3 + 4 + 5. Query-type counters, errors, backend attribution ─────────── */

static void test_query_type_telemetry(void) {
    char* before = render_metrics();

    /* Two writes, two reads. */
    const char* set1[] = { "SET", "w52:key", "one" };
    const char* set2[] = { "SET", "w52:key2", "two" };
    const char* get1[] = { "GET", "w52:key" };
    const char* get2[] = { "GET", "w52:key2" };
    for (size_t i = 0; i < 2; i++) {
        char* reply = exec_command(3, i == 0 ? set1 : set2);
        assert(strcmp(reply, "+OK\r\n") == 0);
        free(reply);
    }
    for (size_t i = 0; i < 2; i++) {
        char* reply = exec_command(2, i == 0 ? get1 : get2);
        assert(reply[0] == '$');
        free(reply);
    }
    /* A successful command that finds nothing is not an error. */
    const char* missing[] = { "GET", "w52:absent" };
    char* nil = exec_command(2, missing);
    assert(strcmp(nil, "$-1\r\n") == 0);
    free(nil);

    char* after = render_metrics();
    double sets = require_metric(after, "qihse_queries_total{type=\"set\"}") -
                  require_metric(before, "qihse_queries_total{type=\"set\"}");
    double gets = require_metric(after, "qihse_queries_total{type=\"get\"}") -
                  require_metric(before, "qihse_queries_total{type=\"get\"}");
    assert(sets == 2.0);
    assert(gets == 3.0); /* two hits + one miss, all GETs */
    /* Untouched types stay at zero: the label space is finite, so "absent"
     * means "no such query", not "no data yet". */
    assert(require_metric(after, "qihse_queries_total{type=\"vector\"}") == 0.0);
    assert(require_metric(after, "qihse_queries_total{type=\"federation\"}") == 0.0);

    /* Latency histogram moved with the same events. */
    double count = require_metric(after, "qihse_query_latency_seconds_count{type=\"set\"}") -
                   require_metric(before, "qihse_query_latency_seconds_count{type=\"set\"}");
    double sum = require_metric(after, "qihse_query_latency_seconds_sum{type=\"set\"}") -
                 require_metric(before, "qihse_query_latency_seconds_sum{type=\"set\"}");
    assert(count == 2.0);
    assert(sum > 0.0); /* a real measurement, not a placeholder zero */
    /* Every bound plus +Inf is rendered for the series, and the buckets are
     * monotonic up to _count. */
    char series[128];
    snprintf(series, sizeof(series), "qihse_query_latency_seconds_bucket{type=\"set\",");
    assert(count_lines_with_prefix(after, series) == 17u); /* 16 bounds + +Inf */
    double inf = require_metric(after, "qihse_query_latency_seconds_bucket{type=\"set\",le=\"+Inf\"}");
    double first = require_metric(after, "qihse_query_latency_seconds_bucket{type=\"set\",le=\"5e-05\"}");
    assert(inf >= first);
    assert(inf == require_metric(after, "qihse_query_latency_seconds_count{type=\"set\"}"));

    /* Success is not an error: the error counter is a control, not a mirror. */
    assert(require_metric(after, "qihse_query_errors_total{type=\"get\"}") -
           require_metric(before, "qihse_query_errors_total{type=\"get\"}") == 0.0);

    /* Backend attribution follows the command. */
    double kv = require_metric(after, "qihse_backend_queries_total{backend=\"kv\"}") -
                require_metric(before, "qihse_backend_queries_total{backend=\"kv\"}");
    assert(kv == 5.0);
    assert(require_metric(after, "qihse_backend_queries_total{backend=\"vector\"}") == 0.0);
    free(before);
    free(after);
    printf("PASS query types: counters, latency histogram and backend attribution move\n");
}

static void test_error_telemetry(void) {
    char* before = render_metrics();

    /* Wrong arity: a classified command that fails. */
    const char* bad_set[] = { "SET", "w52:key" };
    char* reply = exec_command(2, bad_set);
    assert(strncmp(reply, "-ERR", 4) == 0);
    free(reply);

    /* Unknown command: classified as `other`, never as a new label value. */
    const char* unknown[] = { "W52.NOT.A.COMMAND", "x" };
    reply = exec_command(2, unknown);
    assert(strncmp(reply, "-ERR", 4) == 0);
    free(reply);

    char* after = render_metrics();
    assert(require_metric(after, "qihse_query_errors_total{type=\"set\"}") -
           require_metric(before, "qihse_query_errors_total{type=\"set\"}") == 1.0);
    assert(require_metric(after, "qihse_query_errors_total{type=\"other\"}") -
           require_metric(before, "qihse_query_errors_total{type=\"other\"}") == 1.0);
    /* The failed SET was still a SET that ran, and it was attributed to KV. */
    assert(require_metric(after, "qihse_queries_total{type=\"set\"}") -
           require_metric(before, "qihse_queries_total{type=\"set\"}") == 1.0);
    /* Two control-plane commands ran between the two snapshots: the unknown
     * command, and the METRICS.RENDER that produced `before` (a render is
     * counted after it takes its own snapshot, so it appears in the next one).
     * Naming both is the point — a delta that "just happens" to be 2 would
     * prove nothing about attribution. */
    assert(require_metric(after, "qihse_backend_queries_total{backend=\"control\"}") -
           require_metric(before, "qihse_backend_queries_total{backend=\"control\"}") == 2.0);
    /* The failed SET was attributed to the engine it would have written to,
     * not to the control plane. */
    assert(require_metric(after, "qihse_backend_queries_total{backend=\"kv\"}") -
           require_metric(before, "qihse_backend_queries_total{backend=\"kv\"}") == 1.0);
    /* No series was created for the unknown command name. */
    assert(strstr(after, "W52.NOT.A.COMMAND") == NULL);
    free(before);
    free(after);
    printf("PASS errors: error counter moves, unknown command lands in `other`\n");
}

static void test_backend_availability(void) {
    char* text = render_metrics();
    /* This server was created with a KV store and a tsdb, and with no vector,
     * column, document, graph or FTS engine attached. */
    assert(require_metric(text, "qihse_backend_available{backend=\"kv\"}") == 1.0);
    assert(require_metric(text, "qihse_backend_available{backend=\"timeseries\"}") == 1.0);
    assert(require_metric(text, "qihse_backend_available{backend=\"vector\"}") == 0.0);
    assert(require_metric(text, "qihse_backend_available{backend=\"document\"}") == 0.0);
    assert(require_metric(text, "qihse_backend_available{backend=\"graph\"}") == 0.0);
    assert(require_metric(text, "qihse_backend_available{backend=\"fts\"}") == 0.0);
    assert(require_metric(text, "qihse_backend_available{backend=\"control\"}") == 1.0);
    free(text);
    printf("PASS backend availability: reflects the engines actually attached\n");
}

/* ── 6. Cluster and replication status ──────────────────────────────────── */

static void test_cluster_and_replication(void) {
    char* text = render_metrics();
    /* Single-node topology created by the server: one node, all slots owned,
     * primary role, healthy. */
    assert(require_metric(text, "qihse_cluster_nodes_total") == 1.0);
    assert(require_metric(text, "qihse_cluster_nodes_healthy") == 1.0);
    assert(require_metric(text, "qihse_cluster_slots_assigned") == 16384.0);
    assert(require_metric(text, "qihse_cluster_local_role") == 0.0);
    /* Federation state is an info-style family bounded by the state enum:
     * exactly one member is 1, so the sum is always 1 and a state the enum
     * does not name cannot appear. */
    double sum = 0.0;
    for (size_t i = 0; i < 6; i++) {
        const char* names[] = { "connected", "degraded", "isolated",
                                "recovering", "fenced", "maintenance" };
        char series[96];
        snprintf(series, sizeof(series), "qihse_federation_state{state=\"%s\"}", names[i]);
        sum += require_metric(text, series);
    }
    assert(sum == 1.0);
    free(text);

    /* Replication status moves when a duplicate write cannot reach the peer.
     * The peer is a port bound and immediately released, so the connect is
     * refused rather than hanging. */
    int probe = socket(AF_INET, SOCK_STREAM, 0);
    assert(probe >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(probe, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    socklen_t addr_len = sizeof(addr);
    assert(getsockname(probe, (struct sockaddr*)&addr, &addr_len) == 0);
    uint16_t dead_port = ntohs(addr.sin_port);
    close(probe);

    char peer[64];
    snprintf(peer, sizeof(peer), "127.0.0.1:%u", (unsigned)dead_port);
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = qihse_resp_server_store(g_server);
    config.port = 0;
    config.auth_required = false;
    config.require_full_coverage = false;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    config.enable_uwp_bridge = true;
    config.redundancy_peer = peer;
    qihse_resp_server_t* peer_server = qihse_resp_server_create(&config);
    assert(peer_server != NULL);

    qihse_resp_server_t* previous = g_server;
    g_server = peer_server;
    const char* set[] = { "SET", "w52:replicated", "value" };
    char* reply = exec_command(3, set);
    assert(strcmp(reply, "+OK\r\n") == 0); /* local commit stands regardless */
    free(reply);
    char* peer_metrics = render_metrics();
    assert(require_metric(peer_metrics, "qihse_replication_attempts_total") == 1.0);
    assert(require_metric(peer_metrics, "qihse_replication_failures_total") == 1.0);
    free(peer_metrics);
    g_server = previous;
    qihse_resp_server_destroy(peer_server);
    printf("PASS cluster/replication: topology gauges sampled, replication counters move\n");
}

/* ── 7. XDP counters ────────────────────────────────────────────────────── */

static uint32_t build_tcp_frame(uint8_t* buf, uint32_t bufsize,
                                const char* payload, uint32_t payload_len) {
    uint32_t header_len = (uint32_t)(sizeof(struct ether_header) +
                                     sizeof(struct ip) + sizeof(struct tcphdr));
    assert(buf && payload && bufsize >= header_len + payload_len);
    memset(buf, 0, header_len);
    struct ether_header* eth = (struct ether_header*)buf;
    eth->ether_type = htons(ETHERTYPE_IP);
    struct ip* iph = (struct ip*)(buf + sizeof(struct ether_header));
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src.s_addr = htonl(0x0a0000c9u);
    iph->ip_dst.s_addr = htonl(0x0a000002u);
    struct tcphdr* tcph = (struct tcphdr*)(buf + sizeof(struct ether_header) + sizeof(struct ip));
    tcph->source = htons(49152);
    tcph->dest = htons(6379);
    tcph->doff = 5;
    memcpy(buf + header_len, payload, payload_len);
    return header_len + payload_len;
}

static void test_xdp_counters(void) {
    uint8_t* frame = NULL;
    assert(posix_memalign((void**)&frame, 4096, 4096) == 0);
    memset(frame, 0, 4096);
    const char* dirty = "w52@corp.internal:W52Pass1! | src=telemetry_test";
    uint32_t frame_len = build_tcp_frame(frame, 4096, dirty, (uint32_t)strlen(dirty));

    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv != NULL);

    char* before = render_metrics();
    double denied_before = require_metric(before, "qihse_xdp_ingest_denied_total");
    double ingested_before = require_metric(before, "qihse_xdp_artifacts_ingested_total");
    double dropped_before = require_metric(before, "qihse_xdp_frames_dropped_total");

    /* A guest without the declared clearance: refused, and counted as a
     * refusal rather than as a malformed frame. */
    assert(qihse_af_xdp_ingest_frame_zero_copy_user(frame, frame_len, kv, NULL, 5, 0, g_guest) == 0u);

    char* mid = render_metrics();
    assert(require_metric(mid, "qihse_xdp_ingest_denied_total") - denied_before == 1.0);
    assert(require_metric(mid, "qihse_xdp_frames_dropped_total") - dropped_before == 0.0);
    free(mid);

    /* The operator, at a clearance the payload is declared at: ingested. */
    assert(qihse_af_xdp_ingest_frame_zero_copy_user(frame, frame_len, kv, NULL, 0, 0, g_operator) >= 1u);

    char* after = render_metrics();
    assert(require_metric(after, "qihse_xdp_artifacts_ingested_total") - ingested_before >= 1.0);
    /* A frame that carries nothing extractable is a drop, not an ingest. */
    uint8_t* empty = NULL;
    assert(posix_memalign((void**)&empty, 4096, 4096) == 0);
    memset(empty, 0, 4096);
    uint32_t empty_len = build_tcp_frame(empty, 4096, "", 0);
    assert(qihse_af_xdp_ingest_frame_zero_copy_user(empty, empty_len, kv, NULL, 0, 0, g_operator) == 0u);
    char* last = render_metrics();
    assert(require_metric(last, "qihse_xdp_frames_dropped_total") - dropped_before == 1.0);
    free(last);
    free(before);
    free(after);
    free(empty);
    free(frame);
    qihse_kv_store_destroy(kv);
    printf("PASS XDP: denial, ingest and drop counters each move on their event\n");
}

int main(void) {
    char data_dir[] = "/tmp/qihse-w52-metrics-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    g_operator = qihse_auth_get_user(0);
    assert(g_operator != NULL);
    g_guest = qihse_auth_create_user(g_operator, 52, QIHSE_ROLE_GUEST, 0, 0,
                                     GUEST_PASSWORD, false);
    assert(g_guest != NULL);

    /* 1 + 2: the registry's own guarantees. */
    test_registry_bound();
    test_histogram_buckets();

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    assert(tsdb != NULL);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.tsdb = tsdb;
    config.port = 0;
    config.auth_required = true;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    config.enable_uwp_bridge = true; /* qihse_resp_server_execute requires it */
    g_server = qihse_resp_server_create(&config);
    assert(g_server != NULL);

    /* 3 + 4 + 5 */
    test_query_type_telemetry();
    test_error_telemetry();
    test_backend_availability();
    /* 6 */
    test_cluster_and_replication();
    /* 7 */
    test_xdp_counters();

    qihse_resp_server_destroy(g_server);
    g_server = NULL;
    qihse_tsdb_destroy(tsdb);
    qihse_kv_store_destroy(store);

    printf("test_metrics_w52_telemetry: all assertions passed\n");
    return 0;
}
