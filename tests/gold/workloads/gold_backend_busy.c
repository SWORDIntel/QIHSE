/*
 * gold_backend_busy.c — gold workload (area: observability).
 *
 * Closes "backend-utilization": busy-time accounting now exists.
 * qihse_backend_busy_microseconds_total{backend} accumulates the wall
 * time each engine backend spends INSIDE command dispatch (the same
 * chokepoint that counts backend_queries_total and observes query
 * latency), so utilization is busy time, not just dispatch share.
 *
 * Sampled through the REAL wire path (in-process RESP server +
 * qihse_resp_server_execute -> METRICS.RENDER):
 *
 *   1. the series renders with the expected name and backend labels
 *      (kv at minimum — the workload itself drives KV traffic);
 *   2. after N commands, the kv backend's busy time is NONZERO;
 *   3. busy time is MONOTONIC: another burst of commands never
 *      decreases it;
 *   4. busy time and dispatch count stay distinct facts (a busy count
 *      of zero for an untouched backend, nonzero for a driven one).
 */

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_vector_db.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool run_cmd(qihse_resp_server_t* server, qihse_user_t* user,
                    size_t argc, const char* const argv[],
                    char* out, size_t out_cap) {
    qihse_resp_arg_t args[16];
    assert(argc <= sizeof args / sizeof args[0]);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (char*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t* reply = NULL;
    size_t reply_len = 0;
    if (!qihse_resp_server_execute(server, user, argc, args,
                                   &reply, &reply_len))
        return false;
    size_t n = reply_len < out_cap - 1u ? reply_len : out_cap - 1u;
    if (reply) {
        memcpy(out, reply, n);
        free(reply);
    }
    out[n] = '\0';
    return true;
}

/* Extract the value of
 * qihse_backend_busy_microseconds_total{backend="kv"} from a RENDER. */
static unsigned long long parse_kv_busy(const char* render) {
    const char* needle =
        "qihse_backend_busy_microseconds_total{backend=\"kv\"} ";
    const char* p = strstr(render, needle);
    if (!p) return 0ull;
    return strtoull(p + strlen(needle), NULL, 10);
}

int main(void) {
    {
        char qdd[] = "build/gold_backend_busy_XXXXXX";
        if (!mkdtemp(qdd)) return 1;
        setenv("QIHSE_DATA_DIR", qdd, 1);
    }
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("BusyGatePass1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    qihse_vector_db_t vdb =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.auth_required = false;
    cfg.port = 0;
    cfg.store = store;
    cfg.vdb = vdb;
    cfg.enable_uwp_bridge = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server);

    char reply[65536];
    const char* metrics[] = { "METRICS.RENDER" };

    /* 1+2: drive 200 KV commands, then the series must render nonzero. */
    for (unsigned i = 0; i < 200u; i++) {
        char key[32], val[32];
        snprintf(key, sizeof key, "busy:k%u", i);
        snprintf(val, sizeof val, "v%u", i);
        const char* put[] = { "SET", key, val };
        assert(run_cmd(server, op, 3u, put, reply, sizeof reply));
    }
    for (unsigned i = 0; i < 200u; i++) {
        char key[32];
        snprintf(key, sizeof key, "busy:k%u", i);
        const char* get[] = { "GET", key };
        assert(run_cmd(server, op, 2u, get, reply, sizeof reply));
    }
    assert(run_cmd(server, op, 1u, metrics, reply, sizeof reply));
    assert(strstr(reply, "qihse_backend_busy_microseconds_total") != NULL);
    unsigned long long busy1 = parse_kv_busy(reply);
    assert(busy1 > 0ull);

    /* 3: monotonic — another burst, then the value never decreases. */
    for (unsigned i = 0; i < 200u; i++) {
        char key[32];
        snprintf(key, sizeof key, "busy:k%u", i);
        const char* get[] = { "GET", key };
        assert(run_cmd(server, op, 2u, get, reply, sizeof reply));
    }
    assert(run_cmd(server, op, 1u, metrics, reply, sizeof reply));
    unsigned long long busy2 = parse_kv_busy(reply);
    assert(busy2 >= busy1);

    /* 4: distinct facts — a backend never driven reports 0 busy time. */
    const char* graph_needle =
        "qihse_backend_busy_microseconds_total{backend=\"graph\"} ";
    const char* gp = strstr(reply, graph_needle);
    if (gp) {
        unsigned long long graph_busy = strtoull(
            gp + strlen(graph_needle), NULL, 10);
        assert(graph_busy == 0ull);
    }
    /* And the count metric is present alongside (busy != count surface). */
    assert(strstr(reply, "qihse_backend_queries_total") != NULL);

    printf("backend busy: kv %llu -> %llu us over 600 commands, monotonic, "
           "graph idle\n", busy1, busy2);
    printf("output=kv busy %llu -> %llu us, monotonic\n", busy1, busy2);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    return 0;
}
