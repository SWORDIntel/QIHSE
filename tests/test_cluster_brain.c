/*
 * test_cluster_brain.c — Cluster brain phase-1 unit test (observe/journal).
 *
 * Exercises src/spinnaker/qihse_cluster_brain.c against a synthetic topology
 * with no network: a resp server is created (not started) purely to host the
 * topology the brain reads.
 *
 *   1. all-healthy cluster -> BRAIN_START + OBSERVE journaled, no alarms
 *   2. peer marked failed  -> ASYMMETRY (R2) + ISOLATED (R3) journaled
 *   3. peer healthy again  -> RECONNECTED journaled
 *   4. throughout          -> slot ownership never modified (phase 1 observes
 *                             and journals; it does not act)
 *
 * Actuation (R1 re-home under --brain-act) is phase 2 and is not implemented
 * in the current source; the no-action assertion below is the property that
 * phase-2 work must preserve.
 *
 * Journal location is relative (build/) per the repository path policy.
 */
#include "qihse_cluster_brain.h"
#include "qihse_cluster_slot.h"
#include "qihse_event_stream.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void sleep_ms(uint64_t ms) {
    struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    nanosleep(&ts, NULL);
}

static void add_node(qihse_cluster_topology_t* topo, const char* seed,
                     const char* host, uint16_t port, uint16_t bus_port,
                     bool healthy, uint16_t* idx_out) {
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
    snprintf(node.host, sizeof(node.host), "%s", host);
    node.port = port;
    node.bus_port = bus_port;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = healthy;
    uint16_t idx = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(topo, &node, &idx));
    if (idx_out) *idx_out = idx;
}

typedef struct {
    bool brain_start;
    bool brain_stop;
    bool observe;
    bool asymmetry;
    bool isolated;
    bool reconnected;
    int observe_count;
} journal_kinds_t;

static void journal_scan(const char* dir, journal_kinds_t* out) {
    memset(out, 0, sizeof(*out));
    qihse_event_stream_t* journal =
        qihse_event_stream_open(dir, QIHSE_ES_DURABILITY_NONE, true);
    assert(journal);
    uint64_t cursor = 0;
    qihse_es_record_header_t header;
    uint8_t* payload = NULL;
    size_t payload_size = 0;
    char text[2048];
    while (qihse_event_stream_iterate(journal, "cluster.brain", &cursor, &header,
                                      &payload, &payload_size)) {
        if (payload && payload_size < sizeof(text)) {
            memcpy(text, payload, payload_size);
            text[payload_size] = '\0';
            if (strstr(text, "\"kind\":\"BRAIN_START\"")) out->brain_start = true;
            else if (strstr(text, "\"kind\":\"BRAIN_STOP\"")) out->brain_stop = true;
            else if (strstr(text, "\"kind\":\"OBSERVE\"")) {
                out->observe = true;
                out->observe_count++;
            } else if (strstr(text, "\"kind\":\"ASYMMETRY\"")) out->asymmetry = true;
            else if (strstr(text, "\"kind\":\"ISOLATED\"")) out->isolated = true;
            else if (strstr(text, "\"kind\":\"RECONNECTED\"")) out->reconnected = true;
        }
        free(payload);
        payload = NULL;
    }
    qihse_event_stream_destroy(journal);
}

static void run_brain(qihse_resp_server_t* server, const char* dir, uint32_t interval_s) {
    qihse_brain_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server = server;
    cfg.journal_dir = dir;
    cfg.dsa_key_path = NULL; /* unsigned journal for the test */
    cfg.interval_seconds = interval_s;
    cfg.act = false;
    assert(qihse_cluster_brain_start(&cfg));
    sleep_ms((uint64_t)interval_s * 1000u + 600u);
    qihse_cluster_brain_stop();
}

static void snapshot_owners(qihse_cluster_topology_t* topo, uint16_t* owners) {
    assert(qihse_cluster_topology_slot_owner_snapshot(topo, owners,
                                                      QIHSE_CLUSTER_SLOT_COUNT) ==
           QIHSE_CLUSTER_SLOT_COUNT);
}

int main(void) {
    char root[] = "build/brain_journal_XXXXXX";
    assert(mkdtemp(root));
    char dir_a[600], dir_b[600], dir_c[600];
    snprintf(dir_a, sizeof(dir_a), "%s/run_a", root);
    snprintf(dir_b, sizeof(dir_b), "%s/run_b", root);
    snprintf(dir_c, sizeof(dir_c), "%s/run_c", root);
    assert(mkdir(dir_a, 0700) == 0);
    assert(mkdir(dir_b, 0700) == 0);
    assert(mkdir(dir_c, 0700) == 0);

    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    char local_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("brain-test-local-node",
                                    strlen("brain-test-local-node"), local_id);
    scfg.node_id = local_id; /* must be a hex node id (40 chars) */
    scfg.auth_required = false;
    scfg.port = 0; /* never started: the brain only needs the topology */
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    assert(server);
    qihse_cluster_topology_t* topo = qihse_resp_server_topology(server);
    assert(topo);

    uint16_t local = qihse_cluster_topology_local_node(topo);
    assert(local != QIHSE_CLUSTER_NODE_NONE);
    uint16_t peer = QIHSE_CLUSTER_NODE_NONE;
    add_node(topo, "brain-test-peer", "192.0.2.10", 7001u, 17001u, true, &peer);
    assert(qihse_cluster_topology_assign_range(topo, 0u, 8191u, local));
    assert(qihse_cluster_topology_assign_range(topo, 8192u, 16383u, peer));

    uint16_t owners_before[QIHSE_CLUSTER_SLOT_COUNT];
    uint16_t owners_after[QIHSE_CLUSTER_SLOT_COUNT];
    snapshot_owners(topo, owners_before);

    journal_kinds_t kinds;

    /* 1 — all healthy: observe only, no policy alarm. */
    run_brain(server, dir_a, 1u);
    journal_scan(dir_a, &kinds);
    assert(kinds.brain_start);
    assert(kinds.brain_stop);
    assert(kinds.observe && kinds.observe_count >= 1);
    assert(!kinds.asymmetry);
    assert(!kinds.isolated);
    printf("PASS healthy cluster journals OBSERVE with no alarms\n");

    /* 2 — peer failed: R2 asymmetry + R3 isolation are journaled, nothing acts. */
    assert(qihse_cluster_topology_set_node_health(topo, peer, false));
    run_brain(server, dir_b, 1u);
    journal_scan(dir_b, &kinds);
    assert(kinds.observe);
    assert(kinds.asymmetry);
    assert(kinds.isolated);
    snapshot_owners(topo, owners_after);
    assert(memcmp(owners_before, owners_after,
                  sizeof(owners_before)) == 0);
    printf("PASS failed peer journals ASYMMETRY + ISOLATED, ownership unchanged\n");

    /* 3 — peer healthy again: RECONNECTED is journaled once. */
    assert(qihse_cluster_topology_set_node_health(topo, peer, true));
    run_brain(server, dir_c, 1u);
    journal_scan(dir_c, &kinds);
    assert(kinds.observe);
    assert(kinds.reconnected);
    assert(!kinds.asymmetry);
    printf("PASS recovered peer journals RECONNECTED\n");

    qihse_resp_server_destroy(server);
    printf("cluster brain tests passed\n");
    return 0;
}
