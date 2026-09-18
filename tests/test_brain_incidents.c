/*
 * test_brain_incidents.c — W3.6: incident retrieval over QIHSE's own indexes.
 *
 * The dogfooding claim: an operator can find an incident the brain recorded,
 * using QIHSE's own FTS and vector recall rather than a separate log nobody
 * can query. Incidents are written as EPISODIC memories, so both recall paths
 * apply to them with no special-case code.
 *
 *   1. An incident the brain actually produced is retrievable by a query that
 *      describes it: brain -> journal -> memory -> index -> recall.
 *   2. It is retrievable SEMANTICALLY as well as lexically, so the vector path
 *      is exercised by real operational data.
 *   3. ROUTINE kinds are NOT incidents. OBSERVE fires every cycle; indexing it
 *      would swamp the incident history and bury a fault in a wall of
 *      observations.
 *
 * This test also found a real defect: recording an incident put a key into the
 * managed keyspace, which the slot-ownership probe counted as shardable data,
 * so the brain re-homed a range it should have left alone. See
 * cluster_key_is_node_local() in qihse_resp_engine.c.
 */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_cluster_brain.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char data_root[] = "build/brain_incidents_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);
    char jdir[] = "build/brain_inc_j_XXXXXX";
    assert(mkdtemp(jdir));

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("IncidentPass1!"));
    qihse_user_t* sys = qihse_auth_get_user(0);
    assert(sys);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    char local_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("brain-inc-local", strlen("brain-inc-local"), local_id);
    scfg.node_id = local_id;
    scfg.auth_required = false;
    scfg.port = 0;
    scfg.store = store;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    assert(server);

    /* ISOLATED requires a peer to exist AND be unhealthy (the check is
     * `node_count > 1 && healthy_peers == 0`), so add one that never answers.
     * Observe-only: this test is about retrieval, not actuation. */
    {
        qihse_cluster_topology_t* topo = qihse_resp_server_topology(server);
        assert(topo);
        qihse_cluster_node_t peer;
        memset(&peer, 0, sizeof peer);
        qihse_cluster_node_id_from_seed("brain-inc-peer", strlen("brain-inc-peer"), peer.id);
        snprintf(peer.host, sizeof peer.host, "127.0.0.1");
        peer.port = 7199;
        peer.role = QIHSE_CLUSTER_NODE_PRIMARY;
        peer.healthy = false;
        uint16_t pidx = 0;
        assert(qihse_cluster_topology_upsert_node(topo, &peer, &pidx));
    }

    qihse_brain_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    bcfg.server = server;
    bcfg.journal_dir = jdir;
    bcfg.interval_seconds = 1u;
    bcfg.act = false;
    assert(qihse_cluster_brain_start(&bcfg));
    sleep(3);
    qihse_cluster_brain_stop();

    /* 1. retrievable lexically */
    qihse_ai_memory_hit_t hits[16];
    memset(hits, 0, sizeof hits);
    size_t n = qihse_ai_memory_recall_mode(server, sys, "isolated", 16u,
                                           QIHSE_AIMEM_MODE_BM25, hits, 16u);
    bool found = false;
    for (size_t i = 0; i < n; i++)
        if (hits[i].text && strstr(hits[i].text, "ISOLATED")) found = true;
    qihse_ai_memory_hits_free(hits, n);
    if (!found) { fprintf(stderr, "ISOLATED incident not retrievable lexically\n"); return 1; }
    printf("PASS incident retrieval (lexical): an operator finds the ISOLATED incident\n");

    /* 2. and semantically */
    memset(hits, 0, sizeof hits);
    n = qihse_ai_memory_recall_mode(server, sys, "no healthy peers reachable", 16u,
                                    QIHSE_AIMEM_MODE_SEMANTIC, hits, 16u);
    found = false;
    for (size_t i = 0; i < n; i++)
        if (hits[i].text && strstr(hits[i].text, "ISOLATED")) found = true;
    qihse_ai_memory_hits_free(hits, n);
    if (!found) { fprintf(stderr, "ISOLATED incident not retrievable semantically\n"); return 1; }
    printf("PASS incident retrieval (semantic): the vector path finds it too\n");

    /* 3. routine traffic did not become incidents */
    memset(hits, 0, sizeof hits);
    n = qihse_ai_memory_recall_mode(server, sys, "OBSERVE", 32u,
                                    QIHSE_AIMEM_MODE_BM25, hits, 32u);
    size_t observe_hits = 0;
    for (size_t i = 0; i < n; i++)
        if (hits[i].text && strstr(hits[i].text, "incident OBSERVE")) observe_hits++;
    qihse_ai_memory_hits_free(hits, n);
    if (observe_hits != 0u) {
        fprintf(stderr, "%zu OBSERVE records were indexed as incidents\n", observe_hits);
        return 1;
    }
    size_t total = qihse_ai_memory_count(server, sys);
    if (total == 0u || total > 8u) {
        fprintf(stderr, "%zu memories after a 3-cycle run, expected 1-8\n", total);
        return 1;
    }
    printf("PASS routine traffic excluded: 0 OBSERVE indexed, %zu incident memories\n", total);

    qihse_ai_memory_reset();
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("brain incident retrieval tests passed\n");
    return 0;
}
