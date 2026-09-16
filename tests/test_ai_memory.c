/*
 * test_ai_memory.c — Local-first AI memory (ai_fabric.md item 5).
 *
 *   A. episodic + semantic memories store, index, recall (BM25 > 0), fetch by
 *      id, and count
 *   B. forget removes the record from recall, by-id fetch, and the count
 *   C. RBAC: a low-clearance principal cannot recall, fetch, or count a
 *      memory written above its clearance (invariant-3 negative test)
 *
 * No cluster or network is needed: the module runs against a bare resp
 * server (store + FTS index).
 */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static bool text_contains(const char* haystack, const char* needle) {
    return haystack && strstr(haystack, needle) != NULL;
}

int main(void) {
    /* Isolate the KV namespace: qihse_kv_store_create() loads whatever the
     * ambient data directory holds, which would make counts non-deterministic. */
    char data_root[] = "build/aimem_data_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("aimem-test", strlen("aimem-test"), node_id);
    scfg.node_id = node_id;
    scfg.auth_required = false;
    scfg.port = 0;
    scfg.store = store;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    assert(server);

    /* A — store, recall, fetch, count. */
    char id_episodic[QIHSE_AIMEM_ID_LEN + 1u];
    char id_semantic[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, operator_user,
                                 "deployed the keystone index on the t320 node",
                                 QIHSE_AIMEM_EPISODIC, id_episodic));
    assert(qihse_ai_memory_store(server, operator_user,
                                 "keystone classification uses a trigram index",
                                 QIHSE_AIMEM_SEMANTIC, id_semantic));
    assert(strlen(id_episodic) == QIHSE_AIMEM_ID_LEN);
    assert(strcmp(id_episodic, id_semantic) != 0);
    assert(qihse_ai_memory_count(server, operator_user) == 2u);

    qihse_ai_memory_hit_t hits[8];
    memset(hits, 0, sizeof hits);
    size_t found = qihse_ai_memory_recall(server, operator_user, "keystone", 8u, hits, 8u);
    assert(found == 2u);
    assert(hits[0].score > 0.0);
    bool saw_episodic = false, saw_semantic = false;
    for (size_t i = 0; i < found; i++) {
        assert(hits[i].text != NULL);
        if (text_contains(hits[i].text, "t320")) saw_episodic = true;
        if (text_contains(hits[i].text, "trigram")) saw_semantic = true;
    }
    assert(saw_episodic && saw_semantic);
    qihse_ai_memory_hits_free(hits, found);

    qihse_ai_memory_hit_t one;
    memset(&one, 0, sizeof one);
    assert(qihse_ai_memory_get(server, operator_user, id_episodic, &one));
    assert(one.kind == QIHSE_AIMEM_EPISODIC);
    assert(text_contains(one.text, "t320"));
    free(one.text);
    printf("PASS memories store, recall by relevance, fetch by id, and count\n");

    /* B — forget. */
    assert(qihse_ai_memory_forget(server, operator_user, id_episodic));
    memset(hits, 0, sizeof hits);
    found = qihse_ai_memory_recall(server, operator_user, "keystone", 8u, hits, 8u);
    for (size_t i = 0; i < found; i++) {
        assert(!text_contains(hits[i].text, "t320")); /* forgotten record is gone */
    }
    qihse_ai_memory_hits_free(hits, found);
    memset(&one, 0, sizeof one);
    assert(!qihse_ai_memory_get(server, operator_user, id_episodic, &one));
    assert(qihse_ai_memory_count(server, operator_user) == 1u);
    printf("PASS forgotten memory disappears from recall, fetch, and count\n");

    /* C — invariant 3: a low-clearance principal cannot recall, fetch, or
     * count a memory written above its clearance. */
    qihse_user_t* cleo = qihse_auth_create_user(operator_user, 4310u, QIHSE_ROLE_ANALYST, 3u,
                                                0x1u, "AnalystPass123!", false);
    assert(cleo != NULL);
    qihse_user_t* guest = qihse_auth_create_user(operator_user, 4311u, QIHSE_ROLE_GUEST, 1u,
                                                 0x0u, "GuestAccount123!", false);
    assert(guest != NULL);

    char id_classified[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, cleo,
                                 "classified ledger keystone reconciliation note",
                                 QIHSE_AIMEM_SEMANTIC, id_classified));

    /* The analyst sees it... */
    qihse_ai_memory_hit_t analyst_hit;
    memset(&analyst_hit, 0, sizeof analyst_hit);
    assert(qihse_ai_memory_get(server, cleo, id_classified, &analyst_hit));
    assert(analyst_hit.classification == 3u);
    free(analyst_hit.text);

    /* ...the guest must not, by search, by id, or by count. */
    memset(hits, 0, sizeof hits);
    found = qihse_ai_memory_recall(server, guest, "ledger", 8u, hits, 8u);
    assert(found == 0u);
    qihse_ai_memory_hits_free(hits, found);
    memset(&one, 0, sizeof one);
    assert(!qihse_ai_memory_get(server, guest, id_classified, &one));
    assert(one.text == NULL); /* no payload disclosure on denial */
    assert(qihse_ai_memory_count(server, guest) == 0u);
    assert(qihse_ai_memory_count(server, cleo) >= 1u);
    printf("PASS low-clearance principal denied classified memory (no disclosure)\n");

    qihse_ai_memory_reset();
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("ai memory tests passed\n");
    return 0;
}
