/*
 * test_ai_memory_ext.c — AI memory read-path extensions (W4.3, folds into W2.3).
 *
 * The claims under test:
 *
 *   1. KIND filtering narrows recall and count. Episodic ("what happened")
 *      and semantic ("what is known") memories share one namespace and one
 *      index, so before this the two competed for the same limit and there
 *      was no way to ask for one kind — `kind` was write-only metadata.
 *   2. The kind filter is applied AFTER the authorization-aware resolve, so it
 *      can only remove hits the principal could already see. The negative case
 *      is explicit: a low-clearance principal filtering by the kind of a
 *      record above its clearance gets nothing, on every ranking mode, with no
 *      payload — the filter is not a way around the visibility check, and it
 *      cannot widen the result set.
 *   3. An unrecognised kind is REFUSED (0 hits, 0 count) rather than treated
 *      as "any": a filter that silently widens to everything is the defect
 *      this parameter must not introduce.
 *   4. A NULL security context fails closed on every new entry point
 *      (invariant 1: NULL must not become an authorization bypass).
 *   5. The filter is bounded: a limit far beyond the buffer cannot overflow
 *      it, and a filtered recall never writes more hits than the buffer holds.
 *   6. Durability, stated exactly: records and their vectors are durable
 *      (KV + WAL); the FTS index and the vector cache are process-local and
 *      re-derived from the KV namespace, so a reopen restores recall.
 */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MARK_CLASSIFIED "CLASSIFIED-KEYSTONE-MARKER"
#define MARK_GUEST      "GUEST-KEYSTONE-MARKER"
#define MARK_DURABLE    "DURABLE-KEYSTONE-MARKER"

static bool text_contains(const char* haystack, const char* needle) {
    return haystack && strstr(haystack, needle) != NULL;
}

/* Recall through the kind filter and check every returned hit is one the
 * caller is actually allowed to read. Returns the hit count; *out_marker is
 * set when a hit carries `marker`. */
static size_t recall_kind(qihse_resp_server_t* server, qihse_user_t* user,
                          const char* query, size_t limit, qihse_ai_memory_mode_t mode,
                          uint32_t kind, qihse_ai_memory_hit_t* hits, size_t cap,
                          const char* marker, bool* out_marker) {
    memset(hits, 0, cap * sizeof(*hits));
    size_t n = qihse_ai_memory_recall_kind(server, user, query, limit, mode, kind,
                                           hits, cap);
    assert(n <= cap);
    if (out_marker) *out_marker = false;
    for (size_t i = 0; i < n; i++) {
        assert(hits[i].text != NULL);
        /* Invariant 1, checked on every hit of every filtered recall: a
         * returned hit is one the principal can read. */
        assert(qihse_auth_can_access(user, hits[i].classification, hits[i].sci_compartment));
        if (kind != QIHSE_AIMEM_KIND_ANY) assert(hits[i].kind == kind);
        if (marker && text_contains(hits[i].text, marker) && out_marker) *out_marker = true;
    }
    return n;
}

static qihse_resp_server_t* make_server(qihse_kv_store_t* store, const char* seed) {
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed(seed, strlen(seed), node_id);
    scfg.node_id = node_id;
    scfg.auth_required = false;
    scfg.port = 0;
    scfg.store = store;
    return qihse_resp_server_create(&scfg);
}

int main(void) {
    /* Isolate the KV namespace: qihse_kv_store_create() loads whatever the
     * ambient data directory holds, which would make counts non-deterministic. */
    char data_root[] = "build/aimem_ext_data_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_t* server = make_server(store, "aimem-ext");
    assert(server);

    /* ── A. the kind filter narrows recall and count ───────────────────── */
    char id_e1[QIHSE_AIMEM_ID_LEN + 1u], id_e2[QIHSE_AIMEM_ID_LEN + 1u];
    char id_s1[QIHSE_AIMEM_ID_LEN + 1u], id_s2[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, op, "keystone incident: node t320 rebooted",
                                 QIHSE_AIMEM_EPISODIC, id_e1));
    assert(qihse_ai_memory_store(server, op, "keystone incident: replica fell behind",
                                 QIHSE_AIMEM_EPISODIC, id_e2));
    assert(qihse_ai_memory_store(server, op, "keystone uses a trigram index",
                                 QIHSE_AIMEM_SEMANTIC, id_s1));
    assert(qihse_ai_memory_store(server, op, "keystone slot count is fixed",
                                 QIHSE_AIMEM_SEMANTIC, id_s2));

    assert(qihse_ai_memory_count_kind(server, op, QIHSE_AIMEM_KIND_ANY) == 4u);
    assert(qihse_ai_memory_count_kind(server, op, QIHSE_AIMEM_EPISODIC) == 2u);
    assert(qihse_ai_memory_count_kind(server, op, QIHSE_AIMEM_SEMANTIC) == 2u);
    /* ANY is exactly what the pre-existing count reports. */
    assert(qihse_ai_memory_count_kind(server, op, QIHSE_AIMEM_KIND_ANY) ==
           qihse_ai_memory_count(server, op));

    qihse_ai_memory_hit_t hits[16];
    size_t n = recall_kind(server, op, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                           QIHSE_AIMEM_EPISODIC, hits, 16u, NULL, NULL);
    assert(n == 2u);
    for (size_t i = 0; i < n; i++) assert(text_contains(hits[i].text, "incident"));
    qihse_ai_memory_hits_free(hits, n);

    n = recall_kind(server, op, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                    QIHSE_AIMEM_SEMANTIC, hits, 16u, NULL, NULL);
    assert(n == 2u);
    for (size_t i = 0; i < n; i++) assert(!text_contains(hits[i].text, "incident"));
    qihse_ai_memory_hits_free(hits, n);

    /* ANY equals the unfiltered recall, so the filter only ever removes. */
    n = recall_kind(server, op, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                    QIHSE_AIMEM_KIND_ANY, hits, 16u, NULL, NULL);
    assert(n == 4u);
    qihse_ai_memory_hits_free(hits, n);
    memset(hits, 0, sizeof hits);
    size_t n_plain = qihse_ai_memory_recall_mode(server, op, "keystone", 16u,
                                                 QIHSE_AIMEM_MODE_BM25, hits, 16u);
    assert(n_plain == 4u);
    qihse_ai_memory_hits_free(hits, n_plain);

    /* The filter holds on every ranking mode, not just BM25. */
    static const qihse_ai_memory_mode_t modes[3] = {
        QIHSE_AIMEM_MODE_BM25, QIHSE_AIMEM_MODE_SEMANTIC, QIHSE_AIMEM_MODE_HYBRID
    };
    for (size_t m = 0; m < 3u; m++) {
        n = recall_kind(server, op, "keystone", 16u, modes[m], QIHSE_AIMEM_EPISODIC,
                        hits, 16u, NULL, NULL);
        assert(n == 2u);
        qihse_ai_memory_hits_free(hits, n);
        n = recall_kind(server, op, "keystone", 16u, modes[m], QIHSE_AIMEM_SEMANTIC,
                        hits, 16u, NULL, NULL);
        assert(n == 2u);
        qihse_ai_memory_hits_free(hits, n);
    }
    printf("PASS kind filter narrows recall and count on BM25, SEMANTIC and HYBRID\n");

    /* ── B. an unrecognised kind is refused, not widened to ANY ────────── */
    memset(hits, 0, sizeof hits);
    assert(qihse_ai_memory_recall_kind(server, op, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                                       7u, hits, 16u) == 0u);
    assert(qihse_ai_memory_recall_kind(server, op, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                                       QIHSE_AIMEM_SEMANTIC + 1u, hits, 16u) == 0u);
    assert(qihse_ai_memory_recall_kind(server, op, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                                       0xFFFFFFFFu, hits, 16u) == 0u);
    for (size_t i = 0; i < 16u; i++) assert(hits[i].text == NULL);
    assert(qihse_ai_memory_count_kind(server, op, 7u) == 0u);
    assert(qihse_ai_memory_count_kind(server, op, 0xFFFFFFFFu) == 0u);
    /* ...and the store still refuses ANY as a kind to write. */
    assert(!qihse_ai_memory_store(server, op, "keystone kindless", QIHSE_AIMEM_KIND_ANY,
                                  id_e1));
    printf("PASS unrecognised kind refused (0 hits, 0 count), not defaulted to ANY\n");

    /* ── C. NULL security context fails closed on every new entry point ── */
    memset(hits, 0, sizeof hits);
    assert(qihse_ai_memory_recall_kind(server, NULL, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                                       QIHSE_AIMEM_KIND_ANY, hits, 16u) == 0u);
    assert(qihse_ai_memory_recall_kind(server, NULL, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                                       QIHSE_AIMEM_EPISODIC, hits, 16u) == 0u);
    assert(qihse_ai_memory_recall_kind(server, NULL, "keystone", 16u, QIHSE_AIMEM_MODE_SEMANTIC,
                                       QIHSE_AIMEM_SEMANTIC, hits, 16u) == 0u);
    assert(qihse_ai_memory_recall_kind(NULL, op, "keystone", 16u, QIHSE_AIMEM_MODE_BM25,
                                       QIHSE_AIMEM_EPISODIC, hits, 16u) == 0u);
    for (size_t i = 0; i < 16u; i++) assert(hits[i].text == NULL); /* no payload */
    assert(qihse_ai_memory_count_kind(server, NULL, QIHSE_AIMEM_KIND_ANY) == 0u);
    assert(qihse_ai_memory_count_kind(server, NULL, QIHSE_AIMEM_EPISODIC) == 0u);
    assert(qihse_ai_memory_count_kind(NULL, op, QIHSE_AIMEM_KIND_ANY) == 0u);
    printf("PASS NULL security context fails closed on recall_kind and count_kind\n");

    /* ── D. the kind filter cannot widen the authorization filter ──────── */
    qihse_user_t* analyst = qihse_auth_create_user(op, 7310u, QIHSE_ROLE_ANALYST, 3u,
                                                   0x1u, "AnalystPass123!", false);
    assert(analyst);
    qihse_user_t* guest = qihse_auth_create_user(op, 7311u, QIHSE_ROLE_GUEST, 1u,
                                                 0x0u, "GuestAccount123!", false);
    assert(guest);

    char id_secret_e[QIHSE_AIMEM_ID_LEN + 1u], id_secret_s[QIHSE_AIMEM_ID_LEN + 1u];
    char id_guest_e[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, analyst,
                                 "keystone " MARK_CLASSIFIED " zebra incident note",
                                 QIHSE_AIMEM_EPISODIC, id_secret_e));
    assert(qihse_ai_memory_store(server, analyst,
                                 "keystone " MARK_CLASSIFIED " semantic ledger note",
                                 QIHSE_AIMEM_SEMANTIC, id_secret_s));
    assert(qihse_ai_memory_store(server, guest,
                                 "keystone " MARK_GUEST " own episodic note",
                                 QIHSE_AIMEM_EPISODIC, id_guest_e));

    assert(qihse_ai_memory_count_kind(server, analyst, QIHSE_AIMEM_EPISODIC) >= 1u);
    assert(qihse_ai_memory_count_kind(server, guest, QIHSE_AIMEM_KIND_ANY) == 1u);
    assert(qihse_ai_memory_count_kind(server, guest, QIHSE_AIMEM_EPISODIC) == 1u);
    assert(qihse_ai_memory_count_kind(server, guest, QIHSE_AIMEM_SEMANTIC) == 0u);
    /* A count that adds up: ANY is the two kinds and nothing else. */
    assert(qihse_ai_memory_count_kind(server, guest, QIHSE_AIMEM_KIND_ANY) ==
           qihse_ai_memory_count_kind(server, guest, QIHSE_AIMEM_EPISODIC) +
           qihse_ai_memory_count_kind(server, guest, QIHSE_AIMEM_SEMANTIC));

    /* Every (mode, kind) pair the guest can ask for, including the kind of the
     * record above its clearance: the only thing it may ever see is its own. */
    for (size_t m = 0; m < 3u; m++) {
        static const uint32_t kinds[3] = { QIHSE_AIMEM_KIND_ANY, QIHSE_AIMEM_EPISODIC,
                                           QIHSE_AIMEM_SEMANTIC };
        for (size_t k = 0; k < 3u; k++) {
            bool saw_secret = false;
            n = recall_kind(server, guest, "keystone", 16u, modes[m], kinds[k],
                            hits, 16u, MARK_CLASSIFIED, &saw_secret);
            assert(!saw_secret);
            if (kinds[k] == QIHSE_AIMEM_EPISODIC || kinds[k] == QIHSE_AIMEM_KIND_ANY) {
                assert(n == 1u);
                assert(text_contains(hits[0].text, MARK_GUEST));
            } else {
                /* Filtering BY THE KIND OF THE HIDDEN RECORD reaches nothing. */
                assert(n == 0u);
            }
            qihse_ai_memory_hits_free(hits, n);
        }
    }

    /* A query that only the classified record matches, filtered by that
     * record's own kind: the guest never receives the classified payload. A
     * vector ranking returns candidates regardless of similarity, so the
     * guest's own record may come back here; the classified one never may. */
    for (size_t m = 0; m < 3u; m++) {
        bool saw_secret = false;
        n = recall_kind(server, guest, "zebra", 16u, modes[m], QIHSE_AIMEM_EPISODIC,
                        hits, 16u, MARK_CLASSIFIED, &saw_secret);
        assert(!saw_secret);
        if (modes[m] == QIHSE_AIMEM_MODE_BM25) {
            assert(n == 0u); /* nothing the guest can read contains "zebra" */
        } else {
            assert(n == 1u); /* only the guest's own candidate resolves */
            assert(text_contains(hits[0].text, MARK_GUEST));
        }
        qihse_ai_memory_hits_free(hits, n);
    }
    /* ...while the analyst, who may see it, does get it on every mode. */
    for (size_t m = 0; m < 3u; m++) {
        bool saw_secret = false;
        n = recall_kind(server, analyst, "zebra", 16u, modes[m], QIHSE_AIMEM_EPISODIC,
                        hits, 16u, MARK_CLASSIFIED, &saw_secret);
        assert(saw_secret);
        if (modes[m] == QIHSE_AIMEM_MODE_BM25) assert(n == 1u);
        qihse_ai_memory_hits_free(hits, n);
    }
    /* By id as well: the filter is not a fetch path, and get() is unchanged. */
    qihse_ai_memory_hit_t one;
    memset(&one, 0, sizeof one);
    assert(!qihse_ai_memory_get(server, guest, id_secret_e, &one));
    assert(one.text == NULL);
    printf("PASS kind filter cannot widen authorization: guest gets only its own on every mode/kind\n");

    /* ── E. bounded: a huge limit cannot overflow the caller's buffer ──── */
    /* 7 memories exist at this point: 4 written by the operator, 2 by the
     * analyst above its clearance, 1 by the guest. The operator sees all 7. */
    memset(hits, 0, sizeof hits);
    n = recall_kind(server, op, "keystone", (size_t)-1, QIHSE_AIMEM_MODE_BM25,
                    QIHSE_AIMEM_EPISODIC, hits, 16u, NULL, NULL);
    assert(n == 4u); /* 2 own + 1 analyst + 1 guest, all visible to the operator */
    qihse_ai_memory_hits_free(hits, n);
    n = recall_kind(server, op, "keystone", (size_t)-1, QIHSE_AIMEM_MODE_BM25,
                    QIHSE_AIMEM_KIND_ANY, hits, 16u, NULL, NULL);
    assert(n == 7u);
    qihse_ai_memory_hits_free(hits, n);
    /* A buffer smaller than the match set is respected, and the tail is left
     * untouched (nothing written past the count returned). */
    memset(hits, 0, sizeof hits);
    n = recall_kind(server, op, "keystone", (size_t)-1, QIHSE_AIMEM_MODE_BM25,
                    QIHSE_AIMEM_SEMANTIC, hits, 2u, NULL, NULL);
    assert(n == 2u);
    for (size_t i = n; i < 16u; i++) assert(hits[i].text == NULL);
    qihse_ai_memory_hits_free(hits, n);
    /* limit 0 falls back to the module default (10), still bounded by out_cap. */
    memset(hits, 0, sizeof hits);
    n = recall_kind(server, op, "keystone", 0u, QIHSE_AIMEM_MODE_BM25,
                    QIHSE_AIMEM_KIND_ANY, hits, 16u, NULL, NULL);
    assert(n == 7u);
    qihse_ai_memory_hits_free(hits, n);
    printf("PASS bounded: oversized limit and small buffer both respected\n");

    /* ── F. what is durable and what is not ───────────────────────────── */
    /* Records and vectors are durable (KV + WAL). The FTS index and the vector
     * cache are process-local: they are dropped here and must be re-derived
     * from the KV namespace after the reopen. */
    size_t guest_before = qihse_ai_memory_count_kind(server, guest, QIHSE_AIMEM_KIND_ANY);
    char id_durable[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, analyst,
                                 "keystone durable ledger " MARK_DURABLE " note",
                                 QIHSE_AIMEM_SEMANTIC, id_durable));
    size_t op_after = qihse_ai_memory_count_kind(server, op, QIHSE_AIMEM_KIND_ANY);

    qihse_ai_memory_reset();
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);

    store = qihse_kv_store_create();
    assert(store);
    server = make_server(store, "aimem-ext");
    assert(server);

    memset(&one, 0, sizeof one);
    assert(qihse_ai_memory_get(server, analyst, id_durable, &one));
    assert(text_contains(one.text, MARK_DURABLE));
    free(one.text);
    assert(qihse_ai_memory_count_kind(server, op, QIHSE_AIMEM_KIND_ANY) == op_after);
    assert(qihse_ai_memory_count_kind(server, guest, QIHSE_AIMEM_KIND_ANY) == guest_before);
    bool saw_durable = false;
    n = recall_kind(server, op, "durable", 16u, QIHSE_AIMEM_MODE_BM25,
                    QIHSE_AIMEM_SEMANTIC, hits, 16u, MARK_DURABLE, &saw_durable);
    assert(saw_durable); /* the lazy index rebuild found the durable record */
    qihse_ai_memory_hits_free(hits, n);
    saw_durable = false;
    n = recall_kind(server, op, "durable", 16u, QIHSE_AIMEM_MODE_SEMANTIC,
                    QIHSE_AIMEM_SEMANTIC, hits, 16u, MARK_DURABLE, &saw_durable);
    assert(saw_durable); /* the stored vector reloaded from KV */
    qihse_ai_memory_hits_free(hits, n);
    /* Clearance still holds on the reopened store. */
    n = recall_kind(server, guest, "durable", 16u, QIHSE_AIMEM_MODE_SEMANTIC,
                    QIHSE_AIMEM_SEMANTIC, hits, 16u, MARK_DURABLE, NULL);
    assert(n == 0u);
    qihse_ai_memory_hits_free(hits, n);
    printf("PASS durability: records and vectors survive a reopen, index and vector cache rebuild\n");

    qihse_ai_memory_reset();
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("ai memory extension tests passed\n");
    return 0;
}
