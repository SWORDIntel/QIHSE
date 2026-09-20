/* tests/test_resp_hybrid.c — hybrid FTS+vector fusion through the RESP
 * server path (VECHYBRID).
 *
 * The fusion primitive (qihse_vector_db_search_multimodal) was verified
 * in-process; this test drives it through the protocol surface and checks:
 *
 *   - a real fused result set: vector-nearest and BM25-ranked docs merge
 *     under RRF, each row carrying [id, score, semantic class];
 *   - the FTS clause is required and an unconfigured FTS index is an
 *     explicit error, never a silent vector-only fallback;
 *   - AGENTS.md invariant 3: a low-clearance principal does NOT see a
 *     document indexed above its clearance, through the fused path.
 */
#include "qihse_resp_wire.h"
#include "qihse_fusion.h"
#include "qihse_fts.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static qihse_resp_server_t* g_server;

static bool run_cmd(qihse_user_t* user, size_t argc, const char* const* argv,
                    char* out, size_t out_cap) {
    qihse_resp_arg_t args[16];
    assert(argc <= 16u);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (char*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t* reply = NULL;
    size_t reply_len = 0;
    if (!qihse_resp_server_execute(g_server, user, argc, args,
                                   &reply, &reply_len)) {
        return false;
    }
    size_t n = reply_len < out_cap - 1u ? reply_len : out_cap - 1u;
    memcpy(out, reply, n);
    out[n] = '\0';
    free(reply);
    return true;
}

/* True when the RESP reply contains a row whose first field is `:id`. */
static bool reply_has_id(const char* reply, uint64_t id) {
    char needle[32];
    snprintf(needle, sizeof needle, "*3\r\n:%llu\r\n", (unsigned long long)id);
    return strstr(reply, needle) != NULL;
}

int main(void) {
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);

    qihse_kv_store_t* store = qihse_kv_store_create();
    qihse_vector_db_t vdb =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    qihse_fts_index_t* fts = qihse_fts_create();
    assert(store && vdb && fts);

    /* Corpus: ids are shared between the vector db and the FTS index.
     * Vector rows carry no classification (they are UNCLASSIFIED by
     * construction — see the VECSET collection note in the engine), so the
     * classified document gets NO vector: its only fused-path entry is the
     * FTS modality, which enforces the caller's clearance. */
    const float v[][4] = {
        {1.0f, 0.0f, 0.0f, 0.0f},   /* 1: vector-near AND fts hit */
        {0.0f, 1.0f, 0.0f, 0.0f},   /* 2: fts hit, vector-far */
        {0.9f, 0.1f, 0.0f, 0.0f},   /* 3: vector-near, no fts term */
    };
    for (uint64_t i = 1; i <= 3; i++) {
        const uint64_t ids[] = { i };
        assert(qihse_vector_db_add_vectors(vdb, v[i - 1], 1, 4, ids,
                                           NULL, NULL));
    }
    const char* docs[] = {
        "supply chain provenance ledger entry",
        "fleet telemetry heartbeat frame",
        "unrelated catalogue blurb",
        "supply chain classified annex",
    };
    const uint16_t cls[] = { 0, 0, 0, 2 };
    const qihse_keystone_class_t kls[] = {
        QIHSE_KEYSTONE_CLASS_GOVERNMENT, QIHSE_KEYSTONE_CLASS_CONSUMER,
        QIHSE_KEYSTONE_CLASS_CONSUMER, QIHSE_KEYSTONE_CLASS_GOVERNMENT,
    };
    for (uint64_t i = 1; i <= 4; i++) {
        assert(qihse_fts_add_document_user(fts, i, docs[i - 1],
                                           strlen(docs[i - 1]), cls[i - 1], 0,
                                           kls[i - 1], op));
    }

    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.auth_required = false;
    cfg.port = 0;
    cfg.store = store;
    cfg.vdb = vdb;
    cfg.fts = fts;
    cfg.enable_uwp_bridge = true;  /* qihse_resp_server_execute requires it */
    g_server = qihse_resp_server_create(&cfg);
    assert(g_server != NULL);

    char reply[65536];

    /* ── fused path returns real merged rows ─────────────────────────── */
    const char* hyb[] = { "VECHYBRID", "4", "3", "1", "0", "0", "0",
                          "FTS", "supply chain" };
    assert(run_cmd(op, 9u, hyb, reply, sizeof reply));
    assert(reply[0] == '*');
    /* Doc 1 is both vector-nearest and an FTS hit → definitely present. */
    assert(reply_has_id(reply, 1));
    /* Doc 3 is vector-near but not an FTS hit → vector modality surfaces it. */
    assert(reply_has_id(reply, 3));
    /* Rows carry [id, score, class]: every row is a 3-element array. */
    assert(strstr(reply, "*3\r\n") != NULL);
    printf("PASS vechybrid: fused vector+FTS result set over RESP\n");

    /* ── the FTS clause is required; missing/unconfigured is explicit ── */
    const char* nofts[] = { "VECHYBRID", "4", "3", "1", "0", "0", "0" };
    assert(run_cmd(op, 7u, nofts, reply, sizeof reply));
    assert(strstr(reply, "ERR") != NULL);

    qihse_resp_server_config_t cfg2;
    qihse_resp_server_config_init(&cfg2);
    cfg2.auth_required = false;
    cfg2.port = 0;
    cfg2.store = store;
    cfg2.vdb = vdb;
    cfg2.enable_uwp_bridge = true;
    qihse_resp_server_t* nofts_server = qihse_resp_server_create(&cfg2);
    assert(nofts_server != NULL);
    {
        /* Temporarily repoint g_server at the FTS-less server. */
        qihse_resp_server_t* keep = g_server;
        g_server = nofts_server;
        assert(run_cmd(op, 9u, hyb, reply, sizeof reply));
        assert(strstr(reply, "full-text index is not configured") != NULL);
        g_server = keep;
    }
    qihse_resp_server_destroy(nofts_server);
    printf("PASS vechybrid: missing FTS clause / unconfigured index are "
           "explicit errors\n");

    /* ── low-clearance principal does not see the classified doc ─────── */
    qihse_user_t* low = qihse_auth_create_user(op, 77u, QIHSE_ROLE_ANALYST,
                                               0u, 0u, "LowPass12345!", false);
    assert(low != NULL);
    /* The operator sees doc 4 (classification 2, term-matched). */
    assert(run_cmd(op, 9u, hyb, reply, sizeof reply));
    assert(reply_has_id(reply, 4));
    /* The low-clearance user does not, through the same fused command. */
    assert(run_cmd(low, 9u, hyb, reply, sizeof reply));
    assert(!reply_has_id(reply, 4));
    printf("PASS vechybrid: classified doc filtered out for low-clearance "
           "principal (invariant 3)\n");

    /* ── qihse_index_bytes{index="hnsw"} is emitted by the same server ── */
    {
        const char* rend[] = { "METRICS.RENDER" };
        assert(run_cmd(op, 1u, rend, reply, sizeof reply));
        assert(strstr(reply, "qihse_index_bytes{index=\"hnsw\"}") != NULL);
        /* The FTS backend reports real availability now that config.fts
         * exists — previously it was pinned at 0 regardless. */
        assert(strstr(reply, "qihse_backend_available{backend=\"fts\"} 1")
               != NULL);
        printf("PASS vechybrid: index-bytes + backend-availability metrics "
               "emitted\n");
    }

    qihse_resp_server_destroy(g_server);
    qihse_fts_destroy(fts);
    qihse_kv_store_destroy(store);
    printf("test_resp_hybrid: all hybrid FTS+vector server-path tests passed\n");
    return 0;
}
