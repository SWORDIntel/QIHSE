/*
 * test_ai_memory_embed.c — embedding-backed semantic recall (ai_fabric.md §5).
 *
 * The claims under test:
 *
 *   1. The semantic path is REAL, not lexical in disguise. A provider that
 *      maps two lexically-disjoint words to the same vector must make a query
 *      match a document that shares NO tokens with it. If this test passed
 *      with the built-in lexical embedder alone, it would be proving nothing.
 *   2. Clearance filtering holds on EVERY ranking mode. An embedding is
 *      derived from the text and can leak it, so a semantic search that
 *      skipped the visibility filter would be an exfiltration path.
 *   3. Vectors from different providers are never compared. Embeddings from
 *      different models are not comparable, and comparing them yields
 *      confident nonsense rather than an error.
 *   4. Forgetting a memory drops its vector, so it cannot keep consuming a
 *      candidate slot and push a visible memory out of the top-k.
 *   5. A provider that cannot embed is refused, rather than silently
 *      degrading semantic recall to lexical while reporting semantic.
 */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── A provider whose vectors are lexical-independent ──────────────────── */

/* Maps a fixed vocabulary so that "alpha" and "beta" are IDENTICAL vectors
 * despite sharing no characters. A query for "alpha" must therefore match a
 * document containing only "beta" — which no lexical ranking can do. */
#define SYN_DIM 8u
static bool syn_embed(const char* text, float* out, size_t dim, void* ctx) {
    (void)ctx;
    if (!text || !out || dim != SYN_DIM) return false;
    memset(out, 0, dim * sizeof(float));
    if (strstr(text, "alpha") || strstr(text, "beta")) {
        out[0] = 1.0f;               /* the synonym group */
    } else if (strstr(text, "gamma")) {
        out[1] = 1.0f;               /* an unrelated group */
    } else {
        out[2] = 1.0f;               /* everything else is mutually similar */
    }
    return true;
}

static const qihse_ai_memory_embedder_t g_syn = {
    "test-synonym-8", SYN_DIM, syn_embed, NULL
};

/* A provider that always fails, to prove it is refused rather than installed. */
static bool broken_embed(const char* t, float* o, size_t d, void* c) {
    (void)t; (void)o; (void)d; (void)c;
    return false;
}

static size_t recall(qihse_resp_server_t* s, qihse_user_t* u, const char* q,
                     qihse_ai_memory_mode_t m, qihse_ai_memory_hit_t* hits,
                     size_t cap) {
    size_t n = qihse_ai_memory_recall_mode(s, u, q, cap, m, hits, cap);
    return n;
}

int main(void) {
    char data_root[] = "build/aimem_embed_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("aimem-embed", strlen("aimem-embed"), node_id);
    scfg.node_id = node_id;
    scfg.auth_required = false;
    scfg.port = 0;
    scfg.store = store;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    assert(server);

    /* ── the built-in provider is honest about being lexical ───────────── */
    assert(strcmp(qihse_ai_memory_embedder_name(), "builtin-lexical-256") == 0);
    assert(qihse_ai_memory_embedding_dim() == 256u);
    printf("PASS builtin provider: named for what it is, dim %zu\n",
           qihse_ai_memory_embedding_dim());

    /* ── a provider that cannot embed is REFUSED ──────────────────────── */
    /* Install-time validation catches what is checkable at install time: a
     * missing embed function, a missing name, an out-of-range dimension. It
     * cannot know whether a function pointer WORKS — that is a runtime
     * question, covered separately below. */
    qihse_ai_memory_embedder_t nofn = { "nofn", 8u, NULL, NULL };
    assert(!qihse_ai_memory_set_embedder(&nofn));
    /* Still the built-in: a refusal must not half-install. */
    assert(strcmp(qihse_ai_memory_embedder_name(), "builtin-lexical-256") == 0);
    qihse_ai_memory_embedder_t noname = { "", 8u, syn_embed, NULL };
    assert(!qihse_ai_memory_set_embedder(&noname));
    qihse_ai_memory_embedder_t toowide = { "wide", QIHSE_AIMEM_MAX_DIM + 1u, syn_embed, NULL };
    assert(!qihse_ai_memory_set_embedder(&toowide));
    qihse_ai_memory_embedder_t zerodim = { "zero", 0u, syn_embed, NULL };
    assert(!qihse_ai_memory_set_embedder(&zerodim));
    printf("PASS provider validation: an unusable provider is refused, not half-installed\n");

    /* A provider whose embed function FAILS AT RUNTIME is a different case and
     * must degrade rather than crash or lie: semantic recall yields no vector
     * candidates, and lexical recall is unaffected. */
    {
        qihse_ai_memory_embedder_t flaky = { "test-flaky-8", SYN_DIM, broken_embed, NULL };
        assert(qihse_ai_memory_set_embedder(&flaky));
        qihse_ai_memory_reset();
        char id_flaky[QIHSE_AIMEM_ID_LEN + 1u];
        assert(qihse_ai_memory_store(server, op, "delta", QIHSE_AIMEM_SEMANTIC, id_flaky));
        qihse_ai_memory_hit_t fh[4];
        memset(fh, 0, sizeof fh);
        assert(recall(server, op, "delta", QIHSE_AIMEM_MODE_SEMANTIC, fh, 4u) == 0u);
        qihse_ai_memory_hits_free(fh, 0u);
        /* Lexical is untouched by the embedder failing. */
        memset(fh, 0, sizeof fh);
        size_t fn = recall(server, op, "delta", QIHSE_AIMEM_MODE_BM25, fh, 4u);
        assert(fn >= 1u);
        qihse_ai_memory_hits_free(fh, fn);
        assert(qihse_ai_memory_set_embedder(NULL));
        qihse_ai_memory_reset();
        printf("PASS runtime embed failure: semantic degrades to no vector candidates, lexical unaffected\n");
    }

    /* ── install the synonym provider ─────────────────────────────────── */
    assert(qihse_ai_memory_set_embedder(&g_syn));
    assert(strcmp(qihse_ai_memory_embedder_name(), "test-synonym-8") == 0);
    assert(qihse_ai_memory_embedding_dim() == SYN_DIM);

    char id_beta[QIHSE_AIMEM_ID_LEN + 1u];
    char id_gamma[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, op, "beta", QIHSE_AIMEM_SEMANTIC, id_beta));
    assert(qihse_ai_memory_store(server, op, "gamma", QIHSE_AIMEM_SEMANTIC, id_gamma));

    /* ── 1. the semantic path is real ─────────────────────────────────── */
    qihse_ai_memory_hit_t hits[8];
    memset(hits, 0, sizeof hits);
    size_t n = recall(server, op, "alpha", QIHSE_AIMEM_MODE_SEMANTIC, hits, 8u);
    assert(n >= 1u);
    /* "alpha" shares no characters with "beta" — only the embedding relates
     * them, so a lexical ranking could not have produced this hit. */
    assert(strcmp(hits[0].text, "beta") == 0);
    assert(hits[0].score > 0.9); /* identical unit vectors */
    qihse_ai_memory_hits_free(hits, n);

    /* The same query lexically finds nothing, which is the contrast that
     * makes the assertion above meaningful. */
    memset(hits, 0, sizeof hits);
    n = recall(server, op, "alpha", QIHSE_AIMEM_MODE_BM25, hits, 8u);
    assert(n == 0u);
    qihse_ai_memory_hits_free(hits, n);
    printf("PASS semantic is real: 'alpha' matches 'beta' semantically and nothing lexically\n");

    /* ── 2. clearance filtering holds on every mode ───────────────────── */
    qihse_user_t* analyst = qihse_auth_create_user(op, 5310u, QIHSE_ROLE_ANALYST, 3u,
                                                   0x1u, "AnalystPass123!", false);
    assert(analyst);
    qihse_user_t* guest = qihse_auth_create_user(op, 5311u, QIHSE_ROLE_GUEST, 1u,
                                                 0x0u, "GuestAccount123!", false);
    assert(guest);

    char id_secret[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, analyst, "beta SECRET-CLEARANCE-MARKER",
                                 QIHSE_AIMEM_SEMANTIC, id_secret));

    /* The analyst's memory is the closest vector to "alpha" — it contains
     * "beta". A semantic search that skipped the visibility filter would
     * return it to the guest. */
    memset(hits, 0, sizeof hits);
    n = recall(server, guest, "alpha", QIHSE_AIMEM_MODE_SEMANTIC, hits, 8u);
    assert(n == 0u);
    for (size_t i = 0; i < n; i++) assert(hits[i].text == NULL);
    qihse_ai_memory_hits_free(hits, n);

    memset(hits, 0, sizeof hits);
    n = recall(server, guest, "alpha", QIHSE_AIMEM_MODE_HYBRID, hits, 8u);
    assert(n == 0u);
    qihse_ai_memory_hits_free(hits, n);

    /* And the analyst does see their own. */
    memset(hits, 0, sizeof hits);
    n = recall(server, analyst, "alpha", QIHSE_AIMEM_MODE_SEMANTIC, hits, 8u);
    assert(n >= 1u);
    bool saw_secret = false;
    for (size_t i = 0; i < n; i++) {
        if (strstr(hits[i].text, "SECRET-CLEARANCE-MARKER")) saw_secret = true;
    }
    assert(saw_secret);
    qihse_ai_memory_hits_free(hits, n);
    printf("PASS clearance on semantic: guest gets 0 hits where the nearest vector is above its clearance\n");

    /* ── 3. vectors from another provider are not compared ────────────── */
    /* Switch provider. The stored vectors were produced by test-synonym-8 and
     * must not be compared against a query embedded by the built-in one. */
    assert(qihse_ai_memory_set_embedder(NULL));
    qihse_ai_memory_reset(); /* drop the loaded vectors so they reload filtered */
    memset(hits, 0, sizeof hits);
    n = recall(server, op, "alpha", QIHSE_AIMEM_MODE_SEMANTIC, hits, 8u);
    /* "beta" exists and is visible, but its vector is from another provider,
     * so it must not be scored. A dimension mismatch alone would also catch
     * this; the provider NAME is what makes it explicit. */
    for (size_t i = 0; i < n; i++) {
        assert(strcmp(hits[i].text, "beta") != 0);
    }
    qihse_ai_memory_hits_free(hits, n);
    printf("PASS provider binding: vectors from another provider are never scored\n");

    /* ── 4. forgetting drops the vector ───────────────────────────────── */
    assert(qihse_ai_memory_set_embedder(&g_syn));
    qihse_ai_memory_reset();
    assert(qihse_ai_memory_forget(server, op, id_beta));
    memset(hits, 0, sizeof hits);
    n = recall(server, op, "alpha", QIHSE_AIMEM_MODE_SEMANTIC, hits, 8u);
    for (size_t i = 0; i < n; i++) {
        assert(strcmp(hits[i].text, "beta") != 0);
    }
    qihse_ai_memory_hits_free(hits, n);
    printf("PASS forget: a forgotten memory stops ranking semantically\n");

    /* ── 5. hybrid fuses both rank lists ──────────────────────────────── */
    memset(hits, 0, sizeof hits);
    n = recall(server, op, "gamma", QIHSE_AIMEM_MODE_HYBRID, hits, 8u);
    assert(n >= 1u);
    assert(strcmp(hits[0].text, "gamma") == 0);
    qihse_ai_memory_hits_free(hits, n);
    printf("PASS hybrid: fuses lexical and vector ranks\n");

    /* An unknown mode is refused rather than silently defaulting. */
    memset(hits, 0, sizeof hits);
    assert(qihse_ai_memory_recall_mode(server, op, "gamma", 8u,
                                       (qihse_ai_memory_mode_t)99, hits, 8u) == 0u);
    printf("PASS unknown mode refused rather than defaulted\n");

    qihse_ai_memory_reset();
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("ai memory embedding tests passed\n");
    return 0;
}
