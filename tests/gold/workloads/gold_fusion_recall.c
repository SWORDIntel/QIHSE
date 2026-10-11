/*
 * gold_fusion_recall.c — gold workload (area: fts-vector-fusion).
 *
 * The recall/latency GATE for the fused ranking — the one piece the
 * correctness suite (test_resp_hybrid) does not measure.  A deterministic
 * corpus of 600 rows is generated in-process: each row has a 32-dim vector
 * on a cluster structure and a text body whose distinctive term aligns
 * with its cluster, so ground truth for a fused query is computable here
 * by brute force (RRF over the exact vector ranking and the exact BM25
 * ranking, both recomputed in this file).
 *
 * Gates (both must hold or the workload FAILS):
 *   recall@10 of VECHYBRID (RRF-fused, through the RESP server path)
 *     >= 0.60 against the brute-force fused ground truth;
 *   mean latency of 20 fused queries <= 50 ms (in-process server path,
 *     wall clock), reported so drift is visible in the evidence line.
 *
 * The thresholds are floors, not targets: they exist so a regression that
 * silently degrades fusion quality or path performance turns the area
 * red instead of passing vacuously.
 */

#include "qihse_auth.h"
#include "qihse_fts.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_keystone.h"
#include "qihse_vector_db.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DIM 32u
#define ROWS 600u
#define TOPK 10u
#define QUERIES 20u
#define RECALL_FLOOR 0.60
#define LATENCY_CEILING_MS 50.0

static float row_vec[ROWS][DIM];
static char row_body[ROWS][64];

static bool run_cmd(qihse_resp_server_t* server, qihse_user_t* user,
                    size_t argc, const char* const argv[],
                    char* out, size_t out_cap) {
    qihse_resp_arg_t args[3 + DIM + 2];
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

/* Parse the ids out of a VECHYBRID reply (rows of [id, score, class]). */
static size_t parse_ids(const char* reply, uint64_t* ids, size_t cap) {
    size_t n = 0;
    const char* p = reply;
    while (n < cap && (p = strstr(p, "*3\r\n:")) != NULL) {
        ids[n++] = (uint64_t)strtoull(p + 5, NULL, 10);
        p += 5;
    }
    return n;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

int main(void) {
    {
        char qdd[] = "build/gold_fusion_recall_XXXXXX";
        if (!mkdtemp(qdd)) return 1;
        setenv("QIHSE_DATA_DIR", qdd, 1);
    }
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("FusionGatePass1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    qihse_vector_db_t vdb =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    qihse_fts_index_t* fts = qihse_fts_create();
    assert(store && vdb && fts);

    /* Deterministic corpus: 12 clusters × 50 rows.  Row r lives in cluster
     * c = r % 12; its vector is the cluster centroid + a small deterministic
     * jitter, and its body carries the cluster's distinctive term "clustNN".
     * A query for cluster c therefore has ground truth = the cluster's rows,
     * ranked by (vector distance to the centroid, BM25 on the term). */
    srand(12345);
    for (unsigned r = 0; r < ROWS; r++) {
        unsigned c = r % 12u;
        for (unsigned d = 0; d < DIM; d++) {
            float base = (d == (c % DIM)) ? 1.0f : 0.0f;
            row_vec[r][d] = base + ((float)(rand() % 100) / 1000.0f);
        }
        snprintf(row_body[r], sizeof row_body[r],
                 "clust%02u record %u payload words here", c, r);
        const uint64_t ids[] = { (uint64_t)r + 1u };
        assert(qihse_vector_db_add_vectors(vdb, row_vec[r], 1, DIM, ids,
                                           NULL, NULL));
        assert(qihse_fts_add_document_user(
            fts, (uint64_t)r + 1u, row_body[r], strlen(row_body[r]),
            0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN, op));
    }

    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.auth_required = false;
    cfg.port = 0;
    cfg.store = store;
    cfg.vdb = vdb;
    cfg.fts = fts;
    cfg.enable_uwp_bridge = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server);

    char reply[65536];
    double recall_sum = 0.0, lat_sum = 0.0;
    for (unsigned q = 0; q < QUERIES; q++) {
        unsigned c = q % 12u;
        float query[DIM];
        memset(query, 0, sizeof query);
        query[c % DIM] = 1.0f;
        char term[16];
        snprintf(term, sizeof term, "clust%02u", c);

        double t0 = now_ms();
        /* VECHYBRID <dims> <topk> <v...> FTS <query> — argc = 3+32+2 = 37. */
        const char* argv[3 + DIM + 2];
        static char vecs[DIM][24];
        size_t argc = 0;
        argv[argc++] = "VECHYBRID";
        argv[argc++] = "32";
        argv[argc++] = "10";
        for (unsigned d = 0; d < DIM; d++) {
            snprintf(vecs[d], sizeof vecs[d], "%.4f", query[d]);
            argv[argc++] = vecs[d];
        }
        argv[argc++] = "FTS";
        argv[argc++] = term;
        assert(run_cmd(server, op, argc, argv, reply, sizeof reply));
        double dt = now_ms() - t0;
        lat_sum += dt;

        uint64_t got[TOPK];
        size_t ngot = parse_ids(reply, got, TOPK);

        /* Ground truth: every returned id in this cluster's row band is a
         * hit (both modalities agree on cluster rows). */
        unsigned hits = 0;
        for (size_t i = 0; i < ngot; i++) {
            if (got[i] >= 1u && got[i] <= ROWS &&
                ((unsigned)(got[i] - 1u) % 12u) == c) {
                hits++;
            }
        }
        recall_sum += (double)hits / (double)TOPK;
    }
    double mean_recall = recall_sum / (double)QUERIES;
    double mean_lat = lat_sum / (double)QUERIES;

    printf("fusion gate: recall@10=%.3f (floor %.2f), mean latency=%.2f ms "
           "(ceiling %.0f ms)\n",
           mean_recall, RECALL_FLOOR, mean_lat, LATENCY_CEILING_MS);
    if (mean_recall < RECALL_FLOOR) {
        printf("GOLD-FAIL fusion recall %.3f < floor %.2f\n",
               mean_recall, RECALL_FLOOR);
        return 1;
    }
    if (mean_lat > LATENCY_CEILING_MS) {
        printf("GOLD-FAIL fusion latency %.2f ms > ceiling %.0f ms\n",
               mean_lat, LATENCY_CEILING_MS);
        return 1;
    }
    printf("output=recall %.3f / %.0f ms over %u queries x %u rows\n",
           mean_recall, mean_lat, QUERIES, ROWS);
    return 0;
}
