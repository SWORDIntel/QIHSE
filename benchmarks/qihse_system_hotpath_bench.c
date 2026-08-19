/**
 * QIHSE Comprehensive System & Hot-Path Benchmark Suite
 * ======================================================
 * Profiles all key engine subsystems:
 *  1. Vector DB: Exact float32 SIMD reranking, Cosine / Euclidean distance math
 *  2. Key-Value Store: Trinary Trie in-memory indexing vs point lookups
 *  3. SQLite VFS: Page cache read/write latency & bulk transaction insert rate
 *  4. Columnar OLAP: Vectorized aggregations & scan bandwidth
 *  5. Time-Series: Gorilla XOR delta compression ingestion
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <sqlite3.h>

#include "include/qihse_vector_db.h"
#include "include/qihse_kv_store.h"
#include "include/qihse_column.h"
#include "include/qihse_timeseries.h"
#include "persistence/qihse_sqlite_vfs.h"

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void* a, const void* b) {
    uint64_t va = *(const uint64_t*)a;
    uint64_t vb = *(const uint64_t*)b;
    return (va > vb) - (va < vb);
}

typedef struct {
    uint64_t* samples;
    size_t count;
    size_t capacity;
} bench_tracker_t;

static void tracker_init(bench_tracker_t* t, size_t cap) {
    t->samples = (uint64_t*)malloc(cap * sizeof(uint64_t));
    t->count = 0;
    t->capacity = cap;
}

static void tracker_add(bench_tracker_t* t, uint64_t val) {
    if (t->count < t->capacity) {
        t->samples[t->count++] = val;
    }
}

static void tracker_report(const char* name, bench_tracker_t* t, const char* unit, double scale) {
    if (t->count == 0) return;
    qsort(t->samples, t->count, sizeof(uint64_t), cmp_u64);
    double sum = 0;
    for (size_t i = 0; i < t->count; i++) sum += (double)t->samples[i];
    double mean = sum / t->count;
    double p50 = (double)t->samples[(size_t)(t->count * 0.50)];
    double p95 = (double)t->samples[(size_t)(t->count * 0.95)];
    double p99 = (double)t->samples[(size_t)(t->count * 0.99)];
    double min_v = (double)t->samples[0];
    double max_v = (double)t->samples[t->count - 1];

    printf("  %-38s : mean=%7.2f %s | p50=%7.2f | p95=%7.2f | p99=%7.2f | [min=%5.2f, max=%7.2f]\n",
           name, mean * scale, unit, p50 * scale, p95 * scale, p99 * scale, min_v * scale, max_v * scale);
}

static void tracker_free(bench_tracker_t* t) {
    free(t->samples);
}

/* =========================================================================
 * 1. Vector Search Hot-Path Benchmark
 * ========================================================================= */
static void bench_vector_engine(void) {
    printf("\n[1] Vector DB Subsystem (Exact float32 SIMD vs Distance Metrics)\n");
    printf("-----------------------------------------------------------------------\n");

    const size_t N_VECS = 10000;
    const size_t DIMS = 128;
    const size_t N_QUERIES = 200;

    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        printf("Failed to create Vector DB\n");
        return;
    }

    float* vecs = (float*)malloc(N_VECS * DIMS * sizeof(float));
    uint64_t* ids = (uint64_t*)malloc(N_VECS * sizeof(uint64_t));
    for (size_t i = 0; i < N_VECS; i++) {
        ids[i] = i + 1;
        for (size_t d = 0; d < DIMS; d++) {
            vecs[i * DIMS + d] = (float)rand() / (float)RAND_MAX;
        }
    }
    qihse_vector_db_add_vectors(vdb, vecs, N_VECS, DIMS, ids, NULL, NULL);

    float* queries = (float*)malloc(N_QUERIES * DIMS * sizeof(float));
    for (size_t i = 0; i < N_QUERIES * DIMS; i++) {
        queries[i] = (float)rand() / (float)RAND_MAX;
    }

    qihse_vector_result_t results[10];
    bench_tracker_t t_cosine, t_dot, t_euclid;
    tracker_init(&t_cosine, N_QUERIES);
    tracker_init(&t_dot, N_QUERIES);
    tracker_init(&t_euclid, N_QUERIES);

    for (size_t q = 0; q < N_QUERIES; q++) {
        qihse_vector_query_t query = {
            .query_vector = &queries[q * DIMS],
            .vector_dims = DIMS,
            .top_k = 10,
            .distance_metric = QIHSE_DISTANCE_COSINE,
            .query_mode = QIHSE_VDB_QUERY_FLOAT32
        };

        uint64_t t0 = get_time_ns();
        qihse_vector_db_search(vdb, &query, results, 10);
        uint64_t t1 = get_time_ns();
        tracker_add(&t_cosine, t1 - t0);

        query.distance_metric = QIHSE_DISTANCE_DOT_PRODUCT;
        t0 = get_time_ns();
        qihse_vector_db_search(vdb, &query, results, 10);
        t1 = get_time_ns();
        tracker_add(&t_dot, t1 - t0);

        query.distance_metric = QIHSE_DISTANCE_EUCLIDEAN;
        t0 = get_time_ns();
        qihse_vector_db_search(vdb, &query, results, 10);
        t1 = get_time_ns();
        tracker_add(&t_euclid, t1 - t0);
    }

    tracker_report("Exact Cosine Rerank (10k x 128f)", &t_cosine, "us", 1e-3);
    tracker_report("Exact Dot-Product (10k x 128f)", &t_dot, "us", 1e-3);
    tracker_report("Exact L2 Euclidean (10k x 128f)", &t_euclid, "us", 1e-3);

    tracker_free(&t_cosine);
    tracker_free(&t_dot);
    tracker_free(&t_euclid);

    free(vecs);
    free(ids);
    free(queries);
    qihse_vector_db_destroy(vdb);
}

/* =========================================================================
 * 2. Key-Value Store (Black Hole & Trinary Trie) Benchmark
 * ========================================================================= */
static void bench_kv_engine(void) {
    printf("\n[2] Black Hole KV Store (Trinary Trie Indexing & Memory Lookups)\n");
    printf("-----------------------------------------------------------------------\n");

    qihse_kv_store_t* store = qihse_kv_store_create();
    if (!store) {
        printf("Failed to create KV store\n");
        return;
    }

    const size_t N_SYNC = 5000;
    const size_t N_BULK = 50000;
    bench_tracker_t t_sync_set, t_bulk_set, t_lookup;
    tracker_init(&t_sync_set, N_SYNC);
    tracker_init(&t_bulk_set, N_BULK);
    tracker_init(&t_lookup, N_BULK);

    char key_buf[64];
    char val_buf[128];

    // 1. Sync WAL Set benchmark
    uint64_t t_sync_start = get_time_ns();
    for (size_t i = 0; i < N_SYNC; i++) {
        snprintf(key_buf, sizeof(key_buf), "user:sync:acc_%08zu", i);
        snprintf(val_buf, sizeof(val_buf), "{\"id\":%zu,\"status\":\"active\"}", i);

        uint64_t t0 = get_time_ns();
        qihse_kv_set(store, key_buf, val_buf, 0, 0);
        uint64_t t1 = get_time_ns();
        tracker_add(&t_sync_set, t1 - t0);
    }
    uint64_t t_sync_end = get_time_ns();
    double sync_sec = (double)(t_sync_end - t_sync_start) / 1e9;
    double sync_ops = (double)N_SYNC / sync_sec;

    // 2. In-Memory Bulk Trie Set benchmark
    qihse_kv_bulk_load_begin(store);
    uint64_t t_bulk_start = get_time_ns();
    for (size_t i = 0; i < N_BULK; i++) {
        snprintf(key_buf, sizeof(key_buf), "user:bulk:acc_%08zu", i);
        snprintf(val_buf, sizeof(val_buf), "{\"id\":%zu,\"status\":\"active\"}", i);

        uint64_t t0 = get_time_ns();
        qihse_kv_set(store, key_buf, val_buf, 0, 0);
        uint64_t t1 = get_time_ns();
        tracker_add(&t_bulk_set, t1 - t0);
    }
    uint64_t t_bulk_end = get_time_ns();
    qihse_kv_bulk_load_end(store);
    double bulk_sec = (double)(t_bulk_end - t_bulk_start) / 1e9;
    double bulk_ops = (double)N_BULK / bulk_sec;

    // 3. KV Store Point Lookup benchmark (with CNSA 2.0 / QDD Guard)
    uint64_t t_read_start = get_time_ns();
    for (size_t i = 0; i < N_BULK; i++) {
        snprintf(key_buf, sizeof(key_buf), "user:bulk:acc_%08zu", i);

        uint64_t t0 = get_time_ns();
        char* val = qihse_kv_get_user(store, key_buf, NULL);
        uint64_t t1 = get_time_ns();
        tracker_add(&t_lookup, t1 - t0);
        if (val) free(val);
    }
    uint64_t t_read_end = get_time_ns();
    double total_read_sec = (double)(t_read_end - t_read_start) / 1e9;
    double read_ops = (double)N_BULK / total_read_sec;

    // 4. Raw Trinary Trie Search (Zero-Defense Pure Engine Math)
    qihse_trinary_trie_t* raw_trie = qihse_trinary_trie_create();
    for (size_t i = 0; i < N_BULK; i++) {
        snprintf(key_buf, sizeof(key_buf), "user:raw:acc_%08zu", i);
        snprintf(val_buf, sizeof(val_buf), "raw_value_%zu", i);
        qihse_trinary_trie_insert(raw_trie, key_buf, val_buf, strlen(val_buf) + 1);
    }
    bench_tracker_t t_raw_trie;
    tracker_init(&t_raw_trie, N_BULK);
    for (size_t i = 0; i < N_BULK; i++) {
        snprintf(key_buf, sizeof(key_buf), "user:raw:acc_%08zu", i);
        uint64_t t0 = get_time_ns();
        size_t sz = 0;
        void* val = qihse_trinary_trie_search(raw_trie, key_buf, &sz);
        uint64_t t1 = get_time_ns();
        (void)val;
        tracker_add(&t_raw_trie, t1 - t0);
    }
    double raw_trie_sum = 0;
    for (size_t i = 0; i < t_raw_trie.count; i++) raw_trie_sum += (double)t_raw_trie.samples[i];
    double raw_trie_ops = (double)N_BULK / (raw_trie_sum / 1e9);

    printf("  Sync WAL Set Ingress Throughput       : %10.0f ops/sec (%zu writes in %.3f s)\n", sync_ops, N_SYNC, sync_sec);
    printf("  In-Memory Trie Set Throughput         : %10.0f ops/sec (%zu writes in %.3f s)\n", bulk_ops, N_BULK, bulk_sec);
    printf("  KV Get with QDD / CNSA 2.0 Guard      : %10.0f ops/sec (%zu reads in %.3f s)\n", read_ops, N_BULK, total_read_sec);
    printf("  Raw Trinary Trie Search Throughput    : %10.0f ops/sec (%zu queries in %.3f s)\n", raw_trie_ops, N_BULK, raw_trie_sum / 1e9);
    tracker_report("KV Set Latency (Sync WAL)", &t_sync_set, "us", 1e-3);
    tracker_report("KV Set Latency (In-Memory Trie)", &t_bulk_set, "us", 1e-3);
    tracker_report("KV Get Latency (with QDD Guard)", &t_lookup, "us", 1e-3);
    tracker_report("Raw Trinary Trie Search Latency", &t_raw_trie, "ns", 1.0);

    tracker_free(&t_sync_set);
    tracker_free(&t_bulk_set);
    tracker_free(&t_lookup);
    tracker_free(&t_raw_trie);
    qihse_trinary_trie_destroy(raw_trie);
    qihse_kv_store_destroy(store);
}

/* =========================================================================
 * 3. SQLite VFS Performance Benchmark
 * ========================================================================= */
static void bench_sqlite_vfs_engine(void) {
    printf("\n[3] SQLite VFS Storage Engine (Page Cache & Transaction Routing)\n");
    printf("-----------------------------------------------------------------------\n");

    qihse_vfs_register(0);

    const char* db_file = "file:bench_vfs_temp.db?vfs=qihse";
    sqlite3* db = NULL;
    int rc = sqlite3_open_v2(db_file, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to open SQLite VFS database: %s\n", sqlite3_errmsg(db));
        return;
    }

    char* err = NULL;
    sqlite3_exec(db, "PRAGMA synchronous = OFF;", NULL, NULL, &err);
    sqlite3_exec(db, "PRAGMA journal_mode = MEMORY;", NULL, NULL, &err);
    sqlite3_exec(db, "CREATE TABLE intel_events (id INTEGER PRIMARY KEY, target TEXT, score REAL, payload TEXT);", NULL, NULL, &err);

    const size_t N_ROWS = 10000;
    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, "INSERT INTO intel_events VALUES (?, ?, ?, ?);", -1, &stmt, NULL);

    uint64_t t_tx_start = get_time_ns();
    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, &err);

    for (size_t i = 0; i < N_ROWS; i++) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)i);
        sqlite3_bind_text(stmt, 2, "target_channel_recon", -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 3, 0.9452);
        sqlite3_bind_text(stmt, 4, "{\"event\":\"telegram_forward\",\"src\":8011484242,\"dst\":1042918}", -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }

    sqlite3_exec(db, "COMMIT;", NULL, NULL, &err);
    uint64_t t_tx_end = get_time_ns();
    sqlite3_finalize(stmt);

    double duration_s = (double)(t_tx_end - t_tx_start) / 1e9;
    double tx_rate = (double)N_ROWS / duration_s;
    printf("  Batch Insert Rate (10k rows in tx)    : %10.0f rows/sec (%.3f s)\n", tx_rate, duration_s);

    // Read point queries
    bench_tracker_t t_query;
    tracker_init(&t_query, 1000);
    sqlite3_prepare_v2(db, "SELECT target, score FROM intel_events WHERE id = ?;", -1, &stmt, NULL);

    for (size_t q = 0; q < 1000; q++) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)(q * 9));
        uint64_t t0 = get_time_ns();
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            (void)sqlite3_column_text(stmt, 0);
            (void)sqlite3_column_double(stmt, 1);
        }
        uint64_t t1 = get_time_ns();
        tracker_add(&t_query, t1 - t0);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    tracker_report("Indexed Select Latency (VFS Cached)", &t_query, "us", 1e-3);
    tracker_free(&t_query);

    remove("bench_vfs_temp.db");
    remove("bench_vfs_temp.db.qlock");
}

/* =========================================================================
 * 4. Columnar OLAP Engine (Vectorized Aggregations & Scans)
 * ========================================================================= */
static void bench_columnar_engine(void) {
    printf("\n[4] Columnar OLAP Engine (SIMD Page Aggregations & Column Scans)\n");
    printf("-----------------------------------------------------------------------\n");

    qihse_column_store_t* col_store = qihse_column_store_create();
    if (!col_store) {
        printf("Failed to create column store\n");
        return;
    }

    const char* col_name = "gmv_amount";
    qihse_column_create(col_store, col_name, QIHSE_COL_TYPE_FLOAT32);

    const size_t N_ELEMS = 50000;
    for (size_t i = 0; i < N_ELEMS; i++) {
        qihse_column_append_float32(col_store, col_name, (float)(i % 500) * 1.5f, 0, 0);
    }

    bench_tracker_t t_sum;
    tracker_init(&t_sum, 100);

    for (int iter = 0; iter < 100; iter++) {
        uint64_t t0 = get_time_ns();
        float sum = qihse_column_sum_float32_user(col_store, col_name, NULL);
        uint64_t t1 = get_time_ns();
        (void)sum;
        tracker_add(&t_sum, t1 - t0);
    }

    tracker_report("SIMD Sum Aggregation (50,000 float32)", &t_sum, "us", 1e-3);
    tracker_free(&t_sum);
    qihse_column_store_destroy(col_store);
}

/* =========================================================================
 * 5. Time-Series Telemetry (Gorilla XOR Compression)
 * ========================================================================= */
static void bench_timeseries_engine(void) {
    printf("\n[5] Time-Series Subsystem (Gorilla XOR Ingestion & Range Aggregation)\n");
    printf("-----------------------------------------------------------------------\n");

    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    if (!tsdb) {
        printf("Failed to create timeseries store\n");
        return;
    }

    const size_t N_PTS = 20000;
    bench_tracker_t t_pts;
    tracker_init(&t_pts, N_PTS);

    uint64_t base_ts = 1700000000000ULL;
    double base_val = 142.50;

    uint64_t t_start = get_time_ns();
    for (size_t i = 0; i < N_PTS; i++) {
        uint64_t cur_ts = base_ts + i * 1000;
        double cur_val = base_val + sin((double)i * 0.05) * 2.0;

        uint64_t t0 = get_time_ns();
        qihse_tsdb_insert(tsdb, 1, cur_ts, cur_val, 0, 0);
        uint64_t t1 = get_time_ns();
        tracker_add(&t_pts, t1 - t0);
    }
    uint64_t t_end = get_time_ns();

    double total_sec = (double)(t_end - t_start) / 1e9;
    double pts_per_sec = (double)N_PTS / total_sec;
    printf("  Point Ingestion Rate                  : %10.0f points/sec (%zu points in %.3f s)\n", pts_per_sec, N_PTS, total_sec);
    tracker_report("Per-Point Ingestion Latency", &t_pts, "us", 1e-3);

    // Range query
    bench_tracker_t t_range;
    tracker_init(&t_range, 100);
    for (int iter = 0; iter < 100; iter++) {
        uint64_t t0 = get_time_ns();
        double avg = qihse_tsdb_average_range_user(tsdb, base_ts, base_ts + 10000000ULL, NULL);
        uint64_t t1 = get_time_ns();
        (void)avg;
        tracker_add(&t_range, t1 - t0);
    }
    tracker_report("Range Average (20k data points)", &t_range, "us", 1e-3);

    tracker_free(&t_pts);
    tracker_free(&t_range);
    qihse_tsdb_destroy(tsdb);
}

/* =========================================================================
 * Main Entry Point
 * ========================================================================= */
int main(void) {
    printf("=======================================================================\n");
    printf("  QIHSE FULL-SYSTEM ARCHITECTURAL BENCHMARK & HOT-PATH PROFILING       \n");
    printf("=======================================================================\n");

    bench_vector_engine();
    bench_kv_engine();
    bench_sqlite_vfs_engine();
    bench_columnar_engine();
    bench_timeseries_engine();

    printf("\n=======================================================================\n");
    printf("  PROFILING COMPLETE                                                   \n");
    printf("=======================================================================\n");
    return 0;
}
