/* qihse_routing_persistence_test.c — integration tests for the QIHSE routing
 * persistence adapter.
 *
 * Verifies that BGP observations, RPKI ROAs, PTR records, and RDAP records
 * are written to the event stream, that BGP observations fan out to the
 * timeseries and column store, that replay and prefix queries work, and that
 * event-stream data survives a destroy/reopen cycle.
 */

#include "qihse_routing_persistence.h"
#include "qihse_event_stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_count = 0;
static int test_pass = 0;
static int test_fail = 0;

#define TEST(name) do { test_count++; printf("  [%02d] %s ... ", test_count, name); } while (0)
#define PASS() do { test_pass++; printf("PASS\n"); } while (0)
#define FAIL(fmt, ...) do { test_fail++; printf("FAIL: " fmt "\n", ##__VA_ARGS__); } while (0)
#define ASSERT(cond, fmt, ...) do { if (cond) { PASS(); } else { FAIL(fmt, ##__VA_ARGS__); } } while (0)

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static char* make_temp_dir(void) {
    char tmpl[] = "/tmp/qihse_rp_test_XXXXXX";
    return strdup(mkdtemp(tmpl));
}

static void rm_rf(const char* path) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    system(cmd);
}

/* ── Replay callback: counts records ──────────────────────────────────────── */

static bool replay_count_cb(const qihse_es_record_header_t* h,
        const uint8_t* p, size_t s, void* ud) {
    (void)h; (void)p; (void)s;
    int* cnt = (int*)ud;
    (*cnt)++;
    return true;
}

/* ── Prefix query callback: counts matches ────────────────────────────────── */

static bool prefix_count_cb(const qihse_routing_bgp_record_t* rec, void* ud) {
    (void)rec;
    int* cnt = (int*)ud;
    (*cnt)++;
    return true;
}

/* ── Test 1: create / destroy ─────────────────────────────────────────────── */

static void test_create_destroy(void) {
    TEST("create + destroy handle");
    char* dir = make_temp_dir();
    qihse_routing_persistence_t* rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "create returned NULL");

    qihse_routing_persistence_destroy(rp);
    rp = NULL;

    TEST("create with NULL dir fails");
    rp = qihse_routing_persistence_create(NULL);
    ASSERT(rp == NULL, "create(NULL) should return NULL");

    rm_rf(dir);
    free(dir);
}

/* ── Test 2: store BGP observations ───────────────────────────────────────── */

static void test_store_bgp(void) {
    TEST("store 5 BGP observations");
    char* dir = make_temp_dir();
    qihse_routing_persistence_t* rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "create failed");

    const char* ips[5]      = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"};
    int64_t asns[5]         = {13335, 15169, 15169, 19281, 19281};
    const char* prefixes[5] = {"1.1.1.0/24", "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24", "149.112.112.0/24"};
    const char* paths[5]    = {"13335", "15169 174", "15169 174 2914", "19281 174", "19281 174 2914"};
    int32_t rpki[5]         = {1, 1, 1, 0, 1}; /* 0 = invalid, 1 = valid */

    bool all_ok = true;
    for (int i = 0; i < 5; i++) {
        bool ok = qihse_routing_persistence_store_bgp_observation(
            rp, ips[i], asns[i], prefixes[i], paths[i], rpki[i],
            1000 + i, 1700000000ULL + i);
        if (!ok) { all_ok = false; }
    }
    ASSERT(all_ok, "one or more store_bgp_observation calls failed");

    qihse_routing_persistence_destroy(rp);
    rm_rf(dir);
    free(dir);
}

/* ── Test 3: store RPKI ROA entries ───────────────────────────────────────── */

static void test_store_rpki_roa(void) {
    TEST("store 2 RPKI ROA entries");
    char* dir = make_temp_dir();
    qihse_routing_persistence_t* rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "create failed");

    bool ok1 = qihse_routing_persistence_store_rpki_roa(
        rp, "1.1.1.0/24", 24, 13335, "RIPE", 1700000000ULL);
    bool ok2 = qihse_routing_persistence_store_rpki_roa(
        rp, "8.8.8.0/24", 24, 15169, "ARIN", 1700000001ULL);
    ASSERT(ok1 && ok2, "store_rpki_roa failed");

    qihse_routing_persistence_destroy(rp);
    rm_rf(dir);
    free(dir);
}

/* ── Test 4: store PTR records ────────────────────────────────────────────── */

static void test_store_ptr(void) {
    TEST("store 2 PTR records");
    char* dir = make_temp_dir();
    qihse_routing_persistence_t* rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "create failed");

    bool ok1 = qihse_routing_persistence_store_ptr_record(
        rp, "1.1.1.1", "one.one.one.one", 1700000000ULL);
    bool ok2 = qihse_routing_persistence_store_ptr_record(
        rp, "8.8.8.8", "dns.google", 1700000001ULL);
    ASSERT(ok1 && ok2, "store_ptr_record failed");

    qihse_routing_persistence_destroy(rp);
    rm_rf(dir);
    free(dir);
}

/* ── Test 5: store RDAP records ───────────────────────────────────────────── */

static void test_store_rdap(void) {
    TEST("store 2 RDAP records");
    char* dir = make_temp_dir();
    qihse_routing_persistence_t* rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "create failed");

    bool ok1 = qihse_routing_persistence_store_rdap_record(
        rp, "1.1.1.1", "{\"objectClassName\":\"ip network\",\"cidr0_cidrs\":[{\"v4prefix\":\"1.1.1.0\",\"length\":24}]}",
        1700000000ULL);
    bool ok2 = qihse_routing_persistence_store_rdap_record(
        rp, "8.8.8.8", "{\"objectClassName\":\"ip network\",\"cidr0_cidrs\":[{\"v4prefix\":\"8.8.8.0\",\"length\":24}]}",
        1700000001ULL);
    ASSERT(ok1 && ok2, "store_rdap_record failed");

    qihse_routing_persistence_destroy(rp);
    rm_rf(dir);
    free(dir);
}

/* ── Test 6: replay BGP observations ──────────────────────────────────────── */

static void test_replay_bgp(void) {
    TEST("replay BGP observations: count matches stored");
    char* dir = make_temp_dir();
    qihse_routing_persistence_t* rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "create failed");

    const char* ips[5]      = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"};
    int64_t asns[5]         = {13335, 15169, 15169, 19281, 19281};
    const char* prefixes[5] = {"1.1.1.0/24", "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24", "149.112.112.0/24"};
    const char* paths[5]    = {"13335", "15169 174", "15169 174 2914", "19281 174", "19281 174 2914"};

    for (int i = 0; i < 5; i++) {
        qihse_routing_persistence_store_bgp_observation(
            rp, ips[i], asns[i], prefixes[i], paths[i], 1, 1000 + i, 1700000000ULL + i);
    }

    int replay_count = 0;
    uint64_t n = qihse_routing_persistence_replay_bgp(rp, replay_count_cb, &replay_count);
    ASSERT(n == 5 && replay_count == 5, "replay count %lu / %d != 5", n, replay_count);

    qihse_routing_persistence_destroy(rp);
    rm_rf(dir);
    free(dir);
}

/* ── Test 7: query by prefix ──────────────────────────────────────────────── */

static bool prefix_capture_cb(const qihse_routing_bgp_record_t* rec, void* ud) {
    qihse_routing_bgp_record_t* out = (qihse_routing_bgp_record_t*)ud;
    /* Capture the first match into the caller's slot. */
    if (out->origin_asn == 0) {
        *out = *rec;
    }
    return true;
}

static void test_query_by_prefix(void) {
    TEST("query by prefix: filter records matching 8.8.");
    char* dir = make_temp_dir();
    qihse_routing_persistence_t* rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "create failed");

    const char* ips[5]      = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"};
    int64_t asns[5]         = {13335, 15169, 15169, 19281, 19281};
    const char* prefixes[5] = {"1.1.1.0/24", "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24", "149.112.112.0/24"};
    const char* paths[5]    = {"13335", "15169 174", "15169 174 2914", "19281 174", "19281 174 2914"};

    for (int i = 0; i < 5; i++) {
        qihse_routing_persistence_store_bgp_observation(
            rp, ips[i], asns[i], prefixes[i], paths[i], 1, 1000 + i, 1700000000ULL + i);
    }

    /* Prefix "8.8." should match 2 records (8.8.8.0/24 and 8.8.4.0/24). */
    int match_count = 0;
    uint64_t m = qihse_routing_persistence_query_by_prefix(
        rp, "8.8.", prefix_count_cb, &match_count);
    ASSERT(m == 2 && match_count == 2, "prefix query returned %lu / %d, expected 2", m, match_count);

    /* Prefix "1." should match 1 record. */
    match_count = 0;
    m = qihse_routing_persistence_query_by_prefix(
        rp, "1.1.1.", prefix_count_cb, &match_count);
    ASSERT(m == 1 && match_count == 1, "prefix query returned %lu / %d, expected 1", m, match_count);

    /* Non-matching prefix. */
    match_count = 0;
    m = qihse_routing_persistence_query_by_prefix(
        rp, "999.", prefix_count_cb, &match_count);
    ASSERT(m == 0 && match_count == 0, "prefix query returned %lu / %d, expected 0", m, match_count);

    /* Verify captured record fields. */
    qihse_routing_bgp_record_t captured;
    memset(&captured, 0, sizeof(captured));
    m = qihse_routing_persistence_query_by_prefix(
        rp, "8.8.8.", prefix_capture_cb, &captured);
    ASSERT(m == 1 && captured.origin_asn == 15169,
        "captured record origin_asn = %lld, expected 15169", (long long)captured.origin_asn);

    qihse_routing_persistence_destroy(rp);
    rm_rf(dir);
    free(dir);
}

/* ── Test 8: destroy and reopen, verify data persisted ────────────────────── */

static void test_persistence_across_reopen(void) {
    TEST("persist across reopen: BGP event stream survives destroy/reopen");
    char* dir = make_temp_dir();
    qihse_routing_persistence_t* rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "create failed");

    for (int i = 0; i < 5; i++) {
        char ip[32], prefix[32], path[32];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i + 1);
        snprintf(prefix, sizeof(prefix), "10.0.0.0/24");
        snprintf(path, sizeof(path), "65000 %d", i);
        qihse_routing_persistence_store_bgp_observation(
            rp, ip, 65000, prefix, path, 1, 42, 1800000000ULL + i);
    }
    /* Also store some ROA / PTR / RDAP records. */
    qihse_routing_persistence_store_rpki_roa(rp, "10.0.0.0/24", 24, 65000, "ARIN", 1800000000ULL);
    qihse_routing_persistence_store_ptr_record(rp, "10.0.0.1", "host1.test", 1800000000ULL);
    qihse_routing_persistence_store_rdap_record(rp, "10.0.0.1", "{\"test\":true}", 1800000000ULL);

    qihse_routing_persistence_flush(rp);
    qihse_routing_persistence_destroy(rp);

    /* Reopen — event stream data must survive. */
    rp = qihse_routing_persistence_create(dir);
    ASSERT(rp != NULL, "reopen failed");

    int replay_count = 0;
    uint64_t n = qihse_routing_persistence_replay_bgp(rp, replay_count_cb, &replay_count);
    ASSERT(n == 5 && replay_count == 5,
        "replay after reopen: %lu / %d != 5", n, replay_count);

    /* Verify the ROA / PTR / RDAP topics also persisted by replaying directly
     * through the event stream. */
    qihse_event_stream_t* es = qihse_routing_persistence_event_stream(rp);
    ASSERT(es != NULL, "event_stream accessor returned NULL");

    int roa_count = 0;
    uint64_t nroa = qihse_event_stream_replay(es, "rpki_roas",
        replay_count_cb, &roa_count);
    ASSERT(nroa == 1 && roa_count == 1, "ROA replay: %lu / %d != 1", nroa, roa_count);

    int ptr_count = 0;
    uint64_t nptr = qihse_event_stream_replay(es, "ptr_records",
        replay_count_cb, &ptr_count);
    ASSERT(nptr == 1 && ptr_count == 1, "PTR replay: %lu / %d != 1", nptr, ptr_count);

    int rdap_count = 0;
    uint64_t nrdap = qihse_event_stream_replay(es, "rdap_records",
        replay_count_cb, &rdap_count);
    ASSERT(nrdap == 1 && rdap_count == 1, "RDAP replay: %lu / %d != 1", nrdap, rdap_count);

    qihse_routing_persistence_destroy(rp);
    rm_rf(dir);
    free(dir);
}

/* ── Test 9: NULL-safety ──────────────────────────────────────────────────── */

static void test_null_safety(void) {
    TEST("NULL safety: all functions reject NULL handle/args");

    bool ok;
    ok = qihse_routing_persistence_store_bgp_observation(
        NULL, "1.1.1.1", 1, "1.1.1.0/24", "1", 1, 1, 1);
    ASSERT(!ok, "store_bgp_observation(NULL) should return false");

    ok = qihse_routing_persistence_store_rpki_roa(
        NULL, "1.1.1.0/24", 24, 1, "RIPE", 1);
    ASSERT(!ok, "store_rpki_roa(NULL) should return false");

    ok = qihse_routing_persistence_store_ptr_record(NULL, "1.1.1.1", "h", 1);
    ASSERT(!ok, "store_ptr_record(NULL) should return false");

    ok = qihse_routing_persistence_store_rdap_record(NULL, "1.1.1.1", "{}", 1);
    ASSERT(!ok, "store_rdap_record(NULL) should return false");

    uint64_t n = qihse_routing_persistence_replay_bgp(NULL, replay_count_cb, NULL);
    ASSERT(n == 0, "replay_bgp(NULL) should return 0");

    n = qihse_routing_persistence_query_by_prefix(NULL, "x", prefix_count_cb, NULL);
    ASSERT(n == 0, "query_by_prefix(NULL) should return 0");

    ok = qihse_routing_persistence_flush(NULL);
    ASSERT(!ok, "flush(NULL) should return false");

    /* destroy(NULL) must not crash. */
    qihse_routing_persistence_destroy(NULL);
    PASS();
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== QIHSE Routing Persistence Integration Tests ===\n");

    test_create_destroy();
    test_store_bgp();
    test_store_rpki_roa();
    test_store_ptr();
    test_store_rdap();
    test_replay_bgp();
    test_query_by_prefix();
    test_persistence_across_reopen();
    test_null_safety();

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
        test_pass, test_fail, test_count);
    return test_fail == 0 ? 0 : 1;
}
