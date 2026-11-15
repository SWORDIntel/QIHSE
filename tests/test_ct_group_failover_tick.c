/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef NDEBUG
#undef NDEBUG
#endif

/* Exercise the actual static scheduler, not a copy of its eligibility logic.
 * The existing API harness supplies real auth/topology/journal/producer calls
 * and deterministic KV, common-authority and transport boundary doubles. */
#include "qihse_cluster_ownership_journal.h"
static unsigned tick_replays;
static int tick_journal_replay(const char* directory,
    qihse_cluster_ownership_txn_cb callback, void* context, bool* unresolved) {
    ++tick_replays;
    return qihse_cluster_ownership_journal_replay_txn(directory, callback, context, unresolved);
}
#define qihse_cluster_ownership_journal_replay_txn tick_journal_replay
#define main ct_tick_daemon_main
#include "../tools/qihse_cluster_daemon.c"
#undef main
#undef qihse_cluster_ownership_journal_replay_txn
#define main ct_tick_api_harness_main
#include "test_ct_lane_promotion_recovery.c"
#undef main

static struct {
    qihse_cluster_topology_t* topology;
    qihse_cluster_ownership_context_t ownership;
    ct_identity_map_set_t maps;
    qihse_ct_group_config_t group;
    qihse_qkp_replication_peer_t peers[3];
    qihse_user_t* low;
    bool fail_refresh_once, fail_journal_once;
    unsigned promotions, map_lookups;
    uint16_t selected_successor;
    ct_group_promotion_cache_t promotion_cache;
} tick_fixture;

bool __real_qihse_cluster_failover_promote_lane(
    qihse_cluster_ownership_context_t*, const char*, uint16_t,
    bool*, char*, size_t);
bool __wrap_qihse_cluster_failover_promote_lane(
    qihse_cluster_ownership_context_t* ownership, const char* lane,
    uint16_t successor, bool* pending, char* error, size_t capacity) {
    tick_fixture.promotions++;
    tick_fixture.selected_successor = successor;
    return __real_qihse_cluster_failover_promote_lane(ownership, lane,
        successor, pending, error, capacity);
}

/* SOURCE recovery must not consult the election/current-owner path. Never
 * dereference the synthetic mesh: an accidental election is observable. */
bool qihse_consensus_mesh_range_group_transition_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    const char* group, qihse_consensus_range_request_t* request,
    qihse_consensus_range_decision_t* decision, bool* found) {
    (void)mesh; (void)principal; (void)group; (void)request; (void)decision;
    tick_fixture.map_lookups++;
    *found = false;
    return false;
}

static bool tick_refresh(void* context, qihse_user_t* user,
    const uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES], char* error, size_t cap) {
    assert(refresh(context, user, slots, error, cap));
    if (tick_fixture.fail_refresh_once) {
        tick_fixture.fail_refresh_once = false;
        errno = EIO;
        return false;
    }
    if (tick_fixture.fail_journal_once) {
        char lock[1024];
        int n = snprintf(lock, sizeof lock, "%s/slot-ownership.journal.lock", fixture.directory);
        assert(n > 0 && (size_t)n < sizeof lock && chmod(lock, 0644) == 0);
        tick_fixture.fail_journal_once = false;
    }
    return true;
}

static void run_tick_as(uint16_t local_index, const char* local_qkp) {
    ct_group_failover_tick((void*)(uintptr_t)1, &tick_fixture.ownership,
        tick_fixture.topology, (void*)(uintptr_t)3, &tick_fixture.maps,
        tick_fixture.peers, 3u, &tick_fixture.group, 1u, local_index, local_qkp,
        &tick_fixture.promotion_cache);
}

static void run_tick(void) { run_tick_as(1u, qkp_ids[1]); }

static void reset_case(const char* root, const char* name) {
    qihse_user_t* op = fixture.op;
    qihse_user_t* service = fixture.service;
    memset(&fixture, 0, sizeof(fixture));
    fixture.op = op; fixture.service = service;
    tick_fixture.promotions = 0u; tick_replays = 0u;
    tick_fixture.map_lookups = 0u;
    tick_fixture.selected_successor = QIHSE_CLUSTER_NODE_NONE;
    tick_fixture.fail_refresh_once = false; tick_fixture.fail_journal_once = false;
    assert(qihse_cluster_topology_set_local_node(tick_fixture.topology, 1u));
    char directory[512];
    assert(snprintf(directory, sizeof(directory), "%s/%s", root, name) > 0);
    setup_committed(directory, tick_fixture.topology);
    fixture.common_final = true;
    tick_fixture.ownership.principal = fixture.op;
    memset(&tick_fixture.group, 0, sizeof(tick_fixture.group));
    strcpy(tick_fixture.group.lane_id, lane_id);
    strcpy(tick_fixture.group.owner_topology_id, topology_ids[0]);
    strcpy(tick_fixture.group.successor_topology_id, topology_ids[1]);
    strcpy(tick_fixture.group.generation, fixture.committed.generation);
    memcpy(tick_fixture.group.slot_bitmap, fixture.committed.slot_bitmap,
        sizeof(tick_fixture.group.slot_bitmap));
    memset(&tick_fixture.maps, 0, sizeof(tick_fixture.maps));
    tick_fixture.maps.count = 3u;
    for (size_t i = 0; i < 3u; ++i) {
        strcpy(tick_fixture.maps.entries[i].topology_id, topology_ids[i]);
        strcpy(tick_fixture.maps.entries[i].qkp_node_id, qkp_ids[i]);
        tick_fixture.peers[i] = (qihse_qkp_replication_peer_t){
            .node_id = qkp_ids[i], .dsa_pub_path = "synthetic-unused-pin"};
    }
}

static void test_admitted_retry(const char* root) {
    reset_case(root, "admitted-refresh-retry");
    tick_fixture.fail_refresh_once = true;
    run_tick();
    assert(tick_fixture.promotions == 1u && tick_fixture.selected_successor == 2u);
    assert(!fixture.lane.promotion_pending && fixture.lane.admitted);
    assert(fixture.finalizes == 1u && fixture.refreshes == 1u);
    assert(!fixture.reserves && !fixture.prepares && !fixture.signatures);
    assert_journal(3u, 0u);

    /* Admission already cleared pending; only the durable COMMITTED record
     * identifies the unfinished operation. Health must not elect a new ID. */
    assert(qihse_cluster_topology_set_node_health(tick_fixture.topology, 0u, true));
    assert(qihse_cluster_topology_set_node_health(tick_fixture.topology, 2u, false));
    run_tick();
    assert(tick_fixture.promotions == 2u && tick_fixture.selected_successor == 2u);
    assert(fixture.finalizes == 2u && fixture.refreshes == 2u);
    assert_journal(4u, 1u); /* count_journal checks every record's exact ID. */
    for (unsigned i = 0; i < 3u; ++i) run_tick();
    assert(tick_fixture.promotions == 2u && fixture.finalizes == 2u &&
        fixture.refreshes == 2u && !tick_fixture.map_lookups);
    assert(!fixture.reserves && !fixture.prepares && !fixture.signatures);
    assert_journal(4u, 1u);
    if (tick_replays != 2u) fprintf(stderr, "idle promotion replay count=%u expected=2\n", tick_replays);
    assert(tick_replays == 2u);
    puts("PASS actual tick: admitted COMMITTED retry keeps ID and finalizes once");
}

static void test_finalized_append_retry(const char* root) {
    reset_case(root, "finalized-append-retry");
    tick_fixture.fail_journal_once = true;
    run_tick();
    assert(tick_replays == 1u && tick_fixture.promotions == 1u && fixture.lane.admitted &&
        !fixture.lane.promotion_pending);
    assert_journal(3u, 0u);
    char lock[1024];
    int n = snprintf(lock, sizeof lock, "%s/slot-ownership.journal.lock", fixture.directory);
    assert(n > 0 && (size_t)n < sizeof lock && chmod(lock, 0600) == 0);
    run_tick();
    assert(tick_replays == 1u && tick_fixture.promotions == 2u);
    assert_journal(4u, 1u);
    for (unsigned i = 0; i < 8u; ++i) run_tick();
    assert(tick_replays == 2u && tick_fixture.promotions == 2u && fixture.finalizes == 2u &&
        fixture.refreshes == 2u && !tick_fixture.map_lookups);
    puts("PASS cached post-FINAL retry survives failed FINALIZED append; terminal idle avoids replay");
}

static void test_pending_stale_successor(const char* root) {
    reset_case(root, "pending-stale-successor");
    assert(qihse_cluster_topology_set_node_health(tick_fixture.topology, 0u, true));
    assert(qihse_cluster_topology_set_node_health(tick_fixture.topology, 2u, false));
    run_tick();
    assert(tick_fixture.promotions == 1u && tick_fixture.selected_successor == 2u);
    assert(!fixture.lane.promotion_pending && fixture.lane.admitted);
    assert(fixture.finalizes == 1u && fixture.refreshes == 1u);
    assert_journal(4u, 1u);
    run_tick();
    assert(tick_fixture.promotions == 1u && fixture.finalizes == 1u &&
        fixture.refreshes == 1u && !tick_fixture.map_lookups);
    assert(!fixture.reserves && !fixture.prepares && !fixture.signatures);
    assert_journal(4u, 1u);
    puts("PASS actual tick: pending SOURCE common FINAL ignores stale health");
}

static void journal_path(char out[1024]) {
    int length = snprintf(out, 1024u, "%s/slot-ownership.journal", fixture.directory);
    assert(length > 0 && length < 1024);
}

static void warm_promotion_cache(void) {
    tick_fixture.peers[2].dsa_pub_path = NULL;
    run_tick();
    assert(tick_replays == 1u && !tick_fixture.promotions && tick_fixture.promotion_cache.found);
    tick_fixture.peers[2].dsa_pub_path = "synthetic-unused-pin";
}
static void test_cache_terminal_append(const char* root) {
    reset_case(root, "cache-terminal-append"); warm_promotion_cache();
    qihse_cluster_ownership_txn_t txn = fixture.committed;
    txn.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_ownership_journal_append_txn(fixture.directory, &txn) == 0);
    for (unsigned i = 0; i < 9u; ++i) run_tick();
    assert(tick_replays == 2u && !tick_fixture.promotions && !tick_fixture.promotion_cache.found);
    puts("PASS warm promotion cache invalidates on terminal append and stays idle");
}
static void test_cache_replacement(const char* root) {
    reset_case(root, "cache-inode-replacement"); warm_promotion_cache();
    char path[1024], saved[1100]; journal_path(path);
    struct stat before, after; assert(stat(path, &before) == 0);
    int n = snprintf(saved, sizeof saved, "%s.native-original", path);
    assert(n > 0 && (size_t)n < sizeof saved && access(saved, F_OK) != 0 && errno == ENOENT);
    assert(rename(path, saved) == 0);
    qihse_cluster_ownership_txn_t txn = fixture.committed;
    memset(txn.target_id, 'e', QIHSE_CLUSTER_NODE_ID_LEN); txn.target_id[QIHSE_CLUSTER_NODE_ID_LEN] = 0;
    txn.phase = QIHSE_OWNERSHIP_INTENT; txn.target_lsn = 0u;
    memset(txn.proof_digest, 0, sizeof txn.proof_digest);
    assert(qihse_cluster_ownership_journal_append_txn(fixture.directory, &txn) == 0);
    txn.phase = QIHSE_OWNERSHIP_PREPARED;
    assert(qihse_cluster_ownership_journal_append_txn(fixture.directory, &txn) == 0);
    txn.phase = QIHSE_OWNERSHIP_COMMITTED; txn.target_lsn = fixture.committed.target_lsn;
    memcpy(txn.proof_digest, fixture.committed.proof_digest, sizeof txn.proof_digest);
    assert(qihse_cluster_ownership_journal_append_txn(fixture.directory, &txn) == 0);
    assert(stat(path, &after) == 0 && before.st_ino != after.st_ino && before.st_size == after.st_size);
    for (unsigned i = 0; i < 9u; ++i) run_tick();
    assert(tick_replays == 2u && !tick_fixture.promotions && !fixture.finalizes && !fixture.refreshes);
    puts("PASS same-path equal-size journal replacement invalidates cached promotion identity");
}
static void test_cache_mutation(const char* root, bool preserve_mtime) {
    reset_case(root, preserve_mtime ? "cache-ctime-mutation" : "cache-mtime-mutation");
    warm_promotion_cache();
    char path[1024], saved[1100]; journal_path(path);
    int n = snprintf(saved, sizeof saved, "%s.native-original", path);
    assert(n > 0 && (size_t)n < sizeof saved);
    FILE* source = fopen(path, "rb"); FILE* copy = fopen(saved, "wbx"); assert(source && copy);
    unsigned char bytes[512]; size_t count;
    while ((count = fread(bytes, 1u, sizeof bytes, source)) != 0u)
        assert(fwrite(bytes, 1u, count, copy) == count);
    assert(!ferror(source) && fclose(source) == 0 && fflush(copy) == 0 &&
        fsync(fileno(copy)) == 0 && fclose(copy) == 0);
    struct stat before, after; assert(stat(path, &before) == 0);
    FILE* f = fopen(path, "r+b"); assert(f && fseek(f, -1L, SEEK_END) == 0);
    int last = fgetc(f); assert(last != EOF && fseek(f, -1L, SEEK_END) == 0);
    assert(fputc(last ^ 1u, f) != EOF && fflush(f) == 0);
    struct timespec times[2] = {before.st_atim, before.st_mtim};
    if (!preserve_mtime) ++times[1].tv_sec;
    assert(futimens(fileno(f), times) == 0 && fsync(fileno(f)) == 0 && fclose(f) == 0);
    assert(stat(path, &after) == 0 && before.st_ino == after.st_ino && before.st_size == after.st_size);
    assert(before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec);
    if (preserve_mtime) assert(before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
    qihse_kv_ct_lane_status_t lane = fixture.lane;
    run_tick();
    assert(tick_replays == 2u && !tick_fixture.promotions && !tick_fixture.promotion_cache.valid &&
        !tick_fixture.promotion_cache.found && !memcmp(&lane, &fixture.lane, sizeof lane));
    run_tick();
    assert(tick_replays == 3u && !tick_fixture.promotions && !fixture.finalizes && !fixture.refreshes);
    puts("PASS same-size journal corruption invalidates cache, drops partial candidates and retries errors");
}
static void test_cache_live_inputs(const char* root) {
    reset_case(root, "cache-live-inputs"); warm_promotion_cache();
    tick_fixture.ownership.principal = tick_fixture.low; run_tick();
    tick_fixture.ownership.principal = fixture.op;
    char generation[sizeof fixture.lane.generation]; memcpy(generation, fixture.lane.generation, sizeof generation);
    memset(fixture.lane.generation, 'f', sizeof fixture.lane.generation - 1u); run_tick();
    memcpy(fixture.lane.generation, generation, sizeof generation);
    tick_fixture.peers[2].dsa_pub_path = NULL; run_tick();
    tick_fixture.peers[2].dsa_pub_path = "synthetic-unused-pin";
    assert(tick_replays == 1u && !tick_fixture.promotions);
    tick_fixture.fail_refresh_once = true; run_tick();
    assert(tick_replays == 1u && tick_fixture.promotions == 1u && tick_fixture.selected_successor == 2u);
    run_tick();
    assert(tick_replays == 1u && tick_fixture.promotions == 2u);
    puts("PASS cached discovery rechecks live principal, generation and successor pin");
}

static void assert_no_effects(uint16_t local_index, const char* local_qkp) {
    qihse_kv_ct_lane_status_t before = fixture.lane;
    struct stat before_stat, after_stat;
    char path[1024]; journal_path(path);
    bool exists = stat(path, &before_stat) == 0;
    for (unsigned i = 0; i < 2u; ++i) run_tick_as(local_index, local_qkp);
    assert(!tick_fixture.promotions && !tick_fixture.map_lookups);
    assert(!fixture.reserves && !fixture.prepares && !fixture.finalizes &&
        !fixture.refreshes && !fixture.signatures);
    assert(!memcmp(&before, &fixture.lane, sizeof(before)));
    if (exists) {
        assert(stat(path, &after_stat) == 0);
        assert(before_stat.st_size == after_stat.st_size);
    } else {
        assert(stat(path, &after_stat) == -1 && errno == ENOENT);
    }
}

/* Keep the original journal intact, and build a separate valid transaction
 * history when a negative needs a mismatched record rather than corrupt bytes. */
static void install_changed_journal(void) {
    char directory[512];
    int length = snprintf(directory, sizeof(directory), "%s/changed", fixture.directory);
    assert(length > 0 && (size_t)length < sizeof(directory));
    assert(mkdir(directory, 0700) == 0);
    qihse_cluster_ownership_txn_t txn = fixture.committed;
    txn.phase = QIHSE_OWNERSHIP_INTENT;
    txn.target_lsn = 0u; memset(txn.proof_digest, 0, sizeof(txn.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(directory, &txn) == 0);
    txn.phase = QIHSE_OWNERSHIP_PREPARED;
    assert(qihse_cluster_ownership_journal_append_txn(directory, &txn) == 0);
    txn = fixture.committed;
    assert(qihse_cluster_ownership_journal_append_txn(directory, &txn) == 0);
    strcpy(fixture.directory, directory);
}

static void test_negatives(const char* root) {
    for (unsigned pending = 0; pending < 2u; ++pending) {
        reset_case(root, pending ? "no-work-pending" : "no-work-admitted");
        char directory[512];
        int length = snprintf(directory, sizeof(directory), "%s/empty", fixture.directory);
        assert(length > 0 && (size_t)length < sizeof(directory));
        assert(mkdir(directory, 0700) == 0);
        strcpy(fixture.directory, directory);
        fixture.lane.promotion_pending = pending != 0u;
        assert_no_effects(1u, qkp_ids[1]);
    }

    reset_case(root, "foreign-source");
    strcpy(fixture.lane.source_id, qkp_ids[0]);
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "foreign-local-identity");
    assert_no_effects(1u, qkp_ids[0]); assert_journal(3u, 0u);

    reset_case(root, "foreign-local-index");
    assert_no_effects(0u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "foreign-target-record");
    strcpy(fixture.committed.target_id, topology_ids[2]);
    install_changed_journal();
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "foreign-target-qkp-record");
    strcpy(fixture.committed.target_qkp_id, qkp_ids[2]);
    install_changed_journal();
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "lane-mismatch");
    fixture.lane.lane_id[0] = 'c';
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "generation-mismatch");
    fixture.lane.generation[0] = 'c';
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "slot-mismatch");
    fixture.lane.slot_bitmap[1] ^= 0x02u;
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "peer-mismatch");
    strcpy(fixture.lane.peer_id, qkp_ids[0]);
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "missing-successor-pin");
    tick_fixture.peers[2].dsa_pub_path = NULL;
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "successor-mapping-mismatch");
    strcpy(tick_fixture.maps.entries[2].qkp_node_id, "foreign-qkp");
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);

    reset_case(root, "unreadable-journal");
    char path[1024]; journal_path(path);
    char saved[1100];
    assert(snprintf(saved, sizeof(saved), "%s.saved", path) > 0);
    assert(rename(path, saved) == 0);
    assert(mkdir(path, 0700) == 0); /* EISDIR even when run by root. */
    bool unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(fixture.directory,
        NULL, NULL, &unresolved) < 0);
    assert_no_effects(1u, qkp_ids[1]);

    reset_case(root, "malformed-journal");
    journal_path(path);
    FILE* journal = fopen(path, "ab"); assert(journal);
    assert(fwrite("invalid-frame", 1u, 13u, journal) == 13u);
    assert(fclose(journal) == 0);
    assert(qihse_cluster_ownership_journal_replay_txn(fixture.directory,
        NULL, NULL, &unresolved) < 0);
    assert_no_effects(1u, qkp_ids[1]);

    reset_case(root, "low-principal");
    tick_fixture.ownership.principal = tick_fixture.low;
    assert_no_effects(1u, qkp_ids[1]); assert_journal(3u, 0u);
    assert(!fixture.status_calls);
    puts("PASS actual tick: no-work, identity/tuple/pin, journal and authorization negatives");
}

int main(void) {
    unsigned retry_ticks = 0u;
    for (unsigned i = 0; i < 10u; ++i)
        assert(!ct_group_map_retry_due(7u, 7u, false, false, &retry_ticks));
    for (unsigned i = 0; i < 4u; ++i)
        assert(!ct_group_map_retry_due(7u, 7u, true, false, &retry_ticks));
    assert(ct_group_map_retry_due(7u, 7u, true, false, &retry_ticks));
    for (unsigned i = 0; i < 4u; ++i)
        assert(!ct_group_map_retry_due(7u, 7u, false, true, &retry_ticks));
    assert(ct_group_map_retry_due(7u, 7u, false, true, &retry_ticks));
    assert(ct_group_map_retry_due(8u, 7u, false, false, &retry_ticks) && !retry_ticks);
    puts("PASS routing retry: bounded pending/staging retry without another common commit");
    char root[] = "./ct_group_failover_tick_XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("PromotionRecoveryOperator42!"));
    fixture.op = qihse_auth_authenticate_id(0u, "PromotionRecoveryOperator42!");
    fixture.service = qihse_auth_create_user(fixture.op, 919u, QIHSE_ROLE_GUEST,
        5u, 1u, "PromotionRecoveryService42!", false);
    tick_fixture.low = qihse_auth_create_user(fixture.op, 920u, QIHSE_ROLE_GUEST,
        0u, 0u, "PromotionRecoveryLow42!", false);
    assert(fixture.op && fixture.service && tick_fixture.low);
    tick_fixture.topology = qihse_cluster_topology_create();
    assert(tick_fixture.topology);
    for (size_t i = 0; i < 3u; ++i) {
        qihse_cluster_node_t node = {0}; uint16_t index = UINT16_MAX;
        char seed[32]; snprintf(seed, sizeof(seed), "promotion-recovery-%zu", i);
        qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
        strcpy(topology_ids[i], node.id); strcpy(node.host, "127.0.0.1");
        node.port = (uint16_t)(17100u + i); node.bus_port = (uint16_t)(27100u + i);
        node.role = QIHSE_CLUSTER_NODE_PRIMARY; node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        node.healthy = true;
        assert(qihse_cluster_topology_upsert_node(tick_fixture.topology, &node, &index) && index == i);
    }
    tick_fixture.ownership = (qihse_cluster_ownership_context_t){
        .store = (void*)(uintptr_t)1, .bus = (void*)(uintptr_t)2,
        .topology = tick_fixture.topology, .principal = fixture.op,
        .data_principal = fixture.service, .peer_id = peer_id,
        .lane_claim = read_claim, .lane_verify_claim = verify_claim,
        .range_reserve = reserve_unused, .range_finalize_promotion = finalize_unused,
        .range_refresh = tick_refresh, .promotion_successor_prepare = successor_prepare};
    test_admitted_retry(root);
    test_finalized_append_retry(root);
    test_pending_stale_successor(root);
    test_cache_terminal_append(root);
    test_cache_replacement(root);
    test_cache_mutation(root, false);
    test_cache_mutation(root, true);
    test_cache_live_inputs(root);
    test_negatives(root);
    qihse_cluster_topology_destroy(tick_fixture.topology);
    puts("PASS CT group failover tick deterministic regressions");
    return 0; /* Preserve synthetic trees, especially on assertion failure. */
}
