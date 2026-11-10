#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_crc16.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

#define RETAINED_LIMIT (16u * 1024u * 1024u)

static const char LANE_A[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char LANE_B[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char GEN_A[33] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_B[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static void bitmap_set(uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], uint16_t slot) {
    bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
}

static bool bitmap_has(const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], uint16_t slot) {
    return (bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0;
}

static char *key_for_slot(const char *prefix, uint16_t wanted_slot) {
    char candidate[128];
    for (unsigned i = 0; i < 1000000u; ++i) {
        int n = snprintf(candidate, sizeof(candidate), "%s%u", prefix, i);
        assert(n > 0 && (size_t)n < sizeof(candidate));
        if (qihse_cluster_key_slot(candidate, (size_t)n) == wanted_slot) {
            char *out = strdup(candidate);
            assert(out);
            return out;
        }
    }
    assert(!"could not find key for requested cluster slot");
    return NULL;
}

static void assert_value(qihse_kv_store_t *store, qihse_user_t *user,
                         const char *key, const char *expected) {
    char *value = qihse_kv_get_user(store, key, user);
    if (!expected) assert(value == NULL);
    else assert(value && strcmp(value, expected) == 0);
    free(value);
}

int main(void) {
    char data_dir[] = "./ct_lanes_XXXXXX";
    umask(0077);
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtLaneOperator1!"));
    qihse_user_t *op = qihse_auth_authenticate_id(0u, "CtLaneOperator1!");
    assert(op);
    qihse_user_t *low = qihse_auth_create_user(op, 8401u, QIHSE_ROLE_ANALYST,
                                                0u, 0u, "CtLaneLow1!", false);
    qihse_user_t *peer = qihse_auth_create_user(op, 8402u, QIHSE_ROLE_ANALYST,
                                                 5u, 3u, "CtLanePeer1!", false);
    assert(low && peer);

    /* Two disjoint lanes on one store. Keys are generated against the actual
     * cluster hash so this tests routing by slot rather than assumed prefixes. */
    uint8_t slots_a[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t slots_b[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint16_t slot_a = 127u, slot_b = 12000u;
    assert(slot_a != slot_b);
    bitmap_set(slots_a, slot_a);
    bitmap_set(slots_b, slot_b);
    assert(!bitmap_has(slots_a, slot_b) && !bitmap_has(slots_b, slot_a));
    char *key_a = key_for_slot("commons/lane-a-", slot_a);
    char *key_b = key_for_slot("t:73/lane-b-", slot_b);

    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    unsigned char token_a[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char token_b[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE_A, slots_a,
        "node-a", "peer-a", GEN_A, token_a, RETAINED_LIMIT));
    assert(qihse_kv_ct_lane_receiver_bind(store, op, LANE_B, slots_b,
        "peer-b", "node-a", GEN_B, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0u, 0u, token_b));
    assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_A, token_a));
    assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_B, token_b));

    qihse_kv_ct_lane_status_t status_a = {0}, status_b = {0};
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_a.mode == QIHSE_KV_CT_LANE_SOURCE &&
           status_b.mode == QIHSE_KV_CT_LANE_RECEIVER);
    assert(memcmp(status_a.slot_bitmap, slots_a, sizeof(slots_a)) == 0);
    assert(memcmp(status_b.slot_bitmap, slots_b, sizeof(slots_b)) == 0);
    assert(!qihse_kv_ct_lane_status(store, low, LANE_A, &status_a));
    assert(!qihse_kv_ct_lane_status(store, peer, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", &status_a));

    /* Lane B starts from a real canonical empty baseline, not cursor zero by
     * convention. Its lane-specific owner token seals only that lane. */
    unsigned char empty_digest[32];
    assert(qihse_kv_ct_lane_receiver_empty_baseline_seal(store, op, LANE_B,
        token_b, empty_digest));
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b) &&
           status_b.baseline_sealed && status_b.baseline_row_seq == 0u);

    qihse_kv_replica_snapshot_t *baseline = NULL;
    uint64_t baseline_seq = UINT64_MAX;
    unsigned char baseline_digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, LANE_A,
        &baseline, &baseline_seq, baseline_digest) == 0);
    assert(baseline && baseline_seq == 0u);
    assert(!qihse_kv_ct_lane_source_reconcile_peer(store, op, low, LANE_A,
        "peer-a", GEN_A, baseline_digest, 0u));
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_A,
        "peer-a", GEN_A, baseline_digest, 0u));
    qihse_kv_replica_snapshot_destroy(baseline);

    qihse_kv_ct_writer_scope_t *scope = NULL;
    assert(!qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_b, &scope));
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_a, &scope));
    assert(qihse_kv_set_user(store, key_a, "lane-a-v1", 4u, 1u, op));
    assert(!qihse_kv_set_user(store, key_b, "wrong-lane-write", 4u, 1u, op));
    assert_value(store, op, key_a, NULL); /* durable ACK gates primary reads */

    qihse_kv_ct_group_t *groups = NULL;
    size_t group_count = 0u;
    uint64_t resume = 0u;
    assert(!qihse_kv_ct_lane_source_read(store, low, LANE_A, GEN_A,
        0u, 8u, 65536u, &groups, &group_count, &resume));
    assert(qihse_kv_ct_lane_source_read(store, peer, LANE_A, GEN_A,
        0u, 8u, 65536u, &groups, &group_count, &resume));
    assert(group_count == 1u && resume == 1u && groups[0].count == 1u);
    assert(strcmp(groups[0].records[0].key, key_a) == 0 &&
           strcmp(groups[0].records[0].value, "lane-a-v1") == 0 &&
           groups[0].records[0].classification == 4u &&
           groups[0].records[0].sci_compartment == 1u &&
           groups[0].records[0].resource_tenant_id == 0u);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A,
        "peer-a", GEN_A, resume));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_ct_groups_free(groups, group_count);
    groups = NULL;
    assert_value(store, op, key_a, "lane-a-v1");

    /* Apply a B-lane delta while this same process remains the admitted A
     * source. Verify both slot routing and all security metadata survive. */
    qihse_kv_ct_record_t row_b = {
        .key = key_b, .value = "lane-b-v1", .change_seq = 1u,
        .actor_id = qihse_user_get_id(peer), .actor_tenant_id = 0u,
        .resource_tenant_id = 73u, .classification = 4u,
        .sci_compartment = 1u, .actor_kind = QIHSE_KV_CT_ACTOR_USER,
        .tombstone = false
    };
    qihse_kv_ct_group_t group_b = {0};
    snprintf(group_b.source_id, sizeof(group_b.source_id), "%s", "peer-b");
    snprintf(group_b.generation, sizeof(group_b.generation), "%s", GEN_B);
    group_b.stream_position = 1u;
    group_b.first_seq = group_b.last_seq = 1u;
    group_b.records = &row_b;
    group_b.count = 1u;
    uint64_t b_cursor = 0u;
    assert(!qihse_kv_ct_lane_receiver_apply(store, low, LANE_B,
        &group_b, &b_cursor));
    row_b.resource_tenant_id = 0u; /* key-derived tenant is authoritative */
    assert(!qihse_kv_ct_lane_receiver_apply(store, peer, LANE_B,
        &group_b, &b_cursor));
    row_b.resource_tenant_id = 73u;
    assert(qihse_kv_ct_lane_receiver_apply(store, peer, LANE_B,
        &group_b, &b_cursor) && b_cursor == 1u);
    assert_value(store, op, key_b, NULL); /* receiver lane is not yet promoted */
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a) &&
           status_a.mode == QIHSE_KV_CT_LANE_SOURCE &&
           status_a.acknowledged_position == 1u);
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b) &&
           status_b.mode == QIHSE_KV_CT_LANE_RECEIVER &&
           status_b.durable_position == 1u && status_b.baseline_sealed);

    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_a.mode == QIHSE_KV_CT_LANE_SOURCE &&
           status_a.acknowledged_position == 1u && !status_a.admitted);
    assert(status_b.mode == QIHSE_KV_CT_LANE_RECEIVER &&
           status_b.durable_position == 1u && status_b.baseline_sealed);
    assert_value(store, op, key_a, NULL); /* source requires peer re-admission */
    assert_value(store, op, key_b, NULL); /* recovery must not promote by itself */
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_A,
        "peer-a", GEN_A, status_a.baseline_digest, status_a.acknowledged_position));

    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A,
        token_a, &scope));
    assert(qihse_kv_set_user(store, key_a, "lane-a-v2", 4u, 1u, op));
    assert(qihse_kv_ct_lane_source_read(store, peer, LANE_A, GEN_A,
        1u, 8u, 65536u, &groups, &group_count, &resume));
    assert(group_count == 1u && resume == 2u &&
           strcmp(groups[0].records[0].value, "lane-a-v2") == 0);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A,
        "peer-a", GEN_A, resume));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_ct_groups_free(groups, group_count);

    qihse_kv_store_destroy(store);
    qihse_auth_release_principal_scoped(op);
    qihse_auth_release_principal_scoped(low);
    qihse_auth_release_principal_scoped(peer);
    free(key_a);
    free(key_b);
    aimem_fixture_cleanup(data_dir);
    return 0;
}
