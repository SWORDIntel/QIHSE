/* test_ownership_journal.c — append/replay/corruption tests for the durable
 * slot-ownership journal (COPY → PERSIST → SWITCH → GC). */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <arpa/inet.h>

#include "qihse_cluster_ownership.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_audit.h"
#include "qihse_federation.h"

#ifdef QIHSE_OWNERSHIP_JOURNAL_TEST_WRAP_FSYNC
static bool fail_next_fsync_after_success;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    int rc = __real_fsync(fd);
    if (rc == 0 && fail_next_fsync_after_success) {
        fail_next_fsync_after_success = false;
        errno = EINVAL;
        return -1;
    }
    return rc;
}
#endif

static void remove_fixture(const char* path) {
    DIR* dir = opendir(path);
    assert(dir);
    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        assert(unlinkat(dirfd(dir), entry->d_name, 0) == 0);
    }
    assert(closedir(dir) == 0);
    assert(rmdir(path) == 0);
}

typedef struct {
    int count;
    uint16_t last_start, last_end;
    char last_owner[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint64_t last_epoch;
} replay_ctx_t;

static void on_entry(const qihse_cluster_ownership_entry_t* e, void* ctx) {
    replay_ctx_t* r = (replay_ctx_t*)ctx;
    r->count++;
    r->last_start = e->start;
    r->last_end = e->end;
    strncpy(r->last_owner, e->owner_id, QIHSE_CLUSTER_NODE_ID_LEN);
    r->last_owner[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    r->last_epoch = e->config_epoch;
}

typedef struct { unsigned count; qihse_cluster_ownership_phase_t last; } txn_replay_t;
static bool on_txn(const qihse_cluster_ownership_txn_t* t, void* ctx) {
    txn_replay_t* r = ctx;
    r->count++;
    r->last = t->phase;
    return true;
}
static qihse_cluster_ownership_txn_t txn(qihse_cluster_ownership_phase_t phase) {
    qihse_cluster_ownership_txn_t t;
    memset(&t, 0, sizeof(t));
    t.phase = phase; t.start = 500; t.end = 550; t.config_epoch = 8;
    t.source_lsn = 100; t.target_lsn = phase == QIHSE_OWNERSHIP_COMMITTED ? 100 : 0;
    strcpy(t.transfer_id, "ct2-test-1"); strcpy(t.source_id, "node-a");
    strcpy(t.target_id, "node-b"); strcpy(t.generation, "generation-3");
    strcpy(t.source_qkp_id, "qkp-source-configured");
    strcpy(t.target_qkp_id, "qkp-target-configured");
    strcpy(t.owner_id, phase == QIHSE_OWNERSHIP_COMMITTED ? "node-b" : "node-a");
    if (phase == QIHSE_OWNERSHIP_COMMITTED) memset(t.proof_digest, 0x5a, sizeof(t.proof_digest));
    return t;
}

static void assert_txn_zero(const qihse_cluster_ownership_txn_t* t) {
    const unsigned char* p = (const unsigned char*)t;
    for (size_t i = 0; i < sizeof(*t); ++i) assert(p[i] == 0);
}

static qihse_cluster_ownership_txn_t finalized_ct2(const char* id,
                                                    uint16_t first,
                                                    uint16_t last,
                                                    uint64_t epoch) {
    qihse_cluster_ownership_txn_t p = txn(QIHSE_OWNERSHIP_PREPARED);
    snprintf(p.transfer_id, sizeof(p.transfer_id), "%s", id);
    p.start = first; p.end = last; p.config_epoch = epoch;
    qihse_cluster_ownership_txn_t c = p;
    c.phase = QIHSE_OWNERSHIP_COMMITTED;
    c.target_lsn = 1u; /* target and source cursors are independent domains */
    snprintf(c.owner_id, sizeof(c.owner_id), "%s", c.target_id);
    memset(c.proof_digest, 0x6b, sizeof(c.proof_digest));
    c.phase = QIHSE_OWNERSHIP_FINALIZED;
    return c;
}

typedef struct {
    char node[4][QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char pin[4][QIHSE_KV_CT_ID_MAX + 1u];
} promotion_pin_map_t;

static bool promotion_peer_id(void* opaque, const char* topology_id,
                              char out[QIHSE_KV_CT_ID_MAX + 1u]) {
    promotion_pin_map_t* map = opaque;
    if (!map || !topology_id || !out) return false;
    for (size_t i = 0; i < 4; ++i) {
        if (!strcmp(map->node[i], topology_id)) {
            snprintf(out, QIHSE_KV_CT_ID_MAX + 1u, "%s", map->pin[i]);
            return true;
        }
    }
    return false;
}

static void promotion_seal_fields(qihse_cluster_bus_ct1_promotion_update_t* u) {
    char cursor[32];
    snprintf(cursor, sizeof(cursor), "%llu", (unsigned long long)u->durable_cursor);
    const char* fields[] = {u->source_id, u->target_id, u->source_qkp_id,
        u->target_qkp_id, u->successor_id, u->successor_qkp_id,
        u->generation, u->next_generation, cursor};
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    assert(md);
    unsigned int n = 0;
    assert(EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1);
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i)
        assert(EVP_DigestUpdate(md, fields[i], strlen(fields[i])) == 1);
    assert(EVP_DigestFinal_ex(md, u->promotion_digest, &n) == 1 && n == 32);
    EVP_MD_CTX_free(md);
    assert(qihse_cluster_bus_ct1_promotion_seal(u));
}

static void test_signed_ct1_promotion_supersession(qihse_kv_store_t* store,
                                                    qihse_user_t* op,
                                                    qihse_user_t* guest) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);
    promotion_pin_map_t pins;
    memset(&pins, 0, sizeof(pins));
    const char* seeds[] = {"promotion-A", "promotion-B", "promotion-S", "promotion-C"};
    const char* pin_names[] = {"pin-A", "pin-B", "pin-S", "pin-C"};
    qihse_cluster_node_t nodes[4];
    uint16_t ix[4];
    for (size_t i = 0; i < 4; ++i) {
        memset(&nodes[i], 0, sizeof(nodes[i]));
        qihse_cluster_node_id_from_seed(seeds[i], strlen(seeds[i]), nodes[i].id);
        snprintf(pins.node[i], sizeof(pins.node[i]), "%s", nodes[i].id);
        snprintf(pins.pin[i], sizeof(pins.pin[i]), "%s", pin_names[i]);
        snprintf(nodes[i].host, sizeof(nodes[i].host), "127.0.0.1");
        nodes[i].port = (uint16_t)(7200 + i);
        nodes[i].bus_port = (uint16_t)(17200 + i);
        nodes[i].role = QIHSE_CLUSTER_NODE_PRIMARY;
        nodes[i].primary_index = QIHSE_CLUSTER_NODE_NONE;
        nodes[i].healthy = true;
        nodes[i].config_epoch = i == 1 ? 10u : 8u;
        assert(qihse_cluster_topology_upsert_node(topo, &nodes[i], &ix[i]));
    }
    assert(qihse_cluster_topology_adopt_range(topo, 100, 110, ix[0], 8u));
    assert(qihse_cluster_topology_adopt_range(topo, 104, 106, ix[3], 11u));

    qihse_cluster_bus_ct1_promotion_update_t event;
    memset(&event, 0, sizeof(event));
    event.magic = QIHSE_CLUSTER_BUS_CT1_PROMOTION_MAGIC;
    event.start = 100; event.end = 110; event.config_epoch = 10;
    event.durable_cursor = 55;
    snprintf(event.transfer_id, sizeof(event.transfer_id), "ct1-overlap-A-B");
    snprintf(event.source_id, sizeof(event.source_id), "%s", pins.node[0]);
    snprintf(event.target_id, sizeof(event.target_id), "%s", pins.node[1]);
    snprintf(event.source_qkp_id, sizeof(event.source_qkp_id), "%s", pins.pin[0]);
    snprintf(event.target_qkp_id, sizeof(event.target_qkp_id), "%s", pins.pin[1]);
    snprintf(event.successor_id, sizeof(event.successor_id), "%s", pins.node[2]);
    snprintf(event.successor_qkp_id, sizeof(event.successor_qkp_id), "%s", pins.pin[2]);
    snprintf(event.generation, sizeof(event.generation), "generation-old");
    snprintf(event.next_generation, sizeof(event.next_generation), "generation-new");
    for (uint32_t slot = 100; slot <= 110; ++slot)
        event.slot_bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
    promotion_seal_fields(&event);

    qihse_cluster_ownership_context_t ownership = {
        .topology = topo, .store = store, .principal = op,
        .peer_id = promotion_peer_id, .peer_id_context = &pins
    };
    char err[256];
    qihse_cluster_ownership_txn_t canonical_txn;
    memset(&canonical_txn, 0, sizeof(canonical_txn));
    canonical_txn.start = event.start;
    canonical_txn.end = event.end;
    canonical_txn.config_epoch = event.config_epoch;
    canonical_txn.source_lsn = event.durable_cursor;
    snprintf(canonical_txn.transfer_id, sizeof(canonical_txn.transfer_id), "%s", event.transfer_id);
    snprintf(canonical_txn.source_id, sizeof(canonical_txn.source_id), "%s", event.source_id);
    snprintf(canonical_txn.target_id, sizeof(canonical_txn.target_id), "%s", event.target_id);
    snprintf(canonical_txn.source_qkp_id, sizeof(canonical_txn.source_qkp_id), "%s", event.source_qkp_id);
    snprintf(canonical_txn.target_qkp_id, sizeof(canonical_txn.target_qkp_id), "%s", event.target_qkp_id);
    snprintf(canonical_txn.owner_id, sizeof(canonical_txn.owner_id), "%s", event.successor_id);
    snprintf(canonical_txn.generation, sizeof(canonical_txn.generation), "%s", event.generation);
    snprintf(canonical_txn.next_generation, sizeof(canonical_txn.next_generation), "%s", event.next_generation);
    snprintf(canonical_txn.lane_id, sizeof(canonical_txn.lane_id),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    memcpy(canonical_txn.slot_bitmap, event.slot_bitmap, sizeof(canonical_txn.slot_bitmap));
    memcpy(canonical_txn.proof_digest, event.promotion_digest, sizeof(canonical_txn.proof_digest));
    qihse_cluster_bus_ct1_promotion_update_v2_t canonical_event;
    memset(&canonical_event, 0, sizeof(canonical_event));
    canonical_event.magic = QIHSE_CLUSTER_BUS_CT1_PROMOTION_V2_MAGIC;
    canonical_event.base = event;
    snprintf(canonical_event.lane_id, sizeof(canonical_event.lane_id), "%s", canonical_txn.lane_id);
    assert(qihse_cluster_bus_ct1_promotion_v2_seal(&canonical_event));
    uint8_t canonical_digest[32];
    assert(qihse_cluster_ownership_promotion_event_digest(&ownership,
        &canonical_txn, canonical_digest));
    assert(memcmp(canonical_digest, canonical_event.event_digest, sizeof(canonical_digest)) == 0);
    OPENSSL_cleanse(canonical_digest, sizeof(canonical_digest));
    OPENSSL_cleanse(&canonical_event, sizeof(canonical_event));
    qihse_cluster_ownership_context_t low_context = ownership;
    low_context.principal = guest;
    assert(!qihse_cluster_ownership_receive_ct1_promotion(&low_context,
        &event, err, sizeof(err)));
    assert(strstr(err, "active System Operator") != NULL);
    uint16_t denied_owner = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_get_slot(topo, 100, &denied_owner, NULL, NULL));
    assert(denied_owner == ix[0]);
    qihse_cluster_bus_ct1_promotion_update_t forged = event;
    forged.target_id[0] = forged.target_id[0] == 'a' ? 'b' : 'a';
    assert(!qihse_cluster_ownership_receive_ct1_promotion(&ownership,
        &forged, err, sizeof(err)));
    forged = event;
    snprintf(forged.successor_id, sizeof(forged.successor_id), "untrusted-successor");
    snprintf(forged.successor_qkp_id, sizeof(forged.successor_qkp_id), "pin-untrusted");
    promotion_seal_fields(&forged);
    assert(!qihse_cluster_ownership_receive_ct1_promotion(&ownership,
        &forged, err, sizeof(err)));

    /* This observer missed A->B. A later valid B->C promotion cannot replace
     * A's unrelated local ownership without an authenticated skipped-link
     * proof, even though its epoch is newer and C's target proof is valid. */
    qihse_cluster_bus_ct1_promotion_update_t skipped = event;
    skipped.config_epoch = 12;
    snprintf(skipped.transfer_id, sizeof(skipped.transfer_id), "ct1-skipped-A-B-C");
    snprintf(skipped.source_id, sizeof(skipped.source_id), "%s", pins.node[1]);
    snprintf(skipped.target_id, sizeof(skipped.target_id), "%s", pins.node[3]);
    snprintf(skipped.source_qkp_id, sizeof(skipped.source_qkp_id), "%s", pins.pin[1]);
    snprintf(skipped.target_qkp_id, sizeof(skipped.target_qkp_id), "%s", pins.pin[3]);
    promotion_seal_fields(&skipped);
    assert(!qihse_cluster_ownership_receive_ct1_promotion(&ownership,
        &skipped, err, sizeof(err)));
    assert(strstr(err, "conflicts with a newer or same-epoch owner") != NULL);

    /* The bus handler has verified the target signature; ownership validation
     * persists ADOPTED, updates the still-lagging outer runs, and skips only
     * the newer B->C middle slots. */
    bool adopted = qihse_cluster_ownership_receive_ct1_promotion(&ownership,
        &event, err, sizeof(err));
    if (!adopted) fprintf(stderr, "CT1 promotion adoption failed: %s\n", err);
    assert(adopted);
    for (uint16_t slot = 100; slot <= 110; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        uint64_t epoch = 0;
        assert(qihse_cluster_topology_get_slot(topo, slot, &owner, NULL, NULL));
        assert(qihse_cluster_topology_get_slot_epoch(topo, slot, &epoch));
        if (slot >= 104 && slot <= 106) assert(owner == ix[3] && epoch == 11u);
        else assert(owner == ix[1] && epoch == 10u);
    }

    /* Restart with a stale topology after B has since advanced and become a
     * replica of C. Replaying the old durable A->B receipt must not restore
     * A's slots to B or roll B back to primary. */
    assert(qihse_kv_ct_source_enable(store, op, "stale-source:1",
        "stale-successor:1", "stale-generation:1", NULL,
        128u * 1024u * 1024u));
    for (unsigned replay_case = 0; replay_case < 2; ++replay_case) {
        qihse_cluster_topology_t* replay_topo = qihse_cluster_topology_create();
        assert(replay_topo);
        qihse_cluster_node_t replay_nodes[4];
        uint16_t replay_ix[4];
        for (size_t i = 0; i < 4; ++i) {
            replay_nodes[i] = nodes[i];
            replay_nodes[i].config_epoch = 20u;
            assert(qihse_cluster_topology_upsert_node(replay_topo,
                &replay_nodes[i], &replay_ix[i]));
        }
        replay_nodes[1].role = QIHSE_CLUSTER_NODE_REPLICA;
        replay_nodes[1].primary_index = replay_case ? replay_ix[0] : replay_ix[3];
        replay_nodes[1].config_epoch = replay_case ? 10u : 20u;
        assert(qihse_cluster_topology_upsert_node(replay_topo, &replay_nodes[1], NULL));
        assert(qihse_cluster_topology_adopt_range(replay_topo, 100, 100, replay_ix[0], 8u));
        ownership.topology = replay_topo;
        bool replay_unresolved = true;
        assert(qihse_cluster_ownership_replay(&ownership, &replay_unresolved,
            err, sizeof(err)));
        assert(!replay_unresolved);
        qihse_cluster_node_t replay_check;
        assert(qihse_cluster_topology_get_node(replay_topo, replay_ix[1], &replay_check));
        assert(replay_check.role == QIHSE_CLUSTER_NODE_REPLICA &&
               replay_check.primary_index == replay_nodes[1].primary_index &&
               replay_check.config_epoch == replay_nodes[1].config_epoch);
        uint16_t replay_owner = QIHSE_CLUSTER_NODE_NONE;
        assert(qihse_cluster_topology_get_slot(replay_topo, 100,
            &replay_owner, NULL, NULL));
        assert(replay_owner == replay_ix[0]);
        qihse_cluster_topology_destroy(replay_topo);
    }

    /* One valid maximal run carries the full signed bitmap. Disjoint slots in
     * the same durable promotion event must be adopted together. */
    qihse_cluster_topology_t* disjoint_topo = qihse_cluster_topology_create();
    assert(disjoint_topo);
    for (size_t i = 0; i < 4; ++i) assert(qihse_cluster_topology_upsert_node(
        disjoint_topo, &nodes[i], &ix[i]));
    assert(qihse_cluster_topology_adopt_range(disjoint_topo, 200, 200, ix[0], 8u));
    assert(qihse_cluster_topology_adopt_range(disjoint_topo, 202, 202, ix[0], 8u));
    qihse_cluster_bus_ct1_promotion_update_t disjoint = event;
    disjoint.start = 200; disjoint.end = 200;
    disjoint.config_epoch = 12;
    snprintf(disjoint.transfer_id, sizeof(disjoint.transfer_id), "ct1-disjoint-A-B");
    memset(disjoint.slot_bitmap, 0, sizeof(disjoint.slot_bitmap));
    disjoint.slot_bitmap[200 / 8u] |= (uint8_t)(1u << (200 % 8u));
    disjoint.slot_bitmap[202 / 8u] |= (uint8_t)(1u << (202 % 8u));
    promotion_seal_fields(&disjoint);
    ownership.topology = disjoint_topo;
    assert(qihse_cluster_ownership_receive_ct1_promotion(&ownership,
        &disjoint, err, sizeof(err)));
    for (uint16_t slot = 200; slot <= 202; slot += 2) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        uint64_t epoch = 0;
        assert(qihse_cluster_topology_get_slot(disjoint_topo, slot, &owner, NULL, NULL));
        assert(qihse_cluster_topology_get_slot_epoch(disjoint_topo, slot, &epoch));
        assert(owner == ix[1] && epoch == disjoint.config_epoch);
    }
    qihse_cluster_topology_destroy(disjoint_topo);

    /* A signed A->B event can arrive after B's node epoch advanced for other
     * ranges. Even when B remains a primary, the old proof cannot establish
     * that A's lagging slots still belong to B; they must wait for the newer
     * promotion chain. */
    for (unsigned role_case = 0; role_case < 3; ++role_case) {
        nodes[0].role = QIHSE_CLUSTER_NODE_PRIMARY;
        nodes[0].primary_index = QIHSE_CLUSTER_NODE_NONE;
        nodes[0].config_epoch = 20;
        nodes[1].role = role_case == 1 ? QIHSE_CLUSTER_NODE_PRIMARY :
                                             QIHSE_CLUSTER_NODE_REPLICA;
        nodes[1].primary_index = role_case == 1 ? QIHSE_CLUSTER_NODE_NONE :
                                    role_case == 0 ? ix[3] : ix[0];
        nodes[1].config_epoch = role_case == 2 ? 10 : 20;
        nodes[2].config_epoch = 20;
        nodes[3].config_epoch = 20;
        qihse_cluster_topology_t* stale_topo = qihse_cluster_topology_create();
        assert(stale_topo);
        for (size_t i = 0; i < 4; ++i) assert(qihse_cluster_topology_upsert_node(
            stale_topo, &nodes[i], &ix[i]));
        assert(qihse_cluster_topology_adopt_range(stale_topo, 100, 100, ix[0], 8u));
        assert(qihse_cluster_topology_adopt_range(stale_topo, 101, 110, ix[3], 20u));
        ownership.topology = stale_topo;
        snprintf(event.transfer_id, sizeof(event.transfer_id), "ct1-stale-role-check");
        event.config_epoch = 10;
        promotion_seal_fields(&event);
        assert(qihse_cluster_ownership_receive_ct1_promotion(&ownership,
            &event, err, sizeof(err)));
        qihse_cluster_node_t check;
        assert(qihse_cluster_topology_get_node(stale_topo, ix[1], &check));
        assert(check.role == nodes[1].role &&
               check.primary_index == nodes[1].primary_index &&
               check.config_epoch == nodes[1].config_epoch);
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        assert(qihse_cluster_topology_get_slot(stale_topo, 100, &owner, NULL, NULL));
        assert(owner == ix[0]);

        qihse_cluster_topology_destroy(stale_topo);
    }
    qihse_cluster_topology_destroy(topo);
    puts("[PASS] signed CT1 promotion validates pins, preserves overlap, and skips stale role rollback");
}

typedef struct {
    qihse_cluster_ownership_context_t* ownership;
    promotion_pin_map_t pins;
    char allowed_transfer_id[2][QIHSE_OWNERSHIP_ID_MAX + 1u];
    uint8_t allowed_slots[2][QIHSE_OWNERSHIP_SLOT_BITMAP_BYTES];
    uint16_t final_owner[QIHSE_CLUSTER_SLOT_COUNT];
    uint64_t final_epoch[QIHSE_CLUSTER_SLOT_COUNT];
} promotion_chain_authority_t;

static bool chain_range_check(void* opaque, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction, char* err, size_t err_cap) {
    promotion_chain_authority_t* state = opaque;
    if (err && err_cap) err[0] = '\0';
    bool ok = qihse_auth_user_is_active(principal) &&
        qihse_user_get_role(principal) == QIHSE_ROLE_OPERATOR;
    if (ok && state && transaction && transaction->lane_id[0]) {
        ok = false;
        for (size_t i = 0; i < 2u; ++i)
            if (!strcmp(transaction->transfer_id, state->allowed_transfer_id[i]) &&
                CRYPTO_memcmp(transaction->slot_bitmap, state->allowed_slots[i],
                    sizeof(transaction->slot_bitmap)) == 0) {
                ok = true;
                break;
            }
    }
    return ok;
}

static bool chain_range_refresh(void* opaque, qihse_user_t* principal,
    const uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES], char* err, size_t err_cap) {
    promotion_chain_authority_t* state = opaque;
    if (!state || !state->ownership || !slots ||
        !qihse_auth_user_is_active(principal) ||
        qihse_user_get_role(principal) != QIHSE_ROLE_OPERATOR) return false;
    for (uint32_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; ++slot) {
        if (!(slots[slot / 8u] & (uint8_t)(1u << (slot % 8u)))) continue;
        uint16_t owner = state->final_owner[slot];
        uint64_t epoch = state->final_epoch[slot];
        if (owner == QIHSE_CLUSTER_NODE_NONE || !epoch ||
            !qihse_cluster_topology_adopt_range(state->ownership->topology,
                (uint16_t)slot, (uint16_t)slot, owner, epoch)) {
            if (err && err_cap) snprintf(err, err_cap,
                "test common ownership map has no committed owner for slot %u", slot);
            return false;
        }
    }
    return true;
}

static bool chain_range_reserve(void* opaque, qihse_user_t* principal,
    qihse_cluster_ownership_txn_t* transaction, char* err, size_t err_cap) {
    return chain_range_check(opaque, principal, transaction, err, err_cap);
}

static bool chain_range_finalize(void* opaque, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    const qihse_cluster_ct_activation_receipt_t* receipt,
    char* err, size_t err_cap) {
    (void)receipt;
    return chain_range_check(opaque, principal, transaction, err, err_cap);
}

static bool chain_promotion_finalize(void* opaque, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    const qihse_kv_ct_proof_t* promoted_proof,
    const uint8_t event_digest[32], char* err, size_t err_cap) {
    (void)promoted_proof; (void)event_digest;
    return chain_range_check(opaque, principal, transaction, err, err_cap);
}

static bool chain_lane_claim(void* opaque, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    qihse_kv_ct_lane_authority_claim_t* claim) {
    promotion_chain_authority_t* state = opaque;
    if (!state || !claim || !qihse_auth_user_is_active(principal)) return false;
    memset(claim, 0, sizeof(*claim));
    claim->operation = QIHSE_KV_CT_LANE_AUTH_PROMOTION;
    snprintf(claim->transfer_id, sizeof(claim->transfer_id), "%s", transaction->transfer_id);
    snprintf(claim->source_group_id, sizeof(claim->source_group_id), "%s", transaction->lane_id);
    snprintf(claim->target_group_id, sizeof(claim->target_group_id), "%s", transaction->lane_id);
    snprintf(claim->source_qkp_id, sizeof(claim->source_qkp_id), "%s", transaction->source_qkp_id);
    snprintf(claim->target_qkp_id, sizeof(claim->target_qkp_id), "%s", transaction->target_qkp_id);
    snprintf(claim->source_generation, sizeof(claim->source_generation), "%s", transaction->generation);
    snprintf(claim->target_generation, sizeof(claim->target_generation), "%s", transaction->next_generation);
    uint16_t successor = QIHSE_CLUSTER_NODE_NONE;
    if (!qihse_cluster_topology_find_node(state->ownership->topology,
            transaction->owner_id, &successor)) return false;
    char successor_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    if (!promotion_peer_id(&state->pins, transaction->owner_id, successor_qkp)) return false;
    snprintf(claim->successor_qkp_id, sizeof(claim->successor_qkp_id), "%s", successor_qkp);
    claim->grant_epoch = transaction->config_epoch;
    claim->source_cut = transaction->source_lsn;
    claim->target_cursor = transaction->target_lsn;
    memcpy(claim->slots, transaction->slot_bitmap, sizeof(claim->slots));
    uint8_t event_digest[32];
    bool ok = qihse_cluster_ownership_promotion_event_digest(state->ownership,
        transaction, event_digest);
    if (ok) memcpy(claim->promotion_event_digest, event_digest, sizeof(event_digest));
    OPENSSL_cleanse(event_digest, sizeof(event_digest));
    OPENSSL_cleanse(successor_qkp, sizeof(successor_qkp));
    return ok;
}

static bool chain_lane_verify(void* opaque, qihse_user_t* principal,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool require_final) {
    (void)opaque; (void)require_final;
    return claim && qihse_auth_user_is_active(principal) &&
        qihse_user_get_role(principal) == QIHSE_ROLE_OPERATOR;
}

static size_t sign_ct1_certificate(uint8_t* out, size_t cap,
    const qihse_cluster_bus_ct1_promotion_update_v2_t* update,
    uint32_t sender_index, void* private_key,
    const qihse_federation_node_identity_t* identity) {
    size_t frame_len = QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(*update);
    assert(frame_len + 4700u <= cap);
    uint32_t be = htonl(QIHSE_CLUSTER_BUS_MAGIC);
    memcpy(out, &be, 4u);
    be = htonl(QIHSE_BUS_MSG_SLOT_UPDATE); memcpy(out + 4u, &be, 4u);
    be = htonl(sender_index); memcpy(out + 8u, &be, 4u);
    be = htonl((uint32_t)sizeof(*update)); memcpy(out + 12u, &be, 4u);
    memcpy(out + QIHSE_CLUSTER_BUS_HEADER_SIZE, update, sizeof(*update));
    uint8_t signature[4627];
    size_t signature_len = sizeof(signature);
    assert(qihse_federation_sign(private_key, out, frame_len, signature, &signature_len));
    uint8_t* trailer = out + frame_len;
    *trailer++ = 1u;
    *trailer++ = (uint8_t)(signature_len & 0xffu);
    *trailer++ = (uint8_t)(signature_len >> 8);
    memcpy(trailer, identity->node_id.bytes, 16u); trailer += 16u;
    memcpy(trailer, signature, signature_len); trailer += signature_len;
    *trailer++ = 1u;
    *trailer++ = (uint8_t)(signature_len & 0xffu);
    *trailer++ = (uint8_t)(signature_len >> 8);
    *trailer++ = 'Q'; *trailer++ = 'B'; *trailer++ = 'S';
    OPENSSL_cleanse(signature, sizeof(signature));
    return (size_t)(trailer - out);
}

static void test_signed_ct1_missing_predecessor_chain(qihse_kv_store_t* store,
    qihse_user_t* op, qihse_user_t* guest) {
    (void)store;
    char chain_data_dir[] = "./tests/.qihse_ct1_chain_store_XXXXXX";
    assert(mkdtemp(chain_data_dir));
    const char* old_data_dir = getenv("QIHSE_DATA_DIR");
    char* saved_data_dir = old_data_dir ? strdup(old_data_dir) : NULL;
    assert(!old_data_dir || saved_data_dir);
    assert(setenv("QIHSE_DATA_DIR", chain_data_dir, 1) == 0);
    qihse_kv_store_t* chain_store = qihse_kv_store_create_user(op);
    assert(chain_store);
    if (saved_data_dir) {
        assert(setenv("QIHSE_DATA_DIR", saved_data_dir, 1) == 0);
        free(saved_data_dir);
    } else assert(unsetenv("QIHSE_DATA_DIR") == 0);
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology);
    qihse_federation_node_identity_t identities[2];
    void* private_keys[2] = {NULL, NULL};
    memset(identities, 0, sizeof(identities));
    qihse_cluster_node_t nodes[4];
    uint16_t indices[4];
    promotion_chain_authority_t authority;
    memset(&authority, 0, sizeof(authority));
    const char* names[] = {"chain-A", "chain-B", "chain-C", "chain-observer"};
    const char* pins[] = {"chain-pin-A", "chain-pin-B", "chain-pin-C", "chain-pin-observer"};
    for (size_t i = 0; i < 4; ++i) {
        memset(&nodes[i], 0, sizeof(nodes[i]));
        qihse_cluster_node_id_from_seed(names[i], strlen(names[i]), nodes[i].id);
        snprintf(nodes[i].host, sizeof(nodes[i].host), "127.0.0.1");
        nodes[i].port = (uint16_t)(7600u + i); nodes[i].bus_port = (uint16_t)(17600u + i);
        nodes[i].role = QIHSE_CLUSTER_NODE_PRIMARY;
        nodes[i].primary_index = QIHSE_CLUSTER_NODE_NONE;
        nodes[i].healthy = true; nodes[i].config_epoch = 4u;
        snprintf(authority.pins.node[i], sizeof(authority.pins.node[i]), "%s", nodes[i].id);
        snprintf(authority.pins.pin[i], sizeof(authority.pins.pin[i]), "%s", pins[i]);
    }
    for (size_t i = 0; i < 2; ++i) {
        size_t target = i + 1u;
        assert(qihse_cluster_node_federation_uuid(nodes[target].id,
            identities[i].node_id.bytes));
        snprintf(identities[i].hostname, sizeof(identities[i].hostname), "ct1-chain-%zu", i);
        snprintf(identities[i].boot_id, sizeof(identities[i].boot_id), "ct1-chain-boot-%zu", i);
        identities[i].identity_kind = QIHSE_IDENTITY_HOST_AGENT;
        assert(qihse_federation_node_keygen_alg(
            qihse_kv_store_data_directory(store), QIHSE_SIG_ML_DSA_87, &identities[i]));
        qihse_federation_node_identity_t existing_identity;
        bool identity_preexisting = qihse_federation_node_identity_read(store,
            op, &identities[i].node_id, &existing_identity);
        if (identity_preexisting) {
            fprintf(stderr, "unexpected preexisting chain identity %s\n",
                identities[i].key_handle);
            abort();
        }
        if (!qihse_federation_node_enroll_request(store, op, &identities[i])) {
            fprintf(stderr, "chain enroll request failed: keylen=%u alg=%u key=%s errno=%d\n",
                identities[i].public_key_len, (unsigned)identities[i].sig_alg,
                identities[i].key_handle, errno);
            fprintf(stderr, "operator=%d scope=%d keydir=%s\n",
                qihse_auth_user_is_active(op), qihse_infra_scope_check(op, QIHSE_SCOPE_NODE_ENROLL),
                qihse_kv_store_data_directory(chain_store));
            abort();
        }
        assert(qihse_federation_node_enroll_approve(store, op, &identities[i].node_id, 1u));
        private_keys[i] = qihse_federation_node_key_load(identities[i].key_handle);
        assert(private_keys[i]);
    }
    for (size_t i = 0; i < 4; ++i)
        assert(qihse_cluster_topology_upsert_node(topology, &nodes[i], &indices[i]));
    assert(qihse_cluster_topology_set_local_node(topology, indices[3]));
    assert(qihse_cluster_topology_adopt_range(topology, 100u, 101u, indices[0], 4u));
    qihse_cluster_bus_config_t bus_config;
    memset(&bus_config, 0, sizeof(bus_config));
    bus_config.topology = topology; bus_config.local_node_index = indices[3];
    bus_config.bus_port = 0u; bus_config.bind_address = "127.0.0.1";
    bus_config.federation_store = store; bus_config.federation_user = op;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&bus_config);
    assert(bus);
    promotion_pin_map_t* map = &authority.pins;
    qihse_cluster_ownership_context_t ownership;
    memset(&ownership, 0, sizeof(ownership));
    ownership.topology = topology; ownership.bus = bus; ownership.store = chain_store;
    ownership.principal = op; ownership.data_principal = op;
    ownership.peer_id = promotion_peer_id; ownership.peer_id_context = map;
    ownership.range_reserve = chain_range_reserve;
    ownership.range_check_reserved = chain_range_check;
    ownership.range_finalize = chain_range_finalize;
    ownership.range_check_finalized = chain_range_check;
    ownership.range_abort = chain_range_check;
    ownership.range_finalize_promotion = chain_promotion_finalize;
    ownership.lane_claim = chain_lane_claim; ownership.lane_verify_claim = chain_lane_verify;
    ownership.range_refresh = chain_range_refresh;
    ownership.range_authority_context = &authority;
    authority.ownership = &ownership;
    for (size_t i = 0; i < QIHSE_CLUSTER_SLOT_COUNT; ++i)
        authority.final_owner[i] = QIHSE_CLUSTER_NODE_NONE;
    authority.final_owner[100] = indices[2]; authority.final_epoch[100] = 6u;
    authority.final_owner[101] = indices[3]; authority.final_epoch[101] = 7u;

    qihse_cluster_bus_ct1_promotion_update_v2_t updates[2];
    memset(updates, 0, sizeof(updates));
    const size_t sources[] = {0u, 1u}, targets[] = {1u, 2u}, successors[] = {2u, 0u};
    const char* generations[] = {"chain-generation-A", "chain-generation-B"};
    const char* next_generations[] = {"chain-generation-B", "chain-generation-C"};
    uint8_t* envelopes[2] = {calloc(1, 8192u), calloc(1, 8192u)};
    assert(envelopes[0] && envelopes[1]);
    size_t lengths[2] = {0, 0};
    for (size_t i = 0; i < 2; ++i) {
        qihse_cluster_bus_ct1_promotion_update_t* base = &updates[i].base;
        base->magic = QIHSE_CLUSTER_BUS_CT1_PROMOTION_MAGIC;
        base->start = 100u; base->end = (uint16_t)(i ? 100u : 101u);
        base->config_epoch = (uint64_t)(5u + i);
        base->durable_cursor = 50u + i;
        snprintf(base->transfer_id, sizeof(base->transfer_id), "ct1-chain-%zu", i);
        snprintf(base->source_id, sizeof(base->source_id), "%s", nodes[sources[i]].id);
        snprintf(base->target_id, sizeof(base->target_id), "%s", nodes[targets[i]].id);
        snprintf(base->source_qkp_id, sizeof(base->source_qkp_id), "%s", pins[sources[i]]);
        snprintf(base->target_qkp_id, sizeof(base->target_qkp_id), "%s", pins[targets[i]]);
        snprintf(base->successor_id, sizeof(base->successor_id), "%s", nodes[successors[i]].id);
        snprintf(base->successor_qkp_id, sizeof(base->successor_qkp_id), "%s", pins[successors[i]]);
        snprintf(base->generation, sizeof(base->generation), "%s", generations[i]);
        snprintf(base->next_generation, sizeof(base->next_generation), "%s", next_generations[i]);
        base->slot_bitmap[100u / 8u] |= (uint8_t)(1u << (100u % 8u));
        if (!i) base->slot_bitmap[101u / 8u] |= (uint8_t)(1u << (101u % 8u));
        promotion_seal_fields(base);
        updates[i].magic = QIHSE_CLUSTER_BUS_CT1_PROMOTION_V2_MAGIC;
        updates[i].target_cursor = 80u + i;
        snprintf(updates[i].lane_id, sizeof(updates[i].lane_id),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        assert(qihse_cluster_bus_ct1_promotion_v2_seal(&updates[i]));
        snprintf(authority.allowed_transfer_id[i],
            sizeof(authority.allowed_transfer_id[i]), "%s", base->transfer_id);
        memcpy(authority.allowed_slots[i], base->slot_bitmap,
            sizeof(base->slot_bitmap));
        lengths[i] = sign_ct1_certificate(envelopes[i], 8192u, &updates[i],
            (uint32_t)indices[targets[i]], private_keys[i], &identities[i]);
    }
    const uint8_t* ordered[] = {envelopes[0], envelopes[1]};
    char err[192] = {0};
    for (size_t i = 0; i < 2u; ++i) {
        qihse_cluster_bus_ct1_promotion_update_v2_t decoded;
        qihse_uuid_t signer;
        qihse_federation_node_identity_t enrolled;
        assert(qihse_federation_node_identity_read(store, op,
            &identities[i].node_id, &enrolled));
        assert(enrolled.trust == QIHSE_TRUST_APPROVED);
        size_t siglen = (size_t)envelopes[i][lengths[i] - 5u] |
            ((size_t)envelopes[i][lengths[i] - 4u] << 8u);
        size_t signed_len = lengths[i] - (25u + siglen);
        assert(siglen <= 4627u && signed_len == QIHSE_CLUSTER_BUS_HEADER_SIZE +
            sizeof(updates[i]));
        assert(qihse_federation_verify(enrolled.sig_alg, enrolled.public_key,
            enrolled.public_key_len, envelopes[i], signed_len,
            envelopes[i] + signed_len + 19u, siglen));
        bool certificate_ok = qihse_cluster_bus_ct1_certificate_verify(bus,
            envelopes[i], lengths[i], &decoded, &signer);
        if (!certificate_ok) fprintf(stderr, "QCP2 cert %zu failed decode, len=%zu\n", i, lengths[i]);
        assert(certificate_ok);
    }
    qihse_cluster_ownership_context_t guest_ownership = ownership;
    guest_ownership.principal = guest;
    assert(!qihse_cluster_ownership_receive_ct1_promotion_chain(&guest_ownership,
        ordered, lengths, 2u, err, sizeof(err)));
    for (uint16_t slot = 100; slot <= 101; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE; uint64_t epoch = 0;
        assert(qihse_cluster_topology_get_slot(topology, slot, &owner, NULL, NULL));
        assert(qihse_cluster_topology_get_slot_epoch(topology, slot, &epoch));
        assert(owner == indices[0] && epoch == 4u);
    }
    bool chain_ok = qihse_cluster_ownership_receive_ct1_promotion_chain(&ownership,
        ordered, lengths, 2u, err, sizeof(err));
    if (!chain_ok) fprintf(stderr, "QCP2 chain rejected: %s\n", err);
    assert(chain_ok);
    for (uint16_t slot = 100; slot <= 101; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE; uint64_t epoch = 0;
        assert(qihse_cluster_topology_get_slot(topology, slot, &owner, NULL, NULL));
        assert(qihse_cluster_topology_get_slot_epoch(topology, slot, &epoch));
        assert(owner == authority.final_owner[slot] && epoch == authority.final_epoch[slot]);
    }
    qihse_cluster_topology_t* replay_topology = qihse_cluster_topology_create();
    assert(replay_topology);
    uint16_t replay_indices[4];
    for (size_t i = 0; i < 4; ++i)
        assert(qihse_cluster_topology_upsert_node(replay_topology, &nodes[i],
            &replay_indices[i]));
    assert(qihse_cluster_topology_set_local_node(replay_topology, replay_indices[3]));
    assert(qihse_cluster_topology_adopt_range(replay_topology, 100u, 101u,
        replay_indices[0], 4u));
    qihse_cluster_ownership_context_t replay_ownership = ownership;
    replay_ownership.topology = replay_topology;
    replay_ownership.bus = NULL;
    authority.ownership = &replay_ownership;
    bool replay_unresolved = false;
    bool replay_ok = qihse_cluster_ownership_replay_control(&replay_ownership,
        &replay_unresolved, err, sizeof(err));
    if (!replay_ok || replay_unresolved)
        fprintf(stderr, "CT1 chain replay failed: unresolved=%d %s\n",
            replay_unresolved, err);
    assert(replay_ok && !replay_unresolved);
    for (uint16_t slot = 100; slot <= 101; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE; uint64_t epoch = 0;
        assert(qihse_cluster_topology_get_slot(replay_topology, slot, &owner, NULL, NULL));
        assert(qihse_cluster_topology_get_slot_epoch(replay_topology, slot, &epoch));
        assert(owner == authority.final_owner[slot] && epoch == authority.final_epoch[slot]);
    }
    for (size_t i = 0; i < 4; ++i) {
        qihse_cluster_node_t replay_node;
        assert(qihse_cluster_topology_get_node(replay_topology, replay_indices[i],
            &replay_node));
        assert(replay_node.role == QIHSE_CLUSTER_NODE_PRIMARY);
        assert(replay_node.config_epoch >= 4u);
    }
    qihse_cluster_topology_destroy(replay_topology);
    authority.ownership = &ownership;
    const uint8_t* reversed[] = {envelopes[1], envelopes[0]};
    assert(!qihse_cluster_ownership_receive_ct1_promotion_chain(&ownership,
        reversed, lengths, 2u, err, sizeof(err)));
    qihse_cluster_bus_ct1_promotion_update_v2_t forged = updates[1];
    forged.base.end = 102u;
    forged.base.slot_bitmap[102u / 8u] |= (uint8_t)(1u << (102u % 8u));
    assert(qihse_cluster_bus_ct1_promotion_seal(&forged.base));
    assert(qihse_cluster_bus_ct1_promotion_v2_seal(&forged));
    uint8_t* forged_envelope = calloc(1, 8192u);
    assert(forged_envelope);
    size_t forged_len = sign_ct1_certificate(forged_envelope, 8192u, &forged,
        (uint32_t)indices[2], private_keys[1], &identities[1]);
    const uint8_t* conflicting[] = {envelopes[0], forged_envelope};
    size_t conflicting_lengths[] = {lengths[0], forged_len};
    assert(!qihse_cluster_ownership_receive_ct1_promotion_chain(&ownership,
        conflicting, conflicting_lengths, 2u, err, sizeof(err)));
    for (uint16_t slot = 100; slot <= 101; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE; uint64_t epoch = 0;
        assert(qihse_cluster_topology_get_slot(topology, slot, &owner, NULL, NULL));
        assert(qihse_cluster_topology_get_slot_epoch(topology, slot, &epoch));
        /* Rejection preserves the newer common map, including the CT2
         * transition interleaved with this historical promotion chain. */
        assert(owner == authority.final_owner[slot] && epoch == authority.final_epoch[slot]);
    }
    assert(qihse_cluster_ownership_receive_ct1_promotion_chain(&ownership,
        ordered, lengths, 2u, err, sizeof(err)));
    txn_replay_t adopted_count = {0};
    bool adopted_pending = false;
    assert(qihse_cluster_ownership_journal_replay_txn(
        qihse_kv_store_data_directory(chain_store), on_txn, &adopted_count,
        &adopted_pending) == 2);
    assert(adopted_count.count == 2u && !adopted_pending);
    free(forged_envelope);
    free(envelopes[0]); free(envelopes[1]);
    for (size_t i = 0; i < 2; ++i) qihse_federation_node_key_free(private_keys[i]);
    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topology);
    char chain_journal[PATH_MAX];
    assert(snprintf(chain_journal, sizeof(chain_journal), "%s/slot-ownership.journal",
        qihse_kv_store_data_directory(chain_store)) > 0);
    assert(unlink(chain_journal) == 0);
    qihse_kv_store_destroy(chain_store);
    remove_fixture(chain_data_dir);
    puts("[PASS] signed CT1 A->B->C chain repairs a missed predecessor, replays only slot ownership, and rejects reordered/conflicting certificates");
}

typedef struct {
    const char* dir;
    qihse_cluster_ownership_txn_t txn;
    int result;
} terminal_race_t;
static void* append_terminal_race(void* opaque) {
    terminal_race_t* r = opaque;
    r->result = qihse_cluster_ownership_journal_append_txn(r->dir, &r->txn);
    return NULL;
}

typedef struct {
    const char* data_dir;
    qihse_user_t* expected_principal;
    unsigned reserve_calls;
    uint64_t epoch;
    bool reject_reservation;
} range_authority_test_t;

static bool range_authority_test_reserve(void* opaque, qihse_user_t* principal,
    qihse_cluster_ownership_txn_t* draft, char* err, size_t err_cap) {
    range_authority_test_t* state = opaque;
    assert(state && principal == state->expected_principal && draft);
    assert(draft->phase == QIHSE_OWNERSHIP_INTENT && draft->config_epoch == 0 &&
        draft->source_lsn == 0 && draft->start == 3 && draft->end == 5);
    bool unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(state->data_dir,
        NULL, NULL, &unresolved) == 0 && !unresolved);
    state->reserve_calls++;
    draft->config_epoch = state->epoch;
    if (err && err_cap) err[0] = '\0';
    return !state->reject_reservation;
}

static bool range_authority_test_check(void* opaque, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* txn, char* err, size_t err_cap) {
    range_authority_test_t* state = opaque;
    assert(state && principal == state->expected_principal && txn);
    if (err && err_cap) err[0] = '\0';
    return txn->config_epoch == state->epoch;
}

static bool capture_txn(const qihse_cluster_ownership_txn_t* txn, void* opaque) {
    qihse_cluster_ownership_txn_t* out = opaque;
    *out = *txn;
    return true;
}

static bool range_authority_test_finalize(void* opaque, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* txn,
    const qihse_cluster_ct_activation_receipt_t* receipt,
    char* err, size_t err_cap) {
    (void)receipt;
    return range_authority_test_check(opaque, principal, txn, err, err_cap);
}

static void test_range_authority_reserve_precedes_intent(qihse_user_t* op) {
    char data_dir_buf[] = "./tests/.qihse_range_authority_XXXXXX";
    assert(mkdtemp(data_dir_buf));
    const char* old_env = getenv("QIHSE_DATA_DIR");
    char* old_data_dir = old_env ? strdup(old_env) : NULL;
    assert(!old_env || old_data_dir);
    assert(setenv("QIHSE_DATA_DIR", data_dir_buf, 1) == 0);
    qihse_kv_store_t* store = qihse_kv_store_create();
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(store && topology);
    const char* data_dir = qihse_kv_store_data_directory(store);
    assert(data_dir && *data_dir);
    qihse_cluster_node_t nodes[2];
    uint16_t indices[2];
    const char* seeds[] = {"range-auth-source", "range-auth-target"};
    const char* pins[] = {"range-auth-qkp-source", "range-auth-qkp-target"};
    for (size_t i = 0; i < 2; ++i) {
        memset(&nodes[i], 0, sizeof(nodes[i]));
        qihse_cluster_node_id_from_seed(seeds[i], strlen(seeds[i]), nodes[i].id);
        snprintf(nodes[i].host, sizeof(nodes[i].host), "127.0.0.1");
        nodes[i].port = (uint16_t)(7500u + i);
        nodes[i].bus_port = (uint16_t)(17500u + i);
        nodes[i].role = QIHSE_CLUSTER_NODE_PRIMARY;
        nodes[i].healthy = true;
        assert(qihse_cluster_topology_upsert_node(topology, &nodes[i], &indices[i]));
    }
    assert(qihse_cluster_topology_set_local_node(topology, indices[0]));
    assert(qihse_cluster_topology_adopt_range(topology, 3, 5, indices[0], 2));
    assert(qihse_kv_ct_source_enable(store, op, pins[0], "range-auth-replica",
        "range-auth-generation", NULL, 128u * 1024u * 1024u));

    promotion_pin_map_t pin_map;
    memset(&pin_map, 0, sizeof(pin_map));
    for (size_t i = 0; i < 2; ++i) {
        snprintf(pin_map.node[i], sizeof(pin_map.node[i]), "%s", nodes[i].id);
        snprintf(pin_map.pin[i], sizeof(pin_map.pin[i]), "%s", pins[i]);
    }
    range_authority_test_t state = {.data_dir = data_dir,
        .expected_principal = op, .epoch = 42, .reject_reservation = true};
    qihse_cluster_ownership_context_t context = {
        .topology = topology, .store = store, .principal = op,
        .data_principal = op, .peer_id = promotion_peer_id,
        .peer_id_context = &pin_map, .range_reserve = range_authority_test_reserve,
        .range_check_reserved = range_authority_test_check,
        .range_finalize = range_authority_test_finalize,
        .range_check_finalized = range_authority_test_check,
        .range_abort = range_authority_test_check,
        .range_authority_context = &state
    };
    uint64_t source_cut = 0;
    bool recovery = false;
    char err[192] = {0};
    qihse_cluster_ownership_context_t incomplete = context;
    incomplete.range_abort = NULL;
    assert(!qihse_cluster_ownership_transfer_prepare_ex(&incomplete,
        "range-auth-incomplete", indices[0], indices[1], 3, 5,
        &source_cut, &recovery, err, sizeof(err)));
    assert(state.reserve_calls == 0 && !recovery && source_cut == 0);
    bool prepared_ok = qihse_cluster_ownership_transfer_prepare_ex(&context,
        "range-auth-transfer", indices[0], indices[1], 3, 5,
        &source_cut, &recovery, err, sizeof(err));
    assert(!prepared_ok && state.reserve_calls == 1 && !recovery && source_cut == 0);
    qihse_cluster_ownership_txn_t intent;
    memset(&intent, 0, sizeof(intent));
    bool unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(data_dir,
        capture_txn, &intent, &unresolved) == 0 && !unresolved);
    OPENSSL_cleanse(&intent, sizeof(intent));
    qihse_cluster_topology_destroy(topology);
    qihse_kv_store_destroy(store);
    if (old_data_dir) {
        assert(setenv("QIHSE_DATA_DIR", old_data_dir, 1) == 0);
        free(old_data_dir);
    } else {
        assert(unsetenv("QIHSE_DATA_DIR") == 0);
    }
}

int main(void) {
    char dir[] = "./tests/.qihse_journal_XXXXXX";
    assert(mkdtemp(dir));

    /* append 3 entries */
    assert(qihse_cluster_ownership_journal_append(dir, 100, 199, "node-a", 5) == 0);
    assert(qihse_cluster_ownership_journal_append(dir, 200, 299, "node-b", 6) == 0);
    assert(qihse_cluster_ownership_journal_append(dir, 300, 399, "node-c", 4) == 0);

    /* replay: 3 entries, front-to-back, content preserved (incl. a lower epoch) */
    replay_ctx_t r;
    memset(&r, 0, sizeof(r));
    int n = qihse_cluster_ownership_journal_replay(dir, on_entry, &r);
    assert(n == 3);
    assert(r.count == 3);
    assert(r.last_start == 300 && r.last_end == 399);
    assert(strcmp(r.last_owner, "node-c") == 0);
    assert(r.last_epoch == 4);
    printf("[PASS] journal append + replay (3 entries, order + content)\n");

    /* corrupt the tail byte of the LAST record — replay must skip it, keep the 3 valid */
    char path[1024];
    snprintf(path, sizeof(path), "%s/slot-ownership.journal", dir);
    FILE* f = fopen(path, "r+b");
    assert(f);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, sz - 1, SEEK_SET);
    fputc(0xFF, f);
    fclose(f);

    memset(&r, 0, sizeof(r));
    n = qihse_cluster_ownership_journal_replay(dir, on_entry, &r);
    assert(n == 2);
    assert(r.last_start == 200 && r.last_end == 299); /* the corrupt 3rd record is skipped */
    printf("[PASS] corrupt tail record skipped, earlier entries preserved\n");

    /* no journal → 0 (not an error) */
    char dir2[] = "./tests/.qihse_journal_empty_XXXXXX";
    assert(mkdtemp(dir2));
    memset(&r, 0, sizeof(r));
    n = qihse_cluster_ownership_journal_replay(dir2, on_entry, &r);
    assert(n == 0);
    printf("[PASS] absent journal replays as empty\n");

    /* V2 transfer phases are ordered, durable and distinct from v1 ownership
     * entries. PREPARED/COMMITTED remain unresolved until FINALIZED or ABORTED. */
    char dir3[] = "./tests/.qihse_journal_v2_XXXXXX";
    assert(mkdtemp(dir3));
    assert(qihse_cluster_ownership_journal_append(dir3, 1, 9, "legacy", 2) == 0);
    qihse_cluster_ownership_txn_t prepared = txn(QIHSE_OWNERSHIP_PREPARED);
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &prepared) == 0);
    bool unresolved = false; txn_replay_t tr = {0};
    n = qihse_cluster_ownership_journal_replay_txn(dir3, on_txn, &tr, &unresolved);
    assert(n == 1 && unresolved && tr.last == QIHSE_OWNERSHIP_PREPARED);
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &prepared) < 0);
    qihse_cluster_ownership_txn_t committed = txn(QIHSE_OWNERSHIP_COMMITTED);
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &committed) == 0);
    qihse_cluster_ownership_txn_t finalized = committed;
    finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &finalized) == 0);
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    n = qihse_cluster_ownership_journal_replay_txn(dir3, on_txn, &tr, &unresolved);
    assert(n == 3 && !unresolved && tr.count == 3 && tr.last == QIHSE_OWNERSHIP_FINALIZED);
    memset(&r, 0, sizeof(r));
    assert(qihse_cluster_ownership_journal_replay(dir3, on_entry, &r) == 1);
    assert(r.last_start == 1 && strcmp(r.last_owner, "legacy") == 0);
    qihse_cluster_ownership_txn_t ct1_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    strcpy(ct1_prepare.transfer_id, "ct1-test-1");
    strcpy(ct1_prepare.lane_id,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    strcpy(ct1_prepare.next_generation, "next-generation-4");
    ct1_prepare.slot_bitmap[10 / 8u] |= (uint8_t)(1u << (10 % 8u));
    ct1_prepare.slot_bitmap[11 / 8u] |= (uint8_t)(1u << (11 % 8u));
    ct1_prepare.slot_bitmap[12 / 8u] |= (uint8_t)(1u << (12 % 8u));
    ct1_prepare.start = 10; ct1_prepare.end = 12;
    /* CT1 uses the fixed owner field to persist its explicitly selected next
     * successor across a crash before receiver generation promotion. */
    strcpy(ct1_prepare.owner_id, "node-c");
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &ct1_prepare) == 0);
    qihse_cluster_ownership_txn_t ct1_commit = ct1_prepare;
    ct1_commit.phase = QIHSE_OWNERSHIP_COMMITTED;
    /* CT1 target cursor is a sealed baseline row sequence, independent of the
     * source replication cursor. */
    ct1_commit.target_lsn = 1u;
    memset(ct1_commit.proof_digest, 0x35, sizeof(ct1_commit.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &ct1_commit) == 0);
    qihse_cluster_ownership_txn_t ct1_finalized = ct1_commit;
    ct1_finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &ct1_finalized) == 0);
    char dir_cross_domain[] = "./tests/.qihse_journal_cross_domain_XXXXXX";
    assert(mkdtemp(dir_cross_domain));
    qihse_cluster_ownership_txn_t cross_domain_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    strcpy(cross_domain_prepare.transfer_id, "ct2-cross-domain-cursors");
    cross_domain_prepare.source_lsn = 1000;
    assert(qihse_cluster_ownership_journal_append_txn(dir_cross_domain,
        &cross_domain_prepare) == 0);
    qihse_cluster_ownership_txn_t cross_domain_commit = cross_domain_prepare;
    cross_domain_commit.phase = QIHSE_OWNERSHIP_COMMITTED;
    cross_domain_commit.target_lsn = 1;
    strcpy(cross_domain_commit.owner_id, cross_domain_commit.target_id);
    memset(cross_domain_commit.proof_digest, 0x44, sizeof(cross_domain_commit.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(dir_cross_domain,
        &cross_domain_commit) == 0);
    puts("[PASS] CT2 source/target cursors are independent domains");

    /* Promotion INTENT predates its quorum-assigned epoch. Bind it once,
     * while preserving every known field and rejecting later epoch changes. */
    char dir_promotion_intent[] = "./tests/.qihse_journal_promotion_intent_XXXXXX";
    assert(mkdtemp(dir_promotion_intent));
    qihse_cluster_ownership_txn_t promotion_intent = txn(QIHSE_OWNERSHIP_INTENT);
    strcpy(promotion_intent.transfer_id, "ct1-unassigned-epoch");
    memset(promotion_intent.lane_id, 'a', 64u); promotion_intent.lane_id[64] = 0;
    strcpy(promotion_intent.next_generation, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    for (uint32_t slot = promotion_intent.start; slot <= promotion_intent.end; ++slot)
        promotion_intent.slot_bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
    promotion_intent.config_epoch = 0u;
    assert(qihse_cluster_ownership_journal_append_txn(dir_promotion_intent, &promotion_intent) == 0);
    qihse_cluster_ownership_txn_t promotion_prepared = promotion_intent;
    promotion_prepared.phase = QIHSE_OWNERSHIP_PREPARED;
    promotion_prepared.config_epoch = 7u;
    qihse_cluster_ownership_txn_t changed_identity = promotion_prepared;
    changed_identity.target_id[0] ^= 1;
    assert(qihse_cluster_ownership_journal_append_txn(dir_promotion_intent, &changed_identity) != 0);
    assert(qihse_cluster_ownership_journal_append_txn(dir_promotion_intent, &promotion_prepared) == 0);
    qihse_cluster_ownership_txn_t changed_epoch = promotion_prepared;
    changed_epoch.phase = QIHSE_OWNERSHIP_COMMITTED;
    changed_epoch.config_epoch++;
    memset(changed_epoch.proof_digest, 0x71, sizeof(changed_epoch.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(dir_promotion_intent, &changed_epoch) != 0);
    memset(&tr, 0, sizeof(tr)); unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(dir_promotion_intent, on_txn, &tr,
        &unresolved) == 2);
    assert(unresolved && tr.last == QIHSE_OWNERSHIP_PREPARED);
    puts("[PASS] promotion INTENT binds the assigned epoch once");

    /* A durable INTENT must survive the crash window before the backing CT
     * fence is installed. A matching PREPARED frame may then bind the exact
     * observed cut and continue through the normal terminal transition. */
    char dir_intent[] = "./tests/.qihse_journal_intent_XXXXXX";
    assert(mkdtemp(dir_intent));
    qihse_cluster_ownership_txn_t intent = txn(QIHSE_OWNERSHIP_INTENT);
    strcpy(intent.transfer_id, "ct2-intent-crash-window");
    intent.source_lsn = 0;
    assert(qihse_cluster_ownership_journal_append_txn(dir_intent, &intent) == 0);
    memset(&tr, 0, sizeof(tr)); unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(dir_intent, on_txn, &tr,
        &unresolved) == 1);
    assert(unresolved && tr.last == QIHSE_OWNERSHIP_INTENT);
    qihse_cluster_ownership_txn_t intent_prepared = intent;
    intent_prepared.phase = QIHSE_OWNERSHIP_PREPARED;
    intent_prepared.source_lsn = 1234;
    assert(qihse_cluster_ownership_journal_append_txn(dir_intent,
        &intent_prepared) == 0);
    qihse_cluster_ownership_txn_t intent_committed = intent_prepared;
    intent_committed.phase = QIHSE_OWNERSHIP_COMMITTED;
    intent_committed.target_lsn = 1234;
    strcpy(intent_committed.owner_id, intent_committed.target_id);
    memset(intent_committed.proof_digest, 0x71,
        sizeof(intent_committed.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(dir_intent,
        &intent_committed) == 0);
    qihse_cluster_ownership_txn_t intent_finalized = intent_committed;
    intent_finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_ownership_journal_append_txn(dir_intent,
        &intent_finalized) == 0);
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    assert(qihse_cluster_ownership_journal_replay_txn(dir_intent, on_txn, &tr,
        &unresolved) == 4);
    assert(!unresolved && tr.last == QIHSE_OWNERSHIP_FINALIZED);
    qihse_cluster_ownership_txn_t finalized_id_reuse = intent;
    finalized_id_reuse.phase = QIHSE_OWNERSHIP_INTENT;
    finalized_id_reuse.end++;
    errno = 0;
    assert(qihse_cluster_ownership_journal_append_txn(dir_intent,
        &finalized_id_reuse) == -1 && errno == EEXIST);
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    assert(qihse_cluster_ownership_journal_replay_txn(dir_intent, on_txn, &tr,
        &unresolved) == 4);
    assert(!unresolved && tr.last == QIHSE_OWNERSHIP_FINALIZED);
    puts("[PASS] durable CT2 intent binds the fence cut after restart");

#ifdef QIHSE_OWNERSHIP_JOURNAL_TEST_WRAP_FSYNC
    /* fsync can report EINVAL after the complete INTENT frame has reached the
     * journal. The append result must say a write may have occurred; errno is
     * not a safe proxy for side effects. A duplicate-ID preflight rejection
     * must leave that result false. */
    char dir_write_outcome[] = "./tests/.qihse_journal_write_outcome_XXXXXX";
    assert(mkdtemp(dir_write_outcome));
    qihse_cluster_ownership_txn_t uncertain_intent = txn(QIHSE_OWNERSHIP_INTENT);
    strcpy(uncertain_intent.transfer_id, "ct2-fsync-einval-after-write");
    uncertain_intent.source_lsn = 0;
    bool write_may_have_occurred = false;
    fail_next_fsync_after_success = true;
    errno = 0;
    assert(qihse_cluster_ownership_journal_append_txn_ex(dir_write_outcome,
        &uncertain_intent, &write_may_have_occurred) == -1 && errno == EINVAL);
    assert(write_may_have_occurred && !fail_next_fsync_after_success);
    memset(&tr, 0, sizeof(tr)); unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(dir_write_outcome,
        on_txn, &tr, &unresolved) == 1);
    assert(unresolved && tr.last == QIHSE_OWNERSHIP_INTENT);
    write_may_have_occurred = true;
    errno = 0;
    assert(qihse_cluster_ownership_journal_append_txn_ex(dir_write_outcome,
        &uncertain_intent, &write_may_have_occurred) == -1 && errno == EEXIST);
    assert(!write_may_have_occurred);
    remove_fixture(dir_write_outcome);
    puts("[PASS] journal append reports uncertain writes independently of errno");
#endif

    /* A peer's proof-bearing CT1 promotion is journaled as ADOPTED before
     * routing changes. Replay must preserve that terminal peer-side record. */
    char dir_adopted[] = "./tests/.qihse_journal_adopted_XXXXXX";
    assert(mkdtemp(dir_adopted));
    qihse_cluster_ownership_txn_t adopted = txn(QIHSE_OWNERSHIP_ADOPTED);
    strcpy(adopted.transfer_id, "ct1-signed-adoption");
    strcpy(adopted.next_generation, "generation-4");
    strcpy(adopted.owner_id, "node-c");
    adopted.start = 10; adopted.end = 12;
    adopted.target_lsn = adopted.source_lsn;
    adopted.slot_bitmap[10 / 8u] |= (uint8_t)(1u << (10 % 8u));
    adopted.slot_bitmap[11 / 8u] |= (uint8_t)(1u << (11 % 8u));
    adopted.slot_bitmap[12 / 8u] |= (uint8_t)(1u << (12 % 8u));
    memset(adopted.proof_digest, 0x72, sizeof(adopted.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(dir_adopted, &adopted) == 0);
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    assert(qihse_cluster_ownership_journal_replay_txn(dir_adopted, on_txn, &tr,
        &unresolved) == 1);
    assert(!unresolved && tr.last == QIHSE_OWNERSHIP_ADOPTED);
    puts("[PASS] signed CT1 adoption is durable before local routing");

    qihse_cluster_ownership_txn_t abort_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    strcpy(abort_prepare.transfer_id, "ct2-abort-1");
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &abort_prepare) == 0);
    qihse_cluster_ownership_txn_t aborted = abort_prepare;
    aborted.phase = QIHSE_OWNERSHIP_ABORTED;
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &aborted) == 0);
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    n = qihse_cluster_ownership_journal_replay_txn(dir3, on_txn, &tr, &unresolved);
    assert(n == 8 && !unresolved && tr.count == 8 && tr.last == QIHSE_OWNERSHIP_ABORTED);
    qihse_cluster_ownership_txn_t aborted_id_reuse = abort_prepare;
    aborted_id_reuse.phase = QIHSE_OWNERSHIP_INTENT;
    aborted_id_reuse.start++;
    errno = 0;
    assert(qihse_cluster_ownership_journal_append_txn(dir3,
        &aborted_id_reuse) == -1 && errno == EEXIST);
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    assert(qihse_cluster_ownership_journal_replay_txn(dir3, on_txn, &tr,
        &unresolved) == 8);
    assert(!unresolved && tr.last == QIHSE_OWNERSHIP_ABORTED);
    printf("[PASS] v1 compatibility + v2 CT1/CT2 prepare/commit recovery ordering\n");

    /* Two processes/threads may race to finalize one PREPARED transfer. The
     * stable sidecar lock must serialize replay/validate/append/fsync so only
     * one terminal phase becomes durable. */
    char dir_race[] = "./tests/.qihse_journal_race_XXXXXX";
    assert(mkdtemp(dir_race));
    qihse_cluster_ownership_txn_t race_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    strcpy(race_prepare.transfer_id, "ct2-terminal-race");
    assert(qihse_cluster_ownership_journal_append_txn(dir_race, &race_prepare) == 0);
    terminal_race_t commit_race = {.dir = dir_race, .txn = txn(QIHSE_OWNERSHIP_COMMITTED)};
    terminal_race_t abort_race = {.dir = dir_race, .txn = txn(QIHSE_OWNERSHIP_ABORTED)};
    strcpy(commit_race.txn.transfer_id, "ct2-terminal-race");
    strcpy(abort_race.txn.transfer_id, "ct2-terminal-race");
    pthread_t commit_thread, abort_thread;
    assert(pthread_create(&commit_thread, NULL, append_terminal_race, &commit_race) == 0);
    assert(pthread_create(&abort_thread, NULL, append_terminal_race, &abort_race) == 0);
    assert(pthread_join(commit_thread, NULL) == 0 && pthread_join(abort_thread, NULL) == 0);
    assert((commit_race.result == 0) != (abort_race.result == 0));
    if (commit_race.result == 0) {
        qihse_cluster_ownership_txn_t race_final = commit_race.txn;
        race_final.phase = QIHSE_OWNERSHIP_FINALIZED;
        assert(qihse_cluster_ownership_journal_append_txn(dir_race, &race_final) == 0);
    }
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    n = qihse_cluster_ownership_journal_replay_txn(dir_race, on_txn, &tr, &unresolved);
    assert(!unresolved);
    assert((abort_race.result == 0 && n == 2 && tr.last == QIHSE_OWNERSHIP_ABORTED) ||
           (commit_race.result == 0 && n == 3 && tr.last == QIHSE_OWNERSHIP_FINALIZED));
    printf("[PASS] concurrent COMMIT/ABORT permits exactly one durable terminal phase\n");

    char dir_multi[] = "./tests/.qihse_journal_multi_XXXXXX";
    assert(mkdtemp(dir_multi));
    for (unsigned i = 0; i < 2; ++i) {
        qihse_cluster_ownership_txn_t p = txn(QIHSE_OWNERSHIP_PREPARED);
        snprintf(p.transfer_id, sizeof(p.transfer_id), "ct2-sequential-%u", i);
        p.config_epoch += i;
        p.start = (uint16_t)(500 + i); p.end = p.start;
        assert(qihse_cluster_ownership_journal_append_txn(dir_multi, &p) == 0);
        qihse_cluster_ownership_txn_t c = p;
        c.phase = QIHSE_OWNERSHIP_COMMITTED; c.target_lsn = c.source_lsn;
        strcpy(c.owner_id, c.target_id); memset(c.proof_digest, (int)(0x70 + i), 32);
        assert(qihse_cluster_ownership_journal_append_txn(dir_multi, &c) == 0);
        c.phase = QIHSE_OWNERSHIP_FINALIZED;
        assert(qihse_cluster_ownership_journal_append_txn(dir_multi, &c) == 0);
    }
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    n = qihse_cluster_ownership_journal_replay_txn(dir_multi, on_txn, &tr, &unresolved);
    assert(n == 6 && !unresolved && tr.count == 6 && tr.last == QIHSE_OWNERSHIP_FINALIZED);
    printf("[PASS] sequential ownership transactions replay after restart without current peer seals\n");

    /* A torn prepared record is not silently discarded: startup receives a
     * hard error and a fence-required unresolved indication. */
    char dir4[] = "./tests/.qihse_journal_torn_XXXXXX";
    assert(mkdtemp(dir4));
    assert(qihse_cluster_ownership_journal_append_txn(dir4, &prepared) == 0);
    snprintf(path, sizeof(path), "%s/slot-ownership.journal", dir4);
    int fd = open(path, O_WRONLY | O_APPEND);
    assert(fd >= 0 && write(fd, "partial", 7) == 7 && close(fd) == 0);
    unresolved = false; errno = 0;
    assert(qihse_cluster_ownership_journal_replay_txn(dir4, NULL, NULL, &unresolved) < 0);
    assert(unresolved);
    printf("[PASS] torn v2 tail requires fenced recovery\n");

    char dir5[] = "./tests/.qihse_journal_corrupt_v2_XXXXXX";
    assert(mkdtemp(dir5));
    assert(qihse_cluster_ownership_journal_append_txn(dir5, &prepared) == 0);
    snprintf(path, sizeof(path), "%s/slot-ownership.journal", dir5);
    fd = open(path, O_RDWR);
    assert(fd >= 0);
    assert(lseek(fd, 70, SEEK_SET) == 70);
    unsigned char byte = 0;
    assert(read(fd, &byte, 1) == 1);
    byte ^= 0x80;
    assert(lseek(fd, 70, SEEK_SET) == 70 && write(fd, &byte, 1) == 1 && close(fd) == 0);
    unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(dir5, NULL, NULL, &unresolved) < 0);
    assert(unresolved);
    printf("[PASS] corrupt v2 record is rejected and fenced\n");

    /* Public ownership getters are Operator-only, zero outputs on every
     * refusal, and finalized CT2 outcomes remain queryable after later work. */
    char auth_dir[] = "./tests/.qihse_ownership_lookup_XXXXXX";
    assert(mkdtemp(auth_dir));
    assert(setenv("QIHSE_DATA_DIR", auth_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OwnershipLookup-Op-Password-9!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op && qihse_auth_user_is_active(op));
    qihse_user_t* guest = qihse_auth_create_user(op, 991u, QIHSE_ROLE_GUEST,
        0u, 0u, "OwnershipLookup-Guest-Password-9!", false);
    assert(guest);
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    const char* store_dir = qihse_kv_store_data_directory(store);
    assert(store_dir && *store_dir);
    test_range_authority_reserve_precedes_intent(op);
    test_signed_ct1_missing_predecessor_chain(store, op, guest);
    test_signed_ct1_promotion_supersession(store, op, guest);
    qihse_cluster_ownership_context_t ownership = {.store = store, .principal = op};

    qihse_cluster_ownership_txn_t old_final = finalized_ct2(
        "terminal-retry-original", 100u, 120u, 20u);
    qihse_cluster_ownership_txn_t prep_old = old_final;
    prep_old.phase = QIHSE_OWNERSHIP_PREPARED;
    prep_old.target_lsn = 0u; memset(prep_old.proof_digest, 0, sizeof(prep_old.proof_digest));
    snprintf(prep_old.owner_id, sizeof(prep_old.owner_id), "%s", prep_old.source_id);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &prep_old) == 0);
    qihse_cluster_ownership_txn_t commit_old = old_final;
    commit_old.phase = QIHSE_OWNERSHIP_COMMITTED;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &commit_old) == 0);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &old_final) == 0);

    qihse_cluster_ownership_txn_t later = finalized_ct2(
        "terminal-retry-later", 121u, 140u, 21u);
    qihse_cluster_ownership_txn_t prep_later = later;
    prep_later.phase = QIHSE_OWNERSHIP_PREPARED;
    prep_later.target_lsn = 0u; memset(prep_later.proof_digest, 0, sizeof(prep_later.proof_digest));
    snprintf(prep_later.owner_id, sizeof(prep_later.owner_id), "%s", prep_later.source_id);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &prep_later) == 0);
    qihse_cluster_ownership_txn_t commit_later = later;
    commit_later.phase = QIHSE_OWNERSHIP_COMMITTED;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &commit_later) == 0);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &later) == 0);

    qihse_cluster_ownership_txn_t current = txn(QIHSE_OWNERSHIP_PREPARED);
    snprintf(current.transfer_id, sizeof(current.transfer_id), "terminal-retry-current");
    current.config_epoch = 22u;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &current) == 0);

    qihse_cluster_ownership_txn_t got;
    memset(&got, 0xa5, sizeof(got));
    assert(qihse_cluster_ownership_transfer_get_finalized(&ownership,
        "terminal-retry-original", &got, NULL, 0));
    assert(got.phase == QIHSE_OWNERSHIP_FINALIZED &&
        !strcmp(got.transfer_id, old_final.transfer_id) &&
        got.config_epoch == old_final.config_epoch &&
        got.start == old_final.start && got.end == old_final.end &&
        got.target_lsn == old_final.target_lsn &&
        memcmp(got.proof_digest, old_final.proof_digest, 32u) == 0);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_finalized(&ownership,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(qihse_cluster_ownership_transfer_get_prepared(&ownership,
        "terminal-retry-current", &got, NULL, 0));
    assert(got.phase == QIHSE_OWNERSHIP_PREPARED);

    qihse_cluster_ownership_context_t denied = ownership;
    denied.principal = guest;
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_finalized(&denied,
        "terminal-retry-original", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_prepared(&denied,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);

    qihse_cluster_ownership_txn_t current_commit = current;
    current_commit.phase = QIHSE_OWNERSHIP_COMMITTED;
    current_commit.target_lsn = 1u;
    snprintf(current_commit.owner_id, sizeof(current_commit.owner_id), "%s",
        current_commit.target_id);
    memset(current_commit.proof_digest, 0x7c, sizeof(current_commit.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &current_commit) == 0);
    memset(&got, 0xa5, sizeof(got));
    assert(qihse_cluster_ownership_transfer_get_committed(&ownership,
        "terminal-retry-current", &got, NULL, 0));
    assert(got.phase == QIHSE_OWNERSHIP_COMMITTED &&
        !strcmp(got.transfer_id, current_commit.transfer_id));
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_prepared(&ownership,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_committed(&denied,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    qihse_cluster_ownership_txn_t current_final = current_commit;
    current_final.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &current_final) == 0);

    /* FINALIZED replay is local and idempotent when the target is offline.
     * It repairs only slots still at this transfer's source epoch; a later
     * owner and the target's current role remain untouched. */
    promotion_pin_map_t finish_pins;
    memset(&finish_pins, 0, sizeof(finish_pins));
    qihse_cluster_topology_t* finish_topology = qihse_cluster_topology_create();
    assert(finish_topology);
    qihse_cluster_node_t finish_nodes[3];
    uint16_t finish_ix[3];
    const char* finish_seeds[] = {"finish-finalized-source", "finish-finalized-target",
                                  "finish-finalized-later-owner"};
    const char* finish_qkps[] = {"finish-qkp-a", "finish-qkp-b", "finish-qkp-c"};
    for (size_t i = 0; i < 3; ++i) {
        memset(&finish_nodes[i], 0, sizeof(finish_nodes[i]));
        qihse_cluster_node_id_from_seed(finish_seeds[i], strlen(finish_seeds[i]),
                                        finish_nodes[i].id);
        snprintf(finish_pins.node[i], sizeof(finish_pins.node[i]), "%s", finish_nodes[i].id);
        snprintf(finish_pins.pin[i], sizeof(finish_pins.pin[i]), "%s", finish_qkps[i]);
        snprintf(finish_nodes[i].host, sizeof(finish_nodes[i].host), "127.0.0.1");
        finish_nodes[i].port = (uint16_t)(7400 + i);
        finish_nodes[i].bus_port = (uint16_t)(17400 + i);
        finish_nodes[i].role = i == 0 ? QIHSE_CLUSTER_NODE_PRIMARY :
            QIHSE_CLUSTER_NODE_REPLICA;
        finish_nodes[i].primary_index = i == 0 ? QIHSE_CLUSTER_NODE_NONE : finish_ix[0];
        finish_nodes[i].healthy = true;
        finish_nodes[i].config_epoch = 5;
        assert(qihse_cluster_topology_upsert_node(finish_topology,
            &finish_nodes[i], &finish_ix[i]));
    }
    assert(qihse_cluster_topology_set_local_node(finish_topology, finish_ix[0]));
    assert(qihse_cluster_topology_adopt_range(finish_topology, 100, 100, finish_ix[0], 10));
    assert(qihse_cluster_topology_adopt_range(finish_topology, 101, 101, finish_ix[2], 30));
    assert(qihse_cluster_topology_adopt_range(finish_topology, 102, 102, finish_ix[1], 20));
    qihse_cluster_ownership_txn_t finish_txn = finalized_ct2(
        "finish-finalized-local", 100, 102, 20);
    snprintf(finish_txn.source_id, sizeof(finish_txn.source_id), "%s", finish_nodes[0].id);
    snprintf(finish_txn.target_id, sizeof(finish_txn.target_id), "%s", finish_nodes[1].id);
    snprintf(finish_txn.owner_id, sizeof(finish_txn.owner_id), "%s", finish_nodes[1].id);
    snprintf(finish_txn.source_qkp_id, sizeof(finish_txn.source_qkp_id), "%s", finish_qkps[0]);
    snprintf(finish_txn.target_qkp_id, sizeof(finish_txn.target_qkp_id), "%s", finish_qkps[1]);
    qihse_cluster_ownership_txn_t finish_prepare = finish_txn;
    finish_prepare.phase = QIHSE_OWNERSHIP_PREPARED;
    finish_prepare.target_lsn = 0;
    memset(finish_prepare.proof_digest, 0, sizeof(finish_prepare.proof_digest));
    snprintf(finish_prepare.owner_id, sizeof(finish_prepare.owner_id), "%s",
             finish_prepare.source_id);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &finish_prepare) == 0);
    qihse_cluster_ownership_txn_t finish_commit = finish_txn;
    finish_commit.phase = QIHSE_OWNERSHIP_COMMITTED;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &finish_commit) == 0);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &finish_txn) == 0);
    qihse_cluster_ownership_context_t finish_ownership = {
        .topology = finish_topology, .store = store, .principal = op,
        .peer_id = promotion_peer_id, .peer_id_context = &finish_pins
    };
    assert(qihse_cluster_ownership_transfer_finish_finalized(&finish_ownership,
        finish_txn.transfer_id, NULL, 0));
    uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
    uint64_t epoch = 0;
    assert(qihse_cluster_topology_get_slot(finish_topology, 100, &owner, NULL, NULL));
    assert(qihse_cluster_topology_get_slot_epoch(finish_topology, 100, &epoch));
    assert(owner == finish_ix[1] && epoch == 20);
    assert(qihse_cluster_topology_get_slot(finish_topology, 101, &owner, NULL, NULL));
    assert(qihse_cluster_topology_get_slot_epoch(finish_topology, 101, &epoch));
    assert(owner == finish_ix[2] && epoch == 30);
    assert(qihse_cluster_topology_get_slot(finish_topology, 102, &owner, NULL, NULL));
    assert(qihse_cluster_topology_get_slot_epoch(finish_topology, 102, &epoch));
    assert(owner == finish_ix[1] && epoch == 20);
    qihse_cluster_node_t finish_target;
    assert(qihse_cluster_topology_get_node(finish_topology, finish_ix[1], &finish_target));
    assert(finish_target.role == QIHSE_CLUSTER_NODE_REPLICA &&
           finish_target.primary_index == finish_ix[0] && finish_target.config_epoch == 20);
    assert(!qihse_cluster_ownership_transfer_finish_finalized(&finish_ownership,
        "wrong-finalized-id", NULL, 0));
    qihse_cluster_topology_destroy(finish_topology);

    qihse_cluster_ownership_txn_t getter_abort_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    snprintf(getter_abort_prepare.transfer_id, sizeof(getter_abort_prepare.transfer_id),
             "operator-aborted-getter");
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &getter_abort_prepare) == 0);
    qihse_cluster_ownership_txn_t getter_abort_final = getter_abort_prepare;
    getter_abort_final.phase = QIHSE_OWNERSHIP_ABORTED;
    getter_abort_final.target_lsn = 0;
    memset(getter_abort_final.proof_digest, 0, sizeof(getter_abort_final.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &getter_abort_final) == 0);
    memset(&got, 0xa5, sizeof(got));
    assert(qihse_cluster_ownership_transfer_get_aborted(&ownership,
        "operator-aborted-getter", &got, NULL, 0));
    assert(got.phase == QIHSE_OWNERSHIP_ABORTED &&
        !strcmp(got.transfer_id, getter_abort_final.transfer_id));
    OPENSSL_cleanse(&getter_abort_prepare, sizeof(getter_abort_prepare));
    OPENSSL_cleanse(&getter_abort_final, sizeof(getter_abort_final));

    qihse_cluster_ownership_txn_t lane_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    snprintf(lane_prepare.transfer_id, sizeof(lane_prepare.transfer_id),
             "ct1-lane-journal-v3");
    memset(lane_prepare.lane_id, 'a', 64u);
    lane_prepare.lane_id[64] = '\0';
    for (uint32_t slot = lane_prepare.start; slot <= lane_prepare.end; ++slot)
        lane_prepare.slot_bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &lane_prepare) == 0);
    qihse_cluster_ownership_txn_t lane_commit = lane_prepare;
    lane_commit.phase = QIHSE_OWNERSHIP_COMMITTED;
    lane_commit.target_lsn = lane_commit.source_lsn;
    snprintf(lane_commit.owner_id, sizeof(lane_commit.owner_id), "%s", lane_commit.target_id);
    memset(lane_commit.proof_digest, 0x45, sizeof(lane_commit.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &lane_commit) == 0);
    qihse_cluster_ownership_txn_t lane_final = lane_commit;
    lane_final.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &lane_final) == 0);
    memset(&got, 0, sizeof(got));
    assert(qihse_cluster_ownership_transfer_get_finalized(&ownership,
        "ct1-lane-journal-v3", &got, NULL, 0));
    assert(!strcmp(got.lane_id, lane_prepare.lane_id));
    OPENSSL_cleanse(&lane_prepare, sizeof(lane_prepare));
    OPENSSL_cleanse(&lane_commit, sizeof(lane_commit));
    OPENSSL_cleanse(&lane_final, sizeof(lane_final));

    assert(qihse_auth_destroy_user(op, 991u));
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_finalized(&denied,
        "terminal-retry-original", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_committed(&denied,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    denied.principal = NULL;
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_finalized(&denied,
        "terminal-retry-original", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_committed(&denied,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    qihse_kv_store_destroy(store);
    qihse_audit_shutdown();
    const char* fixtures[] = {dir, dir2, dir3, dir_cross_domain, dir_race,
                             dir_multi, dir4, dir5, auth_dir, dir_intent,
                             dir_adopted};
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i)
        remove_fixture(fixtures[i]);
    printf("[PASS] finalized CT2 retry survives later phases; getters require active system Operator\n");

    printf("All ownership journal tests passed.\n");
    return 0;
}
