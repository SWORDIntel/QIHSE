#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_cluster_ownership.h"
#include "qihse_cluster_range_authority.h"
#include "qihse_crc16.h"
#include "qihse_audit.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Use the actual adapter and its canonical transition digest. Only the typed
 * common log is deterministic; native proofs, KV and ownership are not mocked. */
#include "../src/spinnaker/qihse_cluster_range_authority.c"

enum { CASES = 4 };
typedef struct {
    qihse_consensus_range_request_t request;
    qihse_consensus_range_grant_t grant;
    qihse_consensus_range_decision_t decision;
    qihse_consensus_range_phase_t phase;
    uint64_t source_cut;
} common_record_t;
static common_record_t common[CASES];
static bool available = true;
static unsigned lookups, attempted_abort;
static char nodes[3][QIHSE_CLUSTER_NODE_ID_LEN + 1u];
static const char target_group[] = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char target_generation[] = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
static const char unmarked_group[] = "5555555555555555555555555555555555555555555555555555555555555555";

bool qihse_consensus_mesh_range_lookup_user(qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, const char* id,
    qihse_consensus_range_request_t* request, qihse_consensus_range_grant_t* grant,
    qihse_consensus_range_decision_t* decision, qihse_consensus_range_phase_t* phase) {
    assert(mesh && principal && id && request && grant && decision && phase);
    ++lookups;
    if (!available) return false;
    for (size_t i = 0; i < CASES; ++i) if (!strcmp(common[i].request.transfer_id, id)) {
        *request = common[i].request; *grant = common[i].grant;
        *decision = common[i].decision; *phase = common[i].phase;
        return true;
    }
    memset(request, 0, sizeof *request); memset(grant, 0, sizeof *grant);
    memset(decision, 0, sizeof *decision); *phase = QIHSE_RANGE_PHASE_NONE;
    return true;
}
bool qihse_consensus_mesh_range_abort_user(qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, const qihse_consensus_range_request_t* request,
    const qihse_consensus_range_grant_t* grant, const uint8_t digest[32],
    uint32_t timeout, qihse_consensus_range_decision_t* decision) {
    (void)mesh; (void)principal; (void)request; (void)grant;
    (void)digest; (void)timeout; (void)decision;
    ++attempted_abort;
    assert(!"staging discovery must never create a common ABORT"); return false;
}
static bool pins(void* opaque, const char* node, char out[65]) {
    (void)opaque;
    const char* qkp[] = {"qkp-a", "qkp-c", "qkp-d"};
    for (size_t i = 0; i < 3u; ++i) if (!strcmp(node, nodes[i])) {
        snprintf(out, 65u, "%s", qkp[i]); return true;
    }
    return false;
}
static void bit(uint8_t* bitmap, uint16_t slot) { bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u)); }
static void empty_bitmap(const qihse_kv_ct_lane_status_t* status) {
    for (size_t i = 0; i < sizeof status->slot_bitmap; ++i) assert(!status->slot_bitmap[i]);
}
static void txn_from_record(size_t i, qihse_cluster_ownership_txn_t* t) {
    common_record_t* r = &common[i]; memset(t, 0, sizeof *t);
    snprintf(t->transfer_id, sizeof t->transfer_id, "%s", r->request.transfer_id);
    snprintf(t->source_id, sizeof t->source_id, "%s", nodes[0]);
    snprintf(t->target_id, sizeof t->target_id, "%s", nodes[1]);
    snprintf(t->owner_id, sizeof t->owner_id, "%s", nodes[0]);
    snprintf(t->source_qkp_id, sizeof t->source_qkp_id, "qkp-a");
    snprintf(t->target_qkp_id, sizeof t->target_qkp_id, "qkp-c");
    snprintf(t->generation, sizeof t->generation, "%s", r->request.source_generation);
    snprintf(t->lane_id, sizeof t->lane_id, "%s", r->request.source_group_id);
    t->start = t->end = (uint16_t)(100u + i);
    t->source_lsn = r->source_cut; t->config_epoch = r->grant.grant_epoch;
    memcpy(t->slot_bitmap, r->request.slots, sizeof t->slot_bitmap);
}
static void init_record(size_t i) {
    common_record_t* r = &common[i]; memset(r, 0, sizeof *r);
    r->phase = QIHSE_RANGE_PHASE_RESERVED; r->request.op = QIHSE_RANGE_OP_TRANSFER;
    snprintf(r->request.transfer_id, sizeof r->request.transfer_id, "prepared-only-%zu", i);
    snprintf(r->request.source_topology_id, sizeof r->request.source_topology_id, "%s", nodes[0]);
    snprintf(r->request.target_topology_id, sizeof r->request.target_topology_id, "%s", nodes[1]);
    snprintf(r->request.source_qkp_id, sizeof r->request.source_qkp_id, "qkp-a");
    snprintf(r->request.target_qkp_id, sizeof r->request.target_qkp_id, "qkp-c");
    memset(r->request.source_group_id, '1' + (int)i, 64u);
    memset(r->request.source_generation, 'a' + (int)i, 32u);
    snprintf(r->request.target_group_id, sizeof r->request.target_group_id, "%s", target_group);
    snprintf(r->request.target_generation, sizeof r->request.target_generation, "%s", target_generation);
    snprintf(r->request.successor_qkp_id, sizeof r->request.successor_qkp_id, "qkp-d");
    bit(r->request.slots, (uint16_t)(100u + i));
    r->grant.reserve_index = 10u + i; r->grant.grant_epoch = 100u + i;
    memset(r->grant.reserve_digest, (int)(10u + i), 32u); r->source_cut = 17u + i;
}
static void terminal(size_t i, bool abort_decision) {
    common_record_t* r = &common[i];
    qihse_cluster_ownership_txn_t* t = calloc(1u, sizeof *t); assert(t);
    txn_from_record(i, t);
    t->phase = abort_decision ? QIHSE_OWNERSHIP_ABORTED : QIHSE_OWNERSHIP_FINALIZED;
    if (!abort_decision) {
        qihse_kv_ct_lane_authority_claim_t* claim = calloc(1u, sizeof *claim); assert(claim);
        memcpy(claim->slots, r->request.slots, sizeof claim->slots);
        memset(claim->range_digest, 0x66, sizeof claim->range_digest);
        memset(claim->image_digest, 0x77, sizeof claim->image_digest);
        assert(qihse_kv_ct_lane_transfer_checksum(claim, t->proof_digest));
        free(claim);
    }
    assert(transition_digest(t, abort_decision ? "QIHSE-RANGE-ABORTED-1" :
        "QIHSE-RANGE-ACTIVATED-1", r->decision.evidence_digest));
    r->decision.decision_index = 200u + i;
    r->decision.grant_epoch = r->grant.grant_epoch;
    memset(r->decision.decision_digest, (int)(20u + i), 32u);
    r->phase = abort_decision ? QIHSE_RANGE_PHASE_ABORTED : QIHSE_RANGE_PHASE_FINALIZED;
    free(t);
}
static char* key_for(uint16_t slot) {
    char key[64];
    for (unsigned i = 0; i < 1000000u; ++i) {
        snprintf(key, sizeof key, "staging-discovery-%u", i);
        if (qihse_cluster_key_slot(key, strlen(key)) == slot) return strdup(key);
    }
    abort();
}
static void historical_rebind(qihse_kv_store_t* store, qihse_cluster_topology_t* topology,
    qihse_user_t* op, qihse_user_t* peer, qihse_user_t* low) {
    init_record(0u); terminal(0u, true);
    struct historical {
        qihse_cluster_ownership_txn_t txn;
        qihse_kv_ct_lane_status_t before, after;
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], after_token[QIHSE_KV_CT_TOKEN_BYTES];
        uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES];
    } *s = calloc(1u, sizeof *s); assert(s);
    char* key = key_for(100u); assert(key);
    assert(qihse_kv_set_user(store, key, "new incarnation survives", 4u, 1u, op));
    bit(s->slots, 100u);
    const char* group = common[0].request.source_group_id;
    const char* generation = "ffffffffffffffffffffffffffffffff";
    assert(qihse_kv_ct_lane_source_enable(store, op, group, s->slots,
        "qkp-c", "qkp-d", generation, s->token, 1u << 20));
    qihse_kv_replica_snapshot_t* image = NULL; uint64_t seq; unsigned char digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, group, &image, &seq, digest) == 0);
    qihse_kv_replica_snapshot_destroy(image);
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, group,
        "qkp-d", generation, digest, 0u));
    assert(qihse_cluster_topology_adopt_range(topology, 100u, 100u, 1u, 500u));
    qihse_cluster_ownership_context_t c = {.topology = topology, .store = store,
        .principal = op, .data_principal = op, .peer_id = pins};
    qihse_cluster_range_authority_t authority = {.mesh = (qihse_consensus_mesh_t*)common,
        .local_ownership = &c};
    c.range_authority_context = &authority;
    c.lane_claim = qihse_cluster_range_authority_claim;
    c.lane_verify_claim = qihse_cluster_range_authority_verify_claim_user;
    c.lane_verify_aborted = qihse_cluster_range_authority_verify_aborted_claim_user;
    c.range_abort = qihse_cluster_range_authority_abort;
    c.range_reserve = qihse_cluster_range_authority_reserve;
    c.range_check_reserved = qihse_cluster_range_authority_check_reserved;
    c.range_finalize = qihse_cluster_range_authority_finalize;
    c.range_check_finalized = qihse_cluster_range_authority_check_finalized;
    txn_from_record(0u, &s->txn);
    const char* directory = qihse_kv_store_data_directory(store);
    s->txn.phase = QIHSE_OWNERSHIP_INTENT; s->txn.source_lsn = 0u;
    assert(qihse_cluster_ownership_journal_append_txn(directory, &s->txn) == 0);
    s->txn.phase = QIHSE_OWNERSHIP_PREPARED; s->txn.source_lsn = common[0].source_cut;
    assert(qihse_cluster_ownership_journal_append_txn(directory, &s->txn) == 0);
    s->txn.phase = QIHSE_OWNERSHIP_ABORTED;
    assert(qihse_cluster_ownership_journal_append_txn(directory, &s->txn) == 0);
    char journal[512]; struct stat before, after;
    int n = snprintf(journal, sizeof journal, "%s/slot-ownership.journal", directory);
    assert(n > 0 && (size_t)n < sizeof journal && stat(journal, &before) == 0);
    assert(!qihse_kv_ct_lane_status(store, op, target_group, &s->after));
    assert(qihse_kv_ct_lane_status(store, op, group, &s->before));
    uint64_t rows = qihse_kv_change_seq(store);
    for (unsigned i = 0; i < 2u; ++i) {
        bool unresolved = true; char error[256];
        bool ok = qihse_cluster_ownership_replay(&c, &unresolved, error, sizeof error);
        if (!ok || unresolved) fprintf(stderr, "historical replay ok=%d unresolved=%d: %s\n", ok, unresolved, error);
        assert(ok && !unresolved);
        assert(qihse_kv_ct_lane_status(store, op, group, &s->after) &&
            !memcmp(&s->before, &s->after, sizeof s->after));
        assert(qihse_kv_ct_lane_owner_token_get(store, op, group, s->after_token) &&
            !memcmp(s->token, s->after_token, sizeof s->token));
        assert(qihse_kv_change_seq(store) == rows && !attempted_abort);
        uint16_t owner; uint64_t epoch;
        assert(qihse_cluster_topology_get_slot(topology, 100u, &owner, NULL, NULL) && owner == 1u);
        assert(qihse_cluster_topology_get_slot_epoch(topology, 100u, &epoch) && epoch == 500u);
        assert(stat(journal, &after) == 0 && before.st_ino == after.st_ino && before.st_size == after.st_size);
    }
    char* value = qihse_kv_get_user(store, key, op);
    assert(value && !strcmp(value, "new incarnation survives")); free(value);
    assert(!qihse_kv_get_user(store, key, low));
    free(key); free(s);
    puts("PASS historical ABORT without either old capability preserves rebound SOURCE incarnation");
}
static void write_legacy004(const char* directory) {
    enum { V4 = 2663, V5 = V4 + 9 };
    char path[512], saved[512];
    int n = snprintf(path, sizeof path, "%s/ct-lanes.bin", directory);
    assert(n > 0 && (size_t)n < sizeof path);
    FILE* f = fopen(path, "rb"); assert(f);
    assert(fseek(f, 0, SEEK_END) == 0); long length = ftell(f); rewind(f);
    assert(length >= 20 && length <= (long)(20u + QIHSE_KV_CT_MAX_LANES * V5));
    unsigned char* bytes = malloc((size_t)length); assert(bytes);
    assert(fread(bytes, 1u, (size_t)length, f) == (size_t)length && fclose(f) == 0);
    assert(!memcmp(bytes, "QCTLN005", 8u));
    uint32_t count = ((uint32_t)bytes[8] << 24) | ((uint32_t)bytes[9] << 16) |
        ((uint32_t)bytes[10] << 8) | bytes[11];
    assert(count <= QIHSE_KV_CT_MAX_LANES && (size_t)length == 20u + (size_t)count * V5);
    for (uint32_t i = 0; i < count; ++i)
        memmove(bytes + 12u + (size_t)i * V4, bytes + 12u + (size_t)i * V5, V4);
    memcpy(bytes, "QCTLN004", 8u);
    size_t end = 12u + (size_t)count * V4;
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < end; ++i) hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    for (size_t i = 0; i < 8u; ++i) bytes[end + i] = (unsigned char)(hash >> (56u - i * 8u));
    n = snprintf(saved, sizeof saved, "%s/ct-lanes.original005", directory);
    assert(n > 0 && (size_t)n < sizeof saved && access(saved, F_OK) != 0 && errno == ENOENT);
    assert(rename(path, saved) == 0);
    f = fopen(path, "wbx"); assert(f);
    assert(fwrite(bytes, 1u, end + 8u, f) == end + 8u && fflush(f) == 0 &&
        fsync(fileno(f)) == 0 && fclose(f) == 0);
    int parent = open(directory, O_RDONLY | O_DIRECTORY); assert(parent >= 0);
    assert(fsync(parent) == 0 && close(parent) == 0); free(bytes);
}
int main(int argc, char** argv) {
    bool legacy = argc == 2 && !strcmp(argv[1], "--legacy004");
    bool historical = argc == 2 && !strcmp(argv[1], "--historical-rebind");
    assert(argc == 1 || legacy || historical);
    umask(0077); alarm(120);
    char dir[] = "./ownership_staging_discovery_XXXXXX"; assert(mkdtemp(dir));
    fprintf(stderr, "staging discovery fixture: %s (preserved)\n", dir);
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0 && setenv("QIHSE_LOG_DIR", dir, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator("StagingDiscoveryOp1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "StagingDiscoveryOp1!"); assert(op);
    qihse_user_t* peer = qihse_auth_create_user(op, 6302u, QIHSE_ROLE_ANALYST, 7u, 7u,
        "StagingDiscoveryPeer1!", false);
    qihse_user_t* low = qihse_auth_create_user(op, 6303u, QIHSE_ROLE_ANALYST, 0u, 0u,
        "StagingDiscoveryLow1!", false); assert(peer && low);
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create(); assert(topology);
    uint16_t indices[3];
    for (size_t i = 0; i < 3u; ++i) {
        qihse_cluster_node_t node = {0}; char seed[64];
        snprintf(seed, sizeof seed, "staging-discovery-node-%zu", i);
        qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
        snprintf(nodes[i], sizeof nodes[i], "%s", node.id);
        snprintf(node.host, sizeof node.host, "127.0.0.1");
        node.port = (uint16_t)(8000u + i); node.bus_port = (uint16_t)(18000u + i);
        node.role = QIHSE_CLUSTER_NODE_PRIMARY; node.healthy = true;
        node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        assert(qihse_cluster_topology_upsert_node(topology, &node, &indices[i]));
    }
    assert(qihse_cluster_topology_set_local_node(topology, indices[1]));
    assert(qihse_cluster_topology_adopt_range(topology, 100u, 104u, indices[0], 1u));
    qihse_kv_store_t* store = qihse_kv_store_create_user(op); assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    if (historical) {
        historical_rebind(store, topology, op, peer, low);
        qihse_kv_store_destroy(store); qihse_cluster_topology_destroy(topology);
        qihse_audit_shutdown(); return 0;
    }
    char* high_key = key_for(9000u);
    assert(high_key && qihse_kv_set_user(store, high_key, "unrelated classified", 4u, 1u, op));
    struct state {
        uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES];
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
        qihse_kv_ct_lane_status_t before[CASES + 2], after;
        qihse_kv_ct_lane_transfer_status_t transfer;
        qihse_kv_ct_lane_authority_claim_t claim;
        qihse_cluster_ownership_txn_t txn;
        qihse_kv_ct_lane_staging_candidate_t candidate;
    } *s = calloc(1u, sizeof *s); assert(s);
    bit(s->slots, 9000u);
    assert(qihse_kv_ct_lane_source_enable(store, op, target_group, s->slots,
        "qkp-c", "qkp-d", target_generation, s->token, 1u << 20));
    qihse_kv_replica_snapshot_t* baseline = NULL; unsigned char digest[32]; uint64_t baseline_seq;
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, target_group,
        &baseline, &baseline_seq, digest) == 0);
    qihse_kv_replica_snapshot_destroy(baseline);
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, target_group,
        "qkp-d", target_generation, digest, 0u));
    memset(s->slots, 0, sizeof s->slots); bit(s->slots, 104u);
    assert(qihse_kv_ct_lane_receiver_bind(store, op, unmarked_group, s->slots,
        "qkp-a", "qkp-c", "ffffffffffffffffffffffffffffffff",
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 0u, s->token));
    qihse_cluster_ownership_context_t c = {.topology = topology, .store = store,
        .principal = op, .data_principal = op, .peer_id = pins};
    qihse_cluster_range_authority_t authority = {.mesh = (qihse_consensus_mesh_t*)common,
        .local_ownership = &c};
    c.range_authority_context = &authority;
    c.lane_claim = qihse_cluster_range_authority_claim;
    c.lane_verify_claim = qihse_cluster_range_authority_verify_claim_user;
    c.lane_verify_aborted = qihse_cluster_range_authority_verify_aborted_claim_user;
    c.range_abort = qihse_cluster_range_authority_abort;
    c.range_reserve = qihse_cluster_range_authority_reserve;
    c.range_check_reserved = qihse_cluster_range_authority_check_reserved;
    c.range_finalize = qihse_cluster_range_authority_finalize;
    c.range_check_finalized = qihse_cluster_range_authority_check_finalized;
    qihse_cluster_range_verifier_t verifier = {.authority = &authority, .principal = op};
    for (size_t i = 0; i < CASES; ++i) {
        init_record(i); common_record_t* r = &common[i];
        txn_from_record(i, &s->txn);
        assert(qihse_cluster_range_authority_claim(&authority, op, &s->txn, &s->claim));
        qihse_kv_ct_proof_t* proof = qihse_kv_ct_lane_authority_proof_create(store, op, op,
            &s->claim, qihse_cluster_range_authority_verify_reservation_claim, &verifier);
        assert(proof && qihse_kv_ct_lane_receiver_prepare(store, op, op, &s->claim,
            proof, qihse_cluster_range_authority_verify_reservation_claim, &verifier, s->token));
        qihse_kv_ct_proof_destroy(proof);
        assert(qihse_kv_ct_lane_status(store, op, r->request.source_group_id, &s->before[i]));
    }
    assert(qihse_kv_sync_store(store));
    uint64_t rows = qihse_kv_change_seq(store);
    memset(&s->claim, 0, sizeof s->claim); memset(&s->txn, 0, sizeof s->txn);
    memset(s->token, 0, sizeof s->token);
    qihse_kv_store_destroy(store);
    common[0].phase = QIHSE_RANGE_PHASE_NONE; terminal(2u, true); terminal(3u, false);
    if (legacy) write_legacy004(dir);
    store = qihse_kv_store_create_user(op); assert(store); c.store = store;
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    assert(qihse_kv_ct_lane_transfer_status(store, op, &s->transfer) && !s->transfer.active);
    txn_from_record(3u, &s->txn); s->txn.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_range_authority_claim(&authority, op, &s->txn, &s->claim));
    memset(s->claim.range_digest, 0x66, sizeof s->claim.range_digest);
    memset(s->claim.image_digest, 0x77, sizeof s->claim.image_digest);
    assert(qihse_cluster_range_authority_verify_claim_user(&authority, op, &s->claim, true));
    assert(!qihse_cluster_range_authority_verify_aborted_claim_user(&authority, op, &s->claim));
    memset(&s->claim, 0, sizeof s->claim); memset(&s->txn, 0, sizeof s->txn);
    size_t cursor = 2u;
    memset(&s->candidate, 0xa5, sizeof s->candidate);
    assert(qihse_kv_ct_lane_staging_next_user(store, low, &cursor, &s->candidate) == -1 &&
        errno == EACCES && cursor == 2u);
    const unsigned char* cleared = (const unsigned char*)&s->candidate;
    for (size_t i = 0; i < sizeof s->candidate; ++i) assert(!cleared[i]);
    unsigned seen = 0u; int next; cursor = 0u;
    while ((next = qihse_kv_ct_lane_staging_next_user(store, op, &cursor, &s->candidate)) == 1) {
        size_t i;
        for (i = 0u; i < CASES; ++i)
            if (!strcmp(s->candidate.transfer_id, common[i].request.transfer_id)) break;
        assert(i < CASES && !(seen & (1u << i)));
        seen |= 1u << i;
        assert(s->candidate.source_cut_known == !legacy &&
            s->candidate.source_cut == (legacy ? 0u : common[i].source_cut) &&
            s->candidate.reserve_index == common[i].grant.reserve_index &&
            !strcmp(s->candidate.lane_id, common[i].request.source_group_id) &&
            !strcmp(s->candidate.generation, common[i].request.source_generation));
    }
    assert(next == 0 && seen == (1u << CASES) - 1u);
    for (size_t i = 0; i < sizeof s->candidate; ++i) assert(!cleared[i]);
    for (size_t i = 0; i < CASES; ++i)
        assert(qihse_kv_ct_lane_status(store, op, common[i].request.source_group_id, &s->before[i]));
    assert(qihse_kv_ct_lane_status(store, op, target_group, &s->before[CASES]));
    assert(qihse_kv_ct_lane_status(store, op, unmarked_group, &s->before[CASES + 1]));
    char error[256]; unsigned before_lookups = lookups;
    c.principal = low;
    assert(!qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
    assert(lookups == before_lookups); c.principal = op;
    available = false;
    assert(!qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
    for (size_t i = 0; i < CASES; ++i) {
        assert(qihse_kv_ct_lane_status(store, op, common[i].request.source_group_id, &s->after));
        assert(!memcmp(&s->before[i], &s->after, sizeof s->after));
    }
    available = true;
    if (!legacy) {
        unsigned char exact[32]; memcpy(exact, common[2].decision.evidence_digest, sizeof exact);
        txn_from_record(2u, &s->txn); s->txn.phase = QIHSE_OWNERSHIP_ABORTED;
        ++s->txn.source_lsn;
        assert(transition_digest(&s->txn, "QIHSE-RANGE-ABORTED-1", common[2].decision.evidence_digest));
        assert(qihse_cluster_range_authority_claim(&authority, op, &s->txn, &s->claim) &&
            qihse_cluster_range_authority_verify_aborted_claim_user(&authority, op, &s->claim));
        --s->claim.source_cut;
        assert(!qihse_cluster_range_authority_verify_aborted_claim_user(&authority, op, &s->claim));
        assert(!qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
        for (size_t i = 0; i < CASES; ++i) {
            assert(qihse_kv_ct_lane_status(store, op, common[i].request.source_group_id, &s->after));
            assert(!memcmp(&s->before[i], &s->after, sizeof s->after));
        }
        assert(qihse_kv_change_seq(store) == rows && !attempted_abort);
        memcpy(common[2].decision.evidence_digest, exact, sizeof exact);
        assert(qihse_cluster_range_authority_verify_aborted_claim_user(&authority, op, &s->claim));
        memset(&s->claim, 0, sizeof s->claim); memset(&s->txn, 0, sizeof s->txn);
    }
    bool ready = qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error);
    assert(qihse_kv_ct_lane_status(store, op, common[2].request.source_group_id, &s->after));
    assert(!ready);
    if (legacy) {
        assert(!memcmp(&s->before[2], &s->after, sizeof s->after));
        txn_from_record(2u, &s->txn); s->txn.phase = QIHSE_OWNERSHIP_ABORTED;
        assert(qihse_cluster_range_authority_claim(&authority, op, &s->txn, &s->claim));
        qihse_kv_ct_proof_t* proof = qihse_kv_ct_lane_authority_proof_create(store, op, op,
            &s->claim, qihse_cluster_range_authority_verify_aborted_claim, &verifier);
        assert(proof && qihse_kv_ct_lane_owner_token_get(store, op,
            common[2].request.source_group_id, s->token));
        assert(qihse_kv_ct_lane_transfer_abort(store, op, op, &s->claim, proof,
            qihse_cluster_range_authority_verify_aborted_claim, &verifier, s->token));
        qihse_kv_ct_proof_destroy(proof);
        assert(qihse_kv_ct_lane_status(store, op, common[2].request.source_group_id, &s->after));
    }
    empty_bitmap(&s->after);
    for (size_t i = 0; i < CASES; ++i) if (i != 2u) {
        assert(qihse_kv_ct_lane_status(store, op, common[i].request.source_group_id, &s->after));
        assert(!memcmp(&s->before[i], &s->after, sizeof s->after));
    }
    assert(qihse_kv_ct_lane_status(store, op, target_group, &s->after) &&
        !memcmp(&s->before[CASES], &s->after, sizeof s->after));
    assert(qihse_kv_change_seq(store) == rows && !attempted_abort);
    assert(qihse_kv_ct_lane_status(store, op, unmarked_group, &s->after) &&
        !memcmp(&s->before[CASES + 1], &s->after, sizeof s->after));
    assert(qihse_kv_ct_lane_transfer_status(store, op, &s->transfer) && !s->transfer.active);
    assert(!qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
    assert(qihse_kv_ct_lane_status(store, op, common[2].request.source_group_id, &s->after));
    empty_bitmap(&s->after);
    memset(&s->claim, 0, sizeof s->claim); memset(&s->txn, 0, sizeof s->txn);
    memset(s->token, 0, sizeof s->token);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op); assert(store); c.store = store;
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    assert(!qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
    assert(qihse_kv_ct_lane_status(store, op, common[2].request.source_group_id, &s->after));
    empty_bitmap(&s->after);
    assert(qihse_kv_change_seq(store) == rows && !attempted_abort);
    assert(qihse_kv_ct_lane_status(store, op, unmarked_group, &s->after) &&
        !memcmp(&s->before[CASES + 1], &s->after, sizeof s->after));
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, target_group,
        "qkp-d", target_generation, s->before[CASES].baseline_digest, 0u));
    char* value = qihse_kv_get_user(store, high_key, op);
    assert(value && !strcmp(value, "unrelated classified")); free(value);
    assert(!qihse_kv_get_user(store, high_key, low));
    qihse_kv_store_destroy(store); free(high_key); free(s);
    qihse_cluster_topology_destroy(topology);
    qihse_audit_shutdown();
    puts(legacy ? "PASS 004 staging cut stays unknown; only explicit exact ABORT can retire it" :
        "PASS nonzero-cut pre-import discovery consumes only exact common ABORT after reopen");
    if (!legacy) {
        const char* modes[] = {"--legacy004", "--historical-rebind"};
        for (size_t i = 0; i < sizeof modes / sizeof modes[0]; ++i) {
            pid_t child = fork(); assert(child >= 0);
            if (!child) { execl("/proc/self/exe", "test_ownership_staging_discovery", modes[i], (char*)NULL); _exit(127); }
            int status; pid_t waited;
            do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
            assert(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
    }
    return 0;
}
