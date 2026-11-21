#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_cluster_ownership.h"
#include "qihse_crc16.h"
#include "aimem_fixture_cleanup.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum stage_fault { STAGE_FAULT_NONE, STAGE_FAULT_META_BEFORE,
    STAGE_FAULT_META_AFTER, STAGE_FAULT_UNLINK };
static enum stage_fault stage_fault;
static char stage_lanes_path[512], stage_transfer_path[512];
static dev_t stage_parent_dev;
static ino_t stage_parent_ino;
static bool stage_metadata_published;
static unsigned stage_fault_hits, stage_metadata_renames, stage_unlink_calls;

int rename(const char* oldpath, const char* newpath) {
    bool selected = stage_fault != STAGE_FAULT_NONE && !strcmp(newpath, stage_lanes_path);
    if (selected && stage_fault == STAGE_FAULT_META_BEFORE) {
        stage_fault = STAGE_FAULT_NONE; ++stage_fault_hits; errno = EIO; return -1;
    }
    int rc = (int)syscall(SYS_rename, oldpath, newpath);
    if (selected && rc == 0) {
        ++stage_metadata_renames;
        if (stage_fault == STAGE_FAULT_META_AFTER) stage_metadata_published = true;
    }
    return rc;
}
int fsync(int fd) {
    struct stat st;
    if (stage_fault == STAGE_FAULT_META_AFTER && stage_metadata_published &&
        fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_dev == stage_parent_dev && st.st_ino == stage_parent_ino) {
        stage_fault = STAGE_FAULT_NONE; stage_metadata_published = false;
        ++stage_fault_hits; errno = EIO; return -1;
    }
    return (int)syscall(SYS_fsync, fd);
}
int unlink(const char* path) {
    if (stage_fault != STAGE_FAULT_NONE && !strcmp(path, stage_transfer_path)) {
        ++stage_unlink_calls;
        if (stage_fault == STAGE_FAULT_UNLINK) {
            stage_fault = STAGE_FAULT_NONE; ++stage_fault_hits; errno = EIO; return -1;
        }
    }
    return (int)syscall(SYS_unlink, path);
}

static const char LANE_A[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char LANE_C[] = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char LANE_OTHER[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char GEN_A[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_C[] = "cccccccccccccccccccccccccccccccc";
static const char GEN_OTHER[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

typedef struct {
    qihse_kv_ct_lane_authority_claim_t claim;
    unsigned phase; /* 0 RESERVED, 1 FINAL, 2 ABORT */
} decision_t;
typedef struct {
    decision_t decisions[6];
    char nodes[3][QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    bool fail_abort, hide_abort;
    unsigned abort_calls;
} authority_t;

static bool operator_active(qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM;
}
static decision_t* decision(authority_t* a, const char* id) {
    for (size_t i = 0; i < sizeof a->decisions / sizeof a->decisions[0]; ++i)
        if (!strcmp(a->decisions[i].claim.transfer_id, id)) return &a->decisions[i];
    return NULL;
}
static bool peer_id(void* opaque, const char* node, char out[65]) {
    authority_t* a = opaque;
    const char* pins[] = {"qkp-a", "qkp-c", "qkp-d"};
    for (size_t i = 0; i < 3; ++i) if (!strcmp(a->nodes[i], node)) {
        snprintf(out, 65, "%s", pins[i]); return true;
    }
    return false;
}
static bool claim_get(void* opaque, qihse_user_t* op,
    const qihse_cluster_ownership_txn_t* txn, qihse_kv_ct_lane_authority_claim_t* out) {
    authority_t* a = opaque;
    decision_t* d = decision(a, txn->transfer_id);
    if (!operator_active(op) || !d ||
        (d->phase == 2 && txn->phase != QIHSE_OWNERSHIP_ABORTED)) return false;
    *out = d->claim;
    if (d->phase) {
        out->final_decision_index = out->reserve_index + 100u;
        memset(out->final_decision_digest, d->phase == 2 ? 0xAB : 0xFA, 32);
    }
    return true;
}
static bool verify_claim(void* opaque, qihse_user_t* op,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool require_final) {
    authority_t* a = opaque;
    decision_t* d = decision(a, claim->transfer_id);
    return operator_active(op) && d && d->phase != 2 &&
        claim->reserve_index == d->claim.reserve_index &&
        !strcmp(claim->source_group_id, d->claim.source_group_id) &&
        !strcmp(claim->source_generation, d->claim.source_generation) &&
        claim->source_cut == d->claim.source_cut &&
        !memcmp(claim->slots, d->claim.slots, sizeof(claim->slots)) &&
        (!require_final || (d->phase == 1 &&
            claim->final_decision_index == claim->reserve_index + 100u));
}
static bool verify_aborted(void* opaque, qihse_user_t* op,
    const qihse_kv_ct_lane_authority_claim_t* claim) {
    authority_t* a = opaque;
    decision_t* d = decision(a, claim->transfer_id);
    return operator_active(op) && d && d->phase == 2 && !a->hide_abort &&
        claim->reserve_index == d->claim.reserve_index &&
        claim->source_cut == d->claim.source_cut && claim->target_cursor == 0u &&
        claim->final_decision_index == claim->reserve_index + 100u &&
        claim->final_decision_digest[0] == 0xAB &&
        !strcmp(claim->source_group_id, d->claim.source_group_id) &&
        !strcmp(claim->source_generation, d->claim.source_generation) &&
        !memcmp(claim->slots, d->claim.slots, sizeof(claim->slots));
}
static bool verify_adapter(void* opaque,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool require_final) {
    void** p = opaque;
    return verify_claim(p[0], p[1], claim, require_final);
}
static bool aborted_adapter(void* opaque,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool terminal) {
    (void)terminal;
    void** p = opaque;
    return verify_aborted(p[0], p[1], claim);
}
static bool range_check(void* opaque, qihse_user_t* op,
    const qihse_cluster_ownership_txn_t* txn, char* error, size_t cap) {
    (void)opaque; (void)txn; (void)error; (void)cap;
    return operator_active(op);
}
static bool range_reserve(void* opaque, qihse_user_t* op,
    qihse_cluster_ownership_txn_t* txn, char* error, size_t cap) {
    return range_check(opaque, op, txn, error, cap);
}
static bool range_final(void* opaque, qihse_user_t* op,
    const qihse_cluster_ownership_txn_t* txn,
    const qihse_cluster_ct_activation_receipt_t* receipt, char* error, size_t cap) {
    (void)receipt;
    return range_check(opaque, op, txn, error, cap);
}
static bool range_abort(void* opaque, qihse_user_t* op,
    const qihse_cluster_ownership_txn_t* txn, char* error, size_t cap) {
    authority_t* a = opaque;
    ++a->abort_calls;
    decision_t* d = decision(a, txn->transfer_id);
    (void)error; (void)cap;
    if (!operator_active(op) || !d || a->fail_abort || d->phase == 1 ||
        txn->phase != QIHSE_OWNERSHIP_ABORTED ||
        txn->source_lsn != d->claim.source_cut) return false;
    d->phase = 2;
    return true;
}
static void bit(uint8_t* slots, uint16_t slot) {
    slots[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
}
static char* key_at_slot(uint16_t slot) {
    char key[64];
    for (unsigned i = 0; i < 1000000u; ++i) {
        snprintf(key, sizeof(key), "abort-key-%u", i);
        if (qihse_cluster_key_slot(key, strlen(key)) == slot) return strdup(key);
    }
    abort();
}
static void init_decision(authority_t* a, size_t index, const char* id,
    uint16_t slot, uint64_t cut) {
    decision_t* d = &a->decisions[index];
    memset(d, 0, sizeof(*d));
    qihse_kv_ct_lane_authority_claim_t* c = &d->claim;
    c->operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(c->transfer_id, sizeof(c->transfer_id), "%s", id);
    snprintf(c->source_group_id, sizeof(c->source_group_id), "%s", LANE_A);
    snprintf(c->target_group_id, sizeof(c->target_group_id), "%s", LANE_C);
    snprintf(c->source_qkp_id, sizeof(c->source_qkp_id), "qkp-a");
    snprintf(c->target_qkp_id, sizeof(c->target_qkp_id), "qkp-c");
    snprintf(c->successor_qkp_id, sizeof(c->successor_qkp_id), "qkp-d");
    snprintf(c->source_generation, sizeof(c->source_generation), "%s", GEN_A);
    snprintf(c->target_generation, sizeof(c->target_generation), "%s", GEN_C);
    c->grant_epoch = index + 10u; c->reserve_index = index + 20u;
    memset(c->reserve_digest, (int)index + 1, 32); c->source_cut = cut;
    bit(c->slots, slot);
}
static qihse_cluster_ownership_txn_t txn_for(authority_t* a, size_t index,
    qihse_cluster_ownership_phase_t phase, uint16_t slot) {
    const qihse_kv_ct_lane_authority_claim_t* c = &a->decisions[index].claim;
    qihse_cluster_ownership_txn_t t = {0};
    t.phase = phase; t.start = t.end = slot; t.config_epoch = c->grant_epoch;
    t.source_lsn = c->source_cut;
    snprintf(t.transfer_id, sizeof(t.transfer_id), "%s", c->transfer_id);
    snprintf(t.source_id, sizeof(t.source_id), "%s", a->nodes[0]);
    snprintf(t.target_id, sizeof(t.target_id), "%s", a->nodes[1]);
    snprintf(t.source_qkp_id, sizeof(t.source_qkp_id), "%s", c->source_qkp_id);
    snprintf(t.target_qkp_id, sizeof(t.target_qkp_id), "%s", c->target_qkp_id);
    snprintf(t.generation, sizeof(t.generation), "%s", c->source_generation);
    snprintf(t.lane_id, sizeof(t.lane_id), "%s", c->source_group_id);
    snprintf(t.owner_id, sizeof(t.owner_id), "%s", t.source_id);
    memcpy(t.slot_bitmap, c->slots, sizeof(t.slot_bitmap));
    return t;
}
static void source_lane(qihse_kv_store_t* store, qihse_user_t* op,
    qihse_user_t* peer, const char* lane, const char* generation,
    const char* source, const char* successor, uint16_t slot, unsigned char token[32]) {
    uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0}; bit(bitmap, slot);
    if (!qihse_kv_ct_lane_source_enable(store, op, lane, bitmap, source,
            successor, generation, token, 1u << 20)) {
        fprintf(stderr, "source enable failed: lane=%s errno=%d\n", lane, errno);
        abort();
    }
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t seq = 0; unsigned char digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, lane,
        &snapshot, &seq, digest) == 0);
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, lane,
        successor, generation, digest, 0u));
}
static void fence(qihse_kv_store_t* store, qihse_user_t* op,
    authority_t* authority, size_t index, const unsigned char token[32]) {
    qihse_kv_ct_lane_authority_claim_t* claim = &authority->decisions[index].claim;
    void* verification[] = {authority, op};
    qihse_kv_ct_proof_t* proof = qihse_kv_ct_lane_authority_proof_create(
        store, op, op, claim, verify_adapter, verification);
    uint64_t cut = UINT64_MAX;
    assert(proof && qihse_kv_ct_lane_transfer_source_fence(store, op, op,
        claim, proof, verify_adapter, verification, token, &cut));
    assert(cut == claim->source_cut);
    qihse_kv_ct_proof_destroy(proof);
}
static void assert_active(qihse_kv_store_t* store, qihse_user_t* op,
    const char* id) {
    qihse_kv_ct_lane_transfer_status_t state = {0};
    assert(qihse_kv_ct_lane_transfer_status(store, op, &state));
    assert(state.active == (id != NULL));
    if (id) assert(!strcmp(state.claim.transfer_id, id));
}

static void journal_digest(const char* path, unsigned char out[32]) {
    FILE* f = fopen(path, "rb");
    EVP_MD_CTX* hash = EVP_MD_CTX_new();
    assert(f && hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1);
    unsigned char bytes[512]; size_t n;
    while ((n = fread(bytes, 1u, sizeof bytes, f)) != 0u)
        assert(EVP_DigestUpdate(hash, bytes, n) == 1);
    assert(!ferror(f) && fclose(f) == 0);
    unsigned size = 0u;
    assert(EVP_DigestFinal_ex(hash, out, &size) == 1 && size == 32u);
    EVP_MD_CTX_free(hash);
}

static __attribute__((noinline)) void foreign_intent_guard(
    qihse_cluster_ownership_context_t* c, const uint16_t indices[3],
    const char* protected_key, const char* unrelated_key) {
    struct guard {
        qihse_kv_ct_lane_transfer_status_t before, after;
        qihse_kv_ct_lane_status_t lanes[2], after_lane;
        qihse_cluster_ownership_txn_t txn;
    }* g = calloc(1u, sizeof(*g));
    assert(g && qihse_kv_ct_lane_transfer_status(c->store, c->principal, &g->before));
    assert(g->before.active && g->before.phase == 1u);
    const char* lanes[] = {LANE_A, LANE_OTHER};
    for (unsigned i = 0; i < 2u; ++i)
        assert(qihse_kv_ct_lane_status(c->store, c->principal, lanes[i], &g->lanes[i]));
    authority_t* a = c->range_authority_context;
    init_decision(a, 2, "foreign-unfenced-intent", 100, 0);
    g->txn = txn_for(a, 2, QIHSE_OWNERSHIP_INTENT, 100);
    const char* directory = qihse_kv_store_data_directory(c->store);
    char journal[512], saved[512]; struct stat st;
    int n = snprintf(journal, sizeof journal, "%s/slot-ownership.journal", directory);
    assert(n > 0 && (size_t)n < sizeof journal);
    assert(lstat(journal, &st) == -1 && errno == ENOENT);
    n = snprintf(saved, sizeof saved, "%s/guard-phase-1.journal", directory);
    assert(n > 0 && (size_t)n < sizeof saved);
    assert(lstat(saved, &st) == -1 && errno == ENOENT);
    assert(qihse_cluster_ownership_journal_append_txn(directory, &g->txn) == 0);
    unsigned char before_digest[32], after_digest[32];
    journal_digest(journal, before_digest);
    unsigned abort_calls = a->abort_calls;
    uint64_t rows = qihse_kv_change_seq(c->store);
    const char* keys[] = {protected_key, unrelated_key};
    char* before_values[] = {
        qihse_kv_get_user(c->store, keys[0], c->principal),
        qihse_kv_get_user(c->store, keys[1], c->principal)
    };
    assert(before_values[1] && !strcmp(before_values[1], "unrelated remains usable"));
    for (unsigned replay = 0; replay < 2u; ++replay) {
        char error[256] = {0}; bool unresolved = false;
        if (replay) {
            assert(!qihse_cluster_ownership_replay_control(c, &unresolved, error, sizeof error));
            assert(unresolved && error[0]);
        } else {
            assert(!qihse_cluster_ownership_transfer_abort(c, g->txn.transfer_id,
                indices[0], indices[1], error, sizeof error));
            assert(strstr(error, "does not match its durable source fence"));
        }
        assert(a->abort_calls == abort_calls && a->decisions[2].phase == 0u);
        assert(qihse_kv_ct_lane_transfer_status(c->store, c->principal, &g->after) &&
            !memcmp(&g->before, &g->after, sizeof g->before));
        for (unsigned i = 0; i < 2u; ++i) {
            memset(&g->after_lane, 0, sizeof g->after_lane);
            assert(qihse_kv_ct_lane_status(c->store, c->principal, lanes[i], &g->after_lane) &&
                !memcmp(&g->lanes[i], &g->after_lane, sizeof g->after_lane));
        }
        for (unsigned i = 0; i < 2u; ++i) {
            char* value = qihse_kv_get_user(c->store, keys[i], c->principal);
            assert(before_values[i] ? (value && !strcmp(value, before_values[i])) : !value);
            free(value);
        }
        assert(qihse_kv_change_seq(c->store) == rows);
        journal_digest(journal, after_digest);
        assert(!memcmp(before_digest, after_digest, sizeof before_digest));
    }
    assert(rename(journal, saved) == 0); /* Preserve the rejected INTENT, not an older journal. */
    free(before_values[0]); free(before_values[1]);
    free(g);
}

static void assert_lanes_unchanged(qihse_kv_store_t* store, qihse_user_t* op,
    const qihse_kv_ct_lane_status_t* a, const qihse_kv_ct_lane_status_t* c,
    uint64_t rows) {
    qihse_kv_ct_lane_status_t* now = calloc(2u, sizeof(*now)); assert(now);
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &now[0]) &&
        !memcmp(a, &now[0], sizeof(*a)));
    assert(qihse_kv_ct_lane_status(store, op, LANE_C, &now[1]) &&
        !memcmp(c, &now[1], sizeof(*c)));
    assert(qihse_kv_change_seq(store) == rows);
    free(now);
}

/* Exercise the canonical older wire format, not a native-struct dump. Only
 * this fixture's closed, unmarked receiver image is rewritten. */
static void legacy_lane_metadata(const char* directory, bool downgrade) {
    enum { V3 = 2558, V4 = V3 + 105, V5 = V4 + 9 };
    char path[512], saved[512];
    int n = snprintf(path, sizeof path, "%s/ct-lanes.bin", directory);
    assert(n > 0 && (size_t)n < sizeof path);
    FILE* f = fopen(path, "rb"); assert(f);
    assert(fseek(f, 0, SEEK_END) == 0);
    long length = ftell(f);
    assert(length >= 20 && length <= (long)(20u + QIHSE_KV_CT_MAX_LANES * V5));
    rewind(f);
    unsigned char* bytes = malloc((size_t)length); assert(bytes);
    assert(fread(bytes, 1u, (size_t)length, f) == (size_t)length && fclose(f) == 0);
    assert(!memcmp(bytes, "QCTLN004", 8u) || !memcmp(bytes, "QCTLN005", 8u));
    size_t record = !memcmp(bytes, "QCTLN005", 8u) ? V5 : V4;
    uint32_t count = ((uint32_t)bytes[8] << 24) | ((uint32_t)bytes[9] << 16) |
        ((uint32_t)bytes[10] << 8) | bytes[11];
    assert(count <= QIHSE_KV_CT_MAX_LANES && (size_t)length == 20u + (size_t)count * record);
    if (!downgrade) {
        for (uint32_t i = 0; i < count; ++i)
            for (size_t j = V3; j < record; ++j)
                assert(bytes[12u + (size_t)i * record + j] == 0u);
    } else {
        for (uint32_t i = 0; i < count; ++i)
            memmove(bytes + 12u + (size_t)i * V3, bytes + 12u + (size_t)i * record, V3);
        memcpy(bytes, "QCTLN003", 8u);
        size_t end = 12u + (size_t)count * V3;
        uint64_t hash = UINT64_C(14695981039346656037);
        for (size_t i = 0; i < end; ++i) hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
        for (size_t i = 0; i < 8u; ++i) bytes[end + i] = (unsigned char)(hash >> (56u - i * 8u));
        n = snprintf(saved, sizeof saved, "%s/ct-lanes.before-legacy", directory);
        assert(n > 0 && (size_t)n < sizeof saved && access(saved, F_OK) != 0 && errno == ENOENT);
        assert(rename(path, saved) == 0);
        f = fopen(path, "wbx"); assert(f);
        assert(fwrite(bytes, 1u, end + 8u, f) == end + 8u && fflush(f) == 0 &&
            fsync(fileno(f)) == 0 && fclose(f) == 0);
        int fd = open(directory, O_RDONLY | O_DIRECTORY); assert(fd >= 0);
        assert(fsync(fd) == 0 && close(fd) == 0);
    }
    free(bytes);
}

static int target_case(const char* directory, bool successor, bool staging,
    enum stage_fault requested_fault) {
    alarm(120);
    assert(setenv("QIHSE_DATA_DIR", directory, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator("LaneAbortOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0, "LaneAbortOperator1!");
    qihse_user_t* peer = qihse_auth_create_user(op, 8911, QIHSE_ROLE_ANALYST,
        5, 1, "LaneAbortPeer1!", false);
    qihse_user_t* low = qihse_auth_create_user(op, 8912, QIHSE_ROLE_ANALYST,
        0, 0, "LaneAbortLow1!", false);
    assert(op && peer && low);
    authority_t authority = {0};
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology);
    uint16_t indices[3];
    for (size_t i = 0; i < 3; ++i) {
        qihse_cluster_node_t node = {0};
        char name[32]; snprintf(name, sizeof(name), "lane-abort-node-%zu", i);
        qihse_cluster_node_id_from_seed(name, strlen(name), node.id);
        snprintf(authority.nodes[i], sizeof(authority.nodes[i]), "%s", node.id);
        snprintf(node.host, sizeof(node.host), "127.0.0.1");
        node.port = (uint16_t)(7900 + i); node.bus_port = (uint16_t)(17900 + i);
        node.role = QIHSE_CLUSTER_NODE_PRIMARY; node.healthy = true;
        node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        assert(qihse_cluster_topology_upsert_node(topology, &node, &indices[i]));
    }
    assert(qihse_cluster_topology_set_local_node(topology, indices[0]));
    assert(qihse_cluster_topology_adopt_range(topology, 100, 100, indices[0], 1));
    qihse_kv_store_t* store = NULL;
    qihse_cluster_ownership_context_t c = {.topology = topology, .store = store,
        .principal = op, .data_principal = op, .peer_id = peer_id,
        .peer_id_context = &authority, .range_reserve = range_reserve,
        .range_check_reserved = range_check, .range_finalize = range_final,
        .range_check_finalized = range_check, .range_abort = range_abort,
        .lane_claim = claim_get, .lane_verify_claim = verify_claim,
        .lane_verify_aborted = verify_aborted, .range_authority_context = &authority};
    char error[256]; bool unresolved = false;
    qihse_kv_ct_lane_status_t status;
    /* A cancelled stage on C has no source-local singleton fence. */
    store = qihse_kv_store_create_user(op); assert(store); c.store = store;
    char* existing_key = NULL;
    qihse_kv_replica_snapshot_t* existing_image = NULL;
    if (!successor) {
        existing_key = key_at_slot(100);
        assert(existing_key && qihse_kv_set_user(store, existing_key,
            "preserved receiver row", 4, 1, op));
        assert(qihse_kv_sync_store(store));
        assert(qihse_kv_replica_snapshot_create(store, op, "*",
            &existing_image) == 0);
        if (staging) {
            assert(qihse_kv_del_user(store, existing_key, op));
            assert(qihse_kv_sync_store(store));
        }
    }
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    assert(qihse_cluster_topology_set_local_node(topology, indices[successor ? 2 : 1]));
    unsigned char token_c[32], receiver_token[32];
    if (!successor) {
        source_lane(store, op, peer, LANE_C, GEN_C, "qkp-c", "qkp-d", 9000, token_c);
    } else {
        uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0}; bit(bitmap, 9000);
        assert(qihse_kv_ct_lane_receiver_bind(store, op, LANE_C, bitmap,
            "qkp-c", "qkp-d", GEN_C, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, 0, token_c));
        unsigned char digest[32];
        assert(qihse_kv_ct_lane_receiver_empty_baseline_seal(store, op,
            LANE_C, token_c, digest));
    }
    char* target_key = NULL;
    if (staging) {
        target_key = key_at_slot(9000); assert(target_key);
        qihse_kv_ct_writer_scope_t* scope = NULL;
        assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_C, token_c, &scope));
        assert(qihse_kv_set_user(store, target_key, "protected target remains", 4, 1, op));
        qihse_kv_ct_writer_scope_leave(scope);
        assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_C, "qkp-d", GEN_C, 1u));
    }
    qihse_kv_ct_lane_status_t target_before = {0};
    assert(qihse_kv_ct_lane_status(store, op, LANE_C, &target_before));
    init_decision(&authority, 3, successor ? "successor-cancel-stage" : "target-cancel-stage", 100, 0);
    qihse_kv_ct_lane_authority_claim_t* incoming = &authority.decisions[3].claim;
    if (!staging)
        assert(qihse_kv_ct_lane_receiver_bind(store, op, LANE_A, incoming->slots,
            "qkp-a", successor ? "qkp-d" : "qkp-c", GEN_A,
            QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, 0, receiver_token));
    void* verification[] = {&authority, op};
    struct stage_guard {
        qihse_kv_ct_lane_authority_claim_t aborted, other;
        qihse_cluster_ownership_txn_t txn;
        qihse_kv_ct_lane_status_t before_lane, after_lane;
        qihse_kv_ct_lane_transfer_status_t before_transfer, after_transfer;
        unsigned char old_token[32];
    } *g = staging ? calloc(1u, sizeof(*g)) : NULL;
    qihse_kv_ct_proof_t* old_abort = NULL;
    uint64_t guarded_rows = qihse_kv_change_seq(store);
    if (staging) {
        assert(g);
        init_decision(&authority, 0, "target-prepared-only", 102, 0);
        snprintf(authority.decisions[0].claim.source_generation,
            sizeof authority.decisions[0].claim.source_generation, "%s", GEN_OTHER);
        qihse_kv_ct_proof_t* reserved = qihse_kv_ct_lane_authority_proof_create(
            store, op, op, &authority.decisions[0].claim, verify_adapter, verification);
        assert(reserved && qihse_kv_ct_lane_receiver_prepare(store, op, op,
            &authority.decisions[0].claim, reserved, verify_adapter, verification, g->old_token));
        assert_active(store, op, NULL);
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &g->before_lane));
        assert(!qihse_kv_ct_lane_transfer_abort(store, op, op,
            &authority.decisions[0].claim, NULL, aborted_adapter, verification, g->old_token));
        assert_lanes_unchanged(store, op, &g->before_lane, &target_before, guarded_rows);
        assert(!qihse_kv_ct_lane_transfer_abort(store, op, op,
            &authority.decisions[0].claim, reserved, aborted_adapter, verification, g->old_token));
        assert_lanes_unchanged(store, op, &g->before_lane, &target_before, guarded_rows);
        qihse_kv_ct_proof_destroy(reserved);
        authority.decisions[0].phase = 2;
        g->txn = txn_for(&authority, 0, QIHSE_OWNERSHIP_ABORTED, 102);
        assert(claim_get(&authority, op, &g->txn, &g->aborted));
        old_abort = qihse_kv_ct_lane_authority_proof_create(store, op, op,
            &g->aborted, aborted_adapter, verification);
        assert(old_abort);
        unsigned char bad_token[32]; memcpy(bad_token, g->old_token, sizeof bad_token);
        bad_token[0] ^= 1u;
        assert(memcmp(bad_token, token_c, sizeof bad_token));
        assert(!qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            old_abort, aborted_adapter, verification, bad_token));
        assert_lanes_unchanged(store, op, &g->before_lane, &target_before, guarded_rows);
        authority.hide_abort = true;
        assert(!qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            old_abort, aborted_adapter, verification, g->old_token));
        authority.hide_abort = false;
        assert_lanes_unchanged(store, op, &g->before_lane, &target_before, guarded_rows);
        init_decision(&authority, 1, "target-other-generation", 102, 0);
        authority.decisions[1].phase = 2;
        g->txn = txn_for(&authority, 1, QIHSE_OWNERSHIP_ABORTED, 102);
        assert(claim_get(&authority, op, &g->txn, &g->other));
        qihse_kv_ct_proof_t* other = qihse_kv_ct_lane_authority_proof_create(
            store, op, op, &g->other, aborted_adapter, verification);
        assert(other && qihse_kv_ct_lane_transfer_abort(store, op, op,
            &g->other, other, aborted_adapter, verification, token_c));
        qihse_kv_ct_proof_destroy(other);
        assert_lanes_unchanged(store, op, &g->before_lane, &target_before, guarded_rows);
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &g->after_lane) &&
            !memcmp(&g->before_lane, &g->after_lane, sizeof g->before_lane));
        assert(qihse_kv_change_seq(store) == guarded_rows);
        assert(qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            old_abort, aborted_adapter, verification, g->old_token));
        assert(qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            old_abort, aborted_adapter, verification, g->old_token));
    }
    qihse_kv_ct_proof_t* proof = qihse_kv_ct_lane_authority_proof_create(
        store, op, op, incoming, verify_adapter, verification);
    assert(proof);
    if (staging) {
        assert(qihse_kv_ct_lane_receiver_prepare(store, op, op, incoming, proof,
            verify_adapter, verification, receiver_token));
        assert(memcmp(receiver_token, g->old_token, sizeof receiver_token));
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &g->before_lane));
        assert(qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            old_abort, aborted_adapter, verification, token_c));
        assert_lanes_unchanged(store, op, &g->before_lane, &target_before, guarded_rows);
        assert(!qihse_kv_ct_lane_transfer_abort(store, op, op, incoming,
            old_abort, aborted_adapter, verification, token_c));
        assert_lanes_unchanged(store, op, &g->before_lane, &target_before, guarded_rows);
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &g->after_lane) &&
            !memcmp(&g->before_lane, &g->after_lane, sizeof g->before_lane));
        assert_active(store, op, NULL);
    }
    assert(qihse_kv_ct_lane_transfer_target_import_begin(store, op, op,
        incoming, proof, verify_adapter, verification, token_c));
    if (staging) {
        assert(qihse_kv_ct_lane_transfer_status(store, op, &g->before_transfer));
        assert(!qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            old_abort, aborted_adapter, verification, token_c));
        assert_lanes_unchanged(store, op, &g->before_lane, &target_before, guarded_rows);
        assert(qihse_kv_ct_lane_transfer_status(store, op, &g->after_transfer) &&
            !memcmp(&g->before_transfer, &g->after_transfer, sizeof g->before_transfer));
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &g->after_lane) &&
            !memcmp(&g->before_lane, &g->after_lane, sizeof g->before_lane));
        assert(qihse_kv_change_seq(store) == guarded_rows);
        qihse_kv_ct_proof_destroy(old_abort);
    }
    qihse_kv_ct_proof_destroy(proof);
    qihse_cluster_ownership_txn_t target_prepared = txn_for(&authority, 3, QIHSE_OWNERSHIP_PREPARED, 100);
    if (!successor)
        assert(qihse_cluster_ownership_journal_append_txn(directory, &target_prepared) == 0);
    authority.decisions[3].phase = 1; /* Wrong terminal decision must not un-fence. */
    assert(!qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof(error)));
    assert_active(store, op, incoming->transfer_id);
    authority.decisions[3].phase = 0;
    proof = qihse_kv_ct_lane_authority_proof_create(store, op, op, incoming,
        verify_adapter, verification);
    assert(proof);
    char empty_path[512];
    assert(snprintf(empty_path, sizeof(empty_path), "%s/empty-incoming.qfs", directory) > 0);
    FILE* empty = fopen(empty_path, "wb");
    assert(empty);
    EVP_MD_CTX* hash = EVP_MD_CTX_new();
    assert(hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1);
    if (existing_image) {
        unsigned char buffer[4096];
        uint64_t offset = 0u;
        size_t bytes = 0u;
        do {
            assert(qihse_kv_replica_snapshot_read(existing_image, op, offset,
                buffer, sizeof buffer, &bytes));
            assert(fwrite(buffer, 1u, bytes, empty) == bytes);
            assert(EVP_DigestUpdate(hash, buffer, bytes) == 1);
            offset += bytes;
        } while (bytes != 0u);
        qihse_kv_replica_snapshot_destroy(existing_image);
    }
    assert(fclose(empty) == 0);
    unsigned char image_digest[32]; unsigned digest_bytes = 0u;
    assert(EVP_DigestFinal_ex(hash, image_digest, &digest_bytes) == 1 &&
        digest_bytes == sizeof(image_digest));
    EVP_MD_CTX_free(hash);
    uint64_t before_import = qihse_kv_change_seq(store);
    assert(qihse_kv_ct_lane_transfer_target_import_apply_file(store, op, peer, op,
        incoming, proof, verify_adapter, verification, empty_path, image_digest, token_c));
    if (existing_key) assert(qihse_kv_change_seq(store) == before_import + (staging ? 1u : 0u));
    qihse_kv_ct_proof_destroy(proof);
    authority.decisions[3].phase = 2;
    if (requested_fault != STAGE_FAULT_NONE) {
        assert(staging && g);
        const char* data = qihse_kv_store_data_directory(store);
        struct stat parent; assert(data && stat(data, &parent) == 0);
        int n = snprintf(stage_lanes_path, sizeof stage_lanes_path, "%sct-lanes.bin", data);
        assert(n > 0 && (size_t)n < sizeof stage_lanes_path);
        n = snprintf(stage_transfer_path, sizeof stage_transfer_path, "%sct-lane-transfer.bin", data);
        assert(n > 0 && (size_t)n < sizeof stage_transfer_path);
        stage_parent_dev = parent.st_dev; stage_parent_ino = parent.st_ino;
        stage_metadata_published = false;
        stage_fault_hits = stage_metadata_renames = stage_unlink_calls = 0u;
        unsigned char before_digest[32], after_digest[32];
        journal_digest(stage_transfer_path, before_digest);
        assert(qihse_kv_ct_lane_transfer_status(store, op, &g->before_transfer));
        stage_fault = requested_fault;
        assert(!qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
        assert(stage_fault_hits == 1u && stage_fault == STAGE_FAULT_NONE);
        assert(stage_metadata_renames == (requested_fault == STAGE_FAULT_META_BEFORE ? 0u : 1u));
        assert(stage_unlink_calls == (requested_fault == STAGE_FAULT_UNLINK ? 1u : 0u));
        journal_digest(stage_transfer_path, after_digest);
        assert(!memcmp(before_digest, after_digest, sizeof before_digest));
        if (requested_fault == STAGE_FAULT_UNLINK) {
            assert(qihse_kv_ct_lane_transfer_status(store, op, &g->after_transfer) &&
                !memcmp(&g->before_transfer, &g->after_transfer, sizeof g->before_transfer));
        } else {
            assert(!qihse_kv_ct_lane_transfer_status(store, op, &g->after_transfer));
            assert(errno == EIO);
        }
        qihse_kv_store_destroy(store);
        store = qihse_kv_store_create_user(op); assert(store); c.store = store;
        qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
        assert(qihse_kv_ct_lane_transfer_status(store, op, &g->after_transfer) &&
            !memcmp(&g->before_transfer, &g->after_transfer, sizeof g->before_transfer));
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status));
        if (requested_fault == STAGE_FAULT_META_BEFORE)
            assert(!memcmp(status.slot_bitmap, incoming->slots, sizeof status.slot_bitmap));
        else for (size_t i = 0; i < sizeof status.slot_bitmap; ++i)
            assert(status.slot_bitmap[i] == 0u);
        assert(qihse_kv_ct_lane_status(store, op, LANE_C, &status));
        assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_C,
            "qkp-d", GEN_C, status.baseline_digest, status.durable_position));
        assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_C, token_c));
        fprintf(stderr, "staging fault=%u witnessed and reopened before exact ABORT retry\n",
            (unsigned)requested_fault);
    }
    assert(qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof(error)));
    assert_active(store, op, NULL);
    if (!successor)
        assert(qihse_cluster_ownership_replay_control(&c, &unresolved, error, sizeof(error)) && !unresolved);
    assert(qihse_kv_ct_lane_status(store, op, LANE_C, &status));
    assert(status.mode == (successor ? QIHSE_KV_CT_LANE_RECEIVER : QIHSE_KV_CT_LANE_SOURCE));
    assert(status.admitted == target_before.admitted &&
        status.baseline_sealed == target_before.baseline_sealed &&
        status.durable_position == target_before.durable_position &&
        !memcmp(status.slot_bitmap, target_before.slot_bitmap, sizeof(status.slot_bitmap)));
    if (staging) {
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status));
        bool retired = true;
        for (size_t i = 0; i < sizeof status.slot_bitmap; ++i)
            retired &= status.slot_bitmap[i] == 0u;
        qihse_kv_store_destroy(store);
        store = qihse_kv_store_create_user(op); assert(store); c.store = store;
        qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
        assert(qihse_kv_ct_lane_status(store, op, LANE_C, &status));
        assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_C,
            "qkp-d", GEN_C, status.baseline_digest, status.durable_position));
        assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_C, token_c));
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status));
        for (size_t i = 0; i < sizeof status.slot_bitmap; ++i)
            retired &= status.slot_bitmap[i] == 0u;
        init_decision(&authority, 2, "target-cancel-disjoint-retry", 101, 0);
        incoming = &authority.decisions[2].claim;
        proof = qihse_kv_ct_lane_authority_proof_create(store, op, op, incoming,
            verify_adapter, verification);
        assert(proof);
        bool prepared = qihse_kv_ct_lane_receiver_prepare(store, op, op, incoming,
            proof, verify_adapter, verification, receiver_token);
        if (!prepared) fprintf(stderr, "staging disjoint prepare refused errno=%d retired=%d\n",
            errno, retired);
        assert(prepared && retired);
        assert(qihse_kv_ct_lane_transfer_target_import_begin(store, op, op,
            incoming, proof, verify_adapter, verification, token_c));
        qihse_kv_ct_proof_destroy(proof);
        authority.decisions[2].phase = 2;
        assert(qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
        assert_active(store, op, NULL);
        char* target_value = qihse_kv_get_user(store, target_key, op);
        assert(target_value && !strcmp(target_value, "protected target remains"));
        free(target_value);
        assert(!qihse_kv_get_user(store, target_key, low));
        /* Retired rows are deliberately not publicly owned. Reimporting the
         * original authenticated image must find identical bytes/labels and
         * perform no row replacement, rather than bypassing the read fence. */
        init_decision(&authority, 4, "target-cancel-original-image-retry", 100, 0);
        incoming = &authority.decisions[4].claim;
        proof = qihse_kv_ct_lane_authority_proof_create(store, op, op, incoming,
            verify_adapter, verification);
        assert(proof && qihse_kv_ct_lane_receiver_prepare(store, op, op, incoming,
            proof, verify_adapter, verification, receiver_token));
        assert(qihse_kv_ct_lane_transfer_target_import_begin(store, op, op,
            incoming, proof, verify_adapter, verification, token_c));
        uint64_t rows = qihse_kv_change_seq(store);
        assert(qihse_kv_ct_lane_transfer_target_import_apply_file(store, op, peer, op,
            incoming, proof, verify_adapter, verification, empty_path, image_digest, token_c));
        assert(qihse_kv_change_seq(store) == rows);
        qihse_kv_ct_proof_destroy(proof);
        const char* keys[] = {target_key};
        const char* values[] = {"protected target remains"};
        for (size_t i = 0; i < sizeof keys / sizeof keys[0]; ++i) {
            qihse_kv_replica_snapshot_t* image = NULL;
            assert(qihse_kv_replica_snapshot_create(store, op, keys[i], &image) == 0);
            uint64_t size = 0u;
            assert(qihse_kv_replica_snapshot_size(image, op, &size));
            char bytes[256]; size_t got = 0u;
            assert(size < sizeof bytes && qihse_kv_replica_snapshot_read(image, op,
                0u, bytes, sizeof bytes - 1u, &got) && got == size);
            bytes[got] = '\0';
            size_t kl, vl; unsigned long long expiry, seq;
            unsigned classification, sci, flags; int header = 0;
            assert(sscanf(bytes, "%zu %zu %llu %u %u %u %llu%n", &kl, &vl,
                &expiry, &classification, &sci, &flags, &seq, &header) == 7);
            assert(classification == 4u && sci == 1u && flags == 0u && expiry == 0u);
            assert(header > 0 && bytes[header] == '\n' && kl == strlen(keys[i]) && vl == strlen(values[i]));
            assert((size_t)header + 1u + kl + vl + 1u == got);
            assert(!memcmp(bytes + header + 1, keys[i], kl) &&
                !memcmp(bytes + header + 1 + kl, values[i], vl) && bytes[got - 1u] == '\n');
            qihse_kv_replica_snapshot_destroy(image);
            assert(!qihse_kv_get_user(store, keys[i], low));
        }
        assert(qihse_kv_change_seq(store) == rows);
        /* Complete this native transfer, then cancel preparation that precedes
         * import_begin replacing the retained phase-4 descriptor. */
        assert(qihse_kv_ct_lane_transfer_status(store, op, &g->before_transfer));
        memcpy(authority.decisions[4].claim.image_digest, g->before_transfer.image_digest, 32u);
        memcpy(authority.decisions[4].claim.range_digest, g->before_transfer.range_digest, 32u);
        authority.decisions[4].phase = 1;
        g->txn = txn_for(&authority, 4, QIHSE_OWNERSHIP_FINALIZED, 100);
        assert(claim_get(&authority, op, &g->txn, &g->other));
        proof = qihse_kv_ct_lane_authority_proof_create(store, op, op, &g->other,
            verify_adapter, verification);
        assert(proof && qihse_kv_ct_lane_transfer_membership_finalize(store, op, op,
            &g->other, proof, verify_adapter, verification, receiver_token, token_c));
        qihse_kv_ct_proof_destroy(proof);
        assert(qihse_kv_ct_lane_transfer_status(store, op, &g->before_transfer) &&
            g->before_transfer.phase == 4u);
        assert(qihse_kv_ct_lane_status(store, op, LANE_C, &g->before_lane));
        char descriptor[512];
        int n = snprintf(descriptor, sizeof descriptor, "%sct-lane-transfer.bin",
            qihse_kv_store_data_directory(store));
        assert(n > 0 && (size_t)n < sizeof descriptor);
        unsigned char before_digest[32], after_digest[32];
        journal_digest(descriptor, before_digest);
        init_decision(&authority, 5, "target-prepare-after-completed", 101, 0);
        proof = qihse_kv_ct_lane_authority_proof_create(store, op, op,
            &authority.decisions[5].claim, verify_adapter, verification);
        assert(proof && qihse_kv_ct_lane_receiver_prepare(store, op, op,
            &authority.decisions[5].claim, proof, verify_adapter, verification, receiver_token));
        qihse_kv_ct_proof_destroy(proof);
        authority.decisions[5].phase = 2;
        g->txn = txn_for(&authority, 5, QIHSE_OWNERSHIP_ABORTED, 101);
        assert(claim_get(&authority, op, &g->txn, &g->aborted));
        proof = qihse_kv_ct_lane_authority_proof_create(store, op, op,
            &g->aborted, aborted_adapter, verification);
        journal_digest(descriptor, after_digest);
        assert(!memcmp(before_digest, after_digest, sizeof before_digest));
        qihse_kv_ct_proof_destroy(proof); proof = NULL;
        memset(receiver_token, 0, sizeof receiver_token); memset(token_c, 0, sizeof token_c);
        memset(g->old_token, 0, sizeof g->old_token);
        memset(&g->aborted, 0, sizeof g->aborted); memset(&g->txn, 0, sizeof g->txn);
        qihse_kv_store_destroy(store);
        store = qihse_kv_store_create_user(op); assert(store); c.store = store;
        journal_digest(descriptor, after_digest);
        assert(!memcmp(before_digest, after_digest, sizeof before_digest));
        assert(qihse_kv_ct_lane_transfer_status(store, op, &g->after_transfer) &&
            !memcmp(&g->before_transfer, &g->after_transfer, sizeof g->before_transfer));
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &g->after_lane) &&
            (g->after_lane.slot_bitmap[101u / 8u] & (1u << (101u % 8u))));
        assert(qihse_kv_ct_lane_status(store, op, LANE_C, &g->before_lane));
        assert(qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &g->after_lane));
        for (size_t i = 0; i < sizeof g->after_lane.slot_bitmap; ++i)
            assert(!g->after_lane.slot_bitmap[i]);
        g->txn = txn_for(&authority, 5, QIHSE_OWNERSHIP_ABORTED, 101);
        assert(claim_get(&authority, op, &g->txn, &g->aborted));
        proof = qihse_kv_ct_lane_authority_proof_create(store, op, op,
            &g->aborted, aborted_adapter, verification);
        assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_A, receiver_token));
        assert(proof && qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            proof, aborted_adapter, verification, receiver_token));
        assert(qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            proof, aborted_adapter, verification, receiver_token));
        assert(qihse_kv_ct_lane_status(store, op, LANE_C, &g->after_lane) &&
            !memcmp(&g->before_lane, &g->after_lane, sizeof g->before_lane));
        qihse_kv_ct_proof_destroy(proof);
        memset(receiver_token, 0, sizeof receiver_token); memset(token_c, 0, sizeof token_c);
        memset(g->old_token, 0, sizeof g->old_token);
        memset(&g->aborted, 0, sizeof g->aborted); memset(&g->txn, 0, sizeof g->txn);
        qihse_kv_store_destroy(store);
        store = qihse_kv_store_create_user(op); assert(store); c.store = store;
        /* Inspect before any retry can mask nondurable retirement. */
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &g->after_lane));
        for (size_t i = 0; i < sizeof g->after_lane.slot_bitmap; ++i)
            assert(!g->after_lane.slot_bitmap[i]);
        journal_digest(descriptor, after_digest);
        assert(!memcmp(before_digest, after_digest, sizeof before_digest));
        assert(qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof error));
        g->txn = txn_for(&authority, 5, QIHSE_OWNERSHIP_ABORTED, 101);
        assert(claim_get(&authority, op, &g->txn, &g->aborted));
        proof = qihse_kv_ct_lane_authority_proof_create(store, op, op,
            &g->aborted, aborted_adapter, verification);
        assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_A, receiver_token));
        assert(proof && qihse_kv_ct_lane_transfer_abort(store, op, op, &g->aborted,
            proof, aborted_adapter, verification, receiver_token));
        qihse_kv_ct_proof_destroy(proof);
        assert(qihse_kv_ct_lane_transfer_status(store, op, &g->after_transfer) &&
            !memcmp(&g->before_transfer, &g->after_transfer, sizeof g->before_transfer));
        journal_digest(descriptor, after_digest);
        assert(!memcmp(before_digest, after_digest, sizeof before_digest));
        assert(qihse_kv_change_seq(store) == rows);
        free(existing_key); free(target_key);
        puts("PASS reservation-owned staging ABORT permits disjoint receiver reuse after reopen");
    } else if (existing_key) {
        qihse_kv_store_destroy(store);
        legacy_lane_metadata(directory, true);
        store = qihse_kv_store_create_user(op);
        assert(store);
        legacy_lane_metadata(directory, false);
        qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
        /* Re-admit only the target SOURCE lane. Reusing the classified receiver
         * image under a new reservation must not rewrite even one row. */
        source_lane(store, op, peer, LANE_C, GEN_C, "qkp-c", "qkp-d", 9000, token_c);
        assert(qihse_kv_ct_lane_receiver_bind(store, op, LANE_A, incoming->slots,
            "qkp-a", "qkp-c", GEN_A, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, 0,
            receiver_token));
        init_decision(&authority, 3, "target-cancel-stage-retry", 100, 0);
        incoming = &authority.decisions[3].claim;
        proof = qihse_kv_ct_lane_authority_proof_create(store, op, op, incoming,
            verify_adapter, verification);
        assert(proof && qihse_kv_ct_lane_receiver_prepare(store, op, op, incoming,
            proof, verify_adapter, verification, receiver_token));
        assert(qihse_kv_ct_lane_transfer_target_import_begin(store, op,
            op, incoming, proof, verify_adapter, verification, token_c));
        before_import = qihse_kv_change_seq(store);
        assert(!qihse_kv_ct_lane_transfer_target_import_apply_file(store, op,
            peer, low, incoming, proof, verify_adapter, verification, empty_path,
            image_digest, token_c));
        assert(qihse_kv_ct_lane_transfer_target_import_apply_file(store, op, peer,
            op, incoming, proof, verify_adapter, verification, empty_path,
            image_digest, token_c));
        assert(qihse_kv_change_seq(store) == before_import);
        qihse_kv_ct_proof_destroy(proof);
        authority.decisions[3].phase = 2;
        c.store = store;
        assert(qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof(error)));
        assert_active(store, op, NULL);
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status) &&
            !memcmp(status.slot_bitmap, incoming->slots, sizeof status.slot_bitmap));
        qihse_kv_store_destroy(store);
        store = qihse_kv_store_create_user(op); assert(store);
        assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status) &&
            !memcmp(status.slot_bitmap, incoming->slots, sizeof status.slot_bitmap));
        puts("PASS legacy unmarked receiver upgrades without acquiring staging cleanup authority");
        free(existing_key);
    }
    free(g);
    qihse_kv_store_destroy(store);
    qihse_cluster_topology_destroy(topology);
    qihse_auth_release_principal_scoped(low);
    qihse_auth_release_principal_scoped(peer);
    qihse_auth_release_principal_scoped(op);
    return 0;
}

static bool zero_cut_latest(const qihse_cluster_ownership_txn_t* txn, void* opaque) {
    qihse_cluster_ownership_txn_t* latest = opaque;
    assert(!strcmp(txn->transfer_id, latest->transfer_id));
    *latest = *txn;
    return true;
}

typedef struct {
    qihse_kv_ct_lane_transfer_status_t before, after;
    qihse_kv_ct_lane_status_t lanes[2], after_lane;
    qihse_cluster_ownership_txn_t latest, prepared;
    uint16_t owner[2], peer_index[2];
    qihse_cluster_slot_state_t slot_state[2];
    uint64_t epoch[2], rows;
    unsigned char file_digest[3][32];
    dev_t file_dev[3];
    ino_t file_ino[3];
} zero_cut_expect_t;

static const char* zero_cut_native_files[] = {
    "ct-lanes.bin", "ct-lane-transfer.bin", "slot-ownership.journal"
};

static zero_cut_expect_t* zero_cut_expectation(const char* directory,
    qihse_user_t* op, bool verify_files) {
    assert(operator_active(op));
    zero_cut_expect_t* g = calloc(1u, sizeof(*g)); assert(g);
    char path[512];
    int n = snprintf(path, sizeof path, "%s/zero-cut.expect", directory);
    assert(n > 0 && (size_t)n < sizeof path);
    FILE* f = fopen(path, "rb"); assert(f);
    assert(fread(g, 1u, sizeof(*g), f) == sizeof(*g));
    assert(fgetc(f) == EOF && !ferror(f) && fclose(f) == 0);
    if (verify_files) {
        for (unsigned i = 0; i < 3u; ++i) {
            struct stat st; unsigned char digest[32];
            n = snprintf(path, sizeof path, "%s/%s", directory, zero_cut_native_files[i]);
            assert(n > 0 && (size_t)n < sizeof path);
            assert(lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
                st.st_dev == g->file_dev[i] && st.st_ino == g->file_ino[i]);
            journal_digest(path, digest);
            assert(!memcmp(digest, g->file_digest[i], sizeof digest));
        }
    }
    return g;
}

static __attribute__((noinline)) void zero_cut_case(
    qihse_cluster_ownership_context_t* c, qihse_user_t* peer, qihse_user_t* low,
    const uint16_t indices[3], unsigned char token_a[32], unsigned char token_other[32],
    bool recover, int witness_fd) {
    zero_cut_expect_t* g = recover
        ? zero_cut_expectation(getenv("QIHSE_DATA_DIR"), c->principal, false)
        : calloc(1u, sizeof(*g));
    assert(g);
    authority_t* a = c->range_authority_context;
    qihse_user_t* op = c->principal;
    const char* directory = getenv("QIHSE_DATA_DIR");
    const char* lanes[] = {LANE_A, LANE_OTHER};
    const char* generations[] = {GEN_A, GEN_OTHER};
    const char* successors[] = {"qkp-c", "qkp-d"};
    unsigned char* tokens[] = {token_a, token_other};
    const uint16_t slots[] = {100, 9000};
    char* key = key_at_slot(100);
    assert(directory && key && !qihse_kv_get_user(c->store, key, op));
    uint64_t rows = qihse_kv_change_seq(c->store);
    assert(rows == 0u);
    init_decision(a, 3, "lane-zero-cut-fenced-intent", 100, 0);
    bool unresolved = false;
    char expected_path[512];
    int expected_n = snprintf(expected_path, sizeof expected_path,
        "%s/zero-cut.expect", directory);
    assert(expected_n > 0 && (size_t)expected_n < sizeof expected_path);
    if (recover) {
        /* Same-build expectations only: never feed this image to native recovery. */
        assert(g->rows == rows && g->latest.phase == QIHSE_OWNERSHIP_INTENT &&
            g->latest.source_lsn == 0u &&
            !strcmp(g->latest.transfer_id, a->decisions[3].claim.transfer_id));
        assert(!memcmp(&g->before.claim, &a->decisions[3].claim,
            sizeof g->before.claim));
        goto native_reopened;
    }
    g->latest = txn_for(a, 3, QIHSE_OWNERSHIP_INTENT, 100);
    assert(g->latest.source_lsn == 0u);
    assert(qihse_cluster_ownership_journal_append_txn(directory, &g->latest) == 0);
    assert(qihse_cluster_ownership_journal_replay_txn(directory, zero_cut_latest,
        &g->latest, &unresolved) == 1 && unresolved);
    assert(g->latest.phase == QIHSE_OWNERSHIP_INTENT && g->latest.source_lsn == 0u);
    /* Stop after the real, ACK-durable empty-range fence, before PREPARED. */
    fence(c->store, op, a, 3, token_a);
    assert(qihse_kv_ct_lane_transfer_status(c->store, op, &g->before));
    assert(g->before.active && g->before.phase == 1u && g->before.source_fenced &&
        g->before.source_cut == 0u && g->before.claim.source_cut == 0u &&
        !strcmp(g->before.claim.transfer_id, g->latest.transfer_id));
    for (unsigned i = 0; i < 2u; ++i) {
        assert(qihse_kv_ct_lane_status(c->store, op, lanes[i], &g->lanes[i]));
        assert(qihse_cluster_topology_get_slot(c->topology, slots[i],
            &g->owner[i], &g->slot_state[i], &g->peer_index[i]));
        assert(qihse_cluster_topology_get_slot_epoch(c->topology, slots[i], &g->epoch[i]));
    }
    if (witness_fd >= 0) {
        assert(qihse_cluster_ownership_journal_replay_txn(directory, zero_cut_latest,
            &g->latest, &unresolved) == 1 && unresolved);
        assert(g->latest.phase == QIHSE_OWNERSHIP_INTENT &&
            g->latest.source_lsn == 0u &&
            !strcmp(g->latest.transfer_id, g->before.claim.transfer_id));
        g->rows = rows;
        for (unsigned i = 0; i < 3u; ++i) {
            char path[512]; struct stat st;
            int n = snprintf(path, sizeof path, "%s/%s", directory, zero_cut_native_files[i]);
            assert(n > 0 && (size_t)n < sizeof path);
            assert(lstat(path, &st) == 0 && S_ISREG(st.st_mode));
            g->file_dev[i] = st.st_dev; g->file_ino[i] = st.st_ino;
            journal_digest(path, g->file_digest[i]);
        }
        FILE* f = fopen(expected_path, "wbx"); assert(f);
        assert(fwrite(g, 1u, sizeof(*g), f) == sizeof(*g) && fflush(f) == 0 &&
            fsync(fileno(f)) == 0 && fclose(f) == 0);
        int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        assert(fd >= 0 && fsync(fd) == 0 && close(fd) == 0);
        static const char witness[] =
            "SOURCE_FENCED_PHASE1_INTENT0 lane-zero-cut-fenced-intent\n";
        ssize_t sent;
        do { sent = write(witness_fd, witness, sizeof witness - 1u); }
        while (sent < 0 && errno == EINTR);
        assert(sent == (ssize_t)(sizeof witness - 1u));
        assert(kill(getpid(), SIGKILL) == 0);
        _exit(126);
    }
    qihse_kv_store_destroy(c->store);
    c->store = qihse_kv_store_create_user(op);
    assert(c->store);
    qihse_kv_store_set_replication_principal_id(c->store, qihse_user_get_id(peer));
native_reopened:
    if (recover) {
        /* All files were checked before native open. Startup legitimately
         * republishes lane metadata with SOURCE admission disarmed; the fence
         * descriptor and INTENT-only journal must still be byte-identical. */
        for (unsigned i = 1u; i < 3u; ++i) {
            char path[512]; struct stat st; unsigned char digest[32];
            int n = snprintf(path, sizeof path, "%s/%s", directory, zero_cut_native_files[i]);
            assert(n > 0 && (size_t)n < sizeof path);
            assert(lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
                st.st_dev == g->file_dev[i] && st.st_ino == g->file_ino[i]);
            journal_digest(path, digest);
            assert(!memcmp(digest, g->file_digest[i], sizeof digest));
        }
        for (unsigned i = 0; i < 2u; ++i) {
            assert(qihse_kv_ct_lane_status(c->store, op, lanes[i], &g->after_lane));
            assert(g->after_lane.mode == QIHSE_KV_CT_LANE_SOURCE &&
                !g->after_lane.admitted && g->lanes[i].admitted);
            g->after_lane.admitted = g->lanes[i].admitted;
            assert(!memcmp(&g->after_lane, &g->lanes[i], sizeof g->after_lane));
            uint16_t owner, peer_index; qihse_cluster_slot_state_t state; uint64_t epoch;
            assert(qihse_cluster_topology_get_slot(c->topology, slots[i],
                &owner, &state, &peer_index));
            assert(qihse_cluster_topology_get_slot_epoch(c->topology, slots[i], &epoch));
            assert(owner == g->owner[i] && state == g->slot_state[i] &&
                peer_index == g->peer_index[i] && epoch == g->epoch[i]);
        }
    }
    assert(qihse_kv_ct_lane_transfer_status(c->store, op, &g->after) &&
        !memcmp(&g->before, &g->after, sizeof g->before));
    assert(qihse_cluster_ownership_journal_replay_txn(directory, zero_cut_latest,
        &g->latest, &unresolved) == 1 && unresolved);
    assert(g->latest.phase == QIHSE_OWNERSHIP_INTENT && g->latest.source_lsn == 0u);
    /* Admission is runtime state: explicitly reconcile both SOURCE lanes. */
    for (unsigned i = 0; i < 2u; ++i) {
        assert(qihse_kv_ct_lane_status(c->store, op, lanes[i], &g->after_lane));
        assert(qihse_kv_ct_lane_source_reconcile_peer(c->store, op, peer, lanes[i],
            successors[i], generations[i], g->after_lane.baseline_digest,
            g->after_lane.durable_position));
        assert(qihse_kv_ct_lane_owner_token_get(c->store, op, lanes[i], tokens[i]));
    }
    unsigned abort_calls = a->abort_calls;
    char error[256] = {0};
    for (unsigned replay = 0; replay < 2u; ++replay) {
        unresolved = false;
        if (!replay) {
            assert(qihse_cluster_ownership_replay_control(c, &unresolved, error, sizeof error));
        } else {
            assert(!qihse_cluster_ownership_replay(c, &unresolved, error, sizeof error));
            assert(error[0]);
        }
        assert(unresolved && a->abort_calls == abort_calls && a->decisions[3].phase == 0u);
        assert(qihse_kv_ct_lane_transfer_status(c->store, op, &g->after) &&
            !memcmp(&g->before, &g->after, sizeof g->before));
        assert(qihse_kv_change_seq(c->store) == rows);
        assert(qihse_cluster_ownership_journal_replay_txn(directory, zero_cut_latest,
            &g->latest, &unresolved) == 2 && unresolved);
        assert(g->latest.phase == QIHSE_OWNERSHIP_PREPARED && g->latest.source_lsn == 0u &&
            !strcmp(g->latest.transfer_id, a->decisions[3].claim.transfer_id) &&
            !strcmp(g->latest.lane_id, LANE_A) && !strcmp(g->latest.generation, GEN_A) &&
            !memcmp(g->latest.slot_bitmap, a->decisions[3].claim.slots, sizeof g->latest.slot_bitmap));
        for (unsigned i = 0; i < 2u; ++i) {
            memset(&g->after_lane, 0, sizeof g->after_lane);
            assert(qihse_kv_ct_lane_status(c->store, op, lanes[i], &g->after_lane) &&
                !memcmp(&g->lanes[i], &g->after_lane, sizeof g->after_lane));
        }
    }
    char journal[512]; unsigned char before_digest[32], after_digest[32];
    int n = snprintf(journal, sizeof journal, "%s/slot-ownership.journal", directory);
    assert(n > 0 && (size_t)n < sizeof journal);
    journal_digest(journal, before_digest);
    g->prepared = g->latest;
    qihse_kv_ct_writer_scope_t* scope = NULL;
    for (unsigned rejected = 0; rejected < 2u; ++rejected) {
        if (!rejected) {
            /* A valid admitted SOURCE capability must still obey the live fence. */
            assert(qihse_kv_ct_writer_scope_enter_lane(c->store, op, LANE_A, token_a, &scope));
            assert(!qihse_kv_set_user(c->store, key, "fenced write must fail", 4, 1, op));
        } else {
            c->principal = low;
            assert(!qihse_cluster_ownership_transfer_abort(c, g->latest.transfer_id,
                indices[0], indices[1], error, sizeof error));
            c->principal = op;
        }
        assert(a->abort_calls == abort_calls && a->decisions[3].phase == 0u);
        memset(&g->after, 0, sizeof g->after);
        assert(qihse_kv_ct_lane_transfer_status(c->store, op, &g->after) &&
            !memcmp(&g->before, &g->after, sizeof g->before));
        assert(qihse_kv_change_seq(c->store) == rows);
        journal_digest(journal, after_digest);
        assert(!memcmp(before_digest, after_digest, sizeof before_digest));
        assert(qihse_cluster_ownership_journal_replay_txn(directory, zero_cut_latest,
            &g->latest, &unresolved) == 2 && unresolved);
        assert(g->latest.phase == QIHSE_OWNERSHIP_PREPARED && g->latest.source_lsn == 0u &&
            !memcmp(&g->prepared, &g->latest, sizeof g->latest));
        for (unsigned i = 0; i < 2u; ++i) {
            memset(&g->after_lane, 0, sizeof g->after_lane);
            assert(qihse_kv_ct_lane_status(c->store, op, lanes[i], &g->after_lane) &&
                !memcmp(&g->lanes[i], &g->after_lane, sizeof g->after_lane));
            uint16_t owner, peer_index; qihse_cluster_slot_state_t state; uint64_t epoch;
            assert(qihse_cluster_topology_get_slot(c->topology, slots[i], &owner, &state, &peer_index));
            assert(qihse_cluster_topology_get_slot_epoch(c->topology, slots[i], &epoch));
            assert(owner == g->owner[i] && state == g->slot_state[i] &&
                peer_index == g->peer_index[i] && epoch == g->epoch[i]);
        }
        if (!rejected) qihse_kv_ct_writer_scope_leave(scope);
    }
    assert(qihse_cluster_ownership_transfer_abort(c, g->latest.transfer_id,
        indices[0], indices[1], error, sizeof error));
    assert(a->abort_calls == abort_calls + 1u && a->decisions[3].phase == 2u);
    assert_active(c->store, op, NULL);
    assert(qihse_kv_change_seq(c->store) == rows);
    assert(qihse_cluster_ownership_journal_replay_txn(directory, zero_cut_latest,
        &g->latest, &unresolved) == 3 && !unresolved);
    assert(g->latest.phase == QIHSE_OWNERSHIP_ABORTED && g->latest.source_lsn == 0u);
    journal_digest(journal, before_digest);
    assert(qihse_cluster_ownership_transfer_abort(c, g->latest.transfer_id,
        indices[0], indices[1], error, sizeof error));
    /* Abort retries and terminal replay recheck the same common decision. */
    assert(a->abort_calls == abort_calls + 2u && a->decisions[3].phase == 2u);
    assert(qihse_cluster_ownership_replay_control(c, &unresolved, error, sizeof error) && !unresolved);
    assert(a->abort_calls == abort_calls + 3u && a->decisions[3].phase == 2u);
    assert_active(c->store, op, NULL);
    journal_digest(journal, after_digest);
    assert(!memcmp(before_digest, after_digest, sizeof before_digest));
    assert(qihse_kv_change_seq(c->store) == rows);
    for (unsigned i = 0; i < 2u; ++i) {
        memset(&g->after_lane, 0, sizeof g->after_lane);
        assert(qihse_kv_ct_lane_status(c->store, op, lanes[i], &g->after_lane) &&
            !memcmp(&g->lanes[i], &g->after_lane, sizeof g->after_lane));
    }
    scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(c->store, op, LANE_A, token_a, &scope));
    assert(qihse_kv_set_user(c->store, key, "zero-cut classified progress", 4, 1, op));
    qihse_kv_ct_writer_scope_leave(scope);
    assert(qihse_kv_ct_lane_source_ack(c->store, peer, LANE_A, "qkp-c", GEN_A, 1u));
    char* value = qihse_kv_get_user(c->store, key, op);
    assert(value && !strcmp(value, "zero-cut classified progress"));
    free(value);
    assert(!qihse_kv_get_user(c->store, key, low));
    rows = qihse_kv_change_seq(c->store);
    assert(rows == 1u);
    assert(qihse_kv_ct_lane_status(c->store, op, LANE_A, &g->lanes[0]));
    assert(g->lanes[0].admitted && g->lanes[0].durable_position == 1u &&
        g->lanes[0].acknowledged_position == 1u);
    /* A distinct authenticated reservation reuses the released native fence. */
    init_decision(a, 2, "lane-zero-cut-classified-retry", 100, 1u);
    assert(strcmp(a->decisions[2].claim.transfer_id, a->decisions[3].claim.transfer_id) &&
        a->decisions[2].claim.reserve_index != a->decisions[3].claim.reserve_index);
    g->prepared = txn_for(a, 2, QIHSE_OWNERSHIP_PREPARED, 100);
    fence(c->store, op, a, 2, token_a);
    memset(&g->before, 0, sizeof g->before);
    assert(qihse_kv_ct_lane_transfer_status(c->store, op, &g->before));
    assert(g->before.active && g->before.phase == 1u && g->before.source_fenced &&
        g->before.source_cut == 1u && g->before.claim.source_cut == 1u &&
        !memcmp(&g->before.claim, &a->decisions[2].claim, sizeof g->before.claim));
    assert(qihse_cluster_ownership_journal_append_txn(directory, &g->prepared) == 0);
    assert(qihse_cluster_ownership_transfer_get_prepared(c, g->prepared.transfer_id,
        &g->latest, error, sizeof error) &&
        !memcmp(&g->prepared, &g->latest, sizeof g->latest));
    assert(qihse_cluster_ownership_journal_replay_txn(directory, NULL, NULL,
        &unresolved) == 4 && unresolved);
    journal_digest(journal, before_digest);
    scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(c->store, op, LANE_A, token_a, &scope));
    assert(!qihse_kv_set_user(c->store, key, "retry must preserve classified row", 4, 1, op));
    qihse_kv_ct_writer_scope_leave(scope);
    memset(&g->after, 0, sizeof g->after);
    assert(qihse_kv_ct_lane_transfer_status(c->store, op, &g->after) &&
        !memcmp(&g->before, &g->after, sizeof g->before));
    assert(qihse_kv_change_seq(c->store) == rows);
    journal_digest(journal, after_digest);
    assert(!memcmp(before_digest, after_digest, sizeof before_digest));
    assert(a->abort_calls == abort_calls + 3u && a->decisions[2].phase == 0u &&
        a->decisions[3].phase == 2u);
    assert(qihse_cluster_ownership_transfer_abort(c, g->prepared.transfer_id,
        indices[0], indices[1], error, sizeof error));
    assert(a->abort_calls == abort_calls + 4u && a->decisions[2].phase == 2u &&
        a->decisions[3].phase == 2u);
    assert_active(c->store, op, NULL);
    assert(qihse_cluster_ownership_transfer_get_aborted(c, g->prepared.transfer_id,
        &g->latest, error, sizeof error));
    g->prepared.phase = QIHSE_OWNERSHIP_ABORTED;
    assert(!memcmp(&g->prepared, &g->latest, sizeof g->latest));
    assert(qihse_cluster_ownership_journal_replay_txn(directory, NULL, NULL,
        &unresolved) == 5 && !unresolved);
    assert(qihse_kv_change_seq(c->store) == rows);
    /* Inspect the classified payload only after the exact common ABORT releases it. */
    value = qihse_kv_get_user(c->store, key, op);
    assert(value && !strcmp(value, "zero-cut classified progress"));
    free(value);
    assert(!qihse_kv_get_user(c->store, key, low));
    for (unsigned i = 0; i < 2u; ++i) {
        memset(&g->after_lane, 0, sizeof g->after_lane);
        assert(qihse_kv_ct_lane_status(c->store, op, lanes[i], &g->after_lane) &&
            !memcmp(&g->lanes[i], &g->after_lane, sizeof g->after_lane));
    }
    assert(qihse_kv_ct_lane_status(c->store, op, LANE_OTHER, &g->after_lane) &&
        !memcmp(&g->lanes[1], &g->after_lane, sizeof g->after_lane));
    for (unsigned i = 0; i < 2u; ++i) {
        uint16_t owner, peer_index; qihse_cluster_slot_state_t state; uint64_t epoch;
        assert(qihse_cluster_topology_get_slot(c->topology, slots[i], &owner, &state, &peer_index));
        assert(qihse_cluster_topology_get_slot_epoch(c->topology, slots[i], &epoch));
        assert(owner == g->owner[i] && state == g->slot_state[i] &&
            peer_index == g->peer_index[i] && epoch == g->epoch[i]);
    }
    free(key); free(g);
    puts("PASS zero-cut fence: PREPARED0 and low abort preserve fence, common ABORT releases writes, classified retry preserved");
}

static __attribute__((noinline)) void run_zero_cut_case(const char* executable) {
    char directory[] = "./lane_abort_zero_cut_XXXXXX", self[4096];
    assert(mkdtemp(directory) && realpath(executable, self));
    fprintf(stderr, "zero-cut fixture: %s (preserved on failure)\n", directory);
    pid_t child = fork(); assert(child >= 0);
    if (child == 0) {
        alarm(120);
        execl(self, self, "--zero-cut", directory, (char*)NULL);
        _exit(127);
    }
    int status = 0; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
    assert(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    aimem_fixture_cleanup(directory);
}

static __attribute__((noinline)) void run_zero_cut_crash_case(const char* executable) {
    char directory[] = "./lane_abort_zero_cut_crash_XXXXXX", self[4096];
    assert(mkdtemp(directory) && realpath(executable, self));
    fprintf(stderr, "zero-cut SIGKILL fixture: %s (preserved)\n", directory);
    int pipefd[2]; assert(pipe(pipefd) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (child == 0) {
        assert(close(pipefd[0]) == 0);
        char fd[32];
        int n = snprintf(fd, sizeof fd, "%d", pipefd[1]);
        assert(n > 0 && (size_t)n < sizeof fd);
        execl(self, self, "--zero-cut-crash", directory, fd, (char*)NULL);
        _exit(127);
    }
    assert(close(pipefd[1]) == 0);
    static const char expected[] =
        "SOURCE_FENCED_PHASE1_INTENT0 lane-zero-cut-fenced-intent\n";
    char witness[sizeof expected]; size_t used = 0u;
    for (;;) {
        assert(used < sizeof witness);
        ssize_t n = read(pipefd[0], witness + used, sizeof witness - used);
        if (n < 0 && errno == EINTR) continue;
        assert(n >= 0);
        if (!n) break;
        used += (size_t)n;
    }
    assert(close(pipefd[0]) == 0);
    int status = 0; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    assert(waited == child);
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM)
        fprintf(stderr, "FAIL zero-cut crash watchdog expired: %s\n", directory);
    assert(used == sizeof expected - 1u &&
        !memcmp(witness, expected, sizeof expected - 1u));
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    char path[512];
    int n = snprintf(path, sizeof path, "%s/zero-cut-crash.witness", directory);
    assert(n > 0 && (size_t)n < sizeof path);
    FILE* report = fopen(path, "wx"); assert(report);
    assert(fwrite(witness, 1u, used, report) == used &&
        fprintf(report, "signal=%d\n", WTERMSIG(status)) > 0 &&
        fflush(report) == 0 && fsync(fileno(report)) == 0 && fclose(report) == 0);
    child = fork(); assert(child >= 0);
    if (child == 0) {
        execl(self, self, "--zero-cut-recover", directory, (char*)NULL);
        _exit(127);
    }
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    assert(waited == child);
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM)
        fprintf(stderr, "FAIL zero-cut recovery watchdog expired: %s\n", directory);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("PASS witnessed SIGKILL/fresh-exec zero-cut SOURCE fence recovery");
}

int main(int argc, char** argv) {
    if (argc == 3 && !strcmp(argv[1], "--target")) return target_case(argv[2], false, false, STAGE_FAULT_NONE);
    if (argc == 3 && !strcmp(argv[1], "--successor")) return target_case(argv[2], true, false, STAGE_FAULT_NONE);
    if (argc == 3 && !strcmp(argv[1], "--staging")) return target_case(argv[2], false, true, STAGE_FAULT_NONE);
    if (argc == 3 && !strcmp(argv[1], "--staging-meta-before"))
        return target_case(argv[2], false, true, STAGE_FAULT_META_BEFORE);
    if (argc == 3 && !strcmp(argv[1], "--staging-meta-after"))
        return target_case(argv[2], false, true, STAGE_FAULT_META_AFTER);
    if (argc == 3 && !strcmp(argv[1], "--staging-unlink"))
        return target_case(argv[2], false, true, STAGE_FAULT_UNLINK);
    bool zero_crash = argc == 4 && !strcmp(argv[1], "--zero-cut-crash");
    bool zero_recover = argc == 3 && !strcmp(argv[1], "--zero-cut-recover");
    bool zero_cut = (argc == 3 && !strcmp(argv[1], "--zero-cut")) ||
        zero_crash || zero_recover;
    assert(argc == 1 || zero_cut);
    int witness_fd = -1;
    if (zero_crash) {
        char* end = NULL; errno = 0;
        long fd = strtol(argv[3], &end, 10);
        assert(!errno && end != argv[3] && !*end && fd >= 3 && fd <= INT_MAX);
        witness_fd = (int)fd;
    }
    if (zero_cut) {
        assert(signal(SIGALRM, SIG_DFL) != SIG_ERR);
        sigset_t unblocked;
        assert(sigemptyset(&unblocked) == 0 && sigaddset(&unblocked, SIGALRM) == 0);
        assert(sigprocmask(SIG_UNBLOCK, &unblocked, NULL) == 0);
        alarm(120);
    }
    umask(0077);
    if (!zero_cut) {
        run_zero_cut_case(argv[0]);
        run_zero_cut_crash_case(argv[0]);
    }
    char source_root[] = "./lane_abort_source_XXXXXX";
    const char* source_dir = zero_cut ? argv[2] : source_root;
    char target_dir[] = "./lane_abort_target_XXXXXX";
    char successor_dir[] = "./lane_abort_successor_XXXXXX";
    if (!zero_cut)
        assert(mkdtemp(source_root) && mkdtemp(target_dir) && mkdtemp(successor_dir));
    assert(setenv("QIHSE_DATA_DIR", source_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator("LaneAbortOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0, "LaneAbortOperator1!");
    qihse_user_t* peer = qihse_auth_create_user(op, 8911, QIHSE_ROLE_ANALYST,
        5, 1, "LaneAbortPeer1!", false);
    qihse_user_t* low = qihse_auth_create_user(op, 8912, QIHSE_ROLE_ANALYST,
        0, 0, "LaneAbortLow1!", false);
    assert(op && peer && low);
    authority_t authority = {0};
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology);
    uint16_t indices[3];
    for (size_t i = 0; i < 3; ++i) {
        qihse_cluster_node_t node = {0};
        char name[32]; snprintf(name, sizeof(name), "lane-abort-node-%zu", i);
        qihse_cluster_node_id_from_seed(name, strlen(name), node.id);
        snprintf(authority.nodes[i], sizeof(authority.nodes[i]), "%s", node.id);
        snprintf(node.host, sizeof(node.host), "127.0.0.1");
        node.port = (uint16_t)(7900 + i); node.bus_port = (uint16_t)(17900 + i);
        node.role = QIHSE_CLUSTER_NODE_PRIMARY; node.healthy = true;
        node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        assert(qihse_cluster_topology_upsert_node(topology, &node, &indices[i]));
    }
    assert(qihse_cluster_topology_set_local_node(topology, indices[0]));
    assert(qihse_cluster_topology_adopt_range(topology, 100, 100, indices[0], 1));
    if (zero_recover) {
        zero_cut_expect_t* expected = zero_cut_expectation(source_dir, op, true);
        free(expected);
    }
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    unsigned char token_a[32], token_other[32];
    if (!zero_recover) {
        source_lane(store, op, peer, LANE_A, GEN_A, "qkp-a", "qkp-c", 100, token_a);
        source_lane(store, op, peer, LANE_OTHER, GEN_OTHER, "qkp-a", "qkp-d", 9000, token_other);
    }
    qihse_cluster_ownership_context_t c = {.topology = topology, .store = store,
        .principal = op, .data_principal = op, .peer_id = peer_id,
        .peer_id_context = &authority, .range_reserve = range_reserve,
        .range_check_reserved = range_check, .range_finalize = range_final,
        .range_check_finalized = range_check, .range_abort = range_abort,
        .lane_claim = claim_get, .lane_verify_claim = verify_claim,
        .lane_verify_aborted = verify_aborted, .range_authority_context = &authority};
    if (zero_cut) {
        zero_cut_case(&c, peer, low, indices, token_a, token_other,
            zero_recover, witness_fd);
        qihse_kv_store_destroy(c.store);
        qihse_cluster_topology_destroy(topology);
        qihse_auth_release_principal_scoped(low);
        qihse_auth_release_principal_scoped(peer);
        qihse_auth_release_principal_scoped(op);
        return 0;
    }
    char* protected_key = key_at_slot(100);
    char* unrelated_key = key_at_slot(9000);
    assert(protected_key && unrelated_key);
    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_a, &scope));
    assert(qihse_kv_set_user(store, protected_key, "classified", 4, 1, op));
    qihse_kv_ct_writer_scope_leave(scope);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A, "qkp-c", GEN_A, 1));
    assert(!qihse_kv_get_user(store, protected_key, low));
    init_decision(&authority, 0, "lane-abort-1", 100, 1);
    fence(store, op, &authority, 0, token_a);
    qihse_cluster_ownership_txn_t t = txn_for(&authority, 0, QIHSE_OWNERSHIP_PREPARED, 100);
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_OTHER, token_other, &scope));
    assert(qihse_kv_set_user(store, unrelated_key, "unrelated remains usable", 0, 0, op));
    qihse_kv_ct_writer_scope_leave(scope);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_OTHER, "qkp-d", GEN_OTHER, 1u));
    foreign_intent_guard(&c, indices, protected_key, unrelated_key);
    assert(qihse_cluster_ownership_journal_append_txn(source_dir, &t) == 0);
    char error[256];
    c.principal = low;
    assert(!qihse_cluster_ownership_transfer_abort(&c, t.transfer_id, indices[0], indices[1], error, sizeof(error)));
    c.principal = op; authority.fail_abort = true;
    assert(!qihse_cluster_ownership_transfer_abort(&c, t.transfer_id, indices[0], indices[1], error, sizeof(error)));
    assert_active(store, op, t.transfer_id);
    authority.fail_abort = false; authority.hide_abort = true;
    assert(!qihse_cluster_ownership_transfer_abort(&c, t.transfer_id, indices[0], indices[1], error, sizeof(error)));
    assert(authority.decisions[0].phase == 2);
    assert_active(store, op, t.transfer_id);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op); assert(store); c.store = store;
    authority.hide_abort = false;
    bool unresolved = true;
    assert(qihse_cluster_ownership_replay_control(&c, &unresolved, error, sizeof(error)) && !unresolved);
    assert_active(store, op, NULL);
    assert(qihse_cluster_ownership_transfer_abort(&c, t.transfer_id, indices[0], indices[1], error, sizeof(error)));

    /* A historical abort receipt cannot release the next operation's fence. */
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    qihse_kv_ct_lane_status_t status;
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status));
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_A,
        "qkp-c", GEN_A, status.baseline_digest, status.durable_position));
    assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_A, token_a));
    init_decision(&authority, 1, "lane-abort-2", 100, 1);
    fence(store, op, &authority, 1, token_a);
    qihse_cluster_ownership_txn_t t2 = txn_for(&authority, 1, QIHSE_OWNERSHIP_PREPARED, 100);
    assert(qihse_cluster_ownership_journal_append_txn(source_dir, &t2) == 0);
    t.phase = QIHSE_OWNERSHIP_ABORTED;
    unsigned char checksum[32];
    assert(qihse_cluster_ownership_source_phase_receipt(&c, "ABORTED", &t, checksum, error, sizeof(error)));
    assert_active(store, op, t2.transfer_id);
    assert(qihse_cluster_ownership_replay_control(&c, &unresolved, error, sizeof(error)) && unresolved);
    assert_active(store, op, t2.transfer_id);
    assert(qihse_cluster_ownership_transfer_abort(&c, t2.transfer_id, indices[0], indices[1], error, sizeof(error)));
    assert_active(store, op, NULL);

    /* The pre-fence INTENT crash window closes through the same common ABORT. */
    init_decision(&authority, 2, "lane-unfenced-intent", 100, 0);
    qihse_cluster_ownership_txn_t intent = txn_for(&authority, 2, QIHSE_OWNERSHIP_INTENT, 100);
    assert(qihse_cluster_ownership_journal_append_txn(source_dir, &intent) == 0);
    assert(qihse_cluster_ownership_replay_control(&c, &unresolved, error, sizeof(error)) && !unresolved);
    assert(authority.decisions[2].phase == 2);
    intent.phase = QIHSE_OWNERSHIP_ABORTED;
    intent.lane_id[0] = '\0'; /* Actual source-phase wire has no lane field. */
    memset(intent.slot_bitmap, 0, sizeof(intent.slot_bitmap));
    assert(qihse_cluster_ownership_source_phase_receipt(&c, "ABORTED", &intent,
        checksum, error, sizeof(error)));
    qihse_kv_store_destroy(store);

    char self[4096]; assert(realpath(argv[0], self));
    pid_t child = fork(); assert(child >= 0);
    if (child == 0) {
        execl(self, self, "--target", target_dir, (char*)NULL);
        _exit(127);
    }
    int child_status = 0;
    assert(waitpid(child, &child_status, 0) == child);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    child = fork(); assert(child >= 0);
    if (child == 0) {
        execl(self, self, "--successor", successor_dir, (char*)NULL);
        _exit(127);
    }
    assert(waitpid(child, &child_status, 0) == child);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    const char* stages[] = {"--staging", "--staging-meta-before",
        "--staging-meta-after", "--staging-unlink"};
    for (size_t i = 0; i < sizeof stages / sizeof stages[0]; ++i) {
        char staging_dir[] = "./lane_abort_staging_XXXXXX";
        assert(mkdtemp(staging_dir));
        fprintf(stderr, "staging fixture: %s mode=%s (preserved)\n", staging_dir, stages[i]);
        child = fork(); assert(child >= 0);
        if (child == 0) {
            execl(self, self, stages[i], staging_dir, (char*)NULL);
            _exit(127);
        }
        pid_t waited;
        do { waited = waitpid(child, &child_status, 0); } while (waited < 0 && errno == EINTR);
        assert(waited == child && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }
    qihse_cluster_topology_destroy(topology);
    qihse_auth_release_principal_scoped(low);
    qihse_auth_release_principal_scoped(peer);
    qihse_auth_release_principal_scoped(op);
    free(protected_key); free(unrelated_key);
    aimem_fixture_cleanup(source_dir); aimem_fixture_cleanup(target_dir);
    aimem_fixture_cleanup(successor_dir);
    puts("PASS lane abort: typed decisions, crash retry, later-fence isolation and staged target recovery");
    return 0;
}
