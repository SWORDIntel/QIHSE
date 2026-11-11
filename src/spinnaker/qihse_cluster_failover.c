#include "qihse_cluster_failover.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_maintenance.h"
#include "qihse_cluster_ownership.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_platform.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t fo_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

#ifndef _WIN32
#include <pthread.h>
#endif

#define FO_FAILBACK_STABLE_MS_DEFAULT 3000u
#define FO_FAILBACK_POLL_MS_DEFAULT 1000u
#define FO_LEDGER_MAX 1024u

/* One range this node took over through the sharded fallback and still owes
 * back to its original owner. */
typedef struct {
    uint16_t failed_index;
    uint16_t start, end;
    uint32_t attempts;
    uint64_t healthy_since_ms;   /* 0 = owner not currently healthy */
    uint64_t next_attempt_ms;
    bool done;
} fo_ledger_entry_t;

struct qihse_cluster_failover {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    qihse_cluster_maintenance_t* maintenance_gate; /* borrowed */
    qihse_kv_store_t* ct_store; /* borrowed */
    qihse_user_t* ct_principal; /* borrowed */
    char ct_lane_id[65];
    char ct_local_qkp_id[QIHSE_QKP_NODE_ID_LEN + 1u];
    qihse_cluster_topology_qkp_id_fn topology_qkp_id;
    void* topology_qkp_id_context;
    qihse_cluster_ct_election_authorized_fn ct_election_authorized;
    void* ct_election_context;
    char ct_auto_successor_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_ct_complete_fn ct_complete;
    void* ct_complete_context;
    uint16_t ct_pending_successor;
    char ct_pending_generation[33];
    uint16_t local_node_index;
    bool single_coordinator;
    bool startup_paused;
    bool activity_started;
    uint64_t failover_events;
    uint64_t last_attempt_ms;
    pthread_mutex_t lock;

    /* Failback. ledger_lock is a LEAF lock (never held across a call out), so
     * it cannot invert against `lock` or the bus lock. */
    qihse_cluster_failback_fn failback_fn;
    void* failback_user;
    uint32_t stable_ms;
    uint32_t poll_ms;
    pthread_mutex_t ledger_lock;
    fo_ledger_entry_t* ledger;
    size_t ledger_count;
    size_t ledger_capacity;
    uint64_t failbacks;
    pthread_t worker;
    bool worker_started;
    int stop;
};

static void* fo_failback_main(void* arg);

typedef struct {
    const char* lane_id;
    bool found;
    qihse_cluster_ownership_txn_t txn;
} fo_lane_journal_scan_t;

static bool fo_lane_journal_scan(const qihse_cluster_ownership_txn_t* txn,
                                void* opaque) {
    fo_lane_journal_scan_t* scan = opaque;
    if (!txn || !scan || !scan->lane_id) return false;
    if (txn->next_generation[0] && !strcmp(txn->lane_id, scan->lane_id)) {
        scan->txn = *txn;
        scan->found = true;
    }
    return true;
}

typedef struct {
    qihse_cluster_ownership_context_t* ownership;
    qihse_user_t* principal;
} fo_lane_verify_context_t;

static bool fo_lane_verify_adapter(void* opaque,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool require_final) {
    fo_lane_verify_context_t* context = opaque;
    qihse_cluster_ownership_context_t* ownership = context ? context->ownership : NULL;
    return ownership && ownership->lane_verify_claim &&
        ownership->lane_verify_claim(ownership->range_authority_context,
            context->principal, claim, require_final);
}

static bool fo_find_qkp_node(qihse_cluster_ownership_context_t* ownership,
    const char* qkp_id, uint16_t* out_index, qihse_cluster_node_t* out_node) {
    if (!ownership || !ownership->topology || !ownership->peer_id ||
        !qkp_id || !*qkp_id || !out_index || !out_node) return false;
    qihse_cluster_node_t* nodes = calloc(QIHSE_CLUSTER_MAX_NODES, sizeof(*nodes));
    if (!nodes) return false;
    size_t count = qihse_cluster_topology_nodes(ownership->topology, nodes,
        QIHSE_CLUSTER_MAX_NODES);
    uint16_t found = QIHSE_CLUSTER_NODE_NONE;
    bool duplicate = false;
    char mapped[QIHSE_KV_CT_ID_MAX + 1u];
    for (size_t i = 0; i < count; ++i) {
        memset(mapped, 0, sizeof(mapped));
        if (ownership->peer_id(ownership->peer_id_context, nodes[i].id, mapped) &&
            strcmp(mapped, qkp_id) == 0) {
            if (found != QIHSE_CLUSTER_NODE_NONE) { duplicate = true; break; }
            found = (uint16_t)i;
            *out_node = nodes[i];
        }
    }
    free(nodes);
    if (duplicate || found == QIHSE_CLUSTER_NODE_NONE) return false;
    *out_index = found;
    return true;
}

static bool fo_lane_random_hex(char out[33]) {
    uint8_t random[16];
    static const char hex[] = "0123456789abcdef";
    if (RAND_bytes(random, sizeof(random)) != 1) return false;
    for (size_t i = 0; i < sizeof(random); ++i) {
        out[2u * i] = hex[random[i] >> 4];
        out[2u * i + 1u] = hex[random[i] & 15u];
    }
    out[32] = '\0';
    OPENSSL_cleanse(random, sizeof(random));
    return true;
}

static bool fo_lane_audit_digest(const qihse_cluster_ownership_txn_t* txn,
    const char* successor_qkp, uint8_t out[32]) {
    char lsn[32];
    snprintf(lsn, sizeof(lsn), "%llu", (unsigned long long)txn->source_lsn);
    const char* fields[] = {txn->source_id, txn->target_id, txn->source_qkp_id,
        txn->target_qkp_id, txn->owner_id, successor_qkp,
        txn->generation, txn->next_generation, lsn};
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    unsigned int n = 0;
    bool ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1;
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); ++i)
        ok = EVP_DigestUpdate(md, fields[i], strlen(fields[i])) == 1;
    if (ok) ok = EVP_DigestFinal_ex(md, out, &n) == 1 && n == 32u;
    EVP_MD_CTX_free(md);
    return ok;
}

static bool fo_lane_make_update(qihse_cluster_ownership_context_t* ownership,
    const qihse_cluster_ownership_txn_t* txn, const char* successor_qkp,
    qihse_cluster_bus_ct1_promotion_update_v2_t* update) {
    if (!ownership || !txn || !update || !txn->lane_id[0] ||
        !txn->next_generation[0]) return false;
    memset(update, 0, sizeof(*update));
    update->magic = QIHSE_CLUSTER_BUS_CT1_PROMOTION_V2_MAGIC;
    update->target_cursor = txn->target_lsn;
    update->base.magic = QIHSE_CLUSTER_BUS_CT1_PROMOTION_MAGIC;
    update->base.start = txn->start;
    update->base.end = txn->end;
    update->base.config_epoch = txn->config_epoch;
    update->base.durable_cursor = txn->source_lsn;
    snprintf(update->base.transfer_id, sizeof(update->base.transfer_id), "%s", txn->transfer_id);
    snprintf(update->base.source_id, sizeof(update->base.source_id), "%s", txn->source_id);
    snprintf(update->base.target_id, sizeof(update->base.target_id), "%s", txn->target_id);
    snprintf(update->base.successor_id, sizeof(update->base.successor_id), "%s", txn->owner_id);
    snprintf(update->base.source_qkp_id, sizeof(update->base.source_qkp_id), "%s", txn->source_qkp_id);
    snprintf(update->base.target_qkp_id, sizeof(update->base.target_qkp_id), "%s", txn->target_qkp_id);
    snprintf(update->base.successor_qkp_id, sizeof(update->base.successor_qkp_id), "%s", successor_qkp);
    snprintf(update->base.generation, sizeof(update->base.generation), "%s", txn->generation);
    snprintf(update->base.next_generation, sizeof(update->base.next_generation), "%s", txn->next_generation);
    memcpy(update->base.slot_bitmap, txn->slot_bitmap, sizeof(update->base.slot_bitmap));
    memcpy(update->base.promotion_digest, txn->proof_digest, sizeof(update->base.promotion_digest));
    snprintf(update->lane_id, sizeof(update->lane_id), "%s", txn->lane_id);
    return qihse_cluster_bus_ct1_promotion_seal(&update->base) &&
        qihse_cluster_bus_ct1_promotion_v2_seal(update);
}

static bool fo_lane_find_certificate(qihse_cluster_ownership_context_t* ownership,
    const char* lane_id, const uint8_t event_digest[32], uint8_t** out_envelope,
    size_t* out_len, uint8_t out_digest[32]) {
    if (out_envelope) *out_envelope = NULL;
    if (out_len) *out_len = 0;
    if (out_digest) memset(out_digest, 0, 32u);
    if (!ownership || !ownership->store || !ownership->data_principal ||
        !ownership->bus || !lane_id || !event_digest || !out_envelope ||
        !out_len || !out_digest) return false;
    uint8_t* page = malloc(8192u);
    if (!page) return false;
    uint8_t after[32] = {0};
    bool found = false;
    while (!found) {
        size_t length = 0;
        uint8_t last[32] = {0};
        bool more = false;
        if (!qihse_kv_ct_lane_certificate_page(ownership->store,
                ownership->data_principal, lane_id, after, page, 8192u,
                &length, last, &more)) break;
        size_t off = 0;
        while (off < length) {
            if (length - off < 36u) { off = length + 1u; break; }
            uint32_t n = ((uint32_t)page[off] << 24) |
                ((uint32_t)page[off + 1u] << 16) |
                ((uint32_t)page[off + 2u] << 8) | page[off + 3u];
            const uint8_t* digest = page + off + 4u;
            const uint8_t* envelope = page + off + 36u;
            if (!n || n > QIHSE_CLUSTER_BUS_CT1_CERTIFICATE_MAX ||
                n > length - off - 36u) { off = length + 1u; break; }
            qihse_cluster_bus_ct1_promotion_update_v2_t candidate;
            qihse_uuid_t signer;
            memset(&candidate, 0, sizeof(candidate));
            memset(&signer, 0, sizeof(signer));
            bool valid = qihse_cluster_bus_ct1_certificate_verify(ownership->bus,
                envelope, n, &candidate, &signer) &&
                CRYPTO_memcmp(candidate.event_digest, event_digest, 32u) == 0 &&
                strcmp(candidate.lane_id, lane_id) == 0;
            OPENSSL_cleanse(&candidate, sizeof(candidate));
            OPENSSL_cleanse(&signer, sizeof(signer));
            if (valid) {
                uint8_t* saved = malloc(n);
                if (saved) {
                    memcpy(saved, envelope, n);
                    memcpy(out_digest, digest, 32u);
                    *out_envelope = saved;
                    *out_len = n;
                    found = true;
                }
                break;
            }
            off += 36u + n;
        }
        if (!more || found || off > length) break;
        if (CRYPTO_memcmp(last, after, 32u) == 0) break;
        memcpy(after, last, sizeof(after));
    }
    OPENSSL_cleanse(page, 8192u);
    free(page);
    OPENSSL_cleanse(after, sizeof(after));
    return found;
}

static qihse_cluster_failover_t* fo_create(const qihse_cluster_failover_config_t* config,
                                            bool paused) {
    if (!config || !config->topology) return NULL;
    if (strnlen(config->ct_local_qkp_id, sizeof(config->ct_local_qkp_id)) >=
        sizeof(config->ct_local_qkp_id)) return NULL;
    size_t lane_len = strnlen(config->ct_lane_id, sizeof(config->ct_lane_id));
    if (lane_len >= sizeof(config->ct_lane_id) || (lane_len && lane_len != 64u)) return NULL;
    for (size_t i = 0; i < lane_len; ++i)
        if (!((config->ct_lane_id[i] >= '0' && config->ct_lane_id[i] <= '9') ||
              (config->ct_lane_id[i] >= 'a' && config->ct_lane_id[i] <= 'f'))) return NULL;
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)calloc(1, sizeof(*fo));
    if (!fo) return NULL;
    fo->startup_paused = paused;
    fo->topology = config->topology;
    fo->bus = config->bus;
    fo->maintenance_gate = config->maintenance_gate;
    fo->ct_store = config->ct_store;
    fo->ct_principal = config->ct_principal;
    memcpy(fo->ct_lane_id, config->ct_lane_id,
           strnlen(config->ct_lane_id, sizeof(config->ct_lane_id)) + 1u);
    memcpy(fo->ct_local_qkp_id, config->ct_local_qkp_id,
           strnlen(config->ct_local_qkp_id, sizeof(config->ct_local_qkp_id)) + 1u);
    fo->topology_qkp_id = config->topology_qkp_id;
    fo->topology_qkp_id_context = config->topology_qkp_id_context;
    fo->ct_election_authorized = config->ct_election_authorized;
    fo->ct_election_context = config->ct_election_context;
    if (config->ct_auto_successor_id) {
        if (!config->ct_complete || !config->ct_election_authorized ||
            !config->ct_store || !config->ct_principal ||
            !*config->ct_auto_successor_id ||
            strlen(config->ct_auto_successor_id) > QIHSE_CLUSTER_NODE_ID_LEN) {
            free(fo); return NULL;
        }
        snprintf(fo->ct_auto_successor_id, sizeof(fo->ct_auto_successor_id),
                 "%s", config->ct_auto_successor_id);
    }
    fo->ct_complete = config->ct_complete;
    fo->ct_complete_context = config->ct_complete_context;
    fo->local_node_index = config->local_node_index;
    fo->single_coordinator = config->single_coordinator;
    fo->failback_fn = config->failback_fn;
    fo->failback_user = config->failback_user_data;
    fo->stable_ms = config->failback_stable_ms ? config->failback_stable_ms
                                               : FO_FAILBACK_STABLE_MS_DEFAULT;
    fo->poll_ms = config->failback_poll_ms ? config->failback_poll_ms
                                           : FO_FAILBACK_POLL_MS_DEFAULT;
    if (pthread_mutex_init(&fo->lock, NULL) != 0) {
        free(fo);
        return NULL;
    }
    if (pthread_mutex_init(&fo->ledger_lock, NULL) != 0) {
        pthread_mutex_destroy(&fo->lock);
        free(fo);
        return NULL;
    }
    if (fo->failback_fn || fo->ct_auto_successor_id[0]) {
        fo->ledger = (fo_ledger_entry_t*)calloc(FO_LEDGER_MAX, sizeof(*fo->ledger));
        if (!fo->ledger) {
            pthread_mutex_destroy(&fo->ledger_lock);
            pthread_mutex_destroy(&fo->lock);
            free(fo);
            return NULL;
        }
        fo->ledger_capacity = FO_LEDGER_MAX;
        if (pthread_create(&fo->worker, NULL, fo_failback_main, fo) == 0) {
            fo->worker_started = true;
        } else {
            free(fo->ledger);
            pthread_mutex_destroy(&fo->ledger_lock);
            pthread_mutex_destroy(&fo->lock);
            free(fo);
            return NULL;
        }
    }
    return fo;
}

qihse_cluster_failover_t* qihse_cluster_failover_create(const qihse_cluster_failover_config_t* config) {
    return fo_create(config, false);
}

qihse_cluster_failover_t* qihse_cluster_failover_create_paused(const qihse_cluster_failover_config_t* config) {
    return fo_create(config, true);
}

bool qihse_cluster_failover_pause_startup(qihse_cluster_failover_t* fo) {
    if (!fo) return false;
    pthread_mutex_lock(&fo->lock);
    /* Takeover callbacks run under the bus lock and may only take the leaf
     * ledger lock. Serialize the hold with debt insertion here instead. Once
     * the worker drains debt, activity_started already forbids a late hold. */
    pthread_mutex_lock(&fo->ledger_lock);
    bool ok = !fo->activity_started && fo->ledger_count == 0;
    if (ok) fo->startup_paused = true;
    pthread_mutex_unlock(&fo->ledger_lock);
    pthread_mutex_unlock(&fo->lock);
    return ok;
}

bool qihse_cluster_failover_resume(qihse_cluster_failover_t* fo) {
    if (!fo) return false;
    pthread_mutex_lock(&fo->lock);
    bool changed = fo->startup_paused;
    fo->startup_paused = false;
    fo->activity_started = true;
    pthread_mutex_unlock(&fo->lock);
    return changed;
}

bool qihse_cluster_failover_register_maintenance(qihse_cluster_failover_t* fo) {
    return fo && fo->maintenance_gate &&
        qihse_cluster_maintenance_register(fo->maintenance_gate,
                                            QIHSE_MAINT_WRITER_FAILOVER, true);
}

bool qihse_cluster_failover_is_paused(qihse_cluster_failover_t* fo) {
    if (!fo) return false;
    pthread_mutex_lock(&fo->lock);
    bool paused = fo->startup_paused;
    pthread_mutex_unlock(&fo->lock);
    return paused;
}

void qihse_cluster_failover_destroy(qihse_cluster_failover_t* fo) {
    if (!fo) return;
    if (fo->worker_started) {
        __atomic_store_n(&fo->stop, 1, __ATOMIC_RELEASE);
        pthread_join(fo->worker, NULL);
    }
    free(fo->ledger);
    pthread_mutex_destroy(&fo->ledger_lock);
    pthread_mutex_destroy(&fo->lock);
    free(fo);
}

uint16_t qihse_cluster_failover_best_replica(const qihse_cluster_topology_t* topology,
                                             uint16_t primary_index) {
    if (!topology || primary_index == QIHSE_CLUSTER_NODE_NONE) return QIHSE_CLUSTER_NODE_NONE;
    /* Heap, not a 256-entry array on the stack. At ~150 bytes per node that
     * was 88 KB of frame in a function on the failover path, and this one is
     * PUBLIC and lock-free, so it can be called from anywhere. */
    qihse_cluster_node_t* nodes = (qihse_cluster_node_t*)malloc(
        QIHSE_CLUSTER_MAX_NODES * sizeof(qihse_cluster_node_t));
    if (!nodes) return QIHSE_CLUSTER_NODE_NONE;
    size_t count = qihse_cluster_topology_nodes(topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    uint16_t best = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].role != QIHSE_CLUSTER_NODE_REPLICA) continue;
        if (nodes[i].primary_index != primary_index) continue;
        if (!nodes[i].healthy) continue;
        if (best == QIHSE_CLUSTER_NODE_NONE || nodes[i].index < best) {
            best = nodes[i].index;
        }
    }
    free(nodes);
    return best;
}

/* The coordinator is the lowest-index healthy primary.
 *
 * A helper rather than an inline 256-entry array so the frame stays small and
 * the buffer has ONE exit. handle() has several early returns that unlock the
 * mutex; threading a free through each of them is how a leak gets introduced
 * later by someone adding a sixth. */
static uint16_t fo_find_coordinator(const qihse_cluster_topology_t* topology) {
    if (!topology) return QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_node_t* nodes = (qihse_cluster_node_t*)malloc(
        QIHSE_CLUSTER_MAX_NODES * sizeof(qihse_cluster_node_t));
    if (!nodes) return QIHSE_CLUSTER_NODE_NONE;
    size_t count = qihse_cluster_topology_nodes(topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    uint16_t coordinator = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].role != QIHSE_CLUSTER_NODE_PRIMARY || !nodes[i].healthy) continue;
        if (coordinator == QIHSE_CLUSTER_NODE_NONE || nodes[i].index < coordinator) {
            coordinator = nodes[i].index;
        }
    }
    free(nodes);
    return coordinator;
}

/* Sharded-cluster fallback successor: the healthy PRIMARY with the smallest
 * node ID, excluding the failed node.
 *
 * The choice must be IDENTICAL on every node that observes the failure, or each
 * survivor nominates a different successor and they all claim the range at once.
 * Node IDs are the only cluster-wide stable identity: topology indexes are
 * assigned in each node's own upsert order, and uptime is each node's local
 * observation. An earlier revision ranked by uptime and gave the LOCAL node an
 * unbeatable score, so every survivor chose itself: during a rolling restart
 * the survivors raced conflicting takeovers of the same range. Same
 * single-exit reasoning as fo_find_coordinator. */
static uint16_t fo_pick_fallback_successor(qihse_cluster_failover_t* fo,
                                           uint16_t failed_node_index, uint64_t now) {
    (void)now;
    qihse_cluster_node_t* nodes = (qihse_cluster_node_t*)malloc(
        QIHSE_CLUSTER_MAX_NODES * sizeof(qihse_cluster_node_t));
    if (!nodes) return QIHSE_CLUSTER_NODE_NONE;
    size_t count = qihse_cluster_topology_nodes(fo->topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    size_t best = count; /* index into nodes[], count = none */
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].index == failed_node_index) continue;
        if (nodes[i].role != QIHSE_CLUSTER_NODE_PRIMARY || !nodes[i].healthy) continue;
        if (best == count || strcmp(nodes[i].id, nodes[best].id) < 0) best = i;
    }
    uint16_t chosen = best == count ? QIHSE_CLUSTER_NODE_NONE : nodes[best].index;
    free(nodes);
    return chosen;
}

/* Remember a range this node took over so it can be handed back. */
static void fo_ledger_record(qihse_cluster_failover_t* fo, uint16_t failed,
                             uint16_t start, uint16_t end) {
    pthread_mutex_lock(&fo->ledger_lock);
    for (size_t i = 0; i < fo->ledger_count; i++) {
        fo_ledger_entry_t* e = &fo->ledger[i];
        if (!e->done && e->failed_index == failed && e->start == start && e->end == end) {
            pthread_mutex_unlock(&fo->ledger_lock);
            return;
        }
    }
    if (fo->ledger_count == fo->ledger_capacity) {
        size_t next_capacity = fo->ledger_capacity ? fo->ledger_capacity * 2u : FO_LEDGER_MAX;
        fo_ledger_entry_t* next = (fo_ledger_entry_t*)realloc(
            fo->ledger, next_capacity * sizeof(*next));
        if (next) {
            fo->ledger = next;
            fo->ledger_capacity = next_capacity;
        }
    }
    if (fo->ledger_count < fo->ledger_capacity) {
        fo_ledger_entry_t* e = &fo->ledger[fo->ledger_count++];
        memset(e, 0, sizeof(*e));
        e->failed_index = failed;
        e->start = start;
        e->end = end;
        fprintf(stderr, "qihse-cluster-failback: ledgered slots %u-%u taken over from node %u\n",
                (unsigned)start, (unsigned)end, (unsigned)failed);
    } else {
        fprintf(stderr, "qihse-cluster-failback: CRITICAL: cannot retain failback debt for slots %u-%u from node %u; allocation failed\n",
                (unsigned)start, (unsigned)end, (unsigned)failed);
    }
    pthread_mutex_unlock(&fo->ledger_lock);
}

static bool fo_promote_locked(qihse_cluster_failover_t* fo,
                                    uint16_t failed_primary_index,
                                    uint16_t replica_index) {
    if (!fo || !fo->topology) return false;
    if (failed_primary_index == QIHSE_CLUSTER_NODE_NONE || replica_index == QIHSE_CLUSTER_NODE_NONE) return false;

    qihse_cluster_node_t replica;
    if (!qihse_cluster_topology_get_node(fo->topology, replica_index, &replica)) return false;
    /* Valid successors: a dedicated REPLICA of the failed primary, or (the
     * sharded-cluster fallback) another healthy PRIMARY with the smallest
     * node ID (see fo_pick_fallback_successor). A failed/unhealthy successor
     * is never chosen. */
    if (replica.role != QIHSE_CLUSTER_NODE_REPLICA && replica.role != QIHSE_CLUSTER_NODE_PRIMARY) return false;
    if (!replica.healthy) return false;

    /* CT.1/CT.2: health and replica role do not prove that the successor has
     * a durable, replayed copy of the failed primary's writes. Check BEFORE
     * changing either its role or any slot owner. No pinned durable cursor or
     * data-availability proof is wired into this coordinator yet, so a
     * data-bearing takeover must fail closed. Explicit topology assignment
     * during initialization does not use this failover path. */
    qihse_cluster_slot_range_t* ranges = (qihse_cluster_slot_range_t*)malloc(
        QIHSE_CLUSTER_SLOT_COUNT * sizeof(qihse_cluster_slot_range_t));
    if (!ranges) return false;
    size_t range_count = qihse_cluster_topology_ranges(fo->topology, ranges, QIHSE_CLUSTER_SLOT_COUNT);
    for (size_t i = 0; i < range_count; i++) {
        if (ranges[i].owner_index == failed_primary_index) {
            fprintf(stderr, "qihse-cluster-failover: refusing unproven takeover of slots %u-%u from node %u by node %u\n",
                    (unsigned)ranges[i].start, (unsigned)ranges[i].end,
                    (unsigned)failed_primary_index, (unsigned)replica_index);
            free(ranges);
            return false;
        }
    }
    free(ranges);

    /* With no slot range to inherit, promoting the role cannot redirect data. */
    replica.role = QIHSE_CLUSTER_NODE_PRIMARY;
    replica.primary_index = QIHSE_CLUSTER_NODE_NONE;
    replica.healthy = true;
    if (!qihse_cluster_topology_upsert_node(fo->topology, &replica, NULL))
        return false;

    /* Broadcast the node role update */
    if (fo->bus) qihse_cluster_bus_broadcast_node_update(fo->bus, replica_index);

    return true;
}

static void fo_set_err(char* err, size_t cap, const char* message) {
    if (err && cap) snprintf(err, cap, "%s", message ? message : "CT1 promotion failed");
}

static bool fo_qkp_id(qihse_cluster_failover_t* fo, const char* topology_id,
                      char out[QIHSE_QKP_NODE_ID_LEN + 1u]) {
    if (!fo || !fo->topology_qkp_id || !topology_id || !out) return false;
    memset(out, 0, QIHSE_QKP_NODE_ID_LEN + 1u);
    if (!fo->topology_qkp_id(fo->topology_qkp_id_context, topology_id, out)) return false;
    size_t n = strnlen(out, QIHSE_QKP_NODE_ID_LEN + 1u);
    return n > 0 && n <= QIHSE_QKP_NODE_ID_LEN;
}

bool qihse_cluster_failover_ct_successor_slotless(
    const qihse_cluster_topology_t* topology,
    uint16_t failed_primary_index, uint16_t promoted_local_index,
    uint16_t new_successor_index, char* err, size_t err_cap) {
    if (!topology || failed_primary_index == QIHSE_CLUSTER_NODE_NONE ||
        promoted_local_index == QIHSE_CLUSTER_NODE_NONE ||
        new_successor_index == QIHSE_CLUSTER_NODE_NONE ||
        new_successor_index == failed_primary_index ||
        new_successor_index == promoted_local_index) {
        fo_set_err(err, err_cap, "CT1 successor must be a distinct configured node");
        return false;
    }
    qihse_cluster_node_t successor;
    if (!qihse_cluster_topology_get_node(topology, new_successor_index, &successor) ||
        !successor.healthy) {
        fo_set_err(err, err_cap, "CT1 successor must be healthy and configured");
        return false;
    }
    qihse_cluster_slot_range_t* ranges = calloc(QIHSE_CLUSTER_SLOT_COUNT,
                                                 sizeof(*ranges));
    if (!ranges) {
        fo_set_err(err, err_cap, "could not inspect CT1 successor slot ownership");
        return false;
    }
    size_t count = qihse_cluster_topology_ranges(topology, ranges,
                                                  QIHSE_CLUSTER_SLOT_COUNT);
    bool owns = false;
    for (size_t i = 0; i < count && i < QIHSE_CLUSTER_SLOT_COUNT; ++i)
        if (ranges[i].owner_index == new_successor_index) { owns = true; break; }
    free(ranges);
    if (owns) {
        fo_set_err(err, err_cap, "CT1 successor owns slots; a full baseline could overwrite unrelated data");
        return false;
    }
    fo_set_err(err, err_cap, "");
    return true;
}

/* This explicit path is invoked only after the embedding's consensus/election
 * gate has selected the local replica. Health-only and bus-only callers still
 * use fo_promote_locked(), which refuses data-bearing ownership changes. */
static bool fo_promote_ct_locked(qihse_cluster_failover_t* fo,
                                 uint16_t failed_primary_index,
                                 uint16_t replica_index,
                                 uint16_t new_successor_index,
                                 char out_new_generation[33],
                                 char* err, size_t err_cap) {
    if (!fo || !fo->ct_store || !fo->ct_principal || !fo->ct_election_authorized ||
        replica_index != fo->local_node_index || !fo->ct_local_qkp_id[0]) {
        fo_set_err(err, err_cap, "CT1 proof, authenticated store, or election context is not configured for the local candidate");
        return false;
    }
    qihse_cluster_node_t failed, replica, successor;
    if (!qihse_cluster_topology_get_node(fo->topology, failed_primary_index, &failed) ||
        !qihse_cluster_topology_get_node(fo->topology, replica_index, &replica) ||
        failed.role != QIHSE_CLUSTER_NODE_PRIMARY || failed.healthy || !replica.healthy ||
        replica.role != QIHSE_CLUSTER_NODE_REPLICA || replica.primary_index != failed_primary_index) {
        fo_set_err(err, err_cap, "candidate is not the healthy dedicated replica of the failed primary");
        return false;
    }
    if (!qihse_cluster_failover_ct_successor_slotless(fo->topology,
            failed_primary_index, replica_index, new_successor_index, err, err_cap) ||
        !qihse_cluster_topology_get_node(fo->topology, new_successor_index, &successor))
        return false;
    char failed_qkp[QIHSE_QKP_NODE_ID_LEN + 1u];
    if (!fo_qkp_id(fo, failed.id, failed_qkp)) {
        fo_set_err(err, err_cap, "failed topology node has no configured QKP identity mapping");
        return false;
    }
    char local_qkp_mapping[QIHSE_QKP_NODE_ID_LEN + 1u];
    if (!fo_qkp_id(fo, replica.id, local_qkp_mapping) ||
        strcmp(local_qkp_mapping, fo->ct_local_qkp_id) != 0) {
        /* The spelling is intentionally not compared to the topology ID: this
         * mapping callback is the trusted bridge between identity namespaces. */
        fo_set_err(err, err_cap, "local topology-to-QKP pin mapping does not match the configured endpoint");
        return false;
    }
    if (!strcmp(failed_qkp, fo->ct_local_qkp_id)) {
        fo_set_err(err, err_cap, "source and local successor resolve to the same QKP identity");
        return false;
    }
    char successor_qkp[QIHSE_QKP_NODE_ID_LEN + 1u];
    if (!fo_qkp_id(fo, successor.id, successor_qkp) ||
        !strcmp(successor_qkp, failed_qkp) ||
        !strcmp(successor_qkp, fo->ct_local_qkp_id)) {
        fo_set_err(err, err_cap, "new successor is missing a trusted distinct QKP pin mapping");
        return false;
    }
    qihse_kv_ct_receiver_status_t receiver;
    memset(&receiver, 0, sizeof(receiver));
    if (!qihse_kv_ct_receiver_status(fo->ct_store, fo->ct_principal, &receiver) ||
        strcmp(receiver.source_id, failed_qkp) != 0 ||
        !receiver.generation[0]) {
        fo_set_err(err, err_cap, "persisted receiver identity or generation does not match the configured peers");
        return false;
    }
    qihse_kv_ct_proof_t* proof = qihse_kv_ct_promotion_proof_create(
        fo->ct_store, fo->ct_principal, failed_qkp, fo->ct_local_qkp_id,
        receiver.generation, receiver.durable_cursor);
    if (!proof) {
        fo_set_err(err, err_cap, "could not create persisted receiver promotion proof");
        return false;
    }
    bool ok = false;
    const char *proof_source = NULL, *proof_target = NULL, *proof_generation = NULL;
    const char *proof_transfer = NULL;
    uint16_t proof_first = 0, proof_last = 0;
    uint64_t proof_source_lsn = 0, proof_target_lsn = 0;
    uint8_t proof_checksum[32] = {0}, owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    uint8_t random[16] = {0};
    qihse_cluster_slot_range_t* ranges = NULL;
    size_t range_count = 0;
    char new_generation[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    const char* data_dir = qihse_kv_store_data_directory(fo->ct_store);
    if (!data_dir || !qihse_kv_ct_proof_validate(fo->ct_store, fo->ct_principal, NULL, proof) ||
        !qihse_kv_ct_proof_fields(fo->ct_store, fo->ct_principal, NULL, proof,
            &proof_transfer, &proof_source, &proof_target,
            &proof_generation, &proof_first, &proof_last, &proof_source_lsn,
            &proof_target_lsn, proof_checksum) ||
        !proof_source || !proof_target || !proof_generation ||
        strcmp(proof_source, failed_qkp) || strcmp(proof_target, fo->ct_local_qkp_id) ||
        strcmp(proof_generation, receiver.generation) ||
        proof_source_lsn != receiver.durable_cursor || proof_target_lsn != proof_source_lsn ||
        !qihse_kv_ct_owner_token_get(fo->ct_store, fo->ct_principal, owner_token)) {
        fo_set_err(err, err_cap, "receiver proof, QKP identity, durable cursor, or owner authorization did not validate");
        goto done;
    }
    if (!fo->ct_election_authorized(fo->ct_election_context, failed.id, replica.id,
            receiver.generation, receiver.durable_cursor)) {
        fo_set_err(err, err_cap, "cluster consensus lease/quorum did not authorize this promotion");
        goto done;
    }
    ranges = calloc(QIHSE_CLUSTER_SLOT_COUNT, sizeof(*ranges));
    if (!ranges) { fo_set_err(err, err_cap, "out of memory reading owned slot ranges"); goto done; }
    range_count = qihse_cluster_topology_ranges(fo->topology, ranges, QIHSE_CLUSTER_SLOT_COUNT);
    size_t owned = 0;
    for (size_t i = 0; i < range_count; ++i) owned += ranges[i].owner_index == failed_primary_index;
    if (!owned) { fo_set_err(err, err_cap, "failed primary owns no slot ranges"); goto done; }
    static const char hex[] = "0123456789abcdef";
    if (RAND_bytes(random, sizeof(random)) != 1) { fo_set_err(err, err_cap, "secure generation allocation failed"); goto done; }
    for (size_t i = 0; i < sizeof(random); ++i) {
        new_generation[i * 2u] = hex[random[i] >> 4];
        new_generation[i * 2u + 1u] = hex[random[i] & 15u];
    }
    new_generation[32] = '\0';
    char source_lsn_text[32];
    snprintf(source_lsn_text, sizeof(source_lsn_text), "%llu",
             (unsigned long long)proof_source_lsn);
    const uint8_t* digest_data[9] = {
        (const uint8_t*)failed.id, (const uint8_t*)replica.id,
        (const uint8_t*)failed_qkp, (const uint8_t*)fo->ct_local_qkp_id,
        (const uint8_t*)successor.id, (const uint8_t*)successor_qkp,
        (const uint8_t*)receiver.generation, (const uint8_t*)new_generation,
        (const uint8_t*)source_lsn_text
    };
    size_t digest_len[9] = {strlen(failed.id), strlen(replica.id), strlen(failed_qkp),
                            strlen(fo->ct_local_qkp_id), strlen(successor.id),
                            strlen(successor_qkp), strlen(receiver.generation),
                            strlen(new_generation), strlen(source_lsn_text)};
    uint8_t audit_digest[32]; unsigned int digest_n = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    bool digest_ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1;
    for (size_t i = 0; digest_ok && i < 9; ++i)
        digest_ok = EVP_DigestUpdate(md, digest_data[i], digest_len[i]) == 1;
    if (digest_ok) digest_ok = EVP_DigestFinal_ex(md, audit_digest, &digest_n) == 1 && digest_n == 32;
    EVP_MD_CTX_free(md);
    if (!digest_ok) { fo_set_err(err, err_cap, "failed to fingerprint the validated proof for the journal"); goto done; }
    uint64_t epoch = qihse_cluster_topology_epoch(fo->topology);
    if (epoch == UINT64_MAX) { fo_set_err(err, err_cap, "topology config epoch exhausted"); goto done; }
    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    txn.phase = QIHSE_OWNERSHIP_PREPARED;
    txn.start = QIHSE_CLUSTER_SLOT_COUNT;
    txn.end = 0;
    snprintf(txn.transfer_id, sizeof(txn.transfer_id), "ct1-%.24s-%llu", new_generation,
             (unsigned long long)epoch);
    snprintf(txn.source_id, sizeof(txn.source_id), "%s", failed.id);
    snprintf(txn.target_id, sizeof(txn.target_id), "%s", replica.id);
    snprintf(txn.source_qkp_id, sizeof(txn.source_qkp_id), "%s", failed_qkp);
    snprintf(txn.target_qkp_id, sizeof(txn.target_qkp_id), "%s", fo->ct_local_qkp_id);
    snprintf(txn.generation, sizeof(txn.generation), "%s", receiver.generation);
    snprintf(txn.next_generation, sizeof(txn.next_generation), "%s", new_generation);
    /* The existing owner field binds the selected successor for CT1. This
     * preserves the fixed v2 frame while making recovery deterministic. */
    snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", successor.id);
    txn.config_epoch = ++epoch;
    txn.source_lsn = proof_source_lsn;
    for (size_t i = 0; i < range_count; ++i) {
        if (ranges[i].owner_index != failed_primary_index) continue;
        if (ranges[i].end >= QIHSE_CLUSTER_SLOT_COUNT || ranges[i].start > ranges[i].end) {
            fo_set_err(err, err_cap, "topology contains an invalid owned range"); goto done;
        }
        for (uint32_t slot = ranges[i].start; slot <= ranges[i].end; ++slot) {
            txn.slot_bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
            if (slot < txn.start) txn.start = (uint16_t)slot;
            if (slot > txn.end) txn.end = (uint16_t)slot;
        }
    }
    if (txn.start >= QIHSE_CLUSTER_SLOT_COUNT ||
        qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        fo_set_err(err, err_cap, "could not persist complete CT1 ownership prepare manifest"); goto done;
    }
    /* A single complete manifest precedes the generation switch. This closes
     * the crash window where only some disjoint ranges had been journaled. */
    if (!qihse_kv_ct_receiver_promote(fo->ct_store, fo->ct_principal, proof,
            new_generation, successor_qkp, owner_token)) {
        fo_set_err(err, err_cap, "receiver refused durable generation promotion");
        goto done;
    }
    /* Expose the durable generation even if a later journal/bus operation
     * fails. Runtime recovery must not abandon an already switched receiver. */
    if (out_new_generation) memcpy(out_new_generation, new_generation, 33u);
    txn.phase = QIHSE_OWNERSHIP_COMMITTED;
    txn.target_lsn = proof_target_lsn;
    memcpy(txn.proof_digest, audit_digest, sizeof(txn.proof_digest));
    if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        fo_set_err(err, err_cap, "could not persist CT1 ownership commit record"); goto done;
    }
    /* All proof, receiver generation and journal commits are durable before
     * changing the in-memory route. Existing gossip adoption remains denied. */
    replica.role = QIHSE_CLUSTER_NODE_PRIMARY;
    replica.primary_index = QIHSE_CLUSTER_NODE_NONE;
    replica.healthy = true;
    replica.config_epoch = epoch;
    if (!qihse_cluster_topology_upsert_node(fo->topology, &replica, NULL)) {
        fo_set_err(err, err_cap, "durable promotion is pending topology recovery"); goto done;
    }
    successor.role = QIHSE_CLUSTER_NODE_REPLICA;
    successor.primary_index = replica_index;
    successor.config_epoch = epoch;
    if (!qihse_cluster_topology_upsert_node(fo->topology, &successor, NULL)) {
        fo_set_err(err, err_cap, "promoted source is durable; successor role update needs recovery"); goto done;
    }
    for (size_t i = 0; i < range_count; ++i) {
        if (ranges[i].owner_index != failed_primary_index) continue;
        if (!qihse_cluster_topology_adopt_range(fo->topology, ranges[i].start,
                ranges[i].end, replica_index, epoch)) {
            fo_set_err(err, err_cap, "durable promotion is pending topology recovery"); goto done;
        }
    }
    if (fo->bus) {
        qihse_cluster_bus_ct1_promotion_update_t update;
        memset(&update, 0, sizeof(update));
        update.magic = QIHSE_CLUSTER_BUS_CT1_PROMOTION_MAGIC;
        update.start = txn.start; update.end = txn.end;
        update.config_epoch = txn.config_epoch;
        update.durable_cursor = txn.source_lsn;
        snprintf(update.transfer_id, sizeof(update.transfer_id), "%s", txn.transfer_id);
        snprintf(update.source_id, sizeof(update.source_id), "%s", txn.source_id);
        snprintf(update.target_id, sizeof(update.target_id), "%s", txn.target_id);
        snprintf(update.source_qkp_id, sizeof(update.source_qkp_id), "%s", txn.source_qkp_id);
        snprintf(update.target_qkp_id, sizeof(update.target_qkp_id), "%s", txn.target_qkp_id);
        snprintf(update.successor_id, sizeof(update.successor_id), "%s", txn.owner_id);
        snprintf(update.successor_qkp_id, sizeof(update.successor_qkp_id), "%s", successor_qkp);
        snprintf(update.generation, sizeof(update.generation), "%s", txn.generation);
        snprintf(update.next_generation, sizeof(update.next_generation), "%s", txn.next_generation);
        memcpy(update.slot_bitmap, txn.slot_bitmap, sizeof(update.slot_bitmap));
        memcpy(update.promotion_digest, txn.proof_digest, sizeof(update.promotion_digest));
        if (qihse_cluster_bus_ct1_promotion_seal(&update))
            (void)qihse_cluster_bus_broadcast_ct1_promotion(fo->bus, &update);
        OPENSSL_cleanse(&update, sizeof(update));
    }
    if (fo->bus) qihse_cluster_bus_broadcast_node_update(fo->bus, replica_index);
    if (fo->bus) qihse_cluster_bus_broadcast_node_update(fo->bus, new_successor_index);
    if (out_new_generation) memcpy(out_new_generation, new_generation, 33u);
    ok = true;
done:
    if (ranges) free(ranges);
    qihse_kv_ct_proof_destroy(proof);
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    OPENSSL_cleanse(random, sizeof(random));
    if (ok) fo_set_err(err, err_cap, "");
    return ok;
}

bool qihse_cluster_failover_promote_ct(qihse_cluster_failover_t* fo,
                                       uint16_t failed_primary_index,
                                       uint16_t replica_index,
                                       uint16_t new_successor_index,
                                       char out_new_generation[33],
                                       char* err, size_t err_cap) {
    if (out_new_generation) out_new_generation[0] = '\0';
    if (!fo || !out_new_generation) {
        fo_set_err(err, err_cap, "failover coordinator and generation output are required");
        return false;
    }
    if (fo->maintenance_gate && !qihse_cluster_maintenance_enter(
            fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER)) {
        fo_set_err(err, err_cap, "cluster maintenance gate refused failover"); return false;
    }
    pthread_mutex_lock(&fo->lock);
    fo->activity_started = true;
    bool ok = !fo->startup_paused && fo_promote_ct_locked(
        fo, failed_primary_index, replica_index, new_successor_index,
        out_new_generation, err, err_cap);
    if (ok) fo->failover_events++;
    if (!ok && fo->startup_paused) fo_set_err(err, err_cap, "failover is paused during startup");
    pthread_mutex_unlock(&fo->lock);
    if (fo->maintenance_gate)
        qihse_cluster_maintenance_leave(fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER);
    return ok;
}

static bool fo_lane_status_matches_txn(const qihse_kv_ct_lane_status_t* lane,
    const qihse_cluster_ownership_txn_t* txn, const char* promoted_qkp) {
    return lane && txn && lane->mode == QIHSE_KV_CT_LANE_SOURCE &&
        !strcmp(lane->lane_id, txn->lane_id) &&
        !strcmp(lane->source_id, promoted_qkp) &&
        !strcmp(lane->generation, txn->next_generation) &&
        CRYPTO_memcmp(lane->slot_bitmap, txn->slot_bitmap,
            sizeof(txn->slot_bitmap)) == 0;
}

static bool fo_lane_wait_for_successor(qihse_cluster_ownership_context_t* ownership,
    const qihse_cluster_ownership_txn_t* txn,
    const uint8_t certificate_digest[32],
    const uint8_t event_digest[32], qihse_kv_ct_lane_status_t* out_status) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000};
    const uint64_t deadline = fo_now_ms() + 30000u;
    do {
        memset(out_status, 0, sizeof(*out_status));
        if (!qihse_kv_ct_lane_status(ownership->store, ownership->principal,
                txn->lane_id, out_status) ||
            !fo_lane_status_matches_txn(out_status, txn, txn->target_qkp_id))
            return false;
        /* The promoted lane must remain non-routable/non-writable until the
         * common FINAL has been durably recorded. */
        if (out_status->baseline_sealed && out_status->promotion_pending &&
            out_status->admitted &&
            out_status->baseline_row_seq == txn->target_lsn &&
            out_status->durable_position >= out_status->baseline_stream_cut &&
            out_status->acknowledged_position >= out_status->baseline_stream_cut &&
            CRYPTO_memcmp(out_status->certificate_head_digest,
                certificate_digest, 32u) == 0 &&
            CRYPTO_memcmp(out_status->certificate_ack_digest,
                certificate_digest, 32u) == 0)
            return true;
        if (fo_now_ms() >= deadline) break;
        nanosleep(&pause, NULL);
    } while (true);
    (void)event_digest;
    return false;
}

/* A common FINAL can precede the local admission or FINALIZED journal write.
 * Recover that completed authority decision from its persisted readiness
 * marker, without repeating the obsolete election or RESERVED-only bind. */
static bool fo_lane_resume_final(qihse_cluster_ownership_context_t* ownership,
    qihse_cluster_ownership_txn_t* txn, const char* data_dir,
    bool* out_final_seen, char* err, size_t err_cap) {
    *out_final_seen = false;
    qihse_kv_ct_lane_authority_claim_t final_claim = {0}, marker = {0};
    fo_lane_verify_context_t verifier = {ownership, ownership->principal};
    if (!ownership->lane_claim(ownership->range_authority_context,
            ownership->principal, txn, &final_claim) ||
        !final_claim.final_decision_index ||
        !ownership->lane_verify_claim(ownership->range_authority_context,
            ownership->principal, &final_claim, true)) return false;
    *out_final_seen = true;
    qihse_kv_ct_proof_t* ready = qihse_kv_ct_lane_promoted_proof_get(
        ownership->store, ownership->principal, ownership->data_principal,
        txn->lane_id, final_claim.promotion_event_digest,
        fo_lane_verify_adapter, &verifier);
    bool ok = ready && qihse_kv_ct_lane_authority_proof_fields(
            ownership->store, ownership->principal, ownership->data_principal,
            ready, &marker) &&
        !strcmp(marker.transfer_id, txn->transfer_id) &&
        !strcmp(marker.source_group_id, txn->lane_id) &&
        !strcmp(marker.target_group_id, txn->lane_id) &&
        !strcmp(marker.source_qkp_id, txn->source_qkp_id) &&
        !strcmp(marker.target_qkp_id, txn->target_qkp_id) &&
        !strcmp(marker.source_generation, txn->generation) &&
        !strcmp(marker.target_generation, txn->next_generation) &&
        marker.source_cut == txn->source_lsn && marker.target_cursor == txn->target_lsn &&
        marker.grant_epoch == txn->config_epoch &&
        CRYPTO_memcmp(marker.slots, txn->slot_bitmap, sizeof(txn->slot_bitmap)) == 0 &&
        CRYPTO_memcmp(marker.promotion_event_digest,
            final_claim.promotion_event_digest, 32u) == 0;
    qihse_kv_ct_proof_destroy(ready);
    if (ok) {
        memcpy(final_claim.range_digest, marker.range_digest, 32u);
        memcpy(final_claim.image_digest, marker.image_digest, 32u);
        memcpy(final_claim.certificate_head_digest, marker.certificate_head_digest, 32u);
    }
    qihse_kv_ct_proof_t* proof = ok ? qihse_kv_ct_lane_authority_proof_create(
        ownership->store, ownership->principal, ownership->data_principal,
        &final_claim, fo_lane_verify_adapter, &verifier) : NULL;
    ok = proof && qihse_kv_ct_lane_promotion_finalize(ownership->store,
        ownership->principal, ownership->data_principal, &final_claim,
        proof, fo_lane_verify_adapter, &verifier) &&
        ownership->range_refresh(ownership->range_authority_context,
            ownership->principal, txn->slot_bitmap, err, err_cap);
    qihse_kv_ct_proof_destroy(proof);
    if (ok && txn->phase != QIHSE_OWNERSHIP_FINALIZED) {
        txn->phase = QIHSE_OWNERSHIP_FINALIZED;
        ok = qihse_cluster_ownership_journal_append_txn(data_dir, txn) == 0;
    }
    OPENSSL_cleanse(&marker, sizeof(marker));
    OPENSSL_cleanse(&final_claim, sizeof(final_claim));
    if (!ok) fo_set_err(err, err_cap,
        "common FINAL is durable; local readiness/admission recovery remains pending");
    else fo_set_err(err, err_cap, "");
    return ok;
}

bool qihse_cluster_failover_promote_lane(
    qihse_cluster_ownership_context_t* ownership, const char* lane_id,
    uint16_t new_successor_index, bool* out_pending,
    char* err, size_t err_cap) {
    if (out_pending) *out_pending = false;
    if (!ownership || !ownership->topology || !ownership->store ||
        !ownership->principal || !ownership->data_principal || !ownership->bus ||
        !ownership->peer_id || !ownership->lane_claim ||
        !ownership->lane_verify_claim || !ownership->range_reserve ||
        !ownership->range_finalize_promotion || !ownership->range_refresh ||
        !ownership->promotion_successor_prepare || !lane_id ||
        strlen(lane_id) != QIHSE_KV_CT_LANE_ID_MAX ||
        new_successor_index == QIHSE_CLUSTER_NODE_NONE || !out_pending ||
        !qihse_auth_user_is_active(ownership->principal) ||
        qihse_user_get_role(ownership->principal) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(ownership->principal) != QIHSE_TENANT_SYSTEM) {
        fo_set_err(err, err_cap, "active System Operator, lane authority, and successor staging context are required");
        return false;
    }
    for (size_t i = 0; i < QIHSE_KV_CT_LANE_ID_MAX; ++i)
        if (!((lane_id[i] >= '0' && lane_id[i] <= '9') ||
              (lane_id[i] >= 'a' && lane_id[i] <= 'f'))) {
            fo_set_err(err, err_cap, "lane ID must be canonical lowercase hexadecimal");
            return false;
        }

    const char* data_dir = qihse_kv_store_data_directory(ownership->store);
    if (!data_dir) { fo_set_err(err, err_cap, "ownership journal directory is unavailable"); return false; }
    fo_lane_journal_scan_t scan = {.lane_id = lane_id};
    bool unresolved = false;
    if (qihse_cluster_ownership_journal_replay_txn(data_dir,
            fo_lane_journal_scan, &scan, &unresolved) < 0) {
        fo_set_err(err, err_cap, "lane promotion journal is unreadable");
        return false;
    }

    qihse_kv_ct_lane_status_t lane;
    memset(&lane, 0, sizeof(lane));
    if (!qihse_kv_ct_lane_status(ownership->store, ownership->principal,
            lane_id, &lane)) {
        fo_set_err(err, err_cap, "configured CT receiver lane is unavailable");
        return false;
    }
    bool have_txn = scan.found &&
        (scan.txn.phase == QIHSE_OWNERSHIP_INTENT ||
         scan.txn.phase == QIHSE_OWNERSHIP_PREPARED ||
         scan.txn.phase == QIHSE_OWNERSHIP_COMMITTED);
    *out_pending = have_txn;
    if (scan.found && scan.txn.phase == QIHSE_OWNERSHIP_FINALIZED &&
        fo_lane_status_matches_txn(&lane, &scan.txn, scan.txn.target_qkp_id)) {
        qihse_kv_ct_lane_authority_claim_t completed = {0};
        bool done = lane.admitted && !lane.promotion_pending &&
            ownership->lane_claim(ownership->range_authority_context,
                ownership->principal, &scan.txn, &completed) &&
            ownership->lane_verify_claim(ownership->range_authority_context,
                ownership->principal, &completed, true) &&
            ownership->range_refresh(ownership->range_authority_context,
                ownership->principal, scan.txn.slot_bitmap, err, err_cap);
        OPENSSL_cleanse(&completed, sizeof(completed));
        OPENSSL_cleanse(&lane, sizeof(lane));
        if (!done) fo_set_err(err, err_cap, "finalized lane promotion is not durably admitted");
        else fo_set_err(err, err_cap, "");
        return done;
    }
    if (scan.found && scan.txn.phase == QIHSE_OWNERSHIP_COMMITTED) {
        bool final_seen = false;
        bool done = fo_lane_resume_final(ownership, &scan.txn, data_dir,
            &final_seen, err, err_cap);
        if (done || final_seen) {
            OPENSSL_cleanse(&lane, sizeof(lane));
            *out_pending = !done;
            return done;
        }
    }
    uint16_t local_index = qihse_cluster_topology_local_node(ownership->topology);
    uint16_t source_index = QIHSE_CLUSTER_NODE_NONE;
    uint16_t successor_index = new_successor_index;
    qihse_cluster_node_t source, target, successor;
    memset(&source, 0, sizeof(source)); memset(&target, 0, sizeof(target));
    memset(&successor, 0, sizeof(successor));
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    char target_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    char successor_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    bool identities_ok;
    if (have_txn) {
        identities_ok = qihse_cluster_topology_find_node(ownership->topology,
                scan.txn.source_id, &source_index) &&
            qihse_cluster_topology_get_node(ownership->topology, source_index, &source) &&
            qihse_cluster_topology_find_node(ownership->topology,
                scan.txn.target_id, &local_index) &&
            qihse_cluster_topology_get_node(ownership->topology, local_index, &target) &&
            qihse_cluster_topology_find_node(ownership->topology,
                scan.txn.owner_id, &successor_index) &&
            qihse_cluster_topology_get_node(ownership->topology, successor_index, &successor) &&
            ownership->peer_id(ownership->peer_id_context, source.id, source_qkp) &&
            ownership->peer_id(ownership->peer_id_context, target.id, target_qkp) &&
            ownership->peer_id(ownership->peer_id_context, successor.id, successor_qkp) &&
            !strcmp(source_qkp, scan.txn.source_qkp_id) &&
            !strcmp(target_qkp, scan.txn.target_qkp_id) &&
            successor_index == new_successor_index &&
            qihse_cluster_topology_local_node(ownership->topology) == local_index;
    } else {
        identities_ok = fo_find_qkp_node(ownership, lane.source_id,
                &source_index, &source) &&
            local_index != QIHSE_CLUSTER_NODE_NONE && local_index != source_index &&
            qihse_cluster_topology_get_node(ownership->topology, local_index, &target) &&
            ownership->peer_id(ownership->peer_id_context, source.id, source_qkp) &&
            ownership->peer_id(ownership->peer_id_context, target.id, target_qkp) &&
            !strcmp(source_qkp, lane.source_id) && !strcmp(target_qkp, lane.peer_id) &&
            qihse_cluster_topology_get_node(ownership->topology, successor_index, &successor) &&
            ownership->peer_id(ownership->peer_id_context, successor.id, successor_qkp);
    }
    bool ok = identities_ok && successor.healthy && target.healthy && !source.healthy &&
        successor_index != source_index && successor_index != local_index &&
        strcmp(successor_qkp, source_qkp) && strcmp(successor_qkp, target_qkp);
    if (!ok) {
        OPENSSL_cleanse(&lane, sizeof(lane));
        fo_set_err(err, err_cap, "lane source failure, local replica, or successor does not match trusted pins/topology");
        return false;
    }

    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    if (have_txn) {
        txn = scan.txn;
        if (strcmp(txn.lane_id, lane_id) || strcmp(txn.owner_id, successor.id)) {
            OPENSSL_cleanse(&lane, sizeof(lane));
            fo_set_err(err, err_cap, "a different lane promotion is already durable and must be resumed with its original successor");
            *out_pending = true;
            return false;
        }
    }

    if (!have_txn) {
        if (lane.mode != QIHSE_KV_CT_LANE_RECEIVER || !lane.baseline_sealed ||
            !lane.generation[0] ||
            lane.source_id[0] == '\0' || strcmp(lane.peer_id, target_qkp)) {
            OPENSSL_cleanse(&lane, sizeof(lane));
            fo_set_err(err, err_cap, "failed-source lane lacks a sealed receiver baseline or exact local pin");
            return false;
        }
        uint32_t first = QIHSE_CLUSTER_SLOT_COUNT, last = 0;
        for (uint32_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; ++slot) {
            if (!(lane.slot_bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u)))) continue;
            if (slot < first) first = slot;
            last = slot;
        }
        if (first >= QIHSE_CLUSTER_SLOT_COUNT || !fo_lane_random_hex(txn.next_generation)) {
            OPENSSL_cleanse(&lane, sizeof(lane));
            fo_set_err(err, err_cap, "lane is empty or generation allocation failed");
            return false;
        }
        txn.phase = QIHSE_OWNERSHIP_INTENT;
        txn.start = (uint16_t)first; txn.end = (uint16_t)last;
        txn.source_lsn = lane.durable_position;
        txn.target_lsn = 0;
        snprintf(txn.source_id, sizeof(txn.source_id), "%s", source.id);
        snprintf(txn.target_id, sizeof(txn.target_id), "%s", target.id);
        snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", successor.id);
        snprintf(txn.source_qkp_id, sizeof(txn.source_qkp_id), "%s", source_qkp);
        snprintf(txn.target_qkp_id, sizeof(txn.target_qkp_id), "%s", target_qkp);
        snprintf(txn.generation, sizeof(txn.generation), "%s", lane.generation);
        snprintf(txn.lane_id, sizeof(txn.lane_id), "%s", lane_id);
        memcpy(txn.slot_bitmap, lane.slot_bitmap, sizeof(txn.slot_bitmap));
        snprintf(txn.transfer_id, sizeof(txn.transfer_id), "ct1-%s", txn.next_generation);
        if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
            OPENSSL_cleanse(&lane, sizeof(lane)); OPENSSL_cleanse(&txn, sizeof(txn));
            fo_set_err(err, err_cap, "could not persist lane promotion intent before reservation");
            return false;
        }
        *out_pending = true;
        have_txn = true;
    }

    /* INTENT/PREPARED journal records intentionally have no target cursor.
     * Rebuild it from the durable receiver baseline on retry; source cursor
     * and row-sequence baseline are independent domains for lane promotion. */
    if (txn.phase == QIHSE_OWNERSHIP_INTENT ||
        txn.phase == QIHSE_OWNERSHIP_PREPARED)
        txn.target_lsn = lane.baseline_row_seq;

    qihse_kv_ct_lane_authority_claim_t claim;
    qihse_kv_ct_proof_t* reserved_proof = NULL;
    memset(&claim, 0, sizeof(claim));
    if (!qihse_cluster_ownership_promotion_reserve(ownership, &txn,
            &claim, &reserved_proof, err, err_cap)) goto lane_pending;
    if (txn.phase == QIHSE_OWNERSHIP_INTENT) {
        qihse_cluster_ownership_txn_t prepared_txn = txn;
        prepared_txn.phase = QIHSE_OWNERSHIP_PREPARED;
        prepared_txn.target_lsn = 0;
        memset(prepared_txn.proof_digest, 0, sizeof(prepared_txn.proof_digest));
        if (qihse_cluster_ownership_journal_append_txn(data_dir,
                &prepared_txn) != 0) {
            qihse_kv_ct_proof_destroy(reserved_proof);
            OPENSSL_cleanse(&claim, sizeof(claim));
            fo_set_err(err, err_cap, "reserved promotion could not persist PREPARED journal phase");
            goto lane_pending;
        }
        txn.phase = QIHSE_OWNERSHIP_PREPARED;
    }

    if (lane.mode == QIHSE_KV_CT_LANE_RECEIVER) {
        uint8_t token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
        bool promoted = qihse_kv_ct_lane_owner_token_get(ownership->store,
                ownership->principal, lane_id, token) &&
            qihse_kv_ct_lane_receiver_promote(ownership->store,
                ownership->principal, ownership->data_principal, &claim,
                reserved_proof, fo_lane_verify_adapter,
                &(fo_lane_verify_context_t){ownership, ownership->principal}, token);
        OPENSSL_cleanse(token, sizeof(token));
        if (!promoted) {
            qihse_kv_ct_proof_destroy(reserved_proof);
            OPENSSL_cleanse(&claim, sizeof(claim));
            fo_set_err(err, err_cap, "receiver lane could not enter pending promotion state");
            goto lane_pending;
        }
    } else if (!fo_lane_status_matches_txn(&lane, &txn, target_qkp) ||
               (!lane.promotion_pending && !lane.admitted)) {
        qihse_kv_ct_proof_destroy(reserved_proof);
        OPENSSL_cleanse(&claim, sizeof(claim));
        fo_set_err(err, err_cap, "existing source lane does not match its durable promotion transaction");
        goto lane_pending;
    }
    qihse_kv_ct_proof_destroy(reserved_proof);

    /* The new generation starts at CT position zero. Its immutable baseline
     * row watermark is captured after receiver promotion; the old receiver's
     * baseline and old generation's CT cursor are different sequence domains.
     * Seal this image before signing the event so retries retain one tuple. */
    qihse_kv_replica_snapshot_t* baseline = NULL;
    uint64_t baseline_row = 0;
    uint8_t baseline_digest[32];
    bool baseline_ok = qihse_kv_ct_lane_source_baseline_snapshot_create(
        ownership->store, ownership->data_principal, lane_id, &baseline,
        &baseline_row, baseline_digest) == 0;
    qihse_kv_replica_snapshot_destroy(baseline);
    OPENSSL_cleanse(baseline_digest, sizeof(baseline_digest));
    if (!baseline_ok || (txn.phase == QIHSE_OWNERSHIP_COMMITTED &&
                         txn.target_lsn != baseline_row)) {
        OPENSSL_cleanse(&claim, sizeof(claim));
        fo_set_err(err, err_cap, "new-generation immutable baseline is unavailable or differs from its signed promotion");
        goto lane_pending;
    }
    txn.target_lsn = baseline_row;

    qihse_cluster_bus_ct1_promotion_update_v2_t update;
    memset(&update, 0, sizeof(update));
    uint8_t* envelope = NULL;
    size_t envelope_len = 0;
    uint8_t certificate_digest[32] = {0};
    if (!fo_lane_audit_digest(&txn, successor_qkp, txn.proof_digest)) {
        OPENSSL_cleanse(&claim, sizeof(claim));
        fo_set_err(err, err_cap, "could not fingerprint the reserved lane promotion tuple");
        goto lane_pending;
    }
    if (!fo_lane_make_update(ownership, &txn, successor_qkp, &update)) {
        OPENSSL_cleanse(&claim, sizeof(claim));
        fo_set_err(err, err_cap, "cannot construct canonical QCP2 promotion event");
        goto lane_pending;
    }
    memcpy(claim.promotion_event_digest, update.event_digest, 32u);
    claim.target_cursor = txn.target_lsn;
    if (!fo_lane_find_certificate(ownership, lane_id, update.event_digest,
            &envelope, &envelope_len, certificate_digest)) {
        if (!qihse_cluster_bus_ct1_promotion_certificate_create(ownership->bus,
                &update, &envelope, &envelope_len) ||
            !qihse_kv_ct_lane_certificate_append(ownership->store,
                ownership->principal, lane_id, txn.next_generation,
                envelope, envelope_len, certificate_digest)) {
            qihse_cluster_bus_ct1_certificate_free(envelope, envelope_len);
            OPENSSL_cleanse(&update, sizeof(update));
            OPENSSL_cleanse(&claim, sizeof(claim));
            fo_set_err(err, err_cap, "exact target-signed QCP2 certificate could not be persisted on the promoted lane");
            goto lane_pending;
        }
    }
    memcpy(claim.certificate_head_digest, certificate_digest, 32u);
    qihse_cluster_bus_ct1_certificate_free(envelope, envelope_len);
    envelope = NULL;
    envelope_len = 0;
    bool needs_commit = txn.phase != QIHSE_OWNERSHIP_COMMITTED;
    txn.phase = QIHSE_OWNERSHIP_COMMITTED;
    if (needs_commit && qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        OPENSSL_cleanse(&update, sizeof(update));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(certificate_digest, sizeof(certificate_digest));
        fo_set_err(err, err_cap, "signed lane promotion could not persist its committed journal phase");
        goto lane_pending;
    }

    if (!ownership->promotion_successor_prepare(
            ownership->promotion_successor_context, successor_index,
            &claim, err, err_cap)) {
        OPENSSL_cleanse(&update, sizeof(update));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(certificate_digest, sizeof(certificate_digest));
        goto lane_pending;
    }
    qihse_kv_ct_lane_status_t promoted_status;
    memset(&promoted_status, 0, sizeof(promoted_status));
    if (!fo_lane_wait_for_successor(ownership, &txn, certificate_digest,
            update.event_digest, &promoted_status)) {
        OPENSSL_cleanse(&promoted_status, sizeof(promoted_status));
        OPENSSL_cleanse(&update, sizeof(update));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(certificate_digest, sizeof(certificate_digest));
        fo_set_err(err, err_cap, "successor baseline/certificate ACK is still pending");
        goto lane_pending;
    }
    memcpy(claim.image_digest, promoted_status.baseline_digest, 32u);
    OPENSSL_cleanse(&promoted_status, sizeof(promoted_status));
    if (!qihse_kv_ct_lane_promotion_ready(ownership->store,
            ownership->principal, ownership->data_principal, &claim,
            fo_lane_verify_adapter,
            &(fo_lane_verify_context_t){ownership, ownership->principal})) {
        OPENSSL_cleanse(&update, sizeof(update));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(certificate_digest, sizeof(certificate_digest));
        fo_set_err(err, err_cap, "promoted lane readiness marker could not be persisted");
        goto lane_pending;
    }
    qihse_kv_ct_proof_t* promoted_proof = qihse_kv_ct_lane_promoted_proof_get(
        ownership->store, ownership->principal, ownership->data_principal,
        lane_id, update.event_digest, fo_lane_verify_adapter,
        &(fo_lane_verify_context_t){ownership, ownership->principal});
    bool finalized = promoted_proof &&
        qihse_cluster_ownership_promotion_finalize(ownership, &txn,
            promoted_proof, update.event_digest, err, err_cap);
    qihse_kv_ct_proof_destroy(promoted_proof);
    if (!finalized) {
        OPENSSL_cleanse(&update, sizeof(update));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(certificate_digest, sizeof(certificate_digest));
        if (!err || !err_cap || !err[0]) fo_set_err(err, err_cap, "quorum FINAL promotion decision remains pending");
        goto lane_pending;
    }

    qihse_kv_ct_lane_authority_claim_t final_claim;
    memset(&final_claim, 0, sizeof(final_claim));
    qihse_kv_ct_proof_t* final_proof = NULL;
    bool final_claim_ok = ownership->lane_claim(
            ownership->range_authority_context, ownership->principal,
            &txn, &final_claim) &&
        final_claim.operation == QIHSE_KV_CT_LANE_AUTH_PROMOTION &&
        !strcmp(final_claim.transfer_id, txn.transfer_id) &&
        !strcmp(final_claim.source_group_id, lane_id) &&
        !strcmp(final_claim.target_group_id, lane_id) &&
        final_claim.grant_epoch == txn.config_epoch &&
        final_claim.source_cut == txn.source_lsn &&
        final_claim.target_cursor == txn.target_lsn &&
        CRYPTO_memcmp(final_claim.slots, txn.slot_bitmap, sizeof(txn.slot_bitmap)) == 0;
    if (final_claim_ok) {
        memcpy(final_claim.certificate_head_digest, certificate_digest, 32u);
        memcpy(final_claim.promotion_event_digest, update.event_digest, 32u);
        memcpy(final_claim.range_digest, claim.range_digest, 32u);
        memcpy(final_claim.image_digest, claim.image_digest, 32u);
        final_proof = qihse_kv_ct_lane_authority_proof_create(ownership->store,
            ownership->principal, ownership->data_principal, &final_claim,
            fo_lane_verify_adapter,
            &(fo_lane_verify_context_t){ownership, ownership->principal});
    }
    final_claim_ok = final_claim_ok && final_proof &&
        qihse_kv_ct_lane_authority_proof_validate(ownership->store,
            ownership->principal, ownership->data_principal, final_proof,
            fo_lane_verify_adapter,
            &(fo_lane_verify_context_t){ownership, ownership->principal}, true) &&
        qihse_kv_ct_lane_promotion_finalize(ownership->store,
            ownership->principal, ownership->data_principal, &final_claim,
            final_proof, fo_lane_verify_adapter,
            &(fo_lane_verify_context_t){ownership, ownership->principal});
    qihse_kv_ct_proof_destroy(final_proof);
    if (!final_claim_ok || !ownership->range_refresh(
            ownership->range_authority_context, ownership->principal,
            txn.slot_bitmap, err, err_cap)) {
        OPENSSL_cleanse(&final_claim, sizeof(final_claim));
        OPENSSL_cleanse(&update, sizeof(update));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(certificate_digest, sizeof(certificate_digest));
        fo_set_err(err, err_cap, "common FINAL is durable but local lane admission/routing recovery remains pending");
        goto lane_pending;
    }
    txn.phase = QIHSE_OWNERSHIP_FINALIZED;
    if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        OPENSSL_cleanse(&final_claim, sizeof(final_claim));
        OPENSSL_cleanse(&update, sizeof(update));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(certificate_digest, sizeof(certificate_digest));
        fo_set_err(err, err_cap, "lane is admitted but FINALIZED journal append needs recovery");
        goto lane_pending;
    }
    uint8_t* relay_envelope = NULL;
    size_t relay_envelope_len = 0;
    uint8_t relay_digest[32] = {0};
    if (fo_lane_find_certificate(ownership, lane_id, update.event_digest,
            &relay_envelope, &relay_envelope_len, relay_digest)) {
        (void)qihse_cluster_bus_relay_ct1_certificate(ownership->bus,
            relay_envelope, relay_envelope_len);
        qihse_cluster_bus_ct1_certificate_free(relay_envelope,
            relay_envelope_len);
    }
    OPENSSL_cleanse(relay_digest, sizeof(relay_digest));
    OPENSSL_cleanse(&final_claim, sizeof(final_claim));
    OPENSSL_cleanse(&update, sizeof(update));
    OPENSSL_cleanse(&claim, sizeof(claim));
    OPENSSL_cleanse(certificate_digest, sizeof(certificate_digest));
    OPENSSL_cleanse(&lane, sizeof(lane));
    OPENSSL_cleanse(&txn, sizeof(txn));
    *out_pending = false;
    fo_set_err(err, err_cap, "");
    return true;

lane_pending:
    OPENSSL_cleanse(&lane, sizeof(lane));
    OPENSSL_cleanse(&txn, sizeof(txn));
    *out_pending = true;
    return false;
}

static bool qihse_cluster_failover_promote_inner(qihse_cluster_failover_t* fo,
                                    uint16_t failed_primary_index,
                                    uint16_t replica_index) {
    if (!fo) return false;
    pthread_mutex_lock(&fo->lock);
    fo->activity_started = true;
    bool ok = !fo->startup_paused &&
        fo_promote_locked(fo, failed_primary_index, replica_index);
    pthread_mutex_unlock(&fo->lock);
    return ok;
}

bool qihse_cluster_failover_promote(qihse_cluster_failover_t* fo,
                                    uint16_t failed_primary_index,
                                    uint16_t replica_index) {
    if (!fo) return false;
    if (!fo->maintenance_gate) return qihse_cluster_failover_promote_inner(fo, failed_primary_index, replica_index);
    if (!qihse_cluster_maintenance_enter(fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER)) return false;
    bool result = qihse_cluster_failover_promote_inner(fo, failed_primary_index, replica_index);
    qihse_cluster_maintenance_leave(fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER);
    return result;
}

static uint16_t qihse_cluster_failover_handle_inner(qihse_cluster_failover_t* fo,
                                       uint16_t failed_node_index) {
    if (!fo || !fo->topology) return QIHSE_CLUSTER_NODE_NONE;
    pthread_mutex_lock(&fo->lock);
    fo->activity_started = true;
    if (fo->startup_paused) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
    }
    /* cooldown: while a dead node REMAINS unhealthy the bus re-fires on_fail
     * every cycle; promote is idempotent but the broadcasts are not free.
     * Stamp last_attempt_ms only after passing the coordinator and asymmetry
     * evidence gates so a deferred check_health cycle is not locked out for
     * 30s. */
    if (fo->last_attempt_ms && fo_now_ms() - fo->last_attempt_ms < 30000u) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
    }

    qihse_cluster_node_t failed;
    if (!qihse_cluster_topology_get_node(fo->topology, failed_node_index, &failed)) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
    }

    /* Only failover if the failed node was a primary */
    if (failed.role != QIHSE_CLUSTER_NODE_PRIMARY) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
    }

    /* In single-coordinator mode, only the local node performs failover */
    if (fo->single_coordinator && failed_node_index != fo->local_node_index) {
        /* The ordinary coordinator path is a healthy primary. A configured CT1
         * successor is a replica instead; let it reach the proof path only
         * when it is the unique configured successor. The consensus callback
         * in fo_promote_ct_locked still has to approve the live lease/quorum. */
        bool local_ct_successor = fo->ct_store && fo->ct_principal &&
            fo->ct_election_authorized &&
            qihse_cluster_failover_best_replica(fo->topology, failed_node_index) ==
                fo->local_node_index;
        uint16_t coordinator = local_ct_successor ? fo->local_node_index :
            fo_find_coordinator(fo->topology);
        if (coordinator != fo->local_node_index) {
            pthread_mutex_unlock(&fo->lock);
            return QIHSE_CLUSTER_NODE_NONE;
        }
    }

    uint16_t replica = qihse_cluster_failover_best_replica(fo->topology, failed_node_index);
    if (replica == QIHSE_CLUSTER_NODE_NONE) {
        /* Sharded-cluster fallback: no dedicated replica exists, so the
         * healthy primary with the lexicographically smallest node ID
         * succeeds the failed primary and inherits its slot ranges. */
        uint64_t now = fo_now_ms();
        /* Evidence gate: if ANY bus participant recently reported the failed
         * node healthy, this looks like an asymmetric link — defer so we
         * don't strip ranges from a node the rest of the cluster can reach.
         * check_health re-fires on_fail each cycle, so the failover executes
         * as soon as the confirming evidence goes stale. */
        if (fo->bus) {
            uint64_t last_healthy = qihse_cluster_bus_last_observed_healthy(fo->bus, failed_node_index);
            if (last_healthy > 0 && now - last_healthy < QIHSE_CLUSTER_BUS_TIMEOUT_MS) {
                pthread_mutex_unlock(&fo->lock);
                return QIHSE_CLUSTER_NODE_NONE; /* deferred: asymmetry suspect */
            }
        }
        uint16_t best = fo_pick_fallback_successor(fo, failed_node_index, now);
        if (best == QIHSE_CLUSTER_NODE_NONE) {
            pthread_mutex_unlock(&fo->lock);
            return QIHSE_CLUSTER_NODE_NONE;
        }
        replica = best;
    }

    fo->last_attempt_ms = fo_now_ms();
    bool promoted = false;
    if (fo->ct_auto_successor_id[0]) {
        uint16_t successor = QIHSE_CLUSTER_NODE_NONE;
        char generation[33] = {0}, error[256] = {0};
        /* Only the local dedicated receiver may consume the persisted proof.
         * Election authorization below requires a committed quorum decision. */
        if (replica == fo->local_node_index &&
            qihse_cluster_topology_find_node(fo->topology,
                fo->ct_auto_successor_id, &successor) &&
            (promoted = fo_promote_ct_locked(fo, failed_node_index, replica, successor,
                generation, error, sizeof(error)), generation[0])) {
            memcpy(fo->ct_pending_generation, generation, sizeof(generation));
            fo->ct_pending_successor = successor;
        }
        if (error[0]) fprintf(stderr, "qihse-cluster-failover: automatic CT1 deferred: %s\n", error);
    } else {
        promoted = fo_promote_locked(fo, failed_node_index, replica);
    }
    if (promoted) {
        fo->failover_events++;
        fprintf(stderr, "qihse-cluster-failover: node %u failed; node %u takes its slots%s\n",
                (unsigned)failed_node_index, (unsigned)replica,
                replica == fo->local_node_index ? " (this node)" : "");
    }
    pthread_mutex_unlock(&fo->lock);
    return promoted ? replica : QIHSE_CLUSTER_NODE_NONE;
}

uint16_t qihse_cluster_failover_handle(qihse_cluster_failover_t* fo,
                                       uint16_t failed_node_index) {
    if (!fo) return QIHSE_CLUSTER_NODE_NONE;
    if (!fo->maintenance_gate) return qihse_cluster_failover_handle_inner(fo, failed_node_index);
    if (!qihse_cluster_maintenance_enter(fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER))
        return QIHSE_CLUSTER_NODE_NONE;
    uint16_t result = qihse_cluster_failover_handle_inner(fo, failed_node_index);
    qihse_cluster_maintenance_leave(fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER);
    return result;
}

void qihse_cluster_failover_on_fail_cb(qihse_cluster_topology_t* topology,
                                       uint16_t failed_node_index,
                                       void* user_data) {
    (void)topology;
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)user_data;
    if (!fo) return;
    if (fo->ct_auto_successor_id[0]) return; /* worker reads current topology */
    qihse_cluster_failover_handle(fo, failed_node_index);
}

uint64_t qihse_cluster_failover_events(const qihse_cluster_failover_t* fo) {
    return fo ? __atomic_load_n(&fo->failover_events, __ATOMIC_ACQUIRE) : 0u;
}

/* ── failback ────────────────────────────────────────────────────────────── */

static bool fo_slot_is_ours(const qihse_cluster_failover_t* fo, uint32_t slot) {
    uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_slot_state_t state = QIHSE_CLUSTER_SLOT_STABLE;
    return qihse_cluster_topology_get_slot(fo->topology, (uint16_t)slot, &owner, &state, NULL) &&
           owner == fo->local_node_index && state == QIHSE_CLUSTER_SLOT_STABLE;
}

/* One pass over the ledger: for every entry whose owner has been continuously
 * healthy long enough, hand the slots we STILL own back to it. */
static void fo_failback_pass_inner(qihse_cluster_failover_t* fo) {
    if (qihse_cluster_failover_is_paused(fo)) return;
    uint64_t now = fo_now_ms();
    pthread_mutex_lock(&fo->ledger_lock);
    size_t n = fo->ledger_count;
    pthread_mutex_unlock(&fo->ledger_lock);
    pthread_mutex_lock(&fo->lock);
    /* An empty pass may have begun before the before-listen hold was set.
     * Recheck after reading the ledger; once work exists, live pausing is
     * forbidden rather than pretending to drain an in-flight handoff. */
    if (n) fo->activity_started = true;
    bool paused = fo->startup_paused;
    pthread_mutex_unlock(&fo->lock);
    if (paused) return;

    for (size_t i = 0; i < n && !__atomic_load_n(&fo->stop, __ATOMIC_ACQUIRE); i++) {
        fo_ledger_entry_t e;
        pthread_mutex_lock(&fo->ledger_lock);
        e = fo->ledger[i];
        pthread_mutex_unlock(&fo->ledger_lock);
        if (e.done) continue;

        qihse_cluster_node_t owner;
        bool healthy = qihse_cluster_topology_get_node(fo->topology, e.failed_index, &owner) &&
                       owner.healthy;
        pthread_mutex_lock(&fo->ledger_lock);
        /* Require CONTINUOUS health: a flapping node must not trigger a bulk
         * transfer that its next blip would immediately invalidate. */
        if (!healthy) fo->ledger[i].healthy_since_ms = 0;
        else if (fo->ledger[i].healthy_since_ms == 0) fo->ledger[i].healthy_since_ms = now;
        e = fo->ledger[i];
        pthread_mutex_unlock(&fo->ledger_lock);
        if (!healthy || now - e.healthy_since_ms < fo->stable_ms || now < e.next_attempt_ms)
            continue;

        /* Hand back only what we still own: the range may have been split or
         * re-homed (operator, brain) since the takeover. */
        bool any_ours = false, all_ok = true;
        uint32_t s = e.start;
        while (s <= e.end) {
            if (!fo_slot_is_ours(fo, s)) { s++; continue; }
            uint32_t r = s;
            while (r + 1u <= e.end && fo_slot_is_ours(fo, r + 1u)) r++;
            any_ours = true;
            char err[256];
            err[0] = '\0';
            int rc = fo->failback_fn(fo->failback_user, (uint16_t)s, (uint16_t)r,
                                     e.failed_index, err, sizeof(err));
            if (rc == 0) {
                fprintf(stderr, "qihse-cluster-failback: slots %u-%u handed back to node %u\n",
                        (unsigned)s, (unsigned)r, (unsigned)e.failed_index);
            } else {
                all_ok = false;
                fprintf(stderr, "qihse-cluster-failback: slots %u-%u to node %u failed: %s "
                        "(will retry)\n", (unsigned)s, (unsigned)r, (unsigned)e.failed_index,
                        err[0] ? err : "unspecified");
            }
            s = r + 1u;
        }

        pthread_mutex_lock(&fo->ledger_lock);
        if (!any_ours || all_ok) {
            fo->ledger[i].done = true;
            if (any_ours) fo->failbacks++;
        } else {
            uint32_t attempts = ++fo->ledger[i].attempts;
            uint32_t shift = attempts > 6u ? 6u : attempts;
            fo->ledger[i].next_attempt_ms = fo_now_ms() + ((uint64_t)fo->poll_ms << shift);
        }
        pthread_mutex_unlock(&fo->ledger_lock);
    }

    /* Compact finished entries. Only this thread removes; record() only appends. */
    pthread_mutex_lock(&fo->ledger_lock);
    size_t w = 0;
    for (size_t i = 0; i < fo->ledger_count; i++) {
        if (fo->ledger[i].done) continue;
        if (w != i) fo->ledger[w] = fo->ledger[i];
        w++;
    }
    fo->ledger_count = w;
    pthread_mutex_unlock(&fo->ledger_lock);
}

static void fo_failback_pass(qihse_cluster_failover_t* fo) {
    if (!fo->maintenance_gate) { fo_failback_pass_inner(fo); return; }
    if (!qihse_cluster_maintenance_enter(fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER)) return;
    fo_failback_pass_inner(fo);
    qihse_cluster_maintenance_leave(fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER);
}

static void* fo_failback_main(void* arg) {
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)arg;
    while (!__atomic_load_n(&fo->stop, __ATOMIC_ACQUIRE)) {
        if (fo->ct_auto_successor_id[0]) {
            char generation[33]; uint16_t successor;
            pthread_mutex_lock(&fo->lock);
            memcpy(generation, fo->ct_pending_generation, sizeof(generation));
            successor = fo->ct_pending_successor;
            bool paused = fo->startup_paused;
            pthread_mutex_unlock(&fo->lock);
            if (!paused && generation[0]) {
                bool admitted = !fo->maintenance_gate || qihse_cluster_maintenance_enter(
                    fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER);
                if (admitted) {
                    bool complete = fo->ct_complete(fo->ct_complete_context,
                        successor, generation);
                    if (complete) {
                        pthread_mutex_lock(&fo->lock);
                        if (!strcmp(generation, fo->ct_pending_generation))
                            fo->ct_pending_generation[0] = '\0';
                        pthread_mutex_unlock(&fo->lock);
                    }
                    if (fo->maintenance_gate) qihse_cluster_maintenance_leave(
                        fo->maintenance_gate, QIHSE_MAINT_WRITER_FAILOVER);
                }
            } else if (!paused) {
                qihse_cluster_node_t local;
                if (qihse_cluster_topology_get_node(fo->topology, fo->local_node_index,
                        &local) && local.role == QIHSE_CLUSTER_NODE_REPLICA &&
                    local.primary_index != QIHSE_CLUSTER_NODE_NONE)
                    qihse_cluster_failover_handle(fo, local.primary_index);
            }
        }
        if (fo->failback_fn) fo_failback_pass(fo);
        /* Sleep in short slices so destroy() never waits a full poll interval. */
        for (uint32_t slept = 0; slept < fo->poll_ms &&
                                 !__atomic_load_n(&fo->stop, __ATOMIC_ACQUIRE); slept += 20u) {
            struct timespec ts = {0, 20L * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

void qihse_cluster_failover_on_takeover_cb(qihse_cluster_topology_t* topology,
                                           uint16_t previous_owner_index,
                                           uint16_t start, uint16_t end,
                                           void* user_data) {
    (void)topology;
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)user_data;
    if (!fo || !fo->failback_fn) return;
    /* Called with the bus lock held: never acquire fo->lock here, since
     * promotion holds it while broadcasting. Gossip is not fenced by the
     * hold: retain the debt, but the worker must not transfer until release. */
    fo_ledger_record(fo, previous_owner_index, start, end);
}

uint64_t qihse_cluster_failover_failbacks(const qihse_cluster_failover_t* fo) {
    if (!fo) return 0u;
    qihse_cluster_failover_t* m = (qihse_cluster_failover_t*)fo;
    pthread_mutex_lock(&m->ledger_lock);
    uint64_t v = m->failbacks;
    pthread_mutex_unlock(&m->ledger_lock);
    return v;
}

size_t qihse_cluster_failover_pending_failbacks(const qihse_cluster_failover_t* fo) {
    if (!fo) return 0u;
    qihse_cluster_failover_t* m = (qihse_cluster_failover_t*)fo;
    pthread_mutex_lock(&m->ledger_lock);
    size_t pending = 0;
    for (size_t i = 0; i < m->ledger_count; i++)
        if (!m->ledger[i].done) pending++;
    pthread_mutex_unlock(&m->ledger_lock);
    return pending;
}
