#include "qihse_cluster_failover.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_maintenance.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_platform.h"
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

static qihse_cluster_failover_t* fo_create(const qihse_cluster_failover_config_t* config,
                                            bool paused) {
    if (!config || !config->topology) return NULL;
    if (strnlen(config->ct_local_qkp_id, sizeof(config->ct_local_qkp_id)) >=
        sizeof(config->ct_local_qkp_id)) return NULL;
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)calloc(1, sizeof(*fo));
    if (!fo) return NULL;
    fo->startup_paused = paused;
    fo->topology = config->topology;
    fo->bus = config->bus;
    fo->maintenance_gate = config->maintenance_gate;
    fo->ct_store = config->ct_store;
    fo->ct_principal = config->ct_principal;
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
