#include "qihse_cluster_failover.h"
#include "qihse_cluster_bus.h"
#include "qihse_platform.h"
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
    uint16_t local_node_index;
    bool single_coordinator;
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
    fo_ledger_entry_t ledger[FO_LEDGER_MAX];
    size_t ledger_count;
    uint64_t failbacks;
    pthread_t worker;
    bool worker_started;
    int stop;
};

static void* fo_failback_main(void* arg);

qihse_cluster_failover_t* qihse_cluster_failover_create(const qihse_cluster_failover_config_t* config) {
    if (!config || !config->topology) return NULL;
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)calloc(1, sizeof(*fo));
    if (!fo) return NULL;
    fo->topology = config->topology;
    fo->bus = config->bus;
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
    if (fo->failback_fn) {
        if (pthread_create(&fo->worker, NULL, fo_failback_main, fo) == 0) {
            fo->worker_started = true;
        } else {
            /* No worker means no failback; failover itself still works. */
            fo->failback_fn = NULL;
        }
    }
    return fo;
}

void qihse_cluster_failover_destroy(qihse_cluster_failover_t* fo) {
    if (!fo) return;
    if (fo->worker_started) {
        __atomic_store_n(&fo->stop, 1, __ATOMIC_RELEASE);
        pthread_join(fo->worker, NULL);
    }
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
    if (fo->ledger_count < FO_LEDGER_MAX) {
        fo_ledger_entry_t* e = &fo->ledger[fo->ledger_count++];
        memset(e, 0, sizeof(*e));
        e->failed_index = failed;
        e->start = start;
        e->end = end;
        fprintf(stderr, "qihse-cluster-failback: ledgered slots %u-%u taken over from node %u\n",
                (unsigned)start, (unsigned)end, (unsigned)failed);
    } else {
        fprintf(stderr, "qihse-cluster-failback: ledger full, slots %u-%u from node %u will not be failed back\n",
                (unsigned)start, (unsigned)end, (unsigned)failed);
    }
    pthread_mutex_unlock(&fo->ledger_lock);
}

bool qihse_cluster_failover_promote(qihse_cluster_failover_t* fo,
                                    uint16_t failed_primary_index,
                                    uint16_t replica_index) {
    if (!fo || !fo->topology) return false;
    if (failed_primary_index == QIHSE_CLUSTER_NODE_NONE || replica_index == QIHSE_CLUSTER_NODE_NONE) return false;

    qihse_cluster_node_t replica;
    if (!qihse_cluster_topology_get_node(fo->topology, replica_index, &replica)) return false;
    /* Valid successors: a dedicated REPLICA of the failed primary, or (the
     * sharded-cluster fallback) another healthy PRIMARY with the most
     * continuous presence. A failed/unhealthy successor is never chosen. */
    if (replica.role != QIHSE_CLUSTER_NODE_REPLICA && replica.role != QIHSE_CLUSTER_NODE_PRIMARY) return false;
    if (!replica.healthy) return false;

    /* A successor that was ALREADY a primary is the sharded fallback (no
     * replica held this data): that takeover is the one failback undoes. A
     * dedicated replica promoted here carries the data and the old primary
     * rejoins as its replica, so it is not ledgered. */
    bool fallback_takeover = replica.role == QIHSE_CLUSTER_NODE_PRIMARY;

    /* Promote the successor to primary */
    replica.role = QIHSE_CLUSTER_NODE_PRIMARY;
    replica.primary_index = QIHSE_CLUSTER_NODE_NONE;
    replica.healthy = true;
    qihse_cluster_topology_upsert_node(fo->topology, &replica, NULL);

    /* Reassign all slot ranges owned by the failed primary to the promoted
     * replica. Heap, not a QIHSE_CLUSTER_SLOT_COUNT array on the stack: that
     * was ~96 KB of frame, the same defect the brain carried. */
    qihse_cluster_slot_range_t* ranges = (qihse_cluster_slot_range_t*)malloc(
        QIHSE_CLUSTER_SLOT_COUNT * sizeof(qihse_cluster_slot_range_t));
    if (!ranges) return false;
    size_t range_count = qihse_cluster_topology_ranges(fo->topology, ranges, QIHSE_CLUSTER_SLOT_COUNT);
    for (size_t i = 0; i < range_count; i++) {
        if (ranges[i].owner_index == failed_primary_index) {
            qihse_cluster_topology_assign_range(fo->topology, ranges[i].start, ranges[i].end, replica_index);
            if (fo->bus) qihse_cluster_bus_broadcast_slot_update(fo->bus, ranges[i].start, ranges[i].end, replica_index);
            if (fallback_takeover && fo->failback_fn && replica_index == fo->local_node_index)
                fo_ledger_record(fo, failed_primary_index, ranges[i].start, ranges[i].end);
        }
    }
    free(ranges);

    /* Broadcast the node role update */
    if (fo->bus) qihse_cluster_bus_broadcast_node_update(fo->bus, replica_index);

    return true;
}

uint16_t qihse_cluster_failover_handle(qihse_cluster_failover_t* fo,
                                       uint16_t failed_node_index) {
    if (!fo || !fo->topology) return QIHSE_CLUSTER_NODE_NONE;
    pthread_mutex_lock(&fo->lock);
    /* cooldown: while a dead node REMAINS unhealthy the bus re-fires on_fail
     * every cycle; promote is idempotent but the broadcasts are not free */
    if (fo->last_attempt_ms && fo_now_ms() - fo->last_attempt_ms < 30000u) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
    }
    fo->last_attempt_ms = fo_now_ms();

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
        /* Check if the local node is the coordinator (lowest-index healthy primary) */
        uint16_t coordinator = fo_find_coordinator(fo->topology);
        if (coordinator != fo->local_node_index) {
            pthread_mutex_unlock(&fo->lock);
            return QIHSE_CLUSTER_NODE_NONE;
        }
    }

    uint16_t replica = qihse_cluster_failover_best_replica(fo->topology, failed_node_index);
    if (replica == QIHSE_CLUSTER_NODE_NONE) {
        /* Sharded-cluster fallback: no dedicated replica exists, so the
         * healthy node with the LONGEST CONTINUOUS PRESENCE (most uptime as
         * observed on our bus) succeeds the failed primary and inherits its
         * slot ranges. Its data must have been duplicated by the redundancy
         * link; anything not duplicated is lost with the failed node — that
         * is the documented cost of the phase-1 redundancy design. */
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

    bool promoted = qihse_cluster_failover_promote(fo, failed_node_index, replica);
    if (promoted) {
        fo->failover_events++;
        fprintf(stderr, "qihse-cluster-failover: node %u failed; node %u takes its slots%s\n",
                (unsigned)failed_node_index, (unsigned)replica,
                replica == fo->local_node_index ? " (this node)" : "");
    }
    pthread_mutex_unlock(&fo->lock);
    return promoted ? replica : QIHSE_CLUSTER_NODE_NONE;
}

void qihse_cluster_failover_on_fail_cb(qihse_cluster_topology_t* topology,
                                       uint16_t failed_node_index,
                                       void* user_data) {
    (void)topology;
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)user_data;
    if (!fo) return;
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
static void fo_failback_pass(qihse_cluster_failover_t* fo) {
    uint64_t now = fo_now_ms();
    pthread_mutex_lock(&fo->ledger_lock);
    size_t n = fo->ledger_count;
    pthread_mutex_unlock(&fo->ledger_lock);

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

static void* fo_failback_main(void* arg) {
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)arg;
    while (!__atomic_load_n(&fo->stop, __ATOMIC_ACQUIRE)) {
        fo_failback_pass(fo);
        /* Sleep in short slices so destroy() never waits a full poll interval. */
        for (uint32_t slept = 0; slept < fo->poll_ms &&
                                 !__atomic_load_n(&fo->stop, __ATOMIC_ACQUIRE); slept += 20u) {
            struct timespec ts = {0, 20L * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
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
