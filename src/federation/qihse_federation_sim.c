/*
 * QIHSE deterministic distributed simulation — federation stage F8.
 * See docs/plans/qihse_federation_upgrade_plan.md §44.1.
 *
 * Everything here is deterministic: the PRNG is seeded, and time comes from
 * the virtual clock.  No wall-clock reads, no threads, no real sockets, so a
 * scenario with a given seed produces identical results on every run.
 */
#include "qihse_federation_sim.h"

#include <stdio.h>
#include <string.h>

/* ── Deterministic PRNG (splitmix64) ───────────────────────────────────── */

void qihse_sim_rng_seed(qihse_sim_rng_t* rng, uint64_t seed) {
    if (!rng) return;
    /* Avoid the all-zero state, which splitmix64 handles but which makes
     * "did I seed this?" debugging harder. */
    rng->state = seed ? seed : 0x9E3779B97F4A7C15ULL;
}

uint64_t qihse_sim_rng_next(qihse_sim_rng_t* rng) {
    if (!rng) return 0;
    rng->state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = rng->state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

uint32_t qihse_sim_rng_below(qihse_sim_rng_t* rng, uint32_t bound) {
    if (bound == 0) return 0;
    return (uint32_t)(qihse_sim_rng_next(rng) % (uint64_t)bound);
}

bool qihse_sim_rng_chance(qihse_sim_rng_t* rng, uint32_t permille) {
    if (permille == 0) return false;
    if (permille >= 1000u) return true;
    return qihse_sim_rng_below(rng, 1000u) < permille;
}

/* ── Fault configuration ───────────────────────────────────────────────── */

void qihse_sim_faults_init(qihse_sim_faults_t* faults) {
    if (!faults) return;
    memset(faults, 0, sizeof(*faults));
    /* A healthy network by default: scenarios opt into faults explicitly so a
     * failure is always attributable to the fault that was injected. */
    faults->loss_permille = 0;
    faults->duplication_permille = 0;
    faults->reorder_permille = 0;
    faults->delay_ms = 1;
    faults->jitter_ms = 0;
    faults->crash_disk_writes = false;
    faults->disk_fail_permille = 0;
}

/* ── Simulation lifecycle ──────────────────────────────────────────────── */

void qihse_sim_init(qihse_sim_t* sim, uint64_t seed, size_t node_count) {
    if (!sim) return;
    memset(sim, 0, sizeof(*sim));
    qihse_sim_rng_seed(&sim->rng, seed);
    qihse_sim_faults_init(&sim->faults);
    sim->now_ms = 1000000u; /* start at a non-zero virtual time */
    if (node_count > QIHSE_SIM_MAX_NODES) node_count = QIHSE_SIM_MAX_NODES;
    sim->node_count = node_count;

    for (size_t i = 0; i < node_count; i++) {
        qihse_sim_node_t* n = &sim->nodes[i];
        n->status = QIHSE_SIM_NODE_UP;
        n->clock_offset_ms = 0;
        n->clock_synced = true;
        n->restarts = 0;

        /* Deterministic identities derived from the seed and index, so the
         * same seed always produces the same cluster. */
        char seed_buf[64];
        snprintf(seed_buf, sizeof(seed_buf), "sim-node-%llu-%zu",
                 (unsigned long long)seed, i);
        (void)qihse_uuid_from_seed(seed_buf, strlen(seed_buf), &n->node_id);
        snprintf(seed_buf, sizeof(seed_buf), "sim-boot-%llu-%zu-0",
                 (unsigned long long)seed, i);
        (void)qihse_uuid_from_seed(seed_buf, strlen(seed_buf), &n->boot_id);
    }
}

/* ── Virtual clock ─────────────────────────────────────────────────────── */

void qihse_sim_advance(qihse_sim_t* sim, uint64_t ms) {
    if (!sim) return;
    sim->now_ms += ms;
}

uint64_t qihse_sim_wall_ms(const qihse_sim_t* sim, size_t node) {
    if (!sim) return 0;
    if (node >= sim->node_count) return sim->now_ms;
    int64_t base = (int64_t)sim->now_ms;
    int64_t effective = base + sim->nodes[node].clock_offset_ms;
    if (effective < 0) effective = 0;
    return (uint64_t)effective;
}

uint64_t qihse_sim_mono_ms(const qihse_sim_t* sim, size_t node) {
    (void)node;
    if (!sim) return 0;
    /* The monotonic clock is immune to the per-node offset, which is exactly
     * the property that lets a scenario prove HLC ordering survives a bad
     * wall clock. */
    return sim->now_ms;
}

/* ── Node lifecycle ────────────────────────────────────────────────────── */

void qihse_sim_crash_node(qihse_sim_t* sim, size_t node) {
    if (!sim || node >= sim->node_count) return;
    sim->nodes[node].status = QIHSE_SIM_NODE_CRASHED;
    sim->nodes[node].clock_synced = false;
}

void qihse_sim_restart_node(qihse_sim_t* sim, size_t node) {
    if (!sim || node >= sim->node_count) return;
    qihse_sim_node_t* n = &sim->nodes[node];
    n->status = QIHSE_SIM_NODE_UP;
    n->restarts++;
    /* A restart is a new boot session, so the old boot UUID is now stale.
     * This is what makes an old packet replay detectable. */
    char seed_buf[64];
    snprintf(seed_buf, sizeof(seed_buf), "sim-boot-%zu-%u",
             node, n->restarts);
    (void)qihse_uuid_from_seed(seed_buf, strlen(seed_buf), &n->boot_id);
    n->clock_synced = true;
}

void qihse_sim_set_clock_offset(qihse_sim_t* sim, size_t node, int64_t offset_ms) {
    if (!sim || node >= sim->node_count) return;
    sim->nodes[node].clock_offset_ms = offset_ms;
}

void qihse_sim_set_clock_synced(qihse_sim_t* sim, size_t node, bool synced) {
    if (!sim || node >= sim->node_count) return;
    sim->nodes[node].clock_synced = synced;
}

/* ── Partition control ─────────────────────────────────────────────────── */

void qihse_sim_partition(qihse_sim_t* sim, size_t a, size_t b, bool blocked) {
    if (!sim || a >= sim->node_count || b >= sim->node_count) return;
    sim->partition[a][b] = blocked;
}

void qihse_sim_isolate(qihse_sim_t* sim, size_t node) {
    if (!sim || node >= sim->node_count) return;
    /* Block both directions for every peer, but leave the other peers able to
     * talk to each other: this is a single-node isolation, not a split. */
    for (size_t i = 0; i < sim->node_count; i++) {
        if (i == node) continue;
        sim->partition[node][i] = true;
        sim->partition[i][node] = true;
    }
}

void qihse_sim_heal_all(qihse_sim_t* sim) {
    if (!sim) return;
    memset(sim->partition, 0, sizeof(sim->partition));
}

/* ── Message delivery ──────────────────────────────────────────────────── */

qihse_sim_verdict_t qihse_sim_route(qihse_sim_t* sim, size_t from, size_t to) {
    if (!sim || from >= sim->node_count || to >= sim->node_count) return QIHSE_SIM_DROP;
    if (from == to) return QIHSE_SIM_DELIVER_ONCE;

    sim->messages_sent++;

    /* A crashed or paused endpoint cannot send or receive. */
    if (sim->nodes[from].status != QIHSE_SIM_NODE_UP ||
        sim->nodes[to].status != QIHSE_SIM_NODE_UP) {
        sim->messages_dropped++;
        return QIHSE_SIM_DROP;
    }
    /* Partition (checked in the direction of travel, so asymmetric splits
     * behave correctly). */
    if (sim->partition[from][to]) {
        sim->messages_dropped++;
        return QIHSE_SIM_DROP;
    }
    if (qihse_sim_rng_chance(&sim->rng, sim->faults.loss_permille)) {
        sim->messages_dropped++;
        return QIHSE_SIM_DROP;
    }
    if (qihse_sim_rng_chance(&sim->rng, sim->faults.reorder_permille)) {
        sim->messages_reordered++;
    }
    if (qihse_sim_rng_chance(&sim->rng, sim->faults.duplication_permille)) {
        sim->messages_duplicated++;
        sim->messages_delivered += 2u;
        return QIHSE_SIM_DELIVER_TWICE;
    }
    sim->messages_delivered++;
    return QIHSE_SIM_DELIVER_ONCE;
}

bool qihse_sim_disk_write_fails(qihse_sim_t* sim, size_t node) {
    if (!sim || node >= sim->node_count) return true;
    if (!sim->faults.crash_disk_writes) return false;
    return qihse_sim_rng_chance(&sim->rng, sim->faults.disk_fail_permille);
}

uint64_t qihse_sim_latency_ms(qihse_sim_t* sim) {
    if (!sim) return 0;
    uint64_t latency = sim->faults.delay_ms;
    if (sim->faults.jitter_ms > 0) {
        latency += qihse_sim_rng_below(&sim->rng, (uint32_t)sim->faults.jitter_ms + 1u);
    }
    return latency;
}

/* ── Scenario assertions ───────────────────────────────────────────────── */

/* Can `from` reach `to` right now?  Used for quorum evaluation; mirrors the
 * routing decision minus the probabilistic faults, because quorum is a
 * topological question, not a packet-loss question. */
static bool sim_reachable(const qihse_sim_t* sim, size_t from, size_t to) {
    if (!sim || from >= sim->node_count || to >= sim->node_count) return false;
    if (from == to) return sim->nodes[from].status == QIHSE_SIM_NODE_UP;
    if (sim->nodes[from].status != QIHSE_SIM_NODE_UP) return false;
    if (sim->nodes[to].status != QIHSE_SIM_NODE_UP) return false;
    return !sim->partition[from][to];
}

void qihse_sim_evaluate_quorum(const qihse_sim_t* sim, size_t from,
                               const qihse_federation_group_t* group,
                               qihse_sim_quorum_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!sim || !group) return;

    for (size_t i = 0; i < group->member_count; i++) {
        const qihse_federation_group_member_t* m = &group->members[i];
        /* Find the member in the simulation by node UUID. */
        for (size_t j = 0; j < sim->node_count; j++) {
            if (!qihse_uuid_equal(&sim->nodes[j].node_id, &m->member_id)) continue;
            bool reachable = sim_reachable(sim, from, j);
            if (m->is_witness) {
                if (reachable) out->witnesses_reachable++;
            } else if (m->is_voter) {
                out->voters_total++;
                if (reachable) out->voters_reachable++;
            }
            break;
        }
    }

    /* Strict majority of voters.  A witness can break a tie only when the
     * voters are evenly split and no majority exists on its own. */
    if (out->voters_total == 0) {
        out->quorum = false;
    } else if (out->voters_reachable * 2u > out->voters_total) {
        out->quorum = true;
    } else if (out->voters_total == 2u && out->voters_reachable == 1u &&
               out->witnesses_reachable >= 1u) {
        out->quorum = true;
    } else {
        out->quorum = false;
    }
}

void qihse_sim_assert_init(qihse_sim_assert_t* a) {
    if (!a) return;
    memset(a, 0, sizeof(*a));
}

bool qihse_sim_expect(qihse_sim_assert_t* a, bool condition, const char* message) {
    if (!a) return condition;
    a->checks++;
    if (!condition) {
        a->failures++;
        snprintf(a->last_failure, sizeof(a->last_failure), "%s",
                 message ? message : "(no message)");
    }
    return condition;
}
