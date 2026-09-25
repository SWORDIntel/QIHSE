#ifndef QIHSE_FEDERATION_SIM_H
#define QIHSE_FEDERATION_SIM_H

/*
 * QIHSE deterministic distributed simulation — federation stage F8.
 * See docs/plans/qihse_federation_upgrade_plan.md §44.1 (deterministic distributed simulation).
 *
 * The simulator provides a virtual clock, a seeded PRNG, and fault injectors
 * for packet loss, duplication, reordering, delay, partition (including
 * asymmetric), process crash, disk write failure, and stale clocks.
 *
 * It deliberately does NOT reimplement the federation protocol.  Scenarios
 * drive the real F1–F7 entry points and use this harness only to decide what
 * the network and the hosts do between calls.  That way a passing scenario is
 * evidence about the shipped code, not about a parallel model of it.
 *
 * Determinism: every injector decision comes from the seeded PRNG, and all
 * time comes from the virtual clock, so a scenario with a given seed and
 * schedule produces byte-identical results on every run and every machine.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_SIM_MAX_NODES 8u

/* ── Deterministic PRNG ────────────────────────────────────────────────── */

typedef struct {
    uint64_t state;
} qihse_sim_rng_t;

void qihse_sim_rng_seed(qihse_sim_rng_t* rng, uint64_t seed);
uint64_t qihse_sim_rng_next(qihse_sim_rng_t* rng);
/* Uniform in [0, bound). Returns 0 when bound is 0. */
uint32_t qihse_sim_rng_below(qihse_sim_rng_t* rng, uint32_t bound);
/* True with probability permille/1000. */
bool qihse_sim_rng_chance(qihse_sim_rng_t* rng, uint32_t permille);

/* ── Fault configuration ───────────────────────────────────────────────── */

typedef struct {
    uint32_t loss_permille;        /* drop a message */
    uint32_t duplication_permille; /* deliver a message twice */
    uint32_t reorder_permille;     /* deliver out of order */
    uint64_t delay_ms;             /* base one-way delay */
    uint64_t jitter_ms;            /* additional uniform jitter */
    bool crash_disk_writes;        /* make disk writes fail */
    uint32_t disk_fail_permille;   /* probability a write fails */
} qihse_sim_faults_t;

void qihse_sim_faults_init(qihse_sim_faults_t* faults);

/* ── Simulation state ──────────────────────────────────────────────────── */

typedef enum {
    QIHSE_SIM_NODE_UP = 0,
    QIHSE_SIM_NODE_CRASHED,
    QIHSE_SIM_NODE_PAUSED      /* stopped but not crashed (e.g. mid-snapshot) */
} qihse_sim_node_status_t;

typedef struct {
    qihse_uuid_t node_id;
    qihse_sim_node_status_t status;
    /* Virtual wall clock offset for this node, in milliseconds.  Negative
     * offsets are expressed by a large unsigned value subtracted from the
     * global clock; use qihse_sim_wall_ms() to read the effective time. */
    int64_t clock_offset_ms;
    bool clock_synced;
    /* Boot/session UUID: changes when a node restarts, which is what makes
     * an old packet's boot id detectably stale. */
    qihse_uuid_t boot_id;
    uint32_t restarts;
} qihse_sim_node_t;

typedef struct {
    qihse_sim_rng_t rng;
    qihse_sim_faults_t faults;
    uint64_t now_ms;                 /* virtual clock */
    size_t node_count;
    qihse_sim_node_t nodes[QIHSE_SIM_MAX_NODES];
    /* partition[a][b] == true means a cannot reach b (asymmetric-capable). */
    bool partition[QIHSE_SIM_MAX_NODES][QIHSE_SIM_MAX_NODES];
    /* Counters for observability assertions. */
    uint64_t messages_sent;
    uint64_t messages_dropped;
    uint64_t messages_duplicated;
    uint64_t messages_reordered;
    uint64_t messages_delivered;
} qihse_sim_t;

/* Initialise with a seed and `node_count` nodes.  Node UUIDs and boot UUIDs
 * are derived deterministically from the seed so scenarios are reproducible. */
void qihse_sim_init(qihse_sim_t* sim, uint64_t seed, size_t node_count);

/* ── Virtual clock ─────────────────────────────────────────────────────── */

void qihse_sim_advance(qihse_sim_t* sim, uint64_t ms);
/* Effective wall-clock reading for a node, including its offset. */
uint64_t qihse_sim_wall_ms(const qihse_sim_t* sim, size_t node);
/* Monotonic reading for a node: never affected by clock offsets. */
uint64_t qihse_sim_mono_ms(const qihse_sim_t* sim, size_t node);

/* ── Node lifecycle ────────────────────────────────────────────────────── */

void qihse_sim_crash_node(qihse_sim_t* sim, size_t node);
/* Restart assigns a NEW boot UUID and clears the crash, which is how a
 * scenario proves that a packet from the previous boot is rejected. */
void qihse_sim_restart_node(qihse_sim_t* sim, size_t node);
void qihse_sim_set_clock_offset(qihse_sim_t* sim, size_t node, int64_t offset_ms);
void qihse_sim_set_clock_synced(qihse_sim_t* sim, size_t node, bool synced);

/* ── Partition control (asymmetric) ────────────────────────────────────── */

void qihse_sim_partition(qihse_sim_t* sim, size_t a, size_t b, bool blocked);
void qihse_sim_isolate(qihse_sim_t* sim, size_t node);
void qihse_sim_heal_all(qihse_sim_t* sim);

/* ── Message delivery decision ─────────────────────────────────────────── */

typedef enum {
    QIHSE_SIM_DELIVER_ONCE = 0,
    QIHSE_SIM_DELIVER_TWICE,
    QIHSE_SIM_DROP
} qihse_sim_verdict_t;

/* Decide what happens to one message from `from` to `to`.  Consults the
 * partition matrix, node status, and the fault probabilities. */
qihse_sim_verdict_t qihse_sim_route(qihse_sim_t* sim, size_t from, size_t to);

/* Whether a disk write on this node should fail right now. */
bool qihse_sim_disk_write_fails(qihse_sim_t* sim, size_t node);

/* One-way latency for a message, honouring the delay and jitter config. */
uint64_t qihse_sim_latency_ms(qihse_sim_t* sim);

/* ── Scenario bookkeeping ──────────────────────────────────────────────── */

/* Quorum evaluation for a scoped replication group (plan §15).
 *
 * Quorum is per group, never whole-federation: a group whose voters are
 * unreachable must not be able to commit, while an unrelated group whose
 * voters are reachable must be unaffected.  A reachable witness breaks a
 * tie without being able to form quorum on its own. */
typedef struct {
    size_t voters_reachable;
    size_t voters_total;
    size_t witnesses_reachable;
    bool quorum;
} qihse_sim_quorum_t;

void qihse_sim_evaluate_quorum(const qihse_sim_t* sim, size_t from,
                               const qihse_federation_group_t* group,
                               qihse_sim_quorum_t* out);

/* A tiny assertion helper so scenarios can report which invariant broke.
 * Returns true when `condition` holds; on failure it records the message. */
typedef struct {
    uint32_t checks;
    uint32_t failures;
    char last_failure[192];
} qihse_sim_assert_t;

void qihse_sim_assert_init(qihse_sim_assert_t* a);
bool qihse_sim_expect(qihse_sim_assert_t* a, bool condition, const char* message);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_SIM_H */
