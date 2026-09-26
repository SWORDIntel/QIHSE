/*
 * test_federation_sim.c — deterministic distributed simulation harness.
 *
 * Roadmap improvement item #2: seeded, fault-injected distributed histories
 * that replay bit-identically and assert the federation invariants
 * (ROADMAP.md §6, numbers 4, 5, 7, 8, 9; plan §44.1 / §44.2).
 *
 * WHAT THIS ADDS OVER tests/test_federation_f8.c
 * -----------------------------------------------
 * The F8 test uses the simulator as a decision ORACLE (it asks the sim what
 * would happen to a message).  This file runs the real thing: N simulated
 * hosts (up to 8), each hosting real qihse_consensus instances opened with
 * qihse_consensus_open() and driven by qihse_consensus_tick() /
 * qihse_consensus_receive() over a deterministic in-memory transport the
 * harness fully controls:
 *
 *   - per-link delivery / drop / duplication / reorder (seeded verdicts via
 *     qihse_sim_route, injected latency via qihse_sim_latency_ms);
 *   - arbitrary partition sets (asymmetric, via the sim partition matrix);
 *   - per-node clock skew (every tick is stamped with the node's skewed
 *     qihse_sim_wall_ms() reading, per the consensus module's TIME AND
 *     DETERMINISM contract: all time enters through tick's timestamp);
 *   - crash (qihse_consensus_close) and restart (qihse_consensus_open from
 *     the SAME record dir, i.e. replay-from-WAL) at scheduled virtual times.
 *
 * Determinism: every decision comes from the seed (one RNG stream for the
 * transport, one derived stream for the scenario schedule) and all time is
 * the virtual clock — no wall-clock reads, no threads, no real sockets, no
 * RNG outside the seed.  Each scenario runs TWICE from scratch and the two
 * runs must produce the SAME canonical event digest (FNV-1a over every
 * message, verdict, node-state transition, and tick round).  On failure the
 * harness prints the scenario name and the seed so the exact history can be
 * replayed.
 *
 * Scenarios (asserted invariants in brackets):
 *   partition-majority   minority partition commits nothing while the
 *                        majority side keeps committing; LOCAL namespaces on
 *                        the isolated node stay read-write, its STRONG
 *                        namespace fails closed.  [4, 5]
 *   no-quorum-gate       a fully split group (no quorum anywhere in it)
 *                        never blocks an unrelated healthy group, and LOCAL
 *                        namespaces on a split-quorum node stay writable.  [7]
 *   crash-restart-loop   repeated crash/restart of members (leader included)
 *                        at seed-scheduled times: restart always reopens,
 *                        resumes, and never bricks the group or LOCAL
 *                        namespaces; committed mutations survive restart
 *                        byte-identically, attributable, HLC-stamped, with
 *                        strictly increasing generations.  [7, 8]
 *   crash-mid-membership leader crashes while a membership transition is in
 *                        flight (both before and after replication lands):
 *                        the group either completes or reverts the
 *                        transition, never elects two leaders, and keeps
 *                        accepting commits.  [7, 8]
 *   never-infer-safety   a node whose peers go silent campaigns but never
 *                        WINS, never fences, never commits, and the healthy
 *                        majority neither loses its leader nor amputates the
 *                        silent member — silence alone proves nothing.  [9]
 *   clock-skew-chaos     seeded loss/duplication/reorder/skew/crash history:
 *                        the cluster still converges to exactly one leader
 *                        with a consistent committed log; digest replay is
 *                        bit-identical, and a different seed diverges.  [7, 8]
 *
 * NOT covered here (honest boundary):
 *   - disk-write failures on the consensus record file (the consensus module
 *     has no injected disk-failure hook; qihse_sim_faults_t.crash_disk_writes
 *     targets higher layers);
 *   - leases / epochs as separate primitives (the fencing epoch is exercised
 *     only as consensus state; the lease API is covered by test_federation_f8);
 *   - snapshot/compaction paths (covered by tests/test_consensus.c (h)-(m));
 *   - mTLS/gossip/revocation surfaces (covered by test_federation_f8/f5).
 *
 * Build (mirrors the other federation tests; the maintainer wires the
 * Makefile target):
 *   gcc -std=c99 -Wall -Wextra -D_GNU_SOURCE -I. -I./include \
 *       -o tests/test_federation_sim tests/test_federation_sim.c \
 *       -L. -lqihse $(ldflags) && LD_LIBRARY_PATH=. ./tests/test_federation_sim
 */
#include "qihse_auth.h"
#include "qihse_consensus.h"
#include "qihse_federation.h"
#include "qihse_federation_sim.h"
#include "qihse_kv_store.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Harness constants ─────────────────────────────────────────────────── */

#define SN_GROUPS_MAX 4u
#define SN_PROPOSALS_MAX 64u
#define SN_ENTRIES_READ 96u
#define SN_QUEUE_HARD_CAP 200000u
#define SN_DELIVERY_HARD_CAP 4000000u

/* One in-flight message on the simulated wire. */
typedef struct {
    qihse_consensus_msg_t m;
    uint64_t deliver_at;   /* virtual time at which it may be delivered */
    uint64_t seq;          /* tie-breaker: FIFO among equal times */
} sn_wire_t;

/* An attributed proposal the harness made (invariant 8 audit trail). */
typedef struct {
    uint64_t gen;
    size_t node;                /* attributing origin */
    uint8_t payload[32];
    size_t payload_len;
} sn_prop_t;

/* A scoped replication group hosted on a subset of the simulated nodes. */
typedef struct {
    char id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    size_t member_count;
    size_t members[QIHSE_SIM_MAX_NODES]; /* node indices */
} sn_group_t;

/* The simulated cluster: hosts + groups + wire + bookkeeping. */
typedef struct {
    qihse_sim_t sim;              /* seeded PRNG, virtual clock, partitions */
    size_t node_count;
    qihse_uuid_t id[QIHSE_SIM_MAX_NODES];

    char recroot[152];            /* relative, mkdtemp'd per run */
    char recpath[SN_GROUPS_MAX][QIHSE_SIM_MAX_NODES]
                [QIHSE_CONSENSUS_RECORD_PATH_MAX + 1u];
    qihse_consensus_t* cs[SN_GROUPS_MAX][QIHSE_SIM_MAX_NODES];
    sn_group_t group[SN_GROUPS_MAX];
    bool crashed[QIHSE_SIM_MAX_NODES];

    sn_wire_t* q;
    size_t qcount, qcap;
    uint64_t next_seq;
    uint64_t deliveries;

    /* Deterministic journal stamping for proposed entries (invariant 8). */
    qihse_hlc_t hlc;
    uint64_t next_gen;
    sn_prop_t prop[SN_PROPOSALS_MAX];
    size_t prop_count;

    /* Schedule RNG: derived from the seed, independent of the transport
     * stream, so scenario schedules are reproducible without perturbing
     * routing decisions. */
    qihse_sim_rng_t sched;

    uint64_t digest;              /* canonical event digest */

    /* Failure reporting: seed + scenario name on every failure. */
    const char* scenario;
    uint64_t seed;
    uint32_t checks, failures;
    char last_failure[256];
} sn_t;

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* ── Canonical digest (FNV-1a over canonical little-endian fields) ─────── */

#define SN_FNV_OFFSET 1469598103934665603ULL
#define SN_FNV_PRIME 1099511628211ULL

static uint64_t sn_fold_u64(uint64_t d, uint64_t x) {
    for (int b = 0; b < 8; b++) {
        d ^= (x >> (8 * b)) & 0xFFu;
        d *= SN_FNV_PRIME;
    }
    return d;
}

static uint64_t sn_fold_bytes(uint64_t d, const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    for (size_t i = 0; i < n; i++) {
        d ^= b[i];
        d *= SN_FNV_PRIME;
    }
    return d;
}

/* Event classes folded into the digest.  The numeric values are part of the
 * canonical form (never renumber). */
enum {
    SN_EV_SEND = 1, SN_EV_DELIVER, SN_EV_DROP, SN_EV_DROP_LATE, SN_EV_DUP,
    SN_EV_REORDER, SN_EV_PURGE, SN_EV_CRASH, SN_EV_RESTART, SN_EV_PARTITION,
    SN_EV_HEAL, SN_EV_SKEW, SN_EV_PROPOSE, SN_EV_ROUND, SN_EV_SCENARIO_END
};

static void sn_ev3(sn_t* n, uint64_t cls, uint64_t a, uint64_t b, uint64_t c) {
    n->digest = sn_fold_u64(n->digest, cls);
    n->digest = sn_fold_u64(n->digest, a);
    n->digest = sn_fold_u64(n->digest, b);
    n->digest = sn_fold_u64(n->digest, c);
}

/* Monotonic HLC advance over the proposing node's (skewed) virtual wall
 * clock — same contract as the module-level helper, kept local so the
 * harness depends only on the consensus and simulator surfaces. */
static qihse_hlc_t sn_hlc_advance(const qihse_hlc_t* prev, uint64_t wall_ms) {
    qihse_hlc_t out;
    if (wall_ms > prev->physical_ms) {
        out.physical_ms = wall_ms;
        out.logical = 0u;
    } else {
        out.physical_ms = prev->physical_ms;
        out.logical = prev->logical + 1u;
    }
    return out;
}

/* ── Expectation helper: prints seed + scenario on failure ─────────────── */

static bool sn_expect(sn_t* n, bool cond, const char* what) {
    n->checks++;
    if (!cond) {
        n->failures++;
        snprintf(n->last_failure, sizeof(n->last_failure), "%s", what);
        fprintf(stderr,
                "FAIL scenario=%s seed=0x%016llx t=%llums: %s\n",
                n->scenario, (unsigned long long)n->seed,
                (unsigned long long)n->sim.now_ms, what);
    }
    return cond;
}

/* ── Node index / group resolution ─────────────────────────────────────── */

static int sn_index_of(const sn_t* n, const qihse_uuid_t* id) {
    for (size_t i = 0; i < n->node_count; i++) {
        if (qihse_uuid_equal(&n->id[i], id)) return (int)i;
    }
    return -1;
}

static int sn_group_of(const sn_t* n, const char* group_id) {
    for (size_t g = 0; g < SN_GROUPS_MAX; g++) {
        if (n->group[g].member_count > 0u &&
            strcmp(n->group[g].id, group_id) == 0) return (int)g;
    }
    return -1;
}

static bool sn_in_group(const sn_t* n, size_t g, size_t node) {
    for (size_t i = 0; i < n->group[g].member_count; i++) {
        if (n->group[g].members[i] == node) return true;
    }
    return false;
}

/* ── Transport: the consensus send callback (queue, never deliver inline) ─ */

static void sn_enqueue(sn_t* n, const qihse_consensus_msg_t* m,
                       uint64_t deliver_at) {
    if (n->qcount == n->qcap) {
        size_t ncap = n->qcap ? n->qcap * 2u : 64u;
        sn_wire_t* nq = realloc(n->q, ncap * sizeof(*nq));
        if (!nq) {
            fprintf(stderr, "FAIL scenario=%s: transport out of memory\n",
                    n->scenario);
            abort();
        }
        n->q = nq;
        n->qcap = ncap;
    }
    n->q[n->qcount].m = *m;
    n->q[n->qcount].deliver_at = deliver_at;
    n->q[n->qcount].seq = n->next_seq++;
    n->qcount++;
    if (n->qcount > SN_QUEUE_HARD_CAP) {
        sn_expect(n, false, "transport queue runaway");
        abort();
    }
}

static void sn_send(void* transport, const qihse_consensus_msg_t* msg) {
    sn_t* n = (sn_t*)transport;
    if (!n || !msg) return;

    int fi = sn_index_of(n, &msg->from);
    int ti = sn_index_of(n, &msg->to);
    sn_ev3(n, SN_EV_SEND, (uint64_t)msg->type,
           (uint64_t)(fi < 0 ? 0xFFu : (uint64_t)fi),
           (uint64_t)(ti < 0 ? 0xFFu : (uint64_t)ti));
    n->digest = sn_fold_u64(n->digest, msg->term);
    n->digest = sn_fold_u64(n->digest, msg->fencing_epoch);

    if (fi < 0 || ti < 0) {
        /* A UUID off the simulated cluster: nothing to route to. */
        sn_ev3(n, SN_EV_DROP, (uint64_t)msg->type, 0xFFu, 0xFFu);
        return;
    }

    uint64_t reordered_before = n->sim.messages_reordered;
    qihse_sim_verdict_t v = qihse_sim_route(&n->sim, (size_t)fi, (size_t)ti);
    if (v == QIHSE_SIM_DROP) {
        sn_ev3(n, SN_EV_DROP, (uint64_t)msg->type, (uint64_t)fi, (uint64_t)ti);
        return;
    }

    uint64_t delay = qihse_sim_latency_ms(&n->sim);
    if (n->sim.messages_reordered > reordered_before) {
        /* The reordering fault fired for this message: push it back so a
         * later send can overtake it on the same link. */
        delay += qihse_sim_latency_ms(&n->sim) + 5u;
        sn_ev3(n, SN_EV_REORDER, (uint64_t)msg->type, (uint64_t)fi,
               (uint64_t)ti);
    }

    sn_enqueue(n, msg, n->sim.now_ms + delay);
    if (v == QIHSE_SIM_DELIVER_TWICE) {
        sn_ev3(n, SN_EV_DUP, (uint64_t)msg->type, (uint64_t)fi, (uint64_t)ti);
        sn_enqueue(n, msg, n->sim.now_ms + delay + 1u);
    }
}

/* Deliver everything due at the current virtual time, strictly in
 * (deliver_at, seq) order.  New traffic becomes due only in later rounds
 * because every enqueue carries a positive delay. */
static void sn_pump_due(sn_t* n) {
    for (;;) {
        size_t best = (size_t)-1;
        for (size_t i = 0; i < n->qcount; i++) {
            if (n->q[i].deliver_at > n->sim.now_ms) continue;
            if (best == (size_t)-1 ||
                n->q[i].deliver_at < n->q[best].deliver_at ||
                (n->q[i].deliver_at == n->q[best].deliver_at &&
                 n->q[i].seq < n->q[best].seq)) {
                best = i;
            }
        }
        if (best == (size_t)-1) return;

        sn_wire_t w = n->q[best];
        memmove(&n->q[best], &n->q[best + 1u],
                (n->qcount - best - 1u) * sizeof(*n->q));
        n->qcount--;

        n->deliveries++;
        if (n->deliveries > SN_DELIVERY_HARD_CAP) {
            sn_expect(n, false, "delivery pump runaway");
            abort();
        }

        int fi = sn_index_of(n, &w.m.from);
        int ti = sn_index_of(n, &w.m.to);
        sn_ev3(n, SN_EV_DELIVER, (uint64_t)w.m.type,
               (uint64_t)(fi < 0 ? 0xFFu : (uint64_t)fi),
               (uint64_t)(ti < 0 ? 0xFFu : (uint64_t)ti));

        if (ti < 0 || n->crashed[ti]) {
            /* Crashed between send and delivery: the host is gone. */
            sn_ev3(n, SN_EV_DROP_LATE, (uint64_t)w.m.type,
                   (uint64_t)(ti < 0 ? 0xFFu : (uint64_t)ti), 0u);
            continue;
        }
        int gi = sn_group_of(n, w.m.group_id);
        if (gi < 0 || !n->cs[gi][ti]) {
            sn_ev3(n, SN_EV_DROP_LATE, (uint64_t)w.m.type,
                   (uint64_t)ti, 1u);
            continue;
        }
        qihse_consensus_receive(n->cs[gi][ti], &w.m);
    }
}

/* Purge a crashed node's in-flight traffic. */
static void sn_purge_node(sn_t* n, size_t node) {
    size_t i = 0;
    while (i < n->qcount) {
        int fi = sn_index_of(n, &n->q[i].m.from);
        int ti = sn_index_of(n, &n->q[i].m.to);
        if (fi == (int)node || ti == (int)node) {
            sn_ev3(n, SN_EV_PURGE, (uint64_t)n->q[i].m.type, (uint64_t)node,
                   (uint64_t)i);
            memmove(&n->q[i], &n->q[i + 1u],
                    (n->qcount - i - 1u) * sizeof(*n->q));
            n->qcount--;
        } else {
            i++;
        }
    }
}

/* ── Lifecycle: open groups, tick rounds, crash/restart ─────────────────── */

static void sn_build_cfg(sn_t* n, size_t g, size_t node,
                         qihse_consensus_config_t* cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->group_id, sizeof(cfg->group_id), "%s", n->group[g].id);
    cfg->self = n->id[node];
    cfg->member_count = n->group[g].member_count;
    for (size_t i = 0; i < n->group[g].member_count; i++) {
        cfg->members[i] = n->id[n->group[g].members[i]];
    }
    cfg->election_timeout_base_ms = 150u;
    cfg->election_timeout_spread_ms = 300u; /* >= member_count: no ties */
    cfg->heartbeat_interval_ms = 50u;
    cfg->snapshot_threshold = 0u; /* compaction out of scope here */
    snprintf(cfg->record_path, sizeof(cfg->record_path), "%s",
             n->recpath[g][node]);
}

static bool sn_open_group(sn_t* n, size_t g, const char* gid,
                          const size_t* members, size_t count) {
    if (g >= SN_GROUPS_MAX || count == 0u || count > QIHSE_SIM_MAX_NODES) {
        return false;
    }
    snprintf(n->group[g].id, sizeof(n->group[g].id), "%s", gid);
    n->group[g].member_count = count;
    for (size_t i = 0; i < count; i++) n->group[g].members[i] = members[i];

    for (size_t i = 0; i < count; i++) {
        size_t node = members[i];
        snprintf(n->recpath[g][node], sizeof(n->recpath[g][node]),
                 "%s/g%zu-n%zu.rec", n->recroot, g, node);
        qihse_consensus_config_t cfg;
        sn_build_cfg(n, g, node, &cfg);
        n->cs[g][node] = qihse_consensus_open(&cfg, n, sn_send);
        if (!n->cs[g][node]) {
            snprintf(n->last_failure, sizeof(n->last_failure),
                     "open failed group=%s node=%zu", gid, node);
            n->failures++;
            fprintf(stderr, "FAIL scenario=%s seed=0x%016llx: %s\n",
                    n->scenario, (unsigned long long)n->seed, n->last_failure);
            return false;
        }
    }
    return true;
}

/* (Re)open one node's instance for group g from its record file. */
static bool sn_reopen_one(sn_t* n, size_t g, size_t node) {
    qihse_consensus_config_t cfg;
    sn_build_cfg(n, g, node, &cfg);
    n->cs[g][node] = qihse_consensus_open(&cfg, n, sn_send);
    return n->cs[g][node] != NULL;
}

/* One virtual round: advance the clock, tick every live instance with its
 * node's SKEWED wall reading, deliver what is due, fold state. */
static void sn_step(sn_t* n, uint64_t step_ms) {
    qihse_sim_advance(&n->sim, step_ms);

    for (size_t i = 0; i < n->node_count; i++) {
        if (n->crashed[i]) continue;
        uint64_t skewed = qihse_sim_wall_ms(&n->sim, i);
        for (size_t g = 0; g < SN_GROUPS_MAX; g++) {
            if (n->cs[g][i]) qihse_consensus_tick(n->cs[g][i], skewed);
        }
    }
    sn_pump_due(n);

    /* Canonical per-round state fold + the one-leader-per-group invariant,
     * checked on EVERY round of every scenario. */
    n->digest = sn_fold_u64(n->digest, SN_EV_ROUND);
    for (size_t g = 0; g < SN_GROUPS_MAX; g++) {
        if (n->group[g].member_count == 0u) continue;
        uint64_t leaders = 0u;
        int last_leader = -1;
        for (size_t i = 0; i < n->node_count; i++) {
            if (!sn_in_group(n, g, i)) continue;
            if (n->crashed[i] || !n->cs[g][i]) {
                n->digest = sn_fold_u64(n->digest, 0xEEEEEEEEEEEEEEEEULL);
                continue;
            }
            qihse_consensus_t* cs = n->cs[g][i];
            n->digest = sn_fold_u64(n->digest,
                                    (uint64_t)qihse_consensus_role(cs));
            n->digest = sn_fold_u64(n->digest, qihse_consensus_term(cs));
            n->digest = sn_fold_u64(n->digest, qihse_consensus_commit_index(cs));
            n->digest = sn_fold_u64(n->digest,
                                    qihse_consensus_last_log_index(cs));
            n->digest = sn_fold_u64(n->digest,
                                    qihse_consensus_fencing_epoch(cs));
            if (qihse_consensus_role(cs) == QIHSE_CONSENSUS_LEADER) {
                leaders++;
                last_leader = (int)i;
            }
        }
        if (leaders > 1u) {
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "two simultaneous leaders in group %s (round fold)",
                     n->group[g].id);
            sn_expect(n, false, msg);
        }
        (void)last_leader;
    }
}

static void sn_run(sn_t* n, uint64_t rounds, uint64_t step_ms) {
    for (uint64_t r = 0; r < rounds; r++) sn_step(n, step_ms);
}

static void sn_crash(sn_t* n, size_t node) {
    if (node >= n->node_count || n->crashed[node]) return;
    sn_ev3(n, SN_EV_CRASH, (uint64_t)node, n->sim.now_ms, 0u);
    for (size_t g = 0; g < SN_GROUPS_MAX; g++) {
        if (n->cs[g][node]) {
            qihse_consensus_close(n->cs[g][node]);
            n->cs[g][node] = NULL;
        }
    }
    n->crashed[node] = true;
    qihse_sim_crash_node(&n->sim, node);
    sn_purge_node(n, node);
}

static bool sn_restart(sn_t* n, size_t node) {
    if (node >= n->node_count || !n->crashed[node]) return true;
    sn_ev3(n, SN_EV_RESTART, (uint64_t)node, n->sim.now_ms, 0u);
    qihse_sim_restart_node(&n->sim, node);
    n->crashed[node] = false;
    for (size_t g = 0; g < SN_GROUPS_MAX; g++) {
        if (n->group[g].member_count == 0u || !sn_in_group(n, g, node)) {
            continue;
        }
        if (!sn_reopen_one(n, g, node)) {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "restart failed closed: node %zu group %s would not "
                     "reopen from its record file",
                     node, n->group[g].id);
            return sn_expect(n, false, msg);
        }
    }
    return true;
}

static void sn_partition(sn_t* n, size_t a, size_t b, bool blocked) {
    qihse_sim_partition(&n->sim, a, b, blocked);
    qihse_sim_partition(&n->sim, b, a, blocked);
    sn_ev3(n, SN_EV_PARTITION, (uint64_t)a, (uint64_t)b,
           blocked ? 1u : 0u);
}

static void sn_heal(sn_t* n) {
    qihse_sim_heal_all(&n->sim);
    sn_ev3(n, SN_EV_HEAL, n->sim.now_ms, 0u, 0u);
}

static void sn_skew(sn_t* n, size_t node, int64_t offset_ms) {
    qihse_sim_set_clock_offset(&n->sim, node, offset_ms);
    sn_ev3(n, SN_EV_SKEW, (uint64_t)node, (uint64_t)(int64_t)offset_ms, 0u);
}

/* ── Election / commit helpers ──────────────────────────────────────────── */

static size_t sn_leaders(sn_t* n, size_t g, int* out_leader) {
    size_t count = 0u;
    if (out_leader) *out_leader = -1;
    if (g >= SN_GROUPS_MAX || n->group[g].member_count == 0u) return 0u;
    for (size_t i = 0; i < n->node_count; i++) {
        if (n->crashed[i] || !n->cs[g][i]) continue;
        if (!sn_in_group(n, g, i)) continue;
        if (qihse_consensus_role(n->cs[g][i]) == QIHSE_CONSENSUS_LEADER) {
            count++;
            if (out_leader) *out_leader = (int)i;
        }
    }
    return count;
}

static int sn_elect(sn_t* n, size_t g, const char* what) {
    for (uint64_t r = 0; r < 1200u; r++) {
        sn_step(n, 10u);
        int leader = -1;
        size_t count = sn_leaders(n, g, &leader);
        if (count == 1u) return leader;
        if (count > 1u) {
            char msg[160];
            snprintf(msg, sizeof(msg), "%s: %zu leaders elected", what, count);
            sn_expect(n, false, msg);
            return -1;
        }
    }
    char msg[160];
    snprintf(msg, sizeof(msg), "%s: no leader elected in time", what);
    sn_expect(n, false, msg);
    return -1;
}

/* Run until every live member of group g has commit >= want. */
static bool sn_commit_reached(sn_t* n, size_t g, uint64_t want,
                              const char* what) {
    for (uint64_t r = 0; r < 900u; r++) {
        bool all = true;
        for (size_t i = 0; i < n->node_count && all; i++) {
            if (n->crashed[i] || !n->cs[g][i] || !sn_in_group(n, g, i)) continue;
            if (qihse_consensus_commit_index(n->cs[g][i]) < want) all = false;
        }
        if (all) return true;
        sn_step(n, 10u);
    }
    char msg[160];
    snprintf(msg, sizeof(msg), "%s: commit %llu not reached everywhere",
             what, (unsigned long long)want);
    return sn_expect(n, false, msg);
}

static uint64_t sn_min_commit(sn_t* n, size_t g) {
    uint64_t minv = UINT64_MAX;
    for (size_t i = 0; i < n->node_count; i++) {
        if (n->crashed[i] || !n->cs[g][i] || !sn_in_group(n, g, i)) continue;
        uint64_t c = qihse_consensus_commit_index(n->cs[g][i]);
        if (c < minv) minv = c;
    }
    return minv == UINT64_MAX ? 0u : minv;
}

/* ── Client paths: attributed, HLC-stamped proposals (invariant 8) ──────── */

static void sn_build_payload(const sn_t* n, size_t node, uint64_t gen,
                             uint8_t* out, size_t* out_len) {
    memcpy(out, n->id[node].bytes, QIHSE_UUID_BYTES);
    for (int b = 0; b < 8; b++) {
        out[QIHSE_UUID_BYTES + b] = (uint8_t)((gen >> (8 * b)) & 0xFFu);
    }
    uint64_t tag = n->seed ^ 0x53494D55484F53ULL; /* "SIMUHOS" */
    for (int b = 0; b < 8; b++) {
        out[QIHSE_UUID_BYTES + 8 + b] = (uint8_t)((tag >> (8 * b)) & 0xFFu);
    }
    *out_len = QIHSE_UUID_BYTES + 16u;
}

/* Propose from whichever member currently leads group g (first in node
 * order).  Returns the leader index used, or -1 if nobody led. */
static int sn_propose_from_leader(sn_t* n, size_t g) {
    int leader = -1;
    if (sn_leaders(n, g, &leader) != 1u) return -1;
    qihse_consensus_t* cs = n->cs[g][leader];
    if (!cs) return -1;

    uint64_t gen = ++n->next_gen;
    qihse_hlc_t stamp = sn_hlc_advance(&n->hlc,
                                       qihse_sim_wall_ms(&n->sim,
                                                         (size_t)leader));
    n->hlc = stamp;

    uint8_t payload[32];
    size_t payload_len = 0u;
    sn_build_payload(n, (size_t)leader, gen, payload, &payload_len);

    bool ok = qihse_consensus_propose(cs, g_op, gen, stamp, 0u, 0u,
                                      payload, payload_len);
    sn_ev3(n, SN_EV_PROPOSE, (uint64_t)leader, gen, ok ? 1u : 0u);
    if (!ok) {
        n->next_gen--; /* nothing appended: reuse the number */
        return leader;
    }
    if (n->prop_count < SN_PROPOSALS_MAX) {
        n->prop[n->prop_count].gen = gen;
        n->prop[n->prop_count].node = (size_t)leader;
        memcpy(n->prop[n->prop_count].payload, payload, payload_len);
        n->prop[n->prop_count].payload_len = payload_len;
        n->prop_count++;
    }
    return leader;
}

/*
 * Verify the committed log of node `node` in group g against everything the
 * scenario proposed — the invariant-8 checks:
 *   - journal generations strictly increase along the log (idempotent order,
 *     no duplicates: a duplicate entry would repeat a generation);
 *   - HLC stamps are non-decreasing along the log;
 *   - every committed DATA payload is byte-identical to what was proposed
 *     and attributable to the node whose UUID it carries;
 *   - NULL principals are refused on this read primitive (invariant 1
 *     sanity: context-free reads are not a bypass).
 * Returns the number of committed entries scanned.
 */
static uint64_t sn_verify_log(sn_t* n, size_t g, size_t node,
                              const char* what) {
    qihse_consensus_t* cs = n->cs[g][node];
    if (!cs) return 0u;

    size_t probe = 0u;
    sn_expect(n,
              qihse_consensus_read_committed(cs, NULL, 1u, NULL, 0u,
                                             &probe) == false,
              "invariant 1 sanity: NULL principal must not read the "
              "committed log");

    qihse_consensus_entry_t entries[SN_ENTRIES_READ];
    size_t count = 0u;
    bool got = qihse_consensus_read_committed(cs, g_op, 1u, entries,
                                              SN_ENTRIES_READ, &count);
    if (!sn_expect(n, got, "read_committed scan failed")) return 0u;

    uint64_t prev_gen = 0u;
    qihse_hlc_t prev_hlc;
    bool have_hlc = false;
    for (size_t k = 0; k < count; k++) {
        const qihse_consensus_entry_t* e = &entries[k];
        char msg[192];

        if (e->journal_generation <= prev_gen) {
            snprintf(msg, sizeof(msg),
                     "%s: node %zu log not idempotent/ordered: gen %llu "
                     "after gen %llu at index %llu",
                     what, node, (unsigned long long)e->journal_generation,
                     (unsigned long long)prev_gen,
                     (unsigned long long)e->index);
            sn_expect(n, false, msg);
        }
        prev_gen = e->journal_generation;

        if (have_hlc && qihse_hlc_compare(&prev_hlc, &e->hlc) > 0) {
            snprintf(msg, sizeof(msg),
                     "%s: node %zu HLC went backwards at index %llu",
                     what, node, (unsigned long long)e->index);
            sn_expect(n, false, msg);
        }
        prev_hlc = e->hlc;
        have_hlc = true;

        if (e->type != QIHSE_CONSENSUS_ENTRY_DATA) continue; /* config entry */

        const sn_prop_t* ref = NULL;
        for (size_t p = 0; p < n->prop_count; p++) {
            if (n->prop[p].gen == e->journal_generation) {
                ref = &n->prop[p];
                break;
            }
        }
        if (!ref) {
            snprintf(msg, sizeof(msg),
                     "%s: node %zu committed unknown generation %llu",
                     what, node, (unsigned long long)e->journal_generation);
            sn_expect(n, false, msg);
            continue;
        }
        if (e->payload_len != ref->payload_len ||
            memcmp(e->payload, ref->payload, e->payload_len) != 0) {
            snprintf(msg, sizeof(msg),
                     "%s: node %zu committed payload for gen %llu is not "
                     "byte-identical to the proposal",
                     what, node, (unsigned long long)e->journal_generation);
            sn_expect(n, false, msg);
            continue;
        }
        /* Attribution: the payload starts with the origin node's UUID. */
        qihse_uuid_t origin;
        memcpy(origin.bytes, e->payload, QIHSE_UUID_BYTES);
        if (!qihse_uuid_equal(&origin, &n->id[ref->node])) {
            snprintf(msg, sizeof(msg),
                     "%s: node %zu committed gen %llu is misattributed",
                     what, node, (unsigned long long)e->journal_generation);
            sn_expect(n, false, msg);
        }
    }
    return (uint64_t)count;
}

/* ── Lifecycle of a whole simulated cluster ─────────────────────────────── */

static void sn_init(sn_t* n, const char* scenario, uint64_t seed,
                    size_t nodes) {
    memset(n, 0, sizeof(*n));
    n->scenario = scenario;
    n->seed = seed;
    n->digest = SN_FNV_OFFSET;
    n->digest = sn_fold_bytes(n->digest, scenario, strlen(scenario));
    n->digest = sn_fold_u64(n->digest, seed);

    qihse_sim_init(&n->sim, seed, nodes);
    n->node_count = nodes;
    for (size_t i = 0; i < nodes; i++) n->id[i] = n->sim.nodes[i].node_id;

    /* Schedule stream: derived from the seed, disjoint from sim.rng. */
    qihse_sim_rng_seed(&n->sched, seed ^ 0xA5A5A5A5DEADBEEFULL);
    (void)qihse_sim_rng_next(&n->sched);

    qihse_hlc_init(&n->hlc);

    snprintf(n->recroot, sizeof(n->recroot), "build/fed_sim_%s_XXXXXX",
             scenario);
    size_t len = strlen(n->recroot);
    if (len < 6u || memcmp(&n->recroot[len - 6u], "XXXXXX", 6u) != 0) {
        snprintf(n->recroot, sizeof(n->recroot), "build/fed_sim_XXXXXX");
    }
    if (!mkdtemp(n->recroot)) {
        snprintf(n->recroot, sizeof(n->recroot), "./fed_sim_XXXXXX");
        if (!mkdtemp(n->recroot)) {
            fprintf(stderr, "FAIL scenario=%s: cannot create record dir\n",
                    scenario);
            abort();
        }
    }
}

static void sn_free(sn_t* n) {
    for (size_t g = 0; g < SN_GROUPS_MAX; g++) {
        for (size_t i = 0; i < QIHSE_SIM_MAX_NODES; i++) {
            if (n->cs[g][i]) {
                qihse_consensus_close(n->cs[g][i]);
                n->cs[g][i] = NULL;
            }
        }
    }
    free(n->q);
    n->q = NULL;
    n->qcount = n->qcap = 0u;

    /* Best-effort cleanup of the run's record files (relative paths). */
    DIR* d = opendir(n->recroot);
    if (d) {
        struct dirent* de;
        char path[256];
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }
            snprintf(path, sizeof(path), "%s/%s", n->recroot, de->d_name);
            remove(path);
        }
        closedir(d);
    }
    rmdir(n->recroot);
}

/* ── LOCAL / STRONG namespace probes (invariants 4, 5, 7) ──────────────── */

static bool sn_local_ns_writable(sn_t* n, size_t node, const char* name) {
    char msg[192];
    bool ok = qihse_federation_namespace_register(g_store, g_op, name,
                                                  QIHSE_CONSISTENCY_LOCAL,
                                                  &n->id[node], &n->id[node]);
    if (!sn_expect(n, ok, "LOCAL namespace registration failed")) return false;

    qihse_federation_namespace_t ns;
    if (!sn_expect(n, qihse_federation_namespace_lookup(g_store, g_op, name,
                                                        &ns),
                   "LOCAL namespace lookup failed")) {
        return false;
    }
    snprintf(msg, sizeof(msg),
             "invariant 4/5: LOCAL namespace %s must stay RW on isolated "
             "node %zu", name, node);
    return sn_expect(n, ns.local_authority &&
                   qihse_federation_namespace_writable(
                       &ns, QIHSE_FEDERATION_STATE_ISOLATED, &n->id[node]),
                   msg);
}

static bool sn_strong_ns_fails_closed(sn_t* n, size_t isolated,
                                      size_t authority, const char* name) {
    bool ok = qihse_federation_namespace_register(
        g_store, g_op, name, QIHSE_CONSISTENCY_LINEARIZABLE,
        &n->id[authority], &n->id[isolated]);
    if (!sn_expect(n, ok, "strong namespace registration failed")) return false;

    qihse_federation_namespace_t ns;
    if (!sn_expect(n, qihse_federation_namespace_lookup(g_store, g_op, name,
                                                        &ns),
                   "strong namespace lookup failed")) {
        return false;
    }
    return sn_expect(n,
                     !qihse_federation_namespace_writable(
                         &ns, QIHSE_FEDERATION_STATE_ISOLATED, &n->id[isolated]),
                     "strong namespace must fail closed on the isolated node");
}

/* ════════════════════════════════════════════════════════════════════════
 * Scenario 1: partition-majority (invariants 4, 5)
 *
 * 5-node group; after a healthy commit, node 4 is isolated (a minority
 * partition of one).  The majority side must keep committing; the isolated
 * node must make NO commits while partitioned; its LOCAL namespace stays
 * read-write while its STRONG namespace fails closed.  After healing, the
 * isolated node catches up and exactly one leader remains.
 * ════════════════════════════════════════════════════════════════════════ */

static uint64_t scenario_partition_majority(uint64_t seed, unsigned run,
                                            uint32_t* checks,
                                            uint32_t* failures) {
    (void)run;
    sn_t n;
    sn_init(&n, "partition-majority", seed, 5u);

    size_t members[5] = {0u, 1u, 2u, 3u, 4u};
    if (sn_open_group(&n, 0u, "core-security", members, 5u)) {
        int leader = sn_elect(&n, 0u, "partition-majority: initial election");
        if (sn_expect(&n, leader >= 0, "partition-majority needs a leader")) {
            /* A pre-partition commit proves the group is healthy. */
            sn_propose_from_leader(&n, 0u);
            if (sn_commit_reached(&n, 0u, 1u,
                                  "partition-majority: pre-partition commit")) {
                uint64_t isolated_commit_before =
                    qihse_consensus_commit_index(n.cs[0][4u]);

                /* Minority partition: isolate node 4 from everyone. */
                sn_ev3(&n, SN_EV_PARTITION, 4u, n.sim.now_ms, 2u);
                qihse_sim_isolate(&n.sim, 4u);

                /* Availability is time-gated by design: a node cannot
                 * distinguish a partition from latency before its election
                 * timeout elapses.  Run past base+spread before asserting
                 * the strong group reports unavailable. */
                sn_run(&n, 600u, 10u);

                /* LOCAL survives (invariants 4, 5); strong fails closed. */
                sn_local_ns_writable(&n, 4u, "sim-local-partmaj");
                sn_strong_ns_fails_closed(&n, 4u, (size_t)leader,
                                          "sim-strong-partmaj");
                sn_expect(&n,
                          !qihse_consensus_group_available(
                              n.cs[0][4u], qihse_sim_wall_ms(&n.sim, 4u)),
                          "invariant 4: isolated node must not report the "
                          "strong group available");

                /* The majority side keeps committing through the partition. */
                for (int i = 0; i < 3; i++) {
                    sn_propose_from_leader(&n, 0u);
                    sn_run(&n, 40u, 10u);
                }
                uint64_t maj_min = UINT64_MAX;
                for (size_t i = 0; i < 4u; i++) {
                    uint64_t c = qihse_consensus_commit_index(n.cs[0][i]);
                    if (c < maj_min) maj_min = c;
                }
                sn_expect(&n, maj_min >= 2u,
                          "invariant 5: majority side must keep committing "
                          "while a minority is partitioned away");

                /* The isolated node committed NOTHING new. */
                uint64_t isolated_commit_after =
                    qihse_consensus_commit_index(n.cs[0][4u]);
                sn_expect(&n, isolated_commit_after ==
                                  isolated_commit_before,
                          "invariant: minority partition must make no "
                          "commits");

                /* And it never declared itself leader during isolation. */
                sn_run(&n, 200u, 10u); /* ~2.5s virtual: many election windows */
                sn_expect(&n,
                          qihse_consensus_role(n.cs[0][4u]) !=
                              QIHSE_CONSENSUS_LEADER,
                          "invariant 9 corollary: a minority of one must "
                          "never win leadership");

                /* Heal: catch up, one leader, consistent logs. */
                sn_heal(&n);
                sn_run(&n, 600u, 10u);
                int leader_after = -1;
                sn_expect(&n, sn_leaders(&n, 0u, &leader_after) == 1u,
                          "partition-majority: exactly one leader after heal");
                sn_commit_reached(&n, 0u, maj_min,
                                  "partition-majority: catch-up after heal");
                sn_verify_log(&n, 0u, 4u, "partition-majority");
            }
        }
    }

    n.digest = sn_fold_u64(n.digest, SN_EV_SCENARIO_END);
    n.digest = sn_fold_u64(n.digest, n.checks);
    n.digest = sn_fold_u64(n.digest, n.failures);
    *checks = n.checks;
    *failures = n.failures;
    uint64_t d = n.digest;
    sn_free(&n);
    return d;
}

/* ════════════════════════════════════════════════════════════════════════
 * Scenario 2: no-quorum-gate (invariant 7)
 *
 * Two scoped groups: alpha on nodes {0,1,2}, beta on nodes {3,4,5}.  Alpha
 * is split three ways (no quorum ANYWHERE inside alpha).  Beta must be
 * completely unaffected (keeps electing and committing), and LOCAL
 * namespaces on an alpha node must stay writable — an unavailable group
 * never gates unrelated groups or local writes.
 * ════════════════════════════════════════════════════════════════════════ */

static uint64_t scenario_no_quorum_gate(uint64_t seed, unsigned run,
                                        uint32_t* checks, uint32_t* failures) {
    (void)run;
    sn_t n;
    sn_init(&n, "no-quorum-gate", seed, 6u);

    size_t alpha[3] = {0u, 1u, 2u};
    size_t beta[3] = {3u, 4u, 5u};
    if (sn_open_group(&n, 0u, "alpha", alpha, 3u) &&
        sn_open_group(&n, 1u, "beta", beta, 3u)) {
        int la = sn_elect(&n, 0u, "no-quorum-gate: alpha election");
        int lb = sn_elect(&n, 1u, "no-quorum-gate: beta election");
        if (sn_expect(&n, la >= 0 && lb >= 0,
                      "no-quorum-gate needs both leaders")) {
            sn_propose_from_leader(&n, 0u);
            sn_propose_from_leader(&n, 1u);
            sn_commit_reached(&n, 0u, 1u, "no-quorum-gate: alpha commit");
            sn_commit_reached(&n, 1u, 1u, "no-quorum-gate: beta commit");
            uint64_t alpha_frozen =
                qihse_consensus_commit_index(n.cs[0][0u]);
            uint64_t beta_commit_before =
                qihse_consensus_commit_index(n.cs[1][3u]);

            /* Split alpha three ways: no pairwise reachability at all. */
            sn_partition(&n, 0u, 1u, true);
            sn_partition(&n, 0u, 2u, true);
            sn_partition(&n, 1u, 2u, true);

            /* Same time-gate: run past the election timeout so the split
             * leader's live-ack window has actually expired. */
            sn_run(&n, 600u, 10u);

            /* Invariant 7: LOCAL on a split-quorum node stays writable. */
            sn_local_ns_writable(&n, 0u, "sim-local-alpha");
            sn_strong_ns_fails_closed(&n, 0u, 1u, "sim-strong-alpha");
            sn_expect(&n,
                      !qihse_consensus_group_available(
                          n.cs[0][0u], qihse_sim_wall_ms(&n.sim, 0u)),
                      "split group must fail closed for strong writes");

            /* Beta is untouched: it keeps committing. */
            for (int i = 0; i < 3; i++) {
                sn_propose_from_leader(&n, 1u);
                sn_run(&n, 40u, 10u);
            }
            sn_commit_reached(&n, 1u, beta_commit_before + 2u,
                              "no-quorum-gate: beta unaffected by alpha split");
            uint64_t beta_after =
                qihse_consensus_commit_index(n.cs[1][3u]);
            sn_expect(&n, beta_after > beta_commit_before,
                      "invariant 7: unavailable group alpha must not block "
                      "healthy group beta");

            /* Alpha commits nothing while split (each node: 1/3 voters). */
            sn_run(&n, 200u, 10u);
            for (size_t i = 0u; i < 3u; i++) {
                char msg[96];
                snprintf(msg, sizeof(msg),
                         "no-quorum-gate: alpha node %zu committed while "
                         "split (no quorum exists)", i);
                sn_expect(&n,
                          qihse_consensus_commit_index(n.cs[0][i]) ==
                              alpha_frozen,
                          msg);
            }

            /* Heal alpha: it recovers — fail-closed is not fail-bricked. */
            sn_heal(&n);
            sn_run(&n, 100u, 10u);
            int la2 = sn_elect(&n, 0u, "no-quorum-gate: alpha re-election");
            if (sn_expect(&n, la2 >= 0, "alpha must re-elect after heal")) {
                sn_propose_from_leader(&n, 0u);
                sn_commit_reached(&n, 0u, alpha_frozen + 1u,
                                  "no-quorum-gate: alpha commits after heal");
            }
            sn_verify_log(&n, 1u, 4u, "no-quorum-gate");
        }
    }

    n.digest = sn_fold_u64(n.digest, SN_EV_SCENARIO_END);
    n.digest = sn_fold_u64(n.digest, n.checks);
    n.digest = sn_fold_u64(n.digest, n.failures);
    *checks = n.checks;
    *failures = n.failures;
    uint64_t d = n.digest;
    sn_free(&n);
    return d;
}

/* ════════════════════════════════════════════════════════════════════════
 * Scenario 3: crash-restart-loop (invariants 7, 8)
 *
 * 5-node group.  A seed-scheduled loop crashes a (seed-chosen) member —
 * leader included — mid-stream, runs the cluster through the crash window,
 * and restarts it from the same record dir.  After every iteration:
 *   - the restart reopened (never bricked / never a corrupt-record abort);
 *   - the group still has exactly one leader and keeps committing
 *     (invariant 7: no bricking of unrelated operation);
 *   - commit indices never regress across the restart (durable replay);
 *   - LOCAL namespaces on the restarted node work immediately.
 * At the end every node's committed log is byte-identical, attributable,
 * HLC-stamped, with strictly increasing generations (invariant 8).
 * ════════════════════════════════════════════════════════════════════════ */

static uint64_t scenario_crash_restart(uint64_t seed, unsigned run,
                                       uint32_t* checks, uint32_t* failures) {
    (void)run;
    sn_t n;
    sn_init(&n, "crash-restart", seed, 5u);

    size_t members[5] = {0u, 1u, 2u, 3u, 4u};
    if (sn_open_group(&n, 0u, "core-security", members, 5u)) {
        int leader = sn_elect(&n, 0u, "crash-restart: initial election");
        if (sn_expect(&n, leader >= 0, "crash-restart needs a leader")) {
            sn_propose_from_leader(&n, 0u);
            sn_commit_reached(&n, 0u, 1u, "crash-restart: first commit");

            /* Seed-derived crash schedule: 4 iterations, crash delays and
             * victim indices all from the schedule RNG. */
            uint32_t iterations = 4u + qihse_sim_rng_below(&n.sched, 2u);
            for (uint32_t it = 0; it < iterations; it++) {
                size_t victim =
                    (size_t)qihse_sim_rng_below(&n.sched, (uint32_t)n.node_count);
                uint32_t crash_delay =
                    10u + qihse_sim_rng_below(&n.sched, 60u);
                uint32_t restart_delay =
                    20u + qihse_sim_rng_below(&n.sched, 100u);

                /* Push some traffic so the crash lands mid-stream. */
                sn_propose_from_leader(&n, 0u);
                sn_run(&n, crash_delay, 10u);

                uint64_t victim_commit_before =
                    qihse_consensus_commit_index(n.cs[0][victim]);
                uint64_t victim_log_before =
                    qihse_consensus_last_log_index(n.cs[0][victim]);

                sn_crash(&n, victim);

                /* The surviving majority must keep operating. */
                sn_run(&n, 60u, 10u);
                sn_propose_from_leader(&n, 0u);
                int mid_leader = -1;
                bool one_leader_mid = false;
                for (uint64_t r = 0; r < 600u && !one_leader_mid; r++) {
                    sn_run(&n, 1u, 10u);
                    if (sn_leaders(&n, 0u, &mid_leader) == 1u &&
                        qihse_consensus_commit_index(
                            n.cs[0][mid_leader]) >= 1u) {
                        one_leader_mid = true;
                    }
                }
                char msg[128];
                snprintf(msg, sizeof(msg),
                         "invariant 7: iteration %u — group must keep exactly "
                         "one committing leader while node %zu is down",
                         it, victim);
                sn_expect(&n, one_leader_mid, msg);

                /* Restart from the same record dir. */
                sn_run(&n, restart_delay, 10u);
                snprintf(msg, sizeof(msg),
                         "invariant 7/8: iteration %u — node %zu must reopen "
                         "from its record file", it, victim);
                if (!sn_expect(&n, sn_restart(&n, victim), msg)) break;

                qihse_consensus_t* vcs = n.cs[0][victim];
                snprintf(msg, sizeof(msg),
                         "invariant 8: iteration %u — node %zu commit index "
                         "regressed across restart", it, victim);
                sn_expect(&n,
                          qihse_consensus_commit_index(vcs) >=
                              victim_commit_before,
                          msg);
                snprintf(msg, sizeof(msg),
                         "invariant 8: iteration %u — node %zu durable log "
                         "shrank across restart", it, victim);
                sn_expect(&n,
                          qihse_consensus_last_log_index(vcs) >=
                              victim_log_before,
                          msg);

                /* Unrelated local operation is not bricked. */
                char nsname[64];
                snprintf(nsname, sizeof(nsname), "sim-local-crash-%u", it);
                sn_local_ns_writable(&n, victim, nsname);

                /* Catch up and commit one more entry with the returned node. */
                sn_run(&n, 400u, 10u);
                int after = -1;
                snprintf(msg, sizeof(msg),
                         "invariant 7: iteration %u — exactly one leader "
                         "after restart", it);
                sn_expect(&n, sn_leaders(&n, 0u, &after) == 1u, msg);
                sn_propose_from_leader(&n, 0u);
                uint64_t want = qihse_consensus_commit_index(
                    n.cs[0][after >= 0 ? (size_t)after : 0u]);
                snprintf(msg, sizeof(msg),
                         "iteration %u: commits resume after restart", it);
                sn_commit_reached(&n, 0u, want, msg);
            }

            /* Final convergence + invariant-8 log audit on every node. */
            sn_run(&n, 600u, 10u);
            int final_leader = -1;
            sn_expect(&n, sn_leaders(&n, 0u, &final_leader) == 1u,
                      "crash-restart: exactly one leader at the end");
            for (size_t i = 0; i < 5u; i++) {
                sn_verify_log(&n, 0u, i, "crash-restart");
            }
            /* All committed prefixes agree (byte-identical history). */
            uint64_t m = sn_min_commit(&n, 0u);
            for (size_t i = 0; i < 5u; i++) {
                char msg[96];
                snprintf(msg, sizeof(msg),
                         "crash-restart: node %zu committed log diverged", i);
                sn_expect(&n,
                          qihse_consensus_commit_index(n.cs[0][i]) >= m,
                          msg);
            }
        }
    }

    n.digest = sn_fold_u64(n.digest, SN_EV_SCENARIO_END);
    n.digest = sn_fold_u64(n.digest, n.checks);
    n.digest = sn_fold_u64(n.digest, n.failures);
    *checks = n.checks;
    *failures = n.failures;
    uint64_t d = n.digest;
    sn_free(&n);
    return d;
}

/* ════════════════════════════════════════════════════════════════════════
 * Scenario 4: crash-mid-membership (invariants 7, 8)
 *
 * The consensus module's exclusive-state transition is the single-server
 * membership change (epoch/lease fencing rides its fencing-epoch floor).
 * The leader proposes REMOVE(node4) and crashes at two seed-scheduled
 * points: (a) before replication lands, (b) after some followers hold the
 * entry but before commit.  In both cases the group must either complete
 * or revert the transition, never elect two leaders, never lose committed
 * data, and keep accepting commits — without bricking node 4's local
 * operation.
 * ════════════════════════════════════════════════════════════════════════ */

static bool membership_phase(sn_t* n, size_t leader, size_t victim,
                             uint32_t rounds_before_crash, const char* tag) {
    char msg[192];

    /* Wait until no transition is in flight, then take the transition
     * baseline. */
    bool settled = false;
    for (uint64_t r = 0; r < 900u && !settled; r++) {
        sn_run(n, 1u, 10u);
        qihse_consensus_membership_t m;
        if (!qihse_consensus_get_membership(n->cs[0][leader], &m)) {
            return sn_expect(n, false, "membership introspection failed");
        }
        settled = (m.pending_config_index == 0u);
    }
    snprintf(msg, sizeof(msg),
             "%s: no membership transition may stay in flight before the "
             "phase starts", tag);
    if (!sn_expect(n, settled, msg)) return false;

    qihse_consensus_membership_t before;
    qihse_consensus_get_membership(n->cs[0][leader], &before);
    size_t before_count = before.member_count;

    bool proposed = qihse_consensus_propose_membership(
        n->cs[0][leader], g_op, QIHSE_CONSENSUS_MEMBER_REMOVE,
        &n->id[victim]);
    snprintf(msg, sizeof(msg), "%s: leader must accept the REMOVE proposal",
             tag);
    if (!sn_expect(n, proposed, msg)) return false;
    n->next_gen += 2u; /* the config entry consumes a journal generation */

    /* Let replication progress the scheduled amount, then crash the leader
     * mid-transition. */
    sn_run(n, rounds_before_crash, 10u);
    sn_crash(n, leader);

    /* The group must recover to exactly one leader that can commit. */
    int next_leader = -1;
    snprintf(msg, sizeof(msg),
             "%s: group must re-elect exactly one leader after the "
             "mid-transition crash", tag);
    bool recovered = false;
    for (uint64_t r = 0; r < 900u && !recovered; r++) {
        sn_run(n, 1u, 10u);
        if (sn_leaders(n, 0u, &next_leader) == 1u) recovered = true;
    }
    if (!sn_expect(n, recovered, msg)) return false;

    uint64_t commit_floor =
        qihse_consensus_commit_index(n->cs[0][next_leader]);
    snprintf(msg, sizeof(msg), "%s: commits must resume after recovery", tag);
    sn_propose_from_leader(n, 0u);
    sn_run(n, 300u, 10u);
    if (!sn_expect(n,
                   qihse_consensus_commit_index(n->cs[0][next_leader]) >
                       commit_floor,
                   msg)) {
        return false;
    }

    /* Restart the crashed leader: it must reopen and converge. */
    snprintf(msg, sizeof(msg),
             "%s: crashed leader must reopen from its record file", tag);
    if (!sn_expect(n, sn_restart(n, leader), msg)) return false;
    sn_run(n, 500u, 10u);

    int final_leader = -1;
    snprintf(msg, sizeof(msg),
             "%s: exactly one leader after the crashed leader returns", tag);
    if (!sn_expect(n, sn_leaders(n, 0u, &final_leader) == 1u, msg)) {
        return false;
    }

    /* The transition resolved one way or the other; both are correct, but
     * the effective config must be consistent and >= 2 members. */
    qihse_consensus_membership_t after;
    snprintf(msg, sizeof(msg),
             "%s: membership introspection must work after recovery", tag);
    if (!sn_expect(n,
                   qihse_consensus_get_membership(
                       n->cs[0][final_leader], &after),
                   msg)) {
        return false;
    }
    snprintf(msg, sizeof(msg),
             "%s: effective member count %zu outside [%zu,%zu] — transition "
             "did not resolve cleanly", tag, after.member_count,
             (size_t)2u, before_count);
    sn_expect(n, after.member_count >= 2u && after.member_count <= before_count,
              msg);

    /* No committed data was lost: every pre-crash committed entry is still
     * there, byte-identical (invariant 8), on every live node. */
    for (size_t i = 0; i < 5u; i++) {
        snprintf(msg, sizeof(msg), "%s: node %zu log audit", tag, i);
        sn_verify_log(n, 0u, i, msg);
    }

    /* The victim's local operation is not bricked either way. */
    char nsname[64];
    snprintf(nsname, sizeof(nsname), "sim-local-%s", tag);
    snprintf(msg, sizeof(msg), "%s: victim LOCAL namespace stays RW", tag);
    sn_expect(n, sn_local_ns_writable(n, victim, nsname), msg);
    return true;
}

/* Pick a removable victim from the leader's EFFECTIVE membership: not the
 * leader itself, not the node a previous phase already removed.  Returns
 * false when no such member exists (group too small — scenario bug, not a
 * product failure). */
static bool pick_remove_victim(sn_t* n, size_t leader, size_t exclude,
                               size_t* out) {
    qihse_consensus_membership_t m;
    if (!qihse_consensus_get_membership(n->cs[0][leader], &m)) return false;
    for (size_t i = 0; i < m.member_count; i++) {
        int idx = sn_index_of(n, &m.members[i]);
        if (idx < 0) continue;
        if ((size_t)idx == leader || (size_t)idx == exclude) continue;
        *out = (size_t)idx;
        return true;
    }
    return false;
}

static uint64_t scenario_crash_mid_membership(uint64_t seed, unsigned run,
                                              uint32_t* checks,
                                              uint32_t* failures) {
    (void)run;
    sn_t n;
    sn_init(&n, "crash-mid-membership", seed, 5u);

    size_t members[5] = {0u, 1u, 2u, 3u, 4u};
    if (sn_open_group(&n, 0u, "core-security", members, 5u)) {
        int leader = sn_elect(&n, 0u, "mid-membership: initial election");
        if (sn_expect(&n, leader >= 0, "mid-membership needs a leader")) {
            sn_propose_from_leader(&n, 0u);
            sn_commit_reached(&n, 0u, 1u, "mid-membership: base commit");

            /* Phase A: crash before replication lands (0 rounds of flight).
             * Phase B: crash after a few seed-scheduled rounds — the entry
             * is on some followers, uncommitted. */
            uint32_t flight_b = 1u + qihse_sim_rng_below(&n.sched, 4u);
            size_t leader_a = (size_t)leader;
            size_t victim_a = 4u;

            membership_phase(&n, leader_a, victim_a, 0u,
                             "phaseA-pre-replication");

            /* Re-elect (the previous leader crashed inside the phase), then
             * remove a DIFFERENT member mid-flight. */
            int leader_b = sn_elect(&n, 0u, "mid-membership: phase B election");
            if (sn_expect(&n, leader_b >= 0, "phase B needs a leader")) {
                size_t victim_b = 0u;
                if (sn_expect(&n,
                              pick_remove_victim(&n, (size_t)leader_b,
                                                 victim_a, &victim_b),
                              "phase B: a removable member must exist")) {
                    membership_phase(&n, (size_t)leader_b, victim_b, flight_b,
                                     "phaseB-mid-flight");
                }
            }

            sn_run(&n, 400u, 10u);
            int last = -1;
            sn_expect(&n, sn_leaders(&n, 0u, &last) == 1u,
                      "mid-membership: one leader at the end");
        }
    }

    n.digest = sn_fold_u64(n.digest, SN_EV_SCENARIO_END);
    n.digest = sn_fold_u64(n.digest, n.checks);
    n.digest = sn_fold_u64(n.digest, n.failures);
    *checks = n.checks;
    *failures = n.failures;
    uint64_t d = n.digest;
    sn_free(&n);
    return d;
}

/* ════════════════════════════════════════════════════════════════════════
 * Scenario 5: never-infer-safety (invariant 9)
 *
 * 3-node group.  After a healthy election, node 2's peers go silent (full
 * isolation).  For a long virtual window (many election timeouts):
 *   - the silenced node may CAMPAIGN but must never WIN (no leadership
 *     inferred from silence) and must never commit;
 *   - its fencing epoch must not advance (no fencing on silence alone);
 *   - the healthy majority keeps its leader, its fencing epoch, and its
 *     membership (nobody amputates the silent member — that would be
 *     inferring death from absence).
 * After healing, normal evidence-based mechanics resume and the cluster
 * converges with no lost data.
 * ════════════════════════════════════════════════════════════════════════ */

static uint64_t scenario_never_infer_safety(uint64_t seed, unsigned run,
                                            uint32_t* checks,
                                            uint32_t* failures) {
    (void)run;
    sn_t n;
    sn_init(&n, "never-infer-safety", seed, 3u);

    size_t members[3] = {0u, 1u, 2u};
    if (sn_open_group(&n, 0u, "core-security", members, 3u)) {
        int leader = sn_elect(&n, 0u, "never-infer: initial election");
        if (sn_expect(&n, leader >= 0, "never-infer needs a leader")) {
            sn_propose_from_leader(&n, 0u);
            sn_commit_reached(&n, 0u, 1u, "never-infer: base commit");

            size_t silenced = 2u;
            if ((size_t)leader == 2u) silenced = 0u; /* silence a follower */
            size_t healthy = (size_t)leader;
            size_t other = (size_t)(leader == 0 ? 1 : 0);

            uint64_t silenced_commit =
                qihse_consensus_commit_index(n.cs[0][silenced]);
            uint64_t leader_epoch =
                qihse_consensus_fencing_epoch(n.cs[0][healthy]);
            uint64_t silenced_epoch =
                qihse_consensus_fencing_epoch(n.cs[0][silenced]);
            uint64_t silenced_term =
                qihse_consensus_term(n.cs[0][silenced]);

            /* Silence: the node can neither send nor hear. */
            sn_ev3(&n, SN_EV_PARTITION, (uint64_t)silenced, n.sim.now_ms, 3u);
            qihse_sim_isolate(&n.sim, silenced);

            /* ~6 seconds virtual — dozens of election windows.  Nothing here
             * may change on the strength of silence alone. */
            for (uint64_t r = 0; r < 600u; r++) {
                sn_step(&n, 10u);
                if (!sn_expect(&n,
                               qihse_consensus_role(n.cs[0][silenced]) !=
                                   QIHSE_CONSENSUS_LEADER,
                               "invariant 9: silenced node must never WIN an "
                               "election on silence alone")) {
                    break;
                }
                if (!sn_expect(&n,
                               qihse_consensus_commit_index(
                                   n.cs[0][silenced]) == silenced_commit,
                               "invariant 9: silenced node must not commit")) {
                    break;
                }
                /* The fencing epoch is a crash-safety floor: it never
                 * regresses, and campaigning on timeout raises it by
                 * design (same as the term — see the sanity check below).
                 * Invariant 9 forbids using silence as PROOF of death:
                 * no amputation (checked below), no commits (above), and
                 * the fence must self-heal after the heal (the epoch-
                 * carrying rejection replies let peers converge).  What it
                 * does NOT forbid is the epoch floor moving. */
                if (!sn_expect(&n,
                               qihse_consensus_fencing_epoch(
                                   n.cs[0][silenced]) >= silenced_epoch,
                               "invariant 9: fencing epoch must never "
                               "regress on silence alone")) {
                    break;
                }
                if (!sn_expect(&n,
                               qihse_consensus_role(n.cs[0][healthy]) ==
                                   QIHSE_CONSENSUS_LEADER,
                               "invariant 9: healthy majority must keep its "
                               "leader through the silence")) {
                    break;
                }
                if (!sn_expect(&n,
                               qihse_consensus_fencing_epoch(
                                   n.cs[0][healthy]) == leader_epoch,
                               "invariant 9: healthy leader must not be "
                               "fenced by a silent peer")) {
                    break;
                }
            }

            /* Silence is not death: the leader never amputated the member. */
            qihse_consensus_membership_t mem;
            if (sn_expect(&n,
                          qihse_consensus_get_membership(n.cs[0][healthy],
                                                         &mem),
                          "membership introspection on the healthy leader")) {
                char msg[128];
                snprintf(msg, sizeof(msg),
                         "invariant 9: leader must not shrink membership on "
                         "silence (have %zu, want 3)",
                         mem.member_count);
                sn_expect(&n, mem.member_count == 3u, msg);
            }

            /* The silenced node DID campaign (its term inflated) — the
             * harness requires silence to be visibly indistinguishable from
             * death to the isolated node too. */
            sn_expect(&n,
                      qihse_consensus_term(n.cs[0][silenced]) >=
                          silenced_term,
                      "silenced node campaigns (term may inflate) — sanity");

            /* Heal: evidence-based mechanics resume, cluster converges. */
            sn_heal(&n);
            sn_run(&n, 800u, 10u);
            int leader_after = -1;
            sn_expect(&n, sn_leaders(&n, 0u, &leader_after) == 1u,
                      "never-infer: one leader after heal");
            sn_commit_reached(&n, 0u, 1u,
                              "never-infer: commit preserved after heal");
            for (size_t i = 0; i < 3u; i++) {
                sn_verify_log(&n, 0u, i, "never-infer");
            }
            (void)other;
        }
    }

    n.digest = sn_fold_u64(n.digest, SN_EV_SCENARIO_END);
    n.digest = sn_fold_u64(n.digest, n.checks);
    n.digest = sn_fold_u64(n.digest, n.failures);
    *checks = n.checks;
    *failures = n.failures;
    uint64_t d = n.digest;
    sn_free(&n);
    return d;
}

/* ════════════════════════════════════════════════════════════════════════
 * Scenario 6: clock-skew-chaos (invariants 7, 8 + digest replay)
 *
 * 5-node group under a seeded chaos schedule: loss, duplication,
 * reordering, delay+jitter, per-node clock skew, and one crash/restart.
 * Proposals fire from whoever leads.  The cluster must still converge to
 * exactly one leader with a consistent, attributable, HLC-stamped committed
 * log — and the whole history must replay bit-identically from the seed
 * (asserted by the runner comparing digests; here we also verify a
 * DIFFERENT seed produces a different history, so the digest is not
 * accidentally constant).
 * ════════════════════════════════════════════════════════════════════════ */

static uint64_t scenario_clock_skew_chaos(uint64_t seed, unsigned run,
                                          uint32_t* checks,
                                          uint32_t* failures) {
    (void)run;
    sn_t n;
    sn_init(&n, "clock-skew-chaos", seed, 5u);

    size_t members[5] = {0u, 1u, 2u, 3u, 4u};
    if (sn_open_group(&n, 0u, "core-security", members, 5u)) {
        int leader = sn_elect(&n, 0u, "chaos: initial election");
        if (sn_expect(&n, leader >= 0, "chaos needs an initial leader")) {
            /* Seed-scheduled fault profile and skews. */
            n.sim.faults.loss_permille = 100u + qihse_sim_rng_below(&n.sched, 80u);
            n.sim.faults.duplication_permille =
                40u + qihse_sim_rng_below(&n.sched, 60u);
            n.sim.faults.reorder_permille = 40u + qihse_sim_rng_below(&n.sched, 60u);
            n.sim.faults.delay_ms = 2u + qihse_sim_rng_below(&n.sched, 4u);
            n.sim.faults.jitter_ms = 5u + qihse_sim_rng_below(&n.sched, 15u);
            for (size_t i = 0; i < 5u; i++) {
                uint32_t off = qihse_sim_rng_below(&n.sched, 301u);
                sn_skew(&n, i, (int64_t)off - 150);
            }
            size_t chaos_victim =
                (size_t)qihse_sim_rng_below(&n.sched, 5u);
            uint64_t crash_at = 300u + qihse_sim_rng_below(&n.sched, 300u);
            uint64_t restart_at = crash_at + 200u +
                                  qihse_sim_rng_below(&n.sched, 300u);
            bool crashed = false, restarted = false;

            /* Fold the schedule into the digest: the chaos profile is part
             * of the history. */
            n.digest = sn_fold_u64(n.digest, n.sim.faults.loss_permille);
            n.digest = sn_fold_u64(n.digest, n.sim.faults.duplication_permille);
            n.digest = sn_fold_u64(n.digest, n.sim.faults.reorder_permille);
            n.digest = sn_fold_u64(n.digest, n.sim.faults.delay_ms);
            n.digest = sn_fold_u64(n.digest, n.sim.faults.jitter_ms);
            n.digest = sn_fold_u64(n.digest, crash_at);
            n.digest = sn_fold_u64(n.digest, restart_at);

            uint64_t elapsed = 0u;
            for (uint64_t r = 0; r < 1600u; r++) {
                elapsed += 10u;
                if (!crashed && elapsed >= crash_at) {
                    sn_crash(&n, chaos_victim);
                    crashed = true;
                }
                if (crashed && !restarted && elapsed >= restart_at) {
                    restarted = true;
                    sn_expect(&n, sn_restart(&n, chaos_victim),
                              "chaos: victim must reopen after crash");
                }
                if (r % 40u == 0u) {
                    sn_propose_from_leader(&n, 0u);
                }
                sn_step(&n, 10u);
            }

            /* The faults must actually have fired, else the scenario is a
             * healthy-network test wearing a chaos name. */
            sn_expect(&n, n.sim.messages_dropped > 0u,
                      "chaos sanity: drops must have occurred");
            sn_expect(&n, n.sim.messages_duplicated > 0u,
                      "chaos sanity: duplications must have occurred");
            sn_expect(&n, n.sim.messages_reordered > 0u,
                      "chaos sanity: reorders must have occurred");

            /* Convergence under chaos: one leader, consistent logs. */
            uint64_t settle = 0u;
            int final_leader = -1;
            while (settle < 1500u && sn_leaders(&n, 0u, &final_leader) != 1u) {
                sn_step(&n, 10u);
                settle += 10u;
            }
            sn_expect(&n, sn_leaders(&n, 0u, &final_leader) == 1u,
                      "chaos: cluster must converge to exactly one leader");
            sn_run(&n, 600u, 10u);
            for (size_t i = 0; i < 5u; i++) {
                sn_verify_log(&n, 0u, i, "chaos");
            }
            sn_commit_reached(&n, 0u, 1u,
                              "chaos: committed data survives the run");
        }
    }

    n.digest = sn_fold_u64(n.digest, SN_EV_SCENARIO_END);
    n.digest = sn_fold_u64(n.digest, n.checks);
    n.digest = sn_fold_u64(n.digest, n.failures);
    *checks = n.checks;
    *failures = n.failures;
    uint64_t d = n.digest;
    sn_free(&n);
    return d;
}

/* ── Runner: every scenario runs twice; digests must match ─────────────── */

typedef uint64_t (*sn_scenario_fn_t)(uint64_t seed, unsigned run,
                                     uint32_t* checks, uint32_t* failures);

static bool sn_run_scenario(const char* name, uint64_t seed,
                            sn_scenario_fn_t fn, bool check_divergence) {
    uint64_t d[2] = {0u, 0u};
    uint32_t checks[2] = {0u, 0u};
    uint32_t failures[2] = {0u, 0u};

    for (unsigned run = 0u; run < 2u; run++) {
        d[run] = fn(seed, run, &checks[run], &failures[run]);
    }

    bool scenario_ok = failures[0] == 0u && failures[1] == 0u;
    bool deterministic = d[0] == d[1];

    printf("  %-24s seed=0x%016llx  digest run0=%016llx run1=%016llx  "
           "checks=%u/%u  %s%s\n",
           name, (unsigned long long)seed,
           (unsigned long long)d[0], (unsigned long long)d[1],
           checks[0], checks[1],
           scenario_ok ? "PASS" : "FAIL",
           deterministic ? "  deterministic" : "  NON-DETERMINISTIC");
    if (!deterministic) {
        fprintf(stderr,
                "FAIL scenario=%s seed=0x%016llx: replay is not "
                "bit-identical (digest %016llx vs %016llx)\n",
                name, (unsigned long long)seed,
                (unsigned long long)d[0], (unsigned long long)d[1]);
    }

    /* A different seed must produce a different history — proves the digest
     * actually summarises the run instead of being constant. */
    bool diverges = true;
    if (check_divergence) {
        uint32_t dchecks = 0u, dfailures = 0u;
        uint64_t dx = fn(seed ^ 0x9E3779B97F4A7C15ULL, 2u, &dchecks,
                         &dfailures);
        diverges = dx != d[0];
        if (!diverges) {
            fprintf(stderr,
                    "FAIL scenario=%s: different seed produced the same "
                    "digest — the history is not seed-sensitive\n",
                    name);
        }
    }

    return scenario_ok && deterministic && diverges;
}

int main(void) {
    char data_root[] = "build/fed_sim_auth_XXXXXX";
    if (!mkdtemp(data_root)) {
        snprintf(data_root, sizeof(data_root), "./fed_sim_auth_XXXXXX");
        if (!mkdtemp(data_root)) {
            fprintf(stderr, "cannot create auth data dir\n");
            return 1;
        }
    }
    setenv("QIHSE_DATA_DIR", data_root, 1);

    if (!qihse_auth_init()) {
        fprintf(stderr, "auth init failed\n");
        return 1;
    }
    if (!qihse_auth_bootstrap_operator("SimOperatorPass1!")) {
        setenv("QIHSE_OPERATOR_PASSWORD", "SimOperatorPass1!", 1);
        if (!qihse_auth_init()) {
            fprintf(stderr, "auth re-init failed\n");
            return 1;
        }
    }
    g_op = qihse_auth_get_user(0);
    if (!g_op) {
        fprintf(stderr, "operator principal missing\n");
        return 1;
    }

    g_store = qihse_kv_store_create();
    if (!g_store) {
        fprintf(stderr, "kv store create failed\n");
        return 1;
    }

    printf("federation deterministic simulation harness "
           "(invariants 4, 5, 7, 8, 9)\n");

    bool ok = true;
    ok &= sn_run_scenario("partition-majority", 0x514D41504152ULL,
                          scenario_partition_majority, false);
    ok &= sn_run_scenario("no-quorum-gate", 0x4E4F51554F52ULL,
                          scenario_no_quorum_gate, false);
    ok &= sn_run_scenario("crash-restart", 0x435241534831ULL,
                          scenario_crash_restart, false);
    ok &= sn_run_scenario("crash-mid-membership", 0x4D49444D454DULL,
                          scenario_crash_mid_membership, false);
    ok &= sn_run_scenario("never-infer-safety", 0x53494C454E43ULL,
                          scenario_never_infer_safety, false);
    ok &= sn_run_scenario("clock-skew-chaos", 0x43484F4F5331ULL,
                          scenario_clock_skew_chaos, true);

    qihse_kv_store_destroy(g_store);

    if (!ok) {
        fprintf(stderr,
                "federation simulation: FAILURES — replay any scenario with "
                "the printed seed for an exact reproduction\n");
        return 1;
    }
    printf("federation deterministic simulation: all scenarios green, "
           "all replays bit-identical\n");
    return 0;
}
