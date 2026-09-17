#include "qihse_cluster_brain.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_ops.h"
#include "qihse_cluster_slot.h"
#include "qihse_event_stream.h"
#include "qihse_pqc_crypto.h"
#include "qihse_auth.h"

#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BRAIN_TOPIC "cluster.brain"
#define BRAIN_MAX_NODES 64u
#define BRAIN_MAX_HANDOFFS 16u

/* A re-home awaiting R4 evaluation: the range, where it went, and when the
 * rollback window closes. `moved < collected` means the transfer stopped
 * partway and ownership must go back. */
typedef struct {
    bool active;
    uint16_t first, last;
    uint16_t target;
    uint64_t deadline_ms;
    uint64_t moved, collected;
} brain_handoff_t;

/* Per-range cooldown so the brain cannot thrash a range it just touched. */
typedef struct {
    bool used;
    uint16_t first, last;
    uint64_t until_ms;
} brain_cooldown_t;

typedef struct brain_pool brain_pool_t; /* persistent scan pool (see below) */

typedef struct {
    qihse_resp_server_t* server;
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    char journal_dir[512];
    char dsa_key_path[576];
    pthread_mutex_t journal_lock;
    uint32_t interval_seconds;
    bool act;
    uint32_t act_cooldown_seconds;
    uint32_t rollback_window_seconds;
    bool running;
    qihse_event_stream_t* journal;
    brain_handoff_t handoffs[BRAIN_MAX_HANDOFFS];
    brain_cooldown_t cooldowns[BRAIN_MAX_HANDOFFS];
    uint64_t unhealthy_since[BRAIN_MAX_NODES]; /* 0 = healthy or not yet observed */
    uint32_t prune_timeout_seconds;
    uint32_t rebalance_min_slots;
    brain_pool_t* pool; /* scan workers, created at start and reused every cycle */
    qihse_cluster_slot_range_t* ranges; /* range snapshot reused by every act
                                         * check; NULL = not allocated, so the
                                         * checks skip instead of acting */
    pthread_t thread;
} brain_t;

static brain_t* g_brain = NULL;
static pthread_mutex_t g_brain_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t brain_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t brain_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* Append one record to the durable journal. Decisions/observations carry an
 * ML-DSA-87 signature over the record body when a signing key is configured.
 * `brain` is owned by the calling thread (stop() joins before freeing). */
static void brain_journal(brain_t* brain, const char* kind, const char* detail) {
    if (!brain || !brain->journal) return;
    char body[1024];
    int n = snprintf(body, sizeof(body),
                     "{\"t\":%llu,\"kind\":\"%s\",\"detail\":%s}",
                     (unsigned long long)brain_now_ms(), kind, detail);
    if (n <= 0 || n >= (int)sizeof(body)) return;

    uint8_t sig[QIHSE_MLDSA_SIGNATURE_SIZE];
    char sig_hex[QIHSE_MLDSA_SIGNATURE_SIZE * 2u + 1u];
    size_t sig_hex_len = 0;
    if (brain->dsa_key_path[0] &&
        qihse_pqc_sign_path((const uint8_t*)body, (size_t)n, sig, brain->dsa_key_path)) {
        for (size_t i = 0; i < QIHSE_MLDSA_SIGNATURE_SIZE; i++)
            snprintf(sig_hex + i * 2u, 3u, "%02x", sig[i]);
        sig_hex[16] = '\0'; /* journal the first 16 bytes of the sig: tamper evidence, not bulk */
        sig_hex_len = 32u;
        OPENSSL_cleanse(sig, sizeof(sig));
    }

    uint8_t record[1600];
    size_t len;
    if (sig_hex_len) {
        len = (size_t)snprintf((char*)record, sizeof(record),
                               "{\"rec\":%s,\"sig8\":\"%.32s\"}", body, sig_hex);
    } else {
        len = (size_t)snprintf((char*)record, sizeof(record), "{\"rec\":%s}", body);
    }
    if (len == 0 || len >= sizeof(record)) return;
    pthread_mutex_lock(&brain->journal_lock);
    qihse_event_stream_append(brain->journal, BRAIN_TOPIC, record, len);
    pthread_mutex_unlock(&brain->journal_lock);
}

/* ---- Parallel slot triage ------------------------------------------------
 * The observe pass used to walk all 16384 slots serially, taking the
 * topology lock once per slot. Now: ONE bulk snapshot (single lock hold),
 * then the run-coalescing analysis runs lock-free on the private copy,
 * split across worker threads. Deterministic: workers own contiguous slot
 * chunks, results merge in chunk order, identical output at any T. */

typedef struct {
    uint16_t owner;
    uint16_t start;
    uint16_t end;
} brain_run_t;

typedef struct {
    const uint16_t* owners;
    uint32_t start;
    uint32_t end;
    brain_run_t* runs;
    size_t count;
    size_t cap;
} brain_scan_t;

static void scan_push(brain_scan_t* w, uint16_t owner, uint32_t start, uint32_t end) {
    if (w->count && w->runs[w->count - 1u].owner == owner &&
        (uint32_t)w->runs[w->count - 1u].end + 1u == start) {
        w->runs[w->count - 1u].end = (uint16_t)end;
        return;
    }
    if (w->count == w->cap) {
        size_t next = w->cap ? w->cap * 2u : 256u;
        brain_run_t* grown = realloc(w->runs, next * sizeof(*grown));
        if (!grown) return; /* drop runs on OOM: journal stays best-effort */
        w->runs = grown;
        w->cap = next;
    }
    w->runs[w->count].owner = owner;
    w->runs[w->count].start = (uint16_t)start;
    w->runs[w->count].end = (uint16_t)end;
    w->count++;
}

static void* scan_worker(void* argument) {
    brain_scan_t* w = (brain_scan_t*)argument;
    for (uint32_t s = w->start; s < w->end; s++) {
        uint16_t owner = w->owners[s];
        if (owner == QIHSE_CLUSTER_NODE_NONE) continue;
        scan_push(w, owner, s, s);
    }
    return NULL;
}

static uint32_t brain_worker_count(void) {
    const char* env = getenv("QIHSE_BRAIN_WORKERS");
    if (env && *env) {
        long v = strtol(env, NULL, 10);
        if (v >= 1 && v <= 32) return (uint32_t)v;
    }
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    uint32_t t = (uint32_t)cores > 8u ? 8u : (uint32_t)cores;
    return t;
}

/* ---- Persistent scan pool ------------------------------------------------
 * A fresh pthread per chunk per cycle was the dominant cost of the observe
 * pass (thread creation, not slot triage: ~730-780 us/cycle at 8 workers on
 * the 2-node lab). The pool is created once by qihse_cluster_brain_start()
 * and reused by every scan — workers park on a condvar between rounds and
 * wake to triage their own chunk.
 *
 * Determinism is unchanged: a chunk is still a contiguous slice of the slot
 * array, the brain thread still owns chunk 0, and results are merged in chunk
 * order only after every chunk has reported done. No worker can see or
 * reorder another's runs, so output never depends on completion order (or on
 * the chunk count at all).
 *
 * Lifecycle: create at brain start, destroy after the brain thread is joined.
 * Workers are never detached and never cancelled — destroy broadcasts `stop`,
 * a worker caught mid-chunk finishes that chunk and parks, then exits. */

#define BRAIN_MAX_WORKERS 32u /* matches the QIHSE_BRAIN_WORKERS ceiling */

typedef struct {
    brain_pool_t* pool;
    uint32_t index; /* chunk this worker owns (1..chunks-1) */
    uint64_t round; /* last round this worker executed */
} brain_pool_worker_t;

struct brain_pool {
    brain_scan_t scans[BRAIN_MAX_WORKERS]; /* one descriptor per chunk */
    pthread_t threads[BRAIN_MAX_WORKERS];  /* one per chunk 1..chunks-1 */
    brain_pool_worker_t workers[BRAIN_MAX_WORKERS];
    uint32_t chunks;  /* chunks in use; chunk 0 belongs to the owning thread */
    uint32_t want;    /* last requested count (0 = never sized) */
    uint32_t pending; /* worker chunks still running this round */
    uint64_t round;   /* round counter; a worker runs when it lags this */
    bool stop;        /* destroy requested */
    pthread_mutex_t lock;
    pthread_cond_t work; /* owner -> workers: a round is open */
    pthread_cond_t done; /* workers -> owner: the round is complete */
};

/* One pool worker: park until the owner opens a round this worker has not run
 * yet, triage its own chunk, park again. Chunks run lock-free; only the round
 * handshake touches the pool lock, so workers never block each other. */
static void* brain_pool_worker(void* argument) {
    brain_pool_worker_t* w = (brain_pool_worker_t*)argument;
    brain_pool_t* pool = w->pool;
    pthread_mutex_lock(&pool->lock);
    for (;;) {
        while (!pool->stop && pool->round == w->round) pthread_cond_wait(&pool->work, &pool->lock);
        if (pool->stop) break; /* mid-chunk work already finished above */
        uint64_t round = pool->round;
        pthread_mutex_unlock(&pool->lock);
        scan_worker(&pool->scans[w->index]);
        pthread_mutex_lock(&pool->lock);
        w->round = round;
        if (--pool->pending == 0u) pthread_cond_signal(&pool->done);
    }
    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

/* Park the current workers and start `chunks - 1` fresh ones. Called by the
 * owning thread between rounds only, so no chunk is ever half-written. A
 * worker that cannot be spawned shrinks the pool instead of failing the scan:
 * chunk 0 always belongs to the owning thread, so a pool of one chunk is the
 * serial fallback. Failed spawns are not retried until the requested count
 * changes, so an OOM cannot turn into a per-cycle spawn storm. */
static void brain_pool_resize(brain_pool_t* pool, uint32_t chunks) {
    if (chunks > BRAIN_MAX_WORKERS) chunks = BRAIN_MAX_WORKERS;
    if (chunks < 1u) chunks = 1u;
    if (chunks == pool->want) return;

    pthread_mutex_lock(&pool->lock);
    pool->stop = true;
    pthread_cond_broadcast(&pool->work);
    pthread_mutex_unlock(&pool->lock);
    for (uint32_t i = 1; i < pool->chunks; i++) pthread_join(pool->threads[i], NULL);

    pool->stop = false;
    pool->round = 0;
    pool->pending = 0;
    pool->chunks = chunks;
    pool->want = chunks;
    for (uint32_t i = 1; i < chunks; i++) {
        brain_pool_worker_t* w = &pool->workers[i];
        w->pool = pool;
        w->index = i;
        w->round = 0;
        if (pthread_create(&pool->threads[i], NULL, brain_pool_worker, w) != 0) {
            pool->chunks = i; /* owning thread covers chunk 0; threads 1..i-1 started */
            break;
        }
    }
}

/* Create the pool with `chunks` chunks (chunk 0 is the owning thread's).
 * Returns NULL only when the pool itself cannot be allocated or initialised;
 * the caller then scans serially. Thread creation failure is not fatal — the
 * pool simply shrinks to the chunks it could start. */
static brain_pool_t* brain_pool_create(uint32_t chunks) {
    brain_pool_t* pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&pool->work, NULL) != 0) {
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&pool->done, NULL) != 0) {
        pthread_cond_destroy(&pool->work);
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }
    brain_pool_resize(pool, chunks);
    return pool;
}

/* Stop and join every worker, then release the pool. A worker mid-chunk is
 * never cancelled: it finishes, parks, sees `stop`, and exits. The owning
 * thread calls this between rounds, so the drain below normally returns
 * immediately; it exists so a round can never be torn down half-written. */
static void brain_pool_destroy(brain_pool_t* pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->lock);
    while (pool->pending) pthread_cond_wait(&pool->done, &pool->lock);
    pool->stop = true;
    pthread_cond_broadcast(&pool->work);
    pthread_mutex_unlock(&pool->lock);
    for (uint32_t i = 1; i < pool->chunks; i++) pthread_join(pool->threads[i], NULL);
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->work);
    pthread_cond_destroy(&pool->done);
    free(pool);
}

/* Run one triage round over `owners`: the owning thread takes chunk 0, the
 * pool's workers take the rest, and the call returns only once every chunk is
 * written. A worker executes a round only when its own round counter lags the
 * pool's, so no chunk is ever scanned twice. Returns the chunks used. */
static uint32_t brain_pool_scan(brain_pool_t* pool, const uint16_t* owners) {
    uint32_t chunk = (QIHSE_CLUSTER_SLOT_COUNT + pool->chunks - 1u) / pool->chunks;
    for (uint32_t i = 0; i < pool->chunks; i++) {
        brain_scan_t* scan = &pool->scans[i];
        scan->owners = owners;
        scan->start = i * chunk;
        scan->end = scan->start + chunk;
        if (scan->end > QIHSE_CLUSTER_SLOT_COUNT) scan->end = QIHSE_CLUSTER_SLOT_COUNT;
    }

    pthread_mutex_lock(&pool->lock);
    pool->round++;
    pool->pending = pool->chunks - 1u;
    pthread_cond_broadcast(&pool->work);
    pthread_mutex_unlock(&pool->lock);

    scan_worker(&pool->scans[0]); /* the owner takes chunk 0: no idle-core tax */

    if (pool->chunks > 1u) {
        pthread_mutex_lock(&pool->lock);
        while (pool->pending) pthread_cond_wait(&pool->done, &pool->lock);
        pthread_mutex_unlock(&pool->lock);
    }
    return pool->chunks;
}

/* Release a chunk's run list. The pool reuses its descriptors, so a stale run
 * count must never survive into the next round. */
static void brain_scan_clear(brain_scan_t* scan) {
    free(scan->runs);
    scan->runs = NULL;
    scan->count = 0;
    scan->cap = 0;
}

static void brain_observe(brain_t* brain) {
    qihse_cluster_node_t nodes[BRAIN_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(brain->topology, nodes, BRAIN_MAX_NODES);
    uint16_t local = qihse_cluster_topology_local_node(brain->topology);

    uint64_t t0 = brain_now_us();
    uint16_t* owners = malloc(QIHSE_CLUSTER_SLOT_COUNT * sizeof(uint16_t));
    if (!owners) return;
    if (qihse_cluster_topology_slot_owner_snapshot(brain->topology, owners,
                                                   QIHSE_CLUSTER_SLOT_COUNT) != QIHSE_CLUSTER_SLOT_COUNT) {
        free(owners);
        return;
    }

    uint32_t workers = brain_worker_count();
    if (workers > QIHSE_CLUSTER_SLOT_COUNT) workers = QIHSE_CLUSTER_SLOT_COUNT;
    brain_scan_t serial; /* used only when the pool could not be created */
    brain_scan_t* scans;
    if (brain->pool) {
        /* Re-size first if the configured count changed since the last cycle:
         * a stale count is never used, and re-sizing happens between rounds. */
        brain_pool_resize(brain->pool, workers);
        scans = brain->pool->scans;
        workers = brain_pool_scan(brain->pool, owners);
    } else {
        /* No pool: triage the whole array on this thread rather than skip the
         * observation (the OBSERVE record then reports workers=1). */
        memset(&serial, 0, sizeof(serial));
        serial.owners = owners;
        serial.end = QIHSE_CLUSTER_SLOT_COUNT;
        scan_worker(&serial);
        scans = &serial;
        workers = 1u;
    }

    /* Merge chunk results in order; coalesce runs across chunk boundaries. */
    size_t total = 0;
    for (uint32_t i = 0; i < workers; i++) total += scans[i].count;
    brain_run_t* merged = malloc((total ? total : 1u) * sizeof(*merged));
    size_t merged_count = 0;
    if (merged) {
        for (uint32_t i = 0; i < workers; i++) {
            for (size_t r = 0; r < scans[i].count; r++) {
                brain_run_t* run = &scans[i].runs[r];
                if (merged_count && merged[merged_count - 1u].owner == run->owner &&
                    (uint32_t)merged[merged_count - 1u].end + 1u == run->start) {
                    merged[merged_count - 1u].end = run->end;
                } else {
                    merged[merged_count++] = *run;
                }
            }
        }
    }

    char detail[900];
    int off = snprintf(detail, sizeof(detail), "{\"nodes\":[");
    for (size_t i = 0; i < count && off > 0 && off < 800; i++) {
        char runs_buf[240];
        int roff = 0;
        uint32_t runs = 0;
        if (merged) {
            for (size_t r = 0; r < merged_count && roff < (int)(sizeof(runs_buf) - 32u); r++) {
                if (merged[r].owner != nodes[i].index) continue;
                roff += snprintf(runs_buf + roff, (size_t)(sizeof(runs_buf) - (size_t)roff),
                                 "%s%u-%u", runs ? "," : "", merged[r].start, merged[r].end);
                runs++;
            }
        }
        off += snprintf(detail + off, (size_t)(sizeof(detail) - (size_t)off),
                        "%s{\"id\":\"%.12s\",\"addr\":\"%s:%u\",\"healthy\":%s,\"self\":%s,\"slots\":\"%s\"}",
                        i ? "," : "", nodes[i].id, nodes[i].host, nodes[i].port,
                        nodes[i].healthy ? "true" : "false",
                        nodes[i].index == local ? "true" : "false", runs ? runs_buf : "");
    }
    snprintf(detail + off, (size_t)(sizeof(detail) - (size_t)off),
             "],\"scan_us\":%llu,\"workers\":%u}",
             (unsigned long long)(brain_now_us() - t0), workers);
    brain_journal(brain, "OBSERVE", detail);

    for (uint32_t i = 0; i < workers; i++) brain_scan_clear(&scans[i]);
    free(merged);
    free(owners);
}

/* R3: isolated — no healthy peers. Journal once per incident; never act. */
static void brain_check_isolation(brain_t* brain, const qihse_cluster_node_t* nodes, size_t count) {
    uint16_t local = qihse_cluster_topology_local_node(brain->topology);
    size_t healthy_peers = 0;
    for (size_t i = 0; i < count; i++)
        if (nodes[i].index != local && nodes[i].healthy) healthy_peers++;
    static bool isolated_reported = false;
    if (healthy_peers == 0 && count > 1 && !isolated_reported) {
        brain_journal(brain, "ISOLATED", "{\"reason\":\"no healthy peers reachable\"}");
        isolated_reported = true;
    } else if (healthy_peers > 0 && isolated_reported) {
        brain_journal(brain, "RECONNECTED", "{\"reason\":\"healthy peer observed\"}");
        isolated_reported = false;
    }
}

/* R2: asymmetry — a peer I consider failed. Quarantine observations only:
 * acting on a possibly-private partition is how clusters split brains. */
static void brain_check_asymmetry(brain_t* brain, const qihse_cluster_node_t* nodes, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (!nodes[i].healthy && nodes[i].host[0]) {
            char detail[512];
            snprintf(detail, sizeof(detail), "{\"peer\":\"%s:%u\",\"policy\":\"quarantine-noaction\"}",
                     nodes[i].host, nodes[i].port);
            brain_journal(brain, "ASYMMETRY", detail);
            return;
        }
    }
}

/* ---- Actuation (R1 re-home + R4 rollback) -------------------------------
 * Every action goes through qihse_cluster_handoff_range() — the same audited
 * path CLUSTER MOVESLOTS uses — so the brain adds policy, never data-path
 * code. One action per cycle keeps the journal readable and the state
 * reversible. */

static bool brain_range_cooled(brain_t* brain, uint16_t first, uint16_t last, uint64_t now) {
    for (size_t i = 0; i < BRAIN_MAX_HANDOFFS; i++) {
        brain_cooldown_t* c = &brain->cooldowns[i];
        if (!c->used || c->first != first || c->last != last) continue;
        return now < c->until_ms;
    }
    return false;
}

static void brain_range_cooldown(brain_t* brain, uint16_t first, uint16_t last, uint64_t now) {
    brain_cooldown_t* slot = &brain->cooldowns[0];
    for (size_t i = 0; i < BRAIN_MAX_HANDOFFS; i++) {
        brain_cooldown_t* c = &brain->cooldowns[i];
        if (!c->used || (c->first == first && c->last == last)) {
            slot = c;
            break;
        }
    }
    slot->used = true;
    slot->first = first;
    slot->last = last;
    slot->until_ms = now + (uint64_t)brain->act_cooldown_seconds * 1000u;
}

/* Healthy primary to receive a re-homed range. Capability-aware placement
 * (ai_fabric.md §4): prefer nodes that advertise headroom via NODE_CAP
 * (free RAM minus a load penalty); nodes that have not advertised yet stay
 * eligible at the lowest score. Uptime breaks ties, so the choice stays
 * deterministic and journalable. Excludes the failed owner and the local
 * node (we are the actor). */
static uint16_t brain_pick_target(brain_t* brain, const qihse_cluster_node_t* nodes, size_t count,
                                  uint16_t failed_owner, uint16_t local) {
    uint64_t now = brain_now_ms();
    int64_t best_score = 0;
    uint64_t best_uptime = 0;
    uint16_t best = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].index == failed_owner || nodes[i].index == local) continue;
        if (!nodes[i].healthy || nodes[i].role != QIHSE_CLUSTER_NODE_PRIMARY) continue;
        uint64_t first_seen = 0;
        uint64_t uptime = 0;
        if (brain->bus &&
            qihse_cluster_bus_peer_first_seen(brain->bus, nodes[i].index, &first_seen) &&
            first_seen > 0) {
            uptime = now > first_seen ? now - first_seen : 0;
        }
        int64_t score = 0;
        uint32_t free_ram = 0;
        uint16_t load = 0;
        if (brain->bus &&
            qihse_cluster_bus_node_caps(brain->bus, nodes[i].index, NULL, NULL, NULL,
                                        &free_ram, &load)) {
            score = (int64_t)free_ram - (int64_t)load * 64;
        }
        if (best == QIHSE_CLUSTER_NODE_NONE || score > best_score ||
            (score == best_score && uptime > best_uptime)) {
            best_score = score;
            best_uptime = uptime;
            best = nodes[i].index;
        }
    }
    return best;
}

/* Journal evidence for a placement decision: the capability profile the
 * choice was based on (or null when the node has not advertised). */
static void brain_caps_evidence(brain_t* brain, uint16_t index, char* out, size_t cap) {
    uint8_t isa = 0, npu = 0, gpu = 0;
    uint32_t free_ram = 0;
    uint16_t load = 0;
    if (brain->bus &&
        qihse_cluster_bus_node_caps(brain->bus, index, &isa, &npu, &gpu, &free_ram, &load)) {
        snprintf(out, cap,
                 "{\"isa\":%u,\"npu\":%u,\"gpu\":%u,\"free_ram_mb\":%u,\"load_pct\":%u}",
                 (unsigned)isa, (unsigned)npu, (unsigned)gpu, (unsigned)free_ram,
                 (unsigned)load);
    } else {
        snprintf(out, cap, "null");
    }
}

/* R1 — failed-owner re-home. Evidence-gated exactly like the failover
 * coordinator: if ANY peer recently observed the owner healthy this is an
 * asymmetric link, not a dead node, so the brain journals and waits.
 * Returns true when an action was taken. */
static bool brain_check_rehome(brain_t* brain) {
    if (!brain->act || !brain->server) return false;
    qihse_cluster_node_t nodes[BRAIN_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(brain->topology, nodes, BRAIN_MAX_NODES);
    uint16_t local = qihse_cluster_topology_local_node(brain->topology);
    if (count == 0 || local == QIHSE_CLUSTER_NODE_NONE) return false;

    qihse_cluster_node_t self;
    if (!qihse_cluster_topology_get_node(brain->topology, local, &self) || !self.healthy)
        return false;

    /* R3 guard: with no healthy peer there is nowhere safe to move a range. */
    size_t healthy_peers = 0;
    for (size_t i = 0; i < count; i++)
        if (nodes[i].index != local && nodes[i].healthy) healthy_peers++;
    if (healthy_peers == 0) return false;

    /* The range snapshot is the brain-owned heap buffer, never a stack array:
     * 16384 ranges is ~96 KB and this runs on the brain thread, where a frame
     * that size is a hazard (AGENTS.md, "bounded stack frames"). The buffer is
     * allocated once at start and reused every cycle. A brain without one
     * (allocation failed) skips the check rather than acting on an empty
     * range list. */
    qihse_cluster_slot_range_t* ranges = brain->ranges;
    if (!ranges) return false;

    bool acted = false;
    uint64_t now = brain_now_ms();
    size_t range_count = qihse_cluster_topology_ranges(brain->topology, ranges,
                                                       QIHSE_CLUSTER_SLOT_COUNT);
    for (size_t r = 0; r < range_count; r++) {
        uint16_t owner = ranges[r].owner_index;
        if (owner == QIHSE_CLUSTER_NODE_NONE || owner == local) continue;
        qihse_cluster_node_t owner_node;
        if (!qihse_cluster_topology_get_node(brain->topology, owner, &owner_node)) continue;
        if (owner_node.healthy) continue;
        if (brain_range_cooled(brain, ranges[r].start, ranges[r].end, now)) continue;
        /* Evidence gate: same rule the failover coordinator applies. */
        if (brain->bus) {
            uint64_t last_healthy = qihse_cluster_bus_last_observed_healthy(brain->bus, owner);
            if (last_healthy > 0 && now - last_healthy < QIHSE_CLUSTER_BUS_TIMEOUT_MS) continue;
        }
        uint16_t target = brain_pick_target(brain, nodes, count, owner, local);
        if (target == QIHSE_CLUSTER_NODE_NONE) continue;

        /* Only re-home a range this node can actually serve. */
        if (!qihse_cluster_range_has_local_keys(brain->server, ranges[r].start, ranges[r].end,
                                                4096u)) {
            char detail[192];
            snprintf(detail, sizeof(detail),
                     "{\"range\":\"%u-%u\",\"owner\":\"%.12s\",\"reason\":\"no-local-data\"}",
                     ranges[r].start, ranges[r].end, owner_node.id);
            brain_journal(brain, "REHOME_SKIP", detail);
            brain_range_cooldown(brain, ranges[r].start, ranges[r].end, now);
            continue;
        }

        uint64_t moved = 0, collected = 0;
        char err[160];
        int rc = qihse_cluster_handoff_range(brain->server, ranges[r].start, ranges[r].end,
                                             target, &moved, &collected, err, sizeof(err));
        char caps[192];
        brain_caps_evidence(brain, target, caps, sizeof(caps));
        char detail[512];
        snprintf(detail, sizeof(detail),
                 "{\"range\":\"%u-%u\",\"from\":\"%.12s\",\"to\":%u,\"moved\":%llu,"
                 "\"collected\":%llu,\"ok\":%s,\"err\":\"%s\",\"target_caps\":%s}",
                 ranges[r].start, ranges[r].end, owner_node.id, (unsigned)target,
                 (unsigned long long)moved, (unsigned long long)collected,
                 rc == 0 ? "true" : "false", rc == 0 ? "" : err, caps);
        brain_journal(brain, "REHOME", detail);
        brain_range_cooldown(brain, ranges[r].start, ranges[r].end, now);

        /* R4: evaluate this handoff once the rollback window closes. */
        for (size_t i = 0; i < BRAIN_MAX_HANDOFFS; i++) {
            if (brain->handoffs[i].active) continue;
            brain->handoffs[i].active = true;
            brain->handoffs[i].first = ranges[r].start;
            brain->handoffs[i].last = ranges[r].end;
            brain->handoffs[i].target = target;
            brain->handoffs[i].deadline_ms =
                now + (uint64_t)brain->rollback_window_seconds * 1000u;
            brain->handoffs[i].moved = moved;
            brain->handoffs[i].collected = collected;
            break;
        }
        acted = true;
        break; /* one action per cycle: predictable, journalable, reversible */
    }
    return acted;
}

/* R4 — rollback. A re-home is kept only if the range arrived completely and
 * the target is still healthy when the window closes; otherwise ownership
 * returns to the local node, which still holds whatever did not transfer. */
static void brain_check_rollback(brain_t* brain) {
    if (!brain->act) return;
    uint64_t now = brain_now_ms();
    uint16_t local = qihse_cluster_topology_local_node(brain->topology);
    for (size_t i = 0; i < BRAIN_MAX_HANDOFFS; i++) {
        brain_handoff_t* h = &brain->handoffs[i];
        if (!h->active || now < h->deadline_ms) continue;
        qihse_cluster_node_t target_node;
        bool target_ok = qihse_cluster_topology_get_node(brain->topology, h->target,
                                                         &target_node) &&
                         target_node.healthy;
        const char* reason = NULL;
        if (h->moved < h->collected) reason = "transfer-incomplete";
        else if (!target_ok) reason = "target-unhealthy";
        if (reason) {
            if (qihse_cluster_set_range_owner(brain->server, h->first, h->last, local)) {
                char detail[256];
                snprintf(detail, sizeof(detail),
                         "{\"range\":\"%u-%u\",\"target\":%u,\"reason\":\"%s\",\"moved\":%llu,"
                         "\"collected\":%llu}",
                         h->first, h->last, (unsigned)h->target, reason,
                         (unsigned long long)h->moved, (unsigned long long)h->collected);
                brain_journal(brain, "ROLLBACK", detail);
                brain_range_cooldown(brain, h->first, h->last, now);
            }
        } else {
            char detail[192];
            snprintf(detail, sizeof(detail), "{\"range\":\"%u-%u\",\"target\":%u,\"moved\":%llu}",
                     h->first, h->last, (unsigned)h->target, (unsigned long long)h->moved);
            brain_journal(brain, "REHOME_CONFIRM", detail);
        }
        h->active = false;
    }
}

/* R6 — stale-node prune. A node that has been unhealthy for the prune timeout
 * with no peer reporting it healthy is removed from this node's view, so
 * CLUSTER NODES stops accumulating corpses. Nodes that still own slots are
 * refused (failover / R1 must re-home them first). */
static void brain_check_prune(brain_t* brain, const qihse_cluster_node_t* nodes, size_t count) {
    if (!brain->act || !brain->prune_timeout_seconds) return;
    uint64_t now = brain_now_ms();
    uint16_t local = qihse_cluster_topology_local_node(brain->topology);
    for (size_t i = 0; i < count; i++) {
        uint16_t idx = nodes[i].index;
        if (idx >= BRAIN_MAX_NODES || idx == local) continue;
        if (nodes[i].healthy) {
            brain->unhealthy_since[idx] = 0;
            continue;
        }
        if (brain->unhealthy_since[idx] == 0) {
            brain->unhealthy_since[idx] = now;
            continue;
        }
        if (now - brain->unhealthy_since[idx] <
            (uint64_t)brain->prune_timeout_seconds * 1000u) {
            continue;
        }
        /* Evidence gate: a peer still seeing it healthy means an asymmetric
         * link, not a dead node. */
        if (brain->bus) {
            uint64_t last_healthy = qihse_cluster_bus_last_observed_healthy(brain->bus, idx);
            if (last_healthy > 0 && now - last_healthy < QIHSE_CLUSTER_BUS_TIMEOUT_MS) continue;
        }
        if (qihse_cluster_topology_remove_node(brain->topology, idx)) {
            char detail[224];
            snprintf(detail, sizeof(detail),
                     "{\"node\":\"%.12s\",\"addr\":\"%s:%u\",\"unhealthy_ms\":%llu}",
                     nodes[i].id, nodes[i].host, nodes[i].port,
                     (unsigned long long)(now - brain->unhealthy_since[idx]));
            brain_journal(brain, "PRUNE", detail);
            brain->unhealthy_since[idx] = 0;
        }
        /* EBUSY = still owns slots: expected until the range is re-homed. */
    }
}

/* R5 — rebalance on join. A healthy, slotless primary receives a proportional
 * share from the largest owner. Deterministic: only the largest owner acts
 * (tie-break by lowest index), so exactly one node moves the range. */
static void brain_check_rebalance(brain_t* brain, const qihse_cluster_node_t* nodes, size_t count) {
    if (!brain->act || !brain->rebalance_min_slots || count < 2u) return;
    /* Same brain-owned heap range snapshot as brain_check_rehome; without it
     * there is no range view, so no range is donated. */
    qihse_cluster_slot_range_t* ranges = brain->ranges;
    if (!ranges) return;
    uint16_t local = qihse_cluster_topology_local_node(brain->topology);
    size_t range_count = qihse_cluster_topology_ranges(brain->topology, ranges,
                                                       QIHSE_CLUSTER_SLOT_COUNT);

    size_t healthy = 0;
    for (size_t i = 0; i < count; i++)
        if (nodes[i].healthy) healthy++;

    /* Largest owner among healthy nodes (deterministic tie-break by index). */
    size_t best_slots = 0;
    uint16_t best_owner = QIHSE_CLUSTER_NODE_NONE;
    size_t my_slots = 0;
    for (size_t i = 0; i < count; i++) {
        if (!nodes[i].healthy) continue;
        size_t owned = 0;
        for (size_t r = 0; r < range_count; r++) {
            if (ranges[r].owner_index != nodes[i].index) continue;
            owned += (size_t)(ranges[r].end - ranges[r].start) + 1u;
        }
        if (nodes[i].index == local) my_slots = owned;
        if (best_owner == QIHSE_CLUSTER_NODE_NONE || owned > best_slots) {
            best_slots = owned;
            best_owner = nodes[i].index;
        }
    }
    if (best_owner != local || my_slots < brain->rebalance_min_slots) return;

    for (size_t i = 0; i < count; i++) {
        if (nodes[i].index == local || !nodes[i].healthy) continue;
        if (nodes[i].role != QIHSE_CLUSTER_NODE_PRIMARY) continue;
        size_t owned = 0;
        for (size_t r = 0; r < range_count; r++) {
            if (ranges[r].owner_index != nodes[i].index) continue;
            owned += (size_t)(ranges[r].end - ranges[r].start) + 1u;
        }
        if (owned != 0) continue; /* not a joiner */

        /* Donate the tail of our largest range; never more than half of it. */
        size_t pick_len = 0;
        uint16_t pick_end = 0;
        for (size_t r = 0; r < range_count; r++) {
            if (ranges[r].owner_index != local) continue;
            size_t len = (size_t)(ranges[r].end - ranges[r].start) + 1u;
            if (len > pick_len) {
                pick_len = len;
                pick_end = ranges[r].end;
            }
        }
        size_t give = my_slots / (healthy ? healthy : 1u);
        if (give > pick_len / 2u) give = pick_len / 2u;
        if (give == 0) return;
        uint16_t first = (uint16_t)(pick_end - give + 1u);
        uint64_t now = brain_now_ms();
        if (brain_range_cooled(brain, first, pick_end, now)) return;

        uint64_t moved = 0, collected = 0;
        char err[160];
        int rc = qihse_cluster_handoff_range(brain->server, first, pick_end, nodes[i].index,
                                             &moved, &collected, err, sizeof(err));
        char detail[320];
        snprintf(detail, sizeof(detail),
                 "{\"range\":\"%u-%u\",\"to\":\"%.12s\",\"moved\":%llu,\"collected\":%llu,"
                 "\"ok\":%s,\"err\":\"%s\"}",
                 first, pick_end, nodes[i].id, (unsigned long long)moved,
                 (unsigned long long)collected, rc == 0 ? "true" : "false",
                 rc == 0 ? "" : err);
        brain_journal(brain, "REBALANCE", detail);
        brain_range_cooldown(brain, first, pick_end, now);
        return; /* one action per cycle */
    }
}

static void* brain_main(void* argument) {
    /* The thread owns its brain struct for its whole lifetime: stop() joins
     * the thread BEFORE freeing, so these accesses need no lock. */
    brain_t* brain = (brain_t*)argument;
    brain_journal(brain, "BRAIN_START", brain->act ? "{\"mode\":\"act\"}" : "{\"mode\":\"observe\"}");
    while (__atomic_load_n(&brain->running, __ATOMIC_ACQUIRE)) {
        qihse_cluster_node_t nodes[BRAIN_MAX_NODES];
        size_t count = brain->topology
                           ? qihse_cluster_topology_nodes(brain->topology, nodes, BRAIN_MAX_NODES)
                           : 0;
        if (count > 0) {
            brain_observe(brain);
            brain_check_isolation(brain, nodes, count);
            brain_check_asymmetry(brain, nodes, count);
            brain_check_prune(brain, nodes, count);
            /* R1 and R5 both move data: at most one of them acts per cycle. */
            if (!brain_check_rehome(brain)) brain_check_rebalance(brain, nodes, count);
        }
        brain_check_rollback(brain);
        uint32_t ms = brain->interval_seconds * 1000u;
        struct timespec ts = { (time_t)(ms / 1000u), (long)((ms % 1000u) * 1000000L) };
        nanosleep(&ts, NULL);
    }
    brain_journal(brain, "BRAIN_STOP", "{}");
    return NULL;
}

bool qihse_cluster_brain_start(const qihse_brain_config_t* config) {
    if (!config || !config->server || !config->journal_dir || !*config->journal_dir) return false;
    pthread_mutex_lock(&g_brain_lock);
    if (g_brain && g_brain->running) {
        pthread_mutex_unlock(&g_brain_lock);
        return true; /* already running */
    }
    brain_t* brain = calloc(1, sizeof(*brain));
    if (!brain) {
        pthread_mutex_unlock(&g_brain_lock);
        return false;
    }
    brain->server = config->server;
    brain->topology = qihse_resp_server_topology(config->server);
    snprintf(brain->journal_dir, sizeof(brain->journal_dir), "%s", config->journal_dir);
    if (config->dsa_key_path && *config->dsa_key_path)
        snprintf(brain->dsa_key_path, sizeof(brain->dsa_key_path), "%s", config->dsa_key_path);
    brain->interval_seconds = config->interval_seconds ? config->interval_seconds : 5u;
    brain->act = config->act;
    brain->act_cooldown_seconds = config->act_cooldown_seconds ? config->act_cooldown_seconds : 30u;
    brain->rollback_window_seconds =
        config->rollback_window_seconds ? config->rollback_window_seconds : 60u;
    brain->prune_timeout_seconds = config->prune_timeout_seconds;
    brain->rebalance_min_slots = config->rebalance_min_slots;
    brain->bus = qihse_resp_server_bus(config->server);
    brain->running = true;

    brain->journal = qihse_event_stream_create(brain->journal_dir);
    if (!brain->journal) brain->journal = qihse_event_stream_open(brain->journal_dir, QIHSE_ES_DURABILITY_NONE, false);
    if (!brain->journal || pthread_mutex_init(&brain->journal_lock, NULL) != 0) {
        if (brain->journal) qihse_event_stream_destroy(brain->journal);
        free(brain);
        pthread_mutex_unlock(&g_brain_lock);
        return false;
    }
    qihse_pqc_init_providers();

    /* Persistent scan pool: created once here and reused by every cycle, so
     * the observe pass no longer pays a thread spawn per chunk. A pool that
     * cannot be created is NOT fatal — brain_observe() then triages the slot
     * array serially on the brain thread. */
    brain->pool = brain_pool_create(brain_worker_count());

    /* Actuation needs a full range snapshot: 16384 ranges is ~96 KB, which
     * must not sit on the brain thread's stack (AGENTS.md, "bounded stack
     * frames"). One heap buffer is allocated here and reused by every act
     * check, so no cycle pays a malloc/free. Observe-only brains never
     * allocate it. An allocation failure is NOT fatal either: the act checks
     * then skip (no re-home, no rebalance) instead of acting on an empty
     * range list, and the degraded mode is journaled once. */
    if (brain->act) {
        brain->ranges = malloc(QIHSE_CLUSTER_SLOT_COUNT * sizeof(qihse_cluster_slot_range_t));
        if (!brain->ranges)
            brain_journal(brain, "BRAIN_DEGRADED",
                          "{\"reason\":\"range-snapshot-unavailable\",\"act\":\"disabled\"}");
    }

    if (pthread_create(&brain->thread, NULL, brain_main, brain) != 0) {
        brain_pool_destroy(brain->pool);
        free(brain->ranges);
        qihse_event_stream_destroy(brain->journal);
        pthread_mutex_destroy(&brain->journal_lock);
        free(brain);
        pthread_mutex_unlock(&g_brain_lock);
        return false;
    }
    g_brain = brain;
    pthread_mutex_unlock(&g_brain_lock);
    return true;
}

void qihse_cluster_brain_stop(void) {
    pthread_mutex_lock(&g_brain_lock);
    brain_t* brain = g_brain;
    g_brain = NULL;
    pthread_mutex_unlock(&g_brain_lock);
    if (!brain) return;
    __atomic_store_n(&brain->running, false, __ATOMIC_RELEASE);
    pthread_join(brain->thread, NULL); /* thread finishes its cycle on its own struct */
    /* The brain thread is joined, so no round is in flight: this parks the
     * idle workers and joins them before the brain struct goes away. */
    brain_pool_destroy(brain->pool);
    free(brain->ranges); /* the act checks ran on the joined thread only */
    qihse_event_stream_destroy(brain->journal);
    pthread_mutex_destroy(&brain->journal_lock);
    free(brain);
}
