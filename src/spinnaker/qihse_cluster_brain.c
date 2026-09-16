#include "qihse_cluster_brain.h"
#include "qihse_cluster_bus.h"
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

typedef struct {
    qihse_resp_server_t* server;
    qihse_cluster_topology_t* topology;
    char journal_dir[512];
    char dsa_key_path[576];
    pthread_mutex_t journal_lock;
    uint32_t interval_seconds;
    bool act;
    bool running;
    qihse_event_stream_t* journal;
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
    brain_scan_t* scans = calloc(workers, sizeof(*scans));
    if (!scans) {
        free(owners);
        return;
    }
    uint32_t chunk = (QIHSE_CLUSTER_SLOT_COUNT + workers - 1u) / workers;

    for (uint32_t i = 0; i < workers; i++) {
        scans[i].owners = owners;
        scans[i].start = i * chunk;
        scans[i].end = scans[i].start + chunk;
        if (scans[i].end > QIHSE_CLUSTER_SLOT_COUNT) scans[i].end = QIHSE_CLUSTER_SLOT_COUNT;
    }
    /* spawn workers for all but the first chunk; the calling thread takes
     * the first chunk so no idle-core tax at T=1 */
    pthread_t threads[31];
    uint32_t spawned = 0;
    for (uint32_t i = 1; i < workers; i++) {
        if (scans[i].start >= scans[i].end) break;
        if (pthread_create(&threads[spawned], NULL, scan_worker, &scans[i]) == 0) spawned++;
        else { scan_worker(&scans[i]); } /* degrade to serial on spawn failure */
    }
    scan_worker(&scans[0]);
    for (uint32_t i = 0; i < spawned; i++) pthread_join(threads[i], NULL);

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
            for (size_t r = 0; r < merged_count && roff < (int)sizeof(runs_buf) - 32u; r++) {
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

    for (uint32_t i = 0; i < workers; i++) free(scans[i].runs);
    free(scans);
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
            char detail[256];
            snprintf(detail, sizeof(detail), "{\"peer\":\"%s:%u\",\"policy\":\"quarantine-noaction\"}",
                     nodes[i].host, nodes[i].port);
            brain_journal(brain, "ASYMMETRY", detail);
            return;
        }
    }
}

static void* brain_main(void* argument) {
    /* The thread owns its brain struct for its whole lifetime: stop() joins
     * the thread BEFORE freeing, so these accesses need no lock. */
    brain_t* brain = (brain_t*)argument;
    brain_journal(brain, "BRAIN_START", "{\"mode\":\"observe\"}");
    while (__atomic_load_n(&brain->running, __ATOMIC_ACQUIRE)) {
        qihse_cluster_node_t nodes[BRAIN_MAX_NODES];
        size_t count = brain->topology
                           ? qihse_cluster_topology_nodes(brain->topology, nodes, BRAIN_MAX_NODES)
                           : 0;
        if (count > 0) {
            brain_observe(brain);
            brain_check_isolation(brain, nodes, count);
            brain_check_asymmetry(brain, nodes, count);
        }
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

    if (pthread_create(&brain->thread, NULL, brain_main, brain) != 0) {
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
    qihse_event_stream_destroy(brain->journal);
    pthread_mutex_destroy(&brain->journal_lock);
    free(brain);
}
