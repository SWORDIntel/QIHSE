#ifndef QIHSE_CLUSTER_BRAIN_H
#define QIHSE_CLUSTER_BRAIN_H

/* Cluster brain — decision making for QIHSE clusters (phase 1).
 *
 * Mines MEMSHADOW for the useful parts (persistent decision journal, health
 * monitoring with rollback, deterministic telemetry, signed records) without
 * the bloat. See docs/architecture/cluster_brain.md.
 *
 * Phase 1 = observe + remember + decide, with acting gated behind an
 * explicit flag. Every observation/decision is appended to a durable
 * qihse_event_stream (topic "cluster.brain") and decisions are signed with
 * the node's ML-DSA-87 key when one is configured.
 */

#include <stdint.h>
#include <stdbool.h>
#include "qihse_resp_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    qihse_resp_server_t* server;
    const char* journal_dir;        /* event-stream directory (created) */
    const char* dsa_key_path;       /* ML-DSA-87 signing key (NULL = unsigned) */
    uint32_t interval_seconds;      /* observation cadence (default 5) */
    bool act;                       /* false = observe/journal/decide only */
} qihse_brain_config_t;

/* Start the brain thread. Returns false on allocation/startup failure. */
bool qihse_cluster_brain_start(const qihse_brain_config_t* config);

/* Stop the brain thread and flush the journal. MUST be called before the
 * server topology is freed — the brain references it every cycle. */
void qihse_cluster_brain_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_BRAIN_H */
