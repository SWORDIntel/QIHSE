#ifndef QIHSE_OVERLAY_H
#define QIHSE_OVERLAY_H

/* QIHSE overlay — IRC dead-drop bootstrap (phase 1b).
 *
 * A per-node IRC client thread runs alongside the cluster bus so nodes
 * discover each other over the internet with zero manual topology.  Every
 * 30 s the node posts a signed record to a shared IRC channel:
 *
 *     QIHSE1 <base64( HMAC-SHA-384(key, json) || json )>
 *     json = {"ep":"host:port","bus":port,"id":"<node_id hex>","ts":<unix_ms>}
 *
 * with key = cluster operator password.  All inbound records are verified
 * (HMAC + ±5 min timestamp freshness) before the discovered endpoint is
 * introduced to the bus with qihse_cluster_bus_meet().  The IRC server is
 * an untrusted bulletin board: the HMAC proves the record came from a node
 * that holds the operator password, the timestamp bounds replay, and the
 * signature covers the endpoint so it cannot be redirected.  ML-DSA signing
 * of records is a phase-2 upgrade.
 *
 * See docs/architecture/overlay_protocol.md, "Layer 2: IRC dead-drop
 * bootstrap".  Layer 1 (veiled framing) and Layer 3 (DHT peer exchange)
 * live elsewhere.
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wire constants of the QIHSE1 dead-drop record. */
#define QIHSE_OVERLAY_RECORD_PREFIX "QIHSE1"
#define QIHSE_OVERLAY_HMAC_SIZE 48u          /* HMAC-SHA-384 digest bytes */
#define QIHSE_OVERLAY_ADVERTISE_MS 30000u    /* beacon cadence */
#define QIHSE_OVERLAY_FRESHNESS_MS 300000u   /* ±5 min replay window */

struct qihse_cluster_bus;

typedef struct {
    const char* irc_server;    /* host:port of the IRC server */
    const char* irc_channel;   /* e.g. "#qihse-fabric" */
    const char* nick_prefix;   /* e.g. "qihse" */
    const char* node_id;       /* 40-char hex from topology */
    const char* bind_host;     /* this node's advertise host */
    uint16_t bind_port;        /* this node's bus port */
    const char* hmac_password; /* cluster operator password */
    struct qihse_cluster_bus* bus; /* for qihse_cluster_bus_meet() */
} qihse_overlay_config_t;

/* Start the IRC bootstrap thread.  The config is copied; the caller may
 * release it after this returns.  Returns false on invalid config,
 * allocation, or thread-creation failure.  Starting an already-running
 * overlay returns true (singleton per process). */
bool qihse_overlay_start(const qihse_overlay_config_t* config);

/* Stop the IRC bootstrap thread and release all overlay resources.  Safe
 * to call when not running; blocks until the thread has exited (bounded). */
void qihse_overlay_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_OVERLAY_H */
