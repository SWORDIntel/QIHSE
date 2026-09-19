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
 * bootstrap".  Layer 1 (veiled framing) lives in the cluster bus; layer 3
 * (DHT peer exchange) lives here too, behind the gate note below.
 */

#include "qihse_cluster_slot.h"

#include <stdbool.h>
#include <stddef.h>
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
    /* Start the IRC bootstrap WITHOUT layer 3 (the DHT peer exchange).  The
     * DHT is enabled by default because it is the internet-scale discovery
     * path the overlay exists for; this is the operator's off switch for a
     * deployment that wants the dead-drop and not the extra surface. */
    bool disable_dht;
} qihse_overlay_config_t;

/* Start the IRC bootstrap thread.  The config is copied; the caller may
 * release it after this returns.  Returns false on invalid config,
 * allocation, or thread-creation failure.  Starting an already-running
 * overlay returns true (singleton per process). */
bool qihse_overlay_start(const qihse_overlay_config_t* config);

/* Stop the IRC bootstrap thread and release all overlay resources.  Safe
 * to call when not running; blocks until the thread has exited (bounded).
 * Stops the DHT too when this call started it. */
void qihse_overlay_stop(void);

/* ── Layer 3: DHT peer exchange (simplified Kademlia) ─────────────────────
 *
 * WHAT THIS BUYS: a peer-exchange HINT SOURCE, and nothing more.  A
 * QIHSE_BUS_MSG_DHT_FIND query is answered with up to QIHSE_DHT_K peers the
 * responder already knows, ordered by XOR distance to the target node id —
 * the Kademlia ordering, without k-buckets, without an iterative lookup, and
 * without storing anything at a key (there is no FIND_VALUE and no value
 * store: a value store reachable by an unauthenticated datagram is a
 * poisoning target with no benefit over the bus that already carries the
 * cluster's state).  It does NOT improve routing: slot ownership and
 * membership still travel on the bus (MEET/SLOT_UPDATE), and a DHT reply is
 * never consulted to decide where a key lives.
 *
 * WHAT A RECORD CANNOT DO.  A DHT record is UNAUTHENTICATED: no signature,
 * MAC or key is carried, and nothing binds the node id in it to the sender.
 * The only action a hint can cause is a DIAL — qihse_cluster_bus_meet() to
 * the hinted endpoint, the same call the IRC path makes for an IRC record.
 * It cannot upsert a topology node, cannot write a federation identity or
 * capability record, cannot change a trust state, and cannot acquire
 * authority: qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_MEET) is false and
 * the dial path refuses to run if that ever stops being true.  Membership is
 * decided by the peer's own MEET reply, and usable identity by F5 enrollment
 * (qihse_federation_node_capability_lookup_admissible()).  When a federation
 * trust context is configured, a hint for a REVOKED identity is never dialed:
 * the DHT may not undo an operator decision, and it may not make one either.
 *
 * Everything is bounded because every input is attacker-controlled: the peer
 * list is capped at QIHSE_DHT_K, both frames are fixed-size with no length
 * field to lie about, a lookup is ONE hop (a FIND is never forwarded, so a
 * request cannot recurse or amplify), replies and dials are rate-limited per
 * second, and hint state is a fixed-size dedupe table a flood cannot grow.
 */

#define QIHSE_DHT_K 8u                 /* peers returned per reply (doc: k=8) */
#define QIHSE_DHT_FRAME_VERSION 1u
#define QIHSE_DHT_HOST_MAX 64u         /* dialable host text incl. NUL */
#define QIHSE_DHT_MAX_HINTS 64u        /* dialed-endpoint dedupe table */
#define QIHSE_DHT_SERVE_WINDOW_MS 1000u
#define QIHSE_DHT_SERVE_MAX_PER_WINDOW 16u  /* NODES replies per second */
#define QIHSE_DHT_HINT_WINDOW_MS 1000u
#define QIHSE_DHT_HINT_MAX_PER_WINDOW 32u   /* hint entries examined per second */
#define QIHSE_DHT_DIAL_WINDOW_MS 1000u
#define QIHSE_DHT_DIAL_MAX_PER_WINDOW 4u    /* MEETs caused per second */

/* Fixed-size wire payloads.  There is no variable-length field and no length
 * field at all: a frame either has exactly the size below or it is dropped,
 * which is the strongest available bound on every length. */
#define QIHSE_DHT_FIND_PAYLOAD_SIZE \
    (4u + 8u + 2u + (QIHSE_CLUSTER_NODE_ID_LEN + 1u) * 2u + QIHSE_DHT_HOST_MAX)
#define QIHSE_DHT_NODES_HEADER_SIZE \
    (4u + 8u + QIHSE_CLUSTER_NODE_ID_LEN + 1u)
#define QIHSE_DHT_ENTRY_SIZE \
    (QIHSE_CLUSTER_NODE_ID_LEN + 1u + QIHSE_DHT_HOST_MAX + 2u)
#define QIHSE_DHT_NODES_MAX_PAYLOAD \
    (QIHSE_DHT_NODES_HEADER_SIZE + QIHSE_DHT_K * QIHSE_DHT_ENTRY_SIZE)

typedef struct {
    const char* node_id;           /* this node's 40-char lowercase hex id */
    const char* advertise_host;    /* this node's dialable IPv4 advertise host */
    uint16_t advertise_port;       /* this node's bus port */
    struct qihse_cluster_bus* bus; /* transport and MEET sink (required) */
    /* Optional federation trust context (qihse_kv_store_t* / qihse_user_t*).
     * Used as a NEGATIVE filter only: a hint whose derived UUID resolves to a
     * REVOKED identity is never dialed.  It cannot admit anything.  NULL (the
     * default) means "no negative filter configured". */
    void* federation_store;
    void* federation_user;
} qihse_overlay_dht_config_t;

typedef struct {
    char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char host[QIHSE_DHT_HOST_MAX];
    uint16_t port;
    uint64_t dialed_ms;   /* monotonic ms the hint was dialed */
} qihse_overlay_dht_hint_t;

typedef struct {
    uint64_t finds_served;
    uint64_t finds_rejected;      /* malformed/stale/self FIND frames */
    uint64_t finds_rate_limited;
    uint64_t nodes_accepted;      /* well-formed, fresh NODES frames */
    uint64_t nodes_rejected;      /* malformed/stale/self NODES frames */
    uint64_t frames_stale;        /* dropped by the +-5 min replay window */
    uint64_t hints_dialed;        /* hints that passed every gate and were dialed */
    uint64_t hints_duplicate;     /* endpoint already in the dedupe table */
    uint64_t hints_self;          /* hint named this node or its own endpoint */
    uint64_t hints_revoked;       /* trust context says REVOKED */
    uint64_t hints_rate_limited;  /* window budget exhausted */
} qihse_overlay_dht_stats_t;

/* Enable the DHT hint table.  This is what makes the QIHSE_BUS_MSG_DHT_* 
 * handlers act at all: without it they drop every frame, which is the
 * fail-closed default for every bus in the tree that does not run the
 * overlay.  Returns false on invalid config (bad node id, missing bus,
 * non-literal advertise host) or when already running.  qihse_overlay_start()
 * enables it automatically unless config->disable_dht is set. */
bool qihse_overlay_dht_start(const qihse_overlay_dht_config_t* config);

/* Disable the DHT and release its state.  Safe to call when not enabled.
 * Blocks (bounded) for an in-flight handler; if one does not finish the state
 * is leaked rather than freed under a live thread. */
void qihse_overlay_dht_stop(void);

/* Is the DHT hint table enabled in this process? */
bool qihse_overlay_dht_enabled(void);

/* Copy the dialed-hint dedupe table (bounded at QIHSE_DHT_MAX_HINTS) into
 * `out`; returns the number of hints held.  Diagnostics and tests. */
size_t qihse_overlay_dht_hints(qihse_overlay_dht_hint_t* out, size_t capacity);

void qihse_overlay_dht_stats(qihse_overlay_dht_stats_t* out_stats);

/* Ask a peer for the peers it knows closest to `target_id`.  One datagram,
 * one hop, no recursion: this is a query, not a lookup walk.  Returns false
 * when the DHT is not enabled for this bus, the arguments are not dialable,
 * or this node has no dialable advertise endpoint for the reply. */
bool qihse_overlay_dht_query(struct qihse_cluster_bus* bus, const char* host,
                             uint16_t port, const char* target_id);

/* Frame handlers, called by the cluster bus dispatch for
 * QIHSE_BUS_MSG_DHT_FIND / QIHSE_BUS_MSG_DHT_NODES.  Both are no-ops when the
 * DHT is not enabled for that bus, and neither can make anything a member:
 * see the gate note above.  Return true when the frame was well-formed, fresh
 * and acted on.
 *
 * The FIND handler is given the cluster topology read-only: a reply may only
 * hand back endpoints the responder itself already knows, so the exchange can
 * never invent a peer.  It never writes to it. */
bool qihse_overlay_dht_handle_find(struct qihse_cluster_bus* bus,
                                   const qihse_cluster_topology_t* topology,
                                   const uint8_t* payload, size_t payload_len);
bool qihse_overlay_dht_handle_nodes(struct qihse_cluster_bus* bus,
                                    const uint8_t* payload, size_t payload_len);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_OVERLAY_H */
