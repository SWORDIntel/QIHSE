#ifndef QIHSE_ROUTING_PERSISTENCE_H
#define QIHSE_ROUTING_PERSISTENCE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "qihse_event_stream.h"

/* ── Opaque handle ───────────────────────────────────────────────────────── */

typedef struct qihse_routing_persistence qihse_routing_persistence_t;

/* ── BGP observation record (mirrors column store row) ───────────────────── */

typedef struct qihse_routing_bgp_record {
    int64_t  ip_hash;        /* 64-bit hash of endpoint IP */
    int64_t  origin_asn;     /* origin AS number */
    char     prefix[64];     /* announced prefix (CIDR) */
    int32_t  rpki_state;     /* RPKI validation state */
    int64_t  collector_id;   /* collector identifier */
    int64_t  timestamp;      /* observation timestamp */
} qihse_routing_bgp_record_t;

/* ── Callbacks ────────────────────────────────────────────────────────────── */

/* Replay callback — same shape as qihse_es_replay_cb for passthrough. */
typedef bool (*qihse_routing_bgp_cb)(
    const qihse_es_record_header_t* header,
    const uint8_t* payload,
    size_t payload_size,
    void* user_data);

/* Prefix-query callback — invoked once per matching column-store row. */
typedef bool (*qihse_routing_prefix_cb)(
    const qihse_routing_bgp_record_t* rec,
    void* user_data);

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

/* Create a persistence handle backed by an event stream, timeseries DB,
 * and column store.  The log_dir is used for the durable event stream. */
qihse_routing_persistence_t* qihse_routing_persistence_create(const char* log_dir);

void qihse_routing_persistence_destroy(qihse_routing_persistence_t* rp);

/* ── Store operations ─────────────────────────────────────────────────────── */

/* Store a BGP observation.
 * Writes:
 *   a) event stream record (topic="bgp_observations", schema_id=1, JSON payload)
 *   b) timeseries point (series_id=hashed_ip, value=origin_asn)
 *   c) column store appends: ip_hash, origin_asn, prefix, rpki_state,
 *      collector_id, timestamp */
bool qihse_routing_persistence_store_bgp_observation(
    qihse_routing_persistence_t* rp,
    const char* endpoint_ip,
    int64_t origin_asn,
    const char* prefix,
    const char* as_path,
    int32_t rpki_state,
    int64_t collector_id,
    uint64_t timestamp);

/* Store an RPKI ROA entry (event stream record, topic="rpki_roas"). */
bool qihse_routing_persistence_store_rpki_roa(
    qihse_routing_persistence_t* rp,
    const char* prefix,
    uint32_t max_length,
    int64_t asn,
    const char* trust_anchor,
    uint64_t timestamp);

/* Store a PTR record (event stream record, topic="ptr_records"). */
bool qihse_routing_persistence_store_ptr_record(
    qihse_routing_persistence_t* rp,
    const char* ip,
    const char* hostname,
    uint64_t timestamp);

/* Store an RDAP record (event stream record, topic="rdap_records"). */
bool qihse_routing_persistence_store_rdap_record(
    qihse_routing_persistence_t* rp,
    const char* ip,
    const char* rdap_json,
    uint64_t timestamp);

/* ── Read / query ─────────────────────────────────────────────────────────── */

/* Replay all committed BGP observation records via callback.
 * Returns the number of records replayed. */
uint64_t qihse_routing_persistence_replay_bgp(
    qihse_routing_persistence_t* rp,
    qihse_routing_bgp_cb callback,
    void* user_data);

/* Scan the column store for records whose prefix matches the given prefix
 * string (simple string prefix check).  Invokes callback once per match.
 * Returns the number of matching records. */
uint64_t qihse_routing_persistence_query_by_prefix(
    qihse_routing_persistence_t* rp,
    const char* prefix,
    qihse_routing_prefix_cb callback,
    void* user_data);

/* Access the underlying event stream handle for direct topic replay. */
qihse_event_stream_t* qihse_routing_persistence_event_stream(
    qihse_routing_persistence_t* rp);

/* ── Maintenance ──────────────────────────────────────────────────────────── */

/* Flush all underlying stores to disk. */
bool qihse_routing_persistence_flush(qihse_routing_persistence_t* rp);

#endif /* QIHSE_ROUTING_PERSISTENCE_H */
