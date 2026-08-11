/* qihse_routing_persistence.c — QIHSE persistence adapter for routing intelligence.
 *
 * Bridges QIHSE's three persistence engines (event stream, timeseries, column
 * store) with BGP / routing observation data.  Each BGP observation is fanned
 * out to all three engines; RPKI ROA, PTR, and RDAP records are written to the
 * event stream only.
 *
 * The event stream is the durable, replayable commit log (SHA-384 integrity).
 * The timeseries DB receives one point per BGP observation keyed by a hash of
 * the endpoint IP.  The column store receives one row per BGP observation
 * across six columns.  Because the column store exposes no public read API,
 * an in-memory mirror of appended rows is maintained so that prefix queries
 * can be served without reaching into private internals.
 */

#include "qihse_routing_persistence.h"
#include "qihse_event_stream.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/* ── Constants ────────────────────────────────────────────────────────────── */

#define QIHSE_RP_TOPIC_BGP   "bgp_observations"
#define QIHSE_RP_TOPIC_ROA   "rpki_roas"
#define QIHSE_RP_TOPIC_PTR   "ptr_records"
#define QIHSE_RP_TOPIC_RDAP  "rdap_records"

#define QIHSE_RP_BGP_SCHEMA_ID 1u

#define QIHSE_RP_PREFIX_MAX 64
#define QIHSE_RP_IP_MAX     64
#define QIHSE_RP_AS_PATH_MAX 512
#define QIHSE_RP_HOSTNAME_MAX 256
#define QIHSE_RP_TA_MAX 64
#define QIHSE_RP_RDAP_MAX 4096

/* Column names in the column store. */
#define QIHSE_RP_COL_IP_HASH     "rp_ip_hash"
#define QIHSE_RP_COL_ORIGIN_ASN  "rp_origin_asn"
#define QIHSE_RP_COL_PREFIX      "rp_prefix"
#define QIHSE_RP_COL_RPKI_STATE  "rp_rpki_state"
#define QIHSE_RP_COL_COLLECTOR   "rp_collector_id"
#define QIHSE_RP_COL_TIMESTAMP   "rp_timestamp"

/* ── Internal record mirror ───────────────────────────────────────────────── */

typedef struct qihse_rp_mirror {
    qihse_routing_bgp_record_t* rows;
    size_t count;
    size_t capacity;
} qihse_rp_mirror_t;

/* ── Handle ───────────────────────────────────────────────────────────────── */

struct qihse_routing_persistence {
    qihse_event_stream_t*    event_stream;
    qihse_tsdb_t*            tsdb;
    qihse_column_store_t*    column_store;
    qihse_rp_mirror_t        bgp_mirror;
};

/* ── Helpers ──────────────────────────────────────────────────────────────── */

/* Compute SHA-384 of (topic || payload) — same EVP pattern as qihse_event_stream.c. */
static void qihse_rp_compute_event_id(
        const char* topic,
        const uint8_t* payload,
        size_t payload_size,
        uint8_t out[QIHSE_ES_EVENT_ID_SIZE]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(out, 0, QIHSE_ES_EVENT_ID_SIZE); return; }
    EVP_DigestInit_ex(ctx, EVP_sha384(), NULL);
    EVP_DigestUpdate(ctx, topic, strlen(topic));
    EVP_DigestUpdate(ctx, payload, payload_size);
    unsigned int outlen = 0;
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

/* 64-bit FNV-1a hash of a string. */
static int64_t qihse_rp_hash_ip(const char* ip) {
    uint64_t h = 1469598103934665603ULL; /* FNV offset basis */
    for (const unsigned char* p = (const unsigned char*)ip; *p; ++p) {
        h ^= (uint64_t)*p;
        h *= 1099511628211ULL; /* FNV prime */
    }
    return (int64_t)h;
}

/* Append a row to the in-memory mirror. */
static bool qihse_rp_mirror_append(
        qihse_rp_mirror_t* m,
        int64_t ip_hash,
        int64_t origin_asn,
        const char* prefix,
        int32_t rpki_state,
        int64_t collector_id,
        int64_t timestamp) {
    if (m->count >= m->capacity) {
        size_t new_cap = m->capacity == 0 ? 64 : m->capacity * 2;
        qihse_routing_bgp_record_t* rows =
            realloc(m->rows, new_cap * sizeof(*rows));
        if (!rows) return false;
        m->rows = rows;
        m->capacity = new_cap;
    }
    qihse_routing_bgp_record_t* r = &m->rows[m->count++];
    r->ip_hash = ip_hash;
    r->origin_asn = origin_asn;
    strncpy(r->prefix, prefix ? prefix : "", QIHSE_RP_PREFIX_MAX - 1);
    r->prefix[QIHSE_RP_PREFIX_MAX - 1] = '\0';
    r->rpki_state = rpki_state;
    r->collector_id = collector_id;
    r->timestamp = (int64_t)timestamp;
    return true;
}

/* Create the six BGP columns in the column store (idempotent). */
static void qihse_rp_init_columns(qihse_column_store_t* store) {
    qihse_column_create(store, QIHSE_RP_COL_IP_HASH,    QIHSE_COL_TYPE_INT64);
    qihse_column_create(store, QIHSE_RP_COL_ORIGIN_ASN, QIHSE_COL_TYPE_INT64);
    qihse_column_create(store, QIHSE_RP_COL_PREFIX,     QIHSE_COL_TYPE_STRING_DICT);
    qihse_column_create(store, QIHSE_RP_COL_RPKI_STATE, QIHSE_COL_TYPE_INT32);
    qihse_column_create(store, QIHSE_RP_COL_COLLECTOR,  QIHSE_COL_TYPE_INT64);
    qihse_column_create(store, QIHSE_RP_COL_TIMESTAMP,  QIHSE_COL_TYPE_INT64);
}

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

qihse_routing_persistence_t* qihse_routing_persistence_create(const char* log_dir) {
    if (!log_dir) return NULL;

    qihse_routing_persistence_t* rp = calloc(1, sizeof(*rp));
    if (!rp) return NULL;

    rp->event_stream = qihse_event_stream_create(log_dir);
    if (!rp->event_stream) {
        free(rp);
        return NULL;
    }

    rp->tsdb = qihse_tsdb_create();
    if (!rp->tsdb) {
        qihse_event_stream_destroy(rp->event_stream);
        free(rp);
        return NULL;
    }

    rp->column_store = qihse_column_store_create();
    if (!rp->column_store) {
        qihse_tsdb_destroy(rp->tsdb);
        qihse_event_stream_destroy(rp->event_stream);
        free(rp);
        return NULL;
    }

    qihse_rp_init_columns(rp->column_store);
    return rp;
}

void qihse_routing_persistence_destroy(qihse_routing_persistence_t* rp) {
    if (!rp) return;
    free(rp->bgp_mirror.rows);
    if (rp->column_store) qihse_column_store_destroy(rp->column_store);
    if (rp->tsdb)         qihse_tsdb_destroy(rp->tsdb);
    if (rp->event_stream) qihse_event_stream_destroy(rp->event_stream);
    free(rp);
}

/* ── Store: BGP observation ───────────────────────────────────────────────── */

bool qihse_routing_persistence_store_bgp_observation(
        qihse_routing_persistence_t* rp,
        const char* endpoint_ip,
        int64_t origin_asn,
        const char* prefix,
        const char* as_path,
        int32_t rpki_state,
        int64_t collector_id,
        uint64_t timestamp) {
    if (!rp || !rp->event_stream || !rp->tsdb || !rp->column_store) return false;
    if (!endpoint_ip || !prefix || !as_path) return false;

    /* (a) Build compact JSON payload and append to event stream. */
    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"endpoint_ip\":\"%s\",\"origin_asn\":%lld,\"prefix\":\"%s\","
        "\"as_path\":\"%s\",\"rpki_state\":%d,\"collector_id\":%lld,"
        "\"timestamp\":%llu}",
        endpoint_ip,
        (long long)origin_asn,
        prefix,
        as_path,
        (int)rpki_state,
        (long long)collector_id,
        (unsigned long long)timestamp);
    if (n < 0 || (size_t)n >= sizeof(json)) return false;
    size_t payload_size = (size_t)n;

    uint8_t event_id[QIHSE_ES_EVENT_ID_SIZE];
    qihse_rp_compute_event_id(QIHSE_RP_TOPIC_BGP,
        (const uint8_t*)json, payload_size, event_id);

    uint64_t off = qihse_event_stream_append_record(
        rp->event_stream, QIHSE_RP_TOPIC_BGP, QIHSE_RP_BGP_SCHEMA_ID,
        event_id, (const uint8_t*)json, payload_size);
    if (off == 0) return false;

    /* (b) Insert timeseries point: series_id = hashed IP, value = origin ASN. */
    int64_t ip_hash = qihse_rp_hash_ip(endpoint_ip);
    uint32_t series_id = (uint32_t)(uint64_t)ip_hash; /* low 32 bits */
    bool ts_ok = qihse_tsdb_insert(
        rp->tsdb, series_id, timestamp, (double)origin_asn, 0, 0);
    if (!ts_ok) return false;

    /* (c) Append to column store: six columns. */
    uint16_t cls = 0, sci = 0;
    if (!qihse_column_append_int64(rp->column_store, QIHSE_RP_COL_IP_HASH,
            ip_hash, cls, sci)) return false;
    if (!qihse_column_append_int64(rp->column_store, QIHSE_RP_COL_ORIGIN_ASN,
            origin_asn, cls, sci)) return false;
    if (!qihse_column_append_string(rp->column_store, QIHSE_RP_COL_PREFIX,
            prefix, cls, sci)) return false;
    if (!qihse_column_append_int32(rp->column_store, QIHSE_RP_COL_RPKI_STATE,
            rpki_state, cls, sci)) return false;
    if (!qihse_column_append_int64(rp->column_store, QIHSE_RP_COL_COLLECTOR,
            collector_id, cls, sci)) return false;
    if (!qihse_column_append_int64(rp->column_store, QIHSE_RP_COL_TIMESTAMP,
            (int64_t)timestamp, cls, sci)) return false;

    /* Mirror the row for prefix queries. */
    if (!qihse_rp_mirror_append(&rp->bgp_mirror, ip_hash, origin_asn,
            prefix, rpki_state, collector_id, timestamp)) {
        return false;
    }

    return true;
}

/* ── Store: RPKI ROA ──────────────────────────────────────────────────────── */

bool qihse_routing_persistence_store_rpki_roa(
        qihse_routing_persistence_t* rp,
        const char* prefix,
        uint32_t max_length,
        int64_t asn,
        const char* trust_anchor,
        uint64_t timestamp) {
    if (!rp || !rp->event_stream) return false;
    if (!prefix || !trust_anchor) return false;

    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"prefix\":\"%s\",\"max_length\":%u,\"asn\":%lld,"
        "\"trust_anchor\":\"%s\",\"timestamp\":%llu}",
        prefix,
        (unsigned)max_length,
        (long long)asn,
        trust_anchor,
        (unsigned long long)timestamp);
    if (n < 0 || (size_t)n >= sizeof(json)) return false;
    size_t payload_size = (size_t)n;

    uint8_t event_id[QIHSE_ES_EVENT_ID_SIZE];
    qihse_rp_compute_event_id(QIHSE_RP_TOPIC_ROA,
        (const uint8_t*)json, payload_size, event_id);

    uint64_t off = qihse_event_stream_append_record(
        rp->event_stream, QIHSE_RP_TOPIC_ROA, 1,
        event_id, (const uint8_t*)json, payload_size);
    return off != 0;
}

/* ── Store: PTR record ────────────────────────────────────────────────────── */

bool qihse_routing_persistence_store_ptr_record(
        qihse_routing_persistence_t* rp,
        const char* ip,
        const char* hostname,
        uint64_t timestamp) {
    if (!rp || !rp->event_stream) return false;
    if (!ip || !hostname) return false;

    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"ip\":\"%s\",\"hostname\":\"%s\",\"timestamp\":%llu}",
        ip, hostname, (unsigned long long)timestamp);
    if (n < 0 || (size_t)n >= sizeof(json)) return false;
    size_t payload_size = (size_t)n;

    uint8_t event_id[QIHSE_ES_EVENT_ID_SIZE];
    qihse_rp_compute_event_id(QIHSE_RP_TOPIC_PTR,
        (const uint8_t*)json, payload_size, event_id);

    uint64_t off = qihse_event_stream_append_record(
        rp->event_stream, QIHSE_RP_TOPIC_PTR, 1,
        event_id, (const uint8_t*)json, payload_size);
    return off != 0;
}

/* ── Store: RDAP record ───────────────────────────────────────────────────── */

bool qihse_routing_persistence_store_rdap_record(
        qihse_routing_persistence_t* rp,
        const char* ip,
        const char* rdap_json,
        uint64_t timestamp) {
    if (!rp || !rp->event_stream) return false;
    if (!ip || !rdap_json) return false;

    /* Wrap the caller's RDAP JSON inside an envelope.  We escape double
     * quotes in the embedded JSON so the outer payload stays valid. */
    char escaped[QIHSE_RP_RDAP_MAX];
    size_t ei = 0;
    for (const char* p = rdap_json; *p && ei < sizeof(escaped) - 2; ++p) {
        if (*p == '"' || *p == '\\') {
            if (ei >= sizeof(escaped) - 3) break;
            escaped[ei++] = '\\';
        }
        escaped[ei++] = *p;
    }
    escaped[ei] = '\0';

    char json[QIHSE_RP_RDAP_MAX + 256];
    int n = snprintf(json, sizeof(json),
        "{\"ip\":\"%s\",\"rdap\":\"%s\",\"timestamp\":%llu}",
        ip, escaped, (unsigned long long)timestamp);
    if (n < 0 || (size_t)n >= sizeof(json)) return false;
    size_t payload_size = (size_t)n;

    uint8_t event_id[QIHSE_ES_EVENT_ID_SIZE];
    qihse_rp_compute_event_id(QIHSE_RP_TOPIC_RDAP,
        (const uint8_t*)json, payload_size, event_id);

    uint64_t off = qihse_event_stream_append_record(
        rp->event_stream, QIHSE_RP_TOPIC_RDAP, 1,
        event_id, (const uint8_t*)json, payload_size);
    return off != 0;
}

/* ── Replay BGP observations ──────────────────────────────────────────────── */

uint64_t qihse_routing_persistence_replay_bgp(
        qihse_routing_persistence_t* rp,
        qihse_routing_bgp_cb callback,
        void* user_data) {
    if (!rp || !rp->event_stream || !callback) return 0;
    return qihse_event_stream_replay(
        rp->event_stream, QIHSE_RP_TOPIC_BGP, callback, user_data);
}

/* ── Query by prefix ──────────────────────────────────────────────────────── */

uint64_t qihse_routing_persistence_query_by_prefix(
        qihse_routing_persistence_t* rp,
        const char* prefix,
        qihse_routing_prefix_cb callback,
        void* user_data) {
    if (!rp || !prefix || !callback) return 0;

    size_t plen = strlen(prefix);
    uint64_t matches = 0;

    for (size_t i = 0; i < rp->bgp_mirror.count; ++i) {
        const qihse_routing_bgp_record_t* r = &rp->bgp_mirror.rows[i];
        if (strncmp(r->prefix, prefix, plen) == 0) {
            matches++;
            if (!callback(r, user_data)) break;
        }
    }
    return matches;
}

/* ── Accessor ─────────────────────────────────────────────────────────────── */

qihse_event_stream_t* qihse_routing_persistence_event_stream(
        qihse_routing_persistence_t* rp) {
    if (!rp) return NULL;
    return rp->event_stream;
}

/* ── Flush ────────────────────────────────────────────────────────────────── */

bool qihse_routing_persistence_flush(qihse_routing_persistence_t* rp) {
    if (!rp) return false;
    bool ok = true;
    if (rp->event_stream) {
        ok = ok && qihse_event_stream_flush(rp->event_stream);
    }
    if (rp->tsdb) {
        qihse_tsdb_compress_flush(rp->tsdb);
    }
    return ok;
}
