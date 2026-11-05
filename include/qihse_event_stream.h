#ifndef QIHSE_EVENT_STREAM_H
#define QIHSE_EVENT_STREAM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_auth.h"

/* ── Record framing ─────────────────────────────────────────────────────── */

#define QIHSE_ES_MAGIC 0x51455354u   /* "QEST" */
#define QIHSE_ES_FORMAT_VERSION 1u
#define QIHSE_ES_RECORD_HEADER_SIZE 88u  /* 40 fixed fields + 48 event_id */
#define QIHSE_ES_MAX_PAYLOAD (16u * 1024u * 1024u)  /* 16 MiB */
#define QIHSE_ES_SEGMENT_MAX (256u * 1024u * 1024u) /* 256 MiB */
#define QIHSE_ES_TOPIC_MAX 64
#define QIHSE_ES_EVENT_ID_SIZE 48  /* SHA-384 = 48 bytes */

/* Record flags */
#define QIHSE_ES_F_COMMITTED 0x01u
#define QIHSE_ES_F_CORRUPT   0x02u

/* Durability modes */
typedef enum {
    QIHSE_ES_DURABILITY_NONE = 0,      /* no fsync — fastest, may lose recent */
    QIHSE_ES_DURABILITY_FDATASYNC = 1, /* fdatasync after each commit */
    QIHSE_ES_DURABILITY_FULL = 2       /* fdatsync + rename for atomic rotation */
} qihse_es_durability_t;

/* V1 on-disk record header (88 bytes). Layout retained for compatibility. */
typedef struct qihse_es_record_header {
    uint32_t magic;            /* QIHSE_ES_MAGIC */
    uint32_t format_version;   /* QIHSE_ES_FORMAT_VERSION */
    uint32_t flags;            /* QIHSE_ES_F_* */
    uint32_t schema_id;        /* caller-defined schema version */
    uint64_t stream_offset;   /* monotonic byte offset of this record */
    uint64_t payload_size;     /* payload length in bytes */
    uint64_t prev_record_offset; /* 0 for first record, else offset of predecessor */
    uint8_t  event_id[QIHSE_ES_EVENT_ID_SIZE]; /* SHA-384 of (topic || payload) */
    /* — total 88 bytes — */
} qihse_es_record_header_t;

/* ── Opaque handle ───────────────────────────────────────────────────────── */

typedef struct qihse_event_stream qihse_event_stream_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

qihse_event_stream_t* qihse_event_stream_create(const char* log_directory);
void qihse_event_stream_destroy(qihse_event_stream_t* stream);

/* Open with explicit durability mode and owner-only permissions. */
qihse_event_stream_t* qihse_event_stream_open(
    const char* log_directory,
    qihse_es_durability_t durability,
    bool read_only);

/* Flush all pending writes to disk. */
bool qihse_event_stream_flush(qihse_event_stream_t* stream);

/* ── Append (write path) ─────────────────────────────────────────────────── */

/* Append a record with schema version and event ID.
 * The event_id must be QIHSE_ES_EVENT_ID_SIZE bytes (SHA-384).
 * Returns the stream offset of the committed record, or 0 on failure.
 * Rejects duplicate event IDs already present in the topic. */
uint64_t qihse_event_stream_append_record(
    qihse_event_stream_t* stream,
    const char* topic,
    uint32_t schema_id,
    const uint8_t* event_id,       /* QIHSE_ES_EVENT_ID_SIZE bytes */
    const uint8_t* payload,
    size_t payload_size);

/* Legacy append — computes event_id as SHA-384(topic || payload) internally. */
bool qihse_event_stream_append(
    qihse_event_stream_t* stream,
    const char* topic,
    const uint8_t* payload,
    size_t payload_size);

/* ── Read path ────────────────────────────────────────────────────────────── */

/* Read a record by monotonic stream offset.
 * Returns the record header, payload, and actual bytes read.
 * Caller must free *out_payload. */
bool qihse_event_stream_read(
    qihse_event_stream_t* stream,
    const char* topic,
    uint64_t stream_offset,
    qihse_es_record_header_t* out_header,
    uint8_t** out_payload,
    size_t* out_payload_size);

/* Iterate records in order. Pass cursor=0 for first call.
 * Returns false when no more records. Updates cursor for next call. */
bool qihse_event_stream_iterate(
    qihse_event_stream_t* stream,
    const char* topic,
    uint64_t* cursor,
    qihse_es_record_header_t* out_header,
    uint8_t** out_payload,
    size_t* out_payload_size);

/* Get the current committed length of a topic log. */
uint64_t qihse_event_stream_length(
    qihse_event_stream_t* stream,
    const char* topic);

/* Check if an event ID exists in the topic (duplicate rejection). */
bool qihse_event_stream_has_event_id(
    qihse_event_stream_t* stream,
    const char* topic,
    const uint8_t* event_id);

/* ── Recovery ─────────────────────────────────────────────────────────────── */

/* Replay committed records from the beginning of a topic.
 * Calls callback for each committed, non-corrupt record.
 * Stops at first torn or corrupt tail. */
typedef bool (*qihse_es_replay_cb)(
    const qihse_es_record_header_t* header,
    const uint8_t* payload,
    size_t payload_size,
    void* user_data);

uint64_t qihse_event_stream_replay(
    qihse_event_stream_t* stream,
    const char* topic,
    qihse_es_replay_cb callback,
    void* user_data);

/* Truncate any uncommitted (torn) tail records after the last valid commit. */
bool qihse_event_stream_truncate_torn_tail(
    qihse_event_stream_t* stream,
    const char* topic);

/* ── Zero-copy consumption (sendfile) ─────────────────────────────────────── */

bool qihse_event_stream_consume_zero_copy(
    qihse_event_stream_t* stream,
    const char* topic,
    uint64_t offset,
    int network_socket_fd,
    size_t count);

/* Authenticated V2 logs occupy a separate, non-legacy-addressable namespace.
 * The tenant is always derived from the active principal, never supplied by a
 * caller. Classification and SCI are part of the topic identity. */
#define QIHSE_ES_FORMAT_VERSION_V2 2u
#define QIHSE_ES_V2_TRAILER_SIZE QIHSE_ES_EVENT_ID_SIZE
#define QIHSE_ES_BATCH_MAX_RECORDS 1024u
#define QIHSE_ES_BATCH_MAX_BYTES (64u * 1024u * 1024u)

typedef struct qihse_es_scope {
    const char* topic;
    uint16_t classification;
    uint16_t sci;
} qihse_es_scope_t;

typedef struct qihse_es_batch_record {
    uint32_t schema_id;
    const uint8_t* event_id; /* optional; otherwise hash scoped topic + payload */
    const uint8_t* payload;
    size_t payload_size;
} qihse_es_batch_record_t;

typedef struct qihse_es_batch_result {
    uint64_t stream_offset; /* actual byte offset, including zero */
    bool duplicate;         /* existing IDs return their original offset */
} qihse_es_batch_result_t;

typedef struct qihse_es_read_record {
    qihse_es_record_header_t header;
    uint8_t* payload; /* owned by caller; release with batch_free */
    size_t payload_size;
} qihse_es_read_record_t;

/* One exclusive topic lock spans recovery, deduplication and all writes.
 * Durability modes sync once before and once after group commit. A batch is
 * not a crash-atomic transaction: recovery can retain a committed prefix.
 * Returns false on errors; results are only valid on success. */
bool qihse_event_stream_append_batch(qihse_event_stream_t* stream,
    const qihse_user_t* user, const qihse_es_scope_t* scope,
    const qihse_es_batch_record_t* records, size_t count,
    qihse_es_batch_result_t* results);

/* Cursor is a byte offset, initially zero; only record boundaries are accepted.
 * At most capacity records / max_payload_bytes are returned (bounded by the
 * constants above). On failure cursor is unchanged and no payload is returned.
 * An empty successful read is EOF. Too small a budget for the first record
 * fails rather than masquerading as EOF. Integrity is checked before disclosure. */
bool qihse_event_stream_read_batch(qihse_event_stream_t* stream,
    const qihse_user_t* user, const qihse_es_scope_t* scope,
    uint64_t* cursor, qihse_es_read_record_t* records, size_t capacity,
    size_t max_payload_bytes, size_t* out_count);
void qihse_event_stream_batch_free(qihse_es_read_record_t* records, size_t count);

/* Stable, domain-separated content identities. Member IDs bind an archive ID
 * and exact member name; they do not depend on batch order or stream offset. */
bool qihse_event_stream_archive_id(const uint8_t* archive, size_t archive_size,
    const char* scan_version, uint32_t schema_id,
    uint8_t out_id[QIHSE_ES_EVENT_ID_SIZE]);
bool qihse_event_stream_member_id(
    const uint8_t archive_id[QIHSE_ES_EVENT_ID_SIZE], const char* member_name,
    const char* scan_version, uint32_t schema_id,
    uint8_t out_id[QIHSE_ES_EVENT_ID_SIZE]);

#endif /* QIHSE_EVENT_STREAM_H */
