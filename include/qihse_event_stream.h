#ifndef QIHSE_EVENT_STREAM_H
#define QIHSE_EVENT_STREAM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

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

/* On-disk record header (64 bytes, fixed-width little-endian). */
typedef struct qihse_es_record_header {
    uint32_t magic;            /* QIHSE_ES_MAGIC */
    uint32_t format_version;   /* QIHSE_ES_FORMAT_VERSION */
    uint32_t flags;            /* QIHSE_ES_F_* */
    uint32_t schema_id;        /* caller-defined schema version */
    uint64_t stream_offset;   /* monotonic byte offset of this record */
    uint64_t payload_size;     /* payload length in bytes */
    uint64_t prev_record_offset; /* 0 for first record, else offset of predecessor */
    uint8_t  event_id[QIHSE_ES_EVENT_ID_SIZE]; /* SHA-384 of (topic || payload) */
    /* — total 64 bytes when packed — */
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

#endif /* QIHSE_EVENT_STREAM_H */
